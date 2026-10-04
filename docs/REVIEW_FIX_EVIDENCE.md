# 리뷰 수정과 재현 증거

기준: PR #1의 `a9ab769c7c6970da772d32eeed84189f74926a76` → 이 문서가 포함된 후속 수정 커밋.
검증일: 2026-10-04. 실행 환경: Linux. **Windows OS 실측은 수행하지 않았습니다.**

## 결과 요약

| 문제 | 수정 전 증거 | 수정 후 | 증거의 범위 |
| --- | --- | --- | --- |
| UTF-8 바이트 경계 읽기 | 실제 Node 파일 작업과 전송 fixture에서 정상 파일 읽기가 lifecycle 오류로 바뀜 | 정확한 바이트를 base64로 보존하고 실제 encoding 반환 | 실제 JS 코드, 네이티브 종료 상태는 모의 |
| 일반 파일 오류 | 없는 파일/잘못된 UTF-8 편집이 BROKER_LOST 또는 세션 BLOCKED로 바뀜 | 종료 확인 시 FILE_OPERATION_FAILED로 보고하고 세션 재사용 | 실제 파일 worker + JS broker, Windows 격리 아님 |
| 기존 방화벽 규칙의 제한 조건 잔존 | 기존 SID-only 검증식을 추출한 portable 모델에서 좁은 application 등의 조건을 허용 | 전체 조건 일치 검증, 충돌 규칙 무수정 거부 | COM property readback 모델; Windows 패킷 차단 실측 아님 |
| 다른 계정에서 broker 감시 핸들 열기 | 기존 helper 경로의 PID 재열기를 잡는 소스 계약 테스트 2건 실패 | broker가 최소 SYNCHRONIZE 핸들 전달, helper가 PID로 다시 열지 않음 | 소스 계약 검사; Windows 전용 테스트는 컴파일만 |

## 1. 파일 처리: 실제 코드 재현

회귀 테스트: `tests/native-backend/file-regressions.test.mjs`.

`node --test tests/native-backend/file-regressions.test.mjs`

- 수정 전: 4개 실패. [로그](review-evidence/2026-10-04/js-before.log)
- 수정 후: 4개 통과. [로그](review-evidence/2026-10-04/js-after.log)
- 원본 0.2.0 ZIP을 별도 임시 디렉터리에 풀고 새 회귀 테스트만 주입한 독립 재검사에서도 4개 실패를 확인했습니다.
- ASCII·한글·이모지·악센트 문자의 모든 1바이트 구간, 잘못된 UTF-8 파일, BOM, 파일 없음, 이후 세션 재사용을 검사합니다.
- UTF-8로 독립 해석할 수 없는 범위는 대체문자 삽입·바이트 삭제·추가 읽기 없이 base64를 반환합니다. 호출자는 실제 encoding을 확인해야 합니다.
- 파일 오류를 복구 가능으로 분류하는 것은 프로세스 종료가 확인된 경우뿐입니다. 미확인 종료와 알 수 없는 오류는 계속 BLOCKED입니다. 실패한 쓰기의 자동 롤백을 보장하지 않습니다.

## 2. 방화벽: 검증식 모델 재현

테스트 대상: `native/windows-sandbox/src/network/firewall_scope.rs`. 실제 Windows COM 어댑터도 같은 validator를 사용합니다.

- 기존 코드의 `!actual_str.contains(spec.offline_sid)` 판정을 그대로 추출하고 모의 속성을 공급한 baseline: 1개 통과, 22개 실패. [모델 소스](review-evidence/2026-10-04/firewall-baseline-model.rs), [로그](review-evidence/2026-10-04/firewall-before-model.log)
- 수정 후 전체 속성 비교: 23개 통과. [로그](review-evidence/2026-10-04/firewall-after.log)
- 이 22개는 누락된 readback 검증 사례입니다. 기존 setter가 이미 덮어쓰던 속성도 포함하므로, 22개의 Windows 우회를 재현했다는 뜻이 아닙니다. 원래 결함의 핵심은 application/service/local address/interface/port처럼 기존 제한이 남는 경우입니다.
- 기존 규칙은 전체 예상 조건과 일치할 때만 읽기 방식으로 수용합니다. 이름 충돌 시 다른 규칙을 수정하지 않습니다. 신규 규칙은 조건을 명시하고 등록 전후 검증합니다.
- Windows의 COM 문자열 정규화가 다르면 안전하게 setup 실패할 수 있습니다. 실제 호환성·통신 차단·정책 적용은 Windows에서 확인해야 합니다. [세부 계약](FIREWALL_RULE_SCOPE.md)

모델은 `rustc --edition=2021 --test docs/review-evidence/2026-10-04/firewall-baseline-model.rs -o <임시경로>`로 다시 실행할 수 있으며 실패가 예상 결과입니다.

## 3. 부모 감시: 코드 계약과 Windows 테스트 소스

`cargo test --locked --manifest-path native/windows-sandbox/Cargo.toml --test broker_wait_contract`

- 수정 전 2개 실패: [로그](review-evidence/2026-10-04/handle-before-contract.log)
- 수정 후 2개 통과: [로그](review-evidence/2026-10-04/handle-after-contract.log)
- broker가 보호된 suspended helper에 상속 불가·SYNCHRONIZE-only 핸들을 전달한 뒤 ACL admission/resume을 진행합니다. helper는 받은 로컬 핸들을 안전하게 복제해 소유하고 PID를 다시 열지 않습니다.
- Windows 전용 테스트 3개는 최소 권한·상속/소유권·잘못된 핸들 및 제한 DACL의 OpenProcess 실패 대 기존 핸들 복제를 검사하도록 작성되어 있습니다. **컴파일만 했으며 실행하지 않았습니다.** 실제 전용 계정 간 동작도 아직 미검증입니다.

## 최종 검사

- JS: 실제 Pi SDK 초기화 포함 **66/66 통과**, skip 없음. [로그](review-evidence/2026-10-04/js-full.log)
- JS 구문: **12개 모듈 통과**. [로그](review-evidence/2026-10-04/js-syntax.log)
- Python probe: **16개 통과**. [로그](review-evidence/2026-10-04/python-tests.log)
- Rust Linux: **28개 unit + 2개 소스 계약 통과**. [로그](review-evidence/2026-10-04/rust-tests.log)
- Windows GNU: `cargo check --locked --offline --target x86_64-pc-windows-gnu --all-targets` 통과. [로그](review-evidence/2026-10-04/windows-typecheck.log)
- Rust formatting 통과. Windows 링크·실행·보안 설정 변경은 수행하지 않았습니다.

## 여전히 남은 차단 조건

두 production gate는 false입니다. helper 시작 전후 동일 계정 프로세스의 핸들 획득 race, 승인/정책 인증 endpoint, orphan 확인, durable ACL 복구·repair/uninstall, 실행 직전 네트워크 실효성 재확인, 실제 Windows 검증은 남아 있습니다. 이번 수정은 이 항목들의 해결이나 생산 환경 안전성을 의미하지 않습니다.
