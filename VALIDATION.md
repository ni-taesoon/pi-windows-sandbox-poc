# 소스 분리 버전 검증 결과

검증일: 2026-10-04. 기존 외부 CLI 기반 버전 대신 독립 Rust 소스와 직접 Pi 어댑터를 검사한 기록입니다.

## 실행한 검사

| 검사 | 결과 | 의미 |
| --- | --- | --- |
| JavaScript 전체 테스트와 실제 Pi SDK 초기화 검사 | 61 PASS | 정책·파일·취소·바이너리 출력·native 요청 계약, 실제 Pi 1.0.2 메모리 세션 초기화 포함 |
| JavaScript 구문 검사 | PASS | 소스 문법 유효성 |
| Python probe 로직 테스트 | 16 PASS | mock/임시 파일 기반, 네트워크 실측 없음 |
| `cargo test --locked` | portable 5 PASS | 정책 mask, JSON 계약과 닫힌 production gate 검사 |
| `cargo check --locked --target x86_64-pc-windows-gnu --all-targets` | PASS, 미사용 코드 경고 존재 | Windows 전용 library 및 test 코드 타입 검사 |
| Linux native `status` 실행 | PASS | `nativeValidated:false`, `platformSupported:false` 확인 |

사용 환경은 Linux x64, Node.js 24.19.0, Python 3.12.14, Rust/Cargo 1.99.0입니다. Rust 공식 배포 도구와 Windows GNU standard-library target을 사용했습니다. Windows용 바이너리를 링크하거나 Windows에서 코드를 실행한 결과가 아닙니다. Pi 검사에는 모델 요청·API 키·호스트 도구 실행이 없습니다.

## 이번 변경에서 수정한 문제

- UTF-8이 아닌 원본을 수정 전에 거부하여 요청 밖의 바이트 손상을 방지
- 겹치는 편집 일치도 중복으로 판단
- 파일 내용 한도와 JSON/base64 전송 한도 분리
- stdout/stderr 각각의 UTF-8 경계를 보존하고 native 출력은 base64로 전달
- 이미 취소된 요청을 spawn 전에 차단
- 중복 루트 구분자 정규화와 진단 오류 종료 상태 정정
- 부모 종료/timeout/output limit을 정상 종료와 구분하고 프로세스 정리 후 결과 수집
- Windows credential file 동기 I/O 옵션, desktop station 일치, 필요한 Windows API feature 정정
- 쓰기 deny mask에서 읽기 공통 권한 제외, 대상 handle pin·hardlink 거부·중복 guard 처리 보완

이 수정과 테스트는 전체 보안 보장을 뜻하지 않습니다. 특히 file expectedHash는 낙관적 충돌 검사이며 협조하지 않는 writer와의 원자적 CAS를 보장하지 않습니다.

## 실제로 가져온 것

`third_party/codex/SOURCE_MANIFEST.json`에 각 원본 경로, 고정 upstream commit, 원본 SHA-256 및 수정된 파일 SHA-256을 기록합니다. 토큰·ACL·Win32 helper·DPAPI·Firewall/WFP·no-reparse 코드와 해당 테스트를 분리했습니다. 독립 Cargo workspace가 crates.io 의존성만 사용하며 Codex workspace/app/CLI/model/login 크레이트를 의존하지 않습니다.

새 broker/admission/process/credential-store/IPC 조합은 제품용 실험 코드입니다. 원본 재사용과 새 코드의 경계를 문서화했고, 원본과 동일한 보안·호환성을 주장하지 않습니다.

## 남은 구현과 설계 문제

다음은 단순히 테스트만 안 한 항목이 아니라 추가 코드 또는 설계가 필요한 부분입니다.

- UI 승인과 결합한 공개 broker IPC 및 신뢰 정책/digest 검증 경로
- 이전 동일 계정 프로세스가 없는지 확인하는 startup isolation 및 재시작 복구
- helper 생성 후 DACL 강화 전의 기존 같은 계정 프로세스 handle 획득 위험
- durable ACL journal/부분 실패 복구, 안전한 repair/uninstall와 제품 설치·업데이트
- 실행 직전 실제 네트워크 보호 유효성 재검증과 일반화된 경로 정책
- online 승인 및 패키지 다운로드 경로
- 공개 실행 endpoint를 위 구성에 연결한 완결된 제품 흐름

계정 lease는 허가된 동시 요청을 직렬화하지만, 이전 orphan이 없음을 증명하지 않습니다. DACL을 나중에 강화해도 이미 얻은 handle을 취소할 수는 없습니다. 이 위험을 해결하고 검증하기 전에는 production 실행을 활성화하지 않습니다.

## 실행하지 않은 검사

- Windows SDK/linker로 만든 실행 바이너리의 실제 실행
- Windows 전용 unit test의 실행 및 보안 경계 통합 시험
- 실제 계정 생성/활성화/로그온, ACL 변경, Firewall/WFP 설정·정리
- 두 단계 helper 실행과 Job·후손 종료, crash/timeout/cancel의 실제 효과
- 실제 파일·네트워크·named pipe·reparse/hardlink 경계 검증
- Python/pip/npm의 sandbox 내 실행
- 실제 모델 요청에서 결과 파일까지 이어지는 Pi end-to-end
- Electron UI, 설치/업데이트/제거, macOS

public `run`과 JS native backend는 닫힌 상태를 유지합니다. 상태 상수만 true로 바꾸는 것은 미완료 통합이나 Windows 검증을 대체하지 않습니다. `docs/WINDOWS_VALIDATION.md`에 따라 별도 승인된 테스트 환경에서 다음 검증을 진행해야 합니다.
