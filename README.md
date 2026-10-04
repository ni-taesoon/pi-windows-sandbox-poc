# Pi Windows Sandbox 소스 분리 PoC

Pi는 에이전트 엔진으로 유지하고, Codex의 **샌드박스 관련 소스만** 분리해 자체 Windows 실행 계층을 만드는 실험용 저장소입니다.

**Codex 앱·CLI·모델 호출·로그인·세션 관리 코드를 실행 의존성으로 포함하지 않습니다.** `codex.exe` 설치, Codex 로그인, 기존 Codex 전용 계정은 필요하지 않습니다. 원본 소스의 출처와 라이선스는 보존합니다.

## 현재 범위

이 버전은 별도 Cargo workspace의 Rust 샌드박스 코드와 Node.js/Pi 어댑터입니다. 실제 토큰·ACL·계정·네트워크·프로세스 API를 가진 소스이며, 외부 Codex CLI를 호출하는 이전 버전과 다릅니다.

그러나 **실제 Windows 격리 검증을 통과한 완성 실행 제품은 아닙니다.** 공개 실행 경로와 JS backend의 `nativeValidated` 게이트는 false입니다. 검증되지 않은 계정/권한/네트워크 설정에서 에이전트를 실행하지 않습니다. 저수준 라이브러리 API는 신뢰되는 호출자와 문서화한 사전 조건을 요구합니다. 상세 구현 범위와 미완료 통합은 [native README](native/windows-sandbox/README.md), 검사 결과는 [VALIDATION.md](VALIDATION.md)를 참조하세요.

## 구조

| 경로 | 역할 |
| --- | --- |
| `packages/core` | 불변 정책, 세션 상태, 요청 검증, 중복 방지, 출력/시간 제한과 취소 |
| `packages/pi-adapter` | Pi 파일·PowerShell 도구를 broker 요청으로 변환; 호스트 실행 우회 금지 |
| `packages/native-backend` | 자체 `pi-windows-sandbox` 요청/응답 계약; 실행 게이트 유지 |
| `native/windows-sandbox` | 독립 Rust crate와 Win32 샌드박스 라이브러리 |
| `third_party/codex` | 원본 라이선스, NOTICE, 고정 출처와 변경 기록 |
| `scripts/python-sandbox-probe.py` | 승인된 전용 시험 대상에 대한 Python 관측 스크립트 |
| `tests` | JS 계약·도구·파일 회귀시험과 Python 로직 시험 |

native 내부의 역할은 다음과 같습니다.

- `token`, `token_user`, `winutil`: 제한 토큰과 SID 처리
- `acl`: Windows 파일 접근 권한 연산
- `desktop`, `process`: 전용 데스크톱, 프로세스/Job, 출력과 종료 관리
- `network`: 전용 계정 대상 Firewall/WFP 코드
- `setup`: 제품 소유 계정과 자격 증명 관련 준비 API
- `admission`: 신뢰된 호출자의 정책과 제한된 실행을 연결하는 실험용 계층

현재 native 요청은 offline 정책만 받습니다. 온라인 패키지 다운로드·설치 승인 경로는 아직 구현하지 않았습니다. 기존 코드의 online 모드를 이 버전에서 지원한다고 가정하지 마세요.

Windows 계정·ACL·방화벽 변경은 관리자 승인 및 별도 실제 환경 검증이 필요한 작업입니다. 저장소의 기본 테스트/진단 명령은 이를 수행하지 않습니다. 앱의 승인 IPC, 설치/업데이트/제거, 복구 UX와 Electron 화면은 완성되지 않았습니다.

## 검사 방법

Node.js 22.19.0 이상에서 기본 JS 검사를 실행합니다. 기본 검사는 API 키나 모델 호출을 요구하지 않습니다.

```sh
npm test
npm run check
npm run diagnose
```

실제 Pi SDK의 메모리 세션 초기화 시험은 [어댑터 README](packages/pi-adapter/README.md)를 따릅니다. Rust 검사는 다음과 같습니다.

```sh
cd native/windows-sandbox
cargo test --locked
cargo check --locked --target x86_64-pc-windows-gnu --all-targets
```

Windows 대상 검사를 위해 해당 Rust standard-library target 설치가 필요합니다. `cargo check`는 타입/컴파일 검사이며 Windows에서 실행하거나 링크된 Windows EXE를 만든 결과가 아닙니다. 실제 Windows 바이너리 빌드에는 Windows SDK 및 해당 linker를 포함한 빌드 환경이 필요합니다.

Python 로직 검사는 다음과 같습니다.

```sh
python3 -B scripts/python-sandbox-probe.py --self-test
python3 -B -m unittest discover -s tests/python-probe -p 'test_*.py' -v
```

## 보안 조건

1. Pi의 모든 파일·명령 도구는 같은 정책 경로를 통과합니다. 비신뢰 확장과 호스트 `fs`/`child_process` fallback을 열지 않습니다.
2. 제한 토큰·ACL·네트워크 코드가 있다는 이유로 안전성을 보장하지 않습니다. 실제 계정 전환, 파일/네트워크 거부, Job 후손 정리, 재분석 지점과 IPC 검증이 필요합니다.
3. 읽기 모델은 OS 계정 권한 내 넓은 읽기와 명시적 deny입니다. 선택한 파일만 볼 수 있는 기밀성 경계가 아닙니다.
4. 에이전트가 읽은 결과는 호스트의 Pi를 통해 모델에 전달될 수 있습니다. child의 offline 네트워크만으로 정보 전달이 전부 차단되지는 않습니다.
5. 소스에 존재하는 저수준 관리자 준비 함수를 사용자 승인 없이 실행하지 않습니다. 임의 JSON의 정책 hash나 PID가 승인 또는 인증 증거는 아닙니다.
6. 불완전한 준비/취소/정리 결과는 BLOCKED로 처리합니다. 원래 사용자 권한의 일반 실행으로 자동 전환하지 않습니다.
7. 테스트용 fake backend 통과, 성공한 빌드, 상태 JSON의 숫자만으로 실제 OS 격리를 인증하지 않습니다.

## 이전 버전과의 차이

이전 `packages/codex-backend`, 공식 Codex 실행 파일 hash/호출 경로, C++ 외부 감독 실행기는 제거했습니다. 대신 자체 Rust 소스와 직접 실행 계약을 둡니다. 원본 Codex commit은 **소스 출처**이며 런타임 의존성이 아닙니다. 이전 설치/진단 명령을 이 버전에 적용하지 마세요.

원본 pin: `a956835d020762cb2b570053af06f643a11c0ecc`.
라이선스와 정확한 원본/변경 파일 관계는 [PROVENANCE.md](third_party/codex/PROVENANCE.md)를 참조하세요. 원본의 동작을 그대로 보장한다고 주장하지 않으며, 변경된 제한 정책은 별도 Windows 회귀 검증 대상입니다.

## 다음 단계

[Windows 검증 계획](docs/WINDOWS_VALIDATION.md)에 따라 별도 테스트 환경에서 빌드·통합·격리 검사를 수행합니다. [Python probe](docs/PYTHON_PROBE.md)는 그 검사의 일부를 돕는 도구이며 전체 보안 검사를 대체하지 않습니다. 미완료 통합과 승인 경로를 구현하고 검증한 다음에만 정식 실행 게이트를 열 수 있습니다.
