# 검증 결과

검증일: 2026-10-04

## 실행한 검사

환경은 Linux x64, Node.js v24.19.0입니다. JavaScript 구문 검사와 실행 검증이며 TypeScript 컴파일 검증은 아닙니다.

| 검사 | 결과 | 보장 범위 |
| --- | --- | --- |
| `npm test` | 46 PASS, 0 FAIL, 1 선택 검사 SKIP | core 21, Codex reference 15, Pi adapter 10 테스트 |
| 실제 Pi 1.0.2 선택 검사 별도 실행 | 1 PASS | 실제 npm SDK 메모리 세션 초기화, 도구 등록, 폐기. 모델 호출 없음 |
| `npm run check` | JavaScript 10개 구문 검사 PASS | Node 구문 유효성 |
| `sh tests/supervisor-contract/run.sh` | PASS | 실제 portable C++ JSON parser/Windows 인수 quoting 계약. g++ 경고를 오류로 처리 |
| `npm run diagnose` | 정상 종료, nativeEnforcement false | 기본 실행이 OS 변경이나 자식 명령 실행을 하지 않음 |

실제 Pi 검사는 레지스트리의 `@earendil-works/pi-coding-agent@1.0.2`를 별도 개발용 경로에 설치하고 수행했습니다. API 키·모델 요청·호스트 도구 실행 없이 빈 인증 저장소와 명시적인 도구 집합으로 초기화했습니다. 해당 node_modules는 배포 ZIP에 포함하지 않았습니다.

## 수정 후 회귀 검증한 문제

- 요청 JSON이 실행 담당자의 runtime/activation 설정을 덮어쓰지 못하도록 분리했습니다.
- 정책을 정규화하고 hash를 검증한 뒤 보호 runtime 경로와 쓰기 경로를 비교합니다.
- 취소 뒤 close 이벤트가 오지 않는 transport에 bounded watchdog을 적용합니다. 종료를 확인하지 못하면 cleanup을 성공으로 표시하지 않습니다.
- prepare 중 close가 발생하거나 prepare가 늦게 끝나도 세션을 재활성화하지 않습니다. 미정리 상태는 BLOCKED를 유지합니다.
- 파일의 expectedHash 확인은 낙관적 충돌 검사이며, 협조하지 않는 외부 writer에 대한 원자적 CAS라는 표현을 제거했습니다.

## Python probe 추가 검증

`python3 -m unittest discover -s tests/python-probe -p 'test_*.py' -v`의 16개 테스트와 `python3 scripts/python-sandbox-probe.py --self-test`를 Linux Python 3.12.14에서 통과했습니다. 단위 테스트는 mock과 임시 시험 파일만 사용하며 실제 네트워크 probe는 하지 않았습니다. self-test 결과의 mode는 `logic-only`, nativeEnforcementAttested와 cleanupVerified는 false입니다. 이는 아래 Windows 실검증을 대체하지 않습니다.

## 실행하지 않은 검사

- Windows SDK/MSVC로 native supervisor 컴파일
- 실제 Windows 계정 생성, ACL/방화벽/WFP 설정 또는 삭제
- 실제 Codex Windows 전용 계정으로 실행한 후손의 outer Job 상속
- 취소, 정상 종료, 부모 crash 시 Windows 프로세스 트리 정리
- 실제 파일·네트워크·IPC 우회 차단
- 실제 sandbox 내 Python/pip/npm 및 문서 생성
- Electron UI 또는 Windows 설치 프로그램/업데이트/제거
- 실제 모델에 요청하는 Pi end-to-end 실행
- macOS 실행 및 배포

## 명확한 완료 범위

완료한 것은 독립 PoC의 정책·도구 연결 코드, 참조 실행 경로, 감독 실행기 소스와 비네이티브 테스트입니다. 현재 `CodexReferenceBackend`는 정식 broker에 `nativeEnforcement:true`를 광고하지 않으며, 실제 에이전트 실행은 기본 차단됩니다. 별도의 명시적 Windows 실험 경로는 연구 담당자가 별도 테스트 환경에서 검증하기 위한 것이며 정상 운영 경로가 아닙니다.

Windows 시험으로 보안 경계를 확인한 뒤 실제 검증 결과를 제공하는 backend 통합이 필요합니다. 준비되지 않은 상태에서 capability 상수를 true로 바꾸는 것은 검증이 아닙니다. 자체 제품용 계정과 설치기를 만들기 전에는 기존 Codex와 함께 배포하지 않습니다.

## 버전 기준

- Codex CLI: 0.160.0 / source `a956835d020762cb2b570053af06f643a11c0ecc`
- Pi coding-agent: 1.0.2 / 조사 source `200387122ca450d6387f033949423114a270b96c`
- Supervisor source protocol: 1 / version 0.1.0

공식 Codex Windows release 파일 hash는 참조 backend에 고정되어 있습니다. 이 코드와 문서의 최신 main 호환성을 주장하지 않습니다. 원본 출처와 상세 계약은 각 모듈 README를 참조하세요.
