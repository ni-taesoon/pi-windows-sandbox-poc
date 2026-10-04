# Pi Windows Sandbox PoC

Electron 제품의 Pi 도구를 Windows 네이티브 샌드박스에 연결하기 위한 독립 연구용 코드입니다. 실제 보안 경계는 Codex의 Windows 구현을 참고하며, 이 저장소는 정책 계층, Pi 도구 어댑터, 고정된 Codex CLI 참조 백엔드, Windows 감독 실행기 소스를 분리합니다.

## 현재 상태

**상용 실행기 또는 Windows 보안 검증 완료 제품이 아닙니다.** Linux 개발 환경에서 JavaScript 테스트와 실제 Pi SDK의 비네트워크 초기화 검증을 수행합니다. Windows helper의 컴파일, 실제 ACL/방화벽 차단, 사용자 전환 후 Job 상속, 취소·종료 및 설치/제거는 별도 Windows 환경에서 확인해야 합니다. 최종 검증 기록은 [VALIDATION.md](VALIDATION.md)를 보세요.

검증되지 않은 백엔드는 broker가 거부합니다. 실패 시 일반 호스트 실행으로 되돌아가는 경로는 제공하지 않습니다. 테스트용 가짜 backend가 통과했다고 OS 격리가 입증된 것은 아닙니다.

## 왜 별도 감독 실행기가 필요한가

조사한 Codex 0.160.0의 command runner는 정상 명령 종료 시 후손 프로세스를 보존하는 경로가 있습니다. 따라서 Codex CLI 종료 코드만으로 프로세스 트리가 전부 정리됐다고 판단할 수 없습니다. Windows 감독 실행기 소스는 외부 Job Object로 프로세스 수명 주기를 제한하는 방식을 검증하기 위한 것입니다. 실제 Codex 전용 계정으로 시작한 runner와 후손이 이 Job에 남는지 Windows에서 확인해야 합니다.

## 구성

| 위치 | 역할 |
| --- | --- |
| `packages/core` | 불변 정책, 요청 검증, 중복 실행 방지, 제한된 결과, 취소와 정리 상태 |
| `packages/pi-adapter` | Pi의 파일·실행 도구 교체, SDK 버전 제한, 확장 자동 로딩 억제 |
| `packages/codex-backend` | 고정 Codex 버전의 명시적 sandbox 상태와 파일 worker를 연결하는 참조 구현 |
| `native/supervisor` | Windows Job 기반 비관리자 감독 실행기 소스와 빌드 안내 |
| `tests` | 정책·어댑터·참조 계약 테스트. OS 보안 시험과 구분 |
| `docs/WINDOWS_VALIDATION.md` | 실제 Windows 검증 순서와 중단 조건 |

현재 PoC에는 Electron UI, 제품 전용 계정 프로비저너, 서명 설치 프로그램, 자동 업데이트, macOS 실행기가 포함되지 않습니다. 향후 제품 통합 시 이 구성요소를 추가해야 합니다.

## 바로 실행할 수 있는 테스트

Node.js 22.19.0 이상을 사용합니다. 기본 테스트에는 npm 의존성 설치나 API 키가 필요하지 않습니다.

```sh
npm test
npm run check
```

기본 테스트에서는 실제 명령을 샌드박스 밖에서 실행하는 mock을 제공하지 않습니다. 테스트 폴더의 fake는 요청과 응답을 검증하는 데만 사용합니다. 실제 Pi SDK 초기화 검증은 선택 사항이며 [어댑터 안내](packages/pi-adapter/README.md)를 따릅니다. 모델 호출이나 API 키는 필요하지 않습니다.

## Windows에서 시작하기 전에

Python의 허용 폴더 쓰기와 전용 canary 폴더 쓰기 거부를 확인할 스크립트는 `scripts/python-sandbox-probe.py`입니다. 준비·실행 계약과 판정 한계는 [Python 검증 안내](docs/PYTHON_PROBE.md)를 따르세요. 현재 실행한 것은 Linux의 로직 테스트뿐이며, Windows 샌드박스에서 이 스크립트를 실행한 결과는 아직 없습니다.

1. **기존 Codex 및 실제 업무 데이터가 없는 별도의 Windows 테스트 환경**을 준비합니다.
2. supervisor와 참조 backend의 개별 README를 읽고 고정 버전과 바이너리 식별을 확인합니다.
3. 로컬 계정 생성, ACL 변경, 방화벽/WFP 설정 및 가능한 UAC 요청을 실행 담당자가 명시적으로 승인합니다. 이 저장소 작성 과정에서 그러한 변경을 수행하지 않았습니다.
4. 실제 Python/셸 실행 전에 무결성, 권한, Job 상속, 네트워크 차단 및 프로세스 정리 시험을 완료합니다.
5. 격리 실패, 부모 종료 뒤 잔여 프로세스, 정책 해석 불일치가 발견되면 실행을 중단합니다. 플래그를 바꿔 안전성 검사를 우회하지 않습니다.

별도의 `CODEX_HOME`만 지정해도 Codex의 전역 전용 계정 이름이 분리되는 것은 아닙니다. 최초 실행뿐 아니라 복구/권한 갱신에도 시스템 상태 변경이 일어날 수 있습니다. 기존 설치와 병행하는 운영 도구로 배포하지 마세요.

## 보안 범위

- 기본 읽기 모델은 OS 계정 권한 내 넓은 읽기와 명시적 deny의 조합입니다. 선택한 파일만 보이는 모델이 아닙니다.
- JavaScript의 경로 검사는 입력 계약 검사입니다. junction, hardlink, 재분석 지점과 TOCTOU에 대한 OS 차단을 대신하지 않습니다.
- 모든 Pi 파일·실행 도구는 broker를 통과해야 합니다. 사용자 확장이나 다른 도구가 신뢰 호스트의 `fs` 또는 `child_process`를 직접 쓰면 이 보장 밖입니다.
- 파일을 읽을 수 있으면 도구 결과가 모델 입력으로 전송될 수 있습니다. offline 실행만으로 이 전송 경로가 사라지지 않습니다.
- API 키, 제품 정책과 설치 자격증명을 child 인수·환경·작업 디렉터리에 넣지 않습니다.
- 패키지 설치 스크립트도 비신뢰 코드입니다. 호스트 `pip`/`npm`으로 자동 재시도하지 않습니다.
- Windows 커널이나 관리자, 신뢰 호스트 프로세스 장악을 방어하는 VM 경계로 설명하지 않습니다.

## 다음 구현 단계

Windows 시험 결과를 먼저 확보한 뒤, 필요한 Codex 구성요소를 고정 소스에서 분리하고 제품 전용 계정·보안 객체·설치/업데이트/제거 경로로 교체합니다. 현재 참조 CLI의 전역 계정과 복구 동작을 제품의 최종 설치 계약으로 삼지 않습니다. 보안 보장이 확인되지 않은 상태에서 Electron UI를 붙여 기능을 공개하지 않습니다.

이전에 전달한 Windows 네이티브 샌드박스 SDD의 출시 요구사항은 이 PoC가 모두 구현한 기능 목록이 아닙니다. 구현된 범위와 검증되지 않은 범위를 분리해 검토하세요.

## 참고

- [OpenAI Windows sandbox 설계](https://openai.com/index/building-codex-windows-sandbox/)
- [Codex 0.160.0 고정 소스](https://github.com/openai/codex/tree/a956835d020762cb2b570053af06f643a11c0ecc)
- [Pi SDK](https://github.com/earendil-works/pi/tree/200387122ca450d6387f033949423114a270b96c)
- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)

외부 Codex/Pi 및 런타임 바이너리는 이 소스 패키지에 포함하지 않습니다. 각 공급자의 라이선스, 보안 업데이트와 배포 의무는 별도로 검토해야 합니다.
