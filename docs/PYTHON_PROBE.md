# Python 샌드박스 검증 준비

스크립트: `scripts/python-sandbox-probe.py`.
이 버전은 외부 Codex CLI를 사용하지 않습니다. 이전 버전의 Codex operator 설정이나 `--explicit-windows-experiment` 명령을 사용하지 마세요. 공개 native 실행 경로가 아직 차단되어 있어, Python을 샌드박스에서 실행한 결과는 없습니다.

## 지금 실행 가능한 검사

```sh
python3 -B scripts/python-sandbox-probe.py --self-test
python3 -B -m unittest discover -s tests/python-probe -p 'test_*.py' -v
```

이 검사는 로직, mock과 임시 시험 파일만 사용합니다. 실제 Windows 계정/ACL/방화벽을 바꾸거나 네트워크 시험을 하지 않습니다. `nativeEnforcementAttested`와 `cleanupVerified`는 false입니다.

## 실제 실행의 전제

신뢰되는 Windows 시험 담당자가 자체 Rust 실행기의 계정·권한·네트워크 준비와 라이브러리 통합을 먼저 검증해야 합니다. 관리자 보안 설정 변경은 명시적으로 승인받아야 합니다. 이 스크립트를 실행하려고 native 게이트를 임의로 true로 바꾸거나 호스트 Python으로 대체해서는 안 됩니다.

시험용 Python 바이너리·표준 라이브러리·스크립트를 신뢰되는 읽기 전용 위치에 두고 절대 경로와 파일 hash를 기록합니다. 작업 폴더와 아래 canary 폴더는 업무 데이터가 없는 별도 임시 위치로 준비합니다.

- 허용 workspace: 고유 시험 파일을 생성하고 읽어볼 곳
- denied-write canary: workspace 및 모든 쓰기 허용 경로 바깥의 전용 시험 폴더
- 두 경로는 겹치지 않고, 미리 존재하며, 정상 writable volume 위에 있어야 합니다.
- 신뢰되는 호스트에서 각 경로에 고유 baseline 파일을 생성/읽기/삭제할 수 있음을 별도로 확인합니다.
- 실제 사용자 문서·시스템 폴더를 거부 대상 fixture로 사용하지 않습니다.
- symlink/junction/reparse point/하드링크 marker를 사용하지 않습니다. 시험 중 경로를 바꾸지 않습니다.

담당자가 소문자 UUID `TOKEN`을 생성하고 denied fixture 안에 `pi-python-canary-TOKEN.marker`를 새로 만듭니다. 내용은 ASCII `pi-python-sandbox-canary-v1\nTOKEN\n`이며 줄바꿈은 LF입니다. 이미 있는 파일은 덮어쓰지 않습니다. marker는 읽을 수 있게 유지하면서 fixture의 쓰기를 차단해야 합니다.

실제 native 통합이 검증된 후 전달할 Python 인수 형태는 다음과 같습니다. 이것은 실행 예시 계약이며 자동 실행 스크립트가 아닙니다.

```text
<검증된 python.exe> <보호된 python-sandbox-probe.py>
  --workspace <허용된 시험 폴더>
  --denied-write-canary-dir <별도 거부 시험 폴더>
  --canary-token <TOKEN>
  --operator-approved-test-targets
  --cleanup-allowed
```

TCP 검사는 담당자가 통제하는 숫자 IP/포트를 `--network-host`, `--network-port`로 명시한 경우에만 수행합니다. 공급한 대상이 호스트에서는 실제로 연결되는지 직전 baseline을 확인해야 합니다. 기본값은 네트워크 SKIP입니다. 임의 인터넷 대상이나 개인정보를 전송하지 않으며 application payload를 보내지 않습니다.

## 판정

- 허용 쓰기 PASS: 고유 파일을 독점 생성하고 내용을 읽어 확인
- 거부 쓰기 PASS: dedicated marker 확인 후 쓰기 시 명시적인 permission denial 관측
- TCP PASS: 공급한 대상에서 명시적 permission denial 관측
- timeout, connection refused, unreachable, 없는 경로 또는 확인 불가: INCONCLUSIVE
- 금지 쓰기나 TCP 연결 성공: FAIL
- 자식 프로세스 정리: 이 스크립트는 자식을 만들지 않으며 항상 SKIP. 외부 신뢰 관찰자가 별도로 확인

전체 status의 PASS는 수행한 좁은 관측만 통과했다는 뜻입니다. 네트워크와 lifetime이 SKIP이면 검증하지 않은 것입니다. 기존 OS ACL/방화벽도 permission denial을 만들 수 있으므로 원인 판별에는 별도의 baseline/상태 증거가 필요합니다. 읽기 기밀성이나 전체 보안 경계를 인증하는 테스트가 아닙니다.

허용 파일은 `--cleanup-allowed`일 때 해당 실행에서 만든 파일만 삭제합니다. 거부 쓰기가 예상과 달리 성공하면 빈 고유 파일을 남기고 FAIL을 반환하므로 담당자가 확인 후 정리합니다. 결과·로그에는 실제 비밀번호, API 키와 사용자 파일 내용을 넣지 않습니다.
