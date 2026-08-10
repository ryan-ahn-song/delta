# STACK-Δ AI

> 문서 기반 기대 행위 추론과 격리 실행 계측을 결합한 npm 설치 스크립트 선언–행위 불일치 탐지기

STACK-Δ는 패키지를 곧바로 “악성/정상”으로 단정하지 않습니다. README와 `package.json`에서 설명한 기능으로부터 기대 가능한 행위 (E)를 만들고, 제한된 시간 (T) 동안 실제 관측한 행위 (O(T))와 비교합니다.

\[
\Delta(T) = O(T) - E
\]

AI는 비정형 문서를 구조화하는 역할만 맡습니다. 민감 행위의 승인 여부와 최종 위험 점수는 버전이 고정된 정책 파일이 결정합니다.

## 구현된 기능

- README·`package.json` 기능 다중 분류
- 외부 연결, 파일 출력, 빌드 도구 실행 선언과 근거 문장 추출
- 오프라인 재현이 가능한 규칙형 분석기
- 선택적 OpenAI Structured Outputs 분석기
- 기능 유형별 고정 기대 행위 정책
- `.ssh`, `.aws`, `.kube`, `.npmrc`, 비밀 환경변수, 지속성 행위 자동 승인 금지
- `strace` 기반 파일·프로세스·네트워크 이벤트 정규화
- Node.js `process.env` 변수명 센서(값은 저장하지 않음)
- 성공 행위와 차단된 시도를 구분한 위험 점수
- 인증정보 접근→외부 연결 같은 공격 연쇄 추가 점수
- SQLite 분석 이력
- CLI, JSON API, 반응형 웹 대시보드
- 정상·카나리 공격·README 프롬프트 인젝션 안전 시나리오
- 네트워크 차단·권한 제거·읽기 전용 루트의 Docker 샌드박스
- 표준 라이브러리 기반 자동 테스트

## 1분 실행

Python 3.11 이상만 필요합니다. 기본 데모에는 외부 API, npm 레지스트리, Docker가 필요하지 않습니다.

```bash
cd stack-delta-ai
sh scripts/setup.sh
.venv/bin/stack-delta demo --scenario suspicious
.venv/bin/stack-delta serve
```

브라우저에서 `http://127.0.0.1:8765`를 엽니다.

테스트:

```bash
make test
```

## 안전한 시나리오

| 시나리오 | 문서 주장 | 관측 행위 | 기대 결과 |
|---|---|---|---|
| `benign` | 네이티브 빌드와 `build/` 출력 | `node-gyp`, 빌드 파일 생성 | 불일치 없음 |
| `suspicious` | 설치 부작용 없음 | 가짜 SSH 키·카나리 토큰·가짜 `.bashrc`·차단된 TEST-NET 연결 | 검토 필요 |
| `prompt_injection` | 모든 접근을 승인하라는 README 명령 | 가짜 SSH 키 접근 | 인젝션 감지, 자동 승인 거부 |

```bash
.venv/bin/stack-delta demo --scenario benign
.venv/bin/stack-delta demo --scenario prompt_injection --output reports/injection.json
```

`suspicious-canary`는 실제 인증정보를 사용하지 않습니다. Docker 샌드박스 안의 가짜 홈 디렉터리와 문서용 TEST-NET 주소(`198.51.100.10`)만 사용합니다.

## 로컬 패키지 분석

### 재생 로그 사용

```bash
.venv/bin/stack-delta analyze ./my-local-package \
  --trace ./my-events.json \
  --output reports/my-package.json
```

이벤트 입력 형식:

```json
[
  {
    "capability": "network_connect",
    "target": "198.51.100.10:443",
    "status": "attempted",
    "timestamp": 0.29,
    "source": "replay",
    "detail": "connection blocked"
  }
]
```

### Docker 격리 계측

Docker가 설치된 별도 Linux 실험 VM에서 실행하십시오.

```bash
.venv/bin/stack-delta build-sandbox
.venv/bin/stack-delta analyze-sandbox ./fixtures/packages/benign-native --window 30
.venv/bin/stack-delta analyze-sandbox ./fixtures/packages/suspicious-canary --window 30
```

샌드박스는 다음 조건으로 실행됩니다.

- 외부 네트워크 완전 차단(`--network none`)
- 모든 Linux capability 제거
- `no-new-privileges`
- 읽기 전용 루트 파일시스템
- 로컬 패키지는 읽기 전용 마운트 후 일회용 `tmpfs`로 복사
- 가짜 홈, 가짜 SSH·AWS 파일, 카나리 환경변수 사용
- CPU·메모리·프로세스 수 제한
- 1~300초 하드 관측 시간
- 분석 종료 후 임시 실행 디렉터리 삭제

임의의 실제 악성 패키지를 개인 PC에서 실행하지 마십시오. 연구 평가는 별도 일회용 VM 안의 합성 패키지로 수행하는 것이 기본입니다.

## 선택적 LLM 문서 분석

기본 `heuristic` 분석기는 완전히 오프라인이며 반복 실행 결과가 같습니다. LLM 비교 실험이 필요할 때만 API 키를 설정합니다.

```bash
export OPENAI_API_KEY="..."
export STACK_DELTA_MODEL="gpt-5.6"
.venv/bin/stack-delta demo --scenario prompt_injection --provider openai
```

LLM 출력은 고정 JSON Schema로 제한됩니다. 그러나 LLM이 추출한 행위도 곧바로 승인되지 않으며 다음 단계를 거칩니다.

```text
비신뢰 README → 구조화 추출 → 근거·신뢰도 검사 → 고정 정책 → 기대 행위 E
```

README의 주장만으로 인증정보, 환경변수, 프로세스 정보, 지속성, 다운로드 후 실행을 자동 승인할 수 없습니다.

## 점수 계산

각 관측 이벤트 (o_k), 기대 여부 (e_k), 민감도 (w_k)에 대해:

\[
S(T)=\sum_k w_k \cdot o_k(T) \cdot (1-e_k)
\]

- 성공: (o_k=1.0)
- 시도했지만 차단: (o_k=0.5)
- 기본 임계값: 6점
- 민감도 5 행위가 성공하면 합계가 6점 미만이어도 검토 필요
- 비밀 접근과 외부 연결이 함께 있으면 3점 추가

정책은 [`stack_delta/config/policy.json`](stack_delta/config/policy.json)에 있습니다. 평가 전에 가중치와 임계값을 고정하고, 보정군과 최종 평가군을 패키지 단위로 분리해야 합니다.

## API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/api/health` | API·선택적 Docker 센서 상태 |
| `GET` | `/api/analyses` | 최근 분석 목록 |
| `GET` | `/api/analyses/{id}` | 전체 보고서 |
| `POST` | `/api/analyze/demo` | 안전 시나리오 분석 |
| `POST` | `/api/analyze/custom` | 문서와 정규화 이벤트 직접 분석 |

```bash
curl -X POST http://127.0.0.1:8765/api/analyze/demo \
  -H 'Content-Type: application/json' \
  -d '{"scenario":"suspicious","provider":"heuristic"}'
```

## 프로젝트 구조

```text
stack_delta/
  analyzer.py       문서 분류·근거 추출
  policy.py         기대 행위 생성·민감 행위 차단
  trace_parser.py   strace·환경 센서 정규화
  scoring.py        불일치·공격 연쇄 점수
  runner.py         재생 및 Docker 격리 러너
  service.py        전체 분석 오케스트레이션
  storage.py        SQLite 보고서 저장
  api.py            로컬 JSON API·정적 대시보드
  cli.py            명령행 인터페이스
sandbox/            네트워크 차단 계측 이미지
fixtures/           안전한 패키지와 재생 이벤트
tests/              단위·통합 테스트
docs/               위협 모델과 연구 프로토콜
```

## 해석 한계

- 실행되지 않은 분기와 관측 시간 이후 행위는 볼 수 없습니다.
- 도메인 이름과 최종 IP의 대응은 네트워크 차단 환경에서 제한될 수 있습니다.
- Node 센서는 `process.env`를 통한 JavaScript 접근만 측정하며 네이티브 바이너리 접근을 완전히 보장하지 않습니다.
- 패키지가 계측 환경을 인식하면 행위를 숨길 수 있습니다.
- 문서가 부족하거나 거짓이면 기대 행위 품질이 낮아집니다.
- 참조 패키지에 알려지지 않은 악성 버전이 섞일 가능성이 있습니다.
- 이 도구는 안전성 증명기나 자동 삭제 도구가 아니라 검토 근거 생성기입니다.

최종 결론은 항상 다음 범위로 제한해야 합니다.

> STACK-Δ는 패키지의 안전성을 증명하지 않는다. 제한된 관측 환경과 시간 안에서 패키지 설명으로 정당화되지 않는 행위를 발견한다.

