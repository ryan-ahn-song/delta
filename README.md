# DELTA 전체 소스코드 패키지

이 압축 파일은 DELTA 프로젝트의 제출·인수인계용 소스 패키지입니다.

## 포함 구성

- `delta-security-ide/`: VS Code형 브라우저 코드 편집기와 정적 보안 분석 UI
- `stack-delta-ai/`: 문서 기반 기대 행위, 정책 점수, 재생 로그, Docker 격리 계측을 포함한 분석 백엔드
- `delta-logo/`: 편집 가능한 SVG 로고와 PNG 앱 아이콘

의존성 폴더, 가상환경, Git 이력, 빌드 산출물, 실행 중 생성되는 SQLite DB와 분석 보고서는 제외했습니다.

## 1. 웹 IDE 실행

요구 사항: Node.js 22.13 이상

```bash
cd delta-security-ide
npm install
npm run dev
```

검증:

```bash
npm run lint
npm test
```

## 2. 분석 백엔드 실행

요구 사항: Python 3.11 이상

```bash
cd stack-delta-ai
sh scripts/setup.sh
.venv/bin/stack-delta demo --scenario suspicious
.venv/bin/stack-delta serve
```

브라우저에서 `http://127.0.0.1:8765`를 엽니다.

검증:

```bash
make test
```

Docker 격리 계측은 Docker가 설치된 별도 Linux 실험 VM에서만 실행하십시오. 임의의 실제 악성 패키지를 개인 PC에서 실행하지 마십시오.

## 현재 통합 상태

`delta-security-ide`는 브라우저 안에서 소스 텍스트를 정적 분석하며, `stack-delta-ai`는 재생 로그와 격리 실행을 다루는 별도 백엔드입니다. 두 구성요소 사이의 실시간 API 연결은 아직 구현되지 않았습니다.

## 패키징 전 검증 결과

- 웹 IDE ESLint 통과
- 웹 IDE 프로덕션 빌드 통과
- 웹 IDE 렌더 테스트 1개 통과
- 분석 백엔드 단위·통합 테스트 14개 통과

최종 검증일: 2026-08-11
