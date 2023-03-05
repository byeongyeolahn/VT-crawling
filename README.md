## VirusTotal-crawling

### 코드 기능

`전체 기능`

수집한 악성 샘플에 대해서 재검토하기 위한 크롤링 코드

`main.py`

크롤러 동작 수행 및 Json(결과) 파일 변환

`file_list.py`

파일 중복 검사 및 md5 해시 변환

### 사용법

1. `main.py` 실행
2. 터미널 창에 크롬 드라이브 경로 입력
3. Input Redirection Detail Web Site 에는 **detection** 입력
4. 10~30개 사이 캡차 수동으로 진행해줘야 정상적으로 동작
    
    (500번 이상의 Request 요청 시 일정 시간동안 정지)
    

**동일한 경로 내 sample 디렉토리 생성 후 검토를 원하는 샘플 모두 sample 디렉토리로 이동시킨 후 동작시키기**
