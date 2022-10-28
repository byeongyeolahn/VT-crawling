from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import time 

def main_crawling():
    options = Options()
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
    options.add_argument('user-agent=' + user_agent)
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    options.add_experimental_option('prefs', {
        # "download.default_directory": "다운로드 받고자 하는 폴더 경로",
        "download.prompt_for_download": False,
        "download.directory_upgrade": True,
        "safebrowsing.enabled": True})
    driver = webdriver.Chrome(options=options)

    #URL 연결 
    url_link = 'https://www.virustotal.com/gui/home/upload'
    driver.get(url_link)
    time.sleep(3)

    #검색 창 열기
    driver.find_element(By.XPATH, '//*[@id="view-container"]/home-view//div/div/div/div[1]/div[1]/ul/li[3]/a').click()

    #파일 정보 얻길 원하는 해시값 입력 
    query = '해시값'
    search_tab = driver.find_element(By.CSS_SELECTOR, '#searchInput')
    search_tab.send_keys(query)
    search_tab.send_keys(Keys.ENTER)



if __name__ == '__main__':
    main_crawling()
