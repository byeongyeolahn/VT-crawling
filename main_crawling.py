from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from pyshadow.main import Shadow
import time
import os

#파일 리스트 인자로 받아서 URL 연결

def get_driver():
    options = webdriver.ChromeOptions()
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    driver = webdriver.Chrome(options=options)
    #명시적 대기
    driver.implicitly_wait(3)
    return driver

def main(file, option):
    driver=get_driver()
    if option == 'default':#URL 연결 
        for  i in range(len(file)):
            url_link = 'VT 링크'.format(file[i][:-4])
            driver.get(url_link)
            shadow = Shadow(driver)
            # 명시적 대기
            shadow.set_explicit_wait(5)
            First_submission_Time = shadow.find_element("div > div > div:nth-child(1) > div > a:nth-child(2)")
            print("First Submission Time : " + str(First_submission_Time))
    else:
        for  i in range(len(file)):
            #옵션에 따른 창 접근 
            link_info = 'VT 링크'.format(file[i][:-4])
            url_link = link_info + str(option)
            driver.get(url_link)
            print("============================================")
            print("###" + str(url_link) + "접속...###")
            shadow = Shadow(driver)
            # 명시적 대기
            shadow.set_explicit_wait(20, 5)
            shadow.find_element_by_xpath('//*[@id="report"]//div/div[2]/div/ul/li[3]/a').click()
            First_submission_Time = shadow.find_element("vt-ui-key-val-table")
            print("First Submission Time : " + str(First_submission_Time.text))

def file_list(file_path):
    print("============================================")
    print("###파일 목록 수집 중...###")
    fl = os.listdir(file_path)
    print("###파일 목록 수집 완료!###")
    return fl

if __name__ == '__main__':
    apk_file_path = "APK 파일 존재 경로"
    fl = file_list(apk_file_path)
    main(fl, 'details')
