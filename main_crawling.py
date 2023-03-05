from selenium import webdriver
from pyshadow.main import Shadow
import time
import os
import string_list
import shutil
import json
import dataframe
import argparse
import file_list
import hashlib

CHROMEDRIVER_PATH =input("[+] Input ChromeDriver Path : ")

#CSV 파일에 넣을 Value List 생성
detection_value = []
family = []
error_hash = []

#시작 시 알림 함수
def start():
    print("================================================================================")
    print("[+] VT Crawling Start ! ")     
    start = time.time()
    if os.path.isdir('json_dic'):
        print('[+] json_dic 디렉토리 존재')
    else:
        os.mkdir('json_dic')
    return start

def file_hash(file):
    f = open(f'sample\\{file}', 'rb')
    data = f.read()
    hash = hashlib.md5(data).hexdigest()
    return hash
    
def get_driver():
    options = webdriver.ChromeOptions()
    # options.add_experimental_option('debuggerAddress', '127.0.0.1:9222')
    driver = webdriver.Chrome(CHROMEDRIVER_PATH, options=options)
    #명시적 대기
    driver.implicitly_wait(3)
    return driver

#실제 값 들고오는 크롤러
def main_crawling(file, option):
    driver=get_driver()
    # 옵션에 따른 URL 접근
    file_num = len(file)
    for i in range(len(file)):
        try:
            link_info = 'https://www.virustotal.com/gui/file/{}/'.format(file[i][:-4])
            if option == 'details':
                link_info = link_info + str(option) 
            driver.get(link_info)
            time.sleep(1)
            
            #에러 발생 예외 처리
            if "item-not-found" in driver.current_url:
                continue
            if "captcha" in driver.current_url:
                driver.back()
                time.sleep(1)
            if "too-many-requests" in driver.current_url:
                time.sleep(1)
                driver.get(link_info)
            print("================================================================================")
            print("[+] " + str(link_info) + " 접속")    
            shadow = Shadow(driver)
            shadow.set_explicit_wait(20, 5)
        except:
            print("[+] " + str(file[i])  + " 링크 접속 중 에러 발생")
            error_hash.append(file[i])
    
    # detail 창일 경우
        if option == 'details':
            File_detail = shadow.find_element('vt-ui-file-details')
            
            File_detail_list = (File_detail.text).split('\n')
        elif option == 'detection':
            try:
                detection_element = shadow.find_element('vt-ui-expandable')
                detection_list = (detection_element.text).split('\n')
            except:
                print("[+] " + str(file[i])  + " Element, 데이터 크롤링 중 에러 발생")
                error_hash.append(file[i])
                continue
            md5_hash = file_hash(file[i])
            crawling_parse(md5_hash, detection_list, 'detection')
            time.sleep(1)

        
        else:
            print('Option Value Error')
        print("[+] 진행도 : " + str(i+1) + "/" + str(file_num))

def crawling_parse(file_name, data, option):
    if option == "detection":
        vendor_list = []
        vendor_value = []
        for vl in range(int(len(data)/2+1)):
            try:
                if vl == 0:
                    continue
                else:
                    vendor_list.append(data[2*vl])
                    vendor_value.append(data[(2*vl-1)])
            except:
                print("[+] 진단명, 회사 파싱 중 오류 발생" )
        vendor_value.remove("Do you want to automate checks?")
        return Determining_Malware(file_name, vendor_list, vendor_value)
        

    elif option == "details":
        title_string = string_list.detail_string()
        target_string = []
        for t in range(len(title_string)):
            first = data.index(title_string[t])
            next = data.index(title_string[t+1])


def Determining_Malware(file_name, company, detection_name):
    # 스코어
    type_error = detection_name.count('Unable to process file type')
    undetected = detection_name.count('Undetected')
    total = len(detection_name) - type_error
    detected = total - undetected

    #분류 결과(Top 15로 변경 예정)
    print("[+] " + str(file_name) + "의 Score : " + str(detected) + "/" + str(total))

    # 라벨링 작업 진행
    if detected <= 1:
        print("[+] " + str(file_name) + "정상으로 분류")
        detection_value.append('0')

    else:
        print("[+] " + str(file_name) + "악성으로 분류")
        detection_value.append('1')
    # Json 생성
    list_to_dictionary(file_name, company, detection_name)
    

def list_to_dictionary(file_name, company, detection_name):
    vendor_list = company
    dictionary = {vendor_list[d] : detection_name[d] for d in range(len(detection_name))}

    slice_filename = file_name[:-4]
    json_name = "./json_dic/" + str(file_name) + ".json"
    
    classification_list = string_list.classification_list()
    detection_name_string = ''.join(detection_name)
    
    with open(json_name, "w") as json_file:
        json.dump(dictionary, json_file, indent=4, sort_keys=True)
        for cl in range(len(classification_list)):
            count = 0
            count = detection_name_string.count(classification_list[cl])
            if cl == 0:
                dic = {classification_list[cl] : count}
            else:
                dic[classification_list[cl]] = count
        
        max_value = class_tag(dic)
        print("[+] String 카운트 수 : " + str(dic))
        print("[+] 분류 결과 : " + str(max_value))
        
        json.dump(dic, json_file, indent=4, sort_keys=True)
    print("[+] " + str(json_name) + "파일 변환 완료")

def class_tag(dictionary):
    max_key = max(dictionary, key=dictionary.get)
    return max_key



if __name__ == '__main__':
    start = start()
    # 샘플 존재 경로
    target_file = file_list.file_list_load()  
    # Crawling Stat
    crawling_data = main_crawling(target_file, input("Input Redirection Detail Web Site :"))

    print("총 걸린 분류 시간 :", time.time() - start)
    print("[+] 작업 완료")
