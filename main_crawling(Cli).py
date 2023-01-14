from selenium import webdriver
from pyshadow.main import Shadow
import time
import os
import string_list
import shutil
import json
import pandas as pd
import dataframe
import argparse

#Cli 옵션 
parser = argparse.ArgumentParser(description="사용법 test 입니다")
parser.add_argument('-p', type=str, help = '-p C:\\Users\\**\\Desktop\\User\\ChromeDriver\\chromedriver.exe' )
parser.add_argument('-o', type=str, help = '-o detection')

args = parser.parse_args()

CHROMEDRIVER_PATH = args.p


detection_value = []
family = []

#시작 시 알림 함수
def start():
    print("================================================================================")
    print("[+] VT Crawling Start ! ")       
    start = time.time()
    return start

# 드라이버 호출
def get_driver():
    options = webdriver.ChromeOptions()
    # options.add_argument('headless')
    # options.add_argument('window-size = 1920x1080')
    # options.add_argument('disable-gpu')
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    driver = webdriver.Chrome(CHROMEDRIVER_PATH, options=options)
    #명시적 대기
    driver.implicitly_wait(3)
    return driver

#실제 값 들고오는 크롤러(값에 대한 파서 따로 구축 예정)
def main_crawling(file, option):
    driver=get_driver()
    # 옵션에 따른 URL 접근
    for i in range(len(file)):
        link_info = 'https://www.virustotal.com/gui/file/{}/'.format(file[i])
        if option == 'detection':
            link_info = 'https://www.virustotal.com/gui/file/{}'.format(file[i])
            driver.get(link_info)
            print("================================================================================")
            print("[+] " + str(link_info) + " 접속")  
        
        else:
            url_link = link_info + str(option)
            driver.get(url_link)
            print("================================================================================")
            print("[+]" + str(url_link) + " 접속")
        
        #Shadow 객체 생성
        shadow = Shadow(driver)
        # 명시적 대기
        shadow.set_explicit_wait(20, 5)
    
    # detail 창일 경우
        if option == 'details':
            interesting_String = shadow.find_element('vt-ui-code-block')
            print("[+] interesting String :\n" + str(interesting_String.text))
            print("================================================================================")
            File_detail = shadow.find_element('vt-ui-file-details')
            File_detail_text = File_detail.text
            print(File_detail_text)
            File_detail_list = File_detail_text.split('\n')
            print(File_detail_list)
            return File_detail_list
        
        elif option == 'detection':
            time.sleep(5) # 에러 발생 시만 넣기
            detection_element = shadow.find_element('vt-ui-expandable')
            detection = detection_element.text
            detection_list = detection.split('\n')
            crawling_parse(file[i], detection_list, 'detection')
            time.sleep(5)
        
        else:
            print('Option Value Error')

def crawling_parse(file_name, data, option):
    if option == "detection":
        vendor_list = []
        vendor_value = []
        for vl in range(int(len(data)/2+1)):
            try:
                if vl == 0:
                    continue
                else:
                    vendor_list.append(data[2*vl-1])
                    vendor_value.append(data[(2*vl)])
            except:
                print("[+] 진단명, 회사 파싱 중 오류 발생" )
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
    print(str(file_name) + "의 Score : " + str(detected) + "/" + str(total))

    # 라벨링 작업 진행
    if detected <= 39:
        print("[+] " + str(file_name) + "분류(정상) 완료")
        detection_value.append('0')

    else:
        print("[+] " + str(file_name) + "분류(악성) 완료")
        detection_value.append('1')
    # Json 생성
    list_to_dictionary(file_name, company, detection_name)

def class_tag(dictionary):
    max_key = [di for di, vi in dictionary.items() if max(dictionary.values() == vi)]
    print(max_key)
    return max_key

def label_family(classification, max):
    return str(classification.index(max)+2)

def list_to_dictionary(file_name, company, detection_name):
    vendor_list = company
    if vendor_list > detection_name:
        dictionary = {vendor_list[d] : detection_name[d] for d in range(len(vendor_list))}
    else:
        dictionary = {vendor_list[d] : detection_name[d] for d in range(len(detection_name))}

    slice_filename = file_name[:-4]
    json_name = "./json_dic/" + str(slice_filename) + ".json"
    
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

        #분류될 카테고리 도출
        max_value = class_tag(dic)
        print("분류 결과 : " + str(max_value))

        #패밀리 라벨링
        family.append(label_family(classification_list, max_value))
        #Json 변환
        json.dump(dic, json_file, indent=4, sort_keys=True)

    print("[+] " + str(json_name) + "파일 변환 완료")

def class_tag(dictionary):
    # max_key = [kc for kc, vc in dictionary.items() if max(dictionary.values()) == vc]
    max_key = max(dictionary.keys())
    return max_key

def file_list_fun(data):
    print("================================================================================")
    print("[+] 파일 목록 수집 중...")    
    df = data['sha256'].to_list()
    print("[+] 파일 목록 수집 완료")
    return df

def csv_value_add(df, family, detection):
    df['family'] = pd.Series(family)
    df['detection'] = pd.Series(detection)
    return df

if __name__ == '__main__':
    start = start()
    #CSV 병합
    if os.path.isfile('sample/result.csv'):
        print("[+] result.csv 파일이 존재")
        df = pd.read_csv('sample/result.csv')
    else:
        df = dataframe.csv_load('sample')
    
    #파일 목록 획득
    file_list = file_list_fun(df)
    # crawling_data = main_crawling(file_list, 'detection')
    crawling_data = main_crawling(file_list, args.o)

    # CSV 값 쓰기 
    labeled_df = csv_value_add(df, family, detection_value)
    try:
        labeled_df.to_csv('sample/result.csv', index=False)
    except:
        print("[+] 동일 파일 이름 존재")
        labeled_df.to_csv('sample/result2.csv', index=False)

    print("총 걸린 분류 시간 :", time.time() - start)
    print("[+] 작업 완료")
    #파서 실행
