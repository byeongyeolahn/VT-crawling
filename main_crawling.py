from selenium import webdriver
from pyshadow.main import Shadow
import time
import os
import string_list
import shutil
import json

# parser = argparse.ArgumentParser(description="사용법 test 입니다")
# parser.add)argument('-')
# #파일 리스트 인자로 받아서 URL 연결

#chromedriver 경로 설정(작업 공간과 동일 경로에 있으면 에러 발생함)

CHROMEDRIVER_PATH = 'C:\\Users\\quddu\\\Desktop\\뺑열\\\Coding\\CHROMEDRIVER\\chromedriver.exe'

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
        link_info = 'https://www.virustotal.com/gui/file/{}/'.format(file[i][:-4])
        if option == 'detection':
            link_info = 'https://www.virustotal.com/gui/file/{}'.format(file[i][:-4])
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
            score_element = shadow.find_element('vt-ui-detections-widget')
            score = score_element.text
            print(score)
            
            detection_element = shadow.find_element('vt-ui-expandable')
            detection = detection_element.text
            detection_list = detection.split('\n')
            crawling_parse(file[i], detection_list, 'detection')
            time.sleep(5)
        
        else:
            print('Option Value Error')
            

def file_list(file_path):
    print("================================================================================")
    print("[+] 파일 목록 수집 중...")
    fl = os.listdir(file_path)
    print("[+] 파일 목록 수집 완료")
    return fl

def crawling_parse(file_name, data, option):
    if option == "detection":
        #벤더사 목록 불러옴
        vendor_list = string_list.vendor_list()
        #진단명 저장할 리스트
        vendor_value = []
        for vl in range(len(vendor_list)):
            try:
                # 벤더사에 맞는 진단명을 동일한 인덱스로 측정
                vender_index = data.index(vendor_list[vl])
                vendor_value.append(data[vender_index+1])
            except:
                print("[+] " + str(vendor_list[vl] + "이(가) 존재하지 않음"))
        return Determining_Malware(file_name, vendor_list, vendor_value)
        
        print(vendor_value)
    elif option == "details":
        title_string = string_list.detail_string()
        target_string = []
        for t in range(len(title_string)):
            first = data.index(title_string[t])
            next = data.index(title_string[t+1])


def Determining_Malware(file_name, company, detection_name):
    total = len(detection_name)
    type_error = detection_name.count('Unable to process file type')
    undetected = detection_name.count('Undetected')
    detected = total - (type_error + undetected)
    print(str(file_name) + "의 Score : " + str(detected) + "/" + str(total))
    start_path = "sample/" + str(file_name)
    target_path = "mal_apk/" + str(file_name)
    if detected <= 1:
        shutil.move("sampl\\/{file}", "benign_apk\\{file}}").format(file= file_name)
        print()
    else:
        shutil.move(start_path, target_path)
    print("[+] " + str(file_name) + "분류(악성) 완료")

    # dic로 전환
    list_to_dictionary(file_name, company, detection_name)

def create_dec(tag_list):
    if os.path.isdir('./mal_apk') and os.path.isdir('./benign_apk'):
        print("[+] 모든 디렉토리 이미 존재")
    else:
        os.mkdir('./mal_apk')
        os.mkdir('./benign_apk')
        os.mkdir('./json_dic')
        for ct in range(len(tag_list)):
            dic_name = './mal_apk/{}'.format(tag_list[ct])
            os.mkdir(dic_name)
            print(str(dic_name) + " 디렉토리 생성")
        print("================================================================================")
        print("[+] 디렉토리 생성 완료")

def list_to_dictionary(file_name, company, detection_name):
    vendor_list = company
    if vendor_list > detection_name:
        dictionary = {vendor_list[d] : detection_name[d] for d in range(len(vendor_list))}
    else:
        dictionary = {vendor_list[d] : detection_name[d] for d in range(len(detection_name))}

    slice_filename = file_name[:-4]
    json_name = "./json_dic/" + str(slice_filename) + ".json"
    with open(json_name, "w") as json_file:
        json.dump(dictionary, json_file, indent=4, sort_keys=True)
    print("[+] " + str(json_name) + ".json 파일 변환 완료")
# def Mal_Classification(file_path, detection_name):
    # vendor_top_15 = string_list.vendor_top_15()

    

if __name__ == '__main__':
    start = time.time()
    #디렉토리 생성
    create_dec(string_list.classification_list())

    apk_file_path = "sample" # 분류 대상 샘플 존재 경로
    # apk_file_path = "C:\\Users\\SCHCsRC\\Desktop\\test_dic"
    fl = file_list(apk_file_path)

    crawling_data = main_crawling(fl, 'detection')
    print("총 걸린 분류 시간 :", time.time() - start)
    print("[+] 작업 완료")
    #파서 실행
