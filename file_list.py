import dataframe
import os

def file_list_load():
    json_file_name = []
    df = dataframe.dataframe_load()
    csv_file_name = df['sha256'].to_list()
    json_file = os.listdir('json_dic')
    for jf in range(len(json_file)):
        temp = json_file[jf]
        json_file_name.append(temp[:-5])
    print("[+] 총 샘플의 개수 : " + str(len(csv_file_name)))
    print("[+] 기존 진행된 샘플의 개수 : " + str(len(json_file_name)))
    for cr in range(len(json_file_name)):
        csv_file_name.remove(json_file_name[cr])
    print("[+] 이번에 진행될 샘플의 개수 : " + str(len(csv_file_name)))
    return csv_file_name
