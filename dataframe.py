from glob import glob
import pandas as pd
import os

def csv_load(path):
    full_path = str(path) + '/*.csv'
    file_list = glob(full_path)

    full_dataset = pd.DataFrame()

    for file in file_list:
        temp_dataset = pd.read_csv(file, sep = ',', encoding='utf-8')
        full_dataset = pd.concat([full_dataset, temp_dataset], axis = 0)
        # full_dataset = full_dataset.drop(full_dataset.columns[0], axis =1)
    full_dataset.to_csv('sample/result.csv', index=False)
    return full_dataset

def dataframe_load():
    if os.path.isfile('sample/result.csv'):
        print("[+] result.csv 파일이 존재")
        df = pd.read_csv('sample/result.csv')
    else:
        df = csv_load('sample')
    return df


def csv_value_add(df, family, detection):
    df['family'] = family
    df['detection'] = detection
    return df
