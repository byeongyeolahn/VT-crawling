def vendor_list():
    company_list = ['AhnLab-V3', 'Avira (no cloud)', 'BitDefenderFalx', 'Comodo', 'Cynet', 'Cyren', 'ESET-NOD32', 'Fortinet', 'Google', 'Ikarus', 
                    'Jiangmin', 'K7GW', 'Kaspersky', 'Lionic', 'MaxSecure', 'McAfee', 'McAfee-GW-Edition', 'Microsoft', 'NANO-Antivirus',
                    'QuickHeal', 'Rising', 'Sophos', 'Symantec', 'Symantec Mobile Insight', 'Tencent', 'Trustlook', 'VirIT', 'ZoneAlarm by Check Point',
                    'Acronis (Static ML)', 'Ad-Aware', 'Alibaba', 'ALYac', 'Antiy-AVL', 'Arcabit', 'Avast', 'Avast-Mobile', 'Baidu', 'BitDefender',
                    'BitDefenderTheta', 'Bkav Pro', 'ClamAV', 'CMC', 'DrWeb', 'Emsisoft', 'eScan', 'F-Secure', 'GData', 'Gridinsoft (no cloud)',
                    'K7AntiVirus', 'Kingsoft', 'Malwarebytes', 'MAX', 'Panda', 'Sangfor Engine Zero', 'SUPERAntiSpyware', 'TACHYON', 'Trellix (FireEye)',
                    'TrendMicro', 'TrendMicro-HouseCall', 'VBA32', 'VIPRE', 'ViRobot', 'Yandex', 'Zillya', 'Zoner', 'CrowdStrike Falcon',
                    'Cybereason', 'Cylance', 'Elastic', 'Palo Alto Networks', 'SecureAge', 'SentinelOne (Static ML)', 'TEHTRIS', 'Trapmine',
                    'Webroot']
    return company_list

def detail_string():
    detail_title = ['MD5', 'SHA-1', 'SHA-256', 'Vhash', 'SSDEEP', 'TLSH', 'File type', 'Magic', 'File size', 'First Submission',
                    'Last Submission', 'Last Analysis', 'Earliest Contents Modification', 'Latest Contents Modification', 'Names', 'Package Name',
                    'Main Activity', 'Internal Version', 'Displayed Version', 'Minimum SDK Version', 'Valid From', 'Valid To' , 'Serial Number', 'Thumbprint', 'Distinguished Name',
                    'Permissions', 'Activities', 'Services', 'Receivers', 'Providers', 'Intent Filters By Action', 'Interesting Strings' ]
    return detail_title

def classification_list():
    mal_tag = ['Adware', 'Ransomware', 'Spyware', 'Dropper', 'Banker', 'Phishing', 'SMS', 'Backdoor']
    return mal_tag

def dic_list_load():
    dic_list = ['./mal_apk', './benign_apk', './json_dic']
    return dic_lis
