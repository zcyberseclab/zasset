import os
import subprocess
import gzip
import shutil

def clean_vendor_name(vendor):
    # 需要移除的关键字列表
    remove_words = [
        'Limited', 'Ltd', 'LLC', 'Corporation', 'Corp', 'Inc.', 'Inc', 'Co.', 
        'Co', 'Company', 'Technologies', 'Technology', 'International', 
        'Electronics', 'Electric', 'Industries', 'Industry', 'Industrial',
        'Communications', 'Communication', 'Solutions', 'Systems', 'System',
        'Manufacturing', 'Incorporated', 'Group', 'Holdings', 'Holding',
        'Enterprise', 'Enterprises', 'GmbH', 'AG', 'AB', 'SA', 'SAS', 'BV',
        'PLC', 'PTY', 'L.L.C', 'A/S', 'S.p.A', 'S.A.', 'S.A', 'B.V.',
        'Equipment', 'Equipments','Corporate'
    ]
    
    # 移除括号及其内容
    while '(' in vendor and ')' in vendor:
        start = vendor.find('(')
        end = vendor.find(')') + 1
        vendor = vendor[:start] + vendor[end:]
    
    # 分割成单词
    words = vendor.split()
    
    # 过滤掉不需要的关键字
    words = [word for word in words if word not in remove_words]
    
    # 重新组合
    return ' '.join(words).strip()

def convert_mac_to_oui(mac_str):
    # 移除冒号并转换为大写
    mac = mac_str.replace(':', '').upper()
    return mac[:6]

def convert_file():
    with open('mac_vendor_map.py', 'r') as infile:
        with open('oui.txt', 'w') as outfile:
            # 跳过第一行的 mac_vendor_map = {
            next(infile)
            
            for line in infile:
                if '}' in line:  # 跳过最后一行
                    break
                    
                # 解析每一行
                parts = line.strip().split('"')
                if len(parts) >= 4:
                    mac = parts[1]
                    vendor = parts[3]
                    
                    # 清理厂商名称
                    vendor = clean_vendor_name(vendor)
                    
                    # 如果清理后还有内容，则写入
                    if vendor:
                        # 转换格式并写入
                        oui = convert_mac_to_oui(mac)
                        outfile.write(f"{oui} {vendor}\n")

def post_process():
    # 1. 压缩文件
    with open('oui.txt', 'rb') as f_in:
        with gzip.open('oui.txt.gz', 'wb', compresslevel=9) as f_out:
            shutil.copyfileobj(f_in, f_out)
    
    # 2. 移动压缩文件到 pkg 目录
    pkg_dir = os.path.join('..', 'pkg')
    if not os.path.exists(pkg_dir):
        os.makedirs(pkg_dir)
    
    dest_file = os.path.join(pkg_dir, 'oui.txt.gz')
    # Remove destination file if it exists
    if os.path.exists(dest_file):
        os.remove(dest_file)
    os.rename('oui.txt.gz', dest_file)
    
    # 3. 删除原始的 oui.txt 文件
    data_file = os.path.join('..', 'data', 'oui.txt')
    if os.path.exists(data_file):
        os.remove(data_file)

if __name__ == "__main__":
    convert_file()
    post_process() 