import subprocess
import os
import csv
import logging
from multiprocessing import Pool

import angr


MAX_THTREADS = 4

# 펌웨어 이미지들이 모여있는 경로 (MODIFY)
fw_directory = os.getcwd()

# 언패킹 할 루트 디렉토리 경로
unpack_directory = os.path.join(os.getcwd(), 'unpack')

# csv 파일을 저장할 경로
csv_file_path = os.path.join(os.getcwd(), 'binaries.csv')


def firmware_unpacking(fw_directory):
  """
  디렉토리 내의 모든 펌웨어에 대해 언패킹을 수행하는 함수

  [Params]
  fw_directory: 펌웨어 샘플들이 있는 디렉토리 경로

  [Return]
  None
  
  """
  # 펌웨어 파일 언패킹
  for fw in os.listdir(fw_directory):
    fw_path = os.path.join(fw_directory, fw)
    if os.path.isfile(fw_path):
      subprocess.run(['binwalk', '-eM', fw_path, '-C', unpack_directory])

def find_all_binaries(unpack_directory):
  """
  언패킹된 펌웨어 샘플들의 디렉토리에서 각 펌웨어들이 가지고 있는 모든 바이너리들의 이름을 반환

  [Params]
  unpack_directory: 언패킹된 펌웨어 샘플들이 있는 디렉토리 경로

  [Return]
  binaries(list): 각 펌웨어 샘플들의 모든 바이너리 집합
  """
  
  binaries = []
  # 언패킹된 루트 디렉토리 순회
  for unpacked_fw in os.lilstdir(unpack_directory):
    unpack_path = os.path.join(unpack_directory, unpacked_fw)
    if os.path.isdir(unpack_path):
      for root, dirs, files in os.walk(unpack_path):
        for file in files:
          if file.endswith('.so'): # 라이브러리 파일 제외
            continue
          full_path = os.path.join(root, file)

          try:
            file_type = subprocess.check_output(['file', '-b', full_path]).decode()
            if 'ELF' in file_type and 'executable' in file_type:
              binaries.append(file)
              
          except subprocess.CalledProcessError as e:
            pass
            
  return binaries
  
def add_columns_csv(name, contents, csv_file_path):
  """
  csv 파일에 contents의 내용을 name이라는 이름의 열로 추가

  [Params]
  name: 추가할 열의 이름
  contents: csv 파일에 추가할 내용
  csv_file_path: 수정할 csv 파일의 경로

  [Returns]
  None
  
  """
  
  with open(csv_file_path, 'a', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow([name])
    for content in contents:
      writer.writerow([content])

# feature 추출 함수
def extract_features()

# feature 추출 (멀티스레드)
def extract_features_thread(b, bins=None):
  """
  Binary 리스트 안의 Binary들로부터 Feature들을 추출하는 함수

  [Params]
  b: binary
  bin: binaries (펌웨어 샘플 내의 모든 바이너리를 고려하려면 None으로 남김)

  [Return]
  None
  
  """
  return

if __name__ == '__main__':
  
  firmware_unpacking(fw_directory)
  binaries = find_all_binaries(unpack_directory)
  add_columns_csv('Binary Name', binaries, csv_file_path)
