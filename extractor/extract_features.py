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
  None.
  """
  


# 펌웨어 파일 언패킹
for fw in os.listdir(fw_directory):
  fw_path = os.path.join(fw_directory, fw)
  if os.path.isfile(fw_path):
    subprocess.run(['binwalk', '-eM', fw_path, '-C', unpack_directory])

binaries = []

# 언패킹 된 루트 디렉토리 순회
for unpacked_fw in os.listdir(unpack_directory):
  unpack_path = os.path.join(unpack_directory, unpacked_fw)
  if os.path.isdir(unpack_path):    
    for root, dirs, files in os.walk(unpack_path):
      for file in files:
        if file.endswith('.so'):
          continue
        full_path = os.path.join(root, file)

        try:
          file_type = subprocess.check_output(['file', '-b', full_path]).decode()
          if 'ELF' in file_type and 'executable' in file_type:
            binaries.append(file)

        except subprocess.CalledProcessError as e:
          pass

# CSV 파일에 바이너리 추가
with open(csv_file_path, 'a', newline='') as csvfile:
  writer = csv.writer(csvfile)
  writer.writerow(['Binary Name'])
  for binary in binaries:
    writer.writerow([binary])
