import subprocess
import os
import csv
import logging
from multiprocessing import Pool
from functools import partial

import angr

MAX_THREADS = 4

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
  paths(list): 바이너리의 경로
  """
  
  binaries = []
  paths = []
  
  # 언패킹된 루트 디렉토리 순회
  for unpacked_fw in os.listdir(unpack_directory):
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
              paths.append(full_path)
              
          except subprocess.CalledProcessError as e:
            pass
            
  return binaries, paths
  
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
      
def add_columns_csv_new(name, contents, csv_file_path):
    """
    CSV 파일에 contents의 내용을 name이라는 이름의 열로 추가
    
    [Params]
    name: 추가할 열의 이름
    contents: csv 파일에 추가할 내용
    csv_file_path: 수정할 csv 파일의 경로
    
    [Returns]
    None
    """
    
    # 기존 CSV 파일을 읽고 모든 데이터를 저장
    rows = []
    with open(csv_file_path, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)
        rows = [row for row in reader]
    
    # 열의 이름을 첫 번째 행에 추가
    if len(rows) > 0:
        rows[0].append(name)
    
    # 새로운 열의 내용을 추가
    for i, content in enumerate(contents, start=1):
        # 이미 존재하는 행에 내용 추가
        if i < len(rows):
            rows[i].append(content)
        # 새로운 행이 필요한 경우 (contents가 기존 행보다 많은 경우)
        else:
            rows.append([''] * (len(rows[0]) - 1) + [content])  # 이전 열들은 비워두고 새 내용 추가
    
    # 수정된 데이터로 CSV 파일 덮어쓰기
    with open(csv_file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(rows)

# feature 추출
#def extract_features(bins):
#  """
#  Binary 리스트 안의 Binary들로부터 Feature들을 추출하는 함수
#
#  [Params]
#  bin: binaries
#
#  [Return]
#  tot_bb(list): 바이너리들의 basic block 개수
#  
#  """
#  tot_bb = []
#  
#  for b in bins:
#    logging.info(f"Binary: {os.path.basename(b)}")
#
#    try:
#      p = angr.Project(b, auto_load_libs=False)  
#    except Exception as e:
#      logging.error(f"Failed to load binary {b}: {e}")
#      tot_bb.append("Fail")
#      continue
#
#    try:
#      cfg = p.analyses.CFG()
#      num_bb = len(cfg.model.nodes())
#      tot_bb.append(num_bb) 
#    except Exception as e:
#      logging.error(f"Failed to generate CFG for binary {b}: {e}")
#      tot_bb.append(0)
#      continue
#      
#  return tot_bb  

# feature 추출
def extract_features(function, p, cfg):
  """
  basic block의 개수, 메모리 비교 연산의 개수, branch의 개수를 반환하는 함수

  [Params]
  function: angr function
  p: angr project
  cfg: control-flow graph

  [Return]
  n_blocks(int): number of basic blocks
  n_memcmp(int): number of memory comparisons
  n_branches(int): number of branches
  
  """

  n_blocks = 0
  n_memcmp = 0
  n_branches = 0
  strings = []

  for block_addr in function.block_addrs:
    n_blocks += 1

    try:
      bb_block = p.factory.block(block_addr)
      cfg_node = cfg.model.get_any_node(block_addr)
      succs = cfg_node.successors
    except:
      continue

    # 분기문이 아닌 경우
    if not succs:
      continue

    if bb_block.vex.jumpkind == 'Ijk_Call':
      

if __name__ == '__main__':
  
  firmware_unpacking(fw_directory)
  binaries, paths = find_all_binaries(unpack_directory)
  add_columns_csv_new('Binary Name', binaries, csv_file_path)
  tot_bb_list = extract_features(paths)
  add_columns_csv('Num of BB', tot_bb_list, csv_file_path)
