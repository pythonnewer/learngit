import os
import pandas as pd
import nmap
from functools import partial
from multiprocessing import Pool
import time
print('Start')
os.chdir(r"F:\security_situation")
scanner = nmap.PortScanner()
def scan(host,port):
    scanner.scan(hosts=host,ports=port)
    with open(host+'.csv',encoding='utf-8',mode='w') as fp:
        fp.write(scanner.csv())

def ipClean(file):
    ipTxt = open(file,encoding='utf-8').readlines()
    if ipTxt[0].strip() == '<pre>':
        ipTxt = ipTxt[1:-1]
    target = []
    for line in ipTxt:
        temp = line.split('\t')[:-1]
        ipD = []
        for i,j in zip(temp[0].split('.'),temp[1].split('.')):
            if i != j:ipD.append(i+'-'+j)
            else:ipD.append(i)
            
        target.append('.'.join(ipD))
    #target = ','.join(target)
    return target

if __name__ == "__main__":
    a = time.time()
    hostlist = ipClean('SCip.txt')
    
    port = '''21,22,23,25,110,143,80,81,82,83,88,135,139,443,445,902,912,443,445,512,513,514,1433,
    1521,2082,2083,2181,2601,2604,3128,3690,4848,8088,8086,8081,8080,3306,5432,3389,
    5984,6379,7001,7002,8069,9200,9300,8888'''
    pool = Pool(4)
    nmargu = partial(scan,port=port)
    pool.map(nmargu,hostlist)
    print(time.time()-a)