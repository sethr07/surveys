#!/usr/bin/python3
"""
Script for counting IPs that were mapped by zmap. 
Count em and plot em.
"""
import matplotlib.pyplot as plt 
import pandas as pd 

def search_str(file_path, st, tot_mapped = None, p25s = None):
    if tot_mapped is None:
        tot_mapped = []
    if p25s is None:
        p25s = []

    with open(file_path, 'r') as file:
        content = file.readlines()
        for line in content:
            print(line)
            if st in line:
                data = line.split()
                print(data)
                #ips = data[9]
                #time = data[16]
                #tot_mapped.append(ips)
                #p25s.append(time)

"""
lists for graphing stuff
"""
mapped = []
p25s = []

# main line processing 
logfile = "/home/rs/data/smtp/runs/IE-20220329-194902/20220329-194902.out"
line = "1d6:52:40 100% (1s left); send:"

search_str(logfile, line)

