#!/usr/bin/python3
"""
Script for DNS Comparasion Timings
2 DNS Setups - 1. Default DNS on Ubunutu and 2. Stubby + Unbound
"""

import matplotlib.pyplot as plt 
from matplotlib.pyplot import figure
import pandas as pd

# search string function inspired from stackoverflow
def search_str(file_path, st, ip_list = None, time_list = None):
    if ip_list is None:
        ip_list = []
    if time_list is None:
        time_list = []

    with open(file_path, 'r') as file:
        content = file.readlines()
        for line in content:
            if st in line:
                data = line.split()
                ips = data[9]
                time = data[16]
                ip_list.append(ips)
                time_list.append(time)


"""
List to store and plot timings and time differences 
"""
times_old_setup = []
times_new_setup = []
no_ips = []
                
# main line processing 
logfile1 = "/home/rs/data/smtp/runs/IE-20220329-194902_18.04/20220410-012727.out"
logfile2 = "/home/rs/data/smtp/runs/IE-20220329-194902_done/20220411-014338.out"
line = "Reading fingerprints and rdns, did:"

search_str(logfile1,line, no_ips, times_old_setup)
search_str(logfile2,line, None, times_new_setup)

df = pd.DataFrame(list(zip(no_ips, times_old_setup, times_new_setup)))
df = df.rename(columns={0:'No of IPs', 1:'DNS by ISP', 2:'Stubby+Unbound (Cloudflare)'})
df['No of IPs'] = df['No of IPs'].astype(float)
df['DNS by ISP'] = df['DNS by ISP'].astype(float)
df['Stubby+Unbound (Cloudflare)'] = df['Stubby+Unbound (Cloudflare)'].astype(float)

# plot it and save 
textstr = "\nDNS Test Done:\nISP: 10/04/22 \nStubby:11/04/22 \n"
figure(figsize=(12, 8), dpi=80)
df.plot(x=0, y=[1,2])
plt.figtext(0.00000005, 0.0005, textstr, fontsize=8)
plt.title("Average Time per IP Comparasion")
plt.xlabel("Number of IPs Analysed")
plt.ylabel("Average Time per IP (s)")
plt.savefig("/home/rs/results/newdnscomp.png")
