#!/usr/bin/python3

"""
Script to plot cipher suites.
Data from ciphersuites.sh
"""

import matplotlib.pyplot as plt 
import numpy as np 
import pandas as pd 
import seaborn as sns

indir = "/home/rs/data/smtp/runs/IE-20220329-194902/"
infile = f'{indir}ciphersuites.txt'
plot_dict = {}

with open(infile) as f:
    for line in f:
        data = line.split()
        plot_dict[data[2]] = data[0]
        
        
"""
Plot it
"""
sns.set_theme(style="whitegrid")
df = pd.DataFrame({'Cipher Suite': plot_dict.keys(), 'No of IPs': plot_dict.values()})
print(df.head())
df['No of IPs'] = df['No of IPs'].astype(float)
plt.style.use('seaborn')
plt.rcParams['figure.figsize'] = (16.0, 12.0)
plt.rcParams["patch.force_edgecolor"] = True
colors = sns.color_palette('husl', n_colors=len(df))
sns.set(font_scale = 2)


p = sns.barplot(x ='Cipher Suite', y = 'No of IPs', data=df, hue=df['Cipher Suite'], dodge=False)
plt.xticks([])
plt.legend(bbox_to_anchor=(1, 0), loc="best", borderaxespad=0, fontsize=11)
plt.title('TLS Cipher Suites Seen')
plt.savefig("/home/rs/newgraph.png")

sns.barplot(x = 'No of IPs', y = 'Cipher Suite', data = df)
plt.yticks([])
plt.xticks(df['No of IPs'])
plt.title('TLS Cipher Suites Seen')
plt.savefig("/home/rs/ciphersuites.png")



