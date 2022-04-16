#!/usr/bin/python3


from matplotlib import lines
import matplotlib.pyplot as plt 
from matplotlib.patches import Patch
import numpy as np 
import pandas as pd 
import matplotlib
from matplotlib import cm
import seaborn as sns



indir = "/home/rs/data/smtp/runs/IE-20220329-194902/"
infile = indir + "ciphersuites.txt"



code = []
nos = []
cipher = []

plot_dict = {}
with open(infile) as f:
    for line in f:
        data = line.split()
        plot_dict[data[2]] = data[0]
        
        
"""
Plot it
"""

#names = list(plot_dict.keys())
#values = list(plot_dict.values())

df = pd.DataFrame({'Cipher Suite': plot_dict.keys(), 'No of IPs': plot_dict.values()})
print(df.head())
df['No of IPs'] = df['No of IPs'].astype(float)

plt.style.use('seaborn')
plt.rcParams['figure.figsize'] = (16.0, 10.0)
plt.rcParams["patch.force_edgecolor"] = True
colors = sns.color_palette('husl', n_colors=len(df))

p = sns.barplot(x=df.index, y=df['No of IPs'], data=df, hue=df['Cipher Suite'])
plt.legend(bbox_to_anchor=(1.04, 0.5), loc='center left', borderaxespad=0)

"""


fig,ax = plt.subplots()

ax.barh(df['Cipher Suite'], df["No of IPs"], color=plt.cm.Paired(np.arange(len(df))))
x_legend = '\n'.join(f'{n} - {name}' for n,name in zip(df.index,df['Cipher Suite']))

t = ax.text(.7,.2,x_legend,transform=ax.figure.transFigure)
fig.subplots_adjust(right=.80)

plt.title("Cipher Suites Seen")
plt.xlabel('No of IPs')
plt.ylabel('Cipher Suites')


#plt.bar(range(len(plot_dict)), values, tick_label=names)
"""

plt.savefig("/home/rs/newgraph.png")

