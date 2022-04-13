#!/usr/bin/python3

"""
check the protocol versions being used 
This goes back to records.fresh as I don't keep the versioning info
in the fingerprint structure (TODO: add version stuff to metadata
in FP structures)
we'll count versions per-port overall, and for IPs that are, and
are not, within a cluster
for that last, an initial step is to select the IPs from the 
dodgy.json which are those not within clusters
"""
import re, os, sys, argparse, tempfile, gc
import json
import jsonpickle # install via  "$ sudo pip install -U jsonpickle"
import time, datetime
from dateutil import parser as dparser  # for parsing time from comand line and certs
import pytz
from SurveyFuncs import get_p22 # for adding back TZ info to allow comparisons

# our own stuff
from SurveyFuncs import *  

# counters, per port, per version 
counters = {'o': {}, 'c': {}, 'nc': {}}

for pstr in portstrings:
    """
    overall counters
    in-cluster counters
    not in-cluster counters
    """
    counters['o'][pstr]={}
    counters['c'][pstr]={}
    counters['nc'][pstr]={}

# counter updater
def counterupdate(inout,pstr,ver):
    if ver in counters['o'][pstr]:
        counters['o'][pstr][ver]=counters['o'][pstr][ver]+1
    else:
        counters['o'][pstr][ver]=1
    if inout:
        if ver in counters['c'][pstr]:
            counters['c'][pstr][ver]=counters['c'][pstr][ver]+1
        else:
            counters['c'][pstr][ver]=1
    else:
        if ver in counters['nc'][pstr]:
            counters['nc'][pstr][ver]=counters['nc'][pstr][ver]+1
        else:
            counters['nc'][pstr][ver]=1


# command line arg handling 
argparser=argparse.ArgumentParser(description='Count protocol versions in a run')
argparser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing output from zgrab')
argparser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put latex table')
argparser.add_argument('-d','--dodgy_file',     
                    dest='dodgy',
                    help='file in which we find non-clustered IPs')
argparser.add_argument('-c','--collisions',     
                    dest='collisions',
                    help='file in which we find clustered IPs')
args=argparser.parse_args()

infile = args.infile if args.infile is not None else "records.fresh"
outfile = args.outfile if args.outfile is not None else "versions.tex"
dodgyfile = args.dodgy if args.dodgy is not None else "dodgy.json"
collfile = "collisions.json" if args.collisions is None else args.collisions

"""
we won't fully decode this, just grep out the IP addresses
do: grep '^    "ip":' dodgyfile
"""

dodgycount = 0
clusterips = []
ooccount = 0
oocips = []
thatip = ''
df = open(dodgyfile,"r")

for line in df:
    if re.search('^    "ip"', line):
        thatip=line.split()[1][1:-2]
        print("IP: ", thatip)
        print("\n")
        dodgycount+=1
        if dodgycount % 100 == 0:
            print (sys.stderr, "Reading dodgies, did: " + str(dodgycount))
    if re.search('"wrong_country"',line):
        ooccount+=1
        oocips.append(thatip)
print (sys.stderr, "Done reading dodgies, did: " + str(dodgycount))
print (sys.stderr, "Number of ooc IPs: " + str(len(oocips)))

fp=getnextfprint(cf)
clcount=0
while fp:
    clusterips.append(fp.ip)
    clcount+=1
    if clcount % 100 == 0:
        print (sys.stderr, "Reading cluster IPs, did: " + str(clcount))
    fp=getnextfprint(cf)
cf.close()
print (sys.stderr, "Number of non-cluster IPs: " + str(len(clusterips)))


# encoder options
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)

# keep track of how long this is taking per ip
peripaverage=0
overallcount=0
somekeycount=0

"""
initialise to versions we know about - others that we don't
will be added as we find 'em - that may screw up the latex 
output but that'll be visible and can be fixed as we see 'em
"""
sshversions=["1.99", "2.0"]
tlsversions=["SSLv3","TLSv1.0","TLSv1.1","TLSv1.2"]

# init counters
for ctype in counters:
    for pstr in portstrings:
        if pstr=="p22":
            for ver in sshversions:
                counters[ctype][pstr][ver]=0
        else:
            for ver in tlsversions:
                counters[ctype][pstr][ver]=0

# count our fp exceptions
sshfpes=0
tlsfpes=0

with open(infile,'r') as f:
    for line in f:
        ipstart=time.time()
        j_content = json.loads(line)
        thisip=j_content['ip'].strip()
        badrec=False
        somekey=False
        
        # ignore if not in-country
        if thisip in oocips:
            print (sys.stderr, "IP : " + thisip + " is out of country")
            continue

        incluster=False
        if thisip in clusterips:
            incluster=True
        print (sys.stderr, "IP : " + thisip + " incluster: " + str(incluster))
        
        for pstr in portstrings:
            if pstr == 'p22':
                try:
                    data = j_content['p22']['data']['ssh']
                    sshver = data['result']['server_id']['version']
                    """
                    make sure we got an FP for that - sometimes we get protocol versions
                    but don't get an FP, which skews the numbers. That can happen
                    e.g. if something doesn't decode or whatever
                    attempting to get this should cause an exception if it's not there
                    """
                    try:
                        shk, fp = get_p22(data)
                        print(sys.stderr, "IP2 : " + thisip + " incluster: " + str(incluster))
                        counterupdate(incluster,'p22',sshver)
                        somekey=True
                        if sshver not in sshversions:
                            sshversions.append(sshver)
                    except Exception as e:
                        sshfpes+=1
                        print (sys.stderr, "p22 ver/FP exception #" + str(sshfpes) + " " + str(e) + " ip:" + thisip)
                except Exception as e:
                    print (sys.stderr, "p22 exception " + str(e) + " ip:" + thisip)
                    pass
            elif pstr == 'p443':