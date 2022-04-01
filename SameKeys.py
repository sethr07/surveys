#!/usr/bin/python3
#
# Copyright (C) 2018 Stephen Farrell, stephen.farrell@cs.tcd.ie
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# check who's re-using the same keys 
# this script takes in the output from zgrab2 i.e. records.fresh
# it will use a class instance per ip to store differnet informations we need to store
# it will start out by creating a json structure for each line in the abobve line
# it will then store info like ip, asn info if there otherwise it will use the mmdb funcs
# Then for each port we the ip will go through try and catch statements for eahc port and store
# info like fingerprints and certs in the data
# each ip is also looked up and comapred using reverse dns to make sure it matches.

import os, sys, argparse, tempfile, gc, re
import profile
import json
import socket
import time, datetime
import jsonpickle 
from dateutil import parser as dparser  # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons
from SurveyFuncs import *
import cProfile, pstats
from threading import Thread

#default values
#indir=os.environ['HOME']+'/data/smtp/runs/IE-20220315-203316/' #for testing, will change after
#infile=indir+"records.fresh"
infile="records.fresh"
outfile="collisions.json"
statfile = "memstats.txt"
sf = open(statfile, "w")

# command line arg handling 
argparser=argparse.ArgumentParser(description='Scan records for collisions')
argparser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing list of IPs')
argparser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json records (one per line)')
argparser.add_argument('-p','--ports',     
                    dest='portstring',
                    help='comma-sep list of ports to scan')
argparser.add_argument('-s','--scandate',     
                    dest='scandatestring',
                    help='time at which to evaluate certificate validity')
argparser.add_argument('-c','--country',     
                    dest='country',
                    help='country in which we\'re interested, use XX if you don\'t care, default is IE')
argparser.add_argument('-f','--fps',     
                    dest='fpfile',
                    help='pre-existing fingerprints file')
args=argparser.parse_args()

if args.scandatestring is None:
    scandate=datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
    print(sys.stderr, "No (or bad) scan time provided, using 'now'")
else:
    scandate=dparser.parse(args.scandatestring).replace(tzinfo=pytz.UTC)
    print (sys.stderr, "Scandate: using " + args.scandatestring + "\n")

def_country='IE'
country=def_country
if args.country is not None:
    country=args.country
    print (sys.stderr, "Doing a " + country + "run")

if args.infile is not None:
    infile=args.infile

if args.outfile is not None:
    outfile=args.outfile

# this is an array to hold the set of keys we find
profiler = cProfile.Profile()
fingerprints=[]
overallcount=0
badcount=0
goodcount=0

# encoder options
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)

#not tested this one right now
if args.fpfile is not None:
    # read fingerprints from fpfile
    fpf=open(args.fpfile,"r")
    f=getnextfprint(fpf)
    fpcount=0
    while f:
        fingerprints.append(f)
        fpcount+=1
        if fpcount % 100 == 0:
            print (sys.stderr, "Read " + str(fpcount) + " fingerprints from " + args.fpfile)
        f=getnextfprint(fpf)
    fpf.close()
else:
    profiler.enable()
    bads={}
    peripaverage=0  #keep track of how long this is taking per ip
    with open(infile,'r') as f:
        for line in f:
            ipstart=time.time() 
            badrec=False
            j_content = json.loads(line) #one json structure per line
            somekey=False
            thisone=OneFP() # initialise class in surveyfuncs
            thisone.ip_record=overallcount #no of ips
            thisone.ip=j_content['ip'].strip() #get ip from json strcuture
            if 'writer' in j_content:
                thisone.writer=j_content['writer'] 

            try:
                asn=j_content['autonomous_system']['name'].lower()
                asndec=int(j_content['autonomous_system']['asn'])
                thisone.asn=asn 
                thisone.asndec=asndec
                if country != 'XX' and j_content['location']['country_code'] != country:
                    badrec=True
                    print (sys.stderr, "Bad country for ip",thisone.ip,"location:",j_content['location']['country_code'],"Asked for CC:",country)
                    j_content['wrong_country']=j_content['location']['country_code'] 
            except:
                # look that chap up ourselves
                mm_inited=False
                if not mm_inited:
                    mm_setup()
                    mm_inited=True
                asninfo=mm_info(thisone.ip)
                thisone.asn=asninfo['asn']
                thisone.asndec=asninfo['asndec']
                if country != 'XX' and asninfo['cc'] != country:
                    # just record as baddy if the country-code is (now) wrong?
                    # mark it so we can revisit later too
                    print (sys.stderr, "Bad country for ip",thisone.ip,"asn:",asninfo['cc'],"Asked for CC:",country)
                    j_content['wrong_country']=asninfo['cc']
                    badrec=True

            for pstr in portstrings:
                thisone.analysis[pstr]={}           
    
            thisone.analysis['nameset']={}
            nameset=thisone.analysis['nameset']

            print("\nDoing analysis for ip: ", thisone.ip)
            # get reverse dns for ip
            #th = Thread(target=get_rdns(thisone.ip, nameset))
            #th.start()
            rdns = get_rdns(thisone.ip, nameset)
            #nameset['rdns']=rdns            
            # name from smtp banner
            try:
                p25=j_content['p25']
                bn = "y"
                if thisone.writer=="FreshGrab.py":
                    banner=get_dets_email(p25,bn)  
                else:
                    banner=p25['smtp']['starttls']['banner'] 
                ts=banner.split()
                if ts[0]=="220":
                    banner_fqdn=ts[1]
                    nameset['banner']=banner_fqdn
                #need to work this out ->    
                elif ts[0].startswith("220-"):
                    banner_fqdn=ts[0][4:]
                    nameset['banner']=banner_fqdn
            except Exception as e: 
                print (sys.stderr, "FQDN banner exception " + str(e) + " for record:" + str(overallcount) + " ip:" + thisone.ip)
                nameset['banner']=''  
            # ssh info
            try:
                if thisone.writer=="FreshGrab.py":
                    data = j_content['p25']['data']['smtp']['result']['tls']
                    cert, fp = get_dets_email(data, None)
                else:
                    tls=j_content['p25']['smtp']['starttls']['tls']
                    cert=tls['certificate']
                    
                get_tls(thisone.writer,'p25',data,j_content['ip'],thisone.analysis['p25'],scandate)
                get_certnames('p25',cert,nameset)
                thisone.fprints['p25']=fp
                somekey=True
            except Exception as e: 
                print (sys.stderr, "p25 exception for:" + thisone.ip + ":" + str(e))
                pass  

            try:
                if thisone.writer=="FreshGrab.py":
                    data = j_content['p22']['data']['ssh']
                    shk, fp = get_dets_ssh(data)

                    if shk['algorithm']=='ssh-rsa':
                        thisone.analysis['p22']['rsalen']=shk['rsa_public_key']['length']
                    else:
                        thisone.analysis['p22']['alg']=shk['algorithm']
                else:
                    # need toe edit - censys
                    data = j_content['p22']['0']['ssh']
                    fp=j_content['p22']['0']['ssh']['server_host_key']['fingerprint_sha256'] 
                    shk=j_content['p22']['0']['ssh']['v2']['algorithim_selection']
                    if shk['key_algorithm']=='ssh-rsa':
                        thisone.analysis['p22']['rsalen']=shk['rsa_public_key']['length']
                    else:
                        thisone.analysis['p22']['alg']=shk['key_algorithm']
                thisone.fprints['p22']=fp
                somekey=True
            except Exception as e: 
                print(sys.stderr, "p22 exception  for:" + thisone.ip + ":" + str(e))
                pass

            try:
                if thisone.writer=="FreshGrab.py":
                    data = j_content['p110']['data']['pop3']['result']['tls']
                    cert, fp = get_dets_email(data,None)
                    get_tls(thisone.writer,'p110',data,j_content['ip'],thisone.analysis['p110'],scandate)
                else:
                    # not tested
                    data = j_content['p110']['pop3']['starttls']['tls']
                    cert, fp = get_email_dets_cen(data)
                    get_tls(thisone.writer,'p110',data,j_content['ip'],thisone.analysis['p110'],scandate)
                get_certnames('p110',cert,nameset)
                thisone.fprints['p110']=fp
                somekey=True
            except Exception as e: 
                print(sys.stderr, "p110 exception for:" + thisone.ip + ":" + str(e))
                pass

            try:
                if thisone.writer=="FreshGrab.py":
                    data = j_content['p143']['data']['imap']['result']['tls']
                    cert, fp = get_dets_email(data, None)
                    get_tls(thisone.writer,'p143',data,j_content['ip'],thisone.analysis['p143'],scandate)
                else:
                # need toe edit - censys
                    data = j_content['p143']['imap']['starttls']['tls']
                    cert, fp = get_email_dets_cen(data)
                    get_tls(thisone.writer,'p143',data,j_content['ip'],thisone.analysis['p143'],scandate)
                get_certnames('p143',cert,nameset)
                thisone.fprints['p143']=fp
                somekey=True
            except Exception as e: 
                print (sys.stderr, "p143 exception for:" + thisone.ip + ":" + str(e))
                pass

            try:
                if thisone.writer=="FreshGrab.py":
                    data = j_content['p443']['data']['http']['result']['response']['request']['tls_log']
                    cert, fp = get_dets_http(data)
                    get_tls(thisone.writer,'p443',data,j_content['ip'],thisone.analysis['p443'],scandate)
                else:
                    data = j_content['p443']['https']['tls']
                    cert, fp = get_dets_http_cen(data)
                    get_tls(thisone.writer,'p443',data,j_content['ip'],thisone.analysis['p443'],scandate)
                get_certnames('p443',cert,nameset)
                thisone.fprints['p443']=fp
                somekey=True
            except Exception as e: 
                print(sys.stderr, "p443 exception for:" + thisone.ip + ":" + str(e))
                pass

            try:
                if thisone.writer=="FreshGrab.py":
                    data = j_content['p587']['data']['smtp']['result']['tls']
                    cert, fp = get_dets_email(data, None)
                    get_tls(thisone.writer,'p587',data,j_content['ip'],thisone.analysis['p587'],scandate)
                    somekey=True
                    get_certnames('p587',cert,nameset)
                    thisone.fprints['p587']=fp
                else:
                    # censys.io has no p587 for now
                    pass
            except Exception as e: 
                print(sys.stderr, "p587 exception for:" + thisone.ip + ":" + str(e))
                pass

            try:
                if thisone.writer=="FreshGrab.py":
                    data = j_content['p993']['data']['imap']['result']['tls']
                    cert, fp = get_dets_email(data, None)
                    get_tls(thisone.writer,'p993',data,j_content['ip'],thisone.analysis['p993'],scandate)
                else:
                    data = j_content['p993']['imap']['starttls']['tls']
                    cert, fp = get_email_dets_cen(data)
                    get_tls(thisone.writer,'p993',j_content['p993']['imaps']['tls']['tls'],j_content['ip'],thisone.analysis['p993'],scandate)
                get_certnames('p993',cert,nameset)
                thisone.fprints['p993']=fp
                somekey=True
            except Exception as e: 
                print (sys.stderr, "p993 exception for:" + thisone.ip + ":" + str(e))
                pass
            
            besty=[]
            nogood=True # assume none are good
            tmp={}
            #try verify names a bit
            for k in nameset:
                v=nameset[k]
                # see if we can verify the value as matching our give IP
                if v != '' and not fqdn_bogon(v):
                    rip = get_dns(v, thisone.ip)
                    if rip == thisone.ip: #if it matches dns
                        besty.append(k)
                    else:
                        tmp[k+'-ip']=rip
                        #print("Not matched: ", rip)
                        # some name has an IP, even if not what we expect
                        nogood=False

            for k in tmp:
                nameset[k]=tmp[k]
            
            nameset['allbad']=nogood
            nameset['besty']=besty
    
            if not badrec and somekey:
                goodcount += 1
                fingerprints.append(thisone)
            else:
                bads[badcount]=j_content
                badcount += 1
            overallcount += 1
    
            # update average
            ipend=time.time()
            thistime=ipend-ipstart
            peripaverage=((overallcount*peripaverage)+thistime)/(overallcount+1)
            if overallcount % 5 == 0:
                print (sys.stderr, "Reading fingerprints and rdns, did: " + str(overallcount) + \
                        " most recent ip " + thisone.ip + \
                        " average time/ip: " + str(peripaverage) \
                        + " last time: " + str(thistime))
            del j_content
            del thisone
    f.close()
    gc.collect()

    # this gets crapped on each time (for now)
    keyf=open('fingerprints.json', 'w')
    bstr=jsonpickle.encode(fingerprints)
    #bstr=jsonpickle.encode(fingerprints,unpicklable=False)
    keyf.write(bstr)
    del bstr
    keyf.write("\n")
    keyf.close()

    # this gets crapped on each time (for now)
    # in this case, these are the hosts with no crypto anywhere (except
    # maybe on p22)
    badf=open('dodgy.json', 'w')
    bstr=jsonpickle.encode(bads,unpicklable=False)
    badf.write(bstr + '\n')
    del bstr
    badf.close()
    del bads

    # this gets crapped on each time (for now)
    keyf= open('all-key-fingerprints.json', 'w')
    keyf.write("[\n")


profiler.disable()
stats = pstats.Stats(profiler).sort_stats('tottime')
stats.print_stats()
stats.dump_stats('stats2.dmp')

# might split this section into another file
# it takes hella long to debug then
# do clusters 
# end of fpfile is not None
# identify 'em
checkcount=0
colcount=0
mostcollisions=0
biggestcollider=-1
clusternum=0
fl=len(fingerprints)
clustertime1 = time.time() #testing 

for i in range(0,fl):
    r1=fingerprints[i] #first rec
    rec1=r1.ip_record
    for j in range(i+1,fl):
        r2=fingerprints[j] #next rec
        rec2=r2.ip_record
        r1r2coll=False # so we remember if there was one
        for k1 in r1.fprints:
            for k2 in r2.fprints:
                if r1.fprints[k1]==r2.fprints[k2]:
                    if r1.clusternum==0 and r2.clusternum==0:
                        clusternum += 1
                        r1.clusternum=clusternum
                        r2.clusternum=clusternum
                    elif r1.clusternum==0 and r2.clusternum>0:
                        r1.clusternum=r2.clusternum
                    elif r1.clusternum>0 and r2.clusternum==0:
                        r2.clusternum=r1.clusternum
                    elif r1.clusternum>0 and r2.clusternum>0 and r1.clusternum!=r2.clusternum:
                        # merge 'em, check all clusters up to r2 and do the merging
                        # into r1.clusternum from r2.clusternum
                        # note we waste a clusternum here
                        for k in range(0,j):
                            if fingerprints[k].clusternum==r2.clusternum:
                                fingerprints[k].clusternum=r1.clusternum
                        r2.clusternum=r1.clusternum

                    colcount += 1
                    r1r2coll=True # so we remember if there was one
                    if rec2 not in r1.rcs:
                        r1.rcs[rec2]={}
                        r1.rcs[rec2]['ip']=r2.ip
                        if r2.asn != r1.asn:
                            r1.rcs[rec2]['asn']=r2.asn
                            r1.rcs[rec2]['asndec']=r2.asndec
                        r1.rcs[rec2]['ports']=collmask('0x0',k1,k2)
                        r1.nrcs += 1
                    else: 
                        r12=r1.rcs[rec2]
                        r12['ports'] = collmask(r12['ports'],k1,k2)

                    if rec1 not in r2.rcs:
                        r2.rcs[rec1]={}
                        r2.rcs[rec1]['ip']=r1.ip
                        if r2.asn != r1.asn:
                            r2.rcs[rec1]['asn']=r1.asn
                            r2.rcs[rec1]['asndec']=r1.asndec
                        r2.rcs[rec1]['ports']=collmask('0x0',k2,k1)
                        r2.nrcs += 1
                    else: 
                        r21=r2.rcs[rec1]
                        r21['ports'] = collmask(r21['ports'],k2,k1)

        if r1r2coll==True: # so we remember if there was one
            if r1.nrcs > mostcollisions:
                mostcollisions = r1.nrcs
                biggestcollider = r1.ip_record
            if r2.nrcs > mostcollisions:
                mostcollisions = r2.nrcs
                biggestcollider = r2.ip_record

    # print that one
    if args.fpfile is None:
        bstr=jsonpickle.encode(r1,unpicklable=False)
        keyf.write(bstr + ',\n')
        del bstr
    checkcount += 1

    if checkcount % 100 == 0:
        print (sys.stderr, "Checking colisions, did: " + str(checkcount) + " found: " + str(colcount) + " remote collisions")

    if checkcount % 1000 == 0:
        gc.collect()

if args.fpfile is None:
    keyf.write(']\n')
    keyf.close()

colcount=0
noncolcount=0
accumcount=0

# do clusters 
clustersizes={}
clustersizes[0]=0
for f in fingerprints:
    if f.clusternum in clustersizes:
        clustersizes[f.clusternum]+=1
    else:
        clustersizes[f.clusternum]=1

for f in fingerprints:
    f.csize=clustersizes[f.clusternum]

histogram={}
clusterf=open("clustersizes.csv","w")
cw = csv.writer(clusterf, lineterminator='\n')
print(clusterf, "clusternum,size")
csize_headers = ["clusternum", "size"]
cw.writerow(csize_headers)

for c in clustersizes:
    print (clusterf, str(c) + ", " + str(clustersizes[c]))
    csize=clustersizes[c]
    data = [c, csize]
    cw.writerow(data)
    if clustersizes[c] in histogram:
        histogram[clustersizes[c]]= histogram[clustersizes[c]]+1
    else:
        histogram[clustersizes[c]]=1
#print (clusterf, "\n")
print (clusterf, "clustersize,#clusters,collider")
csize_headers2 = ["clustersize,#clusters,collider"]
cw.writerow(csize_headers2)
# "collider" is y or n, so we mark the special "no-external collisions cluster" with an "n"
for h in histogram:
    if h==clustersizes[0]:
        data = [h, histogram[h], "n"]
        cw.writerow(data)
        print (clusterf, str(h) + "," + str(histogram[h]) + ",n")
    else:
        data = [h, histogram[h], "y"]
        cw.writerow(data)
        print (clusterf, str(h) + "," + str(histogram[h]) + ",y")
del clustersizes
clusterf.close()

colf=open(outfile, 'w')
colf.write('[\n')
firstone=True
mergedclusternums=[]

try:
    for f in fingerprints:
        if f.nrcs!=0:
            if f.clusternum not in mergedclusternums:
                mergedclusternums.append(f.clusternum)
            for recn in f.rcs:
                cip=f.rcs[recn]['ip']
                f.rcs[recn]['str_colls']=expandmask(f.rcs[recn]['ports'])
            bstr=jsonpickle.encode(f,unpicklable=False)
            if not firstone:
                colf.write('\n,\n')
            firstone=False
            colf.write(bstr)
            del bstr
            colcount += 1
        else:
            noncolcount += 1
        accumcount += 1
        if accumcount % 100 == 0:
            # exit early for debug purposes
            #break
            print (sys.stderr, "Saving collisions, did: " + str(accumcount) + " found: " + str(colcount) + " IP's with remote collisions")
except Exception as e: 
    print (sys.stderr, "Saving exception " + str(e))

# this gets crapped on each time (for now)
colf.write('\n]\n')
colf.close()
mergedclusternum=len(mergedclusternums)

del fingerprints
clustertime2 = time.time()
ttime = clustertime2-clustertime1

print("\nTotal time taken for clustering: ", ttime)
print(sys.stderr, "\toverall: " + str(overallcount) + "\n\t" + \
        "good: " + str(goodcount) + "\n\t" + \
        "bad: " + str(badcount) + "\n\t" + \
        "remote collisions: " + str(colcount) + "\n\t" + \
        "no collisions: " + str(noncolcount) + "\n\t" + \
        "most collisions: " + str(mostcollisions) + " for record: " + str(biggestcollider) + "\n\t" + \
        "non-merged total clusters: " + str(clusternum) + "\n\t" + \
        "merged total clusters: " + str(mergedclusternum) + "\n\t" + \
        "Scandate used is: " + str(scandate))