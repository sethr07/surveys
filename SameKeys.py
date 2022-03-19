#!/usr/bin/python3.9
# Copyright (C) 2018 Stephen Farrell, stephen.farrell@cs.tcd.ie
# 
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

# check who's re-using the same keys 

import os, sys, argparse, tempfile, gc, re
import json
import jsonpickle 
import time, datetime
from dateutil import parser as dparser  # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons
from SurveyFuncs import *

# default values
indir=os.environ['HOME']+'/data/smtp/runs/IE-20220315-203316/'
infile=indir+"records.fresh"
outfile="collisions.json"

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
    print(f)
    fpcount=0
    while f:
        fingerprints.append(f)
        fpcount+=1
        if fpcount % 100 == 0:
            print (sys.stderr, "Read " + str(fpcount) + " fingerprints from " + args.fpfile)
        f=getnextfprint(fpf)
    fpf.close()
else:
    #started from here
    bads={}
    # keep track of how long this is taking per ip
    peripaverage=0
    with open(infile,'r') as f:
        for line in f:
            #line is json structre - output from zmap 
            #print(line)
            ipstart=time.time() 
            badrec=False
            j_content = json.loads(line) #one json structure per line
            #print(j_content)
            somekey=False
            thisone=OneFP() # initialise class in surveyfuncs
            thisone.ip_record=overallcount #no of ips
            thisone.ip=j_content['ip'].strip() #get ip from json strcuture
            #print(thisone.ip)
            if 'writer' in j_content:
                thisone.writer=j_content['writer'] #get writer
            #try and get asn info for json line 
            try:
                asn=j_content['autonomous_system']['name'].lower()
                #print(asn)
                asndec=int(j_content['autonomous_system']['asn'])
                #print(asndec)
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
                #print(asninfo)
                #print("fixing up asn info",asninfo)
                thisone.asn=asninfo['asn']
                thisone.asndec=asninfo['asndec']
                if country != 'XX' and asninfo['cc'] != country:
                    # just record as baddy if the country-code is (now) wrong?
                    # mark it so we can revisit later too
                    print (sys.stderr, "Bad country for ip",thisone.ip,"asn:",asninfo['cc'],"Asked for CC:",country)
                    j_content['wrong_country']=asninfo['cc']
                    badrec=True
            #the ports 
            for pstr in portstrings:
                thisone.analysis[pstr]={}
            
            #with open("jcontent.json", "w") as k:
                #json.dump(j_content,k)               
    
            thisone.analysis['nameset']={}
            nameset=thisone.analysis['nameset']
            try:
                # name from reverse DNS
                rdnsrec=socket.gethostbyaddr(thisone.ip)
                #print(rdnsrec)
                rdns=rdnsrec[0]
                #print ("FQDN reverse: " + str(rdns))
                nameset['rdns']=rdns
            except Exception as e: 
                print (sys.stderr, "FQDN reverse exception " + str(e) + " for record:" + thisone.ip)
                #nameset['rdns']=''
                pass

            # name from banner
            try:
                p25=j_content['p25']
                #print(p25['data'])
                if thisone.writer=="FreshGrab.py":
                    #print(p25['data']['smtp']['result'])
                    banner=p25['data']['smtp']['result']['banner'] #this matches the reverse dns (not all of them ofc) 
                #else:
                    #banner=p25['smtp']['starttls']['banner'] 
                
                ts=banner.split()
                print(ts)
                if ts[0]=="220":
                    banner_fqdn=ts[1]
                    print("fqdn banner: \n")
                    print(banner_fqdn)
                    nameset['banner']=banner_fqdn
                #need t work this out ->    
                elif ts[0].startswith("220-"):
                    print("Startws with fqdn: \n")
                    banner_fqdn=ts[0][4:]
                    print(banner_fqdn)
                    nameset['banner']=banner_fqdn
            except Exception as e: 
                print (sys.stderr, "FQDN banner exception " + str(e) + " for record:" + str(overallcount) + " ip:" + thisone.ip)
                nameset['banner']=''
    
            try:
                if thisone.writer=="FreshGrab.py":
                    fp=j_content['p22']['data']['ssh']['result']['key_exchange']['server_host_key']['fingerprint_sha256'] 
                    #print("fp for ssh: ", fp)
                    #print("\n")
                    shk=j_content['p22']['data']['ssh']['result']['key_exchange']['server_host_key']
                    #print("SSH: ", shk)
                    #print("\n")
                    if shk['algorithm']=='ssh-rsa':
                        print("it is ")
                        thisone.analysis['p22']['rsalen']=shk['rsa_public_key']['length']
                    else:
                        thisone.analysis['p22']['alg']=shk['algorithm']
                        print(shk['algorithm'])
                #dont know what this section (->) is doing        
                else:
                    fp=j_content['p22']['ssh']['v2']['server_host_key']['fingerprint_sha256'] 
                    shk=j_content['p22']['ssh']['v2']['server_host_key']
                    if shk['key_algorithm']=='ssh-rsa':
                        thisone.analysis['p22']['rsalen']=shk['rsa_public_key']['length']
                    else:
                        thisone.analysis['p22']['alg']=shk['key_algorithm']
                thisone.fprints['p22']=fp
                somekey=True
            except Exception as e: 
                print (sys.stderr, "p22 exception " + str(e) + " ip:" + thisone.ip)
                pass

            besty=[]
            nogood=True # assume none are good
            tmp={}
            # try verify names a bit
            #print("Printing nameste?")
            #print(nameset)
            for k in nameset:
                v=nameset[k]
                #print("Printing V: ", v)
                #print "checking: " + k + " " + v
                # see if we can verify the value as matching our give IP
                if v != '' and not fqdn_bogon(v):
                    try:
                        rip=socket.gethostbyname(v)
                        #print(rip)
                        if rip == thisone.ip:
                            besty.append(k)
                        else:
                            tmp[k+'-ip']=rip
                        # some name has an IP, even if not what we expect
                        nogood=False
                    except Exception as e: 
                        #oddly, an NXDOMAIN seems to cause an exception, so these happen
                        #print >> sys.stderr, "Error making DNS query for " + v + " for ip:" + thisone.ip + " " + str(e)
                        pass

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

            
           