#!/usr/bin/python3

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

# read out the port 22 collisions and verify those using ssh-keyscan

import os, sys, argparse, tempfile, gc
import json, jsonpickle
import time
import subprocess
import binascii

from SurveyFuncs import *

# command line arg handling 
parser=argparse.ArgumentParser(description='Do a confirmation scan of ssh key hashes')
parser.add_argument('-d','--dryrun',     
                    help='just do a dry-run, listing IPs that would be checked',
                    action='store_true')
parser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing list of collisions')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json results (one per line)')
parser.add_argument('-s','--sleep',     
                    dest='sleepsecs',
                    help='number of seconds to sleep between ssh-keyscan (fractions allowed)')
args=parser.parse_args()

infile = "collisions.json"
outfile = "sshrecs.two"
# default to a 100ms wait between checks
defsleep=0.1

if args.outfile is not None:
    out_f=open(args.outfile,"w")
else:
    out_f=sys.stdout
print("Running ",sys.argv[0:]," starting at",time.asctime(time.localtime(time.time())))
out_f.write("Running " + str(sys.argv[0:]) + "starting at" + str(time.asctime(time.localtime(time.time()))))

outfile="collisions.json"
sleepval=defsleep
if args.sleepsecs is not None:
    sleepval=float(args.sleepsecs)
    print ("Will sleep for " + str(sleepval) + " seconds between ssh-keyscans")
    out_f.write("Will sleep for " + str(sleepval) + " seconds between ssh-keyscans")

def gethostkey(ip):
    rv=[]
    try:
        time.sleep(sleepval)
        cmd='/usr/bin/ssh-keyscan ' + ip 
        proc_scan=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        pc=proc_scan.communicate()
        print(pc)
        lines=pc[0].split('b\n')
        print ("lines: " + str(lines) + "\n")
        for x in range(0,len(lines)):
            print (lines[x])
            if lines[x]=='\n' or lines[x]=='' or lines[x][0]=='#':
                continue
            # pass to ssh-keygen
            cmd='/usr/bin/ssh-keygen -l -f -'
            proc_hash=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=None)
            pc=proc_hash.communicate(input=lines[x])
            print(pc)
            b64hashes=pc[0].split('\n')
            for y in range(0,len(b64hashes)):
                if b64hashes[y]=='\n' or b64hashes[y]=='' or b64hashes[y]==[]:
                    continue
                #print b64hashes[y]
                foo=b64hashes[y].split()
                #print foo
                fooh=foo[1][7:]
                #print fooh
                barh=binascii.a2b_base64(fooh+'===')
                #print str(barh)
                ahhash=binascii.hexlify(barh)
                #print ahhash
                rv.append(ahhash)
    except Exception as e:
        out_f.write("gethostkey"+str(ip)+str(e))
        print ("gethostkey",ip,e)
        pass
    return rv

def anymatch(one,other):
    # might handle both-empty case nicely
    if one == other:
        return True
    try:
        for x in one:
            for y in other:
                if x==y and x!="error":
                    #print "anymatch",x,y
                    return True
    except Exception as e:
        out_f.write("nomatch: x" + str(x) + "y" + str(y) + str(e))
        print("nomatch: x",x,"y",y,e)
        pass
    return False

# mainline processing

fp=open(infile,"r")

ipsdone={}

ipmatrix={}

ipcount=0
ttcount=0
matches=0
mismatches=0
f=getnextfprint(fp)
while f:
    ipcount+=1
    ip=f.ip
    if 'p22' not in f.fprints:
        out_f.write("Ignoring" + ip + "no SSH involved")
        print("Ignoring",ip,"no SSH involved")
    else:
        ttcount+=1
        out_f.write("Checking " + ip + " recorded as: " + f.fprints['p22'])
        print ("Checking " + ip + " recorded as: " + f.fprints['p22'])
        if args.dryrun:
            f=getnextfprint(fp)
            continue
        hkey=gethostkey(ip)
        if hkey:
            out_f.write("keys at " + ip + " now are:"+str(hkey))
            print("keys at " + ip + " now are:"+str(hkey))
        else:
            out_f.write("No ssh keys visible at " + ip + " now")
            print("No ssh keys visible at " + ip + " now")
        ipsdone[ip]=hkey
        for ind in f.rcs:
            pip=f.rcs[ind]['ip']
            str_colls=f.rcs[ind]['str_colls']
            if 'p22' in str_colls:
                if ip in ipmatrix:
                    if pip in ipmatrix[ip]:
                        out_f.write("\tChecking"+str(ip)+"vs"+str(pip)+"done already")
                        print ("\tChecking",ip,"vs",pip,"done already")
                        continue
                else:
                    ipmatrix[ip]={}
                ipmatrix[ip][pip]=True
                out_f.write("\tChecking"+str(ip)+"vs"+str(pip))
                print ("\tChecking",ip,"vs",pip)
                if pip in ipmatrix:
                    if ip in ipmatrix[pip]:
                        continue
                else:
                    ipmatrix[pip]={}
                ipmatrix[pip][ip]=True
                if pip in ipsdone:
                    pkey=ipsdone[pip]
                else:
                    pkey=gethostkey(pip)
                    ipsdone[pip]=pkey
                if pkey:
                    out_f.write("\t"+ "keys at " + pip + " now are: " + str(pkey))
                    print(out_f, "\t"+ "keys at " + pip + " now are: " + str(pkey))
                else:
                    out_f.write("\tNo ssh keys visible at " + pip + " now")
                    print(out_f, "\tNo ssh keys visible at " + pip + " now")

                if anymatch(pkey,hkey):
                    matches+=1
                else:
                    out_f.write("EEK - Discrepency between "+ ip +" and " + pip) 
                    out_f.write("EEK - " + ip + " == " + str(hkey))
                    out_f.write("EEK - " + pip + " == " + str(pkey))
                    print("EEK - Discrepency between "+ ip +" and " + pip)
                    print("EEK - " + ip + " == " + str(hkey))
                    print ("EEK - " + pip + " == " + str(pkey))
                    mismatches+=1
    f=getnextfprint(fp)

out_f.write("TwentyTwo,infile,ipcount,22count,matches,mismatches")
out_f.write("TwentyTwo,"+args.infile+","+str(ipcount)+","+str(ttcount)+","+str(matches)+","+str(mismatches))
print(out_f, "TwentyTwo,infile,ipcount,22count,matches,mismatches")
print(out_f, "TwentyTwo,"+args.infile+","+str(ipcount)+","+str(ttcount)+","+str(matches)+","+str(mismatches))
#print >>out_f, ipsdone

out_f.write("Ran " + str(sys.argv[0:]) + " finished at " + str(time.asctime(time.localtime(time.time()))))
print("Ran ",sys.argv[0:]," finished at ",time.asctime(time.localtime(time.time())))

#jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
#print jsonpickle.encode(ipmatrix)

if args.outfile:
    out_f.close()
