#!/usr/bin/python
#set -x 
# # Permission is hereby granted, free of charge, to any person obtaining a copy
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
# Grabs IPs from GeoIPWhois.csv which is created using maxmind 
# country and ipv4 network block databases. This script filters out
# the network blocks according to the country provided.
# Default is IE, Ireland

import os, sys, argparse, tempfile, gc
import csv
import netaddr
import socket

# command line arg handling 
parser=argparse.ArgumentParser(description='Write out IP ranges from the country in question')
parser.add_argument('-i','--input-dir',     
                    dest='indir',
                    help='directory name containing list of IPs in ccv files')
parser.add_argument('-4','--ipv4',
                    dest='v4file',
                    help='file name containing maxmind IPv4 address ranges for countries')
parser.add_argument('--nov4',
                    dest='nov4',
                    help='don\'t bother with IPv4', action='store_true')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json records (one per line)')
parser.add_argument('-c','--country',     
                    dest='country',
                    help='file in which to put stderr output from zgrab')
args=parser.parse_args()

#default cases incase user does not provide custom inputs
def_country="IE"
def_indir=os.environ['HOME']+'/code/surveys/mmdb/'
def_outfile="mm-ips."+def_country
def_v4file='GeoIPCountryWhois.csv'

country=def_country
indir=def_indir
outfile=def_outfile

if args.country is not None:
    country=args.country
    outfile="mm-ips."+country

if args.indir is not None:
    indir=args.indir

if args.outfile is not None:
    outfile=args.outfile

if args.v4file is not None:
    v4file=indir+args.v4file
else:
    v4file=indir+def_v4file

dov4=True
if args.nov4:
    dov4=False

# can we read inputs?
nov4=False
if not os.access(v4file,os.R_OK):
    nov4=True
if dov4 and nov4:
    print(sys.stderr, "Can't read IPv4 input file " + v4file + " - exiting")
    sys.exit(1)

# can we write output?
if os.path.isfile(outfile) and not os.access(outfile,os.W_OK):
    print(sys.stderr, "Can't write onput file " + outfile + " - exiting")
    sys.exit(1)

if dov4:
    data = []
    lc=0 # lines count
    mc=0 # matching count
    v4outfile=outfile+".v4"
    of=open(v4outfile,'w')
    with open(v4file) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        writer = csv.writer(of)
        for _ in readCSV:
            if _[2]==country:
                cidr = _[0]
                data = [cidr]
                writer.writerow(data)
                mc+=1
            lc+=1
            if (lc%1000)==0:
                print(sys.stderr, "v4: read " + str(lc) + " records, " + str(mc) + " matching")
        of.close()
    print(sys.stderr, "v4: read " + str(lc) + " records, " + str(mc) + " matching")

#maybe v6?
