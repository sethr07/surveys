#!/usr/bin/python3
#
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
#
# Report the collisions, via graphs and text

import sys
import os
import tempfile
import gc
import copy
import argparse
import time, datetime
from dateutil import parser as dparser  # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons
from pympler import asizeof
from SurveyFuncs import *
# install via  "$ sudo pip install -U jsonpickle"
import jsonpickle
# direct to graphviz ...
import graphviz as gv

# if > this number of nodes we simplify graphing by not making edges
# for specific ports, but just mail,web,ssh etc.
toobiggraph=10
# default output directory

#NB:
# need to test dir with skey-all.sh
outdir = "graphs"

# graph rendering func
def rendergraph(cnum,gvgraph,dynleg,legendwanted,odir,dorender):
    #print "Graphing cluster: " + str(cnum)
    # optional legend...
    if legendwanted:
        lgr=gv.Graph(name="legend",node_attr={'shape': 'box'})
        lgr.attr('graph',rank="source")
        lgr.node("Cluster " + str(cnum))
        #print "with legend" + str(dynleg)
        for leg in dynleg:
            ss=leg.split()
            lgr.node(ss[0],label=ss[0],color=ss[1])
        gvgraph.subgraph(lgr)
    # render if not too big... this can fail due to graphviz bugginess (I assume)
    try:
        glen=len(gvgraph.source)
        if not dorender or glen > maxglen:
            if dorender:
                print(sys.stderr, "Not rendering graph for cluster "+ str(cnum) + " - too long: " + str(glen))
            gvgraph.save(odir + "/graph"+str(cnum)+".dot")
            if not dorender:
                return True
            else:
                return False
        else:
            gvgraph.render(odir + "/graph"+str(cnum)+".dot")
            return True
    except Exception as e: 
        print (sys.stderr, "Ecxeption rendering cluster: " + str(cnum)) 
        print (sys.stderr, "Exception: " + str(e))
        print (sys.stderr, "Maybe you got bored and killed a process?")
        return False

# command line arg handling 
parser=argparse.ArgumentParser(description='Graph the collisions found by SameKeys.py')
parser.add_argument('-f','--file',     
                    dest='fname',
                    help='json file containing key fingerprint collisions')
parser.add_argument('-o','--output_dir',     
                    dest='outdir',
                    help='directory in which to put (maybe many) graph files')
parser.add_argument('-l','--legend',
                    help='include a legend on each graph, or just create ./legend.dot.svg if no other args',
                    action='store_true')
parser.add_argument('-n','--neato',
                    help='switch to neato graphviz thing (default=sfdp)',
                    action='store_true')
parser.add_argument('-g','--rendergraph',     
                    help='include generation of graphic form of cluster graph',
                    action='store_true')
parser.add_argument('-c','--country',     
                    dest='country',
                    help='country in which we\'re interested')
parser.add_argument('-a','--anonymise',     
                    help='replace IP in graphs with index',
                    action='store_true')
parser.add_argument('-r','--restart',     
                    help='restart from a previous run (don\'t overwrite cluster files)',
                    action='store_true')
args=parser.parse_args()

# default render graphs == off (due to diskspace)
dorendergraph=False
# if this then just print legend
if args.rendergraph:
    dorendergraph=True

print ("Dorender=",dorendergraph)

doanon=False
if args.anonymise:
    doanon=True

# default country 
def_country='IE'
country=def_country
if args.country is not None:
    country=args.country

# if this then just print legend
if args.fname is None and args.legend:
    print (args)
    printlegend()
    sys.exit(0)

fname="collisions.json"
if args.fname is not None:
    fname=args.fname

if args.outdir:
    outdir=args.outdir

if args.neato:
    the_engine='neato'

# checks - can we write to outdir...
try:
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    testfile = tempfile.TemporaryFile(dir = outdir)
    testfile.close()
except Exception as e:
    print (sys.stderr, "Can't create output directory " + outdir + " - exiting:" + str(e))
    sys.exit(1)

if not os.access(outdir,os.W_OK):
    print (sys.stderr, "Can't write to output directory " + outdir + " - exiting")
    sys.exit(1)

# main line processing ...

# we need to pass over all the fingerprints to make a graph for each
# cluster, note that due to cluster merging (in SameKeys.py) we may
# not see all cluster members as peers of the first cluster member

# ipdone and edgedone are ok to be global as each ip is only in one
# cluster and hence same with edges
# need to be careful with memory for the edges - on EE data those
# seem to explode
#ipdone=set()
ipdone=[]
edgedone=set()

checkcount=0
grr={}
dynlegs={}
actualcnums=[]
# a list of graphs we didn't end up rendering
notrendered=[]
clustercount=0
# a count of how many ips we've done for each cluster
clipsdone={}

# cluster report strings
creps={}

# max size of dot file we try to render
maxglen=500000

# playing with this to see if we get better perf
#domem=True
domem=False

# open file
if domem==False:
    fp=open(fname,"r")

# on one host (with python 2.7.12) it seems that I need to
# first set the options for the json backend before doing
# it for the simplejson backend. Without this, the json
# is output with one line per encooded thing, which breaks
# later tooling.
# on another (with python 2.7.14) just the 2nd call is 
# enough to get the indentation correct. 
# bit odd but whatever works I guess;-)
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)

def nfp():
    return getnextfprint_mem(fname) if domem else getnextfprint(fp)

#f=getnextfprint(fp)
f=nfp()
while f:
    cnum=f.clusternum
    # if in re-start mode, skip this one if the relevant clusterfile exists
    # in the CWD
    if args.restart and os.path.exists("cluster"+str(cnum)+".json"):
        print (sys.stderr, "Skipping  cluster " + str(cnum) + " as restart mode set")
        # read next fp
        checkcount += 1
        del f
        #f=getnextfprint(fp)
        f=nfp()
        continue
    if cnum in clipsdone and clipsdone[cnum]==-1:
        print (sys.stderr, "Rendered cluster " + str(cnum) + " already")
        # read next fp
        checkcount += 1
        del f
        #f=getnextfprint(fp)
        f=nfp()
        continue
    dynleg=set()
    edgesadded=0
    csize=f.csize
    nrcs=f.nrcs
    if cnum>=0 and nrcs>0:
        newgraph=False
        if cnum not in actualcnums:
            clustercount += 1
            newgraph=True
            actualcnums.append(cnum)
            gvgraph=gv.Graph(format=the_format,engine=the_engine)
            gvgraph.attr('graph',splines='true')
            gvgraph.attr('graph',overlap='false')
            grr[cnum]=gvgraph
            if args.legend:
                dynlegs[cnum]=dynleg
            #print >>sys.stderr, "\tnew graph for cluster " + str(cnum) + " size is: " + str(asizeof.asizeof(gvgraph))
            print (sys.stderr, "New graph for cluster " + str(cnum)) 
        else:
            gvgraph=grr[cnum]
            if args.legend:
                dynleg=dynlegs[cnum]

        # figure colour for node for this fingerprint based on ASN
        if f.asndec==0 and f.asn=="unknown":
            # look that chap up ourselves
            mm_inited=False
            if not mm_inited:
                mm_setup()
                mm_inited=True
            asninfo=mm_info(f.ip)
            #print "fixing up asn info",asninfo
            f.asn=asninfo['asn']
            f.asndec=asninfo['asndec']
            if asninfo['cc'] != country:
                # TODO: what to actually if the country-code is (now) wrong?
                print (sys.stderr, "Bad country for ip",f.ip,"ASN-CC:",asninfo['cc'],"Asked for CC:",country)

        asncol=asn2colour(f.asndec)
        mainind=str(len(ipdone))
        # have we processed this node already?
        if f.ip not in ipdone:
            if doanon:
                gvgraph.node(mainind,color=asncol,style="filled")
            else:
                gvgraph.node(f.ip,color=asncol,style="filled")
            #ipdone.add(f.ip)
            ipdone.append(f.ip)
        else:
            mainind=str(ipdone.index(f.ip))

        # process peers ("key sharers") for this node
        for recn in f.rcs:
            cip=f.rcs[recn]['ip']
            ename=edgename(f.ip,cip)
            backename=edgename(cip,f.ip)
            cind=str(len(ipdone))
            if cip not in ipdone:
                try:
                    ccol=asn2colour(f.rcs[recn]['asndec'])
                    if doanon:
                        gvgraph.node(cind,color=ccol,style="filled")
                    else:
                        gvgraph.node(cip,color=ccol,style="filled")
                except:
                    if doanon:
                        gvgraph.node(cind,color=asncol,style="filled")
                    else:
                        gvgraph.node(cip,color=asncol,style="filled")
                #ipdone.add(cip)
                ipdone.append(cip)
            else:
                cind=str(ipdone.index(cip))

            # add edge for that to this
            if ename not in edgedone and backename not in edgedone:
                colours=[]
                if csize > toobiggraph:
                    #print "Simplifying graph for cluseer " + str(cnum)
                    mask2fewercolours(f.rcs[recn]['ports'],colours,dynleg)
                else:
                    mask2colours(f.rcs[recn]['ports'],colours,dynleg)
                for col in colours:
                    if doanon:
                        gvgraph.edge(mainind,cind,color=col)
                    else:
                        gvgraph.edge(f.ip,cip,color=col)
                edgedone.add(ename)
                edgesadded+=len(colours)
                del colours

    fstr=jsonpickle.encode(f)
    if cnum not in creps:
        creps[cnum]="[\n" + fstr 
    else:
        creps[cnum]+= ",\n" + fstr 

    if cnum in clipsdone:
        clipsdone[cnum] += 1
        if clipsdone[cnum]%100==0:
            print (sys.stderr, "\tsizeof graph for cluster " + str(cnum) +  \
                "  with " + str(clipsdone[cnum]) + " of " + str(csize) +  \
                " done is: " + str(asizeof.asizeof(gvgraph)) +  \
                " legend:"  + str(asizeof.asizeof(dynleg)) +   \
                " Added " + str(edgesadded) + " edges")
        if clipsdone[cnum] == csize:
            try:
                repf=open("cluster"+str(cnum)+".json","w")
                repf.write(creps[cnum])
                nl="\n]\n"
                repf.write(nl)
                repf.write(creps[cnum])
                repf.write("\n]\n")
                #print (creps[cnum])
                #print ("\n]\n")
                repf.close()
                del creps[cnum]
                clipsdone[cnum] = -1
                print (sys.stderr, "Wrote cluster"+str(cnum)+".json")
            except:
                print (sys.stderr, "Failed to write json file for cluster " + str(cnum))

            rv=rendergraph(cnum,gvgraph,dynleg,args.legend,outdir,dorendergraph)
            if rv:
                print ("Rendered graph for cluster " + str(cnum))
                del grr[cnum]
            else:
                notrendered.append(cnum)
                print (sys.stderr, "Failed to graph cluster " + str(cnum))
    else:
        clipsdone[cnum] = 1


    if not args.legend:
        del dynleg

    # print something now and then to keep operator amused
    now=datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
    checkcount += 1
    if checkcount % 100 == 0:
        print (sys.stderr, "Creating graphs, fingerprint: " + str(checkcount) + " most recent cluster " + str(cnum) + \
                    " IPs: " + str(len(ipdone)) + " edges: " + str(len(edgedone)) + " #clusters: " + str(len(actualcnums)) + \
                    " at: " + str(now))
    if checkcount % 1000 == 0:
        gc.collect()

    # read next fp
    del f
    #f=getnextfprint(fp)
    f=nfp()

# close file
if domem==False:
    fp.close()

del grr

summary_fp=open(outdir+"/summary.txt","a+")
summary_fp.write("collisions: " + str(checkcount) + "\n\t" + \
        "total clusters: " + str(clustercount) + "\n\t" + \
        "graphs not rendered: " + str(notrendered))
summary_fp.close()

print (sys.stderr, "collisions: " + str(checkcount) + "\n\t" + \
        "total clusters: " + str(clustercount) + "\n\t" + \
        "graphs not rendered: " + str(notrendered))