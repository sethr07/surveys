#!/usr/bin/python3
#
# Copyright (C) 2018-2022 Stephen Farrell, stephen.farrell@cs.tcd.ie
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
import re
import json
import csv
import os, sys
from socket import gethostbyaddr, gethostbyname
from dateutil import parser as dparser
import jsonpickle
import geoip2.database
import graphviz as gv
import itertools
import dns.resolver
import dns.query

# using a class needs way less memory than random dicts apparently
class OneFP():
    __slots__ = ['writer', 'ip_record', 'ip', 'asn', 'asndec', 'clusternum', 'fprints', 'csize', 'nrcs', 'rcs',
                 'analysis']

    def __init__(self):
        self.writer = 'unknown'
        self.ip_record = -1  # no of ips
        self.ip = ''  # ip
        self.asn = ''  # autonomous system info from mm
        self.asndec = 0
        self.clusternum = 0  # what cluster is it in
        self.fprints = {}  # fingeprints for each port
        self.csize = 1  # cluster size
        self.nrcs = 0
        self.rcs = {}
        self.analysis = {}


def printOneFP(f):
    print(jsonpickle.encode(f))


portstrings = ['p22', 'p25', 'p110', 'p143', 'p443', 'p587', 'p993']

# some "constants" for the above
KEYTYPE_UNKNOWN = 0  # initial value
KEYTYPE_RSASHORT = 1  # <1024
KEYTYPE_RSA1024 = 2  # 1024<=len<2048
KEYTYPE_RSA2048 = 3  # exactly 2048 only
KEYTYPE_RSA4096 = 4  # exactly 4096 only
KEYTYPE_ODD = 5  # anything else
KEYTYPE_ECDSA = 6  # for those oddballs
KEYTYPE_EDDSA = 6  # for those oddballs, when they start to show
KEYTYPE_OTHER = 8  # if we do find something else, e.g. EDDSA
# some "constants" for certs
CERTTYPE_UNKNOWN = 0  # initial value
CERTTYPE_GOOD = 1  # browser-trusted and timely
CERTTYPE_SC = 2  # self-cert and timely
CERTTYPE_EXPIRED = 3  # browser-trusted but not timely
CERTTYPE_SCEXPIRED = 4  # self-cert but not timely
CERTTYPE_OTHER = 5  # oddbballs, don't expect any
MAXSAN = 100  # A few certs have waaay too many sans (1500+), we're only bothering with this many at most


##########################################
# try and get memory usage of class 
def get_size(obj, seen=None):
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    return size


#############################
# Report Reuse Stuff
#############################
the_engine = 'sfdp'
the_format = 'svg'
# this is manually made symmetric around the diagonal
# variant - make all the mail colours the same
merged_nportscols = [ \
    'black', 'bisque', 'yellow', 'aquamarine', 'darkgray', 'chocolate', 'magenta', \
    'bisque', 'blue', 'blue', 'blue', 'violet', 'blue', 'blue', \
    'yellow', 'blue', 'blue', 'blue', 'coral', 'blue', 'blue', \
    'aquamarine', 'blue', 'blue', 'blue', 'darkkhaki', 'blue', 'blue', \
    'darkgray', 'violet', 'coral', 'darkkhaki', 'orange', 'darkseagreen', 'blue', \
    'turquoise', 'blue', 'blue', 'blue', 'blue', 'blue', 'blue',
    'magenta', 'blue', 'blue', 'blue', 'darkseagreen', 'blue', 'blue', ]
# new way - individual colours per port-pair  - this is manually made symmetric around the diagonal
unmerged_nportscols = [ \
    'black', 'bisque', 'yellow', 'aquamarine', 'darkgray', 'turquoise', 'magenta', \
    'bisque', 'blue', 'blanchedalmond', 'crimson', 'violet', 'wheat', 'brown', \
    'yellow', 'blanchedalmond', 'chartreuse', 'cyan', 'coral', 'yellowgreen', 'darkred', \
    'aquamarine', 'crimson', 'cyan', 'darkblue', 'darkkhaki', 'chocolate', 'darksalmon', \
    'darkgray', 'violet', 'coral', 'darkkhaki', 'orange', 'cornsilk', 'darkseagreen', \
    'turquoise', 'wheat', 'yellowgreen', 'chocolate', 'cornsilk', 'deeppink', 'deepskyblue', \
    'magenta', 'brown', 'darkred', 'darksalmon', 'darkseagreen', 'deepskyblue', 'maroon', \
    ]
# pick one of these - the first merges many mail port combos
# leading to clearer graphs, the 2nd keeps all the details
# nportscols=merged_nportscols
nportscols = unmerged_nportscols

def mask2colours(mask, colours, dynleg):
    """
    colours - return a list of logical-Or of port-specific colour settings
    """
    intmask = int(mask, 16)
    portcount = len(portstrings)
    for i in range(0, portcount):
        for j in range(0, portcount):
            cmpmask = (1 << (j + 8 * i))
            if intmask & cmpmask:
                cnum = i * len(portstrings) + j
                colcode = nportscols[cnum]
                if colcode not in colours:
                    colours.append(colcode)
                    if i > j:
                        dynleg.add(portstrings[i] + "-" + portstrings[j] + " " + colcode)
                    else:
                        dynleg.add(portstrings[j] + "-" + portstrings[i] + " " + colcode)


def mask2fewercolours(mask, colours, dynleg):
    intmask = int(mask, 16)
    portcount = len(portstrings)
    for i in range(0, portcount):
        for j in range(0, portcount):
            cmpmask = (1 << (j + 8 * i))
            if intmask & cmpmask:
                cnum = i * len(portstrings) + j
                colcode = merged_nportscols[cnum]
                if colcode not in colours:
                    colours.append(colcode)
                    # recall i and j index this: portstrings=['p22','p25','p110','p143','p443','p587','p993']
                    if i == 0 and j == 0:
                        dynleg.add("ssh" + " " + colcode)
                    elif i == 4 and j == 4:
                        dynleg.add("web" + " " + colcode)
                    elif (i == 1 or i == 2 or i == 3 or i == 5 or i == 6) and (
                            j == 1 or j == 2 or j == 3 or j == 5 or j == 6):
                        dynleg.add("mail" + " " + colcode)
                    elif i > j:
                        dynleg.add(portstrings[i] + "-" + portstrings[j] + " " + colcode)
                    else:
                        dynleg.add(portstrings[j] + "-" + portstrings[i] + " " + colcode)


def printlegend():
    """
    print the legend for the graph
    """
    leg = gv.Graph(format=the_format, engine='neato', name="legend")
    leg.attr('graph', splines='true')
    leg.attr('graph', overlap='false')
    leg.attr('edge', overlap='false')
    portcount = len(portstrings)
    c = 0
    for i in range(0, portcount):
        for j in range(0, portcount):
            cnum = i * len(portstrings) + j
            colcode = nportscols[cnum]
            portpair = portstrings[i] + "-" + portstrings[j]
            leg.edge(portstrings[i], portstrings[j], color=colcode)
    leg.render("legend.dot")


def asn2colour(asn):
    asni = int(asn)
    return '#A5A5A5' if asni == 0 else '#' + "%06X" % (asni & 0xffffff)


def ip2int(ip):
    sip = ip.split(".")
    sip = list(map(int, sip))
    iip = sip[0] * 256 ** 3 + sip[1] * 256 ** 2 + sip[2] * 256 + sip[3]
    del sip
    return iip


def edgename(ip1, ip2):
    """
    Return a string that is a unique name for an edge between two IPs
    """
    int1 = ip2int(ip1)
    int2 = ip2int(ip2)
    int3 = int2 * 2 ** 32 + int1
    del int1
    del int2
    return int3


def file_in_mem(fname):
    return len(giantbuffer) != 0


def load_file_to_mem(fname):
    global giantbuffer
    print(sys.stderr, f"Reading {fname} into RAM")
    fp = open(fname)
    giantbuffer = fp.read()
    fp.close()
    print(sys.stderr, f"Done reading {fname} into RAM")
    print(len(giantbuffer))


def readline_mem():
    global offset
    start_offset = offset
    if offset >= len(giantbuffer):
        print(sys.stderr, f"Offset {str(offset)} >= {len(giantbuffer)}!")
        return ""
    while giantbuffer[offset] != '\n':
        offset += 1
    # print "|"+giantbuffer[start_offset:offset]+"|"
    offset += 1
    return giantbuffer[start_offset:offset]


def getnextfprint_mem(fname):
    """
    as above, but first read entire file into memory and 
    handle it there
    read the next fingerprint from the file pointer
    fprint is a json structure, pretty-printed, so we'll
    read to the first line that's just an "{" until
    the next line that's just a "}"
    or... sometimes we might get one fp structure per line
    surrounded with a '[' at the top and a ']' at
    the end, in that case fps are separated with a 
    line containing a single comma, i.e. ",\n"
    the first thing on fp lines in such cases is
    '{"fprints":' so we'll take such a line as holding
     an entire json fp
    """
    
    if not file_in_mem(fname):
        load_file_to_mem(fname)

    magicfpstrs = ['{"fprints":', \
                   '{"py/object": "SurveyFuncs.OneFP", "fprints":']
    line = readline_mem()
    indented = False
    while line:
        # print "preline:", line
        if line == "{\n":
            break
        if line == "  {\n":
            indented = True
            break
        if re.match("\s*{\s*", line) is not None:
            break
        for ms in magicfpstrs:
            if line.startswith(ms):
                # print ms
                foo = line.strip()
                if foo.endswith("},"):
                    # print "stripping"
                    foo = foo[:-1]
                # print foo.strip()
                jthing = json.loads(foo.strip())
                onething = j2o(jthing)
                del jthing
                return onething
        line = readline_mem()
    jstr = ""
    while line:
        # print "postline:", line
        jstr += line
        if not indented and line == "}\n":
            break
        # note - indented version here is due to other tooling, not v. predictable 
        # and it has an extra space after the closing brace for some reason
        if indented and (line == "  } \n" or line == "  }\n" or line == "  } \n"):
            break
        if (not indented and line == "},\n") or (indented and line == "  }, \n"):
            # same as above but take away the "," at the end
            # print "|"+jstr[-10:]+"|"
            jstr = jstr.strip()
            jstr = jstr.strip(',')
            # print "|"+jstr[-10:]+"|"
            break
        line = readline_mem()
    if line:
        # print jstr
        jthing = json.loads(jstr)
        onething = j2o(jthing)
        del jthing
        return onething
    else:
        return line


########################################
# Stuff for finding collisions
########################################
def indexport(index):
    """
    Returns the port string for the given index.
    """
    return portstrings[index]

def portindex(pname):
    """
    Returns the index of the port with the given name.
    """
    for pind in range(len(portstrings)):
        if portstrings[pind] == pname:
            return pind
    print(sys.stderr, f"Error - unknown port: {pname}")
    return -1


def collmask(mask, k1, k2):
    """
    Returns the collision mask for the given two keys.
    """
    try:
        lp = portindex(k1)
        rp = portindex(k2)
        intmask = int(mask, 16)
        intmask |= (1 << (rp + 8 * lp))
        newmask = "0x%016x" % intmask
    except Exception as e:
        print(sys.stderr, "collmask exception, k1: " + k1 + " k2: " + k2 + " lp:" + str(lp) + " rp: " + str(
            rp) + " exception: " + str(e))
        pass
    return newmask


def expandmask(mask):
    emask = ""
    intmask = int(mask, 16)
    portcount = len(portstrings)
    for i, j in itertools.product(range(portcount), range(portcount)):
        cmpmask = (1 << (j + 8 * i))
        if intmask & cmpmask:
            emask += f'{indexport(i)}=={indexport(j)};'
    return emask


########################################
# Stuff for reading fprints json file
########################################
def j2o(jthing):
    ot = OneFP()
    # print json.dumps(jthing)
    ot.ip = jthing['ip']
    ot.ip_record = jthing['ip_record']
    ot.writer = jthing['writer']
    ot.asn = jthing['asn']
    ot.asndec = jthing['asndec']
    ot.clusternum = jthing['clusternum']
    ot.fprints = jthing['fprints']
    ot.csize = jthing['csize']
    ot.nrcs = jthing['nrcs']
    ot.rcs = jthing['rcs']
    ot.analysis = jthing['analysis']
    # printOneFP(ot)
    return ot


def getnextfprint(fp):
    """
    read the next fingerprint from the file pointer
    fprint is a json structure, pretty-printed, so we'll
    read to the first line that's just an "{" until
    the next line that's just a "}"
    or sometimes we might get one fp structure per line
    surrounded with a '[' at the top and a ']' at
    the end, in that case fps are separated with a 
    line containing a single comma, i.e. ",\n"
    the first thing on fp lines in such cases is
    '{"fprints":' so we'll take such a line as holding
    an entire json fp
    """
    magicfpstrs = ['{"fprints":', \
                   '{"py/object": "SurveyFuncs.OneFP", "fprints":']
    line = fp.readline()
    indented = False
    while line:
        # print "preline:", line
        if line == "{\n":
            break
        if line == "  {\n":
            indented = True
            break
        if re.match("\s*{\s*", line) is not None:
            break
        for ms in magicfpstrs:
            if line.startswith(ms):
                # print ms
                foo = line.strip()
                if foo.endswith("},"):
                    # print "stripping"
                    foo = foo[:-1]
                # print foo.strip()
                jthing = json.loads(foo.strip())
                onething = j2o(jthing)
                del jthing
                return onething
        line = fp.readline()
    jstr = ""
    while line:
        # print "postline:", line
        jstr += line
        if not indented and line == "}\n":
            break
        # note - indented version here is due to other tooling, not v. predictable 
        # and it has an extra space after the closing brace for some reason
        if indented and (line == "  } \n" or line == "  }\n" or line == "  } \n"):
            break
        if (not indented and line == "},\n") or (indented and line == "  }, \n"):
            # same as above but take away the "," at the end
            # print "|"+jstr[-10:]+"|"
            jstr = jstr.strip()
            jstr = jstr.strip(',')
            # print "|"+jstr[-10:]+"|"
            break
        line = fp.readline()
    if line:
        # print jstr
        jthing = json.loads(jstr)
        onething = j2o(jthing)
        del jthing
        return onething
    else:
        return line


########################################
########################################
# Data Analysis Stuff 
########################################
def fqdn_bogon(dn):
    """
    check if supposed domain name is a bogon so as to avoid
    doing e.g. DNS checks
    """
    try:
        # if there are no dots, for us, it's bogus
        if dn.find('.') == -1:
            return True
        # if it ends-with ".internal" it's bogus
        if dn.endswith(".internal"):
            return True
        # if it ends-with ".example.com" it's bogus
        if dn.endswith("example.com"):
            return True
        # if it ends-with ".localdomain" it's bogus
        if dn.endswith(".localdomain"):
            return True
        # if it ends-with ".local" it's bogus
        if dn.endswith(".local"):
            return True
        # if it ends-with ".arpa" it's bogus
        if dn.endswith(".arpa"):
            return True
        # if it's ESMTP it's bogus
        if dn == "ESMTP":
            return True
        # wildcards are also bogons
        if dn.find('*') != -1:
            return True
    except:
        return True
    return False

# Stuff for parsing out info from zgrab2 output.
def check_cert_validity(before, after, scandate):
    """
    analyse the tls details - this ought to work for other ports as well 
    as p25. Xcandate is needed to check if cert was expired at time of scan
    """
    if before <= scandate < after:
        return True
    elif before > scandate or after < scandate:
        return False
    else:
        return None


def get_tls(writer, portstr, tls, ip, tlsdets, scandate):
    """
     we'll put each in a try/except to set true/false values
     would chain work in browser two flavours of TLS struct - one from Censys and one from local zgrabs
     first is the local variant, 2nd censys.io
    """
    try:
        if writer == 'FreshGrab.py':
            data_parsed = tls['handshake_log']['server_certificates']['certificate']['parsed']
            tlsdets['cipher_suite'] = tls['handshake_log']['server_hello']['cipher_suite']['value']
            tlsdets['browser_trusted'] = tls['handshake_log']['server_certificates']['validation']['browser_trusted']
            tlsdets['self_signed'] = data_parsed['signature']['self_signed']
            notbefore = dparser.parse(data_parsed['validity']['start'])
            notafter = dparser.parse(data_parsed['validity']['end'])
            try:
                spki = data_parsed['subject_key_info']
                if spki['key_algorithm']['name'] == 'RSA':
                    tlsdets['rsalen'] = spki['rsa_public_key']['length']
                elif spki['key_algorithm']['name'] == 'ECDSA':
                    tlsdets['ecdsacurve'] = spki['ecdsa_public_key']['curve']
                else:
                    tlsdets['spkialg'] = spki['key_algorithm']['name']
            except:
                print(sys.stderr, "RSA exception for ip: " + ip + "spki:" + \
                      str(tls['server_certificates']['certificate']['parsed']['subject_key_info']))
                tlsdets['spkialg'] = "unknown"
        else:
            # censys.io
            tlsdets['cipher_suite'] = int(tls['cipher_suite']['id'], 16)
            tlsdets['browser_trusted'] = tls['validation']['browser_trusted']
            tlsdets['self_signed'] = tls['certificate']['parsed']['signature']['self_signed']
            notbefore = dparser.parse(tls['certificate']['parsed']['validity']['start'])
            notafter = dparser.parse(tls['certificate']['parsed']['validity']['end'])

            try:
                spki = tls['certificate']['parsed']['subject_key_info']
                if spki['key_algorithm']['name'] == 'rsa':
                    tlsdets['rsalen'] = spki['rsa_public_key']['length']
                elif spki['key_algorithm']['name'] == 'ECDSA':
                    tlsdets['ecdsacurve'] = spki['ecdsa_public_key']['curve']
                else:
                    tlsdets['spkialg'] = spki['key_algorithm']['name']
            except:
                print(sys.stderr, "RSA exception for ip: " + ip + "spki:" + \
                      str(tls['server_certificates']['certificate']['parsed']['subject_key_info']))
                tlsdets['spkialg'] = "unknown"

        tlsdets['timely'] = check_cert_validity(notbefore, notafter, scandate)
        # tlsdets['ip']=ip
    except Exception as e:
        print(sys.stderr, "get_tls exception for " + ip + ":" + portstr + str(e))
        pass
    return True


def dn2cn(dn):
    """
     Extract a CN= from a DN, if present - moar curses on the X.500 namers!
     mind you, X.500 names were set in stone in 1988 so it's a bit late. 
      Pity we still use 'em though. 
      dn = distinguished name
    """
    try:
        start_needle = "CN="
        start_pos = dn.find(start_needle)
        if start_pos == -1:
            # no commonName there... bail
            return ''
        start_pos += len(start_needle)
        end_needle = ","
        end_pos = dn.find(end_needle, start_pos)
        if end_pos == -1:
            end_pos = len(dn)
        cnstr = dn[start_pos:end_pos]
        # print "dn2cn " + cnstr + " d: " + dn + " s: " + str(start_pos) + " e: " + str(end_pos)
    except Exception as e:
        print(sys.stderr, f"dn2cn exception {str(e)}")
        return ''
    return cnstr


def check_no_sans(sans, nameset):
    """
    checks number of sans for each port
    stops if sans exceed MAXSAN
    """
    count = 0
    for _ in sans:
        nameset[+'san' + str(count)] = sans[count]
        count += 1
        if count > MAXSAN:
            toobig = str(len(sans))
            nameset['san' + str(count + 1)] = "Bollox-eoo-many-sans-1-" + toobig
            print(sys.stderr, "Too many bleeding ( " + toobig + ") sans ")
            break


def get_certnames(portstring, cert, nameset):
    try:
        dn = cert['parsed']['subject_dn']
        dn_fqdn = dn2cn(dn)
        nameset[f'{portstring}dn'] = dn_fqdn
    except Exception as e:
        # print (sys.stderr, "FQDN dn exception " + str(e) + " for record:" + str(count))
        pass
    # name from cert SAN
    try:
        sans = cert['parsed']['extensions']['subject_alt_name']
        san_fqdns = sans['dns_names']
        # we ignore all non dns_names - there are very few in our data (maybe 145 / 12000)
        # and they're mostly otherName with opaque OID/value so not that useful. (A few
        # are emails but we'll skip 'em for now)
        # print (f"FQDN san {str(san_fqdns)}") 
        check_no_sans(san_fqdns, nameset)
    except Exception as e:
        # these are v. common
        # print (sys.stderr, "FQDN san exception " + str(e) + " for record:" + str(count))
        pass
    return


def get_p25(data, banner):
    """
    get p25 banner or datat depending on banner flag
    """
    if banner:
        banner = data['data']['smtp']['result']['banner']
        ts = banner.split()
        if ts[0] == "220":
            banner_fqdn = ts[1]
        elif ts[0].startswith("220-"):
            banner_fqdn = ts[0][4:]
        return banner_fqdn
    else:
        cert = data['handshake_log']['server_certificates']['certificate']
        fp = cert['parsed']['subject_key_info']['fingerprint_sha256']
        return cert, fp


def get_p25_cens(data):
    """
    get p25 censys data - not verified
    """
    cert = data['certificate']
    fp = cert['parsed']['subject_key_info']['fingerprint_sha256']
    return cert, fp


def get_p22(data):
    """
    get p22 data
    """
    shk = data['result']['key_exchange']['server_host_key']
    fp = shk['fingerprint_sha256']
    return shk, fp


def get_p443(data):
    """
    get p443 data
    """
    cert = data['handshake_log']['server_certificates']['certificate']
    fp = cert['parsed']['subject_key_info']['fingerprint_sha256']
    return cert, fp


def get_p443_cens(data):
    """
    get p443 censys data - not verified
    """
    cert = data['certificate']
    fp = cert['parsed']['subject_key_info']['fingerprint_sha256']
    return cert, fp


########################################
# MaxMind Stuff 
########################################
mmdbpath = 'code/surveys/mmdb/'
mmdbdir = os.environ['HOME'] + '/' + mmdbpath


def mm_setup():
    """
    setup maxmind db
    """
    global asnreader
    global cityreader
    global countryreader
    global countrycodes
    countrycodes = []
    asnreader = geoip2.database.Reader(f'{mmdbdir}GeoLite2-ASN.mmdb')
    cityreader = geoip2.database.Reader(f'{mmdbdir}GeoLite2-City.mmdb')
    countryreader = geoip2.database.Reader(f'{mmdbdir}GeoLite2-Country.mmdb')
    with open(f'{mmdbdir}countrycodes.csv') as ccf:
        lines = csv.reader(ccf)
        countrycodes.extend(iter(lines))
        ccf.close


def mm_info(ip):
    """
    get info about ip from maxmind db
    """
    rv = {'ip': ip}
    try:
        extract_from_mm(ip, rv)
    except Exception as e:
        print(sys.stderr, f"mm_info exception for: {ip}{str(e)}")
        rv['asndec'] = 'unknown'
        rv['asn'] = -1
        rv['cc'] = 'unknown'
        rv['cc-city'] = 'unknown'
    return rv


def extract_from_mm(ip, rv):
    """
    extract info from maxmind db
    """
    asnresponse = asnreader.asn(ip)
    rv['asndec'] = asnresponse.autonomous_system_number
    rv['asn'] = asnresponse.autonomous_system_organization
    cityresponse = cityreader.city(ip)
    countryresponse = countryreader.country(ip)
    rv['lat'] = cityresponse.location.latitude
    rv['long'] = cityresponse.location.longitude
    print("\n\n")
    rv['cc'] = cityresponse.country.iso_code
    if cityresponse.country.iso_code != countryresponse.country.iso_code:
        rv['cc-city'] = cityresponse.country.iso_code


def mm_ipcc(ip, cc):
    """
    cross check ip info from maxmind db
    """
    if cc == "XX":
        return True
    countryresponse = countryreader.country(ip)
    return cc == countryresponse.country.iso_code


def get_rdns(ip, nameset):
    """
    get reverse dns for ip
    """
    try:
        rdns = gethostbyaddr(ip)[0]
        nameset['rdns'] = rdns
    except Exception as e:
        print(sys.stderr, f"FQDN reverse exception {str(e)} for record:{ip}")

# trying out with stubby + unbound 
# did a test on two machines - this setup supposedely much faster
def get_dns(host, ip):
    """
    get dns for host
    """
    try:
        return gethostbyname(host)
    except Exception as e:
        print(sys.stderr, f"Error making DNS query for {host} for ip:{ip} {str(e)}")


# Fast DNS options - might try multithreading with existing one.
# definitely much quicker than socket - avg time/ip = 0.4s as compared to 3s with socket
def get_dns_py(host, ip):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    try:
        ip = resolver.query(host, 'a')
        for val in ip:
            return val.to_text()
    except Exception as e:
        print(f"Error making DNS Query for {str(ip)}{str(e)}")

########################################
