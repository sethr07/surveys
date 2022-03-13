import re
import json
import jsonpickle
import copy
import os, sys, socket
import geoip2.database

# using a class needs way less memory than random dicts apparently
class OneFP():
    __slots__ = [   'writer',
                    'ip_record',
                    'ip',
                    'asn',
                    'asndec',
                    'fprints',
                    'csize',
                    'nsrc',
                    'rcs',
                    'analysis']
    def __init__(self):
        self.writer='unknown'
        self.ip_record=-1
        self.ip=''
        self.asn=''
        self.asndec=0
        self.clusternum=0
        self.fprints={}
        self.csize=1
        self.nrcs=0
        self.rcs={}
        self.analysis={}

# some "constants" for the above
KEYTYPE_UNKNOWN=0           # initial value
KEYTYPE_RSASHORT=1          # <1024
KEYTYPE_RSA1024=2           # 1024<=len<2048
KEYTYPE_RSA2048=3           # exactly 2048 only
KEYTYPE_RSA4096=4           # exactly 4096 only
KEYTYPE_ODD=5               # anything else
KEYTYPE_ECDSA=6             # for those oddballs
KEYTYPE_EDDSA=6             # for those oddballs, when they start to show
KEYTYPE_OTHER=8             # if we do find something else, e.g. EDDSA

# some "constants" for certs
CERTTYPE_UNKNOWN=0          # initial value
CERTTYPE_GOOD=1             # browser-trusted and timely
CERTTYPE_SC=2               # self-cert and timely
CERTTYPE_EXPIRED=3          # browser-trusted but not timely
CERTTYPE_SCEXPIRED=4        # self-cert but not timely
CERTTYPE_OTHER=5            # oddbballs, don't expect any

# A few certs have waaay too many sans (1500+), we're only bothering with this
# many at most
MAXSAN=100

portstrings=['p22','p25','p110','p143','p443','p587','p993']


def printOneFP(f):
    print (jsonpickle.encode(f))

def j2o(jthing):
    ot=OneFP()
    #print json.dumps(jthing)
    ot.ip=jthing['ip']
    ot.ip_record=jthing['ip_record']
    ot.writer=jthing['writer']
    ot.asn=jthing['asn']
    ot.asndec=jthing['asndec']
    ot.clusternum=jthing['clusternum']
    ot.fprints=jthing['fprints']
    ot.csize=jthing['csize']
    ot.nrcs=jthing['nrcs']
    ot.rcs=jthing['rcs']
    ot.analysis=jthing['analysis']
    #printOneFP(ot)
    return ot

###########################
# Functions for getting same keys
###########################
def getnextfprint(fp):
    # read the next fingerprint from the file pointer
    # fprint is a json structure, pretty-printed, so we'll
    # read to the first line that's just an "{" until
    # the next line that's just a "}"
    # or...
    # sometimes we might get one fp structure per line
    # surrounded with a '[' at the top and a ']' at
    # the end, in that case fps are separated with a 
    # line containing a single comma, i.e. ",\n"
    # the first thing on fp lines in such cases is
    # '{"fprints":' so we'll take such a line as holding
    # an entire json fp
    magicfpstrs= ['{"fprints":', \
                    '{"py/object": "SurveyFuncs.OneFP", "fprints":' ]
    line=fp.readline()
    indented=False
    while line:
        #print "preline:", line
        if line=="{\n":
            break
        if line=="  {\n":
            indented=True
            break
        if re.match("\s*{\s*",line) is not None:
            break
        for ms in magicfpstrs:
            if line.startswith(ms):
                #print ms
                foo=line.strip()
                if foo.endswith("},"):
                    #print "stripping"
                    foo=foo[:-1]
                #print foo.strip()
                jthing=json.loads(foo.strip())
                onething=j2o(jthing)
                del jthing
                return onething
        line=fp.readline()
    jstr=""
    while line:
        #print "postline:", line
        jstr += line
        if not indented and line=="}\n": 
            break
        # note - indented version here is due to other tooling, not v. predictable 
        # and it has an extra space after the closing brace for some reason
        if indented and (line=="  } \n" or line=="  }\n"  or  line=="  } \n"): 
            break
        if (not indented and line=="},\n") or (indented and line=="  }, \n"):
            # same as above but take away the "," at the end
            #print "|"+jstr[-10:]+"|"
            jstr=jstr.strip()
            jstr=jstr.strip(',')
            #print "|"+jstr[-10:]+"|"
            break
        line=fp.readline()
    if line:
        #print jstr
        jthing=json.loads(jstr)
        onething=j2o(jthing)
        del jthing
        return onething
    else:
        return line

###########################
# MaxMind Stuff 
###########################
mmdbpath = 'code/surveys/mmdb/'
mmdbir = os.environ['HOME'] + '/' + mmdbpath

#sets up API calls in mmdb directory
def mm_setup():
    global asnreader
    global cityreader
    global countryreader
    global countrycodes

    asnreader = geoip2.database.Reader(mmdbir + 'GeoLite2-ASN.mmdb')
    cityreader = geoip2.database.Reader(mmdbir + 'GeoLite2-City.mmdb')
    countryreader = geoip2.database.Reader(mmdbir + 'GeoLite2-Country.mmdb')
    countrycodes = []

    with open(mmdbir + 'countrycodes.csv') as ccf:
        for line in ccf:
            cc = line.strip()
            countrycodes.append(cc)
        ccf.close

#returns back the ip address information in the database
def mm_info(ip):
    rv = {}
    rv['ip'] = ip
    try:
        asnresponse = asnreader.asn(ip)
        rv['asndec']=asnresponse.autonomous_system_number
        rv['asn']=asnresponse.autonomous_system_organization
        cityresponse=cityreader.city(ip)
        countryresponse=countryreader.country(ip)
        rv['lat']=cityresponse.location.latitude
        rv['long']=cityresponse.location.longitude
        print("\n\n")
        rv['cc']=cityresponse.country.iso_code

        if cityresponse.country.iso_code != countryresponse.country.iso_code:
            rv['cc-city']=cityresponse.country.iso_code
    
    except Exception as e:
        print(sys.stderr, "mm_info exception for: " + ip + str(e))
        rv['asndec']='unknown'
        rv['asn']=-1
        rv['cc']='unknown'
        rv['cc-city']='unknown'
    
    return rv

#checks for ip against country using mmdb databases
def mm_ipcc(ip, cc):
    if cc == "XX":
        return True
    elif cc not in countrycodes:
        countryresponse = countryreader.country(ip)
        if cc == countryresponse.country.iso_code:
            return True
        else:
            return False
    else:
        return False
###########################



    

