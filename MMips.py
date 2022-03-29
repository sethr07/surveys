#!/usr/bin/python3
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
#script for making GeipCountrywhois csv for input to zmap
import os
import pandas as pd
#directories and files
indir=os.environ['HOME']+'/code/surveys/mmdb/'
v4file=indir+'GeoLite2-Country-Blocks-IPv4.csv'
localefile = indir+'GeoLite2-Country-Locations-en.csv'
outfile = indir+'GeoIPCountryWhois.csv'

v4file = pd.read_csv(v4file)
v4file = v4file.drop(v4file.columns[[2,3,4,5]], axis=1)
geoip = pd.read_csv(localefile)
geoip = geoip.drop(geoip.columns[[1,2,3,6]], axis=1)
final_csv = v4file.merge(geoip, how='left', on="geoname_id")
final_csv.to_csv(outfile, index=False)
