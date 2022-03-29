#!/bin/bash
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
##################################
#Script that setups the maxmind directory.
#Installs mmdb databases - asn, city, country
#Installs Country csvs 
#installs country codes
#Calls python script for creating GeoIPWHoisCountry.csv

echo "Setting up MaxMind API"
CURRDIR=$HOME/code/surveys
dpath=`grep mmdbpath $HOME/code/surveys/SurveyFuncs.py  | head -1 | awk -F\' '{print $2}' | sed -e 's/\/$//'`
DESTDIR=$HOME/$dpath

if [ ! -d $DESTDIR ]
then
	mkdir -p $DESTDIR
fi
if [ ! -d $DESTDIR ]
then
	echo "Can't create $DESTDIR - exiting"
	exit 11
fi

cd $DESTDIR

#you might need to change this location depening on your setup
#get your key from maxmind website
KEYFILE="$HOME/mm-key.txt"
if [ ! -f $KEYFILE ]
then
    echo "No $KEYFILE - exiting"
    exit 1
fi
key=`cat $KEYFILE`

for db in City Country ASN
do
	tarball="GeoLite2-$db.tar.gz"
	url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-$db&license_key=$key&suffix=tar.gz"
	echo "Getting $url"
	wget -q $url -O $tarball
	if [ "$?" != "0" ]
	then
		echo "Failed to download $url"
	else
		tar xzvf $tarball
		dbdate=`ls -d "GeoLite2-$db"_* | awk -F"_" '{print $2}'`
		dirname="GeoLite2-$db"_"$dbdate"
		fname="GeoLite2-$db"
		cp $dirname/$fname.mmdb $DESTDIR/$fname-$dbdate.mmdb
		# update link
		ln -sf $DESTDIR/$fname-$dbdate.mmdb $DESTDIR/$fname.mmdb
		rm -f $tarball
	fi
done

#get csv file to make GeoIPcountry csv file
now=`date +%Y%m%d`
csv_url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=$key&suffix=zip"
zip="geoip_download?edition_id=GeoLite2-Country-CSV&license_key=$key&suffix=zip"
wget $csv_url
unzip $zip
rm -f $zip

echo "Getting Country Codes file"
cc_url="https://dev.maxmind.com/static/csv/codes/iso3166.csv?lang=en"
wget $cc_url
cc_file="iso3166.csv?lang=en"
cc_fname="cc.csv"
cp $cc_file $cc_fname
rm -f $cc_file
# delete country name coloumn and make a new csv - just need country code
awk -F "\"*,\"*" '{print $1}' cc.csv > countrycodes.csv
rm -f $cc_fname

echo "Getting data from GeoCountryWhois.csv"
dbdate=`ls -d "GeoLite2-Country-CSV"_* | awk -F"_" '{print $2}'`
dirname="GeoLite2-Country-CSV_$dbdate"
fname1="GeoLite2-Country-Blocks-IPv4.csv"
fname2="GeoLite2-Country-Locations-en.csv"
cp $dirname/$fname1 $DESTDIR/$fname1
cp $dirname/$fname2 $DESTDIR/$fname2

echo "Creating csv file of ips country wise"
$CURRDIR/MMCreateGeoIP.py
rm -f $fname1
rm -f $fname2
echo "MMDB Setup Done."

