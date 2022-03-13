#!/bin/bash

#Scrip that does the maxmind stuff.
#Makes the mmdb directory.
#Installs mmdb databases
#Installs Country wise csv file
#installs country codes
#Calls python script for creating GeoIpWHoisCountry.csv



DESTDIR=$HOME/code/surveys/mmdb
CURRDIR=$HOME/code/surveys

#dpath=`grep mmdbpath $HOME/code/surveys/SurveyFuncs.py  | head -1 | awk -F\' '{print $2}' | sed -e 's/\/$//'`
#DESTDIR=$HOME/$dpath

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

key="AnRjFrGF9x75YmrD"
for db in City Country ASN
do
	url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-$db&license_key=$key&suffix=tar.gz"
	echo "Getting $url"
	wget -q $url
	tarball="geoip_download?edition_id=GeoLite2-$db&license_key=$key&suffix=tar.gz"
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
	fi
done

#get csv file to make GeoIPcountry csv file
now=`date +%Y%m%d`
csv_url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=$key&suffix=zip"
zip="geoip_download?edition_id=GeoLite2-Country-CSV&license_key=$key&suffix=zip"
wget $csv_url
unzip $zip

echo "Getting Country Code file"
cc_url="https://dev.maxmind.com/static/csv/codes/iso3166.csv?lang=en"
wget $cc_url
cc_file="iso3166.csv?lang=en"
cc_fname="countrycodes.txt"
cp $cc_file $cc_fname

echo "Getting data from GeoCountryWhois.csv"
dbdate=`ls -d "GeoLite2-Country-CSV"_* | awk -F"_" '{print $2}'`
dirname="GeoLite2-Country-CSV_$dbdate"
fname1="GeoLite2-Country-Blocks-IPv4.csv"
fname2="GeoLite2-Country-Locations-en.csv"
cp $dirname/$fname1 $DESTDIR/$fname1
cp $dirname/$fname2 $DESTDIR/$fname2

cd $CURRDIR
echo "creating csv file of ips country wise"
python3 MMCreateGeoIP.py
echo "Done"

