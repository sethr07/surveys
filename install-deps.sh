#!/bin/bash
startdir=`/bin/pwd`

# this script will install the various bits'n'pieces needed to get this
# survey stuff working
# installs all python modules required
# installs zmap
# isntalls go 1.15.5 for zgrab2
# installs zgrab2
# runs mm_update script which makes the mmdb dir and builds the required databases
# Also sets gopath for go to work

# Last tested on 18.04 - 2022/03

sudo apt-get update
sudo apt-get -y upgrade
sudo apt-get -y install wget
sudo apt-get -y install git unzip

if [ ! -d $HOME/code ]
then
	mkdir -p $HOME/code
fi 
if [ ! -d $HOME/code/surveys ]
then
	cd $HOME/code
	git clone -b rahul-01 https://github.com/sethr07/surveys.git
else
	# may as well do an update
	cd $HOME/code/surveys
	git pull
fi

for subdir in runs IE EE 
do
	if [ ! -d $HOME/data/smtp/$subdir ]
	then
		mkdir -p $HOME/data/smtp/$subdir
	fi
done

sudo apt-get -y install zmap

# maxmind stuff
./mm_update.sh

if [ ! -d /usr/lib/go-1.15 ]
then
mkdir -p $HOME/code/go
	cd $HOME/code/go
	GOTARBALL=go1.15.5.linux-amd64.tar.gz
	GOURL=https://golang.org/dl/$GOTARBALL
	wget $GOURL
	tar xzvf $GOTARBALL
	sudo mv go /usr/lib/go-1.15.5
	sudo ln -sf /usr/lib/go-1.15.5/usr/lib/go
	sudo ln -sf /usr/lib/go-1.15.5/bin/go /usr/bin/go

	# add GOPATH to .bashrc
	donealready=`grep GOPATH $HOME/.bashrc`
	if [[ "$donealready" == "" ]]
	then
		echo "export GOPATH=$HOME/go" >>$HOME/.bashrc
	fi
	export GOPATH=$HOME/go
fi

# zgrab2 stuff
go get github.com/zmap/zgrab2
cd $GOPATH/src/github.com/zmap/zgrab2
go build
# put it on PATH
sudo ln -sf $HOME/go/src/github.com/zmap/zgrab/zgrab /usr/local/bin
cd $starddir
echo "Done! (I hope:-)"