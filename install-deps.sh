#!/bin/bash
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
# this script will install the various bits'n'pieces needed to get this
# survey stuff working
# installs all python modules required
# installs zmap2
# isntalls go 1.15.5 for zgrab2
# installs zgrab2
# runs mm_update script which makes the mmdb dir and builds the required databases
# Also sets gopath for golang to work

# Last tested on 18.04 - 2022/03

startdir=`/bin/pwd`
sudo apt-get update
sudo apt-get -y upgrade
sudo apt-get -y install wget
sudo apt-get -y install git unzip

#sudo apt-get -y install python3-pip
#sudo -H pip3 install pandas netaddr jsonpickle geoip2 graphviz pympler
# better way install requirements
pip3 install -r requirements.txt

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
echo "Installing Golang."
if [ ! -d /usr/lib/go-1.15.5 ]
then
    mkdir -p $HOME/code/go
    cd $HOME/code/go
    GOTARBALL=go1.15.5.linux-amd64.tar.gz
    GOURL=https://golang.org/dl/$GOTARBALL
    wget $GOURL
    if [ ! -f $GOTARBALL ]
    then
	echo "Can't read $GOTARBALL"
    	exit 1
    fi
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
    rm -f $GOTARBALL
fi

# zgrab2 stuff
go get github.com/zmap/zgrab2
cd $GOPATH/src/github.com/zmap/zgrab2
# go build - wasn not working on my ubunut 18.04 for some reason. not sure why.
make 
# put it on PATH
sudo ln -sf $HOME/go/src/github.com/zmap/zgrab/zgrab /usr/local/bin
cd $starddir
echo "Done! (I hope:-)"
