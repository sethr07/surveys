#!bin/bash
#set -x

function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

startdir=`/bin/pwd`
echo "Running $0 at $NOW"


function usage()
{
	echo "$0 [-m] [-s <source-code-directory>] [-r <results-directory>] [-p <inter-dir>] [-c <country>] [-i <ips-src>] [-z <zmap-port>] [-k <skips>]"
	echo "	-m means do the maxmind thing"
	echo "	source-code-directory defaults to \$HOME/code/surveys"
	echo "	country must be IE or EE, default is IE"
	echo "	results-directory defaults to \$HOME/data/smtp/runs"
	echo "	inter-directory is a directory with intermediate results we process further"
	echo "	ips-src is a file with json lines like censys.io's (original censys.io input used if not supplied"
	echo "  zmap-port (default 25) is the port we use to decide what to scan"
	echo "	skips is a comma-sep list of stages to skip: mm,zmap,grab,fresh,cluster,graph"
	exit 99
}

srcdir=$HOME/code/surveys
outdir=$HOME/data/smtp/runs

country="IE"
ipssrc=''
pdir=''
domm='no'
dpath=`grep mmdbpath $HOME/code/surveys/SurveyFuncs.py  | head -1 | awk -F\' '{print $2}' | sed -e 's/\/$//'`
mmdbdir=$HOME/$dpath

zmport="25"
skips=""

if [[ "$zmap_parms" == "" ]]
then
	zmap_parms="-B 100K"
fi

if ! options=$(getopt -s bash -o ms:r:c:i:p:z:k:h -l mm,srcdir:,resdir:,country:,ips:,process:,zmap:,skips:,help -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi

eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
		-h|--help) usage;;
		-m|--mm) domm="yes" ;;
		-s|--srcdir) srcdir="$2"; shift;;
		-z|--zmap) zmport="$2"; shift;;
		-r|--resdir) outdir="$2"; shift;;
		-k|--skips) skips="$2"; shift;;
		-i|--ips) ipssrc="$2"; shift;;
		-p|--process) pdir="$2"; shift;;
		-c|--country) country="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [ "$srcdir" == "" ]
then
	echo "No <code-directory> set"
	usage
fi

if [ ! -d $srcdir ]
then
	echo "$srcdir doesn't exist - exiting"
	usage
fi

if [ "$outdir" == "" ]
then
	echo "No <results-diretory> set"
	usage
fi

#check if country is known - glitcy. Need to find a solution
#cknown=`grep $country /home/rs/code/surveys/mmdb/countrycodes.txt`
#echo $cknown
#if [[ "$country" != "$cknown" && "$country" != "XX" ]]
#then
#	echo "Country $country isn't known"
#	exit 87
#fi


# place for results - might get changed by pdir
resdir=$outdir/$country\-$NOW
# this is the first one that changes disk

if [ "$pdir" == "" ]
then
	if [ ! -d $outdir ]
	then
		mkdir -p $outdir
	fi
	if [ ! -d $outdir ]
	then
		echo "Can't create $outdir - exiting"
		exit 5
	fi

	# just in case an error causes us to crap out within a second
	while [ -d $resdir ]
	do
		echo "Name collision! Sleeping a bit"
		sleep 5
		NOW=$(whenisitagain)
		resdir=$outdir/$country-$NOW
	done
	if [ ! -d $resdir ]
	then
		mkdir -p $resdir
	fi
else
	# continue processing of partly done directory content
	resdir=$pdir
	if [ ! -d $resdir ]
	then
		echo "No intermediate directory $pdir - exiting"
		exit 8
	fi
fi

cd $resdir
# make life easier
#cp $srcdir/Makefile .
logf=$NOW.out
run=$NOW

echo "Starting at $NOW, log in $logf" 
echo "Starting at $NOW, log in $logf" >>$logf

# Variables to have set
unset SKIP_MM
unset SKIP_ZMAP
unset SKIP_GRAB
unset SKIP_FRESH
unset SKIP_CLUSTER
unset SKIP_GRAPH

# files uses as tell-tales
TELLTALE_MM="mm-ips."$country".v4"
TELLTALE_ZMAP="zmap.ips"
TELLTALE_GRAB="input.ips"
TELLTALE_FRESH="records.fresh"
TELLTALE_CLUSTER="collisions.json"

if [ "$pdir" != "" ]
then
	# figure out where we're at...
	# if we have a $TELLTALE_GRAB then no need to grab
	if [ -f $TELLTALE_MM ]
	then
		SKIP_MM=yes
	fi
	if [ -f $TELLTALE_ZMAP ]
	then
		SKIP_ZMAP=yes
	fi
	if [ -f $TELLTALE_GRAB ]
	then
		SKIP_GRAB=yes
	fi
	# if we have a $TELLTALE_FRESH then no need to fresh
	if [ -f $TELLTALE_FRESH ]
	then
		SKIP_FRESH=yes
	fi
	# if we have a $TELLTALE_CLUSTER no need to cluster
	if [ -f $TELLTALE_CLUSTER ]
	then
		SKIP_CLUSTER=yes
	fi
	# if we have a graphed no need to graph
	if [ -f graphs.done ]
	then
		SKIP_GRAPH=yes
	fi
fi

echo "Starting Maxmind stuff"
python3 /$srcdir/IPsFromMM.py -c $country >>$logf 2>&1

echo "starting zmap"
sudo zmap $zmap_parms -p $zmport -w $TELLTALE_MM -o $TELLTALE_ZMAP
ln -s $TELLTALE_ZMAP $TELLTALE_GRAB
echo "zmap finished."

echo "starting fresh grab"
python3 /$srcdir/FreshGrab.py -i $TELLTALE_GRAB -o $TELLTALE_FRESH -c $country
echo "grabbed finished."

#echo "Starting check for collisions."
#python3 /$srcdir/SameKeys.py