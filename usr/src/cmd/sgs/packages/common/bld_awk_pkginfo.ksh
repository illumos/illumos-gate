#!/usr/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1993-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
# Simple script which builds the awk_pkginfo awk script.  This awk script
# is used to convert the pkginfo.tmpl files into pkginfo files
# for the build.
#


usage()
{
   echo "usage: bld_awk_pkginfo -R <readme> -r <release> -m <mach> -o <awk_script>"
}
#
# Awk strings
#
VERSION="VERSION\="
PRODVERS="^PRODVERS\="
ARCH='ARCH=\"ISA\"'


#
# parse command line
#
mach=""
release=""
awk_script=""
readme=""
debug=""

while getopts DR:o:r:m: c
do
   case $c in
   D)
   	debug=1
	;;
   o)
      awk_script=$OPTARG
      ;;
   m)
      mach=$OPTARG
      ;;
   r)
      release=$OPTARG
      ;;
   R)
   	readme=$OPTARG
	;;
   \?)
      usage
      exit 1
      ;;
   esac
done

if [[ ( -z $release ) || ( -z $mach ) || ( -z $awk_script ) \
    || ( -z $readme) ]]
then
   usage
   exit 1
fi

if [[ -f $awk_script ]]
then
	rm -f $awk_script
fi

#
# Build REV= field based on date
#
rev=$(date "+%y.%m.%d.%H.%M")

#
# Build PRODVERS string - same as in libconv/common/bld_vernote.ksh
#
readmerev=$(grep '^#pragma ident' $readme | awk '{print $4;}')

if [[ ( -z $readmerev ) || ( $readmerev = "%""I""%" ) ]]; then
	opwd=$(pwd)
	readdir=$(dirname $readme)
	readbase=$(basename $readme)
	cd $readdir
	readmerev=$(sccs get -p $readbase 2>/dev/null | \
		grep '^#pragma ident' | \
		awk '{print $4;}')
	if [[ -z $readmerev ]]; then
		readmerev='0.0'
	fi
	cd $opwd
	debug="1"
fi

if [[ ! -z $debug ]]; then
	wsname=
	if [[ ! -z $CODEMGR_WS ]]; then
		wsname=$(basename $CODEMGR_WS)
	fi
	readmerev=${readmerev}":"${wsname}"-${USER}-"$(date +%m/%d/%y)
fi

prodver="${release}-${readmerev}"
#
# Build awk script which will process all the
# pkginfo.tmpl files.
#
rm -f $awk_script
cat << EOF > $awk_script
/$VERSION/ {
      sub(/\=[^=]*$/,"=$rev\"")
      print
      next
   }
/$PRODVERS/ { 
      printf "PRODVERS=\"%s\"\n", "$prodver" 
      next
   }
/$ARCH/ {
      printf "ARCH=\"%s\"\n", "$mach"
      next
   }
{ print }
EOF

