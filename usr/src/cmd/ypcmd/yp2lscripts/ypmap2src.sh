#! /usr/bin/sh
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ypmap2src -- script to generate source files from YP maps.
#


# Please save a copy of this script before making any changes.


usage()
{
echo "Usage: $PROG [-t] [[-c custom-map-name] ...] [-d domain] -o output-directory [[source-file] ...]"
echo " t - Generate source files from TRADITIONAL NIS MAPS, default is NIS2LDAP maps."
echo " c - Name of the custom map for which source file needs to be generated."
echo " d - Specify a different domain, default is local system domain name."
echo " o - Specify the output directory where source files can be generated."
echo "source-file - The name of the source file for which needs to be generated."
exit 0
}

parse_argument()
{
while getopts "tc:d:o:" ARG
do
  case $ARG in

    t) N2LPREFIX=""
       MAP_LIST="$NIS_ONLY_MAP_LIST"
       ;;
    c) CUST_LIST="$CUST_LIST $OPTARG"
       ;;
    d) DOMAIN=$OPTARG
       MAPDIR=/var/yp/"$DOMAIN"
       ;;
    o) OUTDIR=$OPTARG
       ;;
    *) echo "ERROR : Invalid argument"
       usage
       exit 1
       ;;
  esac
done

# This is to handle if "-t" is supplied after "-c"
for MAP in $CUST_LIST
do
  CUST_MAP_LIST="$CUST_MAP_LIST ${N2LPREFIX}$MAP"
done

if [ -z "$OUTDIR" ]; then
  echo "ERROR : output directory has to be specified."
  usage
  exit 1
fi

# Set source list if supplied 
shift `expr $OPTIND - 1`
CMDLINE_SRC_LIST="$@"

[ $DEBUG -eq 1 ] && echo CMDLINE_SRC_LIST = $CMDLINE_SRC_LIST

# If source(s) supplied on command line, then generate ONLY those file(s).

if [ "$CMDLINE_SRC_LIST" != "" ]; then
  MAP_LIST=""
  CMDLINE_SRCS=1

  for SRC in $CMDLINE_SRC_LIST
  do
    [ $DEBUG -eq 1 ] && echo Parsing Command line SRC = $SRC
  
    case $SRC in
      passwd )
        MAP=${N2LPREFIX}passwd.byuid
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      group )
        MAP=${N2LPREFIX}group.byname
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      hosts )
        MAP=${N2LPREFIX}hosts.byaddr
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      ipnodes )
        MAP=${N2LPREFIX}ipnodes.byaddr
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      ethers )
        MAP=${N2LPREFIX}ethers.byname
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      networks )
        MAP=${N2LPREFIX}networks.byaddr
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      rpc )
        MAP=${N2LPREFIX}rpc.bynumber
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      services )
        MAP=${N2LPREFIX}services.byname
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      protocols )
        MAP=${N2LPREFIX}protocols.bynumber
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      netgroup )
        MAP=${N2LPREFIX}netgroup
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      bootparams )
        MAP=${N2LPREFIX}bootparams
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      aliases )
        MAP=${N2LPREFIX}mail.aliases
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      publickey )
        MAP=${N2LPREFIX}publickey.byname
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      netid )
        MAP=${N2LPREFIX}netid.byname
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      netmasks )
        MAP=${N2LPREFIX}netmasks.byaddr
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      passwd.adjunct )
        MAP=${N2LPREFIX}passwd.adjunct.byname
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      group.adjunct )
        MAP=${N2LPREFIX}group.adjunct.byname
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      timezone )
        MAP=${N2LPREFIX}timezone.byname
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      auto.* )
        MAP=${N2LPREFIX}${SRC}
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      auth_attr )
        MAP=${N2LPREFIX}auth_attr
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      exec_attr )
        MAP=${N2LPREFIX}exec_attr
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      prof_attr )
        MAP=${N2LPREFIX}prof_attr
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      user_attr )
        MAP=${N2LPREFIX}user_attr
        MAP_LIST="$MAP_LIST $MAP"
         ;;
      audit_user )
        MAP=${N2LPREFIX}audit_user
        MAP_LIST="$MAP_LIST $MAP"
         ;;
     *) # Not a default source, could be a custom source.
        # Then generate source files from all the available
        # DBM files for this custom source.

        MAPFOUND=0

        for dbmfile in $MAPDIR/${N2LPREFIX}${SRC}.dir \
            $MAPDIR/${N2LPREFIX}${SRC}.*.dir
        do
          MAP=`basename $dbmfile .dir`
          if [ -f $MAPDIR/${MAP}.pag ]; then
            MAPFOUND=1
            CUST_MAP_LIST="$CUST_MAP_LIST $MAP"
          fi
        done

        [ $MAPFOUND -eq 0 ] && \
           echo ERROR : No maps found for $SRC. Skipping..
        ;;
   esac
  done

fi

}


is_root_user()
{
  case `id` in
    uid=0\(root\)*) return 0
                    ;;
    * )             return 1
                    ;;
  esac
}


create_passwd()
{
SRCFILE=passwd
SHADOW=shadow

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort the entries in ascending order of uid
sort -n -t: -k3,3 $TMPDIR/${MAP}.cut > $TMPDIR/${MAP}.sort

# If passwd.adjunct is used, the actual password is stored in
# this map, and the passwd map contains "##<uid>" as the passwd.
# In that case, do not generate the shadow file.

UID=`head -1 $TMPDIR/${MAP}.sort | cut -f1 -d:`
PSWD=`head -1 $TMPDIR/${MAP}.sort | cut -f2 -d:`
if [ "$PSWD" != "##${UID}" ]; then

  #Create the shadow file with blank passwd aging information
  cut -f 1,2 -d: $TMPDIR/${MAP}.sort |
      sed 's/$/:::::::/' > $OUTDIR/$SHADOW
  
  #Make the shadow file readable to root only
  chmod 400 $OUTDIR/$SHADOW
  
  #Create the passwd file with "x" as the passwd
  awk ' BEGIN { FS = ":"; OFS = ":"}
        {$2 = "x"; print}' $TMPDIR/${MAP}.sort > $OUTDIR/$SRCFILE
else
  cp $TMPDIR/${MAP}.sort $OUTDIR/$SRCFILE
fi

}


create_group()
{
SRCFILE=group

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort the entries in ascending order of gid
sort -n -t: -k3,3 $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_hosts()
{
SRCFILE=hosts

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort the hosts ip addresses in ascending order
sort -n -t. -k1,1 -k2,2 -k3,3 -k4,4 $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_ipnodes()
{
SRCFILE=ipnodes

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

grep -v "::" $TMPDIR/${MAP}.cut >$TMPDIR/${MAP}.V4
grep "::" $TMPDIR/${MAP}.cut >$TMPDIR/${MAP}.V6

# Sort the ip addresses in ascending order
sort -n -t. -k1,1 -k2,2 -k3,3 -k4,4 $TMPDIR/${MAP}.V4 > $OUTDIR/$SRCFILE

# V6 addresses due to hex chars, can't be sorted this way.
# So just do the default string sort.
sort $TMPDIR/${MAP}.V6 >> $OUTDIR/$SRCFILE
}


create_ethers()
{
SRCFILE=ethers

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort ethernet addresses based on host names
sort -b -k2 $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_networks()
{
SRCFILE=networks

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort networks based on their names
sort $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_rpc()
{
SRCFILE=rpc

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort entries in the increasing order of RPC number
sort -n -k2 $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_services()
{
SRCFILE=services

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort entries in the increasing order of RPC number
sort -n -k2 $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_protocols()
{
SRCFILE=protocols

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort entries in the increasing order of RPC number
sort -n -k2 $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_netgroup()
{
SRCFILE=netgroup

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

cp $TMPDIR/${MAP}.grep $OUTDIR/$SRCFILE
}


create_bootparams()
{
SRCFILE=bootparams

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Sort the entries
sort $TMPDIR/${MAP}.grep > $OUTDIR/$SRCFILE
}


create_aliases()
{
SRCFILE=aliases

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Replace first " " with ": " to make it similar to aliases
sed 's/ /: /' $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.sed

# Sort aliases entries alphabetically
sort $TMPDIR/${MAP}.sed > $OUTDIR/$SRCFILE
}


create_publickey()
{
SRCFILE=publickey

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Sort entries alphabetically
sort $TMPDIR/${MAP}.grep > $OUTDIR/$SRCFILE
}


create_netid()
{
SRCFILE=netid

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# netid source files is used to add other domain
# entries. So, filter out local domain entries
grep -v "@${DOMAIN}" $TMPDIR/${MAP}.grep > $OUTDIR/$SRCFILE
}


create_netmasks()
{
SRCFILE=netmasks

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Sort the network numbers in ascending order
sort -n -t. -k1,1 -k2,2 -k3,3 -k4,4 $TMPDIR/${MAP}.grep > $OUTDIR/$SRCFILE
}


create_passwd_adjunct()
{
SRCFILE=passwd.adjunct

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines. It has three of them.
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME | grep -v YP_SECURE > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

## Check if sorting is ok, or leave it as it is.
# Sort the entries in alphabetical order
sort $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_group_adjunct()
{
SRCFILE=group.adjunct

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines. It has three of them.
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME | grep -v YP_SECURE > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort the entries in alphabetical order
sort $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_timezone()
{
SRCFILE=timezone

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort the entries in alphabetical order
sort $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_auto_src()
{
SRCFILE=$MAP

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Sort entries alphabetically
sort $TMPDIR/${MAP}.grep > $OUTDIR/$SRCFILE
}


create_auth_attr()
{
SRCFILE=auth_attr

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort entries in the alphabetical order
sort $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_exec_attr()
{
SRCFILE=exec_attr

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key which is made of three fields. space is part of key
cut -f 3- -d ":" $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut1
cut -f 2- -d " " $TMPDIR/${MAP}.cut1 > $TMPDIR/${MAP}.cut2

# Sort entries in the alphabetical order
sort $TMPDIR/${MAP}.cut2 > $OUTDIR/$SRCFILE
}


create_prof_attr()
{
SRCFILE=prof_attr

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key. It is difficult here as space is part of the key.
# From the "key key" part, extract "key", and then paste it with
# the rest of the entry.
cut -f1 -d: $TMPDIR/${MAP}.grep |
awk '{
  STR = $1
  for (i=2; i <= NF/2; i++) {
    STR = STR  " " $i
  }
print STR
}' > $TMPDIR/${MAP}.cut1

cut -f2- -d: $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut2
paste -d ":" $TMPDIR/${MAP}.cut1 $TMPDIR/${MAP}.cut2 > $TMPDIR/${MAP}.cut

# Sort entries in the alphabetical order
sort $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_user_attr()
{
SRCFILE=user_attr

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort entries in the alphabetical order
sort $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


create_audit_user()
{
SRCFILE=audit_user

makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines. It has 3 of them.
grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
  grep -v "YP_DOMAIN_NAME $DOMAIN" |
  grep -v YP_MASTER_NAME | grep -v YP_SECURE > $TMPDIR/${MAP}.grep

# Remove the key
cut -f 2- -d " " $TMPDIR/${MAP}.grep > $TMPDIR/${MAP}.cut

# Sort entries in the alphabetical order
sort $TMPDIR/${MAP}.cut > $OUTDIR/$SRCFILE
}


## MAIN ##

PROG=`basename $0`

# Only root can read the NIS maps, so no point allowing
# non-root users to be able to run this script.
is_root_user
if [ $? -ne 0 ]; then
  echo "ERROR : Only root can run $PROG"
  exit 1
fi

# Prevent non-root users from reading/writing
umask 077

# Initialize default values.
DOMAIN=`/usr/bin/domainname`
MAPDIR=/var/yp/"$DOMAIN"	# Default to local domain
N2LPREFIX=LDAP_

NIS_ONLY_MAP_LIST="passwd.byuid
                   group.byname
                   hosts.byaddr
                   ipnodes.byaddr
                   ethers.byname
                   networks.byaddr
                   rpc.bynumber
                   services.byname
                   protocols.bynumber
                   netgroup
                   bootparams
                   mail.aliases
                   publickey.byname
                   netid.byname
                   netmasks.byaddr
                   passwd.adjunct.byname
                   group.adjunct.byname
                   timezone.byname
                   auth_attr
                   exec_attr
                   prof_attr
                   user_attr
                   audit_user"

NIS2LDAP_MAP_LIST="${N2LPREFIX}passwd.byuid
                   ${N2LPREFIX}group.byname
                   ${N2LPREFIX}hosts.byaddr
                   ${N2LPREFIX}ipnodes.byaddr
                   ${N2LPREFIX}ethers.byname
                   ${N2LPREFIX}networks.byaddr
                   ${N2LPREFIX}rpc.bynumber
                   ${N2LPREFIX}services.byname
                   ${N2LPREFIX}protocols.bynumber
                   ${N2LPREFIX}netgroup
                   ${N2LPREFIX}bootparams
                   ${N2LPREFIX}mail.aliases
                   ${N2LPREFIX}publickey.byname
                   ${N2LPREFIX}netid.byname
                   ${N2LPREFIX}netmasks.byaddr
                   ${N2LPREFIX}passwd.adjunct.byname
                   ${N2LPREFIX}group.adjunct.byname
                   ${N2LPREFIX}timezone.byname
                   ${N2LPREFIX}auth_attr
                   ${N2LPREFIX}exec_attr
                   ${N2LPREFIX}prof_attr
                   ${N2LPREFIX}user_attr
                   ${N2LPREFIX}audit_user"


# If auto maps exist, add them to the respective lists.
for dbmfile in $MAPDIR/auto.*.dir
do
  MAP=`basename $dbmfile .dir`
  if [ -f $MAPDIR/${MAP}.pag ]; then
    NIS_ONLY_MAP_LIST="$NIS_ONLY_MAP_LIST $MAP"
  fi
done

for dbmfile in $MAPDIR/${N2LPREFIX}auto.*.dir
do
  MAP=`basename $dbmfile .dir`
  if [ -f $MAPDIR/${MAP}.pag ]; then
    NIS2LDAP_MAP_LIST="$NIS2LDAP_MAP_LIST $MAP"
  fi
done

# Default to N2L maps
MAP_LIST="$NIS2LDAP_MAP_LIST"

# Safe place to avoid anyone from reading sensitive data.
TMPDIR="/var/tmp/ypmap2src"

DEBUG=0			# Default to debug off
DEBUG=1
OUTDIR=""
CUST_MAP_LIST=""
CMDLINE_SRCS=0


parse_argument $*

[ $DEBUG -eq 1 ] && echo DOMAIN = $DOMAIN
[ $DEBUG -eq 1 ] && echo OUTDIR = $OUTDIR
[ $DEBUG -eq 1 ] && echo TMPDIR = $TMPDIR
[ $DEBUG -eq 1 ] && echo CUST_MAP_LIST = $CUST_MAP_LIST
[ $DEBUG -eq 1 ] && echo MAP_LIST = $MAP_LIST

[ $DEBUG -eq 1 ] && echo MAPDIR = $MAPDIR
if [ ! -d "$MAPDIR" ]; then
  echo ERROR : NIS Map directory $MAPDIR does not exist.
  exit 1
fi

if [ ! -d "$OUTDIR" ]; then
  echo output directory $OUTDIR does not exist. Creating it.
  mkdir -p $OUTDIR
  if [ $? -ne 0 ]; then
    echo ERROR : Failed to create output directory $OUTDIR
    exit 1
  fi
fi

# Cleanup if the temp directory has been leftover
[ -d "$TMPDIR" ] && rm -rf $TMPDIR
mkdir $TMPDIR
if [ $? -ne 0 ]; then
  echo ERROR : Failed to create temp directory $TMPDIR
  exit 1
fi


for MAP in $MAP_LIST
do
  [ $DEBUG -eq 1 ] && echo Processing MAP = $MAP

  if [ ! -f $MAPDIR/${MAP}.dir ] || [ ! -f $MAPDIR/${MAP}.pag ]; then

    [ $CMDLINE_SRCS -ne 0 ] && \
        echo ERROR : Missing DBM file for $MAP in $MAPDIR . Skipping..

    [ $DEBUG -eq 1 ] && [ $CMDLINE_SRCS -eq 0 ] && \
        echo No DBM file for $MAP in $MAPDIR . Skipping..
    continue
  fi

  case $MAP in
    ${N2LPREFIX}passwd.byuid )
      create_passwd
       ;;
    ${N2LPREFIX}group.byname )
      create_group
       ;;
    ${N2LPREFIX}hosts.byaddr )
      create_hosts
       ;;
    ${N2LPREFIX}ipnodes.byaddr )
      create_ipnodes
       ;;
    ${N2LPREFIX}ethers.byname )
      create_ethers
       ;;
    ${N2LPREFIX}networks.byaddr )
      create_networks
       ;;
    ${N2LPREFIX}rpc.bynumber )
      create_rpc
       ;;
    ${N2LPREFIX}services.byname )
      create_services
       ;;
    ${N2LPREFIX}protocols.bynumber )
      create_protocols
       ;;
    ${N2LPREFIX}netgroup )
      create_netgroup
       ;;
    ${N2LPREFIX}bootparams )
      create_bootparams
       ;;
    ${N2LPREFIX}mail.aliases )
      create_aliases
       ;;
    ${N2LPREFIX}publickey.byname )
      create_publickey
       ;;
    ${N2LPREFIX}netid.byname )
      create_netid
       ;;
    ${N2LPREFIX}netmasks.byaddr )
      create_netmasks
       ;;
    ${N2LPREFIX}passwd.adjunct.byname )
      create_passwd_adjunct
       ;;
    ${N2LPREFIX}group.adjunct.byname )
      create_group_adjunct
       ;;
    ${N2LPREFIX}timezone.byname )
      create_timezone
       ;;
    ${N2LPREFIX}auto.* )
      create_auto_src
       ;;
    ${N2LPREFIX}auth_attr )
      create_auth_attr
       ;;
    ${N2LPREFIX}exec_attr )
      create_exec_attr
       ;;
    ${N2LPREFIX}prof_attr )
      create_prof_attr
       ;;
    ${N2LPREFIX}user_attr )
      create_user_attr
       ;;
    ${N2LPREFIX}audit_user )
      create_audit_user
       ;;
   *) # Not a default map, could be a custom map.
      CUST_MAP_LIST="$CUST_MAP_LIST $MAP"
      ;;
 esac
done


for MAP in $CUST_MAP_LIST
do
  [ $DEBUG -eq 1 ] && echo Processing Custom MAP = $MAP

  if [ ! -f $MAPDIR/${MAP}.dir ] || [ ! -f $MAPDIR/${MAP}.pag ]; then
    echo ERROR : Missing DBM file for $MAP in $MAPDIR . Skipping..
    continue
  fi

  makedbm -u $MAPDIR/$MAP > $TMPDIR/$MAP

# Remove the YP operational lines. Assuming each custom map
# has only these entries (three in n2l mode as shown below, and
# two in vanilla NIS mode as it does not have "YP_DOMAIN_NAME".
# But that does not require any changes in the code). Modify it
# appropriately in other cases.

  grep -v YP_LAST_MODIFIED $TMPDIR/$MAP |
    grep -v "YP_DOMAIN_NAME $DOMAIN" |
    grep -v YP_MASTER_NAME > $TMPDIR/${MAP}.grep

# If further processing (e.g., removing key, sorting etc.)
# is required, then update the script appropriately.
  cp $TMPDIR/${MAP}.grep $OUTDIR/$MAP

done

# Leave the temp directory if debug is set
[ $DEBUG -eq 0 ] && rm -rf $TMPDIR

exit 0
