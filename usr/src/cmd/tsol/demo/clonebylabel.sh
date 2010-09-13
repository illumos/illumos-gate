#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# clonebylabel
#
# This script installs zones by cloning a zfs snapshot.
# For each sensitivity label dominated by the clearance
# a zone is installed if necessary. If the zone name is
# not already defined in tnzonecfg, the user is prompted
# to provide a unique zone name.
#
# $1 is the label upper bound (clearance)
#
# $2 is the zone snaphot to clone for a new zone

ZONECFG=/etc/security/tsol/tnzonecfg
clearance=$1
image=$2

#
# Configure a zone
#

configure()
{
	config=/tmp/zfg.$$
	echo "create -F -t SUNWtsoldef" > $config
	echo "set zonepath=/zone/$zonename" >> $config
	echo "commit" >> $config
	/usr/sbin/zonecfg -z $zonename -f $config
	rm $config
}

#
# Clone a zone
#

clone()
{
        echo Cloning $zonename from $image ...
	found=`zoneadm -z $zonename list -p 2>/dev/null`
        if [ $found ]; then
		true
	else
		echo "$zonename is being configured."
		configure
        fi
        /usr/sbin/zfs clone $image zone/$zonename
	/usr/sbin/zoneadm -z $zonename attach -F
}

#
# Create missing zones for each label dominated by clearance
#

for label in `lslabels -h "$clearance"`; do
    zonename=`/bin/grep $label: $ZONECFG | cut -d ":" -f1`
    if [ $zonename ]; then
	state=`zoneadm -z $zonename list -p 2>/dev/null | cut -d ":" -f3`
	if [ $state ]; then
	    if [ $state != configured ]; then
		echo $zonename is already installed.
		continue
	    fi
	fi    	
    else
    	zonelabel=`hextoalabel $label`
    	echo Enter zone name for $zonelabel
    	echo or RETURN to skip this label:
    	read zonename
    	if [ $zonename ]; then
    		nz=`/bin/grep "^$zonename:" $ZONECFG | cut -d ":" -f1`
    		if [ $nz ]; then
    	   		echo $zonename is already used for another label.
    		else
    	   		echo "$zonename:$label:0::" >> $ZONECFG
    		fi
    	else
    		echo Skipping zone for $zonelabel
    		continue
    	fi
    fi
    clone
done
