#!/usr/bin/ksh
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
#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

typeset -r PROG=$(basename $0)
typeset -r CTAG_NULL="-"

#
# help message
#
help()
{
	$xopt

	cluster_configured
	CLUSTER_CONFIGURED=$?

	echo "\
usage:
	$PROG
	$PROG -i
	$PROG -e [-r][-p]
	$PROG -d [-r]" >&2
	if [ $CLUSTER_CONFIGURED -eq 1 ]; then
		echo "\
	$PROG -s" >&2
	fi

	echo "\
	-i	: display information on the Availability Suite services
	-e	: enable Availability Suite services (all, by default)
	-d	: disable Availability Suite services (all, by default)
	-r	: enable/disable Remote Mirror
	-p	: enable Point in Time Copy" >&2
	if [ $CLUSTER_CONFIGURED -eq 1 ]; then
		echo "\
	-s	: set the location of the cluster configuration database" >&2
	fi
	echo "\
	-x	: turn on script debugging (may be used with any valid option)

	 When executed with no options or with nothing but -x, $PROG runs in
	 interactive fashion, allowing the user to initialize the local (and
	 if applicable, the cluster) configuration database, and to start the
	 Availability Suite services." >&2

	exit 2
}

########################## SET GLOBAL VARIABLES ######################

# root directory
PKG_INSTALL_ROOT=""
export PKG_INSTALL_ROOT

# set lib path
LD_LIBRARY_PATH=/usr/lib:/usr/lib
export LD_LIBRARY_PATH

# set dscfg
DSCFG="/usr/sbin/dscfg"
export DSCFG

# set parser config location
PCONFIG="/etc/dscfg_format"
export PCONFIG

# set local dscfg location
export LOCAL_DSCFG="/etc/dscfg_local"

# set cluster dscfg reference file
export CLUSTER_REF="/etc/dscfg_cluster"

# a service that has a dependency on us
FS_LOCAL_SVC="svc:/system/filesystem/local"

NODELIST="/tmp/nodelist"
DSCFGLOCKDCF="/etc/dscfg_lockdb"
DSCFG_DEPEND_NOCHK="/tmp/.dscfgadm_pid"

# SMF defines
MANIFEST_PATH=/lib/svc/manifest/system

# SMF services (enable and disable)
SMF_ENABLE="nws_scm nws_sv nws_ii nws_rdc nws_rdcsyncd"
SMF_DISABLE="nws_rdcsyncd nws_rdc nws_ii nws_sv nws_scm"

# state of each service
nws_scm_enabled=0
nws_sv_enabled=0
nws_ii_enabled=0
nws_rdc_enabled=0
nws_rdcsyncd_enabled=0

# set path
PATH=/usr/bin:/usr/sbin:/sbin/sh
export PATH

# set architecture
ARCH=`uname -p`
export ARCH
OS_MINOR=`uname -r | cut -d '.' -f2`

# number of sectors required for database
# 1024*1024*5.5/512
REQUIRED=11264

# must set here, else seen as null in MAIN
VALID_DB_ENTERED=0

NO_ARGS=0

# for debugging
xopt=

# set lengthy message here
CLUST_LOC_MESS="The current location is invalid for a Sun StorageTek \
Data Services configuration database.  Once a valid location is \
entered (raw slice on \"did\" device), you may upgrade the existing \
database to this new location - following the procedure outlined \
in the Installation and Configuration Guide."

########################## SET GLOBAL VARIABLES ######################


########################## ERROR  ####################################

# called with optional error msg $1
# prints basic guidelines for configuration of the database location
error()
{
    $xopt

    echo >&2
    echo "INSTALLATION ERROR" >&2
    echo "Error: $1" >&2
    echo >&2
    in_cluster

    if [ $? -eq 1 ]; then
	echo "GENERAL INSTALLATION RULES:" >&2
	echo "\tBecause you are installing on a cluster," >&2
	echo "\tthe database must be located on a raw slice of a did device.">&2
	echo "\t  e.g. /dev/did/rdsk/d17s1" >&2
    fi
    # let?
    MB=`expr $REQUIRED / 2 / 1024`
    echo "\t$REQUIRED sectors ($MB MBs) are required for the database." >&2
}

########################## ERROR  ####################################

########################## ALL LOCATION TESTS ########################

# sets numerous environment variables describing the state of the system
get_system_state()
{
	$xopt

	valid_local_dscfg_exists
	VALID_LOCAL_DB=$?
	OLD_VALID_LOCAL_DB=$VALID_LOCAL_DB

	in_cluster
	IN_CLUSTER=$?

	cluster_configured
	CLUSTER_CONFIGURED=$?

	if [ $IN_CLUSTER = 1 ]; then
		valid_cluster_dscfg_exists
		VALID_CLUSTER_DB=$?
		OLD_VALID_CLUSTER_DB=$VALID_CLUSTER_DB
	else
		VALID_CLUSTER_DB=0
	fi
}

# Checks if in cluster
# returns 1 if in cluster, else 0
#
in_cluster()
{
    $xopt

    if [ -x /usr/sbin/clinfo ]; then
	    clinfo
	if [ $? -eq 0 ]; then
            return 1
	else
	    return 0
	fi
    else
        return 0
    fi
}

# checks if a system is configured as a cluster
# returns 1 if configured as a cluster, 0 if not
#
cluster_configured()
{
    $xopt

    if [ -f /etc/cluster/nodeid ]; then
	return 1
    else
	return 0
    fi
}

# Check the list of Sun Cluster device groups known in the dscfg, determing
# if they are currently enabled on this Sun Cluster node. If so, fail allowing
# the system administator to scswitch them elsewhere.
#
check_device_groups()
{
	$xopt

	if [ $VALID_CLUSTER_DB == 1 ]; then
		DEVICE_GROUPS=`$DSCFG -s $FILE_LOC -l 2>/dev/null | \
		grep "^dsvol:" | cut -d' ' -f3 | sort | uniq | xargs`
		for x in $DEVICE_GROUPS
		do
			$DSCFG -D $x 2>/dev/null
			if [ $? -eq 1 ]
			then
				IN_USE="$IN_USE $x"
			fi
		done

		if [ -n "$IN_USE" ]
		then
		    print "The following Sun Cluster device groups are in use "
		    print "by Availability Suite on this node."
		    print ""
		    print "$IN_USE"
		    print ""
		    print "'scswitch' them to another Sun Cluster node before "
		    print "attempting to disable any data services."
		    return 1
		else
		    return 0
		fi
	fi
	
	return 0
}

# checks to see if this is a char device in the
# /dev/did/rdsk directory returns 1 if so.
#
is_did_device()
{
	$xopt

	DID=`echo $1 | awk -F/ '{print $3}'`
	RDSK=`echo $1 | awk -F/ '{print $4}'`

	if [ "did" = $DID -a "rdsk" = $RDSK -a -c $1 ]; then
		return 1
	else	
		return 0
	fi
}

#
# checks size of area for db location
#
check_size()
{
	$xopt

	# if in cluster look for d*s*
	SLICE=`echo $1 | sed -n 's/.*d.*s\(.*\)/\1/p'`

	SECTORS=`prtvtoc $1 | tr -s ' '| grep "^ $SLICE " | awk '{print $5}'`

	if [ -z "$SECTORS" ]; then
            echo "SLICE at $1 not found on this device"
            return 0
	fi

	# if required size is greater than space available, then fail
	if [ $REQUIRED -gt $SECTORS ]; then
		return 0
	else
		return 1
	fi
}

# looks in dscfg_cluster reference file.  if a location is configured,
# tests to see if it is a valid database.  if so, returns 1
#
valid_cluster_dscfg_exists()
{
    $xopt

    if [ -s $CLUSTER_REF ]; then
	FILE_LOC=`head -1 $CLUSTER_REF`
	contains_data $FILE_LOC
	return $?
    else
	return 0
    fi
}


# checks for the existence of dscfg_local database, and if it exists,
# tests to see if it is a valid database.  if so, returns 1
#
valid_local_dscfg_exists()
{
    $xopt

    if [ -s $LOCAL_DSCFG ]; then
	contains_data $LOCAL_DSCFG
	return $?
    else
       return 0
    fi
}

# used to test if a valid DS config database exists on machine already
# MAGIC_STRING is the top line in the config used in v3.1 & v3.2
#
contains_data()
{
    $xopt

    # dscfg distinct strings, varies on the architecture
    if [ $ARCH = "sparc" ]
    then
	MAGIC_STRING="MAGI"
    elif [ $ARCH = "i386" ]
    then
	MAGIC_STRING="IGAM"
    fi

    # Create a PID unique temporary file
    TMP_FILE=/tmp/$$

    # Write the first or 16th block (skipping over VTOC) to
    # the TMP_FILE, then scan for the presence of the "MAGI"
    #
    for offset in 0 16
    do
	if [ ! -z "$1" ]; then
	    dd if=$1 of=$TMP_FILE count=1 iseek=$offset 2>/dev/null
	    FILECONTENTS=`strings $TMP_FILE | head -1 2>/dev/null`
	    if [ `echo $FILECONTENTS | grep -c "$MAGIC_STRING"` -gt 0 ]; then
		rm $TMP_FILE
		return 1
	    fi
	fi
    done

    rm $TMP_FILE
    return 0
}

########################## ALL LOCATION TESTS ########################


########################## MAIN FUNCTIONS ############################

# since location already has been set, asks what to do now?  keeping
# it still checks the size (since an upgrade from 3.0 may still be
# occuring) and also checks if was an old cluster config on disallowed
# /dev/did/dsk directory
#
# returns:
#	0 if cluster location is invalid or the user does not want to keep it
#	1 if the location is valid and the user wants to keep it.
#
keep_it()
{
    $xopt

    NOTE="\nThe Sun StorageTek Data Services database configuration"
    NOTE="$NOTE location has already been set."
    echo $NOTE

    echo "\nCurrent location: $PKG_INSTALL_ROOT$FILE_LOC"

    QUEST="Would you like to preserve the existing configuration"
    QUEST="$QUEST information at its current location? "

    ANS=`ckyorn -Qd n -p "$QUEST"`

    case $ANS in
	y|Y|yes|YES|Yes)
            #Since the user has said "yes I want to keep this current one"
            #it may actually be a 3.x database, which only required 4.5mb
            #space, so now will check that there is room to grow another 1mb"
	    check_location $FILE_LOC
            if [ $? = 0 ]; then
		error "$CLUST_LOC_MESS"
		return 0
	    else
		OLD_FILE_LOC=$FILE_LOC
		FILE_LOC=$NULL
		return 1
	    fi
            ;;
	*)
            return 0
            ;;
    esac
}

#
# asks if user wants to keep existing db information, overwrite with
# a new db, or view the contents, and be asked again...
# returns:
#	0 if old location is bad
#	1 if old location is good
#
preserve_overwrite_maybe()
{
    $xopt

    echo "\nIt appears a valid database configuration exists here already."

    while true
    do
      SAFE_LOC=$FILE_LOC

	echo "\nWould you like to preserve this information and continue?"
	echo "\ty - preserve current configuration"
	echo "\tn - overwrite with new configuration"
	echo "\tmaybe - view contents of current configuration"

	ANS=`ckkeywd -Q y n maybe`
	case $ANS in
	  y)
		check_location $FILE_LOC
		if [ $? = 0 ]; then
			error "$CLUST_LOC_MESS"
			return 0
		else
			$DSCFG -s "$FILE_LOC" -C $CTAG_NULL >/dev/null 2>&1
			OLD_FILE_LOC=$FILE_LOC
			FILE_LOC=$NULL
			return 1
		fi
		;;
	  n)
		check_location $FILE_LOC
		if [ $? = 0 ]; then
			error "$CLUST_LOC_MESS"
			return 0
		else
			return 1
		fi
		;;

	  maybe)
		# print contents of this db config.
		echo "\nContents of database configuration found at $SAFE_LOC are:"
 		$DSCFG -l -s "$FILE_LOC" | more
		FILE_LOC=$SAFE_LOC
		continue
              ;;
	esac
    done
}

# gets location from user
#
get_location()
{
    $xopt

    #Checks for absolute path name, and if file name and file doesn't
    #exist, creates it.
    echo "\n\n----------ENTER DATABASE CONFIGURATION LOCATION-----------------"
    echo "Note:	 Please ensure this location meets all requirements specified"
    echo "in the Availability Suite Installation Guide."

    FILE_LOC=`ckpath -artwQ -p "Enter location:"`
    if [ $? = 1 ]
	then
	    exit 1
	fi

    # allow non-root user to access for least privileges
    chmod 666 $FILE_LOC
}


#
# tests for proper config
#
# returns:
#	0 if bad location
#	1 if good location
#
check_location()
{
	$xopt

	# set to FILE_LOC
	LOCATION=$1

	did_clust_msg="You are in cluster and $LOCATION is not valid DID device"

	# Set "actual file location" variable here to equal file location
	# entered by user because getting here means contains_data was already
	# successfully called before and now the two can equal each other for
	# future testing.

	SAFE_LOC=$FILE_LOC

	if [ $IN_CLUSTER = 1 -o $CLUSTER_CONFIGURED = 1 ]; then
		if [ -b "$LOCATION" ] || [ -c "$LOCATION" ]; then
			is_did_device $LOCATION
			if [ $? = 0 ]; then
				error "$did_clust_msg"
				return 0
			fi
		else
			error "$did_clust_msg"
			return 0
		fi
	else
		echo "Location may not be changed in a non Sun Cluster OE." 2>&1
		return 0
	fi

	check_size $LOCATION

	if [ $? != 1 ]; then
		error "$LOCATION does not meet minimum space requirement."
		return 0
	else
		return 1
	fi
}

#
# Notifies the user that the SMF services are online,
# and gives him the option to disable the services before proceeding.  If
# the services are not disabled, the program cannot proceed with setting
# a new dscfg location.
#
ask_to_disable()
{
    $xopt

    echo "\
\nYour services must be disabled before a new configuration location is set.\n"

    QUEST="Would you like to disable the services now and continue with the"
    QUEST="$QUEST Availability Suite setup? " 

    ANS=`ckyorn -Qd n -p "$QUEST"`

    case $ANS
	in y|Y|yes|YES|Yes)
	    return 1
	    ;;
	*)
            return 0
            ;;
    esac
}

#
# Asks the user if he would like to enable the services now.  If so,
# import them (if necessary) and enable them.
#
ask_to_enable()
{
    $xopt

    echo "\
\nIf you would like to start using the Availability Suite immediately, you may
start the SMF services now.  You may also choose to start the services later
using the $PROG -e command."

    QUEST="Would you like to start the services now? "

    ANS=`ckyorn -Qd n -p "$QUEST"`

    case $ANS
	in y|Y|yes|YES|Yes)
	    return 1
	    ;;
	*)
            return 0
            ;;
    esac
}

#
# display information about the system
#
display_info()
{
	$xopt

	typeset grp_error_flg=0
	typeset -L15 svc state en SVC="SERVICE" STATE="STATE" EN="ENABLED"
	echo "$SVC\t$STATE\t$EN"

	for i in $SMF_ENABLE
	do
		is_imported $i
		if [ $? = 1 ]
		then
			state=`svcprop -c -p restarter/state \
			    svc:/system/${i}:default`
			en=`svcprop -c -p general/enabled \
			    svc:/system/${i}:default`
			check_fs_local_grouping $i
			if [ $? -ne 0 ]
			then
				svc="${i}***"
				grp_error_flg=$((grp_error_flg + 1))
			else
				svc=$i
			fi

			echo "$svc\t$state\t$en"
		fi
	done

	print "\nAvailability Suite Configuration:"
	printf "Local configuration database: "
	if [ $VALID_LOCAL_DB = 1 ]
	then
		print "valid"	
	else
		print "invalid"	
	fi

	if [ $CLUSTER_CONFIGURED = 1 ]
	then
		printf "cluster configuration database: "
		if [ $VALID_CLUSTER_DB = 1 ]
		then
			print "valid"	
			print "cluster configuration location: ${FILE_LOC}"
		else
			print "invalid"	
		fi
	fi

	if [ $grp_error_flg -gt 0 ]
	then
		typeset p
		typeset p_has
		if [ $grp_error_flg -gt 1 ]
		then
			p="s"
			p_has="have"
		else
			p=""
			p_has="has"
		fi

		printf "\n*** Warning: The service$p above $p_has an incorrect "
		printf "dependency.  To repair the\n"
		printf "problem, run \"dscfgadm\".\n"
	fi
}

#
# initialize the local configuration database (only called if none exists)
# returns 0 if successful, 1 if failed
#
initialize_local_db()
{
	$xopt

	echo "Could not find a valid local configuration database."
	echo "Initializing local configuration database..."
	echo y | ${DSCFG} -i > /dev/null 2>&1
	${DSCFG} -i -p ${PCONFIG} > /dev/null 2>&1

	# Make sure the new location is initialized properly
	valid_local_dscfg_exists
	VALID_LOCAL_DB=$?
	if [ $VALID_LOCAL_DB != 1 ]
	then
		echo "Unable to initialize local configuration database" >&2
		return 1
	else	
		echo "Successfully initialized local configuration database"
	fi

	return 0
}

#
# initialize the cluster configuration database, if necessary
# returns 0 if successful, 1 if failed
#
initialize_cluster_db()
{
	$xopt

	if [ ! -n "$FILE_LOC" ]
	then
		return 0
	fi

	echo "Initializing cluster configuration database..."
	${DSCFG} -s ${FILE_LOC} -C $CTAG_NULL > /dev/null 2>&1
	echo y | ${DSCFG} -i -C $CTAG_NULL > /dev/null 2>&1
	${DSCFG} -i -p ${PCONFIG} -C $CTAG_NULL > /dev/null 2>&1

	# make sure the cluster db is valid now
	valid_cluster_dscfg_exists
	VALID_CLUSTER_DB=$?
	if [ $VALID_CLUSTER_DB != 1 ]
	then
		echo "Unable to initialize cluster configuration database" >&2
			return 1
	else
		echo "Successfully initialized cluster configuration database"
	fi

	return 0

}

#
# prompt the user for a config location and set AVS to use that location
#
set_cluster_config()
{

$xopt

REPEAT=0
while [ $REPEAT -eq 0 ]; do
  # See if user has entered location already, and it was an existing
  # db.	 Retruns FILE_LOC value
  if [ $VALID_DB_ENTERED = 1 ]; then

	# reset
      VALID_DB_ENTERED=0
	preserve_overwrite_maybe

	# if 1, location passes, and FILE_LOC being passed to end, else
      # set VALID_CLUSTER_DB to 0 since the "valid one" isn't valid anymore
      # (bad size, etc) thereby when looping go straight to get_location
      if [ $? = 1 ]; then
          REPEAT=1
          continue
      else
          VALID_CLUSTER_DB=0
          continue
      fi
  fi

  # if 1, then valid db exists, now see what user wants to do
  if [ $VALID_CLUSTER_DB = 1 ]; then
      SAFE_LOC=$FILE_LOC
      keep_it

      # if 0, then user can't or won't keep location.  set PROMPT
      # so we will get new location from user.
      if [ $? = 0 ]; then
          PROMPT=0
      else
          PROMPT=1
	fi
  fi

  # if either are 0, then user wants or needs new db as outlined in
  # earlier comments
  if [ $VALID_CLUSTER_DB = 0 ] || [ $PROMPT = 0 ]; then
	#
	# We cannot proceed if the services are running.  Give the user
	# a chance to stop the services.  If he chooses not to, bail.
	#
	check_enabled
	if [ $? = 1 ]
	then
		show_enabled
		ask_to_disable
		if [ $? = 0 ]
		then
			echo "A new configuration location was not set."
			exit 1
		else
			disable_services
			if [ $? != 0 ]
			then
				exit 1
			fi	
		fi
			
	fi
			
	get_location
	contains_data $FILE_LOC

	# if 1, then user entered an existsing db location, loop
	# back to ask what to do with it
	if [ $? = 1 ]; then
	  VALID_DB_ENTERED=1
	  continue
	else
          check_location $FILE_LOC

	  # if 0, that means location has failed, loop and
	  # get_location again
	  if [ $? = 0 ]; then
		VALID_CLUSTER_DB=0
		continue
	  fi
          # entered location passes tests
	  REPEAT=1
	  continue
	fi
  else
      # user wants to leave location where and how it is
	# FILE_LOC being passed all the way to end
	REPEAT=1
	continue
  fi
done

}

########################## MAIN FUNCTIONS ############################

######################## SMF HELPER FUNCTIONS ########################
#
# check if any SMF service is online (enabled)
#
check_enabled()
{
	$xopt
	typeset ret=0
	typeset svc

	for svc in $SMF_ENABLE
	do
		is_enabled $svc
		eval ${svc}_enabled=$?
		ret=$((ret | ${svc}_enabled))
	done

	return $ret
}

#
# Display which services are enabled.  (Must be called after check_enabled)
#
show_enabled()
{
	$xopt
	typeset svc

	echo "\nThe following Availability Suite services are enabled:"

	for svc in $SMF_ENABLE
	do
	if (( ${svc}_enabled == 1 ))
	then
	    printf "$svc "
	fi
	done

	echo ""
}


#
# check if the given SMF service is online (enabled)
# 
# $1: service name to check for
#
is_enabled()
{
	$xopt
	typeset en

	is_imported $1
	if [ $? = 1 ]
	then
		en=`svcprop -c -p general/enabled svc:/system/${1}:default`
		if [ $en = "true" ]
		then
			return 1
		fi
	fi
	
	return 0
	
}

#
# If necessary, flag no dependency check
#
no_depend_check()
{
	$xopt
	typeset pid
	typeset msg=0

	if [ $OS_MINOR -lt 11 ]
	then
		if [ -f $DSCFG_DEPEND_NOCHK ]
		then
			pid=`cat $DSCFG_DEPEND_NOCHK`
			echo "Another dscfgadm disable is in progress."
			echo "Waiting for pid: $pid to terminate..."

			while [ -f $DSCFG_DEPEND_NOCHK ]
			do
				if (( msg && (msg % 6 == 0)))
				then
					printf "\nAnother dscfgadm disable "
					printf "(pid: $pid) still appears to "
					printf " be in progress.\n"
					printf "If this is not the case, you "
					printf "may remove "
					printf "$DSCFG_DEPEND_NOCHK.\n"
				fi
				sleep 5
				msg=$((msg + 1))
			done
		fi

		touch $DSCFG_DEPEND_NOCHK
		echo $$ >> $DSCFG_DEPEND_NOCHK
	fi
}

#
# If necessary, remove the no dependency check flag
#
rm_no_depend_check()
{
	$xopt
	if [ $OS_MINOR -lt 11 ]
	then
		rm -f $DSCFG_DEPEND_NOCHK
	fi
}

# 
# set the filesystem/local dependency type and refresh
#
# $1: service name
# $2: either "require_all" or "optional_all"
#
set_fs_local_grouping()
{
	$xopt
	typeset svc=$1
	typeset dep_group=$2

	# set proper dependency type for fs-local
	if [ $svc != nws_rdcsyncd ]; then
		svccfg -s $FS_LOCAL_SVC setprop \
		   ${svc}-local-fs/grouping=$dep_group
		if [ $? -ne 0 ]
		then
			printf "command failed: svccfg -s $FS_LOCAL_SVC "
			printf "setprop ${svc}-local-fs/grouping=$dep_group "
			printf ">&2\n"
			return 1
		fi

		# we need local-fs to know about the new grouping attributes
		svcadm refresh ${FS_LOCAL_SVC}:default
		if [ $? -ne 0 ]
		then
			print "Failed to refresh ${FS_LOCAL_SVC} >&2"
			return 1
		fi
	fi

	return 0
}

#
# check if the grouping dependency type for filesystem/local is correct
#
# input:
# $1: service name
#
# returns:
#	0 if the setting is correct
#	1 if the setting is incorrect
# outputs: sets CORRECT_GROUPING with the value of what the grouping should be.
#
check_fs_local_grouping()
{
	$xopt
	typeset svc=$1
	typeset cur_grouping

	if [ $svc = nws_rdcsyncd ]
	then
		return 0
	fi

	# If it's not imported, we just return success, since we don't want
	# further processing
	is_imported $svc
	if [ $? = 0 ]
	then
		return 0
	fi

	# get the current grouping value from the repository
	cur_grouping=`svcprop -c -p ${svc}-local-fs/grouping $FS_LOCAL_SVC`

	# Figure out what the grouping should be (based on enabled status)
	is_enabled $svc
	if [ $? = 1 ]
	then
		CORRECT_GROUPING="require_all"
	else
		CORRECT_GROUPING="optional_all"
	fi

	if [ "$cur_grouping" != "$CORRECT_GROUPING" ]
	then
		# grouping is incorrect
		return 1
	else 
		# grouping is just fine
		return 0
	fi
}

#
# enable/disable the given SMF service.  Also, update the filesystem-local
# dependency, if appropriate.
#
# $1: service name to check for
# $2: "enable" or "disable"
#
svc_operation()
{
	$xopt
	typeset svc=$1
	typeset command=$2
	typeset enable_state
	typeset dep_group

	# If disabling, then enable_state better be true, and we are
	# transitioning to "option_all" grouping
	if [ $command = "disable" ]
	then
		enable_state=1
		dep_group="optional_all"

	# If enabling, then enable_state better be false, and we are
	# transitioning to "require_all" grouping
	elif [ $command = "enable" ]
	then	
		enable_state=0
		dep_group="require_all"
	else
		echo "invalid command: $command" >&2
	fi

	is_imported $svc
	if [ $? = 1 ]
	then
		is_enabled $svc
		if [ $? = $enable_state ]
		then
			if [ $enable_state -eq 1 ]
			then
				# we're doing a disable--remove hard dependency
				set_fs_local_grouping $svc $dep_group
				if [ $? -ne 0 ]
				then
					return 1
				fi
			fi

			svcadm $command -s svc:/system/$svc
			if [ $? != 0 ]
			then
				echo "$svc failed to $command" >&2
				return 1
			fi

			if [ $enable_state -eq 0 ]
			then
				# we just did an enable--create hard dependency 
				set_fs_local_grouping $svc $dep_group
				if [ $? -ne 0 ]
				then
					return 1
				fi
			fi

		else
			echo "$svc service already ${command}d... skipping"
		fi
	fi

	return 0
}

#
# This chart summarizes the behavior of the -r and -p sub-options for the 
# -e and -d options.
# There are 5 possible states, and 5 transitions out of each state.
#
# states: (vertical axis)
# -------
# 0: no services enabled
# C: one or both core services enabled (illegal state)
# R: both core services and RM services enabled
# P: both core services and PITC service enabled
# A: all services enabled
#
# transitions: (horizontal axis)
# ------------
# +/-a: enable/disable, respectively, with neither -r nor -p
# +/-r: enable/disable, respectively, with -r flag
# +p: enable with -p flag
#
# The result of the function is the next state after the action has been 
# successfully performed.
#
#      +a | -a | +r | -r | +p | 
#   ++----+----+----+----+----+ 
#   ++----+----+----+----+----+
# 0 || A  | 0* | R  | 0* | P  |
# --++----+----+----+----+----+
# C || A* | 0* | R  | 0  | P  | 
# --++----+----+----+----+----+
# R || A* | 0* | R* | 0  | A  |
# --++----+----+----+----+----+
# P || A* | 0* | A* | P* | P* |
# --++----+----+----+----+----+
# A || A* | 0  | A* | P  | A* |
# --++----+----+----+----+----+
#
# *: warning message is displayed, stating that a service is already
#    enabled/disabled.
#

# enable the SMF services needed for the Availability Suite
#
enable_services()
{
	$xopt
	typeset svc

	# first, import them if they have not yet been imported
	import_services

	# if neither r_flag nor p_flag is set, enable all services
	if (( (r_flag | p_flag) == 0 ))
	then
		for svc in $SMF_ENABLE
		do
			if ! svc_operation $svc enable
			then
				return 1
			fi
		done
	else
		# figure out which services are enabled
		check_enabled

		# First, make sure both core services are enabled
		for svc in nws_scm nws_sv
		do
			if (( ${svc}_enabled == 0 )) && \
				! svc_operation $svc enable
			then
				return 1	
			fi
		done

		if ((p_flag))
		then
			if ! svc_operation nws_ii enable
			then
				return 1
			fi
		fi
		
		if ((r_flag))
		then
			for svc in nws_rdc nws_rdcsyncd
			do
				if ! svc_operation $svc enable
				then
					return 1
				fi
			done
		fi

	fi	

	return 0
}

#
# disable the SMF services needed for the Availability Suite
#
disable_services()
{
	$xopt
	typeset svc

	check_device_groups
	if [ $? == 1 ]
	then
		return 1
	fi

	# This flags the shutdown scripts to not check to make sure the
	# services' dependents have been disabled.  The flag must be removed
	# before returning from this function.
	no_depend_check

	# NB: p_flag is not allowed for disables.  II should not be
	# disabled if sndr is enabled.  If rdc is not enabled, disabling just
        # II is equivalent to disabling all the remaining services.

	# If no flags passed in, just disable everything
	if (( r_flag == 0 ))
	then
		for svc in $SMF_DISABLE
		do
			if ! svc_operation $svc disable
			then
				rm_no_depend_check
				return 1
			fi
		done

		# Now that we've disable the services, lets unload them
		# from the Solaris kernel
		#
		modinfo | grep '(nws:' | grep -v "kRPC Stub" | sort -r | cut -d' ' -f1 | xargs -l modunload -i 2>/dev/null
		modinfo | grep '(nws:' | grep -v "kRPC Stub" | sort -r | cut -d' ' -f1 | xargs -l modunload -i 2>/dev/null
	else
		# we're disabling just rdc.  If II is not already enabled,
		# we disable core services, as well.
		
		# figure out which services are enabled
		check_enabled

		for svc in nws_rdcsyncd nws_rdc
		do
			if ! svc_operation $svc disable
			then
				rm_no_depend_check
				return 1
			fi
		done

		if (( nws_ii_enabled == 0 ))
		then
			for svc in nws_sv nws_scm
			do
				if ((${svc}_enabled)) && \
					! svc_operation $svc disable
				then
					rm_no_depend_check
					return 1	
				fi
			done
		fi
	fi


	rm_no_depend_check
	return 0
}

#
# check if a service has been imported into the repository
# $1: service to check 
# returns 1 if it is imported, 0 if it is not
#
is_imported()
{
	$xopt

	typeset svc=$1

	svcprop -q -p general/entity_stability svc:/system/${svc}
	if [ $? = 1 ]
	then
		return 0
	else
		return 1
	fi
}

#
# import the SMF services into the repository, if necessary
#
import_services()
{
	$xopt
	typeset svc

 	for svc in $SMF_ENABLE
	do
          	import_service $svc
	done
}

#
# check to see if an SMF service is in the repository.	If it is not,
# import it in.
# $1: name of service to import
#
import_service()
{
	$xopt
 	typeset svc=$1

	is_imported $svc
	if [ $? = 0 ]
	then
		if [ -f $PKG_INSTALL_ROOT/$MANIFEST_PATH/$svc.xml ]
		then
			svccfg import $PKG_INSTALL_ROOT/$MANIFEST_PATH/$svc.xml

			if [ $OS_MINOR -lt 11 ]
			then
				# workaround for 6221374--let local-fs know
				# that it depends on us.
				svcadm refresh ${FS_LOCAL_SVC}:default
			fi
		fi
	fi
}


########################## MAIN ######################################

# getopt processing
enable=0
disable=0
set_location=0
get_info=0
r_flag=0
p_flag=0
while getopts "xedsirp" opt 2>/dev/null
do
  	case $opt in
	\?)
           	help
		;;
	e)
          	enable=1
		;;
	d)
          	disable=1
		;;
	x)
          	xopt="set -x"
		set -x
		;;
	s)
		set_location=1
		;;
	i)
		get_info=1
		;;
	r)
		r_flag=1
		;;
	p)
		p_flag=1
		;;
	esac
done

# at most one option (besides -x) may be specified at a time
options_count=$((enable + disable + set_location + get_info))
if [ $options_count -gt 1 ]
then
	help
elif [ $options_count = 0 ]
then
	NO_ARGS=1
fi

if (( ((r_flag + p_flag) > 0) && ((enable | disable) == 0) ))
then
	echo "-r and -p options may only be used with -d or -e options" >&2
	return 1
elif (( p_flag && disable ))
then
	echo "The -p option may not be used with the -d option" >&2
	return 1
fi



# set all the system information variables
get_system_state

# if we're enabling, we need to make sure we have a valid dscfg out there.
if [ $enable = 1 -a $VALID_LOCAL_DB != 1 ]
then
	echo "Cannot find a valid configuration database" >&2
	return 1
fi

if [ $NO_ARGS = 1 ]
then

	# only initialize the database if necessary
	if [ $VALID_LOCAL_DB = 1 ]; then
		echo "Local configuration database is already initialized."
	else
		initialize_local_db
		if [ $? != 0 ]; then
			return 1
		fi
	fi

	if [ $CLUSTER_CONFIGURED = 1 ]
	then
		if [ $VALID_CLUSTER_DB = 1 ]; then
			printf "Cluster configuration database is already "
			printf "initialized.\n"
		else	
			# ask the user for a cluster database location
			set_cluster_config

			# initialize the new db
			initialize_cluster_db
			if [ $? != 0 ]; then
				return 1
			fi
		fi

	fi

	# make sure that the local filesystem dependency type is correct
	for svc in $SMF_ENABLE
	do       
		check_fs_local_grouping $svc
		if [ $? -ne 0 ]
		then
			# NOTE: check_fs_local_grouping sets CORRECT_GROUPING
			# To avoid this issue in the future, always administer
			# the services using dscfgadm.
			printf "Warning: Fixing dependency for $svc.\n"
			set_fs_local_grouping $svc $CORRECT_GROUPING
			if [ $? -ne 0 ]
			then
				return 1
			fi
		fi
	done

	# give the user the chance to startup AVS services, if not started
	check_enabled
	if [ $? = 1 ]; then
		if [ $OLD_VALID_LOCAL_DB = 0 ]; then
			printf "WARNING: AVS services are running on a system "
			printf "which had no valid configuration\ndatabase\n"
		fi
		show_enabled
	else
		ask_to_enable
		if [ $? = 1 ]; then
			enable_services
			if [ $? != 0 ]
			then
				return 1
			fi
		fi
	fi

elif [ $enable = 1 ]
then
	enable_services
	if [ $? != 0 ]
	then
		return 1
	fi

elif [ $disable = 1 ]
then
    	disable_services
	if [ $? != 0 ]
	then
		return 1
	fi

elif [ $get_info = 1 ]
then
	display_info

elif [ $set_location = 1 ]
then
	if [ $CLUSTER_CONFIGURED = 1 ]
	then
		# ask the user for a cluster database location
		set_cluster_config

		# initialize the new db
		initialize_cluster_db
		if [ $? != 0 ]; then
			return 1
		fi
	else
		echo "$PROG -s is only available on Sun Cluster OE systems" >&2
		return 1
	fi
fi

return 0


########################## MAIN ######################################

