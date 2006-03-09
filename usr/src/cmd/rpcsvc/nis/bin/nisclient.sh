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
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# nisclient -- script to setup NIS+ clients

#
# print_usage(): ask user if they want to see detailed usage msg.
#
print_usage()
{
   echo
   get_yesno "  Do you want to see more information on this command? \\n\
  (type 'y' to get a detailed description, 'n' to exit)"
   if [ $ANS = "n" -o $ANS = "N" ]
   then
    echo
    return 1
   else
    print_more
   fi
   exit 1
}


#
# print_more(): print the usage message.
#
print_more()
{
	more << EOF
USAGE:
  o to create credentials for NIS+ client or NIS+ principals:
	$PROG  -c  [-o]  [-v]  [-x]  [-l <NIS+_password>] [-d <NIS+_domain>]
		<name> ...

  o to initialize NIS+ client machines:
	$PROG  -i  [-S 0|2]  [-v]  [-x]  -h <NIS+_server_host>
		[-a <NIS+_server_addr>]  [-d <NIS+_domain>]

  o to initialize NIS+ users:
	$PROG -u  [-v]  [-x]

  o to restore the network service environment:
	$PROG -r

OPTIONS:
     -a <NIS+_server_addr>
	 specifies the IP address for the NIS+ server.  This option is
	 *ONLY* used with the "-i" option.

     -c  adds DES credentials for NIS+ principals.

     -d <NIS+_domain>
	 specifies the NIS+ domain where the credential should be created
	 when used in conjuction with the -c option.  It specifies the
	 name for the new NIS+ domain when used in conjuction with the
	 -i option.  The default is your current domain name.

     -h <NIS+_server_host>
	 specifies the NIS+ server's hostname.  This option is *ONLY*
	 used with the "-i" option.

     -i  initializes a NIS+ client machine.  Also see the -S option.

     -l <network_password>
	 specifies the network password for the clients.  This option is
	 *ONLY* used with the "-c" option.  If this option is not specified,
	 this script will prompt you for the network password.

     -o  overwrite existing credential entries.  The default is not
	 to overwrite.  This is *ONLY* used with the "-c" option.

     -r  restores the network service environment.

     -S 0|2
	 specifies the authentication level for the NIS+ client.  Level 0 is
	 for unauthenticated clients and level 2 is for authenticated (DES)
	 clients.  The default is to set up with level 2 authentication.
	 This option is *ONLY* used with -i option.  nisclient always uses
	 level 2 authentication (DES) for both -c and -u options.  There is
	 no need to run nisclient with -u and -c for level 0 authentication.

     -u  initializes a NIS+ user.

     -v  runs this script in verbose mode.

     -x  turns the "echo" mode on.  This script just prints the commands
	 that it would have executed.  The commands are printed with
	 leading "+++".  Note that the commands are not actually executed.
	 The default is off.

EOF
}


print_ciru_usage()
{
   if [ "$ERRciru_OPTION" = "$ciru_OPTION" ]
   then
  		echo "**WARNING: You have specified the '$ciru_OPTION' option twice."
		return 0
   fi
   echo
   echo "**ERROR: You have specified the '$ERRciru_OPTION' option after"
   echo "         having selected the '$ciru_OPTION' option."
   echo "Please select only one of these options: '-c', '-i', '-r' or '-u'."
   print_usage
   exit 1
}


#^L
# Generic Routines:
# -----------------
#
# This section contains general routines.
#       get_ans()       - prompts the message and waits for an input
#       get_yesno()     - prompts the message and waits for a Y or N answer
#       tolower(): converts upper to lower case.
#

#
# get_ans(): gets an answer from the user.
#		$1  instruction/comment/description/question
#		$2  default value
#
get_ans()
{
	if [ -z "$2" ]
	then
		echo "$1 \c"
	else
		echo "$1 [$2] \c"
	fi
	read ANS
	if [ -z "$ANS" ]
	then
		ANS=$2
	fi
}


##########  get_yesno constants:
##
##  There are two very common phrases passed to get_yesno:
##   These have been parameterized to provide "ease of use".
##	 Thus, there are three message "types" which are possible:
##	 --$CONTINUE:  "Do you want to continue? (type 'y' to continue, 'n' to exit this script)"
##   --$CONFIRM:   "Is this information correct? (type 'y' to accept, 'n' to change)"
##   --actual string is passed.
##
##	If the message is $CONTINUE, get_yesno will exit if the response is no.
##
###########
CONTINUE=2
CONFIRM=1
#
# get_yesno(): get the yes or no answer.
#		$1  message type  or message.
#
#
#
get_yesno()
{
	ANS="X"

	case $1 in
	$CONTINUE )
		INFOTEXT="Do you want to continue? (type 'y' to continue, 'n' to exit this script)"
		;;
	$CONFIRM )
		INFOTEXT="Is this information correct? (type 'y' to accept, 'n' to change)"
		;;
    *) INFOTEXT="$1"
		;;
	esac

	while [ "$ANS" != "y" -a "$ANS" != "n" -a "$ANS" != "Y" -a "$ANS" != "N" ]
	do
		get_ans "$INFOTEXT" ""
	done

	if [ "$1" = "$CONTINUE" ]; then
		if [ $ANS = "n" -o $ANS = "N" ]
		then
			exit
		fi
	fi

}


#
# tolower(): converts upper to lower case.
#               $1  string to convert
#
tolower()
{
	echo "$1" | tr '[A-Z]' '[a-z]'
}


#
# smf(5) routines
#	restart_instance() - restart instance or enable if not enabled
#

#
# restart_instance [-t] instance_fmri
#
restart_instance() {
	if [ "$1" = "-t" ]; then
		flag=-t
		shift
	else
		flag=
	fi

	if [ "`/usr/bin/svcprop -p restarter/state $1`" = "disabled" ];
	then
		/usr/sbin/svcadm enable $flag $1
	else
		/usr/sbin/svcadm restart $1
	fi
}


#^L
# Common Routines:
# ---------------
#
# This section contains common routines for the script.
#       init()          - initializes all the variables
#       parse_arg()     - parses the command line arguments
#

#
# init(): initializes variables and options
#
init()
{

	VERB='> /dev/null'
	PROG=`basename $0`
	ECHO="eval"
	BACKUP=no_nisplus
	DOM=`nisdefaults -d`
	NODOT=`echo $DOM | sed -e "s/\.$//"`
	SEC_DOM_NODOT=""
	SEC_DOM_DOT=""
	SEC=x
	PAS=""
	GEN=FALSE
	DEFSEC=x
	OWRITE="false"
	HOST=
	ADDR=

	OS=`uname -r | cut -d. -f1`
	OSVER=`uname -r | cut -d. -f2`

	#
	# The following files need special handling:
	# - they must be backed up and removed before initializing the client.
	#   These files are then automatically generated by nisinit and chkey
	#   during the initialization process.
	# - during the restore process, these files must be removed if the
	#   backup files are not found.
	#
	DEL_REST_FILES="/var/nis/NIS_COLD_START /var/nis/client_info /etc/.rootkey"

	#
	# The following file needs to be removed before the initialization
	# and restoring process.  There is no need to backup this file because
	# this file is generated by the nis_cachemgr automatically.
	#
	DELETE_FILES="/var/nis/NIS_SHARED_DIRCACHE /var/nis/.pref_servers"

	#
	# RESTORE_FILES variable contains a list of files that need to
	# be restored if the backup file exists.  Otherwise, the current
	# file should be left alone.
	#
	# May have to restore the /etc/inet/ipnodes file if the client is
	# initialized with an IPv6 address for the NIS+ server.
	#
	RESTORE_FILES="/etc/defaultdomain $HOSTS_FILE"

	#
	# REST_DOM_DIR variable is the same as RESTORE_FILES except for
	# directories.  Specifically, this is for directories which are
	# *not* generated by this script, rather just need renaming to
	# avoid conflicts in a NIS+ client environment.
	#
	REST_DOM_DIR="/var/yp/binding/$NODOT"

	#
	# The following section is needed for 4.x support.
	#
	# Again, /etc/inet/ipnodes file may need to be added in the future.

	HOSTS_FILE=/etc/inet/hosts
	PATH=/usr/lib/nis:/usr/sbin:/usr/bin:/usr/lib/netsvc/yp:$PATH; export PATH
	RESTORE_FILES="$RESTORE_FILES /etc/nsswitch.conf"
	YPPROC="ypbind -broadcast"
}


#
# parse_arg(): parses the input arguments.
# It returns the number to be shift in the argument list.
#
parse_arg()
{
	while getopts "a:cd:g:h:ik:l:orS:uvx" ARG
	do
		case $ARG in
		a)	ADDR=$OPTARG;;
		c)	if [ -z "$ACTION" ]
			then
				ACTION="create"
				ciru_OPTION="-c"
			else
				ERRciru_OPTION="-c"
				print_ciru_usage
			fi;;
		d)	if [ "`echo $OPTARG | sed -e 's/.*\(.\)$/\1/'`" != "." ]
			then
				NODOT=$OPTARG
				DOM=${NODOT}.
			else
				DOM=$OPTARG
				NODOT=`echo $DOM | sed -e "s/\.$//"`
			fi
			REST_DOM_DIR="/var/yp/binding/$NODOT";;
		g)	GEN="TRUE"
			GENFILE=$OPTARG;;
		h)	HOST=$OPTARG;;
		i)	if [ -z "$ACTION" ]
			then
				ACTION="init"
				ciru_OPTION="-i"
			else
				ERRciru_OPTION="-i"
				print_ciru_usage
			fi;;
		k)	if [ "`echo $OPTARG | sed -e 's/.*\(.\)$/\1/'`" != "." ]
			then
				SEC_DOM_NODOT=$OPTARG
				SEC_DOM_DOT=${NODOT}.
			else
				SEC_DOM_DOT=$OPTARG
				SEC_DOM_NODOT=`echo $SEC_DOM_DOT | sed -e "s/\.$//"`
			fi;;
		l)	PAS=$OPTARG;;
		o)	OWRITE="";;
		r)	if [ -z "$ACTION" ]
			then
				ACTION="restore"
				ciru_OPTION="-r"
			else
				ERRciru_OPTION="-r"
				print_ciru_usage
			fi;;
        	S)	VALUE=`expr "$OPTARG" : "\([02]\)"`
            		if [ -z "$VALUE" ]
            		then
                		echo "**ERROR: invalid security level."
	  			echo "	It must be either 0 or 2."
               		 	exit 1
            		fi
            		SEC=$VALUE;;
		v)	VERB="";;
		u)	if [ -z "$ACTION" ]
			then
				ACTION="user"
				ciru_OPTION="-u"
			else
				ERRciru_OPTION="-u"
				print_ciru_usage
			fi;;
		x)	ECHO="echo +++";;
		\?)	print_usage
			exit 1;;
		*)	echo "**ERROR: Should never get to this point!!!!!"
			print_usage
			exit 1;;
		esac
	done
	return `expr $OPTIND - 1`
}


#^L
# Common Routines used by -c and -i:
# ----------------------------------
#
# This section contains routines to setup a client.
#	setup_backup()	- sets up the the backup files
#	setup_domain()	- sets up the domain
#	setup_server()	- sets up the server information
#	setup_switch()	- sets up the switch
#	setup_security()- sets up the local keys
#	do_nisinit()	- runs the nisinit command
#	rm_servdata()	- deletes /var/nis/data, /var/nis/trans.log &
#			  /var/nis/data.dict*
#

#
# setup_backup(): backup all the files specfied in variable $RESTORE_FILES
# to <file>.$BACKUP and save a temporary copy of previous backup.
#
setup_backup()
{
	eval "echo setting up backup files... $VERB"

	trap restore_tmp 2

	# ... save a copy of current backup copies
	for FILE in $RESTORE_FILES $DEL_REST_FILES
	do
		if [ -f $FILE.$BACKUP ]
		then
			$ECHO mv $FILE.$BACKUP $FILE.$BACKUP.$$ > /dev/null &
		fi
	done

	# ... save a copy of these special files: coldstart and rootkey
	for FILE in $DEL_REST_FILES
	do
		if [ -f $FILE ]
		then
			eval "echo saving a copy of $FILE... $VERB"
			$ECHO cp $FILE $FILE.$BACKUP
		fi
	done

	trap restore_here 2
}


#
# setup_domain(): sets up "domainname" and "/etc/defaultdomain" with the specified
# domain information.
#
setup_domain()
{
	echo "setting up domain information \"$DOM\"..."
	if [ `nisdefaults -d` != $DOM ]
	then
		# NODOT is used to support 4.x YP clients
		$ECHO domainname $NODOT
	fi

	# ... we need to check the /etc/defaultdomain file separately.
	# We cannot assume that the /etc/defaultdomain is set to the
	# same value as the domainname is.
	#
	DEFDOM=`sed -n -e "1p" /etc/defaultdomain`
	if [ "$DEFDOM" != $NODOT ]
	then
		$ECHO "cp /etc/defaultdomain /etc/defaultdomain.$BACKUP > /dev/null"
		$ECHO "domainname > /etc/defaultdomain"
	fi
	echo ""

	# ... save a copy of current backup copies just like for
	# $RESTORE_FILES and $DEL_REST_FILES, but since this script
	# does not generate a new version of the directories, we
	# just rename it, and restore later if necessary.
	for FILE in $REST_DOM_DIR
	do
		if [ -d $FILE ]
		then
		    if [ -d $FILE.$BACKUP ]
		    then
			    $ECHO mv -f $FILE.$BACKUP $FILE.$BACKUP.$$ > /dev/null &
		    fi
		    $ECHO mv -f $FILE $FILE.$BACKUP > /dev/null &
		fi
	done
}



#
# setup_server(): adds server information into /etc/hosts file.
# Initializes $ADDR & $HOST (addr & name of place to get COLDSTART file)
#
# Will have to modify this function to account for IPV6 addresses being
# passed as the server address (when the NIS+ servers start running over IPV6).

setup_server()
{
	eval "echo setting up NIS+ server information... $VERB"
	while [ -z "$HOST" ]
	do
		get_ans "Type server's hostname:" ""
		HOST=$ANS
	done
	# Parse $HOSTS_FILE, first kill all comments,
	# then check for $HOST as a word by itself,
	# then take just the first such line.
	# Characters within [] are <space> and <tab>.
	ENTRY=`sed -e 's/#.*$//' $HOSTS_FILE | \
		awk '/[ 	]'$HOST'([ 	]|$)/ \
		{ print $0; exit}'`
	if [ "$ENTRY" ]
	then
		if [ -z "$ADDR" ]
		then
			eval "echo $HOST is already in the /etc/hosts file. $VERB"
			echo ""
			ADDR=`echo $ENTRY | awk '{print $1}'`
			return
		else
			OLD_ADDR=`echo $ENTRY | awk '{print $1}'`
			$ECHO "cp $HOSTS_FILE $HOSTS_FILE.$BACKUP"
			$ECHO "sed -e \"/$ENTRY/s/^$OLD_ADDR/$ADDR/\" \
				$HOSTS_FILE > /tmp/hosts.$$"
			$ECHO mv /tmp/hosts.$$ $HOSTS_FILE > /dev/null
			return
		fi
	elif [ -z "$ADDR" ]
	then
		DEFADDR=""
		zone=`/sbin/zonename`
		PROC=`/usr/bin/pgrep -z $zone ypbind`
		if [ ! -z "$PROC" ]
		then
			# ... try yp maps
			DEFADDR=`ypmatch $HOST hosts 2> /dev/null | cut -d' ' -f1`
		else
			# ... try nisplus tables
			if [ -f /var/nis/NIS_COLD_START ]
			then
				DEFADDR=`nismatch -P $HOST hosts.org_dir 2> /dev/null | cut -d' ' -f3`
			fi
		fi
		while [ -z "$ADDR" ]
		do
			get_ans "Type server ${HOST}'s IP address:" "$DEFADDR"
			ADDR=$ANS
		done
	fi

	$ECHO "cp $HOSTS_FILE $HOSTS_FILE.$BACKUP"
	$ECHO "echo $ADDR  $HOST >> $HOSTS_FILE"
	eval "echo $VERB"
}


#
# setup_switch(): copies the nisplus switch configuration file to
# nsswitch.conf.
#
setup_switch()
{
	echo "setting up the name service switch information..."
	$ECHO "/bin/rm -f /etc/.rootkey 2> /dev/null"
	diff /etc/nsswitch.conf /etc/nsswitch.nisplus > /dev/null
	if [ $? -eq 0 ]
	then
		eval "echo The switch configuration file is already set to use NISPLUS. $VERB"
		echo ""
		restart_instance network/rpc/keyserv:default
		return
	fi

	$ECHO "cp /etc/nsswitch.conf /etc/nsswitch.conf.$BACKUP"
	$ECHO "cp /etc/nsswitch.nisplus /etc/nsswitch.conf"

	restart_instance network/rpc/keyserv:default
	echo ""
}


#
#	print_passwd_request()
#	Utility print routine for setup_security & old_setup_security
#   Made a routine to provide consistency in outputting messages,
#	and so only 1 place has to be changed.
#		$1 is the same as $1 for the calling routine.
#
print_passwd_request()
{
	eval "echo setting up security information for $1... $VERB"
	echo "At the prompt below, type the network password (also known"
	echo "as the Secure-RPC password) that you obtained either"
	echo "from your administrator or from running the nispopulate script."
}


#
# setup_security(): runs chkey to change the network password same as the
# login passwd.
#		$1  specifies root or user setup
#
setup_security()
{
	if [ $1 = "root" ]
	then
		MESS="root"
	else
		MESS="user"
	fi
	print_passwd_request $1
	$ECHO "chkey -p > /dev/null"
	if [ $? -ne 0 ]
	then
		echo "**ERROR: chkey failed."
		echo ""
		echo "The network password that you have entered is invalid."
		echo "If this machine was initialized before as a NIS+ client,"
		echo "please enter the $MESS login password as the network"
		echo "password."
		echo "Or re-type the network password that your administrator"
		echo "gave you."
		echo ""

		$ECHO "chkey -p > /dev/null"
		if [ $? -ne 0 ]
		then
			echo "**ERROR: chkey failed again."
			echo "Please contact your network administrator to verify your network password."
			if [ $1 = "root" ]
			then
				restore_here
			fi
		fi
	fi
	echo ""
	echo "Your network password has been changed to your login one."
	echo "Your network and login passwords are now the same."
	echo ""
}


#
# do_nisinit(): runs nisinit.
# use $ADDR, as /etc/hosts isn't read if nis+ running
#
# Will have to modify this function for working with IPV6 NIS+ servers
do_nisinit()
{
	eval "echo running nisinit command ... $VERB"

	$ECHO "/bin/rm -f $DELETE_FILES 2> /dev/null"
	$ECHO "mv -f /var/nis/NIS_COLD_START /var/nis/NIS_COLD_START.$BACKUP 2> /dev/null"
	if [ -z "$SEC_DOM_DOT" ]
	then
		eval "echo nisinit -c -H $ADDR ... $VERB"
		$ECHO "nisinit -c -H $ADDR > /dev/null"
	else
		eval "echo nisinit -c -k $SEC_DOM_DOT -H $ADDR ... $VERB"
		$ECHO "nisinit -c -k $SEC_DOM_DOT -H $ADDR > /dev/null"
	fi
	if [ $? -ne 0 ]
	then
		echo "**ERROR: nisinit failed."
		restore_here
	fi
	echo ""
}



#
# rm_servdata(): removes the directory /var/nis/data, the trans.log file,
# and the /var/nis/data.dict* file(s) if the client machine is a NIS+
# server machine.
#
rm_servdata()
{
        $ECHO "rm -f /var/nis/trans.log > /dev/null"
        $ECHO "rm -f /var/nis/data.dict* > /dev/null"
        $ECHO "rm -rf /var/nis/data > /dev/null"
        echo ""
}



#
#
# Client initialization Routine:
# -------------------------------
#
# This section contains routine to initialize a client.
#	init_client()	- the main module to initialize a client
#

#
# init_client(): initializes client
#
init_client()
{
	eval "echo initializing client machine... $VERB"
	WHO=`id | sed -e "s/uid=[0-9]*(\([^ )]*\)).*/\1/"`
	if [ $WHO != "root" ]
	then
		echo "**ERROR: You must be root to use the -i option."
		exit 1
	fi

	echo ""
	if [ ! -z "$SEC_DOM_DOT" ]
	then
		eval "echo comparing the system domain and the secured RPC domain... $VERB"
		check_rpc_domain
		if [ "$SEC_DOM_DOT" != "$DOM" ]
		then
			echo "Initializing client `uname -n` for Secure RPC domain \"$SEC_DOM_NODOT\"."
			echo "The system default domainname will be set to a different domain \"$DOM\"."
		else
			echo "Initializing client `uname -n` for domain \"$DOM\"."
		fi
	else
		echo "Initializing client `uname -n` for domain \"$DOM\"."
	fi
		

	if [ -d /var/nis/data ]
	then
		echo ""
		echo "WARNING: this machine serves NIS+ directories. Once this script is"
		echo "executed, you will not be able to restore the existing NIS+ server"
		echo "environment. Are you sure you want to proceed?"
		get_yesno "(type 'y' to continue, 'n' to exit this script)"
		if [ $ANS = "n" -o $ANS = "N" ]
		then
			exit
		fi
		echo "Once initialization is done, you will need to reboot your"
		echo "machine."
		echo ""
	else
		echo "Once initialization is done, you will need to reboot your"
		echo "machine."
		echo ""
		get_yesno $CONTINUE
		echo ""
	fi

	eval "echo killing NIS and/or NIS+ processes... $VERB"
	svcadm disable network/nis/client
	svcadm disable -t network/rpc/nisplus
	eval "echo stopping nscd ... $VERB"
	svcadm disable -t system/name-service-cache
	eval "echo '' $VERB"

	setup_backup

	setup_server

	setup_domain

	setup_switch

	do_nisinit

	if [ "$SEC" = "2" ]
	then
		eval "echo -S 2 option specified, setting up security... $VERB"
		setup_security root
	elif [ "$SEC" = "x" ]
	then
		LOOKUP_DOM=${SEC_DOM_DOT:-$DOM}
		if nistest '[cname='`nisdefaults -h`'],cred.org_dir'.$LOOKUP_DOM;
		then
			eval "echo credential exists for setting up security... $VERB"
			setup_security root
		fi
	fi

	svcadm enable network/rpc/nisplus
	eval "echo starting nscd ... $VERB"
	svcadm enable system/name-service-cache

	remove_tmp

	# As this operation is likely configuration changing, restart the
	# name-services milestone (such that configuration-sensitive services
	# are in turn restarted).
	/usr/sbin/svcadm restart milestone/name-services

	echo "Client initialization completed!!"
	echo "Please reboot your machine for changes to take effect."
}


#
#
# User initialization Routine:
# -----------------------------
#
# This section contains routine to initialize an user.
#	init_user()	- the main module to initialize an user
#

#
# init_user(): initializes user
#
init_user()
{
	if [ $OS -eq 4 ]
	then
		echo "**ERROR: NIS+ client libraries are not available in 4.x"
		echo "	You must access NIS+ tables through NIS (YP)."
		exit 1
	fi

	eval "echo initializing user information... $VERB"
	WHO=`id | sed -e "s/uid=[0-9]*(\([^ )]*\)).*/\1/"`
	if [ $WHO = "root" ]
	then
		echo "**ERROR: You cannot use the -u option as a root user."
		print_usage
		exit 1
	fi

	if [ "$SEC" = "2" ]
	then
		eval "echo -S 2 option specified, setting up security... $VERB"
		setup_security user
		eval "echo User initialization completed!! $VERB"
	elif [ "$SEC" = "0" ]
	then
		echo "**WARNING: it is not necessary to initialize NIS+ users"
		echo "	for unauthenticated users."
	elif [ "$SEC" = "x" ]
	then
		WHO=`id | sed -e "s/uid=[0-9]*(\([^ )]*\)).*/\1/"`
		if nistest '[cname='$WHO.$DOM'],cred.org_dir'.$DOM;
		then
			eval "echo credential exists for setting up security... $VERB"
			setup_security user
			eval "echo User initialization completed!! $VERB"
		else
			echo "**WARNING: you do not have NIS+ credentials."
			echo "	You can either use NIS+ service as an unauthenticated user"
			echo "	or ask your network administrator to create a credentital for you."
		fi
	fi
}




#
#
# Restore Routines:
# -----------------
#
# This section contains routines to restore the environment.
#	restore_domain()- restores the domain
#	restore_switch()- restores the switch
#	mv_file()	- moves file.$BACKUP file
#	restore_file()	- restores all the files
#	restore_nis()	- restores all NIS+ files
#	restore_service()
#			- restart either NIS or NIS+ daemons
#	restore()	- the main module to restore the environment
#	restore_here()	- same as restore() except it's called from init_client()
#	restore_tmp()	- restores temporary backup files for previous backups
#	remove_tmp()	- remove the backup files for the previous backups
#

#
# restore_domain(): resets the "domainname" according to "/etc/defaultdomain".
#
restore_domain()
{
	DEFDOM=`sed -n -e "1p" /etc/defaultdomain`
	NODOT=`echo $DEFDOM | sed -e "s/\.$//"`
	echo "restoring domain to $DEFDOM..."
	if [ "${NODOT}." != `nisdefaults -d` ]
	then
		$ECHO domainname ${NODOT}
	fi
	echo ""
}


#
# restore_switch(): restarts the switch if necessary.
# restarts nscd to ensure that it tracks the switch
#
restore_switch()
{
	eval "echo '' $VERB"
	restart_instance network/rpc/keyserv:default
	eval "echo restarting nscd ... $VERB"
	restart_instance system/name-service-cache:default
}


#
# mv_file(): moves file.$BACKUP to file.
#		$1  file name to be moved.
#
mv_file()
{
	$ECHO "mv -f $1.$BACKUP $1 > /dev/null"
}


#
# restore_file(): restores the file specified.
#		$1  the file to be restored
# This routine will restore any file that has the backup file <file>.$BACKUP.
# The following table shows which backup files are created when the nisclient
# script is run based on the previous name service setup.
#
#	Files	 |  NIS -> NIS+	|  NIS+ -> NIS+
#     -----------+---------------+----------------
#     rootkey	 |	no	|	yes
#     coldstart  |	no	|	yes
#     client_info|	no	|	yes
#     switch	 |	yes	|	maybe
#     hosts	 |	maybe	|	maybe
#     domain	 |	maybe	|	maybe
#
# Based on this table, those special files defined in $DEL_REST_FILES need to
# be restored if any files from $RESTORE_FILES were restored (specially switch),
# or if backup files for all the files in $DEL_REST_FILES were found.
#
restore_file()
{
	for FILE in $RESTORE_FILES
	do
		if [ -f $FILE.$BACKUP ]
		then
			if mv_file $FILE;
			then
				RESTORE=TRUE
				echo "	File $FILE restored!"
			else
				echo "**ERROR: could not restore file $FILE"
				exit 1
			fi
		fi
	done

	for FILE in $REST_DOM_DIR
	do
		if [ -d $FILE.$BACKUP ]
		then
			if mv_file $FILE;
			then
				RESTORE=TRUE
				echo "	Directory $FILE restored!"
			else
				echo "**ERROR: could not restore directory $FILE"
				exit 1
			fi
		fi
	done

	# ... check if the backup files exist for the special files in
	# $DEL_REST_FILES
	if [ "$RESTORE" != "TRUE" ]
	then
		for FILE in $DEL_REST_FILES
		do
			if [ ! -f $FILE.$BACKUP ]
			then
				return
			fi
		done
	fi

	# ... restore special files: coldstart and rootkey
	# If the backup file exists, then restore.  Otherwise, remove
	# the file.
	#
	for FILE in $DEL_REST_FILES
	do
		if [ -f $FILE.$BACKUP ]
		then
			if mv_file $FILE;
			then
				RESTORE="TRUE"
				echo "	File $FILE restored!"
			else
				echo "**ERROR: could not restore file $FILE"
				exit 1
			fi
		else
			if [ -f $FILE ]
			then
				$ECHO "/bin/rm -f $FILE 2> /dev/null"
			fi
		fi
	done
}


#
# restore_nis(): removes the cache files: NIS_SHARED_DIRCACHE and
#	.pref_servers.
#
restore_nis()
{
	# ... remove the dircache file
	for CACHE in $DELETE_FILES
	do
		if [ -f $CACHE ]
		then
			$ECHO "/bin/rm -f $CACHE 2> /dev/null"
		fi
	done
}


#
# restore_service(): starts ypbind by checking the switch file.
# If NIS+ service is to be restored, it will start nis_cachemgr.
#
restore_service()
{
	SWITCH=`grep "^[a-z]*:" /etc/nsswitch.conf`

	if [ $OS -eq 5 ]
	then
		echo $SWITCH | grep -s "\<nisplus\>" >/dev/null
		if [ $? -eq 0 ]
		then
			echo "Will not start up ypbind process because the nsswitch.conf"
			echo "file shows that you are not using NIS."
			echo "restarting nis_cachemgr process..."
			restart_instance network/rpc/nisplus:default
			echo ""
			return
		else
			svcadm disable network/rpc/nisplus:default
		fi
	fi

	echo $SWITCH | grep -s "\<nis\>" >/dev/null
	if [ $? -eq 0 ]
	then
		echo "restarting NIS (YP) process..."
		svcadm enable network/nis/client:default
		echo ""
	fi
}


#
# restore(): restores the previous network information service.
#
restore()
{
	if [ $OS -eq 4 ]
	then
		echo "**ERROR: NIS+ client libraries are not available in 4.x"
		echo "	You must access NIS+ tables through NIS (YP)."
		exit 1
	fi

	WHO=`id | sed -e "s/uid=[0-9]*(\([^ )]*\)).*/\1/"`
	if [ $WHO != "root" ]
	then
		echo "This script must be run as root ..."
		exit 1
	fi

	echo "This script will restore the previous network information"
	echo "service.  It recovers all the files with the no_nisplus "
	echo "extension and restarts either NIS+ or NIS client processes"
	echo "according to the /etc/nsswitch.conf configuration file."
	echo ""
	echo "Once restore is done, you will need to reboot your machine."
	get_yesno $CONTINUE

	svcadm disable -t network/rpc/nisplus
	svcadm disable -t network/nis/client

	restore_file

	if [ "$RESTORE" = "TRUE" ]
	then
		restore_domain

		restore_switch

		restore_service

		echo "Client files restored!"
		echo "Please reboot your machine for changes to take effect."
	else
		echo "Nothing to restore from!"
		echo "This script can only restore from NIS+ setup done with"
		echo "nisclient command."
	fi

	# Again:  a configuration changing operation, so restart the
	# name-services milestone.
	/usr/sbin/svcadm restart milestone/name-services
}


#
# restore_here(): same as restore() except it's called from init_client()
# when it fails to initialize a client.
#
restore_here()
{
	echo ""
	echo "Restoring your network service..."
	echo ""

	svcadm disable -t network/rpc/nisplus
	svcadm disable -t network/nis/client

	restore_file

	if [ "$RESTORE" = "TRUE" ]
	then
		restore_domain

		restore_switch

		restore_service

		echo "Client files restored!"
	fi
	restore_tmp

	/usr/sbin/svcadm restart milestone/name-services
	exit 1
}


#
# restore_tmp(): restores temporary backup files for previous backups.
#
restore_tmp()
{
	# ... restore from temporary backup files for previous backup
	for FILE in $RESTORE_FILES $DEL_REST_FILES
	do
		if [ -f $FILE.$BACKUP.$$ ]
		then
			eval "echo restoring the temporary backup file for $FILE... $VERB"
			$ECHO mv -f $FILE.$BACKUP.$$ $FILE.$BACKUP > /dev/null
		fi
	done
	for FILE in $REST_DOM_DIR
	do
		if [ -d $FILE.$BACKUP.$$ ]
		then
			eval "echo restoring the temporary backup directory for $FILE... $VERB"
			$ECHO mv -f $FILE.$BACKUP.$$ $FILE.$BACKUP > /dev/null
		fi
	done
	exit 1
}


#
# remove_tmp(): remove the backup files for the previous backups
#
remove_tmp()
{
	for FILE in $RESTORE_FILES $DEL_REST_FILES
	do
		if [ -f $FILE.$BACKUP.$$ ]
		then
			eval "echo removing the temporary backup file for $FILE... $VERB"
			$ECHO "/bin/rm -f $FILE.$BACKUP.$$"
		fi
	done
	for FILE in $REST_DOM_DIR
	do
		if [ -d $FILE.$BACKUP.$$ ]
		then
			eval "echo removing the temporary backup directory for $FILE... $VERB"
			$ECHO "/bin/rm -rf $FILE.$BACKUP.$$"
		fi
	done
}


#
#
# Adding client Routines:
# -----------------------
#
# This section contains routines to add a client or a principal into
# credential table.
#	check_perm()	- check for the write permission of a given object
#	check_domainname()
#			- check to see if the domainname has at least 2 components
#	check_rpc_domain()
#			- compares the system default domain and the secured
#			  domain defines by the -k option
#	check_domain()	- check a directory is valid and get the servers'
#			  info
#	check_type()	- check the type of name specified
#	add_LOCALcred() - adds the LOCAL credential into the credential table
#	add_DEScred()	- adds the DES credential into the credential table
#	add_RSAcred()	- adds the RSA credential into the credential table
#	add_cred()	- adds credentials into the credential table
#	insert_cred()	- the main module to add credentials
#	

#
# check_perm(): checks if we have write permission to the NIS+ table
# This should be replaced with nisaccess command when it's available
#		$1  the table to be checked.
#
check_perm()
{
	if [ "$ECHO" = "echo" ]
	then
		return
	fi

	echo "checking $1 permission..."
	MYPRINC=`nisdefaults -p`
	if [ $MYPRINC = "nobody" ]
	then
		if nistest -a n=c $1;
		then
			return
		else
			return 1
		fi
	fi

	DUMMY=`nisls -ld $1`
	if [ $? -ne 0 ]
	then
		exit 1
	fi
	OWN=`echo $DUMMY | cut -d" " -f3`
	if [ "$OWN" = $MYPRINC ]
	then
		if nistest -a o=c $1;
		then
			return
		else
			return 1
		fi
	fi

	DUMMY=`nisls -ldg $1`
	if [ $? -ne 0 ]
	then
		exit 1
	fi
	OWN=`echo $DUMMY | cut -d" " -f3`
	if [ ! -z "$OWN" ]
	then
		if nisgrpadm -t -s "$OWN" $MYPRINC;
		then
			if nistest -a g=c $1;
			then
				return
			else
				return 1
			fi
		fi
	fi

	if nistest -a w=c $1;
	then
		return
	else
		return 1
	fi
}


#
# check_domainname(): check validity of a domain name.  Currently we check
#	that it has at least two components.
#		$1  the domain name to be checked
#
check_domainname()
{
	if [ ! -z "$1" ]
	then
		t=`expr "$1" : '[^.]\{1,\}[.][^.]\{1,\}'`
		if [ "$t" = 0 ]
		then
			echo '**ERROR: invalid domain name ('$1')'
			echo '  It must have at least two components.'
			echo '  For example, "company.com.".'
			print_usage
			exit 1
		fi
	fi
}

#
# check_rpc_domain(): compares the secured domain against the system default
#	domain.  We check to make sure that the local system domain (defined in
#	the /etc/defaultdomain or by the -d option if specified) is at the same
#	level or below the domain specified by the -k option. This is required
#	mainly to support server living in its own domain fix.
check_rpc_domain()
{
	if [ -z "$SEC_DOM_DOT" ]
	then
		return
	fi

	if nistest -c $DOM le $SEC_DOM_DOT;
	then
		:
	else
		echo '***ERROR: invalid -k domain name ('$SEC_DOM_NODOT')'
		echo '	The system default domain ('$NODOT') must be either the same'
		echo '	as or a descendant of the Secure RPC domain ('$SEC_DOM_NODOT')'
		echo '	where the key is stored.'
		echo '	For example, if the system default domain is defined as'
		echo '	(sub.company.com), then the -k domain can be defined as either'
		echo '	sub.company.com or company.com.'
		exit 1
	fi
}


#
# check_domain(): checks if it's a valid domain and get the server's info.
#
check_domain()
{
	if [ "$ECHO" = "echo" ]
	then
		return
	fi

	echo "checking $DOM domain..."
	if nistest -t D $DOM;
	then
		:
	else
		echo "**ERROR: Don't know about the domain \"$DOM\"."
		echo "	 Please check the domain name."
		exit 1
	fi

	niscat -o $DOM > /tmp/$PROG.$$
	if [ $? -ne 0 ]
	then
		rm -f /tmp/$PROG.$$ > /dev/null
		exit 1
	fi
	SERVER=`sed -n -e "s/	Name *: //p" /tmp/$PROG.$$ | sed -n -e "1p"`
	rm -f /tmp/$PROG.$$ > /dev/null
	SER_NAME=`echo $SERVER | cut -d. -f1`
	SER_DOM=`echo $SERVER | cut -d. -f2-`
	if [ $SER_DOM = $SER_NAME ]
	then
		$SER_DOM=$DOM
	fi

	#
	# Will have to check ipnodes.org_dir also when NIS+ server has IPv6
	# interfaces.
	#
	DUMMY=`nismatch -P $SER_NAME hosts.org_dir.$SER_DOM`
	if [ $? -eq 0 ]
	then
		SERVER=`echo $DUMMY | sed -n -e "1p"`
		SER_ADDR=`echo $SERVER | cut -d" " -f3`
	else
		DUMMY=`grep -v "^#" $HOSTS_FILE | grep -i -s $SER_NAME`
		if [ $? -eq 0 ]
		then
			SERVER=`echo $DUMMY | sed -e "s/	/ /g"`
			SER_ADDR=`echo $SERVER | cut -d" " -f1`
		else
			echo "**ERROR: Couldn't get the server ${SER_NAME}'s address."
			exit 1
		fi
	fi
	echo ""
}



#
# check_type(): checks what type of credential to add into the credential
# table.  It tries to match the given name agains the passwd.org_dir and
# hosts.org_dir tables.  It assigns the value of "user" if the name is found
# in the passwd table and "host" if it's found in the hosts table.
#  *** The name cannot be in both table ***
#		$1  name
#
check_type()
{
	eval "echo checking info type for $NAME... $VERB"
	UTYPE="FALSE"
	HTYPE="FALSE"
	ARG=$1
	LARG=$1
	NEWNAME=""
	
   	# Checking both for IPV4 and IPV6 hosts
   	DUM1=`nismatch -P name=$ARG hosts.org_dir.$DOM`;

   	if [ $? -ne 0 ]
   	then
      		if nistest ipnodes.org_dir.$DOM;
      		then
         		DUM1=`nismatch -P name=$ARG ipnodes.org_dir.$DOM`;
      		fi
   	fi

	if [ -n "$DUM1" ]
	then
		H_NAME=`echo $DUM1 | cut -d' ' -f1`
		H_ALIAS=`echo $DUM1 | cut -d' ' -f2`
		if [ "`tolower $H_NAME`" != "`tolower $H_ALIAS`" ]
		then
			echo "**WARNING: $H_ALIAS is an alias name for host $H_NAME."
			echo "You cannot create credential for host alias."
			get_yesno "Do you want to create the credential for $H_NAME?"
			if [ $ANS = "y" -o $ANS = "Y" ]
			then
				NEWNAME=$H_NAME
				LARG=$H_NAME
				HTYPE="TRUE"
			else
				HTYPE="SKIP"	# for error message handling
			fi
		else
			HTYPE="TRUE"
		fi
	fi

	if nistest '[name='$LARG'],passwd.org_dir.'$DOM;
	then
		if [ $HTYPE = "TRUE" ]
		then
			echo "**ERROR: this name \"$LARG\" is in both the passwd and hosts tables."
			echo "	You cannot have an username same as the hostname."
			return 1
		fi
		UTYPE="TRUE"
	fi

	if [ $UTYPE = "TRUE" ]
	then
		TYPE="user"
	elif [ $HTYPE = "TRUE" ]
	then
		TYPE="host"
	else
		if [ $HTYPE != "SKIP" ]
		then
			echo "**ERROR: invalid name \"$LARG\"."
			echo "	It is neither an host nor an user name."
		fi
		return 1
	fi
}




#
# add_LOCALcred(): adds the LOCAL credential into the credential table.
#
add_LOCALcred()
{
	echo "adding LOCAL credential for $1..."

	DUMMY=`nismatch -P name=$1 passwd.org_dir.$DOM`
	if [ $? -ne 0 ]
	then
		return 1
	fi
	UID=`echo $DUMMY | cut -d: -f3`

	if [ $? -ne 0 ]
	then
		return 1
	fi
	$ECHO nisaddcred -p $UID -P $1.$DOM local $DOM
	return $?
}




#
# add_RSAcred(): adds the RSA credential into the credential table.
#		$1  either username or hostname
#		$2  password if specified
#
add_RSAcred()
{
	echo "adding RSA credential for $1..."

	if [ $# -eq 1 ]
	then
		$ECHO nisaddcred -p $1.$DOM -P $1.$DOM rsa $DOM
		return $?
	fi

	echo "nisaddcred -l $2 -p $1.$DOM -P $1.$DOM rsa $DOM"
	return $?
}

#
# add_DEScred(): adds the DES credential into the credential table.
#		$1  either username or hostname
#		$2  password if specified
#
add_DEScred()
{
	echo "adding DES credential for $1..."

	if [ $# -eq 2 ]
	then
		LPASS="-l $2"
	else
		LPASS=""
	fi
	if [ $TYPE = "user" ]
	then
		$ECHO nisaddcred $LPASS -p unix.${UID}@$NODOT -P $1.$DOM des $DOM
	else
		$ECHO nisaddcred $LPASS -p unix.$1@$NODOT -P $1.$DOM des $DOM
	fi
	return $?
}




#
# add_cred(): adds the credential.
#		$*  names to be added.
#
add_cred()
{
	while [ $# -ne 0 ]
	do
		NAME=$1
		check_type $NAME

		if [ $? -eq 0 ]
		then
			if [ ! -z "$NEWNAME" ]
			then
				NAME=$NEWNAME
			fi

			DUMMY=`nismatch $NAME.$DOM cred.org_dir.$DOM > /dev/null`
			if [ $? -eq 0 ]
			then
				if [ -z "$OWRITE" ]
				then
					echo ... overwriting the existing entry for principal $NAME!
				else
					echo ... principal $NAME already exist -- skipped!
					shift
					continue
				fi
			fi

			if [ $TYPE = "user" ]
			then
				if add_LOCALcred $NAME;
				then
					eval echo ... added LOCAL credential for $NAME. $VERB
				else
					eval "echo ... could not add LOCAL credential for $NAME. $VERB"
					TYPE="fail"
				fi
			fi
	
			if [ $TYPE != "fail" ]
			then
				case $SEC in
				2)      SECTYPE=DES;;
				3)      SECTYPE=RSA;;
				esac

				if add_${SECTYPE}cred $NAME $PAS;
				then
					eval "echo ... added $SECTYPE credential for $NAME. $VERB"
				else
					eval "echo ... could not add $SECTYPE credential for $NAME. $VERB"
					TYPE="fail"
				fi
			fi
			echo ""

			if [ $TYPE = "host" ]
			then
				DOIT=DOIT
			elif [ $TYPE = "user" ]
			then
				USERDOIT=DOIT
			fi

		fi
		shift
	done
}



#
# insert_cred(): adds NIS+ client or principals credentials
#
insert_cred()
{
	if [ $# -eq 0 ]
	then
		echo "**ERROR: missing hostnames or usernames."
		print_usage
		exit 1
	fi

	if [ "$SEC" = "0" ]
	then
		echo "**WARNING: it is not necessary to create NIS+ credentials"
		echo "	for unauthenticated users."
		return
	fi
	if [ "$SEC" != "2" -a "$SEC" != "x" ]
	then
		echo "**ERROR: invalid security level $SEC."
	fi
	SEC=2

	case $SEC in
	2)	MESS=DES;;
	3)	MESS=RSA;;
	esac
	echo ""
	echo "You will be adding $MESS credentials in domain $DOM for"
	echo $*
	echo ""
	if [ -z "$OWRITE" ]
	then
		echo "** nisclient will overwrite existing entries in the credential"
		echo "** table for hosts and users specified above."
	else
		echo "** nisclient will not overwrite any existing entries in the"
		echo "** credential table."
	fi
	echo ""
	get_yesno $CONTINUE
	echo ""

	check_domain

	check_perm cred.org_dir.$DOM
	if [ $? -ne 0 ]
	then
		echo "Sorry, no permission to create credentials!"
		exit 1
	fi
	echo ""

	add_cred $*

	if [ "$DOIT" = "DOIT" ]
	then
		if [ $GEN = "TRUE" ]
		then
			$ECHO "echo '#!/bin/sh' > $GENFILE"
			$ECHO "echo '#' > $GENFILE"
			$ECHO "echo '' > $GENFILE"
			$ECHO "echo "nisclient -i -h $SER_NAME -a $SER_ADDR -d $DOM" > $GENFILE"
		fi
		echo "For all new NIS+ clients added, you will need to run the"
		echo "following on the client's machine:"
		echo "nisclient -i -h $SER_NAME -a $SER_ADDR -d $DOM"
	fi

	if [ "$USERDOIT" = "DOIT" ]
	then
		echo ""
		echo "For all new NIS+ users added, you will need to update"
		echo "their keys on all machines that they are currently logged"
		echo "in by running keylogin(1), chkey(1), or nisclient(1M)."
	fi
}



#
#
# 			* * * MAIN * * *
#

# Display the obsolescence message in all the cases
echo ""
echo "********        ********    WARNING    ********        ********"
echo "NIS+ might not be supported in a future release. Tools to aid"
echo "the migration from NIS+ to LDAP are available in the Solaris 9"
echo "operating environment. For more information, visit"
echo "http://www.sun.com/directory/nisplus/transition.html"
echo "********        ********    *******    ********        ********"
echo ""

init

umask 22

parse_arg $*
shift $?

check_domainname "$DOM"

case $ACTION in
"init")
	init_client;;
"user")
	init_user;;
"create")
	insert_cred $*;;
"restore")
	restore;;
*)
	echo "**ERROR: you must specify one of the these options: -c, -i, -u, -r."
	print_usage
	exit 1
esac
