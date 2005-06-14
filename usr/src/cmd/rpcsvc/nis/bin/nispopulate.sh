#!/bin/sh
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
# Copyright (c) 1992-1997 by Sun Microsystems, Inc.
# All rights reserved.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# nispopulate -- script to populate NIS+ tables


#
# print_usage(): ask user if they want to see detailed usage msg.
#
print_usage()
{
   echo
   get_yesno "  Do you want to see more information on this command? \\n\
  (type 'y' to get a detailed description, 'n' to exit)"
   if [ $ANS = "y" -o $ANS = "Y" ]
   then
    print_more
   fi
   echo ""
   exit 1
}

print_more()
{
	more << EOF
USAGE:
  o to populate the table from NIS maps:
     $PROG  -Y  [-f]  [-n]  [-S 0|2]  [-u]  [-v]  [-x]  -h <NIS_server_host> 
		[-a <NIS_server_addr>]  [-l <network_passwd>]
		[-d <NIS+_domain>]  -y <NIS_domain>  [table] ...

  o to populate the table from files:
     $PROG  -F  [-f]  [-u]  [-v]  [-x]  [-S 0|2]  [-d <NIS+_domain>]
		[-l <network_passwd>]  [-p <directory_path>]  [table] ...

  o to populate the credential table from hosts/passwd tables:
     $PROG  -C  [-f]  [-v]  [-x]  [-d <NIS+_domain>] 
		[-l <network_passwd>]  [hosts|passwd]
OPTIONS:
     -a <NIS_server_addr> 
         specifies the IP address for the NIS server.  This option is
         *ONLY* used with the "-Y" option. 

     -C  populate the NIS+ credential table from passwd and hosts tables
	 using DES authentication (security level 2).

     -d <NIS+_domain>
	 specifies the NIS+ domain.  The default is the local domain.

     -F  populate NIS+ tables from files.

     -f  forces this script to populate the NIS+ tables without prompting
	 for confirmation.

     -h <NIS_server_host>
	 specifies the NIS server hostname to copy the NIS map from.  This
	 is *ONLY* used with the "-Y" option.  This host must be already
	 exist in either the NIS+ hosts table or /etc/hosts file.  If the
	 hostname is not defined, this script will prompt you for its IP
	 address.

     -l <network_passwd>
	 specifies the network password for populating the NIS+ credential
	 table.  This is *ONLY* used when you are populating the hosts and
	 passwd tables.  The default passwd is "nisplus".

     -n  do not overwrite local NIS maps in /var/yp/<NISdomain>
    	 directory if they already exist.  The default is to overwrite
	 the existing NIS maps in the local /var/yp/<NISdomain> 
	 directory.  This is *ONLY* used with the "-Y" option.

     -p <directory_path>
	 specifies the directory path where the files are stored.
	 This is *ONLY* used with the "-F" option.  The default is the
	 current working directory.

     -S 0|2
	 specifies the authentication level for the NIS+ client.  Level 0 is
	 for unauthenticated clients and no credentials will be created for
	 users and hosts in the specified domain.  Level 2 is for authenticated
	 (DES) clients and DES credentials will be created for users and hosts
	 in the specified domain.  The default is to set up with level 2
	 authentication (DES).  There is no need to run nispopulate with -C
	 for level 0 authentication.

     -u  updates the NIS+ tables (ie., adds, deletes, modifies) from either
	 files or NIS maps.  This option should be used to bring an NIS+
	 table up to date when there are only a small number of changes. 
	 The default is to add to the NIS+ tables without deleting any
	 existing entries.  Also, see the -n option for updating NIS+ 
	 tables from existing maps in the /var/yp directory.

     -v  runs this script in verbose mode.

     -x  turns the "echo" mode on.  This script just prints the commands
	 that it would have executed.  The commands are printed with
	 leading "+++".  Note that the commands are not actually executed.
	 The default is off.

     -Y  populate the NIS+ tables from NIS maps.

     -y <NIS_domain>
	 specifies the NIS domain to copy the NIS maps from.  This is 
	 *ONLY* used with the "-Y" option.  The default domain name is
	 the same as the local domain name.
EOF
}

print_CFY_usage()
{
   if [ "$ERRCFY_OPTION" = "$CFY_OPTION" ]
   then
    echo "**WARNING: You have specified the '$CFY_OPTION' option twice."
    return
   fi
   echo
   echo "**ERROR: You have specified the '$ERRCFY_OPTION' option after"
   echo "         having selected the '$CFY_OPTION' option."
   echo "Please select only one of these options: '-C', '-F' or '-Y'."
   print_usage
   exit 1
}


#NOTE:
#Standard NIS+ table names are:
#$MAPS shadow
#(shadow map is only used when populating from files)


#
# Generic Routines:
# -----------------
# 
# This section contains general routines.
#	get_ans()	- prompts the message and waits for an input
#	get_yesno()	- prompts the message and waits for a Y or N answer
#	tolower()	- converts upper to lower case.
#

#
# get_ans(): gets an asnwer from the user.
#		$1  instruction/comment/description/question
#		$2  default value
#
get_ans()
{
	if [ -z "$2" ]
	then
		if [ $OS -eq 5 ]
		then
			echo "$1 \c"
		else
			echo -n "$1 "
		fi
	else
		if [ $OS -eq 5 ]
		then
			echo "$1 [$2] \c"
		else
			echo -n "$1 [$2] "
		fi
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
#	$1	string to convert
#
tolower()
{
	echo "$1" | tr '[A-Z]' '[a-z]'
}



#
# Common Routines:
# ---------------
# 
# This section contains common routines for the script.
#	init()		- initializes all the variables
#	parse_arg()	- parses the command line arguments
#	check_perm()	- checks for the write permission for an object
#	get_security()	- gets the security information
#	update_info()	- updates the setup information
#	print_info()	- prints the setup information
#	confirm()	- prompts the user for confirmation
#	is_standard()	- check if it's a member of the standard maps
#

#
# init(): initializes variables and options
#
init()
{

	PROG=`basename $0`
	CFY_OPTION=""		# Keep track of Y, F or C option for error msgs.
	ERRCFY_OPTION=""	# 2nd C, F or Y error option.
	VERB='> /dev/null'	# NULL or "> /dev/null"
	VERB_OPT=''		# verbose option for nisaddent
	ECHO="eval"		# eval or echo
	BACKUP="no_nisplus"
	DOM=`nisdefaults -d`	# domainname with DOT
	NODOT=`echo $DOM | sed -e "s/\.$//"`
	YPDOM="$NODOT"		# YPdomain

	ACTION=""		# master or replica
	FORCE=""		# NULL or TRUE
	YPHOST=""		# NULL or <YPhostname>
	DIRPATH=""		# directory path where the files are
	PASSWD="nisplus"	# credential password
	UPDATE=""		# nisaddent update option
	NEW="overwrite"		# overwrite local NIS maps
	NSSWITCH="/etc/nsswitch.conf"

	STANDARD=""		# prints either standard or non-standard

	OS=`uname -r | cut -d. -f1`
	SEC=2			# security level
	TMPDIR=${TMPDIR:-/tmp}	# temporary directory
	MAPS="auto_master auto_home ethers group hosts ipnodes networks passwd protocols services rpc netmasks bootparams netgroup aliases timezone"
	MAPS="$MAPS auth_attr exec_attr prof_attr user_attr audit_user"

	if [ $OS -eq 5 ]
	then
      HOSTS_FILE=/etc/inet/hosts
		PATH=/usr/lib/nis:/usr/sbin:/usr/bin:/usr/lib/netsvc/yp:$PATH; export PATH
	else
                HOSTS_FILE=/etc/hosts
		PATH=/usr/etc/nis:/usr/etc:/usr/bin:/usr/etc/yp:$PATH; export PATH
	fi

}




#
# parse_arg(): parses the input arguments.
# It returns the number to be shift in the argument list.
#
parse_arg()
{
	while getopts "a:Cd:Ffh:l:np:S:uvxYy:" ARG
	do
		case $ARG in
		a)      ADDR=$OPTARG;;
		C)	if [ -z "$ACTION" ]
			then
				ACTION="cred"
				CFY_OPTION="-C"
			else
				ERRCFY_OPTION="-C"
				print_CFY_usage
			fi;;

		d)	if [ "`echo $OPTARG | sed -e 's/.*\(.\)$/\1/'`" != "." ]
			then
				NODOT=$OPTARG
				DOM=${NODOT}.
			else
				DOM=$OPTARG
				NODOT=`echo $DOM | sed -e "s/\.$//"`
			fi ;;
		F)	if [ -z "$ACTION" ]
			then
				ACTION="file"
				CFY_OPTION="-F"
			else
				ERRCFY_OPTION="-F"
				print_CFY_usage
			fi;;
		f)	FORCE="TRUE";;
		h)	YPHOST=$OPTARG;;
		l)	PASSWD=$OPTARG;;
		n)	NEW="";;
		p)	if [ -d $OPTARG ]
			then
				DIRPATH=$OPTARG
			else
				echo "**ERROR: directory $OPTARG does not exist."
				exit 1
			fi;;
		S)	VALUE=`expr "$OPTARG" : "\([02]\)"`
                        if [ -z "$VALUE" ]
                        then
                                echo "**ERROR: invalid security level."
                                echo "  It must be either 0 or 2."
                                echo "  This can only be used with -F and -Y options."
                                exit 1
                        fi
                        SEC=$VALUE;;
		u)	UPDATE="-m";;
		v)	VERB=""
			VERB_OPT="-v";;
		x)	ECHO="echo +++";;
		Y)	if [ -z "$ACTION" ]
			then
				ACTION="yp"
				CFY_OPTION="-Y"
			else
				ERRCFY_OPTION="-Y"
				print_CFY_usage
			fi;;
		y)	if [ "`echo $OPTARG | sed -e 's/.*\(.\)$/\1/'`" != "." ]
			then
				YPDOM=$OPTARG
			else
				YPDOM=`echo $OPTARG | sed -e "s/\.$//"`
			fi ;;
		\?)	print_usage ;;
		*)	echo "**ERROR: Should never get to this point!!!!!"
			print_usage ;;
		esac
	done
	return `expr $OPTIND - 1`
}




#
# get_security(): gets the security information
#
get_security()
{
	while [ /bin/true ]
	do
		get_ans "Security level (2=DES, 3=RSA):" $SEC
		VALUE=`expr "$ANS" : "\([23]\)"`
		if [ -z "$VALUE" -o "$VALUE" -lt 2 -o "$VALUE" -gt 3 ]
		then
			echo "**ERROR: invalid security level."
			echo "  It must be either 2 or 3."
		else
			SEC=$VALUE
			break
		fi
	done
	SEC=$ANS
}



#
# update_info(): updates the information.
#
update_info()
{
	echo ""
	# ...domainname
	get_ans "NIS+ domain name:" $DOM
	if [ "`echo $ANS | sed -e 's/.*\(.\)$/\1/'`" != "." ]
	then
		NODOT=$ANS
		DOM=${ANS}.
	else
		DOM=${ANS}
		NODOT=`echo $ANS | sed -e "s/\.$//"`
	fi

	case $ACTION in
	"yp")	# ...YP domainname
		while [ /bin/true ]
		do
			get_ans "NIS domain name:" $YPDOM
			if [ ! -z "$ANS" ]
			then
				if [ "`echo $ANS | sed -e 's/.*\(.\)$/\1/'`" != "." ]
				then
					YPDOM=${ANS}
				else
					YPDOM=`echo $ANS | sed -e "s/\.$//"`
				fi
				break
			fi
			echo "**WARNING: you must specify the NIS domain name."
		done

		# ...YP host name
		while [ /bin/true ]
		do
			get_ans "NIS Hostname:" $YPHOST
			if [ ! -z "$ANS" ]
			then
				YPHOST=$ANS
				break
			fi
			echo "**WARNING: you must specify the NIS server hostname."
		done
		;;
	"file")	# ...directory path for the files
		DEFAULT=${DIRPATH:-"(current directory)"}
		while [ /bin/true ]
		do
			get_ans "Directory Path:" "$DEFAULT"
			if [ "$ANS" != "$DEFAULT" ]
			then
				if [ -d $ANS ]
				then
					DIRPATH=$ANS
					break
				else
					echo "**ERROR: directory $ANS does not exist."
					echo "	Please try again."
				fi
			else
				break
			fi
		done
		;;
	"cred")	# ... security level
		get_security

		# ... credential password
		get_ans "Credential password:" "$PASSWD"
		PASSWD=$ANS
		;;
	esac
}


#
# print_info(): prints the information on the screen.
#
print_info()
{
	# ...domainname
	echo "NIS+ domain name		: $DOM"

	# ...YP info
	case $ACTION in
	"yp") 	echo "NIS (YP) domain			: ${YPDOM:-(not available)}"
		echo "NIS (YP) server hostname	: ${YPHOST:-(not available)}"
		;;
	"file") echo "Directory Path			: ${DIRPATH:-(current directory)}"
		;;
	"cred")	case $SEC in
		0)	MESS="0=NO_SEC";;
		1)	MESS="1=SYS";;
		2)	MESS="2=DES";;
		3)	MESS="3=RSA";;
		*)	MESS="INVALID";;
		esac
		echo "Security Level		: $MESS"
		echo "Credential Password	: $PASSWD"
		;;
	esac
}


#
# confirm(): asks for user confirmation.  If declined, then it will step
# the user through a question answer session.
#
confirm()
{
	while [ /bin/true ]
	do
		echo ""
		print_info
		echo ""

		get_yesno $CONFIRM
		if [ $ANS = "y" -o $ANS = "Y" ]
		then
			return
		fi

		update_info
	done
}



#
# check_perm(): checks if we have write permission to the NIS+ object
# This should be replaced with nisaccess command when it's available
#		$1  the table to be checked.
#
check_perm()
{
	eval "echo checking $1 permission... $VERB"
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
# is_standard(): checks if the argument passed is a member of the standard
# maps.  It returns standard if the argument is a member, else it returns
# non-standard.
#		$1  the table name to be checked.
#
is_standard()
{
	for EACHT in $MAPS
	do
		V1=`echo "$1" | tr '[A-Z]' '[a-z]'`
		if [ $V1 = $EACHT ]
		then
			echo "standard"
			return
		fi
	done
	echo "non-standard"
	return
}



#
# Populate from YP Routines:
# --------------------------
# 
# This section contains the routine to populate the table from YP maps.
# It will copy the maps from the YP server if not already exists in the
# /var/yp/<YPdomain>.
#	from_yp()	- populates the NIS+ tables from YP map.
#

#
# yp_trans(): translate a name type to NIS map name for ypxfr.
#		$1  type name
# NOTE: netid.byname map is not supported.
#
yp_trans()
{
	if [ $# -eq 0 ]
	then
		return
	fi

	case $1 in
	"aliases")	echo "mail.aliases";;
        "bootparams")	echo "bootparams";;
	"ethers")	echo "ethers.byaddr";;
	"group")	echo "group.byname";;
        "hosts")	echo "hosts.byaddr";;
        "ipnodes")	echo "ipnodes.byaddr";;
        "netmasks")	echo "netmasks.byaddr";;
        "networks")	echo "networks.byname";;
        "passwd")	echo "passwd.byname";;
        "shadow")	echo "passwd.byname";;
        "protocols")	echo "protocols.byname";;
        "rpc")		echo "rpc.bynumber";;
        "services")	echo "services.byname";;
        "netgroup")	echo "netgroup";;
        "timezone")	echo "timezone.byname";;

        auto.*)		echo $1;;
        auto_*)		echo `echo $1 | sed -e 's/\([^_]*\)_\(.*\)/\1.\2/'`;;
	*)		echo $1;;
	esac
}



#
# nisplus_trans(): translate a name type to NIS+ map name for ypxfr.
#		$1  name type
# NOTE: netid.byname map is not supported.
#
nisplus_trans()
{
	if [ $# -eq 0 ]
	then
		return
	fi

	case $1 in
	"shadow")	echo "passwd";;
	"aliases")	echo "mail_aliases";;
	*.*)		echo $1 | sed -e 's/\./_/';;
        *)		echo $1;;
	esac
}

#
#	print_interrupt_warning
#
#	used by from_yp & from_files to caution user.
#
print_interrupt_warning()
{
	echo "**WARNING:  Interrupting this script after choosing to continue"
	echo "may leave the tables only partially populated.  This script does"
	echo "not do any automatic recovery or cleanup."
	echo ""
}

#
# from_yp(): populates the NIS+ tables from YP map.
#
from_yp()
{
	ERRFOUND=""
	if [ -z "$FORCE" ]
	then
		confirm
	else
		echo ""
		print_info
	fi

	if [ -z "$YPDOM" -o -z "$YPHOST" ]
	then
		echo ""
		echo "**ERROR: you must specify both the NIS domain name (-y)"
		echo "	and the NIS server hostname (-h)."
		print_usage
	fi

	# 
	#  Try to determine IP address.  If it was specified on the
	#  command line, we use that.  If that fails, we try going through
	#  the switch (with the getent command).  If that fails, we
	#  look in the /etc/hosts file.  If we still don't get it,
	#  we ask.  If we have to ask, then we add the IP address
	#  to the hosts file so we won't have to bug them if this
	#  script is run again (adding the entry is a little incorrect,
	#  but quite helpful).
	#
   
      # May have to modify at this point to support IPV6

	if [ -z "$ADDR" ]
	then
		ADDR=`getent hosts "$YPHOST" | awk '{print $1}'`
	fi

	if [ -z "$ADDR" ]
	then
		ADDR=`grep -s -i "\<$YPHOST\>" $HOSTS_FILE | grep -s -v "^#" | awk '{print $1}'`
	fi

	if [ -z "$ADDR" ]
	then
		get_ans "Type the IP address for NIS (YP) server ${YPHOST}:" ""
		ADDR=$ANS
		if [ ! -f $HOSTS_FILE.$BACKUP ]
		then
			$ECHO cp $HOSTS_FILE $HOSTS_FILE.$BACKUP
		fi
		$ECHO "echo $ADDR  $YPHOST >> $HOSTS_FILE"
	fi

	if [ $# -eq 0 ]
	then
		TABLES=$MAPS
		STANDARD=standard
	else
		TABLES=$*
		STANDARD=following
	fi

	# ...remove the "." from the domainname
	YPDOM=`echo $YPDOM | sed -e "s/\.$//"`


	echo ""
	echo "This script will populate the $STANDARD NIS+ tables for domain "
	echo "$DOM from the NIS (YP) maps in domain ${YPDOM}:"
	echo $TABLES
	echo ""

	print_interrupt_warning

	if [ -z "$FORCE" ]
	then
		get_yesno $CONTINUE
		echo ""
	fi

	if [ "$SEC" != "0" ]
	then
		check_nsswitch
	fi

	if [ ! -d /var/yp/$YPDOM ]
	then
		eval "echo creating /var/yp/$YPDOM... $VERB"
		$ECHO mkdir -p /var/yp/$YPDOM
	fi

	# ... populating standard files
	for EACH in $TABLES
	do
		# ... check if table exits
		NISTAB=`nisplus_trans $EACH`
		if nistest -t T $NISTAB.org_dir.$DOM;
		then
			eval "echo $NISTAB.org_dir.$DOM OK... $VERB"
		else
			echo "**ERROR($?): table $NISTAB.org_dir.$DOM does not exist."
			echo "	$NISTAB table will not be loaded."
			ERRFOUND="$ERRFOUND $NISTAB"
			if [ "$ECHO" = "eval" ]
			then
				continue
			fi
		fi

		# ...transfer the YP map from YP server
		YPNAME=`yp_trans $EACH`
		YPXFR="ypxfr"
		TMPYPF=$TMPDIR/ypxfr.$$
		if [ ! -z "$NEW" ]
		then
			if [ -f /var/yp/$YPDOM/${YPNAME}.dir ]
			then
				eval "echo removing existing local NIS \(YP\) map... $VERB"
				$ECHO /bin/rm -f /var/yp/$YPDOM/${YPNAME}.*
			fi
			eval "echo copying NIS \(YP\) map from server... $VERB"
			$ECHO "$YPXFR -c -d $YPDOM -h $ADDR $YPNAME > $TMPYPF"
			if [ $? -ne 0 ]
			then
				cat $TMPYPF
				/bin/rm -f $TMPYPF > /dev/null
				echo "**ERROR: NIS map transfer failed."
				echo "	$NISTAB table will not be loaded."
				echo ""
				ERRFOUND="$ERRFOUND $NISTAB"
				continue
			fi
			/bin/rm -f $TMPYPF > /dev/null
		else
			if [ -f /var/yp/$YPDOM/${YPNAME}.dir ]
			then
				eval "echo using the existing NIS \(YP\) map... $VERB"
			else
				eval "echo copying NIS \(YP\) map from server... $VERB"
				$ECHO "$YPXFR -c -d $YPDOM -h $ADDR $YPNAME > $TMPYPF"
				if [ $? -ne 0 ]
				then
					cat $TMPYPF
					/bin/rm -f $TMPYPF > /dev/null
					echo "**ERROR: NIS map transfer failed."
					echo "	$NISTAB table will not be loaded."
					echo ""
					ERRFOUND="$ERRFOUND $NISTAB"
					continue
				fi
				/bin/rm -f $TMPYPF > /dev/null
			fi
		fi

		# ...special conversion for netgroup, timezone and auto.master
		# maps
		OK="yes"
		if [ $EACH = "netgroup" -a `tolower $YPDOM` != `tolower $NODOT` ]
		then
			eval "echo converting $EACH map... $VERB"
			TMPFILE=$TMPDIR/netgroup.$$
			$ECHO "makedbm -u /var/yp/$YPDOM/netgroup \
			    | sed -e s/$YPDOM/$NODOT/g > $TMPFILE"
			if [ $? -eq 0 ]
			then
				eval "echo makedbm -u OK... $VERB"
				$ECHO makedbm $TMPFILE \
					/var/yp/$YPDOM/netgroup
			else
				OK=""
			fi
			if [ $? -ne 0 -o -z "$OK" ]
			then
				echo "**WARNING: NIS netgroup map conversion failed."
				echo "	netgroup table will not be loaded."
				ERRFOUND="$ERRFOUND $NISTAB"
				$ECHO "/bin/rm -f $TMPFILE > /dev/null"
				continue
			fi
			$ECHO "/bin/rm -f $TMPFILE > /dev/null"
		elif [ $EACH = "timezone" ]
		then
			eval "echo converting $EACH map... $VERB"
			TMPFILE=$TMPDIR/timezone.$$
			$ECHO "makedbm -u /var/yp/$YPDOM/timezone.byname \
				> $TMPFILE"
			if [ $? -eq 0 ]
			then
				eval "echo makedbm -u OK... $VERB"
				$ECHO "grep -i '[^\.]$NODOT' $TMPFILE > /dev/null"
				if [ $? -eq 1 ]
				then
					LOCAL_TZ=`grep -i "^$YPDOM" $TMPFILE | \
						cut -d' ' -f2`
					if [ -z "$LOCAL_TZ" ]
					then
						echo "**WARNING: couldn't convert timezone!"
						echo "Please manually add timezone for $NODOT.\n"
					else
						LOCAL_TZ="$LOCAL_TZ $NODOT"
					fi
				fi
			else
				echo "**WARNING: NIS timezone map conversion failed."
				echo "	timezone table will not be loaded."
				ERRFOUND="$ERRFOUND $NISTAB"
				$ECHO "/bin/rm -f $TMPFILE > /dev/null"
				continue
			fi
			$ECHO "/bin/rm -f $TMPFILE > /dev/null"
		elif [ $NISTAB = "auto_master" ]
		then
			eval "echo converting $EACH map... $VERB"
			TMPFILE=$TMPDIR/auto.master.$$
			$ECHO "makedbm -u /var/yp/$YPDOM/auto.master \
				| sed "s/auto./auto_/g" > $TMPFILE"
			if [ $? -eq 0 ]
			then
				eval "echo makedbm -u OK... $VERB"
				$ECHO makedbm $TMPFILE \
					/var/yp/$YPDOM/auto.master
			else
				OK=""
			fi
			if [ $? -ne 0 -o -z "$OK" ]
			then
				echo "**WARNING: NIS auto.master map conversion failed."
				echo "	auto.master table will not be loaded."
				ERRFOUND="$ERRFOUND $NISTAB"
				$ECHO "/bin/rm -f $TMPFILE > /dev/null"
				continue
			fi
			$ECHO "/bin/rm -f $TMPFILE > /dev/null"
		fi

		STAND=`is_standard $EACH`
		echo "populating $NISTAB table from $YPDOM NIS (YP) domain..."
		if [ `expr "$YPNAME" : 'auto\.'` -eq 5 -o \
			$STAND = "non-standard" ]
		then
			eval "echo adding $STAND key-value table $NISTAB... $VERB"
			$ECHO nisaddent $VERB_OPT $UPDATE -y $YPDOM \
				-Y $YPNAME -t $NISTAB.org_dir key-value $DOM
		else
			eval "echo adding standard table $NISTAB... $VERB"
			if [ "$EACH" = "aliases" ]
			then
				$ECHO nisaddent $VERB_OPT $UPDATE -y $YPDOM $EACH $DOM
			else
				$ECHO nisaddent $VERB_OPT $UPDATE -y $YPDOM $NISTAB $DOM
			fi
		fi
		if [ $? -eq 1 ]
		then
			echo "**WARNING: failed to populate $NISTAB table."
			ERRFOUND="$ERRFOUND $NISTAB"
		else
			if [ $NISTAB = "timezone" -a ! -z "$LOCAL_TZ" ]
			then
				echo "$LOCAL_TZ" | \
					nisaddent $VERB_OPT -a $NISTAB $DOM
			fi
			if [ $? -eq 1 ]
			then 
				echo "**WARNING: failed to populate $NISTAB table."
				ERRFOUND="$ERRFOUND $NISTAB"
			else
				echo "$NISTAB table done."
				if [ $EACH = "hosts" -o $EACH = "ipnodes" -o $EACH = "passwd" ]
				then
					if [ "$SEC" != "0" ]
					then
						add_cred_auto $EACH
					fi
				fi
			fi
		fi
		echo ""
	done
	
	do_password_print

	if [ -z "$ERRFOUND" ]
	then
		echo ""
		echo "Done!"
	else
		echo ""
		echo "nispopulate failed to populate the following tables:"
		echo "$ERRFOUND"
		exit 1
	fi
}



#
# Populate from files Routines:
# -----------------------------
# 
# This section contains the routine to populate the table from files.
#	from_files()	- populates the NIS+ tables from files.
#		$*  table types to be added, defaults to all standard tables
#

#
# from_files(): populates the NIS+ tables from files.
#
from_files()
{
	ERRFOUND=""
	if [ -z "$FORCE" ]
	then
		confirm
	else
		echo ""
		print_info
	fi

	# shadow file is only supported in 5.x
	if [ $OS -eq 5 ]
	then
		MAPS="$MAPS shadow"
	fi

	if [ $# -eq 0 ]
	then
		TABLES=$MAPS
		STANDARD="standard"
	else
		TABLES=$*
		STANDARD="following"
	fi
	echo ""
	echo "This script will populate the $STANDARD NIS+ tables for domain "
	echo "$DOM from the files in ${DIRPATH:-current directory}:"
	echo $TABLES
	echo ""

	print_interrupt_warning

	if [ -z "$FORCE" ]
	then
		get_yesno $CONTINUE
		echo ""
	fi

	if [ "$SEC" != "0" ]
	then
		check_nsswitch
	fi

	# ... populating standard files
	DIRPATH=${DIRPATH:-'.'}
	for EACH in $TABLES
	do
		# ... check if table exits
		NISTAB=`nisplus_trans $EACH`
		if nistest -t T $NISTAB.org_dir.$DOM;
		then
			eval "echo $NISTAB.org_dir.$DOM OK... $VERB"
		else
			echo "**ERROR($?): table $NISTAB.org_dir.$DOM does not exist."
			echo "	$NISTAB table will not be loaded."
			ERRFOUND="$ERRFOUND $NISTAB"
			if [ "$ECHO" = "eval" ]
			then
				continue
			fi
		fi

		if [ -f ${DIRPATH}/$EACH ]
		then
			STAND=`is_standard $EACH`
			echo populating $NISTAB table from file ${DIRPATH}/$EACH...
			if [ `expr "$EACH" : 'auto[._]'` -eq 5 -o \
				$STAND = "non-standard" ]
			then
				eval "echo adding $STAND key-value table $NISTAB... $VERB"
				$ECHO nisaddent $VERB_OPT $UPDATE -f \
					${DIRPATH}/$EACH -t \
					$NISTAB.org_dir key-value $DOM
			else
				eval "echo adding standard table $NISTAB... $VERB"
				if [ $EACH = "aliases" -o $EACH = "shadow" ]
				then
					$ECHO nisaddent $VERB_OPT $UPDATE -f ${DIRPATH}/$EACH $EACH $DOM
				else
					$ECHO nisaddent $VERB_OPT $UPDATE -f ${DIRPATH}/$EACH $NISTAB $DOM
				fi
			fi
			if [ $? -eq 1 ]
			then
				echo "**WARNING: failed to populate $NISTAB table."
				ERRFOUND="$ERRFOUND $NISTAB"
			else
				echo "$NISTAB table done."
				if [ $EACH = "hosts" -o $EACH = "ipnodes" -o $EACH = "passwd" ]
				then
					if [ "$SEC" != "0" ]
					then
						add_cred_auto $EACH
					fi
				fi
			fi
		else
			echo "**WARNING: file ${DIRPATH}/$EACH does not exist!"
			echo "	$NISTAB table will not be loaded."
			ERRFOUND="$ERRFOUND $NISTAB"
		fi
		echo ""
	done

	do_password_print

	if [ -z "$ERRFOUND" ] 
	then
		echo ""
		echo "Done!"
	else
		echo ""
		echo "nispopulate failed to populate the following tables:"
		echo "$ERRFOUND"
		exit 1
	fi
}




#
# Populate the credential table Routines:
# --------------------------------------
# 
# This section contains the routine to populate the credential table from 
# either passwd or hosts tabls.  Default is both passwd and hosts.
# 
#	add_cred()	- routine to populate credential
#	add_cred_auto()	- routine to populate credential automatically
#			after populating the passwd or hosts table.
#
#	print_passwd__add_cred
#	print_host__add_cred
#     These routines are used by do_cred to create a shell
#     commands file that contains a routine (add_cred) which
#	  is called by each entry in the respective table.
#		do_cred subsequently runs this shell script.
#
#	do_cred()	- populates the NIS+ credential table.
#		$*  tables to populate from, defaults to both passwd and hosts
#		    tables.
#	do_print_password()  - this routine is used to print the
#		password used for the credential entries at the END of
#		populating all tables (per request of tech pubs).	
#

#
#  Check that "publickey: nisplus" appears in nsswitch.conf.  We
#  Do this by stripping comments and the running an awk script.
#  The awk script searches for the publickey line and then looks
#  for "nisplus" within the line.  It prints:
#
#      0 - no publickey entry in nswitch.conf
#      1 - no "nisplus" in publickey entry
#      2 - publickey entry is okay (has "nisplus")
#

check_nsswitch() {

	cat > /tmp/t.$$ <<'EOF'
	/^[ 	]*publickey[ 	]*:/ {
		for (i=2; i<=NF; i++)
			if ($(i) == "nisplus") {
				found = 2;
				exit;
			}
		found = 1;
		exit;
	}
	END {
		if (found)
			print found
		else
			print 0
	}
EOF

	if [ ! -f $NSSWITCH ]
	then
		echo "**ERROR: the $NSSWITCH file does not exist."
		exit 1
	fi

	t=`cat $NSSWITCH | sed 's/#.*//' | awk -f /tmp/t.$$`

	/bin/rm -f /tmp/t.$$

	if [ "$t" -eq 0 ]
	then
		echo "**ERROR: there is no publickey entry in $NSSWITCH."
		echo "It should be:"
		echo "        publickey: nisplus"
		exit 1
	elif [ "$t" -eq 1 ]
	then
		echo "**ERROR: the publickey entry in $NSSWITCH is:"
		grep '^[ 	]*publickey[ 	]*:' $NSSWITCH > /tmp/t.$$
		echo "        `cat /tmp/t.$$`"
		echo "It should be:"
		echo "        publickey: nisplus"
		/bin/rm -f /tmp/t.$$
		exit 1
	fi
}

#
# add_cred(): populate the NIS+ credential from hosts, ipnodes or passwd
# tables.  This is for -C option:
#	$* tables to populate from.
#
add_cred()
{
	if [ -z "$FORCE" ]
	then
		confirm
	else
		echo ""
		print_info
	fi
	if [ "$SEC" = "0" ]
	then
		echo "***WARNING: no credential will be created for level 0 security."
		exit
	fi

	if [ $# -eq 0 ]
	then
		TABS="passwd hosts ipnodes"
	else
		TABS=$*
	fi

	echo ""
	echo "This script will populate the NIS+ credential tables for domain "
	echo "$DOM from the following table(s): $TABS"
	echo ""

	if [ -z "$FORCE" ]
	then
		get_yesno $CONTINUE
		echo ""
	fi
	do_cred $TABS
}

#
# add_cred_auto(): populate the NIS+ credential tables automatically
# after populating the passwd or hosts tables.
#	$* table to populate from
#
add_cred_auto()
{
	echo ""
	echo "Populating the NIS+ credential table for domain $DOM"
	echo "from $1 table."
	echo ""
	do_cred $1
}

#
##################################
#    SHELL FILE CREATION ROUTINES
##################################
#
#  These routines create the actual cmd files that
#  are used in do_cred to load the passwd, hosts and ipnodes tables.
#
##################################
print_passwd__add_cred()
{
### 3 strings are dependent upon user options.
##   as listed under "1." "2. & 3."
####
# 1. the form of the nisaddcred command:
####
case $SEC in
2) NISADDCRED="nisaddcred -l $PASSWD -p unix.\$2@$NODOT -P \$1.$DOM des $DOM $VERB"
   ;;
3) NISADDCRED="nisaddcred -l $PASSWD -p \$1.$DOM -P \$1.$DOM rsa $DOM $VERB"
   ;;
esac
# 2. & 3. the lines output if verbose has been selected:
if [ -z "$VERB" ]; then
	VERB1='echo " ...$1 already exists"'
	VERB2='echo " ...added $1"'
else
	VERB1=""
	VERB2=""
fi

cat << EOF > $TMPFILE
 
###################
#   WHAT THE PASSWORD FILE LOOKS LIKE
###################
#! /bin/sh
 
# \$1 user name
# \$2 user id 
 
ERR=2
add_cred()
{
  DUMMY=\`nismatch \$1.'$DOM' cred.org_dir.'$DOM' > /dev/null\`
  if [ \$? -eq 0 ]; then
	$VERB1
	return
  fi
  nisaddcred -p \$2 -P \$1.$DOM local $DOM $VERB
  if [ \$? -eq 0 ]; then
	$NISADDCRED
	if [ \$? -eq 0 ]; then
		$VERB2
		ERR=0
	else
		ERR=1
    	fi
   else
	ERR=1
   fi
}

EOF
##################
#   END OF PASSWORD FILE
##################
}


print_host__add_cred()
{
### 3 strings are dependent upon user options.
##   as listed under "1." "2. & 3."
####
# 1. the form of the nisaddcred command:
####
case $SEC in
2) NISADDCRED="nisaddcred -l $PASSWD -p unix.\$1@$NODOT -P \$1.$DOM des $DOM $VERB"
   ;;
3) NISADDCRED="nisaddcred -l $PASSWD -p \$1.$DOM -P \$1.$DOM rsa $DOM $VERB"
   ;;
esac
# 2. & 3. the lines output if verbose has been selected:
if [ -z "$VERB" ]; then
    VERB1='echo " ...$1 already exists"'
    VERB2='echo " ...added $1"'
else
    VERB1=""
    VERB2=""
fi

cat << EOF > $TMPFILE

###################
#   WHAT THE HOSTS FILE LOOKS LIKE
###################
#! /bin/sh

# \$1 host name 

ERR=2 
add_cred() 
{ 
   DUMMY=\`nismatch \$1.$DOM cred.org_dir.$DOM > /dev/null\` 
   if [ \$? -eq 0 ]; then 
   	$VERB1
   	return 
   fi 
   $NISADDCRED
   if [ \$? -eq 0 ]; then 
    ERR=0 
    $VERB2
   else 
     	ERR=1 
   fi 
} 

EOF
##################
#   END OF HOSTS FILE
##################
}


#
#
# do_cred(): populates the NIS+ credential table.
#
do_cred()
{
	CRED_ERRFOUND=99

	if [ $# -eq 0 ]
	then
		TABLES="passwd hosts ipnodes"
	else
		TABLES=$*
	fi

	# ... populating the credential table
	for EACH in $TABLES
	do
		# ... check if table exits
		case $EACH in
		"passwd")
			TMPFILE=$TMPDIR/passwd_$$
			print_passwd__add_cred

			echo dumping passwd table...
			$ECHO "niscat -M passwd.org_dir.$DOM | \
			awk -F: '{ printf (\"add_cred %s %s\n\", \$1, \$3) }' \
				>> $TMPFILE"
			if [ $? -ne 0 ]
			then
				DUMP_ERR=1
			else
				echo 'exit' >> $TMPFILE
				DUMP_ERR=0
			fi
			;;
		"hosts")
			TMPFILE=$TMPDIR/hosts_$$
			print_host__add_cred

			echo dumping hosts table...
			$ECHO "niscat -M hosts.org_dir.$DOM | \
				awk '{ printf (\"add_cred %s\n\", \$1) }' | \
				sort | uniq >> $TMPFILE"
			if [ $? -ne 0 ]
			then
				DUMP_ERR=1
			else
				echo 'exit' >> $TMPFILE
				DUMP_ERR=0
			fi
			;;
         	"ipnodes")
            		TMPFILE=$TMPDIR/ipnodes_$$
            		print_host__add_cred
   
            		echo dumping ipnodes table...
            		$ECHO "niscat -M ipnodes.org_dir.$DOM | \
               		awk '{ printf (\"add_cred %s\n\", \$1) }' | \
               		sort | uniq >> $TMPFILE"
            		if [ $? -ne 0 ]
            		then
               			DUMP_ERR=1
            		else
               			echo 'exit' >> $TMPFILE
               			DUMP_ERR=0
            		fi
            		;;
		*)	echo "Don't know how to do >>$EACH<<"
			exit;;
		esac

		$ECHO chmod +x $TMPFILE
		if [ $DUMP_ERR -eq 0 ]
		then
			echo "loading credential table..."
			$ECHO $TMPFILE
			CRED_ERRFOUND=$?
			if [ $CRED_ERRFOUND -eq 0 ]
			then
				if [ -z "$CREDTABLESADDED" ]
				then
					CREDTABLESADDED=$EACH
				else
					CREDTABLESADDED="$CREDTABLESADDED and $EACH"
				fi 
			fi
		else
			echo "**ERROR: failed dumping $EACH table."
			CRED_ERRFOUND=1
		fi
		echo
		$ECHO "/bin/rm $TMPFILE > /dev/null"
	done

	if [ $CRED_ERRFOUND -eq 0 ]
	then
		echo ""
		echo "The credential table for domain $DOM has been populated."
		echo
		echo "The password used will be $PASSWD."
		echo
	else
		echo ""
		echo "nispopulate failed to populate the credential table."
		return 1
	fi
}

#
#	Routine to print password for hosts, ipnodes and password table,
#		at END of populating all of the tables.
#
do_password_print()
{
    if [ ! -z "$CREDTABLESADDED" ]
	then
		echo
		echo
		echo "Credentials have been added for the entries in the"
		echo "$CREDTABLESADDED table(s).  Each entry was given a default"
		echo "network password (also known as a Secure-RPC password)."
		echo "This password is:"
		echo
		echo "                  $PASSWD"
		echo
		echo "Use this password when the nisclient script requests the"
		echo "network password."
		echo 
	fi
}

#
#
# 			* * * MAIN * * *
#

init

parse_arg $*
shift $?

case $ACTION in
"yp")
	from_yp $*;;
"file")
	from_files $*;;
"cred")
	add_cred $*
	do_password_print;;
*)
	echo
	echo "**ERROR: you must specify one of these options: -C, -F, or -Y"
	print_usage
esac
