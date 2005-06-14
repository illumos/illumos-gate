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
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.

#pragma ident	"%Z%%M%	%I%	%E% SMI"

EXIT=255
TBLNAME=proto_op_access
TBLTYPE=proto_op_access_tbl
VERBOSE=0
REMOVE=0
LIST=0

print_usage()
{
	echo "Usage:	$0 [-v] directory operation rights"
	echo "		$0 [-r] [-v] directory operation"
	echo "		$0 [-l] [-v] directory [operation]"
}

# no_dot(): check if arg has a trailing dot.
no_dot()
{
	if [ "`echo $1 | sed -e 's/.*\(.\)$/\1/'`" != "." ]
	then
		return 0
	fi
	return 1
}

# parse_opt(): Parse options. Returns the number of arguments to shift
#              in order to get to the non-option arguments.
parse_opt()
{
	while getopts "vrl" ARG
	do
		case $ARG in
		v)	VERBOSE=1;;
		r)	REMOVE=1;;
		l)	LIST=1;;
		\?)	print_usage
			exit $EXIT;;
		*)	print_usage
			exit $EXIT
		esac
	done
	return `expr $OPTIND - 1`
}

# unknown_op(): Check that operation (NIS_PING etc.) is known
unknown_op()
{
	case $OPERATION in
	NIS_CHECKPOINT|nis_checkpoint|CHECKPOINT|checkpoint)
		OPERATION=NIS_CHECKPOINT;;
	NIS_CPTIME|nis_cptime|CPTIME|cptime)
		OPERATION=NIS_CPTIME;;
	NIS_MKDIR|nis_mkdir|MKDIR|mkdir)
		OPERATION=NIS_MKDIR;;
	NIS_PING|nis_ping|PING|ping)
		OPERATION=NIS_PING;;
	NIS_RMDIR|nis_rmdir|RMDIR|rmdir)
		OPERATION=NIS_RMDIR;;
	NIS_SERVSTATE|nis_servstate|SERVSTATE|servstate)
		OPERATION=NIS_SERVSTATE;;
	NIS_STATUS|nis_status|STATUS|status)
		OPERATION=NIS_STATUS;;
	*)	return 0;;
	esac
	return 1
}

# print_rights(): parse and print access rights
print_rights()
{
	op=$1
	shift
	rights="<unknown>"
	owner="<none>"
	group="<none>"
	while [ $# -gt 0 ]; do
		case $1 in
		Owner)
			shift
			if [ $1 = ":" ]; then
				shift
				if [ $1 != "Group" ]; then
					owner=$1
					shift
				fi
			fi;;
		Group)
			shift
			if [ $1 = ":" ]; then
				shift
				if [ $1 != "Access" ]; then
					group=$1
					shift
				fi
			fi;;
		Access)
			shift
			if [ $1 = "Rights" ]; then
				shift
				if [ $1 = ":" ]; then
					shift
					rights=$1
					while [ $# -gt 0 ]; do
						shift
					done
				fi
			fi;;
		*)
			shift;;
		esac
	done
	echo "$op\t $rights\t $owner\t $group"
	return $?
}

# print_op(): print access rights for the specified operation
print_op()
{
	nismatch op=$1 $TBLNAME.$DIRECTORY > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		print_rights $1 `niscat -oM \[op=$1\]$TBLNAME.$DIRECTORY`
	fi
	return $?
}

# Main

PATH=/usr/lib/nis:/usr/sbin:/usr/bin

# Parse the options, if any
parse_opt $*
shift $?

# Check that we've got the correct number of arguments
case $# in
1)	if [ $LIST -eq 0 ]; then
		print_usage
		exit $EXIT
	fi
	DIRECTORY=$1;;

2)	if [ $LIST -eq 0 -a $REMOVE -eq 0 ]; then
		print_usage
		exit $EXIT
	elif [ $LIST -ne 0 -a $REMOVE -ne 0 ]; then
		echo "The -l and -r options are mutually exclusive"
		exit $EXIT
	fi
	if [ $LIST -ne 0 ]; then
		LIST=2
	fi
	DIRECTORY=$1
	OPERATION=$2
	if unknown_op; then
		echo "Unknown operation $OPERATION"
		exit $EXIT
	fi;;

3)	if [ $LIST -ne 0 -o $REMOVE -ne 0 ]; then
		print_usage
		exit $EXIT
	fi
	DIRECTORY=$1
	OPERATION=$2
	if unknown_op; then
		echo "Unknown operation $OPERATION"
		exit $EXIT
	fi
	RIGHTS=$3;;

*)	print_usage
	exit $EXIT;;
esac

# If no trailing dot in directory name, add the domain name
if no_dot $DIRECTORY;
then
	DIRECTORY=$DIRECTORY.`domainname`.
fi

# Does the directory exist ?
niscat -o $DIRECTORY > /dev/null 2>&1
STAT=$?
if [ $STAT -ne 0 ]; then
	echo "$DIRECTORY: no such NIS+ directory"
	exit $STAT
fi

# Does the table exist ?
niscat -o $TBLNAME.$DIRECTORY > /dev/null 2>&1
TBLEXISTS=$?

# List all or just one operation
if [ $LIST -eq 1 ]; then
	if [ $TBLEXISTS -ne 0 ]; then
		echo "No operation access table for $DIRECTORY"
		exit 0
	fi
	if [ $VERBOSE -eq 1 ]; then
		echo "Listing access for all operations for $DIRECTORY"
	fi
	echo "Operation\t n---o---g---w---\t Owner\t\t\t Group"
	echo ""
	for OP in NIS_CHECKPOINT NIS_CPTIME NIS_MKDIR NIS_PING NIS_RMDIR \
			NIS_SERVSTATE NIS_STATUS; do
		print_op $OP
		STAT=$?
	done
	exit $STAT
elif [ $LIST -eq 2 ]; then
	if [ $TBLEXISTS -ne 0 ]; then
		echo "No operation access table for $DIRECTORY"
		exit 0
	fi
	if [ $VERBOSE -eq 1 ]; then
		echo "Listing access for $OPERATION for $DIRECTORY"
	fi
	print_op $OPERATION
	exit $?
fi

# Remove an operation
if [ $REMOVE -eq 1 ]; then
	if [ $TBLEXISTS -ne 0 ]; then
		echo "No operation access table for $DIRECTORY"
		exit 0
	fi
	nismatch op=$OPERATION $TBLNAME.$DIRECTORY > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		if [ $VERBOSE -eq 1 ]; then
			echo "No $OPERATION access control for $DIRECTORY"
		fi
		exit 0
	else
		if [ $VERBOSE -eq 1 ]; then
			echo "Removing $OPERATION access control for $DIRECTORY"
		fi
		nistbladm -R \[op=$OPERATION\]$TBLNAME.$DIRECTORY
		exit $?
	fi
fi

# Create the table if it doesn't exist already
if [ $TBLEXISTS -ne 0 ]; then
	if [ $VERBOSE -eq 1 ]; then
		echo "Creating access control table in $DIRECTORY"
	fi
	nistbladm -c $TBLTYPE op=SI,o=rmcd,g=r,w=r,n=r subop=SI,o=rmcd,g=r,w=r,n=r $TBLNAME.$DIRECTORY
	STAT=$?
	if [ $STAT -ne 0 ]; then
		exit $STAT
	fi
fi

# If no entry for the operation, create it with requested rights
nismatch op=$OPERATION $TBLNAME.$DIRECTORY > /dev/null 2>&1
if [ $? -ne 0 ]; then
	if [ $VERBOSE -eq 1 ]; then
		echo "Creating $OPERATION access control entry for $DIRECTORY"
	fi
	nistbladm -a -D access=$RIGHTS op=$OPERATION $TBLNAME.$DIRECTORY
	exit $?
fi

# Modify existing entry
if [ $VERBOSE -eq 1 ]; then
	echo "Changing $OPERATION access control entry for $DIRECTORY"
fi
nischmod $RIGHTS \[op=$OPERATION\]$TBLNAME.$DIRECTORY

exit $?
