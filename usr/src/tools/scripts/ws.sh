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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
#	This script sets up the environment variables for a SunOS
#	codemgr workspace and spawns a shell with the environment
#	setup.  
#
#	The following Environment variables are set:
#		CODEMGR_WS
#		ONBLD_DIR
#		SRC
#		TSRC
#		ROOT
#		PARENT_ROOT
#		MACH
#		MAKEFLAGS
#		ENVCPPFLAGS{1-4}
#		ENVLDLIBS{1-3}
#	
#	The MAKEFLAGS environment variable is set to force make
#	to read default make variables from the environment.	
#
#	Workspace names can be specified in two forms: pathname
#	and hostname:pathname.  If the hostname:pathname form is used
#	the script accesses the environment through the /net automounter
#	map.
#

#
# function to produce a pathname from a workspace name or subdirectory.
# The workspace name can have hostname:pathname format.
#

fmtwsname(){
	awk -F: '$1 != $0 { print "/net/"$1$2 } \
		 $1 == $0 { print $0 }'
}

#
# function to check to see if a proto area is new or old format
#
check_proto()
{
	# Check for problematic parent specification and adjust
	proto=`echo $1|fmtwsname`
	# 
	# if proto contains a /usr/include directory we assume
	# that this is an old style proto area 
	#
	if [ -d $proto/usr/include ]; then
		echo $proto
	else
		echo "${proto}/root_${MACH}"
	fi
}

cleanup_env()
{
	# keep the env. clean when returning
	unset setenv osbld_flag os_rev wsosdir protofile wsname ofs proto \
		pwd parent PROTO1 PROTO2 PROTO3 tmpwsname
	return 0
}

if [ "$1" = "-e" ]; then
	setenv=true
	shift
else
	setenv=false
fi

if [ $# -lt 1 ]; then
	set -- `workspace name`
	[ $# -eq 1 ] && echo "Defaulting to workspace $1"
fi

if [ $# -lt 1 ]; then
	echo "usage: ws [-e] [workspace_name]" >&2
	if $setenv; then
		cleanup_env
		return 1
	else
		exit 1
	fi
fi

#
#	This variable displays the nested activations of workspaces.
#	This is done here to get the exact name the user entered.
#
WS_STACK="$1 $WS_STACK"; export WS_STACK

wsname=`echo $1|fmtwsname`
shift

#
# Checking for CODEMGR_WSPATH
#
if [ "(" "${CODEMGR_WSPATH}x" != "x" ")" -a "(" ! -d $wsname ")" -a \
     "(" `expr "$wsname" : "\/"` = "0" ")" ] 
then
	ofs=$IFS
	IFS=": 	"
	for i in $CODEMGR_WSPATH 
	do
		if [ -d ${i}/${wsname} ]; then
			wsname=${i}/${wsname}
			break
		fi
	done
	IFS=$ofs
fi

# to translate it to an absolute pathname.  We need an
# absolute pathname in order to set CODEMGR_WS.
#
if [ `expr "$wsname" : "\/"` = "0" ] 
then
	pwd=`pwd`
	wsname="$pwd/$wsname"
fi

if [ ! -d $wsname/Codemgr_wsdata ]; then
	echo "Error: $wsname is not a workspace" >&2
	if $setenv; then
		cleanup_env
		return 1
	else
		exit 1
	fi
fi

tmpwsname=`(cd $wsname >/dev/null && workspace name)`
if [ -z "$tmpwsname" ]; then
	echo "Error: $wsname is not a workspace" >&2
	if $setenv; then
		cleanup_env
		return 1
	else
		exit 1
	fi
fi
wsname=$tmpwsname

#
#	Check to see if this is a valid workspace
#
if [ ! -d $wsname ]; then
	echo "$wsname . . . no such directory" >&2
	if $setenv; then
		cleanup_env
		return 1
	else
		exit 1
	fi
fi
if [ -d ${wsname}/Codemgr_wsdata ]; then
	CM_DATA=Codemgr_wsdata
else
	echo "$wsname is not a workspace" >&2
	if $setenv; then
		cleanup_env
		return 1
	else
		exit 1
	fi
fi

CODEMGR_WS=$wsname; export CODEMGR_WS
SRC=$CODEMGR_WS/usr/src; export SRC
TSRC=$CODEMGR_WS/usr/ontest; export TSRC

wsosdir=$CODEMGR_WS/$CM_DATA/sunos
protofile=$wsosdir/protodefs

if [ ! -f $protofile ]; then
	if [ ! -w $CODEMGR_WS/$CM_DATA ]; then
		#
		# The workspace doesn't have a protodefs file and I am
		# unable to create one.  Tell user and use /tmp instead.
		#
		echo "Unable to create the proto defaults file ($protofile)."

		# Just make one in /tmp
		wsosdir=/tmp
		protofile=$wsosdir/protodefs
	fi

	if [ ! -d $wsosdir ]; then
		mkdir $wsosdir
	fi

	cat << PROTOFILE_EoF > $protofile
#!/bin/sh
#
#	Set default proto areas for this workspace
#	NOTE: This file was initially automatically generated.
#
#	Feel free to edit this file.  If this file is removed
#	it will be rebuilt containing default values.
#
#	The variable CODEMGR_WS is available to this script.
#
#	PROTO1 is the first proto area searched and is typically set
#	to a proto area associated with the workspace.  The ROOT
#	environment variable is set to the same as PROTO1.  If you
#	will be doing make installs this proto area needs to be writable.
#
#	PROTO2 and PROTO3 are set to proto areas to search before the
#	search proceeds to the local machine or the proto area specified by
#	TERMPROTO.
#
#	TERMPROTO (if specified) is the last place searched.  If
#	TERMPROTO is not specified the search will end at the local
#	machine.
#

PROTO1=\$CODEMGR_WS/proto

if [ -f "\$CODEMGR_WS/Codemgr_wsdata/parent" ]; then
   #
   # If this workspace has an codemgr parent then set PROTO2 to
   # point to the parents proto space.
   #
   parent=\`workspace parent \$CODEMGR_WS\`
   if [ -n \$parent ]; then
	   PROTO2=\$parent/proto
   fi
fi
PROTOFILE_EoF

fi

. $protofile

# This means you don't have to type make -e all of the time

MAKEFLAGS=e; export MAKEFLAGS

#
#	Set up the environment variables
#
MACH=`uname -p`
ROOT=/proto/root_${MACH}	# default


ENVCPPFLAGS1=
ENVCPPFLAGS2=
ENVCPPFLAGS3=
ENVCPPFLAGS4=
ENVLDLIBS1=
ENVLDLIBS2=
ENVLDLIBS3=

if [ "$PROTO1" != "" ]; then	# first proto area specifed
	PROTO1=`check_proto $PROTO1`
	ROOT=$PROTO1
	ENVCPPFLAGS1=-I$ROOT/usr/include
	export ENVCPPFLAGS1
	ENVLDLIBS1="-L$ROOT/lib -L$ROOT/usr/lib"
	export ENVLDLIBS1

	if [ "$PROTO2" != "" ]; then	# second proto area specifed
		PROTO2=`check_proto $PROTO2`
		ENVCPPFLAGS2=-I$PROTO2/usr/include
		export ENVCPPFLAGS2
		ENVLDLIBS2="-L$PROTO2/lib -L$PROTO2/usr/lib"
		export ENVLDLIBS2

		if [ "$PROTO3" != "" ]; then	# third proto area specifed
			PROTO3=`check_proto $PROTO3`
			ENVCPPFLAGS3=-I$PROTO3/usr/include
			export ENVCPPFLAGS3
			ENVLDLIBS3="-L$PROTO3/lib -L$PROTO3/usr/lib"
			export ENVLDLIBS3
		fi
	fi
fi

export ROOT

if [ "$TERMPROTO" != "" ]; then	# fallback area specifed
	TERMPROTO=`check_proto $TERMPROTO`
	ENVCPPFLAGS4="-Y I,$TERMPROTO/usr/include"
	export ENVCPPFLAGS4
	ENVLDLIBS3="$ENVLDLIBS3 -Y P,$TERMPROTO/lib:$TERMPROTO/usr/lib"
	export ENVLDLIBS3
fi

#
# Now let's set those variables which are either 4.1.x specific
# or 5.0 specific
#
os_rev=`uname -r`
osbld_flag=0

if [ `expr $os_rev : "4\.1"` = "3" ]; then # This is a 4.1.x machine
   # 
   # Enable all of the DOUBLECROSS_ROOT components for the 4.1.x compile
   #
   DOUBLECROSS_ROOT=${DOUBLECROSS_ROOT="/crossroot"}
   PATH=$DOUBLECROSS_ROOT/usr/ccs/bin:$DOUBLECROSS_ROOT/usr/bin:$DOUBLECROSS_ROOT/usr/sbin:$PATH
   export DOUBLECROSS_ROOT PATH
elif [ `expr $os_rev : "5\."` = "2" ]; then
   # 
   # Enable any 5.x specific variables here
   #
   if [ ${ONBLD_DIR:-NULL} = "NULL" ]; then
      if [ -d /opt/onbld/bin ]; then
	 ONBLD_DIR=/opt/onbld/bin
      elif [ -d /usr/onbld/bin ]; then
	 ONBLD_DIR=/usr/onbld/bin
      fi
   fi
   if [ -d ${ONBLD_DIR:-\\NULL} ] ; then
      PATH=${ONBLD_DIR}:${PATH}
      osbld_flag=1
      export PATH
   fi
   if [ "$PROTO2" != "" ]; then
      # This should point to the parent's proto
      PARENT_ROOT=$PROTO2
      export PARENT_ROOT
   else
      # Clear it in case it's already in the env.
      PARENT_ROOT=
   fi
   export ONBLD_DIR
   export MACH
else
   #
   # This is neither a 5.x machine nor a 4.1.x machine - something is wrong
   #
   echo "***WARNING: this script is meant to be run on a 4.1.x and/or a 5.x"
   echo "            operating system.  This machine appears to be running:"
   echo "                          $os_rev "
fi

echo ""
echo "Workspace (\$CODEMGR_WS)      : $CODEMGR_WS"
if [ -n "$parent" ]; then
   echo "Workspace Parent             : $parent"
fi
echo "Proto area (\$ROOT)           : $ROOT"
if [ -n "$PARENT_ROOT" ]; then
   echo "Parent proto area (\$PARENT_ROOT) : $PARENT_ROOT"
fi
echo "Root of source (\$SRC)        : $SRC"
echo "Root of test source (\$TSRC)  : $TSRC"
if [ $osbld_flag = "1" ]; then
   echo "Prepended to PATH            : $ONBLD_DIR"
fi
echo "Current directory (\$PWD)     : $CODEMGR_WS"
echo ""

cd $CODEMGR_WS

if $setenv; then
	cleanup_env
else
	exec ${SHELL:-sh} "$@"
fi
