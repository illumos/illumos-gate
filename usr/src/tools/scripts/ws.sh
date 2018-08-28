#!/bin/ksh -p
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
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

fmtwsname()
{
	awk -F: '$1 != $0 { print "/net/"$1$2 } \
		 $1 == $0 { print $0 }'
}

#
# Return a valid proto area, if one exists.
#
check_proto()
{
	if [[ -z $1 ]]; then
		return
	fi

	if [[ "$SCM_MODE" = "teamware" ]]; then
		# Check for problematic parent specification and adjust
		proto=`echo $1|fmtwsname`
		echo "${proto}/root_${MACH}"
	elif [[ "$SCM_MODE" = "mercurial" ]]; then
		proto=$1
		#
		# If the proto is a local repository then we can use it
		# to point to the parents proto area. Don't bother to
		# check if it exists or not, we never did for Teamware,
		# since it might appear later anyway.
		#
		if [[ "${proto##ssh://}" == "$proto" && \
		     "${proto##http://}" == "$proto" && \
		     "${proto##https://}" == "$proto" ]]; then
			echo "${proto}/root_${MACH}"
		fi
	elif [[ "$SCM_MODE" = "git" ]]; then
		#
                # For git, we make no attempt to deal with the possibility of
                # remote parent workspaces because, in the protodefs file, we
                # don't actually acknowledge the concept of a parent workspace
                # at all, in keeping with the rest of our git support.
                #
		echo "${1}/root_${MACH}"
	fi
}

cleanup_env()
{
	# keep the env. clean when returning
	unset setenv osbld_flag os_rev wsosdir protofile wsname ofs proto \
		pwd parent PROTO1 PROTO2 PROTO3 tmpwsname
	return 0
}

if [[ "$1" = "-e" ]]; then
	setenv=true
	shift
else
	setenv=false
fi

WHICH_SCM=$(/bin/dirname $(whence $0))/which_scm
if [[ ! -x $WHICH_SCM ]]; then
	WHICH_SCM=which_scm
fi

#
# No workspace/repository path was given, so try and detect one from our
# current directory we're in
#
if [[ $# -lt 1 ]]; then
	if env CODEMGR_WS="" $WHICH_SCM | read SCM_MODE tmpwsname && \
	    [[ $SCM_MODE != unknown ]]; then
		echo "Defaulting to $SCM_MODE repository $tmpwsname"
	else
		echo "usage: ws [-e] [workspace_name]" >&2
		if $setenv; then
			cleanup_env
			return 1
		else
			exit 1
		fi
	fi
else
	#
	# A workspace/repository path was passed in, grab it and pop
	# it off the stack
	#
	tmpwsname=$1
	shift
fi

#
#	This variable displays the nested activations of workspaces.
#	This is done here to get the exact name the user entered.
#
WS_STACK="$tmpwsname $WS_STACK"; export WS_STACK

#
# Set the workspace name and unset tmpwsname (as we reuse it later)
#
wsname=`echo $tmpwsname|fmtwsname`
unset tmpwsname

#
# Checking for CODEMGR_WSPATH
#
if [[ -n ${CODEMGR_WSPATH} && ( ! -d $wsname ) && \
     ( `expr "$wsname" : "\/"` = "0" ) ]] 
then
	ofs=$IFS
	IFS=": 	"
	for i in $CODEMGR_WSPATH 
	do
		if [[ -d ${i}/${wsname} ]]; then
			wsname=${i}/${wsname}
			break
		fi
	done
	IFS=$ofs
fi

#
# to translate it to an absolute pathname.  We need an
# absolute pathname in order to set CODEMGR_WS.
#
if [[ `expr "$wsname" : "\/"` = "0" ]] 
then
	pwd=`pwd`
	wsname="$pwd/$wsname"
fi

#
#	Check to see if this is a valid workspace
#
if [[ ! -d $wsname ]]; then
	echo "$wsname . . . no such directory" >&2
	if $setenv; then
		cleanup_env
		return 1
	else
		exit 1
	fi
fi

#
# This catches the case of a passed in workspace path
# Check which type of SCM is in use by $wsname.
#
(cd $wsname && env CODEMGR_WS="" $WHICH_SCM) | read SCM_MODE tmpwsname
if [[ $? != 0 || "$SCM_MODE" == unknown ]]; then
	echo "Error: Unable to detect a supported SCM repository in $wsname"
	if $setenv; then
		cleanup_env
		return 1
	else
		exit 1
	fi
fi

wsname=$tmpwsname
CODEMGR_WS=$wsname ; export CODEMGR_WS
SRC=$wsname/usr/src; export SRC
TSRC=$wsname/usr/ontest; export TSRC

if [[ "$SCM_MODE" = "teamware" && -d ${wsname}/Codemgr_wsdata ]]; then
	CM_DATA="Codemgr_wsdata"
	wsosdir=$CODEMGR_WS/$CM_DATA/sunos
	protofile=$wsosdir/protodefs
elif [[ "$SCM_MODE" = "mercurial" && -d ${wsname}/.hg ]]; then
	CM_DATA=".hg"
	wsosdir=$CODEMGR_WS/$CM_DATA
	protofile=$wsosdir/org.opensolaris.protodefs
elif [[ "$SCM_MODE" = "git" && -d ${wsname}/.git ]]; then
	CM_DATA=".git"
	wsosdir=$CODEMGR_WS/$CM_DATA
	protofile=$wsosdir/org.opensolaris.protodefs
else
	echo "$wsname is not a supported workspace; type is $SCM_MODE" >&2
	if $setenv; then
		cleanup_env
		return 1
	else
		exit 1
	fi
fi

MACH=`uname -p`

if [[ ! -f $protofile ]]; then
	if [[ ! -w $CODEMGR_WS/$CM_DATA ]]; then
		#
		# The workspace doesn't have a protodefs file and I am
		# unable to create one.  Tell user and use /tmp instead.
		#
		echo "Unable to create the proto defaults file ($protofile)."

		# Just make one in /tmp
		wsosdir=/tmp
		protofile=$wsosdir/protodefs
	fi

	if [[ ! -d $wsosdir ]]; then
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
PROTOFILE_EoF
	
	if [[ "$SCM_MODE" = "teamware" ]]; then
		cat << PROTOFILE_EoF >> $protofile
if [[ -f "\$CODEMGR_WS/Codemgr_wsdata/parent" ]]; then
   #
   # If this workspace has an codemgr parent then set PROTO2 to
   # point to the parents proto space.
   #
   parent=\`workspace parent \$CODEMGR_WS\`
   if [[ -n \$parent ]]; then
	   PROTO2=\$parent/proto
   fi
fi
PROTOFILE_EoF
	elif [[ "$SCM_MODE" = "mercurial" ]]; then
		cat << PROTOFILE_EoF >> $protofile
parent=\`(cd \$CODEMGR_WS && hg path default 2>/dev/null)\`
if [[ \$? -eq 0 && -n \$parent ]]; then
   [[ -n \$(check_proto \$parent/proto) ]] && PROTO2=\$parent/proto
fi
PROTOFILE_EoF
	fi
fi

. $protofile

# This means you don't have to type make -e all of the time

MAKEFLAGS=e; export MAKEFLAGS

#
#	Set up the environment variables
#
ROOT=/proto/root_${MACH}	# default

ENVCPPFLAGS1=
ENVCPPFLAGS2=
ENVCPPFLAGS3=
ENVCPPFLAGS4=
ENVLDLIBS1=
ENVLDLIBS2=
ENVLDLIBS3=

#
# Work around folks who have historically used GCC_ROOT and convert it to
# GNUC_ROOT. We leave GCC_ROOT in the environment for now (though this could
# mess up the case where multiple different gcc versions are being used to
# shadow).
#
if [[ -n "${GCC_ROOT}" ]]; then
	export GNUC_ROOT=${GCC_ROOT}
fi

PROTO1=`check_proto $PROTO1`
if [[ -n "$PROTO1" ]]; then	# first proto area specifed
	ROOT=$PROTO1
	ENVCPPFLAGS1=-I$ROOT/usr/include
	export ENVCPPFLAGS1
	ENVLDLIBS1="-L$ROOT/lib -L$ROOT/usr/lib"
	export ENVLDLIBS1

	PROTO2=`check_proto $PROTO2`
	if [[ -n "$PROTO2" ]]; then	# second proto area specifed
		ENVCPPFLAGS2=-I$PROTO2/usr/include
		export ENVCPPFLAGS2
		ENVLDLIBS2="-L$PROTO2/lib -L$PROTO2/usr/lib"
		export ENVLDLIBS2

		PROTO3=`check_proto $PROTO3`
		if [[ -n "$PROTO3" ]]; then	# third proto area specifed
			ENVCPPFLAGS3=-I$PROTO3/usr/include
			export ENVCPPFLAGS3
			ENVLDLIBS3="-L$PROTO3/lib -L$PROTO3/usr/lib"
			export ENVLDLIBS3
		fi
	fi
fi

export ROOT

if [[ -n "$TERMPROTO" ]]; then	# fallback area specifed
	TERMPROTO=`check_proto $TERMPROTO`
	ENVCPPFLAGS4="-Y I,$TERMPROTO/usr/include"
	export ENVCPPFLAGS4
	ENVLDLIBS3="$ENVLDLIBS3 -Y P,$TERMPROTO/lib:$TERMPROTO/usr/lib"
	export ENVLDLIBS3
fi

osbld_flag=0

if [[ -z "$ONBLD_DIR" ]]; then
	ONBLD_DIR=$(/bin/dirname $(whence $0))
fi

if ! echo ":$PATH:" | grep ":${ONBLD_DIR}:" > /dev/null; then
	PATH="${ONBLD_DIR}:${ONBLD_DIR}/${MACH}:${PATH}"
	osbld_flag=1
fi

export PATH

if [[ -n "$PROTO2" ]]; then
   # This should point to the parent's proto
   PARENT_ROOT=$PROTO2
   export PARENT_ROOT
else
   # Clear it in case it's already in the env.
   PARENT_ROOT=
fi
export ONBLD_DIR
export MACH

os_rev=`uname -r`
os_name=`uname -s`

if [[ $os_name != "SunOS" || `expr $os_rev : "5\."` != "2" ]]; then
   #
   # This is not a SunOS 5.x machine - something is wrong
   #
   echo "***WARNING: this script is meant to be run on SunOS 5.x."
   echo "            This machine appears to be running: $os_name $os_rev"
fi

echo ""
echo "Workspace                    : $wsname"
if [[ -n "$parent" ]]; then
   echo "Workspace Parent             : $parent"
fi
echo "Proto area (\$ROOT)           : $ROOT"
if [[ -n "$PARENT_ROOT" ]]; then
   echo "Parent proto area (\$PARENT_ROOT) : $PARENT_ROOT"
fi
echo "Root of source (\$SRC)        : $SRC"
echo "Root of test source (\$TSRC)  : $TSRC"
if [[ $osbld_flag = "1" ]]; then
   echo "Prepended to PATH            : $ONBLD_DIR"
fi
echo "Current directory (\$PWD)     : $wsname"
echo ""

cd $wsname

if $setenv; then
	cleanup_env
else
	exec ${SHELL:-sh} "$@"
fi
