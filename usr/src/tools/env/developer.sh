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
# ident	"%Z%%M%	%I%	%E% SMI"
#

#	Configuration variables for the runtime environment of the nightly
# build script and other tools for construction and packaging of releases.
# This script is sourced by 'nightly' and 'bldenv' to set up the environment
# for the build. This example is suitable for building a developers workspace,
# which will contain the resulting packages and archives. It is based off
# the onnv release. It sets NIGHTLY_OPTIONS to make nightly do:
#	creates cpio archives for bfu (-a)
#	runs 'make check' (-C)
#	DEBUG and non-DEBUG builds (-D)
#	runs lint in usr/src (-l plus the LINTDIRS variable)
#	sends mail on completion (-m and the MAILTO variable)
#	creates packages for PIT/RE (-p)
#	checks for changes in ELF runpaths (-r)
#
NIGHTLY_OPTIONS="-aCDlmpr";		export NIGHTLY_OPTIONS

# This is a variable for the rest of the script - GATE doesn't matter to
# nightly itself
GATE=onnv-bugfixes;			export GATE

# CODEMGR_WS - where is your workspace at (or what should nightly name it)
CODEMGR_WS="/builds/$GATE";			export CODEMGR_WS

# PARENT_WS is used to determine the parent of this workspace. This is
# for the options that deal with the parent workspace (such as where the
# proto area will go).
PARENT_WS="/ws/onnv-gate";			export PARENT_WS

# CLONE_WS is the workspace nightly should do a bringover from. Since it's
# going to bringover usr/src, this could take a while, so we use the
# clone instead of the gate (see the gate's README).
CLONE_WS="/ws/onnv-clone";			export CLONE_WS

# This flag controls whether to build the closed source.  If
# undefined, nightly(1) and bldenv(1) will set it according to whether
# the closed source tree is present.  CLOSED_IS_PRESENT="no" means not
# building the closed sources.
# CLOSED_IS_PRESENT="yes";		export CLOSED_IS_PRESENT

# The bringover, if any, is done as STAFFER.
# Set STAFFER to your own login as gatekeeper or developer
# The point is to use group "staff" and avoid referencing the parent
# workspace as root.
# Some scripts optionally send mail messages to MAILTO.
#
STAFFER=nobody;				export STAFFER
MAILTO=$STAFFER;			export MAILTO

# The project (see project(4)) under which to run this build.  If not
# specified, the build is simply run in a new task in the current project.
BUILD_PROJECT=;				export BUILD_PROJECT

# You should not need to change the next four lines
LOCKNAME="`basename $CODEMGR_WS`_nightly.lock"; export LOCKNAME
ATLOG="$CODEMGR_WS/log";			export ATLOG
LOGFILE="$ATLOG/nightly.log";			export LOGFILE
MACH=`uname -p`;				export MACH

# REF_PROTO_LIST - for comparing the list of stuff in your proto area
# with. Generally this should be left alone, since you want to see differences
# from your parent (the gate).
#
REF_PROTO_LIST=$PARENT_WS/usr/src/proto_list_${MACH}; export REF_PROTO_LIST

# where cpio archives of the OS are placed. Usually this should be left
# alone too.
CPIODIR="${CODEMGR_WS}/archives/${MACH}/nightly";	export CPIODIR

#
#	build environment variables, including version info for mcs, motd,
# motd, uname and boot messages. Mostly you shouldn't change this except
# when the release slips (nah) or you move an environment file to a new
# release
#
ROOT="$CODEMGR_WS/proto/root_${MACH}";	export ROOT
SRC="$CODEMGR_WS/usr/src";         	export SRC
VERSION="$GATE";			export VERSION

#
# the RELEASE and RELEASE_DATE variables are set in Makefile.master;
# there might be special reasons to override them here, but that
# should not be the case in general
#
# RELEASE="5.10.1";			export RELEASE
# RELEASE_DATE="October 2007";		export RELEASE_DATE

# proto area in parent for optionally depositing a copy of headers and
# libraries corresponding to the protolibs target
# not applicable given the NIGHTLY_OPTIONS
#
PARENT_ROOT=$PARENT_WS/proto/root_$MACH; export PARENT_ROOT

#
#       package creation variable. you probably shouldn't change this either.
#
PKGARCHIVE="${CODEMGR_WS}/packages/${MACH}/nightly";	export PKGARCHIVE

# we want make to do as much as it can, just in case there's more than
# one problem.
MAKEFLAGS=k;	export MAKEFLAGS

# Magic variable to prevent the devpro compilers/teamware from sending
# mail back to devpro on every use.
UT_NO_USAGE_TRACKING="1"; export UT_NO_USAGE_TRACKING

# Build tools - don't set these unless you know what you're doing.  These
# variables allows you to get the compilers and onbld files locally or
# through cachefs.  Set BUILD_TOOLS to pull everything from one location.
# Alternately, you can set ONBLD_TOOLS to where you keep the contents of
# SUNWonbld and SPRO_ROOT to where you keep the compilers.
#
#BUILD_TOOLS=/opt;				export BUILD_TOOLS
#ONBLD_TOOLS=/opt/onbld;			export ONBLD_TOOLS
#SPRO_ROOT=/opt/SUNWspro;			export SPRO_ROOT

# This goes along with lint - it is a series of the form "A [y|n]" which
# means "go to directory A and run 'make lint'" Then mail me (y) the
# difference in the lint output. 'y' should only be used if the area you're
# linting is actually lint clean or you'll get lots of mail.
# You shouldn't need to change this though.
#LINTDIRS="$SRC y";	export LINTDIRS

#
# Reference to IA32 IHV workspace, proto area and packages
#
#IA32_IHV_WS=/ws/${GATE}-ihv;				export IA32_IHV_WS
#IA32_IHV_ROOT=$IA32_IHV_WS/proto/root_i386;		export IA32_IHV_ROOT
#IA32_IHV_PKGS=$IA32_IHV_WS/packages/i386/nightly;	export IA32_IHV_PKGS

#
# Reference to binary-only IA32 IHV packages
#
#IA32_IHV_BINARY_PKGS=/ws/${GATE}-ihv-bin
#export IA32_IHV_BINARY_PKGS

#
# Destination for sparc realmode package SUNWrmodu
#
#SPARC_RM_PKGARCHIVE="${CODEMGR_WS}/packages/sparc_realmode/nightly"
#export SPARC_RM_PKGARCHIVE

# Set this flag to 'n' to disable the automatic validation of the dmake
# version in use.  The default is to check it.
#CHECK_DMAKE=y

# Set this flag to 'n' to disable the use of 'checkpaths'.  The default,
# if the 'N' option is not specified, is to run this test.
#CHECK_PATHS=y

# Set this flag to 'y' to enable the use of elfsigncmp to validate the
# output of elfsign.  Doing so requires that 't' be set in NIGHTLY_OPTIONS.
# The default is to not verify them.
#VERIFY_ELFSIGN=n

# BRINGOVER_FILES is the list of files nightly passes to bringover.
# If not set the default is "usr", but it can be used for bringing
# over deleted_files or other nifty directories.
#BRINGOVER_FILES="usr deleted_files"

# POST_NIGHTLY can be any command to be run at the end of nightly.  See
# nightly(1) for interactions between environment variables and this command.
#POST_NIGHTLY=
