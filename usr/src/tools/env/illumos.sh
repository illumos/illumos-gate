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
# Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2015, OmniTI Computer Consulting, Inc. All rights reserved.
# Copyright 2016 RackTop Systems.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2020 Joyent, Inc.
# Copyright 2024 Bill Sommerfeld <sommerfeld@hamachi.org>
#
# - This file is sourced by "bldenv" and "nightly" and should not
#   be executed directly.
# - This script is only interpreted by ksh93 and explicitly allows the
#   use of ksh93 language extensions.


# -----------------------------------------------------------------------------
# Parameters you are likely to want to change
# -----------------------------------------------------------------------------

#       DEBUG build only (-D, -F)
#       do not bringover from the parent (-n)
#       runs 'make check' (-C)
#       checks for new interfaces in libraries (-A)
#       sends mail on completion (-m and the MAILTO variable)
#       creates packages for PIT/RE (-p)
#       checks for changes in ELF runpaths (-r)
#       build and use this workspace's tools in $SRC/tools (-t)
export NIGHTLY_OPTIONS='-FnCDAmprt'

# Some scripts optionally send mail messages to MAILTO.
#export MAILTO=

# CODEMGR_WS - where is your workspace at
export CODEMGR_WS="${CODEMGR_WS:-`git rev-parse --show-toplevel`}"

# Compilers may be specified using the following variables:
# PRIMARY_CC	- primary C compiler
# PRIMARY_CCC	- primary C++ compiler
#
# SHADOW_CCS    - list of shadow C compilers
# SHADOW_CCCS	- list of shadow C++ compilers
#
# Each entry has the form <name>,<path to binary>,<style> where name is a
# free-form name (possibly used in the makefiles to guard options), path is
# the path to the executable.  style is the 'style' of command line taken by
# the compiler, currently either gnu (or gcc) or sun (or cc), which is also
# used by Makefiles to guard options.
#
# for example:
# export PRIMARY_CC=gcc4,/opt/gcc/4.4.4/bin/gcc,gnu
# export PRIMARY_CCC=gcc4,/opt/gcc/4.4.4/bin/g++,gnu
# export SHADOW_CCS=studio12,/opt/SUNWspro/bin/cc,sun
# export SHADOW_CCCS=studio12,/opt/SUNWspro/bin/CC,sun
#
# There can be several space-separated entries in SHADOW_* to run multiple
# shadow compilers.
#
# To disable shadow compilation, unset SHADOW_* or set them to the empty string.
#
export GNUC_ROOT=/usr/gcc/10
export PRIMARY_CC=gcc10,$GNUC_ROOT/bin/gcc,gnu
export PRIMARY_CCC=gcc10,$GNUC_ROOT/bin/g++,gnu
export SHADOW_CCS=gcc7,/usr/gcc/7/bin/gcc,gnu
export SHADOW_CCCS=gcc7,/usr/gcc/7/bin/g++,gnu

# comment to disable smatch
export ENABLE_SMATCH=1

# Comment this out to disable support for SMB printing, i.e. if you
# don't want to bother providing the CUPS headers this needs.
export ENABLE_SMB_PRINTING=

# If your distro uses certain versions of Perl, make sure either Makefile.master
# contains your new defaults OR your .env file sets them.
# These are how you would override for building on OmniOS r151028, for example.
#export PERL_VERSION=5.28
#export PERL_VARIANT=-thread-multi
#export PERL_PKGVERS=

# To disable building of the 32-bit or 64-bit perl modules (or both),
# uncomment these lines:
#export BUILDPERL32='#'
#export BUILDPERL64='#'

# If your distro uses certain versions of Python, make sure either
# Makefile.master contains your new defaults OR your .env file sets them.
#export PYTHON3_VERSION=3.9
#export PYTHON3_PKGVERS=-39
#export PYTHON3_SUFFIX=

# Set console color scheme either by build type:
#
#export RELEASE_CONSOLE_COLOR="-DDEFAULT_ANSI_FOREGROUND=ANSI_COLOR_BLACK \
#	-DDEFAULT_ANSI_BACKGROUND=ANSI_COLOR_WHITE"
#
#export DEBUG_CONSOLE_COLOR="-DDEFAULT_ANSI_FOREGROUND=ANSI_COLOR_RED \
#	-DDEFAULT_ANSI_BACKGROUND=ANSI_COLOR_WHITE"
#
# or just one for any build type:
#
#export DEFAULT_CONSOLE_COLOR="-DDEFAULT_ANSI_FOREGROUND=ANSI_COLOR_BLACK \
#	-DDEFAULT_ANSI_BACKGROUND=ANSI_COLOR_WHITE"

# Set if your distribution has different package versioning
#export PKGVERS_BRANCH=2018.0.0.17900

# Skip Java 11 builds on distributions that don't support it
#export BLD_JAVA_11=

# POST_NIGHTLY can be any command to be run at the end of nightly.  See
# nightly(1) for interactions between environment variables and this command.
#POST_NIGHTLY=

# Populates /etc/versions/build on each nightly run
export BUILDVERSION_EXEC="git describe --all --long --dirty"

# -----------------------------------------------------------------------------
# You are less likely to need to modify parameters below.
# -----------------------------------------------------------------------------

# Maximum number of dmake jobs.  The recommended number is 2 + NCPUS,
# where NCPUS is the number of logical CPUs on your build system.
function maxjobs
{
	nameref maxjobs=$1
	integer ncpu
	integer -r min_mem_per_job=512 # minimum amount of memory for a job

	ncpu=$(builtin getconf ; getconf 'NPROCESSORS_ONLN')
	(( maxjobs=ncpu + 2 ))

	# Throttle number of parallel jobs launched by dmake to a value which
	# gurantees that all jobs have enough memory. This was added to avoid
	# excessive paging/swapping in cases of virtual machine installations
	# which have lots of CPUs but not enough memory assigned to handle
	# that many parallel jobs
	if [[ $(/usr/sbin/prtconf 2>'/dev/null') == ~(E)Memory\ size:\ ([[:digit:]]+)\ Megabytes ]] ; then
		integer max_jobs_per_memory # parallel jobs which fit into physical memory
		integer physical_memory # physical memory installed

		# The array ".sh.match" contains the contents of capturing
		# brackets in the last regex, .sh.match[1] will contain
		# the value matched by ([[:digit:]]+), i.e. the amount of
		# memory installed
		physical_memory="10#${.sh.match[1]}"

		((
			max_jobs_per_memory=round(physical_memory/min_mem_per_job) ,
			maxjobs=fmax(2, fmin(maxjobs, max_jobs_per_memory))
		))
	fi

	return 0
}

maxjobs DMAKE_MAX_JOBS # "DMAKE_MAX_JOBS" passed as ksh(1) name reference
export DMAKE_MAX_JOBS

# path to onbld tool binaries
ONBLD_BIN='/opt/onbld/bin'

# PARENT_WS is used to determine the parent of this workspace. This is
# for the options that deal with the parent workspace (such as where the
# proto area will go).
export PARENT_WS="${PARENT_WS:-}"

# CLONE_WS is the workspace nightly should do a bringover from.
# The bringover, if any, is done as STAFFER.
export CLONE_WS="${CLONE_WS:-}"

# Set STAFFER to your own login as gatekeeper or developer
# The point is to use group "staff" and avoid referencing the parent
# workspace as root.
export STAFFER="$LOGNAME"
export MAILTO="${MAILTO:-$STAFFER}"

# If you wish the mail messages to be From: an arbitrary address, export
# MAILFROM.
#export MAILFROM="user@example.com"

# The project (see project(5)) under which to run this build.  If not
# specified, the build is simply run in a new task in the current project.
export BUILD_PROJECT=''

# You should not need to change the next three lines
export ATLOG="$CODEMGR_WS/log"
export LOGFILE="$ATLOG/nightly.log"
export MACH="$(uname -p)"

#
#  The following macro points to the closed binaries.  Once illumos has
#  totally freed itself, we can remove this reference.
#
# Location of encumbered binaries.
export ON_CLOSED_BINS="/opt/onbld/closed"

# REF_PROTO_LIST - for comparing the list of stuff in your proto area
# with. Generally this should be left alone, since you want to see differences
# from your parent (the gate).
#
export REF_PROTO_LIST="$PARENT_WS/usr/src/proto_list_${MACH}"


export ROOT="$CODEMGR_WS/proto/root_${MACH}"
export SRC="$CODEMGR_WS/usr/src"
export MULTI_PROTO="no"

#
#	build environment variables, including version info for mcs, motd,
# motd, uname and boot messages. Mostly you shouldn't change this except
# when the release slips (nah) or you move an environment file to a new
# release
#
#export VERSION="${VERSION:-`git describe --long --all HEAD | cut -d/ -f2-`}"

#
# the RELEASE and RELEASE_DATE variables are set in Makefile.master;
# there might be special reasons to override them here, but that
# should not be the case in general
#
# export RELEASE='5.11'
# export RELEASE_DATE='October 2007'

# proto area in parent for optionally depositing a copy of headers and
# libraries corresponding to the protolibs target
# not applicable given the NIGHTLY_OPTIONS
#
export PARENT_ROOT="$PARENT_WS/proto/root_$MACH"
export PARENT_TOOLS_ROOT="$PARENT_WS/usr/src/tools/proto/root_$MACH-nd"

# Package creation variables.  You probably shouldn't change these,
# either.
#
# PKGARCHIVE determines where the repository will be created.
#
# PKGPUBLISHER_REDIST controls the publisher setting for the repository.
#
export PKGARCHIVE="${CODEMGR_WS}/packages/${MACH}/nightly"
# export PKGPUBLISHER_REDIST='on-redist'

# Package manifest format version.
export PKGFMT_OUTPUT='v2'

# We want make to do as much as it can, just in case there's more than
# one problem.
# We also must set e in MAKEFLAGS as the makefiles depend on importing
# the environment variables set here.
export MAKEFLAGS='ke'

# Build tools - don't change these unless you know what you're doing.  These
# variables allows you to get the compilers and onbld files locally.
# Set BUILD_TOOLS to pull everything from one location.
# Alternately, you can set ONBLD_TOOLS to where you keep the contents of
# SUNWonbld.
export BUILD_TOOLS='/opt'
#export ONBLD_TOOLS='/opt/onbld'

# Set this flag to 'n' to disable the use of 'checkpaths'.  The default,
# if the 'N' option is not specified, is to run this test.
#CHECK_PATHS='y'

if [[ "$ENABLE_SMATCH" == "1" ]]; then
	SMATCHBIN=$CODEMGR_WS/usr/src/tools/proto/root_$MACH-nd/opt/onbld/bin/$MACH/smatch
	export SHADOW_CCS="$SHADOW_CCS smatch,$SMATCHBIN,smatch"
fi
