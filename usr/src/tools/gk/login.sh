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
# example .login for root build user (often 'gk').
# sets up for potential dmake use in parallel-make mode

unset ignoreeof
umask 002
stty erase  werase  kill  intr 

setenv NIS_PATH 'org_dir.$:$'
setenv EDITOR /usr/bin/vi
setenv MACH `uname -p`

set noglob; eval `/usr/ucb/tset -Q -s -e -k - -m dialup:vt102`; unset noglob
setenv MANPATH /usr/man:/usr/local/man:/usr/local/doctools/man:/opt/onbld/man
setenv DMAKE_MODE parallel
set hostname=`uname -n`
if ( ! -f ~/.make.machines ) then
	set maxjobs=4
else
	set maxjobs="`grep $hostname ~/.make.machines | tail -1 | awk -F= '{print $ 2;}'`"
	if ( "$maxjobs" == "" ) then
		set maxjobs=4
	endif
endif
setenv DMAKE_MAX_JOBS $maxjobs


set path=( \
	/opt/onbld/bin \
	/opt/onbld/bin/${MACH} \
	/opt/SUNWspro/bin \
	/opt/teamware/bin \
	/usr/ccs/bin \
	/usr/proc/bin \
	/usr/openwin/bin \
	/bin \
	/usr/bin \
	/usr/sbin \
	/sbin \
	/usr/local/bin \
	/usr/ucb \
	/etc \
	/usr/etc \
)
