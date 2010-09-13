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
# Copyright (c) 1993-1998 by Sun Microsystems, Inc.
# All rights reserved.
# 
#ident	"%Z%%M%	%I%	%E% SMI"
#
# example .cshrc for root build user (often 'gk').

set filec
set history=100
set noclobber
set ignoreeof
set notify

unset nse1
unset nse2

umask 002

# if ($?USER == 0 || $?prompt == 0) exit

alias ls "ls -aF"

if ( ! $?HOSTNAME ) then
	setenv HOSTNAME `uname -n`
endif

if ( ! $?TERM ) then
	setenv TERM sun
endif

set prompt="{${USER}:${HOSTNAME}:\!} "
