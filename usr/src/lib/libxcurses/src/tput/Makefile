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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1996, by Sun Microsystems, Inc.
# All rights reserved.
#
# lib/libxcurses/src/tput/Makefile
#

#
# tput.mk
#
# Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
#
###
### This makefile INTENTIONALLY AVOIDS MKS MAKE EXTENSIONS in order
### to be portable to other systems that supply only a vanilla/POSIX
### make.
###
#
#
# This makefile assumes that a make wrapper, $RD/bin/$SYS/make,
# loads the required make config file, $RD/h/$SYS/config.mk.
# The make wrapper is a shell script that does :
#
#	make -f $RD/h/$SYS/config.mk $@
#
# Note that $RD/bin/$SYS should be ahead of /bin and /usr/bin in PATH.
#
#MAKE	= rmake
#
#CFLAGS	= -D_XOPEN_SOURCE
#
#SRC	= tput.c
#EXE	= tput$E
#
#$O$E :
#	$(LD) $(LDFLAGS) $(CFLAGS) -o $@ $< -lcurses
#
#all :: $(EXE)
#
#install : all
#	$(CP) $(EXE) $(RD)/bin/$(SYS)
#
#clobber :: clean
#	$(RM) $(EXE)

all:
	@echo this tput is not currently used by Solaris
	@echo use tput in usr/src/lib/libcurses
