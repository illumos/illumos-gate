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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 1989-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/lp/filter/postscript/Makefile
#

include 	../../Makefile.lp

COMMON_SUBDIRS = \
		common		\
		postreverse	\
        	dpost		\
		postio		\
        	postprint	\
        	posttek		\
        	postdmd		\
        	postdaisy	\
        	postmd		\
		postplot	\
        	postscript	\
		postcomm	\
		picpack		\
		download	\
        	font		\
		filtdesc

SUBDIRS= $(COMMON_SUBDIRS)

ROOTDIRS =	$(ROOTLIBLPPOST)

TXTS=		README

.KEEP_STATE:

all:  		$(TXTS) $(SUBDIRS)

install:	$(ROOTDIRS) .WAIT $(SUBDIRS)

clean clobber strip lint catalog:	$(SUBDIRS)

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTDIRS):
		$(INS.dir)

FRC:
