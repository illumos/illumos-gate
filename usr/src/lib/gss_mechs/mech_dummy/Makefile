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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# lib/gss_mechs/mech_dummy/Makefile
#
#
# This make file will build mech_dummy.so.1. This shared object
# contains all the functionality needed to support the Dummy GSS-API
# mechanism. 
#

include ../../../Makefile.master

SUBDIRS= $(MACH) $(BUILD64) $(MACH64)

# include library definitions
include ../../Makefile.lib

HDRS=

CHECKHDRS= $(HDRS:%.h=%.check)

$(ROOTDIRS)/%:	%
	$(INS.file)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

all:	.WAIT $(SUBDIRS)

lint:	.WAIT $(SUBDIRS)

install: all

install_h:

DUPLICATE_SRC = dmech.c

clean clobber:  $(SUBDIRS)

check: $(CHECKHDRS)

# include library targets
# include ../../Makefile.targ

$(MACH) $(MACH64):      FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
