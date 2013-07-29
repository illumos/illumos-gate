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
# uts/sun4v/huron/Makefile
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
#	This makefile drives the production of the sun4v huron platform
#	modules.
#
#	sun4v huron implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Include common rules.
#
include $(UTSBASE)/sun4v/Makefile.sun4v

USR_PLAT_DIR = $(ROOT)/usr/platform

include $(UTSBASE)/sun4v/Makefile.huron

def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint
lintlib		:=	TARGET= lintlib
modlintlib	:=	TARGET= modlintlib
modlist		:=	TARGET= modlist
modlist		:=	NO_STATE= -K $$MODSTATE$$$$
clean.lint	:=	TARGET= clean.lint
check		:=	TARGET= check

#
#	Default build targets.
#
.KEEP_STATE:

def:

lintlib:      unix

IMPLEMENTED_PLATFORM	= SUNW,SPARC-Enterprise-T5120
LINKED_PLATFORMS	= SUNW,SPARC-Enterprise-T5220


$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%): $(USR_PLAT_DIR)
	$(INS.slink3)

all:

install:	$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%)

install_h check:

lint:

clean:

clobber:	clean

modlist:
