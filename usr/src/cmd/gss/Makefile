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
# Copyright (c) 1997 - 1998 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/gss/Makefile
#
# include global definitions
include ../../Makefile.master

COMMON_SUBDIRS=		\
	etc		\
	gssd		\
	gsscred		\
	gsscred_clean

i386_SUBDIRS=

sparc_SUBDIRS=

#
# commands that are messaged
# note that 'lp' comes first (see previous comment about 'lp')
#
MSGSUBDIRS= gssd gsscred

#
# commands that use dcgettext for localized time, LC_TIME
#
DCSUBDIRS=

#
# commands that belong only to the basic security module
#
BSMSUBDIRS=

#
# commands not owned by the systems group
#
BWOSDIRS=

all :=		TARGET= all
install :=	TARGET= install
install_h :=	TARGET= install_h
check :=	TARGET= check
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg
_dc :=		TARGET= _dc

.KEEP_STATE:

SUBDIRS = $(COMMON_SUBDIRS)  $($(MACH)_SUBDIRS)

.PARALLEL:	$(BWOSDIRS) $(SUBDIRS) $(MSGSUBDIRS)  $(BSMSUBDIRS)

all install clean clobber lint: $(SUBDIRS) $(BSMSUBDIRS)

# those commands which install headers possibly needed by other commands.
install_h check:

_msg: $(MSGSUBDIRS) _dc

_dc: $(DCSUBDIRS)

$(BWOSDIRS) $(SUBDIRS) $(BSMSUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
