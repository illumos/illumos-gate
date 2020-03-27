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
# lib/libprtdiag/sparc/sun4v/Makefile
#
# Platform specific Makefile for libprtdiag.
#
# PLATFORM is the target for the binary installation.
#

PLATFORM	= sun4v

OBJECTS		= io.o cpu.o memory.o kstat.o prom.o \
			pdevinfo_funcs.o display_funcs.o \
			pdevinfo_sun4v.o display_sun4v.o

include		../../Makefile.com

SRCS		= $(OBJECTS:%.o=../../common/%.c)
LDLIBS		+= -lpicl -lm

#
# used for creating message catalogue files
#
TEXT_DOMAIN=	SUNW_OST_OSLIB
SED=		sed
GREP=		grep

.KEEP_STATE:

all:		$(LIBS)

install:	all $(USR_PSM_LIBS)


include		$(SRC)/lib/Makefile.targ

POFILE=		libprtdiag_sun4v.po
POFILES=	generic.po

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../../common/*.c`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po
