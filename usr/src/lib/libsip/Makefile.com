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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY = libsip.a
VERS    = .1
OBJECTS = sip_headers.o sip_msg.o sip_gids.o \
	sip_timeout.o sip_xaction_state_mc.o sip_xaction.o \
	sip_hash.o sip_itf.o sip_ui.o sip_reass.o sip_dialog.o \
	sip_dialog_ui.o sip_xaction_ui.o sip_parse_generic.o \
	sip_parse_uri.o sip_uri_ui.o sip_parse_hdrs.o \
	sip_add_hdrs.o sip_hdrs_ui.o sip_logging.o

include ../../Makefile.lib

SRCDIR =	../common
LIBS =		$(DYNLIB) $(LINTLIB)
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)
LDLIBS +=	-lmd5 -lc

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-DOS='"solaris"' -D__OS_solaris -DNDEBUG

# not linted
SMATCH=off

.KEEP_STATE:

all:		$(LIBS)

lint:		lintcheck

include ../../Makefile.targ
