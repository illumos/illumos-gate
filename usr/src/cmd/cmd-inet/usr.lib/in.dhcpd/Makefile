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
# cmd/cmd-inet/usr.lib/in.dhcpd/Makefile
#

CMN_DIR = $(SRC)/common/net/dhcp
NSU_DIR = $(ROOTLIBINET)/dhcp/nsu

PROG	= in.dhcpd
MANIFEST= dhcp-server.xml

LOCAL_OBJS =	bootp.o dhcp.o dhcptab.o encode.o generic.o hash.o icmp.o \
		interfaces.o logging.o main.o misc.o per_dnet.o relay.o
LOCAL_SRCS =	$(LOCAL_OBJS:%.o=%.c)

CMN_OBJS =	ipv4_sum.o
CMN_SRCS =	$(CMN_OBJS:%.o=$(CMN_DIR)/%.c)

SRCS =		$(LOCAL_SRCS) $(CMN_SRCS)
OBJS =		$(LOCAL_OBJS) $(CMN_OBJS)

include ../../../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)

CPPFLAGS  += -DNDEBUG -DNPROBE -D_REENTRANT -I./ -I$(CMN_DIR)
#
# -erroff=E_BAD_FORMAT_STR2 added to workaround bug 6696366 
#
LINTFLAGS += -u -erroff=E_BAD_FORMAT_STR2
LDFLAGS	  += -L$(NSU_DIR) -R/usr/lib/inet/dhcp/nsu $(MAPFILE.NGB:%=-M%)
LDLIBS    += $(NSU_DIR)/rfc2136.so.1 -ldhcpsvc -ldhcputil -linetutil \
	     -lsocket -lnsl -lmtmalloc -lresolv
lint := LDLIBS = $(LDLIBS.cmd) -ldhcpsvc -ldhcputil -linetutil -lsocket -lnsl

CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-parentheses

#
# Debugging support; toggle on if needed.
#
#CPPFLAGS += -DDEBUG		# if used, remove -DNDEBUG above
#CPPFLAGS += -DTNF_DEBUG
#COPTFLAG = -g
#COPTFLAG += -xprofile=func

# for messaging catalog. No messages are present in CMN_DIR sources.
POFILES = $(LOCAL_OBJS:%.o=%.po)
XGETFLAGS += -a -x in.dhcpd.xcl

.PARALLEL:	$(OBJS)
.WAIT:		$(PROG)
.KEEP_STATE:

all:		$(PROG)

$(PROG): 	$(OBJS) $(MAPFILE.NGB)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

include ../Makefile.lib

install:	all $(ROOTLIBINETPROG) $(ROOTMANIFEST)

%.o:		$(CMN_DIR)/%.c
		$(COMPILE.c) $(OUTPUT_OPTION) $<
		$(POST_PROCESS_O)

$(POFILE):	$(POFILES)
		$(RM)	$@
		$(CAT) $(POFILES) > $@

check:		$(CHKMANIFEST)

clean:
		$(RM) $(OBJS)

lint:		lint_SRCS

include ../../../Makefile.targ
