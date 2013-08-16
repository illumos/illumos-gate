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
# Makefile for policy testing code
#

PROG =	kmfcfg

OBJS =	kmfcfg.o \
	list.o \
	delete.o \
	util.o \
	create.o \
	modify.o \
	export.o \
	import.o \
	install.o \
	uninstall.o

include ../../Makefile.cmd

KMFDIR		= $(SRC)/lib/libkmf
SRCS		= $(OBJS:%.o=%.c)

POFILES		= $(OBJS:%.o=%.po)
POFILE		= $(PROG)_msg.po
MSGFILES	= $(SRCS:%.c=%.i)

CPPFLAGS	+= -I$(ADJUNCT_PROTO)/usr/include/libxml2 \
		-I$(KMFDIR)/include -I.
LDLIBS		+= -L$(ROOT)/usr/lib -lkmf -lcryptoutil
XMLLIB		= -lxml2

.KEEP_STATE:

XMLDIR=		$(ROOT)/etc/security
DTDDIR=		$(ROOT)/usr/share/lib/xml/dtd
ROOTDTDS=	$(DTDDIR)/kmfpolicy.dtd
ROOTXML=	$(XMLDIR)/kmfpolicy.xml

$(ROOTDTDS) :=	FILEMODE = 444

$(ROOTXML)  :=	FILEMODE = 644

all:	$(PROG) $(ROOTDTDS)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(XMLLIB)
	$(POST_PROCESS)

$(POFILE):	$(POFILES)
	$(RM) $@; $(CAT) $(POFILES) > $@

install:	all $(ROOTDTDS) $(ROOTXML) $(ROOTPROG)

$(XMLDIR)/%: %
	$(INS.file)

$(DTDDIR)/%: %
	$(INS.file)

clean:
	$(RM) $(OBJS)

lint : lint_SRCS

include ../../Makefile.targ
