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

LIBRARY =		mod_ipp.a
VERS =
OBJECTS = mod_ipp.o

include ../../Makefile.lib
include ../../Makefile.rootfs

APACHEMODDIR =	$(ROOT)/usr/apache/libexec
APACHECONFDIR =	$(ROOT)/etc/apache
LISTENERDIR =	$(ROOT)/var/lp/ipp-listener

ROOTDIRS =	$(ROOT)/usr/apache $(APACHEMODDIR) $(APACHECONFDIR) \
		$(ROOT)/var/lp $(LISTENERDIR)

$(ROOT)/var/lp:=	DIRMODE = 775
$(ROOT)/var/lp:=	FILEMODE = 775

LIBS =			$(DYNLIB)

SRCS = $(OBJECTS:%.o = %.c)


CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I../libipp-listener/common
CPPFLAGS +=	-I../libipp-core/common
CPPFLAGS +=	-I/usr/apache/include
CPPFLAGS +=	-DEAPI
ZDEFS =		$(ZNODEFS)

MAPFILES =	mapfile

LDLIBS +=	-lipp-listener -lipp-core -lpapi -lc

#	SMF manifest
MANIFEST=       ipp-listener.xml
ROOTMANIFESTDIR=        $(ROOT)/var/svc/manifest/application/print
ROOTMANIFEST=		$(MANIFEST:%=$(ROOTMANIFESTDIR)/%)
$(ROOTMANIFEST)         := FILEMODE= 444

#	Apache module
$(APACHEMODDIR)/$(LIBLINKS):	$(ROOTDIRS)

#	Apache config
APACHECONFFILE=	$(APACHECONFDIR)/httpd-standalone-ipp.conf
$(APACHECONFFILE)         := FILEMODE= 644
LISTENERFILE=	$(LISTENERDIR)/index.html
$(LISTENERFILE)         := FILEMODE= 444

$(ROOT)/var/lp:=	FILEMODE = 0775

$(APACHEMODDIR)/$(LIBLINKS):=	FILEMODE = 0555

$(ROOTMANIFESTDIR)/% $(APACHEMODDIR)/% $(APACHECONFDIR)/% $(LISTENERDIR)/%:	%
	$(INS.file)

$(ROOTDIRS):
	$(INS.dir)

.KEEP_STATE:

all:	$(LIBS)

install:	all $(APACHEMODDIR)/$(LIBLINKS) $(APACHECONFFILE) \
		$(LISTENERFILE) $(ROOTMANIFEST)

install_h:

lint:

include ../../Makefile.targ
