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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

LIBRARY =		mod_ipp.a
VERS =
OBJECTS = mod_ipp.o

include ../../Makefile.lib
include ../../Makefile.rootfs

# These *BASE paths are used ONLY at build time to locate headers.
# This builds against Apache 2.2 but the module should work with
# any Apache 2.x version, and APR 1.3 or later.
APACHEBASE =	/usr/apache2/2.2
APR_BASE =	/usr/apr/1.3
APRUBASE =	/usr/apr-util/1.3

IPPCONFDIR =	$(ROOT)/etc/lp/ipp
IPPLIBDIR =	$(ROOT)/usr/lib/lp/ipp
LISTENERDIR =	$(ROOT)/var/lp/ipp-listener

ROOTDIRS =	$(ROOT)/etc/lp $(IPPCONFDIR) \
		$(ROOT)/usr/lib/lp $(IPPLIBDIR) \
		$(ROOT)/var/lp $(LISTENERDIR)

$(ROOT)/etc/lp:=	DIRMODE = 775
$(ROOT)/var/lp:=	DIRMODE = 775
$(ROOT)/var/lp:=	FILEMODE = 775

LIBS =			$(DYNLIB)

SRCS = $(OBJECTS:%.o = %.c)


CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I../libipp-listener/common
CPPFLAGS +=	-I../libipp-core/common
CPPFLAGS +=	-I$(ADJUNCT_PROTO)$(APACHEBASE)/include
CPPFLAGS +=	-I$(ADJUNCT_PROTO)$(APR_BASE)/include
CPPFLAGS +=	-I$(ADJUNCT_PROTO)$(APRUBASE)/include
CPPFLAGS +=	-DAPACHE2
CPPFLAGS +=	-DEAPI

# See: /usr/apache2/2.2/build/config_vars.mk
# Make sure to build with compatible flags.
CPPFLAGS +=	-D_REENTRANT -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

MAPFILES =	mapfile httpd-syms.map

LDLIBS +=	-lipp-listener -lipp-core -lpapi -lc

#	SMF manifest
MANIFEST=       ipp-listener.xml
ROOTMANIFESTDIR=        $(ROOT)/lib/svc/manifest/application/print
ROOTMANIFEST=		$(MANIFEST:%=$(ROOTMANIFESTDIR)/%)
$(ROOTMANIFEST)         := FILEMODE= 444

#	Apache module
#	LIBLINKS is not a link here, just the bare *.so name
$(IPPLIBDIR)/$(LIBLINKS):	$(ROOTDIRS)

#	Apache config
APACHECONFFILE=	$(IPPCONFDIR)/httpd-standalone-ipp.conf
$(APACHECONFFILE)         := FILEMODE= 644
LISTENERFILE=	$(LISTENERDIR)/index.html
$(LISTENERFILE)         := FILEMODE= 444

$(ROOT)/var/lp:=	FILEMODE = 0775

$(IPPLIBDIR)/$(LIBLINKS):=	FILEMODE = 0555

$(ROOTMANIFESTDIR)/% $(IPPLIBDIR)/% $(IPPCONFDIR)/% $(LISTENERDIR)/%:	%
	$(INS.file)

$(ROOTDIRS):
	$(INS.dir)

.KEEP_STATE:

all:	$(LIBS)

install:	all $(IPPLIBDIR)/$(LIBLINKS) $(APACHECONFFILE) \
		$(LISTENERFILE) $(ROOTMANIFEST)

install_h:

lint:

include ../../Makefile.targ
