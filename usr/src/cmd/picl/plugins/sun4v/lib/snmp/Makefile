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
# Copyright 2019 Peter Tribble.
#

#
# cmd/picl/plugins/sun4v/lib/snmp/Makefile
#

LIBRARY=	libpiclsnmp.a
VERS=		.1
OBJECTS=	snmplib.o pdu.o asn1.o

# include library definitions
include $(SRC)/Makefile.psm
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/sun4v

include $(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS=		$(DYNLIB)

ROOTLIBDIR      = $(ROOT_PLATFORM)/lib

CLEANFILES=	$(LINTOUT) $(LINTLIB)
CLOBBERFILES += $(LIBLINKS)

CPPFLAGS +=	-I. -I../../include -I$(SRC)/uts/sun4v
CPPFLAGS +=	-D_REENTRANT

#
# Do NOT uncomment the following two lines, unless you want to test
# the behavior of the library with an SNMP agent over network.
#
#CPPFLAGS +=	-DUSE_SOCKETS
#LDLIBS +=	-lsocket -lnsl

CFLAGS +=	$(CCVERBOSE) -DBIG_ENDIAN
LDLIBS +=	-lc -lnvpair

.KEEP_STATE:


SUBDIRS=

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint

all:  $(DYNLIB) $(LIBLINKS)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS)

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

lint :
	$(LINT.c) -m $(SRCS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
