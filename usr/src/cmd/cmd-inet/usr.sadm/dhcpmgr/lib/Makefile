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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY=	dhcpmgr.a
VERS= 		.1
OBJECTS= 	dhcptab.o exception.o network.o optiondefs.o service.o \
		inittab.o dd_misc.o dd_opt.o class_cache.o

include $(SRC)/lib/Makefile.lib

SRCDIR =	.

# Override install location
ROOTLIBDIR=	$(ROOT)/usr/sadm/admin/dhcpmgr

LIBS=		$(DYNLIB)

# There should be a mapfile here
MAPFILES =

CPPFLAGS += 	-I../com/sun/dhcpmgr/bridge \
		-I$(JAVA_ROOT)/include \
		-I$(JAVA_ROOT)/include/solaris \
		-I$(SRC)/common/net/dhcp \
		-I. 

CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-uninitialized

LDLIBS +=	-ldhcpsvc -ldhcputil -linetutil -lscf -lsocket -lresolv -lnsl -lc

# definitions for i18n
POFILE=		$(LIBRARY:%.a=%.po)
MSGFILES =	`$(GREP) -l gettext *.[ch]`

.KEEP_STATE:
.PARALLEL: $(OBJECTS)
.WAIT: $(DYNLIB)

all: $(LIBS)

install: all $(ROOTLIBS)

lint:	lintcheck

_msg:   pofile_MSGFILES

include $(SRC)/lib/Makefile.targ
include $(SRC)/Makefile.msg.targ
