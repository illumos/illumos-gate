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

LIBRARY= libpkg.a
VERS=	.1

# include library definitions
OBJECTS=	\
		canonize.o   ckparam.o    ckvolseq.o \
		devtype.o    dstream.o    gpkglist.o \
		gpkgmap.o    isdir.o      logerr.o \
		mappath.o    ncgrpw.o     nhash.o \
		pkgexecl.o   pkgexecv.o   pkgmount.o \
		pkgtrans.o   ppkgmap.o \
		progerr.o    putcfile.o   rrmdir.o \
		runcmd.o     srchcfile.o  tputcfent.o \
		verify.o     security.o   pkgweb.o \
		pkgerr.o     keystore.o   p12lib.o \
		vfpops.o     fmkdir.o     pkgstr.o \
		handlelocalfs.o	pkgserv.o


# include library definitions
include $(SRC)/lib/Makefile.lib

SRCDIR=		../common

POFILE =	libpkg.po
MSGFILES =	$(OBJECTS:%.o=../common/%.i)
CLEANFILES +=   $(MSGFILES)

# This library is NOT lint clean

# openssl forces us to ignore dubious pointer casts, thanks to its clever
# use of macros for stack management.
LINTFLAGS=      -umx -errtags \
		-erroff=E_BAD_PTR_CAST_ALIGN,E_BAD_PTR_CAST
LINTFLAGS +=	-erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
LINTFLAGS64 +=	-erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)


LIBS = $(DYNLIB) $(LINTLIB)


LDLIBS +=	-lc -lssl -lwanboot -lcrypto -lscf -ladm

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-unused-value
CPPFLAGS +=	-I$(SRCDIR) -D_FILE_OFFSET_BITS=64

.KEEP_STATE:

all:	$(LIBS)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

lint: lintcheck

# include library targets
include $(SRC)/lib/Makefile.targ
include $(SRC)/Makefile.msg.targ
