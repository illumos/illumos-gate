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
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

PROG=		elfedit

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/sgs/Makefile.com

COMOBJ =	elfedit.o sys.o util.o elfconst.o

COMOBJ32 =	elfedit_machelf32.o util_machelf32.o

COMOBJ64 =	elfedit_machelf64.o util_machelf64.o

BLTOBJ =	msg.o

OBJS=		$(BLTOBJ) $(COMOBJ) $(COMOBJ32) $(COMOBJ64)

MAPFILE=	../common/mapfile-vers

CPPFLAGS=	-I. -I../common -I../../include -I../../include/$(MACH) \
		-I$(SRC)/lib/libc/inc -I$(SRC)/uts/$(ARCH)/sys \
		$(CPPFLAGS.master) -I$(ELFCAP)
LLDFLAGS =	$(VAR_ELFEDIT_LLDFLAGS)
LLDFLAGS64 =	$(VAR_ELFEDIT_LLDFLAGS64)
LDFLAGS +=	$(VERSREF) -M$(MAPFILE) $(LLDFLAGS)
LDLIBS +=	$(ELFLIBDIR) -lelf $(LDDBGLIBDIR) -llddbg \
		    $(CONVLIBDIR) -lconv -ltecla
NATIVE_LIBS +=	libtecla.so

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	$(CNOWARN_UNINIT)

BLTDEFS =	msg.h
BLTDATA =	msg.c
BLTMESG =	$(SGSMSGDIR)/elfedit

BLTFILES =	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM =	../common/elfedit.msg
SGSMSGTARG =	$(SGSMSGCOM)
SGSMSGALL =	$(SGSMSGCOM)
SGSMSGFLAGS +=	-h $(BLTDEFS) -d $(BLTDATA) -m $(BLTMESG) -n elfedit_msg

SRCS =		$(COMOBJ:%.o=../common/%.c) \
		$(COMOBJ32:%32.o=../common/%.c) \
		$(BLTDATA)

CLEANFILES +=	$(BLTFILES)
