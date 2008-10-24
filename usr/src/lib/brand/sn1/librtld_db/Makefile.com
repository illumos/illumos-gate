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

LIBRARY =	sn1_librtld_db.a
VERS	=	.1
COBJS	=	sn1_librtld_db.o
OBJECTS	=	$(COBJS) $(COBJS64)

include $(SRC)/lib/Makefile.lib
include ../../Makefile.sn1

CSRCS =		$(COBJS:%o=../common/%c)
SRCS  =		$(CSRCS)

SRCDIR =	../common
UTSBASE	=	$(SRC)/uts

#
# ATTENTION:
#	Librtl_db brand plugin libraries should NOT directly invoke any
#	libproc.so interfaces or be linked against libproc.  If a librtl_db
#	brand plugin library uses libproc.so interfaces then it may break
#	any other librtld_db consumers (like mdb) that tries to attach
#	to a branded process.  The only safe interfaces that the a librtld_db
#	brand plugin library can use to access a target process are the
#	proc_service(3PROC) apis.
#
DYNFLAGS +=	$(VERSREF) -M../common/mapfile-vers
LIBS =		$(DYNLIB)
LDLIBS +=	-lc -lrtld_db
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I../ -I$(UTSBASE)/common/brand/sn1 \
			-I../../../../../cmd/sgs/librtld_db/common \
			-I../../../../../cmd/sgs/include \
			-I../../../../../cmd/sgs/include/$(MACH)

ROOTLIBDIR =	$(ROOT)/usr/lib/brand/sn1
ROOTLIBDIR64 =	$(ROOT)/usr/lib/brand/sn1/$(MACH64)

#
# The top level Makefiles define define TEXT_DOMAIN.  But librtld_db.so.1
# isn't internationalized and this library won't be either.  The only
# messages that this library can generate are messages used for debugging
# the operation of the library itself.
#
DTEXTDOM =

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%64.o:	../common/%.c
		$(COMPILE.c) -D_ELF64 $(PICFLAGS) -o $@ $<
		$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
