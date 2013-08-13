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

#
# This make file will build mech_dh.so.1. This shared object
# contains all the functionality needed to support Diffie-Hellman GSS-API
# mechanism. 
#

LIBRARY= mech_dh.a
VERS = .1

MECH =	context.o context_establish.o cred.o crypto.o dhmech.o \
	MICwrap.o name.o oid.o seq.o token.o support.o validate.o

DERIVED_OBJS = xdr_token.o

CRYPTO = md5.o

OBJECTS= $(MECH) $(CRYPTO) $(DERIVED_OBJS)

# include library definitions
include ../../../../Makefile.lib

CPPFLAGS += -I../mech -I../crypto -I$(SRC)/uts/common/gssapi/include

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized

$(PICS) := 	CFLAGS += $(XFFLAG)
$(PICS) := 	CCFLAGS += $(XFFLAG)
$(PICS) :=	CFLAGS64 += $(XFFLAG)
$(PICS) :=	CCFLAGS64 += $(XFFLAG)

DYNFLAGS +=	$(ZIGNORE)

LIBS = $(DYNLIB)
LIBNAME = $(LIBRARY:%.a=%)

MAPFILES =	../mapfile-vers

LDLIBS +=  -lgss -lnsl -lc 

RPCGEN += -C
SED = sed

.KEEP_STATE:

CSRCS= $(MECH:%.o=../mech/%.c) $(CRYPTO:%.o=../crypto/%.c)
SRCS=	$(CSRCS)

ROOTLIBDIR = $(ROOT)/usr/lib/gss
ROOTLIBDIR64 = $(ROOT)/usr/lib/$(MACH64)/gss

#LINTFLAGS += -dirout=lint -errfmt=simple
#LINTFLAGS64 += -dirout=lint -errfmt=simple -errchk all
LINTOUT =	lint.out
LINTSRC =	$(LINTLIB:%.ln=%)
ROOTLINTDIR =	$(ROOTLIBDIR)
#ROOTLINT = 	$(LINTSRC:%=$(ROOTLINTDIR)/%)

CLEANFILES += $(LINTOUT) $(LINTLIB)

lint: lintcheck

$(ROOTLIBDIR):
	$(INS.dir)

$(ROOTLIBDIR64):
	$(INS.dir)

$(OBJS): ../mech/dh_gssapi.h ../mech/token.h ../mech/oid.h


objs/%.o pics/%.o: ../crypto/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: ../mech/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: ../profile/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

# include library targets
include ../../../../Makefile.targ
