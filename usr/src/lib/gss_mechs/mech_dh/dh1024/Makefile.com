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
# This make file will build dh1024.so.1. This shared object
# contains the functionality needed to initialize the  Diffie-Hellman GSS-API
# mechanism with 1024 bit key length. This library, in turn, loads the 
# generic Diffie-Hellman GSS-API backend, dhmech.so
#

LIBRARY= dh1024-0.a
VERS = .1

DH1024=	dh1024.o dh_common.o generic_key.o

OBJECTS= $(DH1024) 

# include library definitions
include ../../../../Makefile.lib

CPPFLAGS += -I../../backend/mech -I../../backend/crypto
CPPFLAGS += -I$(SRC)/lib/libnsl/include
CPPFLAGS += -I$(SRC)/uts/common/gssapi/include

$(PICS) := 	CFLAGS += $(XFFLAG)
$(PICS) := 	CCFLAGS += $(XFFLAG)
$(PICS) :=	CFLAGS64 += $(XFFLAG)
$(PICS) :=	CCFLAGS64 += $(XFFLAG)

DYNFLAGS +=	$(ZIGNORE)

LIBS = $(DYNLIB)
LIBNAME = $(LIBRARY:%.a=%)

MAPFILES =	../mapfile-vers

LDLIBS += -lnsl -lmp -lc

.KEEP_STATE:

SRCS=	../dh1024.c ../../dh_common/dh_common.c ../../dh_common/generic_key.c

ROOTLIBDIR = $(ROOT)/usr/lib/gss
ROOTLIBDIR64 = $(ROOT)/usr/lib/$(MACH64)/gss

#LINTFLAGS += -errfmt=simple
#LINTFLAGS64 += -errfmt=simple
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

# include library targets
include ../../../../Makefile.targ

objs/%.o pics/%.o: ../%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: ../../dh_common/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: ../profile/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)
