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

LIBRARY= 	lib.a

DATEFILE= 	ugdates
DATEFILESRC= 	ugdates.dat
TXT= 		$(DATEFILESRC)

OBJECTS= 	putgrent.o \
		errmsg.o \
		file.o \
		vgid.o \
		vgname.o \
		vgroup.o \
		vuid.o \
		vlogin.o \
		vproj.o \
		dates.o \
		vexpire.o \
		putprojent.o \
		vprojid.o \
		vprojname.o

# include library definitions
include ../../Makefile.cmd
include ../../../lib/Makefile.lib

SRCDIR =	.

GREP= 		grep
FILEMODE=	$(LIBFILEMODE)

PRODUCT=	$(LIBRARY) $(DATEFILE)

# Must retain `lib', since default expands to nothing
LLINTLIB=	llib-l$(LIBRARY:lib%.a=lib).ln

CLEANFILES=	$(LLINTLIB)
CLOBBERFILES=	$(DATEFILE)

GENERAL=	../inc
CPPFLAGS=	-I. -I$(GENERAL) $(CPPFLAGS.master)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-unused-variable
ARFLAGS=	cr
AROBJS=		`$(LORDER) $(OBJS) | $(TSORT)`
LINTFLAGS=	-u

ROOTUSRSADM=	$(ROOT)/usr/sadm
ROOTUSRSADMFILE=$(DATEFILE:%=$(ROOTUSRSADM)/%)

CLOBBERFILES += $(LIBRARY)

.KEEP_STATE:

all:		$(PRODUCT) $(TXT)

$(DATEFILE):	$(DATEFILESRC)
	$(GREP) -v "^#ident" $(DATEFILESRC) > $(DATEFILE)

install:	all $(DATEFILE) $(ROOTUSRSADMFILE)

$(ROOTUSRSADM)/%: %
	$(INS.file)

lint:		$(LLINTLIB)

$(LLINTLIB):	$(SRCS)
	$(LINT.c) -o $(LIBRARY:lib%.a=lib) $(SRCS) > $(LINTOUT) 2>&1

include ../../../lib/Makefile.targ
