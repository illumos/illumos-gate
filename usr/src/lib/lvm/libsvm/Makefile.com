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

LIBRARY=      	libsvm.a 
VERS=          	.1 
OBJECTS=	check_svm.o \
		getdrvname.o \
		metaconf.o \
		metainterfaces.o \
		modops.o \
		start_svm.o \
		debug.o \
		update_mdconf.o

include $(SRC)/lib/lvm/Makefile.lvm

ROOTLIBDIR=	$(ROOT)/usr/snadm/lib

LIBS =		$(DYNLIB) # don't build a static lib
LDLIBS +=	-lmeta -ldevid -lc
#
# XXX There isn't a lint library for libspmicommon.  For now, we work
# around this by only using the library when we build (as opposed to lint).
#
all debug install := LDLIBS += -L$(ADJUNCT_PROTO)/usr/snadm/lib -lspmicommon

DYNFLAGS +=	-R/usr/snadm/lib
CPPFLAGS +=	-D_FILE_OFFSET_BITS=64
CPPFLAGS +=	-I$(SRC)/lib/lvm/libsvm/common/hdrs
ZDEFS =

.KEEP_STATE:

all: $(LIBS)

include $(SRC)/lib/lvm/Makefile.targ
