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
# Copyright (c) 2018, Joyent, Inc.

#
# Makefile for Java Print Manager server
#

LIBRARY =	libpmgr.a
VERS =		.1

JNIHDR_FILES =	com_sun_admin_pm_server_DoPrinterNS.h

OBJECTS =	DoPrinterNS.o NS.o

CLASSFILES =	Printer.class \
		Host.class \
		SysCommand.class \
		NameService.class \
		PrinterUtil.class \
		DoPrinterView.class \
		DoPrinterAdd.class \
		DoPrinterDelete.class \
		DoPrinterUtil.class \
		DoPrinterMod.class \
		DoPrinterNS.class \
		Valid.class \
		Test.class \
		Debug.class \
		PrinterDebug.class \
		pmException.class \
		pmAuthException.class \
		pmAuthRhostException.class \
		pmCmdFailedException.class \
		pmInternalErrorException.class \
		pmHostNotPingableException.class \
		pmNSNotConfiguredException.class \
		pmMisc.class

JNICLASSFILES =	DoPrinterNS.class

include		$(SRC)/lib/Makefile.lib

SRCDIR =	.

# There should be a mapfile here
MAPFILES =

CLASSPATH=	$(SRC)/cmd/print/printmgr

JAVAFILES =	$(CLASSFILES:.class=.java)

ROOTDIRS =	$(ROOT)/usr/sadm/admin \
		$(ROOT)/usr/sadm/admin/printmgr \
		$(ROOT)/usr/sadm/admin/printmgr/lib

# override ROOTLIBDIR and ROOTLINKS
ROOTLIBDIR =	$(ROOT)/usr/sadm/admin/printmgr/lib
ROOTLIBS=       $(LIBS:%=$(ROOTLIBDIR)/%)


# Following variables define where to find header files
CPPFLAGS +=	-I$(JAVA_ROOT)/include -I$(JAVA_ROOT)/include/solaris -I.

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

LDLIBS +=	-lprint -lnsl -lsocket -lc

CLEANFILES=	*.class $(LINTLIB) $(LINTOUT)
CLOBBERFILES=	$(JNIHDR_FILES) $(LIBLINKS)

all: $(CLASSFILES) $(JNIHDR_FILES) $(DYNLIB)

install: all $(ROOTDIRS) $(ROOTLINKS)

#
# Build jni header file
# Use $@ instead of the "unreliable" $*
#
$(JNIHDR_FILES): $(JNICLASSFILES)
	$(JAVAH) -jni -classpath $(CLASSPATH) \
		`echo $@ | sed 's/.h$$//' | tr _ .`

#
# Build standalone programs for testing
#
NS: NS.c
	$(CC) NS.c $(CCGDEBUG) $(ILDOFF) -o NS -DMAIN=1 $(ENVLDLIBS1) $(ENVLIBS2) \
	    -lprint -lnsl -lsocket

lint: $(JNIHDR_FILES) lintcheck

cstyle:
	cstyle $(SRCS)

jstyle:
	jstyle $(JAVAFILES)

_msg:

$(ROOTDIRS):
	$(INS.dir)

include $(SRC)/lib/Makefile.targ
