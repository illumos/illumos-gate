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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#######################################################
#
# Makefile for madman_api_test
#
#######################################################

#
# Makefile.vars
#

include ../../../Makefile.vars


#
# other variables
#

TARGET1=	$(BIN)/madman_api_test
TARGET2=	$(BIN)/asn1_test
TARGET3=	$(BIN)/error_test
TARGET4=	$(BIN)/trap_test
TARGET5=	$(BIN)/madman_trap_test
TARGET6=	$(BIN)/madman_api_test_2


.KEEP_STATE:

SOURCES1.c= madman_api_test.c

SOURCES2.c= asn1_test.c

SOURCES3.c= error_test.c

SOURCES4.c= trap_test.c

SOURCES5.c= madman_trap_test.c

SOURCES6.c= madman_api_test_2.c

SOURCES.h=\
	../snmp_msg.h\
	../impl.h\
	../error.h\
	../trace.h\
	../asn1.h\
	../signals.h\
	../snmp.h\
	../pdu.h\
	../request.h\
	../snmp_api.h\
	../madman_api.h

OBJECTS1= $(SOURCES1.c:%.c=$(BIN)/%.o)
OBJECTS2= $(SOURCES2.c:%.c=$(BIN)/%.o)
OBJECTS3= $(SOURCES3.c:%.c=$(BIN)/%.o)
OBJECTS4= $(SOURCES4.c:%.c=$(BIN)/%.o)
OBJECTS5= $(SOURCES5.c:%.c=$(BIN)/%.o)
OBJECTS6= $(SOURCES6.c:%.c=$(BIN)/%.o)

OBJECTS= $(OBJECTS1) $(OBJECTS2) $(OBJECTS3) $(OBJECTS4) \
	 $(OBJECTS5) $(OBJECTS6)

MYLIBS= ../$(MACH)/libssasnmp.a

LIBS=	-lsocket -lnsl -lelf -lgen 

CPPFLAGS += -I. -I.. -I${BIN}

CFLAGS += -c

LDFLAGS += $(LDLIBS)

LINT=	lint

PURIFY_HOME= /usr/soft/purify3.0

PURIFY= $(PURIFY_HOME)/purify


#######################################################

#
# all
#

all: $(SOURCES.h) $(TARGET1) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5) $(TARGET6)

$(TARGET1): $(BIN) $(OBJECTS1) $(MYLIBS)
	@echo -------------- $@ linkink begins --------------
	$(CC) -o $(TARGET1) $(LDFLAGS) $(OBJECTS1) $(MYLIBS) $(LIBS)
	@echo -------------- $@ linkink ended ---------------

$(TARGET2): $(BIN) $(OBJECTS2) $(MYLIBS)
	@echo -------------- $@ linkink begins --------------
	$(CC) -o $(TARGET2) $(LDFLAGS) $(OBJECTS2) $(MYLIBS) $(LIBS)
	@echo -------------- $@ linkink ended ---------------

$(TARGET3): $(BIN) $(OBJECTS3) $(MYLIBS)
	@echo -------------- $@ linkink begins --------------
	$(CC) -o $(TARGET3) $(LDFLAGS) $(OBJECTS3) $(MYLIBS) $(LIBS)
	@echo -------------- $@ linkink ended ---------------

$(TARGET4): $(BIN) $(OBJECTS4) $(MYLIBS)
	@echo -------------- $@ linkink begins --------------
	$(CC) -o $(TARGET4) $(LDFLAGS) $(OBJECTS4) $(MYLIBS) $(LIBS)
	@echo -------------- $@ linkink ended ---------------

$(TARGET5): $(BIN) $(OBJECTS5) $(MYLIBS)
	@echo -------------- $@ linkink begins --------------
	$(CC) -o $(TARGET5) $(LDFLAGS) $(OBJECTS5) $(MYLIBS) $(LIBS)
	@echo -------------- $@ linkink ended ---------------

$(TARGET6): $(BIN) $(OBJECTS6) $(MYLIBS)
	@echo -------------- $@ linkink begins --------------
	$(CC) -o $(TARGET6) $(LDFLAGS) $(OBJECTS6) $(MYLIBS) $(LIBS)
	@echo -------------- $@ linkink ended ---------------

$(BIN)/%.o: %.c
	@echo -------------- $@ compile begins --------------
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFINES) $*.c -o $@
	@echo -------------- $@ compile ended ---------------


#
# lint
#

lint:
	@echo -------------- $@ begins ----------------------
	$(LINT) $(LDFLAGS) $(CPPFLAGS) $(DEFINES) $(SOURCES.c) $(MYLIBS) $(LIBS)
	@echo -------------- $@ ended -----------------------


#
# purify
#

purify:
	@echo -------------- $@ begins ----------------------
	$(PURIFY) $(CC) -o $(TARGET) $(LDFLAGS) $(OBJECTS) $(MYLIBS) $(LIBS)
	@echo -------------- $@ ended -----------------------


#
# directories
#

$(BIN):
	$(TEST) -d $@ || mkdir $@


#
# clean
#

clean:
	rm -f $(OBJECTS)

clobber: clean
