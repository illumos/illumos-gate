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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#####################################################
#
# Makefile for a SNMP Agent
#
#####################################################

#
# Makefile.vars
#

#####################################################
# Edit the following variables as needed
#####################################################

BIN=		bin

SNMP_ROOT=	/usr

SNMP_LIB=	$(SNMP_ROOT)/lib

SNMP_INC=	$(SNMP_ROOT)/include/snmp

PURIFY_HOME=	/usr/soft/purify3.0


AGENT=		snmpdemo

MIBS=		mib_demo.txt


#####################################################

TARGET=		$(AGENT)d


.KEEP_STATE:

SOURCES.c=\
	$(AGENT)_tree.c\
	$(AGENT)_stub.c\
	$(AGENT)_trap.c\
	$(AGENT)_appl.c\
	$(AGENT)_demoEntry.c

SOURCES.h=\
	$(SNMP_INC)/impl.h\
	$(SNMP_INC)/asn1.h\
	$(SNMP_INC)/error.h\
	$(SNMP_INC)/pdu.h\
	$(SNMP_INC)/trap.h\
	$(SNMP_INC)/node.h\
	$(AGENT)_stub.h

OBJECTS= $(SOURCES.c:%.c=$(BIN)/%.o)


#
#  CC flags
#

DEFINES=

MY_INCLUDE=	-I. -I$(SNMP_INC)

CPPFLAGS +=	$(MY_INCLUDE)

CFLAGS=		-c


#
# LD flags
#

EXT = 1

MYLINKLIBS += $(LDLIBS) -L$(SNMP_LIB) -lssagent -L$(SNMP_LIB) -lssasnmp

LIBS=	$(MYLINKLIBS) -lsocket -lnsl -ly -ll -lelf -lgen

TEST=	test

PURIFY= $(PURIFY_HOME)/purify

PARSER=	$(SNMP_ROOT)/$(BIN)/mibcodegen


#####################################################

#
# all
#

all: $(SOURCES.h) $(TARGET)   

install: all

$(TARGET): $(BIN) $(OBJECTS) $(MYLIBS)
	$(CC) -o $(TARGET) $(LDFLAGS) $(OBJECTS) $(MYLIBS) $(LIBS)

$(BIN)/%.o: %.c  
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFINES) $*.c -o $@


#
# parse
#

parse:	$(MIBS)
	$(PARSER) -b $(AGENT) -f $(MIBS)


#
# lint
#

lint:
	$(LINT) $(LDFLAGS) $(CPPFLAGS) $(DEFINES) $(SOURCES.c) $(MYLIBS) $(LIBS)


#
# purify
#

purify:
	$(PURIFY) $(CC) -o $(TARGET) $(LDFLAGS) $(OBJECTS) $(MYLIBS) $(LIBS)


#
# directories
#

$(BIN):
	@$(TEST) -d $@ || mkdir $@


#
# clean
#

clean:
	$(RM) $(OBJECTS)

clobber: clean
	$(RM) $(TARGET)
