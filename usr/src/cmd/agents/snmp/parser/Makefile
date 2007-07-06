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

##############################################
#
# Makefile for parser
#
##############################################

#
# Makefile.vars
#

include ../../Makefile.vars

include $(SRC)/cmd/Makefile.cmd

TARGET=	mibcodegen

# 
OPTBIN = $(ROOT)/usr/bin
OPTPROG = $(PROG:%=$(OPTBIN)/%)

#
# other variables
#

.KEEP_STATE:

SOURCES.c=\
	parse.c\
	backend.c

SOURCES.h=\
	../snmplib/impl.h\
	../snmplib/error.h\
	../snmplib/asn1.h\
	parse.h

OBJECTS= $(SOURCES.c:%.c=$(BIN)/%.o)

EXT = 1
MYLIBS= ../snmplib/$(MACH)/libssasnmp.so.$(EXT)
MYLINKLIBS += -L../snmplib -lssasnmp

LIBS= -lsocket -lnsl

DEFINES= -D$(TARG_SYS)

CPPFLAGS += -I. -I../snmplib -I../../include/netmgt

CFLAGS += -c 

LDFLAGS += $(LDLIBS)

LINT= lint

MIB_HOME=	../mib

MIBS=		$(MIB_HOME)/mib_core.txt $(MIB_HOME)/mib_example.txt

LINTFLAGS= -aumx

LINT=   lint

CLOBBERFILES += $(TARGET)

##############################################

#
# all
#

all: $(SOURCES.h) $(TARGET)

install: all

$(TARGET): $(BIN) $(OBJECTS) $(MYLIBS)
	$(CC) -o $(TARGET) $(LDFLAGS) $(OBJECTS) $(MYLINKLIBS) $(LIBS)

$(BIN)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFINES) $*.c -o $@

#
# lint
#

lint:
	$(LINT) $(CPPFLAGS) $(DEFINES) $(SOURCES.c)

lintlib: $(BIN) $(LINTTARGET)

$(LINTTARGET) : $(LINTOBJECTS)
	$(LINT) $(LINTOBJECTS) -o $(LIBNAME)
	mv llib-l$(LIBNAME).ln $(LINTTARGET)

$(BIN)/%.ln: %.c
	$(LINT) $(CPPFLAGS) $(DEFINES) $*.c -C $(BIN)/$*

#
# example
#

example:
	$(TARGET) example $(MIBS);


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

include $(SRC)/cmd/Makefile.targ
