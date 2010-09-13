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
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../../Makefile.vars

include $(SRC)/cmd/Makefile.cmd

#
# In order to conform with the Solaris 2.6 way of packaging things,
# we now need to put any deliverable that is specified in the
# prototype file into a common "proto" area, so that their
# packaging scheme knows where to obtain the input binaries.
#

AGENT =	snmp_trapsend
BINPROG = $(AGENT)
OPTBIN = $(ROOT)/usr/sbin
OPTPROG = $(PROG:%=$(OPTBIN)/%)

$(OPTBIN)/%: $(OPTBIN) %
	$(INS.file)

$(OPTBIN):
	$(INS.dir)

SOURCES.c=\
	trapsend.c \
	oid.c \
	usage.c

SOURCES.h=\
	../snmplib/impl.h\
	../snmplib/error.h\
	../snmplib/trace.h\
	../snmplib/asn1.h\
	../snmplib/snmp.h\
	../snmplib/pdu.h \
	./oid.h \
	./usage.h

OBJECTS= $(SOURCES.c:%.c=$(BIN)/%.o)

MYLINKLIBS += $(LDLIBS) -L../snmplib -lssasnmp

LIBS=	-lnsl

CPPFLAGS += -I. -I../snmplib -I../../include/netmgt -I${BIN}

CFLAGS += -c

LINT=lint

.KEEP_STATE:

#######################################################

#
# all
#

FILEMODE = 0755

PROG=$(BINPROG)

CLOBBERFILES=$(AGENT)

all: $(SOURCES.h) $(BINPROG)

install: all $(OPTPROG)


$(BINPROG): $(BIN) $(OBJECTS)
	$(CC) -o $(BINPROG) $(LDFLAGS) $(OBJECTS) $(MYLINKLIBS) $(LIBS)
	$(POST_PROCESS)

$(BIN)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFINES) $*.c -o $@
	$(POST_PROCESS_O)


#
# lint
#

lint:
	$(LINT) $(LDFLAGS) $(CPPFLAGS) $(DEFINES) $(SOURCES.c) $(MYLINKLIBS) $(LIBS)


#
# purify
#

purify:
	$(PURIFY) $(CC) -o $(BINPROG) $(LDFLAGS) $(OBJECTS) $(MYLINKLIBS) $(LIBS)


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
