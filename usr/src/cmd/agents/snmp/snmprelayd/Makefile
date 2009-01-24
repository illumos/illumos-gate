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

include ../../Makefile.vars

MANIFEST = snmpdx.xml
SVCMETHOD = svc-snmpdx

include $(SRC)/cmd/Makefile.cmd

#
# In order to conform with the Solaris 2.6 way of packaging things,
# we now need to put any deliverable that is specified in the
# prototype file into a common "proto" area, so that their
# packaging scheme knows where to obtain the input binaries.
#

AGENT = snmpdx
BINPROG = $(AGENT)
PROG=$(BINPROG)

OPTBIN = $(ROOT)/usr/lib/snmp
OPTPROG = $(PROG:%=$(OPTBIN)/%)

$(OPTPROG):=	FILEMODE = 0755

$(OPTBIN)/%: $(OPTBIN) %
	$(INS.file)

MYCONF = $(CONFIG_FILES)
CONFLOC = $(ROOT)/etc/snmp/conf
CONFRULE = $(MYCONF:%=$(CONFLOC)/%)

$(CONFLOC)/%: $(CONFLOC) %
	$(INS.file)

$(OPTBIN) $(CONFLOC):
	$(INS.dir)

STUB.c = mib_handler.c $(AGENT)_tree.c $(AGENT)_appl.c $(AGENT)_trap.c
STUB.h = $(AGENT)_stub.h

SOURCES.c=\
	agent.c\
	subtree.c\
	session.c\
	dispatcher.c\
	res.c\
	sh_table.c\
	$(STUB.c)

SOURCES.h=\
	../snmplib/impl.h\
	../snmplib/error.h\
	../snmplib/trace.h\
	../snmplib/asn1.h\
	../snmplib/signals.h\
	../snmplib/snmp.h\
	../snmplib/pdu.h\
	../snmplib/request.h\
	snmprelay_msg.h\
	agent.h\
	subtree.h\
	session.h\
	config.h\
	dispatcher.h\
	res.h\
	$(STUB.h)\
	../snmplib/trap.h\
	../agent/access.h\
	../agent/agent_msg.h\
	sh_table.h\
	name.h

#
# We need the config files to build the sacom directory,
# so pull them out of SCCS.
#

CONFIG_FILES =\
	mibiisa.rsrc-\
	snmpdx.acl\
	snmpdx.reg\
	snmpdx.rsrc\
	enterprises.oid

OBJECTS= $(SOURCES.c:%.c=$(BIN)/%.o)

EXT = 1
MYLIBS=	../agent/$(MACH)/libssagent.so.$(EXT) ../snmplib/$(MACH)/libssasnmp.so.$(EXT)
MYLINKLIBS += -L../agent/$(MACH) -lssagent -L../snmplib -lssasnmp

LIBS=	-lsocket -lnsl -ll

# snmpdx has a name clash with main() and libl.so.1.  However, snmpdx must
# still export a number of "yy*" (libl) interfaces, and interfaces for
# libssagent.so.1.  Reduce all other symbols to local scope.
MAPFILES +=	$(MAPFILE.INT) $(MAPFILE.LEX) $(MAPFILE.NGB)
MAPOPTS =	$(MAPFILES:%=-M%)

CPPFLAGS +=	-I. -I../agent -I../snmplib -I../../include/netmgt -I${BIN}
CFLAGS +=	-c -D$(TARG_SYS)
LDFLAGS +=	$(MAPOPTS) $(LDLIBS)

LINT=lint

SNMP_ROOT= ..
PARSER_HOME= $(SNMP_ROOT)/parser
MIB_HOME= $(SNMP_ROOT)/mib
PURIFY_HOME= /usr/soft/purify3.0


MIBS= $(MIB_HOME)/mib_core.txt $(MIB_HOME)/snmpdx.mib
PARSER= $(PARSER_HOME)/$(BIN)/mibcodegen

.KEEP_STATE:

#######################################################

#
# all
#

ROOTMANIFESTDIR = $(ROOTSVCAPPLICATIONMANAGEMENT)

$(CONFRULE) := FILEMODE = 0644
$(CONFLOC)/snmpdx.acl := FILEMODE = 0600
$(CONFRULE) := GROUP = sys

CLOBBERFILES += y.tab.c $(BINPROG)

all: $(SOURCES.h) $(BINPROG) $(CONFIG_FILES)

install: all $(OPTPROG) $(CONFRULE) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

$(BINPROG): $(BIN) $(OBJECTS) $(BIN)/config.o $(MYLIBS) $(MAPFILES)
	$(CC) -o $(BINPROG) $(LDFLAGS) $(OBJECTS) $(BIN)/config.o \
	    $(MYLINKLIBS) $(LIBS)
	$(POST_PROCESS)

$(BIN)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFINES) $*.c -o $@

${BIN}/config.c: config.y
	$(YACC.y) config.y
	$(CAT) name.h y.tab.c > ${BIN}/config.c

${BIN}/config.lex.c: config.l
	$(LEX.l) config.l > ${BIN}/config.lex.c

$(BIN)/config.o: ${BIN}/config.c ${BIN}/config.lex.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFINES) ${BIN}/config.c -o $(BIN)/config.o


#
# parse
#
parse:	$(MIBS)
	$(PARSER) -b $(AGENT) -f $(MIBS)

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
gen:	
	$(RM) $(AGENT)_stub.h
	$(RM) $(AGENT)_stub.c
	$(RM) $(AGENT)_appl.c
	$(RM) $(AGENT)_tree.c
	$(RM) $(AGENT)_trap.c

clean:
	$(RM) $(OBJECTS)
	$(RM) $(BIN)/config.lex.c $(BIN)/config.c $(BIN)/config.o

include $(SRC)/cmd/Makefile.targ
