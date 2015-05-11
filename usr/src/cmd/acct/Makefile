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
# Copyright 2015 Gary Mills
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=		acctcms acctcom acctcon acctcon1 acctcon2 \
		acctdisk acctdusg acctmerg accton acctprc acctprc1 \
		acctprc2 acctwtmp closewtmp fwtmp \
		wtmpfix utmp2wtmp
SHFILE1=	acct chargefee ckpacct dodisk lastlogin\
		monacct nulladm prctmp prdaily prtacct \
		remove runacct shutacct startup turnacct
SHFILE2=	ptecms.awk ptelus.awk
SUBDIRS=	lib
ALL=		$(PROG) $(SHFILE1) $(SHFILE2) holidays

SRCS=		$(PROG:%=%.c)
SHFILE1SRCS=	$(SHFILE1:%=%.sh)

BINPROG=	acctcom
LIBPROG=	acctcms acctcon acctcon1 acctcon2 acctdisk \
		acctdusg acctmerg accton acctprc acctprc1 acctprc2 \
		acctwtmp closewtmp fwtmp utmp2wtmp \
		wtmpfix chargefee ckpacct dodisk monacct \
		lastlogin nulladm prctmp prdaily prtacct \
		remove runacct shutacct startup turnacct \
		ptecms.awk ptelus.awk
ETCPROG=	holidays
INITPROG=	acct

include		../Makefile.cmd

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint

acctcom := LDLIBS += lib/a.a
acctcms acctcon acctcon1 acctmerg acctprc1 acctprc := LDLIBS += lib/a.a

acctdusg:= CPPFLAGS += -D_FILE_OFFSET_BITS=64
acctdusg:= LDLIBS += -lcmdutils

LIBACCTD=	$(ROOTLIB)/acct
ETCACCTD=	$(ROOTETC)/acct
ETCINITD=	$(ROOTETC)/init.d
VARADMD=	$(ROOT)/var/adm
ACCTDIR=	$(VARADMD)/acct
ACCTSUBDIRS=	$(ACCTDIR)/nite $(ACCTDIR)/fiscal $(ACCTDIR)/sum
WKDIRS=		$(ACCTDIR) $(ACCTSUBDIRS)

# DIRS is directories to create. $(ETCINITD) [aka: /etc/init.d] is created
# in /usr/src/Targetdirs and hence should be assumed to exist.
DIRS=		$(LIBACCTD) $(ETCACCTD) $(WKDIRS)

USRBINPROG=	$(BINPROG:%=$(ROOTBIN)/%)
LIBACCTPROG=	$(LIBPROG:%=$(LIBACCTD)/%)
ETCACCTPROG=	$(ETCPROG:%=$(ETCACCTD)/%)
ETCINITPROG=	$(INITPROG:%=$(ETCINITD)/%)

$(LIBACCTD) :=		DIRMODE=	755
$(ETCACCTD) :=		DIRMODE=	755
$(WKDIRS) :=		DIRMODE=	775
$(LIBACCTD)/accton :=	FILEMODE=	04755
$(ETCINITPROG) :=	FILEMODE=	0744
$(ETCACCTPROG) :=	FILEMODE=	0644

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-address

.KEEP_STATE:

.PARALLEL: $(ALL)

all: $(SUBDIRS) .WAIT $(ALL)

install: all .WAIT $(DIRS) .WAIT $(USRBINPROG) $(LIBACCTPROG) $(ETCACCTPROG) \
	$(ETCINITPROG)

THIS_YEAR:sh=	date +%Y

holidays:	FRC
	@if grep $(THIS_YEAR) holidays > /dev/null 2>&1;\
	then \
		:;\
	else \
		$(ECHO) "building holidays";\
		( \
		$(ECHO) "* @(#)holidays\tJanuary 1, `date +%Y`";\
		$(ECHO) "*";\
		$(ECHO) "* Prime/Nonprime Table for UNIX Accounting System";\
		$(ECHO) "*";\
		$(ECHO) "* Curr\tPrime\tNon-Prime";\
		$(ECHO) "* Year\tStart\tStart";\
		$(ECHO) "*";\
		$(ECHO) "  `date +%Y`\t0800\t1800";\
		$(ECHO) "*";\
		$(ECHO) "* only the first column (month/day) is significiant.";\
		$(ECHO) "*";\
		$(ECHO) "* month/day\tCompany";\
		$(ECHO) "* \t\tHoliday";\
		$(ECHO) "*";\
		$(ECHO) "1/1\t\tNew Years Day";\
		$(ECHO) "7/4\t\tIndep. Day";\
		$(ECHO) "12/25\t\tChristmas" ) > holidays;\
	fi

$(DIRS):
	$(INS.dir)

$(LIBACCTD)/% : %
	$(INS.file)

$(ETCACCTD)/% : %
	$(INS.file)

$(ETCINITD)/% : %
	$(INS.file)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(MFLAGS) $(TARGET)

FRC:

clean: $(SUBDIRS)

clobber: $(SUBDIRS)
	$(RM) $(PROG) $(SHFILE1) holidays

lint:	$(SUBDIRS)
	$(LINT.c) $(SRCS)
