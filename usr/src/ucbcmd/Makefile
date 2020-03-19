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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# ucbcmd/Makefile

# include global definitions; SRC should be defined in the shell.
# SRC is needed until RFE 1026993 is implemented.
include $(SRC)/Makefile.master
include $(SRC)/ucbcmd/Makefile.ucbcmd

COMMON_SUBDIRS=		\
	basename	\
	biff		\
	chown		\
	df		\
	du		\
	echo		\
	expr		\
	fastboot	\
	fasthalt	\
	file		\
	from		\
	groups		\
	install.d	\
	ln		\
	ls		\
	mkstr		\
	printenv	\
	rusage		\
	sed		\
	shutdown	\
	stty		\
	sum		\
	test		\
	touch		\
	tr		\
	tset		\
	users		\
	vipw		\
	whereis		\
	whoami

SUBDIRS= $(COMMON_SUBDIRS)

# commands messaged
MSGSUBDIRS = biff install.d mkstr rusage shutdown

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
_msg:=          TARGET= _msg

# Since pre-5.0 system users were told to put /usr/5bin in their path to
# get the 5.0 system behavior, we need this link so that the PATH of
# /usr/5bin:/usr/ucb:/usr/bin does the right thing. (let's see, without
# this link, 5.0 behaves like UCB and 4.1 behaves like SysV... I'm so
# confused...)
ROOTUSR = $(ROOT)/usr
S5LINK = $(ROOTUSR)/5bin
DICTLINK = $(ROOTUSR)/dict

# Symbolic links for source compatibility.  Many utilities that
# were under /usr/ucb in SunOS 4.1, are now in the base;  the
# symbolic links are provided for compatibility.
LINKDEST=	../bin/$(@F)

BINLINKS=		\
	arch		\
	clear		\
	e		\
	edit		\
	ex		\
	vedit		\
	vi		\
	view		\
	finger		\
	fmt		\
	fold		\
	ftp		\
	head		\
	hostid		\
	hostname	\
	logger		\
	mach		\
	more		\
	page		\
	pagesize	\
	netstat		\
	quota		\
	rcp		\
	rdate		\
	renice		\
	rlogin		\
	rsh		\
	ruptime		\
	rwho		\
	script		\
	tail		\
	talk		\
	tcopy		\
	telnet		\
	tftp		\
	uptime		\
	vacation	\
	vmstat		\
	w		\
	wc		\
	whois		\
	xstr

ROOTBINLINKS = $(BINLINKS:%=$(ROOTBIN)/%)

OTHERLINKS = $(ROOTETC)/termcap \
		$(ROOTSHLIB)/zoneinfo/posixrules

$(S5LINK) :=		LINKDEST= bin
$(DICTLINK) :=		LINKDEST= share/lib/dict
$(ROOTBIN)/e :=		LINKDEST= ../bin/edit
$(ROOTBIN)/ex :=	LINKDEST= ../bin/edit
$(ROOTBIN)/page :=	LINKDEST= ../bin/more
$(ROOTBIN)/quota :=	LINKDEST= ../lib/fs/ufs/quota
$(ROOTETC)/termcap :=	LINKDEST= ../usr/share/lib/termcap
$(ROOTBIN)/vi :=	LINKDEST= ../bin/edit
$(ROOTBIN)/view :=	LINKDEST= ../bin/edit
$(ROOTSHLIB)/zoneinfo/posixrules := LINKDEST= US/Eastern

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all clean clobber: $(SUBDIRS)

install: $(SUBDIRS) .WAIT rootlinks

# For messaging catalog
#
_msg:   $(MSGSUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

rootlinks: $(S5LINK) $(DICTLINK) $(ROOTBINLINKS) $(OTHERLINKS)

$(S5LINK) $(DICTLINK) $(ROOTBINLINKS) $(OTHERLINKS):
	$(RM) $@; $(SYMLINK) $(LINKDEST) $@

FRC:
