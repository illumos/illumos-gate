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
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.

SYMPROG= hosts inetd.conf networks protocols services netmasks

# New /etc/inet files shouldn't have /etc entries.
EDITPROG= ipaddrsel.conf ipsecalgs
PROG= datemsk.ndpd ipsecinit.sample ipqosconf.1.sample ipqosconf.2.sample \
    ipqosconf.3.sample
ETCPROG= $(SYMPROG) $(EDITPROG) $(PROG)
SUBDIRS= default dhcp init.d ike nca ppp secret sock2path.d

include ../../Makefile.cmd

all:=		TARGET= all
install:=	TARGET= install

ROOTVAR=	$(ROOT)/var
INETETCDIR=	$(ROOTETC)/inet
INETVARDIR=	$(ROOTVAR)/inet
DIRS= 		$(INETETCDIR) $(INETVARDIR)
SYMDIR= 	inet
ETCINETPROG=	$(ETCPROG:%=$(INETETCDIR)/%)
EDITFILES=	$(SYMPROG:%=$(INETETCDIR)/%) $(EDITPROG:%=$(INETETCDIR)/%)
# Only old /etc/inet files get symlinks in /etc.
SYMETCPROG=	$(SYMPROG:%=sym_%)
SYMIPNODES=	$(INETETCDIR)/ipnodes

FILEMODE= 0444

.KEEP_STATE:

$(EDITFILES) := FILEMODE= 0644

all: $(ETCPROG) $(SUBDIRS)

install: all $(DIRS) $(ETCINETPROG) $(SYMETCPROG) $(SYMIPNODES) $(SUBDIRS)

$(SYMIPNODES) :
	$(RM) $@
	$(SYMLINK) ./hosts $@

$(INETETCDIR)/% : %
	$(INS.file)

sym_% : %
	$(RM) $(ROOTETC)/$<
	$(SYMLINK) $(SYMDIR)/$< $(ROOTETC)/$<

$(DIRS):
	$(INS.dir)

$(SUBDIRS): FRC $(DIRS)
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# datemsk.ndpd is generated from datemsk.template because of a side-effect of
# SCCS.  Some of the datemsk.ndpd format strings include "%<letter>%", which
# SCCS confuses for ID keywords.  datemsk.template should quote the "%"
# with "\" and code below will filter out the "\".  Only datemsk.ndpd format
# strings next to each other need to be quoted.

datemsk.ndpd: datemsk.template
	@while read i; do echo $$i; done < datemsk.template > $@

clean clobber:
	$(RM) datemsk.ndpd

lint:
