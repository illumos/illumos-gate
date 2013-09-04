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

CRON_ENT= adm root sys
CRON_LIB= .proto at.deny cron.deny queuedefs
ETC_SCRIPT= group project ttysrch mailcap mime.types
ZI_SPECIAL= zones-index
SUBDIRS= sun

include ../Makefile.cmd

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint

CROND= $(ROOT)/var/spool/cron
CRONTABD= $(ROOT)/var/spool/cron/crontabs
CRONLIBD= $(ROOT)/etc/cron.d
ETCZONESD= $(ROOT)/etc/zones
DIRS= $(CROND) $(CRONTABD) $(CRONLIBD)

CRONTABS=	$(CRON_ENT:%=$(CRONTABD)/%)
CRONLIBS=	$(CRON_LIB:%=$(CRONLIBD)/%)
ETCSCRIPTS=	$(ETC_SCRIPT:%=$(ROOTETC)/%)
ZISPECIALS=	$(ETCZONESD)/index

FILEMODE= 0644

$(CRONLIBD)/.proto :=	FILEMODE =	0744
$(CRONTABD)/adm :=	FILEMODE =	0600
$(CRONTABD)/sys :=	FILEMODE =	0600
$(CRONTABD)/root :=	FILEMODE =	0600

.KEEP_STATE:

all: $(CRON_ENT) $(CRON_LIB) $(ETC_SCRIPT) $(SUBDIRS)

install: all $(DIRS) $(CRONTABS) $(CRONLIBS) $(ETCSCRIPTS) $(ETCZONESD) \
	$(SUBDIRS) 

$(CRONTABD)/% : %
	$(INS.file)

$(CRONLIBD)/% : %
	$(INS.file)

$(ETCZONESD): $(ZI_SPECIAL)
	$(CP) -f $(ZI_SPECIAL) $(ZISPECIALS)
	$(CHMOD) $(FILEMODE) $(ZISPECIALS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(MFLAGS) $(TARGET)

$(DIRS):
	$(INS.dir)

FRC:

clean clobber: $(SUBDIRS)

lint:
