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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= _sactab _pmtab _sysconfig iu.ap ttydefs

SRCS= $(PROG:%=%.sh)

include ../Makefile.cmd

SUBDIRS= etc

DEFPM=   zsmon

ETCSAFD= $(ROOTETC)/saf
ETCPMD=  $(ETCSAFD)/$(DEFPM)
VARPMD=  $(ROOT)/var/saf/$(DEFPM)

# Don't re-install /etc/saf which is installed by Targetdirs
#DIRS= $(ETCSAFD) $(ETCPMD) $(VARPMD)
DIRS= $(ETCPMD) $(VARPMD)

ETCSAF= _sactab _sysconfig
ETCF=   ttydefs iu.ap
ETCPM=  _pmtab
PMLOG=  log

ROOTETCSAF= $(ETCSAF:%=$(ETCSAFD)/%)
ROOTETCF= $(ETCF:%=$(ROOTETC)/%)
ROOTETCPM = $(ETCPM:%=$(ETCPMD)/%) 
ROOTVARPM = $(PMLOG:%=$(VARPMD)/%) 

FILEMODE= 0644

CLOBBERFILES += $(PMLOG)

$(ETCSAFD)/% : %
	$(INS.file)

$(VARPMD)/% : %
	$(INS.file)

$(ETCPMD)/% : %
	$(INS.file)

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clean
lint :=		TARGET= lint

.KEEP_STATE:

all: $(PROG) $(PMLOG) $(SUBDIRS)

_sysconfig: _sysconf.sh
	$(SH) _sysconf.sh

_sactab _pmtab iu.ap ttydefs:
	$(SH) $@.sh

$(PMLOG):
	$(TOUCH) $@

install: all $(DIRS) $(SUBDIRS) $(ROOTETCSAF) $(ROOTETCF) $(ROOTETCPM) $(ROOTVARPM)

$(DIRS):
	$(INS.dir)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

clean: $(SUBDIRS)

lint: $(SUBDIRS)

FRC:

include ../Makefile.targ
