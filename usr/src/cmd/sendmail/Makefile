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
# Copyright 2019 Garrett D'Amore <garrett@damore.org>
#
# cmd/sendmail/Makefile
#
# Makefile for top level sendmail source directory
#

# static libraries (db, libsm, libsmdb, libsmutil) must be built before
# src and util
SUBDIRS=	cf lib db libsm libsmdb libsmutil .WAIT src util

include 	../Makefile.cmd

ROOTDIRS=	$(ROOT)/var/spool/mqueue $(ROOT)/var/spool/clientmqueue
$(ROOTDIRS):=	DIRMODE = 0750
$(ROOT)/var/spool/clientmqueue:=	DIRMODE = 0770

all:=           TARGET= all
install:=       TARGET= install
clean:=         TARGET= clean
clobber:=       TARGET= clobber
lint:=          TARGET= lint

.KEEP_STATE:

all clean clobber lint:	$(SUBDIRS)

install: 	$(ROOTDIRS) $(SUBDIRS) $(ROOTMANIFEST) $(ROOTSVCSH)

all install:	THIRDPARTYLICENSE

clobber:	FRC
	$(RM) THIRDPARTYLICENSE

.PARALLEL:	$(SUBDIRS)

$(ROOTDIRS):
	$(INS.dir)

$(SUBDIRS): 	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

THIRDPARTYLICENSE: LICENSE db/LICENSE
	$(SED) -n '/SENDMAIL LICENSE/,$$p' LICENSE > $@
	$(ECHO) " " >> $@
	$(SED) -n '/The following are the copyrights/,$$p' db/LICENSE >> $@

FRC:
