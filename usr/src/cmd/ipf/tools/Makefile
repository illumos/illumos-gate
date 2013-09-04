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
# cmd/ipf/tools/Makefile
#
#

LICENCE= IPFILTER.LICENCE

include ../../Makefile.cmd

$(64ONLY)SUBDIRS= $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

USRLIBIPF=		$(ROOTLIB)/ipf
USRLIBIPFLICENCE=	$(LICENCE:%=$(USRLIBIPF)/%) 

FILEMODE= 0755

$(USRLIBIPFLICENCE):=FILEMODE= 0644

all:=           TARGET= all
install:=       TARGET= install
clean:=         TARGET= clean
clobber:=       TARGET= clobber
lint:=          TARGET= lint

$(USRLIBIPF):
	$(INS.dir)

$(USRLIBIPF)/% : %
	$(INS.file)

.KEEP_STATE:

all clean clobber lint: $(SUBDIRS)

install: all $(SUBDIRS) install_local

install_local: $(USRLIBIPF) $(USRLIBIPFLICENCE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(MFLAGS) $(TARGET)

FRC:
