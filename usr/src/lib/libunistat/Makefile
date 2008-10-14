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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# lib/libunistat/Makefile

include		../Makefile.lib

UTSBASE= ../../uts

SUBDIRS=	$(MACH)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
delete :=	TARGET= delete
install :=	TARGET= install
lint :=		TARGET= lint
lintinter :=		TARGET= lintinter
_msg :=		TARGET= _msg
package :=	TARGET= package

LIBRARY= 	libunistat.a

HDRS=		spcs_dtrinkets.h \
		spcs_etrinkets.h \
		spcs_errors.h \
		spcs_etext.h
HDRDIR=		common

ROOTHDRDIR=	$(ROOT)/usr/include/sys/unistat
ROOTHDRS=	$(HDRS:%=$(ROOTHDRDIR)/%)

.KEEP_STATE:

all clean clobber delete lint package lintinter: $(SUBDIRS)

install: $(SUBDIRS)
install_h: $(ROOTHDRDIR) $(ROOTHDRS)

check:

# install rule for install_h target
$(ROOTHDRDIR):
	$(INS.dir)

$(ROOTHDRDIR)/spcs_errors.h: $(MACH)/spcs_errors.h
	$(INS.file) $(MACH)/spcs_errors.h

$(MACH)/spcs_errors.h:	FRC
	@ cd $(MACH); pwd; make spcs_errors.h

$(ROOTHDRDIR)/spcs_s_u.h: common/spcs_s_u.h
	$(INS.file) common/spcs_s_u.h

$(ROOTHDRDIR)/spcs_etext.h: $(MACH)/spcs_etext.h
	$(INS.file) $(MACH)/spcs_etext.h

$(MACH)/spcs_etext.h:	FRC
	@ cd $(MACH); pwd; make spcs_etext.h

$(ROOTHDRDIR)/spcs_dtrinkets.h: $(MACH)/spcs_dtrinkets.h
	$(INS.file) $(MACH)/spcs_dtrinkets.h

$(MACH)/spcs_dtrinkets.h:	FRC
	@ cd $(MACH); pwd; make spcs_dtrinkets.h

$(ROOTHDRDIR)/spcs_etrinkets.h: $(MACH)/spcs_etrinkets.h
	$(INS.file) $(MACH)/spcs_etrinkets.h

$(MACH)/spcs_etrinkets.h:	FRC
	@ cd $(MACH); pwd; make spcs_etrinkets.h

$(MACH) $(MACH64):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
