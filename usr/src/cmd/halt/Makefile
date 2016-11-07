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
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG = halt

include ../Makefile.cmd

#
# Currently Fast Reboot is only supported on x86.
# A new propery config/uadmin_boot_archive_sync is added to
# boot-config service. Which needs a support on sparc also.
#
sparc_SUBDIRS = smf.sparc
i386_SUBDIRS = smf.i386
SUBDIRS = $($(MACH)_SUBDIRS)

ROOTLINKS = $(ROOTUSRSBIN)/poweroff $(ROOTUSRSBIN)/reboot
ROOTSYMLINKS= $(ROOTETC)/halt $(ROOTETC)/reboot

FILEMODE = 0755

.KEEP_STATE:

CPPFLAGS += -I../../lib/libzpool/common
CPPFLAGS += -I../../lib/libscf/inc
CPPFLAGS += -I../../uts/common/fs/zfs

CERRWARN += -_gcc=-Wno-unused-label

LDLIBS += -lbsm -lscf -lzfs -lgen
LDLIBS_i386 +=	-lbe
LDLIBS +=	$(LDLIBS_$(MACH))

CLOBBERFILES += $(ROOTLINKS) $(ROOTSYMLINKS)

all     :=	TARGET = all
install :=	TARGET = install
clean   :=	TARGET = clean
clobber :=	TARGET = clobber
lint    :=	TARGET = lint
lint	:=	LINTFLAGS = -u


all: $(PROG) 

install: all $(ROOTUSRSBINPROG) $(ROOTLINKS) $(ROOTSYMLINKS) $(SUBDIRS)

$(ROOTLINKS): $(ROOTUSRSBINPROG)
	$(RM) $@
	$(LN) $(ROOTUSRSBINPROG) $@

$(ROOTSYMLINKS):
	$(RM) $@
	$(SYMLINK) ../usr/sbin/$(PROG) $@

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

clean:

clobber: $(SUBDIRS)

lint:	lint_PROG

check: $(CHKMANIFEST)

FRC:

include ../Makefile.targ
