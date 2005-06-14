#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include		../../../Makefile.master

sparcv9_ARCHITECTURES = sparcv9
sparc_ARCHITECTURES = $(sparcv9_ARCHITECTURES)
i386_ARCHITECTURES = i386

SUBDIRS = $($(MACH)_ARCHITECTURES)

all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint

.KEEP_STATE:

all install lint clean: $(SUBDIRS)

clobber: $(SUBDIRS)
	$(RM) make.out lint.out

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

#
# Cross-reference customization: include all boot-related source files.
#
UTSDIR =	../../../uts
STANDLIBDIR =	../../../stand/lib
STANDSYSDIRS =	../../../stand/sys ../../../stand/i386/sys
PROMDIRS =	../../promif $(UTSDIR)/intel/promif
NAMESDIRS =	../lib/names
XRDIRS += 	$(STANDLIBDIR) $(STANDSYSDIRS) $(PROMDIRS) $(NAMESDIRS)
XRINCDIRS =	$(UTSDIR)/sun4u $(UTSDIR)/sfmmu $(UTSDIR)/sparc/v7 \
	    	$(UTSDIR)/sparc/v9 $(UTSDIR)/sparc $(UTSDIR)/sun \
		$(UTSDIR)/common $(UTSDIR)/intel $(UTSDIR)/i86pc

cscope.out tags: FRC
	$(XREF) -x $@

FRC:

# EXPORT DELETE START
EXPORT_SRC:
	$(RM) sparc/common/wanboot.c+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< sparc/common/wanboot.c > sparc/common/wanboot.c+
	$(MV) sparc/common/wanboot.c+ sparc/common/wanboot.c
	$(CHMOD) 444 sparc/common/wanboot.c
	$(RM) sparc/common/wbcli.c+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< sparc/common/wbcli.c > sparc/common/wbcli.c+
	$(MV) sparc/common/wbcli.c+ sparc/common/wbcli.c
	$(CHMOD) 444 sparc/common/wbcli.c
	$(RM) sparc/common/ramdisk.c+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< sparc/common/ramdisk.c > sparc/common/ramdisk.c+
	$(MV) sparc/common/ramdisk.c+ sparc/common/ramdisk.c
	$(CHMOD) 444 sparc/common/ramdisk.c
	$(RM) sparcv9/Makefile.com+
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< sparcv9/Makefile.com > sparcv9/Makefile.com+
	$(MV) sparcv9/Makefile.com+ sparcv9/Makefile.com
	$(CHMOD) 444 sparcv9/Makefile.com
	$(RM) Makefile+
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(RM) Makefile
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile
# EXPORT DELETE END
