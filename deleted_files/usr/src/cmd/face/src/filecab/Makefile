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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1990,1998 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/face/src/filecab/Makefile

# include global definitions
include ../../../../Makefile.master

SUBDIRS = fileb

SFILES=		.faceprofile
WFILES=		WASTEBASKET/.pref
PFILES=		pref/.environ pref/.variables pref/.colorpref
STDFILES=	$(SFILES) $(WFILES) $(PFILES)
EXTERNFILES=	allobjs detect.tab
VMFILES=	pathalias
TERRLOG=	TERRLOG

APPLFILES=	$(STDFILES:%=standard/%) \
		$(EXTERNFILES:%=oasys/info/OH/externals/%) \
		$(VMFILES) $(TERRLOG)

# include common face definitions and install rules
include ../Makefile.com

ROOTDIRS=	$(ROOTSTD)/WASTEBASKET $(ROOTSTD)/pref \
		$(ROOTOASYS)/tmp

ROOTTERRLOG=	$(ROOTOASYS)/tmp/$(TERRLOG)
ROOTSTDF=	$(STDFILES:%=$(ROOTSTD)/%)
ROOTEXTERNF=	$(EXTERNFILES:%=$(ROOTEXTERN)/%)
ROOTVMSYSF=	$(VMFILES:%=$(ROOTVMSYS)/%)

DIRMODE=	755
FILEMODE=	644

# conditional assignments
#
all :=          TARGET = all
install :=      TARGET = install
clean :=        TARGET = clean
clobber :=      TARGET = clobber
lint :=         TARGET = lint

$(ROOTTERRLOG) :=	FILEMODE=	622
$(ROOTTERRLOG) :=	OWNER=		bin
# The following is necessary because make gets confused.
$(ROOTDIRS) :=		OWNER=		root

# installation rule
$(ROOTOASYS)/tmp/% : %
	$(INS.file)

.KEEP_STATE:

all: 	$(APPLFILES) $(SUBDIRS)

$(TERRLOG):
	$(RM) $@; touch $@

install: all .WAIT $(ROOTDIRS) .WAIT \
	$(ROOTTERRLOG) $(ROOTSTDF) $(ROOTEXTERNF) $(ROOTVMSYSF) $(SUBDIRS)

$(ROOTTERRLOG): $(ROOTDIRS) $(TERRLOG)

$(ROOTDIRS): $(ROOTSTD) $(ROOTOASYS) $(ROOTEXTERN) $(ROOTVMSYS)
	$(INS.dir)

clean clobber : $(SUBDIRS)
	$(RM) $(TERRLOG)

lint: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
