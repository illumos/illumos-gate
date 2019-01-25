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
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

include		../../../Makefile.master

ROOTDEMODIRBASE=	$(ROOT)/usr/demo/link_audit

DEMOFILES= \
		00README \
		Makefile \
		man/perfcnt.man \
		man/symbindrep.man \
		man/dumpbind.man \
		src/bindings.c \
		src/bindings.h \
		src/dumpbind.c \
		src/env.c \
		src/env.h \
		src/hash.c \
		src/hash.h \
		src/sotruss.ksh \
		src/mach.h \
		src/perfcnt.c \
		src/perfcnt.ksh \
		src/symbindrep.c \
		src/symbindrep.ksh \
		src/truss.c \
		src/who.c \
		src/who.h \
		src/whocalls.ksh

ROOTDEMODIRS=	$(ROOTDEMODIRBASE) .WAIT \
		$(ROOTDEMODIRBASE)/man \
		$(ROOTDEMODIRBASE)/src

ROOTDEMOFILES=	$(DEMOFILES:%=$(ROOTDEMODIRBASE)/%)

$(ROOTDEMODIRS) :=	DIRMODE =	755



SUBDIRS=	$(MACH)

all:=		TARGET=	all
install:=	TARGET=	install
package:=	TARGET=	package
clean:=		TARGET=	clean
clobber:=	TARGET=	clobber

.PARALLEL: $(ROOTDEMOFILES)

.KEEP_STATE:

all clean clobber: \
	$(SUBDIRS)

package install : \
	$(ROOTDEMODIRS) .WAIT $(SUBDIRS) $(ROOTDEMOFILES)

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)
		@if [ -d $(MACH64) ]; then                      \
			cd $(MACH64); pwd; $(MAKE) $(TARGET);   \
		else /bin/true; fi

$(ROOTDEMODIRS):
	$(INS.dir)

$(ROOTDEMODIRBASE)/man/%: man/%
	$(INS.file)

$(ROOTDEMODIRBASE)/src/%: common/%
	$(INS.file)

$(ROOTDEMODIRBASE)/%: common/%
	$(INS.file)

$(ROOTDEMODIRBASE)/%: common/%.demo
	$(INS.rename)

FRC:
