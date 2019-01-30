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
# Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

LIBBASENAME=	libc
LIBRARY=	$(LIBBASENAME:%=%.a)
VERS=		.1

# Note that we build libc_pic.a for the benefit of building
# ld.so.1, but we do not install it.  Only ld.so.1 needs it
# and it must be built in the same workspace as libc.
LIB_PIC= libc_pic.a

ROOTLIB=	$(ROOT)/usr/lib
ROOTFS_LIB=	$(ROOT)/lib
ROOTLIB64=	$(ROOTLIB)/$(MACH64)
ROOTFS_LIB64=	$(ROOTFS_LIB)/$(MACH64)

ROOTVARIANTDIR=	$(ROOTLIB)/libc
ROOTVARIANTDIR64=	$(ROOTLIB64)/libc

# include common library definitions
include ../Makefile.lib

#
# on some architectures, we build multiple libc variants
#
VAR1 =		hwcap1
VAR2 =		hwcap2
VAR3 =		hwcap3

VARBLD_1=	$(MACH:sparc=sparc)
VARBLD=		$(VARBLD_1:i386=)

VARBLD64_1=	$(MACH:sparc=sparcv9)
VARBLD64=	$(VARBLD64_1:i386=)

VAR1_DYNLIB =	$(LIBRARY:%.a=%_$(VAR1).so$(VERS))
VAR1_BLDDIR =	$(MACH)_$(VAR1)/$(VARBLD)
VAR2_DYNLIB =	$(LIBRARY:%.a=%_$(VAR2).so$(VERS))
VAR2_BLDDIR =	$(MACH)_$(VAR2)/$(VARBLD)
VAR3_DYNLIB =	$(LIBRARY:%.a=%_$(VAR3).so$(VERS))
VAR3_BLDDIR =	$(MACH)_$(VAR3)/$(VARBLD)

VAR1_DYNLIB64 =	$(LIBRARY:%.a=%_$(VAR1).so$(VERS))
VAR1_BLDDIR64 =	$(MACH)_$(VAR1)/$(VARBLD64)

i386_VARIANTS=	$(VAR1) $(VAR2) $(VAR3)
sparc_VARIANTS=
sparcv9_VARIANTS=

i386_COMP=
sparc_COMP=	capabilities

MACH_COMP=	$($(MACH)_COMP)

i386_ETC=	$(MACH)/etc
sparc_ETC=

VARIANTS=	$($(MACH)_VARIANTS)
VARIANT_SUBDIRS	= $(VARIANTS:%=$(MACH)_%/$(VARBLD))

VARIANTS64=	$($(MACH64)_VARIANTS)
VARIANT_SUBDIRS64	= $(VARIANTS64:%=$(MACH)_%/$(VARBLD64))

SUBDIRS=	$(MACH_CAP) $(MACH) $(MACH_ETC) $(VARIANT_SUBDIRS)
$(BUILD64)SUBDIRS += $(MACH64) $(VARIANT_SUBDIRS64)

LIBS =		$(DYNLIB)

ROOTLIBS64=	$(ROOTLIBDIR64)/$(DYNLIB)
MACHLIBS64=	$(MACH64)/$(DYNLIB)
VARIANTLIBS=	$(VARIANTS:%=$(MACH)_%/$(VARBLD)/$(LIBBASENAME)_%.so.1)
VARIANTLIBS64=	$(VARIANTS64:%=$(MACH)_%/$(VARBLD64)/$(LIBBASENAME)_%.so.1)
ROOTVARIANTLIBS= $(VARIANTS:%=$(ROOTVARIANTDIR)/$(LIBBASENAME)_%.so.1)
ROOTVARIANTLIBS64= $(VARIANTS64:%=$(ROOTVARIANTDIR64)/$(LIBBASENAME)_%.so.1)

# definitions for install_h target
BASEHDRS=	getxby_door.h
CHECKHDRS=	$(BASEHDRS:%.h=port/gen/%.check)
HDRS=		$(BASEHDRS)

CLOBBERFILES += THIRDPARTYLICENSE extract-copyright

# install rules for install_h target
$(ROOTHDRDIR)/%: port/gen/%
	$(INS.file)

$(ROOTLIBDIR)/$(DYNLIB)	:=	FILEMODE = 755
$(ROOTLIBDIR64)/$(DYNLIB) :=	FILEMODE = 755
$(ROOTFS_LIBDIR)/$(DYNLIB)	:=	FILEMODE = 755
$(ROOTFS_LIBDIR64)/$(DYNLIB)	:=	FILEMODE = 755

$(ROOTVARIANTDIR)			:= FILEMODE= 755
$(ROOTVARIANTDIR)/$(VAR1_DYNLIB)	:= FILEMODE= 755
$(ROOTVARIANTDIR)/$(VAR2_DYNLIB)	:= FILEMODE= 755
$(ROOTVARIANTDIR)/$(VAR3_DYNLIB)	:= FILEMODE= 755

$(ROOTVARIANTDIR64)			:= FILEMODE= 755
$(ROOTVARIANTDIR64)/$(VAR1_DYNLIB64)	:= FILEMODE= 755

.KEEP_STATE:

all:	all_h lib32 $(BUILD64) .WAIT lib64 .WAIT etc THIRDPARTYLICENSE

THIRDPARTYLICENSE: extract-copyright
	$(RM) $@
	./extract-copyright . > $@

etc:	$($(MACH)_ETC)

lib32:	$(MACH_COMP) $(MACHLIBS) $(MACH)/$(LIB_PIC) $(VARIANTLIBS)
	@if $(ELFDUMP) -r $(MACH)/$(DYNLIB) | $(GREP) -w environ ; then \
		$(ECHO) "Error: Invalid reference to environ" ; \
		$(ECHO) "Error: See comments in port/gen/env_data.c" ; \
		exit 1; \
	fi

lib64:	$(MACH_COMP) $(MACHLIBS64) $(MACH64)/$(LIB_PIC) $(VARIANTLIBS64)
	@if $(ELFDUMP) -r $(MACH64)/$(DYNLIB) | $(GREP) -w environ ; then \
		$(ECHO) "Error: Invalid reference to environ" ; \
		$(ECHO) "Error: See comments in port/gen/env_data.c" ; \
		exit 1; \
	fi

$(MACH)/assym.h $(MACH64)/assym.h:
	@cd $(@D); $(MAKE) assym.h

$(VARIANTLIBS): FRC
	@cd $(@D); pwd; VERSION='$(VERSION)' $(MAKE) $(@F)

$(VARIANTLIBS64): FRC
	@cd $(@D); pwd; VERSION='$(VERSION)' $(MAKE) $(@F)

$($(MACH)_ETC): FRC
	@cd $(@); pwd; $(MAKE) $(TARGET)

$($(MACH)_COMP): FRC
	@cd $(@); pwd; $(MAKE) $(TARGET)

install:	all			\
		etc			\
		inslib32		\
		$(BUILD64) inslib64

inslib32:	$(ROOTFS_LIBS) $(ROOTFS_LINKS) $(ROOTVARIANTLIBS)

inslib64:	$(ROOTFS_LIBS64) $(ROOTFS_LINKS64) $(ROOTVARIANTLIBS64)

install_h: all_h $(ROOTHDRS)

all_h:	$(MACH)/assym.h $(MACH64)/assym.h

check:	$(CHECKHDRS)

$(ROOTFS_LIB)/%: $(MACH)/%
	$(INS.file)
$(ROOTFS_LIBDIR)/$(LIBLINKS): $(ROOTFS_LIBDIR)/$(LIBLINKS)$(VERS)
	$(INS.liblink)
$(ROOTFS_LIB64)/%: $(MACH64)/%
	$(INS.file)
$(ROOTFS_LIBDIR64)/$(LIBLINKS): $(ROOTFS_LIBDIR64)/$(LIBLINKS)$(VERS)
	$(INS.liblink)

$(ROOTVARIANTDIR): $(ROOTLIB)
	$(INS.dir)
$(ROOTVARIANTDIR)/%: $(ROOTVARIANTDIR) $(VAR1_BLDDIR)/%
	$(INS.file)
$(ROOTVARIANTDIR)/%: $(ROOTVARIANTDIR) $(VAR2_BLDDIR)/%
	$(INS.file)
$(ROOTVARIANTDIR)/%: $(ROOTVARIANTDIR) $(VAR3_BLDDIR)/%
	$(INS.file)

$(ROOTVARIANTDIR64): $(ROOTLIB64)
	$(INS.dir)
$(ROOTVARIANTDIR64)/%: $(ROOTVARIANTDIR64) $(VAR1_BLDDIR64)/%
	$(INS.file)

$(MACH)/$(LIB_PIC): FRC
	@cd $(MACH); pwd; VERSION='$(VERSION)' $(MAKE) $(LIB_PIC)
$(MACH64)/$(LIB_PIC): FRC
	@cd $(MACH64); pwd; VERSION='$(VERSION)' $(MAKE) $(LIB_PIC)

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint

.PARALLEL:	$(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; VERSION='$(VERSION)' $(MAKE) $(TARGET)

clean: $(SUBDIRS)
clobber: $(SUBDIRS) etc clobber_local
clobber_local:
	$(RM) $(CLOBBERFILES)

lint:

_msg:	$(MSGDOMAIN) catalog

catalog:
	sh ./makelibccatalog.sh $(MSGDOMAIN)

$(MSGDOMAIN):
	$(INS.dir)

cscope.out tags: FRC
	$(XREF) -x $@

FRC:
# include MACH-specific library targets
include ../Makefile.mach
