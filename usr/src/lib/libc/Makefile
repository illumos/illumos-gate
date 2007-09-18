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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
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

ROOTFS_LINTDIR=		$(ROOTFS_LIB)
ROOTFS_LINTDIR64=	$(ROOTFS_LIB64)
ROOTFS_LINTLIB=		$(ROOTFS_LINTDIR)/$(LINTLIB)
ROOTFS_LINTLIB64=	$(ROOTFS_LINTDIR64)/$(LINTLIB)

# include common library definitions
include ../Makefile.lib

#
# on some architectures, we build multiple libc variants
#
VAR1 =		hwcap1
VAR2 =		hwcap2
VAR3 =		hwcap3

VAR1_DYNLIB =	$(LIBRARY:%.a=%_$(VAR1).so$(VERS))
VAR1_BLDDIR =	$(MACH)_$(VAR1)
VAR2_DYNLIB =	$(LIBRARY:%.a=%_$(VAR2).so$(VERS))
VAR2_BLDDIR =	$(MACH)_$(VAR2)
VAR3_DYNLIB =	$(LIBRARY:%.a=%_$(VAR3).so$(VERS))
VAR3_BLDDIR =	$(MACH)_$(VAR3)

i386_VARIANTS=	$(VAR1) $(VAR2) $(VAR3)
sparc_VARIANTS=

i386_ETC=	$(MACH)/etc
sparc_ETC=

VARIANTS=	$($(MACH)_VARIANTS)
VARIANT_SUBDIRS	= $(VARIANTS:%=$(MACH)_%)

SUBDIRS=	$(MACH) $(MACH_ETC) $(VARIANT_SUBDIRS)
$(BUILD64)SUBDIRS += $(MACH64)

LIBS =		$(DYNLIB) $(LINTLIB)

ROOTLIBS64=	$(ROOTLIBDIR64)/$(DYNLIB) $(ROOTLIBDIR64)/$(LINTLIB)
MACHLIBS64=	$(MACH64)/$(DYNLIB) $(MACH64)/$(LINTLIB)
VARIANTLIBS=	$(VARIANTS:%=$(MACH)_%/$(LIBBASENAME)_%.so.1)
ROOTVARIANTLIBS= $(VARIANTS:%=$(ROOTVARIANTDIR)/$(LIBBASENAME)_%.so.1)

# definitions for install_h target
BASEHDRS=	getxby_door.h 
CHECKHDRS=	$(BASEHDRS:%.h=port/gen/%.check)
HDRS=		$(BASEHDRS)

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

.KEEP_STATE:

all:	check_i18n .WAIT lib32 $(BUILD64) .WAIT lib64 .WAIT etc

check_i18n:
	@if [ ! -f $(ROOTFS_LIBDIR)/libc_i18n.a -o \
	    ! -f $(ROOTFS_LIBDIR64)/libc_i18n.a ]; then \
		if [ "$$CLOSED_IS_PRESENT" = no ]; then \
			$(ECHO) "Warning: closed binaries not" \
			    "properly unpacked." >&2;\
			$(ECHO) "Missing libc_i18n.a" >&2; \
			exit 1; \
		else \
			$(ECHO) "Warning: libc_i18n.a must be built" \
			    "before libc can be built." >&2; \
			exit 1; \
		fi \
	fi

etc:	$($(MACH)_ETC)

lib32:	$(MACHLIBS) $(MACH)/$(LIB_PIC) $(VARIANTLIBS)
	mkdir -p $(MACH)/i18n_pics
	cd $(MACH)/i18n_pics ; $(AR) -x $(ROOTFS_LIBDIR)/libc_i18n.a
	$(CHECK_FNAMES) -s $(C_SYNONYMS_H) -l $(MACH)/$(DYNLIB) \
		$(MACH)/pics/*.o $(MACH)/i18n_pics/*.o

lib64:	$(MACHLIBS64) $(MACH64)/$(LIB_PIC) $(VARIANTLIBS)
	mkdir -p $(MACH64)/i18n_pics
	cd $(MACH64)/i18n_pics ; $(AR) -x $(ROOTFS_LIBDIR64)/libc_i18n.a
	$(CHECK_FNAMES) -s $(C_SYNONYMS_H) -l $(MACH64)/$(DYNLIB) \
		$(MACH64)/pics/*.o $(MACH64)/i18n_pics/*.o

$(VARIANTLIBS): FRC
	@cd $(@D); pwd; VERSION='$(VERSION)' $(MAKE) $(@F)
	$(CHECK_FNAMES) -s $(C_SYNONYMS_H) -l $(@D)/$(@F) $(@D)/pics/*.o

$($(MACH)_ETC): FRC
	@cd $(@); pwd; $(MAKE) $(TARGET)

install:	all			\
		etc			\
		inslib32		\
		$(BUILD64) inslib64

inslib32:	$(ROOTFS_LIBS) $(ROOTFS_LINKS) $(ROOTFS_LINT) \
		$(ROOTFS_LINTLIB) \
		$(ROOTVARIANTLIBS)

inslib64:	$(ROOTFS_LIBS64) $(ROOTFS_LINKS64) \
		$(ROOTFS_LINTLIB64)

install_h: $(ROOTHDRS)

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

# install rule for lint library target
$(ROOTFS_LINTDIR)/%: port/%
	$(INS.file)
$(ROOTFS_LINTDIR64)/%: port/%
	$(INS.file)
$(ROOTFS_LINTDIR)/%: $(MACH)/%
	$(INS.file)
$(ROOTFS_LINTDIR64)/%: $(MACH64)/%
	$(INS.file)

$(LINTLIB):
	@cd $(MACH); pwd; VERSION='$(VERSION)' $(MAKE) $@
$(LINTLIB64):
	@cd $(MACH64); pwd; VERSION='$(VERSION)' $(MAKE) $@

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

clean clobber: $(SUBDIRS)
	$(RM) -r $(MACH)/i18n_pics
	$(BUILD64)$(RM) -r $(MACH64)/i18n_pics

lint: $(SUBDIRS)

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
