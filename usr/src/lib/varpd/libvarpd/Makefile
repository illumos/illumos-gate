#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2015 Joyent, Inc.
#

include		../../Makefile.lib

HDRS =		libvarpd.h libvarpd_client.h libvarpd_provider.h
HDRDIR =	common
SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS +=	$(MACH64)

TYPECHECK_LIB =	libvarpd.so.1
TYPELIST = \
	varpd_client_instance_arg_t \
	varpd_client_nprops_arg_t \
	varpd_client_propinfo_arg_t \
	varpd_client_eresp_t \
	varpd_persist_header_t \
	overlay_targ_cache_entry_t \
	overlay_targ_cache_t \
	overlay_targ_cache_iter_t

all :=		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install :=	TARGET = install

.KEEP_STATE:

all clean clobber: $(SUBDIRS)

install:	$(SUBDIRS) $(VARPD_MAPFILES) install_h

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS) $(TYPECHECK)

$(SUBDIRS):  FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../../Makefile.targ
