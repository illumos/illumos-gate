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
#
#	This makefile drives the production of the ip driver 
#	kernel module.
#
#	intel implementation architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= ip
OBJECTS		= $(IP_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(IP_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_STRMOD_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/inet/ip

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK) $(ROOT_CONFFILE)

CINLINEFLAGS = -xinline=tcp_set_ws_value

CFLAGS		+= $(CINLINEFLAGS)

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-type-limits

#
# To get the BPF header files included by ipnet.h
#
INC_PATH	+= -I$(UTSBASE)/common/io/bpf

#
# Depends on md5 and swrand (for SCTP). SCTP needs to depend on
# swrand as it needs random numbers early on during boot before
# kCF subsystem can load swrand.
#
LDFLAGS		+= -dy -Nmisc/md5 -Ncrypto/swrand -Nmisc/hook -Nmisc/neti 

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS) $(SISCHECK_DEPS)

clean:		$(CLEAN_DEPS) $(SISCLEAN_DEPS)

# Need to clobber all build types due to ipctf.a
clobber:	$(CLOBBER_DEPS) $(SISCLEAN_DEPS) \
		clobber.obj32 clobber.obj64 \
		clobber.debug32 clobber.debug64

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS) $(SISCHECK_DEPS)

$(ROOTLINK):	$(ROOT_STRMOD_DIR) $(ROOTMODULE)
	-$(RM) $@; ln $(ROOTMODULE) $@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

#
# The ip CTF data is merged into the genunix module because these types are
# complex and heavily shared.  The genunix build will execute one of the
# rules below to create an archive, ipctf.a, containing the ip objects.  The
# real ip will be uniquified against genunix later in the build, and will
# emerge containing very few types.
#
$(OBJS_DIR)/ipctf.a: $(OBJECTS)
	-$(RM) $@
	$(AR) -r $@ $(OBJECTS)

$(OBJECTS): $(OBJS_DIR)

CLOBBERFILES += $(OBJS_DIR)/ipctf.a

ipctf.obj32: FRC
	@BUILD_TYPE=OBJ32 VERSION='$(VERSION)' $(MAKE) obj32/ipctf.a

ipctf.debug32: FRC
	@BUILD_TYPE=DBG32 VERSION='$(VERSION)' $(MAKE) debug32/ipctf.a

ipctf.obj64: FRC
	@BUILD_TYPE=OBJ64 VERSION='$(VERSION)' $(MAKE) obj64/ipctf.a

ipctf.debug64: FRC
	@BUILD_TYPE=DBG64 VERSION='$(VERSION)' $(MAKE) debug64/ipctf.a
