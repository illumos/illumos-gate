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
#
# uts/sparc/sdbc/Makefile
#
#       This makefile drives the production of the sdbc kernel module
#
#       sparc implementation architecture dependent
#

#
#       Path to the base of the uts directory tree (usually /usr/src/uts).
#
#
UTSBASE = ../..

ARCHDIR:sh = cd ..; basename `pwd`

UTSCOMMON = $(UTSBASE)/common
AVSCOMMON = $(UTSCOMMON)/avs

#
#       Define the module and object file sets.
#
MODULE		= sdbc
OBJECTS		= $(SDBC_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(SDBC_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE      = $(USR_DRV_DIR)/$(MODULE)
INC_PATH	+= -I$(ROOT)/usr/include
INC_PATH	+= -I$(AVSCOMMON)
INC_PATH	+= -I$(AVSCOMMON)/ns/sdbc
CONF_SRCDIR	= $(UTSBASE)/common/avs/ns/sdbc

#
#       Include common rules.
#
include ../Makefile.$(ARCHDIR)
include $(UTSBASE)/common/avs/Makefile.com

CLOBBERFILES += obj*/*.c debug*/*.c obj*/sd_mkiob debug*/sd_mkiob

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(SRC_CONFILE)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# lint pass one enforcement
#
CFLAGS += $(CCVERBOSE) -D_SD_8K_BLKSIZE -D_SDBC_SINGLE_BRD
LDFLAGS += -dy -N"drv/nsctl" -N"drv/ncall" -N"drv/nskern" -N"misc/spuni"
LINTTAGS += -erroff=E_ASSIGN_NARROW_CONV
LINTTAGS += -erroff=E_BAD_PTR_CAST_ALIGN

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-label

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

$(OBJS_DIR)/sd_mkiob:		$(UTSBASE)/common/avs/ns/sdbc/sd_mkiob.sh
	$(CP) $(UTSBASE)/common/avs/ns/sdbc/sd_mkiob.sh $@
	$(CHMOD) 755 $@

$(OBJS_DIR)/sd_iob_impl0.c:	$(UTSBASE)/common/avs/ns/sdbc/sd_iob.h \
				$(OBJS_DIR)/sd_mkiob
	$(OBJS_DIR)/sd_mkiob 0 512 $(AVSCOMMON)/ns/sdbc/sd_iob.h > $@

$(OBJS_DIR)/sd_iob_impl1.c:	$(UTSBASE)/common/avs/ns/sdbc/sd_iob.h \
				$(OBJS_DIR)/sd_mkiob
	$(OBJS_DIR)/sd_mkiob 512 1024 $(AVSCOMMON)/ns/sdbc/sd_iob.h > $@

$(OBJS_DIR)/sd_iob_impl2.c:	$(UTSBASE)/common/avs/ns/sdbc/sd_iob.h \
				$(OBJS_DIR)/sd_mkiob
	$(OBJS_DIR)/sd_mkiob 1024 1536 $(AVSCOMMON)/ns/sdbc/sd_iob.h > $@

$(OBJS_DIR)/sd_iob_impl3.c:	$(UTSBASE)/common/avs/ns/sdbc/sd_iob.h \
				$(OBJS_DIR)/sd_mkiob
	$(OBJS_DIR)/sd_mkiob 1536 2048 $(AVSCOMMON)/ns/sdbc/sd_iob.h > $@

$(OBJS_DIR)/sd_iob_impl4.c:	$(UTSBASE)/common/avs/ns/sdbc/sd_iob.h \
				$(OBJS_DIR)/sd_mkiob
	$(OBJS_DIR)/sd_mkiob 2048 2560 $(AVSCOMMON)/ns/sdbc/sd_iob.h > $@

$(OBJS_DIR)/sd_iob_impl5.c:	$(UTSBASE)/common/avs/ns/sdbc/sd_iob.h \
				$(OBJS_DIR)/sd_mkiob
	$(OBJS_DIR)/sd_mkiob 2560 3072 $(AVSCOMMON)/ns/sdbc/sd_iob.h > $@

$(OBJS_DIR)/sd_iob_impl6.c:	$(UTSBASE)/common/avs/ns/sdbc/sd_iob.h \
				$(OBJS_DIR)/sd_mkiob
	$(OBJS_DIR)/sd_mkiob 3072 3584 $(AVSCOMMON)/ns/sdbc/sd_iob.h > $@

$(OBJS_DIR)/sd_iob_impl7.c:	$(UTSBASE)/common/avs/ns/sdbc/sd_iob.h \
				$(OBJS_DIR)/sd_mkiob
	$(OBJS_DIR)/sd_mkiob 3584 9999 $(AVSCOMMON)/ns/sdbc/sd_iob.h > $@

$(OBJS_DIR)/sd_iob_impl0.o:	$(OBJS_DIR)/sd_iob_impl0.c
	$(COMPILE.c) -o $@ $(OBJS_DIR)/sd_iob_impl0.c
	$(POST_PROCESS_O)

$(OBJS_DIR)/sd_iob_impl1.o:	$(OBJS_DIR)/sd_iob_impl1.c
	$(COMPILE.c) -o $@ $(OBJS_DIR)/sd_iob_impl1.c
	$(POST_PROCESS_O)

$(OBJS_DIR)/sd_iob_impl2.o:	$(OBJS_DIR)/sd_iob_impl2.c
	$(COMPILE.c) -o $@ $(OBJS_DIR)/sd_iob_impl2.c
	$(POST_PROCESS_O)

$(OBJS_DIR)/sd_iob_impl3.o:	$(OBJS_DIR)/sd_iob_impl3.c
	$(COMPILE.c) -o $@ $(OBJS_DIR)/sd_iob_impl3.c
	$(POST_PROCESS_O)

$(OBJS_DIR)/sd_iob_impl4.o:	$(OBJS_DIR)/sd_iob_impl4.c
	$(COMPILE.c) -o $@ $(OBJS_DIR)/sd_iob_impl4.c
	$(POST_PROCESS_O)

$(OBJS_DIR)/sd_iob_impl5.o:	$(OBJS_DIR)/sd_iob_impl5.c
	$(COMPILE.c) -o $@ $(OBJS_DIR)/sd_iob_impl5.c
	$(POST_PROCESS_O)

$(OBJS_DIR)/sd_iob_impl6.o:	$(OBJS_DIR)/sd_iob_impl6.c
	$(COMPILE.c) -o $@ $(OBJS_DIR)/sd_iob_impl6.c
	$(POST_PROCESS_O)

$(OBJS_DIR)/sd_iob_impl7.o:	$(OBJS_DIR)/sd_iob_impl7.c
	$(COMPILE.c) -o $@ $(OBJS_DIR)/sd_iob_impl7.c
	$(POST_PROCESS_O)


#
#	Include common targets.
#
include ../Makefile.targ
