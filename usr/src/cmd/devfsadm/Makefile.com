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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../../Makefile.cmd

COMMON = ..

DEVFSADM_MOD = devfsadm

PLCYSRC = devpolicy.c plcysubr.c

MODLOADDIR = $(COMMON)/../modload

DEVFSADM_SRC = $(COMMON)/$(DEVFSADM_MOD:%=%.c) $(PLCYSRC:%=$(COMMON)/%)
DEVFSADM_OBJ = $(DEVFSADM_MOD:%=%.o) $(PLCYSRC:%.c=%.o)

DEVFSADM_DAEMON = devfsadmd

LINKMOD_DIR = linkmod
DEVFSADM_DIR = devfsadm

CLOBBERFILES = $(MODS) $(DEVLINKTAB) $(DEVFSCOMPATLINKS) $(DEVFSADM_DAEMON)

LINK_SRCS =			\
	$(COMMON)/disk_link.c	\
	$(COMMON)/ieee1394_link.c	\
	$(COMMON)/tape_link.c	\
	$(COMMON)/usb_link.c	\
	$(COMMON)/port_link.c	\
	$(COMMON)/audio_link.c	\
	$(COMMON)/cfg_link.c	\
	$(COMMON)/misc_link.c	\
	$(COMMON)/lofi_link.c	\
	$(COMMON)/ramdisk_link.c	\
	$(COMMON)/fssnap_link.c \
	$(COMMON)/sgen_link.c	\
	$(COMMON)/md_link.c	\
	$(COMMON)/dtrace_link.c	\
	$(MISC_LINK_ISA).c

LINT_MODULES = $(LINK_SRCS:.c=.ln)

LINK_OBJS =			\
	disk_link.o		\
	ieee1394_link.o		\
	tape_link.o		\
	usb_link.o		\
	port_link.o		\
	audio_link.o		\
	cfg_link.o		\
	misc_link.o		\
	lofi_link.o		\
	ramdisk_link.o		\
	fssnap_link.o           \
	sgen_link.o		\
	md_link.o		\
	dtrace_link.o		\
	$(MISC_LINK_ISA).o

LINK_MODS =			\
	SUNW_disk_link.so	\
	SUNW_ieee1394_link.so	\
	SUNW_tape_link.so	\
	SUNW_usb_link.so	\
	SUNW_port_link.so	\
	SUNW_audio_link.so	\
	SUNW_cfg_link.so	\
	SUNW_misc_link.so	\
	SUNW_lofi_link.so	\
	SUNW_ramdisk_link.so	\
	SUNW_fssnap_link.so     \
	SUNW_sgen_link.so	\
	SUNW_md_link.so		\
	SUNW_dtrace_link.so	\
	SUNW_$(MISC_LINK_ISA).so

DEVLINKTAB = devlink.tab
DEVLINKTAB_SRC = $(COMMON)/$(DEVLINKTAB).sh

DEVFSADM_DEFAULT = devfsadm
DEVFSADM_DEFAULT_SRC = $(COMMON)/devfsadm.dfl

COMPAT_LINKS = disks tapes ports audlinks devlinks drvconfig

CPPFLAGS +=	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT \
		-I.. -I../../../uts/common -I$(MODLOADDIR)
CFLAGS += $(CCVERBOSE) $(C_PICFLAGS) -I.. -I$(MODLOADDIR)

LINTFLAGS += -erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS += -erroff=E_NAME_DEF_NOT_USED2
LINTFLAGS += -erroff=E_NAME_MULTIPLY_DEF2

LAZYLIBS = -z lazyload -lzonecfg -z nolazyload
lint := LAZYLIBS = -lzonecfg
LDLIBS += -ldevinfo -lgen -lsysevent -lnvpair -lcmd $(LAZYLIBS)

SRCS = $(DEVFSADM_SRC) $(LINK_SRCS)
OBJS = $(DEVFSADM_OBJ) $(LINK_OBJS)
MODS = $(DEVFSADM_MOD) $(LINK_MODS)

POFILES = $(LINK_SRCS:.c=.po) $(DEVFSADM_SRC:.c=.po)
POFILE = pdevfsadm.po

# install specifics

ROOTLIB_DEVFSADM = $(ROOTLIB)/$(DEVFSADM_DIR)
ROOTLIB_DEVFSADM_LINKMOD = $(ROOTLIB_DEVFSADM)/$(LINKMOD_DIR)

ETCDEFAULT = $(ROOTETC)/default
ETCDEFAULT_DEVFSADM = $(DEVFSADM_DEFAULT:%=$(ETCDEFAULT)/%)

ROOTLIB_DEVFSADM_LINK_MODS = $(LINK_MODS:%=$(ROOTLIB_DEVFSADM_LINKMOD)/%)

ROOTUSRSBIN_COMPAT_LINKS = $(COMPAT_LINKS:%=$(ROOTUSRSBIN)/%)

ROOTUSRSBIN_DEVFSADM = $(DEVFSADM_MOD:%=$(ROOTUSRSBIN)/%)

ROOTLIB_DEVFSADM_DAEMON = $(ROOTLIB_DEVFSADM)/$(DEVFSADM_DAEMON)

ROOTETC_DEVLINKTAB = $(DEVLINKTAB:%=$(ROOTETC)/%)

OWNER= root
GROUP= sys
FILEMODE= 755

$(ROOTETC_DEVLINKTAB) := FILEMODE = 644

$(ETCDEFAULT_DEVFSADM) := FILEMODE = 444

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint


.KEEP_STATE:

all: $(MODS) $(DEVLINKTAB)

install: all				\
	$(ROOTLIB_DEVFSADM)		\
	$(ROOTLIB_DEVFSADM_LINKMOD)	\
	$(ROOTUSRSBIN_DEVFSADM)		\
	$(ROOTETC_DEVLINKTAB)		\
	$(ROOTLIB_DEVFSADM_LINK_MODS)	\
	$(ROOTUSRINCLUDE)		\
	$(ROOTLIB_DEVFSADM_DAEMON)	\
	$(ETCDEFAULT)			\
	$(ETCDEFAULT_DEVFSADM)		\
	$(ROOTUSRSBIN_COMPAT_LINKS)


clean:
	$(RM) $(OBJS) 


lint: $(DEVFSADM_MOD).ln $(LINT_MODULES)

devfsadm.ln: FRC
	$(LINT.c) $(DEVFSADM_SRC) $(LDLIBS)

%.ln: FRC
	$(LINT.c) $(DEVFSADM_SRC) $(@:.ln=.c) $(LDLIBS)

FRC:

include ../../Makefile.targ

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

$(DEVFSADM_MOD): $(DEVFSADM_OBJ)
	$(LINK.c) -o $@ $< $(DEVFSADM_OBJ) $(LDLIBS)
	$(POST_PROCESS)

SUNW_%.so: %.o
	$(LINK.c) -o $@ $(GSHARED) -h $@ $<

%.o: $(COMMON)/%.c
	$(COMPILE.c) -o $@ $<


$(DEVLINKTAB): $(DEVLINKTAB_SRC)
	$(RM) $(DEVLINKTAB)
	/bin/sh $(DEVLINKTAB_SRC) > $(DEVLINKTAB)

$(ETCDEFAULT)/%: %
	$(RM) -r default
	mkdir default
	cp $(DEVFSADM_DEFAULT_SRC) default/$(DEVFSADM_DEFAULT)
	cd default ; $(INS.file)
	$(RM) -r default

$(ETCDEFAULT):
	$(INS.dir)

$(ROOTUSRSBIN):
	$(INS.dir)

$(ROOTLIB_DEVFSADM):
	$(INS.dir)

$(ROOTUSRINCLUDE):
	$(INS.dir)

$(ROOTLIB_DEVFSADM_LINKMOD):
	$(INS.dir)

$(ROOTLIB_DEVFSADM_LINKMOD)/%: %
	$(INS.file)

$(ROOTLIB_DEVFSADM_DAEMON):
	$(RM) $@; $(SYMLINK) ../../sbin/$(DEVFSADM_DIR) $@

$(ROOTUSRSBIN_COMPAT_LINKS):	$(ROOTUSRSBIN_DEVFSADM)
	$(RM) $@ ; $(LN) $(ROOTUSRSBIN_DEVFSADM) $@

#
# Source shared with add_drv/update_drv
#
../plcysubr.c:
	rm -f $@
	ln -s ../modload/plcysubr.c ..
