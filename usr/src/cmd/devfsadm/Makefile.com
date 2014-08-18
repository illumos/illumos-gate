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

# This target builds both a command (daemon) and various shared objects.  This
# isn't a typical target, and the inclusion of both library and command
# Makefiles were probably not in their original design.  However, there doesn't
# presently seem to be a clash of any required definitions.
include ../../../lib/Makefile.lib
include ../../Makefile.cmd

COMMON = ..
UTSBASE = $(COMMON)/../../uts

DEVFSADM_MOD = devfsadm

DEVALLOCSRC =	devalloc.c

PLCYSRC = devpolicy.c plcysubr.c

MODLOADDIR = $(COMMON)/../modload

DEVFSADM_SRC = $(COMMON)/$(DEVFSADM_MOD:%=%.c) \
		$(DEVALLOCSRC:%=$(COMMON)/%) $(PLCYSRC:%=$(COMMON)/%)
DEVFSADM_OBJ = $(DEVFSADM_MOD:%=%.o) $(DEVALLOCSRC:%.c=%.o) $(PLCYSRC:%.c=%.o)

DEVFSADM_DAEMON = devfsadmd

LINKMOD_DIR = linkmod
DEVFSADM_DIR = devfsadm

CLOBBERFILES = $(MODS) $(DEVLINKTAB) $(DEVFSCOMPATLINKS) $(DEVFSADM_DAEMON)
CLOBBERFILES += $(POFILE) $(POFILES) ../plcysubr.c

LINK_OBJS_CMN =			\
	disk_link.o		\
	ieee1394_link.o		\
	dcam1394_link.o		\
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
	smp_link.o		\
	dtrace_link.o		\
	vscan_link.o		\
	zfs_link.o		\
	zut_link.o

LINK_OBJS =	$(LINK_OBJS_CMN) \
		$(LINK_OBJS_$(MACH))

LINK_SRCS =	$(LINK_OBJS_CMN:%.o=$(COMMON)/%.c) \
		$(LINK_OBJS_$(MACH):%.o=%.c)

LINT_MODULES = $(LINK_SRCS:%.c=%.ln)

LINK_MODS =	$(LINK_OBJS:%.o=SUNW_%.so)

DEVLINKTAB = devlink.tab
DEVLINKTAB_SRC = $(COMMON)/$(DEVLINKTAB).sh

COMPAT_LINKS = disks tapes ports audlinks devlinks drvconfig

CPPFLAGS +=	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT \
		-I$(COMMON) -I$(UTSBASE)/common -I$(MODLOADDIR)
CFLAGS += $(CCVERBOSE) $(C_PICFLAGS)

LINTFLAGS += -erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS += -erroff=E_NAME_DEF_NOT_USED2
LINTFLAGS += -erroff=E_NAME_MULTIPLY_DEF2

CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-char-subscripts
CERRWARN += -_gcc=-Wno-parentheses

# Define the dependencies required by devfsadm and all shared objects.
LDLIBS +=		-ldevinfo
devfsadm :=		LDLIBS += -lgen -lsysevent -lnvpair -lzonecfg -lbsm
SUNW_md_link.so :=	LDLIBS += -lmeta
SUNW_disk_link.so :=	LDLIBS += -ldevid
SUNW_sgen_link.so :=	LDLIBS += -ldevid

# All libraries are built from the same SUNW_%.so rule (see below), and define
# their own SONAME using -h explicitly.  Null the generic -h macro that gets
# inherited from Makefile.lib, otherwise we'll get two -h definitions.
HSONAME =

SRCS = $(DEVFSADM_SRC) $(LINK_SRCS)
OBJS = $(DEVFSADM_OBJ) $(LINK_OBJS)
MODS = $(DEVFSADM_MOD) $(LINK_MODS)

POFILES = $(LINK_SRCS:.c=.po) $(DEVFSADM_SRC:.c=.po)
POFILE = pdevfsadm.po

# install specifics

ROOTLIB_DEVFSADM = $(ROOTLIB)/$(DEVFSADM_DIR)
ROOTLIB_DEVFSADM_LINKMOD = $(ROOTLIB_DEVFSADM)/$(LINKMOD_DIR)

ROOTLIB_DEVFSADM_LINK_MODS = $(LINK_MODS:%=$(ROOTLIB_DEVFSADM_LINKMOD)/%)

ROOTUSRSBIN_COMPAT_LINKS = $(COMPAT_LINKS:%=$(ROOTUSRSBIN)/%)

ROOTUSRSBIN_DEVFSADM = $(DEVFSADM_MOD:%=$(ROOTUSRSBIN)/%)

ROOTLIB_DEVFSADM_DAEMON = $(ROOTLIB_DEVFSADM)/$(DEVFSADM_DAEMON)

ROOTETC_DEVLINKTAB = $(DEVLINKTAB:%=$(ROOTETC)/%)

FILEMODE= 755

$(ROOTETC_DEVLINKTAB) := FILEMODE = 644

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
	$(ROOTUSRSBIN_COMPAT_LINKS)


clean:
	$(RM) $(OBJS) 


lint: $(DEVFSADM_MOD).ln $(LINT_MODULES)

devfsadm.ln: $(DEVFSADM_SRC)
	$(LINT.c) $(DEVFSADM_SRC) $(LDLIBS)

%.ln: $(DEVFSADM_SRC) %.c
	$(LINT.c) $(DEVFSADM_SRC) $(@:.ln=.c) $(LDLIBS)

include ../../Makefile.targ

$(POFILE):      $(POFILES)
	$(RM) $@; cat $(POFILES) > $@

$(DEVFSADM_MOD): $(DEVFSADM_OBJ)
	$(LINK.c) -o $@ $< $(DEVFSADM_OBJ) $(LDLIBS)
	$(POST_PROCESS)

SUNW_%.so: %.o $(MAPFILES)
	$(CC) -o $@ $(GSHARED) $(DYNFLAGS) -h $@ $< $(LDLIBS) -lc
	$(POST_PROCESS_SO)

%.o: $(COMMON)/%.c
	$(COMPILE.c) -o $@ $< $(CTFCONVERT_HOOK)
	$(POST_PROCESS_O)


$(DEVLINKTAB): $(DEVLINKTAB_SRC)
	$(RM) $(DEVLINKTAB)
	/bin/sh $(DEVLINKTAB_SRC) > $(DEVLINKTAB)

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
