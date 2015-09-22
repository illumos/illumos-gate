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
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2015 Nexenta Systems, Inc. All rights reserved.
#

# The filesystem independent utilities clri, fsdb, dcopy, labelit, and mkfs
# are all built from the source file switchout.c. They are all then links
# to the same object. This is accomplished by:
#	1) building clri from switchout.c (had to choose one)
#	2) installing it in the target directory
#	3) linking the others to clri.
# In a similar manner, ncheck is linked to ff.

DFPROG=		df
PROG=		$(DFPROG) fsck volcopy ff
ROOTFS_PROG=	mount umount
SPPROG=		clri
MNTTAB=		mnttab
DEFAULTFILES=	fs.dfl

include ../Makefile.cmd

SUBDIR1= lofs zfs
SUBDIR2= dev fd pcfs nfs hsfs proc ctfs udfs ufs tmpfs \
		autofs mntfs objfs sharefs smbclnt reparsed
SUBDIRS= $(SUBDIR1) $(SUBDIR2)
I18NDIRS= $(SUBDIR2)

CLEANFILES +=	deffs.o df.o ff.o fsck.o fssnapsup.o \
		mount.o preenlib.o switchout.o umount.o volcopy.o

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
_msg:=          TARGET= catalog

USRSBINF=	df clri fsck volcopy ff
USRSBINCLRI=	dcopy fsdb fssnap labelit mkfs
USRSBINFF=	ncheck

ETC2SBIN=	mount umount
ETC2USRSBIN=	clri fsdb mkfs fsck labelit dcopy volcopy ff ncheck
USRBIN2USRSBIN=	df
USRXPG4BIN2USRSBIN= df

FSLIB=		fslib.o

ROOTSBINPROG = $(ROOTFS_PROG:%=$(ROOTSBIN)/%)
ROOTUSRSBINLINKS = $(ROOTFS_PROG:%=$(ROOTUSRSBIN)/%)

ROOTUSRSBINF=		$(USRSBINF:%=$(ROOTUSRSBIN)/%)
ROOTUSRSBINCLRI=	$(USRSBINCLRI:%=$(ROOTUSRSBIN)/%)
ROOTUSRSBINFF=		$(USRSBINFF:%=$(ROOTUSRSBIN)/%)
ROOTETCMNTTAB=		$(MNTTAB:%=$(ROOTETC)/%)
SYMETC2SBIN	=	$(ETC2SBIN:%=$(ROOTETC)/%)
SYMETC2USRSBIN	=	$(ETC2USRSBIN:%=$(ROOTETC)/%)
SYMUSRBIN2USRSBIN=	$(USRBIN2USRSBIN:%=$(ROOTBIN)/%)
SYMUSRXPG4BIN2USRSBIN=	$(USRXPG4BIN2USRSBIN:%=$(ROOTXPG4BIN)/%)
SYMDEVNM=		$(ROOTUSRSBIN)/devnm

CPPFLAGS += -D_LARGEFILE64_SOURCE

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-function

$(SPPROG) :=	LDLIBS += -lkstat

$(ROOTETCMNTTAB) := FILEMODE = 444

# for messaging catalog
#
POFILE= fs.d.po
POFILES1= $(PROG:%=%.po) $(ROOTFS_PROG:%=%.po) switchout.po fssnapsup.po
POFILES2= $(I18NDIRS:%=%/%.po)
POFILES=  $(POFILES1) $(POFILES2)
volcopy.po :=   XGETFLAGS += -a -x volcopy.xcl
$(DFPROG).po := XGETFLAGS += -a -x df.xcl

.KEEP_STATE:

# This is too intense when building the whole world.
# .PARALLEL:	$(SUBDIRS)

all:		$(FSLIB) .WAIT $(SUBDIRS) .WAIT all_local

_msg: $(I18NDIRS) $(POFILES1)
	$(RM) $(POFILE)
	cat $(POFILES) > $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	cp $(POFILE) $(MSGDOMAIN)

all_local:	$(PROG) $(ROOTFS_PROG) $(SPPROG) $(MNTTAB) \
		$(DEFAULTFILES)

ff volcopy: deffs.o $$(@F).o
		$(LINK.c) -o $@ $@.o deffs.o $(LDLIBS)
		$(POST_PROCESS)

df: deffs.o $(FSLIB) $$(@F).o
	$(LINK.c) -o $@ $@.o deffs.o $(FSLIB) $(LDLIBS)
	$(POST_PROCESS)

fsck: fsck.o deffs.o preenlib.o
	$(LINK.c) -o $@ fsck.o deffs.o preenlib.o $(LDLIBS)
	$(POST_PROCESS)

mount: deffs.o mount.o $(FSLIB)
	$(LINK.c) -o $@ mount.o deffs.o $(FSLIB) $(LDLIBS)
	$(POST_PROCESS)

umount: umount.o $(FSLIB)
	$(LINK.c) -o $@ umount.o $(FSLIB) $(LDLIBS)
	$(POST_PROCESS)

$(SPPROG):	switchout.o deffs.o fssnapsup.o
	$(LINK.c) -o $@ switchout.o deffs.o fssnapsup.o $(LDLIBS) -ldiskmgt
	$(POST_PROCESS)

install: $(FSLIB) .WAIT $(SUBDIRS) .WAIT install_local

install_local:	all_local $(ROOTSBINPROG) $(ROOTUSRSBINF) $(ROOTUSRSBINCLRI) \
		$(ROOTUSRSBINFF) $(ROOTETCMNTTAB) $(ROOTETCDEFAULTFILES) \
		$(SYMETC2SBIN) $(SYMETC2USRSBIN) \
		$(SYMUSRBIN2USRSBIN) $(SYMUSRXPG4BIN2USRSBIN) $(SYMDEVNM) \
		$(ROOTUSRSBINLINKS)

# Links from /etc to /sbin such as /etc/mount -> ../sbin/mount
$(SYMETC2SBIN):
	-$(RM) $@; $(SYMLINK) ../sbin/$(@F) $@

# Links from /etc to /usr/sbin such as /etc/clri -> ../usr/sbin/clri
$(SYMETC2USRSBIN):
	-$(RM) $@; $(SYMLINK) ../usr/sbin/$(@F) $@

# Links from /usr/bin to /usr/sbin such as /usr/bin/df -> ../sbin/df
$(SYMUSRBIN2USRSBIN):
	-$(RM) $@; $(SYMLINK) ../sbin/$(@F) $@

# Links from /usr/xpg4/bin to /usr/sbin such as /usr/xpg4/bin/df -> ../sbin/df
$(SYMUSRXPG4BIN2USRSBIN):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

# Links from /usr/sbin to /sbin such as /usr/sbin/mount -> ../../sbin/mount
$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

# Symlink from devnm to df in /usr/sbin
$(SYMDEVNM):
	-$(RM) $@; $(SYMLINK) ./df $@

# Multiple names for switchout (clri, dcopy, fsdb, labelit, mkfs)
$(ROOTUSRSBINCLRI):	$(ROOTUSRSBIN)/clri
	-$(RM) $@; $(SYMLINK) ./clri $@

$(MNTTAB):
	touch $(MNTTAB)

fs.dfl:
	$(RM) $@; $(ECHO) "LOCAL=ufs" >$@

# Multiple names for ff (ncheck)
$(ROOTUSRSBINFF):	$(ROOTUSRSBIN)/ff
	-$(RM) $@; $(SYMLINK) ./ff $@

clean: $(SUBDIRS) .WAIT clean_local
clean_local:
	$(RM) $(CLEANFILES)

clobber: $(SUBDIRS) .WAIT clobber_local
clobber_local:	clean_local
	$(RM) $(PROG) $(ROOTFS_PROG) $(SPPROG) $(MNTTAB) $(DEFAULTFILES) \
	$(CLOBBERFILES)

lint:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(MFLAGS) $(TARGET)

FRC:
