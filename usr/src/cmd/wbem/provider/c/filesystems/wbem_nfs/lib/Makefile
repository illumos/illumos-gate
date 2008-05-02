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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/cmd/wbem/Makefile.wbem

LIBNAME =	libWBEMnfs
LIBRARY	=	$(LIBNAME).so
PROG =		$(LIBRARY)
MSG_DOMAIN =	CIM_$(LIBNAME)
TMPFILE =	classes.tmp
TMPFILE1 =	assocclasses.tmp

PROV_OBJECTS = \
	../nfs_filesystem/Solaris_NFS.o \
	../assoc/Solaris_PersistentShareForSystem.o \
	../assoc/Solaris_HostedShare.o \
	../assoc/Solaris_NFSMount.o \
	../assoc/Solaris_NFSShareEntry.o \
	../assoc/Solaris_SharedFileSystem.o \
	../assoc/Solaris_NFSShareSecurityModes.o \
	../assoc/common_functions.o \
	../nfs_share/Solaris_NFSShare.o \
	../nfs_share/Solaris_NFSShareSecurity.o \
	../nfs_share/Solaris_PersistentShare.o \
	../nfs_share/Solaris_ShareService.o \
	../nfs_mount/Solaris_MountService.o \
	../common/nfsprov_methods.o \
	../common/createprop_methods.o \
	../../common/mount_methods/mountprov_methods.o \
	../../common/cmdgeneration/cmdgen.o \
	../../common/cmdgeneration/mount/cmdgen_mount.o \
	../../common/cmdgeneration/mount/nfs/cmdgen_mount_nfs.o \
	../../common/cmdgeneration/mount/cmdgen_mountall.o \
	../../common/cmdgeneration/umount/cmdgen_umount.o \
	../../common/cmdgeneration/umount/cmdgen_umountall.o \
	../../common/cmdgeneration/share/cmdgen_share.o \
	../../common/cmdgeneration/share/cmdgen_shareall.o \
	../../common/cmdgeneration/share/nfs/cmdgen_share_nfs.o \
	../../common/cmdgeneration/unshare/cmdgen_unshare.o \
	../../common/cmdgeneration/unshare/cmdgen_unshareall.o \
	../../common/cmdgeneration/unshare/nfs/cmdgen_unshare_nfs.o \
	../../../wbem_disk/common/util.o

# Just add the name of your provider 
# to this list.
# IMPORTANT: 
# $(LIBNAME) MUST be the last entry

# Add All providers here
WBEM_NFS_CLASSES =	Solaris_NFS \
			Solaris_NFSMount \
			Solaris_NFSShareEntry \
			Solaris_SharedFileSystem \
			Solaris_NFSShareSecurityModes \
			Solaris_NFSShare \
			Solaris_NFSShareSecurity \
			Solaris_PersistentShare \
			Solaris_MountService \
			Solaris_ShareService \
			Solaris_PersistentShareForSystem \
			Solaris_HostedShare \
	                $(LIBNAME)

# Add all association providers here
WBEM_NFS_ASSOC_CLASSES =	Solaris_PersistentShareForSystem \
				Solaris_HostedShare \
				Solaris_NFSMount \
				Solaris_NFSShareEntry \
				Solaris_SharedFileSystem \
				Solaris_NFSShareSecurityModes \
	                	$(LIBNAME)

OBJECTS =	libDispatch.o \
		localFunc.o

LINT_OBJS	= $(OBJECTS:%.o=%.ln)

GENERAL	=	$(ROOTWBEMINC) \
		$(SRC)/cmd/wbem/provider/c/include

CPPFLAGS	+= -I. $(GENERAL:%=-I%) -DPORTMAP -D_REENTRANT -Dpic -D_TS_ERRNO

CFLAGS		+= $(XREGSFLAG) $(C_PICFLAGS)

LINTFLAGS	+= -um
LINTLIBS	= $(LDLIBS.cmd)

LDFLAGS		+= -Mmapfile $(GSHARED) -R/usr/sadm/lib/wbem \
		    $(ZTEXT) $(ZDEFS) $(SOFLAGS)

LDLIBS		+= -L/usr/sadm/lib/wbem -lc -lcimapi -lfsmgt 

POFILE		= _lib.po
MSGFILES	= $(OBJECTS:%.o=%.i)

CLOBBERFILES	+= $(POFILE)

CLEANFILES	= *.tmp master.h classes assocclasses Make.obj libname $(MSGFILES)


all:=		TARGET =	all
install:=	TARGET =	install

.KEEP_STATE:

all:	master.h $(LIBRARY)

$(LIBRARY): $(OBJECTS)
	$(CC) -o $@ $(LDFLAGS) \
	$(PROV_OBJECTS) $(OBJECTS) $(LDLIBS)
	$(POST_PROCESS_SO)

master.h:	Makefile header.sh
		@echo ${WBEM_NFS_CLASSES} > ${TMPFILE}
		@echo ${WBEM_NFS_ASSOC_CLASSES} > ${TMPFILE1}
		sh header.sh

install:	all $(ROOTWBEMPROG)

lint: $(LINT_OBJS)
	$(LINT.c) $(LINTFLAGS) $(LINT_OBJS) $(LINTLIBS)

clean:
		$(RM) $(OBJECTS) $(LIBRARY) $(CLEANFILES) $(LINT_OBJS)

check:
		$(CSTYLE) -p -P $(OBJECTS:%.o=%.c)

catalog:	master.h $(POFILE)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ
