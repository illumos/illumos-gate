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

LIBNAME =	libWBEMdisk
LIBRARY	=	$(LIBNAME).so
PROG =		$(LIBRARY)
MSG_DOMAIN =	CIM_$(LIBNAME)
TMPFILE =	classes.tmp
TMPFILE1 =	assocclasses.tmp

PROV_OBJECTS = \
	../assoc/Solaris_DiskPartitionBasedOnDisk.o \
	../assoc/Sol_DiskPartitionBasedOnFDisk.o \
	../assoc/Solaris_MediaPresent.o \
	../assoc/Solaris_RealizesExtent.o \
	../assoc/Solaris_RealizesDiskDrive.o \
	../assoc/Solaris_SCSIInterface.o \
	../assoc/Solaris_IDEInterface.o \
	../assoc/Solaris_MPXIOInterface.o \
	../assoc/Sol_MPXIOCtrlrLogicalIdentity.o \
	../assoc/Solaris_MPXIOComponent.o \
	../controller/Solaris_USBSCSIController.o \
	../controller/Solaris_SCSIController.o \
	../controller/Solaris_MPXIOController.o \
	../controller/Solaris_IDEController.o \
	../controller/Solaris_GenericController.o \
	../common/util.o \
	../common/drive_descriptors.o \
	../common/partition_descriptors.o \
	../common/logicaldisk_descriptors.o \
	../common/mpxiogroup_descriptors.o \
	../common/ctrl_descriptors.o \
	../common/partbasedon_descriptors.o \
	../common/mediapresent_descriptors.o \
	../common/methods.o \
	../common/disk_descriptors.o \
	../common/realizesextent_descriptors.o \
	../common/realizesdiskdrive_descriptors.o \
	../disk/Solaris_Disk.o \
	../diskdrive/Solaris_DiskDrive.o \
	../diskpartition/Solaris_DiskPartition.o \
	../logicaldisk/Solaris_LogicalDisk.o \
	../mpxio/Solaris_MPXIOGroup.o

# Just add the name of your provider 
# to this list.
# IMPORTANT: 
# $(LIBNAME) MUST be the last entry

WBEM_DISK_CLASSES =	Solaris_DiskDrive \
			Solaris_DiskPartition \
			Solaris_Disk \
			Solaris_LogicalDisk \
			Solaris_SCSIController \
			Solaris_IDEController \
			Solaris_USBSCSIController \
			Solaris_MPXIOController \
			Solaris_GenericController \
			Solaris_DiskPartitionBasedOnDisk \
			Solaris_DiskPartitionBasedOnFDisk \
			Solaris_MediaPresent \
			Solaris_RealizesExtent \
			Solaris_RealizesDiskDrive \
			Solaris_SCSIInterface \
			Solaris_MPXIOInterface \
			Solaris_IDEInterface \
			Solaris_MPXIOComponent \
			Solaris_MPXIOGroup \
			Solaris_MPXIOCtrlrLogicalIdentity \
	                $(LIBNAME)

WBEM_DISK_ASSOC_CLASSES =	Solaris_DiskPartitionBasedOnDisk \
				Solaris_DiskPartitionBasedOnFDisk \
				Solaris_MediaPresent \
				Solaris_RealizesExtent \
				Solaris_RealizesDiskDrive \
				Solaris_SCSIInterface \
				Solaris_MPXIOInterface \
				Solaris_IDEInterface \
				Solaris_MPXIOComponent \
				Solaris_MPXIOCtrlrLogicalIdentity \
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

LDLIBS		+= -L/usr/sadm/lib/wbem -lc -lcimapi -ldiskmgt \
			-lnvpair

POFILE		= _lib.po
MSGFILES	= $(OBJECTS:%.o=%.i)

CLEANFILES	= *.tmp master.h classes assocclasses Make.obj libname $(MSGFILES)

CLOBBERFILES	+= $(POFILE)

.KEEP_STATE:

all:	master.h $(LIBRARY)

$(LIBRARY): $(OBJECTS)
	$(CC) -o $@ $(LDFLAGS) \
	$(PROV_OBJECTS) $(OBJECTS) $(LDLIBS)
	$(POST_PROCESS_SO)

catalog: master.h $(POFILE)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

master.h: Makefile header.sh		
	@echo ${WBEM_DISK_CLASSES} > ${TMPFILE}
	@echo ${WBEM_DISK_ASSOC_CLASSES} > ${TMPFILE1}
	sh header.sh

install:	all $(ROOTWBEMPROG)

lint: $(LINT_OBJS)
	$(LINT.c) $(LINTFLAGS) $(LINT_OBJS) $(LINTLIBS)

clean:
		$(RM) $(OBJECTS) $(LIBRARY) $(CLEANFILES) $(LINT_OBJS)

check:
		$(CSTYLE) -p -P $(OBJECTS:%.o=%.c)

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ
