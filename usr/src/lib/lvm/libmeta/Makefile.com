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
# Copyright 2015 Igor Kozhukhov <ikozhukhov@gmail.com>
#

LIBRARY=       	libmeta.a 
VERS=          	.1 
COMMON =	$(SRC)/common/lvm

CMN_OBJS = md_crc.o md_convert.o md_revchk.o

DERIVED_OBJS = \
	mdiox_xdr.o \
	meta_basic_xdr.o \
	metad_clnt.o \
	metad_xdr.o \
	metamed_clnt.o \
	metamed_xdr.o \
	metamhd_clnt.o \
	metamhd_xdr.o \
	mdmn_commd_xdr.o \
	mhdx_xdr.o

LOCAL_OBJS=        \
	metad_svc_stubs.o \
	meta_admin.o \
	meta_attach.o \
	meta_db.o \
	meta_db_balance.o \
	meta_devadm.o \
	meta_devstamp.o \
	meta_error.o \
	meta_getdevs.o \
	meta_hotspares.o \
	meta_import.o \
	meta_init.o \
	meta_lib_prv.o \
	meta_mdcf.o \
	meta_med_err.o \
	meta_mem.o \
	meta_metad.o \
	meta_metad_subr.o \
	meta_med.o \
	meta_mh.o \
	meta_mirror.o \
	meta_mirror_resync.o \
	meta_mn_comm.o \
	meta_mn_changelog.o \
	meta_mn_handlers.o \
	meta_mn_msg_table.o \
	meta_mn_subr.o \
	meta_mount.o \
	meta_name.o \
	meta_nameinfo.o \
	meta_namespace.o \
	meta_notify.o \
	meta_se_notify.o \
	meta_patch.o \
	meta_patch_root.o \
	meta_print.o \
	meta_raid.o \
	meta_raid_resync.o \
	meta_rename.o \
	meta_repartition.o \
	meta_replace.o \
	meta_reset.o \
	meta_resync.o \
	meta_runtime.o \
	meta_set.o \
	meta_set_drv.o \
	meta_set_hst.o \
	meta_set_med.o \
	meta_set_prv.o \
	meta_set_tkr.o \
	meta_setup.o \
	meta_smf.o \
	meta_stat.o \
	meta_statconcise.o \
	meta_sp.o \
	meta_stripe.o \
	meta_systemfile.o \
	meta_tab.o \
	meta_time.o \
	meta_trans.o \
	meta_userflags.o \
	metarpcopen.o \
	metasplitname.o \
	metagetroot.o \
	sdssc_bind.o

SPC_OBJS= meta_check.o

CMN_SRCS =	$(CMN_OBJS:%.o=$(COMMON)/%.c)
LOCAL_SRCS =	$(LOCAL_OBJS:%.o=../common/%.c)
DERIVED_SRCS =	$(DERIVED_OBJS:%.o=%.c)
SPC_SRCS = 	$(SPC_OBJS:%.o=../common/%.c)

OBJECTS64 =	$(LOCAL_OBJS) $(DERIVED_OBJS) $(CMN_OBJS)
OBJECTS =	$(OBJECTS64) $(SPC_OBJS)

include $(SRC)/lib/lvm/Makefile.lvm

MSGSRCS = $(LOCAL_SRCS) $(SPC_SRCS)
MSGFILES = $(MSGSRCS:%.c=%.i)
POFILE = libmeta.po     

DCFILES = ../common/meta_print.po
DCFILE = libmeta.dc

CLOBBERFILES += $(POFILE) $(DCFILE)

# install this library in the root filesystem
include ../../../Makefile.rootfs

LIBS =		$(DYNLIB) $(LINTLIB)
SRCS =		$(CMN_SRCS) $(LOCAL_SRCS) $(DERIVED_SRCS)
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)
lint :=		SRCS = $(CMN_SRCS) $(LOCAL_SRCS) $(SPC_SRCS)
CPPFLAGS +=     -I$(SRC)/lib/lvm/libmeta/common/hdrs
LDLIBS += 	-lnsl -lc -ladm -ldevid -lgen -lefi -ldevinfo -lscf
CLEANFILES += 	$(DERIVED_SRCS) $(MSGFILES) $(DCFILES)

.KEEP_STATE:

BIG_TARGETS = $(OBJECTS64:%=pics/%)

$(BIG_TARGETS) := CPPFLAGS += -D_LARGEFILE_SOURCE=1 -D_FILE_OFFSET_BITS=64

$(LINTLIB) := CPPFLAGS += -D_LARGEFILE_SOURCE=1 -D_FILE_OFFSET_BITS=64

all: $(LIBS)

install debug: all $(ROOTLIBS) $(ROOTLINT) $(ROOTLINKS)

objs/%.o profs/%.o pics/%.o: $(COMMON)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

mdiox_xdr.c: $(SRC)/uts/common/sys/lvm/mdiox.x
	$(RPCGEN) $(RPCGENFLAGS) -c -i 100 $(SRC)/uts/common/sys/lvm/mdiox.x | \
	$(AWK) '{sub(/uts\/common\/sys\/lvm/, "head"); print $$0}' >$@

meta_basic_xdr.c: $(SRC)/uts/common/sys/lvm/meta_basic.x
	$(RPCGEN) $(RPCGENFLAGS) -c $(SRC)/uts/common/sys/lvm/meta_basic.x | \
	$(AWK) '{sub(/uts\/common\/sys\/lvm/, "head"); print $$0}' >$@

metad_clnt.c: $(SRC)/head/metad.x 
	$(RPCGEN) $(RPCGENFLAGS) -l $(SRC)/head/metad.x -o $@

metad_xdr.c: $(SRC)/head/metad.x
	$(RPCGEN) $(RPCGENFLAGS) -c $(SRC)/head/metad.x -o $@

metamed_clnt.c: $(SRC)/uts/common/sys/lvm/metamed.x
	$(RPCGEN) $(RPCGENFLAGS) -l $(SRC)/uts/common/sys/lvm/metamed.x | \
	$(AWK) '{sub(/uts\/common\/sys\/lvm/, "head"); print $$0}' >$@

metamed_xdr.c: $(SRC)/uts/common/sys/lvm/metamed.x 
	$(RPCGEN) $(RPCGENFLAGS) -c $(SRC)/uts/common/sys/lvm/metamed.x | \
	$(AWK) '{sub(/uts\/common\/sys\/lvm/, "head"); print $$0}' >$@

metamhd_clnt.c: $(SRC)/head/metamhd.x 
	$(RPCGEN) $(RPCGENFLAGS) -l $(SRC)/head/metamhd.x -o $@

metamhd_xdr.c: $(SRC)/head/metamhd.x 
	$(RPCGEN) $(RPCGENFLAGS) -c $(SRC)/head/metamhd.x -o $@

mhdx_xdr.c: $(SRC)/uts/common/sys/lvm/mhdx.x
	$(RPCGEN) $(RPCGENFLAGS) -c $(SRC)/uts/common/sys/lvm/mhdx.x | \
	$(AWK) '{sub(/uts\/common\/sys\/lvm/, "head"); print $$0}' >$@

mdmn_commd_xdr.c: $(SRC)/uts/common/sys/lvm/mdmn_commd.x
	$(RPCGEN) -c $(SRC)/uts/common/sys/lvm/mdmn_commd.x -o $@

$(DCFILE):= XGETFLAGS = -c TRANSLATION_NOTE_LC_TIME -t

$(DCFILE): $(DCFILES)
	$(CAT) $(DCFILES) > $(DCFILE)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

_dc: $(DCMSGDOMAINPOFILE)

include $(SRC)/lib/lvm/Makefile.targ
include $(SRC)/Makefile.msg.targ
