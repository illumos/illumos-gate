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
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
#

LIBRARY =	libfksmbsrv.a
VERS =		.1

OBJS_LOCAL = \
		fksmb_cred.o \
		fksmb_dt.o \
		fksmb_fem.o \
		fksmb_idmap.o \
		fksmb_init.o \
		fksmb_kdoor.o \
		fksmb_sign_pkcs.o \
		fake_lookup.o \
		fake_nblk.o \
		fake_vfs.o \
		fake_vnode.o \
		fake_vop.o \
		fake_xattr.o \
		reparse.o \
		vncache.o

# See also: $SRC/uts/common/Makefile.files
# NB: Intentionally ommitted, compared w/ the above:
#   smb_cred, smb_fem, smb_idmap, smb_init, smb_kdoor
#
OBJS_FS_SMBSRV = \
		smb_acl.o				\
		smb_alloc.o				\
		smb_authenticate.o			\
		smb_close.o				\
		smb_cmn_rename.o			\
		smb_cmn_setfile.o			\
		smb_common_open.o			\
		smb_common_transact.o			\
		smb_create.o				\
		smb_delete.o				\
		smb_dfs.o				\
		smb_directory.o				\
		smb_dispatch.o				\
		smb_echo.o				\
		smb_errno.o				\
		smb_find.o				\
		smb_flush.o				\
		smb_fsinfo.o				\
		smb_fsops.o				\
		smb_kshare.o				\
		smb_kutil.o				\
		smb_lock.o				\
		smb_lock_byte_range.o			\
		smb_locking_andx.o			\
		smb_logoff_andx.o			\
		smb_mangle_name.o			\
		smb_mbuf_marshaling.o			\
		smb_mbuf_util.o				\
		smb_negotiate.o				\
		smb_net.o				\
		smb_node.o				\
		smb_notify.o				\
		smb_nt_cancel.o				\
		smb_nt_create_andx.o			\
		smb_nt_transact_create.o		\
		smb_nt_transact_ioctl.o			\
		smb_nt_transact_notify_change.o		\
		smb_nt_transact_quota.o			\
		smb_nt_transact_security.o		\
		smb_odir.o				\
		smb_ofile.o				\
		smb_open_andx.o				\
		smb_opipe.o				\
		smb_oplock.o				\
		smb_pathname.o				\
		smb_print.o				\
		smb_process_exit.o			\
		smb_query_fileinfo.o			\
		smb_quota.o				\
		smb_read.o				\
		smb_rename.o				\
		smb_sd.o				\
		smb_seek.o				\
		smb_server.o				\
		smb_session.o				\
		smb_session_setup_andx.o		\
		smb_set_fileinfo.o			\
		smb_signing.o				\
		smb_thread.o				\
		smb_tree.o				\
		smb_trans2_create_directory.o		\
		smb_trans2_dfs.o			\
		smb_trans2_find.o			\
		smb_tree_connect.o			\
		smb_unlock_byte_range.o			\
		smb_user.o				\
		smb_vfs.o				\
		smb_vops.o				\
		smb_vss.o				\
		smb_write.o				\
		\
		smb2_dispatch.o \
		smb2_cancel.o \
		smb2_change_notify.o \
		smb2_close.o \
		smb2_create.o \
		smb2_echo.o \
		smb2_flush.o \
		smb2_ioctl.o \
		smb2_lock.o \
		smb2_logoff.o \
		smb2_negotiate.o \
		smb2_ofile.o \
		smb2_oplock.o \
		smb2_qinfo_file.o \
		smb2_qinfo_fs.o \
		smb2_qinfo_sec.o \
		smb2_qinfo_quota.o \
		smb2_query_dir.o \
		smb2_query_info.o \
		smb2_read.o \
		smb2_session_setup.o \
		smb2_set_info.o \
		smb2_setinfo_file.o \
		smb2_setinfo_fs.o \
		smb2_setinfo_quota.o \
		smb2_setinfo_sec.o \
		smb2_signing.o \
		smb2_tree_connect.o \
		smb2_tree_disconn.o \
		smb2_write.o

# Can't just link with -lsmb because of user vs kernel API
# i.e. can't call free with mem from kmem_alloc, which is
# what happens if we just link with -lsmb
OBJS_CMN_SMBSRV = \
		smb_inet.o \
		smb_match.o \
		smb_msgbuf.o \
		smb_native.o \
		smb_netbios_util.o \
		smb_oem.o \
		smb_sid.o \
		smb_string.o \
		smb_token.o \
		smb_token_xdr.o \
		smb_utf8.o \
		smb_xdr.o

OBJS_MISC = \
		acl_common.o \
		pathname.o \
		refstr.o \
		smb_status2winerr.o \
		xattr_common.o

OBJECTS = \
	$(OBJS_LOCAL) \
	$(OBJS_FS_SMBSRV) \
	$(OBJS_CMN_SMBSRV) \
	$(OBJS_MISC)

include ../../../Makefile.lib
include ../../Makefile.lib

# Force SOURCEDEBUG
CSOURCEDEBUGFLAGS	= -g
CCSOURCEDEBUGFLAGS	= -g
STRIP_STABS 	= :


# Note: need our sys includes _before_ ENVCPPFLAGS, proto etc.
CPPFLAGS.first += -I../../../libfakekernel/common
CPPFLAGS.first += -I../common

INCS += -I$(SRC)/uts/common
INCS += -I$(SRC)/common/smbsrv
INCS += -I$(SRC)/common

LINTCHECKFLAGS += -erroff=E_INCONS_ARG_DECL2
LINTCHECKFLAGS += -erroff=E_INCONS_VAL_TYPE_DECL2
LINTCHECKFLAGS += -erroff=E_INCONS_VAL_TYPE_USED2

LDLIBS +=	$(MACH_LDLIBS)
LDLIBS +=	-lfakekernel -lidmap -lcmdutils
LDLIBS +=	-lavl -lnvpair -lnsl -lpkcs11 -lreparse -lc

CPPFLAGS += $(INCS) -D_REENTRANT -D_FAKE_KERNEL
CPPFLAGS += -D_FILE_OFFSET_BITS=64
# Always want DEBUG here
CPPFLAGS += -DDEBUG

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-switch

SRCS=   $(OBJS_LOCAL:%.o=$(SRCDIR)/%.c) \
	$(OBJS_FS_SMBSRV:%.o=$(SRC)/uts/common/fs/smbsrv/%.c) \
	$(OBJS_CMN_SMBSRV:%.o=$(SRC)/common/smbsrv/%.c)

all:

pics/%.o:	$(SRC)/uts/common/fs/smbsrv/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/acl_common.o:	   $(SRC)/common/acl/acl_common.c
	$(COMPILE.c) -o $@ $(SRC)/common/acl/acl_common.c
	$(POST_PROCESS_O)

pics/smb_status2winerr.o:  $(SRC)/common/smbclnt/smb_status2winerr.c
	$(COMPILE.c) -o $@ $(SRC)/common/smbclnt/smb_status2winerr.c
	$(POST_PROCESS_O)

pics/pathname.o:	   $(SRC)/uts/common/fs/pathname.c
	$(COMPILE.c) -o $@ $(SRC)/uts/common/fs/pathname.c
	$(POST_PROCESS_O)

pics/refstr.o:		   $(SRC)/uts/common/os/refstr.c
	$(COMPILE.c) -o $@ $(SRC)/uts/common/os/refstr.c
	$(POST_PROCESS_O)

pics/xattr_common.o:	   $(SRC)/common/xattr/xattr_common.c
	$(COMPILE.c) -o $@ $(SRC)/common/xattr/xattr_common.c
	$(POST_PROCESS_O)

# Makefile.targ has rule for $(SRC)/common/smbsrv/%.c

.KEEP_STATE:

include ../../Makefile.targ
include ../../../Makefile.targ
