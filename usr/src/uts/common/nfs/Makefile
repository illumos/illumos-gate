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
# uts/common/nfs/Makefile
#
# include global definitions
#
include ../../../Makefile.master

HDRS=	export.h	lm.h						\
	mount.h		nfs.h		nfssys.h	nfs_acl.h	\
	nfs_clnt.h	nfs_log.h 	nfs_sec.h	nfs4.h		\
	nfs4_attr.h	nfs4_clnt.h	rnode.h		rnode4.h	\
	nfs4_kprot.h	nfs4_db_impl.h	nfs4_idmap_impl.h \
	nfsid_map.h	auth.h		nfs_cmd.h

ROOTDIRS= $(ROOT)/usr/include/nfs

ROOTHDRS= $(HDRS:%=$(ROOTDIRS)/%)

CHECKHDRS= $(HDRS:%.h=%.check)

$(ROOTDIRS)/%: %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: $(ROOTDIRS) $(ROOTHDRS)

$(ROOTDIRS):
	$(INS.dir)

check:	$(CHECKHDRS)
