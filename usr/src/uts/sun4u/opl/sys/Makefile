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
# Copyright 2019 Peter Tribble.
#
# uts/sun4u/opl/sys/Makefile
#


UTSBASE	= ../../..

#
# include global definitions
#
include ../Makefile.opl

#
# Override defaults.
#
FILEMODE	 = 644

HDRS=		opl_hwdesc.h

CHKHDRS=	dm2s.h		\
		drmach.h	\
		fiomp.h		\
		mc-opl.h	\
		oplkm.h		\
		oplkm_msg.h	\
		sckm_io.h

OPLMSUHDRS=	oplmsu.h	\
		oplmsu_proto.h

PCICMUHDRS=	pcicmu.h	\
		pcmu_cb.h	\
		pcmu_counters.h	\
		pcmu_ecc.h	\
		pcmu_err.h	\
		pcmu_ib.h	\
		pcmu_pbm.h	\
		pcmu_types.h	\
		pcmu_util.h

SCFDHDRS=	opcioif.h	\
		scfdscpif.h	\
		scfostoescf.h

NGDRHDRS=	$(UTSBASE)/sun4u/ngdr/sys/dr.h \
		$(UTSBASE)/sun4u/ngdr/sys/dr_util.h

ROOTHDRS=	$(HDRS:%=$(USR_OPL_ISYS_DIR)/%)

ROOTDIR=	$(ROOT)/usr/share/src
ROOTDIRS=	$(ROOTDIR)/uts $(ROOTDIR)/uts/$(PLATFORM)

CHECKHDRS=	$(HDRS:%.h=%.check) \
		$(CHKHDRS:%.h=%.check) \
		$(OPLMSUHDRS:%.h=oplmsu/%.check) \
		$(PCICMUHDRS:%.h=pcicmu/%.check) \
		$(SCFDHDRS:%.h=scfd/%.check) \
		$(NGDRHDRS:%.h=%.check)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS) $(ROOTHDRS)

install_h: $(ROOTDIRS) .WAIT $(ROOTHDRS) $(ROOTLINK)

check:	$(CHECKHDRS)

#
# install rules
#
$(USR_OPL_ISYS_DIR)/%:	% $(USR_OPL_ISYS_DIR)
	$(INS.file)

FRC:

include ../Makefile.targ
