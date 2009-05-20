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
#

MKNTFS=		mkntfs
NTFSCAT=	ntfscat
NTFSCLONE=	ntfsclone
NTFSCLUSTER=	ntfscluster
NTFSCMP=	ntfscmp
NTFSCP=		ntfscp
NTFSFIX=	ntfsfix
NTFSINFO=	ntfsinfo
NTFSLABEL=	ntfslabel
NTFSLS=		ntfsls
NTFSRESIZE=	ntfsresize
NTFSUNDELETE=	ntfsundelete

include		../Makefile.cmd

C99MODE=	$(C99_ENABLE)
CERRWARN +=	-erroff=E_ATTRIBUTE_PARAM_UNDEFINED
CERRWARN +=	-erroff=E_ENUM_VAL_OVERFLOWS_INT_MAX
CERRWARN +=	-erroff=E_STRUCT_DERIVED_FROM_FLEX_MBR

CPPFLAGS +=	-DHAVE_CONFIG_H \
		-I. \
		-I../../lib/libntfs/common/include/ntfs

MKNTFSOBJS=	attrdef.o boot.o sd.o mkntfs.o utils.o
NTFSCATOBJS=	ntfscat.o utils.o
NTFSCLONEOBJS=	ntfsclone.o utils.o
NTFSCLUSTEROBJS=ntfscluster.o cluster.o utils.o
NTFSCMPOBJS=	ntfscmp.o utils.o
NTFSCPOBJS=	ntfscp.o utils.o
NTFSFIXOBJS=	ntfsfix.o utils.o
NTFSINFOOBJS=	ntfsinfo.o utils.o
NTFSLABELOBJS=	ntfslabel.o utils.o
NTFSLSOBJS=	ntfsls.o utils.o
NTFSRESIZEOBJS=	ntfsresize.o utils.o
NTFSUNDELETEOBJS=ntfsundelete.o utils.o

LDLIBS +=	../../lib/libntfs/i386/libntfs.so.10

ROOTPROG=	$(MKNTFS:%=$(ROOTUSRSBIN)/%) \
		$(NTFSCAT:%=$(ROOTUSRSBIN)/%) \
		$(NTFSCLONE:%=$(ROOTUSRSBIN)/%) \
		$(NTFSCLUSTER:%=$(ROOTUSRSBIN)/%) \
		$(NTFSCMP:%=$(ROOTUSRSBIN)/%) \
		$(NTFSCP:%=$(ROOTUSRSBIN)/%) \
		$(NTFSFIX:%=$(ROOTUSRSBIN)/%) \
		$(NTFSINFO:%=$(ROOTUSRSBIN)/%) \
		$(NTFSLABEL:%=$(ROOTUSRSBIN)/%) \
		$(NTFSLS:%=$(ROOTUSRSBIN)/%) \
		$(NTFSRESIZE:%=$(ROOTUSRSBIN)/%) \
		$(NTFSUNDELETE:%=$(ROOTUSRSBIN)/%)

.KEEP_STATE:
all:		$(MKNTFS) $(NTFSCAT) $(NTFSCLONE) $(NTFSCLUSTER) \
		$(NTFSCMP) $(NTFSCP) $(NTFSFIX) $(NTFSINFO) \
		$(NTFSLABEL) $(NTFSLS) $(NTFSRESIZE) $(NTFSUNDELETE)

$(MKNTFS):	$(MKNTFSOBJS)
	$(LINK.c) -o $(MKNTFS) $(MKNTFSOBJS) $(LDLIBS) -luuid
	$(POST_PROCESS)

$(NTFSCAT):	$(NTFSCATOBJS)
	$(LINK.c) -o $(NTFSCAT) $(NTFSCATOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSCLONE):	$(NTFSCLONEOBJS)
	$(LINK.c) -o $(NTFSCLONE) $(NTFSCLONEOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSCLUSTER):	$(NTFSCLUSTEROBJS)
	$(LINK.c) -o $(NTFSCLUSTER) $(NTFSCLUSTEROBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSCMP):	$(NTFSCMPOBJS)
	$(LINK.c) -o $(NTFSCMP) $(NTFSCMPOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSCP):	$(NTFSCPOBJS)
	$(LINK.c) -o $(NTFSCP) $(NTFSCPOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSFIX):	$(NTFSFIXOBJS)
	$(LINK.c) -o $(NTFSFIX) $(NTFSFIXOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSINFO):	$(NTFSINFOOBJS)
	$(LINK.c) -o $(NTFSINFO) $(NTFSINFOOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSLABEL):	$(NTFSLABELOBJS)
	$(LINK.c) -o $(NTFSLABEL) $(NTFSLABELOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSLS):	$(NTFSLSOBJS)
	$(LINK.c) -o $(NTFSLS) $(NTFSLSOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSRESIZE):	$(NTFSRESIZEOBJS)
	$(LINK.c) -o $(NTFSRESIZE) $(NTFSRESIZEOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NTFSUNDELETE):	$(NTFSUNDELETEOBJS)
	$(LINK.c) -o $(NTFSUNDELETE) $(NTFSUNDELETEOBJS) $(LDLIBS)
	$(POST_PROCESS)

install:	all $(ROOTPROG)

clean:
	$(RM) $(MKNTFS) $(MKNTFSOBJS) \
		$(NTFSCAT) $(NTFSCATOBJS) \
		$(NTFSCLONE) $(NTFSCLONEOBJS) \
		$(NTFSCLUSTER) $(NTFSCLUSTEROBJS) \
		$(NTFSCMP) $(NTFSCMPOBJS) \
		$(NTFSCP) $(NTFSCPOBJS) \
		$(NTFSFIX) $(NTFSFIXOBJS) \
		$(NTFSINFO) $(NTFSINFOOBJS) \
		$(NTFSLABEL) $(NTFSLABELOBJS) \
		$(NTFSLS) $(NTFSLSOBJS) \
		$(NTFSRESIZE) $(NTFSRESIZEOBJS) \
		$(NTFSUNDELETE) $(NTFSUNDELETEOBJS)

#
# This open source is exempted from lint
#
lint:

include		../Makefile.targ
