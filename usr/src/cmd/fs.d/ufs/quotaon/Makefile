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
# Copyright 2015 Nexenta Systems, Inc. All rights reserved.
#
# cmd/fs.d/ufs/quotaon/Makefile

FSTYPE=		ufs
LIBPROG=	quotaon
QUOTAOFF=	quotaoff
ATTMK=		$(LIBPROG)

OTHERINSTALL=	$(ROOTLIBFSTYPE)/$(QUOTAOFF) \
		$(ROOTUSRSBIN)/$(LIBPROG) $(ROOTUSRSBIN)/$(QUOTAOFF)

LINKVALUEON=	../lib/fs/$(FSTYPE)/$(LIBPROG)
LINKVALUEOFF=	../lib/fs/$(FSTYPE)/$(QUOTAOFF)

include		../../Makefile.fstype

$(ROOTINIT_SCRIPT) :=	FILEMODE = 0744

CPPFLAGS +=	-D_LARGEFILE64_SOURCE
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-function

lint:		lint_PROG

$(ROOTLIBFSTYPE)/$(QUOTAOFF):	$(ROOTLIBFSTYPE)/$(LIBPROG) 
		-$(RM) $@; $(LN) $(ROOTLIBFSTYPE)/$(LIBPROG) $@

$(ROOTUSRSBIN)/$(LIBPROG):
		-$(RM) $@; $(SYMLINK) $(LINKVALUEON) $@

$(ROOTUSRSBIN)/$(QUOTAOFF):
		-$(RM) $@; $(SYMLINK) $(LINKVALUEOFF) $@
