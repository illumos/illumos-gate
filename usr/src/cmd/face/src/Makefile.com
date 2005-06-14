#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1990,1998 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/face/src/Makefile.com
#
# common makefile included for face definitions and rules

# these first two directories are default, see /usr/src/Targetdirs
# only the rootdirs target in /usr/src/Makefile should make them.
#
ROOTOAMBASE=	$(ROOT)/usr/sadm/sysadm
ROOTADDONS=	$(ROOTOAMBASE)/add-ons

# other common directories
ROOTSAVE=	$(ROOT)/usr/sadm/pkg/face/save
ROOTINTF=	$(ROOTSAVE)/intf_install
ROOTADDONSFACE= $(ROOTADDONS)/face
ROOTFACE=	$(ROOTADDONSFACE)/applmgmt/FACE

ROOTVMSYS=	$(ROOT)/usr/vmsys
ROOTOASYS=	$(ROOT)/usr/oasys

ROOTOABIN=	$(ROOTOASYS)/bin
ROOTINFO=	$(ROOTOASYS)/info
ROOTINFOOH=	$(ROOTOASYS)/info/OH
ROOTEXTERN=	$(ROOTOASYS)/info/OH/externals
ROOTSTD=	$(ROOTVMSYS)/standard
ROOTVMBIN=	$(ROOTVMSYS)/bin
ROOTVMLIB=	$(ROOTVMSYS)/lib

DIRMODE= 755

# common installation rules
#
$(ROOTINTF)/% : %
	$(INS.file)

$(ROOTFACE)/% : %
	$(INS.file)

$(ROOTOASYS)/% : oasys/%
	$(INS.file)

$(ROOTOABIN)/% : %
	$(INS.file)

$(ROOTVMSYS)/% : %
	$(INS.file)

$(ROOTVMBIN)/% : %
	$(INS.file)

$(ROOTVMLIB)/% : %
	$(INS.file)

$(ROOTVMSYS) $(ROOTOASYS):
	$(INS.dir)

$(ROOTINFO) $(ROOTOABIN):	$(ROOTOASYS)
	$(INS.dir)

$(ROOTINFOOH): $(ROOTINFO)
	$(INS.dir)

$(ROOTEXTERN): $(ROOTINFOOH)
	$(INS.dir)

$(ROOTSTD) $(ROOTVMBIN) $(ROOTVMLIB): $(ROOTVMSYS)
	$(INS.dir)
