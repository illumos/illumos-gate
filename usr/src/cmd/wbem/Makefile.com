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
# cmd/wbem/Makefile.com
#
# Definitions common to both helper commands and providers.
#

include $(SRC)/cmd/Makefile.cmd

ROOTSADM=       $(ROOT)/usr/sadm
ROOTMOF=    	$(ROOTSADM)/mof
ROOTSADMLIB=    $(ROOTSADM)/lib
ROOTWBEM=       $(ROOTSADMLIB)/wbem
ROOTWBEMINC=	/usr/sadm/lib/wbem/include
ROOTUSRMENU=	$(ROOT)/usr/lib/locale/C

ROOTWBEMPROG=   $(PROG:%=$(ROOTWBEM)/%)
ROOTMOFPROG=	$(PROG:%=$(ROOTMOF)/%)

ROOTWBEMDIRS=	$(ROOTSADM) $(ROOTSADMLIB) $(ROOTWBEM) $(ROOTMOF)

DIRMODE= 755
FILEMODE= 755

$(ROOTMOFPROG) := FILEMODE= 644

$(ROOTWBEMDIRS):
	$(INS.dir)

$(ROOTWBEM)/%: %
	$(INS.file)

$(ROOTMOF)/%: %
	$(INS.file)
