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

include $(SRC)/cmd/wbem/Makefile.wbem

REG =	Solaris_DMGT1.0.mof Solaris_NFS1.0.mof CIM2.7.mof

DIRMODE= 755
FILEMODE= 644

VARSADM=			$(ROOT)/var/sadm
VARSADMWBEM=			$(ROOT)/var/sadm/wbem
VARSADMWBEMLOGR=		$(ROOT)/var/sadm/wbem/logr
VARSADMWBEMLOGRPREREG=		$(ROOT)/var/sadm/wbem/logr/preReg

REGDIRS=	$(VARSADM) 				\
		$(VARSADMWBEM)	 			\
		$(VARSADMWBEMLOGR)	 		\
		$(VARSADMWBEMLOGRPREREG)

$(REGDIRS):
	$(INS.dir)

ROOTMOFREG=	$(REG:%=$(ROOTMOF)/%)

.KEEP_STATE:

all:

install: $(REGDIRS) $(ROOTMOFREG)

include $(SRC)/cmd/Makefile.targ
