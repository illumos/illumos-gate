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
# Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
#

MANIFEST=	client.xml
SVCMETHOD=	smb-client

include $(SRC)/cmd/Makefile.cmd

ETCSECURITYFILES =	exec_attr.d/SUNWsmbfs
ROOTETCSECURITY =	$(ROOT)/etc/security
$(ROOTETCSECURITY) :=   DIRMODE = 0755
ROOTETCSECURITYFILES =  $(ETCSECURITYFILES:%=$(ROOTETCSECURITY)/%)
$(ROOTETCSECURITYFILES) := FILEMODE = 0644

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKSMB)

all lint:

install:	$(ROOTMANIFEST) $(ROOTSVCMETHOD) $(ROOTETCSECURITYFILES)

$(ROOTETCSECURITY)/exec_attr.d/%:%
	$(INS.file)

clean:

clobber:

check:		$(CHKMANIFEST)

include $(SRC)/cmd/Makefile.targ
