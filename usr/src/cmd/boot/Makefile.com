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
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/cmd/Makefile.cmd

CFLAGS += $(CCVERBOSE)

ROOTBOOT=		$(ROOT)/boot
ROOTBOOTSOLARIS=	$(ROOTBOOT)/solaris
ROOTBOOTSOLARISBIN=	$(ROOTBOOTSOLARIS)/bin

ROOTBOOTSOLARISBINPROG=	$(BOOTPROG:%=$(ROOTBOOTSOLARISBIN)/%)

$(ROOTBOOTSOLARISBINPROG) := OWNER= root
$(ROOTBOOTSOLARISBINPROG) := GROUP= bin
$(ROOTBOOTSOLARISBINPROG) := FILEMODE= 0555

ROOTBOOTSOLARISDATA=	$(DATA:%=$(ROOTBOOTSOLARIS)/%)

$(ROOTBOOTSOLARISDATA) := OWNER= root
$(ROOTBOOTSOLARISDATA) := GROUP= sys
$(ROOTBOOTSOLARISDATA) := FILEMODE= 0644

ROOTUSRSBINLINKS= $(SBINLINKS:%=$(ROOTUSRSBIN)/%)

ROOTBOOTSOLARISBINLINKS= $(SBINLINKS:%=$(ROOTBOOTSOLARISBIN)/%)
