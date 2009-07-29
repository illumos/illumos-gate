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
# Despite the name, this directory doesn't contain the Java Virtual Machine.
# It only contains base OS/Solaris files for improved integration of a
# Java Virtual Machine.
#

include ../Makefile.cmd

ADMINFILES=	default_java

DIRMODE=	755
FILEMODE=	444

SADM_DIR=	$(ROOT)/var/sadm
SYSTEM_DIR=	$(SADM_DIR)/system
ADMIN_DIR=	$(SYSTEM_DIR)/admin

ROOTDIRS=	$(SADM_DIR) $(SYSTEM_DIR) $(ADMIN_DIR)

ROOTADMINFILES=	$(ADMINFILES:%=$(ADMIN_DIR)/%)

.KEEP_STATE:

all:

install: all $(ROOTDIRS) $(ROOTADMINFILES)

clean:

lint:

$(ROOTDIRS):
	$(INS.dir)

$(ADMIN_DIR)/%: %
	$(INS.file)

include ../Makefile.targ
