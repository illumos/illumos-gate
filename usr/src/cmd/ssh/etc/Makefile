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
#

MANIFEST = ssh.xml
SVCMETHOD = sshd

include ../../Makefile.cmd
include ../Makefile.ssh-common

SSHASKPASS=	$(ROOTLIBSSH)/ssh-askpass
ETCSSHDIR=	$(ROOTETC)/ssh
DIRS=		$(ETCSSHDIR) $(ROOTLIBSSH) $(ROOTLIBSUNSSH)

FILES= sshd_config ssh_config moduli

ETCSSHFILES=	$(FILES:%=$(ETCSSHDIR)/%)

$(ETCSSHFILES) := FILEMODE=	644

ROOTMANIFESTDIR = $(ROOTSVCNETWORK)

$(ETCSSHDIR)/% : %
	$(INS.file)

$(DIRS):
	$(INS.dir)

$(ROOTLIBSSH)/%: %
	$(INS.file)

$(POFILE):

all lint clean clobber _msg:

install: all $(DIRS) $(ETCSSHFILES) $(ROOTMANIFEST) $(ROOTSVCMETHOD) \
	$(SSHASKPASS)

check: $(CHKMANIFEST)

include ../../Makefile.targ
