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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2022 Garrett D'Amore
#
# cmd/cmd-inet/etc/sock2path.d/Makefile
#

SOCK2PATHFILES= \
    driver%2Fnetwork%2Fbpf \
    driver%2Fnetwork%2Frds \
    driver%2Fnetwork%2Frdsv3 \
    driver%2Fnetwork%2Fsdp \
    system%2Fkernel

include ../../../Makefile.cmd

ETCSOCK2PATHDIR=	$(ROOTETC)/sock2path.d
ETCSOCK2PATHFILES=	$(SOCK2PATHFILES:%=$(ETCSOCK2PATHDIR)/%)

FILEMODE=	0644

.KEEP_STATE:

all:
install:	$(ETCSOCK2PATHDIR) $(ETCSOCK2PATHFILES)

$(ETCSOCK2PATHDIR)/%: %
		$(INS.file)

$(ETCSOCK2PATHDIR):
		$(INS.dir)
