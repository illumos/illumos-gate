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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2013 Garrett D'Amore <garrett@damore.org>
#
# lib/libsmedia/plugins/Makefile


SUBDIRS = \
	blkdev \
	scsi \
	floppy

def             :=      TARGET= def
all             :=      TARGET= all
install         :=      TARGET= install
clean           :=      TARGET= clean
clobber         :=      TARGET= clobber
lint            :=      TARGET= lint
modlintlib      :=      TARGET= modlintlib
clean.lint      :=      TARGET= clean.lint
check           :=      TARGET= check
install_h       :=      TARGET= install_h
catalog       	:=      TARGET= catalog

all install install_h clean clobber lint catalog : $(SUBDIRS)

$(SUBDIRS) : FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC : 

