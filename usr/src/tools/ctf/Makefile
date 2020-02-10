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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2020 Joyent, Inc.
#

include ../Makefile.tools

SUBDIRS = stabs ctfstrip libctf ctfdiff ctfdump ctfmerge ctfconvert

.PARALLEL: $(SUBDIRS)

all	:= TARGET= all
install	:= TARGET= install
clean	:= TARGET= clean
clobber	:= TARGET= clobber

.KEEP_STATE:

ctfmerge: libctf
ctfdiff: libctf
ctfdump: libctf
ctfconvert: libctf

all clean clobber install: dwarf .WAIT $(SUBDIRS)

dwarf $(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

#
# This is a somewhat arbitrary list.
#
CTFTOOLS_FILES = \
	bin/i386/ctfconvert \
	bin/i386/ctfdiff \
	bin/i386/ctfdump \
	bin/i386/ctfstabs \
	bin/i386/ctfstrip \
	lib/i386/libctf.so \
	lib/i386/libctf.so.1 \
	lib/i386/libdwarf.so \
	lib/i386/libdwarf.so.1 \
	lib/i386/libelf.so \
	lib/i386/libelf.so.1

# CTFTOOLS_TARBALL should be set in the environment
ctftools: install
	cd $(ROOTONBLD) && $(TAR) cvzf $(CTFTOOLS_TARBALL) $(CTFTOOLS_FILES)

FRC:
