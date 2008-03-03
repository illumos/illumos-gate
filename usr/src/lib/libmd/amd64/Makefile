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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY= libmd.a

MD5_PSR_OBJECTS = md5_amd64.o
SHA1_PSR_OBJECTS = sha1-x86_64.o

include ../Makefile.com
include $(SRC)/lib/Makefile.lib.64

CLEANFILES += md5_amd64.s sha1-x86_64.s

# This prevents <sys/asm_linkage.h> from including C source:
AS_CPPFLAGS += -D_ASM

install: all $(ROOTLIBS64) $(ROOTLINKS64) $(ROOTLINT64)

pics/md5_amd64.o: md5_amd64.s
	$(COMPILE.s) -o $@ ${@F:.o=.s}
	$(POST_PROCESS_O)

pics/sha1-x86_64.o: sha1-x86_64.s
	$(COMPILE.s) -o $@ ${@F:.o=.s}
	$(POST_PROCESS_O)

md5_amd64.s: $(COMDIR)/md5/amd64/md5_amd64.pl
	$(PERL) $? $@

sha1-x86_64.s: $(COMDIR)/sha1/amd64/sha1-x86_64.pl
	$(PERL) $? $@
