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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
# lib/libmd5_psr/Makefile
#

include $(SRC)/Makefile.master

SUBDIRS= spec .WAIT $(MACH) $(BUILD64) $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install

.KEEP_STATE:

.PARALLEL: $(MACH) $(MACH64)

all clean clobber install: $(SUBDIRS)

spec $(MACH) $(MACH64): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

#
# Empty targets.
# lint is an empty target since md5.c is already linted
# up and down in the kernel and a lint library is already
# created in lib/libmd5.
#
_msg install_h check lint:

FRC:
