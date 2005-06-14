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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

#
# Definitions for targets shared by some subdirs, which have
# dependencies in rcap/common, the path to which must be the value of
# COMMON_DIR.
#

LFLAGS=		-t -v
YFLAGS=		-d -v

rcapd_conf.o := CFLAGS   += -erroff=E_STATEMENT_NOT_REACHED
rcapd_conf.o := CFLAGS64 += -erroff=E_STATEMENT_NOT_REACHED

rcapd_conf.c: $(COMMON_DIR)/rcapd_conf.l
	$(RM) rcapd_conf.c
	$(LEX) $(LFLAGS) $(COMMON_DIR)/rcapd_conf.l > $@

rcapd_conf.o: rcapd_conf.c

#
# Switching the order of these would have the undesired effect of having
# the .c.l rule be used to build $(COMMON_DIR)/rcapd_conf.c from
# $(COMMON_DIR)/rcapd_conf.l, instead of building ./rcapd_conf.c.
#
%.o: %.c
	$(COMPILE.c) $<

%.o: $(COMMON_DIR)/%.c
	$(COMPILE.c) $<
%.po: $(COMMON_DIR)/%.c
	$(COMPILE.cpp) $< > $<.i
	$(BUILD.po)
