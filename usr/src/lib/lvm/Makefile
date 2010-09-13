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
# Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.lib

SUBDIRS =	libmeta .WAIT libpreen libsvm
HDRSUBDIRS = 	libsvm
DCSUBDIRS =	libmeta
MSGSUBDIRS =	libmeta

all	:= TARGET = all
clean	:= TARGET = clean
clobber	:= TARGET = clobber
check	:= TARGET = check
debug	:= TARGET = debug
install	:= TARGET = install
install_h := TARGET = install_h
lint	:= TARGET = lint
_dc	:= TARGET = _dc
_msg	:= TARGET = _msg

.KEEP_STATE:

.PARALLEL: $(SUBDIRS)

all clean clobber debug lint: $(SUBDIRS)

install: $(ROOTDIRS) $(SUBDIRS)

_dc: $(DCSUBDIRS)

check install_h: $(HDRSUBDIRS)

_msg: $(MSGSUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/lib/Makefile.targ
