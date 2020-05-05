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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# lib/efcode/efdaemon/Makefile

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64

EFCODEDIR = $(ROOT)/usr/lib/efcode
EFCODEDIR64 = $(EFCODEDIR)/$(MACH64)

CPPFLAGS += -DDEBUG -DFCODE_INTERNAL
CPPFLAGS += -I ../include -I $(ROOT)/usr/platform/sun4u/include

CERRWARN += -_gcc=-Wno-unused-variable

PROG	= efdaemon
EFTARGETS += $(EFCODEDIR64)/$(PROG)
EFTARGETS += $(EFCODEDIR)/efcode.sh

MFSTDIR = $(ROOT)/lib/svc/manifest/platform/sun4u
MFSTDIR_SUN4V = $(ROOT)/lib/svc/manifest/platform/sun4v
MANIFEST = efdaemon.xml
MANIFEST_SUN4V = efdaemon_sun4v.xml
EFTARGETS += $(MFSTDIR)/$(MANIFEST)
EFTARGETS += $(MFSTDIR_SUN4V)/$(MANIFEST_SUN4V)

$(MFSTDIR)/$(MANIFEST) := FILEMODE = 0444
$(MFSTDIR_SUN4V)/$(MANIFEST_SUN4V) := FILEMODE = 0444

all:	$(PROG)

clean:
	-$(RM) $(PROG)
	-$(RM) $(MFSTDIR)/$(MANIFEST)
	-$(RM) $(MFSTDIR_SUN4V)/$(MANIFEST)
	-$(RM) $(MFSTDIR_SUN4V)/$(MANIFEST_SUN4V)

$(EFCODEDIR64)/%: %
	$(INS.file)

$(EFCODEDIR)/%.sh: %.sh
	$(INS.file)

$(MFSTDIR)/%: %
	$(INS.file)

$(MFSTDIR_SUN4V)/%: %
	$(INS.file)

install: all .WAIT $(EFTARGETS)
	-$(MV) $(MFSTDIR_SUN4V)/$(MANIFEST_SUN4V) $(MFSTDIR_SUN4V)/$(MANIFEST)

.KEEP_STATE:

include $(SRC)/cmd/Makefile.targ
