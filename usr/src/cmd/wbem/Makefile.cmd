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
# cmd/wbem/Makefile.cmd
#
# Definitions common to command source for wbem provider helper commands.
#
# include global definitions; SRC should be defined in the shell.
# SRC is needed until RFE 1026993 is implemented.


include $(SRC)/cmd/wbem/Makefile.com

ROOTWBEM32=     $(ROOTWBEM)/$(MACH32)
ROOTWBEM64=     $(ROOTWBEM)/$(MACH64)

ROOTWBEMPROG32= $(PROG:%=$(ROOTWBEM32)/%)
ROOTWBEMPROG64= $(PROG:%=$(ROOTWBEM64)/%)

WBEMTOOLDIRS=	$(ROOTWBEM32)
WBEMTOOLDIRS += $(BUILD64)$(ROOTWBEM64)

$(ROOTWBEM32) $(ROOTWBEM64): $(ROOTWBEMDIRS)
	$(INS.dir)

DIRMODE= 755
FILEMODE= 755

$(ROOTWBEM32)/%: %
	$(INS.file)

$(ROOTWBEM64)/%: %
	$(INS.file)
