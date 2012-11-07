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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# to be included AFTER cmd/Makefile.cmd or lib/Makefile.lib
#

TOP = $(SRC)/cmd/pcidr
INSTALLDIR = /usr/lib/pci

#############################################################################
### used by macros in Makefile.cmd/lib

# There should be a mapfile here
MAPFILES =

HDRDIR = $(TOP)
HDRS_SH = cd $(HDRDIR); ls *.h
HDRS = $(HDRS_SH:sh)

ROOTLIBDIR = $(ROOT)/$(INSTALLDIR)
ROOTCMDDIR = $(ROOTLIBDIR)
#############################################################################

CPPFLAGS += -D_REENTRANT -I$(HDRDIR)

CERRWARN += -_gcc=-Wno-type-limits

# Note that LDFLAGS is NOT used in the build rules for shared objects!
# LDLIBS is limited to -L and -l options; all other options must be added to
# DYNFLAGS for shared objects

LDLIBS += -lc
