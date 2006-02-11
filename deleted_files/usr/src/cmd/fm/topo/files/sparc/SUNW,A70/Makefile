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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

include ../../../../../Makefile.cmd

TOPOFILE = platform.topo
TOPOINCFILES = pcidev.topo pciexdev.topo
TOPOSRCDIR = SUNW,Sun-Fire-T200
TOPOTARGDIR = SUNW,A70
ROOT_TOPO_ROOT = $(ROOT)/usr/lib/fm/topo
ROOT_TOPO_SDIR = $(ROOT_TOPO_ROOT)/$(TOPOSRCDIR)
ROOT_TOPO_DIR = $(ROOT_TOPO_ROOT)/$(TOPOTARGDIR)
ROOT_TOPOFILE = $(TOPOFILE:%=$(ROOT_TOPO_DIR)/%)
ROOT_TOPOINCTARG = $(TOPOINCFILES:%=$(ROOT_TOPO_DIR)/%)

include ../../../Makefile.rootdirs

all:

install:= FILEMODE =	0444

install: $(ROOT_TOPOFILE) $(ROOT_TOPOINCTARG)

clobber:
	$(RM) $(ROOT_TOPOFILE) $(ROOT_TOPOINCTARG)

clean install_h lint _msg:

$(ROOT_TOPO_DIR)/%: $(ROOT_TOPO_SDIR)/%
	$(RM) $@; $(LN) $< $@
