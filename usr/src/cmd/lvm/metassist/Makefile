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
# ident	"%Z%%M%	%I%	%E% SMI"
#

METASSIST_TOPLEVEL = .

PROG = metassist

# Subdirectories with message catalogs
POSUBDIRS = \
	common \
	xml \
	layout \
	controller

# For message catalog
POFILES = $(POSUBDIRS:%=%/%p.po)

# Subdirectories that must be made
SUBDIRS = \
	scripts \
	sysfiles \
	$(POSUBDIRS)

SUBOBJS = \
	common/volume_defaults.o \
	common/volume_devconfig.o \
	common/volume_dlist.o \
	common/volume_error.o \
	common/volume_nvpair.o \
	common/volume_output.o \
	common/volume_request.o \
	common/volume_string.o \
	xml/xml_convert.o \
	layout/layout.o \
	layout/layout_concat.o \
	layout/layout_device_cache.o \
	layout/layout_device_util.o \
	layout/layout_discovery.o \
	layout/layout_dlist_util.o \
	layout/layout_hsp.o \
	layout/layout_messages.o \
	layout/layout_mirror.o \
	layout/layout_request.o \
	layout/layout_slice.o \
	layout/layout_stripe.o \
	layout/layout_svm_util.o \
	layout/layout_validate.o \
	controller/getopt_ext.o \
	controller/metassist.o

include $(METASSIST_TOPLEVEL)/../../Makefile.cmd
include $(METASSIST_TOPLEVEL)/Makefile.env

LDLIBS += -ldiskmgt -lmeta -lnvpair -lxml2 -lxslt -lm

POFILE = metassistp.po

include $(METASSIST_TOPLEVEL)/Makefile.targ

# Build master .po file from subdirs' .po files
$(POFILE): $(POSUBDIRS) .WAIT $(POFILES)
	$(BUILDPO.pofiles)
