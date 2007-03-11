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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

MODULE = sfx4500-disk
CLASS = arch
ARCH = i86pc
SRCS = sfx4500-disk.c diskmon_conf.c topo_gather.c \
	fault_mgr.c hotplug_mgr.c dm_platform.c \
	schg_mgr.c fault_analyze.c scsi_util.c util.c

include ../../Makefile.plugin
LINTFLAGS += -I. -I$(SRC)/lib/fm/topo/modules/i86pc/sata -L$(ROOT)/usr/lib/fm
CFLAGS += -I. -I$(SRC)/lib/fm/topo/modules/i86pc/sata
LDLIBS += -lsysevent -lnvpair -lsmbios -lcfgadm -ltopo -luutil -lipmi
LDFLAGS += -L$(ROOT)/usr/lib/fm -R/usr/lib/fm
