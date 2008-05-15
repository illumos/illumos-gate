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
#ident	"%Z%%M%	%I%	%E% SMI"

include ../../Makefile.cmd
include ../Makefile.hal

DTDS =		fdi.dtd.1
XMLDIR =	$(ROOT)/usr/share/lib/xml/dtd
ROOTDTDS =	$(DTDS:%=$(XMLDIR)/%)

$(ROOTDTDS) :=	FILEMODE = 444
$(ROOTDTDS) :=	OWNER = root
$(ROOTDTDS) :=	GROUP = bin

FDIS =		information/10freedesktop/10-camera-ptp.fdi \
		information/10freedesktop/10-cd-dvd-burner.fdi \
		information/10freedesktop/10-usb-card-readers.fdi \
		information/10freedesktop/10-usb-music-players.fdi \
		information/10freedesktop/10-usb-pda.fdi \
		information/10freedesktop/10-usb-zip-drives.fdi \
		information/10freedesktop/10-wireless-mice.fdi \
		policy/10osvendor/10-laptop-panel-mgmt-policy.fdi \
		policy/10osvendor/10-network-attached.fdi \
		policy/10osvendor/10-power-mgmt-policy.fdi \
		policy/10osvendor/10-cpufreq.fdi \
		policy/10osvendor/10-toshiba-buttons.fdi \
		policy/10osvendor/20-storage-methods.fdi \
		policy/10osvendor/20-zfs-methods.fdi \
		preprobe/10osvendor/10-ide-drives.fdi \
		preprobe/10osvendor/20-ignore-fixed-storage.fdi \
		preprobe/10osvendor/20-ignore-lofi.fdi \
		preprobe/10osvendor/20-printers.fdi
FDIDIR =	$(ROOT_HAL_FDI)
ROOTFDIS =	$(FDIS:%=$(FDIDIR)/%)

$(ROOTFDIS) :=	FILEMODE = 444
$(ROOTFDIS) :=	OWNER = root
$(ROOTFDIS) :=	GROUP = bin

all:

install: $(ROOTDTDS) $(ROOTFDIS)

$(XMLDIR)/%: %
	$(INS.file)

$(FDIDIR)/%: %
	$(INS.file)

clean clobber:

FRC:

