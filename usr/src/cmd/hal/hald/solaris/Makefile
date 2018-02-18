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

OBJS =		devinfo.o devinfo_ieee1394.o devinfo_misc.o devinfo_pci.o \
		devinfo_storage.o devinfo_usb.o hotplug.o osspec.o sysevent.o \
		devinfo_acpi.o devinfo_cpu.o

SRCS =		$(OBJS:%.o=%.c)

MANIFEST =	hal.xml
SVCMETHOD =	svc-hal

include ../../../Makefile.cmd
include ../../Makefile.hal

ROOTMANIFESTDIR =	$(ROOTSVCSYSTEM)
$(ROOTMANIFEST) :=	FILEMODE = 444
$(ROOTLIBSVCMETHOD)/svc-hal:= FILEMODE = 555

CPPFLAGS += $(HAL_DBUS_CPPFLAGS) $(HAL_GLIB_CPPFLAGS) $(HAL_CONFIG_CPPFLAGS)
CSTD =	$(CSTD_GNU99)

.KEEP_STATE:

all: $(OBJS)

install: all $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check: $(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

FRC:

include ../../../Makefile.targ
