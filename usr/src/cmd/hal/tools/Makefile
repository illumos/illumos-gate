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
# ident	"%Z%%M%	%I%	%E% SMI"
#

HAL_PROG =	hal-device hal-find-by-capability hal-find-by-property \
		hal-get-property hal-set-property lshal

SCRIPT =	hal-fdi-validate

STORAGE_METHOD_PROG = hal-storage-closetray hal-storage-eject \
		hal-storage-mount hal-storage-unmount \
		hal-storage-zpool-export hal-storage-zpool-import

STORAGE_PROG =	$(STORAGE_METHOD_PROG) \
		hal-storage-cleanup-mountpoint \
		hal-storage-cleanup-all-mountpoints

PROGSRCS =	$(PROG:%=%.c) $(STORAGE_PROG:%=%.c)

STORAGE_OBJS =		$(STORAGE_PROG:%=%.o)
STORAGE_SHAREDOBJS =	hal-storage-shared.o
STORAGE_SHAREDSRCS =	$(STORAGE_SHAREDOBJS:%.o=%.c)

SRCS =		$(PROGSRCS) $(STORAGE_SHAREDSRCS)

CLOBBERFILES += $(HAL_PROG) $(STORAGE_PROG) $(SCRIPT)
CLEANFILES += $(STORAGE_SHAREDOBJS) $(STORAGE_OBJS)

include ../../Makefile.cmd
include ../Makefile.hal

$(HAL_PROG) :=		LDLIBS += -lc -ldbus-1 -lhal

lshal :=		LDLIBS += -ldbus-glib-1 -lglib-2.0

$(STORAGE_PROG)	:=	LDLIBS += -lc -ldbus-1 -lglib-2.0 -lhal -lhal-storage -lbsm

$(STORAGE_METHOD_PROG) := LDLIBS += -lpolkit

CPPFLAGS += $(HAL_DBUS_CPPFLAGS) $(HAL_GLIB_CPPFLAGS) $(HAL_CONFIG_CPPFLAGS)
CPPFLAGS += -I$(ROOT)/usr/include/hal
CPPFLAGS += -I$(ROOT)/usr/include/libpolkit
C99MODE = $(C99_ENABLE)

ROOTUSRSBINPROG =	$(HAL_PROG:%=$(ROOTUSRSBIN)/%) $(SCRIPT:%=$(ROOTUSRSBIN)/%)

ROOTCMDDIR =		$(ROOTLIB_HAL)
ROOTCMD =		$(STORAGE_PROG:%=$(ROOTCMDDIR)/%)

.KEEP_STATE:

all: $(HAL_PROG) $(STORAGE_PROG) $(SCRIPT)

$(STORAGE_SHAREDOBJS): $(STORAGE_SHAREDSRCS)
	$(COMPILE.c) $(STORAGE_SHAREDSRCS)

hal-storage-closetray: hal-storage-closetray.o $(STORAGE_SHAREDOBJS)
	$(LINK.c) hal-storage-closetray.o $(STORAGE_SHAREDOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

hal-storage-eject: hal-storage-eject.o $(STORAGE_SHAREDOBJS)
	$(LINK.c) hal-storage-eject.o $(STORAGE_SHAREDOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

hal-storage-mount: hal-storage-mount.o $(STORAGE_SHAREDOBJS)
	$(LINK.c) hal-storage-mount.o $(STORAGE_SHAREDOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

hal-storage-unmount: hal-storage-unmount.o $(STORAGE_SHAREDOBJS)
	$(LINK.c) hal-storage-unmount.o $(STORAGE_SHAREDOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

hal-storage-cleanup-mountpoint: hal-storage-cleanup-mountpoint.c \
		$(STORAGE_SHAREDOBJS)
	$(LINK.c) hal-storage-cleanup-mountpoint.c \
		$(STORAGE_SHAREDOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

hal-storage-cleanup-all-mountpoints: hal-storage-cleanup-all-mountpoints.c \
		$(STORAGE_SHAREDOBJS)
	$(LINK.c) hal-storage-cleanup-all-mountpoints.c \
		$(STORAGE_SHAREDOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

hal-storage-zpool-export: hal-storage-zpool.c $(STORAGE_SHAREDOBJS)
	$(LINK.c) -o $@ $(STORAGE_SHAREDOBJS) -DZPOOL_SUBCMD=\"export\" hal-storage-zpool.c $(LDLIBS)
	$(POST_PROCESS)

hal-storage-zpool-import: hal-storage-zpool.c $(STORAGE_SHAREDOBJS)
	$(LINK.c) -o $@ $(STORAGE_SHAREDOBJS) -DZPOOL_SUBCMD=\"import\" hal-storage-zpool.c $(LDLIBS)
	$(POST_PROCESS)

hal-device: hal-device.c
	$(LINK.c) -o $@ hal-device.c $(LDLIBS)
	$(POST_PROCESS)

hal-find-by-capability: hal_find_by_capability.c
	$(LINK.c) -o $@ hal_find_by_capability.c $(LDLIBS)
	$(POST_PROCESS)

hal-find-by-property: hal_find_by_property.c
	$(LINK.c) -o $@ hal_find_by_property.c $(LDLIBS)
	$(POST_PROCESS)

hal-get-property: hal_get_property.c
	$(LINK.c) -o $@ hal_get_property.c $(LDLIBS)
	$(POST_PROCESS)

hal-set-property: hal_set_property.c
	$(LINK.c) -o $@ hal_set_property.c $(LDLIBS)
	$(POST_PROCESS)

lshal: lshal.c
	$(LINK.c) -o $@ lshal.c $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG) $(ROOTCMD)


clean:
	$(RM) $(CLEANFILES)

include ../../Makefile.targ
