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

SUBDIRS =	solaris

PROG =		hald
OBJS =		hald_marshal.o device.o device_info.o device_store.o hald.o \
		hald_dbus.o hald_runner.o ids.o logger.o property.o util.o \
		util_helper.o util_pm.o
OBJS_SOL =	devinfo.o devinfo_ieee1394.o devinfo_misc.o devinfo_pci.o devinfo_storage.o \
		devinfo_usb.o hotplug.o osspec.o sysevent.o devinfo_acpi.o \
		devinfo_cpu.o
OBJS_ALL =	$(OBJS) $(OBJS_SOL:%=solaris/%)
SRCS =		$(OBJS:%.o=%.c)

include ../../Makefile.cmd
include ../Makefile.hal

ROOTCMDDIR =	$(ROOTLIB_HAL)

LDLIBS +=	-lc -lm -ldbus-1 -ldbus-glib-1 -lglib-2.0 -lgobject-2.0 \
		-ldevinfo -lsysevent -lnvpair -lkstat -lcfgadm

all install $(PROG) :=	LDLIBS += -lexpat

CPPFLAGS +=	$(HAL_DBUS_CPPFLAGS) $(HAL_GLIB_CPPFLAGS) $(HAL_CONFIG_CPPFLAGS)
CSTD =	$(CSTD_GNU99)

CLOBBERFILES += hald_marshal.c hald_marshal.h

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
$(PROG) :=	TARGET= all

.KEEP_STATE:

all: $(SUBDIRS) .WAIT $(PROG)

hald_marshal.o: hald_marshal.h hald_marshal.c

hald_marshal.h: hald_marshal.list
	glib-genmarshal --prefix=hald_marshal hald_marshal.list --header >> xgen-gmh \
	&& (cmp -s xgen-gmh hald_marshal.h || cp xgen-gmh hald_marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

hald_marshal.c: hald_marshal.list
	glib-genmarshal --prefix=hald_marshal hald_marshal.list --body >> xgen-gmc \
	&& (cmp -s xgen-gmc hald_marshal.c || cp xgen-gmc hald_marshal.c) \
	&& rm -f xgen-gmc xgen-gmc~

$(PROG): $(SUBDIRS) .WAIT $(OBJS_ALL)
	$(LINK.c) -o $@ $(OBJS_ALL) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTCMD) $(SUBDIRS)

clean: $(SUBDIRS)
	$(RM) $(OBJS) $(OBJS_SOL)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../../Makefile.targ
