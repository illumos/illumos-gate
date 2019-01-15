#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2018, Joyent, Inc.
#

MODULE		= usb
CLASS		= common
SHAREDMODULE	= shared


MODULESRCS	= topo_usb.c topo_usb_acpi.o topo_usb_metadata.o
SHAREDSRCS	= topo_port.c

include ../../Makefile.plugin

CPPFLAGS	+= -I../shared  -I$(SRC)/uts/intel/sys/acpi -DACPI_APPLICATION
CPPFLAGS	+= -D_POSIX_PTHREAD_SEMANTICS
LDLIBS		+= -ldevinfo
