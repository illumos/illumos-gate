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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

include $(SRC)/Makefile.master

CC=     $(GNUC_ROOT)/bin/gcc

install:

SRCS +=	delay.c \
	devicename.c \
	devpath.c \
	efi_console.c \
	efi_driver_utils.c \
	efichar.c \
	efienv.c \
	efinet.c \
	efipart.c \
	efizfs.c \
	env.c \
	errno.c \
	handles.c \
	libefi.c \
	wchar.c

OBJS=	$(SRCS:%.c=%.o)

CPPFLAGS= -D_STANDALONE
CFLAGS  = -O2

CPPFLAGS += -nostdinc -I. -I../../../../../include -I../../../..
CPPFLAGS += -I$(SRC)/common/ficl -I../../../libficl
CPPFLAGS += -I../../include
CPPFLAGS += -I../../include/$(MACHINE)
CPPFLAGS += -I../../../../../lib/libstand
CPPFLAGS += -I../../../zfs
CPPFLAGS += -I../../../../cddl/boot/zfs

# Pick up the bootstrap header for some interface items
CPPFLAGS += -I../../../common
CPPFLAGS += -DTERM_EMU

include ../../Makefile.inc

libefi.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean: clobber
clobber:
	$(RM) $(CLEANFILES) $(OBJS) libefi.a

machine:
	$(RM) machine
	$(SYMLINK) ../../../../$(MACHINE)/include machine

x86:
	$(RM) x86
	$(SYMLINK) ../../../../x86/include x86

%.o:	../%.c
	$(COMPILE.c) $<
