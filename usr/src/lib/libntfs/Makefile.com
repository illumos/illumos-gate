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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY=	libntfs.a
VERS=		.10

#
# All relative to SRCDIR
#

LIBNTFSDIR=	libntfs

OBJECTS=	$(LIBNTFSDIR)/attrib.o \
                $(LIBNTFSDIR)/attrlist.o \
                $(LIBNTFSDIR)/bitmap.o \
                $(LIBNTFSDIR)/bootsect.o \
                $(LIBNTFSDIR)/collate.o \
                $(LIBNTFSDIR)/compat.o \
                $(LIBNTFSDIR)/compress.o \
                $(LIBNTFSDIR)/crypto.o \
                $(LIBNTFSDIR)/debug.o \
                $(LIBNTFSDIR)/device.o \
                $(LIBNTFSDIR)/device_io.o \
                $(LIBNTFSDIR)/dir.o \
                $(LIBNTFSDIR)/gnome-vfs-method.o \
                $(LIBNTFSDIR)/gnome-vfs-module.o \
                $(LIBNTFSDIR)/index.o \
                $(LIBNTFSDIR)/inode.o \
                $(LIBNTFSDIR)/lcnalloc.o \
                $(LIBNTFSDIR)/logfile.o \
                $(LIBNTFSDIR)/logging.o \
                $(LIBNTFSDIR)/mft.o \
                $(LIBNTFSDIR)/misc.o \
                $(LIBNTFSDIR)/mst.o \
                $(LIBNTFSDIR)/runlist.o \
                $(LIBNTFSDIR)/security.o \
                $(LIBNTFSDIR)/unistr.o \
                $(LIBNTFSDIR)/version.o \
                $(LIBNTFSDIR)/volume.o

# include library definitions
include		../../Makefile.lib

SRCDIR =	../common

C99MODE=	$(C99_ENABLE)
CERRWARN +=	-erroff=E_ENUM_VAL_OVERFLOWS_INT_MAX
CERRWARN +=	-erroff=E_STRUCT_DERIVED_FROM_FLEX_MBR
CERRWARN +=	-erroff=E_END_OF_LOOP_CODE_NOT_REACHED
CERRWARN +=	-erroff=E_LOOP_NOT_ENTERED_AT_TOP

LIBS =		$(DYNLIB)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-DHAVE_CONFIG_H \
		-DLTVERSION_LIBNTFS=\"10:0:0\" \
		-I$(SRCDIR)/include/ntfs
DYNFLAGS +=	$(ZINTERPOSE)
LDLIBS +=	-lc -lgnomevfs-2 -lglib-2.0

.KEEP_STATE:

#
# This open source is exempted from lint
#
lint:

# include library targets
include		../../Makefile.targ

pics/$(LIBNTFSDIR)/gnome-vfs-method.o: ../common/$(LIBNTFSDIR)/gnome-vfs-method.c
		$(CC) $(CFLAGS) \
			-I/usr/include/glib-2.0 \
			-I/usr/lib/glib-2.0/include \
			-I/usr/include/gnome-vfs-2.0 \
			-I/usr/include/gnome-vfs-module-2.0 \
			-I/usr/lib/gnome-vfs-2.0/include \
			-I/usr/include/gconf/2 \
			-I/usr/include/orbit-2.0 \
			-I/usr/include/dbus-1.0 \
			-I/usr/lib/dbus-1.0/include \
			-D_PTHREADS -DORBIT2=1 \
			$(CPPFLAGS) -c -o $@ \
			../common/$(LIBNTFSDIR)/gnome-vfs-method.c
		$(POST_PROCESS_O)

pics/$(LIBNTFSDIR)/gnome-vfs-module.o: ../common/$(LIBNTFSDIR)/gnome-vfs-module.c
		$(CC) $(CFLAGS) \
			-I/usr/include/glib-2.0 \
			-I/usr/lib/glib-2.0/include \
			-I/usr/include/gnome-vfs-2.0 \
			-I/usr/include/gnome-vfs-module-2.0 \
			-I/usr/lib/gnome-vfs-2.0/include \
			-I/usr/include/gconf/2 \
			-I/usr/include/orbit-2.0 \
			-I/usr/include/dbus-1.0 \
			-I/usr/lib/dbus-1.0/include \
			-D_PTHREADS -DORBIT2=1 \
			$(CPPFLAGS) -c -o $@ \
			../common/$(LIBNTFSDIR)/gnome-vfs-module.c
		$(POST_PROCESS_O)
