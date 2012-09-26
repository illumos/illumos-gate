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

LIBRARY=	libparted.a
VERS=		.8

#
# All relative to SRCDIR
#

PLIBDIR=	lib
LIBPDIR=	libparted
LIBPADIR=	libparted/arch
LIBPCSDIR=	libparted/cs
LIBAMIGAFS=	libparted/fs/amiga
LIBEXT2FS=	libparted/fs/ext2
LIBFATFS=	libparted/fs/fat
LIBHFS=		libparted/fs/hfs
LIBJFS=		libparted/fs/jfs
LIBLINUXSWAP=	libparted/fs/linux_swap
LIBNTFS=	libparted/fs/ntfs
LIBREISERFS=	libparted/fs/reiserfs
LIBSOLARISX86=	libparted/fs/solaris_x86
LIBUFS=		libparted/fs/ufs
LIBXFS=		libparted/fs/xfs
LIBLABELS=	libparted/labels

OBJECTS=	$(PLIBDIR)/basename.o		$(PLIBDIR)/quotearg.o \
		$(PLIBDIR)/close-stream.o	$(PLIBDIR)/regex.o \
		$(PLIBDIR)/closeout.o		$(PLIBDIR)/rpmatch.o \
		$(PLIBDIR)/dirname.o		$(PLIBDIR)/safe-read.o \
		$(PLIBDIR)/error.o		$(PLIBDIR)/safe-write.o \
		$(PLIBDIR)/exitfail.o		$(PLIBDIR)/strcspn.o \
		$(PLIBDIR)/full-write.o		$(PLIBDIR)/stripslash.o \
		$(PLIBDIR)/getopt.o		$(PLIBDIR)/strndup.o \
		$(PLIBDIR)/version-etc-fsf.o \
		$(PLIBDIR)/localcharset.o	$(PLIBDIR)/version-etc.o \
		$(PLIBDIR)/long-options.o	$(PLIBDIR)/xalloc-die.o \
		$(PLIBDIR)/memcpy.o		$(PLIBDIR)/xmalloc.o \
		$(PLIBDIR)/memmove.o		$(PLIBDIR)/xstrndup.o \
		$(PLIBDIR)/memset.o \
		$(LIBPDIR)/debug.o		$(LIBPDIR)/exception.o \
		$(LIBPDIR)/device.o		$(LIBPDIR)/filesys.o \
		$(LIBPDIR)/timer.o		$(LIBPDIR)/unit.o \
		$(LIBPDIR)/disk.o		$(LIBPDIR)/libparted.o \
		$(LIBPADIR)/solaris.o \
		$(LIBPCSDIR)/constraint.o	$(LIBPCSDIR)/geom.o \
		$(LIBPCSDIR)/natmath.o \
		$(LIBAMIGAFS)/affs.o		$(LIBAMIGAFS)/amiga.o  \
		$(LIBAMIGAFS)/apfs.o		$(LIBAMIGAFS)/asfs.o  \
		$(LIBAMIGAFS)/interface.o \
		$(LIBEXT2FS)/interface.o	$(LIBEXT2FS)/ext2.o \
		$(LIBEXT2FS)/ext2_inode_relocator.o \
		$(LIBEXT2FS)/parted_io.o	$(LIBEXT2FS)/ext2_meta.o \
		$(LIBEXT2FS)/ext2_block_relocator.o \
		$(LIBEXT2FS)/ext2_mkfs.o	$(LIBEXT2FS)/tune.o \
		$(LIBEXT2FS)/ext2_buffer.o	$(LIBEXT2FS)/ext2_resize.o \
		$(LIBFATFS)/table.o		$(LIBFATFS)/bootsector.o \
		$(LIBFATFS)/clstdup.o		$(LIBFATFS)/count.o \
		$(LIBFATFS)/fatio.o		$(LIBFATFS)/traverse.o \
		$(LIBFATFS)/calc.o		$(LIBFATFS)/context.o \
		$(LIBFATFS)/fat.o		$(LIBFATFS)/resize.o \
		$(LIBHFS)/cache.o		$(LIBHFS)/probe.o \
		$(LIBHFS)/advfs.o		$(LIBHFS)/hfs.o \
		$(LIBHFS)/file.o		$(LIBHFS)/reloc.o \
		$(LIBHFS)/advfs_plus.o		$(LIBHFS)/journal.o \
		$(LIBHFS)/file_plus.o		$(LIBHFS)/reloc_plus.o \
		$(LIBJFS)/jfs.o \
		$(LIBLINUXSWAP)/linux_swap.o \
		$(LIBNTFS)/ntfs.o \
		$(LIBREISERFS)/geom_dal.o	$(LIBREISERFS)/reiserfs.o \
		$(LIBSOLARISX86)/solaris_x86.o \
		$(LIBUFS)/ufs.o \
		$(LIBXFS)/xfs.o \
		$(LIBLABELS)/dos.o		$(LIBLABELS)/efi_crc32.o \
		$(LIBLABELS)/mac.o		$(LIBLABELS)/sun.o \
		$(LIBLABELS)/aix.o		$(LIBLABELS)/dvh.o \
		$(LIBLABELS)/gpt.o		$(LIBLABELS)/pc98.o \
		$(LIBLABELS)/bsd.o		$(LIBLABELS)/loop.o \
		$(LIBLABELS)/rdb.o \

# include library definitions
include		../../Makefile.lib

SRCDIR =	../common

C99MODE=	$(C99_ENABLE)
CERRWARN +=	-erroff=E_EXTERN_INLINE_UNDEFINED
CERRWARN +=	-erroff=E_CONST_PROMOTED_UNSIGNED_LONG

LIBS =		$(DYNLIB)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR)/lib -I$(SRCDIR)/include
DYNFLAGS +=	$(ZINTERPOSE)
LDLIBS +=	-ldiskmgt -luuid -lc -lnvpair

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-type-limits

.KEEP_STATE:

#
# This open source is exempted from lint
#
lint:

# include library targets
include		../../Makefile.targ
