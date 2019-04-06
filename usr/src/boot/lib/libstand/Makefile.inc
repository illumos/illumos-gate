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

#
# Notes:
# - We don't use the libc strerror/sys_errlist because the string table is
#   quite large.
#

# standalone components and stuff we have modified locally
SRCS=	$(ZLIB)/gzguts.h $(ZLIB)/zutil.h
SRCS += $(SASRC)/__main.c $(SASRC)/assert.c
SRCS +=	$(SASRC)/bcd.c $(SASRC)/environment.c
SRCS += $(SASRC)/getopt.c $(SASRC)/strtol.c
SRCS += $(SASRC)/strtoul.c $(SASRC)/random.c
SRCS += $(SASRC)/sbrk.c $(SASRC)/twiddle.c
SRCS += $(SASRC)/zalloc.c $(SASRC)/zalloc_malloc.c

OBJS=	__main.o assert.o bcd.o environment.o \
	getopt.o gets.o globals.o pager.o panic.o printf.o \
	strdup.o strerror.o strtol.o strtoul.o random.o \
	sbrk.o twiddle.o zalloc.o zalloc_malloc.o

# private (pruned) versions of libc string functions
SRCS +=	$(SASRC)/strcasecmp.c
OBJS +=	strcasecmp.o

# from libc
SRCS += $(LIBSRC)/libc/net/ntoh.c
OBJS += ntoh.o

# string functions from libc
SRCS +=	$(LIBSRC)/libc/string/bcmp.c $(LIBSRC)/libc/string/bcopy.c
SRCS +=	$(LIBSRC)/libc/string/bzero.c $(LIBSRC)/libc/string/ffs.c
SRCS +=	$(LIBSRC)/libc/string/fls.c $(LIBSRC)/libc/string/memccpy.c
SRCS +=	$(LIBSRC)/libc/string/memchr.c $(LIBSRC)/libc/string/memcmp.c
SRCS +=	$(LIBSRC)/libc/string/memcpy.c $(LIBSRC)/libc/string/memmove.c
SRCS +=	$(LIBSRC)/libc/string/memset.c $(LIBSRC)/libc/string/strcat.c
SRCS +=	$(LIBSRC)/libc/string/strchr.c $(LIBSRC)/libc/string/strcmp.c
SRCS +=	$(LIBSRC)/libc/string/strcpy.c $(LIBSRC)/libc/string/stpcpy.c
SRCS +=	$(LIBSRC)/libc/string/stpncpy.c $(LIBSRC)/libc/string/strcspn.c
SRCS +=	$(LIBSRC)/libc/string/strlcat.c $(LIBSRC)/libc/string/strlcpy.c
SRCS +=	$(LIBSRC)/libc/string/strlen.c $(LIBSRC)/libc/string/strncat.c
SRCS +=	$(LIBSRC)/libc/string/strncmp.c $(LIBSRC)/libc/string/strncpy.c
SRCS +=	$(LIBSRC)/libc/string/strpbrk.c $(LIBSRC)/libc/string/strrchr.c
SRCS +=	$(LIBSRC)/libc/string/strsep.c $(LIBSRC)/libc/string/strspn.c
SRCS +=	$(LIBSRC)/libc/string/strstr.c $(LIBSRC)/libc/string/strtok.c
SRCS +=	$(LIBSRC)/libc/string/swab.c

SRCS += $(SASRC)/qdivrem.c

OBJS +=	bcmp.o bcopy.o bzero.o ffs.o fls.o \
	memccpy.o memchr.o memcmp.o memcpy.o memmove.o memset.o \
	qdivrem.o strcat.o strchr.o strcmp.o strcpy.o stpcpy.o stpncpy.o \
	strcspn.o strlcat.o strlcpy.o strlen.o strncat.o strncmp.o strncpy.o \
	strpbrk.o strrchr.o strsep.o strspn.o strstr.o strtok.o swab.o

# uuid functions from libc
SRCS += $(LIBSRC)/libc/uuid/uuid_create_nil.c
SRCS += $(LIBSRC)/libc/uuid/uuid_equal.c
SRCS += $(LIBSRC)/libc/uuid/uuid_is_nil.c

SRCS += $(SASRC)/uuid_from_string.c
SRCS += $(SASRC)/uuid_to_string.c

OBJS += uuid_create_nil.o uuid_equal.o uuid_from_string.o uuid_is_nil.o \
	uuid_to_string.o

# decompression functionality from libbz2
# NOTE: to actually test this functionality after libbz2 upgrade compile
# loader(8) with LOADER_BZIP2_SUPPORT defined
_bzlib.o _crctable.o _decompress.o _huffman.o _randtable.o bzipfs.o \
:= CFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
SRCS +=	libstand_bzlib_private.h

SRCS +=	_bzlib.c _crctable.c _decompress.c _huffman.c _randtable.c
OBJS +=	_bzlib.o _crctable.o _decompress.o _huffman.o _randtable.o
CLEANFILES +=	_bzlib.c _crctable.c _decompress.c _huffman.c _randtable.c

_bzlib.c: $(SRC)/common/bzip2/bzlib.c
	sed "s|bzlib_private\.h|libstand_bzlib_private.h|" $^ > $@

_crctable.c: $(SRC)/common/bzip2/crctable.c
	sed "s|bzlib_private\.h|libstand_bzlib_private.h|" $^ > $@

_decompress.c: $(SRC)/common/bzip2/decompress.c
	sed "s|bzlib_private\.h|libstand_bzlib_private.h|" $^ > $@

_huffman.c: $(SRC)/common/bzip2/huffman.c
	sed "s|bzlib_private\.h|libstand_bzlib_private.h|" $^ > $@

_randtable.c: $(SRC)/common/bzip2/randtable.c
	sed "s|bzlib_private\.h|libstand_bzlib_private.h|" $^ > $@

CLEANFILES += libstand_bzlib_private.h
libstand_bzlib_private.h: $(SRC)/common/bzip2/bzlib_private.h
	sed -e 's|<stdlib.h>|"stand.h"|' $^ > $@

# decompression functionality from zlib
adler32.o crc32.o _infback.o _inffast.o _inflate.o _inftrees.o _zutil.o \
gzipfs.o gzip.o := CPPFLAGS += -I$(ZLIB)
SRCS +=	$(ZLIB)/adler32.c $(ZLIB)/crc32.c \
	libstand_zutil.h libstand_gzguts.h
OBJS +=	adler32.o crc32.o

_infback.c: $(ZLIB)/infback.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@
_inffast.c: $(ZLIB)/inffast.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@
_inflate.c: $(ZLIB)/inflate.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@
_inftrees.c: $(ZLIB)/inftrees.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@
_zutil.c: $(ZLIB)/zutil.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@

SRCS +=	_infback.c _inffast.c _inflate.c _inftrees.c _zutil.c
OBJS +=	_infback.o _inffast.o _inflate.o _inftrees.o _zutil.o
CLEANFILES +=	_infback.c _inffast.c _inflate.c _inftrees.c _zutil.c

# depend on stand.h being able to be included multiple times
libstand_zutil.h: $(ZLIB)/zutil.h
	sed -e 's|<fcntl.h>|"stand.h"|' \
	    -e 's|<stddef.h>|"stand.h"|' \
	    -e 's|<string.h>|"stand.h"|' \
	    -e 's|<stdio.h>|"stand.h"|' \
	    -e 's|<stdlib.h>|"stand.h"|' \
	    $^ > $@

libstand_gzguts.h: $(ZLIB)/gzguts.h
	sed -e 's|<fcntl.h>|"stand.h"|' \
	    -e 's|<stddef.h>|"stand.h"|' \
	    -e 's|<string.h>|"stand.h"|' \
	    -e 's|<stdio.h>|"stand.h"|' \
	    -e 's|<stdlib.h>|"stand.h"|' \
	    $^ > $@

CLEANFILES += libstand_zutil.h libstand_gzguts.h

# io routines
SRCS +=	$(SASRC)/closeall.c $(SASRC)/dev.c \
	$(SASRC)/ioctl.c $(SASRC)/nullfs.c \
	$(SASRC)/stat.c $(SASRC)/fstat.c $(SASRC)/close.c \
	$(SASRC)/lseek.c $(SASRC)/open.c $(SASRC)/read.c \
	$(SASRC)/write.c $(SASRC)/readdir.c

OBJS +=	closeall.o dev.o ioctl.o nullfs.o stat.o fstat.o close.o lseek.o \
	open.o read.o write.o readdir.o

# network routines
SRCS +=	$(SASRC)/arp.c $(SASRC)/ether.c $(SASRC)/ip.c \
	$(SASRC)/inet_ntoa.c $(SASRC)/in_cksum.c \
	$(SASRC)/net.c $(SASRC)/udp.c $(SASRC)/netif.c \
	$(SASRC)/rpc.c
OBJS +=	arp.o ether.o ip.o inet_ntoa.o in_cksum.o net.o udp.o netif.o rpc.o

# network info services:
SRCS +=	$(SASRC)/bootp.c $(SASRC)/rarp.c \
	$(SASRC)/bootparam.c
OBJS +=	bootp.o rarp.o bootparam.o

# boot filesystems
SRCS +=	$(SASRC)/ufs.c
SRCS += $(SASRC)/nfs.c
SRCS += $(SASRC)/cd9660.c
SRCS += $(SASRC)/tftp.c
SRCS += $(SASRC)/gzipfs.c
SRCS += $(SASRC)/bzipfs.c
SRCS += $(SASRC)/dosfs.c
OBJS +=	ufs.o
OBJS +=	nfs.o
OBJS +=	cd9660.o
OBJS +=	tftp.o
OBJS +=	gzipfs.o
OBJS += bzipfs.o
OBJS += dosfs.o
#
.PARALLEL:
