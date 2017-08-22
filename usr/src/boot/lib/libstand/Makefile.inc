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
SRCS=	$(LIB_BASE)/libz/gzguts.h $(LIB_BASE)/libz/zutil.h
SRCS += $(LIBSTAND_SRC)/__main.c $(LIBSTAND_SRC)/assert.c
SRCS +=	$(LIBSTAND_SRC)/bcd.c $(LIBSTAND_SRC)/environment.c
SRCS += $(LIBSTAND_SRC)/getopt.c $(LIBSTAND_SRC)/strtol.c
SRCS += $(LIBSTAND_SRC)/strtoul.c $(LIBSTAND_SRC)/random.c
SRCS += $(LIBSTAND_SRC)/sbrk.c $(LIBSTAND_SRC)/twiddle.c
SRCS += $(LIBSTAND_SRC)/zalloc.c $(LIBSTAND_SRC)/zalloc_malloc.c

OBJS=	__main.o assert.o bcd.o environment.o \
	getopt.o gets.o globals.o pager.o printf.o \
	strdup.o strerror.o strtol.o strtoul.o random.o \
	sbrk.o twiddle.o zalloc.o zalloc_malloc.o

# private (pruned) versions of libc string functions
SRCS +=	$(LIBSTAND_SRC)/strcasecmp.c
OBJS +=	strcasecmp.o

# from libc
SRCS += $(LIB_BASE)/libc/net/ntoh.c
OBJS += ntoh.o

# string functions from libc
SRCS +=	$(LIB_BASE)/libc/string/bcmp.c $(LIB_BASE)/libc/string/bcopy.c
SRCS +=	$(LIB_BASE)/libc/string/bzero.c $(LIB_BASE)/libc/string/ffs.c
SRCS +=	$(LIB_BASE)/libc/string/fls.c $(LIB_BASE)/libc/string/memccpy.c
SRCS +=	$(LIB_BASE)/libc/string/memchr.c $(LIB_BASE)/libc/string/memcmp.c
SRCS +=	$(LIB_BASE)/libc/string/memcpy.c $(LIB_BASE)/libc/string/memmove.c
SRCS +=	$(LIB_BASE)/libc/string/memset.c $(LIB_BASE)/libc/string/strcat.c
SRCS +=	$(LIB_BASE)/libc/string/strchr.c $(LIB_BASE)/libc/string/strcmp.c
SRCS +=	$(LIB_BASE)/libc/string/strcpy.c $(LIB_BASE)/libc/string/stpcpy.c
SRCS +=	$(LIB_BASE)/libc/string/stpncpy.c $(LIB_BASE)/libc/string/strcspn.c
SRCS +=	$(LIB_BASE)/libc/string/strlcat.c $(LIB_BASE)/libc/string/strlcpy.c
SRCS +=	$(LIB_BASE)/libc/string/strlen.c $(LIB_BASE)/libc/string/strncat.c
SRCS +=	$(LIB_BASE)/libc/string/strncmp.c $(LIB_BASE)/libc/string/strncpy.c
SRCS +=	$(LIB_BASE)/libc/string/strpbrk.c $(LIB_BASE)/libc/string/strrchr.c
SRCS +=	$(LIB_BASE)/libc/string/strsep.c $(LIB_BASE)/libc/string/strspn.c
SRCS +=	$(LIB_BASE)/libc/string/strstr.c $(LIB_BASE)/libc/string/strtok.c
SRCS +=	$(LIB_BASE)/libc/string/swab.c

SRCS += $(LIBSTAND_SRC)/qdivrem.c

OBJS +=	bcmp.o bcopy.o bzero.o ffs.o fls.o \
	memccpy.o memchr.o memcmp.o memcpy.o memmove.o memset.o \
	qdivrem.o strcat.o strchr.o strcmp.o strcpy.o stpcpy.o stpncpy.o \
	strcspn.o strlcat.o strlcpy.o strlen.o strncat.o strncmp.o strncpy.o \
	strpbrk.o strrchr.o strsep.o strspn.o strstr.o strtok.o swab.o

# uuid functions from libc
SRCS += $(LIB_BASE)/libc/uuid/uuid_create_nil.c
SRCS += $(LIB_BASE)/libc/uuid/uuid_equal.c
SRCS += $(LIB_BASE)/libc/uuid/uuid_is_nil.c

SRCS += $(LIBSTAND_SRC)/uuid_from_string.c
SRCS += $(LIBSTAND_SRC)/uuid_to_string.c

OBJS += uuid_create_nil.o uuid_equal.o uuid_from_string.o uuid_is_nil.o \
	uuid_to_string.o

# decompression functionality from libbz2
# NOTE: to actually test this functionality after libbz2 upgrade compile
# loader(8) with LOADER_BZIP2_SUPPORT defined
CFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
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

# decompression functionality from libz
CFLAGS += -DHAVE_MEMCPY -I$(LIB_BASE)/libz
SRCS +=	$(LIB_BASE)/libz/adler32.c $(LIB_BASE)/libz/crc32.c \
	libstand_zutil.h libstand_gzguts.h
OBJS +=	adler32.o crc32.o

_infback.c: $(LIB_BASE)/libz/infback.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@
_inffast.c: $(LIB_BASE)/libz/inffast.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@
_inflate.c: $(LIB_BASE)/libz/inflate.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@
_inftrees.c: $(LIB_BASE)/libz/inftrees.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@
_zutil.c: $(LIB_BASE)/libz/zutil.c
	sed -e "s|zutil\.h|libstand_zutil.h|" \
	    -e "s|gzguts\.h|libstand_gzguts.h|" \
	    $^ > $@

SRCS +=	_infback.c _inffast.c _inflate.c _inftrees.c _zutil.c
OBJS +=	_infback.o _inffast.o _inflate.o _inftrees.o _zutil.o
CLEANFILES +=	_infback.c _inffast.c _inflate.c _inftrees.c _zutil.c

# depend on stand.h being able to be included multiple times
libstand_zutil.h: $(LIB_BASE)/libz/zutil.h
	sed -e 's|<fcntl.h>|"stand.h"|' \
	    -e 's|<stddef.h>|"stand.h"|' \
	    -e 's|<string.h>|"stand.h"|' \
	    -e 's|<stdio.h>|"stand.h"|' \
	    -e 's|<stdlib.h>|"stand.h"|' \
	    $^ > $@

libstand_gzguts.h: $(LIB_BASE)/libz/gzguts.h
	sed -e 's|<fcntl.h>|"stand.h"|' \
	    -e 's|<stddef.h>|"stand.h"|' \
	    -e 's|<string.h>|"stand.h"|' \
	    -e 's|<stdio.h>|"stand.h"|' \
	    -e 's|<stdlib.h>|"stand.h"|' \
	    $^ > $@

CLEANFILES += libstand_zutil.h libstand_gzguts.h

# io routines
SRCS +=	$(LIBSTAND_SRC)/closeall.c $(LIBSTAND_SRC)/dev.c \
	$(LIBSTAND_SRC)/ioctl.c $(LIBSTAND_SRC)/nullfs.c \
	$(LIBSTAND_SRC)/stat.c $(LIBSTAND_SRC)/fstat.c $(LIBSTAND_SRC)/close.c \
	$(LIBSTAND_SRC)/lseek.c $(LIBSTAND_SRC)/open.c $(LIBSTAND_SRC)/read.c \
	$(LIBSTAND_SRC)/write.c $(LIBSTAND_SRC)/readdir.c

OBJS +=	closeall.o dev.o ioctl.o nullfs.o stat.o fstat.o close.o lseek.o \
	open.o read.o write.o readdir.o

# network routines
SRCS +=	$(LIBSTAND_SRC)/arp.c $(LIBSTAND_SRC)/ether.c \
	$(LIBSTAND_SRC)/inet_ntoa.c $(LIBSTAND_SRC)/in_cksum.c \
	$(LIBSTAND_SRC)/net.c $(LIBSTAND_SRC)/udp.c $(LIBSTAND_SRC)/netif.c \
	$(LIBSTAND_SRC)/rpc.c
OBJS +=	arp.o ether.o inet_ntoa.o in_cksum.o net.o udp.o netif.o rpc.o

# network info services:
SRCS +=	$(LIBSTAND_SRC)/bootp.c $(LIBSTAND_SRC)/rarp.c \
	$(LIBSTAND_SRC)/bootparam.c
OBJS +=	bootp.o rarp.o bootparam.o

# boot filesystems
SRCS +=	$(LIBSTAND_SRC)/ufs.c
SRCS += $(LIBSTAND_SRC)/nfs.c
SRCS += $(LIBSTAND_SRC)/cd9660.c
SRCS += $(LIBSTAND_SRC)/tftp.c
SRCS += $(LIBSTAND_SRC)/gzipfs.c
SRCS += $(LIBSTAND_SRC)/bzipfs.c
SRCS += $(LIBSTAND_SRC)/dosfs.c
OBJS +=	ufs.o
OBJS +=	nfs.o
OBJS +=	cd9660.o
OBJS +=	tftp.o
OBJS +=	gzipfs.o
OBJS += bzipfs.o
OBJS += dosfs.o
#
