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
# Copyright 2019 Joyent, Inc.
#

#
# Notes:
# - We don't use the libc strerror/sys_errlist because the string table is
#   quite large.
#

# standalone components and stuff we have modified locally
SRCS +=	$(ZLIB)/gzguts.h $(ZLIB)/zutil.h
SRCS += $(SASRC)/__main.c $(SASRC)/abort.c $(SASRC)/assert.c
SRCS +=	$(SASRC)/bcd.c $(SASRC)/environment.c
SRCS += $(SASRC)/getopt.c $(SASRC)/random.c
SRCS += $(SASRC)/sbrk.c $(SASRC)/twiddle.c
SRCS += $(SASRC)/zalloc.c $(SASRC)/zalloc_malloc.c

OBJECTS += __main.o abort.o assert.o bcd.o environment.o \
	getopt.o gets.o globals.o pager.o panic.o printf.o \
	strdup.o strerror.o strtol.o strtoll.o strtoul.o strtoull.o random.o \
	sbrk.o twiddle.o zalloc.o zalloc_malloc.o

# private (pruned) versions of libc string functions
SRCS +=	$(SASRC)/strcasecmp.c
OBJECTS += strcasecmp.o

# from libc
SRCS += $(SASRC)/ntoh.c
OBJECTS += ntoh.o

# string functions from libc
SRCS +=	$(SASRC)/string/bcmp.c $(SASRC)/string/bcopy.c
SRCS +=	$(SASRC)/string/bzero.c $(SASRC)/string/ffs.c
SRCS +=	$(SASRC)/string/fls.c $(SASRC)/string/memccpy.c
SRCS +=	$(SASRC)/string/memchr.c $(SASRC)/string/memcmp.c
SRCS +=	$(SASRC)/string/memcpy.c $(SASRC)/string/memmove.c
SRCS +=	$(SASRC)/string/memset.c $(SASRC)/string/strcat.c
SRCS +=	$(SASRC)/string/strchr.c $(SASRC)/string/strcmp.c
SRCS +=	$(SASRC)/string/strcpy.c $(SASRC)/string/stpcpy.c
SRCS +=	$(SASRC)/string/stpncpy.c $(SASRC)/string/strcspn.c
SRCS +=	$(SASRC)/string/strlcat.c $(SASRC)/string/strlcpy.c
SRCS +=	$(SASRC)/string/strlen.c $(SASRC)/string/strncat.c
SRCS +=	$(SASRC)/string/strncmp.c $(SASRC)/string/strncpy.c
SRCS +=	$(SASRC)/string/strpbrk.c $(SASRC)/string/strrchr.c
SRCS +=	$(SASRC)/string/strsep.c $(SASRC)/string/strspn.c
SRCS +=	$(SASRC)/string/strstr.c $(SASRC)/string/strtok.c
SRCS +=	$(SASRC)/string/swab.c $(SASRC)/string/strnlen.c

SRCS += $(SASRC)/qdivrem.c

OBJECTS += bcmp.o bcopy.o bzero.o ffs.o fls.o \
	memccpy.o memchr.o memcmp.o memcpy.o memmove.o memset.o \
	qdivrem.o strcat.o strchr.o strcmp.o strcpy.o stpcpy.o stpncpy.o \
	strcspn.o strlcat.o strlcpy.o strlen.o strncat.o strncmp.o strncpy.o \
	strpbrk.o strrchr.o strsep.o strspn.o strstr.o strtok.o swab.o \
	strnlen.o

# uuid functions from libc
SRCS += $(SASRC)/uuid/uuid_create_nil.c
SRCS += $(SASRC)/uuid/uuid_equal.c
SRCS += $(SASRC)/uuid/uuid_is_nil.c

SRCS += $(SASRC)/uuid_from_string.c
SRCS += $(SASRC)/uuid_to_string.c

OBJECTS += uuid_create_nil.o uuid_equal.o uuid_from_string.o uuid_is_nil.o \
	uuid_to_string.o

# decompression functionality from libbz2
# NOTE: to actually test this functionality after libbz2 upgrade compile
# loader(8) with LOADER_BZIP2_SUPPORT defined
objs/_bzlib.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
objs/_bzlib.o := CPPFLAGS += -I$(SRC)/common/bzip2
objs/_bzlib.o: libstand_bzlib_private.h
pics/_bzlib.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
pics/_bzlib.o := CPPFLAGS += -I$(SRC)/common/bzip2
pics/_bzlib.o: libstand_bzlib_private.h
objs/_crctable.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
objs/_crctable.o := CPPFLAGS += -I$(SRC)/common/bzip2
objs/_crctable.o: libstand_bzlib_private.h
pics/_crctable.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
pics/_crctable.o := CPPFLAGS += -I$(SRC)/common/bzip2
pics/_crctable.o: libstand_bzlib_private.h
objs/_decompress.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
objs/_decompress.o := CPPFLAGS += -I$(SRC)/common/bzip2
objs/_decompress.o: libstand_bzlib_private.h
pics/_decompress.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
pics/_decompress.o := CPPFLAGS += -I$(SRC)/common/bzip2
pics/_decompress.o: libstand_bzlib_private.h
objs/_huffman.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
objs/_huffman.o := CPPFLAGS += -I$(SRC)/common/bzip2
objs/_huffman.o: libstand_bzlib_private.h
pics/_huffman.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
pics/_huffman.o := CPPFLAGS += -I$(SRC)/common/bzip2
pics/_huffman.o: libstand_bzlib_private.h
objs/_randtable.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
objs/_randtable.o := CPPFLAGS += -I$(SRC)/common/bzip2
objs/_randtable.o: libstand_bzlib_private.h
pics/_randtable.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
pics/_randtable.o := CPPFLAGS += -I$(SRC)/common/bzip2
pics/_randtable.o: libstand_bzlib_private.h
objs/bzipfs.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
objs/bzipfs.o := CPPFLAGS += -I$(SRC)/common/bzip2
objs/bzipfs.o: libstand_bzlib_private.h
pics/bzipfs.o := CPPFLAGS += -DBZ_LOADER -DBZ_NO_STDIO -DBZ_NO_COMPRESS
pics/bzipfs.o := CPPFLAGS += -I$(SRC)/common/bzip2
pics/bzipfs.o: libstand_bzlib_private.h
SRCS +=	libstand_bzlib_private.h

# too hairy
objs/_inflate.o := SMATCH=off
pics/_inflate.o := SMATCH=off

SRCS +=	_bzlib.c _crctable.c _decompress.c _huffman.c _randtable.c
OBJECTS += _bzlib.o _crctable.o _decompress.o _huffman.o _randtable.o
CLEANFILES += _bzlib.c _crctable.c _decompress.c _huffman.c _randtable.c

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
objs/adler32.o := CPPFLAGS += -I$(ZLIB)
pics/adler32.o := CPPFLAGS += -I$(ZLIB)
objs/crc32.o := CPPFLAGS += -I$(ZLIB)
pics/crc32.o := CPPFLAGS += -I$(ZLIB)
objs/_infback.o := CPPFLAGS += -I$(ZLIB)
pics/_infback.o := CPPFLAGS += -I$(ZLIB)
objs/_infback.o pics/_infback.o: libstand_zutil.h libstand_gzguts.h
objs/_inffast.o := CPPFLAGS += -I$(ZLIB)
pics/_inffast.o := CPPFLAGS += -I$(ZLIB)
objs/_inffast.o pics/_inffast.o: libstand_zutil.h libstand_gzguts.h
objs/_inflate.o := CPPFLAGS += -I$(ZLIB)
pics/_inflate.o := CPPFLAGS += -I$(ZLIB)
objs/_inflate.o pics/_inflate.o: libstand_zutil.h libstand_gzguts.h
objs/_inftrees.o := CPPFLAGS += -I$(ZLIB)
pics/_inftrees.o := CPPFLAGS += -I$(ZLIB)
objs/_inftrees.o pics/_inftrees.o: libstand_zutil.h libstand_gzguts.h
objs/_zutil.o := CPPFLAGS += -I$(ZLIB)
pics/_zutil.o := CPPFLAGS += -I$(ZLIB)
objs/_zutil.o pics/_zutil.o: libstand_zutil.h libstand_gzguts.h
objs/gzipfs.o := CPPFLAGS += -I$(ZLIB)
pics/gzipfs.o := CPPFLAGS += -I$(ZLIB)
objs/gzip.o := CPPFLAGS += -I$(ZLIB)
pics/gzip.o := CPPFLAGS += -I$(ZLIB)

SRCS +=	$(ZLIB)/adler32.c $(ZLIB)/crc32.c \
	libstand_zutil.h libstand_gzguts.h
OBJECTS += adler32.o crc32.o

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
OBJECTS += _infback.o _inffast.o _inflate.o _inftrees.o _zutil.o
CLEANFILES += _infback.c _inffast.c _inflate.c _inftrees.c _zutil.c

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

# lz4 decompression functionality
pics/lz4.o := CPPFLAGS += -I$(LZ4)
objs/lz4.o := CPPFLAGS += -I$(LZ4)
SRCS += $(LZ4)/lz4.c
OBJECTS += lz4.o

# io routines
SRCS +=	$(SASRC)/closeall.c $(SASRC)/dev.c \
	$(SASRC)/ioctl.c $(SASRC)/nullfs.c \
	$(SASRC)/stat.c $(SASRC)/fstat.c $(SASRC)/close.c \
	$(SASRC)/lseek.c $(SASRC)/open.c $(SASRC)/read.c \
	$(SASRC)/write.c $(SASRC)/readdir.c

OBJECTS += closeall.o dev.o ioctl.o nullfs.o stat.o fstat.o close.o lseek.o \
	open.o read.o write.o readdir.o

# SMBios routines
SRCS += smbios.c
OBJECTS += smbios.o
# Export serial numbers, UUID, and asset tag from loader.
# Use little-endian UUID format as defined in SMBIOS 2.6.
pics/smbios.o := CPPFLAGS += -DSMBIOS_SERIAL_NUMBERS -DSMBIOS_LITTLE_ENDIAN_UUID
objs/smbios.o := CPPFLAGS += -DSMBIOS_SERIAL_NUMBERS -DSMBIOS_LITTLE_ENDIAN_UUID

# network routines
SRCS +=	$(SASRC)/arp.c $(SASRC)/ether.c $(SASRC)/ip.c \
	$(SASRC)/inet_ntoa.c $(SASRC)/in_cksum.c \
	$(SASRC)/net.c $(SASRC)/udp.c $(SASRC)/netif.c \
	$(SASRC)/rpc.c
OBJECTS += arp.o ether.o ip.o inet_ntoa.o in_cksum.o net.o udp.o netif.o rpc.o

# network info services:
SRCS +=	$(SASRC)/bootp.c $(SASRC)/rarp.c \
	$(SASRC)/bootparam.c
OBJECTS += bootp.o rarp.o bootparam.o

# boot filesystems
SRCS +=	$(SASRC)/ufs.c
SRCS += $(SASRC)/nfs.c
SRCS += $(SASRC)/cd9660.c
SRCS += $(SASRC)/tftp.c
SRCS += $(SASRC)/gzipfs.c
SRCS += $(SASRC)/bzipfs.c
SRCS += $(SASRC)/dosfs.c
OBJECTS += ufs.o
OBJECTS += nfs.o
OBJECTS += cd9660.o
OBJECTS += tftp.o
OBJECTS += gzipfs.o
OBJECTS += bzipfs.o
OBJECTS += dosfs.o

# utility
SRCS += $(SRC)/common/util/explicit_bzero.c
SRCS += $(SRC)/common/util/memmem.c
OBJECTS += explicit_bzero.o
OBJECTS += memmem.o
