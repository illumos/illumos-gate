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
# Copyright 2015 Toomas Soome <tsoome@me.com>
#

BINDIR=	/boot

# Options used when building app-specific efi components
# See conf/kern.mk for the correct set of these
CFLAGS +=	-m64 -fPIC -ffreestanding -Wformat -msoft-float
CFLAGS +=	-mno-mmx -mno-sse -mno-avx -fshort-wchar -mno-red-zone -mno-aes
CFLAGS +=	-std=gnu99 -Wno-pointer-sign -Wno-empty-body

#CFLAGS +=	-Wsystem-headers -Werror -Wall -Wno-format-y2k -W
#CFLAGS +=	-Wno-unused-parameter -Wstrict-prototypes -Wmissing-prototypes
#CFLAGS +=	-Wpointer-arith -Wreturn-type -Wcast-qual -Wwrite-strings
#CFLAGS +=	-Wswitch -Wshadow -Wunused-parameter -Wcast-align -Wno-cast-qual
#CFLAGS +=	-Wchar-subscripts -Winline -Wnested-externs -Wredundant-decls
#CFLAGS +=	-Wold-style-definition

# include ../Makefile.inc
