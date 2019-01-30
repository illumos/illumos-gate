#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at src/OPENSOLARIS.LICENSE.
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
# Copyright (c) 2018, Joyent, Inc.

SRCS		=	tcvn%UCS-2.c \
            tcvn%UTF-8.c \
            tcvn%viscii.c \
            UCS-2%tcvn.c  \
            UCS-2%viscii.c  \
            UTF-8%tcvn.c  \
            UTF-8%viscii.c  \
            viscii%tcvn.c  \
            viscii%UCS-2.c  \
            viscii%UTF-8.c
COMMON = ../common/

LINK_TARGETS  = UCS-2BE%tcvn.so tcvn%UCS-2BE.so
LINK_TARGETS += UCS-2BE%viscii.so viscii%UCS-2BE.so

# needs work
SMOFF += all_func_returns,deref_check

dummy: all

tcvn%UCS-2LE.o: $(COMMON)tcvn%UCS-2.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DUCS_2LE -c -o $@ $^

tcvn%UCS-2BE.o: $(COMMON)tcvn%UCS-2.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

viscii%UCS-2LE.o: $(COMMON)viscii%UCS-2.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DUCS_2LE -c -o $@ $^

viscii%UCS-2BE.o: $(COMMON)viscii%UCS-2.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

UCS-2LE%tcvn.o: $(COMMON)UCS-2%tcvn.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DUCS_2LE -c -o $@ $^

UCS-2BE%tcvn.o: $(COMMON)UCS-2%tcvn.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

UCS-2LE%viscii.o: $(COMMON)UCS-2%viscii.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DUCS_2LE -c -o $@ $^

UCS-2BE%viscii.o: $(COMMON)UCS-2%viscii.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $^

include $(SRC)/lib/iconv_modules/Makefile.iconv

$(CREATE_LINKS):  $(ICONV_LINK_TARGETS)
	$(SYMLINK) -f tcvn%UCS-2BE.so $(ICONV_DIR)/tcvn%UCS-2.so
	$(SYMLINK) -f UCS-2BE%tcvn.so $(ICONV_DIR)/UCS-2%tcvn.so
	$(SYMLINK) -f UCS-2BE%viscii.so $(ICONV_DIR)/UCS-2%viscii.so
	$(SYMLINK) -f viscii%UCS-2BE.so $(ICONV_DIR)/viscii%UCS-2.so
	$(TOUCH) $@

ALL_SOS  = tcvn%UCS-2LE.so		tcvn%UCS-2BE.so
ALL_SOS += viscii%UCS-2LE.so		viscii%UCS-2BE.so
ALL_SOS += UCS-2LE%tcvn.so		UCS-2BE%tcvn.so
ALL_SOS += UCS-2LE%viscii.so		UCS-2BE%viscii.so
ALL_SOS += UTF-8%tcvn.so			tcvn%UTF-8.so
ALL_SOS += UTF-8%viscii.so		viscii%UTF-8.so
ALL_SOS += tcvn%viscii.so			viscii%tcvn.so

all: $(ALL_SOS)
