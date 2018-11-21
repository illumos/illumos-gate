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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/lib/iconv_modules/Makefile.iconv

COMMON = ../common/

SRCS	= euc2utf_main.c \
	  utf2euc_main.c \
	  874_to_838_main.c \
	  838_to_874_main.c \
	  common_utf.c \
	  euc2utf_sub.c \
	  utf2euc_sub.c

dummy: all

E2U	= eucTH%UTF-8.so
U2E	= UTF-8%eucTH.so
723	= IBM-874%IBM-838.so
327	= IBM-838%IBM-874.so

ALL_SOS	= $(U2E) $(E2U) $(723) $(327)

CFLAGS += -I$(COMMON)

LDFLAGS = $(DYNFLAGS) $(LDLIBS)

install: all

all:	$(ALL_SOS)

#
# Library
#
$(E2U): euc_to_utf_main.o euc_to_utf_sub.o common_utf.o $(COMMON)common_def.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ euc_to_utf_main.o euc_to_utf_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(U2E): utf_to_euc_main.o utf_to_euc_sub.o common_utf.o $(COMMON)common_def.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ utf_to_euc_main.o utf_to_euc_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(723): 874_to_838_main.o 874_to_838_sub.o common_utf.o $(COMMON)common_def.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ 874_to_838_main.o 874_to_838_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(327): 838_to_874_main.o 838_to_874_sub.o common_utf.o $(COMMON)common_def.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ 838_to_874_main.o 838_to_874_sub.o common_utf.o
	$(POST_PROCESS_SO)
