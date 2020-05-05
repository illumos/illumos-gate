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
# Copyright (c) 2018, Joyent, Inc.


include $(SRC)/lib/iconv_modules/Makefile.iconv

install		:=	TARGET = install
all		:=	TARGET = all
clean		:=	TARGET = clean
clobber		:=	TARGET = clobber

dummy:	all

COMMON  = ../common/
ICONV_COMMON  = ../../common/

SRCS    = byte_to_comb.c comb_to_byte.c \
	euc_to_iso2022-7.c iso2022-7_to_euc.c \
	euc_to_johap92.c johap92_to_euc.c \
	euc_to_johap.c johap_to_euc.c \
	euc_to_nbyte.c nbyte_to_euc.c \
	uhang_to_utf_sub.c uhang_to_utf_main.c \
	utf_to_uhang_sub.c utf_to_uhang_main.c \
	unihan_to_UCS_sub.c unihan_to_UCS_main.c \
	ucs_to_unihan.c \
	\
	euc_to_utf_main.c \
	utf_to_euc_main.c \
	njh_to_utf_main.c \
	utf_to_njh_main.c \
	ojh_to_utf_main.c \
	utf_to_ojh_main.c \
	iso_to_utf_main.c \
	utf_to_iso_main.c


E2I     = ko_KR-euc%ko_KR-iso2022-7.so
I2E     = ko_KR-iso2022-7%ko_KR-euc.so
E2J92   = ko_KR-euc%ko_KR-johap92.so
J922E   = ko_KR-johap92%ko_KR-euc.so
E2J     = ko_KR-euc%ko_KR-johap.so
J2E     = ko_KR-johap%ko_KR-euc.so
E2NB    = ko_KR-euc%ko_KR-nbyte.so
NB2E    = ko_KR-nbyte%ko_KR-euc.so
U2UH    = ko_KR-UTF-8%ko_KR-cp949.so
UH2U    = ko_KR-cp949%ko_KR-UTF-8.so

UCS2LE2UH = UCS-2LE%ko_KR-cp949.so
UH2UCS2LE = ko_KR-cp949%UCS-2LE.so
UCS2BE2UH = UCS-2BE%ko_KR-cp949.so
UH2UCS2BE = ko_KR-cp949%UCS-2BE.so

E2U     = ko_KR-euc%ko_KR-UTF-8.so
U2E     = ko_KR-UTF-8%ko_KR-euc.so
N2U     = ko_KR-johap92%ko_KR-UTF-8.so
U2N     = ko_KR-UTF-8%ko_KR-johap92.so
O2U     = ko_KR-johap%ko_KR-UTF-8.so
U2O     = ko_KR-UTF-8%ko_KR-johap.so
I2U     = ko_KR-iso2022-7%ko_KR-UTF-8.so
U2I     = ko_KR-UTF-8%ko_KR-iso2022-7.so

C9332U  = ko_KR-cp933%ko_KR-UTF-8.so
U2C933  = ko_KR-UTF-8%ko_KR-cp933.so

ALL_SOS   = $(E2I) $(I2E) $(E2J92) $(J922E) $(E2J) $(J2E) $(E2NB) $(NB2E) \
	$(U2UH) $(UH2U) $(UH2UCS2LE) $(UCS2LE2UH) $(UH2UCS2BE) $(UCS2BE2UH) \
	$(U2E) $(E2U) $(N2U) $(U2N) $(O2U) $(U2O) $(I2U) $(U2I) \
	$(C9332U) $(U2C933)

LDFLAGS = $(DYNFLAGS) $(LDLIBS) $(CFLAG_OPT)
CPPFLAGS += -I$(ICONV_COMMON) -I../inc

# needs work
SMATCH=off

LINK_TARGETS = $(U2UH) $(C9332U) $(UH2U) $(E2U) $(I2U) $(O2U) $(N2U) \
	$(E2I) $(E2J) $(E2J92) $(E2NB) $(I2E) $(J2E) $(J922E) $(NVBE) \
	$(UCS2BE2UH) $(U2LE2UH) $(U2C933) $(U2E) $(U2I) $(U2O) $(U2N) \
	$(UH2UCS2BE) $(UH2UCS2LE)

all: $(ALL_SOS)

#
# libraries
#
$(E2I): euc_to_iso2022-7.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ euc_to_iso2022-7.o
	$(POST_PROCESS_SO)

$(I2E): iso2022-7_to_euc.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ iso2022-7_to_euc.o
	$(POST_PROCESS_SO)

$(E2J92): euc_to_johap92.o ktable.o comp_to_pack.o c2p.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ comp_to_pack.o c2p.o euc_to_johap92.o ktable.o
	$(POST_PROCESS_SO)

$(J922E): johap92_to_euc.o ktable.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ johap92_to_euc.o ktable.o
	$(POST_PROCESS_SO)

$(E2J): euc_to_johap.o ktable.o comp_to_pack.o c2p.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ euc_to_johap.o ktable.o comp_to_pack.o c2p.o
	$(POST_PROCESS_SO)

$(J2E): johap_to_euc.o ktable.o pack_to_comp.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ johap_to_euc.o ktable.o pack_to_comp.o
	$(POST_PROCESS_SO)

$(E2NB): euc_to_nbyte.o comb_to_byte.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ euc_to_nbyte.o comb_to_byte.o c2p.o ktable.o
	$(POST_PROCESS_SO)

$(NB2E): nbyte_to_euc.o byte_to_comb.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ nbyte_to_euc.o byte_to_comb.o c2p.o ktable.o pack_to_comp.o
	$(POST_PROCESS_SO)

$(U2UH): utf_to_uhang_main.o utf_to_uhang_sub.o common_utf.o common_utf8.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ utf_to_uhang_main.o utf_to_uhang_sub.o common_utf.o common_utf8.o
	$(POST_PROCESS_SO)

$(UH2U): uhang_to_utf_main.o uhang_to_utf_sub.o common_utf.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ uhang_to_utf_main.o uhang_to_utf_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(UH2UCS2LE) : unihan_to_UCS_sub.o unihan_to_UCS-2LE_main.o common_utf.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ unihan_to_UCS_sub.o unihan_to_UCS-2LE_main.o common_utf.o
	$(POST_PROCESS_SO)

$(UCS2LE2UH) : ucs_LE_to_unihan.o utf_to_uhang_sub.o common_utf.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ ucs_LE_to_unihan.o utf_to_uhang_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(UH2UCS2BE) : unihan_to_UCS_sub.o unihan_to_UCS-2BE_main.o common_utf.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ unihan_to_UCS_sub.o unihan_to_UCS-2BE_main.o common_utf.o
	$(POST_PROCESS_SO)

$(UCS2BE2UH) : ucs_BE_to_unihan.o utf_to_uhang_sub.o common_utf.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ ucs_BE_to_unihan.o utf_to_uhang_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(E2U): euc_to_utf_main.o euc_to_utf_sub.o common_utf.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ euc_to_utf_main.o euc_to_utf_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(U2E): utf_to_euc_main.o utf_to_euc_sub.o common_utf.o common_utf8.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ utf_to_euc_main.o utf_to_euc_sub.o common_utf.o common_utf8.o
	$(POST_PROCESS_SO)

$(N2U): njh_to_utf_main.o njh_to_utf_sub.o common_utf.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ njh_to_utf_main.o njh_to_utf_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(U2N): utf_to_njh_main.o utf_to_njh_sub.o common_utf.o common_utf8.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ utf_to_njh_main.o utf_to_njh_sub.o common_utf.o common_utf8.o
	$(POST_PROCESS_SO)

$(O2U): ojh_to_utf_main.o ojh_to_utf_sub.o common_utf.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ ojh_to_utf_main.o ojh_to_utf_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(U2O): utf_to_ojh_main.o utf_to_ojh_sub.o common_utf.o common_utf8.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ utf_to_ojh_main.o utf_to_ojh_sub.o common_utf.o common_utf8.o
	$(POST_PROCESS_SO)

$(I2U): iso_to_utf_main.o euc_to_utf_sub.o common_utf.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ iso_to_utf_main.o euc_to_utf_sub.o common_utf.o
	$(POST_PROCESS_SO)

$(U2I): utf_to_iso_main.o utf_to_euc_sub.o common_utf.o common_utf8.o $(COMMON)common_def.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ utf_to_iso_main.o utf_to_euc_sub.o common_utf.o common_utf8.o
	$(POST_PROCESS_SO)

$(U2C933): UTF8_to_Cp933.o utf8%ibm.o tab_lookup.o $(ICONV_COMMON)tab_lookup.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ UTF8_to_Cp933.o utf8%ibm.o tab_lookup.o
	$(POST_PROCESS_SO)

$(C9332U): Cp933_to_UTF8.o ibm%utf8.o tab_lookup.o $(ICONV_COMMON)tab_lookup.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ Cp933_to_UTF8.o ibm%utf8.o tab_lookup.o
	$(POST_PROCESS_SO)

#
# objs
#
common_utf8.o: $(ICONV_COMMON)common_utf8.c $(COMMON)common_def.h
	$(CC) $(CPPFLAGS) -c $(CFLAGS) $(ICONV_COMMON)common_utf8.c -o $@
	$(POST_PROCESS_O)

ucs_LE_to_unihan.o : $(COMMON)ucs_to_unihan.c
	$(CC) $(CPPFLAGS) -c $(CFLAGS) -DUCS_2LE $(COMMON)ucs_to_unihan.c -o $@
	$(POST_PROCESS_O)

ucs_BE_to_unihan.o : $(COMMON)ucs_to_unihan.c
	$(CC) $(CPPFLAGS) -c $(CFLAGS) -DUCS_2BE $(COMMON)ucs_to_unihan.c -o $@
	$(POST_PROCESS_O)

unihan_to_UCS-2BE_main.o : $(COMMON)unihan_to_UCS_main.c
	$(CC) $(CPPFLAGS) -c $(CFLAGS) -DUCS_2BE $(COMMON)unihan_to_UCS_main.c -o $@
	$(POST_PROCESS_O)

unihan_to_UCS-2LE_main.o : $(COMMON)unihan_to_UCS_main.c
	$(CC) $(CPPFLAGS) -c $(CFLAGS) -DUCS_2LE $(COMMON)unihan_to_UCS_main.c -o $@
	$(POST_PROCESS_O)

ibm%utf8.o : $(ICONV_COMMON)ibm%utf8.c  $(COMMON)common_def.h
	$(CC) $(CPPFLAGS) -c $(CFLAGS) $(ICONV_COMMON)ibm%utf8.c -o $@
	$(POST_PROCESS_O)

utf8%ibm.o: $(ICONV_COMMON)utf8%ibm.c $(COMMON)common_def.h
	$(CC) $(CPPFLAGS) -c $(CFLAGS) $(ICONV_COMMON)utf8%ibm.c -o $@
	$(POST_PROCESS_O)

cnv_utf8ibm.o: $(ICONV_COMMON)cnv_utf8ibm.c $(ICONV_COMMON)tab_lookup.h
	$(CC) $(CPPFLAGS) -c $(CFLAGS) $(ICONV_COMMON)cnv_utf8ibm.c -o $@
	$(POST_PROCESS_O)

cnv_ibmutf8.o: $(ICONV_COMMON)cnv_ibmutf8.c $(ICONV_COMMON)tab_lookup.h
	$(CC) $(CPPFLAGS) -c $(CFLAGS) $(ICONV_COMMON)cnv_ibmutf8.c -o $@
	$(POST_PROCESS_O)

tab_lookup.o: $(ICONV_COMMON)tab_lookup.c $(ICONV_COMMON)tab_lookup.h
	$(CC) $(CPPFLAGS) -c $(CFLAGS) $(ICONV_COMMON)tab_lookup.c -o $@
	$(POST_PROCESS_O)

Cp933_to_UTF8.o: $(COMMON)Cp933_to_UTF8.c $(ICONV_COMMON)tab_lookup.h  $(COMMON)cp933_ucs2.h
	$(CC) $(CPPFLAGS) -c $(CFLAGS) $(COMMON)Cp933_to_UTF8.c -o $@
	$(POST_PROCESS_O)

UTF8_to_Cp933.o: $(COMMON)UTF8_to_Cp933.c $(ICONV_COMMON)tab_lookup.h $(COMMON)ucs2_cp933.h
	$(CC) $(CPPFLAGS) -c $(CFLAGS) $(COMMON)UTF8_to_Cp933.c -o $@
	$(POST_PROCESS_O)

#
# Proto area symlinks
#
$(CREATE_LINKS):	$(ICONV_LINK_TARGETS)
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-cp949.so $(ICONV_DIR)/ko_KR-UTF-8%UnifiedHangul.so
	$(SYMLINK) -f ko_KR-cp933%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR-cp933%UTF-8.so
	$(SYMLINK) -f ko_KR-cp949%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR-cp949%UTF-8.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR-euc%UTF-8.so
	$(SYMLINK) -f ko_KR-iso2022-7%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR-iso2022-7%UTF-8.so
	$(SYMLINK) -f ko_KR-johap%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR-johap%UTF-8.so
	$(SYMLINK) -f ko_KR-johap92%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR-johap92%UTF-8.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR.EUC%UTF-8.so
	$(SYMLINK) -f ko_KR-cp933%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR.cp933%UTF-8.so
	$(SYMLINK) -f ko_KR-cp949%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR.cp949%UTF-8.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR.euc%UTF-8.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-iso2022-7.so $(ICONV_DIR)/ko_KR.euc%ko_KR.iso2022-7.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-johap.so $(ICONV_DIR)/ko_KR.euc%ko_KR.johap.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-johap92.so $(ICONV_DIR)/ko_KR.euc%ko_KR.johap92.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-nbyte.so $(ICONV_DIR)/ko_KR.euc%ko_KR.nbyte.so
	$(SYMLINK) -f ko_KR-iso2022-7%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR.iso2022-7%UTF-8.so
	$(SYMLINK) -f ko_KR-iso2022-7%ko_KR-euc.so $(ICONV_DIR)/ko_KR.iso2022-7%ko_KR.euc.so
	$(SYMLINK) -f ko_KR-johap%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR.johap%UTF-8.so
	$(SYMLINK) -f ko_KR-johap%ko_KR-euc.so $(ICONV_DIR)/ko_KR.johap%ko_KR.euc.so
	$(SYMLINK) -f ko_KR-johap92%ko_KR-UTF-8.so $(ICONV_DIR)/ko_KR.johap92%UTF-8.so
	$(SYMLINK) -f ko_KR-johap92%ko_KR-euc.so $(ICONV_DIR)/ko_KR.johap92%ko_KR.euc.so
	$(SYMLINK) -f ko_KR-nbyte%ko_KR-euc.so $(ICONV_DIR)/ko_KR.nbyte%ko_KR.euc.so
	$(SYMLINK) -f ko_KR-cp949%UCS-2BE.so $(ICONV_DIR)/5601%UCS-2BE.so
	$(SYMLINK) -f ko_KR-cp949%UCS-2LE.so $(ICONV_DIR)/5601%UCS-2LE.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-UTF-8.so $(ICONV_DIR)/5601%UTF-8.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-UTF-8.so $(ICONV_DIR)/EUC-KR%UTF-8.so
	$(SYMLINK) -f ko_KR-iso2022-7%ko_KR-UTF-8.so $(ICONV_DIR)/ISO-2022-KR%UTF-8.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-UTF-8.so $(ICONV_DIR)/KSC5601%UTF-8.so
	$(SYMLINK) -f ko_KR-euc%ko_KR-UTF-8.so $(ICONV_DIR)/KSX1001%UTF-8.so
	$(SYMLINK) -f UCS-2BE%ko_KR-cp949.so $(ICONV_DIR)/UCS-2BE%5601.so
	$(SYMLINK) -f UCS-2LE%ko_KR-cp949.so $(ICONV_DIR)/UCS-2LE%5601.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-euc.so $(ICONV_DIR)/UTF-8%5601.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-euc.so $(ICONV_DIR)/UTF-8%EUC-KR.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-iso2022-7.so $(ICONV_DIR)/UTF-8%ISO-2022-KR.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-euc.so $(ICONV_DIR)/UTF-8%KSC5601.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-euc.so $(ICONV_DIR)/UTF-8%KSX1001.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-cp933.so $(ICONV_DIR)/UTF-8%ko_KR-cp933.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-cp949.so $(ICONV_DIR)/UTF-8%ko_KR-cp949.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-euc.so $(ICONV_DIR)/UTF-8%ko_KR-euc.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-iso2022-7.so $(ICONV_DIR)/UTF-8%ko_KR-iso2022-7.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-johap.so $(ICONV_DIR)/UTF-8%ko_KR-johap.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-johap92.so $(ICONV_DIR)/UTF-8%ko_KR-johap92.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-euc.so $(ICONV_DIR)/UTF-8%ko_KR.EUC.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-cp933.so $(ICONV_DIR)/UTF-8%ko_KR.cp933.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-cp949.so $(ICONV_DIR)/UTF-8%ko_KR.cp949.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-euc.so $(ICONV_DIR)/UTF-8%ko_KR.euc.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-iso2022-7.so $(ICONV_DIR)/UTF-8%ko_KR.iso2022-7.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-johap.so $(ICONV_DIR)/UTF-8%ko_KR.johap.so
	$(SYMLINK) -f ko_KR-UTF-8%ko_KR-johap92.so $(ICONV_DIR)/UTF-8%ko_KR.johap92.so
	$(SYMLINK) -f ko_KR-cp949%ko_KR-UTF-8.so $(ICONV_DIR)/UnifiedHangul%ko_KR-UTF-8.so
	$(TOUCH) $@
FRC:
