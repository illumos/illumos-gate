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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

include $(SRC)/Makefile.master

#
# Common sources come from following directory:
COMMON			= ../common/

include $(SRC)/lib/iconv_modules/Makefile.iconv
include $(SRC)/lib/iconv_modules/utf-8/Makefile.iconv

CLEANFILES =    *.o *.so

.NO_PARALLEL:

.PARALLEL: $(DYNOBJS)

all: $(DYNOBJS)

install: all $(ICONV_DIR)
	for f in $(DYNOBJS) ; do \
		TMP=`echo $$f | $(TR) "+" "%"` ; \
		echo installing $$TMP to $(ICONV_DIR) ; \
		$(RM) $(ICONV_DIR)/$$TMP ; \
		$(CP) $$f $(ICONV_DIR)/$$TMP ; \
		$(CHMOD) 755 $(ICONV_DIR)/$$TMP ; \
	done
	-@echo "done."

clobber: clean

LDLIBS			= -lc

LDFLAGS = $(DYNFLAGS) $(LDLIBS) $(CFLAG_OPT)

# needs work
SMATCH=off

$(DYNOBJS)		:= CFLAGS += $(XREGSFLAG) $(C_PICFLAGS) -D_REENTRANT \
				-I$(COMMON) -I$(COMMON)/tbls $(CPPFLAGS)

$(UCS_2_SOS)		:= CFLAGS += -DUCS_2
$(UCS_2BE_SOS)		:= CFLAGS += -DUCS_2BE
$(UCS_2LE_SOS)		:= CFLAGS += -DUCS_2LE

$(UTF_16_SOS)		:= CFLAGS += -DUTF_16
$(UTF_16BE_SOS)		:= CFLAGS += -DUTF_16BE
$(UTF_16LE_SOS)		:= CFLAGS += -DUTF_16LE

$(UTF_32_SOS)		:= CFLAGS += -DUTF_32
$(UTF_32BE_SOS)		:= CFLAGS += -DUTF_32BE
$(UTF_32LE_SOS)		:= CFLAGS += -DUTF_32LE

$(UCS_4_SOS)		:= CFLAGS += -DUCS_4
$(UCS_4BE_SOS)		:= CFLAGS += -DUCS_4BE
$(UCS_4LE_SOS)		:= CFLAGS += -DUCS_4LE

$(UTF_8_SOS)		:= CFLAGS += -DUTF_8

$(US_ASCII_SOS)		:= CFLAGS += -DUS_ASCII
$(ISO_8859_1_SOS)	:= CFLAGS += -DISO_8859_1
$(ISO_8859_2_SOS)	:= CFLAGS += -DISO_8859_2
$(ISO_8859_3_SOS)	:= CFLAGS += -DISO_8859_3
$(ISO_8859_4_SOS)	:= CFLAGS += -DISO_8859_4
$(ISO_8859_5_SOS)	:= CFLAGS += -DISO_8859_5
$(ISO_8859_6_SOS)	:= CFLAGS += -DISO_8859_6
$(ISO_8859_7_SOS)	:= CFLAGS += -DISO_8859_7
$(ISO_8859_8_SOS)	:= CFLAGS += -DISO_8859_8
$(ISO_8859_9_SOS)	:= CFLAGS += -DISO_8859_9
$(ISO_8859_10_SOS)	:= CFLAGS += -DISO_8859_10
$(ISO_8859_13_SOS)	:= CFLAGS += -DISO_8859_13
$(ISO_8859_14_SOS)	:= CFLAGS += -DISO_8859_14
$(ISO_8859_15_SOS)	:= CFLAGS += -DISO_8859_15
$(ISO_8859_16_SOS)	:= CFLAGS += -DISO_8859_16
$(KOI8_R)		:= CFLAGS += -DKOI8_R
$(KOI8_U)		:= CFLAGS += -DKOI8_U
$(PTCP154)		:= CFLAGS += -DPTCP154
$(CP437_SOS)		:= CFLAGS += -DCP437
$(CP720_SOS)		:= CFLAGS += -DCP720
$(CP737_SOS)		:= CFLAGS += -DCP737
$(CP775_SOS)		:= CFLAGS += -DCP775
$(CP850_SOS)		:= CFLAGS += -DCP850
$(CP852_SOS)		:= CFLAGS += -DCP852
$(CP855_SOS)		:= CFLAGS += -DCP855
$(CP857_SOS)		:= CFLAGS += -DCP857
$(CP860_SOS)		:= CFLAGS += -DCP860
$(CP861_SOS)		:= CFLAGS += -DCP861
$(CP862_SOS)		:= CFLAGS += -DCP862
$(CP863_SOS)		:= CFLAGS += -DCP863
$(CP864_SOS)		:= CFLAGS += -DCP864
$(CP865_SOS)		:= CFLAGS += -DCP865
$(CP866_SOS)		:= CFLAGS += -DCP866
$(CP869_SOS)		:= CFLAGS += -DCP869
$(CP874_SOS)		:= CFLAGS += -DCP874
$(CP1250_SOS)		:= CFLAGS += -DCP1250
$(CP1251_SOS)		:= CFLAGS += -DCP1251
$(CP1252_SOS)		:= CFLAGS += -DCP1252
$(CP1253_SOS)		:= CFLAGS += -DCP1253
$(CP1254_SOS)		:= CFLAGS += -DCP1254
$(CP1255_SOS)		:= CFLAGS += -DCP1255
$(CP1256_SOS)		:= CFLAGS += -DCP1256
$(CP1257_SOS)		:= CFLAGS += -DCP1257
$(CP1258_SOS)		:= CFLAGS += -DCP1258

$(ACE_TO_UTF_8_SO)	:= CFLAGS += -DICV_ACE_TO_UTF8
$(ACE_ALLOW_UNAS_TO_UTF_8_SO)	:= CFLAGS += -DICV_ACE_TO_UTF8 \
						-DICV_IDN_ALLOW_UNASSIGNED
$(UTF_8_TO_ACE_SO)	:= CFLAGS += -DICV_UTF8_TO_ACE
$(UTF_8_TO_ACE_ALLOW_UNAS_SO)	:= CFLAGS += -DICV_UTF8_TO_ACE \
                                               -DICV_IDN_ALLOW_UNASSIGNED
#
# Dependencies and actual compilations are defined at below.
$(SB_TO_UCS_SOS): $(COMMON)/common_defs.h $(COMMON)/sb_to_ucs.h $(COMMON)/sb_to_ucs.c
	$(CC) $(CFLAGS) $(COMMON)/sb_to_ucs.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UCS_TO_SB_SOS): $(COMMON)/common_defs.h $(COMMON)/ucs_to_sb.h $(COMMON)/ucs_to_sb.c
	$(CC) $(CFLAGS) $(COMMON)/ucs_to_sb.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(SB_TO_UTF_8_SOS): $(COMMON)/common_defs.h $(COMMON)/sb_to_utf8.h $(COMMON)/sb_to_utf8.c
	$(CC) $(CFLAGS) $(COMMON)/sb_to_utf8.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UTF_8_TO_SB_SOS): $(COMMON)/common_defs.h $(COMMON)/utf8_to_sb.h $(COMMON)/utf8_to_sb.c
	$(CC) $(CFLAGS) $(COMMON)/utf8_to_sb.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UCS_4_TO_UCS_SOS): $(COMMON)/common_defs.h $(COMMON)/ucs4_to_ucs.h $(COMMON)/ucs4_to_ucs.c
	$(CC) $(CFLAGS) $(COMMON)/ucs4_to_ucs.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UCS_TO_UCS_4_SOS): $(COMMON)/common_defs.h $(COMMON)/ucs_to_ucs4.h $(COMMON)/ucs_to_ucs4.c
	$(CC) $(CFLAGS) $(COMMON)/ucs_to_ucs4.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UCS_4_TO_UTF_32_SOS): $(COMMON)/common_defs.h $(COMMON)/ucs4_to_ucs.h $(COMMON)/ucs4_to_ucs.c
	$(CC) $(CFLAGS) $(COMMON)/ucs4_to_utf32.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UTF_32_TO_UCS_4_SOS): $(COMMON)/common_defs.h $(COMMON)/ucs_to_ucs4.h $(COMMON)/ucs_to_ucs4.c
	$(CC) $(CFLAGS) $(COMMON)/utf32_to_ucs4.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UCS_TO_UTF_8_SOS): $(COMMON)/common_defs.h $(COMMON)/ucs_to_utf8.h $(COMMON)/ucs_to_utf8.c
	$(CC) $(CFLAGS) $(COMMON)/ucs_to_utf8.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UTF_8_TO_UCS_SOS): $(COMMON)/common_defs.h $(COMMON)/utf8_to_ucs.h $(COMMON)/utf8_to_ucs.c
	$(CC) $(CFLAGS) $(COMMON)/utf8_to_ucs.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UCS_TO_UTF_7_SOS): $(COMMON)/common_defs.h $(COMMON)/ucs_to_utf7.h $(COMMON)/ucs_to_utf7.c
	$(CC) $(CFLAGS) $(COMMON)/ucs_to_utf7.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UTF_7_TO_UCS_SOS): $(COMMON)/common_defs.h $(COMMON)/utf7_to_ucs.h $(COMMON)/utf7_to_ucs.c
	$(CC) $(CFLAGS) $(COMMON)/utf7_to_ucs.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UTF_8_TO_UTF_EBCDIC_SO): $(COMMON)/common_defs.h $(COMMON)/utf8_to_utf_ebcdic.h $(COMMON)/utf8_to_utf_ebcdic.c
	$(CC) $(CFLAGS) $(COMMON)/utf8_to_utf_ebcdic.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(UTF_EBCDIC_TO_UTF_8_SO): $(COMMON)/common_defs.h $(COMMON)/utf_ebcdic_to_utf8.h $(COMMON)/utf_ebcdic_to_utf8.c
	$(CC) $(CFLAGS) $(COMMON)/utf_ebcdic_to_utf8.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(ACE_TO_UTF_8_SO): $(COMMON)/ace.h $(COMMON)/ace_utf8.c
	$(CC) $(CFLAGS) $(COMMON)/ace_utf8.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)

$(ACE_ALLOW_UNAS_TO_UTF_8_SO): $(COMMON)/ace.h $(COMMON)/ace_utf8.c
	$(CC) $(CFLAGS) $(COMMON)/ace_utf8.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $@.o
	$(POST_PROCESS_SO)

$(UTF_8_TO_ACE_SO): $(COMMON)/ace.h $(COMMON)/ace_utf8.c
	$(CC) $(CFLAGS) $(COMMON)/ace_utf8.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $@.o
	$(POST_PROCESS_SO)

$(UTF_8_TO_ACE_ALLOW_UNAS_SO): $(COMMON)/ace.h $(COMMON)/ace_utf8.c
	$(CC) $(CFLAGS) $(COMMON)/ace_utf8.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $@.o
	$(POST_PROCESS_SO)

$(UTF_8_TO_UTF_8_SO): $(COMMON)/common_defs.h $(COMMON)/utf8.c
	$(CC) $(CFLAGS) $(COMMON)/utf8.c -c -o $@.o
	$(CC) $(LDFLAGS) $(CFLAGS)  -o  $@ $@.o
	$(POST_PROCESS_SO)
