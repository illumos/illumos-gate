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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/loadkeys/type_4/Makefile

KEYTABLES = \
	us belgium_france germany swiss_german swiss_french uk \
	canada denmark italy netherlands norway portugal spain_latin_america \
	sweden_finland japan korea traditional_chinese us101a_pc \
	reset germany_5 norway_5 sweden_5 uk_5 italy_5 \
	portugal_5 swiss_french_5 us_5 denmark_5 netherlands_5 spain_5 \
	swiss_german_5 france_5 japan_5 korea_5 traditional_chinese_5 canadian_french_5 \
	hungary_5 poland_5 czech_5 russia_5 canadian_french_5_tbits5 \
	germany_hobo norway_hobo sweden_hobo uk_hobo italy_hobo \
	portugal_hobo swiss_french_hobo us_hobo denmark_hobo netherlands_hobo \
	spain_hobo swiss_german_hobo france_hobo japan_hobo korea_hobo \
	traditional_chinese_hobo canadian_french_hobo

include ../../Makefile.cmd

ROOTKEYDIR= $(ROOTSHLIB)/keytables/type_4
ROOTKEYTABLES= $(KEYTABLES:%=$(ROOTKEYDIR)/%)

# there is an install target for each ROOT layout link
#
LAYOUTS= \
	layout_00 layout_01 layout_02 layout_03 layout_04 layout_05 \
	layout_06 layout_07 layout_08 layout_09 layout_0a layout_0b \
	layout_0c layout_0d layout_0e layout_10 layout_11 layout_13 \
	layout_20 layout_21 layout_22 layout_23 layout_24 layout_25 \
	layout_26 layout_27 layout_28 layout_29 layout_2a layout_2b \
	layout_2c layout_2d layout_2e layout_2f layout_30 layout_31 \
	layout_32 layout_33 layout_34 layout_35 layout_36 layout_3f \
	layout_50 layout_51 layout_52 layout_53 layout_54 \
	layout_55 layout_56 layout_57 layout_58 layout_59 layout_5a \
	layout_5b layout_5c layout_5d layout_5e \
	layout_5f layout_60 layout_61

ROOTLINKS= $(LAYOUTS:%=$(ROOTKEYDIR)/%)

$(ROOTKEYTABLES) := FILEMODE = 444

# install rule
$(ROOTKEYDIR)/%: %
	$(INS.file)

COMPATKEYDIR= $(ROOTSHLIB)/keytables

COMPATLINKS= $(LAYOUTS:%=$(COMPATKEYDIR)/%) $(KEYTABLES:%=$(COMPATKEYDIR)/%)

$(COMPATKEYDIR)/%: $(ROOTKEYDIR)/%
	$(RM) $@; ln $< $@

.KEEP_STATE:

all:  $(KEYTABLES)

install: all $(COMPATKEYDIR) $(ROOTKEYDIR) $(ROOTKEYTABLES) $(ROOTLINKS) $(COMPATLINKS)

clean:

$(COMPATKEYDIR):
	$(INS.dir)

$(ROOTKEYDIR): $(COMPATKEYDIR)
	$(INS.dir)

# install targets for ROOT layout links
#
$(ROOTKEYDIR)/layout_00: $(ROOTKEYDIR)/us
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us $@

$(ROOTKEYDIR)/layout_01: $(ROOTKEYDIR)/us
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us $@

$(ROOTKEYDIR)/layout_02: $(ROOTKEYDIR)/belgium_france
	$(RM) $@; $(LN) $(ROOTKEYDIR)/belgium_france $@

$(ROOTKEYDIR)/layout_03: $(ROOTKEYDIR)/canada
	$(RM) $@; $(LN) $(ROOTKEYDIR)/canada $@

$(ROOTKEYDIR)/layout_04: $(ROOTKEYDIR)/denmark
	$(RM) $@; $(LN) $(ROOTKEYDIR)/denmark $@

$(ROOTKEYDIR)/layout_05: $(ROOTKEYDIR)/germany
	$(RM) $@; $(LN) $(ROOTKEYDIR)/germany $@

$(ROOTKEYDIR)/layout_06: $(ROOTKEYDIR)/italy
	$(RM) $@; $(LN) $(ROOTKEYDIR)/italy $@

$(ROOTKEYDIR)/layout_07: $(ROOTKEYDIR)/netherlands
	$(RM) $@; $(LN) $(ROOTKEYDIR)/netherlands $@

$(ROOTKEYDIR)/layout_08: $(ROOTKEYDIR)/norway
	$(RM) $@; $(LN) $(ROOTKEYDIR)/norway $@

$(ROOTKEYDIR)/layout_09: $(ROOTKEYDIR)/portugal
	$(RM) $@; $(LN) $(ROOTKEYDIR)/portugal $@

$(ROOTKEYDIR)/layout_0a: $(ROOTKEYDIR)/spain_latin_america
	$(RM) $@; $(LN) $(ROOTKEYDIR)/spain_latin_america $@

$(ROOTKEYDIR)/layout_0b: $(ROOTKEYDIR)/sweden_finland
	$(RM) $@; $(LN) $(ROOTKEYDIR)/sweden_finland $@

$(ROOTKEYDIR)/layout_0c: $(ROOTKEYDIR)/swiss_french
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_french $@

$(ROOTKEYDIR)/layout_0d: $(ROOTKEYDIR)/swiss_german
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_german $@

$(ROOTKEYDIR)/layout_0e: $(ROOTKEYDIR)/uk
	$(RM) $@; $(LN) $(ROOTKEYDIR)/uk $@

$(ROOTKEYDIR)/layout_10: $(ROOTKEYDIR)/korea
	$(RM) $@; $(LN) $(ROOTKEYDIR)/korea $@

$(ROOTKEYDIR)/layout_11: $(ROOTKEYDIR)/traditional_chinese
	$(RM) $@; $(LN) $(ROOTKEYDIR)/traditional_chinese $@

$(ROOTKEYDIR)/layout_13: $(ROOTKEYDIR)/us101a_pc
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us101a_pc $@

$(ROOTKEYDIR)/layout_20: $(ROOTKEYDIR)/japan
	$(RM) $@; $(LN) $(ROOTKEYDIR)/japan $@

$(ROOTKEYDIR)/layout_21: $(ROOTKEYDIR)/us_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us_5 $@

$(ROOTKEYDIR)/layout_22: $(ROOTKEYDIR)/us_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us_5 $@

$(ROOTKEYDIR)/layout_23: $(ROOTKEYDIR)/france_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/france_5 $@

$(ROOTKEYDIR)/layout_24: $(ROOTKEYDIR)/denmark_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/denmark_5 $@

$(ROOTKEYDIR)/layout_25: $(ROOTKEYDIR)/germany_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/germany_5 $@

$(ROOTKEYDIR)/layout_26: $(ROOTKEYDIR)/italy_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/italy_5 $@

$(ROOTKEYDIR)/layout_27: $(ROOTKEYDIR)/netherlands_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/netherlands_5 $@

$(ROOTKEYDIR)/layout_28: $(ROOTKEYDIR)/norway_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/norway_5 $@

$(ROOTKEYDIR)/layout_29: $(ROOTKEYDIR)/portugal_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/portugal_5 $@

$(ROOTKEYDIR)/layout_2a: $(ROOTKEYDIR)/spain_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/spain_5 $@

$(ROOTKEYDIR)/layout_2b: $(ROOTKEYDIR)/sweden_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/sweden_5 $@

$(ROOTKEYDIR)/layout_2c: $(ROOTKEYDIR)/swiss_french_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_french_5 $@

$(ROOTKEYDIR)/layout_2d: $(ROOTKEYDIR)/swiss_german_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_german_5 $@

$(ROOTKEYDIR)/layout_2e: $(ROOTKEYDIR)/uk_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/uk_5 $@

$(ROOTKEYDIR)/layout_2f: $(ROOTKEYDIR)/korea_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/korea_5 $@

$(ROOTKEYDIR)/layout_30: $(ROOTKEYDIR)/traditional_chinese_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/traditional_chinese_5 $@

$(ROOTKEYDIR)/layout_31: $(ROOTKEYDIR)/japan_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/japan_5 $@

$(ROOTKEYDIR)/layout_32: $(ROOTKEYDIR)/canadian_french_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/canadian_french_5 $@

$(ROOTKEYDIR)/layout_33: $(ROOTKEYDIR)/hungary_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/hungary_5 $@

$(ROOTKEYDIR)/layout_34: $(ROOTKEYDIR)/poland_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/poland_5 $@

$(ROOTKEYDIR)/layout_35: $(ROOTKEYDIR)/czech_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/czech_5 $@

$(ROOTKEYDIR)/layout_36: $(ROOTKEYDIR)/russia_5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/russia_5 $@

$(ROOTKEYDIR)/layout_3f: $(ROOTKEYDIR)/canadian_french_5_tbits5
	$(RM) $@; $(LN) $(ROOTKEYDIR)/canadian_french_5_tbits5 $@

$(ROOTKEYDIR)/layout_50: $(ROOTKEYDIR)/us_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us_hobo $@

$(ROOTKEYDIR)/layout_51: $(ROOTKEYDIR)/us_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us_hobo $@

$(ROOTKEYDIR)/layout_52: $(ROOTKEYDIR)/france_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/france_hobo $@

$(ROOTKEYDIR)/layout_53: $(ROOTKEYDIR)/denmark_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/denmark_hobo $@

$(ROOTKEYDIR)/layout_54: $(ROOTKEYDIR)/germany_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/germany_hobo $@

$(ROOTKEYDIR)/layout_55: $(ROOTKEYDIR)/italy_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/italy_hobo $@

$(ROOTKEYDIR)/layout_56: $(ROOTKEYDIR)/netherlands_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/netherlands_hobo $@

$(ROOTKEYDIR)/layout_57: $(ROOTKEYDIR)/norway_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/norway_hobo $@

$(ROOTKEYDIR)/layout_58: $(ROOTKEYDIR)/portugal_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/portugal_hobo $@

$(ROOTKEYDIR)/layout_59: $(ROOTKEYDIR)/spain_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/spain_hobo $@

$(ROOTKEYDIR)/layout_5a: $(ROOTKEYDIR)/sweden_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/sweden_hobo $@

$(ROOTKEYDIR)/layout_5b: $(ROOTKEYDIR)/swiss_french_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_french_hobo $@

$(ROOTKEYDIR)/layout_5c: $(ROOTKEYDIR)/swiss_german_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_german_hobo $@

$(ROOTKEYDIR)/layout_5d: $(ROOTKEYDIR)/uk_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/uk_hobo $@

$(ROOTKEYDIR)/layout_5e: $(ROOTKEYDIR)/korea_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/korea_hobo $@

$(ROOTKEYDIR)/layout_5f: $(ROOTKEYDIR)/traditional_chinese_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/traditional_chinese_hobo $@

$(ROOTKEYDIR)/layout_60: $(ROOTKEYDIR)/japan_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/japan_hobo $@

$(ROOTKEYDIR)/layout_61: $(ROOTKEYDIR)/canadian_french_hobo
	$(RM) $@; $(LN) $(ROOTKEYDIR)/canadian_french_hobo $@

include ../../Makefile.targ
