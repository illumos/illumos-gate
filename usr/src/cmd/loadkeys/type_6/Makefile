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
#
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/loadkeys/type_6/Makefile

KEYTABLES = \
        us belgium czech denmark finnish france canadian_french \
 	germany greece hungary italy japan korea \
        netherlands norway portugal poland reset spain sweden \
        swiss_french swiss_german taiwan uk \
        slovakia slovenia serbiaandmontenegro \
        iceland croatia bulgaria belarus maltaus \
        maltauk albania turkeyq turkeyf latvia lithuania macedonia russia \
        latinamerica canadian_bilingual brazil

KEYTABLESCONFIG = kbd_layouts

include ../../Makefile.cmd

ROOTKEYTABLESDIR= $(ROOTSHLIB)/keytables
ROOTKEYDIR= $(ROOTKEYTABLESDIR)/type_6
ROOTKEYTABLES= $(KEYTABLES:%=$(ROOTKEYDIR)/%)
ROOTKEYTABLESCON= $(KEYTABLESCONFIG:%=$(ROOTKEYDIR)/%)

# there is an install target for each ROOT layout link
#
LAYOUTS= \
        layout_00 layout_02 layout_04 layout_06 layout_07 layout_08 \
	layout_09 layout_0e layout_0f layout_10 layout_12 layout_13 \
	layout_16 layout_17 layout_19 layout_0a layout_0c layout_109 \
	layout_10a layout_10b layout_1a layout_1b layout_1c layout_1e \
	layout_20 layout_21 layout_100 layout_18 layout_101 layout_102 \
	layout_103 layout_104 layout_105 layout_106 layout_107 layout_108 \
	layout_10f layout_1f layout_23 layout_15 layout_05 layout_11 \
	layout_03 layout_110

ROOTLINKS= $(LAYOUTS:%=$(ROOTKEYDIR)/%)

$(ROOTKEYTABLES) := FILEMODE = 444
$(ROOTKEYTABLESCON) := FILEMODE = 444

# install rule
$(ROOTKEYDIR)/%: %
	$(INS.file)

.KEEP_STATE:

all:  $(KEYTABLES)

install: all $(ROOTKEYTABLESDIR) $(ROOTKEYDIR) $(ROOTKEYTABLES) $(ROOTLINKS)\
	$(ROOTKEYTABLESCON)

clean:

$(ROOTKEYTABLESDIR):
	$(INS.dir)

$(ROOTKEYDIR): $(ROOTKEYTABLESDIR)
	$(INS.dir)

# install targets for ROOT layout links
#
$(ROOTKEYDIR)/layout_00: $(ROOTKEYDIR)/us
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us $@

$(ROOTKEYDIR)/layout_02: $(ROOTKEYDIR)/belgium
	$(RM) $@; $(LN) $(ROOTKEYDIR)/belgium $@

$(ROOTKEYDIR)/layout_03: $(ROOTKEYDIR)/canadian_bilingual
	$(RM) $@; $(LN) $(ROOTKEYDIR)/canadian_bilingual $@

$(ROOTKEYDIR)/layout_04: $(ROOTKEYDIR)/canadian_french
	$(RM) $@; $(LN) $(ROOTKEYDIR)/canadian_french $@

$(ROOTKEYDIR)/layout_05: $(ROOTKEYDIR)/czech
	$(RM) $@; $(LN) $(ROOTKEYDIR)/czech $@

$(ROOTKEYDIR)/layout_06: $(ROOTKEYDIR)/denmark
	$(RM) $@; $(LN) $(ROOTKEYDIR)/denmark $@

$(ROOTKEYDIR)/layout_07: $(ROOTKEYDIR)/finnish
	$(RM) $@; $(LN) $(ROOTKEYDIR)/finnish $@

$(ROOTKEYDIR)/layout_08: $(ROOTKEYDIR)/france
	$(RM) $@; $(LN) $(ROOTKEYDIR)/france $@

$(ROOTKEYDIR)/layout_09: $(ROOTKEYDIR)/germany
	$(RM) $@; $(LN) $(ROOTKEYDIR)/germany $@

$(ROOTKEYDIR)/layout_0a: $(ROOTKEYDIR)/greece
	$(RM) $@; $(LN) $(ROOTKEYDIR)/greece $@

$(ROOTKEYDIR)/layout_0c: $(ROOTKEYDIR)/hungary
	$(RM) $@; $(LN) $(ROOTKEYDIR)/hungary $@

$(ROOTKEYDIR)/layout_0e: $(ROOTKEYDIR)/italy
	$(RM) $@; $(LN) $(ROOTKEYDIR)/italy $@

$(ROOTKEYDIR)/layout_0f: $(ROOTKEYDIR)/japan
	$(RM) $@; $(LN) $(ROOTKEYDIR)/japan $@

$(ROOTKEYDIR)/layout_10: $(ROOTKEYDIR)/korea
	$(RM) $@; $(LN) $(ROOTKEYDIR)/korea $@

$(ROOTKEYDIR)/layout_11: $(ROOTKEYDIR)/latinamerica
	$(RM) $@; $(LN) $(ROOTKEYDIR)/latinamerica $@

$(ROOTKEYDIR)/layout_12: $(ROOTKEYDIR)/netherlands
	$(RM) $@; $(LN) $(ROOTKEYDIR)/netherlands $@

$(ROOTKEYDIR)/layout_13: $(ROOTKEYDIR)/norway
	$(RM) $@; $(LN) $(ROOTKEYDIR)/norway $@

$(ROOTKEYDIR)/layout_16: $(ROOTKEYDIR)/portugal
	$(RM) $@; $(LN) $(ROOTKEYDIR)/portugal $@

$(ROOTKEYDIR)/layout_15: $(ROOTKEYDIR)/poland
	$(RM) $@; $(LN) $(ROOTKEYDIR)/poland $@

$(ROOTKEYDIR)/layout_17: $(ROOTKEYDIR)/russia
	$(RM) $@; $(LN) $(ROOTKEYDIR)/russia $@

$(ROOTKEYDIR)/layout_19: $(ROOTKEYDIR)/spain
	$(RM) $@; $(LN) $(ROOTKEYDIR)/spain $@

$(ROOTKEYDIR)/layout_1a: $(ROOTKEYDIR)/sweden
	$(RM) $@; $(LN) $(ROOTKEYDIR)/sweden $@

$(ROOTKEYDIR)/layout_1b: $(ROOTKEYDIR)/swiss_french
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_french $@

$(ROOTKEYDIR)/layout_1c: $(ROOTKEYDIR)/swiss_german
	$(RM) $@; $(LN) $(ROOTKEYDIR)/swiss_german $@

$(ROOTKEYDIR)/layout_1e: $(ROOTKEYDIR)/taiwan
	$(RM) $@; $(LN) $(ROOTKEYDIR)/taiwan $@

$(ROOTKEYDIR)/layout_20: $(ROOTKEYDIR)/uk
	$(RM) $@; $(LN) $(ROOTKEYDIR)/uk $@

$(ROOTKEYDIR)/layout_21: $(ROOTKEYDIR)/us
	$(RM) $@; $(LN) $(ROOTKEYDIR)/us $@

$(ROOTKEYDIR)/layout_18: $(ROOTKEYDIR)/slovakia
	$(RM) $@; $(LN) $(ROOTKEYDIR)/slovakia $@

$(ROOTKEYDIR)/layout_100: $(ROOTKEYDIR)/slovenia
	$(RM) $@; $(LN) $(ROOTKEYDIR)/slovenia $@

$(ROOTKEYDIR)/layout_101: $(ROOTKEYDIR)/serbiaandmontenegro
	$(RM) $@; $(LN) $(ROOTKEYDIR)/serbiaandmontenegro $@

$(ROOTKEYDIR)/layout_102: $(ROOTKEYDIR)/iceland
	$(RM) $@; $(LN) $(ROOTKEYDIR)/iceland $@

$(ROOTKEYDIR)/layout_103: $(ROOTKEYDIR)/croatia
	$(RM) $@; $(LN) $(ROOTKEYDIR)/croatia  $@

$(ROOTKEYDIR)/layout_104: $(ROOTKEYDIR)/bulgaria
	$(RM) $@; $(LN) $(ROOTKEYDIR)/bulgaria  $@

$(ROOTKEYDIR)/layout_105: $(ROOTKEYDIR)/belarus
	$(RM) $@; $(LN) $(ROOTKEYDIR)/belarus  $@

$(ROOTKEYDIR)/layout_106: $(ROOTKEYDIR)/maltaus
	$(RM) $@; $(LN) $(ROOTKEYDIR)/maltaus  $@

$(ROOTKEYDIR)/layout_107: $(ROOTKEYDIR)/maltauk
	$(RM) $@; $(LN) $(ROOTKEYDIR)/maltauk  $@

$(ROOTKEYDIR)/layout_108: $(ROOTKEYDIR)/albania
	$(RM) $@; $(LN) $(ROOTKEYDIR)/albania  $@

$(ROOTKEYDIR)/layout_109: $(ROOTKEYDIR)/lithuania
	$(RM) $@; $(LN) $(ROOTKEYDIR)/lithuania $@

$(ROOTKEYDIR)/layout_10a: $(ROOTKEYDIR)/latvia
	$(RM) $@; $(LN) $(ROOTKEYDIR)/latvia $@

$(ROOTKEYDIR)/layout_10b: $(ROOTKEYDIR)/macedonia
	$(RM) $@; $(LN) $(ROOTKEYDIR)/macedonia $@

$(ROOTKEYDIR)/layout_10f: $(ROOTKEYDIR)/japan
	$(RM) $@; $(LN) $(ROOTKEYDIR)/japan $@

$(ROOTKEYDIR)/layout_1f: $(ROOTKEYDIR)/turkeyq
	$(RM) $@; $(LN) $(ROOTKEYDIR)/turkeyq  $@

$(ROOTKEYDIR)/layout_23: $(ROOTKEYDIR)/turkeyf
	$(RM) $@; $(LN) $(ROOTKEYDIR)/turkeyf  $@

$(ROOTKEYDIR)/layout_110: $(ROOTKEYDIR)/brazil
	$(RM) $@; $(LN) $(ROOTKEYDIR)/brazil  $@

include ../../Makefile.targ
