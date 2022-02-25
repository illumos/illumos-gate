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

# Copyright 2022 OmniOS Community Edition (OmniOSce) Association.

include ../../Makefile.data

ROOTSHBHYVE=	$(ROOTSH)/bhyve
ROOTSHBHYVEKBD=	$(ROOTSHBHYVE)/kbdlayout

FILES=		default \
		am \
		be be_acc \
		bg_bds bg_phonetic \
		br br_noacc \
		centraleuropean \
		ch ch_acc ch_macbook_acc ch-fr ch-fr_acc \
		cz \
		de de_acc de_noacc \
		dk dk_macbook \
		ee \
		es es_acc es_dvorak \
		fi \
		fr fr_acc fr_dvorak fr_dvorak_acc fr_macbook \
		gr gr_101_acc gr_elot_acc \
		hr \
		hu_101 hu_102 \
		is is_acc \
		it \
		jp jp_capsctrl \
		kz_io kz_kst \
		latinamerican latinamerican_acc \
		lt \
		nl \
		no no_dvorak nordic_asus-eee \
		pl_dvorak \
		pt pt_acc \
		ru ru_shift ru_win \
		se \
		si \
		tr tr_f \
		ua ua_shift_alt \
		uk uk_capsctrl uk_dvorak uk_macbook \
		us_dvorak us_dvorakl us_dvorakp us_dvorakr us_dvorakx \
		us_emacs us_unix

ROOTFILES= $(FILES:%=$(ROOTSHBHYVEKBD)/%)

$(ROOTFILES) := FILEMODE = 0444

all:

install: $(ROOTSHBHYVEKBD) $(ROOTFILES)

clean clobber:

$(ROOTSHBHYVEKBD):
	$(INS.dir)

$(ROOTSHBHYVEKBD)/%: %
	$(INS.file)

