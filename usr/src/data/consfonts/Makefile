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
# Copyright 2017 Toomas Soome <tsoome@me.com>
#

GALLANT_FNT=	Gallant19.fnt
GALLANT_SRC=	Gallant19.bdf

6x12_FNT=	6x12.fnt
6x12_SRC=	ter-u12n.bdf ter-u12b.bdf

8x14_FNT=	8x14.fnt
8x14_SRC=	ter-u14n.bdf ter-u14b.bdf

8x16_FNT=	8x16.fnt
8x16_SRC=	ter-u16n.bdf ter-u16b.bdf

8x16_FNT=	8x16.fnt
8x16_SRC=	ter-u16n.bdf ter-u16b.bdf

10x18_FNT=	10x18.fnt
10x18_SRC=	ter-u18n.bdf ter-u18b.bdf

10x20_FNT=	10x20.fnt
10x20_SRC=	ter-u20n.bdf ter-u20b.bdf

11x22_FNT=	11x22.fnt
11x22_SRC=	ter-u22n.bdf ter-u22b.bdf

12x24_FNT=	12x24.fnt
12x24_SRC=	ter-u24n.bdf ter-u24b.bdf

14x28_FNT=	14x28.fnt
14x28_SRC=	ter-u28n.bdf ter-u28b.bdf

16x32_FNT=	16x32.fnt
16x32_SRC=	ter-u32n.bdf ter-u32b.bdf

FONTS=	$(GALLANT_FNT) $(6x12_FNT) $(8x14_FNT) $(8x16_FNT) $(10x18_FNT)
FONTS += $(10x20_FNT) $(11x22_FNT) $(12x24_FNT) $(14x28_FNT) $(16x32_FNT)
FILES= fonts.dir $(FONTS)

include ../Makefile.data

ROOTFONTDIR=	$(ROOT)/boot/fonts
ROOTFONTS=	$(FILES:%=$(ROOTFONTDIR)/%)
ROOTLINK=	$(ROOTSHLIB)/fonts

$(ROOTFONTS) := FILEMODE = 0444

$(ROOTFONTDIR)/%: %
	$(INS.file)

all:	$(FONTS)

install: all $(ROOTFONTDIR) $(ROOTFONTS) $(ROOTLINK)

clean:
	-$(RM) $(FONTS)

$(ROOTFONTDIR):
	$(INS.dir)

$(ROOTLINK): $(ROOTFONTDIR)
	-$(RM) $@
	-$(LN) -s ../../../boot/fonts $@

$(GALLANT_FNT): $(GALLANT_SRC)
	$(VTFONTCVT) -o $@ $(GALLANT_SRC)

$(6x12_FNT): $(6x12_SRC)
	$(VTFONTCVT) -o $@ $(6x12_SRC)

$(8x14_FNT): $(8x14_SRC)
	$(VTFONTCVT) -o $@ $(8x14_SRC)

$(8x16_FNT): $(8x16_SRC)
	$(VTFONTCVT) -o $@ $(8x16_SRC)

$(10x18_FNT): $(10x18_SRC)
	$(VTFONTCVT) -o $@ $(10x18_SRC)

$(10x20_FNT): $(10x20_SRC)
	$(VTFONTCVT) -o $@ $(10x20_SRC)

$(11x22_FNT): $(11x22_SRC)
	$(VTFONTCVT) -o $@ $(11x22_SRC)

$(12x24_FNT): $(12x24_SRC)
	$(VTFONTCVT) -o $@ $(12x24_SRC)

$(14x28_FNT): $(14x28_SRC)
	$(VTFONTCVT) -o $@ $(14x28_SRC)

$(16x32_FNT): $(16x32_SRC)
	$(VTFONTCVT) -o $@ $(16x32_SRC)

include ../Makefile.targ
