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

6x12b_FNT=	6x12b.fnt
6x12b_SRC=	ter-u12b.bdf

8x14_FNT=	8x14.fnt
8x14_SRC=	ter-u14n.bdf ter-u14b.bdf

8x14b_FNT=	8x14b.fnt
8x14b_SRC=	ter-u14b.bdf

8x14v_FNT=	8x14v.fnt
8x14v_SRC=	ter-u14v.bdf

8x16_FNT=	8x16.fnt
8x16_SRC=	ter-u16n.bdf ter-u16b.bdf

8x16b_FNT=	8x16b.fnt
8x16b_SRC=	ter-u16b.bdf

8x16v_FNT=	8x16v.fnt
8x16v_SRC=	ter-u16v.bdf

10x18_FNT=	10x18.fnt
10x18_SRC=	ter-u18n.bdf ter-u18b.bdf

10x18b_FNT=	10x18b.fnt
10x18b_SRC=	ter-u18b.bdf

10x20_FNT=	10x20.fnt
10x20_SRC=	ter-u20n.bdf ter-u20b.bdf

10x20b_FNT=	10x20b.fnt
10x20b_SRC=	ter-u20b.bdf

11x22_FNT=	11x22.fnt
11x22_SRC=	ter-u22n.bdf ter-u22b.bdf

11x22b_FNT=	11x22b.fnt
11x22b_SRC=	ter-u22b.bdf

12x24_FNT=	12x24.fnt
12x24_SRC=	ter-u24n.bdf ter-u24b.bdf

12x24b_FNT=	12x24b.fnt
12x24b_SRC=	ter-u24b.bdf

14x28_FNT=	14x28.fnt
14x28_SRC=	ter-u28n.bdf ter-u28b.bdf

14x28b_FNT=	14x28b.fnt
14x28b_SRC=	ter-u28b.bdf

16x32_FNT=	16x32.fnt
16x32_SRC=	ter-u32n.bdf ter-u32b.bdf

16x32b_FNT=	16x32b.fnt
16x32b_SRC=	ter-u32b.bdf

FONTS=	$(GALLANT_FNT) $(6x12_FNT) $(8x14_FNT) $(8x16_FNT) $(10x18_FNT)
FONTS += $(10x20_FNT) $(11x22_FNT) $(12x24_FNT) $(14x28_FNT) $(16x32_FNT)
FONTS += $(6x12b_FNT) $(8x14b_FNT) $(8x14v_FNT) $(8x16b_FNT) $(8x16v_FNT)
FONTS += $(10x18b_FNT) $(10x20b_FNT) $(11x22b_FNT) $(12x24b_FNT)
FONTS += $(14x28b_FNT) $(16x32b_FNT)
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

$(6x12b_FNT): $(6x12b_SRC)
	$(VTFONTCVT) -o $@ $(6x12b_SRC)

$(8x14b_FNT): $(8x14b_SRC)
	$(VTFONTCVT) -o $@ $(8x14b_SRC)

$(8x14v_FNT): $(8x14v_SRC)
	$(VTFONTCVT) -o $@ $(8x14v_SRC)

$(8x16b_FNT): $(8x16b_SRC)
	$(VTFONTCVT) -o $@ $(8x16b_SRC)

$(8x16v_FNT): $(8x16v_SRC)
	$(VTFONTCVT) -o $@ $(8x16v_SRC)

$(10x18b_FNT): $(10x18b_SRC)
	$(VTFONTCVT) -o $@ $(10x18b_SRC)

$(10x20b_FNT): $(10x20b_SRC)
	$(VTFONTCVT) -o $@ $(10x20b_SRC)

$(11x22b_FNT): $(11x22b_SRC)
	$(VTFONTCVT) -o $@ $(11x22b_SRC)

$(12x24b_FNT): $(12x24b_SRC)
	$(VTFONTCVT) -o $@ $(12x24b_SRC)

$(14x28b_FNT): $(14x28b_SRC)
	$(VTFONTCVT) -o $@ $(14x28b_SRC)

$(16x32b_FNT): $(16x32b_SRC)
	$(VTFONTCVT) -o $@ $(16x32b_SRC)

include ../Makefile.targ
