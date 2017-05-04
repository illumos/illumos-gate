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
# Copyright 2017 Nexenta Systems, Inc.
# Copyright 2011 EveryCity Ltd. All rights reserved.
# Copyright 2013 DEY Storage Systems, Inc.
# Copyright 2016 Joyent, Inc.
#

include		$(SRC)/data/Makefile.data

CLEANFILES += \
		data/8859-1.cm data/8859-2.cm data/8859-3.cm data/8859-4.cm \
		data/8859-5.cm data/8859-5.cm data/8859-6.cm data/8859-7.cm \
		data/8859-8.cm data/8859-9.cm data/8859-9.cm data/8859-10.cm \
		data/8859-11.cm data/8859-13.cm data/8859-14.cm \
		data/8859-15.cm data/8859-16.cm data/KOI8-R.cm \
		data/UTF-8.ct

include		Makefile.locales

UTF8SRCS=	$(UTF_8_LOCALES:%=data/%.UTF-8.src)

LOCNAMES= \
		$(ISO8859_1_LOCALES:%=%.ISO8859-1) \
		$(ISO8859_2_LOCALES:%=%.ISO8859-2) \
		$(ISO8859_5_LOCALES:%=%.ISO8859-5) \
		$(ISO8859_6_LOCALES:%=%.ISO8859-6) \
		$(ISO8859_7_LOCALES:%=%.ISO8859-7) \
		$(ISO8859_9_LOCALES:%=%.ISO8859-9) \
		$(ISO8859_11_LOCALES:%=%.ISO8859-11) \
		$(ISO8859_13_LOCALES:%=%.ISO8859-13) \
		$(ISO8859_15_LOCALES:%=%.ISO8859-15) \
		$(KOI8_R_LOCALES:%=%.KOI8-R) \
		$(GB18030_LOCALES:%=%.GB18030) \
		$(UTF_8_LOCALES:%=%.UTF-8)

LOCDIRS=	$(LOCNAMES:%=locale/%)

STAMPFILES=	$(LOCDIRS:%=%/stamp)

CATDIRS= \
		$(LOCDIRS:%=%/LC_COLLATE) \
		$(LOCDIRS:%=%/LC_CTYPE) \
		$(LOCDIRS:%=%/LC_MESSAGES) \
		$(LOCDIRS:%=%/LC_MONETARY) \
		$(LOCDIRS:%=%/LC_NUMERIC) \
		$(LOCDIRS:%=%/LC_TIME)

DATA=		$(CATDIRS:%=%/LCL_DATA)

.PARALLEL:

DCOLL=		LC_COLLATE/LCL_DATA
DCTYPE=		LC_CTYPE/LCL_DATA
DMSGS=		LC_MESSAGES/LCL_DATA
DMON=		LC_MONETARY/LCL_DATA
DNUM=		LC_NUMERIC/LCL_DATA
DTIME=		LC_TIME/LCL_DATA

ROOTLOCDIRS=	$(LOCDIRS:%=$(ROOTLIB)/%)
ROOTCATDIRS=	$(CATDIRS:%=$(ROOTLIB)/%)
ROOTDATA=	$(DATA:%=$(ROOTLIB)/%)

# This is a list of locales that happen to have translations for them
# present in the gate.
TRANSLOCS= \
		zz_AA.UTF-8

PRIVTRANSLOCS= \
		zz_AA.UTF-8

TRANSDIR=	translations
TRANSMOS=	$(TRANSLOCS:%=$(TRANSDIR)/%.mo)
OSTMOFILE=	LC_MESSAGES/SUNW_OST_OSLIB.mo
PRIVFILE=	LC_MESSAGES/priv_names

ROOTTRANSLATIONS=$(TRANSLOCS:%=$(ROOTLIB)/locale/%/$(OSTMOFILE))
ROOTPRIVTRANS=	$(PRIVTRANSLOCS:%=$(ROOTLIB)/locale/%/$(PRIVFILE))

$(ROOTDATA):=	FILEMODE=0444

.KEEP_STATE:

all:		$(DATA)

clean:
		$(RM) $(CLEANFILES) $(STAMPFILES)

clobber:	clean
		$(RM) -r $(LOCDIRS)
		$(RM) $(TRANSMOS)

install:	all $(ROOTDATA) $(ROOTTRANSLATIONS) $(ROOTPRIVTRANS)

translate:	$(ROOTTRANSLATIONS) $(ROOTPRIVTRANS)

locale $(ROOTLOCDIRS) $(ROOTCATDIRS):
		$(INS.dir)

$(STAMPFILES):	locale

# Strip LC_CTYPE contents for UTF-8 locales and replace them
# with UTF-8.ct we compiled.
locale/%.UTF-8/stamp: data/%.UTF-8.src data/UTF-8.cm data/UTF-8.ct
		$(SED) '/^LC_CTYPE/,/^END LC_CTYPE/d;$$r data/UTF-8.ct' $< | \
		$(LCDEF) -U -w data/widths.txt -f data/UTF-8.cm $(@D)
		$(TOUCH) $@
# Convert EURO_SIGN to CURRENCY_SIGN for the ISO8859-1 locales
locale/%.ISO8859-1/stamp: data/%.UTF-8.src data/8859-1.cm
		$(SED) 's/EURO_SIGN/CURRENCY_SIGN/' $< | \
		$(LCDEF) -U -w data/widths.txt -f data/8859-1.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-2/stamp: data/%.UTF-8.src data/8859-2.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/8859-2.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-5/stamp: data/%.UTF-8.src data/8859-5.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/8859-5.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-7/stamp: data/%.UTF-8.src data/8859-7.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/8859-7.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-6/stamp: data/%.UTF-8.src data/8859-6.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/8859-6.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-9/stamp: data/%.UTF-8.src data/8859-9.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/8859-9.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-11/stamp: data/%.UTF-8.src data/8859-11.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/8859-11.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-13/stamp: data/%.UTF-8.src data/8859-13.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/8859-13.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-15/stamp: data/%.UTF-8.src data/8859-15.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/8859-15.cm $(@D)
		$(TOUCH) $@
locale/%.KOI8-R/stamp:	data/%.UTF-8.src data/KOI8-R.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/KOI8-R.cm $(@D)
		$(TOUCH) $@
locale/%.GB18030/stamp:	data/%.UTF-8.src data/GB18030.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/GB18030.cm $(@D)
		$(TOUCH) $@

locale/%/$(DCOLL): locale/%/stamp
locale/%/$(DCTYPE): locale/%/stamp
locale/%/$(DMSGS): locale/%/stamp
locale/%/$(DMON): locale/%/stamp
locale/%/$(DNUM): locale/%/stamp
locale/%/$(DTIME): locale/%/stamp

data/UTF-8.ct:	ctype.sh data/manual-input.UTF-8 $(UTF8SRCS)
		@/bin/sh ctype.sh $(UTF8SRCS) > $@

data/%.cm:	convert_map.pl data/%.TXT data/UTF-8.cm
		$(RM) $@
		$(PERL) convert_map.pl $< > $@

$(ROOTDATA):	$(ROOTLOCDIRS) $(ROOTCATDIRS) $(DATA)
		$(RM) $@
		$(CP) $(@:$(ROOTLIB)/%=%) $@
		$(CHMOD) 0444 $@

%.mo:		%.po
		$(MSGFMT) -o $@ $<

$(ROOTLIB)/locale/%/$(OSTMOFILE): $(TRANSDIR)/%.mo
		$(INS.rename)
		$(CHMOD) 0444 $@

$(ROOTLIB)/locale/%/$(PRIVFILE): $(TRANSDIR)/%.priv
		$(INS.rename)
		$(CHMOD) 0444 $@
