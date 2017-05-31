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
include		Makefile.com

LOCNAMES=	$(ISO8859_1_LOCALES:%=%.ISO8859-1) \
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

CATDIRS=	$(LOCDIRS:%=%/LC_COLLATE) \
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
$(ROOTDATA):=	FILEMODE=0444

TRANSDIR=	translations
TRANSMOS=	$(TRANSLOCS:%=$(TRANSDIR)/%.mo)
OSTMOFILE=	LC_MESSAGES/SUNW_OST_OSLIB.mo
PRIVFILE=	LC_MESSAGES/priv_names
ROOTTRANSLATIONS=$(TRANSLOCS:%=$(ROOTLIB)/locale/%/$(OSTMOFILE))
ROOTPRIVTRANS=	$(PRIVTRANSLOCS:%=$(ROOTLIB)/locale/%/$(PRIVFILE))

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

locale/%.GB18030/stamp:	data/%.GB18030.src data/GB18030.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/GB18030.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-1/stamp: data/%.ISO8859-1.src data/ISO8859-1.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/ISO8859-1.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-2/stamp: data/%.ISO8859-2.src data/ISO8859-2.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/ISO8859-2.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-5/stamp: data/%.ISO8859-5.src data/ISO8859-5.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/ISO8859-5.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-6/stamp: data/%.ISO8859-6.src data/ISO8859-6.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/ISO8859-6.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-7/stamp: data/%.ISO8859-7.src data/ISO8859-7.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/ISO8859-7.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-9/stamp: data/%.ISO8859-9.src data/ISO8859-9.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/ISO8859-9.cm $(@D)
		$(TOUCH) $@
# The only locale here is th_TH.ISO8859-11, missing from current CLDR release -
# use UTF-8 source file.
locale/%.ISO8859-11/stamp: data/%.UTF-8.src data/ISO8859-11.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/ISO8859-11.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-13/stamp: data/%.ISO8859-13.src data/ISO8859-13.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/ISO8859-13.cm $(@D)
		$(TOUCH) $@
locale/%.ISO8859-15/stamp: data/%.ISO8859-15.src data/ISO8859-15.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/ISO8859-15.cm $(@D)
		$(TOUCH) $@
locale/%.KOI8-R/stamp:	data/%.KOI8-R.src data/KOI8-R.cm
		$(LCDEF) -U -w data/widths.txt -i $< -f data/KOI8-R.cm $(@D)
		$(TOUCH) $@
# Strip LC_CTYPE contents for UTF-8 locales and replace them
# with common LC_CTYPE definition.
locale/%.UTF-8/stamp: data/%.UTF-8.src data/UTF-8.cm data/common.UTF-8.src
		$(SED) \
		-e '/^LC_CTYPE/,/^END LC_CTYPE/d' \
		-e '$$r data/common.UTF-8.src' $< | \
		$(LCDEF) -U -w data/widths.txt -f data/UTF-8.cm $(@D)
		$(TOUCH) $@

locale/%/$(DCOLL): locale/%/stamp
locale/%/$(DCTYPE): locale/%/stamp
locale/%/$(DMSGS): locale/%/stamp
locale/%/$(DMON): locale/%/stamp
locale/%/$(DNUM): locale/%/stamp
locale/%/$(DTIME): locale/%/stamp

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
