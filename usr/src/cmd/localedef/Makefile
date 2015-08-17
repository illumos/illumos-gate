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
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2011 EveryCity Ltd. All rights reserved.
# Copyright 2013 DEY Storage Systems, Inc.
# Copyright 2015 Joyent, Inc.
#

PROG=localedef

NDIR=native
NPROG=$(NDIR)/localedef

include ../Makefile.cmd

OBJS = 	charmap.o collate.o ctype.o messages.o monetary.o numeric.o time.o \
	scanner.o localedef.o wide.o parser.tab.o
NOBJS = $(OBJS:%.o=native/%.o)

HDRS	= localedef.h

SRCS   = $(OBJS:%.o=%.c)

CPPFLAGS	+= -I $(SRC)/lib/libc/port/locale
NATIVE_CPPFLAGS	+= -I $(SRC)/lib/libc/port/locale
CERRWARN	+= -_gcc=-Wno-char-subscripts
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-unused-label
LDLIBS		+= -lgen
LDLIBS 		+= -lavl
NATIVELDLIBS	+= -lgen

#
# Unfortunately, we have a chicken and an egg problem. libavl is becoming
# public, which means that all of its symbols are in a version that the build
# machine doesn't have and traditionally there has been no libavl compilation
# symlink. Therefore, because we know that we only support building on illumos,
# we regrettably have to link explicitly against the full library path. Sorry.
#
NATIVELDLIBS	+= /usr/lib/libavl.so.1
YFLAGS		= -d -b parser

CLEANFILES	= $(NOBJS) $(OBJS) parser.tab.c parser.tab.h
CLEANFILES	+= \
		UTF-8.cm UTF-8.ct \
		8859-1.cm 8859-2.cm 8859-3.cm 8859-4.cm \
		8859-5.cm 8859-5.cm 8859-6.cm 8859-7.cm \
		8859-8.cm 8859-9.cm 8859-9.cm 8859-10.cm \
		8859-11.cm 8859-13.cm 8859-14.cm 8859-15.cm \
		8859-16.cm \
		KOI8-R.cm
CLOBBERFILES	= $(PROG) $(NPROG) $(POFILE) \
		GB18030.cm UTF-8.cm

PIFILES		= $(OBJS:%.o=%.i)
POFILE		= localedef_cmd.po

ISO8859_1_LOCALES	= \
		da_DK \
		de_CH \
		en_AU en_CA en_GB en_NZ en_US \
		es_AR es_BO es_CL es_CO es_EC es_GT es_MX es_NI es_PA \
		es_PE es_SV es_UY es_VE \
		fr_CA fr_CH \
		is_IS \
		it_CH \
		sv_SE

ISO8859_2_LOCALES	= \
		cs_CZ \
		hr_HR \
		hu_HU \
		pl_PL \
		sq_AL

ISO8859_5_LOCALES	= \
		bg_BG \
		mk_MK \
		ru_RU

ISO8859_6_LOCALES	= 

ISO8859_7_LOCALES	= \
		el_GR

ISO8859_9_LOCALES	= \
		tr_TR

ISO8859_11_LOCALES	= \
		th_TH

ISO8859_13_LOCALES	= \
		lt_LT \
		lv_LV

ISO8859_15_LOCALES	= \
		ca_ES \
		da_DK \
		de_AT de_DE \
		en_GB en_IE en_US \
		es_ES \
		fi_FI \
		fr_BE fr_FR \
		it_IT \
		nl_BE nl_NL \
		pt_PT \
		sv_FI sv_SE

KOI8_R_LOCALES		= \
		ru_RU

GB18030_LOCALES		= \
		zh_CN

#
# All new locales should be in UTF-8 form.
#
UTF_8_LOCALES		= \
		af_ZA \
		ar_AE ar_BH ar_DZ ar_EG ar_IQ ar_JO ar_KW ar_LB ar_LY ar_MA \
		ar_OM ar_QA ar_SA ar_TN ar_YE \
		as_IN \
		az_AZ \
		be_BY \
		bg_BG \
		bn_BD bn_IN \
		bo_CN bo_IN \
		bs_BA \
		ca_ES \
		cs_CZ \
		da_DK \
		de_AT de_BE de_CH de_DE de_LI de_LU \
		el_CY el_GR \
		en_AU en_BW en_BZ en_CA en_GB en_HK en_IE en_IN en_JM en_MH \
		en_MT en_NA en_NZ en_PH en_PK en_SG en_TT en_US en_ZA en_ZW \
		es_AR es_BO es_CL es_CO es_CR es_DO es_EC es_ES es_GQ es_GT \
		es_HN es_MX es_NI es_PA es_PE es_PR es_PY es_SV es_US es_UY \
		es_VE \
		et_EE \
		fi_FI \
		fil_PH \
		fr_BE fr_CA fr_CF fr_CH fr_FR fr_GN fr_LU fr_MC fr_MG fr_ML \
		fr_NE fr_SN \
		ga_IE \
		gu_IN \
		he_IL \
		hi_IN \
		hr_HR \
		hu_HU \
		hy_AM \
		id_ID \
		ii_CN \
		is_IS \
		it_CH it_IT \
		ja_JP \
		ka_GE \
		kk_KZ \
		km_KH \
		kn_IN \
		ko_KR \
		kok_IN \
		lt_LT \
		lv_LV \
		mk_MK \
		ml_IN \
		mn_CN mn_MN \
		mr_IN \
		ms_MY \
		mt_MT \
		ne_IN ne_NP \
		nl_BE nl_NL \
		nb_NO \
		nn_NO \
		or_IN \
		pa_IN pa_PK \
		pl_PL \
		pt_BR pt_GW pt_MZ pt_PT \
		ro_MD ro_RO \
		ru_MD ru_RU ru_UA \
		sa_IN \
		si_LK \
		sk_SK \
		sl_SI \
		sq_AL \
		sr_BA sr_ME sr_RS \
		sv_FI sv_SE \
		ta_IN ta_LK \
		te_IN \
		th_TH \
		tr_TR \
		uk_UA \
		ug_CN \
		ur_IN ur_PK \
		vi_VN \
		zh_CN zh_HK zh_MO zh_SG zh_TW

UTF8SRCS	= $(UTF_8_LOCALES:%=data/%.UTF-8.src)

LOCNAMES	= \
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

LOCDIRS		= $(LOCNAMES:%=locale/%)

STAMPFILES	= $(LOCDIRS:%=%/stamp)

CATDIRS		= \
		$(LOCDIRS:%=%/LC_COLLATE) \
		$(LOCDIRS:%=%/LC_CTYPE) \
		$(LOCDIRS:%=%/LC_MESSAGES) \
		$(LOCDIRS:%=%/LC_MONETARY) \
		$(LOCDIRS:%=%/LC_NUMERIC) \
		$(LOCDIRS:%=%/LC_TIME)

DATA		= $(CATDIRS:%=%/LCL_DATA)

DCOLL		= LC_COLLATE/LCL_DATA
DCTYPE		= LC_CTYPE/LCL_DATA
DMSGS		= LC_MESSAGES/LCL_DATA
DMON		= LC_MONETARY/LCL_DATA
DNUM		= LC_NUMERIC/LCL_DATA
DTIME		= LC_TIME/LCL_DATA

ROOTLOCDIRS	= $(LOCDIRS:%=$(ROOTLIB)/%)
ROOTCATDIRS	= $(CATDIRS:%=$(ROOTLIB)/%)
ROOTDATA	= $(DATA:%=$(ROOTLIB)/%)

$(ROOTDATA)	:= FILEMODE=0444

all: $(PROG) $(DATA)

install: all $(ROOTPROG) $(ROOTDATA)

$(NDIR):
	mkdir $@

$(NDIR)/%.o: %.c
	$(NATIVECC) $(NATIVE_CFLAGS) $(NATIVE_CPPFLAGS) -o $@ -c $<
	$(POST_PROCESS_O)

$(NPROG): $(NDIR) .WAIT $(NOBJS)
	$(LINK.c) $(NOBJS) -o $@ $(NATIVELDLIBS)
	$(POST_PROCESS)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(OBJS) $(NOBJS):	parser.tab.h

parser.tab.c parser.tab.h: parser.y $(HDRS)
	$(YACC) $(YFLAGS) parser.y

lint:	$(SRCS)
	$(LINT.c) $(CPPFLAGS) $(SRCS)

clean:	
	$(RM) $(CLEANFILES)
	$(RM) $(STAMPFILES)

clobber: clean
	$(RM) $(CLOBBERFILES)
	$(RM) -r $(LOCDIRS)
	$(RM) -r $(NDIR)

$(POFILE):	$(PIFILES)
	$(RM) $@
	$(RM) messages.po
	$(XGETTEXT) -s $(PIFILES)
	$(SED) -e '/domain/d' messages.po > $@
	$(RM) $(PIFILES) messages.po

locale $(ROOTLOCDIRS) $(ROOTCATDIRS):
	$(INS.dir)

$(ROOTBIN)/%: $(ROOTBIN) %
	$(INS.file)

# Strip LC_CTYPE contents for UTF-8 locales and replace them
# with UTF-8.ct we compiled
locale/%.UTF-8/stamp:		data/%.UTF-8.src UTF-8.cm \
				UTF-8.ct locale $(NPROG)
	$(SED) '/^LC_CTYPE/,/^END LC_CTYPE/d;$$r UTF-8.ct' $< | \
		./$(NPROG) -U -w data/widths.txt -f UTF-8.cm $(@D)
	$(TOUCH) $@
locale/%.ISO8859-1/stamp:	data/%.UTF-8.src 8859-1.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f 8859-1.cm $(@D)
	$(TOUCH) $@
locale/%.ISO8859-2/stamp:	data/%.UTF-8.src 8859-2.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f 8859-2.cm $(@D)
	$(TOUCH) $@
locale/%.ISO8859-5/stamp:	data/%.UTF-8.src 8859-5.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f 8859-5.cm $(@D)
	$(TOUCH) $@
locale/%.ISO8859-7/stamp:	data/%.UTF-8.src 8859-7.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f 8859-7.cm $(@D)
	$(TOUCH) $@
locale/%.ISO8859-6/stamp:	data/%.UTF-8.src 8859-6.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f 8859-6.cm $(@D)
	$(TOUCH) $@
locale/%.ISO8859-9/stamp:	data/%.UTF-8.src 8859-9.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f 8859-9.cm $(@D)
	$(TOUCH) $@
locale/%.ISO8859-11/stamp:	data/%.UTF-8.src 8859-11.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f 8859-11.cm $(@D)
	$(TOUCH) $@
locale/%.ISO8859-13/stamp:	data/%.UTF-8.src 8859-13.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f 8859-13.cm $(@D)
	$(TOUCH) $@
locale/%.ISO8859-15/stamp:	data/%.UTF-8.src 8859-15.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f 8859-15.cm $(@D)
	$(TOUCH) $@
locale/%.KOI8-R/stamp:		data/%.UTF-8.src KOI8-R.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f KOI8-R.cm $(@D)
	$(TOUCH) $@
locale/%.GB18030/stamp:		data/%.UTF-8.src GB18030.cm locale $(NPROG)
	./$(NPROG) -U -w data/widths.txt -i $< -f GB18030.cm $(@D)
	$(TOUCH) $@

locale/%/$(DCOLL):	locale/%/stamp
locale/%/$(DCTYPE):	locale/%/stamp
locale/%/$(DMSGS):	locale/%/stamp
locale/%/$(DMON):	locale/%/stamp
locale/%/$(DNUM):	locale/%/stamp
locale/%/$(DTIME):	locale/%/stamp

UTF-8.cm: data/UTF-8.cm
	$(LN) -sf data/UTF-8.cm  $@

UTF-8.ct: $(UTF8SRCS)
	$(SH) data/ctype.sh $(UTF8SRCS) > $@

GB18030.cm: data/GB18030.cm
	$(LN) -sf data/GB18030.cm  $@

%.cm: data/%.TXT UTF-8.cm
	$(RM) $@
	$(PERL) data/convert_map.pl $< > $@

$(ROOTDATA):	$(ROOTLOCDIRS) $(ROOTCATDIRS) $(DATA)
	$(RM) $@
	$(CP) $(@:$(ROOTLIB)/%=%) $@
	$(CHMOD) 0444 $@
