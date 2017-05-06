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
#

include		$(SRC)/data/Makefile.data
include		$(SRC)/data/locale/Makefile.com

CMFILES=	$(_CHARMAPS:%=build/%.cm)

GB18030SRCS=	$(GB18030_LOCALES:%=build/%.GB18030.src)
ISO1SRCS=	$(ISO8859_1_LOCALES:%=build/%.ISO8859-1.src)
ISO2SRCS=	$(ISO8859_2_LOCALES:%=build/%.ISO8859-2.src)
ISO5SRCS=	$(ISO8859_5_LOCALES:%=build/%.ISO8859-5.src)
ISO7SRCS=	$(ISO8859_7_LOCALES:%=build/%.ISO8859-7.src)
ISO9SRCS=	$(ISO8859_9_LOCALES:%=build/%.ISO8859-9.src)
ISO11SRCS=	$(_ISO8859_11_LOCALES:%=build/%.ISO8859-11.src)
ISO13SRCS=	$(ISO8859_13_LOCALES:%=build/%.ISO8859-13.src)
ISO15SRCS=	$(ISO8859_15_LOCALES:%=build/%.ISO8859-15.src)
KOI8RSRCS=	$(KOI8_R_LOCALES:%=build/%.KOI8-R.src)
UTF8SRCS=	$(_UTF_8_LOCALES:%=build/%.UTF-8.src)

.PARALLEL:

all:		$(CMFILES) $(GB18030SRCS) $(ISO1SRCS) $(ISO2SRCS) $(ISO5SRCS) \
		$(ISO7SRCS) $(ISO9SRCS) $(ISO13SRCS) $(ISO15SRCS) $(KOI8RSRCS) \
		$(UTF8SRCS)

$(CMFILES):	build posix.jar
		java -jar posix.jar org.unicode.cldr.posix.GenerateCharmap -d build -c $(@F:%.cm=%)

$(GB18030SRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.GB18030.src=%) -c GB18030
$(ISO1SRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.ISO8859-1.src=%) -c ISO8859-1
$(ISO2SRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.ISO8859-2.src=%) -c ISO8859-2
$(ISO5SRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.ISO8859-5.src=%) -c ISO8859-5
$(ISO7SRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.ISO8859-7.src=%) -c ISO8859-7
$(ISO9SRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.ISO8859-9.src=%) -c ISO8859-9
$(ISO13SRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.ISO8859-13.src=%) -c ISO8859-13
$(ISO15SRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.ISO8859-15.src=%) -c ISO8859-15
$(KOI8RSRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.KOI8-R.src=%) -c KOI8-R
$(UTF8SRCS):	build posix.jar
		java -DCLDR_DIR=cldr -jar posix.jar org.unicode.cldr.posix.GeneratePOSIX -d build -m $(@F:%.UTF-8.src=%) -c UTF-8

build:
		$(INS.dir)

posix.jar: posix.xml
		ant -f posix.xml
