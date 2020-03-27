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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/Makefile.master

SUBDIRS =       $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

CODESETS	= IBM-037 \
		  IBM-273 IBM-277 IBM-278 IBM-280 IBM-284 IBM-285 IBM-297 \
		  IBM-420 IBM-424 IBM-500 \
		  IBM-850 IBM-852 IBM-855 IBM-856 IBM-857 IBM-862 IBM-864 \
		  IBM-866 IBM-869 \
		  IBM-870 IBM-871 IBM-875 \
		  IBM-921 IBM-922 IBM-1025 IBM-1026 IBM-1112 \
		  IBM-1122 \
		  IBM-1140 IBM-1141 IBM-1142 IBM-1143 IBM-1144 IBM-1145 \
		  IBM-1146 IBM-1147 IBM-1148 IBM-1149

INPUTFILES1	= $(CODESETS:%=%+UTF-8.src)
INPUTFILES2	= $(CODESETS:%=UTF-8+%.src)
INPUTFILES	= $(INPUTFILES1) $(INPUTFILES2)
BINARYTABLES	= $(INPUTFILES:%.src=%.bt)
GENICONVTBL	= /usr/bin/geniconvtbl
GENI_SRCS	= common/binarytables/srcs
ICONV_DIR	= $(ROOT)/usr/lib/iconv
BTS_DIR		= $(ICONV_DIR)/geniconvtbl/binarytables


all :=          TARGET = all
clean :=        TARGET = clean
clobber :=      TARGET = clobber
install :=      TARGET = install
echo :=         TARGET = echo

$(ICONV_DIR)/alias:=	FILEMODE=0444

.KEEP_STATE:

$(BTS_DIR):
	$(INS.dir)

%.bt: $(GENI_SRCS)/%.src
	$(GENICONVTBL) -o $@ -f $<

$(ICONV_DIR)/%: %
	$(INS.file)

all: $(BINARYTABLES)

# There is no way to escape the make(1S) interpretation of '%' as a wildcard,
# as such we can't install these files using traditional make rules, given
# they contain a % which, while it would match a literal '%' and work
# somewhat, would also match anything else.
#
# We have to, rather unfortunately, loop.
install: all $(BINARYTABLES) $(BTS_DIR) $(ICONV_DIR)/alias
	for f in  $(BINARYTABLES) ; do \
		fp=`echo $$f | $(TR) "+" "%"` ; \
		echo "installing $$f as $(BTS_DIR)/$$fp ..." ; \
		$(RM) $(BTS_DIR)/$$fp ; \
		$(CP) $$f $(BTS_DIR)/$$fp ; \
		$(CHMOD) 0444 $(BTS_DIR)/$$fp; \
	done

clean:
	$(RM) $(BINARYTABLES)

all clean clobber install echo: $(SUBDIRS)

.PARALLEL: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
