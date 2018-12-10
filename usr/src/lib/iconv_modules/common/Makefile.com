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

SRCS	=	646%CODESET.c

ALL_SOS =	646%CODESET.so

LINK_TARGETS  = 646%CODESET.so

dummy: all

include $(SRC)/lib/iconv_modules/Makefile.iconv

$(CREATE_LINKS):  $(ICONV_LINK_TARGETS)
	$(SYMLINK) -f 646%CODESET.so $(ICONV_DIR)/646%5601.so
	$(SYMLINK) -f 646%CODESET.so $(ICONV_DIR)/646%BIG5.so
	$(SYMLINK) -f 646%CODESET.so $(ICONV_DIR)/646%cns11643.so
	$(SYMLINK) -f 646%CODESET.so $(ICONV_DIR)/646%eucJP.so
	$(SYMLINK) -f 646%CODESET.so $(ICONV_DIR)/646%gb2312.so
	$(SYMLINK) -f 646%CODESET.so $(ICONV_DIR)/646%GBK.so
	$(SYMLINK) -f 646%CODESET.so $(ICONV_DIR)/646%PCK.so
	$(SYMLINK) -f 646%CODESET.so $(ICONV_DIR)/646%SJIS.so
	$(TOUCH) $@

all: $(ALL_SOS)
