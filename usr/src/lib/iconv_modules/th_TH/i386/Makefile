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
# Copyright 2017 Alexander Pyhalov
#

include ../Makefile.com

CFLAGS +=  -I.. -I../common/

ICONV_LIBS      = $(ALL_SOS:%=$(ICONV_DIR)/%)

$(ICONV_LIBS) := FILEMODE= 755

install: all $(ICONV_DIR) .WAIT $(ICONV_LIBS)
