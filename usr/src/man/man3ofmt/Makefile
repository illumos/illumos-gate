#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2017 Nexenta Systems, Inc.
#

include		$(SRC)/Makefile.master

MANSECT= 	3ofmt

MANFILES=	ofmt.3ofmt

MANLINKS=	ofmt_close.3ofmt \
		ofmt_open.3ofmt \
		ofmt_print.3ofmt \
		ofmt_strerror.3ofmt \
		ofmt_update_winsize.3ofmt

ofmt_close.3ofmt		:= LINKSRC = ofmt.3ofmt
ofmt_open.3ofmt			:= LINKSRC = ofmt.3ofmt
ofmt_print.3ofmt		:= LINKSRC = ofmt.3ofmt
ofmt_strerror.3ofmt		:= LINKSRC = ofmt.3ofmt
ofmt_update_winsize.3ofmt	:= LINKSRC = ofmt.3ofmt

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install: 	$(ROOTMANFILES) $(ROOTMANLINKS)
