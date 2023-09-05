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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2019 Joyent, Inc.
# Copyright 2023-2025 RackTop Systems, Inc.
#

ALGS	= aes_gmac aes_gmac_enc

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber

.KEEP_STATE:

all clean clobber install: $(ALGS)

$(ALGS): FRC
	$(MAKE) -e -f Makefile.gmac BASEPROG=$@ $(TARGET)

FRC:
