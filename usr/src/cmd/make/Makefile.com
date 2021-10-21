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

# Copyright 2015, Richard Lowe.

MAKE_INCLUDE= $(SRC)/cmd/make/include
CFLAGS += $(CCVERBOSE)
CPPFLAGS += -I$(MAKE_INCLUDE) $(MAKE_DEFS)

# So that it's set even for the libraries we build
TEXT_DOMAIN = SUNW_OST_OSCMD

$(POFILE): $(POFILES)
	$(CAT) $(POFILES) > $@
