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
# Copyright 2019 Joyent, Inc.
# Copyright 2025 MNX Cloud, Inc.
#

BRAND = builder

include $(SRC)/lib/brand/Makefile.brand

PROGS =
XMLDOCS = config.xml platform.xml
TXTS =

CLOBBERFILES = $(ROOTXMLDOCS) $(ROOTTXTS) $(ROOTPROGS) $(ROOTTEMPLATES)

# These shouldn't be necessary, but for some reason the same thing in
# ../../Makefile.brand is not being picked up.
$(ROOTPROGS) := FILEMODE = 755
$(ROOTTXTS) := FILEMODE = 444
$(ROOTXMLDOCS) := FILEMODE = 444
$(ROOTTEMPLATES) := FILEMODE = 444

all: $(PROGS)

install: $(PROGS) $(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTXTS) $(ROOTTEMPLATES)

clean:
	$(RM) $(CLEANFILES)

include $(SRC)/cmd/Makefile.targ
