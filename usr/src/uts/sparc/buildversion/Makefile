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
#

UTSBASE = ../..

MODULE = buildversion
OBJECTS = $(OBJS_DIR)/$(MODULE).o $(OBJS_DIR)/bvstr.o
BVSTR = $(OBJS_DIR)/buildversion
ROOTMODULE = $(ROOT_MISC_DIR)/$(MODULE)

include $(UTSBASE)/sparc/Makefile.sparc

ALL_TARGET = $(BINARY)
INSTALL_TARGET = $(ALL_TARGET) $(ROOTMODULE)

CLEANFILES += $(BVSTR)

.KEEP_STATE:

def: $(DEF_DEPS)

all: $(ALL_DEPS)

clean: $(CLEAN_DEPS)

clobber: $(CLOBBER_DEPS)

install: $(INSTALL_DEPS)

#
# If nightly didn't generate this at all, we do so here
$(SRC)/buildversion:
	echo "version unset" >$(SRC)/buildversion

$(OBJS_DIR)/bvstr.o: $(SRC)/buildversion
	cp $(SRC)/buildversion $(BVSTR)
	printf '\0' >>$(BVSTR)
	elfwrap -64 -z target=sparc -o $@ $(BVSTR)

include $(UTSBASE)/sparc/Makefile.targ
