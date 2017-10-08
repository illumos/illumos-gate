#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= ed
XPG4PROG= ed
XPG6PROG= ed

EDOBJ= ed.o compile.o
XPG4EDOBJ= edobjs.xpg4/ed.o edobjs.xpg4/compile.o  values-xpg4.o
XPG6EDOBJ= edobjs.xpg6/ed.o edobjs.xpg6/compile.o  values-xpg6.o
OBJS= $(EDOBJ) $(XPG4EDOBJ) $(XPG6EDOBJ)
SRCS= ./ed.c ../expr/compile.c 

POFILES= $(EDOBJ:%.o=%.po)

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += -_gcc=-Wno-uninitialized
$(XPG4) := CFLAGS += -DXPG4  
$(XPG6) := CFLAGS += -DXPG6 -I$(SRC)/lib/libc/inc 
lint := LDLIBS += -lgen -lcrypt
LDLIBS += -lmapmalloc -lgen -lcrypt_i
XGETFLAGS += -a -x ed.xcl

MAPFILE.INT =	../expr/mapfile-intf
LDFLAGS +=	$(MAPFILE.INT:%=-M%)

POFILE= ed_cmd.po

%.po: ../expr/%.c
	$(COMPILE.cpp) $< > $*.c.i
	$(XGETTEXT) $(XGETFLAGS) $*.c.i
	$(MV) messages.po $@

.KEEP_STATE:

all:	$(PROG) $(XPG4) $(XPG6)

$(PROG): $(EDOBJ) $(MAPFILE.INT)
	$(LINK.c) $(EDOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(XPG4): edobjs.xpg4 $(XPG4EDOBJ) $(MAPFILE.INT) 
	$(LINK.c) $(XPG4EDOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(XPG6): edobjs.xpg6 $(XPG6EDOBJ)  $(MAPFILE.INT)
	$(LINK.c) $(XPG6EDOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

compile.o:	../expr/compile.c 
	$(COMPILE.c) -o $@ ../expr/compile.c

edobjs.xpg4/%.o:	%.c
	$(COMPILE.c) -o $@ $<

edobjs.xpg4/%.o:	../expr/compile.c
	$(COMPILE.c) -o $@ $<

edobjs.xpg6/%.o:	%.c
	$(COMPILE.c) -o $@ $<

edobjs.xpg6/%.o:	../expr/compile.c
	$(COMPILE.c) -o $@ $<

edobjs.xpg4:
	-@mkdir -p $@

edobjs.xpg6:
	-@mkdir -p $@

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

install: all $(ROOTPROG) $(ROOTXPG4PROG) $(ROOTXPG6PROG)
	$(RM) $(ROOTBIN)/red
	$(LN) $(ROOTBIN)/ed $(ROOTBIN)/red

values-xpg4.o: ../../lib/crt/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../lib/crt/common/values-xpg4.c

values-xpg6.o: ../../lib/crt/common/values-xpg6.c
	$(COMPILE.c) -o $@ ../../lib/crt/common/values-xpg6.c

clean:
	-@rm -rf $(OBJS) $(XPG4) $(XPG6) edobjs.xpg4 edobjs.xpg6 \
		compile.c.i

lint:	lint_PROG

include ../Makefile.targ
