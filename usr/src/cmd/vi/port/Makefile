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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# cmd/vi/port/Makefile

PROG= ex
XPG4PROG= ex
XPG6PROG= ex
LIBPROGS= expreserve exrecover
XD4= exobjs.xpg4
XD6= exobjs.xpg6

EXOBJS=	bcopy.o ex.o ex_addr.o ex_cmds.o ex_cmds2.o \
	ex_cmdsub.o ex_data.o ex_extern.o ex_get.o \
	ex_io.o ex_put.o ex_re.o ex_set.o ex_subr.o \
	ex_temp.o ex_tty.o ex_unix.o ex_v.o ex_vadj.o \
	ex_vget.o ex_vmain.o ex_voper.o ex_vops.o \
	ex_vops2.o ex_vops3.o ex_vput.o ex_vwind.o \
	printf.o
EXOBJS_XPG4= $(EXOBJS) compile.o values-xpg4.o
EXOBJS_XPG6= $(EXOBJS) compile.o values-xpg6.o
XPG4EXOBJS= ${EXOBJS_XPG4:%=$(XD4)/%}
XPG6EXOBJS= ${EXOBJS_XPG6:%=$(XD6)/%}
EXRECOVEROBJS=	exrecover.o ex_extern.o
OBJS= $(EXOBJS) $(XPG4EXOBJS) $(XPG6EXOBJS) expreserve.o exrecover.o
SRCS= $(EXOBJS:%.o=%.c) expreserve.c exrecover.c
TXTS = READ_ME makeoptions asfix.c70 ex.news port.mk.370 port.mk.70	\
	port.mk.c70 port.mk.usg ovdoprnt.s ovprintf.c rofix

include ../../Makefile.cmd

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-clobbered
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-address

#
# For message catalogue files
#
POFILES= $(EXOBJS:%.o=%.po) expreserve.po exrecover.po
POFILE= port.po

# Include all XPG4 and XPG4ONLY changes in the XPG4 version
$(XPG4) := CFLAGS += -DXPG4 -DXPG4ONLY

# Include all XPG4 changes, but don't include XPG4ONLY in the XPG6 version
$(XPG6) := CFLAGS += -DXPG4 -DXPG6 -I$(SRC)/lib/libc/inc

CPPFLAGS +=  -DUSG -DSTDIO -DVMUNIX -DTABS=8 -DSINGLE -DTAG_STACK

# vi maintains its own versions of various routines from libc and libcurses,
# so localize all symbols to avoid name space collisions.
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)

CLOBBERFILES += $(LIBPROGS)
ex :=		LDLIBS += -lmapmalloc -lcurses -lgen -lcrypt_i
$(XPG4) :=	LDLIBS += -lmapmalloc -lcurses -lgen -lcrypt_i
$(XPG6) :=	LDLIBS += -lmapmalloc -lcurses -lgen -lcrypt_i
exrecover :=	LDLIBS += -lmapmalloc -lcrypt_i
lint :=		LDLIBS += -lmapmalloc -lcurses -lgen -lcrypt

ROOTLIBPROGS= $(LIBPROGS:%=$(ROOTLIB)/%)

# hard links to ex
ROOTLINKS= $(ROOTBIN)/edit $(ROOTHASBIN)/edit $(ROOTBIN)/vedit \
	$(ROOTHASBIN)/vedit $(ROOTHASBIN)/vi $(ROOTHASBIN)/view \

ROOTXPG4LINKS= $(ROOTXPG4BIN)/vi $(ROOTXPG4BIN)/view $(ROOTXPG4BIN)/edit \
	$(ROOTXPG4BIN)/vedit
ROOTXPG6LINKS= $(ROOTXPG6BIN)/vi $(ROOTXPG6BIN)/view $(ROOTXPG6BIN)/edit \
	$(ROOTXPG6BIN)/vedit
.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG) $(XPG4) $(XPG6) $(LIBPROGS)

$(PROG): $(EXOBJS)
	$(LINK.c) $(EXOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

ex.xpg4: $(XD4) $(XPG4EXOBJS)
	$(LINK.c) $(XPG4EXOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

ex.xpg6: $(XD6) $(XPG6EXOBJS)
	$(LINK.c) $(XPG6EXOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(XD4)/compile.o $(XD6)/compile.o: ../../expr/compile.c
	$(COMPILE.c) -o $@ ../../expr/compile.c

%values-xpg4.o: ../../../lib/crt/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../../lib/crt/common/values-xpg4.c

%values-xpg6.o: ../../../lib/crt/common/values-xpg6.c
	$(COMPILE.c) -o $@ ../../../lib/crt/common/values-xpg6.c

$(XPG4EXOBJS): $(XD4)

$(XPG6EXOBJS): $(XD6)

$(XD4)/%.o:	%.c
	$(COMPILE.c) -o $@ $<

$(XD6)/%.o:	%.c
	$(COMPILE.c) -o $@ $<

$(XD4):
	-@mkdir -p $@

$(XD6):
	-@mkdir -p $@

exrecover:	$(EXRECOVEROBJS)
	$(LINK.c) $(EXRECOVEROBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

catalog: $(MSGDOMAIN) $(POFILE)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@


install: all $(ROOTHASBINPROG) $(ROOTLIBPROGS) $(ROOTLINKS) \
	$(ROOTXPG4PROG) $(ROOTXPG4LINKS) $(ROOTXPG6PROG) $(ROOTXPG6LINKS)

$(ROOTLINKS): $(ROOTHASBINPROG)
	-$(RM) $@
	-$(LN) -f $(ROOTHASBINPROG) $@

$(ROOTXPG4LINKS): $(ROOTXPG4PROG)
	-$(RM) $@
	-$(LN) -f $(ROOTXPG4PROG) $@

$(ROOTXPG6LINKS): $(ROOTXPG6PROG)
	-$(RM) $@
	-$(LN) -f $(ROOTXPG6PROG) $@

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

include ../../Makefile.targ
