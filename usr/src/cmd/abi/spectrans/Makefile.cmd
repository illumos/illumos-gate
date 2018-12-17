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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

include $(SRC)/cmd/Makefile.cmd

PROG_BIN =	$(ROOTLIB)/abi/$(PROG)
.PRECIOUS:	$(PROG)

U_LIB	=	parse
U_BASE	=	../../parser
U_DIR	= 	$(U_BASE)/$(MACH)
U_LIB_A	=	$(U_DIR)/lib$(U_LIB).a

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(U_BASE) -I..
LDFLAGS	+=	-L$(U_DIR)
LINTFLAGS +=	-xsuF -errtags=yes

# not linted
SMATCH=off

LDLIBS	+=	-l$(U_LIB) -lgen
LINTLIBS =	-L$(U_DIR) -l$(U_LIB)

SRCS	=	$(OBJECTS:%.o=../%.c)

.KEEP_STATE:

all:	$(PROG)

%.o:	../%.y
	$(YACC.y) $<
	$(COMPILE.c) -o $@ y.tab.c
	$(RM) y.tab.c

%.o:	../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(PROG): $(U_LIB_A) $(OBJECTS) $(YACC_OBJS)
	$(LINK.c) -o $@ $(OBJECTS) $(YACC_OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(U_LIB_A):
	@cd $(U_DIR); pwd; $(MAKE) all

install: $(PROG_BIN)

$(PROG_BIN) :=	FILEMODE = 755
$(PROG_BIN): $(PROG)
	$(INS.file) $(PROG)

clean:
	-$(RM) $(OBJECTS) $(YACC_OBJS)

clobber: clean
	-$(RM) $(PROG) $(CLOBBERFILES)

lint:
	$(LINT.c) $(SRCS) $(LINTLIBS)
