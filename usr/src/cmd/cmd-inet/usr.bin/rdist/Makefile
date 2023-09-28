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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG=	rdist
OBJS=	docmd.o expand.o lookup.o main.o server.o
KCMDOBJS=	kcmd.o
YOBJS=	gram.o
SRCS=	$(OBJS:.o=.c) $(CMDINETCOMMONDIR)/$(KCMDOBJS:.o=.c)
YSRCS=	$(YOBJS:.o=.y)

include ../../../Makefile.cmd
include ../../Makefile.cmd-inet

CPPFLAGS +=	-DSYSV -DSTRNET -DBSD_COMP
LDLIBS +=	-lsocket -lnsl
LDFLAGS +=	$(MAPFILE.NGB:%=-Wl,-M%)

include  $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5
LDFLAGS += $(KRUNPATH) -L$(ROOT)$(KLIBDIR_DO) -L$(ROOT)$(KLIBDIR_GL)
LDLIBS +=  -lnsl -lmech_krb5
CPPFLAGS += -I. -I$(CMDINETCOMMONDIR) \
		-I$(SRC)/lib/gss_mechs/mech_krb5 \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	$(CNOWARN_UNINIT)

# because of labels from yacc
gram.o := CERRWARN += -_gcc=-Wno-unused-label

# not linted
SMATCH=off

ROOTSYMLINK=	$(ROOT)/usr/ucb/$(PROG)

# conditional assignments
$(ROOTPROG) :=      FILEMODE=       04555

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS) $(KCMDOBJS) $(YOBJS) $(MAPFILE.NGB)
	$(LINK.c) $(OBJS) $(KCMDOBJS) $(YOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG) $(ROOTSYMLINK)

$(ROOTSYMLINK):
	$(RM) $@; $(SYMLINK) ../bin/$(PROG) $@

clean:
	$(RM) $(OBJS) $(KCMDOBJS) $(YOBJS)

include ../../../Makefile.targ
