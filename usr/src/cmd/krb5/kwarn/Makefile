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
# Copyright 2020 Joyent, Inc.

TESTPROG = kwarndtest

PROG= ktkt_warnd
MANIFEST=	ktkt_warn.xml

KWARNDOBJS = kwarnd.o kwarnd_svc.o kwarnd_proc.o kwarnd_generic.o kwarnd_send.o
KWARNTOBJS = kwarndtest.o

G_OBJS   = kwarnd_xdr.o

OBJS	= $(KWARNDOBJS) $(KWARNTOBJS) $(G_OBJS)
SRCS	= $(OBJS:.o=.c)
RSRC	= kwarnd_xdr.c kwarnd_svc.c kwarnd.h

CLOBBERFILES += $(TESTPROG)

include ../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKSECURITY)

POFILE = $(PROG).po
POFILES = generic.po

CPPFLAGS +=	-D_REENTRANT

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses

# not linted
SMATCH=off

CPPFLAGS += -I../../lib/gss_mechs/mech_krb5/include \
                 -I$(SRC)/lib/gss_mechs/mech_krb5 \
                 -I$(SRC)/lib/gss_mechs/mech_krb5/include \
                 -I$(SRC)/uts/common/gssapi/mechs/krb5/include

ktkt_warnd :=	MAPFILES =	$(MAPFILE.INT) $(MAPFILE.NGB)
ktkt_warnd :=	LDFLAGS +=	$(KRUNPATH) $(MAPFILES:%=-Wl,-M%)
ktkt_warnd :=	LDLIBS +=	-lnsl

LDFLAGS +=	$(KRUNPATH)
LDLIBS +=	$(KMECHLIB)

.KEEP_STATE:

all: $(PROG) $(TESTPROG)

$(PROG):	$(G_OBJS) $(KWARNDOBJS) $$(MAPFILES)
	$(LINK.c) $(KWARNDOBJS) $(G_OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

# the client entry points (kwarn_*_warning) are now avail in mech_krb5.so
$(TESTPROG):    $(KWARNTOBJS)
	$(LINK.c) $(KWARNTOBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

#  Rules to generate derived rpcgen files from kwarnd.x spec file.

kwarnd.h:        kwarnd.x
	$(RM) $@
	$(RPCGEN) -M -h kwarnd.x > $@

kwarnd_svc.c:    kwarnd.x
	$(RM) $@
	$(RPCGEN) -M -m kwarnd.x > $@

kwarnd_xdr.c:    kwarnd.x
	$(RM) $@
	$(RPCGEN) -M -c kwarnd.x > $@

$(OBJS): kwarnd.h

# note that nightly depends on having all of the derived
# .c files built here on 'make install', even though this
# module doesn't use all of those files.
install: $(KRB5LIBPROG) $(RSRC) $(ROOTMANIFEST)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS) $(RSRC)

include ../../Makefile.targ

#additional dependencies

$(LIBRARY) : $(OBJS)
$(DYNLIB) : $(PICS)

FRC:

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
