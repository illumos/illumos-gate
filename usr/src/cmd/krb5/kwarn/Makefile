#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

TESTPROG = kwarndtest 

PROG= ktkt_warnd
MANIFEST=	ktkt_warn.xml

KWARNDOBJS = kwarnd.o kwarnd_svc.o kwarnd_proc.o kwarnd_generic.o kwarnd_send.o
KWARNCOBJS = kwarndtest.o kwarnd_clnt.o \
		kwarnd_clnt_stubs.o kwarnd_handle.o
G_OBJS   = kwarnd_xdr.o 

OBJS	= $(KWARNDOBJS) $(KWARNCOBJS) $(G_OBJS)
SRCS	= $(OBJS:.o=.c)
RSRC	= kwarnd.h kwarnd_clnt.c kwarnd_svc.c kwarnd_xdr.c

CLOBBERFILES += $(TESTPROG)

include ../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKSECURITY)
$(ROOTMANIFEST)		:= FILEMODE= 444

POFILE = $(PROG).po
POFILES = generic.po

COPTFLAG +=	$(XESS) #-I$(KINCDIR) 
CPPFLAGS +=	-D_REENTRANT

CPPFLAGS += -I../../lib/gss_mechs/mech_krb5/include \
                 -I$(SRC)/lib/gss_mechs/mech_krb5 \
                 -I$(SRC)/lib/gss_mechs/mech_krb5/include \
                 -I$(SRC)/uts/common/gssapi/mechs/krb5/include
LDFLAGS += $(KRUNPATH)
LDLIBS += $(KMECHLIB) -lnsl

.KEEP_STATE:

all: $(PROG) $(TESTPROG)

$(PROG):	$(G_OBJS) $(KWARNDOBJS) 
	$(LINK.c) $(KWARNDOBJS) $(G_OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(TESTPROG):       $(G_OBJS) $(KWARNCOBJS) 
	$(LINK.c) $(KWARNCOBJS) $(G_OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

#  Rules to generate derived rpcgen files from kwarnd.x spec file.

kwarnd.h:        kwarnd.x
	$(RM) $@
	$(RPCGEN) -M -h kwarnd.x > $@

kwarnd_clnt.c:   kwarnd.x
	$(RM) $@
	$(RPCGEN) -M -l kwarnd.x > $@

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

lint: lint_SRCS

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
