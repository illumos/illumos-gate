#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG1=kprop
PROG2=kpropd
PROG3=kprop_script
PROG=$(PROG1) $(PROG2) $(PROG3)
MANIFEST=	krb5_prop.xml

OBJS	= \
	kprop.o\
	utils.o\
	kpropd.o \
	kpropd_rpc.o \
	iprop_xdr.o

COMMONOBJS= utils.o
COMMONSRCS= utils.c
CLIENTOBJS= kprop.o
CLIENTSRCS= kprop.c
SERVEROBJS= kpropd.o kpropd_rpc.o
SERVERSRCS= kpropd.c kpropd_rpc.c
DERIVED_OBJS= iprop_xdr.o
DERIVED_SRCS= iprop_xdr.c
SRCS	= $(OBJS:.o=.c)

# Definitions needed to rpcgen iprop-related files
ISRC= iprop.h iprop_xdr.c
KRB5IPROPDIR= $(SRC)/cmd/krb5/iprop
CMD= grep -v "usr/src/cmd/krb5/iprop" > $@

DEFS =  -DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 \
	-DHAVE_COMPILE=1 \
	-DHAVE_STEP=1

CLOBBERFILES += $(RSRC)

include ../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKSECURITY)

TEXT_DOMAIN = SUNW_OST_OSCMD
POFILE = kprop.po
POFILES = generic.po

CFLAGS += $(XESS) $(CCOPTS) $(DEFS) $(LOCALINCLUDE)
CPPFLAGS +=	-I. \
		-I$(KRB5IPROPDIR) \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5\
		-I$(SRC)/lib/krb5 \
		-I$(SRC)/lib/krb5/kadm5 \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-unused-value
CERRWARN +=	-_gcc=-Wno-address

# not linted
SMATCH=off

LDFLAGS +=	$(KRUNPATH) $(KERBRUNPATH)
LDLIBS +=	-lmech_krb5 -lsocket
$(PROG1) :=	LDLIBS += -L$(KRB5LIB) -lkadm5srv
$(PROG2) :=	LDLIBS += -L$(KRB5LIB) -lnsl -lkdb -lkadm5clnt

.KEEP_STATE:

all: $(PROG)

$(PROG1): $(CLIENTOBJS) $(COMMONOBJS)
	$(LINK.c) $(CLIENTOBJS) $(COMMONOBJS) -o $@ $(DEPLIBS) $(LDFLAGS) $(LDARGS) $(LDLIBS)
	$(POST_PROCESS)

$(PROG2): $(SERVEROBJS) $(DERIVED_OBJS) $(COMMONOBJS) $(DEPLIBS)
	$(LINK.c) $(SERVEROBJS) $(DERIVED_OBJS) $(COMMONOBJS) -o $@ $(DEPLIBS) $(LDFLAGS) $(LDARGS) $(LDLIBS)
	$(POST_PROCESS)

# Rules to rpcgen-erate derived files from the iprop.x spec file
iprop.h:	$(KRB5IPROPDIR)/iprop.x
	$(RM) $@
	$(RPCGEN) -h $(KRB5IPROPDIR)/iprop.x > $@

iprop_xdr.c:	iprop.h $(KRB5IPROPDIR)/iprop.x
	$(RM) $@
	$(RPCGEN) -c $(KRB5IPROPDIR)/iprop.x | $(CMD)

# Make dependencies explicit so make sees it.
$(KRB5LIB)/$(PROG3): $(PROG3)
$(OBJS): iprop.h

install: $(KRB5LIBPROG) $(ROOTSVCMETHOD) $(ROOTMANIFEST)

check:	$(CHKMANIFEST)

install_h:
clean:
	$(RM) $(CLIENTOBJS) $(SERVEROBJS) $(DERIVED_OBJS) $(COMMONOBJS) $(PROG) $(ISRC)

lint:
	$(LINT.c) $(CLIENTSRCS) $(COMMONSRCS) $(LDLIBS)
	$(LINT.c) $(SERVERSRCS) $(DERIVED_SRCS) $(COMMONSRCS) $(LDLIBS)

include ../../Makefile.targ

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

FRC:
