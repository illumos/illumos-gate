#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= kadmind
MANIFEST=	kadmin.xml

OBJS	= kadm_rpc_svc.o server_stubs.o ovsec_kadmd.o misc.o server_glue_v1.o \
          ipropd_svc.o

DERIVED_OBJS= iprop_xdr.o

SRCS=	$(OBJS:.o=.c)
SRCS+=	$(DERIVED_OBJS:.o=.c)

# Definitions needed to rpcgen iprop-related files
ISRC= iprop.h iprop_xdr.c
KRB5IPROPDIR= $(SRC)/cmd/krb5/iprop
CMD= grep -v "usr/src/cmd/krb5/iprop" > $@

CLOBBERFILES += $(TESTPROG)

include ../../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(PROG).po
POFILES = generic.po

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKSECURITY)

DEFS = -DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 -DHAVE_COMPILE=1 -DHAVE_STEP=1  -DKRB5_KRB4_COMPAT

CPPFLAGS += -I. -I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		-I$(SRC)/uts/common/gssapi \
		-I$(SRC)/lib/krb5 \
		-I$(SRC)/lib/krb5/kadm5 \
		-I$(SRC)/lib/krb5/kadm5/srv \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(KRB5IPROPDIR) \
		-I$(SRC)/uts/common/gssapi/include/ $(DEFS)

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-function

# not linted
SMATCH=off

LDFLAGS += $(KRUNPATH) $(KERBRUNPATH)
LDLIBS += -lgss -L$(KRB5LIB) \
	-lmech_krb5 -lkadm5srv -lkdb -lnsl -lresolv -lbsm -lpam -lsocket

.KEEP_STATE:

all: $(PROG)

$(PROG):	$(OBJS) $(DERIVED_OBJS)
	$(LINK.c) $(OBJS) $(DERIVED_OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

# Rules to rpcgen-erate derived files from the iprop.x spec file
iprop.h:	$(KRB5IPROPDIR)/iprop.x
	$(RM) $@
	$(RPCGEN) -h $(KRB5IPROPDIR)/iprop.x > $@

iprop_xdr.c:	iprop.h $(KRB5IPROPDIR)/iprop.x
	$(RM) $@
	$(RPCGEN) -c $(KRB5IPROPDIR)/iprop.x | $(CMD)

# Explicitly state the dependancy on iprop.h
$(OBJS): iprop.h

$(KRB5LIBPROG):=	FILEMODE = 0500

install: $(KRB5LIBPROG) $(ROOTSVCMETHOD) $(ROOTMANIFEST)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS) $(DERIVED_OBJS) $(ISRC)

include ../../../Makefile.targ

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

FRC:
