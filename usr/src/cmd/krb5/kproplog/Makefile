#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG		=	kproplog

OBJS		=	kproplog.o
DERIVED_OBJS	=	iprop_xdr.o

SRCS=	$(OBJS:.o=.c)
SRCS+=	$(DERIVED_OBJS:.o=.c)

RSRC=	kproplog.c

# Definitions needed to rpcgen iprop-related files
ISRC= iprop.h iprop_xdr.c
KRB5IPROPDIR= $(SRC)/cmd/krb5/iprop
CMD= grep -v "usr/src/cmd/krb5/iprop" > $@

include	../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

TEXT_DOMAIN = SUNW_OST_OSCMD
POFILE	= kproplog.po
POFILES	= generic.po

LDFLAGS		+=	-R$(KRB5RUNPATH) $(KRUNPATH)
LDLIBS		+=	-L$(KRB5LIB) $(KLIB) -lnsl -lkdb -lkadm5clnt

CPPFLAGS	+=	-I. -I$(SRC)/lib/krb5 \
			-I$(KRB5IPROPDIR) \
			-I$(SRC)/lib/gss_mechs/mech_krb5/include \
			-I$(SRC)/uts/common/gssapi/mechs/krb5/include

CERRWARN	+=	-_gcc=-Wno-unused-variable
CERRWARN	+=	-_gcc=-Wno-unused-function
CERRWARN	+=	-_gcc=-Wno-implicit-function-declaration

# not linted
SMATCH=off

all:		$(PROG)

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

install:	$(KRB5SBINPROG)

lint:	$(ISRC) .WAIT lint_SRCS

clean:
	$(RM) $(OBJS) $(DERIVED_OBJS) $(ISRC)

include ../../Makefile.targ

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po:
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
