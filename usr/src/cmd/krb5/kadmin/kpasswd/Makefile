#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= kpasswd

OBJS	= tty_kpasswd.o kpasswd.o
SRCS	= $(OBJS:.o=.c)

CLOBBERFILES += $(TESTPROG)

include ../../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(PROG).po
POFILES = generic.po

#
# Override $ROOTLIB
#
KRB5LIBDIR=	$(ROOT)$(KERBLIBDIR)

CPPFLAGS += -I$(SRC)/lib/gss_mechs/mech_krb5/include \
	-I$(SRC)/uts/common/gssapi/include/ \
	-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
	-I$(SRC)/lib/krb5 \
	-DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 -DHAVE_UNISTD_H=1 \
	-DHAVE_SYS_TIMEB_H=1 -DHAVE_ALLOCA_H=1 -DHAVE_FTIME=1 \
	-DHAVE_TIMEZONE -DUSE_KADM5_API_VERSION=2

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-function

# not linted
SMATCH=off

LDFLAGS += $(KRUNPATH) $(KERBRUNPATH)
LDLIBS += -L $(KRB5LIBDIR)
LDLIBS += $(KMECHLIB) $(KCLNTLIB)

.KEEP_STATE:

all: $(PROG)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: $(KRB5PROG)

clean:
	$(RM) $(OBJS)

include ../../../Makefile.targ

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@
	$(RM) generic.po

generic.po:
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

