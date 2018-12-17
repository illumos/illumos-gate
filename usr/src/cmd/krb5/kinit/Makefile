#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= kinit

OBJS	= kinit.o
SRCS	= kinit.c

DEFS =  -DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 -DHAVE_PWD_H=1 -DHAVE_COMPILE=1 -DHAVE_STEP=1 

include ../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += -_gcc=-Wno-parentheses

# not linted
SMATCH=off

POFILE = kinit.po
POFILES = generic.po

DEFS = -DHAVE_PWD_H

CPPFLAGS += -I../../lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5 \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		$(DEFS)

LDFLAGS += $(KRUNPATH)
LDLIBS += $(KMECHLIB)

.KEEP_STATE:

all: $(PROG)

$(PROG):       $(OBJS)  
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: $(KRB5PROG)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

include ../../Makefile.targ

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES) 
	$(RM) $@ 
	$(CAT) $(POFILES) > $@ 

generic.po:
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `($(GREP) -l gettext *.[ch] || echo /dev/null)`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
