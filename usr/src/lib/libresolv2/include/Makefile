#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include		../../../Makefile.master

HDRS=		os_version.h port_ipv6.h
TMPHDRS=	new_os_version.h new_port_ipv6.h

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install

.KEEP_STATE:

all lint: $(HDRS)

install: all

clean:
	$(RM) $(HDRS) $(TMPHDRS)

clobber: clean

# os_version.h and port_ipv6.h should be rebuilt when you change OS
# revision. Since that's not easily expressed as a dependency, we
# rebuild them every time.

os_version.h: make_os_version FRC
	$(CHMOD) a+x make_os_version
	./make_os_version

port_ipv6.h: probe_ipv6 FRC
	$(CHMOD) a+x probe_ipv6
	CC="$(CC)" ./probe_ipv6

FRC:
