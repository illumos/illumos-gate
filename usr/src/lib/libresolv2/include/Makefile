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
	$(RM) make_os_version probe_ipv6

# os_version.h and port_ipv6.h should be rebuilt when you change OS
# revision. Since that's not easily expressed as a dependency, we
# rebuild them every time.

os_version.h: make_os_version FRC
	./make_os_version

port_ipv6.h: probe_ipv6 FRC
	CC="$(CC)" ./probe_ipv6

FRC:
