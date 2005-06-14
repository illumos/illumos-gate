#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libresolv/spec/resolv.spec

function	_getlong
version		SUNW_0.7
end

function	_getshort
version		SUNW_0.7
end

function	res_querydomain
version		SUNW_0.7
end

function	res_init
include		<sys/types.h>, <netinet/in.h>, <arpa/nameser.h>, <resolv.h>
declaration	int res_init(void)
version		SUNW_0.7
end

function	res_query
include		<sys/types.h>, <netinet/in.h>, <arpa/nameser.h>, <resolv.h>
declaration	int res_query(const char *dname, int class, int type, \
			u_char *answer, int anslen)
version		SUNW_0.7
end

function	res_search
include		<sys/types.h>, <netinet/in.h>, <arpa/nameser.h>, <resolv.h>
declaration	int res_search(const char *dname, int class, int type, \
			u_char *answer, int anslen)
version		SUNW_0.7
end

function	res_send
include		<sys/types.h>, <netinet/in.h>, <arpa/nameser.h>, <resolv.h>
declaration	int res_send(const uchar_t *msg, int msglen, uchar_t *answer, \
			int anslen)
version		SUNW_0.7
exception	$return == -1
end

function	dn_comp
include		<sys/types.h>, <netinet/in.h>, <arpa/nameser.h>, <resolv.h>
declaration	int dn_comp(const char *exp_dn, u_char *comp_dn, \
			int length, u_char **dnptrs, u_char **lastdnptr)
version		SUNW_0.7
exception	$return == -1
end

function	dn_expand
include		<sys/types.h>, <netinet/in.h>, <arpa/nameser.h>, <resolv.h>
declaration	int dn_expand(const uchar_t *msg, const uchar_t *eomorig, \
			const uchar_t *comp_dn, char *exp_dn, int length)
version		SUNW_0.7
exception	$return == -1
end

function	strcasecmp
version		SUNW_0.7
filter		libc.so.1
end

function	strncasecmp
version		SUNW_0.7
filter		libc.so.1
end

function	dn_skipname
version		SUNW_0.7
end

function	fp_query
version		SUNW_0.7
end

# h_errno moved to explicit mapfile definition to provide correct type and size.

function	hostalias
version		SUNW_0.7
end

function	p_cdname
version		SUNW_0.7
end

function	p_class
version		SUNW_0.7
end

function	p_query
version		SUNW_0.7
end

function	p_rr
version		SUNW_0.7
end

function	p_time
version		SUNW_0.7
end

function	p_type
version		SUNW_0.7
end

function	putlong
version		SUNW_0.7
end
