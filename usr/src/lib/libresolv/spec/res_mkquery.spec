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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libresolv/spec/res_mkquery.spec

function	res_mkquery
include		<sys/types.h>, <struct_rrec_compat.h>
declaration	int res_mkquery(int op, const char *dname, int class, \
			int type, const char *data, int datalen, \
			struct rrec *newrr, uchar_t *buf, int buflen )
version		SUNW_0.7
exception	$return == -1
end		

function	_res
version		SUNW_0.7
end		

# nss_dns.so.1
function	__res_set_no_hosts_fallback
version		SUNWprivate_1.1
end		

# in.named
function	_res_opcodes
version		SUNWprivate_1.1
end		

# in.named
function	_res_resultcodes
version		SUNWprivate_1.1
end		

# nss_dns.so.1
function	res_endhostent
version		SUNWprivate_1.1
end		

# nss_dns.so.1
function	res_gethostbyaddr
version		SUNWprivate_1.1
end		

# nss_dns.so.1m hotjava
function	res_gethostbyname
version		SUNWprivate_1.1
end		

# nss_dns.so.1
function	res_sethostent
version		SUNWprivate_1.1
end		
