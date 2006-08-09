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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libipsecutil/spec/ipsec_util.spec

function	bail
include		<ipsec_util.h>
declaration	void bail(char *what)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	bail_msg
include		<ipsec_util.h>
declaration	void bail_msg(char *fmt, ...)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	dump_sockaddr
include		<ipsec_util.h>
declaration	int dump_sockaddr(struct sockaddr *sa, boolean_t add_only, \
			FILE *where)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	dump_key
include		<ipsec_util.h>
declaration	int dump_key(uint8_t *keyp, uint_t bitlen, FILE *where)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	dump_aalg
include		<ipsec_util.h>
declaration	int dump_aalg(uint8_t aalg, FILE *where)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	dump_ealg
include		<ipsec_util.h>
declaration	int dump_ealg(uint8_t ealg, FILE *where)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	dump_sadb_idtype
include		<ipsec_util.h>
declaration	boolean_t dump_sadb_idtype(uint8_t idtype, FILE *where, int *rc)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	do_interactive
include		<ipsec_util.h>
declaration	void do_interactive(FILE *infile, char *promptstring, \
			parse_cmdln_fn parseit)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	privstr2num
include		<ipsec_util.h>
declaration	int privstr2num(char *str)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	dbgstr2num
include		<ipsec_util.h>
declaration	int dbgstr2num(char *str)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	parsedbgopts
include		<ipsec_util.h>
declaration	int parsedbgopts(char *optarg)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	kmc_insert_mapping
include		<ipsec_util.h>
declaration	int kmc_insert_mapping(char *label)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	kmc_lookup_by_cookie
include		<ipsec_util.h>
declaration	char *kmc_lookup_by_cookie(int cookie)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	spdsock_get_ext
include		<sys/types.h>, <net/pfpolicy.h>, <ipsec_util.h>
declaration	int spdsock_get_ext(spd_ext_t *extv[], spd_msg_t *basehdr, \
			uint_t msgsize, char *diag_buf, uint_t diag_buf_len)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	spdsock_diag
include		<sys/types.h>, <net/pfpolicy.h>, <ipsec_util.h>
declaration	const char *spdsock_diag(int diagnostic)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	keysock_diag
include		<sys/types.h>, <net/pfkeyv2.h>, <ipsec_util.h>
declaration	const char *keysock_diag(int diagnostic)
arch		i386 sparc
version		SUNWprivate_1.1
end

data		nflag
version		SUNWprivate_1.1
end

data		pflag
version		SUNWprivate_1.1
end

data		interactive
version		SUNWprivate_1.1
end

data		readfile
version		SUNWprivate_1.1
end

data		lineno
version		SUNWprivate_1.1
end

data		env
version		SUNWprivate_1.1
end
