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
# lib/libipsecutil/spec/inetutil.spec

function	addipsecalg
include		<ipsec_util.h>
declaration	int addipsecalg(struct ipsecalgent *newbie, uint_t flags)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	delipsecalgbyname
include		<ipsec_util.h>
declaration	int delipsecalgbyname(const char *name, int proto_num)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	delipsecalgbynum
include		<ipsec_util.h>
declaration	int delipsecalgbynum(int alg_num, int proto_num)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	addipsecproto
include		<ipsec_util.h>
declaration	int addipsecproto(const char *proto_name, int proto_num, \
			ipsecalgs_exec_mode_t proto_exec_mode, uint_t flags)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	delipsecprotobyname
include		<ipsec_util.h>
declaration	int delipsecprotobyname(const char *proto_name)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	delipsecprotobynum
include		<ipsec_util.h>
declaration	int delipsecprotobynum(int proto_num)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	getipsecprotos
include		<ipsec_util.h>
declaration	int *getipsecprotos(int *nentries)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	getipsecalgs
include		<ipsec_util.h>
declaration	int *getipsecalgs(int *nentries, int proto_num)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	list_ints
include		<ipsec_util.h>
declaration	int list_ints(FILE *f, int *floater)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	ipsecalgs_diag
include		<ipsec_util.h>
declaration	const char *ipsecalgs_diag(int diag)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	ipsecproto_get_exec_mode
include		<ipsec_util.h>
declaration	int ipsecproto_get_exec_mode(int proto_num, \
			ipsecalgs_exec_mode_t *exec_mode)
arch		i386 sparc
version		SUNWprivate_1.1
end

function	ipsecproto_set_exec_mode
include		<ipsec_util.h>
declaration	int ipsecproto_set_exec_mode(int proto_num, \
			ipsecalgs_exec_mode_t exec_mode)
arch		i386 sparc
version		SUNWprivate_1.1
end
