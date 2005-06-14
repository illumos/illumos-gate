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
# lib/libnsl/spec/ipsec.spec

function	getipsecalgbyname
include		<netdb.h>
declaration	struct ipsecalgent *getipsecalgbyname(const char *name, \
			int proto_num, int *errnop)
version		SUNW_1.9
exception	$return == 0
end

function	getipsecalgbynum
include		<netdb.h>
declaration	struct ipsecalgent *getipsecalgbynum(int alg_num, \
			int proto_num, int *errnop)
version		SUNW_1.9
exception	$return == 0
end

function	getipsecprotobyname
include		<netdb.h>
declaration	int getipsecprotobyname(const char *proto_name)
version		SUNW_1.9
exception	$return == -1
end

function	getipsecprotobynum
include		<netdb.h>
declaration	char *getipsecprotobynum(int proto_num)
version		SUNW_1.9
exception	$return == 0
end

function	freeipsecalgent
include		<netdb.h>
declaration	void freeipsecalgent(struct ipsecalgent *ptr)
version		SUNW_1.9
end

function	_build_internal_algs
include		<ipsec_util.h>
declaration	void _build_internal_algs(ipsec_proto_t **alg_context, \
			int *alg_nums)
version		SUNWprivate_1.4
end

function	_real_getipsecprotos
include		<ipsec_util.h>
declaration	int *_real_getipsecprotos(int *nentries)
version		SUNWprivate_1.4
end

function	_real_getipsecalgs
include		<ipsec_util.h>
declaration	int *_real_getipsecalgs(int *nentries, int proto_num)
version		SUNWprivate_1.4
end

function	_clean_trash
include		<ipsec_util.h>
declaration	void _clean_trash(ipsec_proto_t *proto, int num)
version		SUNWprivate_1.4
end

function	_duplicate_alg
include		<ipsec_util.h>
declaration	struct ipsecalgent *_duplicate_alg(struct ipsecalgent *orig)
version		SUNWprivate_1.4
end

function	_str_to_ipsec_exec_mode
include		<ipsec_util.h>
declaration	int _str_to_ipsec_exec_mode(char *str, \
			ipsecalgs_exec_mode_t *exec_mode)
version		SUNWprivate_1.4
end
