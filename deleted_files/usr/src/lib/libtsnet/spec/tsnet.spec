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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libtsnet/spec/tsnet.spec
#

function	tsol_gettpbyname
include		<libtsnet.h>
declaration	tsol_tpent_t *tsol_gettpbyname(const char *name);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_gettpent
include		<libtsnet.h>
declaration 	tsol_tpent_t *tsol_gettpent(void);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_fgettpent
include		<libtsnet.h>
declaration 	tsol_tpent_t *tsol_gettpent(FILE *);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_freetpent
include		<libtsnet.h>
declaration 	void tsol_freetpent(tsol_tpent_t *);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_settpent
include		<libtsnet.h>
declaration	void tsol_settpent(int stay);
version		SUNWprivate_1.1
end

function	tsol_endtpent
include		<libtsnet.h>
declaration	void tsol_endtpent(void);
version		SUNWprivate_1.1
end

function	str_to_tpstr
include		<libtsnet.h>
declaration	int str_to_tpstr(const char *, int, void *, char *, int);
version		SUNWprivate_1.1
end

function	tpstr_to_ent
include		<libtsnet.h>
declaration	tsol_tpent_t *tpstr_to_ent(tsol_tpstr_t *, int *, char **);
version		SUNWprivate_1.1
end

function	tsol_getrhbyaddr
include		<libtsnet.h>
declaration	tsol_rhent_t *tsol_getrhbyaddr(const void *addr, size_t len, \
		    int type);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_getrhent
include		<libtsnet.h>
declaration 	tsol_rhent_t *tsol_getrhent(void);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_fgetrhent
include		<libtsnet.h>
declaration 	tsol_rhent_t *tsol_getrhent(FILE *);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_freerhent
include		<libtsnet.h>
declaration 	void tsol_freerhent(tsol_rhent_t *);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_setrhent
include		<libtsnet.h>
declaration	void tsol_setrhent(int stay);
version		SUNWprivate_1.1
end

function	tsol_endrhent
include		<libtsnet.h>
declaration	void tsol_endrhent(void);
version		SUNWprivate_1.1
end

function	str_to_rhstr
include		<libtsnet.h>
declaration	int str_to_rhstr(const char *, int, void *, char *, int);
version		SUNWprivate_1.1
end

function	rhstr_to_ent
include		<libtsnet.h>
declaration	tsol_rhent_t *rhstr_to_ent(tsol_rhstr_t *, int *, char **);
version		SUNWprivate_1.1
end

function	tsol_getrhtype
include		<libtsnet.h>
declaration	tsol_host_type_t tsol_getrhtype(char *);
version		SUNWprivate_1.1
end

function	tsol_sgetzcent
include		<libtsnet.h>
declaration	tsol_zcent_t *tsol_sgetzcent(const char *instr, int *errp, \
		    char **errstrp);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_freezcent
include		<libtsnet.h>
declaration 	void tsol_freezcent(tsol_zcent_t *);
version		SUNWprivate_1.1
exception	$return == 0
end

function	sl_to_str
include		<libtsnet.h>
declaration	const char *sl_to_str(const bslabel_t *sl);
version		SUNWprivate_1.1
end

function	rtsa_to_str
include		<libtsnet.h>
declaration	const char *rtsa_to_str(const struct rtsa_s *rtsa, \
		    char *line, size_t len);
version		SUNWprivate_1.1
exception	$return == 0
end

function	rtsa_keyword
include		<libtsnet.h>
declaration	boolean_t rtsa_keyword(const char *opt, struct rtsa_s *rtsa, \
		    int *errp, char **errstr);
version		SUNWprivate_1.1
exception	$return == 0
end

function	tsol_strerror
include		<libtsnet.h>
declaration	const char *tsol_strerror(int libtserr, int errnoval);
version		SUNWprivate_1.1
end

function	tnrhtp
include		<libtsnet.h>
declaration	int tnrhtp(int cmd, tsol_tpent_t *buf);
version		SUNWprivate_1.1
errno		ENOSYS EFAULT EINVAL ENOENT EOPNOTSUPP EPERM
exception	$return == -1
end

function	tnrh
include		<libtsnet.h>
declaration	int tnrh(int cmd, tsol_rhent_t *buf);
version		SUNWprivate_1.1
errno		ENOSYS EFAULT EINVAL ENOENT EOPNOTSUPP EPERM ENOMEM
exception	$return == -1
end

function	tnmlp
include		<libtsnet.h>
declaration	int tnmlp(int cmd, tsol_mlpent_t *buf);
version		SUNWprivate_1.1
errno		ENOSYS EFAULT EINVAL ENOENT EEXIST EOPNOTSUPP EPERM
exception	$return == -1
end
