/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LDAPADDENT_H
#define	_LDAPADDENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ldapaddent.h
 *	common declarations for ldapaddent utility
 */

#ifdef	__cplusplus
extern "C" {
#endif

#undef	GROUP
#undef	GROUP_OBJ
#include <nss_dbdefs.h>
#include <ns_sldap.h>
#include <nis_dhext.h>

extern unsigned	flags;
#define	F_VERBOSE 0x1
#define	F_PASSWD 0x2

#define	BIGBUF		8192
#define	BUFSIZ		1024
#define	LDAP_MAXNAMELEN 1024
#define	GENENT_OK	0
#define	GENENT_PARSEERR 1
#define	GENENT_CBERR	2
#define	GENENT_ERR	3
#define	PARSE_ERR_MSG_LEN 512

extern char	parse_err_msg[PARSE_ERR_MSG_LEN];
extern int	continue_onerror;  /* do not exit on error */

struct line_buf {
	char *str;
	int len;
	int alloc;
};

struct file_loc {
	off_t offset;
	size_t size;
};

extern int genent_user_attr(char *line, int (*cback)());
extern int genent_prof_attr(char *line, int (*cback)());
extern int genent_exec_attr(char *line, int (*cback)());
extern int genent_auth_attr(char *line, int (*cback)());
extern int genent_audit_user(char *line, int (*cback)());
extern int genent_tnrhdb(char *line, int (*cback)());
extern int genent_tnrhtp(char *line, int (*cback)());

extern void dump_user_attr(ns_ldap_result_t *res);
extern void dump_prof_attr(ns_ldap_result_t *res);
extern void dump_exec_attr(ns_ldap_result_t *res);
extern void dump_auth_attr(ns_ldap_result_t *res);
extern void dump_audit_user(ns_ldap_result_t *res);
extern void dump_tnrhdb(ns_ldap_result_t *res);
extern void dump_tnrhtp(ns_ldap_result_t *res);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDAPADDENT_H */
