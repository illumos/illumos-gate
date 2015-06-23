/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1999 by Sun Microsystems, Inc. All rights reserved.
 */

#ifndef	_AUTH_ATTR_H
#define	_AUTH_ATTR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <secdb.h>

/*
 * Some macros used internally by the nsswitch code
 */
#define	AUTH_MMAPLEN			1024
#define	AUTH_POLICY			"/etc/security/policy.conf"
#define	DEF_AUTH			"AUTHS_GRANTED="
#define	AUTHATTR_FILENAME		"/etc/security/auth_attr"
#define	AUTHATTR_DB_NAME		"auth_attr.org_dir"
#define	AUTHATTR_DB_NCOL		6	/* total columns */
#define	AUTHATTR_DB_NKEYCOL		1	/* total searchable columns */
#define	AUTHATTR_DB_TBLT		"auth_attr_tbl"
#define	AUTHATTR_NAME_DEFAULT_KW	"nobody"

#define	AUTHATTR_COL0_KW		"name"
#define	AUTHATTR_COL1_KW		"res1"
#define	AUTHATTR_COL2_KW		"res2"
#define	AUTHATTR_COL3_KW		"short_desc"
#define	AUTHATTR_COL4_KW		"long_desc"
#define	AUTHATTR_COL5_KW		"attr"

/*
 * indices of searchable columns
 */
#define	AUTHATTR_KEYCOL0		0	/* name */


/*
 * Key words used in the auth_attr database
 */
#define	AUTHATTR_HELP_KW		"help"

/*
 * Nsswitch internal representation of authorization attributes.
 */
typedef struct authstr_s {
	char   *name;		/* authorization name */
	char   *res1;		/* reserved for future use */
	char   *res2;		/* reserved for future use */
	char   *short_desc;	/* short description */
	char   *long_desc;	/* long description */
	char   *attr;		/* string of key-value pair attributes */
} authstr_t;

/*
 * API representation of authorization attributes.
 */
typedef struct authattr_s {
	char   *name;		/* authorization name */
	char   *res1;		/* reserved for future use */
	char   *res2;		/* reserved for future use */
	char   *short_desc;	/* short description */
	char   *long_desc;	/* long description */
	kva_t  *attr;		/* array of key-value pair attributes */
} authattr_t;

extern authattr_t *getauthnam(const char *);
extern authattr_t *getauthattr(void);
extern void setauthattr(void);
extern void endauthattr(void);
extern void free_authattr(authattr_t *);
extern int chkauthattr(const char *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _AUTH_ATTR_H */
