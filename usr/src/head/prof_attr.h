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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_PROF_ATTR_H
#define	_PROF_ATTR_H

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/types.h>
#include <secdb.h>


#define	PROFATTR_FILENAME		"/etc/security/prof_attr"
#define	PROFATTR_DB_NAME		"prof_attr.org_dir"
#define	PROFATTR_DB_NCOL		5	/* total columns */
#define	PROFATTR_DB_NKEYCOL		1	/* total searchable columns */
#define	PROFATTR_DB_TBLT		"prof_attr_tbl"
#define	PROFATTR_NAME_DEFAULT_KW	"nobody"

#define	PROFATTR_COL0_KW		"name"
#define	PROFATTR_COL1_KW		"res1"
#define	PROFATTR_COL2_KW		"res2"
#define	PROFATTR_COL3_KW		"desc"
#define	PROFATTR_COL4_KW		"attr"

#define	PROFILE_STOP			"Stop"

#define	DEF_PROF			"PROFS_GRANTED="
#define	DEF_CONSUSER			"CONSOLE_USER="

#define	MAXPROFS			4096

/*
 * indices of searchable columns
 */
#define	PROFATTR_KEYCOL0		0	/* name */


/*
 * Key words used in the prof_attr database
 */
#define	PROFATTR_AUTHS_KW		"auths"
#define	PROFATTR_PROFS_KW		"profiles"
#define	PROFATTR_PRIVS_KW		"privs"


/*
 * Nsswitch representation of profile attributes.
 */

typedef struct profstr_s {
	char   *name;	/* proforization name */
	char   *res1;	/* RESERVED */
	char   *res2;	/* RESERVED */
	char   *desc;	/* description */
	char   *attr;	/* string of key-value pair attributes */
} profstr_t;

typedef struct profattr_s {
	char   *name;	/* proforization name */
	char   *res1;	/* RESERVED */
	char   *res2;	/* RESERVED */
	char   *desc;	/* description */
	kva_t  *attr;	/* array of key-value pair attributes */
} profattr_t;

extern profattr_t *getprofnam(const char *);
extern profattr_t *getprofattr(void);
extern void getproflist(const char *, char **, int *);
extern void setprofattr(void);
extern void endprofattr(void);
extern void free_profattr(profattr_t *);
extern void free_proflist(char **, int);

#ifdef __cplusplus
}
#endif

#endif	/* _PROF_ATTR_H */
