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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef	_PASSWDUTIL_H
#define	_PASSWDUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <shadow.h>
#include <crypt.h>		/* CRYPT_MAXCIPHERTEXTLEN max crypt length */

/* DAY_NOW_32 is a 32-bit value, independent of the architecture */
#ifdef _LP64
#include <sys/types32.h>
#define	DAY_NOW_32	((time32_t)DAY_NOW)
#else
#define	DAY_NOW_32	((time_t)DAY_NOW)
#endif

typedef enum {
	/* from plain passwd */
	ATTR_NAME	= 0x1,
	ATTR_PASSWD	= 0x2,
	ATTR_UID	= 0x4,
	ATTR_GID	= 0x8,
	ATTR_AGE	= 0x10,
	ATTR_COMMENT	= 0x20,
	ATTR_GECOS	= 0x40,
	ATTR_HOMEDIR	= 0x80,
	ATTR_SHELL	= 0x100,
	/* from shadow */
	ATTR_LSTCHG	= 0x200,
	ATTR_MIN	= 0x400,
	ATTR_MAX	= 0x800,
	ATTR_WARN	= 0x1000,
	ATTR_INACT	= 0x2000,
	ATTR_EXPIRE	= 0x4000,
	ATTR_FLAG	= 0x8000,
	/* special operations */
	ATTR_LOCK_ACCOUNT	= 0x10000,
	ATTR_EXPIRE_PASSWORD	= 0x20000,
	ATTR_NOLOGIN_ACCOUNT	= 0x40000,
	ATTR_UNLOCK_ACCOUNT	= 0x80000,
	/* Query operations */
	/* to obtain repository name that contained the info */
	ATTR_REP_NAME		= 0x100000,
	/* special attribute */
	/* to set password following server policy */
	ATTR_PASSWD_SERVER_POLICY	= 0x200000,
	/* get history entry from supporting repositories */
	ATTR_HISTORY	= 0x400000,
	/* Failed login bookkeeping */
	ATTR_FAILED_LOGINS	= 0x800000,	/* get # of failed logins */
	ATTR_INCR_FAILED_LOGINS = 0x1000000,	/* increment + lock if needed */
	ATTR_RST_FAILED_LOGINS	= 0x2000000	/* reset failed logins */
} attrtype;

typedef struct attrlist_s {
	attrtype type;
	union {
		char *val_s;
		int val_i;
	} data;
	struct attrlist_s *next;
} attrlist;

typedef struct {
	char   *type;
	void   *scope;
	size_t  scope_len;
} pwu_repository_t;

#define	PWU_DEFAULT_REP (pwu_repository_t *)NULL

#define	REP_NOREP	0		/* Can't find suitable repository */
#define	REP_FILES	0x0001		/* /etc/passwd, /etc/shadow */
#define	REP_NIS		0x0002
#define	REP_LDAP	0x0004
#define	REP_NSS		0x0008
#define	REP_LAST	REP_NSS
#define	REP_ERANGE	0x8000		/* Unknown repository specified */

#define	REP_COMPAT_NIS		0x1000
#define	REP_COMPAT_LDAP		0x2000

/* For the time being, these are also defined in pam_*.h */
#undef	IS_FILES
#undef	IS_NIS
#undef	IS_LDAP

#define	IS_FILES(r)	(r.type != NULL && strcmp(r.type, "files") == 0)
#define	IS_NIS(r)	(r.type != NULL && strcmp(r.type, "nis") == 0)
#define	IS_LDAP(r)	(r.type != NULL && strcmp(r.type, "ldap") == 0)

#define	MINWEEKS	-1
#define	MAXWEEKS	-1
#define	WARNWEEKS	-1

typedef struct repops {
	int (*checkhistory)(const char *, const char *, pwu_repository_t *);
	int (*getattr)(const char *, attrlist *, pwu_repository_t *);
	int (*getpwnam)(const char *, attrlist *, pwu_repository_t *, void **);
	int (*update)(attrlist *, pwu_repository_t *, void *);
	int (*putpwnam)(const char *, const char *, pwu_repository_t *, void *);
	int (*user_to_authenticate)(const char *, pwu_repository_t *, char **,
	    int *);
	int (*lock)(void);
	int (*unlock)(void);
} repops_t;

extern repops_t files_repops, nis_repops, ldap_repops, nss_repops;

extern repops_t *rops[];

/*
 * utils.c
 */
void turn_on_default_aging(struct spwd *);
int def_getint(char *name, int defvalue);

/*
 * debug.c
 */
void debug_init(void);
void debug(char *, ...);

/*
 * switch_utils.c
 */
#define	PWU_READ	0 /* Read access to the repository */
#define	PWU_WRITE	1 /* Write (update) access to the repository */

int get_ns(pwu_repository_t *, int);
struct passwd *getpwnam_from(const char *, pwu_repository_t *, int);
struct passwd *getpwuid_from(uid_t, pwu_repository_t *, int);
struct spwd *getspnam_from(const char *, pwu_repository_t *, int);
int name_to_int(char *);

/*
 * __set_authtok_attr.c
 */
int __set_authtoken_attr(const char *, const char *, pwu_repository_t *,
    attrlist *, int *);
/*
 * __get_authtokenn_attr.c
 */
int __get_authtoken_attr(const char *, pwu_repository_t *, attrlist *);

/*
 * __user_to_authenticate.c
 */
int __user_to_authenticate(const char *, pwu_repository_t *, char **, int *);

/*
 *	Password history definitions
 */
#define	DEFHISTORY	0	/* default history depth */
#define	MAXHISTORY	26	/* max depth of history 1 yr every 2 weeks */

/*
 * __check_history.c
 */
int __check_history(const char *, const char *, pwu_repository_t *);

int __incr_failed_count(const char *, char *, int);
int __rst_failed_count(const char *, char *);

/*
 * Error / return codes
 */
#define	PWU_SUCCESS		 0	/* update succeeded */
#define	PWU_BUSY		-1	/* Password database busy */
#define	PWU_STAT_FAILED		-2	/* stat of password file failed */
#define	PWU_OPEN_FAILED		-3	/* password file open failed */
#define	PWU_WRITE_FAILED	-4	/* can't write to password file */
#define	PWU_CLOSE_FAILED	-5	/* close returned error */
#define	PWU_NOT_FOUND		-6	/* user not found in database */
#define	PWU_UPDATE_FAILED	-7	/* couldn't update password file */
#define	PWU_NOMEM		-8	/* Not enough memory */
#define	PWU_SERVER_ERROR	-9	/* NIS server errors */
#define	PWU_SYSTEM_ERROR	-10	/* NIS local configuration problem */
#define	PWU_DENIED		-11	/* NIS update denied */
#define	PWU_NO_CHANGE		-12	/* Data hasn't changed */
#define	PWU_REPOSITORY_ERROR	-13	/* Unknown repository specified */
#define	PWU_AGING_DISABLED	-14	/* Modifying min/warn while max==-1 */

/* More errors */

#define	PWU_PWD_TOO_SHORT	-15	/* new passwd too short */
#define	PWU_PWD_INVALID		-16	/* new passwd has invalid syntax */
#define	PWU_PWD_IN_HISTORY	-17	/* new passwd in history list */
#define	PWU_CHANGE_NOT_ALLOWED	-18	/* change not allowed */
#define	PWU_WITHIN_MIN_AGE	-19	/* change not allowed, within min age */
#define	PWU_ACCOUNT_LOCKED	-20	/* account successfully locked */

#ifdef __cplusplus
}
#endif

#endif	/* _PASSWDUTIL_H */
