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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _BSM_LIBBSM_H
#define	_BSM_LIBBSM_H


#include <ctype.h>
#include <secdb.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSLIB"
#endif

extern const char *bsm_dom;

/*
 * For audit_event(5)
 */
struct au_event_ent {
	au_event_t ae_number;
	char	*ae_name;
	char	*ae_desc;
	au_class_t ae_class;
};
typedef struct au_event_ent au_event_ent_t;

/*
 * For audit_class(5)
 */
struct au_class_ent {
	char	*ac_name;
	au_class_t ac_class;
	char	*ac_desc;
};
typedef struct au_class_ent au_class_ent_t;

/*
 * For audit_user(5)
 */
struct au_user_ent {
	char	*au_name;
	au_mask_t au_always;
	au_mask_t au_never;
};
typedef struct au_user_ent au_user_ent_t;

/*
 * Internal representation of audit user in libnsl
 */
typedef struct au_user_str_s {
	char	*au_name;
	char	*au_always;
	char	*au_never;
} au_user_str_t;

/*
 * adrf's version of adr_t
 */
typedef struct adrf_s {
	adr_t	*adrf_adr;
	FILE	*adrf_fp;
} adrf_t;

/*
 * Functions that manipulate bytes from an audit file
 */

extern void	adr_char(adr_t *, char *, int);
extern int	adr_count(adr_t *);
extern void	adr_int32(adr_t *, int32_t *, int);
extern void	adr_uid(adr_t *, uid_t *, int);
extern void	adr_int64(adr_t *, int64_t *, int);
extern void	adr_short(adr_t *, short *, int);
extern void	adr_ushort(adr_t *, ushort_t *, int);
extern void	adr_start(adr_t *, char *);

extern int	adrf_char(adrf_t *, char *, int);
extern int	adrf_int32(adrf_t *, int32_t *, int);
extern int	adrf_int64(adrf_t *, int64_t *, int);
extern int	adrf_short(adrf_t *, short *, int);
extern void	adrf_start(adrf_t *, adr_t *, FILE *);
extern int	adrf_u_char(adrf_t *, uchar_t *, int);
extern int	adrf_u_int32(adrf_t *, uint32_t *, int);
extern int	adrf_u_int64(adrf_t *, uint64_t *, int);
extern int	adrf_u_short(adrf_t *, ushort_t *, int);

/*
 * Functions that manipulate bytes from an audit character stream.
 */

extern void	adrm_start(adr_t *, char *);
extern void	adrm_char(adr_t *, char *, int);
extern void	adrm_short(adr_t *, short *, int);
extern void	adrm_int64(adr_t *, int64_t *, int);
extern void	adrm_int32(adr_t *, int32_t *, int);
extern void	adrm_uid(adr_t *, uid_t *, int);
extern void	adrm_u_int32(adr_t *, uint32_t *, int);
extern void	adrm_u_char(adr_t *, uchar_t *, int);
extern void	adrm_u_int64(adr_t *, uint64_t *, int);
extern void	adrm_u_short(adr_t *, ushort_t *, int);
extern void	adrm_putint32(adr_t *, int32_t *, int);

/*
 * Functions that do I/O for audit files
 */

extern int	au_close(int, int, au_event_t);
extern int	au_open(void);
extern int	au_write(int, token_t *);

/*
 * Functions than manipulate audit events
 */

extern void	setauevent(void);
extern void	endauevent(void);

extern au_event_ent_t	*getauevent(void);
extern au_event_ent_t	*getauevent_r(au_event_ent_t *);
extern au_event_ent_t	*getauevnam(char *);
extern au_event_ent_t	*getauevnam_r(au_event_ent_t *, char *);
extern au_event_ent_t	*getauevnum(au_event_t);
extern au_event_ent_t	*getauevnum_r(au_event_ent_t *, au_event_t);
extern au_event_t	getauevnonam(char *);
extern int		au_preselect(au_event_t, au_mask_t *, int, int);
extern int		cacheauevent(au_event_ent_t **, au_event_t);

/*
 * Functions that manipulate audit classes
 */

extern void	setauclass(void);
extern void	endauclass(void);

extern int	cacheauclass(au_class_ent_t **, au_class_t);
extern int	cacheauclassnam(au_class_ent_t **, char *);
extern au_class_ent_t *getauclassent(void);
extern au_class_ent_t *getauclassent_r(au_class_ent_t *);
extern au_class_ent_t *getauclassnam(char *);
extern au_class_ent_t *getauclassnam_r(au_class_ent_t *, char *);

/*
 * Functions that manipulate audit masks
 */

extern int	au_user_mask(char *, au_mask_t *);
extern int	getauditflagsbin(char *, au_mask_t *);
extern int	getauditflagschar(char *, au_mask_t *, int);
extern int	getfauditflags(au_mask_t *, au_mask_t *, au_mask_t *);
extern boolean_t __chkflags(char *, au_mask_t *, boolean_t, char **);

/*
 * Functions that do system calls
 */

extern int	audit(char *, int);
extern int	auditon(int, caddr_t, int);
extern int	auditdoor(int);
extern int	getaudit(auditinfo_t *);
extern int	getaudit_addr(auditinfo_addr_t *, int);
extern int	getauid(au_id_t *);
extern int	setaudit(auditinfo_t *);
extern int	setaudit_addr(auditinfo_addr_t *, int);
extern int	setauid(au_id_t *);

/*
 * Defines for au_preselect(3)
 */
#define	AU_PRS_SUCCESS	1
#define	AU_PRS_FAILURE	2
#define	AU_PRS_BOTH	(AU_PRS_SUCCESS|AU_PRS_FAILURE)

#define	AU_PRS_USECACHE	0
#define	AU_PRS_REREAD	1

/*
 * Defines for cacheauclass and cacheauevent
 */
#define	AU_CACHE_FREE	0x0000
#define	AU_CACHE_NAME	0x0001
#define	AU_CACHE_NUMBER	0x0002

/* Flags for user-level audit routines: au_open, au_close, au_to_ */
#define	AU_TO_NO_WRITE	0
#define	AU_TO_WRITE	1

/* system audit files for auditd */
#define	AUDITCLASSFILE		"/etc/security/audit_class"
#define	AUDITEVENTFILE		"/etc/security/audit_event"
#define	AUDITUSERFILE		"/etc/security/audit_user"

/* array sizes for audit library structures */
#define	AU_CLASS_NAME_MAX	8
#define	AU_CLASS_DESC_MAX	72
#define	AU_EVENT_NAME_MAX	30
#define	AU_EVENT_DESC_MAX	50
#define	AU_EVENT_LINE_MAX	256

/*
 * Some macros used internally by the nsswitch code
 */
#define	AUDITUSER_FILENAME		"/etc/security/audit_user"
#define	AUDITUSER_DB_NAME		"audit_user.org_dir"
#define	AUDITUSER_DB_NCOL		3	/* total columns */
#define	AUDITUSER_DB_NKEYCOL		1	/* total searchable columns */
#define	AUDITUSER_DB_TBLT		"audit_user_tbl"
#define	AUDITUSER_SUCCESS		0
#define	AUDITUSER_PARSE_ERANGE		1
#define	AUDITUSER_NOT_FOUND		2

#define	AUDITUSER_COL0_KW		"name"
#define	AUDITUSER_COL1_KW		"always"
#define	AUDITUSER_COL2_KW		"never"

/*
 * indices of searchable columns
 */
#define	AUDITUSER_KEYCOL0		0	/* name */


#ifdef	__cplusplus
}
#endif

#endif	/* _BSM_LIBBSM_H */
