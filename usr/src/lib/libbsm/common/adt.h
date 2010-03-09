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
 * adt.h
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This is a contract private interface and is subject to change
 */

#ifndef _ADT_H
#define	_ADT_H

#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <door.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ADT_STRING_MAX	511		/* max non-null characters */
#define	ADT_NO_ATTRIB	(uid_t)-1	/* unattributed user */
#define	ADT_NO_CHANGE	(uid_t)-2	/* no update for this parameter */
#define	ADT_NO_AUDIT	(uid_t)-3	/* unaudited user */

/*
 * terminal id types
 */
#define	ADT_IPv4	1
#define	ADT_IPv6	2

/*
 * for adt_set_user(): ADT_NEW if creating a session for a newly
 * authenticated user -- login -- and ADT_UPDATE if an authenticated
 * user is changing uid/gid -- e.g., su.  ADT_USER changes only the
 * ruid / euid / rgid / egid values and is appropriate for login-like
 * operations where PAM has already set the audit context in the cred.
 * ADT_SETTID is for the special case where it is necessary to store
 * the terminal id in the credential before forking to the login or
 * login-like process.
 */
enum adt_user_context {ADT_NEW, ADT_UPDATE, ADT_USER, ADT_SETTID};

typedef ulong_t			adt_session_flags_t;
typedef struct adt_session_data	adt_session_data_t;
typedef struct adt_export_data	adt_export_data_t;
typedef union adt_event_data	adt_event_data_t;
typedef struct adt_termid	adt_termid_t;
typedef struct translation	adt_translation_t;

/*
 * flag defs for the flags argument of adt_start_session()
 */

#define	ADT_BUFFER_RECORDS	0x2	/* server buffering */
#define	ADT_USE_PROC_DATA	0x1	/* copy audit char's from proc */
	/* | all of above = ADT_FLAGS_ALL  */
#define	ADT_FLAGS_ALL		ADT_BUFFER_RECORDS | \
    ADT_USE_PROC_DATA

/*
 * Functions
 */

extern	int	adt_start_session(adt_session_data_t **,
		    const adt_export_data_t *,
		    adt_session_flags_t);
extern	int	adt_end_session(adt_session_data_t *);
extern	int	adt_dup_session(const adt_session_data_t *,
    adt_session_data_t **);

extern	int	adt_set_proc(const adt_session_data_t *);
extern	int	adt_set_user(const adt_session_data_t *, uid_t, gid_t,
		    uid_t, gid_t, const adt_termid_t *,
		    enum adt_user_context);
extern	int	adt_set_from_ucred(const adt_session_data_t *,
		    const ucred_t *,
		    enum adt_user_context);

extern	size_t	adt_get_session_id(const adt_session_data_t *, char **);

extern	size_t	adt_export_session_data(const adt_session_data_t *,
		    adt_export_data_t **);

extern	adt_event_data_t
		*adt_alloc_event(const adt_session_data_t *, au_event_t);

extern	int	adt_put_event(const adt_event_data_t *, int, int);
extern	void	adt_free_event(adt_event_data_t *);

extern	int	adt_load_termid(int, adt_termid_t **);
extern	int	adt_load_hostname(const char *, adt_termid_t **);
extern	int	adt_load_ttyname(const char *, adt_termid_t **);

extern	boolean_t	adt_audit_enabled(void);
extern	boolean_t	adt_audit_state(int);

/*
 * Special typedefs for translations.
 */

typedef	int	fd_t;		/* file descriptor */

#ifdef	__cplusplus
}
#endif

#endif	/* _ADT_H */
