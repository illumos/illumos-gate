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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _COMMON_H
#define	_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains nisplus module-generic code.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <dhcp_svc_public.h>
#include <rpcsvc/nis.h>

/*
 * Utility macros
 */
#define	TRAIL_DOT(x)	if (x[strlen(x) - 1] != '.') (void) strcat(x, ".")
#define	ENTRY_FLAGS(obj, col) (obj)->EN_data.en_cols.en_cols_val[col].ec_flags
#define	DEFAULT_COL_SEP	' '
#define	NIS_DEF_TTL	3600

/*
 * dhcp table NIS+ related definitions
 */
#define	DSVC_NIS_COOKIE	"sunwnis+"

/* service related */
#define	NIS_BUSY_PAUSE	3	/* Pause for (secs) for a busy nisplus server */

/* generic dhcptab table */
#define	COLS_DT		3	/* total columns */
#define	KEY_DT		0	/* first column contains key */
#define	FLAG_DT		1	/* second column is record type */
#define	VALUE_DT	2	/* third and last column is value portion */

/* generic dhcp_network table */
#define	LEASE_BUF_DN	20 	/* Needs to be big enough to handle largest */
				/* number possible (uint32_t) in ascii form */
				/* 4294967296, plus null. 20 is more than */
				/* adequate */

/* Value type for query spec */
typedef enum { DSVCNIS_STR, DSVCNIS_INT } dsvcnis_qtype_t;

/*
 * nisplus specific handle
 * It contains the object type, name, and a copy of the table object (mainly
 * for the object ID).
 */
typedef struct {
	char		h_cookie[sizeof (DSVC_NIS_COOKIE) + 1];
	nis_name	h_name;		/* non-null if valid */
	uint_t		h_flags;	/* container open flags */
	nis_object	*h_object;	/* container table object */
} dsvcnis_handle_t;

extern nis_name		default_nis_group;	/* default group name */
extern uint_t		default_nis_access;	/* access bits */
extern uint_t		default_nis_ttl;	/* cache time to live */

/* generic nis related functions */
extern dsvcnis_handle_t	*dsvcnis_init_handle(const nis_name, uint_t,
			    nis_object *);
extern boolean_t	dsvcnis_validate_handle(dsvcnis_handle_t *);
extern int		dsvcnis_free_handle(dsvcnis_handle_t **);
extern int		dsvcnis_get_tobject(const char *, const nis_name,
			    const nis_name, nis_object **);
extern int		dsvcnis_set_table_fields(dsvcnis_handle_t *,
			    nis_object *);
extern int		dsvcnis_add_to_qspec(char **, const char *,
			    dsvcnis_qtype_t, void *);
extern int		dsvcnis_maperror_to_dsvc(nis_error, zotypes);
extern int		dsvcnis_validate_object(zotypes, const nis_name,
			    nis_result **, uint_t);
extern int		dsvcnis_get_username(char *, size_t);
extern int		dsvcnis_get_groupname(char *, size_t);
extern boolean_t	dsvcnis_ckperms(uint_t, uint_t, nis_object *);
extern uint64_t		dsvcnis_obj_to_sig(const nis_object *);
extern void		dsvcnis_sig_to_obj(uint64_t, nis_object *);

#ifdef	__cplusplus
}
#endif

#endif	/* !_COMMON_H */
