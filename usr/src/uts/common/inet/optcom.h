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
 */
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_INET_OPTCOM_H
#define	_INET_OPTCOM_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL) && defined(__STDC__)

#include <inet/ipclassifier.h>

/* Options Description Structure */
typedef struct opdes_s {
	t_uscalar_t	opdes_name;	/* option name */
	t_uscalar_t	opdes_level;	/* option "level" */
	int	opdes_access_nopriv;	/* permissions for non-privileged */
	int	opdes_access_priv;	/* permissions for privileged */
	int	opdes_access_req_priv;	/* required privilege, OP_NP if none */
	int	opdes_props;	/* properties of associated with option */
	t_uscalar_t	opdes_size;	/* length of option */
					/* [ or maxlen if variable */
			/* length(OP_VARLEN) property set for option] */
	union {
		/*
		 *
		 * Note: C semantics:
		 * static initializer of "union" type assume
		 * the constant on RHS is of the type of the
		 * first member of the union. So what comes first
		 * is important.
		 */
#define	OPDES_DEFSZ_MAX		64
		int64_t  opdes_def_int64;
		char	opdes_def_charbuf[OPDES_DEFSZ_MAX];
	} opdes_def;
} opdes_t;

#define	opdes_default	opdes_def.opdes_def_int64
#define	opdes_defbuf	opdes_def.opdes_def_charbuf
/*
 * Flags to set in opdes_acces_{all,priv} fields in opdes_t
 *
 *	OA_R	read access
 *	OA_W	write access
 *	OA_RW	read-write access
 *	OA_X	execute access
 *
 * Note: - semantics "execute" access used for operations excuted using
 *		option management interface
 *	- no bits set means this option is not visible. Some options may not
 *	  even be visible to all but priviliged users.
 */
#define	OA_R	0x1
#define	OA_W	0x2
#define	OA_X	0x4

/*
 * Utility macros to test permissions needed to compose more
 * complex ones. (Only a few really used directly in code).
 */
#define	OA_RW	(OA_R|OA_W)
#define	OA_WX	(OA_W|OA_X)
#define	OA_RX	(OA_R|OA_X)
#define	OA_RWX	(OA_R|OA_W|OA_X)

#define	OA_ANY_ACCESS(x) ((x)->opdes_access_nopriv|(x)->opdes_access_priv)
#define	OA_R_NOPRIV(x)	((x)->opdes_access_nopriv & OA_R)
#define	OA_R_ANYPRIV(x)	(OA_ANY_ACCESS(x) & OA_R)
#define	OA_W_NOPRIV(x)	((x)->opdes_access_nopriv & OA_W)
#define	OA_X_ANYPRIV(x)	(OA_ANY_ACCESS(x) & OA_X)
#define	OA_X_NOPRIV(x)	((x)->opdes_access_nopriv & OA_X)
#define	OA_W_ANYPRIV(x)	(OA_ANY_ACCESS(x) & OA_W)
#define	OA_WX_NOPRIV(x)	((x)->opdes_access_nopriv & OA_WX)
#define	OA_WX_ANYPRIV(x)	(OA_ANY_ACCESS(x) & OA_WX)
#define	OA_RWX_ANYPRIV(x)	(OA_ANY_ACCESS(x) & OA_RWX)
#define	OA_RONLY_NOPRIV(x)	(((x)->opdes_access_nopriv & OA_RWX) == OA_R)
#define	OA_RONLY_ANYPRIV(x)	((OA_ANY_ACCESS(x) & OA_RWX) == OA_R)

#define	OP_NP		(-1)			/* No privilege required */
#define	OP_CONFIG	(0)			/* Network configuration */
#define	OP_RAW		(1)			/* Raw packets */
#define	OP_PRIVPORT	(2)			/* Privileged ports */


/*
 * Following macros supply the option and their privilege and
 * are used to determine permissions.
 */
#define	OA_POLICY_OK(x, c) \
		(secpolicy_ip((c), (x)->opdes_access_req_priv, B_FALSE) == 0)

#define	OA_POLICY_ONLY_OK(x, c) \
		(secpolicy_ip((c), (x)->opdes_access_req_priv, B_TRUE) == 0)

#define	OA_MATCHED_PRIV(x, c)	((x)->opdes_access_req_priv != OP_NP && \
		OA_POLICY_ONLY_OK((x), (c)))

#define	OA_READ_PERMISSION(x, c)	(OA_R_NOPRIV(x) || \
		(OA_R_ANYPRIV(x) && OA_POLICY_OK((x), (c))))

#define	OA_WRITE_OR_EXECUTE(x, c)	(OA_WX_NOPRIV(x) || \
		(OA_WX_ANYPRIV(x) && OA_POLICY_OK((x), (c))))

#define	OA_READONLY_PERMISSION(x, c)	(OA_RONLY_NOPRIV(x) || \
		(OA_RONLY_ANYPRIV(x) && OA_POLICY_OK((x), (c))))

#define	OA_WRITE_PERMISSION(x, c)	(OA_W_NOPRIV(x) || \
		(OA_W_ANYPRIV(x) && OA_POLICY_ONLY_OK((x), (c))))

#define	OA_EXECUTE_PERMISSION(x, c)	(OA_X_NOPRIV(x) || \
		(OA_X_ANYPRIV(x) && OA_POLICY_ONLY_OK((x), (c))))

#define	OA_NO_PERMISSION(x, c)		(OA_MATCHED_PRIV((x), (c)) ? \
		((x)->opdes_access_priv == 0) : ((x)->opdes_access_nopriv == 0))

/*
 * Other properties set in opdes_props field.
 */
#define	OP_VARLEN	0x1	/* option is varible length  */
#define	OP_NOT_ABSREQ	0x2	/* option is not a "absolute requirement" */
				/* i.e. failure to negotiate does not */
				/* abort primitive ("ignore" semantics ok) */
#define	OP_NODEFAULT	0x4	/* no concept of "default value"  */
#define	OP_DEF_FN	0x8	/* call a "default function" to get default */
				/* value, not from static table  */


/*
 * Structure to represent attributed of option management specific
 * to one particular layer of "transport".
 */

typedef	t_uscalar_t optlevel_t;

typedef int (*opt_def_fn)(queue_t *, int, int, uchar_t *);
typedef int (*opt_get_fn)(queue_t *, int, int, uchar_t *);
typedef int (*opt_set_fn)(queue_t *, uint_t, int, int, uint_t, uchar_t *,
    uint_t *, uchar_t *, void *, cred_t *);

typedef struct optdb_obj {
	opt_def_fn	odb_deffn;	/* default value function */
	opt_get_fn	odb_getfn;	/* get function */
	opt_set_fn	odb_setfn;	/* set function */
					/* provider or downstream */
	uint_t		odb_opt_arr_cnt; /* count of number of options in db */
	opdes_t		*odb_opt_des_arr; /* option descriptors in db */
	uint_t		odb_valid_levels_arr_cnt;
					/* count of option levels supported */
	optlevel_t	*odb_valid_levels_arr;
					/* array of option levels supported */
} optdb_obj_t;

/*
 * Values for "optset_context" parameter passed to
 * transport specific "setfn()" routines
 */
#define	SETFN_OPTCOM_CHECKONLY		1 /* "checkonly" semantics T_CHECK */
#define	SETFN_OPTCOM_NEGOTIATE		2 /* semantics for T_*_OPTCOM_REQ */
#define	SETFN_UD_NEGOTIATE		3 /* semantics for T_UNITDATA_REQ */
#define	SETFN_CONN_NEGOTIATE		4 /* semantics for T_CONN_*_REQ */

/*
 * Function prototypes
 */
extern void optcom_err_ack(queue_t *, mblk_t *, t_scalar_t, int);
extern void svr4_optcom_req(queue_t *, mblk_t *, cred_t *, optdb_obj_t *);
extern void tpi_optcom_req(queue_t *, mblk_t *, cred_t *, optdb_obj_t *);
extern int  tpi_optcom_buf(queue_t *, mblk_t *, t_scalar_t *, t_scalar_t,
    cred_t *, optdb_obj_t *, void *, int *);
extern t_uscalar_t optcom_max_optsize(opdes_t *, uint_t);
extern int optcom_pkt_set(uchar_t *, uint_t, uchar_t **, uint_t *);
extern int process_auxiliary_options(conn_t *, void *, t_uscalar_t,
    void *, optdb_obj_t *, int (*)(conn_t *, uint_t, int, int, uint_t,
    uchar_t *, uint_t *, uchar_t *, void *, cred_t *), cred_t *);

#endif	/* defined(_KERNEL) && defined(__STDC__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_OPTCOM_H */
