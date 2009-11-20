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

#ifndef _SVC_DG_PRIV_H
#define	_SVC_DG_PRIV_H

/*
 * The svc_dg_data private datastructure shared by some services
 * for nefarious reasons.  THIS IS NOT AN INTERFACE. DO NOT USE.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The size of the option header should include sufficient space for
 * a ucred; we reserve 32 words as before we had ucreds and we allocate
 * sizeof (svc_dg_data) + ucred_size().  Of course, opts must be declared
 * last so it can use the additional memory.
 */
#define	MAX_OPT_WORDS	32

/*
 * kept in xprt->xp_p2
 */
struct svc_dg_data {
	/* Note: optbuf must be the first field, used by ti_opts.c code */
	struct	netbuf optbuf;			/* netbuf for options */
	uint_t	 su_iosz;			/* size of send.recv buffer */
	uint32_t	su_xid; 		/* transaction id */
	XDR	su_xdrs;			/* XDR handle */
	char	su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
	char	*su_cache;			/* cached data, NULL if none */
	struct t_unitdata   su_tudata;		/* tu_data for recv */
	int	opts[MAX_OPT_WORDS];		/* options: MUST BE LAST */
};

#define	get_svc_dg_data(xprt)	((struct svc_dg_data *)((xprt)->xp_p2))

#ifdef __cplusplus
}
#endif

#endif /* _SVC_DG_PRIV_H */
