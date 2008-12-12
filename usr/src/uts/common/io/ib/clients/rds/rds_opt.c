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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/ib/clients/rds/rds.h>
#include <inet/proto_set.h>

#define	rds_max_buf 2097152
opdes_t rds_opt_arr[] = {

{ SO_TYPE,	SOL_SOCKET, OA_R, OA_R, OP_NP, OP_PASSNEXT, sizeof (int), 0 },
{ SO_SNDBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, OP_PASSNEXT, sizeof (int), 0 },
{ SO_RCVBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, OP_PASSNEXT, sizeof (int), 0 },
};

/* ARGSUSED */
int
rds_opt_default(queue_t *q, t_scalar_t level, t_scalar_t name, uchar_t *ptr)
{
	/* no default value processed by protocol specific code currently */
	return (-1);
}

/*
 * This routine retrieves the current status of socket options.
 * It returns the size of the option retrieved.
 */
int
rds_opt_get(queue_t *q, t_scalar_t level, t_scalar_t name, uchar_t *ptr)
{
	int	*i1 = (int *)(uintptr_t)ptr;

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_TYPE:
			*i1 = SOCK_DGRAM;
			break;	/* goto sizeof (int) option return */

		case SO_SNDBUF:
			*i1 = q->q_hiwat;
			break;	/* goto sizeof (int) option return */
		case SO_RCVBUF:
			*i1 = RD(q)->q_hiwat;
			break;	/* goto sizeof (int) option return */
		default:
			return (-1);
		}
		break;
	default:
		return (-1);
	}
	return (sizeof (int));
}

/* This routine sets socket options. */
/* ARGSUSED */
int
rds_opt_set(queue_t *q, uint_t optset_context, int level,
    int name, uint_t inlen, uchar_t *invalp, uint_t *outlenp,
    uchar_t *outvalp, void *thisdg_attrs, cred_t *cr, mblk_t *mblk)
{
	int	*i1 = (int *)(uintptr_t)invalp;
	boolean_t checkonly;

	switch (optset_context) {
	case SETFN_OPTCOM_CHECKONLY:
		checkonly = B_TRUE;
		/*
		 * Note: Implies T_CHECK semantics for T_OPTCOM_REQ
		 * inlen != 0 implies value supplied and
		 * 	we have to "pretend" to set it.
		 * inlen == 0 implies that there is no
		 * 	value part in T_CHECK request and just validation
		 * done elsewhere should be enough, we just return here.
		 */
		if (inlen == 0) {
			*outlenp = 0;
			return (0);
		}
		break;
	case SETFN_OPTCOM_NEGOTIATE:
		checkonly = B_FALSE;
		break;
	default:
		/*
		 * We should never get here
		 */
		*outlenp = 0;
		return (EINVAL);
	}

	ASSERT((optset_context != SETFN_OPTCOM_CHECKONLY) ||
	    (optset_context == SETFN_OPTCOM_CHECKONLY && inlen != 0));

	/*
	 * For fixed length options, no sanity check
	 * of passed in length is done. It is assumed *_optcom_req()
	 * routines do the right thing.
	 */

	switch (level) {
	case SOL_SOCKET:
		switch (name) {

		case SO_SNDBUF:
			if (*i1 > rds_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (!checkonly) {
				q->q_hiwat = *i1;
				q->q_next->q_hiwat = *i1;
			}
			break;
		case SO_RCVBUF:
			if (*i1 > rds_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (!checkonly) {
				RD(q)->q_hiwat = *i1;
				(void) proto_set_rx_hiwat(RD(q), NULL, *i1);
			}
			break;
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	default:
		*outlenp = 0;
		return (EINVAL);
	}
	/*
	 * Common case of OK return with outval same as inval.
	 */
	if (invalp != outvalp) {
		/* don't trust bcopy for identical src/dst */
		(void) bcopy(invalp, outvalp, inlen);
	}
	*outlenp = inlen;
	return (0);
}

uint_t rds_max_optsize; /* initialized when RDS driver is loaded */

#define	RDS_VALID_LEVELS_CNT	A_CNT(rds_valid_levels_arr)

#define	RDS_OPT_ARR_CNT		A_CNT(rds_opt_arr)


optlevel_t rds_valid_levels_arr[] = {
	SOL_SOCKET,
};

/*
 * Initialize option database object for RDS
 *
 * This object represents database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */

optdb_obj_t rds_opt_obj = {
	rds_opt_default,	/* RDS default value function pointer */
	rds_opt_get,		/* RDS get function pointer */
	rds_opt_set,		/* RDS set function pointer */
	B_TRUE,			/* RDS is tpi provider */
	RDS_OPT_ARR_CNT,	/* RDS option database count of entries */
	rds_opt_arr,		/* RDS option database */
	RDS_VALID_LEVELS_CNT,	/* RDS valid level count of entries */
	rds_valid_levels_arr	/* RDS valid level array */
};
