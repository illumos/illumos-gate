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

#include <sys/types.h>
#include <inet/common.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/tpicommon.h>
#include <sys/socket_proto.h>
#include <sys/policy.h>
#include <inet/optcom.h>
#include <inet/ipclassifier.h>

boolean_t
proto_set_rx_hiwat(queue_t *q, conn_t *connp, size_t size)
{

	if (connp != NULL && IPCL_IS_NONSTR(connp)) {
		struct sock_proto_props sopp;

		sopp.sopp_flags = SOCKOPT_RCVHIWAT;
		sopp.sopp_rxhiwat = size;
		(*connp->conn_upcalls->su_set_proto_props)
		    (connp->conn_upper_handle, &sopp);
	} else {
		MBLKP	mp;
		struct stroptions *stropt;

		if (!(mp = allocb(sizeof (*stropt), BPRI_LO)))
			return (B_FALSE);
		mp->b_datap->db_type = M_SETOPTS;
		mp->b_wptr += sizeof (*stropt);
		stropt = (struct stroptions *)mp->b_rptr;
		stropt->so_flags = SO_HIWAT;
		stropt->so_hiwat = size;
		putnext(q, mp);
	}
	return (B_TRUE);
}

boolean_t
proto_set_rx_lowat(queue_t *q, conn_t *connp, size_t size)
{

	if (connp != NULL && IPCL_IS_NONSTR(connp)) {
		struct sock_proto_props sopp;

		sopp.sopp_flags = SOCKOPT_RCVLOWAT;
		sopp.sopp_rxlowat = size;
		(*connp->conn_upcalls->su_set_proto_props)
		    (connp->conn_upper_handle, &sopp);
	} else {
		MBLKP	mp;
		struct stroptions *stropt;

		if (!(mp = allocb(sizeof (*stropt), BPRI_LO)))
			return (B_FALSE);
		mp->b_datap->db_type = M_SETOPTS;
		mp->b_wptr += sizeof (*stropt);
		stropt = (struct stroptions *)mp->b_rptr;
		stropt->so_flags = SO_LOWAT;
		stropt->so_lowat = size;
		putnext(q, mp);
	}
	return (B_TRUE);
}

/*
 * Set maximum packet size. This is the maximum amount of data the protocol
 * wants to be given at any time, Larger data needs to be broken in multiples
 * of maximum packet size and given to the protocol one at a time.
 */
boolean_t
proto_set_maxpsz(queue_t *q, conn_t *connp, size_t size)
{
	if (connp != NULL && IPCL_IS_NONSTR(connp)) {
		struct sock_proto_props sopp;

		sopp.sopp_flags = SOCKOPT_MAXPSZ;
		sopp.sopp_maxpsz = size;
		(*connp->conn_upcalls->su_set_proto_props)
		    (connp->conn_upper_handle, &sopp);
		return (B_TRUE);
	} else {
		struct stdata	*stp;
		queue_t		*wq;
		stp = STREAM(q);

		/*
		 * At this point change of a queue parameter is not allowed
		 * when a multiplexor is sitting on top.
		 */
		if (stp == NULL || stp->sd_flag & STPLEX)
			return (B_FALSE);

		claimstr(stp->sd_wrq);
		wq = stp->sd_wrq->q_next;
		ASSERT(wq != NULL);
		(void) strqset(wq, QMAXPSZ, 0, size);
		releasestr(stp->sd_wrq);
		return (B_TRUE);
	}
}

/* ARGSUSED */
boolean_t
proto_set_tx_maxblk(queue_t *q, conn_t *connp, ssize_t size)
{
	if (connp != NULL && IPCL_IS_NONSTR(connp)) {
		struct sock_proto_props sopp;

		sopp.sopp_flags = SOCKOPT_MAXBLK;
		sopp.sopp_maxblk = size;
		(*connp->conn_upcalls->su_set_proto_props)
		    (connp->conn_upper_handle, &sopp);
	} else {
		MBLKP	mp;
		struct stroptions *stropt;

		if (!(mp = allocb(sizeof (*stropt), BPRI_LO)))
			return (B_FALSE);
		mp->b_datap->db_type = M_SETOPTS;
		mp->b_wptr += sizeof (*stropt);
		stropt = (struct stroptions *)mp->b_rptr;
		stropt->so_flags = SO_MAXBLK;
		stropt->so_maxblk = size;
		putnext(q, mp);
	}
	return (B_TRUE);
}

boolean_t
proto_set_tx_copyopt(queue_t *q, conn_t *connp, int copyopt)
{
	if (connp != NULL && IPCL_IS_NONSTR(connp)) {
		struct sock_proto_props sopp;

		sopp.sopp_flags = SOCKOPT_ZCOPY;
		sopp.sopp_zcopyflag = (ushort_t)copyopt;
		(*connp->conn_upcalls->su_set_proto_props)
		    (connp->conn_upper_handle, &sopp);
	} else {
		MBLKP	mp;
		struct stroptions *stropt;

		if (!(mp = allocb(sizeof (*stropt), BPRI_LO)))
			return (B_FALSE);
		mp->b_datap->db_type = M_SETOPTS;
		mp->b_wptr += sizeof (*stropt);
		stropt = (struct stroptions *)mp->b_rptr;
		stropt->so_flags = SO_COPYOPT;
		stropt->so_copyopt = (ushort_t)copyopt;
		putnext(q, mp);
	}
	return (B_TRUE);
}

boolean_t
proto_set_tx_wroff(queue_t *q, conn_t *connp, size_t size)
{
	if (connp != NULL && IPCL_IS_NONSTR(connp)) {
		struct sock_proto_props sopp;

		sopp.sopp_flags = SOCKOPT_WROFF;
		sopp.sopp_wroff = size;

		/* XXX workaround for CR6757374 */
		if (connp->conn_upper_handle != NULL)
			(*connp->conn_upcalls->su_set_proto_props)
			    (connp->conn_upper_handle, &sopp);
	} else {

		MBLKP	mp;
		struct stroptions *stropt;
		if (!(mp = allocb(sizeof (*stropt), BPRI_LO)))
			return (B_FALSE);
		mp->b_datap->db_type = M_SETOPTS;
		mp->b_wptr += sizeof (*stropt);
		stropt = (struct stroptions *)mp->b_rptr;
		stropt->so_flags = SO_WROFF;
		stropt->so_wroff = (ushort_t)size;
		putnext(q, mp);
	}
	return (B_TRUE);
}

/*
 * set OOBINLINE processing on the socket
 */
void
proto_set_rx_oob_opt(conn_t *connp, boolean_t onoff)
{
	struct sock_proto_props sopp;

	ASSERT(IPCL_IS_NONSTR(connp));

	sopp.sopp_flags = SOCKOPT_OOBINLINE;
	sopp.sopp_oobinline = onoff;
	(*connp->conn_upcalls->su_set_proto_props)
	    (connp->conn_upper_handle, &sopp);
}

/*
 * Translate a TLI(/XTI) error into a system error as best we can.
 */
static const int tli_errs[] = {
		0,		/* no error	*/
		EADDRNOTAVAIL,  /* TBADADDR	*/
		ENOPROTOOPT,	/* TBADOPT	*/
		EACCES,		/* TACCES	*/
		EBADF,		/* TBADF	*/
		EADDRNOTAVAIL,	/* TNOADDR	*/
		EPROTO,		/* TOUTSTATE	*/
		ECONNABORTED,	/* TBADSEQ	*/
		0,		/* TSYSERR - will never get	*/
		EPROTO,		/* TLOOK - should never be sent by transport */
		EMSGSIZE,	/* TBADDATA	*/
		EMSGSIZE,	/* TBUFOVFLW	*/
		EPROTO,		/* TFLOW	*/
		EWOULDBLOCK,	/* TNODATA	*/
		EPROTO,		/* TNODIS	*/
		EPROTO,		/* TNOUDERR	*/
		EINVAL,		/* TBADFLAG	*/
		EPROTO,		/* TNOREL	*/
		EOPNOTSUPP,	/* TNOTSUPPORT	*/
		EPROTO,		/* TSTATECHNG	*/
		/* following represent error namespace expansion with XTI */
		EPROTO,		/* TNOSTRUCTYPE - never sent by transport */
		EPROTO,		/* TBADNAME - never sent by transport */
		EPROTO,		/* TBADQLEN - never sent by transport */
		EADDRINUSE,	/* TADDRBUSY	*/
		EBADF,		/* TINDOUT	*/
		EBADF,		/* TPROVMISMATCH */
		EBADF,		/* TRESQLEN	*/
		EBADF,		/* TRESADDR	*/
		EPROTO,		/* TQFULL - never sent by transport */
		EPROTO,		/* TPROTO	*/
};

int
proto_tlitosyserr(int terr)
{
	ASSERT(terr != TSYSERR);
	if (terr >= (sizeof (tli_errs) / sizeof (tli_errs[0])))
		return (EPROTO);
	else
		return (tli_errs[terr]);
}

/*
 * Verify that address is suitable for connect/sendmsg and is aligned properly
 * Since this is a generic function we do not test for port being zero
 * as some protocols like icmp do not require a port
 */
int
proto_verify_ip_addr(int family, const struct sockaddr *name, socklen_t namelen)
{

	if (name == NULL || !OK_32PTR((char *)name))
		return (EINVAL);

	switch (family) {
	case AF_INET:
		if (name->sa_family != AF_INET) {
			return (EAFNOSUPPORT);
		}

		if (namelen != (socklen_t)sizeof (struct sockaddr_in)) {
			return (EINVAL);
		}
		break;
	case AF_INET6: {
#ifdef DEBUG
		struct sockaddr_in6 *sin6;
#endif /* DEBUG */

		if (name->sa_family != AF_INET6) {
			return (EAFNOSUPPORT);
		}
		if (namelen != (socklen_t)sizeof (struct sockaddr_in6)) {
			return (EINVAL);
		}
#ifdef DEBUG
		/* Verify that apps don't forget to clear sin6_scope_id etc */
		sin6 = (struct sockaddr_in6 *)name;
		if (sin6->sin6_scope_id != 0 &&
		    !IN6_IS_ADDR_LINKSCOPE(&sin6->sin6_addr)) {
			zcmn_err(getzoneid(), CE_WARN,
			    "connect/send* with uninitialized sin6_scope_id "
			    "(%d) on socket. Pid = %d\n",
			    (int)sin6->sin6_scope_id, (int)curproc->p_pid);
		}
#endif /* DEBUG */
		break;
	}
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * Do a lookup of the options in the array.
 * Rerurn NULL if there isn't a match.
 */
opdes_t *
proto_opt_lookup(t_uscalar_t level, t_uscalar_t name, opdes_t *opt_arr,
    uint_t opt_arr_cnt)
{
	opdes_t		*optd;

	for (optd = opt_arr; optd < &opt_arr[opt_arr_cnt];
	    optd++) {
		if (level == (uint_t)optd->opdes_level &&
		    name == (uint_t)optd->opdes_name)
			return (optd);
	}
	return (NULL);
}

/*
 * Do a lookup of the options in the array and do permission and length checking
 * Returns zero if there is no error (note: for non-tpi-providers not being able
 * to find the option is not an error). TPI errors are returned as negative
 * numbers and errnos as positive numbers.
 * If max_len is set we update it based on the max length of the option.
 */
int
proto_opt_check(int level, int name, int len, t_uscalar_t *max_len,
    opdes_t *opt_arr, uint_t opt_arr_cnt, boolean_t negotiate, boolean_t check,
    cred_t *cr)
{
	opdes_t *optd;

	/* Find the option in the opt_arr. */
	optd = proto_opt_lookup(level, name, opt_arr, opt_arr_cnt);
	if (optd == NULL)
		return (-TBADOPT);

	/* Additional checks dependent on operation. */
	if (negotiate) {
		/* Cannot be true at the same time */
		ASSERT(check == B_FALSE);

		if (!OA_WRITE_OR_EXECUTE(optd, cr)) {
			/* can't negotiate option */
			if (!(OA_MATCHED_PRIV(optd, cr)) &&
			    OA_WX_ANYPRIV(optd)) {
				/*
				 * not privileged but privilege
				 * will help negotiate option.
				 */
				return (-TACCES);
			} else {
				return (-TBADOPT);
			}
		}
		/*
		 * Verify size for options
		 * Note: For retaining compatibility with historical
		 * behavior, variable lengths options will have their
		 * length verified in the setfn() processing.
		 * In order to be compatible with SunOS 4.X we return
		 * EINVAL errors for bad lengths.
		 */
		if (!(optd->opdes_props & OP_VARLEN)) {
			/* fixed length - size must match */
			if (len != optd->opdes_size) {
				return (EINVAL);
			}
		}
	} else {
		if (check) {
			if (!OA_RWX_ANYPRIV(optd))
				/* any of "rwx" permission but not none */
				return (-TBADOPT);
		}
		/*
		 * XXX Since T_CURRENT was not there in TLI and the
		 * official TLI inspired TPI standard, getsockopt()
		 * API uses T_CHECK (for T_CURRENT semantics)
		 * Thus T_CHECK includes the T_CURRENT semantics due to that
		 * historical use.
		 */
		if (!OA_READ_PERMISSION(optd, cr)) {
			/* can't read option value */
			if (!(OA_MATCHED_PRIV(optd, cr)) &&
			    OA_R_ANYPRIV(optd)) {
				/*
				 * not privileged but privilege
				 * will help in reading option value.
				 */
				return (-TACCES);
			} else {
				return (-TBADOPT);
			}
		}
	}
	if (max_len != NULL)
		*max_len = optd->opdes_size;

	/* We liked it.  Keep going. */
	return (0);
}
