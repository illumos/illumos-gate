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
/* Copyright (c) 1990 Mentat Inc. */

/*
 * This file contains common code for handling Options Management requests.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/errno.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ddi.h>
#include <sys/debug.h>		/* for ASSERT */
#include <sys/policy.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/mib2.h>
#include <netinet/in.h>
#include "optcom.h"

#include <inet/optcom.h>
#include <inet/ipclassifier.h>
#include <inet/proto_set.h>

/*
 * Function prototypes
 */
static t_scalar_t process_topthdrs_first_pass(mblk_t *, cred_t *, optdb_obj_t *,
    boolean_t *, size_t *);
static t_scalar_t do_options_second_pass(queue_t *q, mblk_t *reqmp,
    mblk_t *ack_mp, cred_t *, optdb_obj_t *dbobjp,
    mblk_t *first_mp, boolean_t is_restart, boolean_t *queued_statusp);
static t_uscalar_t get_worst_status(t_uscalar_t, t_uscalar_t);
static int do_opt_default(queue_t *, struct T_opthdr *, uchar_t **,
    t_uscalar_t *, cred_t *, optdb_obj_t *);
static void do_opt_current(queue_t *, struct T_opthdr *, uchar_t **,
    t_uscalar_t *, cred_t *cr, optdb_obj_t *);
static int do_opt_check_or_negotiate(queue_t *q, struct T_opthdr *reqopt,
    uint_t optset_context, uchar_t **resptrp, t_uscalar_t *worst_statusp,
    cred_t *, optdb_obj_t *dbobjp, mblk_t *first_mp);
static boolean_t opt_level_valid(t_uscalar_t, optlevel_t *, uint_t);
static size_t opt_level_allopts_lengths(t_uscalar_t, opdes_t *, uint_t);
static boolean_t opt_length_ok(opdes_t *, struct T_opthdr *);
static t_uscalar_t optcom_max_optbuf_len(opdes_t *, uint_t);
static boolean_t opt_bloated_maxsize(opdes_t *);

/* Common code for sending back a T_ERROR_ACK. */
void
optcom_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error, int sys_error)
{
	if ((mp = mi_tpi_err_ack_alloc(mp, t_error, sys_error)) != NULL)
		qreply(q, mp);
}

/*
 * The option management routines svr4_optcom_req() and tpi_optcom_req() use
 * callback functions as arguments. Here is the expected interfaces
 * assumed from the callback functions
 *
 *
 * (1) deffn(q, optlevel, optname, optvalp)
 *
 *	- Function only called when default value comes from protocol
 *	 specific code and not the option database table (indicated by
 *	  OP_DEF_FN property in option database.)
 *	- Error return is -1. Valid returns are >=0.
 *	- When valid, the return value represents the length used for storing
 *		the default value of the option.
 *      - Error return implies the called routine did not recognize this
 *              option. Something downstream could so input is left unchanged
 *              in request buffer.
 *
 * (2) getfn(q, optlevel, optname, optvalp)
 *
 *	- Error return is -1. Valid returns are >=0.
 *	- When valid, the return value represents the length used for storing
 *		the actual value of the option.
 *      - Error return implies the called routine did not recognize this
 *              option. Something downstream could so input is left unchanged
 *              in request buffer.
 *
 * (3) setfn(q, optset_context, optlevel, optname, inlen, invalp,
 *	outlenp, outvalp, attrp, cr);
 *
 *	- OK return is 0, Error code is returned as a non-zero argument.
 *      - If negative it is ignored by svr4_optcom_req(). If positive, error
 *        is returned. A negative return implies that option, while handled on
 *	  this stack is not handled at this level and will be handled further
 *	  downstream.
 *	- Both negative and positive errors are treats as errors in an
 *	  identical manner by tpi_optcom_req(). The errors affect "status"
 *	  field of each option's T_opthdr. If sucessfull, an appropriate sucess
 *	  result is carried. If error, it instantiated to "failure" at the
 *	  topmost level and left unchanged at other levels. (This "failure" can
 *	  turn to a success at another level).
 *	- optset_context passed for tpi_optcom_req(). It is interpreted as:
 *        - SETFN_OPTCOM_CHECKONLY
 *		semantics are to pretend to set the value and report
 *		back if it would be successful.
 *		This is used with T_CHECK semantics in XTI
 *        - SETFN_OPTCOM_NEGOTIATE
 *		set the value. Call from option management primitive
 *		T_OPTMGMT_REQ when T_NEGOTIATE flags is used.
 *	  - SETFN_UD_NEGOTIATE
 *		option request came riding on UNITDATA primitive most often
 *		has  "this datagram" semantics to influence prpoerties
 *		affecting an outgoig datagram or associated with recived
 *		datagram
 *		[ Note: XTI permits this use outside of "this datagram"
 *		semantics also and permits setting "management related"
 *		options in this	context and its test suite enforces it ]
 *	  - SETFN_CONN_NEGOTATE
 *		option request came riding on CONN_REQ/RES primitive and
 *		most often has "this connection" (negotiation during
 *		"connection estblishment") semantics.
 *		[ Note: XTI permits use of these outside of "this connection"
 *		semantics and permits "management related" options in this
 *		context and its test suite enforces it. ]
 *
 *	- inlen, invalp is the option length,value requested to be set.
 *	- outlenp, outvalp represent return parameters which contain the
 *	  value set and it might be different from one passed on input.
 *	- attrp points to a data structure that's used by v6 modules to
 *	  store ancillary data options or sticky options.
 *	- cr points to the caller's credentials
 *	- the caller might pass same buffers for input and output and the
 *	  routine should protect against this case by not updating output
 *	  buffers until it is done referencing input buffers and any other
 *	  issues (e.g. not use bcopy() if we do not trust what it does).
 *      - If option is not known, it returns error. We randomly pick EINVAL.
 *        It can however get called with options that are handled downstream
 *        opr upstream so for svr4_optcom_req(), it does not return error for
 *        negative return values.
 *
 */

/*
 * Upper Level Protocols call this routine when they receive
 * a T_SVR4_OPTMGMT_REQ message.  They supply callback functions
 * for setting a new value for a single options, getting the
 * current value for a single option, and checking for support
 * of a single option.  svr4_optcom_req validates the option management
 * buffer passed in, and calls the appropriate routines to do the
 * job requested.
 * XXX Code below needs some restructuring after we have some more
 * macros to support 'struct opthdr' in the headers.
 *
 * IP-MT notes: The option management framework functions svr4_optcom_req() and
 * tpi_optcom_req() allocate and prepend an M_CTL mblk to the actual
 * T_optmgmt_req mblk and pass the chain as an additional parameter to the
 * protocol set functions. If a protocol set function (such as ip_opt_set)
 * cannot process the option immediately it can return EINPROGRESS. ip_opt_set
 * enqueues the message in the appropriate sq and returns EINPROGRESS. Later
 * the sq framework arranges to restart this operation and passes control to
 * the restart function ip_restart_optmgmt() which in turn calls
 * svr4_optcom_req() or tpi_optcom_req() to restart the option processing.
 *
 * XXX Remove the asynchronous behavior of svr_optcom_req() and
 * tpi_optcom_req().
 */
int
svr4_optcom_req(queue_t *q, mblk_t *mp, cred_t *cr, optdb_obj_t *dbobjp,
    boolean_t pass_to_ip)
{
	pfi_t	deffn = dbobjp->odb_deffn;
	pfi_t	getfn = dbobjp->odb_getfn;
	opt_set_fn setfn = dbobjp->odb_setfn;
	opdes_t	*opt_arr = dbobjp->odb_opt_des_arr;
	uint_t opt_arr_cnt = dbobjp->odb_opt_arr_cnt;
	boolean_t topmost_tpiprovider = dbobjp->odb_topmost_tpiprovider;
	opt_restart_t *or;
	struct opthdr *restart_opt;
	boolean_t is_restart = B_FALSE;
	mblk_t	*first_mp;

	t_uscalar_t max_optbuf_len;
	int len;
	mblk_t	*mp1 = NULL;
	struct opthdr *next_opt;
	struct opthdr *opt;
	struct opthdr *opt1;
	struct opthdr *opt_end;
	struct opthdr *opt_start;
	opdes_t	*optd;
	boolean_t	pass_to_next = B_FALSE;
	struct T_optmgmt_ack *toa;
	struct T_optmgmt_req *tor;
	int error;

	/*
	 * Allocate M_CTL and prepend to the packet for restarting this
	 * option if needed. IP may need to queue and restart the option
	 * if it cannot obtain exclusive conditions immediately. Please see
	 * IP-MT notes before the start of svr4_optcom_req
	 */
	if (mp->b_datap->db_type == M_CTL) {
		is_restart = B_TRUE;
		first_mp = mp;
		mp = mp->b_cont;
		ASSERT(mp->b_wptr - mp->b_rptr >=
		    sizeof (struct T_optmgmt_req));
		tor = (struct T_optmgmt_req *)mp->b_rptr;
		ASSERT(tor->MGMT_flags == T_NEGOTIATE);

		or = (opt_restart_t *)first_mp->b_rptr;
		opt_start = or->or_start;
		opt_end = or->or_end;
		restart_opt = or->or_ropt;
		goto restart;
	}

	tor = (struct T_optmgmt_req *)mp->b_rptr;
	/* Verify message integrity. */
	if (mp->b_wptr - mp->b_rptr < sizeof (struct T_optmgmt_req))
		goto bad_opt;
	/* Verify MGMT_flags legal */
	switch (tor->MGMT_flags) {
	case T_DEFAULT:
	case T_NEGOTIATE:
	case T_CURRENT:
	case T_CHECK:
		/* OK - legal request flags */
		break;
	default:
		optcom_err_ack(q, mp, TBADFLAG, 0);
		return (0);
	}
	if (tor->MGMT_flags == T_DEFAULT) {
		/* Is it a request for default option settings? */

		/*
		 * Note: XXX TLI and TPI specification was unclear about
		 * semantics of T_DEFAULT and the following historical note
		 * and its interpretation is incorrect (it implies a request
		 * for default values of only the identified options not all.
		 * The semantics have been explained better in XTI spec.)
		 * However, we do not modify (comment or code) here to keep
		 * compatibility.
		 * We can rethink this if it ever becomes an issue.
		 * ----historical comment start------
		 * As we understand it, the input buffer is meaningless
		 * so we ditch the message.  A T_DEFAULT request is a
		 * request to obtain a buffer containing defaults for
		 * all supported options, so we allocate a maximum length
		 * reply.
		 * ----historical comment end -------
		 */
		/* T_DEFAULT not passed down */
		ASSERT(topmost_tpiprovider == B_TRUE);
		freemsg(mp);
		max_optbuf_len = optcom_max_optbuf_len(opt_arr,
		    opt_arr_cnt);
		mp = allocb(max_optbuf_len, BPRI_MED);
		if (!mp) {
no_mem:;
			optcom_err_ack(q, mp, TSYSERR, ENOMEM);
			return (0);
		}

		/* Initialize the T_optmgmt_ack header. */
		toa = (struct T_optmgmt_ack *)mp->b_rptr;
		bzero((char *)toa, max_optbuf_len);
		toa->PRIM_type = T_OPTMGMT_ACK;
		toa->OPT_offset = (t_scalar_t)sizeof (struct T_optmgmt_ack);
		/* TODO: Is T_DEFAULT the right thing to put in MGMT_flags? */
		toa->MGMT_flags = T_DEFAULT;

		/* Now walk the table of options passed in */
		opt = (struct opthdr *)&toa[1];
		for (optd = opt_arr; optd < &opt_arr[opt_arr_cnt]; optd++) {
			/*
			 * All the options in the table of options passed
			 * in are by definition supported by the protocol
			 * calling this function.
			 */
			if (!OA_READ_PERMISSION(optd, cr))
				continue;
			opt->level = optd->opdes_level;
			opt->name = optd->opdes_name;
			if (!(optd->opdes_props & OP_DEF_FN) ||
			    ((len = (*deffn)(q, opt->level,
			    opt->name, (uchar_t *)&opt[1])) < 0)) {
				/*
				 * Fill length and value from table.
				 *
				 * Default value not instantiated from function
				 * (or the protocol specific function failed it;
				 * In this interpretation of T_DEFAULT, this is
				 * the best we can do)
				 */
				switch (optd->opdes_size) {
				/*
				 * Since options are guaranteed aligned only
				 * on a 4 byte boundary (t_scalar_t) any
				 * option that is greater in size will default
				 * to the bcopy below
				 */
				case sizeof (int32_t):
					*(int32_t *)&opt[1] =
					    (int32_t)optd->opdes_default;
					break;
				case sizeof (int16_t):
					*(int16_t *)&opt[1] =
					    (int16_t)optd->opdes_default;
					break;
				case sizeof (int8_t):
					*(int8_t *)&opt[1] =
					    (int8_t)optd->opdes_default;
					break;
				default:
					/*
					 * other length but still assume
					 * fixed - use bcopy
					 */
					bcopy(optd->opdes_defbuf,
					    &opt[1], optd->opdes_size);
					break;
				}
				opt->len = optd->opdes_size;
			}
			else
				opt->len = (t_uscalar_t)len;
			opt = (struct opthdr *)((char *)&opt[1] +
			    _TPI_ALIGN_OPT(opt->len));
		}

		/* Now record the final length. */
		toa->OPT_length = (t_scalar_t)((char *)opt - (char *)&toa[1]);
		mp->b_wptr = (uchar_t *)opt;
		mp->b_datap->db_type = M_PCPROTO;
		/* Ship it back. */
		qreply(q, mp);
		return (0);
	}
	/* T_DEFAULT processing complete - no more T_DEFAULT */

	/*
	 * For T_NEGOTIATE, T_CURRENT, and T_CHECK requests, we make a
	 * pass through the input buffer validating the details and
	 * making sure each option is supported by the protocol.
	 */
	if ((opt_start = (struct opthdr *)mi_offset_param(mp,
	    tor->OPT_offset, tor->OPT_length)) == NULL)
		goto bad_opt;
	if (!__TPI_OPT_ISALIGNED(opt_start))
		goto bad_opt;

	opt_end = (struct opthdr *)((uchar_t *)opt_start +
	    tor->OPT_length);

	for (opt = opt_start; opt < opt_end; opt = next_opt) {
		/*
		 * Verify we have room to reference the option header
		 * fields in the option buffer.
		 */
		if ((uchar_t *)opt + sizeof (struct opthdr) >
		    (uchar_t *)opt_end)
			goto bad_opt;
		/*
		 * We now compute pointer to next option in buffer 'next_opt'
		 * The next_opt computation above below 'opt->len' initialized
		 * by application which cannot be trusted. The usual value
		 * too large will be captured by the loop termination condition
		 * above. We check for the following which it will miss.
		 * 	-pointer space wraparound arithmetic overflow
		 *	-last option in buffer with 'opt->len' being too large
		 *	 (only reason 'next_opt' should equal or exceed
		 *	 'opt_end' for last option is roundup unless length is
		 *	 too-large/invalid)
		 */
		next_opt = (struct opthdr *)((uchar_t *)&opt[1] +
		    _TPI_ALIGN_OPT(opt->len));

		if ((uchar_t *)next_opt < (uchar_t *)&opt[1] ||
		    ((next_opt >= opt_end) &&
		    (((uchar_t *)next_opt - (uchar_t *)opt_end) >=
		    __TPI_ALIGN_SIZE)))
			goto bad_opt;

		/* sanity check */
		if (opt->name == T_ALLOPT)
			goto bad_opt;

		error = proto_opt_check(opt->level, opt->name, opt->len, NULL,
		    opt_arr, opt_arr_cnt, topmost_tpiprovider,
		    tor->MGMT_flags == T_NEGOTIATE, tor->MGMT_flags == T_CHECK,
		    cr);
		if (error < 0) {
			optcom_err_ack(q, mp, -error, 0);
			return (0);
		} else if (error > 0) {
			optcom_err_ack(q, mp, TSYSERR, error);
			return (0);
		}
	} /* end for loop scanning option buffer */

	/* Now complete the operation as required. */
	switch (tor->MGMT_flags) {
	case T_CHECK:
		/*
		 * Historically used same as T_CURRENT (which was added to
		 * standard later). Code retained for compatibility.
		 */
		/* FALLTHROUGH */
	case T_CURRENT:
		/*
		 * Allocate a maximum size reply.  Perhaps we are supposed to
		 * assume that the input buffer includes space for the answers
		 * as well as the opthdrs, but we don't know that for sure.
		 * So, instead, we create a new output buffer, using the
		 * input buffer only as a list of options.
		 */
		max_optbuf_len = optcom_max_optbuf_len(opt_arr,
		    opt_arr_cnt);
		mp1 = allocb_cred(max_optbuf_len, cr);
		if (!mp1)
			goto no_mem;
		/* Initialize the header. */
		mp1->b_datap->db_type = M_PCPROTO;
		mp1->b_wptr = &mp1->b_rptr[sizeof (struct T_optmgmt_ack)];
		toa = (struct T_optmgmt_ack *)mp1->b_rptr;
		toa->OPT_offset = (t_scalar_t)sizeof (struct T_optmgmt_ack);
		toa->MGMT_flags = tor->MGMT_flags;
		/*
		 * Walk through the input buffer again, this time adding
		 * entries to the output buffer for each option requested.
		 * Note, sanity of option header, last option etc, verified
		 * in first pass.
		 */
		opt1 = (struct opthdr *)&toa[1];

		for (opt = opt_start; opt < opt_end; opt = next_opt) {

			next_opt = (struct opthdr *)((uchar_t *)&opt[1] +
			    _TPI_ALIGN_OPT(opt->len));

			opt1->name = opt->name;
			opt1->level = opt->level;
			len = (*getfn)(q, opt->level,
			    opt->name, (uchar_t *)&opt1[1]);
			/*
			 * Failure means option is not recognized. Copy input
			 * buffer as is
			 */
			if (len < 0) {
				opt1->len = opt->len;
				bcopy(&opt[1], &opt1[1], opt->len);
			} else {
				opt1->len = (t_uscalar_t)len;
			}
			opt1 = (struct opthdr *)((uchar_t *)&opt1[1] +
			    _TPI_ALIGN_OPT(opt1->len));
		} /* end for loop */

		/* Record the final length. */
		toa->OPT_length = (t_scalar_t)((uchar_t *)opt1 -
		    (uchar_t *)&toa[1]);
		mp1->b_wptr = (uchar_t *)opt1;
		/* Ditch the input buffer. */
		freemsg(mp);
		mp = mp1;
		/* Always let the next module look at the option. */
		pass_to_next = B_TRUE;
		break;

	case T_NEGOTIATE:
		first_mp = allocb(sizeof (opt_restart_t), BPRI_LO);
		if (first_mp == NULL) {
			optcom_err_ack(q, mp, TSYSERR, ENOMEM);
			return (0);
		}
		first_mp->b_datap->db_type = M_CTL;
		or = (opt_restart_t *)first_mp->b_rptr;
		or->or_start = opt_start;
		or->or_end =  opt_end;
		or->or_type = T_SVR4_OPTMGMT_REQ;
		or->or_private = 0;
		first_mp->b_cont = mp;
restart:
		/*
		 * Here we are expecting that the response buffer is exactly
		 * the same size as the input buffer.  We pass each opthdr
		 * to the protocol's set function.  If the protocol doesn't
		 * like it, it can update the value in it return argument.
		 */
		/*
		 * Pass each negotiated option through the protocol set
		 * function.
		 * Note: sanity check on option header values done in first
		 * pass and not repeated here.
		 */
		toa = (struct T_optmgmt_ack *)tor;

		for (opt = is_restart ? restart_opt: opt_start; opt < opt_end;
		    opt = next_opt) {
			int error;

			/*
			 * Point to the current option in or, in case this
			 * option has to be restarted later on
			 */
			or->or_ropt = opt;
			next_opt = (struct opthdr *)((uchar_t *)&opt[1] +
			    _TPI_ALIGN_OPT(opt->len));

			error = (*setfn)(q, SETFN_OPTCOM_NEGOTIATE,
			    opt->level, opt->name,
			    opt->len, (uchar_t *)&opt[1],
			    &opt->len, (uchar_t *)&opt[1], NULL, cr, first_mp);
			/*
			 * Treat positive "errors" as real.
			 * Note: negative errors are to be treated as
			 * non-fatal by svr4_optcom_req() and are
			 * returned by setfn() when it is passed an
			 * option it does not handle. Since the option
			 * passed proto_opt_lookup(), it is implied that
			 * it is valid but was either handled upstream
			 * or will be handled downstream.
			 */
			if (error == EINPROGRESS) {
				/*
				 * The message is queued and will be
				 * reprocessed later. Typically ip queued
				 * the message to get some exclusive conditions
				 * and later on calls this func again.
				 */
				return (EINPROGRESS);
			} else if (error > 0) {
				optcom_err_ack(q, mp, TSYSERR, error);
				freeb(first_mp);
				return (0);
			}
			/*
			 * error < 0 means option is not recognized.
			 * But with OP_PASSNEXT the next module
			 * might recognize it.
			 */
		}
		/* Done with the restart control mp. */
		freeb(first_mp);
		pass_to_next = B_TRUE;
		break;
	default:
		optcom_err_ack(q, mp, TBADFLAG, 0);
		return (0);
	}

	if (pass_to_next && (q->q_next != NULL || pass_to_ip)) {
		/* Send it down to the next module and let it reply */
		toa->PRIM_type = T_SVR4_OPTMGMT_REQ; /* Changed by IP to ACK */
		if (q->q_next != NULL)
			putnext(q, mp);
		else
			ip_output(Q_TO_CONN(q), mp, q, IP_WPUT);
	} else {
		/* Set common fields in the header. */
		toa->MGMT_flags = T_SUCCESS;
		mp->b_datap->db_type = M_PCPROTO;
		toa->PRIM_type = T_OPTMGMT_ACK;
		qreply(q, mp);
	}
	return (0);
bad_opt:;
	optcom_err_ack(q, mp, TBADOPT, 0);
	return (0);
}

/*
 * New optcom_req inspired by TPI/XTI semantics
 */
int
tpi_optcom_req(queue_t *q, mblk_t *mp, cred_t *cr, optdb_obj_t *dbobjp,
    boolean_t pass_to_ip)
{
	t_scalar_t t_error;
	mblk_t *toa_mp;
	boolean_t pass_to_next;
	size_t toa_len;
	struct T_optmgmt_ack *toa;
	struct T_optmgmt_req *tor =
	    (struct T_optmgmt_req *)mp->b_rptr;

	opt_restart_t *or;
	boolean_t is_restart = B_FALSE;
	mblk_t	*first_mp = NULL;
	t_uscalar_t worst_status;
	boolean_t queued_status;

	/*
	 * Allocate M_CTL and prepend to the packet for restarting this
	 * option if needed. IP may need to queue and restart the option
	 * if it cannot obtain exclusive conditions immediately. Please see
	 * IP-MT notes before the start of svr4_optcom_req
	 */
	if (mp->b_datap->db_type == M_CTL) {
		is_restart = B_TRUE;
		first_mp = mp;
		toa_mp = mp->b_cont;
		mp = toa_mp->b_cont;
		ASSERT(mp->b_wptr - mp->b_rptr >=
		    sizeof (struct T_optmgmt_req));
		tor = (struct T_optmgmt_req *)mp->b_rptr;
		ASSERT(tor->MGMT_flags == T_NEGOTIATE);

		or = (opt_restart_t *)first_mp->b_rptr;
		goto restart;
	}

	/* Verify message integrity. */
	if ((mp->b_wptr - mp->b_rptr) < sizeof (struct T_optmgmt_req)) {
		optcom_err_ack(q, mp, TBADOPT, 0);
		return (0);
	}

	/* Verify MGMT_flags legal */
	switch (tor->MGMT_flags) {
	case T_DEFAULT:
	case T_NEGOTIATE:
	case T_CURRENT:
	case T_CHECK:
		/* OK - legal request flags */
		break;
	default:
		optcom_err_ack(q, mp, TBADFLAG, 0);
		return (0);
	}

	/*
	 * In this design, there are two passes required on the input buffer
	 * mostly to accomodate variable length options and "T_ALLOPT" option
	 * which has the semantics "all options of the specified level".
	 *
	 * For T_DEFAULT, T_NEGOTIATE, T_CURRENT, and T_CHECK requests, we make
	 * a pass through the input buffer validating the details and making
	 * sure each option is supported by the protocol. We also determine the
	 * length of the option buffer to return. (Variable length options and
	 * T_ALLOPT mean that length can be different for output buffer).
	 */

	pass_to_next = B_FALSE;	/* initial value */
	toa_len = 0;		/* initial value */

	/*
	 * First pass, we do the following
	 *	- estimate cumulative length needed for results
	 *	- set "status" field based on permissions, option header check
	 *	  etc.
	 *	- determine "pass_to_next" whether we need to send request to
	 *	  downstream module/driver.
	 */
	if ((t_error = process_topthdrs_first_pass(mp, cr, dbobjp,
	    &pass_to_next, &toa_len)) != 0) {
		optcom_err_ack(q, mp, t_error, 0);
		return (0);
	}

	/*
	 * A validation phase of the input buffer is done. We have also
	 * obtained the length requirement and and other details about the
	 * input and we liked input buffer so far.  We make another scan
	 * through the input now and generate the output necessary to complete
	 * the operation.
	 */

	toa_mp = allocb_cred(toa_len, cr);
	if (!toa_mp) {
		optcom_err_ack(q, mp, TSYSERR, ENOMEM);
		return (0);
	}

	first_mp = allocb(sizeof (opt_restart_t), BPRI_LO);
	if (first_mp == NULL) {
		freeb(toa_mp);
		optcom_err_ack(q, mp, TSYSERR, ENOMEM);
		return (0);
	}
	first_mp->b_datap->db_type = M_CTL;
	or = (opt_restart_t *)first_mp->b_rptr;
	/*
	 * Set initial values for generating output.
	 */
	or->or_worst_status = T_SUCCESS;
	or->or_type = T_OPTMGMT_REQ;
	or->or_private = 0;
	/* remaining fields fileed in do_options_second_pass */

restart:
	/*
	 * This routine makes another pass through the option buffer this
	 * time acting on the request based on "status" result in the
	 * first pass. It also performs "expansion" of T_ALLOPT into
	 * all options of a certain level and acts on each for this request.
	 */
	if ((t_error = do_options_second_pass(q, mp, toa_mp, cr, dbobjp,
	    first_mp, is_restart, &queued_status)) != 0) {
		freemsg(toa_mp);
		optcom_err_ack(q, mp, t_error, 0);
		return (0);
	}
	if (queued_status) {
		/* Option will be restarted */
		return (EINPROGRESS);
	}
	worst_status = or->or_worst_status;
	/* Done with the first mp */
	freeb(first_mp);
	toa_mp->b_cont = NULL;

	/*
	 * Following code relies on the coincidence that T_optmgmt_req
	 * and T_optmgmt_ack are identical in binary representation
	 */
	toa = (struct T_optmgmt_ack *)toa_mp->b_rptr;
	toa->OPT_length = (t_scalar_t)(toa_mp->b_wptr - (toa_mp->b_rptr +
	    sizeof (struct T_optmgmt_ack)));
	toa->OPT_offset = (t_scalar_t)sizeof (struct T_optmgmt_ack);

	toa->MGMT_flags = tor->MGMT_flags;


	freemsg(mp);		/* free input mblk */

	/*
	 * If there is atleast one option that requires a downstream
	 * forwarding and if it is possible, we forward the message
	 * downstream. Else we ack it.
	 */
	if (pass_to_next && (q->q_next != NULL || pass_to_ip)) {
		/*
		 * We pass it down as T_OPTMGMT_REQ. This code relies
		 * on the happy coincidence that T_optmgmt_req and
		 * T_optmgmt_ack are identical data structures
		 * at the binary representation level.
		 */
		toa_mp->b_datap->db_type = M_PROTO;
		toa->PRIM_type = T_OPTMGMT_REQ;
		if (q->q_next != NULL)
			putnext(q, toa_mp);
		else
			ip_output(Q_TO_CONN(q), toa_mp, q, IP_WPUT);
	} else {
		toa->PRIM_type = T_OPTMGMT_ACK;
		toa_mp->b_datap->db_type = M_PCPROTO;
		toa->MGMT_flags |= worst_status; /* XXX "worst" or "OR" TPI ? */
		qreply(q, toa_mp);
	}
	return (0);
}


/*
 * Following routine makes a pass through option buffer in mp and performs the
 * following tasks.
 *	- estimate cumulative length needed for results
 *	- set "status" field based on permissions, option header check
 *	  etc.
 *	- determine "pass_to_next" whether we need to send request to
 *	  downstream module/driver.
 */

static t_scalar_t
process_topthdrs_first_pass(mblk_t *mp, cred_t *cr, optdb_obj_t *dbobjp,
    boolean_t *pass_to_nextp, size_t *toa_lenp)
{
	opdes_t	*opt_arr = dbobjp->odb_opt_des_arr;
	uint_t opt_arr_cnt = dbobjp->odb_opt_arr_cnt;
	boolean_t topmost_tpiprovider = dbobjp->odb_topmost_tpiprovider;
	optlevel_t *valid_level_arr = dbobjp->odb_valid_levels_arr;
	uint_t valid_level_arr_cnt = dbobjp->odb_valid_levels_arr_cnt;
	struct T_opthdr *opt;
	struct T_opthdr *opt_start, *opt_end;
	opdes_t	*optd;
	size_t allopt_len;
	struct T_optmgmt_req *tor =
	    (struct T_optmgmt_req *)mp->b_rptr;

	*toa_lenp = sizeof (struct T_optmgmt_ack); /* initial value */

	if ((opt_start = (struct T_opthdr *)
	    mi_offset_param(mp, tor->OPT_offset, tor->OPT_length)) == NULL) {
		return (TBADOPT);
	}
	if (!__TPI_TOPT_ISALIGNED(opt_start))
		return (TBADOPT);

	opt_end = (struct T_opthdr *)((uchar_t *)opt_start + tor->OPT_length);

	for (opt = opt_start; opt && (opt < opt_end);
	    opt = _TPI_TOPT_NEXTHDR(opt_start, tor->OPT_length, opt)) {
		/*
		 * Validate the option for length and alignment
		 * before accessing anything in it.
		 */
		if (!(_TPI_TOPT_VALID(opt, opt_start, opt_end)))
			return (TBADOPT);

		/* Find the option in the opt_arr. */
		if (opt->name != T_ALLOPT) {
			optd = proto_opt_lookup(opt->level, opt->name,
			    opt_arr, opt_arr_cnt);
			if (optd == NULL) {
				/*
				 * Option not found
				 *
				 * Verify if level is "valid" or not.
				 * Note: This check is required by XTI
				 *
				 * TPI provider always initializes
				 * the "not supported" (or whatever) status
				 * for the options. Other levels leave status
				 * unchanged if they do not understand an
				 * option.
				 */
				if (topmost_tpiprovider) {
					if (!opt_level_valid(opt->level,
					    valid_level_arr,
					    valid_level_arr_cnt))
						return (TBADOPT);
					/*
					 * level is valid - initialize
					 * option as not supported
					 */
					opt->status = T_NOTSUPPORT;
				}

				*toa_lenp += _TPI_ALIGN_TOPT(opt->len);
				continue;
			}
		} else {
			/*
			 * Handle T_ALLOPT case as a special case.
			 * Note: T_ALLOPT does not mean anything
			 * for T_CHECK operation.
			 */
			allopt_len = 0;
			if (tor->MGMT_flags == T_CHECK ||
			    !topmost_tpiprovider ||
			    ((allopt_len = opt_level_allopts_lengths(opt->level,
			    opt_arr, opt_arr_cnt)) == 0)) {
				/*
				 * This is confusing but correct !
				 * It is not valid to to use T_ALLOPT with
				 * T_CHECK flag.
				 *
				 * T_ALLOPT is assumed "expanded" at the
				 * topmost_tpiprovider level so it should not
				 * be there as an "option name" if this is not
				 * a topmost_tpiprovider call and we fail it.
				 *
				 * opt_level_allopts_lengths() is used to verify
				 * that "level" associated with the T_ALLOPT is
				 * supported.
				 *
				 */
				opt->status = T_FAILURE;
				*toa_lenp += _TPI_ALIGN_TOPT(opt->len);
				continue;
			}
			ASSERT(allopt_len != 0); /* remove ? */

			*toa_lenp += allopt_len;
			opt->status = T_SUCCESS;
			/* XXX - always set T_ALLOPT 'pass_to_next' for now */
			*pass_to_nextp = B_TRUE;
			continue;
		}
		/*
		 * Check if option wants to flow downstream
		 */
		if (optd->opdes_props & OP_PASSNEXT)
			*pass_to_nextp = B_TRUE;

		/* Additional checks dependent on operation. */
		switch (tor->MGMT_flags) {
		case T_DEFAULT:
		case T_CURRENT:

			/*
			 * The proto_opt_lookup() routine call above approved of
			 * this option so we can work on the status for it
			 * based on the permissions for the operation. (This
			 * can override any status for it set at higher levels)
			 * We assume this override is OK since chkfn at this
			 * level approved of this option.
			 *
			 * T_CURRENT semantics:
			 * The read access is required. Else option
			 * status is T_NOTSUPPORT.
			 *
			 * T_DEFAULT semantics:
			 * Note: specification is not clear on this but we
			 * interpret T_DEFAULT semantics such that access to
			 * read value is required for access even the default
			 * value. Otherwise the option status is T_NOTSUPPORT.
			 */
			if (!OA_READ_PERMISSION(optd, cr)) {
				opt->status = T_NOTSUPPORT;
				*toa_lenp += _TPI_ALIGN_TOPT(opt->len);
				/* skip to next */
				continue;
			}

			/*
			 * T_DEFAULT/T_CURRENT semantics:
			 * We know that read access is set. If no other access
			 * is set, then status is T_READONLY.
			 */
			if (OA_READONLY_PERMISSION(optd, cr))
				opt->status = T_READONLY;
			else
				opt->status = T_SUCCESS;
			/*
			 * Option passes all checks. Make room for it in the
			 * ack. Note: size stored in table does not include
			 * space for option header.
			 */
			*toa_lenp += sizeof (struct T_opthdr) +
			    _TPI_ALIGN_TOPT(optd->opdes_size);
			break;

		case T_CHECK:
		case T_NEGOTIATE:

			/*
			 * T_NEGOTIATE semantics:
			 * If for fixed length option value on input is not the
			 * same as value supplied, then status is T_FAILURE.
			 *
			 * T_CHECK semantics:
			 * If value is supplied, semantics same as T_NEGOTIATE.
			 * It is however ok not to supply a value with T_CHECK.
			 */

			if (tor->MGMT_flags == T_NEGOTIATE ||
			    (opt->len != sizeof (struct T_opthdr))) {
				/*
				 * Implies "value" is specified in T_CHECK or
				 * it is a T_NEGOTIATE request.
				 * Verify size.
				 * Note: This can override anything about this
				 * option request done at a higher level.
				 */
				if (!opt_length_ok(optd, opt)) {
					/* bad size */
					*toa_lenp += _TPI_ALIGN_TOPT(opt->len);
					opt->status = T_FAILURE;
					continue;
				}
			}
			/*
			 * The proto_opt_lookup()  routine above() approved of
			 * this option so we can work on the status for it based
			 * on the permissions for the operation. (This can
			 * override anything set at a higher level).
			 *
			 * T_CHECK/T_NEGOTIATE semantics:
			 * Set status to T_READONLY if read is the only access
			 * permitted
			 */
			if (OA_READONLY_PERMISSION(optd, cr)) {
				opt->status = T_READONLY;
				*toa_lenp += _TPI_ALIGN_TOPT(opt->len);
				/* skip to next */
				continue;
			}

			/*
			 * T_CHECK/T_NEGOTIATE semantics:
			 * If write (or execute) access is not set, then status
			 * is T_NOTSUPPORT.
			 */
			if (!OA_WRITE_OR_EXECUTE(optd, cr)) {
				opt->status = T_NOTSUPPORT;
				*toa_lenp += _TPI_ALIGN_TOPT(opt->len);
				/* skip to next option */
				continue;
			}
			/*
			 * Option passes all checks. Make room for it in the
			 * ack and set success in status.
			 * Note: size stored in table does not include header
			 * length.
			 */
			opt->status = T_SUCCESS;
			*toa_lenp += sizeof (struct T_opthdr) +
			    _TPI_ALIGN_TOPT(optd->opdes_size);
			break;

		default:
			return (TBADFLAG);
		}
	} /* for loop scanning input buffer */

	return (0);		/* OK return */
}

/*
 * This routine makes another pass through the option buffer this
 * time acting on the request based on "status" result in the
 * first pass. It also performs "expansion" of T_ALLOPT into
 * all options of a certain level and acts on each for this request.
 */
static t_scalar_t
do_options_second_pass(queue_t *q, mblk_t *reqmp, mblk_t *ack_mp, cred_t *cr,
    optdb_obj_t *dbobjp, mblk_t *first_mp, boolean_t is_restart,
    boolean_t *queued_statusp)
{
	boolean_t topmost_tpiprovider = dbobjp->odb_topmost_tpiprovider;
	int failed_option;
	struct T_opthdr *opt;
	struct T_opthdr *opt_start, *opt_end, *restart_opt;
	uchar_t *optr;
	uint_t optset_context;
	struct T_optmgmt_req *tor = (struct T_optmgmt_req *)reqmp->b_rptr;
	opt_restart_t	*or;
	t_uscalar_t	*worst_statusp;
	int	err;

	*queued_statusp = B_FALSE;
	or = (opt_restart_t *)first_mp->b_rptr;
	worst_statusp = &or->or_worst_status;

	optr = (uchar_t *)ack_mp->b_rptr +
	    sizeof (struct T_optmgmt_ack); /* assumed int32_t aligned */

	/*
	 * Set initial values for scanning input
	 */
	if (is_restart) {
		opt_start = (struct T_opthdr *)or->or_start;
		opt_end = (struct T_opthdr *)or->or_end;
		restart_opt = (struct T_opthdr *)or->or_ropt;
	} else {
		opt_start = (struct T_opthdr *)mi_offset_param(reqmp,
		    tor->OPT_offset, tor->OPT_length);
		if (opt_start == NULL)
			return (TBADOPT);
		opt_end = (struct T_opthdr *)((uchar_t *)opt_start +
		    tor->OPT_length);
		or->or_start = (struct opthdr *)opt_start;
		or->or_end = (struct opthdr *)opt_end;
		/*
		 * construct the mp chain, in case the setfn needs to
		 * queue this and restart option processing later on.
		 */
		first_mp->b_cont = ack_mp;
		ack_mp->b_cont = reqmp;
	}
	ASSERT(__TPI_TOPT_ISALIGNED(opt_start)); /* verified in first pass */

	for (opt = is_restart ? restart_opt : opt_start;
	    opt && (opt < opt_end);
	    opt = _TPI_TOPT_NEXTHDR(opt_start, tor->OPT_length, opt)) {
		or->or_ropt = (struct opthdr *)opt;
		/* verified in first pass */
		ASSERT(_TPI_TOPT_VALID(opt, opt_start, opt_end));

		/*
		 * If the first pass in process_topthdrs_first_pass()
		 * has marked the option as a failure case for the MGMT_flags
		 * semantics then there is not much to do.
		 *
		 * Note: For all practical purposes, T_READONLY status is
		 * a "success" for T_DEFAULT/T_CURRENT and "failure" for
		 * T_CHECK/T_NEGOTIATE
		 */
		failed_option =
		    (opt->status == T_NOTSUPPORT) ||
		    (opt->status == T_FAILURE) ||
		    ((tor->MGMT_flags & (T_NEGOTIATE|T_CHECK)) &&
		    (opt->status == T_READONLY));

		if (failed_option) {
			/*
			 * According to T_DEFAULT/T_CURRENT semantics, the
			 * input values, even if present, are to be ignored.
			 * Note: Specification is not clear on this, but we
			 * interpret that even though we ignore the values, we
			 * can return them as is. So we process them similar to
			 * T_CHECK/T_NEGOTIATE case which has the semantics to
			 * return the values as is. XXX If interpretation is
			 * ever determined incorrect fill in appropriate code
			 * here to treat T_DEFAULT/T_CURRENT differently.
			 *
			 * According to T_CHECK/T_NEGOTIATE semantics,
			 * in the case of T_NOTSUPPORT/T_FAILURE/T_READONLY,
			 * the semantics are to return the "value" part of
			 * option untouched. So here we copy the option
			 * head including value part if any to output.
			 */

			bcopy(opt, optr, opt->len);
			optr += _TPI_ALIGN_TOPT(opt->len);

			*worst_statusp = get_worst_status(opt->status,
			    *worst_statusp);

			/* skip to process next option in buffer */
			continue;

		} /* end if "failed option" */
		/*
		 * The status is T_SUCCESS or T_READONLY
		 * We process the value part here
		 */
		ASSERT(opt->status == T_SUCCESS || opt->status == T_READONLY);
		switch (tor->MGMT_flags) {
		case T_DEFAULT:
			/*
			 * We fill default value from table or protocol specific
			 * function. If this call fails, we pass input through.
			 */
			if (do_opt_default(q, opt, &optr, worst_statusp,
			    cr, dbobjp) < 0) {
				/* fail or pass transparently */
				if (topmost_tpiprovider)
					opt->status = T_FAILURE;
				bcopy(opt, optr, opt->len);
				optr += _TPI_ALIGN_TOPT(opt->len);
				*worst_statusp = get_worst_status(opt->status,
				    *worst_statusp);
			}
			break;

		case T_CURRENT:

			do_opt_current(q, opt, &optr, worst_statusp, cr,
			    dbobjp);
			break;

		case T_CHECK:
		case T_NEGOTIATE:
			if (tor->MGMT_flags == T_CHECK)
				optset_context = SETFN_OPTCOM_CHECKONLY;
			else	/* T_NEGOTIATE */
				optset_context = SETFN_OPTCOM_NEGOTIATE;
			err = do_opt_check_or_negotiate(q, opt, optset_context,
			    &optr, worst_statusp, cr, dbobjp, first_mp);
			if (err == EINPROGRESS) {
				*queued_statusp = B_TRUE;
				return (0);
			}
			break;
		default:
			return (TBADFLAG);
		}
	} /* end for loop scanning option buffer */

	ack_mp->b_wptr = optr;
	ASSERT(ack_mp->b_wptr <= ack_mp->b_datap->db_lim);

	return (0);		/* OK return */
}


static t_uscalar_t
get_worst_status(t_uscalar_t status, t_uscalar_t current_worst_status)
{
	/*
	 * Return the "worst" among the arguments "status" and
	 * "current_worst_status".
	 *
	 * Note: Tracking "worst_status" can be made a bit simpler
	 * if we use the property that status codes are bitwise
	 * distinct.
	 *
	 * The pecking order is
	 *
	 * T_SUCCESS ..... best
	 * T_PARTSUCCESS
	 * T_FAILURE
	 * T_READONLY
	 * T_NOTSUPPORT... worst
	 */
	if (status == current_worst_status)
		return (current_worst_status);
	switch (current_worst_status) {
	case T_SUCCESS:
		if (status == T_PARTSUCCESS)
			return (T_PARTSUCCESS);
		/* FALLTHROUGH */
	case T_PARTSUCCESS:
		if (status == T_FAILURE)
			return (T_FAILURE);
		/* FALLTHROUGH */
	case T_FAILURE:
		if (status == T_READONLY)
			return (T_READONLY);
		/* FALLTHROUGH */
	case T_READONLY:
		if (status == T_NOTSUPPORT)
			return (T_NOTSUPPORT);
		/* FALLTHROUGH */
	case T_NOTSUPPORT:
	default:
		return (current_worst_status);
	}
}

static int
do_opt_default(queue_t *q, struct T_opthdr *reqopt, uchar_t **resptrp,
    t_uscalar_t *worst_statusp, cred_t *cr, optdb_obj_t *dbobjp)
{
	pfi_t	deffn = dbobjp->odb_deffn;
	opdes_t	*opt_arr = dbobjp->odb_opt_des_arr;
	uint_t opt_arr_cnt = dbobjp->odb_opt_arr_cnt;
	boolean_t topmost_tpiprovider = dbobjp->odb_topmost_tpiprovider;

	struct T_opthdr *topth;
	opdes_t *optd;

	if (reqopt->name != T_ALLOPT) {
		/*
		 * lookup the option in the table and fill default value
		 */
		optd = proto_opt_lookup(reqopt->level, reqopt->name,
		    opt_arr, opt_arr_cnt);

		if (optd == NULL) {
			/*
			 * not found - fail this one. Should not happen
			 * for topmost_tpiprovider as calling routine
			 * should have verified it.
			 */
			ASSERT(!topmost_tpiprovider);
			return (-1);
		}

		topth = (struct T_opthdr *)(*resptrp);
		topth->level = reqopt->level;
		topth->name = reqopt->name;
		topth->status = reqopt->status;

		*worst_statusp = get_worst_status(reqopt->status,
		    *worst_statusp);

		if (optd->opdes_props & OP_NODEFAULT) {
			/* header only, no default "value" part */
			topth->len = sizeof (struct T_opthdr);
			*resptrp += sizeof (struct T_opthdr);
		} else {
			int deflen;

			if (optd->opdes_props & OP_DEF_FN) {
				deflen = (*deffn)(q, reqopt->level,
				    reqopt->name, _TPI_TOPT_DATA(topth));
				if (deflen >= 0) {
					topth->len = (t_uscalar_t)
					    (sizeof (struct T_opthdr) + deflen);
				} else {
					/*
					 * return error, this should 'pass
					 * through' the option and maybe some
					 * other level will fill it in or
					 * already did.
					 * (No change in 'resptrp' upto here)
					 */
					return (-1);
				}
			} else {
				/* fill length and value part */
				switch (optd->opdes_size) {
				/*
				 * Since options are guaranteed aligned only
				 * on a 4 byte boundary (t_scalar_t) any
				 * option that is greater in size will default
				 * to the bcopy below
				 */
				case sizeof (int32_t):
					*(int32_t *)_TPI_TOPT_DATA(topth) =
					    (int32_t)optd->opdes_default;
					break;
				case sizeof (int16_t):
					*(int16_t *)_TPI_TOPT_DATA(topth) =
					    (int16_t)optd->opdes_default;
					break;
				case sizeof (int8_t):
					*(int8_t *)_TPI_TOPT_DATA(topth) =
					    (int8_t)optd->opdes_default;
					break;
				default:
					/*
					 * other length but still assume
					 * fixed - use bcopy
					 */
					bcopy(optd->opdes_defbuf,
					    _TPI_TOPT_DATA(topth),
					    optd->opdes_size);
					break;
				}
				topth->len = (t_uscalar_t)(optd->opdes_size +
				    sizeof (struct T_opthdr));
			}
			*resptrp += _TPI_ALIGN_TOPT(topth->len);
		}
		return (0);	/* OK return */
	}

	/*
	 * T_ALLOPT processing
	 *
	 * lookup and stuff default values of all the options of the
	 * level specified
	 * Note: This expansion of T_ALLOPT should happen in
	 * a topmost_tpiprovider.
	 */
	ASSERT(topmost_tpiprovider);
	for (optd = opt_arr; optd < &opt_arr[opt_arr_cnt]; optd++) {
		if (reqopt->level != optd->opdes_level)
			continue;
		/*
		 *
		 * T_DEFAULT semantics:
		 * XXX: we interpret T_DEFAULT semantics such that access to
		 * read value is required for access even the default value.
		 * Else option is ignored for T_ALLOPT request.
		 */
		if (!OA_READ_PERMISSION(optd, cr))
			/* skip this one */
			continue;

		/*
		 * Found option of same level as T_ALLOPT request
		 * that we can return.
		 */

		topth = (struct T_opthdr *)(*resptrp);
		topth->level = optd->opdes_level;
		topth->name = optd->opdes_name;

		/*
		 * T_DEFAULT semantics:
		 * We know that read access is set. If no other access is set,
		 * then status is T_READONLY
		 */
		if (OA_READONLY_PERMISSION(optd, cr)) {
			topth->status = T_READONLY;
			*worst_statusp = get_worst_status(T_READONLY,
			    *worst_statusp);
		} else {
			topth->status = T_SUCCESS;
			/*
			 * Note: *worst_statusp has to be T_SUCCESS or
			 * worse so no need to adjust
			 */
		}

		if (optd->opdes_props & OP_NODEFAULT) {
			/* header only, no value part */
			topth->len = sizeof (struct T_opthdr);
			*resptrp += sizeof (struct T_opthdr);
		} else {
			int deflen;

			if (optd->opdes_props & OP_DEF_FN) {
				deflen = (*deffn)(q, reqopt->level,
				    reqopt->name, _TPI_TOPT_DATA(topth));
				if (deflen >= 0) {
					topth->len = (t_uscalar_t)(deflen +
					    sizeof (struct T_opthdr));
				} else {
					/*
					 * deffn failed.
					 * return just the header as T_ALLOPT
					 * expansion.
					 * Some other level deffn may
					 * supply value part.
					 */
					topth->len = sizeof (struct T_opthdr);
					topth->status = T_FAILURE;
					*worst_statusp =
					    get_worst_status(T_FAILURE,
					    *worst_statusp);
				}
			} else {
				/*
				 * fill length and value part from
				 * table
				 */
				switch (optd->opdes_size) {
				/*
				 * Since options are guaranteed aligned only
				 * on a 4 byte boundary (t_scalar_t) any
				 * option that is greater in size will default
				 * to the bcopy below
				 */
				case sizeof (int32_t):
					*(int32_t *)_TPI_TOPT_DATA(topth) =
					    (int32_t)optd->opdes_default;
					break;
				case sizeof (int16_t):
					*(int16_t *)_TPI_TOPT_DATA(topth) =
					    (int16_t)optd->opdes_default;
					break;
				case sizeof (int8_t):
					*(int8_t *)_TPI_TOPT_DATA(topth) =
					    (int8_t)optd->opdes_default;
					break;
				default:
					/*
					 * other length but still assume
					 * fixed - use bcopy
					 */
					bcopy(optd->opdes_defbuf,
					    _TPI_TOPT_DATA(topth),
					    optd->opdes_size);
				}
				topth->len = (t_uscalar_t)(optd->opdes_size +
				    sizeof (struct T_opthdr));
			}
			*resptrp += _TPI_ALIGN_TOPT(topth->len);
		}
	}
	return (0);
}

static void
do_opt_current(queue_t *q, struct T_opthdr *reqopt, uchar_t **resptrp,
    t_uscalar_t *worst_statusp, cred_t *cr, optdb_obj_t *dbobjp)
{
	pfi_t	getfn = dbobjp->odb_getfn;
	opdes_t	*opt_arr = dbobjp->odb_opt_des_arr;
	uint_t opt_arr_cnt = dbobjp->odb_opt_arr_cnt;
	boolean_t topmost_tpiprovider = dbobjp->odb_topmost_tpiprovider;

	struct T_opthdr *topth;
	opdes_t *optd;
	int optlen;
	uchar_t *initptr = *resptrp;

	/*
	 * We call getfn to get the current value of an option. The call may
	 * fail in which case we copy the values from the input buffer. Maybe
	 * something downstream will fill it in or something upstream did.
	 */

	if (reqopt->name != T_ALLOPT) {
		topth = (struct T_opthdr *)*resptrp;
		*resptrp += sizeof (struct T_opthdr);
		optlen = (*getfn)(q, reqopt->level, reqopt->name, *resptrp);
		if (optlen >= 0) {
			topth->len = (t_uscalar_t)(optlen +
			    sizeof (struct T_opthdr));
			topth->level = reqopt->level;
			topth->name = reqopt->name;
			topth->status = reqopt->status;
			*resptrp += _TPI_ALIGN_TOPT(optlen);
			*worst_statusp = get_worst_status(topth->status,
			    *worst_statusp);
		} else {
			/* failed - reset "*resptrp" pointer */
			*resptrp -= sizeof (struct T_opthdr);
		}
	} else {		/* T_ALLOPT processing */
		ASSERT(topmost_tpiprovider == B_TRUE);
		/* scan and get all options */
		for (optd = opt_arr; optd < &opt_arr[opt_arr_cnt]; optd++) {
			/* skip other levels */
			if (reqopt->level != optd->opdes_level)
				continue;

			if (!OA_READ_PERMISSION(optd, cr))
				/* skip this one */
				continue;

			topth = (struct T_opthdr *)*resptrp;
			*resptrp += sizeof (struct T_opthdr);

			/* get option of this level */
			optlen = (*getfn)(q, reqopt->level, optd->opdes_name,
			    *resptrp);
			if (optlen >= 0) {
				/* success */
				topth->len = (t_uscalar_t)(optlen +
				    sizeof (struct T_opthdr));
				topth->level = reqopt->level;
				topth->name = optd->opdes_name;
				if (OA_READONLY_PERMISSION(optd, cr))
					topth->status = T_READONLY;
				else
					topth->status = T_SUCCESS;
				*resptrp += _TPI_ALIGN_TOPT(optlen);
			} else {
				/*
				 * failed, return as T_FAILURE and null value
				 * part. Maybe something downstream will
				 * handle this one and fill in a value. Here
				 * it is just part of T_ALLOPT expansion.
				 */
				topth->len = sizeof (struct T_opthdr);
				topth->level = reqopt->level;
				topth->name = optd->opdes_name;
				topth->status = T_FAILURE;
			}
			*worst_statusp = get_worst_status(topth->status,
			    *worst_statusp);
		} /* end for loop */
	}
	if (*resptrp == initptr) {
		/*
		 * getfn failed and does not want to handle this option. Maybe
		 * something downstream will or something upstream did. (If
		 * topmost_tpiprovider, initialize "status" to failure which
		 * can possibly change downstream). Copy the input "as is" from
		 * input option buffer if any to maintain transparency.
		 */
		if (topmost_tpiprovider)
			reqopt->status = T_FAILURE;
		bcopy(reqopt, *resptrp, reqopt->len);
		*resptrp += _TPI_ALIGN_TOPT(reqopt->len);
		*worst_statusp = get_worst_status(reqopt->status,
		    *worst_statusp);
	}
}

/* ARGSUSED */
static int
do_opt_check_or_negotiate(queue_t *q, struct T_opthdr *reqopt,
    uint_t optset_context, uchar_t **resptrp, t_uscalar_t *worst_statusp,
    cred_t *cr, optdb_obj_t *dbobjp, mblk_t *first_mp)
{
	pfi_t	deffn = dbobjp->odb_deffn;
	opt_set_fn setfn = dbobjp->odb_setfn;
	opdes_t	*opt_arr = dbobjp->odb_opt_des_arr;
	uint_t opt_arr_cnt = dbobjp->odb_opt_arr_cnt;
	boolean_t topmost_tpiprovider = dbobjp->odb_topmost_tpiprovider;

	struct T_opthdr *topth;
	opdes_t *optd;
	int error;
	t_uscalar_t optlen;
	t_scalar_t optsize;
	uchar_t *initptr = *resptrp;

	ASSERT(reqopt->status == T_SUCCESS);

	if (reqopt->name != T_ALLOPT) {
		topth = (struct T_opthdr *)*resptrp;
		*resptrp += sizeof (struct T_opthdr);
		error = (*setfn)(q, optset_context, reqopt->level, reqopt->name,
		    reqopt->len - sizeof (struct T_opthdr),
		    _TPI_TOPT_DATA(reqopt), &optlen, _TPI_TOPT_DATA(topth),
		    NULL, cr, first_mp);
		if (error) {
			/* failed - reset "*resptrp" */
			*resptrp -= sizeof (struct T_opthdr);
			if (error == EINPROGRESS)
				return (error);
		} else {
			/*
			 * success - "value" already filled in setfn()
			 */
			topth->len = (t_uscalar_t)(optlen +
			    sizeof (struct T_opthdr));
			topth->level = reqopt->level;
			topth->name = reqopt->name;
			topth->status = reqopt->status;
			*resptrp += _TPI_ALIGN_TOPT(optlen);
			*worst_statusp = get_worst_status(topth->status,
			    *worst_statusp);
		}
	} else {		/* T_ALLOPT processing */
		/* only for T_NEGOTIATE case */
		ASSERT(optset_context == SETFN_OPTCOM_NEGOTIATE);
		ASSERT(topmost_tpiprovider == B_TRUE);

		/* scan and set all options to default value */
		for (optd = opt_arr; optd < &opt_arr[opt_arr_cnt]; optd++) {

			/* skip other levels */
			if (reqopt->level != optd->opdes_level)
				continue;

			if (OA_EXECUTE_PERMISSION(optd, cr) ||
			    OA_NO_PERMISSION(optd, cr)) {
				/*
				 * skip this one too. Does not make sense to
				 * set anything to default value for "execute"
				 * options.
				 */
				continue;
			}

			if (OA_READONLY_PERMISSION(optd, cr)) {
				/*
				 * Return with T_READONLY status (and no value
				 * part). Note: spec is not clear but
				 * XTI test suite needs this.
				 */
				topth = (struct T_opthdr *)*resptrp;
				topth->len = sizeof (struct T_opthdr);
				*resptrp += topth->len;
				topth->level = reqopt->level;
				topth->name = optd->opdes_name;
				topth->status = T_READONLY;
				*worst_statusp = get_worst_status(topth->status,
				    *worst_statusp);
				continue;
			}

			/*
			 * It is not read only or execute type
			 * the it must have write permission
			 */
			ASSERT(OA_WRITE_PERMISSION(optd, cr));

			topth = (struct T_opthdr *)*resptrp;
			*resptrp += sizeof (struct T_opthdr);

			topth->len = sizeof (struct T_opthdr);
			topth->level = reqopt->level;
			topth->name = optd->opdes_name;
			if (optd->opdes_props & OP_NODEFAULT) {
				/*
				 * Option of "no default value" so it does not
				 * make sense to try to set it. We just return
				 * header with status of T_SUCCESS
				 * XXX should this be failure ?
				 */
				topth->status = T_SUCCESS;
				continue; /* skip setting */
			}
			if (optd->opdes_props & OP_DEF_FN) {
				if ((optd->opdes_props & OP_VARLEN) ||
				    ((optsize = (*deffn)(q, reqopt->level,
				    optd->opdes_name,
				    (uchar_t *)optd->opdes_defbuf)) < 0)) {
					/* XXX - skip these too */
					topth->status = T_SUCCESS;
					continue; /* skip setting */
				}
			} else {
				optsize = optd->opdes_size;
			}


			/* set option of this level */
			error = (*setfn)(q, SETFN_OPTCOM_NEGOTIATE,
			    reqopt->level, optd->opdes_name, optsize,
			    (uchar_t *)optd->opdes_defbuf, &optlen,
			    _TPI_TOPT_DATA(topth), NULL, cr, NULL);
			if (error) {
				/*
				 * failed, return as T_FAILURE and null value
				 * part. Maybe something downstream will
				 * handle this one and fill in a value. Here
				 * it is just part of T_ALLOPT expansion.
				 */
				topth->status = T_FAILURE;
				*worst_statusp = get_worst_status(topth->status,
				    *worst_statusp);
			} else {
				/* success */
				topth->len += optlen;
				topth->status = T_SUCCESS;
				*resptrp += _TPI_ALIGN_TOPT(optlen);
			}
		} /* end for loop */
		/* END T_ALLOPT */
	}

	if (*resptrp == initptr) {
		/*
		 * setfn failed and does not want to handle this option. Maybe
		 * something downstream will or something upstream
		 * did. Copy the input as is from input option buffer if any to
		 * maintain transparency (maybe something at a level above
		 * did something.
		 */
		if (topmost_tpiprovider)
			reqopt->status = T_FAILURE;
		bcopy(reqopt, *resptrp, reqopt->len);
		*resptrp += _TPI_ALIGN_TOPT(reqopt->len);
		*worst_statusp = get_worst_status(reqopt->status,
		    *worst_statusp);
	}
	return (0);
}

/*
 * The following routines process options buffer passed with
 * T_CONN_REQ, T_CONN_RES and T_UNITDATA_REQ.
 * This routine does the consistency check applied to the
 * sanity of formatting of multiple options packed in the
 * buffer.
 *
 * XTI brain damage alert:
 * XTI interface adopts the notion of an option being an
 * "absolute requirement" from OSI transport service (but applies
 * it to all transports including Internet transports).
 * The main effect of that is action on failure to "negotiate" a
 * requested option to the exact requested value
 *
 *          - if the option is an "absolute requirement", the primitive
 *            is aborted (e.g T_DISCON_REQ or T_UDERR generated)
 *          - if the option is NOT and "absolute requirement" it can
 *            just be ignored.
 *
 * We would not support "negotiating" of options on connection
 * primitives for Internet transports. However just in case we
 * forced to in order to pass strange test suites, the design here
 * tries to support these notions.
 *
 * tpi_optcom_buf(q, mp, opt_lenp, opt_offset, cred, dbobjp, thisdg_attrs,
 *	*is_absreq_failurep)
 *
 * - Verify the option buffer, if formatted badly, return error 1
 *
 * - If it is a "permissions" failure (read-only), return error 2
 *
 * - Else, process the option "in place", the following can happen,
 *	     - if a "privileged" option, mark it as "ignored".
 *	     - if "not supported", mark "ignored"
 *	     - if "supported" attempt negotiation and fill result in
 *	       the outcome
 *			- if "absolute requirement", set "*is_absreq_failurep"
 *			- if NOT an "absolute requirement", then our
 *			  interpretation is to mark is at ignored if
 *			  negotiation fails (Spec allows partial success
 *			  as in OSI protocols but not failure)
 *
 *   Then delete "ignored" options from option buffer and return success.
 *
 */
int
tpi_optcom_buf(queue_t *q, mblk_t *mp, t_scalar_t *opt_lenp,
    t_scalar_t opt_offset, cred_t *cr, optdb_obj_t *dbobjp,
    void *thisdg_attrs, int *is_absreq_failurep)
{
	opt_set_fn setfn = dbobjp->odb_setfn;
	opdes_t *opt_arr = dbobjp->odb_opt_des_arr;
	uint_t opt_arr_cnt = dbobjp->odb_opt_arr_cnt;
	struct T_opthdr *opt, *opt_start, *opt_end;
	mblk_t  *copy_mp_head;
	uchar_t *optr, *init_optr;
	opdes_t *optd;
	uint_t optset_context;
	t_uscalar_t olen;
	int error = 0;

	ASSERT((uchar_t *)opt_lenp > mp->b_rptr &&
	    (uchar_t *)opt_lenp < mp->b_wptr);

	copy_mp_head = NULL;
	*is_absreq_failurep = 0;
	switch (((union T_primitives *)mp->b_rptr)->type) {
	case T_CONN_REQ:
	case T_CONN_RES:
		optset_context = SETFN_CONN_NEGOTIATE;
		break;
	case T_UNITDATA_REQ:
		optset_context = SETFN_UD_NEGOTIATE;
		break;
	default:
		/*
		 * should never get here, all possible TPI primitives
		 * where this can be called from should be accounted
		 * for in the cases above
		 */
		return (EINVAL);
	}

	if ((opt_start = (struct T_opthdr *)
	    mi_offset_param(mp, opt_offset, *opt_lenp)) == NULL) {
		error = ENOPROTOOPT;
		goto error_ret;
	}
	if (!__TPI_TOPT_ISALIGNED(opt_start)) {
		error = ENOPROTOOPT;
		goto error_ret;
	}

	opt_end = (struct T_opthdr *)((uchar_t *)opt_start
	    + *opt_lenp);

	if ((copy_mp_head = copyb(mp)) == (mblk_t *)NULL) {
		error = ENOMEM;
		goto error_ret;
	}

	init_optr = optr = (uchar_t *)&copy_mp_head->b_rptr[opt_offset];

	for (opt = opt_start; opt && (opt < opt_end);
	    opt = _TPI_TOPT_NEXTHDR(opt_start, *opt_lenp, opt)) {
		/*
		 * Validate the option for length and alignment
		 * before accessing anything in it
		 */
		if (!_TPI_TOPT_VALID(opt, opt_start, opt_end)) {
			error = ENOPROTOOPT;
			goto error_ret;
		}

		/* Find the option in the opt_arr. */
		optd = proto_opt_lookup(opt->level, opt->name,
		    opt_arr, opt_arr_cnt);

		if (optd == NULL) {
			/*
			 * Option not found
			 */
			opt->status = T_NOTSUPPORT;
			continue;
		}

		/*
		 * Weird but as in XTI spec.
		 * Sec 6.3.6 "Privileged and ReadOnly Options"
		 * Permission problems (e.g.readonly) fail with bad access
		 * BUT "privileged" option request from those NOT PRIVILEGED
		 * are to be merely "ignored".
		 * XXX Prevents "probing" of privileged options ?
		 */
		if (OA_READONLY_PERMISSION(optd, cr)) {
			error = EACCES;
			goto error_ret;
		}
		if (OA_MATCHED_PRIV(optd, cr)) {
			/*
			 * For privileged options, we DO perform
			 * access checks as is common sense
			 */
			if (!OA_WX_ANYPRIV(optd)) {
				error = EACCES;
				goto error_ret;
			}
		} else {
			/*
			 * For non privileged, we fail instead following
			 * "ignore" semantics dictated by XTI spec for
			 * permissions problems.
			 * Sec 6.3.6 "Privileged and ReadOnly Options"
			 * XXX Should we do "ignore" semantics ?
			 */
			if (!OA_WX_NOPRIV(optd)) { /* nopriv */
				opt->status = T_FAILURE;
				continue;
			}
		}
		/*
		 *
		 * If the negotiation fails, for options that
		 * are "absolute requirement", it is a fatal error.
		 * For options that are NOT "absolute requirements",
		 * and the value fails to negotiate, the XTI spec
		 * only considers the possibility of partial success
		 * (T_PARTSUCCES - not likely for Internet protocols).
		 * The spec is in denial about complete failure
		 * (T_FAILURE) to negotiate for options that are
		 * carried on T_CONN_REQ/T_CONN_RES/T_UNITDATA
		 * We interpret the T_FAILURE to negotiate an option
		 * that is NOT an absolute requirement that it is safe
		 * to ignore it.
		 */

		/* verify length */
		if (!opt_length_ok(optd, opt)) {
			/* bad size */
			if ((optd->opdes_props & OP_NOT_ABSREQ) == 0) {
				/* option is absolute requirement */
				*is_absreq_failurep = 1;
				error = EINVAL;
				goto error_ret;
			}
			opt->status = T_FAILURE;
			continue;
		}

		/*
		 * verified generic attributes. Now call set function.
		 * Note: We assume the following to simplify code.
		 * XXX If this is found not to be valid, this routine
		 * will need to be rewritten. At this point it would
		 * be premature to introduce more complexity than is
		 * needed.
		 * Assumption: For variable length options, we assume
		 * that the value returned will be same or less length
		 * (size does not increase). This makes it OK to pass the
		 * same space for output as it is on input.
		 */

		error = (*setfn)(q, optset_context, opt->level, opt->name,
		    opt->len - (t_uscalar_t)sizeof (struct T_opthdr),
		    _TPI_TOPT_DATA(opt), &olen, _TPI_TOPT_DATA(opt),
		    thisdg_attrs, cr, NULL);

		if (olen > (int)(opt->len - sizeof (struct T_opthdr))) {
			/*
			 * Space on output more than space on input. Should
			 * not happen and we consider it a bug/error.
			 * More of a restriction than an error in our
			 * implementation. Will see if we can live with this
			 * otherwise code will get more hairy with multiple
			 * passes.
			 */
			error = EINVAL;
			goto error_ret;
		}
		if (error != 0) {
			if ((optd->opdes_props & OP_NOT_ABSREQ) == 0) {
				/* option is absolute requirement. */
				*is_absreq_failurep = 1;
				goto error_ret;
			}
			/*
			 * failed - but option "not an absolute
			 * requirement"
			 */
			opt->status = T_FAILURE;
			continue;
		}
		/*
		 * Fill in the only possible successful result
		 * (Note: TPI allows for T_PARTSUCCESS - partial
		 * sucess result code which is relevant in OSI world
		 * and not possible in Internet code)
		 */
		opt->status = T_SUCCESS;

		/*
		 * Add T_SUCCESS result code options to the "output" options.
		 * No T_FAILURES or T_NOTSUPPORT here as they are to be
		 * ignored.
		 * This code assumes output option buffer will
		 * be <= input option buffer.
		 *
		 * Copy option header+value
		 */
		bcopy(opt, optr, opt->len);
		optr +=  _TPI_ALIGN_TOPT(opt->len);
	}
	/*
	 * Overwrite the input mblk option buffer now with the output
	 * and update length, and contents in original mbl
	 * (offset remains unchanged).
	 */
	*opt_lenp = (t_scalar_t)(optr - init_optr);
	if (*opt_lenp > 0) {
		bcopy(init_optr, opt_start, *opt_lenp);
	}

error_ret:
	if (copy_mp_head != NULL)
		freeb(copy_mp_head);
	return (error);
}

static boolean_t
opt_level_valid(t_uscalar_t level, optlevel_t *valid_level_arr,
    uint_t valid_level_arr_cnt)
{
	optlevel_t		*olp;

	for (olp = valid_level_arr;
	    olp < &valid_level_arr[valid_level_arr_cnt];
	    olp++) {
		if (level == (uint_t)(*olp))
			return (B_TRUE);
	}
	return (B_FALSE);
}


/*
 * Compute largest possible size for an option buffer containing
 * all options in one buffer.
 *
 * XXX TBD, investigate use of opt_bloated_maxsize() to avoid
 *     wastefully large buffer allocation.
 */
static size_t
opt_level_allopts_lengths(t_uscalar_t level, opdes_t *opt_arr,
    uint_t opt_arr_cnt)
{
	opdes_t		*optd;
	size_t allopt_len = 0;	/* 0 implies no option at this level */

	/*
	 * Scan opt_arr computing aggregate length
	 * requirement for storing values of all
	 * options.
	 * Note: we do not filter for permissions
	 * etc. This will be >= the real aggregate
	 * length required (upper bound).
	 */

	for (optd = opt_arr; optd < &opt_arr[opt_arr_cnt];
	    optd++) {
		if (level == optd->opdes_level) {
			allopt_len += sizeof (struct T_opthdr) +
			    _TPI_ALIGN_TOPT(optd->opdes_size);
		}
	}
	return (allopt_len);	/* 0 implies level not found */
}

/*
 * Compute largest possible size for an option buffer containing
 * all options in one buffer - a (theoretical?) worst case scenario
 * for certain cases.
 */
t_uscalar_t
optcom_max_optbuf_len(opdes_t *opt_arr, uint_t opt_arr_cnt)
{
	t_uscalar_t max_optbuf_len = sizeof (struct T_info_ack);
	opdes_t		*optd;

	for (optd = opt_arr; optd < &opt_arr[opt_arr_cnt]; optd++) {
		max_optbuf_len += (t_uscalar_t)sizeof (struct T_opthdr) +
		    (t_uscalar_t)_TPI_ALIGN_TOPT(optd->opdes_size);
	}
	return (max_optbuf_len);
}

/*
 * Compute largest possible size for OPT_size for a transport.
 * Heuristic used is to add all but certain extremely large
 * size options; this is done by calling opt_bloated_maxsize().
 * It affects user level allocations in TLI/XTI code using t_alloc()
 * and other TLI/XTI implementation instance strucutures.
 * The large size options excluded are presumed to be
 * never accessed through the (theoretical?) worst case code paths
 * through TLI/XTI as they are currently IPv6 specific options.
 */

t_uscalar_t
optcom_max_optsize(opdes_t *opt_arr, uint_t opt_arr_cnt)
{
	t_uscalar_t max_optbuf_len = sizeof (struct T_info_ack);
	opdes_t		*optd;

	for (optd = opt_arr; optd < &opt_arr[opt_arr_cnt]; optd++) {
		if (!opt_bloated_maxsize(optd)) {
			max_optbuf_len +=
			    (t_uscalar_t)sizeof (struct T_opthdr) +
			    (t_uscalar_t)_TPI_ALIGN_TOPT(optd->opdes_size);
		}
	}
	return (max_optbuf_len);
}

/*
 * The theoretical model used in optcom_max_optsize() and
 * opt_level_allopts_lengths() accounts for the worst case of all
 * possible options for the theoretical cases and results in wasteful
 * memory allocations for certain theoretically correct usage scenarios.
 * In practice, the "features" they support are rarely, if ever,
 * used and even then only by test suites for those features (VSU, VST).
 * However, they result in large allocations due to the increased transport
 * T_INFO_ACK OPT_size field affecting t_alloc() users and TLI/XTI library
 * instance data structures for applications.
 *
 * The following routine opt_bloated_maxsize() supports a hack that avoids
 * paying the tax for the bloated options by excluding them and pretending
 * they don't exist for certain features without affecting features that
 * do use them.
 *
 * XXX Currently implemented only for optcom_max_optsize()
 *     (to reduce risk late in release).
 *     TBD for future, investigate use in optcom_level_allopts_lengths() and
 *     all the instances of T_ALLOPT processing to exclude "bloated options".
 *     Will not affect VSU/VST tests as they do not test with IPPROTO_IPV6
 *     level options which are the only ones that fit the "bloated maxsize"
 *     option profile now.
 */
static boolean_t
opt_bloated_maxsize(opdes_t *optd)
{
	if (optd->opdes_level != IPPROTO_IPV6)
		return (B_FALSE);
	switch (optd->opdes_name) {
	case IPV6_HOPOPTS:
	case IPV6_DSTOPTS:
	case IPV6_RTHDRDSTOPTS:
	case IPV6_RTHDR:
	case IPV6_PATHMTU:
		return (B_TRUE);
	default:
		break;
	}
	return (B_FALSE);
}

static boolean_t
opt_length_ok(opdes_t *optd, struct T_opthdr *opt)
{
	/*
	 * Verify length.
	 * Value specified should match length of fixed length option or be
	 * less than maxlen of variable length option.
	 */
	if (optd->opdes_props & OP_VARLEN) {
		if (opt->len <= optd->opdes_size +
		    (t_uscalar_t)sizeof (struct T_opthdr))
			return (B_TRUE);
	} else {
		/* fixed length option */
		if (opt->len == optd->opdes_size +
		    (t_uscalar_t)sizeof (struct T_opthdr))
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * This routine appends a pssed in hop-by-hop option to the existing
 * option (in this case a cipso label encoded in HOPOPT option). The
 * passed in option is always padded. The 'reservelen' is the
 * length of reserved data (label). New memory will be allocated if
 * the current buffer is not large enough. Return failure if memory
 * can not be allocated.
 */
int
optcom_pkt_set(uchar_t *invalp, uint_t inlen, boolean_t sticky,
    uchar_t **optbufp, uint_t *optlenp, uint_t reservelen)
{
	uchar_t *optbuf;
	uchar_t	*optp;

	if (!sticky) {
		*optbufp = invalp;
		*optlenp = inlen;
		return (0);
	}

	if (inlen == *optlenp - reservelen) {
		/* Unchanged length - no need to reallocate */
		optp = *optbufp + reservelen;
		bcopy(invalp, optp, inlen);
		if (reservelen != 0) {
			/*
			 * Convert the NextHeader and Length of the
			 * passed in hop-by-hop header to pads
			 */
			optp[0] = IP6OPT_PADN;
			optp[1] = 0;
		}
		return (0);
	}
	if (inlen + reservelen > 0) {
		/* Allocate new buffer before free */
		optbuf = kmem_alloc(inlen + reservelen, KM_NOSLEEP);
		if (optbuf == NULL)
			return (ENOMEM);
	} else {
		optbuf = NULL;
	}

	/* Copy out old reserved data (label) */
	if (reservelen > 0)
		bcopy(*optbufp, optbuf, reservelen);

	/* Free old buffer */
	if (*optlenp != 0)
		kmem_free(*optbufp, *optlenp);

	if (inlen > 0)
		bcopy(invalp, optbuf + reservelen, inlen);

	if (reservelen != 0) {
		/*
		 * Convert the NextHeader and Length of the
		 * passed in hop-by-hop header to pads
		 */
		optbuf[reservelen] = IP6OPT_PADN;
		optbuf[reservelen + 1] = 0;
		/*
		 * Set the Length of the hop-by-hop header, number of 8
		 * byte-words following the 1st 8 bytes
		 */
		optbuf[1] = (reservelen + inlen - 1) >> 3;
	}
	*optbufp = optbuf;
	*optlenp = inlen + reservelen;
	return (0);
}

int
process_auxiliary_options(conn_t *connp, void *control, t_uscalar_t controllen,
    void *optbuf, optdb_obj_t *dbobjp, int (*opt_set_fn)(conn_t *, uint_t, int,
    int, uint_t, uchar_t *, uint_t *, uchar_t *, void *, cred_t *))
{
	struct cmsghdr *cmsg;
	opdes_t *optd;
	t_uscalar_t outlen;
	int error = EOPNOTSUPP;
	t_uscalar_t len;
	uint_t opt_arr_cnt = dbobjp->odb_opt_arr_cnt;
	opdes_t *opt_arr = dbobjp->odb_opt_des_arr;

	for (cmsg = (struct cmsghdr *)control;
	    CMSG_VALID(cmsg, control, (uintptr_t)control + controllen);
	    cmsg = CMSG_NEXT(cmsg)) {

		len = (t_uscalar_t)CMSG_CONTENTLEN(cmsg);
		/* Find the option in the opt_arr. */
		optd = proto_opt_lookup(cmsg->cmsg_level, cmsg->cmsg_type,
		    opt_arr, opt_arr_cnt);
		if (optd == NULL) {
			return (EINVAL);
		}
		if (OA_READONLY_PERMISSION(optd, connp->conn_cred)) {
			return (EACCES);
		}
		if (OA_MATCHED_PRIV(optd, connp->conn_cred)) {
			/*
			 * For privileged options, we DO perform
			 * access checks as is common sense
			 */
			if (!OA_WX_ANYPRIV(optd)) {
				return (EACCES);
			}
		} else {
			/*
			 * For non privileged, we fail instead following
			 * "ignore" semantics dictated by XTI spec for
			 * permissions problems.
			 */
			if (!OA_WX_NOPRIV(optd)) { /* nopriv */
				return (EACCES);
			}
		}
		error = opt_set_fn(connp, SETFN_UD_NEGOTIATE, optd->opdes_level,
		    optd->opdes_name, len, (uchar_t *)CMSG_CONTENT(cmsg),
		    &outlen, (uchar_t *)CMSG_CONTENT(cmsg), (void *)optbuf,
		    connp->conn_cred);
		if (error > 0) {
			return (error);
		} else if (outlen > len) {
			return (EINVAL);
		} else {
			/*
			 * error can be -ve if the protocol wants to
			 * pass the option to IP. We donot pass auxiliary
			 * options to IP.
			 */
			error = 0;
		}
	}
	return (error);
}
