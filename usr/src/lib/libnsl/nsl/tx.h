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
 * Copyright 2014 Gary Mills
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TX_H
#define	_TX_H

#include <sys/uio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains declarations local to the TLI/XTI implmentation
 */

/*
 * Look buffer list
 * Could be multiple buffers for MT case
 */
struct _ti_lookbufs {
	struct _ti_lookbufs *tl_next; /* next in list   */
	int	tl_lookclen;	/* "look" ctl part length */
	char	*tl_lookcbuf;	/* pointer to "look" ctl	*/
	int	tl_lookdlen;	/* "look" data length	*/
	char	*tl_lookdbuf;	/* pointer to "look" data */
};

/* TI interface user level structure - one per open file */

struct _ti_user {
	struct _ti_user	*ti_next; 	/* next one		*/
	struct _ti_user	*ti_prev; 	/* previous one	*/
	int	ti_fd;			/* file descriptor	*/
	struct  _ti_lookbufs ti_lookbufs; /* head of list of look buffers */
	int	ti_lookcnt;		/* buffered look flag	*/
	ushort_t ti_flags;		/* flags		*/
	int	ti_rcvsize;	/* connect or disconnect data buf size */
	char	*ti_rcvbuf;		/* connect or disconnect data buffer */
	int	ti_ctlsize;		/* ctl buffer size	*/
	char	*ti_ctlbuf;		/* ctl buffer		*/
	int	ti_state;		/* user level state	*/
	int	ti_ocnt;		/* # outstanding connect indications */
	t_scalar_t	ti_maxpsz;	/* TIDU size		*/
	t_scalar_t	ti_tsdusize;	/* TSDU size		*/
	t_scalar_t	ti_etsdusize;	/* ETSDU size		*/
	t_scalar_t	ti_cdatasize;	/* CDATA_size		*/
	t_scalar_t	ti_ddatasize;	/* DDATA_size		*/
	t_scalar_t	ti_servtype;	/* service type		*/
	t_scalar_t	ti_prov_flag;	/* TPI PROVIDER_flag	*/
	uint_t	ti_qlen;	/* listener backlog limit */
	t_uscalar_t	acceptor_id;	/* Saved acceptor_id value */
	dev_t	ti_rdev;		/* for fd validation */
	ino_t	ti_ino;			/* for fd validation */
	mutex_t ti_lock;	/* lock to protect this data structure */
};

/*
 * Local flags used with ti_flags field in instance structure of
 * type 'struct _ti_user' declared above. Historical note:
 * This namespace constants were previously declared in a
 * a very messed up namespace in timod.h
 */
#define	USED		0x0001	/* data structure in use		*/
#define	MORE		0x0008	/* more data				*/
#define	EXPEDITED	0x0010	/* processing expedited TSDU		*/
#define	V_ACCEPTOR_ID	0x0020	/* acceptor_id field is has valid value	*/
#define	TX_TQFULL_NOTIFIED 0x0040  /* TQFULL error has been returned once  */


/*
 * Valid flags that can be passed by user in t_sndv() or t_snd()
 */

#define	TX_ALL_VALID_FLAGS (T_MORE|T_EXPEDITED|T_PUSH)

#define	_T_MAX(x, y) 		((x) > (y) ? (x) : (y))

/*
 * Following are used to indicate which API entry point is calling common
 * routines
 */
#define		TX_TLI_API	1	/* The API semantics is TLI */
#define		TX_XTI_XNS4_API	2	/* The API semantics is XTI Unix95 */
#define		TX_XTI_XNS5_API	3	/* The API semantics is XTI Unix98 */
#define		TX_XTI_API	TX_XTI_XNS4_API
					/* The base XTI semantics is Unix95 */

/* _T_IS_XTI(x) - Is 'x' an XTI inspired api_semantics */
#define		_T_IS_XTI(x)	((x) != TX_TLI_API)
#define		_T_IS_TLI(x)	((x) == TX_TLI_API)

/* _T_API_VER_LT(x, y) - Is API version 'x' older than API version 'y' */
#define		_T_API_VER_LT(x, y)	((x) < (y))

/*
 * Note: T_BADSTATE also defined in <sys/tiuser.h>
 */
#define	T_BADSTATE 8

#ifdef DEBUG
#include <syslog.h>
#define	_T_TX_SYSLOG2(tiptr, X, Y) if ((tiptr)->ti_state == T_BADSTATE)\
	syslog(X, Y)
#else
#define	_T_TX_SYSLOG2(tiptr, X, Y)
#endif	/* DEBUG */

/*
 * Macro to change state and log invalid state error
 */

#define	_T_TX_NEXTSTATE(event, tiptr, errstr)	\
	{	tiptr->ti_state = tiusr_statetbl[event][(tiptr)->ti_state]; \
		_T_TX_SYSLOG2((tiptr), LOG_ERR, errstr); \
	}

/*
 * External declarations
 */
extern mutex_t _ti_userlock;

/*
 * Useful shared local constants
 */

/*
 * TX_XTI_LEVEL_MAX_OPTBUF:
 * 	Max option buffer requirement reserved for any XTI level options
 *	passed in an option buffer. This is intended as an upper bound.
 *	Regardless of what the providers states in OPT_size of T_info_ack,
 *	XTI level options can also be added to the option buffer and XTI
 *	test suite in particular stuffs XTI level options whether we support
 *	them or not.
 *
 * Here is the heuristic used to arrive at a value:
 *	2* [		// factor of 2 for "repeat options" type testing
 *		(sizeof(struct t_opthdr)+10*sizeof(t_scalar_t))	// XTI_DEBUG
 *	       +(sizeof(struct t_opthdr)+ 2*sizeof(t_scalar_t))	// XTI_LINGER
 *	       +(sizeof(struct t_opthdr)+ sizeof(t_scalar_t))	// XTI_RCVBUF
 *	       +(sizeof(struct t_opthdr)+ sizeof(t_scalar_t))	// XTI_RCVLOWAT
 *	       +(sizeof(struct t_opthdr)+ sizeof(t_scalar_t))	// XTI_SNDBUF
 *	       +(sizeof(struct t_opthdr)+ sizeof(t_scalar_t))	// XTI_SNDLOWAT
 *	   ]
 * => 2* [ 56+24+20+20+20+20 ]
 * =>
 */
#define	TX_XTI_LEVEL_MAX_OPTBUF	320


/*
 * Historic information note:
 * The libnsl/nsl code implements TLI and XTI interfaces using common
 * code. Most data structures are similar in the exposed interfaces for
 * the two interfaces (<tiuser.h> and <xti.h>).
 * The common implementation C files include only <xti.h> which is the
 * superset in terms of the exposed interfaces. However the file <tiuser.h>
 * exposes (via <sys/tiuser.h>), in the past contained certain declarations
 * that are strictly internal to the implementation but were exposed through
 * their presence in the public header (<tiuser.h>).
 * Since the implmentation still needs these declarations, they follow
 * in this file and are removed from exposure through the TLI public header
 * (<tiuser.h>) which exposed them in the past.
 */

/*
 * The following are TLI/XTI user level events which cause
 * state changes.
 * NOTE: Historical namespace pollution warning.
 * Some of the event names share the namespace with structure tags
 * so there are defined inside comments here and exposed through
 * TLI and XTI headers (<tiuser.h> and <xti.h>
 */

#define	T_OPEN 		0
/* #define	T_BIND		1 */
/* #define	T_OPTMGMT	2 */
#define	T_UNBIND	3
#define	T_CLOSE		4
#define	T_SNDUDATA	5
#define	T_RCVUDATA	6
#define	T_RCVUDERR	7
#define	T_CONNECT1	8
#define	T_CONNECT2	9
#define	T_RCVCONNECT	10
#define	T_LISTN		11
#define	T_ACCEPT1	12
#define	T_ACCEPT2	13
#define	T_ACCEPT3	14
#define	T_SND		15
#define	T_RCV		16
#define	T_SNDDIS1	17
#define	T_SNDDIS2	18
#define	T_RCVDIS1	19
#define	T_RCVDIS2	20
#define	T_RCVDIS3	21
#define	T_SNDREL	22
#define	T_RCVREL	23
#define	T_PASSCON	24

#define	T_NOEVENTS	25

#define	T_NOSTATES 	9	/* number of legal states */

extern char tiusr_statetbl[T_NOEVENTS][T_NOSTATES];

/*
 * Band definitions for data flow.
 */
#define	TI_NORMAL	0
#define	TI_EXPEDITED	1

/*
 * Bogus states from tiuser.h
 */
#define	T_FAKE		8	/* fake state used when state	*/
				/* cannot be determined		*/

/*
 * Flags for t_getname() from tiuser.h
 * Note: This routine's counterpart in XTI is substatnially modified
 * (i.e. t_getprotaddr() and does not use these flags)
 */
#define	LOCALNAME	0
#define	REMOTENAME	1

/*
 * GENERAL UTILITY MACROS
 */
#define	A_CNT(arr)	(sizeof (arr)/sizeof (arr[0]))
#define	A_END(arr)	(&arr[A_CNT(arr)])
#define	A_LAST(arr)	(&arr[A_CNT(arr)-1])

/*
 * Following macro compares a signed size obtained from TPI primitive
 * to unsigned size of buffer where it needs to go into passed using
 * the "struct netbuf" type.
 * Since many programs are buggy and forget to initialize "netbuf" or
 * (while unlikely!) allocated buffer can legally even be larger than
 * max signed integer, we use the following macro to do unsigned comparison
 * after verifying that signed quantity is positive.
 */
#define	TLEN_GT_NLEN(tpilen, netbuflen) \
	(((tpilen) > 0) && ((unsigned int)(tpilen) > (netbuflen)))


/*
 *	N.B.:  this interface is deprecated.  Use t_strerror() instead.
 */
extern char *t_errlist[];
extern int t_nerr;

/*
 * UTILITY ROUTINES FUNCTION PROTOTYPES
 */

extern void _t_adjust_iov(int, struct iovec *, int *);
extern struct _ti_user *_t_checkfd(int, int, int);
extern int _t_delete_tilink(int);
extern int _t_rcv_conn_con(struct _ti_user *, struct t_call *, struct strbuf *,
							int);
extern int _t_snd_conn_req(struct _ti_user *, const struct t_call *,
							struct strbuf *);
extern int _t_aligned_copy(struct strbuf *, int, int, char *, t_scalar_t *);
extern struct _ti_user *_t_create(int, struct t_info *, int, int *);
extern int _t_do_ioctl(int, char *, int, int, int *);
extern int _t_is_event(int, struct _ti_user *);
extern int _t_is_ok(int, struct _ti_user *, t_scalar_t);
extern int _t_look_locked(int, struct _ti_user *, int, int);
extern int _t_register_lookevent(struct _ti_user *, caddr_t, int, caddr_t, int);
extern void _t_free_looklist_head(struct _ti_user *);
extern void _t_flush_lookevents(struct _ti_user *);
extern int _t_acquire_ctlbuf(struct _ti_user *, struct strbuf *, int *);
extern int _t_acquire_databuf(struct _ti_user *, struct strbuf *, int *);

/*
 * Core function TLI/XTI routines function prototypes
 */
extern int _tx_accept(int, int, const struct t_call *, int);
extern char *_tx_alloc(int, int, int, int);
extern int _tx_bind(int, const struct t_bind *, struct t_bind *, int);
extern int _tx_close(int, int);
extern int _tx_connect(int, const struct t_call *, struct t_call *, int);
extern int _tx_error(const char *, int);
extern int _tx_free(char *, int, int);
extern int _tx_getinfo(int, struct t_info *, int);
extern int _tx_getname(int, struct netbuf *, int, int);
extern int _tx_getstate(int, int);
extern int _tx_getprotaddr(int, struct t_bind *, struct t_bind *, int);
extern int _tx_listen(int, struct t_call *, int);
extern int _tx_look(int, int);
extern int _tx_open(const char *, int, struct t_info *, int);
extern int _tx_optmgmt(int, const struct t_optmgmt *, struct t_optmgmt *, int);
extern int _tx_rcv(int, char *, unsigned, int *, int);
extern int _tx_rcvconnect(int, struct t_call *, int);
extern int _tx_rcvdis(int, struct t_discon *, int);
extern int _tx_rcvrel(int, int);
extern int _tx_rcvudata(int, struct t_unitdata *, int *, int);
extern int _tx_rcvuderr(int, struct t_uderr *, int);
extern int _tx_snd(int, char *, unsigned, int, int);
extern int _tx_snddis(int, const struct t_call *, int);
extern int _tx_sndrel(int, int);
extern int _tx_sndudata(int, const struct t_unitdata *, int);
extern char *_tx_strerror(int, int);
extern int _tx_sync(int, int);
extern int _tx_unbind(int, int);
extern int _tx_unbind_locked(int, struct _ti_user *, struct strbuf *);
extern int _t_expinline_queued(int, int *);
extern int _t_do_postconn_sync(int, struct _ti_user *);

/*
 * The following helper functions are used by scatter/gather functions,
 * which are defined only for XTI and not available in TLI. Moreover
 * the definition of struct t_iovec which is used below is not visible to
 * TLI. Hence tli_wrappers.c should not see the prototypes below.
 */
#ifndef TLI_WRAPPERS
unsigned int _t_bytecount_upto_intmax(const struct t_iovec *, unsigned int);
void _t_scatter(struct strbuf *, struct t_iovec *, int);
void _t_gather(char *, const struct t_iovec *, unsigned int);
void _t_copy_tiov_to_iov(const struct t_iovec *, int, struct iovec *, int *);

/*
 * The following scatter/gather and other misc. functions are defined only
 * for XTI and not available in TLI. Moreover the definition of struct t_iovec
 * which is used below is not visible to TLI. Hence tli_wrappers.c should not
 * see the prototypes below.
 */
extern int _tx_rcvv(int, struct t_iovec *, unsigned int,  int *, int);
extern int _tx_rcvreldata(int, struct t_discon *, int);
extern int _tx_rcvvudata(int, struct t_unitdata *, struct t_iovec *,
    unsigned int, int *, int);
extern int _tx_sndv(int, const struct t_iovec *, unsigned int, int, int);
extern int _tx_sndreldata(int, struct t_discon *, int);
extern int _tx_sndvudata(int, const struct t_unitdata *, struct t_iovec *,
    unsigned int, int);
extern int _tx_sysconf(int, int);
#endif /* TLI_WRAPPERS */

#ifdef	__cplusplus
}
#endif

#endif	/* _TX_H */
