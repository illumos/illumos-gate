/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "pfil.h"
#include <sys/ptms.h>

typedef	struct	s_ill_s	{
	struct	s_ill_s	*ill_next;	/* Chained in at s_ill_g_head. */
	kmutex_t	s_ill_lock;
	char	ill_name[LIFNAMSIZ];	/* Our name. */
	t_uscalar_t	ill_sap;	/* IP_DL_SAP or IP6_DL_SAP */
	queue_t	*ill_rq;		/* lower stream read queue */
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} localaddr;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} netmask;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} broadaddr;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} dstaddr;
	uint_t	mtu;
} s_ill_t;


typedef	struct	qif	{
	kmutex_t	qf_lock;
	struct	qif	*qf_next;
	void		*qf_ill;
	mblk_t		*qf_m;
	queue_t		*qf_q;
	queue_t		*qf_oq;
	mblk_t		*qf_addrset;
	void		*qf_data;
	struct qifplock {
		kmutex_t	pt_lock;
		kcondvar_t	pt_cv;
		int		pt_refcnt;
	} qf_ptl;
	u_long		qf_nr;
	u_long		qf_nw;
	u_long		qf_bad;
	u_long		qf_copy;
	u_long		qf_copyfail;
	u_long		qf_drop;
	u_long		qf_notip;
	u_long		qf_nodata;
	u_long		qf_notdata;
	size_t		qf_off;
	size_t		qf_hl;	/* header length */
	u_int		qf_num;
	u_int		qf_ppa;
	int		qf_sap;
	int		qf_bound;
	int		qf_flags;
	int		qf_waitack;
	int		qf_max_frag;
	char		qf_name[LIFNAMSIZ];
} qif_t;


#ifdef sun
# if SOLARIS2 < 7
#  define	QF_V4_ADDR(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_local_addr
#  define	QF_V4_BROADCAST(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_broadcast_addr
# else
#  define	QF_V4_ADDR(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_lcl_addr
#  define	QF_V4_BROADCAST(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_brd_addr
# endif
# define	QF_V4_NETMASK(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_net_mask
# define	QF_V4_PEERADDR(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_pp_dst_addr
#endif

#ifdef __hpux
# define	QF_V4_ADDR(x)	((ifinfot_t *)(x)->qf_ill)->ifi_addr[0]
#endif


#define	QF_GROUP	0x0001

extern void *q_to_ill(queue_t *);
extern qif_t *qif_new(queue_t *, int);
extern int qif_attach(queue_t *);
extern void qif_delete(qif_t *, queue_t *);
extern int qif_startup(void);
extern void qif_stop(void);
extern void *qif_iflookup(char *, int);

struct irinfo_s;
extern void *ir_to_ill(struct irinfo_s *ir);
extern qif_t *qif_walk(qif_t **);
extern qif_t *qif_head;
extern int qif_verbose;
extern void qif_update(qif_t *, mblk_t *);
extern void qif_nd_init(void);
#ifndef IRE_ILL_CN
extern void qif_ire_walker(ire_t *, void *);
#endif

extern kmutex_t s_ill_g_head_lock;
extern s_ill_t *s_ill_g_head;
