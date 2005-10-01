/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "pfil.h"
#include <sys/ptms.h>

#ifdef	IRE_ILL_CN
typedef	union	{
	struct sockaddr_in qfa_in;
	struct sockaddr_in6 qfa_in6;
} qfa_t;
# define	qfa_family	qfa_in.sin_family
# define	qfa_v4addr	qfa_in.sin_addr
# define	qfa_v6addr	qfa_in6.sin6_addr
#else
# define	QF_IPIF(x)	((ill_t *)(x)->qf_ill)->ill_ipif
# define	qf_netmask	QF_IPIF->ipif_net_mask
#  define	qf_dstaddr	QF_IPIF->ipif_pp_dst_addr
# if SOLARIS2 <= 7
#  define	qf_localaddr	QF_IPIF->ipif_local_addr
#  define	qf_broadaddr	QF_IPIF->ipif_broadcast_addr
# else
#  define	qf_localaddr	QF_IPIF->ipif_lcl_addr
#  define	qf_broadaddr	QF_IPIF->ipif_brd_addr
# endif
# ifdef	USE_INET6
#  define	qf_v6netmask	QF_IPIF->ipif_v6net_mask
#  define	qf_v6broadaddr	QF_IPIF->ipif_v6brd_addr
#  define	qf_v6dstaddr	QF_IPIF->ipif_v6pp_dst_addr
# endif
#endif

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
	/* for alignment reasons, the lock is first. */
	kmutex_t	qf_lock;
	struct qifplock {
		kmutex_t	pt_lock;
#ifdef sun
		kcondvar_t	pt_cv;
#endif
		int		pt_refcnt;
		int		pt_access;
	} qf_ptl;
	struct	qif	*qf_next;
	struct	qif	*qf_ipmp;	/* Pointer to group qif */
	void		*qf_ill;
	queue_t		*qf_q;
	queue_t		*qf_oq;
	/* statistical data */
	u_long		qf_nr;
	u_long		qf_nw;
	u_long		qf_bad;
	u_long		qf_copy;
	u_long		qf_copyfail;
	u_long		qf_drop;
	u_long		qf_notip;
	u_long		qf_nodata;
	u_long		qf_notdata;
	/* other data for the NIC on this queue */
	size_t		qf_qifsz;
	size_t		qf_hl;		/* header length */
	u_int		qf_num;
	u_int		qf_ppa;		/* Physical Point of Attachment */
	int		qf_sap;		/* Service Access Point */
	int		qf_bound;
	int		qf_flags;
	int		qf_waitack;
	int		qf_max_frag;	/* MTU for interface */
	char		qf_name[LIFNAMSIZ];
	char		*qf_members;

	/* ON10 specific */
	mblk_t		*qf_addrset;
	size_t		qf_off;
	mblk_t		*qf_m;
	void		*qf_data;
} qif_t;


typedef	struct	qpktinfo	{
	/* data that changes per-packet */
	qif_t		*qpi_real;	/* the real one on the STREAM */
	void		*qpi_ill;	/* COPIED */
	mblk_t		*qpi_m;
	queue_t		*qpi_q;
	char		*qpi_name;	/* points to qf_real->qf_name */
	void		*qpi_data;	/* where layer 3 header starts */
	size_t		qpi_off;
	size_t		qpi_hl;		/* COPIED */
	u_int		qpi_ppa;	/* COPIED */
	u_int		qpi_num;	/* COPIED */
	int		qpi_flags;	/* COPIED */
	int		qpi_max_frag;	/* COPIED */
} qpktinfo_t;


#ifdef sun
# if SOLARIS2 <= 7
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
# ifdef	USE_INET6
#  define	QF_V6_BROADCAST(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_v6brd_addr
#  define	QF_V6_NETMASK(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_v6net_mask
#  define	QF_V6_PEERADDR(x)	\
			((ill_t *)(x)->qf_ill)->ill_ipif->ipif_v6pp_dst_addr
# endif
#endif

#ifdef __hpux
# define	QF_V4_ADDR(x)	((ifinfot_t *)(x)->qf_ill)->ifi_addr[0]
#endif


#define	QF_GROUP	0x0001
#define	QF_IPMP		0x0002

extern void *q_to_ill(queue_t *);
extern struct qif *qif_new(queue_t *, int);
extern int qif_attach(queue_t *);
extern void qif_delete(struct qif *, queue_t *);
extern int qif_startup(void);
extern void qif_stop(void);
extern void *qif_iflookup(char *, int);

struct irinfo_s;
extern void *ir_to_ill(struct irinfo_s *ir);

extern struct qif *qif_walk(struct qif **);
extern struct qif *qif_head;
extern int qif_verbose;
extern void qif_update(struct qif *, mblk_t *);
extern void qif_nd_init(void);
extern void qif_ipmp_delete(char *);
extern void qif_ipmp_update(char *);
extern void qif_ipmp_syncmaster(struct qif *, const int);
extern void qif_ipmp_syncslave(struct qif *, const int);

#ifndef IRE_ILL_CN
extern void qif_ire_walker(ire_t *, void *);
#endif

extern kmutex_t s_ill_g_head_lock;
extern s_ill_t *s_ill_g_head;
