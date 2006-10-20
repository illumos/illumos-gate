/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _NET_PFIL_H_
#define _NET_PFIL_H_

#define	PFIL_RELEASE	"2.1.6"
#define	PFIL_VERSION	2010600
#define	PFIL_INTERFACE	2000000

#ifndef __P
# ifdef __STDC__
#  define	__P(x)	x
# else
#  define	__P(x)	()
# endif
#endif

#ifdef sun
# include <inet/ip.h>
# if SOLARIS2 < 9
#  include <netinet/in_systm.h>
#  undef IPOPT_EOL
#  undef IPOPT_NOP
#  undef IPOPT_RR
#  undef IPOPT_LSRR
#  undef IPOPT_SSRR
#  include <netinet/ip.h>
# endif
#endif
#ifdef __hpux
# include <netinet/in_systm.h>
# include <netinet/in.h>
# include <netinet/ip.h>
#endif


typedef	struct packet_filter_hook {
	struct	packet_filter_hook *pfil_next;
	struct	packet_filter_hook **pfil_pnext;
	int	(*pfil_func) __P((struct ip *, int, void *, int,
				  void *, mblk_t **));
	int	pfil_flags;
} packet_filter_hook_t;


typedef	struct	pfil_list	{
	struct	packet_filter_hook	*pfl_top;
	struct	packet_filter_hook	**pfl_tail;
} pfil_list_t;


/*
** HP Port
** spinlocks should be the first member for
** alignment reason. Spinlocks need to be 16 byte 
** aligned. The struct itself is aligned during 
** allocation so that the spinlock starts at a
** 16 byte boundary
*/
typedef struct pfil_head {
	krwlock_t	ph_lock;
	pfil_list_t	ph_in;
	pfil_list_t	ph_out;
	int	ph_init;
} pfil_head_t;


#define	PFIL_IN		0x00000001
#define	PFIL_OUT	0x00000002
#define	PFIL_INOUT	(PFIL_IN|PFIL_OUT)
#define	PFIL_WAITOK	0x00000004
#define	PFIL_GROUP	0x00000008
#define	PFIL_ALL	(PFIL_IN|PFIL_OUT)

/* HPUX Port Major no. for pfil spinlocks */
#define	PFIL_SMAJ	0

void	pfil_init __P((struct pfil_head *));
struct	packet_filter_hook *pfil_hook_get __P((int, struct pfil_head *));
int	pfil_add_hook __P((int (*func) __P((struct ip *, int, void *, int,
					    void *, mblk_t **)), int,
			   struct pfil_head *));
int	pfil_remove_hook __P((int (*func) __P((struct ip *, int, void *, int,
					    void *, mblk_t **)), int,
			   struct pfil_head *));
int pfil_sendbuf(mblk_t *);
mblk_t *pfil_make_dl_packet __P((mblk_t *, struct ip *, void *,
				 char *, queue_t **));
void pfil_send_dl_packet __P((queue_t *, mblk_t *));


extern	int	pfilinterface;
extern	int	pfil_delayed_copy;
extern	int	pfildebug;
extern	struct	pfil_head	pfh_inet4;	/* IPv4 packet processing */
extern	struct	pfil_head	pfh_inet6;	/* IPv6 packet processing */
extern	struct	pfil_head	pfh_sync;	/* Notification of interface */
						/* naming/address changes.   */
extern	krwlock_t	qif_rwlock;
extern	krwlock_t	pfil_rw;

/*
 * NOTE: On Solaris, even though pfilwput(), etc, are prototyped as returning
 * an int, the return value is never checked and much code ignores it, anyway,
 * so for performance reasonsm, various functions return void instead of int.
 */
extern void pfilwput __P((queue_t *q, mblk_t *mp));
extern void pfil_ioctl __P((queue_t *q, mblk_t *mp));
extern int pfil_ioctl_nd __P((queue_t *q, mblk_t *mp));
extern int pfil_nd_init __P((void));
extern void pfil_nd_fini __P((void));
extern int pfil_precheck __P((queue_t *, mblk_t **, int, struct qif *));
extern void pfil_startup __P((void));
extern void pfilmodrput __P((queue_t *q, mblk_t *mp));
extern void pfilmodwput __P((queue_t *q, mblk_t *mp));
extern void pfilmodwsrv __P((queue_t *q));
#ifdef USE_SERVICE_ROUTINE
extern int pfilmodrsrv __P((queue_t *q));
#else
#define pfilmodrsrv  NULL
#endif

#ifdef IRE_ILL_CN
void pfil_addif(queue_t *, const char *, int);
#endif

extern void mb_copydata __P((mblk_t *, size_t , size_t, char *));
extern void mb_copyback __P((mblk_t *, size_t , size_t, char *));
extern int pfildebug;

void pfil_update_ifaddr(mblk_t * mp);
#endif /* _NET_PFIL_H_ */
