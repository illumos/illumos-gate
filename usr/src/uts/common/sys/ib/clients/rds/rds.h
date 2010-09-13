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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RDS_H
#define	_RDS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>

#include <sys/project.h>
#include <sys/tihdr.h>
#include <sys/strsubr.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/strsun.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/optcom.h>

#include <sys/sunldi.h>
#include <sys/dlpi.h>

#include <inet/ip_ire.h>

#undef  dprint
#ifdef DEBUG
extern int rdsdebug;
#define	dprint(level, args)	{ if (rdsdebug > (level)) printf args; }
#else
#define	dprint(level, args) {}
#endif

typedef struct rds_s {
	kmutex_t	rds_lock;	/* protects rds_refcnt */
	int		rds_refcnt;
	kcondvar_t	rds_refcv;
	uint32_t	rds_state;	/* TPI state */
	uint32_t	rds_flags;
	sa_family_t	rds_family;	/* Family from socket() call */
	cred_t		*rds_cred;
	in_port_t	rds_port;	/* Port bound to this stream */
	ipaddr_t	rds_src;	/* Source address of this stream */
	void		*rds_ulpd;	/* queue to send message on */
	struct rds_s	*rds_bind_hash;	/* Bind hash chain */
	struct rds_s	**rds_ptpbhn;	/* Ptr to previous bind hash next. */
	ulong_t		rds_port_quota; /* Port quota */
	zoneid_t	rds_zoneid;
} rds_t;

#define	RDS_CLOSING 	0x1

#define	RDS_INCR_REF_CNT(rds)  { 	\
	mutex_enter(&rds->rds_lock);	\
	rds->rds_refcnt++;	\
	ASSERT(rds->rds_refcnt != 0); \
	mutex_exit(&rds->rds_lock); \
}

#define	RDS_DEC_REF_CNT(rds)  { 	\
	mutex_enter(&rds->rds_lock);	\
	ASSERT(rds->rds_refcnt > 0); \
	rds->rds_refcnt--;	\
	if (rds->rds_refcnt == 1)	\
		cv_broadcast(&(rds)->rds_refcv); \
	if (rds->rds_refcnt == 0) {	\
		rds_free(rds);	\
	} else {	\
		mutex_exit(&rds->rds_lock); \
	}	\
}


#define	RDS_MATCH(rdsp, lport, laddr)               \
	(((rdsp)->rds_port == lport) &&		\
	((rdsp)->rds_src == laddr))

/* RDS bind fanout hash structure. */
typedef struct rds_bind_fanout_s {
	rds_t *rds_bf_rds;
	kmutex_t rds_bf_lock;
#if defined(_LP64) || defined(_I32LPx)
	char    bf_pad[48];
#else
	char    bf_pad[56];
#endif
}rds_bf_t;

extern ldi_ident_t rds_li;

#define	RDS_BIND_FANOUT_SIZE    512
#define	RDS_BIND_HASH(lport) \
	((ntohs((uint16_t)lport)) & (rds_bind_fanout_size - 1))

#define	AF_INET_OFFLOAD 30

extern	uint_t rds_bind_fanout_size;
extern	rds_bf_t *rds_bind_fanout;

extern optdb_obj_t rds_opt_obj;

extern void rds_hash_init();

extern	void rds_free(rds_t *rds);
extern rds_t *rds_create(void *rds_ulpd, cred_t *credp);

extern void rds_bind_hash_remove(rds_t *rds, boolean_t);
extern void rds_bind_hash_insert(rds_bf_t *, rds_t *);
extern rds_t *rds_fanout(ipaddr_t, ipaddr_t, in_port_t, in_port_t, zoneid_t);
extern void rds_add_new_msg(mblk_t *mp, ipaddr_t, ipaddr_t, in_port_t,
    in_port_t);
extern boolean_t rds_verify_bind_address(ipaddr_t addr);
extern boolean_t rds_islocal(ipaddr_t addr);
extern boolean_t rds_if_lookup_by_name(char *if_name);
extern boolean_t rds_if_lookup_by_addr(ipaddr_t addr);


extern void rds_init();
extern void rds_fini();


#ifdef	__cplusplus
}
#endif

#endif	/* _RDS_H */
