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

#ifndef	_NCALL_H
#define	_NCALL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DS_DDICT
#include <sys/time.h>
#endif

#ifdef _KERNEL

/*
 * ncall_t is opaque RPC pointer
 */
typedef	struct ncall_s {
	int	opaque;
} ncall_t;

#define	NCALL_DATA_SZ	8192	/* ncall_put/get_data max size */
#define	NCALL_BROADCAST_ID	(-2) /* magic broadcast nodeid */
/*
 * ncall send flags
 */
#define	NCALL_PEND	1	/* disconnect immediately */
#define	NCALL_UNUSED	2	/* unused */
#define	NCALL_ASYNC	4	/* asynchronous	send (ncall_free implied) */
#define	NCALL_RDATA	8	/* allocate a buffer to receive data in */

extern void ncall_register_svc(int, void (*)(ncall_t *, int *));
extern void ncall_unregister_svc(int);

extern int  ncall_nodeid(char *);
extern char *ncall_nodename(int);
extern int  ncall_mirror(int);
extern int  ncall_self(void);

extern int  ncall_alloc(int, int, int, ncall_t **);
extern int  ncall_timedsend(ncall_t *, int, int, struct timeval *, ...);
extern int  ncall_timedsendnotify(ncall_t *, int, int, struct timeval *,
    void (*)(ncall_t *, void *), void *, ...);
extern int  ncall_broadcast(ncall_t *, int, int, struct timeval *, ...);
extern int  ncall_send(ncall_t *, int, int, ...);
extern int  ncall_read_reply(ncall_t *, int, ...);
extern void ncall_reset(ncall_t *);
extern void ncall_free(ncall_t *);

extern int  ncall_put_data(ncall_t *, void *, int);
extern int  ncall_get_data(ncall_t *, void *, int);

extern int  ncall_sender(ncall_t *);
extern void ncall_reply(ncall_t *, ...);
extern void ncall_pend(ncall_t	*);
extern void ncall_done(ncall_t	*);
extern int ncall_ping(char *, int *);
extern int ncall_maxnodes(void);
extern int ncall_nextnode(void **);
extern int ncall_errcode(ncall_t *, int *);

#endif /* _KERNEL */

#define	NCALLNMLN	257

/*
 * Basic node info
 */
typedef struct ncall_node_s {
	char nc_nodename[NCALLNMLN];	/* Nodename */
	int nc_nodeid;			/* Nodeid */
} ncall_node_t;


#define	_NCIOC_(x)	(('N'<<16)|('C'<<8)|(x))

#define	NC_IOC_GETNODE	_NCIOC_(0)	/* return this node */
#define	NC_IOC_START	_NCIOC_(1)	/* ncall core and stubs start */
#define	NC_IOC_STOP	_NCIOC_(2)	/* ncall stop */
#define	NC_IOC_GETNETNODES	_NCIOC_(3)	/* ncalladm -i */
#define	NC_IOC_PING	_NCIOC_(4)	/* ncalladm -p */
/*
 * _NCIOC_(5) to _NCIOC_(20) are reserved for the implementation module
 */

#define	NCALL_NSC	100	/* 100 - 109 */
#define	NCALL_UNUSED1	110	/* 110 - 119 */
#define	NCALL_UNUSED2	120	/* 120 - 129 */
#define	NCALL_SDBC	130	/* 130 - 149 */
#define	NCALL_STE	150	/* 150 - 159 */
#define	NCALL_HM	160	/* 160 - 169 */

#ifdef __cplusplus
}
#endif

#endif	/* _NCALL_H */
