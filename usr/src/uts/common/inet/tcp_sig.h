/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#ifndef	_INET_TCPSIG_H
#define	_INET_TCPSIG_H

#include <sys/stdbool.h>
#include <inet/keysock.h>
#include <inet/sadb.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct tcpsig_sa {
	list_node_t			ts_link;

	tcp_stack_t			*ts_stack;

	sa_family_t			ts_family;
	struct sockaddr_storage		ts_src;
	struct sockaddr_storage		ts_dst;

	ipsa_key_t			ts_key;

	kmutex_t			ts_lock;

	/* All of the following are protected by ts_lock */

	time_t				ts_addtime;	/* Time added */
	time_t				ts_usetime;	/* Time of first use */
	time_t				ts_lastuse;	/* Time of last use */
	time_t				ts_softexpiretime; /* First soft exp */
	time_t				ts_hardexpiretime; /* First hard exp */

	/* Configured lifetimes */
	uint64_t			ts_softaddlt;
	uint64_t			ts_softuselt;
	uint64_t			ts_hardaddlt;
	uint64_t			ts_harduselt;

	uint64_t			ts_refcnt;
	bool				ts_tombstoned;
	uint_t				ts_state;
} tcpsig_sa_t;

typedef struct tcpsig_db {
	krwlock_t			td_lock;
	list_t				td_salist;
} tcpsig_db_t;

extern void tcpsig_init(tcp_stack_t *);
extern void tcpsig_fini(tcp_stack_t *);
extern void tcpsig_sa_handler(keysock_t *, mblk_t *, sadb_msg_t *,
    sadb_ext_t **);

extern void tcpsig_sa_rele(tcpsig_sa_t *);
extern bool tcpsig_sa_exists(tcp_t *, bool, tcpsig_sa_t **);
extern bool tcpsig_signature(mblk_t *, tcp_t *, tcpha_t *, int, uint8_t *,
    bool);
extern bool tcpsig_verify(mblk_t *, tcp_t *, tcpha_t *, ip_recv_attr_t *,
    uint8_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _INET_TCPSIG_H */
