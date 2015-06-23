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

#ifndef	_INET_KEYSOCK_H
#define	_INET_KEYSOCK_H

#ifdef	__cplusplus
extern "C" {
#endif

extern int keysock_opt_get(queue_t *, int, int, uchar_t *);
extern int keysock_opt_set(queue_t *, uint_t, int, int, uint_t,
    uchar_t *, uint_t *, uchar_t *, void *, cred_t *cr);

/*
 * Object to represent database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */

extern optdb_obj_t	keysock_opt_obj;
extern uint_t		keysock_max_optsize;

/*
 * KEYSOCK stack instances
 */
struct keysock_stack {
	netstack_t		*keystack_netstack;	/* Common netstack */
	/*
	 * keysock_plumbed: zero if plumb not attempted, positive if it
	 * succeeded,  negative if it failed.
	 */
	int			keystack_plumbed;
	caddr_t			keystack_g_nd;
	struct keysockparam_s	*keystack_params;

	kmutex_t		keystack_param_lock;
				/* Protects the NDD variables. */

	/* List of open PF_KEY sockets, protected by keysock_list_lock. */
	kmutex_t		keystack_list_lock;
	struct keysock_s	*keystack_list;

	/*
	 * Consumers table. If an entry is NULL, keysock maintains
	 * the table.
	 */
	kmutex_t		keystack_consumers_lock;

#define	KEYSOCK_MAX_CONSUMERS 256
	struct keysock_consumer_s *keystack_consumers[KEYSOCK_MAX_CONSUMERS];

	/*
	 * State for flush/dump.  This would normally be a boolean_t, but
	 * atomic_cas_32() works best for a known 32-bit quantity.
	 */
	uint32_t		keystack_flushdump;
	int			keystack_flushdump_errno;

	/*
	 * This integer counts the number of extended REGISTERed sockets.  This
	 * determines if we should send extended REGISTERs.
	 */
	uint32_t		keystack_num_extended;

	/*
	 * Global sequence space for SADB_ACQUIRE messages of any sort.
	 */
	uint32_t		keystack_acquire_seq;
};
typedef struct keysock_stack keysock_stack_t;

/*
 * keysock session state (one per open PF_KEY socket (i.e. as a driver))
 *
 * I keep these in a linked list, and assign a monotonically increasing
 * serial ## (which is also the minor number).
 */

typedef struct keysock_s {
	/* Protected by keysock_list_lock. */
	struct keysock_s *keysock_next; /* Next in list */
	struct keysock_s **keysock_ptpn; /* Pointer to previous next */

	kmutex_t keysock_lock; /* Protects the following. */
	queue_t *keysock_rq;   /* Read queue - putnext() to userland */
	queue_t *keysock_wq;   /* Write queue */

	uint_t keysock_state;
	uint_t keysock_flags;
	/* If SADB_SATYPE_MAX (in net/pfkeyv2.h) > 255, rewhack this. */
	uint64_t keysock_registered[4]; /* Registered types for this socket. */

	/* Also protected by keysock_list_lock. */
	minor_t keysock_serial; /* Serial number of this socket. */
	keysock_stack_t		*keysock_keystack;
} keysock_t;

#define	KEYSOCK_NOLOOP	0x1	/* Don't loopback messages (no replies). */
#define	KEYSOCK_PROMISC	0x2	/* Give me all outbound messages. */
				/* DANGER:	Setting this requires EXTRA */
				/* 		privilege on an MLS box. */
#define	KEYSOCK_EXTENDED 0x4	/* Extended REGISTER received. */

/* My apologies for the ugliness of this macro.  And using constants. */
#define	KEYSOCK_ISREG(ks, satype) (((ks)->keysock_registered[(satype) >> 3]) & \
	(1 << ((satype) & 63)))
#define	KEYSOCK_SETREG(ks, satype) (ks)->keysock_registered[(satype) >> 3] |= \
	(1 << ((satype) & 63))

/*
 * Keysock consumers (i.e. AH, ESP), in array based on sadb_msg_satype.
 * For module instances.
 */

typedef struct keysock_consumer_s {
	kmutex_t kc_lock;	/* Protects instance. */

	queue_t *kc_rq;		/* Read queue, requests from AH, ESP. */
	queue_t *kc_wq;		/* Write queue, putnext down */

	/* Other goodies as a need them. */
	uint8_t			kc_sa_type;	/* What sort of SA am I? */
	uint_t			kc_flags;
	keysock_stack_t		*kc_keystack;
} keysock_consumer_t;

/* Can only set flags when keysock_consumer_lock is held. */
#define	KC_INTERNAL 0x1		/* Consumer maintained by keysock itself. */
#define	KC_FLUSHING 0x2		/* SADB_FLUSH pending on this consumer. */

extern int keysock_plumb_ipsec(netstack_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _INET_KEYSOCK_H */
