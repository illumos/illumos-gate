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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SGSBBC_MAILBOX_PRIV_H
#define	_SYS_SGSBBC_MAILBOX_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sgsbbc_mailbox.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Internal flags for message processing
 */
#define	WAIT_FOR_REPLY		0x1
#define	NOWAIT_FOR_REPLY	0x2
#define	WAIT_FOR_SPACE		0x4
#define	NOWAIT_FOR_SPACE	0x8

#define	MBOX_INTRS		4
#define	MBOX_MSGIN_INTR		0
#define	MBOX_MSGOUT_INTR	1
#define	MBOX_SPACEIN_INTR	2
#define	MBOX_SPACEOUT_INTR	3


#define	SBBC_MAILBOXES		2	/* InBox & OutBox */
#define	SBBC_INBOX		0
#define	SBBC_OUTBOX		1
#define	SBBC_MBOX_MSG_TYPES	32	/* this will do for now */
#define	SBBC_MBOX_INTR_TYPES	4	/* see below */


#define	SBBC_MSG_TYPE_MASK	0xffff

/* Number of bytes the mailbox messages align at */
#define	MBOX_ALIGN_BYTES	8	/* align at 8-byte boundary */

#define	PANIC_ENV_EVENT_MSG		"SC triggered Domain shutdown due to " \
					"temperature exceeding limits.\n"

/*
 * This struct is used internally by both the SC & OS mailbox
 * handlers. Every message in the mailbox is made up
 * of a fragment struct followed immediately by some optional
 * user data. (We will allow zero-length messages.)
 *
 * Note: ID == 0 => unsolicited
 *
 * make them all 32-bit ints and add a bit of
 * user-data padding to make life easy for the SC
 */
struct sbbc_fragment {
	uint32_t	f_id;		/* msg_id */
	sbbc_msg_type_t	f_type;		/* msg_type */
	uint32_t	f_status;	/* not used yet */
	uint32_t	f_total_len;
	uint32_t	f_frag_len;
	uint32_t	f_frag_offset;	/* offset into msg_buf */
	uint32_t	f_data[2];	/* for junk mail */
};


typedef enum { INBOX, OUTBOX } mb_type_t;

/*
 * this describes the In/Out mailboxes
 */
typedef struct sbbc_mbox {
	kmutex_t	mb_lock;	/* global lock for this mailbox */
	mb_type_t	mb_type;	/* read-only/read-write */
	/*
	 * If the mailbox is full, we can either block waiting
	 * for space or just return an error. We will make this
	 * dependent on the message flag
	 */
	kcondvar_t	mb_full;	/* protected by mb_lock */
} sbbc_mbox_t;


/*
 * When a message requires a reply, it is put on a waitlist
 * until a message of that type with a matching ID comes in.
 */
struct sbbc_msg_waiter {
	uint32_t		w_id;	/* ID */
	sbbc_msg_t		*w_msg;	/* message we are waiting for */
	kcondvar_t		w_cv;	/* protected by wait_list lock */
	time_t			w_timeout;
	struct sbbc_msg_waiter	*w_next;
};


/*
 * this struct describes the mailbox as seen by the OS
 */
typedef struct sbbc_mailbox {
	/*
	 * Two mailboxes, SC -> OS mbox_in
	 *		  OS -> SC mbox_out
	 */
	sbbc_mbox_t		*mbox_in;
	sbbc_mbox_t		*mbox_out;
	/*
	 * Interrupt handlers. Mailbox registers itself with
	 * the SBBC for the following interrupt types
	 *
	 * SBBC_MAILBOX_IN
	 * SBBC_MAILBOX_OUT
	 * SBBC_MAILBOX_SPACE_IN
	 * SBBC_MAILBOX_SPACE_OUT
	 *
	 * Of course, we should only ever see the *-IN interrupts
	 * but we will register the *-OUT ones as ours anyway to ensure
	 * no-one else tries to overload these interrupt types.
	 *
	 */
	struct {
		kmutex_t	mbox_intr_lock;
		uint_t		mbox_intr_state;
	} intr_state[SBBC_MBOX_INTR_TYPES];

	/*
	 * Message handlers - one per message type
	 * These are used for incoming unsolicited messages
	 */
	sbbc_intrs_t		*intrs[SBBC_MBOX_MSG_TYPES];

	/*
	 * Next message ID
	 */
	uint32_t		mbox_msg_id;

	/*
	 * List of 'waiters' for each incoming message type
	 */
	kmutex_t		mbox_wait_lock[SBBC_MBOX_MSG_TYPES];
	struct sbbc_msg_waiter	*mbox_wait_list[SBBC_MBOX_MSG_TYPES];

} sbbc_mailbox_t;


/*
 * This data will be written by the SC at the
 * start of the mailbox in IOSRAM.
 * This is read from offset 0 with key SBBC_MAILBOX_KEY
 *
 * make them all 32-bit ints and add a bit of
 * user-data padding to make life easy for the SC
 */
struct sbbc_mbox_header {
	uint32_t	mbox_magic;
	uint32_t	mbox_version;
	struct mbox {
		uint32_t	mbox_type;	/* SBBC_{IN|OUT}BOX */
		uint32_t	mbox_offset;	/* from start of mailbox */
						/* SRAM area */
		uint32_t	mbox_len;	/* size in bytes */
		uint32_t	mbox_producer;	/* producer offset from */
						/* start of this mailbox */
		uint32_t	mbox_consumer;  /* consumer offset from */
						/* start of this mailbox */
	} mailboxes[SBBC_MAILBOXES];
	uint32_t	mbox_data[4];		/* pad */
};


extern void	sbbc_mbox_init();
extern void	sbbc_mbox_fini();
extern int	sbbc_mbox_create(sbbc_softstate_t *);
extern int	sbbc_mbox_switch(sbbc_softstate_t *);

extern sbbc_mailbox_t	*master_mbox;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGSBBC_MAILBOX_PRIV_H */
