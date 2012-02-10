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

/*
 * This file contains the implementation of the mboxsc module, a mailbox layer
 * built upon the Starcat IOSRAM driver.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/varargs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include <sys/iosramreg.h>
#include <sys/iosramio.h>
#include <sys/mboxsc.h>
#include <sys/mboxsc_impl.h>

/*
 * Debugging facility
 */
#define	DBGACT_NONE	(0x00000000)
#define	DBGACT_BREAK	(0x00000001)
#define	DBGACT_SHOWPOS	(0x00000002)
#define	DBGACT_DEFAULT	DBGACT_NONE

#define	DBG_DEV		(0x00000001)
#define	DBG_CALLS	(0x00000002)
#define	DBG_RETS	(0x00000004)
#define	DBG_ARGS	(0x00000008)
#define	DBG_KMEM	(0x00000010)
#define	DBG_ALL		(0xFFFFFFFF)

#ifdef DEBUG
static uint32_t	mboxsc_debug_mask = 0x00000000;
#define	DPRINTF0(class, action, fmt) \
	mboxsc_dprintf(__FILE__, __LINE__, (class), (action), (fmt))
#define	DPRINTF1(class, action, fmt, arg1) \
	mboxsc_dprintf(__FILE__, __LINE__, (class), (action), (fmt),\
	    (arg1))
#define	DPRINTF2(class, action, fmt, arg1, arg2) \
	mboxsc_dprintf(__FILE__, __LINE__, (class), (action), (fmt),\
	    (arg1), (arg2))
#define	DPRINTF3(class, action, fmt, arg1, arg2, arg3) \
	mboxsc_dprintf(__FILE__, __LINE__, (class), (action), (fmt),\
	    (arg1), (arg2), (arg3))
#define	DPRINTF4(class, action, fmt, arg1, arg2, arg3, arg4) \
	mboxsc_dprintf(__FILE__, __LINE__, (class), (action), (fmt),\
	    (arg1), (arg2), (arg3), (arg4))
#define	DPRINTF5(class, action, fmt, arg1, arg2, arg3, arg4, arg5) \
	mboxsc_dprintf(__FILE__, __LINE__, (class), (action), (fmt),\
	    (arg1), (arg2), (arg3), (arg4), (arg5))
#else	/* DEBUG */
#define	DPRINTF0(class, action, fmt)
#define	DPRINTF1(class, action, fmt, arg1)
#define	DPRINTF2(class, action, fmt, arg1, arg2)
#define	DPRINTF3(class, action, fmt, arg1, arg2, arg3)
#define	DPRINTF4(class, action, fmt, arg1, arg2, arg3, arg4)
#define	DPRINTF5(class, action, fmt, arg1, arg2, arg3, arg4, arg5)
#endif	/* DEBUG */

/*
 * Basic constants
 */
#ifndef TRUE
#define	TRUE	(1)
#endif	/* TRUE */
#ifndef FALSE
#define	FALSE	(0)
#endif	/* FALSE */


/*
 * Whenever mboxsc_init is called to create a new mailbox, an instance of
 * mboxsc_mbox_t is created and inserted into a hash table to maintain
 * various information about the mailbox.  The mbox_state, mbox_refcount, and
 * mbox_wait fields are all protected by the global mboxsc_lock mutex.
 * If lock contention between mailboxes becomes an issue, each mailbox will
 * need to be given its own mutex to protect the mbox_wait, mbox_state,
 * and mbox_update_wait fields.  The mbox_refcount field will probably need to
 * remain under global protection, however, since it is used to keep track of
 * the number of threads sleeping inside the mailbox's various synchronization
 * mechanisms and would consequently be difficult to protect using those same
 * mechanisms.
 */
typedef struct mboxsc_mbox {
	uint32_t		mbox_key;
	int			mbox_direction;
	void			(*mbox_callback)(void);
	uint32_t		mbox_length;
	uint16_t		mbox_refcount;
	uint16_t		mbox_state;
	kcondvar_t		mbox_wait;
	mboxsc_msghdr_t		mbox_header;
	struct mboxsc_mbox	*mbox_hash_next;
} mboxsc_mbox_t;

/*
 * Various state flags that can be set on a mailbox.  Multiple states may
 * be active at the same time.
 */
#define	STATE_IDLE	(0x0000)
#define	STATE_WRITING	(0x0001)
#define	STATE_READING	(0x0002)
#define	STATE_HDRVALID	(0x0004)

/*
 * Timeout periods for mboxsc_putmsg and mboxsc_getmsg, converted to ticks
 * from the microsecond values found in mboxsc_impl.h.
 */
#define	EAGAIN_POLL		(drv_usectohz(MBOXSC_EAGAIN_POLL_USECS))
#define	PUTMSG_POLL		(drv_usectohz(MBOXSC_PUTMSG_POLL_USECS))
#define	HWLOCK_POLL		(drv_usectohz(MBOXSC_HWLOCK_POLL_USECS))
#define	LOOP_WARN_INTERVAL	(drv_usectohz(MBOXSC_USECS_PER_SECOND * 15))

/*
 * Various tests that are performed on message header fields.
 */
#define	IS_UNSOLICITED_TYPE(type)	((type) != MBOXSC_MSG_REPLY)
#define	MSG_TYPE_MATCHES(type, msgp)	\
	(((type) == 0) || ((type) & (msgp)->msg_type))
#define	MSG_CMD_MATCHES(cmd, msgp)	\
	(((cmd) == 0) || ((cmd) == (msgp)->msg_cmd))
#define	MSG_TRANSID_MATCHES(tid, msgp)	\
	(((tid) == 0) || ((tid) == (msgp)->msg_transid))

/*
 * This macro can be used to determine the size of any field in the message
 * header (or any other struct, for that matter).
 */
#define	FIELD_SIZE(type, field)		(sizeof (((type *)0)->field))

/*
 * Mask used when generating unique transaction ID values.
 * This arbitrarily chosen value will be OR'd together with
 * a counter for each successive internally-generated transaction ID.
 */
#define	TRANSID_GEN_MASK	(0xFFC0000000000000)

/*
 * All existing mailboxes are stored in a hash table with HASHTBL_SIZE
 * entries so they can be rapidly accessed by their key values.
 */
#define	HASHTBL_SIZE	(32)
#define	HASH_KEY(key)	((((key) >> 24) ^ ((key) >> 16) ^ ((key) >> 9) ^\
			    (key)) & (HASHTBL_SIZE - 1));

/*
 * Unfortunately, it is necessary to calculate checksums on data split up
 * amongst different buffers in some cases.  Consequently, mboxsc_checksum
 * accepts a "seed" value as one of its parameters.  When first starting a
 * checksum calculation, the seed should be 0.
 */
#define	CHKSUM_INIT	(0)

/*
 * local variables
 */
static kmutex_t		mboxsc_lock;
static mboxsc_mbox_t	*mboxsc_hash_table[HASHTBL_SIZE];
static uint32_t		mboxsc_flaglock_count;
static uint32_t		mboxsc_active_version = MBOXSC_PROTOCOL_VERSION;
static kcondvar_t	mboxsc_dereference_cv;

/*
 * Structures from modctl.h used for loadable module support.
 * The mboxsc API is a "miscellaneous" module.
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"IOSRAM Mailbox API 'mboxsc'",
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

/*
 * Prototypes for local functions
 */
static void		mboxsc_iosram_callback(void *arg);
static void		mboxsc_hdrchange_callback(void);
static int		mboxsc_add_mailbox(mboxsc_mbox_t *mailboxp);
static void		mboxsc_close_mailbox(mboxsc_mbox_t *mailboxp);
static void		mboxsc_hashinsert_mailbox(mboxsc_mbox_t *mailboxp);
static mboxsc_mbox_t	*mboxsc_hashfind_mailbox_by_key(uint32_t key);
static mboxsc_mbox_t	*mboxsc_hashremove_mailbox_by_key(uint32_t key);
static mboxsc_chksum_t	mboxsc_checksum(mboxsc_chksum_t seed, uint8_t *buf,
	uint32_t length);
static int		mboxsc_lock_flags(uint8_t mandatory, clock_t deadline);
static int		mboxsc_unlock_flags(uint8_t mandatory);
static int		mboxsc_timed_read(clock_t deadline, uint32_t key,
	uint32_t off, uint32_t len, caddr_t dptr);
static int		mboxsc_timed_write(clock_t deadline, uint32_t key,
	uint32_t off, uint32_t len, caddr_t dptr);
static int		mboxsc_timed_get_flag(clock_t deadline, uint32_t key,
	uint8_t *data_validp, uint8_t *int_pendingp);
static int		mboxsc_timed_set_flag(clock_t deadline, uint32_t key,
	uint8_t data_valid, uint8_t int_pending);
static int		mboxsc_timed_send_intr(clock_t deadline);
static int		mboxsc_expire_message(uint32_t key, int *resultp);
static uint64_t		mboxsc_generate_transid(uint64_t prev_transid);
static void		mboxsc_reference_mailbox(mboxsc_mbox_t *mailboxp);
static void		mboxsc_dereference_mailbox(mboxsc_mbox_t *mailboxp);
#ifdef DEBUG
/*PRINTFLIKE5*/
static void		mboxsc_dprintf(const char *file, int line,
	uint32_t class, uint32_t action, const char *fmt, ...);
int			mboxsc_debug(int cmd, void *arg);
#endif /* DEBUG */


/*
 * _init
 *
 * Loadable module support routine.  Initializes global lock and hash table.
 */
int
_init(void)
{
	int		i;
	uint32_t	sms_version;
	int		error = 0;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "_init called\n");

	/*
	 * Initialize all module resources.
	 */
	mutex_init(&mboxsc_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&mboxsc_dereference_cv, NULL, CV_DRIVER, NULL);

	for (i = 0; i < HASHTBL_SIZE; i++) {
		mboxsc_hash_table[i] = NULL;
	}
	mboxsc_flaglock_count = 0;

	if (mod_install(&modlinkage) != 0) {
		goto failed;
	}

	/*
	 * Set the os_mbox_version field in the IOSRAM header to indicate the
	 * highest Mailbox Protocol version we support
	 */
	error = iosram_hdr_ctrl(IOSRAM_HDRCMD_SET_OS_MBOX_VER,
	    (void *)MBOXSC_PROTOCOL_VERSION);
	if (error != 0) {
		goto failed;
	}

	/*
	 * Read the sms_mbox_version field in the IOSRAM header to determine
	 * what the greatest commonly supported version is.
	 */
	error = iosram_hdr_ctrl(IOSRAM_HDRCMD_GET_SMS_MBOX_VER,
	    (void *)&sms_version);
	if (error != 0) {
		goto failed;
	}
	mboxsc_active_version = MIN(MBOXSC_PROTOCOL_VERSION, sms_version);
	DPRINTF2(DBG_DEV, DBGACT_DEFAULT,
	    "sms version: %d, active version: %d\n", sms_version,
	    mboxsc_active_version);

	/*
	 * Register a callback with the IOSRAM driver to receive notification of
	 * changes to the IOSRAM header, in case the sms_mbox_version field
	 * changes.
	 */
	error = iosram_hdr_ctrl(IOSRAM_HDRCMD_REG_CALLBACK,
	    (void *)mboxsc_hdrchange_callback);
	if (error != 0) {
		goto failed;
	}

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "_init ret: 0x%08x\n", error);
	return (0);

	/*
	 * If initialization fails, uninitialize resources.
	 */
failed:
	mutex_destroy(&mboxsc_lock);
	cv_destroy(&mboxsc_dereference_cv);

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "_init ret: 0x%08x\n", error);
	return (error);
}

/*
 * _fini
 *
 * Loadable module support routine. Closes all mailboxes and releases all
 * resources.
 */
int
_fini(void)
{
	int		i;
	int		error = 0;
	mboxsc_mbox_t	*mailboxp;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "_fini called\n");

	/*
	 * Attempt to remove the module.  If successful, close all mailboxes
	 * and deallocate the global lock.
	 */
	error = mod_remove(&modlinkage);
	if (error == 0) {
		mutex_enter(&mboxsc_lock);

		(void) iosram_hdr_ctrl(IOSRAM_HDRCMD_REG_CALLBACK, NULL);

		for (i = 0; i < HASHTBL_SIZE; i++) {
			while (mboxsc_hash_table[i] != NULL) {
				mailboxp = mboxsc_hash_table[i];
				mboxsc_close_mailbox(mailboxp);
			}
		}
		mutex_exit(&mboxsc_lock);
		mutex_destroy(&mboxsc_lock);
		cv_destroy(&mboxsc_dereference_cv);
	}

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "_fini ret: 0x%08x\n", error);
	return (error);
}

/*
 * _info
 *
 * Loadable module support routine.
 */
int
_info(struct modinfo *modinfop)
{
	int		error = 0;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "_info called\n");

	error = mod_info(&modlinkage, modinfop);

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "_info ret: 0x%08x\n", error);

	return (error);
}

/*
 * mboxsc_init
 *
 * Attempts to create a new mailbox.
 */
int
mboxsc_init(uint32_t key, int direction, void (*event_handler)(void))
{
	int		error = 0;
	mboxsc_mbox_t	*mailboxp;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_init called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "direction = %d\n", direction);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "event_handlerp = %p\n",
	    (void *)event_handler);

	/*
	 * Check for valid direction and callback specification.
	 */
	if (((direction != MBOXSC_MBOX_IN) && (direction != MBOXSC_MBOX_OUT)) ||
	    ((event_handler != NULL) && (direction != MBOXSC_MBOX_IN))) {
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_init ret: 0x%08x\n",
		    EINVAL);
		return (EINVAL);
	}

	/*
	 * Allocate memory for the mailbox structure and initialize all
	 * caller-provided fields.
	 */
	mailboxp = (mboxsc_mbox_t *)kmem_zalloc(sizeof (mboxsc_mbox_t),
	    KM_SLEEP);
	DPRINTF2(DBG_KMEM, DBGACT_DEFAULT, "kmem_zalloc(%lu) = %p\n",
	    sizeof (mboxsc_mbox_t), (void *)mailboxp);
	mailboxp->mbox_key = key;
	mailboxp->mbox_direction = direction;
	mailboxp->mbox_callback = event_handler;

	/*
	 * Attempt to add the mailbox.  If unsuccessful, free the allocated
	 * memory.
	 */
	mutex_enter(&mboxsc_lock);
	error = mboxsc_add_mailbox(mailboxp);
	mutex_exit(&mboxsc_lock);

	if (error != 0) {
		DPRINTF2(DBG_KMEM, DBGACT_DEFAULT, "kmem_free(%p, %lu)\n",
		    (void *)mailboxp, sizeof (mboxsc_mbox_t));
		kmem_free(mailboxp, sizeof (mboxsc_mbox_t));
	}

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_init ret: 0x%08x\n", error);
	return (error);
}

/*
 * mboxsc_fini
 *
 * Closes the mailbox with the indicated key, if it exists.
 */
int
mboxsc_fini(uint32_t key)
{
	int		error = 0;
	mboxsc_mbox_t	*mailboxp;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_fini called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);

	/*
	 * Attempt to close the mailbox.
	 */
	mutex_enter(&mboxsc_lock);
	mailboxp = mboxsc_hashfind_mailbox_by_key(key);
	if (mailboxp == NULL) {
		error = EBADF;
	} else {
		while (mailboxp->mbox_refcount != 0) {
			cv_wait(&mboxsc_dereference_cv, &mboxsc_lock);
		}
		mboxsc_close_mailbox(mailboxp);
	}
	mutex_exit(&mboxsc_lock);

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_fini ret: 0x%08x\n", error);
	return (error);
}

/*
 * mboxsc_putmsg
 *
 * Attempt to place a message into an outbound mailbox and signal the
 * recipient.  A successful return (0) indicates that the message was
 * successfully delivered.
 */
int
mboxsc_putmsg(uint32_t key, uint32_t type, uint32_t cmd, uint64_t *transidp,
		uint32_t length, void *datap, clock_t timeout)
{
	int		i;
	int		error = 0;
	int		result;
	int		lock_held = 0;
	int		unlock_err;
	uint8_t		data_valid;
	clock_t		deadline;
	clock_t		remainder;
	mboxsc_chksum_t	checksum;
	mboxsc_mbox_t	*mailboxp;
	mboxsc_msghdr_t	header;

#ifdef DEBUG /* because lint whines about if stmts without consequents */
	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_putmsg called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "type = 0x%x\n", type);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "cmd = 0x%x\n", cmd);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "transidp = %p\n", (void *)transidp);
	if (transidp != NULL) {
		DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "*transidp = 0x%016lx\n",
		    *transidp);
	}
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "length = 0x%x\n", length);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "datap = %p\n", datap);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "timeout = %ld\n", timeout);
#endif /* DEBUG */

	/*
	 * Perform some basic sanity checks on the message.
	 */
	for (i = 0; i < MBOXSC_NUM_MSG_TYPES; i++) {
		if (type == (1 << i)) {
			break;
		}
	}
	if ((i == MBOXSC_NUM_MSG_TYPES) || (cmd == 0) ||
	    ((datap == NULL) && (length != 0)) ||
	    (timeout < MBOXSC_PUTMSG_MIN_TIMEOUT_MSECS) ||
	    (timeout > MBOXSC_PUTMSG_MAX_TIMEOUT_MSECS)) {
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_putmsg ret: 0x%08x\n", EINVAL);
		return (EINVAL);
	}

	/*
	 * Initialize the header structure with values provided by the caller.
	 */
	header.msg_version = mboxsc_active_version;
	header.msg_type = type;
	header.msg_cmd = cmd;
	header.msg_length = MBOXSC_MSGHDR_SIZE + length;
	if (transidp != NULL) {
		header.msg_transid = *transidp;
	} else {
		header.msg_transid = 0;
	}

	/*
	 * Perform additional sanity checks on the mailbox and message.
	 * Make sure that the specified mailbox really exists, that the
	 * given message will fit in it, and that the current message's
	 * transaction ID isn't the same as the last message's transaction
	 * ID unless both messages are replies (it's okay, necessary even,
	 * to reuse a transaction ID when resending a failed reply message,
	 * but that is the only case in which it is permissible).
	 */
	mutex_enter(&mboxsc_lock);
	mailboxp = mboxsc_hashfind_mailbox_by_key(key);

	if (mailboxp == NULL) {
		error = EBADF;
	} else if ((mailboxp->mbox_direction != MBOXSC_MBOX_OUT) ||
	    (length + MBOXSC_PROTOCOL_SIZE > mailboxp->mbox_length) ||
	    ((header.msg_transid == mailboxp->mbox_header.msg_transid) &&
	    ((type & mailboxp->mbox_header.msg_type) != MBOXSC_MSG_REPLY) &&
	    (header.msg_transid != 0))) {
		error = EINVAL;
	}

	if (error != 0) {
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_putmsg ret: 0x%08x\n", error);
		return (error);
	}

	/*
	 * If the message's transaction ID is set to 0, generate a unique
	 * transaction ID and copy it into the message header.  If the message
	 * is successfully delivered and transidp != NULL, we'll copy this new
	 * transid into *transidp later.
	 */
	if (header.msg_transid == 0) {
		header.msg_transid =
		    mboxsc_generate_transid(mailboxp->mbox_header.msg_transid);
	}

	/*
	 * Don't allow mboxsc_putmsg to attempt to place a message for
	 * longer than the caller's timeout.
	 */
	deadline = ddi_get_lbolt() +
	    drv_usectohz(timeout * MBOXSC_USECS_PER_MSEC);

	/*
	 * Increment the reference count on the mailbox to keep it from being
	 * closed, and wait for it to become available.
	 */
	mboxsc_reference_mailbox(mailboxp);
	remainder = 1;
	while ((mailboxp->mbox_state & STATE_WRITING) &&
	    (remainder > 0)) {
		remainder = cv_timedwait_sig(&(mailboxp->mbox_wait),
		    &mboxsc_lock, deadline);
	}

	/*
	 * Check to see whether or not the mailbox became available.  If it
	 * did not, decrement its reference count and return an error to the
	 * caller.
	 */
	if (remainder == -1) {
		error = ENOSPC;
	} else if (remainder == 0) {
		error = EINTR;
	}

	if (error != 0) {
		mboxsc_dereference_mailbox(mailboxp);
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_putmsg ret: 0x%08x\n", error);
		return (error);
	}

	/*
	 * Since the message is valid and we're going to try to write it to
	 * IOSRAM, record its header for future reference (e.g. to make sure the
	 * next message doesn't incorrectly use the same transID).
	 */
	bcopy(&header, &(mailboxp->mbox_header), MBOXSC_MSGHDR_SIZE);

	/*
	 * Flag the mailbox as being in use and release the global lock.
	 */
	mailboxp->mbox_state |= STATE_WRITING;
	mutex_exit(&mboxsc_lock);

	/*
	 * Calculate the message checksum using the header and the data.
	 */
	checksum = mboxsc_checksum(CHKSUM_INIT, (uint8_t *)&header,
	    MBOXSC_MSGHDR_SIZE);
	checksum = mboxsc_checksum(checksum, (uint8_t *)datap, length);

	/*
	 * Attempt to write the message and checksum to IOSRAM until successful,
	 * or as long as time remains and no errors other than EAGAIN are
	 * returned from any call to the IOSRAM driver in case there is a tunnel
	 * switch in progress.
	 */
	error = mboxsc_timed_write(deadline, key, MBOXSC_MSGHDR_OFFSET,
	    MBOXSC_MSGHDR_SIZE, (caddr_t)&header);

	if (error == 0) {
		error = mboxsc_timed_write(deadline, key, MBOXSC_DATA_OFFSET,
		    length, (caddr_t)datap);
	}

	if (error == 0) {
		error = mboxsc_timed_write(deadline, key, header.msg_length,
		    MBOXSC_CHKSUM_SIZE, (caddr_t)&checksum);
	}

	/*
	 * Lock the flags before setting data_valid.  This isn't strictly
	 * necessary for correct protocol operation, but it gives us a chance to
	 * verify that the flags lock is functional before we commit to sending
	 * the message.
	 */
	if (error == 0) {
		error = mboxsc_lock_flags(FALSE, deadline);
		if (error == 0) {
			lock_held = 1;
		} else if (error == EBUSY) {
			error = EAGAIN;
		}
	}

	if (error == 0) {
		error = mboxsc_timed_set_flag(deadline, key, IOSRAM_DATA_VALID,
		    IOSRAM_INT_TO_SSC);
	}

	/*
	 * Unlock the flags.  If an error is encountered, only return it if
	 * another error hasn't been encountered previously.
	 */
	if (lock_held) {
		unlock_err = mboxsc_unlock_flags(TRUE);
		if ((unlock_err != 0) && ((error == 0) || (error == EAGAIN))) {
			error = unlock_err;
		}
	}

	/*
	 * If time ran out or an IOSRAM call failed, notify other callers that
	 * the mailbox is available, decrement its reference count, and return
	 * an error.
	 */
	if (error != 0) {
		ASSERT((error != EINVAL) && (error != EMSGSIZE));
		mutex_enter(&mboxsc_lock);
		mailboxp->mbox_state &= ~STATE_WRITING;
		cv_broadcast(&(mailboxp->mbox_wait));
		mboxsc_dereference_mailbox(mailboxp);
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_putmsg ret: 0x%08x\n", error);
		return (error);
	}

	/*
	 * Send an interrupt to the remote mailbox interface to announce the
	 * presence of a new, valid message.
	 */
	error = mboxsc_timed_send_intr(deadline);

	/*
	 * Wait until either the data_valid flag is set INVALID by the
	 * remote client or time runs out.  Since we're calling delay as
	 * a part of polling the flag anyway, we don't really need to do
	 * the usual continuous retry if iosram_get_flag returns EAGAIN.
	 */
	data_valid = IOSRAM_DATA_VALID;
	if (error == DDI_SUCCESS) {
		do {
			delay(MIN(PUTMSG_POLL, deadline - ddi_get_lbolt()));
			error = iosram_get_flag(key, &data_valid, NULL);
		} while ((data_valid == IOSRAM_DATA_VALID) &&
		    ((error == EAGAIN) || (error == 0)) &&
		    (deadline - ddi_get_lbolt() >= 0));
	}

	/*
	 * If the data_valid flag was set to INVALID by the other side, the
	 * message was successfully transmitted.  If it wasn't, but there
	 * weren't any IOSRAM errors, the operation timed out.  If there was a
	 * problem with the IOSRAM, pass that info back to the caller.
	 */
	if (data_valid == IOSRAM_DATA_INVALID) {
		result = 0;
	} else if ((error == 0) || (error == DDI_FAILURE)) {
		result = ETIMEDOUT;
	} else {
		ASSERT(error != EINVAL);
		result = error;
	}

	/*
	 * If the message has not been picked up, expire it. Note that this may
	 * actually result in detecting successful message delivery if the SC
	 * picks it up at the last moment.  If expiration fails due to an error,
	 * return an error to the user even if the message appears to have
	 * been successfully delivered.
	 */
	if (data_valid == IOSRAM_DATA_VALID) {
		error = mboxsc_expire_message(key, &result);
		if ((error != 0) && ((result == 0) || (result == ETIMEDOUT))) {
			result = error;
		}
	}

	/*
	 * If the message was successfully delivered, and we generated a
	 * transaction ID for the caller, and the caller wants to know what it
	 * was, give it to them.
	 */
	if ((result == 0) && (transidp != NULL) && (*transidp == 0)) {
		*transidp = header.msg_transid;
	}

	/*
	 * Regardless of whether the message was successfully transmitted or
	 * not, notify other callers that the mailbox is available and decrement
	 * its reference count.
	 */
	mutex_enter(&mboxsc_lock);
	mailboxp->mbox_state &= ~STATE_WRITING;
	cv_broadcast(&(mailboxp->mbox_wait));
	mboxsc_dereference_mailbox(mailboxp);
	mutex_exit(&mboxsc_lock);

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_putmsg ret: 0x%08x\n",
	    result);
	return (result);
}

/*
 * mboxsc_getmsg
 *
 * Attempt to retrieve a message from the mailbox with the given key that
 * matches values provided in msgp.  A successful return (0) indicates that
 * a message matching the caller's request was successfully received within
 * timeout milliseconds.  If a message matching the caller's request is
 * detected, but can't be successfully read, an error will be returned even
 * if the caller's timeout hasn't expired.
 */
int
mboxsc_getmsg(uint32_t key, uint32_t *typep, uint32_t *cmdp, uint64_t *transidp,
		uint32_t *lengthp, void *datap, clock_t timeout)
{
	int		error = 0;
	uint32_t	datalen;
	uint8_t		data_valid;
	uint8_t		lock_held;
	mboxsc_chksum_t	read_checksum;
	mboxsc_chksum_t	calc_checksum;
	uint64_t	read_transid;
	clock_t		deadline;
	clock_t		remainder;
	mboxsc_mbox_t	*mailboxp;
	mboxsc_msghdr_t	header;

#ifdef DEBUG /* because lint whines about if stmts without consequents */
	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_getmsg called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "typep = %p\n", (void *)typep);
	if (typep != NULL) {
		DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "*typep = 0x%x\n", *typep);
	}
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "cmdp = %p\n", (void *)cmdp);
	if (cmdp != NULL) {
		DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "*cmdp = 0x%x\n", *cmdp);
	}
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "transidp = %p\n", (void *)transidp);
	if (transidp != NULL) {
		DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "*transidp = 0x%lx\n",
		    *transidp);
	}
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "lengthp = %p\n", (void *)lengthp);
	if (lengthp != NULL) {
		DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "*lengthp = 0x%x\n",
		    *lengthp);
	}
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "datap = %p\n", datap);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "timeout = %ld\n", timeout);
#endif /* DEBUG */

	/*
	 * Perform basic sanity checks on the caller's request.
	 */
	if ((typep == NULL) || (*typep >= (1 << MBOXSC_NUM_MSG_TYPES)) ||
	    (cmdp == NULL) || (transidp == NULL) || (lengthp == NULL) ||
	    ((datap == NULL) && (*lengthp != 0)) ||
	    (timeout < MBOXSC_GETMSG_MIN_TIMEOUT_MSECS) ||
	    (timeout > MBOXSC_GETMSG_MAX_TIMEOUT_MSECS)) {
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_getmsg ret: 0x%08x\n", EINVAL);
		return (EINVAL);
	}

	/*
	 * Don't allow mboxsc_getmsg to attempt to receive a message for
	 * longer than the caller's timeout.
	 */
	deadline = ddi_get_lbolt() +
	    drv_usectohz(timeout * MBOXSC_USECS_PER_MSEC);

	/*
	 * Perform additional sanity checks on the client's request and the
	 * associated mailbox.
	 */
	mutex_enter(&mboxsc_lock);
	mailboxp = mboxsc_hashfind_mailbox_by_key(key);
	if (mailboxp == NULL) {
		error = EBADF;
	} else if (mailboxp->mbox_direction != MBOXSC_MBOX_IN) {
		error = EINVAL;
	}

	if (error != 0) {
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_getmsg ret: 0x%08x\n", error);
		return (error);
	}

	/*
	 * The request is okay, so reference the mailbox (to keep it from being
	 * closed), and proceed with the real work.
	 */
	mboxsc_reference_mailbox(mailboxp);

	/*
	 * Certain failures that may occur late in the process of getting a
	 * message (e.g. checksum error, cancellation by the sender) are
	 * supposed to leave the recipient waiting for the next message to
	 * arrive rather than returning an error.  To facilitate restarting
	 * the message acquisition process, the following label is provided
	 * as a target for a very few judiciously-placed "goto"s.
	 *
	 * The mboxsc_lock mutex MUST be held when jumping to this point.
	 */
mboxsc_getmsg_retry:
	;

	/*
	 * If there is a valid message in the mailbox right now, check to
	 * see if it matches the caller's request.  If not, or if another
	 * caller is already reading it, wait for either the arrival of the
	 * next message or the expiration of the caller's specified timeout.
	 */
	error = 0;
	while (!(mailboxp->mbox_state & STATE_HDRVALID) ||
	    (mailboxp->mbox_state & STATE_READING) ||
	    !MSG_TYPE_MATCHES(*typep, &(mailboxp->mbox_header)) ||
	    !MSG_CMD_MATCHES(*cmdp, &(mailboxp->mbox_header)) ||
	    !MSG_TRANSID_MATCHES(*transidp, &(mailboxp->mbox_header))) {
		remainder = cv_timedwait_sig(&(mailboxp->mbox_wait),
		    &mboxsc_lock, deadline);
		if (remainder == -1) {
			error = ETIMEDOUT;
		} else if (remainder == 0) {
			error = EINTR;
		}

		if (error != 0) {
			mboxsc_dereference_mailbox(mailboxp);
			mutex_exit(&mboxsc_lock);
			DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
			    "mboxsc_getmsg ret: 0x%08x\n", error);
			return (error);
		}
	}

	/*
	 * If somebody sends us a message using a Mailbox Protocol version
	 * greater than the highest one we understand, invalidate the message,
	 * because we can't safely interpret anything beyond the version field.
	 */
	if (mailboxp->mbox_header.msg_version > MBOXSC_PROTOCOL_VERSION) {
		DPRINTF1(DBG_DEV, DBGACT_DEFAULT,
		    "incoming message with unsupported version %d\n",
		    mailboxp->mbox_header.msg_version);
		mailboxp->mbox_state &= ~STATE_HDRVALID;
		goto mboxsc_getmsg_retry;
	}

	/*
	 * At this point, there is a stored message header that matches the
	 * caller's request, but the actual message may no longer be valid
	 * in IOSRAM.  Check the data_valid flag to see whether or not
	 * this is the case.  If the message has expired, go start over.
	 *
	 * The global mutex is held while reading flag data from IOSRAM to
	 * avoid certain race conditions.  One race condition is still
	 * possible (i.e. SC-side has just set the data_valid flag for a
	 * new message, but the stored message header hasn't been updated
	 * yet), but it won't cause incorrect behavior (just some wasted work).
	 */
	error = iosram_get_flag(key, &data_valid, NULL);

	ASSERT(error != EINVAL);
	if (error == 0) {
		if (data_valid != IOSRAM_DATA_VALID) {
			mailboxp->mbox_state &= ~STATE_HDRVALID;
			goto mboxsc_getmsg_retry;
		}
	} else if ((error == EAGAIN) && (deadline - ddi_get_lbolt() >= 0)) {
		mutex_exit(&mboxsc_lock);
		delay(MIN(EAGAIN_POLL, deadline - ddi_get_lbolt()));
		mutex_enter(&mboxsc_lock);
		goto mboxsc_getmsg_retry;
	}

	/*
	 * If the message is larger than the caller's buffer, provide the caller
	 * with the length of the message and return an error.
	 */
	datalen = mailboxp->mbox_header.msg_length - MBOXSC_MSGHDR_SIZE;
	if ((error == 0) && (datalen > *lengthp)) {
		*lengthp = datalen;
		error = EMSGSIZE;
	}

	/*
	 * Note that there's no need to check STATE_HDRVALID before broadcasting
	 * here because the header is guaranteed to be valid at this point.
	 */
	if (error != 0) {
		cv_broadcast(&(mailboxp->mbox_wait));
		mboxsc_dereference_mailbox(mailboxp);
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_getmsg ret: 0x%08x\n", error);
		return (error);
	}

	/*
	 * Store a copy of the current message header, flag the mailbox to
	 * indicate that it is being read and attempt to read the message data
	 * and checksum.
	 */
	bcopy(&(mailboxp->mbox_header), &header, MBOXSC_MSGHDR_SIZE);
	mailboxp->mbox_state |= STATE_READING;
	mutex_exit(&mboxsc_lock);

	if (datalen > 0) {
		error = mboxsc_timed_read(deadline, key, MBOXSC_DATA_OFFSET,
		    datalen, (caddr_t)datap);
	}

	if (error == 0) {
		error = mboxsc_timed_read(deadline, key, header.msg_length,
		    MBOXSC_CHKSUM_SIZE, (caddr_t)&read_checksum);
	}

	/*
	 * Check for errors that may have occurred while accessing IOSRAM.
	 */
	if (error != 0) {
		ASSERT((error != EINVAL) && (error != EMSGSIZE));
		mutex_enter(&mboxsc_lock);
		mailboxp->mbox_state &= ~STATE_READING;
		if (mailboxp->mbox_state & STATE_HDRVALID) {
			cv_broadcast(&(mailboxp->mbox_wait));
		}
		mboxsc_dereference_mailbox(mailboxp);
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_getmsg ret: 0x%08x\n", error);
		return (error);
	}

	/*
	 * Calculate the checksum for the header and data that was read from
	 * IOSRAM.
	 */
	calc_checksum = mboxsc_checksum(CHKSUM_INIT, (uint8_t *)&header,
	    MBOXSC_MSGHDR_SIZE);
	calc_checksum = mboxsc_checksum(calc_checksum, (uint8_t *)datap,
	    datalen);

	/*
	 * If the message header has been invalidated, note the change.
	 * If a the checksum verification fails, invalidate the message
	 * header.  In either case, go back to the beginning and wait
	 * for a new message.
	 */
	mutex_enter(&mboxsc_lock);
	if (!(mailboxp->mbox_state & STATE_HDRVALID)) {
		error = -1;
		DPRINTF0(DBG_DEV, DBGACT_DEFAULT,
		    "mboxsc_getmsg - message invalidated while reading\n");
	} else if (read_checksum != calc_checksum) {
		error = -1;
		mailboxp->mbox_state &= ~STATE_HDRVALID;
		DPRINTF0(DBG_DEV, DBGACT_DEFAULT,
		    "mboxsc_getmsg - message failed checksum\n");
		cmn_err(CE_NOTE,
		    "mboxsc_getmsg - message failed checksum\n");
	}

	if (error == -1) {
		mailboxp->mbox_state &= ~STATE_READING;
		goto mboxsc_getmsg_retry;
	}

	/*
	 * Acquire the hardware lock used for synchronization of data_valid flag
	 * access to avoid race conditions.  If it is acquired, try to check the
	 * current data_valid flag and transaction ID to verify that the message
	 * is still valid.
	 */
	mutex_exit(&mboxsc_lock);

	if ((error = mboxsc_lock_flags(FALSE, deadline)) != 0) {
		lock_held = FALSE;
		/*
		 * We don't "do" EBUSY here, so treat it as EAGAIN.
		 */
		if (error == EBUSY) {
			error = EAGAIN;
		}
	} else {
		lock_held = TRUE;
	}

	if (error == 0) {
		error = mboxsc_timed_get_flag(deadline, key, &data_valid, NULL);
	}

	if ((error == 0) && (data_valid == IOSRAM_DATA_VALID)) {
		error = mboxsc_timed_read(deadline, key,
		    offsetof(mboxsc_msghdr_t, msg_transid),
		    FIELD_SIZE(mboxsc_msghdr_t, msg_transid),
		    (caddr_t)&read_transid);
	}

	/*
	 * If something failed along the way, either the error is unrecoverable
	 * or we're just plain out of time, so unlock the flags if they were
	 * locked, release the mailbox, wake up other potential readers if
	 * there's still a message around, and return.
	 */
	if (error != 0) {
		ASSERT((error != EINVAL) && (error != EMSGSIZE));
		if (lock_held) {
			(void) mboxsc_unlock_flags(TRUE);
		}
		mutex_enter(&mboxsc_lock);
		mailboxp->mbox_state &= ~STATE_READING;
		if (mailboxp->mbox_state & STATE_HDRVALID) {
			cv_broadcast(&(mailboxp->mbox_wait));
		}
		mboxsc_dereference_mailbox(mailboxp);
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_getmsg ret: 0x%08x\n", error);
		return (error);
	}

	/*
	 * If the data_valid flag isn't set to IOSRAM_DATA_VALID, or the
	 * message transaction ID in IOSRAM has changed, the message being
	 * read was timed out by its sender.  Since the data_valid flag can't
	 * change as long as we have the flags locked, we can safely mark the
	 * stored message header invalid if either the data_valid flag isn't set
	 * or the stored transaction ID doesn't match the one we read.  (If
	 * data_valid is set, the transaction ID shouldn't be changing
	 * underneath us.)  On the other hand, if there may still be a valid
	 * message, wake up any pending readers.
	 */
	if ((data_valid != IOSRAM_DATA_VALID) ||
	    (read_transid != header.msg_transid)) {
		mutex_enter(&mboxsc_lock);
		mailboxp->mbox_state &= ~STATE_READING;
		if ((data_valid != IOSRAM_DATA_VALID) ||
		    (mailboxp->mbox_header.msg_transid != read_transid)) {
			mailboxp->mbox_state &= ~STATE_HDRVALID;
		} else if (mailboxp->mbox_state & STATE_HDRVALID) {
			cv_broadcast(&(mailboxp->mbox_wait));
		}

		/*
		 * Unfortunately, we can't be holding mboxsc_lock when we unlock
		 * the flags.  However, we have to hold the flags until here to
		 * make sure the SC doesn't change the message's state while
		 * we're checking to see if we should invalidate our stored
		 * header.
		 */
		mutex_exit(&mboxsc_lock);
		error = mboxsc_unlock_flags(TRUE);
		mutex_enter(&mboxsc_lock);

		DPRINTF0(DBG_DEV, DBGACT_DEFAULT,
		    "mboxsc_getmsg() - message invalidated by sender\n");
		goto mboxsc_getmsg_retry;
	}

	/*
	 * If everything has worked up to this point, all that remains is
	 * to set the data_valid flag to IOSRAM_DATA_INVALID, tidy up, and
	 * return the message.  If the flag can't be set, the message can't
	 * be received, so keep trying as long as there is time.
	 */
	error = mboxsc_timed_set_flag(deadline, key, IOSRAM_DATA_INVALID,
	    IOSRAM_INT_NONE);

	(void) mboxsc_unlock_flags(TRUE);
	mutex_enter(&mboxsc_lock);

	if (error != 0) {
		ASSERT(error != EINVAL);
		mboxsc_dereference_mailbox(mailboxp);
		mailboxp->mbox_state &= ~STATE_READING;
		if (mailboxp->mbox_state & STATE_HDRVALID) {
			cv_broadcast(&(mailboxp->mbox_wait));
		}
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_getmsg ret: 0x%08x\n", error);
		return (error);
	}

	/*
	 * If the message was read 100% successfully and the stored message
	 * header for the mailbox still matches the message that was read,
	 * invalidate it to prevent other readers from trying to read it.
	 */
	if (bcmp(&(mailboxp->mbox_header), &header, MBOXSC_MSGHDR_SIZE) == 0) {
		mailboxp->mbox_state &= ~STATE_HDRVALID;
	} else if (mailboxp->mbox_state & STATE_HDRVALID) {
		cv_broadcast(&(mailboxp->mbox_wait));
	}

	mboxsc_dereference_mailbox(mailboxp);
	mailboxp->mbox_state &= ~STATE_READING;
	mutex_exit(&mboxsc_lock);

	/*
	 * Since we're successfully returning a message, we need to provide the
	 * caller with all of the interesting header information.
	 */
	*typep = header.msg_type;
	*cmdp = header.msg_cmd;
	*transidp = header.msg_transid;
	*lengthp = datalen;

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_getmsg ret: 0x%08x\n", 0);
	return (0);
}

/*
 * mboxsc_ctrl
 *
 * This routine provides access to a variety of services not available through
 * the basic API.
 */
int
mboxsc_ctrl(uint32_t key, uint32_t cmd, void *arg)
{
	int		error = 0;
	mboxsc_mbox_t	*mailboxp;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_ctrl called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "cmd = 0x%x\n", cmd);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "arg = %p\n", arg);

	mutex_enter(&mboxsc_lock);
	mailboxp = mboxsc_hashfind_mailbox_by_key(key);
	if (mailboxp == NULL) {
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_ctrl ret: 0x%08x\n",
		    EBADF);
		return (EBADF);
	}

	switch (cmd) {
		case MBOXSC_CMD_VERSION:
			/*
			 * Return the Protocol version currently in use.  Since
			 * there is only one version that exists right now, we
			 * can't be using anything else.
			 */
			if (arg == NULL) {
				error = EINVAL;
				break;
			}

			*(uint32_t *)arg = MBOXSC_PROTOCOL_VERSION;
			break;

		case MBOXSC_CMD_MAXVERSION:
			/*
			 * Return the highest Protocol version that we support.
			 */
			if (arg == NULL) {
				error = EINVAL;
				break;
			}

			*(uint32_t *)arg = MBOXSC_PROTOCOL_VERSION;
			break;

		case MBOXSC_CMD_MAXDATALEN:
			/*
			 * Return the amount of space available for client data
			 * in the indicated mailbox.
			 */
			if (arg == NULL) {
				error = EINVAL;
				break;
			}

			*(uint32_t *)arg = mailboxp->mbox_length -
			    MBOXSC_PROTOCOL_SIZE;
			break;

		case MBOXSC_CMD_PUTMSG_TIMEOUT_RANGE:
		{
			mboxsc_timeout_range_t *rangep;

			/*
			 * Return the range of acceptable timeout values for
			 * mboxsc_putmsg, expressed in milliseconds.
			 */
			if (arg == NULL) {
				error = EINVAL;
				break;
			}

			rangep = (mboxsc_timeout_range_t *)arg;
			rangep->min_timeout = MBOXSC_PUTMSG_MIN_TIMEOUT_MSECS;
			rangep->max_timeout = MBOXSC_PUTMSG_MAX_TIMEOUT_MSECS;
			break;
		}

		case MBOXSC_CMD_GETMSG_TIMEOUT_RANGE:
		{
			mboxsc_timeout_range_t *rangep;

			/*
			 * Return the range of acceptable timeout values for
			 * mboxsc_getmsg, expressed in milliseconds.
			 */
			if (arg == NULL) {
				error = EINVAL;
				break;
			}

			rangep = (mboxsc_timeout_range_t *)arg;
			rangep->min_timeout = MBOXSC_GETMSG_MIN_TIMEOUT_MSECS;
			rangep->max_timeout = MBOXSC_GETMSG_MAX_TIMEOUT_MSECS;
			break;
		}

		default:
			error = ENOTSUP;
			break;
	}

	mutex_exit(&mboxsc_lock);
	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_ctrl ret: 0x%08x\n", error);
	return (error);
}

/*
 * mboxsc_putmsg_def_timeout
 *
 * This routine returns the default mboxsc_putmsg timeout provided for the
 * convenience of clients.
 */
clock_t
mboxsc_putmsg_def_timeout(void)
{
	return (MBOXSC_PUTMSG_DEF_TIMEOUT_MSECS);
}

/*
 * mboxsc_iosram_callback
 *
 * This routine is registered with the IOSRAM driver for all inbound mailboxes,
 * and performs preliminary processing of all new messages.
 */
static void
mboxsc_iosram_callback(void *arg)
{
	int		error = 0;
	uint8_t		data_valid;
	uint32_t	key = (uint32_t)(uintptr_t)arg;
	mboxsc_mbox_t	*mailboxp;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_iosram_callback called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "arg = 0x%x\n", key);

	mutex_enter(&mboxsc_lock);
	mailboxp = mboxsc_hashfind_mailbox_by_key(key);

	/*
	 * We shouldn't ever receive a callback for a mailbox that doesn't
	 * exist or for an output mailbox.
	 */
	ASSERT(mailboxp != NULL);
	ASSERT(mailboxp->mbox_direction == MBOXSC_MBOX_IN);

	/*
	 * Attempt to read the header of the mailbox.  If the IOSRAM returns
	 * EAGAIN, indicating a tunnel switch is in progress, do not retry
	 * the operation.
	 */
	mailboxp->mbox_state &= ~STATE_HDRVALID;
	error = iosram_rd(key, MBOXSC_MSGHDR_OFFSET, MBOXSC_MSGHDR_SIZE,
	    (caddr_t)&(mailboxp->mbox_header));

	/*
	 * If somebody sends us a message using a Mailbox Protocol version
	 * greater than the highest one we understand, ignore the message,
	 * because we can't safely interpret anything beyond the version field.
	 */
	if (mailboxp->mbox_header.msg_version > MBOXSC_PROTOCOL_VERSION) {
		error = -1;
		DPRINTF1(DBG_DEV, DBGACT_DEFAULT,
		    "incoming message with unsupported version %d\n",
		    mailboxp->mbox_header.msg_version);
	}

	/*
	 * If this message is a repeat of a previous message (which should
	 * only happen with reply messages), it is conceivable that a client
	 * already executing in mboxsc_getmsg for the previous message could
	 * end up receiving the new message before this callback gets a chance
	 * to execute.  If that happens, the data_valid flag will already have
	 * been cleared.  Call iosram_get_flag to see if that is the case, and
	 * do not process the message if it is.
	 */
	if (error == 0) {
		error = iosram_get_flag(key, &data_valid, NULL);
		if ((error == 0) && (data_valid != IOSRAM_DATA_VALID)) {
			error = -1;
		}
	}

	/*
	 * If the iosram_rd call failed, return.
	 */
	if (error != 0) {
		mutex_exit(&mboxsc_lock);
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_iosram_callback ret (0x%08x)\n", error);
		return;
	}

	/*
	 * If the message read from IOSRAM was unsolicited, invoke
	 * its callback.  Otherwise, wake all threads that are waiting
	 * in mboxsc_getmsg.
	 */
	mailboxp->mbox_state |= STATE_HDRVALID;
	if (IS_UNSOLICITED_TYPE(mailboxp->mbox_header.msg_type) &&
	    (mailboxp->mbox_callback != NULL)) {
		mboxsc_reference_mailbox(mailboxp);
		mutex_exit(&mboxsc_lock);
		(*(mailboxp->mbox_callback))();
		mutex_enter(&mboxsc_lock);
		mboxsc_dereference_mailbox(mailboxp);
	} else {
		cv_broadcast(&(mailboxp->mbox_wait));
	}

	mutex_exit(&mboxsc_lock);

	DPRINTF0(DBG_RETS, DBGACT_DEFAULT, "mboxsc_iosram_callback ret\n");
}

/*
 * mboxsc_hdrchange_callback
 *
 * This routine is registered with the IOSRAM driver to react to any changes SMS
 * makes to the IOSRAM header.
 */
static void
mboxsc_hdrchange_callback(void)
{
	int		error;
	uint32_t	sms_version;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT,
	    "mboxsc_hdrchange_callback called\n");

	error = iosram_hdr_ctrl(IOSRAM_HDRCMD_GET_SMS_MBOX_VER,
	    (void *)&sms_version);
	if (error == 0) {
		DPRINTF1(DBG_DEV, DBGACT_DEFAULT,
		    "sms mailbox version = %d\n", sms_version);
		mboxsc_active_version = MIN(MBOXSC_PROTOCOL_VERSION,
		    sms_version);
	}

	DPRINTF0(DBG_RETS, DBGACT_DEFAULT, "mboxsc_hdrchange_callback ret\n");
}


/*
 * mboxsc_add_mailbox
 *
 * If no other mailbox exists with the same key as this mailbox, attempt to
 * retrieve its length from the IOSRAM driver and register the mboxsc callback
 * for the associated IOSRAM chunk.  If successful, initialize the
 * non-client-supplied mailbox fields and insert it into the hash table.
 * NOTE: The caller MUST hold mboxsc_lock to avoid corrupting the hash table.
 */
static int
mboxsc_add_mailbox(mboxsc_mbox_t *mailboxp)
{
	int		error = 0;
	uint32_t	key = mailboxp->mbox_key;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_add_mailbox called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "mailboxp = %p\n", (void *)mailboxp);

	/*
	 * The global lock must be held by the caller.
	 */
	ASSERT(mutex_owned(&mboxsc_lock));

	/*
	 * Don't create the mailbox if it already exists.
	 */
	if (mboxsc_hashfind_mailbox_by_key(key) != NULL) {
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_add_mailbox ret: 0x%08x\n", EEXIST);
		return (EEXIST);
	}

	/*
	 * Obtain the mailbox length and register the mboxsc callback with the
	 * IOSRAM driver.  If either call to the IOSRAM driver fails, or the
	 * chunk is too small to be used as a mailbox, return an error to the
	 * caller.
	 */
	error = iosram_ctrl(key, IOSRAM_CMD_CHUNKLEN, &(mailboxp->mbox_length));

	if ((error == 0) && (mailboxp->mbox_length < MBOXSC_PROTOCOL_SIZE)) {
		error = EFAULT;
	}

	if ((error == 0) && (mailboxp->mbox_direction == MBOXSC_MBOX_IN)) {
		error = iosram_register(key, mboxsc_iosram_callback,
		    (void *)(uintptr_t)(key));
		if (error == EBUSY) {
			error = EFAULT;
		}
	}

	if (error != 0) {
		DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
		    "mboxsc_add_mailbox ret: 0x%08x\n", error);
		return (error);
	}

	/*
	 * Initialize remaining mailbox fields and insert mailbox into
	 * hash table.
	 */
	mailboxp->mbox_state = STATE_IDLE;
	mailboxp->mbox_refcount = 0;
	cv_init(&(mailboxp->mbox_wait), NULL, CV_DRIVER, NULL);
	mboxsc_hashinsert_mailbox(mailboxp);

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_add_mailbox ret: 0x%08x\n",
	    0);
	return (0);
}

/*
 * mboxsc_close_mailbox
 *
 * Remove a mailbox from the hash table, unregister its IOSRAM callback, and
 * deallocate its resources.
 * NOTE: The caller MUST hold mboxsc_lock to avoid corrupting the hash table.
 */
static void
mboxsc_close_mailbox(mboxsc_mbox_t *mailboxp)
{
	int		error = 0;
	uint32_t	key = mailboxp->mbox_key;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_close_mailbox called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "mailboxp = %p\n", (void *)mailboxp);

	/*
	 * The global lock must be held by the caller.
	 */
	ASSERT(mutex_owned(&mboxsc_lock));

	/*
	 * Unregister the mboxsc callback for this particular mailbox.
	 */
	if (mailboxp->mbox_direction == MBOXSC_MBOX_IN) {
		error = iosram_unregister(key);
		if (error == EINVAL) {
			DPRINTF1(DBG_DEV, DBGACT_DEFAULT, "invalid key (0x%08x)"
			    " reported in mboxsc_close_mailbox.\n", key);
			error = 0;
		}
	}

	/*
	 * Remove the mailbox from the hash table and deallocate its resources.
	 */
	(void) mboxsc_hashremove_mailbox_by_key(key);
	cv_destroy(&(mailboxp->mbox_wait));
	DPRINTF2(DBG_KMEM, DBGACT_DEFAULT, "kmem_free(%p, %lu)\n",
	    (void *)mailboxp, sizeof (mboxsc_mbox_t));
	kmem_free(mailboxp, sizeof (mboxsc_mbox_t));

	DPRINTF0(DBG_RETS, DBGACT_DEFAULT, "mboxsc_close_mailbox ret\n");
}

/*
 * mboxsc_hashinsert_mailbox
 *
 * Insert a fully initialized mailbox into the hash table.  No duplicate
 * checking is performed at this point, so the caller is responsible for
 * duplicate prevention if it is desired.
 * NOTE: The caller MUST hold mboxsc_lock to avoid corrupting the hash table.
 */
static void
mboxsc_hashinsert_mailbox(mboxsc_mbox_t *mailboxp)
{
	uint32_t	hash;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT,
	    "mboxsc_hashinsert_mailbox called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "mailboxp = %p\n", (void *)mailboxp);

	/*
	 * The global lock must be held by the caller.
	 */
	ASSERT(mutex_owned(&mboxsc_lock));

	hash = HASH_KEY(mailboxp->mbox_key);
	mailboxp->mbox_hash_next = mboxsc_hash_table[hash];
	mboxsc_hash_table[hash] = mailboxp;

	DPRINTF0(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_hashinsert_mailbox ret\n");
}

/*
 * mboxsc_hashfind_mailbox_by_key
 *
 * Locate a mailbox with the given key in the hash table.  Return a pointer
 * to the mailbox if it exists, or NULL if no matching mailbox is found.
 * NOTE: The caller MUST hold mboxsc_lock to avoid corrupting the hash table.
 */
static mboxsc_mbox_t *
mboxsc_hashfind_mailbox_by_key(uint32_t key)
{
	uint32_t	hash;
	mboxsc_mbox_t	*mailboxp;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT,
	    "mboxsc_hashfind_mailbox_by_key called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);

	/*
	 * The global lock must be held by the caller.
	 */
	ASSERT(mutex_owned(&mboxsc_lock));

	hash = HASH_KEY(key);
	mailboxp = mboxsc_hash_table[hash];
	while (mailboxp != NULL) {
		if (mailboxp->mbox_key == key) {
			break;
		}
		mailboxp = mailboxp->mbox_hash_next;
	}

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_hashfind_mailbox_by_key ret: %p\n", (void *)mailboxp);
	return (mailboxp);
}

/*
 * mboxsc_hashremove_mailbox_by_key
 *
 * Locate a mailbox with the given key in the hash table.  If it exists,
 * remove it from the hash table and return a pointer to it.  Otherwise,
 * return NULL.
 * NOTE: The caller MUST hold mboxsc_lock to avoid corrupting the hash table.
 */
static mboxsc_mbox_t *
mboxsc_hashremove_mailbox_by_key(uint32_t key)
{
	uint32_t	hash;
	mboxsc_mbox_t	*mailboxp;
	mboxsc_mbox_t	*last;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT,
	    "mboxsc_hashremove_mailbox_by_key called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);

	/*
	 * The global lock must be held by the caller.
	 */
	ASSERT(mutex_owned(&mboxsc_lock));

	hash = HASH_KEY(key);
	mailboxp = mboxsc_hash_table[hash];
	last = NULL;
	while (mailboxp != NULL) {
		if (mailboxp->mbox_key == key) {
			break;
		}
		last = mailboxp;
		mailboxp = mailboxp->mbox_hash_next;
	}

	/*
	 * If a mailbox was found, remove it from the hash table.
	 */
	if (mailboxp != NULL) {
		if (last == NULL) {
			mboxsc_hash_table[hash] = mailboxp->mbox_hash_next;
		} else {
			last->mbox_hash_next = mailboxp->mbox_hash_next;
		}

		mailboxp->mbox_hash_next = NULL;
	}

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_hashremove_mailbox_by_key ret: %p\n", (void *)mailboxp);
	return (mailboxp);
}

/*
 * mboxsc_checksum
 *
 * Given a pointer to a data buffer and its length, calculate the checksum of
 * the data contained therein.
 */
static mboxsc_chksum_t
mboxsc_checksum(mboxsc_chksum_t seed, uint8_t *buf, uint32_t length)
{
	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_checksum called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "seed = 0x%x\n", seed);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "buf = %p\n", (void *)buf);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "length = 0x%x\n", length);

	while (length-- > 0) {
		seed += *(buf++);
	}

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_checksum ret: 0x%08x\n",
	    seed);
	return (seed);
}

/*
 * mboxsc_lock_flags
 *
 * Acquire the hardware lock used for data_valid flag synchronization.  If the
 * lock is currently held by SMS and acquisition is mandatory, just keep on
 * trying until it is acquired.  If acquisition is not mandatory, keep trying
 * until the given deadline has been reached.  To avoid loading the system
 * unreasonably on EBUSY or EAGAIN, sleep for an appropriate amount of time
 * before retrying.  If a hardware error is encountered return it to the caller.
 *
 * If the lock is held, but not by SMS, clear it and acquire it.  Nobody
 * else should be grabbing that lock.
 */
static int
mboxsc_lock_flags(uint8_t mandatory, clock_t deadline)
{
	int		error;
	int		warned = 0;
	uint32_t	sema;
	clock_t		pause;
	clock_t		warning_time = ddi_get_lbolt() + LOOP_WARN_INTERVAL;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_lock_flags called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "mandatory = 0x%x\n", mandatory);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "deadline = 0x%lx\n", deadline);

	/*
	 * Keep trying to acquire the lock until successful or (if acquisition
	 * is not mandatory) time runs out.  If EBUSY (lock is already held) or
	 * EAGAIN (tunnel switch in progress) is encountered, sleep for an
	 * appropriate amount of time before retrying.  Any other error is
	 * unrecoverable.
	 */
	do {
		pause = 0;

		/*
		 * Since multiple threads could conceivably want the flag lock
		 * at the same time, we place the lock under a mutex and keep a
		 * counter indicating how many threads have the flags locked at
		 * the moment.
		 */
		mutex_enter(&mboxsc_lock);
		if ((mboxsc_flaglock_count > 0) ||
		    ((error = iosram_sema_acquire(&sema)) == 0)) {
			mboxsc_flaglock_count++;
			mutex_exit(&mboxsc_lock);

			if (warned) {
				cmn_err(CE_WARN, "Flags locked");
			}
			DPRINTF0(DBG_RETS, DBGACT_DEFAULT,
			    "mboxsc_lock_flags ret: 0\n");
			return (0);
		}

		/*
		 * If iosram_sema_acquire returned EBUSY (lock already held),
		 * make sure the lock is held by SMS, since nobody else should
		 * ever be holding it.  If EBUSY or EAGAIN (tunnel switch in
		 * progress) was returned, determine the appropriate amount of
		 * time to sleep before trying again.
		 */
		if (error == EBUSY) {
			if (IOSRAM_SEMA_GET_IDX(sema) != IOSRAM_SEMA_SMS_IDX) {
				(void) iosram_sema_release();
				cmn_err(CE_WARN,
				    "Incorrect flag lock value read (0x%08x)",
				    sema);
			} else {
				pause = (mandatory ? HWLOCK_POLL :
				    MIN(HWLOCK_POLL, deadline -
				    ddi_get_lbolt()));
			}
		} else if (error == EAGAIN) {
			pause = (mandatory ? EAGAIN_POLL : MIN(EAGAIN_POLL,
			    deadline - ddi_get_lbolt()));
		}

		/*
		 * We had to hold the lock until now to protect the potential
		 * iosram_sema_release call above.
		 */
		mutex_exit(&mboxsc_lock);

		/*
		 * If EAGAIN or EBUSY was encountered, we're looping.
		 */
		if ((error == EAGAIN) || (error == EBUSY)) {
			/*
			 * If we've been looping here for a while, something is
			 * probably wrong, so we should generated a warning.
			 */
			if (warning_time - ddi_get_lbolt() <= 0) {
				if (!warned) {
					warned = 1;
					cmn_err(CE_WARN,
					    "Unable to lock flags (0x%08x)",
					    error);
				} else {
					cmn_err(CE_WARN,
					    "Still unable to lock flags");
				}
				warning_time = ddi_get_lbolt() +
				    LOOP_WARN_INTERVAL;
			}

			/*
			 * Sleep a while before trying again.
			 */
			delay(pause);
		}
	} while (((error == EAGAIN) || (error == EBUSY)) &&
	    (mandatory || (deadline - ddi_get_lbolt() >= 0)));

	/*
	 * If something really bad has happened, generate a warning.
	 */
	if ((error != EAGAIN) && (error != EBUSY)) {
		cmn_err(CE_WARN, "Flag locking failed! (%d)", error);
	}

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_lock_flags ret: 0x%08x\n",
	    error);
	return (error);
}

/*
 * mboxsc_unlock_flags
 *
 * Release the hardware lock used for data_valid flag synchronization.
 * If a hardware error is encountered, return it to the caller.  If the
 * mandatory flag is set, loop and retry if EAGAIN is encountered.
 */
static int
mboxsc_unlock_flags(uint8_t mandatory)
{
	int	error;
	int	warned = 0;
	clock_t	warning_time = ddi_get_lbolt() + LOOP_WARN_INTERVAL;

	ASSERT(mboxsc_flaglock_count != 0);
	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_unlock_flags called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "mandatory = 0x%x\n", mandatory);

	do {
		/*
		 * Since multiple threads could conceivably want the flag lock
		 * at the same time, we place the lock under a mutex and keep a
		 * counter indicating how many threads have the flags locked at
		 * the moment.
		 */
		mutex_enter(&mboxsc_lock);
		if ((mboxsc_flaglock_count > 1) ||
		    ((error = iosram_sema_release()) == 0)) {
			mboxsc_flaglock_count--;
			mutex_exit(&mboxsc_lock);

			if (warned) {
				cmn_err(CE_WARN, "Flags unlocked");
			}
			DPRINTF0(DBG_RETS, DBGACT_DEFAULT,
			    "mboxsc_unlock_flags ret: 0\n");
			return (0);
		}
		mutex_exit(&mboxsc_lock);

		/*
		 * If iosram_sema_release returned EAGAIN (tunnel switch in
		 * progress) and unlocking the flags is mandatory, sleep before
		 * trying again.  If we've been trying for a while, display a
		 * warning message too.
		 */
		if ((error == EAGAIN) && mandatory) {
			if (warning_time - ddi_get_lbolt() <= 0) {
				if (!warned) {
					warned = 1;
					cmn_err(CE_WARN, "Unable to unlock "
					    "flags (iosram EAGAIN)");
				} else {
					cmn_err(CE_WARN,
					    "Still unable to unlock flags");
				}
				warning_time = ddi_get_lbolt() +
				    LOOP_WARN_INTERVAL;
			}

			delay(EAGAIN_POLL);
		}
	} while ((error == EAGAIN) && mandatory);

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_unlock_flags ret: 0x%08x\n",
	    error);
	return (error);
}

/*
 * mboxsc_timed_read
 *
 * This function is just a wrapper around iosram_rd that will keep sleeping
 * and retrying, up to a given deadline, if iosram_rd returns EAGAIN
 * (presumably due to a tunnel switch).
 */
static int
mboxsc_timed_read(clock_t deadline, uint32_t key, uint32_t off, uint32_t len,
	caddr_t dptr)
{
	int error;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_timed_read called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "deadline = 0x%lx\n", deadline);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "off = 0x%x\n", off);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "len = 0x%x\n", len);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "dptr = %p\n", (void *)dptr);

	do {
		error = iosram_rd(key, off, len, dptr);
		if (error == EAGAIN) {
			delay(MIN(EAGAIN_POLL, deadline - ddi_get_lbolt()));
		}
	} while ((error == EAGAIN) && (deadline - ddi_get_lbolt() >= 0));

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_timed_read ret: 0x%08x\n", error);
	return (error);
}

/*
 * mboxsc_timed_write
 *
 * This function is just a wrapper around iosram_wr that will keep sleeping
 * and retrying, up to a given deadline, if iosram_wr returns EAGAIN
 * (presumably due to a tunnel switch).
 */
static int
mboxsc_timed_write(clock_t deadline, uint32_t key, uint32_t off, uint32_t len,
	caddr_t dptr)
{
	int error;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_timed_write called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "deadline = 0x%lx\n", deadline);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "off = 0x%x\n", off);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "len = 0x%x\n", len);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "dptr = %p\n", (void *)dptr);

	do {
		error = iosram_wr(key, off, len, dptr);
		if (error == EAGAIN) {
			delay(MIN(EAGAIN_POLL, deadline - ddi_get_lbolt()));
		}
	} while ((error == EAGAIN) && (deadline - ddi_get_lbolt() >= 0));

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_timed_write ret: 0x%08x\n", error);
	return (error);
}

/*
 * mboxsc_timed_get_flag
 *
 * This function is just a wrapper around iosram_get_flag that will keep
 * sleeping and retrying, up to a given deadline, if iosram_get_flag returns
 * EAGAIN (presumably due to a tunnel switch).
 */
static int
mboxsc_timed_get_flag(clock_t deadline, uint32_t key, uint8_t *data_validp,
	uint8_t *int_pendingp)
{
	int error;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_timed_get_flag called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "deadline = 0x%lx\n", deadline);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "data_validp = %p\n",
	    (void *)data_validp);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "int_pendingp = %p\n",
	    (void *)int_pendingp);

	do {
		error = iosram_get_flag(key, data_validp, int_pendingp);
		if (error == EAGAIN) {
			delay(MIN(EAGAIN_POLL, deadline - ddi_get_lbolt()));
		}
	} while ((error == EAGAIN) && (deadline - ddi_get_lbolt() >= 0));

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_timed_get_flag ret: 0x%08x\n", error);
	return (error);
}

/*
 * mboxsc_timed_set_flag
 *
 * This function is just a wrapper around iosram_set_flag that will keep
 * sleeping and retrying, up to a given deadline, if iosram_set_flag returns
 * EAGAIN (presumably due to a tunnel switch).
 */
static int
mboxsc_timed_set_flag(clock_t deadline, uint32_t key, uint8_t data_valid,
	uint8_t int_pending)
{
	int error;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_timed_set_flag called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "deadline = 0x%lx\n", deadline);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "data_valid = %d\n", data_valid);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "int_pending = %d\n", int_pending);

	do {
		error = iosram_set_flag(key, data_valid, int_pending);
		if (error == EAGAIN) {
			delay(MIN(EAGAIN_POLL, deadline - ddi_get_lbolt()));
		}
	} while ((error == EAGAIN) && (deadline - ddi_get_lbolt() >= 0));

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_timed_set_flag ret: 0x%08x\n", error);
	return (error);
}

/*
 * mboxsc_timed_send_intr
 *
 * This function is just a wrapper around iosram_send_intr that will keep
 * sleeping and retrying, up to a given deadline, if iosram_send_intr returns
 * EAGAIN (presumably due to a tunnel switch).
 */
static int
mboxsc_timed_send_intr(clock_t deadline)
{
	int error;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_timed_send_intr called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "deadline = 0x%lx\n", deadline);

	do {
		error = iosram_send_intr();
		if (error == DDI_FAILURE) {
			delay(MIN(EAGAIN_POLL, deadline - ddi_get_lbolt()));
		}
	} while ((error == DDI_FAILURE) && (deadline - ddi_get_lbolt() >= 0));

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_timed_send_intr ret: 0x%08x\n", error);
	return (error);
}

/*
 * mboxsc_expire_message
 *
 * This function is called by mboxsc_putmsg to handle expiration of messages
 * that weren't picked up before they timed out.  It will not return until the
 * message has been picked up (which isn't expected), the message has been
 * successfully expired, or a serious error has been encountered.  If the
 * message is finally picked up, it will set the value pointed to by "resultp"
 * to 0.  Unlike other sections of code, this function will never time out on
 * EAGAIN from the iosram driver, since it is important that both sides of the
 * IOSRAM agree on whether or not a message was delivered successfully.
 */
static int
mboxsc_expire_message(uint32_t key, int *resultp)
{
	int	error = 0;
	int	lock_held = 0;
	int	warned = 0;
	uint8_t	data_valid;
	clock_t	warning_time = ddi_get_lbolt() + LOOP_WARN_INTERVAL;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_expire_message called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%x\n", key);
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "resultp = %p\n", (void *)resultp);

	do {
		error = 0;

		/*
		 * Lock the flags if they aren't locked already.
		 */
		if (!lock_held) {
			error = mboxsc_lock_flags(TRUE, 0);
			if (error == 0) {
				lock_held = 1;
			}
		}

		/*
		 * If the flags were locked successfully, reread the data-valid
		 * flag.
		 */
		if (error == 0) {
			error = iosram_get_flag(key, &data_valid, NULL);
		}

		/*
		 * If the data-valid flag was read successfully, see if it has
		 * been cleared or not, as the other side may have finally read
		 * the message.
		 */
		if (error == 0) {
			if (data_valid == IOSRAM_DATA_INVALID) {
				/*
				 * Surprise!  The SC finally picked up the
				 * message, so delivery succeeded after all.
				 */
				if (*resultp == ETIMEDOUT) {
					*resultp = 0;
				}
			} else {
				/*
				 * The message still hasn't been read, so try to
				 * clear the data-valid flag.
				 */
				error = iosram_set_flag(key,
				    IOSRAM_DATA_INVALID, IOSRAM_INT_NONE);
			}
		}

		/*
		 * If the flags were locked, unlock them, no matter what else
		 * has or has not succeeded.  Don't overwrite the existing value
		 * of "error" unless no errors other than EAGAIN have been
		 * encountered previously.  If we hit EAGAIN at some point,
		 * unlocking the flags here is optional.  In all other cases, it
		 * is mandatory.
		 */
		if (lock_held) {
			int unlock_err;

			if (error == EAGAIN) {
				unlock_err = mboxsc_unlock_flags(FALSE);
			} else {
				unlock_err = mboxsc_unlock_flags(TRUE);
			}

			if (unlock_err == 0) {
				lock_held = 0;
			} else if ((error == 0) || (error == EAGAIN)) {
				error = unlock_err;
			}
		}

		/*
		 * Did we hit a tunnel switch? (iosram driver returns EAGAIN)
		 * If so, sleep for a while before trying the whole process
		 * again.
		 */
		if (error == EAGAIN) {
			/*
			 * If we've been stuck in this loop for a while,
			 * something is probably wrong, and we should display a
			 * warning.
			 */
			if (warning_time - ddi_get_lbolt() <= 0) {
				if (!warned) {
					warned = 1;
					cmn_err(CE_WARN, "Unable to clear flag "
					    "(iosram EAGAIN)");
				} else {
					cmn_err(CE_WARN,
					    "Still unable to clear flag");
				}
				warning_time = ddi_get_lbolt() +
				    LOOP_WARN_INTERVAL;
			}

			delay(EAGAIN_POLL);
		}
	} while (error == EAGAIN);

	/*
	 * If the data-valid flag was not successfully cleared due to some sort
	 * of problem, report it.  Otherwise, if we looped for a while on EAGAIN
	 * and generated a warning about it, indicate that everything is okay
	 * now.
	 */
	if (error != 0) {
		cmn_err(CE_WARN, "Message expiration failure! (%d)", error);
	} else if (warned) {
		cmn_err(CE_WARN, "Flag cleared");
	}

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_expire_message ret: 0x%08x\n", error);
	return (error);
}


/*
 * mboxsc_generate_transid
 *
 * This function generates unique transaction IDs using an incrementing counter.
 * The value generated is guaranteed not to be the same as the prev_transid
 * value passed in by the caller.
 */
static uint64_t
mboxsc_generate_transid(uint64_t prev_transid)
{
	uint64_t	new_transid;
	static uint64_t	transid_counter = 0;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_generate_transid called");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "prev_transid = 0x%016lx\n",
	    prev_transid);

	do {
		new_transid = TRANSID_GEN_MASK | transid_counter++;
		if (transid_counter & TRANSID_GEN_MASK) {
			transid_counter = 0;
		}
	} while (new_transid == prev_transid);

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "mboxsc_generate_transid ret: 0x%016lx", new_transid);
	return (new_transid);
}


/*
 * mboxsc_reference_mailbox
 *
 * Increment the mailbox's reference count to prevent it from being closed.
 * This really doesn't deserve to be a function, but since a dereference
 * function is needed, having a corresponding reference function makes the code
 * clearer.
 */
static void
mboxsc_reference_mailbox(mboxsc_mbox_t *mailboxp)
{
	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_reference_mailbox called");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "mailboxp = 0x%p\n",
	    (void *)mailboxp);

	ASSERT(mutex_owned(&mboxsc_lock));

	mailboxp->mbox_refcount++;

	DPRINTF0(DBG_RETS, DBGACT_DEFAULT, "mboxsc_reference_mailbox ret");
}


/*
 * mboxsc_dereference_mailbox
 *
 * Decrement the mailbox's reference count, and if the count has gone to zero,
 * signal any threads waiting for mailboxes to be completely dereferenced.
 */
static void
mboxsc_dereference_mailbox(mboxsc_mbox_t *mailboxp)
{
	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT,
	    "mboxsc_dereference_mailbox called");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "mailboxp = 0x%p\n",
	    (void *)mailboxp);

	ASSERT(mutex_owned(&mboxsc_lock));

	mailboxp->mbox_refcount--;
	if (mailboxp->mbox_refcount == 0) {
		cv_broadcast(&mboxsc_dereference_cv);
	}

	DPRINTF0(DBG_RETS, DBGACT_DEFAULT, "mboxsc_dereference_mailbox ret");
}


#ifndef DEBUG
/* ARGSUSED */
int
mboxsc_debug(int cmd, void *arg)
{
	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_debug called");
	DPRINTF0(DBG_RETS, DBGACT_DEFAULT, "mboxsc_debug ret");
	return (ENOTSUP);
}
#else	/* DEBUG */

static void	print_hash_table(void);
static int	print_mailbox_by_key(uint32_t key);
static void	print_mailbox(mboxsc_mbox_t *mailboxp);

int
mboxsc_debug(int cmd, void *arg)
{
	int		error = 0;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "mboxsc_debug called\n");

	switch (cmd) {
		case MBOXSC_PRNMBOX:
			error = print_mailbox_by_key((uint32_t)(uintptr_t)arg);
			break;

		case MBOXSC_PRNHASHTBL:
			print_hash_table();
			break;

		case MBOXSC_SETDBGMASK:
			mboxsc_debug_mask = (uint32_t)(uintptr_t)arg;
			break;

		default:
			DPRINTF1(DBG_DEV, DBGACT_DEFAULT,
			    "Error: unknown mboxsc debug cmd (%d)\n", cmd);
			error = ENOTTY;
			break;
	}

	DPRINTF1(DBG_RETS, DBGACT_DEFAULT, "mboxsc_debug ret: 0x%08x\n", error);

	return (error);
}

/*PRINTFLIKE5*/
static void
mboxsc_dprintf(
	const char	*file,
	int		line,
	uint32_t	class,
	uint32_t	action,
	const char	*fmt,
	...)
{
	int		i;
	char		indent_buf[64];
	char		msg_buf[256];
	va_list		adx;
	static uint32_t	indent = 0;

	if (action & DBGACT_SHOWPOS) {
		cmn_err(CE_CONT, "%s at line %d:\n", file, line);
	}

	if (class & DBG_RETS) {
		indent--;
	}

	if (class & mboxsc_debug_mask) {
		indent_buf[0] = '\0';
		for (i = 0; i < indent; i++) {
			(void) strcat(indent_buf, "  ");
		}

		va_start(adx, fmt);
		(void) vsprintf(msg_buf, fmt, adx);
		va_end(adx);

		cmn_err(CE_CONT, "%s%s", indent_buf, msg_buf);
	}

	if (class & DBG_CALLS) {
		indent++;
	}

	if (action & DBGACT_BREAK) {
		debug_enter("");
	}
}

static void
print_hash_table(void)
{
	int		i;
	mboxsc_mbox_t	*mailboxp;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "print_hash_table called\n");

	mutex_enter(&mboxsc_lock);

	for (i = 0; i < HASHTBL_SIZE; i++) {
		DPRINTF1(DBG_DEV, DBGACT_DEFAULT, "hash[%02d]:\n", i);

		for (mailboxp = mboxsc_hash_table[i]; mailboxp != NULL;
		    mailboxp = mailboxp->mbox_hash_next) {
			DPRINTF2(DBG_DEV, DBGACT_DEFAULT,
			    "    key: 0x%08x, dir: %d\n", mailboxp->mbox_key,
			    mailboxp->mbox_direction);
		}
	}

	mutex_exit(&mboxsc_lock);

	DPRINTF0(DBG_RETS, DBGACT_DEFAULT, "print_hash_table ret\n");
}

static int
print_mailbox_by_key(uint32_t key)
{
	int		error = 0;
	mboxsc_mbox_t	*mailboxp;

	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "print_mailbox_by_key called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "key = 0x%08x\n", key);

	mutex_enter(&mboxsc_lock);

	mailboxp = mboxsc_hashfind_mailbox_by_key(key);
	if (mailboxp != NULL) {
		print_mailbox(mailboxp);
		error = 0;
	} else {
		DPRINTF1(DBG_DEV, DBGACT_DEFAULT,
		    "print_mailbox_by_key: no such mbox 0x%08x\n", key);
		error = EBADF;
	}

	mutex_exit(&mboxsc_lock);
	DPRINTF1(DBG_RETS, DBGACT_DEFAULT,
	    "print_mailbox_by_key ret: 0x%08x\n", error);

	return (error);
}

/* ARGSUSED */
static void
print_mailbox(mboxsc_mbox_t *mailboxp)
{
	DPRINTF0(DBG_CALLS, DBGACT_DEFAULT, "print_mailbox called\n");
	DPRINTF1(DBG_ARGS, DBGACT_DEFAULT, "mailboxp = %p\n",
	    (void *)mailboxp);
	if (mailboxp->mbox_direction == MBOXSC_MBOX_IN) {
		DPRINTF3(DBG_DEV, DBGACT_DEFAULT,
		    "key = 0x%08x, dir = %d, callback = %p\n",
		    mailboxp->mbox_key, mailboxp->mbox_direction,
		    (void *)mailboxp->mbox_callback);
	} else {
		DPRINTF2(DBG_DEV, DBGACT_DEFAULT, "key = 0x%08x, dir = %d\n",
		    (int)mailboxp->mbox_key, mailboxp->mbox_direction);
	}
	DPRINTF3(DBG_DEV, DBGACT_DEFAULT,
	    "length = %d, refcount = %d, state = %d\n",
	    mailboxp->mbox_length, mailboxp->mbox_refcount,
	    mailboxp->mbox_state);
	/* LINTED E_BAD_FORMAT_ARG_TYPE2 */
	DPRINTF2(DBG_DEV, DBGACT_DEFAULT, "waitcv = %p, hashnext = %p\n",
	    (void *)&mailboxp->mbox_wait, (void *)mailboxp->mbox_hash_next);
	if (mailboxp->mbox_direction == MBOXSC_MBOX_IN) {
		DPRINTF3(DBG_DEV, DBGACT_DEFAULT,
		    "hdr.type = 0x%x, hdr.cmd = 0x%x, hdr.len = 0x%x\n",
		    mailboxp->mbox_header.msg_type,
		    mailboxp->mbox_header.msg_cmd,
		    mailboxp->mbox_header.msg_length);
		DPRINTF1(DBG_DEV, DBGACT_DEFAULT, "hdr.tid = 0x%016lx\n",
		    mailboxp->mbox_header.msg_transid);
	}
	DPRINTF0(DBG_RETS, DBGACT_DEFAULT, "print_mailbox ret\n");
}
#endif	/* DEBUG */
