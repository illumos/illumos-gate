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

/*
 * Driver for Virtual Disk.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/t_lock.h>
#include <sys/dkio.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/vtoc.h>
#include <sys/open.h>
#include <sys/file.h>
#include <vm/page.h>
#include <sys/callb.h>
#include <sys/disp.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/door.h>
#include <sys/lvm/mdmn_commd.h>
#include <sys/lvm/md_hotspares.h>

#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_names.h>

#include <sys/ddi.h>
#include <sys/proc.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>

#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>

#include <sys/sysevent/svm.h>
#include <sys/lvm/md_basic.h>


/*
 * Machine specific Hertz is kept here
 */
extern clock_t			md_hz;

/*
 * Externs.
 */
extern int			(*mdv_strategy_tstpnt)(buf_t *, int, void*);
extern major_t			md_major;
extern unit_t			md_nunits;
extern set_t			md_nsets;
extern md_set_t			md_set[];
extern md_set_io_t		md_set_io[];
extern md_ops_t			**md_ops;
extern md_ops_t			*md_opslist;
extern ddi_modhandle_t		*md_mods;

extern md_krwlock_t		md_unit_array_rw;
extern kmutex_t			md_mx;
extern kcondvar_t		md_cv;

extern md_krwlock_t		hsp_rwlp;
extern md_krwlock_t		ni_rwlp;

extern int			md_num_daemons;
extern int			md_status;
extern int			md_ioctl_cnt;
extern int			md_mtioctl_cnt;

extern struct metatransops	metatransops;
extern md_event_queue_t		*md_event_queue;
extern md_resync_t		md_cpr_resync;
extern int			md_done_daemon_threads;
extern int			md_ff_daemon_threads;


extern mddb_set_t	*mddb_setenter(set_t setno, int flag, int *errorcodep);
extern void		mddb_setexit(mddb_set_t *s);
extern void		*lookup_entry(struct nm_next_hdr *, set_t,
				side_t, mdkey_t, md_dev64_t, int);
extern struct nm_next_hdr	*get_first_record(set_t, int, int);

struct mdq_anchor	md_done_daemon; /* done request queue */
struct mdq_anchor	md_mstr_daemon; /* mirror timeout requests */
struct mdq_anchor	md_mhs_daemon;	/* mirror hotspare requests queue */
struct mdq_anchor	md_hs_daemon;	/* raid hotspare requests queue */
struct mdq_anchor	md_ff_daemonq;	/* failfast request queue */
struct mdq_anchor	md_mirror_daemon; /* mirror owner queue */
struct mdq_anchor	md_mirror_io_daemon; /* mirror owner i/o queue */
struct mdq_anchor	md_mirror_rs_daemon; /* mirror resync done queue */
struct mdq_anchor	md_sp_daemon;	/* soft-part error daemon queue */

int md_done_daemon_threads = 1;	/* threads for md_done_daemon requestq */
int md_mstr_daemon_threads = 1;	/* threads for md_mstr_daemon requestq */
int md_mhs_daemon_threads = 1;	/* threads for md_mhs_daemon requestq */
int md_hs_daemon_threads = 1;	/* threads for md_hs_daemon requestq */
int md_ff_daemon_threads = 3;	/* threads for md_ff_daemon requestq */
int md_mirror_daemon_threads = 1; /* threads for md_mirror_daemon requestq */
int md_sp_daemon_threads = 1;	/* threads for md_sp_daemon requestq */

#ifdef DEBUG
/* Flag to switch on debug messages */
int md_release_reacquire_debug = 0;	/* debug flag */
#endif

/*
 *
 * The md_request_queues is table of pointers to request queues and the number
 * of threads associated with the request queues.
 * When the number of threads is set to 1, then the order of execution is
 * sequential.
 * The number of threads for all the queues have been defined as global
 * variables to enable kernel tuning.
 *
 */

#define	MD_DAEMON_QUEUES 10

md_requestq_entry_t md_daemon_queues[MD_DAEMON_QUEUES] = {
	{&md_done_daemon, &md_done_daemon_threads},
	{&md_mstr_daemon, &md_mstr_daemon_threads},
	{&md_hs_daemon, &md_hs_daemon_threads},
	{&md_ff_daemonq, &md_ff_daemon_threads},
	{&md_mirror_daemon, &md_mirror_daemon_threads},
	{&md_mirror_io_daemon, &md_mirror_daemon_threads},
	{&md_mirror_rs_daemon, &md_mirror_daemon_threads},
	{&md_sp_daemon, &md_sp_daemon_threads},
	{&md_mhs_daemon, &md_mhs_daemon_threads},
	{0, 0}
};

/*
 * Number of times a message is retried before issuing a warning to the operator
 */
#define	MD_MN_WARN_INTVL	10

/*
 * Setting retry cnt to one (pre decremented) so that we actually do no
 * retries when committing/deleting a mddb rec. The underlying disk driver
 * does several retries to check if the disk is really dead or not so there
 * is no reason for us to retry on top of the drivers retries.
 */

uint_t			md_retry_cnt = 1; /* global so it can be patched */

/*
 * Bug # 1212146
 * Before this change the user had to pass in a short aligned buffer because of
 * problems in some underlying device drivers.  This problem seems to have been
 * corrected in the underlying drivers so we will default to not requiring any
 * alignment.  If the user needs to check for a specific alignment,
 * md_uio_alignment_mask may be set in /etc/system to accomplish this.  To get
 * the behavior before this fix, the md_uio_alignment_mask would be set to 1,
 * to check for word alignment, it can be set to 3, for double word alignment,
 * it can be set to 7, etc.
 *
 * [Other part of fix is in function md_chk_uio()]
 */
static int		md_uio_alignment_mask = 0;

/*
 * for md_dev64_t translation
 */
struct md_xlate_table		*md_tuple_table;
struct md_xlate_major_table	*md_major_tuple_table;
int				md_tuple_length;
uint_t				md_majortab_len;

/* Function declarations */

static int md_create_probe_rqlist(md_probedev_impl_t *plist,
			daemon_queue_t **hdr, intptr_t (*probe_test)());

/*
 * manipulate global status
 */
void
md_set_status(int bits)
{
	mutex_enter(&md_mx);
	md_status |= bits;
	mutex_exit(&md_mx);
}

void
md_clr_status(int bits)
{
	mutex_enter(&md_mx);
	md_status &= ~bits;
	mutex_exit(&md_mx);
}

int
md_get_status()
{
	int result;
	mutex_enter(&md_mx);
	result = md_status;
	mutex_exit(&md_mx);
	return (result);
}

void
md_set_setstatus(set_t setno, int bits)
{
	ASSERT(setno != MD_SET_BAD && setno < MD_MAXSETS);

	mutex_enter(&md_mx);
	md_set[setno].s_status |= bits;
	mutex_exit(&md_mx);
}

void
md_clr_setstatus(set_t setno, int bits)
{
	ASSERT(setno != MD_SET_BAD && setno < MD_MAXSETS);

	mutex_enter(&md_mx);
	md_set[setno].s_status &= ~bits;
	mutex_exit(&md_mx);
}

uint_t
md_get_setstatus(set_t setno)
{
	uint_t result;

	ASSERT(setno != MD_SET_BAD && setno < MD_MAXSETS);

	mutex_enter(&md_mx);
	result = md_set[setno].s_status;
	mutex_exit(&md_mx);
	return (result);
}

/*
 * md_unit_readerlock_common:
 * -------------------------
 * Mark the given unit as having a reader reference. Spin waiting for any
 * writer references to be released.
 *
 * Input:
 *	ui		unit reference
 *	lock_held	0 => ui_mx needs to be grabbed
 *			1 => ui_mx already held
 * Output:
 *	mm_unit_t corresponding to unit structure
 *	ui->ui_readercnt incremented
 */
static void *
md_unit_readerlock_common(mdi_unit_t *ui, int lock_held)
{
	uint_t	flag = MD_UL_WRITER | MD_UL_WANABEWRITER;

	if (!lock_held)
		mutex_enter(&ui->ui_mx);
	while (ui->ui_lock & flag) {
		if (panicstr) {
			if (ui->ui_lock & MD_UL_WRITER)
				panic("md: writer lock is held");
			break;
		}
		cv_wait(&ui->ui_cv, &ui->ui_mx);
	}
	ui->ui_readercnt++;
	if (!lock_held)
		mutex_exit(&ui->ui_mx);
	return (MD_UNIT(ui->ui_link.ln_id));
}

void *
md_unit_readerlock(mdi_unit_t *ui)
{
	return (md_unit_readerlock_common(ui, 0));
}

/*
 * md_unit_writerlock_common:
 * -------------------------
 * Acquire a unique writer reference. Causes previous readers to drain.
 * Spins if a writer reference already exists or if a previous reader/writer
 * dropped the lock to allow a ksend_message to be despatched.
 *
 * Input:
 *	ui		unit reference
 *	lock_held	0 => grab ui_mx
 *			1 => ui_mx already held on entry
 * Output:
 *	mm_unit_t reference
 */
static void *
md_unit_writerlock_common(mdi_unit_t *ui, int lock_held)
{
	uint_t	flag = MD_UL_WRITER;

	if (panicstr)
		panic("md: writer lock not allowed");

	if (!lock_held)
		mutex_enter(&ui->ui_mx);

	while ((ui->ui_lock & flag) || (ui->ui_readercnt != 0)) {
		ui->ui_wanabecnt++;
		ui->ui_lock |= MD_UL_WANABEWRITER;
		cv_wait(&ui->ui_cv, &ui->ui_mx);
		if (--ui->ui_wanabecnt == 0)
			ui->ui_lock &= ~MD_UL_WANABEWRITER;
	}
	ui->ui_lock |= MD_UL_WRITER;
	ui->ui_owner = curthread;

	if (!lock_held)
		mutex_exit(&ui->ui_mx);
	return (MD_UNIT(ui->ui_link.ln_id));
}

void *
md_unit_writerlock(mdi_unit_t *ui)
{
	return (md_unit_writerlock_common(ui, 0));
}

/*
 * md_unit_readerexit_common:
 * -------------------------
 * Release the readerlock for the specified unit. If the reader count reaches
 * zero and there are waiting writers (MD_UL_WANABEWRITER set) wake them up.
 *
 * Input:
 *	ui		unit reference
 *	lock_held	0 => ui_mx needs to be acquired
 *			1 => ui_mx already held
 */
static void
md_unit_readerexit_common(mdi_unit_t *ui, int lock_held)
{
	if (!lock_held)
		mutex_enter(&ui->ui_mx);
	ASSERT((ui->ui_lock & MD_UL_WRITER) == 0);
	ASSERT(ui->ui_readercnt != 0);
	ui->ui_readercnt--;
	if ((ui->ui_wanabecnt != 0) && (ui->ui_readercnt == 0))
		cv_broadcast(&ui->ui_cv);

	if (!lock_held)
		mutex_exit(&ui->ui_mx);
}

void
md_unit_readerexit(mdi_unit_t *ui)
{
	md_unit_readerexit_common(ui, 0);
}

/*
 * md_unit_writerexit_common:
 * -------------------------
 * Release the writerlock currently held on the unit. Wake any threads waiting
 * on becoming reader or writer (MD_UL_WANABEWRITER set).
 *
 * Input:
 *	ui		unit reference
 *	lock_held	0 => ui_mx to be acquired
 *			1 => ui_mx already held
 */
static void
md_unit_writerexit_common(mdi_unit_t *ui, int lock_held)
{
	if (!lock_held)
		mutex_enter(&ui->ui_mx);
	ASSERT((ui->ui_lock & MD_UL_WRITER) != 0);
	ASSERT(ui->ui_readercnt == 0);
	ui->ui_lock &= ~MD_UL_WRITER;
	ui->ui_owner = NULL;

	cv_broadcast(&ui->ui_cv);
	if (!lock_held)
		mutex_exit(&ui->ui_mx);
}

void
md_unit_writerexit(mdi_unit_t *ui)
{
	md_unit_writerexit_common(ui, 0);
}

void *
md_io_readerlock(mdi_unit_t *ui)
{
	md_io_lock_t	*io = ui->ui_io_lock;

	ASSERT(io);  /* checks case where no io lock allocated */
	mutex_enter(&io->io_mx);
	while (io->io_lock & (MD_UL_WRITER | MD_UL_WANABEWRITER)) {
		if (panicstr) {
			if (io->io_lock & MD_UL_WRITER)
				panic("md: writer lock is held");
			break;
		}
		cv_wait(&io->io_cv, &io->io_mx);
	}
	io->io_readercnt++;
	mutex_exit(&io->io_mx);
	return (MD_UNIT(ui->ui_link.ln_id));
}

void *
md_io_writerlock(mdi_unit_t *ui)
{
	md_io_lock_t	*io = ui->ui_io_lock;

	ASSERT(io);  /* checks case where no io lock allocated */
	if (panicstr)
		panic("md: writer lock not allowed");

	mutex_enter(&io->io_mx);
	while ((io->io_lock & MD_UL_WRITER) || (io->io_readercnt != 0)) {
		io->io_wanabecnt++;
		io->io_lock |= MD_UL_WANABEWRITER;
		cv_wait(&io->io_cv, &io->io_mx);
		if (--io->io_wanabecnt == 0)
			io->io_lock &= ~MD_UL_WANABEWRITER;
	}
	io->io_lock |= MD_UL_WRITER;
	io->io_owner = curthread;

	mutex_exit(&io->io_mx);
	return (MD_UNIT(ui->ui_link.ln_id));
}

void
md_io_readerexit(mdi_unit_t *ui)
{
	md_io_lock_t	*io = ui->ui_io_lock;

	mutex_enter(&io->io_mx);
	ASSERT((io->io_lock & MD_UL_WRITER) == 0);
	ASSERT(io->io_readercnt != 0);
	io->io_readercnt--;
	if ((io->io_wanabecnt != 0) && (io->io_readercnt == 0)) {
		cv_broadcast(&io->io_cv);
	}
	mutex_exit(&io->io_mx);
}

void
md_io_writerexit(mdi_unit_t *ui)
{
	md_io_lock_t	*io = ui->ui_io_lock;

	mutex_enter(&io->io_mx);
	ASSERT((io->io_lock & MD_UL_WRITER) != 0);
	ASSERT(io->io_readercnt == 0);
	io->io_lock &= ~MD_UL_WRITER;
	io->io_owner = NULL;

	cv_broadcast(&io->io_cv);
	mutex_exit(&io->io_mx);
}

/*
 * Attempt to grab that set of locks defined as global.
 * A mask containing the set of global locks that are owned upon
 * entry is input.  Any additional global locks are then grabbed.
 * This keeps the caller from having to know the set of global
 * locks.
 */
static int
md_global_lock_enter(int global_locks_owned_mask)
{

	/*
	 * The current implementation has been verified by inspection
	 * and test to be deadlock free.  If another global lock is
	 * added, changing the algorithm used by this function should
	 * be considered.  With more than 2 locks it is difficult to
	 * guarantee that locks are being acquired in the correct order.
	 * The safe approach would be to drop all of the locks that are
	 * owned at function entry and then reacquire all of the locks
	 * in the order defined by the lock hierarchy.
	 */
	mutex_enter(&md_mx);
	if (!(global_locks_owned_mask & MD_GBL_IOCTL_LOCK)) {
		while ((md_mtioctl_cnt != 0) ||
		    (md_status & MD_GBL_IOCTL_LOCK)) {
			if (cv_wait_sig_swap(&md_cv, &md_mx) == 0) {
				mutex_exit(&md_mx);
				return (EINTR);
			}
		}
		md_status |= MD_GBL_IOCTL_LOCK;
		md_ioctl_cnt++;
	}
	if (!(global_locks_owned_mask & MD_GBL_HS_LOCK)) {
		while (md_status & MD_GBL_HS_LOCK) {
			if (cv_wait_sig_swap(&md_cv, &md_mx) == 0) {
				md_status &= ~MD_GBL_IOCTL_LOCK;
				mutex_exit(&md_mx);
				return (EINTR);
			}
		}
		md_status |= MD_GBL_HS_LOCK;
	}
	mutex_exit(&md_mx);
	return (0);
}

/*
 * Release the set of global locks that were grabbed in md_global_lock_enter
 * that were not already owned by the calling thread.  The set of previously
 * owned global locks is passed in as a mask parameter.
 */
static int
md_global_lock_exit(int global_locks_owned_mask, int code,
	int flags, mdi_unit_t *ui)
{
	mutex_enter(&md_mx);

	/* If MT ioctl decrement mt_ioctl_cnt */
	if ((flags & MD_MT_IOCTL)) {
		md_mtioctl_cnt--;
	} else {
		if (!(global_locks_owned_mask & MD_GBL_IOCTL_LOCK)) {
			/* clear the lock and decrement count */
			ASSERT(md_ioctl_cnt == 1);
			md_ioctl_cnt--;
			md_status &= ~MD_GBL_IOCTL_LOCK;
		}
		if (!(global_locks_owned_mask & MD_GBL_HS_LOCK))
			md_status &= ~MD_GBL_HS_LOCK;
	}
	if (flags & MD_READER_HELD)
		md_unit_readerexit(ui);
	if (flags & MD_WRITER_HELD)
		md_unit_writerexit(ui);
	if (flags & MD_IO_HELD)
		md_io_writerexit(ui);
	if (flags & (MD_ARRAY_WRITER | MD_ARRAY_READER)) {
		rw_exit(&md_unit_array_rw.lock);
	}
	cv_broadcast(&md_cv);
	mutex_exit(&md_mx);

	return (code);
}

/*
 * The two functions, md_ioctl_lock_enter, and md_ioctl_lock_exit make
 * use of the md_global_lock_{enter|exit} functions to avoid duplication
 * of code.  They rely upon the fact that the locks that are specified in
 * the input mask are not acquired or freed.  If this algorithm changes
 * as described in the block comment at the beginning of md_global_lock_enter
 * then it will be necessary to change these 2 functions.  Otherwise these
 * functions will be grabbing and holding global locks unnecessarily.
 */
int
md_ioctl_lock_enter(void)
{
	/* grab only the ioctl lock */
	return (md_global_lock_enter(~MD_GBL_IOCTL_LOCK));
}

/*
 * If md_ioctl_lock_exit is being called at the end of an ioctl before
 * returning to user space, then ioctl_end is set to 1.
 * Otherwise, the ioctl lock is being dropped in the middle of handling
 * an ioctl and will be reacquired before the end of the ioctl.
 * Do not attempt to process the MN diskset mddb parse flags unless
 * ioctl_end is true - otherwise a deadlock situation could arise.
 */
int
md_ioctl_lock_exit(int code, int flags, mdi_unit_t *ui, int ioctl_end)
{
	int				ret_val;
	uint_t				status;
	mddb_set_t			*s;
	int				i;
	int				err;
	md_mn_msg_mddb_parse_t		*mddb_parse_msg;
	md_mn_kresult_t			*kresult;
	mddb_lb_t			*lbp;
	int				rval = 1;
	int				flag;

	/* release only the ioctl lock */
	ret_val = md_global_lock_exit(~MD_GBL_IOCTL_LOCK, code, flags, ui);

	/*
	 * If md_ioctl_lock_exit is being called with a possible lock held
	 * (ioctl_end is 0), then don't check the MN disksets since the
	 * call to mddb_setenter may cause a lock ordering deadlock.
	 */
	if (!ioctl_end)
		return (ret_val);

	/*
	 * Walk through disksets to see if there is a MN diskset that
	 * has messages that need to be sent.  Set must be snarfed and
	 * be a MN diskset in order to be checked.
	 *
	 * In a MN diskset, this routine may send messages to the
	 * rpc.mdcommd in order to have the slave nodes re-parse parts
	 * of the mddb.  Messages can only be sent with no locks held,
	 * so if mddb change occurred while the ioctl lock is held, this
	 * routine must send the messages.
	 */
	for (i = 1; i < md_nsets; i++) {
		status = md_get_setstatus(i);

		/* Set must be snarfed and be a MN diskset */
		if ((status & (MD_SET_SNARFED | MD_SET_MNSET)) !=
		    (MD_SET_SNARFED | MD_SET_MNSET))
			continue;

		/* Grab set lock so that set can't change */
		if ((s = mddb_setenter(i, MDDB_MUSTEXIST, &err)) == NULL)
			continue;

		lbp = s->s_lbp;

		/* Re-get set status now that lock is held */
		status = md_get_setstatus(i);

		/*
		 * If MN parsing block flag is set - continue to next set.
		 *
		 * If s_mn_parseflags_sending is non-zero, then another thread
		 * is already currently sending a parse message, so just
		 * release the set mutex.  If this ioctl had caused an mddb
		 * change that results in a parse message to be generated,
		 * the thread that is currently sending a parse message would
		 * generate the additional parse message.
		 *
		 * If s_mn_parseflags_sending is zero then loop until
		 * s_mn_parseflags is 0 (until there are no more
		 * messages to send).
		 * While s_mn_parseflags is non-zero,
		 *	put snapshot of parse_flags in s_mn_parseflags_sending
		 *	set s_mn_parseflags to zero
		 *	release set mutex
		 *	send message
		 *	re-grab set mutex
		 *	set s_mn_parseflags_sending to zero
		 *
		 * If set is STALE, send message with NO_LOG flag so that
		 * rpc.mdcommd won't attempt to log message to non-writeable
		 * replica.
		 */
		mddb_parse_msg = kmem_zalloc(sizeof (md_mn_msg_mddb_parse_t),
		    KM_SLEEP);
		while (((s->s_mn_parseflags_sending & MDDB_PARSE_MASK) == 0) &&
		    (s->s_mn_parseflags & MDDB_PARSE_MASK) &&
		    (!(status & MD_SET_MNPARSE_BLK))) {

			/* Grab snapshot of parse flags */
			s->s_mn_parseflags_sending = s->s_mn_parseflags;
			s->s_mn_parseflags = 0;

			mutex_exit(&md_set[(s)->s_setno].s_dbmx);

			/*
			 * Send the message to the slaves to re-parse
			 * the indicated portions of the mddb. Send the status
			 * of the 50 mddbs in this set so that slaves know
			 * which mddbs that the master node thinks are 'good'.
			 * Otherwise, slave may reparse, but from wrong
			 * replica.
			 */
			mddb_parse_msg->msg_parse_flags =
			    s->s_mn_parseflags_sending;

			for (i = 0; i < MDDB_NLB; i++) {
				mddb_parse_msg->msg_lb_flags[i] =
				    lbp->lb_locators[i].l_flags;
			}
			kresult = kmem_zalloc(sizeof (md_mn_kresult_t),
			    KM_SLEEP);
			while (rval != 0) {
				flag = 0;
				if (status & MD_SET_STALE)
					flag |= MD_MSGF_NO_LOG;
				rval = mdmn_ksend_message(s->s_setno,
				    MD_MN_MSG_MDDB_PARSE, flag,
				    (char *)mddb_parse_msg,
				    sizeof (mddb_parse_msg), kresult);
				/* if the node hasn't yet joined, it's Ok. */
				if ((!MDMN_KSEND_MSG_OK(rval, kresult)) &&
				    (kresult->kmmr_comm_state !=
				    MDMNE_NOT_JOINED)) {
					mdmn_ksend_show_error(rval, kresult,
					    "MD_MN_MSG_MDDB_PARSE");
					cmn_err(CE_WARN, "md_ioctl_lock_exit: "
					    "Unable to send mddb update "
					    "message to other nodes in "
					    "diskset %s\n", s->s_setname);
					rval = 1;
				}
			}
			kmem_free(kresult, sizeof (md_mn_kresult_t));

			/*
			 * Re-grab mutex to clear sending field and to
			 * see if another parse message needs to be generated.
			 */
			mutex_enter(&md_set[(s)->s_setno].s_dbmx);
			s->s_mn_parseflags_sending = 0;
		}
		kmem_free(mddb_parse_msg, sizeof (md_mn_msg_mddb_parse_t));
		mutex_exit(&md_set[(s)->s_setno].s_dbmx);
	}
	return (ret_val);
}

/*
 * Called when in an ioctl and need readerlock.
 */
void *
md_ioctl_readerlock(IOLOCK *lock, mdi_unit_t *ui)
{
	ASSERT(lock != NULL);
	lock->l_ui = ui;
	lock->l_flags |= MD_READER_HELD;
	return (md_unit_readerlock_common(ui, 0));
}

/*
 * Called when in an ioctl and need writerlock.
 */
void *
md_ioctl_writerlock(IOLOCK *lock, mdi_unit_t *ui)
{
	ASSERT(lock != NULL);
	lock->l_ui = ui;
	lock->l_flags |= MD_WRITER_HELD;
	return (md_unit_writerlock_common(ui, 0));
}

void *
md_ioctl_io_lock(IOLOCK *lock, mdi_unit_t *ui)
{
	ASSERT(lock != NULL);
	lock->l_ui = ui;
	lock->l_flags |= MD_IO_HELD;
	return (md_io_writerlock(ui));
}

void
md_ioctl_readerexit(IOLOCK *lock)
{
	ASSERT(lock != NULL);
	lock->l_flags &= ~MD_READER_HELD;
	md_unit_readerexit(lock->l_ui);
}

void
md_ioctl_writerexit(IOLOCK *lock)
{
	ASSERT(lock != NULL);
	lock->l_flags &= ~MD_WRITER_HELD;
	md_unit_writerexit(lock->l_ui);
}

void
md_ioctl_io_exit(IOLOCK *lock)
{
	ASSERT(lock != NULL);
	lock->l_flags &= ~MD_IO_HELD;
	md_io_writerexit(lock->l_ui);
}

/*
 * md_ioctl_releaselocks:
 * --------------------
 * Release the unit locks that are held and stop subsequent
 * md_unit_reader/writerlock calls from progressing. This allows the caller
 * to send messages across the cluster when running in a multinode
 * environment.
 * ioctl originated locks (via md_ioctl_readerlock/md_ioctl_writerlock) are
 * allowed to progress as normal. This is required as these typically are
 * invoked by the message handler that may be called while a unit lock is
 * marked as released.
 *
 * On entry:
 *	variety of unit locks may be held including ioctl lock
 *
 * On exit:
 *      locks released and unit structure updated to prevent subsequent reader/
 *      writer locks being acquired until md_ioctl_reacquirelocks is called
 */
void
md_ioctl_releaselocks(int code, int flags, mdi_unit_t *ui)
{
	/* This actually releases the locks. */
	(void) md_global_lock_exit(~MD_GBL_IOCTL_LOCK, code, flags, ui);
}

/*
 * md_ioctl_reacquirelocks:
 * ----------------------
 * Reacquire the locks that were held when md_ioctl_releaselocks
 * was called.
 *
 * On entry:
 *      No unit locks held
 * On exit:
 *	locks held that were held at md_ioctl_releaselocks time including
 *	the ioctl lock.
 */
void
md_ioctl_reacquirelocks(int flags, mdi_unit_t *ui)
{
	if (flags & MD_MT_IOCTL) {
		mutex_enter(&md_mx);
		md_mtioctl_cnt++;
		mutex_exit(&md_mx);
	} else {
		while (md_ioctl_lock_enter() == EINTR)
			;
	}
	if (flags & MD_ARRAY_WRITER) {
		rw_enter(&md_unit_array_rw.lock, RW_WRITER);
	} else if (flags & MD_ARRAY_READER) {
		rw_enter(&md_unit_array_rw.lock, RW_READER);
	}
	if (ui != (mdi_unit_t *)NULL) {
		if (flags & MD_IO_HELD) {
			(void) md_io_writerlock(ui);
		}

		mutex_enter(&ui->ui_mx);
		if (flags & MD_READER_HELD) {
			(void) md_unit_readerlock_common(ui, 1);
		} else if (flags & MD_WRITER_HELD) {
			(void) md_unit_writerlock_common(ui, 1);
		}
		/* Wake up any blocked readerlock() calls */
		cv_broadcast(&ui->ui_cv);
		mutex_exit(&ui->ui_mx);
	}
}

void
md_ioctl_droplocks(IOLOCK *lock)
{
	mdi_unit_t	*ui;
	int		flags;

	ASSERT(lock != NULL);
	ui = lock->l_ui;
	flags = lock->l_flags;
	if (flags & MD_READER_HELD) {
		lock->l_flags &= ~MD_READER_HELD;
		md_unit_readerexit(ui);
	}
	if (flags & MD_WRITER_HELD) {
		lock->l_flags &= ~MD_WRITER_HELD;
		md_unit_writerexit(ui);
	}
	if (flags & MD_IO_HELD) {
		lock->l_flags &= ~MD_IO_HELD;
		md_io_writerexit(ui);
	}
	if (flags & (MD_ARRAY_WRITER | MD_ARRAY_READER)) {
		lock->l_flags &= ~(MD_ARRAY_WRITER | MD_ARRAY_READER);
		rw_exit(&md_unit_array_rw.lock);
	}
}

void
md_array_writer(IOLOCK *lock)
{
	ASSERT(lock != NULL);
	lock->l_flags |= MD_ARRAY_WRITER;
	rw_enter(&md_unit_array_rw.lock, RW_WRITER);
}

void
md_array_reader(IOLOCK *lock)
{
	ASSERT(lock != NULL);
	lock->l_flags |= MD_ARRAY_READER;
	rw_enter(&md_unit_array_rw.lock, RW_READER);
}

/*
 * Called when in an ioctl and need opencloselock.
 * Sets flags in lockp for READER_HELD.
 */
void *
md_ioctl_openclose_enter(IOLOCK *lockp, mdi_unit_t *ui)
{
	void	*un;

	ASSERT(lockp != NULL);
	mutex_enter(&ui->ui_mx);
	while (ui->ui_lock & MD_UL_OPENORCLOSE)
		cv_wait(&ui->ui_cv, &ui->ui_mx);
	ui->ui_lock |= MD_UL_OPENORCLOSE;

	/* Maintain mutex across the readerlock call */
	lockp->l_ui = ui;
	lockp->l_flags |= MD_READER_HELD;
	un = md_unit_readerlock_common(ui, 1);
	mutex_exit(&ui->ui_mx);

	return (un);
}

/*
 * Clears reader lock using md_ioctl instead of md_unit
 * and updates lockp.
 */
void
md_ioctl_openclose_exit(IOLOCK *lockp)
{
	mdi_unit_t	*ui;

	ASSERT(lockp != NULL);
	ui = lockp->l_ui;
	ASSERT(ui->ui_lock & MD_UL_OPENORCLOSE);

	md_ioctl_readerexit(lockp);

	mutex_enter(&ui->ui_mx);
	ui->ui_lock &= ~MD_UL_OPENORCLOSE;

	cv_broadcast(&ui->ui_cv);
	mutex_exit(&ui->ui_mx);
}

/*
 * Clears reader lock using md_ioctl instead of md_unit
 * and updates lockp.
 * Does not acquire or release the ui_mx lock since the calling
 * routine has already acquired this lock.
 */
void
md_ioctl_openclose_exit_lh(IOLOCK *lockp)
{
	mdi_unit_t	*ui;

	ASSERT(lockp != NULL);
	ui = lockp->l_ui;
	ASSERT(ui->ui_lock & MD_UL_OPENORCLOSE);

	lockp->l_flags &= ~MD_READER_HELD;
	md_unit_readerexit_common(lockp->l_ui, 1);

	ui->ui_lock &= ~MD_UL_OPENORCLOSE;
	cv_broadcast(&ui->ui_cv);
}

void *
md_unit_openclose_enter(mdi_unit_t *ui)
{
	void	*un;

	mutex_enter(&ui->ui_mx);
	while (ui->ui_lock & (MD_UL_OPENORCLOSE))
		cv_wait(&ui->ui_cv, &ui->ui_mx);
	ui->ui_lock |= MD_UL_OPENORCLOSE;

	/* Maintain mutex across the readerlock call */
	un = md_unit_readerlock_common(ui, 1);
	mutex_exit(&ui->ui_mx);

	return (un);
}

void
md_unit_openclose_exit(mdi_unit_t *ui)
{
	md_unit_readerexit(ui);

	mutex_enter(&ui->ui_mx);
	ASSERT(ui->ui_lock & MD_UL_OPENORCLOSE);
	ui->ui_lock &= ~MD_UL_OPENORCLOSE;

	cv_broadcast(&ui->ui_cv);
	mutex_exit(&ui->ui_mx);
}

/*
 * Drop the openclose and readerlocks without acquiring or
 * releasing the ui_mx lock since the calling routine has
 * already acquired this lock.
 */
void
md_unit_openclose_exit_lh(mdi_unit_t *ui)
{
	md_unit_readerexit_common(ui, 1);
	ASSERT(ui->ui_lock & MD_UL_OPENORCLOSE);
	ui->ui_lock &= ~MD_UL_OPENORCLOSE;
	cv_broadcast(&ui->ui_cv);
}

int
md_unit_isopen(
	mdi_unit_t	*ui
)
{
	int		isopen;

	/* check status */
	mutex_enter(&ui->ui_mx);
	isopen = ((ui->ui_lock & MD_UL_OPEN) ? 1 : 0);
	mutex_exit(&ui->ui_mx);
	return (isopen);
}

int
md_unit_incopen(
	minor_t		mnum,
	int		flag,
	int		otyp
)
{
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	int		err = 0;

	/* check type and flags */
	ASSERT(ui != NULL);
	mutex_enter(&ui->ui_mx);
	if ((otyp < 0) || (otyp >= OTYPCNT)) {
		err = EINVAL;
		goto out;
	}
	if (((flag & FEXCL) && (ui->ui_lock & MD_UL_OPEN)) ||
	    (ui->ui_lock & MD_UL_EXCL)) {
		err = EBUSY;
		goto out;
	}

	/* count and flag open */
	ui->ui_ocnt[otyp]++;
	ui->ui_lock |= MD_UL_OPEN;
	if (flag & FEXCL)
		ui->ui_lock |= MD_UL_EXCL;

	/* setup kstat, return success */
	mutex_exit(&ui->ui_mx);
	md_kstat_init(mnum);
	return (0);

	/* return error */
out:
	mutex_exit(&ui->ui_mx);
	return (err);
}

int
md_unit_decopen(
	minor_t		mnum,
	int		otyp
)
{
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	int		err = 0;
	unsigned	i;

	/* check type and flags */
	ASSERT(ui != NULL);
	mutex_enter(&ui->ui_mx);
	if ((otyp < 0) || (otyp >= OTYPCNT)) {
		err = EINVAL;
		goto out;
	} else if (ui->ui_ocnt[otyp] == 0) {
		err = ENXIO;
		goto out;
	}

	/* count and flag closed */
	if (otyp == OTYP_LYR)
		ui->ui_ocnt[otyp]--;
	else
		ui->ui_ocnt[otyp] = 0;
	ui->ui_lock &= ~MD_UL_OPEN;
	for (i = 0; (i < OTYPCNT); ++i)
		if (ui->ui_ocnt[i] != 0)
			ui->ui_lock |= MD_UL_OPEN;
	if (! (ui->ui_lock & MD_UL_OPEN))
		ui->ui_lock &= ~MD_UL_EXCL;

	/* teardown kstat, return success */
	if (! (ui->ui_lock & MD_UL_OPEN)) {
		mutex_exit(&ui->ui_mx);
		md_kstat_destroy(mnum);
		return (0);
	}

	/* return success */
out:
	mutex_exit(&ui->ui_mx);
	return (err);
}

md_dev64_t
md_xlate_targ_2_mini(md_dev64_t targ_devt)
{
	dev32_t		mini_32_devt, targ_32_devt;
	int		i;

	/*
	 * check to see if we're in an upgrade situation
	 * if we are not in upgrade just return the input device
	 */

	if (!MD_UPGRADE)
		return (targ_devt);

	targ_32_devt = md_cmpldev(targ_devt);

	i = 0;
	while (i != md_tuple_length) {
		if (md_tuple_table[i].targ_devt == targ_32_devt) {
			mini_32_devt = md_tuple_table[i].mini_devt;
			return (md_expldev((md_dev64_t)mini_32_devt));
		}
		i++;
	}
	return (NODEV64);
}

md_dev64_t
md_xlate_mini_2_targ(md_dev64_t mini_devt)
{
	dev32_t		mini_32_devt, targ_32_devt;
	int		i;

	if (!MD_UPGRADE)
		return (mini_devt);

	mini_32_devt = md_cmpldev(mini_devt);

	i = 0;
	while (i != md_tuple_length) {
		if (md_tuple_table[i].mini_devt == mini_32_devt) {
			targ_32_devt = md_tuple_table[i].targ_devt;
			return (md_expldev((md_dev64_t)targ_32_devt));
		}
		i++;
	}
	return (NODEV64);
}

void
md_xlate_free(int size)
{
	kmem_free(md_tuple_table, size);
}

char *
md_targ_major_to_name(major_t maj)
{
	char *drv_name = NULL;
	int	i;

	if (!MD_UPGRADE)
		return (ddi_major_to_name(maj));

	for (i = 0; i < md_majortab_len; i++) {
		if (md_major_tuple_table[i].targ_maj == maj) {
			drv_name = md_major_tuple_table[i].drv_name;
			break;
		}
	}
	return (drv_name);
}

major_t
md_targ_name_to_major(char *drv_name)
{
	major_t maj;
	int	i;

	maj = md_getmajor(NODEV64);
	if (!MD_UPGRADE)
		return (ddi_name_to_major(drv_name));

	for (i = 0; i < md_majortab_len; i++) {
		if ((strcmp(md_major_tuple_table[i].drv_name,
		    drv_name)) == 0) {
			maj = md_major_tuple_table[i].targ_maj;
			break;
		}
	}

	return (maj);
}

void
md_majortab_free()
{
	size_t	sz;
	int	i;

	for (i = 0; i < md_majortab_len; i++) {
		freestr(md_major_tuple_table[i].drv_name);
	}

	sz = md_majortab_len * sizeof (struct md_xlate_major_table);
	kmem_free(md_major_tuple_table, sz);
}

/* functions return a pointer to a function which returns an int */

intptr_t (*
md_get_named_service(md_dev64_t dev, int modindex, char *name,
	intptr_t (*Default)()))()
{
	mdi_unit_t		*ui;
	md_named_services_t	*sp;
	int			i;

	/*
	 * Return the first named service found.
	 * Use this path when it is known that there is only
	 * one named service possible (e.g., hotspare interface)
	 */
	if ((dev == NODEV64) && (modindex == ANY_SERVICE)) {
		for (i = 0; i < MD_NOPS; i++) {
			if (md_ops[i] == NULL) {
				continue;
			}
			sp = md_ops[i]->md_services;
			if (sp == NULL)
				continue;
			while (sp->md_service != NULL) {
				if (strcmp(name, sp->md_name) == 0)
					return (sp->md_service);
				sp++;
			}
		}
		return (Default);
	}

	/*
	 * Return the named service for the given modindex.
	 * This is used if there are multiple possible named services
	 * and each one needs to be called (e.g., poke hotspares)
	 */
	if (dev == NODEV64) {
		if (modindex >= MD_NOPS)
			return (Default);

		if (md_ops[modindex] == NULL)
			return (Default);

		sp = md_ops[modindex]->md_services;
		if (sp == NULL)
			return (Default);

		while (sp->md_service != NULL) {
			if (strcmp(name, sp->md_name) == 0)
				return (sp->md_service);
			sp++;
		}
		return (Default);
	}

	/*
	 * Return the named service for this md_dev64_t
	 */
	if (md_getmajor(dev) != md_major)
		return (Default);

	if ((MD_MIN2SET(md_getminor(dev)) >= md_nsets) ||
	    (MD_MIN2UNIT(md_getminor(dev)) >= md_nunits))
		return (NULL);


	if ((ui = MDI_UNIT(md_getminor(dev))) == NULL)
		return (NULL);

	sp = md_ops[ui->ui_opsindex]->md_services;
	if (sp == NULL)
		return (Default);
	while (sp->md_service != NULL) {
		if (strcmp(name, sp->md_name) == 0)
			return (sp->md_service);
		sp++;
	}
	return (Default);
}

/*
 * md_daemon callback routine
 */
boolean_t
callb_md_cpr(void *arg, int code)
{
	callb_cpr_t *cp = (callb_cpr_t *)arg;
	int ret = 0;				/* assume success */

	mutex_enter(cp->cc_lockp);

	switch (code) {
	case CB_CODE_CPR_CHKPT:
		/*
		 * Check for active resync threads
		 */
		mutex_enter(&md_cpr_resync.md_resync_mutex);
		if ((md_cpr_resync.md_mirror_resync > 0) ||
		    (md_cpr_resync.md_raid_resync > 0)) {
			mutex_exit(&md_cpr_resync.md_resync_mutex);
			cmn_err(CE_WARN, "There are Solaris Volume Manager "
			    "synchronization threads running.");
			cmn_err(CE_WARN, "Please try system suspension at "
			    "a later time.");
			ret = -1;
			break;
		}
		mutex_exit(&md_cpr_resync.md_resync_mutex);

		cp->cc_events |= CALLB_CPR_START;
		while (!(cp->cc_events & CALLB_CPR_SAFE))
			/* cv_timedwait() returns -1 if it times out. */
			if ((ret = cv_timedwait(&cp->cc_callb_cv, cp->cc_lockp,
			    lbolt + CPR_KTHREAD_TIMEOUT_SEC * hz)) == -1)
				break;
			break;

	case CB_CODE_CPR_RESUME:
		cp->cc_events &= ~CALLB_CPR_START;
		cv_signal(&cp->cc_stop_cv);
		break;
	}
	mutex_exit(cp->cc_lockp);
	return (ret != -1);
}

void
md_daemon(int pass_thru, mdq_anchor_t *anchor)
{
	daemon_queue_t  *dq;
	callb_cpr_t	cprinfo;

	if (pass_thru && (md_get_status() & MD_GBL_DAEMONS_LIVE))
		return;
	/*
	 * Register cpr callback
	 */
	CALLB_CPR_INIT(&cprinfo, &anchor->a_mx, callb_md_cpr, "md_daemon");

	/*CONSTCOND*/
	while (1) {
		mutex_enter(&anchor->a_mx);
		while ((dq = anchor->dq.dq_next) == &(anchor->dq)) {
			if (pass_thru) {
				/*
				 * CALLB_CPR_EXIT Will do
				 * mutex_exit(&anchor->a_mx)
				 */
				CALLB_CPR_EXIT(&cprinfo);
				return;
			}
			if (md_get_status() & MD_GBL_DAEMONS_DIE) {
				mutex_exit(&anchor->a_mx);
				mutex_enter(&md_mx);
				md_num_daemons--;
				mutex_exit(&md_mx);
				/*
				 * CALLB_CPR_EXIT will do
				 * mutex_exit(&anchor->a_mx)
				 */
				mutex_enter(&anchor->a_mx);
				CALLB_CPR_EXIT(&cprinfo);
				thread_exit();
			}
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&anchor->a_cv, &anchor->a_mx);
			CALLB_CPR_SAFE_END(&cprinfo, &anchor->a_mx);
		}
		dq->dq_prev->dq_next = dq->dq_next;
		dq->dq_next->dq_prev = dq->dq_prev;
		dq->dq_prev = dq->dq_next = NULL;
		anchor->dq.qlen--;
		mutex_exit(&anchor->a_mx);
		(*(dq->dq_call))(dq);
	}
	/*NOTREACHED*/
}

/*
 * daemon_request:
 *
 * Adds requests to appropriate requestq which is
 * anchored by *anchor.
 * The request is the first element of a doubly linked circular list.
 * When the request is a single element, the forward and backward
 * pointers MUST point to the element itself.
 */

void
daemon_request(mdq_anchor_t *anchor, void (*func)(),
				daemon_queue_t *request, callstyle_t style)
{
	daemon_queue_t *rqtp;
	int i = 0;

	rqtp = request;
	if (style == REQ_OLD) {
		ASSERT((rqtp->dq_next == NULL) && (rqtp->dq_prev == NULL));
		/* set it to the new style */
		rqtp->dq_prev = rqtp->dq_next = rqtp;
	}
	ASSERT((rqtp->dq_next != NULL) && (rqtp->dq_prev != NULL));

	/* scan the list and add the function to each element */

	do {
		rqtp->dq_call = func;
		i++;
		rqtp = rqtp->dq_next;
	} while (rqtp != request);

	/* save pointer to tail of the request list */
	rqtp = request->dq_prev;

	mutex_enter(&anchor->a_mx);
	/* stats */
	anchor->dq.qlen += i;
	anchor->dq.treqs += i;
	anchor->dq.maxq_len = (anchor->dq.qlen > anchor->dq.maxq_len) ?
	    anchor->dq.qlen : anchor->dq.maxq_len;

	/* now add the list to request queue */
	request->dq_prev = anchor->dq.dq_prev;
	rqtp->dq_next = &anchor->dq;
	anchor->dq.dq_prev->dq_next = request;
	anchor->dq.dq_prev = rqtp;
	cv_broadcast(&anchor->a_cv);
	mutex_exit(&anchor->a_mx);
}

void
mddb_commitrec_wrapper(mddb_recid_t recid)
{
	int sent_log = 0;
	uint_t retry = md_retry_cnt;
	set_t	setno;

	while (mddb_commitrec(recid)) {
		if (! sent_log) {
			cmn_err(CE_WARN,
			    "md: state database commit failed");
			sent_log = 1;
		}
		delay(md_hz);

		/*
		 * Setting retry cnt to one (pre decremented) so that we
		 * actually do no retries when committing/deleting a mddb rec.
		 * The underlying disk driver does several retries to check
		 * if the disk is really dead or not so there
		 * is no reason for us to retry on top of the drivers retries.
		 */

		if (--retry == 0) {
			setno = mddb_getsetnum(recid);
			if (md_get_setstatus(setno) & MD_SET_TOOFEW) {
				panic(
				    "md: Panic due to lack of DiskSuite state\n"
				    " database replicas. Fewer than 50%% of "
				    "the total were available,\n so panic to "
				    "ensure data integrity.");
			} else {
				panic("md: state database problem");
			}
			/*NOTREACHED*/
		}
	}
}

void
mddb_commitrecs_wrapper(mddb_recid_t *recids)
{
	int sent_log = 0;
	uint_t retry = md_retry_cnt;
	set_t	setno;

	while (mddb_commitrecs(recids)) {
		if (! sent_log) {
			cmn_err(CE_WARN,
			    "md: state database commit failed");
			sent_log = 1;
		}
		delay(md_hz);

		/*
		 * Setting retry cnt to one (pre decremented) so that we
		 * actually do no retries when committing/deleting a mddb rec.
		 * The underlying disk driver does several retries to check
		 * if the disk is really dead or not so there
		 * is no reason for us to retry on top of the drivers retries.
		 */

		if (--retry == 0) {
			/*
			 * since all the records are part of the same set
			 * use the first one to get setno
			 */
			setno = mddb_getsetnum(*recids);
			if (md_get_setstatus(setno) & MD_SET_TOOFEW) {
				panic(
				    "md: Panic due to lack of DiskSuite state\n"
				    " database replicas. Fewer than 50%% of "
				    "the total were available,\n so panic to "
				    "ensure data integrity.");
			} else {
				panic("md: state database problem");
			}
			/*NOTREACHED*/
		}
	}
}

void
mddb_deleterec_wrapper(mddb_recid_t recid)
{
	int sent_log = 0;
	uint_t retry = md_retry_cnt;
	set_t	setno;

	while (mddb_deleterec(recid)) {
		if (! sent_log) {
			cmn_err(CE_WARN,
			    "md: state database delete failed");
			sent_log = 1;
		}
		delay(md_hz);

		/*
		 * Setting retry cnt to one (pre decremented) so that we
		 * actually do no retries when committing/deleting a mddb rec.
		 * The underlying disk driver does several retries to check
		 * if the disk is really dead or not so there
		 * is no reason for us to retry on top of the drivers retries.
		 */

		if (--retry == 0) {
			setno = mddb_getsetnum(recid);
			if (md_get_setstatus(setno) & MD_SET_TOOFEW) {
				panic(
				    "md: Panic due to lack of DiskSuite state\n"
				    " database replicas. Fewer than 50%% of "
				    "the total were available,\n so panic to "
				    "ensure data integrity.");
			} else {
				panic("md: state database problem");
			}
			/*NOTREACHED*/
		}
	}
}

/*
 * md_holdset_enter is called in order to hold the set in its
 * current state (loaded, unloaded, snarfed, unsnarfed, etc)
 * until md_holdset_exit is called.  This is used by the mirror
 * code to mark the set as HOLD so that the set won't be
 * unloaded while hotspares are being allocated in check_4_hotspares.
 * The original fix to the mirror code to hold the set was to call
 * md_haltsnarf_enter, but this will block all ioctls and ioctls
 * must work for a MN diskset while hotspares are allocated.
 */
void
md_holdset_enter(set_t setno)
{
	mutex_enter(&md_mx);
	while (md_set[setno].s_status & MD_SET_HOLD)
		cv_wait(&md_cv, &md_mx);
	md_set[setno].s_status |= MD_SET_HOLD;
	mutex_exit(&md_mx);
}

void
md_holdset_exit(set_t setno)
{
	mutex_enter(&md_mx);
	md_set[setno].s_status &= ~MD_SET_HOLD;
	cv_broadcast(&md_cv);
	mutex_exit(&md_mx);
}

/*
 * Returns a 0 if this thread marked the set as HOLD (success),
 * returns a -1 if set was already marked HOLD (failure).
 * Used by the release_set code to see if set is marked HOLD.
 * HOLD is set by a daemon when hotspares are being allocated
 * to mirror units.
 */
int
md_holdset_testandenter(set_t setno)
{
	mutex_enter(&md_mx);
	if (md_set[setno].s_status & MD_SET_HOLD) {
		mutex_exit(&md_mx);
		return (-1);
	}
	md_set[setno].s_status |= MD_SET_HOLD;
	mutex_exit(&md_mx);
	return (0);
}

void
md_haltsnarf_enter(set_t setno)
{
	mutex_enter(&md_mx);
	while (md_set[setno].s_status & MD_SET_SNARFING)
		cv_wait(&md_cv, &md_mx);

	md_set[setno].s_status |= MD_SET_SNARFING;
	mutex_exit(&md_mx);
}

void
md_haltsnarf_exit(set_t setno)
{
	mutex_enter(&md_mx);
	md_set[setno].s_status &= ~MD_SET_SNARFING;
	cv_broadcast(&md_cv);
	mutex_exit(&md_mx);
}

void
md_haltsnarf_wait(set_t setno)
{
	mutex_enter(&md_mx);
	while (md_set[setno].s_status & MD_SET_SNARFING)
		cv_wait(&md_cv, &md_mx);
	mutex_exit(&md_mx);
}

/*
 * ASSUMED that the md_unit_array_rw WRITER lock is held.
 */
int
md_halt_set(set_t setno, enum md_haltcmd cmd)
{
	int	i, err;

	if (md_set[setno].s_un == NULL || md_set[setno].s_ui == NULL) {
		return (0);
	}

	if ((cmd == MD_HALT_CHECK) || (cmd == MD_HALT_ALL)) {
		for (i = 0; i < MD_NOPS; i++) {
			if (md_ops[i] == NULL)
				continue;
			if ((*(md_ops[i]->md_halt))(MD_HALT_CLOSE, setno)) {
				for (--i; i > 0; --i) {
					if (md_ops[i] == NULL)
						continue;
					(void) (*(md_ops[i]->md_halt))
					    (MD_HALT_OPEN, setno);
				}
				return (EBUSY);
			}
		}

		for (i = 0; i < MD_NOPS; i++) {
			if (md_ops[i] == NULL)
				continue;
			if ((*(md_ops[i]->md_halt))(MD_HALT_CHECK, setno)) {
				for (i = 0; i < MD_NOPS; i++) {
					if (md_ops[i] == NULL)
						continue;
					(void) (*(md_ops[i]->md_halt))
					    (MD_HALT_OPEN, setno);
				}
				return (EBUSY);
			}
		}
	}

	if ((cmd == MD_HALT_DOIT) || (cmd == MD_HALT_ALL)) {
		for (i = 0; i < MD_NOPS; i++) {
			if (md_ops[i] == NULL)
				continue;
			err = (*(md_ops[i]->md_halt))(MD_HALT_DOIT, setno);
			if (err != 0)
				cmn_err(CE_NOTE,
				    "md: halt failed for %s, error %d",
				    md_ops[i]->md_driver.md_drivername, err);
		}

		/*
		 * Unload the devid namespace if it is loaded
		 */
		md_unload_namespace(setno, NM_DEVID);
		md_unload_namespace(setno, 0L);
		md_clr_setstatus(setno, MD_SET_SNARFED);
	}

	return (0);
}

int
md_halt(int global_locks_owned_mask)
{
	set_t			i, j;
	int			err;
	int			init_queues;
	md_requestq_entry_t	*rqp;
	md_ops_t		**pops, *ops, *lops;
	ddi_modhandle_t		mod;
	char			*name;

	rw_enter(&md_unit_array_rw.lock, RW_WRITER);

	/*
	 * Grab the all of the global locks that are not
	 * already owned to ensure that there isn't another
	 * thread trying to access a global resource
	 * while the halt is in progress
	 */
	if (md_global_lock_enter(global_locks_owned_mask) == EINTR)
		return (EINTR);

	for (i = 0; i < md_nsets; i++)
		md_haltsnarf_enter(i);

	/*
	 * Kill the daemon threads.
	 */
	init_queues = ((md_get_status() & MD_GBL_DAEMONS_LIVE) ? FALSE : TRUE);
	md_clr_status(MD_GBL_DAEMONS_LIVE);
	md_set_status(MD_GBL_DAEMONS_DIE);

	rqp = &md_daemon_queues[0];
	i = 0;
	while (!NULL_REQUESTQ_ENTRY(rqp)) {
		cv_broadcast(&rqp->dispq_headp->a_cv);
		rqp = &md_daemon_queues[++i];
	}

	mutex_enter(&md_mx);
	while (md_num_daemons != 0) {
		mutex_exit(&md_mx);
		delay(md_hz);
		mutex_enter(&md_mx);
	}
	mutex_exit(&md_mx);
	md_clr_status(MD_GBL_DAEMONS_DIE);

	for (i = 0; i < md_nsets; i++)
		/*
		 * Only call into md_halt_set if s_un / s_ui are both set.
		 * If they are NULL this set hasn't been accessed, so its
		 * pointless performing the call.
		 */
		if (md_set[i].s_un != NULL && md_set[i].s_ui != NULL) {
			if (md_halt_set(i, MD_HALT_CHECK)) {
				if (md_start_daemons(init_queues))
					cmn_err(CE_WARN,
					    "md: restart of daemon threads "
					    "failed");
				for (j = 0; j < md_nsets; j++)
					md_haltsnarf_exit(j);

				return (md_global_lock_exit(
				    global_locks_owned_mask, EBUSY,
				    MD_ARRAY_WRITER, NULL));
			}
		}

	/*
	 * if we get here we are going to do it
	 */
	for (i = 0; i < md_nsets; i++) {
		/*
		 * Only call into md_halt_set if s_un / s_ui are both set.
		 * If they are NULL this set hasn't been accessed, so its
		 * pointless performing the call.
		 */
		if (md_set[i].s_un != NULL && md_set[i].s_ui != NULL) {
			err = md_halt_set(i, MD_HALT_DOIT);
			if (err != 0)
				cmn_err(CE_NOTE,
				    "md: halt failed set %u, error %d",
				    (unsigned)i, err);
		}
	}

	/*
	 * issue a halt unload to each module to indicate that it
	 * is about to be unloaded.  Each module is called once, set
	 * has no meaning at this point in time.
	 */
	for (i = 0; i < MD_NOPS; i++) {
		if (md_ops[i] == NULL)
			continue;
		err = (*(md_ops[i]->md_halt))(MD_HALT_UNLOAD, 0);
		if (err != 0)
			cmn_err(CE_NOTE,
			    "md: halt failed for %s, error %d",
			    md_ops[i]->md_driver.md_drivername, err);
	}

	/* ddi_modclose the submodules */
	for (i = 0; i < MD_NOPS; i++) {
		/* skip if not open */
		if ((md_ops[i] == NULL) || (md_mods[i] == NULL))
			continue;

		/* find and unlink from md_opslist */
		ops = md_ops[i];
		mod = md_mods[i];
		pops = &md_opslist;
		for (lops = *pops; lops;
		    pops = &lops->md_next, lops = *pops) {
			if (lops == ops) {
				*pops = ops->md_next;
				ops->md_next = NULL;
				break;
			}
		}

		/* uninitialize */
		name = ops->md_driver.md_drivername;
		md_ops[i] = NULL;
		md_mods[i] = NULL;
		ops->md_selfindex = 0;
		ops->md_driver.md_drivername[0] = '\0';
		rw_destroy(&ops->md_link_rw.lock);

		/* close */
		err = ddi_modclose(mod);
		if (err != 0)
			cmn_err(CE_NOTE,
			    "md: halt close failed for %s, error %d",
			    name ? name : "UNKNOWN", err);
	}

	/* Unload the database */
	mddb_unload();

	md_set_status(MD_GBL_HALTED);	/* we are ready to be unloaded */

	for (i = 0; i < md_nsets; i++)
		md_haltsnarf_exit(i);

	return (md_global_lock_exit(global_locks_owned_mask, 0,
	    MD_ARRAY_WRITER, NULL));
}

/*
 * md_layered_open() is an internal routine only for SVM modules.
 * So the input device will be a md_dev64_t, because all SVM modules internally
 * work with that device type.
 * ddi routines on the other hand work with dev_t. So, if we call any ddi
 * routines from here we first have to convert that device into a dev_t.
 */

int
md_layered_open(
	minor_t		mnum,
	md_dev64_t	*dev,
	int		md_oflags
)
{
	int		flag = (FREAD | FWRITE);
	cred_t		*cred_p = kcred;
	major_t		major;
	int		err;
	dev_t		ddi_dev = md_dev64_to_dev(*dev);

	if (ddi_dev == NODEV)
		return (ENODEV);

	major = getmajor(ddi_dev);

	/* metadevice */
	if (major == md_major) {
		mdi_unit_t	*ui;

		/* open underlying driver */
		mnum = getminor(ddi_dev);

		ui = MDI_UNIT(mnum);
		if (md_ops[ui->ui_opsindex]->md_open != NULL) {
			int ret = (*md_ops[ui->ui_opsindex]->md_open)(&ddi_dev,
			    flag, OTYP_LYR, cred_p, md_oflags);
			/*
			 * As open() may change the device,
			 * send this info back to the caller.
			 */
			*dev = md_expldev(ddi_dev);
			return (ret);
		}

		/* or do it ourselves */
		(void) md_unit_openclose_enter(ui);
		err = md_unit_incopen(mnum, flag, OTYP_LYR);
		md_unit_openclose_exit(ui);
		/* convert our ddi_dev back to the dev we were given */
		*dev = md_expldev(ddi_dev);
		return (err);
	}

	/*
	 * Open regular device, since open() may change dev_t give new dev_t
	 * back to the caller.
	 */
	err = dev_lopen(&ddi_dev, flag, OTYP_LYR, cred_p);
	*dev = md_expldev(ddi_dev);
	return (err);
}

/*
 * md_layered_close() is an internal routine only for SVM modules.
 * So the input device will be a md_dev64_t, because all SVM modules internally
 * work with that device type.
 * ddi routines on the other hand work with dev_t. So, if we call any ddi
 * routines from here we first have to convert that device into a dev_t.
 */
void
md_layered_close(
	md_dev64_t	dev,
	int		md_cflags
)
{
	int		flag = (FREAD | FWRITE);
	cred_t		*cred_p = kcred;
	dev_t		ddi_dev = md_dev64_to_dev(dev);
	major_t		major = getmajor(ddi_dev);
	minor_t		mnum = getminor(ddi_dev);

	/* metadevice */
	if (major == md_major) {
		mdi_unit_t	*ui = MDI_UNIT(mnum);

		/* close underlying driver */
		if (md_ops[ui->ui_opsindex]->md_close != NULL) {
			(*md_ops[ui->ui_opsindex]->md_close)
			    (ddi_dev, flag, OTYP_LYR, cred_p, md_cflags);
			return;
		}

		/* or do it ourselves */
		(void) md_unit_openclose_enter(ui);
		(void) md_unit_decopen(mnum, OTYP_LYR);
		md_unit_openclose_exit(ui);
		return;
	}

	/* close regular device */
	(void) dev_lclose(ddi_dev, flag, OTYP_LYR, cred_p);
}

/*
 * saves a little code in mdstrategy
 */
int
errdone(mdi_unit_t *ui, struct buf *bp, int err)
{
	if ((bp->b_error = err) != 0)
		bp->b_flags |= B_ERROR;
	else
		bp->b_resid = bp->b_bcount;
	md_unit_readerexit(ui);
	md_biodone(bp);
	return (1);
}

static int	md_write_label = 0;

int
md_checkbuf(mdi_unit_t *ui, md_unit_t *un, buf_t *bp)
{
	diskaddr_t endblk;
	set_t	setno = MD_UN2SET(un);

	if ((md_get_setstatus(setno) & MD_SET_STALE) &&
	    (! (bp->b_flags & B_READ)))
		return (errdone(ui, bp, EROFS));
	/*
	 * Check early for unreasonable block number.
	 *
	 * b_blkno is defined as adaddr_t which is typedef'd to a long.
	 * A problem occurs if b_blkno has bit 31 set and un_total_blocks
	 * doesn't, b_blkno is then compared as a negative number which is
	 * always less than a positive.
	 */
	if ((u_longlong_t)bp->b_lblkno > (u_longlong_t)un->c.un_total_blocks)
		return (errdone(ui, bp, EINVAL));

	if (bp->b_lblkno == un->c.un_total_blocks)
		return (errdone(ui, bp, 0));

	/*
	 * make sure we don't clobber any labels
	 */
	if ((bp->b_lblkno == 0) && (! (bp->b_flags & B_READ)) &&
	    (un->c.un_flag & MD_LABELED) && (! md_write_label)) {
		cmn_err(CE_NOTE, "md: %s: write to label",
		    md_shortname(getminor(bp->b_edev)));
		return (errdone(ui, bp, EINVAL));
	}

	bp->b_resid = 0;
	endblk = (diskaddr_t)(bp->b_lblkno +
	    howmany(bp->b_bcount, DEV_BSIZE) - 1);

	if (endblk > (un->c.un_total_blocks - 1)) {
		bp->b_resid = dbtob(endblk - (un->c.un_total_blocks - 1));
		endblk = un->c.un_total_blocks - 1;
		bp->b_bcount -= bp->b_resid;
	}
	return (0);
}

/*
 * init_request_queue: initializes the request queues and creates the threads.
 *	return value =  0  :invalid num_threads
 *		     =  n   : n is the number of threads created.
 */

int
init_requestq(
	md_requestq_entry_t *rq, /* request queue info */
	void (*threadfn)(),	 /* function to start the thread */
	caddr_t threadfn_args,	 /* args to the function */
	int pri,		 /* thread priority */
	int init_queue)		 /* flag to init queues */
{
	struct mdq_anchor *rqhead;
	int	i;
	int	num_threads;


	num_threads = *(rq->num_threadsp);
	rqhead = rq->dispq_headp;

	if (NULL_REQUESTQ_ENTRY(rq) || num_threads == 0)
		return (0);

	if (init_queue) {
		rqhead->dq.maxq_len = 0;
		rqhead->dq.treqs = 0;
		rqhead->dq.dq_next = &rqhead->dq;
		rqhead->dq.dq_prev = &rqhead->dq;
		cv_init(&rqhead->a_cv, NULL, CV_DEFAULT, NULL);
		mutex_init(&rqhead->a_mx, NULL, MUTEX_DEFAULT, NULL);
	}
	for (i = 0; i < num_threads; i++) {
		(void) thread_create(NULL, 0, threadfn, threadfn_args, 0, &p0,
		    TS_RUN, pri);
	}
	return (i);
}

static void
start_daemon(struct mdq_anchor *q)
{
	md_daemon(0, q);
	ASSERT(0);
}

/*
 * Creates all the md daemons.
 * Global:
 *	md_num_daemons is set to number of daemons.
 *	MD_GBL_DAEMONS_LIVE flag set to indicate the daemons are active.
 *
 * Return value: 0  success
 *		 1  failure
 */
int
md_start_daemons(int init_queue)
{
	md_requestq_entry_t	*rqp;
	int	cnt;
	int	i;
	int	retval = 0;


	if (md_get_status() & MD_GBL_DAEMONS_LIVE) {
		return (retval);
	}
	md_clr_status(MD_GBL_DAEMONS_DIE);

	rqp = &md_daemon_queues[0];
	i = 0;
	while (!NULL_REQUESTQ_ENTRY(rqp)) {
		cnt = init_requestq(rqp, start_daemon,
		    (caddr_t)rqp->dispq_headp, minclsyspri, init_queue);

		if (cnt && cnt != *rqp->num_threadsp) {
			retval = 1;
			break;
		}
		/*
		 * initialize variables
		 */
		md_num_daemons += cnt;
		rqp = &md_daemon_queues[++i];
	}

	md_set_status(MD_GBL_DAEMONS_LIVE);
	return (retval);
}

int
md_loadsubmod(set_t setno, char *name, int drvrid)
{
	ddi_modhandle_t	mod;
	md_ops_t	**pops, *ops;
	int		i, err;

	/*
	 * See if the submodule is mdopened. If not, i is the index of the
	 * next empty slot.
	 */
	for (i = 0; md_ops[i] != NULL; i++) {
		if (strncmp(name, md_ops[i]->md_driver.md_drivername,
		    MD_DRIVERNAMELEN) == 0)
			return (i);

		if (i == (MD_NOPS - 1))
			return (-1);
	}

	if (drvrid < 0) {
		/* Do not try to add any records to the DB when stale. */
		if (md_get_setstatus(setno) & MD_SET_STALE)
			return (-1);
		drvrid = md_setshared_name(setno, name, 0L);
	}

	if (drvrid < 0)
		return (-1);

	/* open and import the md_ops of the submodules */
	mod = ddi_modopen(name, KRTLD_MODE_FIRST, &err);
	if (mod == NULL) {
		cmn_err(CE_WARN, "md_loadsubmod: "
		    "unable to ddi_modopen %s, error %d\n", name, err);
		return (-1);
	}
	pops = ddi_modsym(mod, "md_interface_ops", &err);
	if (pops == NULL) {
		cmn_err(CE_WARN, "md_loadsubmod: "
		    "unable to import md_interface_ops from %s, error %d\n",
		    name, err);
		(void) ddi_modclose(mod);
		return (-1);
	}

	/* ddi_modsym returns pointer to md_interface_ops in submod */
	ops = *pops;

	/* initialize */
	ops->md_selfindex = i;
	rw_init(&ops->md_link_rw.lock, NULL, RW_DEFAULT, NULL);
	(void) strncpy(ops->md_driver.md_drivername, name,
	    MD_DRIVERNAMELEN);

	/* plumb */
	md_ops[i] = ops;
	md_mods[i] = mod;
	ops->md_next = md_opslist;
	md_opslist = ops;

	/* return index */
	return (i);
}

int
md_getmodindex(md_driver_t *driver, int dont_load, int db_notrequired)
{
	int	i;
	int	modindex;
	char	*name = driver->md_drivername;
	set_t	setno = driver->md_setno;
	int	drvid;
	int	local_dont_load;

	if (setno >= md_nsets)
		return (-1);

	for (i = 0; name[i] != 0; i++)
		if (i == (MD_DRIVERNAMELEN -1))
			return (-1);

	/*
	 * If set is STALE, set local_dont_load to 1 since no records
	 * should be added to DB when stale.
	 */
	if (md_get_setstatus(setno) & MD_SET_STALE) {
		local_dont_load = 1;
	} else {
		local_dont_load = dont_load;
	}

	/*
	 * Single thread ioctl module binding with respect to
	 * similar code executed in md_loadsubmod that is called
	 * from md_snarf_db_set (which is where that path does
	 * its md_haltsnarf_enter call).
	 */
	md_haltsnarf_enter(setno);

	/* See if the submodule is already ddi_modopened. */
	for (i = 0; md_ops[i] != NULL; i++) {
		if (strncmp(name, md_ops[i]->md_driver.md_drivername,
		    MD_DRIVERNAMELEN) == 0) {
			if (! local_dont_load &&
			    (md_getshared_key(setno, name) == MD_KEYBAD)) {
				if (md_setshared_name(setno, name, 0L)
				    == MD_KEYBAD) {
					if (!db_notrequired)
						goto err;
				}
			}
			md_haltsnarf_exit(setno);
			return (i);
		}

		if (i == (MD_NOPS -1))
			break;
	}

	if (local_dont_load)
		goto err;

	drvid = ((db_notrequired) ? 0 : (int)md_getshared_key(setno, name));

	/* ddi_modopen the submodule */
	modindex = md_loadsubmod(setno, name, drvid);
	if (modindex < 0)
		goto err;

	if (md_ops[modindex]->md_snarf != NULL)
		(*(md_ops[modindex]->md_snarf))(MD_SNARF_DOIT, setno);

	md_haltsnarf_exit(setno);
	return (modindex);

err:	md_haltsnarf_exit(setno);
	return (-1);
}

void
md_call_strategy(buf_t *bp, int flags, void *private)
{
	mdi_unit_t	*ui;

	if (mdv_strategy_tstpnt)
		if ((*mdv_strategy_tstpnt)(bp, flags, private) != 0)
			return;
	if (getmajor(bp->b_edev) != md_major) {
		(void) bdev_strategy(bp);
		return;
	}

	flags = (flags & MD_STR_PASSEDON) | MD_STR_NOTTOP;
	ui = MDI_UNIT(getminor(bp->b_edev));
	ASSERT(ui != NULL);
	(*md_ops[ui->ui_opsindex]->md_strategy)(bp, flags, private);
}

/*
 * md_call_ioctl:
 * -------------
 * Issue the specified ioctl to the device associated with the given md_dev64_t
 *
 * Arguments:
 *	dev	- underlying device [md_dev64_t]
 *	cmd	- ioctl to perform
 *	data	- arguments / result location
 *	mode	- read/write/layered ioctl
 *	lockp	- lock reference
 *
 * Returns:
 *	0	success
 *	!=0	Failure (error code)
 */
int
md_call_ioctl(md_dev64_t dev, int cmd, void *data, int mode, IOLOCK *lockp)
{
	dev_t		device = md_dev64_to_dev(dev);
	int		rval;
	mdi_unit_t	*ui;

	/*
	 * See if device is a metadevice. If not call cdev_ioctl(), otherwise
	 * call the ioctl entry-point in the metadevice.
	 */
	if (md_getmajor(dev) != md_major) {
		int	rv;
		rval = cdev_ioctl(device, cmd, (intptr_t)data, mode,
		    ddi_get_cred(), &rv);
	} else {
		ui = MDI_UNIT(md_getminor(dev));
		ASSERT(ui != NULL);
		rval = (*md_ops[ui->ui_opsindex]->md_ioctl)(device, cmd, data,
		    mode, lockp);
	}
	return (rval);
}

void
md_rem_link(set_t setno, int id, krwlock_t *rw, md_link_t **head)
{
	md_link_t	*next;
	md_link_t	**pprev;

	rw_enter(rw, RW_WRITER);

	next = *head;
	pprev = head;
	while (next) {
		if ((next->ln_setno == setno) && (next->ln_id == id)) {
			*pprev = next->ln_next;
			rw_exit(rw);
			return;
		}
		pprev = &next->ln_next;
		next = next->ln_next;
	}

	rw_exit(rw);
}

int
md_dev_exists(md_dev64_t dev)
{

	if (dev == NODEV64)
		return (0);

	if (strcmp(ddi_major_to_name(md_getmajor(dev)), "md") != 0)
		return (1);

	if ((MD_MIN2SET(md_getminor(dev)) >= md_nsets) ||
	    (MD_MIN2UNIT(md_getminor(dev)) >= md_nunits))
		return (0);

	if (MDI_UNIT(md_getminor(dev)) != NULL)
		return (1);

	return (0);
}

md_parent_t
md_get_parent(md_dev64_t dev)
{
	md_unit_t	*un;
	mdi_unit_t	*ui;
	md_parent_t	parent;

	if (md_getmajor(dev) != md_major)
		return (MD_NO_PARENT);

	ui = MDI_UNIT(md_getminor(dev));

	un = (md_unit_t *)md_unit_readerlock(ui);
	parent = un->c.un_parent;
	md_unit_readerexit(ui);

	return (parent);
}

void
md_set_parent(md_dev64_t dev, md_parent_t parent)
{
	md_unit_t	*un;
	mdi_unit_t	*ui;

	if (md_getmajor(dev) != md_major)
		return;

	ui = MDI_UNIT(md_getminor(dev));

	un = (md_unit_t *)md_unit_readerlock(ui);
	un->c.un_parent = parent;
	md_unit_readerexit(ui);
}

void
md_reset_parent(md_dev64_t dev)
{
	md_unit_t	*un;
	mdi_unit_t	*ui;

	if (md_getmajor(dev) != md_major)
		return;

	ui = MDI_UNIT(md_getminor(dev));

	un = (md_unit_t *)md_unit_readerlock(ui);
	un->c.un_parent = MD_NO_PARENT;
	md_unit_readerexit(ui);
}


static intptr_t (*hot_spare_interface)() = (intptr_t (*)())NULL;

int
md_hot_spare_ifc(
	hs_cmds_t	cmd,
	mddb_recid_t	id,
	u_longlong_t	size,
	int		labeled,
	mddb_recid_t	*hs_id,
	mdkey_t		*key,
	md_dev64_t	*dev,
	diskaddr_t	*sblock)
{
	int		err;

	/*
	 * RW lock on hot_spare_interface. We don't want it to change from
	 * underneath us. If hot_spare_interface is NULL we're going to
	 * need to set it. So we need to upgrade to a WRITER lock. If that
	 * doesn't work, we drop the lock and reenter as WRITER. This leaves
	 * a small hole during which hot_spare_interface could be modified
	 * so we check it for NULL again. What a pain. Then if still null
	 * load from md_get_named_service.
	 */

	rw_enter(&hsp_rwlp.lock, RW_READER);
	if (hot_spare_interface == NULL) {
		if (rw_tryupgrade(&hsp_rwlp.lock) == 0) {
			rw_exit(&hsp_rwlp.lock);
			rw_enter(&hsp_rwlp.lock, RW_WRITER);
			if (hot_spare_interface != NULL) {
				err = ((*hot_spare_interface)
				    (cmd, id, size, labeled, hs_id, key, dev,
				    sblock));
				rw_exit(&hsp_rwlp.lock);
				return (err);
			}
		}
		hot_spare_interface = md_get_named_service(NODEV64, ANY_SERVICE,
		    "hot spare interface", 0);
		rw_downgrade(&hsp_rwlp.lock);
	}

	if (hot_spare_interface == NULL) {
		cmn_err(CE_WARN, "md: no hotspare interface");
		rw_exit(&hsp_rwlp.lock);
		return (0);
	}

	err = ((*hot_spare_interface)
	    (cmd, id, size, labeled, hs_id, key, dev, sblock));
	rw_exit(&hsp_rwlp.lock);
	return (err);
}

void
md_clear_hot_spare_interface()
{
	rw_enter(&hsp_rwlp.lock, RW_WRITER);
	hot_spare_interface = NULL;
	rw_exit(&hsp_rwlp.lock);
}


static intptr_t (*notify_interface)() = (intptr_t (*)())NULL;

int
md_notify_interface(
	md_event_cmds_t cmd,
	md_tags_t	tag,
	set_t		set,
	md_dev64_t	dev,
	md_event_type_t event
)
{
	int		err;

	if (md_event_queue == NULL)
		return (0);
	rw_enter(&ni_rwlp.lock, RW_READER);
	if (notify_interface == NULL) {
		if (rw_tryupgrade(&ni_rwlp.lock) == 0) {
			rw_exit(&ni_rwlp.lock);
			rw_enter(&ni_rwlp.lock, RW_WRITER);
			if (notify_interface != NULL) {
				err = ((*notify_interface)
				    (cmd, tag, set, dev, event));
				rw_exit(&ni_rwlp.lock);
				return (err);
			}
		}
		notify_interface = md_get_named_service(NODEV64, ANY_SERVICE,
		    "notify interface", 0);
		rw_downgrade(&ni_rwlp.lock);
	}
	if (notify_interface == NULL) {
		cmn_err(CE_WARN, "md: no notify interface");
		rw_exit(&ni_rwlp.lock);
		return (0);
	}
	err = ((*notify_interface)(cmd, tag, set, dev, event));
	rw_exit(&ni_rwlp.lock);
	return (err);
}

char *
obj2devname(uint32_t tag, uint_t setno, md_dev64_t dev)
{
	char		*setname;
	char		name[MD_MAX_CTDLEN];
	minor_t		mnum = md_getminor(dev);
	major_t		maj = md_getmajor(dev);
	int		rtn = 0;

	/*
	 * Verify that the passed dev_t refers to a valid metadevice.
	 * If it doesn't we can make no assumptions as to what the device
	 * name is. Return NULL in these cases.
	 */
	if (((maj != md_major) || (MD_MIN2UNIT(mnum) >= md_nunits)) ||
	    (MD_MIN2SET(mnum) >= md_nsets)) {
		return (NULL);
	}

	setname = NULL;
	name[0] = '\0';
	switch (tag) {
	case SVM_TAG_HSP:
		if (setno == 0) {
			rtn = snprintf(name, sizeof (name), "hsp%u",
			    (unsigned)MD_MIN2UNIT(mnum));
		} else {
			setname = mddb_getsetname(setno);
			if (setname != NULL) {
				rtn = snprintf(name, sizeof (name), "%s/hsp%u",
				    setname, (unsigned)MD_MIN2UNIT(mnum));
			}
		}
		break;
	case SVM_TAG_DRIVE:
		(void) sprintf(name, "drive");
		break;
	case SVM_TAG_HOST:
		(void) sprintf(name, "host");
		break;
	case SVM_TAG_SET:
		rtn = snprintf(name, sizeof (name), "%s",
		    mddb_getsetname(setno));
		if ((name[0] == '\0') || (rtn >= sizeof (name))) {
			(void) sprintf(name, "diskset");
			rtn = 0;
		}
		break;
	default:
		rtn = snprintf(name, sizeof (name), "%s", md_shortname(mnum));
		break;
	}

	/* Check if we got any rubbish for any of the snprintf's */
	if ((name[0] == '\0') || (rtn >= sizeof (name))) {
		return (NULL);
	}

	return (md_strdup(name));
}

/* Sysevent subclass and mdnotify event type pairs */
struct node {
	char		*se_ev;
	md_event_type_t	md_ev;
};

/*
 * Table must be sorted in case sensitive ascending order of
 * the sysevents values
 */
static struct node ev_table[] = {
	{ ESC_SVM_ADD,			EQ_ADD },
	{ ESC_SVM_ATTACH,		EQ_ATTACH },
	{ ESC_SVM_ATTACHING,		EQ_ATTACHING },
	{ ESC_SVM_CHANGE,		EQ_CHANGE },
	{ ESC_SVM_CREATE,		EQ_CREATE },
	{ ESC_SVM_DELETE,		EQ_DELETE },
	{ ESC_SVM_DETACH,		EQ_DETACH },
	{ ESC_SVM_DETACHING,		EQ_DETACHING },
	{ ESC_SVM_DRIVE_ADD,		EQ_DRIVE_ADD },
	{ ESC_SVM_DRIVE_DELETE,		EQ_DRIVE_DELETE },
	{ ESC_SVM_ENABLE,		EQ_ENABLE },
	{ ESC_SVM_ERRED,		EQ_ERRED },
	{ ESC_SVM_EXCHANGE,		EQ_EXCHANGE },
	{ ESC_SVM_GROW,			EQ_GROW },
	{ ESC_SVM_HS_CHANGED,		EQ_HS_CHANGED },
	{ ESC_SVM_HS_FREED,		EQ_HS_FREED },
	{ ESC_SVM_HOST_ADD,		EQ_HOST_ADD },
	{ ESC_SVM_HOST_DELETE,		EQ_HOST_DELETE },
	{ ESC_SVM_HOTSPARED,		EQ_HOTSPARED },
	{ ESC_SVM_INIT_FAILED,		EQ_INIT_FAILED },
	{ ESC_SVM_INIT_FATAL,		EQ_INIT_FATAL },
	{ ESC_SVM_INIT_START,		EQ_INIT_START },
	{ ESC_SVM_INIT_SUCCESS,		EQ_INIT_SUCCESS },
	{ ESC_SVM_IOERR,		EQ_IOERR },
	{ ESC_SVM_LASTERRED,		EQ_LASTERRED },
	{ ESC_SVM_MEDIATOR_ADD,		EQ_MEDIATOR_ADD },
	{ ESC_SVM_MEDIATOR_DELETE,	EQ_MEDIATOR_DELETE },
	{ ESC_SVM_OFFLINE,		EQ_OFFLINE },
	{ ESC_SVM_OK,			EQ_OK },
	{ ESC_SVM_ONLINE,		EQ_ONLINE },
	{ ESC_SVM_OPEN_FAIL,		EQ_OPEN_FAIL },
	{ ESC_SVM_REGEN_DONE,		EQ_REGEN_DONE },
	{ ESC_SVM_REGEN_FAILED,		EQ_REGEN_FAILED },
	{ ESC_SVM_REGEN_START,		EQ_REGEN_START },
	{ ESC_SVM_RELEASE,		EQ_RELEASE },
	{ ESC_SVM_REMOVE,		EQ_REMOVE },
	{ ESC_SVM_RENAME_DST,		EQ_RENAME_DST },
	{ ESC_SVM_RENAME_SRC,		EQ_RENAME_SRC },
	{ ESC_SVM_REPLACE,		EQ_REPLACE },
	{ ESC_SVM_RESYNC_DONE,		EQ_RESYNC_DONE },
	{ ESC_SVM_RESYNC_FAILED,	EQ_RESYNC_FAILED },
	{ ESC_SVM_RESYNC_START,		EQ_RESYNC_START },
	{ ESC_SVM_RESYNC_SUCCESS,	EQ_RESYNC_SUCCESS },
	{ ESC_SVM_TAKEOVER,		EQ_TAKEOVER }
};

static md_tags_t md_tags[] = {
	TAG_UNK,
	TAG_METADEVICE,
	TAG_UNK,
	TAG_UNK,
	TAG_UNK,
	TAG_UNK,
	TAG_REPLICA,
	TAG_HSP,
	TAG_HS,
	TAG_SET,
	TAG_DRIVE,
	TAG_HOST,
	TAG_MEDIATOR
};

md_event_type_t
ev_get(char *subclass)
{
	int	high, mid, low, p;

	low = 0;
	high = (sizeof (ev_table) / sizeof (ev_table[0])) - 1;
	while (low <= high) {
		mid = (high + low) / 2;
		p = strcmp(subclass, ev_table[mid].se_ev);
		if (p == 0) {
			return (ev_table[mid].md_ev);
		} else if (p < 0) {
			high = mid - 1;
		} else {
			low = mid + 1;
		}
	}

	return (EQ_EMPTY);
}

/*
 * Log mdnotify event
 */
void
do_mdnotify(char *se_subclass, uint32_t tag, set_t setno, md_dev64_t devid)
{
	md_event_type_t	ev_type;
	md_tags_t	md_tag;

	/* Translate sysevent into mdnotify event */
	ev_type = ev_get(se_subclass);

	if (tag >= (sizeof (md_tags) / sizeof (md_tags[0]))) {
		md_tag = TAG_UNK;
	} else {
		md_tag = md_tags[tag];
	}

	NOTIFY_MD(md_tag, setno, devid, ev_type);
}

/*
 * Log SVM sys events
 */
void
svm_gen_sysevent(
	char		*se_class,
	char		*se_subclass,
	uint32_t	tag,
	set_t		setno,
	md_dev64_t	devid
)
{
	nvlist_t		*attr_list;
	sysevent_id_t		eid;
	int			err = DDI_SUCCESS;
	char			*devname;
	extern dev_info_t	*md_devinfo;

	/* Raise the mdnotify event before anything else */
	do_mdnotify(se_subclass, tag, setno, devid);

	if (md_devinfo == NULL) {
		return;
	}

	err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME, KM_NOSLEEP);

	if (err == DDI_SUCCESS) {
		/* Add the version numver */
		err = nvlist_add_uint32(attr_list, SVM_VERSION_NO,
		    (uint32_t)SVM_VERSION);
		if (err != DDI_SUCCESS) {
			goto fail;
		}

		/* Add the tag attribute */
		err = nvlist_add_uint32(attr_list, SVM_TAG, (uint32_t)tag);
		if (err != DDI_SUCCESS) {
			goto fail;
		}

		/* Add the set number attribute */
		err = nvlist_add_uint32(attr_list, SVM_SET_NO, (uint32_t)setno);
		if (err != DDI_SUCCESS) {
			goto fail;
		}

		/* Add the device id attribute */
		err = nvlist_add_uint64(attr_list, SVM_DEV_ID, (uint64_t)devid);
		if (err != DDI_SUCCESS) {
			goto fail;
		}

		/* Add the device name attribute */
		devname = obj2devname(tag, setno, devid);
		if (devname != NULL) {
			err = nvlist_add_string(attr_list, SVM_DEV_NAME,
			    devname);
			freestr(devname);
		} else {
			err = nvlist_add_string(attr_list, SVM_DEV_NAME,
			    "unspecified");
		}
		if (err != DDI_SUCCESS) {
			goto fail;
		}

		/* Attempt to post event */
		err = ddi_log_sysevent(md_devinfo, DDI_VENDOR_SUNW, se_class,
		    se_subclass, attr_list, &eid, DDI_SLEEP);

		nvlist_free(attr_list);
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to log event for %s, %s,"
			    " err=%x", se_class, se_subclass, err);
		}
	}

	return;

fail:
	nvlist_free(attr_list);
	cmn_err(CE_WARN, "Failed to setup attributes for event %s, %s, err=%x",
	    se_class, se_subclass, err);
}

void
md_clear_named_service()
{
	rw_enter(&ni_rwlp.lock, RW_WRITER);
	notify_interface = NULL;
	rw_exit(&ni_rwlp.lock);
}

void
md_create_unit_incore(minor_t mnum, md_ops_t *ops, int alloc_lock)
{
	mdi_unit_t	*ui;
	set_t		setno = MD_MIN2SET(mnum);

	ui = (mdi_unit_t *)kmem_zalloc(sizeof (mdi_unit_t), KM_SLEEP);
	ui->ui_opsindex = ops->md_selfindex;

	/* initialize all the incore conditional variables */
	mutex_init(&ui->ui_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ui->ui_cv, NULL, CV_DEFAULT, NULL);

	if (! (md_get_setstatus(setno) & MD_SET_SNARFING)) {
		rw_enter(&md_unit_array_rw.lock, RW_WRITER);
		MDI_VOIDUNIT(mnum) = (void *) ui;
		rw_exit(&md_unit_array_rw.lock);
	} else
		MDI_VOIDUNIT(mnum) = (void *) ui;

	rw_enter(&ops->md_link_rw.lock, RW_WRITER);
	ui->ui_link.ln_next = ops->md_head;
	ui->ui_link.ln_setno = setno;
	ui->ui_link.ln_id = mnum;
	ops->md_head = &ui->ui_link;
	if (alloc_lock) {
		ui->ui_io_lock = kmem_zalloc(sizeof (md_io_lock_t), KM_SLEEP);
		mutex_init(&ui->ui_io_lock->io_mx, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&ui->ui_io_lock->io_cv, NULL, CV_DEFAULT, NULL);
		mutex_init(&ui->ui_io_lock->io_list_mutex, NULL,
		    MUTEX_DEFAULT, NULL);
		ui->ui_io_lock->io_list_front = NULL;
		ui->ui_io_lock->io_list_back = NULL;
	}
	/* setup the unavailable field */
#if defined(_ILP32)
	if (((md_unit_t *)MD_UNIT(mnum))->c.un_revision & MD_64BIT_META_DEV) {
		ui->ui_tstate |= MD_64MD_ON_32KERNEL;
		cmn_err(CE_NOTE, "d%d is unavailable because 64 bit "
		    "metadevices are not accessible on a 32 bit kernel",
		    mnum);
	}
#endif

	rw_exit(&ops->md_link_rw.lock);
}

void
md_destroy_unit_incore(minor_t mnum, md_ops_t *ops)
{
	mdi_unit_t	*ui;

	/*
	 * ASSUMPTION: md_unit_array_rw WRITER lock is held.
	 */
	ui = MDI_UNIT(mnum);
	if (ui == NULL)
		return;

	md_rem_link(MD_MIN2SET(mnum), mnum, &ops->md_link_rw.lock,
	    &ops->md_head);

	/* destroy the io lock if one is being used */
	if (ui->ui_io_lock) {
		mutex_destroy(&ui->ui_io_lock->io_mx);
		cv_destroy(&ui->ui_io_lock->io_cv);
		kmem_free(ui->ui_io_lock, sizeof (md_io_lock_t));
	}

	/* teardown kstat */
	md_kstat_destroy(mnum);

	/* destroy all the incore conditional variables */
	mutex_destroy(&ui->ui_mx);
	cv_destroy(&ui->ui_cv);

	kmem_free(ui, sizeof (mdi_unit_t));
	MDI_VOIDUNIT(mnum) = (void *) NULL;
}

void
md_rem_names(sv_dev_t *sv, int nsv)
{
	int	i, s;
	int	max_sides;

	if (nsv == 0)
		return;

	/* All entries removed are in the same diskset */
	if (md_get_setstatus(sv[0].setno) & MD_SET_MNSET)
		max_sides = MD_MNMAXSIDES;
	else
		max_sides = MD_MAXSIDES;

	for (i = 0; i < nsv; i++)
		for (s = 0; s < max_sides; s++)
			(void) md_remdevname(sv[i].setno, s, sv[i].key);
}

/*
 * Checking user args before we get into physio - returns 0 for ok, else errno
 * We do a lot of checking against illegal arguments here because some of the
 * real disk drivers don't like certain kinds of arguments. (e.g xy doesn't
 * like odd address user buffer.) Those drivers capture bad arguments in
 * xxread and xxwrite. But since meta-driver calls their strategy routines
 * directly, two bad scenario might happen:
 *	1. the real strategy doesn't like it and panic.
 *	2. the real strategy doesn't like it and set B_ERROR.
 *
 * The second case is no better than the first one, since the meta-driver
 * will treat it as a media-error and off line the mirror metapartition.
 * (Too bad there is no way to tell what error it is.)
 *
 */
int
md_chk_uio(struct uio *uio)
{
	int	i;
	struct iovec *iov;

	/*
	 * Check for negative or not block-aligned offset
	 */
	if ((uio->uio_loffset < 0) ||
	    ((uio->uio_loffset & (DEV_BSIZE - 1)) != 0)) {
		return (EINVAL);
	}
	iov = uio->uio_iov;
	i = uio->uio_iovcnt;

	while (i--) {
		if ((iov->iov_len & (DEV_BSIZE - 1)) != 0)
			return (EINVAL);
		/*
		 * Bug # 1212146
		 * The default is to not check alignment, but we can now check
		 * for a larger number of alignments if desired.
		 */
		if ((uintptr_t)(iov->iov_base) & md_uio_alignment_mask)
			return (EINVAL);
		iov++;
	}
	return (0);
}

char *
md_shortname(
	minor_t		mnum
)
{
	static char	buf[MAXPATHLEN];
	char		*devname;
	char		*invalid = " (Invalid minor number %u) ";
	char		*metaname;
	mdc_unit_t	*un;
	side_t		side;
	set_t		setno = MD_MIN2SET(mnum);
	unit_t		unit = MD_MIN2UNIT(mnum);

	if ((un = MD_UNIT(mnum)) == NULL) {
		(void) snprintf(buf, sizeof (buf), invalid, mnum);
		return (buf);
	}

	/*
	 * If unit is not a friendly name unit, derive the name from the
	 * minor number.
	 */
	if ((un->un_revision & MD_FN_META_DEV) == 0) {
		/* This is a traditional metadevice */
		if (setno == MD_LOCAL_SET) {
			(void) snprintf(buf, sizeof (buf), "d%u",
			    (unsigned)unit);
		} else {
			(void) snprintf(buf, sizeof (buf), "%s/d%u",
			    mddb_getsetname(setno), (unsigned)unit);
		}
		return (buf);
	}

	/*
	 * It is a friendly name metadevice, so we need to get its name.
	 */
	side = mddb_getsidenum(setno);
	devname = (char *)kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (md_getdevname(setno, side, MD_KEYWILD,
	    md_makedevice(md_major, mnum), devname, MAXPATHLEN) == 0) {
		/*
		 * md_getdevname has given us either /dev/md/dsk/<metaname>
		 * or /dev/md/<setname>/dsk/<metname> depending on whether
		 * or not we are in the local set.  Thus, we'll pull the
		 * metaname from this string.
		 */
		if ((metaname = strrchr(devname, '/')) == NULL) {
			(void) snprintf(buf, sizeof (buf), invalid, mnum);
			goto out;
		}
		metaname++;	/* move past slash */
		if (setno == MD_LOCAL_SET) {
			/* No set name. */
			(void) snprintf(buf, sizeof (buf), "%s", metaname);
		} else {
			/* Include setname */
			(void) snprintf(buf, sizeof (buf), "%s/%s",
			    mddb_getsetname(setno), metaname);
		}
	} else {
		/* We couldn't find the name. */
		(void) snprintf(buf, sizeof (buf), invalid, mnum);
	}

out:
	kmem_free(devname, MAXPATHLEN);
	return (buf);
}

char *
md_devname(
	set_t		setno,
	md_dev64_t	dev,
	char		*buf,
	size_t		size
)
{
	static char	mybuf[MD_MAX_CTDLEN];
	int		err;

	if (buf == NULL) {
		buf = mybuf;
		size = sizeof (mybuf);
	} else {
		ASSERT(size >= MD_MAX_CTDLEN);
	}

	err = md_getdevname_common(setno, mddb_getsidenum(setno),
	    0, dev, buf, size, MD_NOWAIT_LOCK);
	if (err) {
		if (err == ENOENT) {
			(void) sprintf(buf, "(Unavailable)");
		} else {
			(void) sprintf(buf, "(%u.%u)",
			    md_getmajor(dev), md_getminor(dev));
		}
	}

	return (buf);
}
void
md_minphys(buf_t *pb)
{
	extern unsigned md_maxbcount;

	if (pb->b_bcount > md_maxbcount)
		pb->b_bcount = md_maxbcount;
}

void
md_bioinit(struct buf *bp)
{
	ASSERT(bp);

	bioinit(bp);
	bp->b_back = bp;
	bp->b_forw = bp;
	bp->b_flags = B_BUSY;	/* initialize flags */
}

void
md_bioreset(struct buf *bp)
{
	ASSERT(bp);

	bioreset(bp);
	bp->b_back = bp;
	bp->b_forw = bp;
	bp->b_flags = B_BUSY;	/* initialize flags */
}

/*
 * md_bioclone is needed as long as the real bioclone only takes a daddr_t
 * as block number.
 * We simply call bioclone with all input parameters but blkno, and set the
 * correct blkno afterwards.
 * Caveat Emptor: bp_mem must not be NULL!
 */
buf_t *
md_bioclone(buf_t *bp, off_t off, size_t len, dev_t dev, diskaddr_t blkno,
		int (*iodone)(buf_t *), buf_t *bp_mem, int sleep)
{
	(void) bioclone(bp, off, len, dev, 0, iodone, bp_mem, sleep);
	bp_mem->b_lblkno = blkno;
	return (bp_mem);
}


/*
 * kstat stuff
 */
void
md_kstat_init_ui(
	minor_t		 mnum,
	mdi_unit_t	*ui
)
{
	if ((ui != NULL) && (ui->ui_kstat == NULL)) {
		set_t	setno = MD_MIN2SET(mnum);
		unit_t  unit = MD_MIN2UNIT(mnum);
		char	module[KSTAT_STRLEN];
		char	*p = module;

		if (setno != MD_LOCAL_SET) {
			char	buf[64];
			char	*s = buf;
			char	*e = module + sizeof (module) - 4;

			(void) sprintf(buf, "%u", setno);
			while ((p < e) && (*s != '\0'))
				*p++ = *s++;
			*p++ = '/';
		}
		*p++ = 'm';
		*p++ = 'd';
		*p = '\0';
		if ((ui->ui_kstat = kstat_create(module, unit, NULL, "disk",
		    KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT)) != NULL) {
			ui->ui_kstat->ks_lock = &ui->ui_mx;
			kstat_install(ui->ui_kstat);
		}
	}
}

void
md_kstat_init(
	minor_t		mnum
)
{
	md_kstat_init_ui(mnum, MDI_UNIT(mnum));
}

void
md_kstat_destroy_ui(
	mdi_unit_t	*ui
)
{
	/*
	 * kstat_delete() interface has it's own locking mechanism and
	 * does not allow holding of kstat lock (ks_lock).
	 * Note: ks_lock == ui_mx from the md_kstat_init_ui().
	 */
	if ((ui != NULL) && (ui->ui_kstat != NULL)) {
		kstat_delete(ui->ui_kstat);
		ui->ui_kstat = NULL;
	}
}

void
md_kstat_destroy(
	minor_t		mnum
)
{
	md_kstat_destroy_ui(MDI_UNIT(mnum));
}

/*
 * In the following subsequent routines, locks are held before checking the
 * validity of ui_kstat. This is done to make sure that we don't trip over
 * a NULL ui_kstat anymore.
 */

void
md_kstat_waitq_enter(
	mdi_unit_t	*ui
)
{
	mutex_enter(&ui->ui_mx);
	if (ui->ui_kstat != NULL)
		kstat_waitq_enter(KSTAT_IO_PTR(ui->ui_kstat));
	mutex_exit(&ui->ui_mx);
}

void
md_kstat_waitq_to_runq(
	mdi_unit_t	*ui
)
{
	mutex_enter(&ui->ui_mx);
	if (ui->ui_kstat != NULL)
		kstat_waitq_to_runq(KSTAT_IO_PTR(ui->ui_kstat));
	mutex_exit(&ui->ui_mx);
}

void
md_kstat_waitq_exit(
	mdi_unit_t	*ui
)
{
	mutex_enter(&ui->ui_mx);
	if (ui->ui_kstat != NULL)
		kstat_waitq_exit(KSTAT_IO_PTR(ui->ui_kstat));
	mutex_exit(&ui->ui_mx);
}

void
md_kstat_runq_enter(
	mdi_unit_t	*ui
)
{
	mutex_enter(&ui->ui_mx);
	if (ui->ui_kstat != NULL)
		kstat_runq_enter(KSTAT_IO_PTR(ui->ui_kstat));
	mutex_exit(&ui->ui_mx);
}

void
md_kstat_runq_exit(
	mdi_unit_t	*ui
)
{
	mutex_enter(&ui->ui_mx);
	if (ui->ui_kstat != NULL)
		kstat_runq_exit(KSTAT_IO_PTR(ui->ui_kstat));
	mutex_exit(&ui->ui_mx);
}

void
md_kstat_done(
	mdi_unit_t	*ui,
	buf_t		*bp,
	int		war
)
{
	size_t  n_done;

	/* check for end of device */
	if ((bp->b_resid != 0) && (! (bp->b_flags & B_ERROR))) {
		n_done = bp->b_bcount;
	} else if (bp->b_bcount < bp->b_resid) {
		n_done = 0;
	} else {
		n_done = bp->b_bcount - bp->b_resid;
	}

	/* do accounting */
	mutex_enter(&ui->ui_mx);
	if (ui->ui_kstat != NULL) {
		if ((! war) && (bp->b_flags & B_READ)) {
			KSTAT_IO_PTR(ui->ui_kstat)->reads++;
			KSTAT_IO_PTR(ui->ui_kstat)->nread += n_done;
		} else {
			KSTAT_IO_PTR(ui->ui_kstat)->writes++;
			KSTAT_IO_PTR(ui->ui_kstat)->nwritten += n_done;
		}
		kstat_runq_exit(KSTAT_IO_PTR(ui->ui_kstat));
	}
	mutex_exit(&ui->ui_mx);
}

pid_t
md_getpid()
{
	pid_t valuep;
	if (drv_getparm(PPID, (pid_t *)&valuep) != 0) {
		ASSERT(0);
		return ((pid_t)0);
	} else {
		ASSERT(valuep);
		return (valuep);
	}
}


proc_t *
md_getproc()
{
	proc_t  *valuep;
	if (drv_getparm(UPROCP, (proc_t **)&valuep) != 0) {
		ASSERT(0);
		return ((proc_t *)NULL);
	} else {
		ASSERT(valuep);
		return (valuep);
	}
}

extern kmutex_t pidlock;

/*
 * this check to see if a process pid pair are still running.  For the
 * disk set lock when both pid/proc are zero then the locks is not
 * currently held.
 */
int
md_checkpid(pid_t pid, proc_t *proc)
{
	int	retval = 1;

	if (pid == 0 && proc == NULL)
		return (0);

	mutex_enter(&pidlock);
	if (prfind(pid)  != proc)
		retval = 0;
	mutex_exit(&pidlock);
	return (retval);
}

/*
 * NAME: md_init_probereq
 *
 * DESCRIPTION: initializes a probe request. Parcels out the mnums such that
 *		they can be dispatched to multiple daemon threads.
 *
 * PARAMETERS: struct md_probedev *p	pointer ioctl input
 *
 * RETURN VALUE: Returns errno
 *
 */

int
md_init_probereq(struct md_probedev_impl *p, daemon_queue_t **hdrpp)
{
	int		err = 0;
	int		modindx;
	intptr_t	(*probe_test)();

	/*
	 * Initialize the semaphores and mutex
	 * for the request
	 */

	p->probe_sema = kmem_alloc(sizeof (ksema_t), KM_SLEEP);

	p->probe_mx = kmem_alloc(sizeof (kmutex_t), KM_SLEEP);
	sema_init(PROBE_SEMA(p), 0, NULL, SEMA_DRIVER, NULL);
	mutex_init(PROBE_MX(p), NULL, MUTEX_DEFAULT, NULL);

	modindx = md_getmodindex(&(p->probe.md_driver), 1, 1);
	probe_test = md_get_named_service(NODEV64, modindx,
	    p->probe.test_name, 0);
	if (probe_test == NULL) {
		err = EINVAL;
		goto err_out;
	}

	err = md_create_probe_rqlist(p, hdrpp, probe_test);
err_out:
	return (err);
}

/*
 * NAME: md_probe_one
 *
 * DESCRIPTION: Generic routine for probing disks. This is called from the
 *		daemon.
 *
 * PARAMETERS: probe_req_t	*reqp	pointer to the probe request structure.
 *
 */

void
md_probe_one(probe_req_t *reqp)
{
	mdi_unit_t		*ui;
	md_probedev_impl_t	*p;
	int			err = 0;

	p = (md_probedev_impl_t *)reqp->private_handle;
	/*
	 * Validate the unit while holding the global ioctl lock, then
	 * obtain the unit_writerlock. Once the writerlock has been obtained
	 * we can release the global lock. As long as we hold one of these
	 * locks this will prevent a metaclear operation being performed
	 * on the metadevice because metaclear takes the readerlock (via
	 * openclose lock).
	 */
	while (md_ioctl_lock_enter() == EINTR)
		;
	ui = MDI_UNIT(reqp->mnum);
	if (ui != NULL) {
		(void) md_unit_writerlock_common(ui, 0);
		(void) md_ioctl_lock_exit(0, 0, 0, FALSE);
		err = (*reqp->probe_fcn)(ui, reqp->mnum);
		md_unit_writerexit(ui);
	} else {
		(void) md_ioctl_lock_exit(0, 0, 0, FALSE);
	}

	/* update the info info in the probe structure */

	mutex_enter(PROBE_MX(p));
	if (err != 0) {
		cmn_err(CE_NOTE, "md_probe_one: err %d mnum %d\n", err,
		    reqp->mnum);
		(void) mdsyserror(&(p->probe.mde), err);
	}

	mutex_exit(PROBE_MX(p));
	sema_v(PROBE_SEMA(p));

	kmem_free(reqp, sizeof (probe_req_t));
}
char *
md_strdup(char *cp)
{
	char *new_cp = NULL;

	new_cp = kmem_alloc(strlen(cp) + 1, KM_SLEEP);

	return (strcpy(new_cp, cp));
}

void
freestr(char *cp)
{
	kmem_free(cp, strlen(cp) + 1);
}

/*
 * Validate the list and skip invalid devices. Then create
 * a doubly linked circular list of devices to probe.
 * The hdr points to the head and tail of this list.
 */

static int
md_create_probe_rqlist(md_probedev_impl_t *plist, daemon_queue_t **hdr,
			intptr_t (*probe_test)())
{
	int i, err, nodevcnt;
	probe_req_t *tp;
	daemon_queue_t *hp;
	minor_t mnum;

	nodevcnt = 0;

	hp = NULL;

	for (i = 0; i <  plist->probe.nmdevs; i++) {
		mnum = ((minor_t *)(uintptr_t)(plist->probe.mnum_list))[i];
		if (MDI_UNIT(mnum) == NULL) {
			cmn_err(CE_WARN, "md: Cannot probe %s since it does "
			    "not exist", md_shortname(mnum));
			nodevcnt++;
			continue;
		}
		tp = kmem_alloc(sizeof (probe_req_t), KM_SLEEP);
		tp->mnum = mnum;
		tp->private_handle = (void *)plist;
		tp->probe_fcn = probe_test;
		if (hp == NULL) {
			hp = (daemon_queue_t *)tp;
			hp->dq_prev = hp->dq_next = (daemon_queue_t *)tp;
		} else {
			tp->dq.dq_next = hp;
			tp->dq.dq_prev = hp->dq_prev;
			hp->dq_prev->dq_next = (daemon_queue_t *)tp;
			hp->dq_prev = (daemon_queue_t *)tp;
		}
	}

	*hdr = hp;
	if (nodevcnt > 0)
		plist->probe.nmdevs -= nodevcnt;

	/*
	 * If there are no devices to be probed because they were
	 * incorrect, then return an error.
	 */
	err = (plist->probe.nmdevs == 0) ? ENODEV : 0;

	return (err);
}

/*
 * This routine increments the I/O count for set I/O operations.  This
 * value is used to determine if an I/O can done.  If a release is in
 * process this will return an error and cause the I/O to be errored.
 */
int
md_inc_iocount(set_t setno)
{
	int	rc = 0;

	if (setno == 0)
		return (0);

	mutex_enter(&md_set_io[setno].md_io_mx);
	if (!(md_set_io[setno].io_state & MD_SET_ACTIVE)) {
		rc = EIO;
		goto out;
	}

	ASSERT(md_set_io[setno].io_cnt >= 0);
	md_set_io[setno].io_cnt++;

out:	mutex_exit(&md_set_io[setno].md_io_mx);
	return (rc);
}

void
md_inc_iocount_noblock(set_t setno)
{

	if (setno == 0)
		return;

	mutex_enter(&md_set_io[setno].md_io_mx);
	md_set_io[setno].io_cnt++;
	mutex_exit(&md_set_io[setno].md_io_mx);
}
void
md_dec_iocount(set_t setno)
{

	if (setno == 0)
		return;

	mutex_enter(&md_set_io[setno].md_io_mx);
	md_set_io[setno].io_cnt--;
	ASSERT(md_set_io[setno].io_cnt >= 0);
	if ((md_set_io[setno].io_state & MD_SET_RELEASE) &&
	    (md_set_io[setno].io_cnt == 0))
		cv_broadcast(&md_set_io[setno].md_io_cv);
	mutex_exit(&md_set_io[setno].md_io_mx);
}

int
md_isblock_setio(set_t setno)
{
	int	rc = 0;

	if (setno == 0)
		return (0);

	mutex_enter(&md_set_io[setno].md_io_mx);
	if (md_set_io[setno].io_state & MD_SET_RELEASE)
		rc = 1;

	mutex_exit(&md_set_io[setno].md_io_mx);
	return (rc);
}

int
md_block_setio(set_t setno)
{
	int	rc = 0;

	if (setno == 0)
		return (1);

	mutex_enter(&md_set_io[setno].md_io_mx);
	md_set_io[setno].io_state = MD_SET_RELEASE;

	while (md_set_io[setno].io_cnt > 0) {
		cv_wait(&md_set_io[setno].md_io_cv,
		    &md_set_io[setno].md_io_mx);
	}
	rc = 1;


	ASSERT(md_set_io[setno].io_cnt == 0);
	mutex_exit(&md_set_io[setno].md_io_mx);

	return (rc);
}

void
md_clearblock_setio(set_t setno)
{
	if (setno == 0)
		return;

	mutex_enter(&md_set_io[setno].md_io_mx);
	md_set_io[setno].io_state = MD_SET_ACTIVE;
	mutex_exit(&md_set_io[setno].md_io_mx);
}

void
md_unblock_setio(set_t setno)
{
	if (setno == 0)
		return;

	mutex_enter(&md_set_io[setno].md_io_mx);
#ifdef DEBUG
	if (md_set_io[setno].io_cnt != 0) {
		cmn_err(CE_NOTE, "set %d count was %ld at take",
		    setno, md_set_io[setno].io_cnt);
	}
#endif /* DEBUG */

	md_set_io[setno].io_state = MD_SET_ACTIVE;
	md_set_io[setno].io_cnt = 0;
	mutex_exit(&md_set_io[setno].md_io_mx);
}

/*
 * Test and set version of the md_block_setio.
 * Set the io_state to keep new I/O from being issued.
 * If there is I/O currently in progress, then set io_state to active
 * and return failure.  Otherwise, return a 1 for success.
 *
 * Used in a MN diskset since the commd must be suspended before
 * this node can attempt to withdraw from a diskset.  But, with commd
 * suspended, I/O may have been issued that can never finish until
 * commd is resumed (allocation of hotspare, etc). So, if I/O is
 * outstanding after diskset io_state is marked RELEASE, then set diskset
 * io_state back to ACTIVE and return failure.
 */
int
md_tas_block_setio(set_t setno)
{
	int	rc;

	if (setno == 0)
		return (1);

	mutex_enter(&md_set_io[setno].md_io_mx);
	md_set_io[setno].io_state = MD_SET_RELEASE;

	if (md_set_io[setno].io_cnt > 0) {
		md_set_io[setno].io_state = MD_SET_ACTIVE;
		rc = 0;
	} else {
		rc = 1;
	}

	mutex_exit(&md_set_io[setno].md_io_mx);

	return (rc);
}

void
md_biodone(struct buf *pb)
{
	minor_t	mnum;
	set_t	setno;
	mdi_unit_t	*ui;

	mnum = getminor(pb->b_edev);
	setno = MD_MIN2SET(mnum);

	if (setno == 0) {
		biodone(pb);
		return;
	}

#ifdef DEBUG
	ui = MDI_UNIT(mnum);
	if (!md_unit_isopen(ui))
		cmn_err(CE_NOTE, "io after close on %s\n", md_shortname(mnum));
#endif /* DEBUG */

	/*
	 * Handle the local diskset
	 */
	if (md_set_io[setno].io_cnt > 0)
		md_dec_iocount(setno);

#ifdef DEBUG
	/*
	 * this is being done after the lock is dropped so there
	 * are cases it may be invalid.  It is advisory.
	 */
	if (md_set_io[setno].io_state & MD_SET_RELEASE) {
		/* Only display this error once for this metadevice */
		if ((ui->ui_tstate & MD_RELEASE_IOERR_DONE) == 0) {
			cmn_err(CE_NOTE,
			    "I/O to %s attempted during set RELEASE\n",
			    md_shortname(mnum));
			ui->ui_tstate |= MD_RELEASE_IOERR_DONE;
		}
	}
#endif /* DEBUG */

	biodone(pb);
}


/*
 * Driver special private devt handling routine
 * INPUT:  md_dev64_t
 * OUTPUT: dev_t, 32 bit on a 32 bit kernel, 64 bit on a 64 bit kernel.
 */
dev_t
md_dev64_to_dev(md_dev64_t dev)
{
	major_t major = (major_t)(dev >> NBITSMINOR64) & MAXMAJ64;
	minor_t minor = (minor_t)(dev & MAXMIN64);

	return (makedevice(major, minor));

}

/*
 * Driver private makedevice routine
 * INPUT:  major_t major, minor_t minor
 * OUTPUT: md_dev64_t, no matter if on 32 bit or 64 bit kernel.
 */
md_dev64_t
md_makedevice(major_t major, minor_t minor)
{
	return (((md_dev64_t)major << NBITSMINOR64) | minor);

}


/*
 * Driver private devt md_getmajor routine
 * INPUT:  dev	a 64 bit container holding either a 32 bit or a 64 bit device
 * OUTPUT: the appropriate major number
 */
major_t
md_getmajor(md_dev64_t dev)
{
	major_t major = (major_t)(dev >> NBITSMINOR64) & MAXMAJ64;

	if (major == 0) {
		/* Here we were given a 32bit dev */
		major = (major_t)(dev >> NBITSMINOR32) & MAXMAJ32;
	}
	return (major);
}

/*
 * Driver private devt md_getminor routine
 * INPUT:  dev	a 64 bit container holding either a 32 bit or a 64 bit device
 * OUTPUT: the appropriate minor number
 */
minor_t
md_getminor(md_dev64_t dev)
{
	minor_t minor;
	major_t major = (major_t)(dev >> NBITSMINOR64) & MAXMAJ64;

	if (major == 0) {
		/* Here we were given a 32bit dev */
		minor = (minor_t)(dev & MAXMIN32);
	} else {
		minor = (minor_t)(dev & MAXMIN64);
	}
	return (minor);
}

int
md_check_ioctl_against_unit(int cmd, mdc_unit_t c)
{
	/*
	 * If the metadevice is an old style device, it has a vtoc,
	 *	in that case all reading EFI ioctls are not applicable.
	 * If the metadevice has an EFI label, reading vtoc and geom ioctls
	 *	are not supposed to work.
	 */
	switch (cmd) {
		case DKIOCGGEOM:
		case DKIOCGAPART:
			/* if > 2 TB then fail */
			if (c.un_total_blocks > MD_MAX_BLKS_FOR_EXTVTOC) {
				return (ENOTSUP);
			}
			break;
		case DKIOCGVTOC:
			/* if > 2 TB then fail */
			if (c.un_total_blocks > MD_MAX_BLKS_FOR_EXTVTOC) {
				return (ENOTSUP);
			}

			/* if > 1 TB but < 2TB return overflow */
			if (c.un_revision & MD_64BIT_META_DEV) {
				return (EOVERFLOW);
			}
			break;
		case DKIOCGEXTVTOC:
			/* if > 2 TB then fail */
			if (c.un_total_blocks > MD_MAX_BLKS_FOR_EXTVTOC) {
				return (ENOTSUP);
			}
			break;
		case DKIOCGETEFI:
		case DKIOCPARTITION:
			if ((c.un_flag & MD_EFILABEL) == 0) {
				return (ENOTSUP);
			}
			break;

		case DKIOCSETEFI:
		/* setting an EFI label should always be ok */
			return (0);

		case DKIOCSVTOC:
			/* if > 2 TB then fail */
			if (c.un_total_blocks > MD_MAX_BLKS_FOR_EXTVTOC) {
				return (ENOTSUP);
			}

			/* if > 1 TB but < 2TB return overflow */
			if (c.un_revision & MD_64BIT_META_DEV) {
				return (EOVERFLOW);
			}
			break;
		case DKIOCSEXTVTOC:
			if (c.un_total_blocks > MD_MAX_BLKS_FOR_EXTVTOC) {
				return (ENOTSUP);
			}
			break;
	}
	return (0);
}

/*
 * md_vtoc_to_efi_record()
 * Input:  record id of the vtoc record
 * Output: record id of the efi record
 * Function:
 *	- reads the  volume name from the vtoc record
 *	- converts the volume name to a format, libefi understands
 *	- creates a new record of size MD_EFI_PARTNAME_BYTES
 *	- stores the volname in that record,
 *	- commits that record
 *	- returns the recid of the efi record.
 * Caveat Emptor:
 *	The calling routine must do something like
 *	- un->c.un_vtoc_id = md_vtoc_to_efi_record(vtoc_recid)
 *	- commit(un)
 *	- delete(vtoc_recid)
 *	in order to keep the mddb consistent in case of a panic in the middle.
 * Errors:
 *	- returns 0 on any error
 */
mddb_recid_t
md_vtoc_to_efi_record(mddb_recid_t vtoc_recid, set_t setno)
{
	struct vtoc	*vtoc;
	ushort_t	*v;
	mddb_recid_t	efi_recid;
	int		i;

	if (mddb_getrecstatus(vtoc_recid) != MDDB_OK) {
		return (0);
	}
	vtoc = (struct vtoc *)mddb_getrecaddr(vtoc_recid);
	efi_recid = mddb_createrec(MD_EFI_PARTNAME_BYTES, MDDB_EFILABEL, 0,
	    MD_CRO_32BIT, setno);
	if (efi_recid < 0) {
		return (0);
	}
	v = (ushort_t *)mddb_getrecaddr(efi_recid);

	/* This for loop read, converts and writes */
	for (i = 0; i < LEN_DKL_VVOL; i++) {
		v[i] = LE_16((uint16_t)vtoc->v_volume[i]);
	}
	/* commit the new record */
	mddb_commitrec_wrapper(efi_recid);

	return (efi_recid);
}

/*
 * Send a kernel message.
 * user has to provide for an allocated result structure
 * If the door handler disappears we retry forever emitting warnings every so
 * often.
 * TODO: make this a flaggable attribute so that the caller can decide if the
 *	 message is to be a 'one-shot' message or not.
 */
int
mdmn_ksend_message(
	set_t		setno,
	md_mn_msgtype_t	type,
	uint_t		flags,
	char		*data,
	int		size,
	md_mn_kresult_t	*result)
{
	door_arg_t	da;
	md_mn_kmsg_t	*kmsg;
	uint_t		retry_cnt = 0;
	int		rval;

	if (size > MDMN_MAX_KMSG_DATA)
		return (ENOMEM);
	kmsg = kmem_zalloc(sizeof (md_mn_kmsg_t), KM_SLEEP);
	kmsg->kmsg_flags = flags;
	kmsg->kmsg_setno = setno;
	kmsg->kmsg_type	= type;
	kmsg->kmsg_size	= size;
	bcopy(data, &(kmsg->kmsg_data), size);

#ifdef DEBUG_COMM
	printf("send msg: set=%d, flags=%d, type=%d, txid = 0x%llx,"
	    " size=%d, data=%d, data2=%d\n",
	    kmsg->kmsg_setno, kmsg->kmsg_flags, kmsg->kmsg_type,
	    kmsg->kmsg_size, *(int *)data, *(int *)(char *)(&kmsg->kmsg_data));


#endif /* DEBUG_COMM */

	da.data_ptr	= (char *)(kmsg);
	da.data_size	= sizeof (md_mn_kmsg_t);
	da.desc_ptr	= NULL;
	da.desc_num	= 0;
	da.rbuf		= (char *)result;
	da.rsize	= sizeof (*result);

	/*
	 * Wait for the door handle to be established.
	 */

	while (mdmn_door_did == -1) {
		if ((++retry_cnt % MD_MN_WARN_INTVL) == 0) {
			cmn_err(CE_WARN, "door handle not yet ready. "
			    "Check if /usr/lib/lvm/mddoors is running");
		}
		delay(md_hz);
	}
	retry_cnt = 0;

	while ((rval = door_ki_upcall_limited(mdmn_door_handle, &da, NULL,
	    SIZE_MAX, 0)) != 0) {
		if (rval == EAGAIN)  {
			if ((++retry_cnt % MD_MN_WARN_INTVL) == 0) {
				cmn_err(CE_WARN, "door call failed. "
				"Check if /usr/lib/lvm/mddoors is running");
			}
		} else {
			cmn_err(CE_WARN,
			    "md door call failed. Returned %d", rval);
		}
		delay(md_hz);
	}
	kmem_free(kmsg, sizeof (md_mn_kmsg_t));

	/*
	 * Attempt to determine if the message failed (with an RPC_FAILURE)
	 * because we are in the middle of shutting the system down.
	 *
	 * If message failed with an RPC_FAILURE when rpc.mdcommd had
	 * been gracefully shutdown (md_mn_is_commd_present returns FALSE)
	 * then don't retry the message anymore.  If message
	 * failed due to any other reason, then retry up to MD_MN_WARN_INTVL
	 * times which should allow a shutting down system time to
	 * notify the kernel of a graceful shutdown of rpc.mdcommd.
	 *
	 * Caller of this routine will need to check the md_mn_commd_present
	 * flag and the failure error in order to determine whether to panic
	 * or not.  If md_mn_commd_present is set to 0 and failure error
	 * is RPC_FAILURE, the calling routine should not panic since the
	 * system is in the process of being shutdown.
	 *
	 */

	retry_cnt = 0;

	if (result->kmmr_comm_state == MDMNE_RPC_FAIL) {
		while (md_mn_is_commd_present() == 1) {
			if ((++retry_cnt % MD_MN_WARN_INTVL) == 0)
				break;
			delay(md_hz);
		}
	}

	return (0);
}

/*
 * Called to propagate the capability of a metadevice to all nodes in the set.
 *
 * On entry, lockp is set if the function has been called from within an ioctl.
 *
 * IOLOCK_RETURN_RELEASE, which drops the md_ioctl_lock is called in this
 * routine to enable other mdioctls to enter the kernel while this
 * thread of execution waits on the completion of mdmn_ksend_message. When
 * the message is completed the thread continues and md_ioctl_lock must be
 * reacquired.  Even though md_ioctl_lock is interruptable, we choose to
 * ignore EINTR as we must not return without acquiring md_ioctl_lock.
 */

int
mdmn_send_capability_message(minor_t mnum, volcap_t vc, IOLOCK *lockp)
{
	md_mn_msg_setcap_t	msg;
	md_mn_kresult_t		*kres;
	mdi_unit_t		*ui = MDI_UNIT(mnum);
	int			ret;
	k_sigset_t		oldmask, newmask;

	(void) strncpy((char *)&msg.msg_setcap_driver,
	    md_ops[ui->ui_opsindex]->md_driver.md_drivername, MD_DRIVERNAMELEN);
	msg.msg_setcap_mnum = mnum;
	msg.msg_setcap_set = vc.vc_set;

	if (lockp)
		IOLOCK_RETURN_RELEASE(0, lockp);
	kres = kmem_zalloc(sizeof (md_mn_kresult_t), KM_SLEEP);

	/*
	 * Mask signals for the mdmd_ksend_message call.  This keeps the door
	 * interface from failing if the user process receives a signal while
	 * in mdmn_ksend_message.
	 */
	sigfillset(&newmask);
	sigreplace(&newmask, &oldmask);
	ret = (mdmn_ksend_message(MD_MIN2SET(mnum), MD_MN_MSG_SET_CAP,
	    MD_MSGF_NO_LOG, (char *)&msg, sizeof (md_mn_msg_setcap_t),
	    kres));
	sigreplace(&oldmask, (k_sigset_t *)NULL);

	if (!MDMN_KSEND_MSG_OK(ret, kres)) {
		mdmn_ksend_show_error(ret, kres, "MD_MN_MSG_SET_CAP");
		ret = EIO;
	}
	kmem_free(kres, sizeof (md_mn_kresult_t));

	if (lockp) {
		IOLOCK_RETURN_REACQUIRE(lockp);
	}
	return (ret);
}

/*
 * Called to clear all of the transient capabilities for a metadevice when it is
 * not open on any node in the cluster
 * Called from close for mirror and sp.
 */

void
mdmn_clear_all_capabilities(minor_t mnum)
{
	md_isopen_t	clumsg;
	int		ret;
	md_mn_kresult_t	*kresult;
	volcap_t	vc;
	k_sigset_t	oldmask, newmask;

	clumsg.dev = md_makedevice(md_major, mnum);
	clumsg.mde = mdnullerror;
	/*
	 * The check open message doesn't have to be logged, nor should the
	 * result be stored in the MCT. We want an up-to-date state.
	 */
	kresult = kmem_zalloc(sizeof (md_mn_kresult_t), KM_SLEEP);

	/*
	 * Mask signals for the mdmd_ksend_message call.  This keeps the door
	 * interface from failing if the user process receives a signal while
	 * in mdmn_ksend_message.
	 */
	sigfillset(&newmask);
	sigreplace(&newmask, &oldmask);
	ret = mdmn_ksend_message(MD_MIN2SET(mnum),
	    MD_MN_MSG_CLU_CHECK,
	    MD_MSGF_STOP_ON_ERROR | MD_MSGF_NO_LOG | MD_MSGF_NO_MCT,
	    (char *)&clumsg, sizeof (clumsg), kresult);
	sigreplace(&oldmask, (k_sigset_t *)NULL);

	if ((ret == 0) && (kresult->kmmr_exitval == 0)) {
		/*
		 * Not open on any node, clear all capabilities, eg ABR and
		 * DMR
		 */
		vc.vc_set = 0;
		(void) mdmn_send_capability_message(mnum, vc, NULL);
	}
	kmem_free(kresult, sizeof (md_mn_kresult_t));
}

/*
 * mdmn_ksend_show_error:
 * ---------------------
 * Called to display the error contents of a failing mdmn_ksend_message() result
 *
 * Input:
 *	rv	- return value from mdmn_ksend_message()
 *	kres	- pointer to result structure filled in by mdmn_ksend_message
 *	s	- Informative message to identify failing condition (e.g.
 *		  "Ownership change") This string will be displayed with
 *		  cmn_err(CE_WARN, "%s *FAILED*",...) to alert the system
 *		  administrator
 */
void
mdmn_ksend_show_error(int rv, md_mn_kresult_t *kres, const char *s)
{
	if (rv == 0) {
		cmn_err(CE_WARN, "%s *FAILED*", s);
		cmn_err(CE_CONT, "exit_val = %d, comm_state = %d, failing_node"
		    " = %d", kres->kmmr_exitval, kres->kmmr_comm_state,
		    kres->kmmr_failing_node);
	} else {
		cmn_err(CE_WARN, "%s *FAILED*, return value = %d", s, rv);
	}
}

/*
 * Callback routine for resync thread. If requested to suspend we mark the
 * commd as not being present.
 */
boolean_t
callb_md_mrs_cpr(void *arg, int code)
{
	callb_cpr_t *cp = (callb_cpr_t *)arg;
	int ret = 0;				/* assume success */

	mutex_enter(cp->cc_lockp);

	switch (code) {
	case CB_CODE_CPR_CHKPT:
		/*
		 * Mark the rpc.mdcommd as no longer present. We are trying to
		 * suspend the system and so we should expect RPC failures to
		 * occur.
		 */
		md_mn_clear_commd_present();
		cp->cc_events |= CALLB_CPR_START;
		while (!(cp->cc_events & CALLB_CPR_SAFE))
			/* cv_timedwait() returns -1 if it times out. */
			if ((ret = cv_timedwait(&cp->cc_callb_cv, cp->cc_lockp,
			    lbolt + CPR_KTHREAD_TIMEOUT_SEC * hz)) == -1)
				break;
			break;

	case CB_CODE_CPR_RESUME:
		cp->cc_events &= ~CALLB_CPR_START;
		cv_signal(&cp->cc_stop_cv);
		break;
	}
	mutex_exit(cp->cc_lockp);
	return (ret != -1);
}


void
md_rem_hspname(set_t setno, mdkey_t n_key)
{
	int	s;
	int	max_sides;


	/* All entries removed are in the same diskset */
	if (md_get_setstatus(setno) & MD_SET_MNSET)
		max_sides = MD_MNMAXSIDES;
	else
		max_sides = MD_MAXSIDES;

	for (s = 0; s < max_sides; s++)
		(void) md_remdevname(setno, s, n_key);
}


int
md_rem_selfname(minor_t selfid)
{
	int	s;
	set_t	setno = MD_MIN2SET(selfid);
	int	max_sides;
	md_dev64_t	dev;
	struct nm_next_hdr	*nh;
	struct nm_name	*n;
	mdkey_t key;

	/*
	 * Get the key since remove routine expects it
	 */
	dev = md_makedevice(md_major, selfid);
	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		return (ENOENT);
	}

	if ((n = (struct nm_name *)lookup_entry(nh, setno, MD_SIDEWILD,
	    MD_KEYWILD, dev, 0L)) == NULL) {
		return (ENOENT);
	}

	/* All entries removed are in the same diskset */
	key = n->n_key;
	if (md_get_setstatus(setno) & MD_SET_MNSET)
		max_sides = MD_MNMAXSIDES;
	else
		max_sides = MD_MAXSIDES;

	for (s = 0; s < max_sides; s++)
		(void) md_remdevname(setno, s, key);

	return (0);
}

void
md_upd_set_unnext(set_t setno, unit_t un)
{
	if (un < md_set[setno].s_un_next) {
		md_set[setno].s_un_next = un;
	}
}

struct hot_spare_pool *
find_hot_spare_pool(set_t setno, int hsp_id)
{
	hot_spare_pool_t *hsp;

	hsp = (hot_spare_pool_t *)md_set[setno].s_hsp;
	while (hsp != NULL) {
		if (hsp->hsp_self_id == hsp_id)
			return (hsp);
		hsp = hsp->hsp_next;
	}

	return ((hot_spare_pool_t *)0);
}
