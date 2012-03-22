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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/t_lock.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/kmem.h>
#include <vm/page.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/lvm/md_trans.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/filio.h>
#include <sys/lvm/md_notify.h>
#include <sys/callb.h>
#include <sys/disp.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

extern int		md_status;
extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];
extern md_ops_t		trans_md_ops;
extern md_krwlock_t	md_unit_array_rw;
extern uint_t		mt_debug;

extern major_t	md_major;

static mt_unit_t *
trans_getun(minor_t mnum, md_error_t *mde, int flags, IOLOCK *lock)
{
	mt_unit_t	*un;
	mdi_unit_t	*ui;
	set_t		setno = MD_MIN2SET(mnum);

	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits)) {
		(void) mdmderror(mde, MDE_INVAL_UNIT, mnum);
		return (NULL);
	}

	if (! (flags & STALE_OK)) {
		if (md_get_setstatus(setno) & MD_SET_STALE) {
			(void) mdmddberror(mde, MDE_DB_STALE, mnum, setno);
			return (NULL);
		}
	}

	ui = MDI_UNIT(mnum);
	if (flags & NO_OLD) {
		if (ui != NULL) {
			(void) mdmderror(mde, MDE_UNIT_ALREADY_SETUP, mnum);
			return (NULL);
		}
		return ((mt_unit_t *)1);
	}

	if (ui == NULL) {
		(void) mdmderror(mde, MDE_UNIT_NOT_SETUP, mnum);
		return (NULL);
	}

	if (flags & ARRAY_WRITER)
		md_array_writer(lock);
	else if (flags & ARRAY_READER)
		md_array_reader(lock);

	if (!(flags & NO_LOCK)) {
		if (flags & WR_LOCK)
			(void) md_ioctl_writerlock(lock, ui);
		else /* RD_LOCK */
			(void) md_ioctl_readerlock(lock, ui);
	}
	un = (mt_unit_t *)MD_UNIT(mnum);

	if (un->c.un_type != MD_METATRANS) {
		(void) mdmderror(mde, MDE_NOT_MT, mnum);
		return (NULL);
	}

	return (un);
}

#ifdef	DEBUG
/*
 * DEBUG ROUTINES
 * 	THESE ROUTINES ARE ONLY USED WHEN ASSERTS ARE ENABLED
 */

extern int		(*mdv_strategy_tstpnt)(buf_t *, int, void*);

/*
 * return the global stats struct
 */
static int
trans_get_transstats(void *d, int mode)
{
	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);

	if (migp->size == 0) {
		migp->size = sizeof (struct transstats);
		return (0);
	}

	if (migp->size < sizeof (struct transstats))
		return (EFAULT);

	if (ddi_copyout(&transstats, (caddr_t)(uintptr_t)migp->mdp,
	    sizeof (struct transstats), mode))
		return (EFAULT);
	return (0);
}

/*
 * test ioctls
 */
/*
 * TEST TRYGETBLK
 */
/*ARGSUSED1*/
static int
trans_test_trygetblk(void *d, int mode, IOLOCK *lock)
{
	mt_unit_t	*un;
	int		test;
	dev_t		dev;
	struct buf	*bp;
	struct buf	*trygetblk();

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);
	migp->size = 0;

	un = trans_getun(migp->id, &migp->mde,
	    RD_LOCK, lock);
	if (un == NULL)
		return (EINVAL);

	dev = un->un_m_dev;

	/*
	 * test 1 -- don't find nonexistant buf
	 */
	test = 1;
	if (bp = trygetblk(dev, 0))
		goto errout;

	/*
	 * test 2 - don't find stale buf
	 */
	test = 2;
	if ((bp = getblk(dev, 0, DEV_BSIZE)) == NULL)
		goto errout;
	bp->b_flags |= (B_STALE|B_DONE);
	brelse(bp);
	if (bp = trygetblk(dev, 0))
		goto errout;

	/*
	 * test 3 -- don't find busy buf
	 */
	test = 3;
	if ((bp = getblk(dev, 0, DEV_BSIZE)) == NULL)
		goto errout;
	if (trygetblk(dev, 0))
		goto errout;
	bp->b_flags |= B_STALE;
	brelse(bp);

	/*
	 * test 4 -- don't find not-done buf
	 */
	test = 4;
	if ((bp = getblk(dev, 0, DEV_BSIZE)) == NULL)
		goto errout;
	brelse(bp);
	if (bp = trygetblk(dev, 0))
		goto errout;

	/*
	 * test 5 -- find an idle buf
	 */
	test = 5;
	if ((bp = bread(dev, 0, DEV_BSIZE)) == NULL)
		goto errout;
	brelse(bp);
	if ((bp = trygetblk(dev, 0)) == NULL)
		goto errout;
	bp->b_flags |= B_STALE;
	brelse(bp);
	bp = 0;

	test = 0;	/* no test failed */
errout:
	if (bp) {
		bp->b_flags |= B_STALE;
		brelse(bp);
	}
	migp->size = test;
	if (test)
		return (EINVAL);
	return (0);
}
/*
 * TEST TRYGETPAGE
 */
static page_t *
trans_trypage(struct vnode *vp, uint_t off)
{
	page_t		*pp;

	/*
	 * get a locked page
	 */
	if ((pp = page_lookup_nowait(vp, off, SE_EXCL)) == NULL)
		return (NULL);
	/*
	 * get the iolock
	 */
	if (!page_io_trylock(pp)) {
		page_unlock(pp);
		return (NULL);
	}
	return (pp);
}

/*ARGSUSED1*/
static int
trans_test_trypage(void *d, int mode, IOLOCK *lock)
{
	mt_unit_t		*un;
	int			test;
	dev_t			dev;
	struct page		*pp;
	struct vnode		*devvp;
	struct vnode		*cvp;
	extern struct vnode	*common_specvp(struct vnode *);
	extern void		pvn_io_done(struct page *);

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);
	migp->size = 0;

	un = trans_getun(migp->id, &migp->mde,
	    RD_LOCK, lock);
	if (un == NULL)
		return (EINVAL);

	dev = un->un_m_dev;
	devvp = makespecvp(dev, VBLK);
	cvp = common_specvp(devvp);

	/*
	 * get rid of the devices pages
	 */
	(void) VOP_PUTPAGE(cvp, (offset_t)0, (uint_t)0, B_INVAL, CRED(), NULL);

	/*
	 * test 1 -- don't find nonexistant page
	 */
	test = 1;
	if (pp = trans_trypage(cvp, 0))
		goto errout;

	/*
	 * test 2 -- don't find busy page
	 */
	test = 2;
	if ((pp = page_create(cvp, 0, 1, PG_WAIT)) == NULL)
		goto errout;
	if (trans_trypage(cvp, 0))
		goto errout;
	pvn_io_done(pp);
	pp = 0;

	/*
	 * test 3 - find an idle page
	 */
	test = 3;
	if ((pp = page_create(cvp, 0, 1, PG_WAIT)) == NULL)
		goto errout;
	pvn_io_done(pp);
	if ((pp = trans_trypage(cvp, 0)) == NULL)
		goto errout;
	pvn_io_done(pp);
	pp = 0;

	test = 0;	/* no test failed */
errout:
	if (pp)
		pvn_io_done(pp);
	/*
	 * get rid of the file's pages
	 */
	(void) VOP_PUTPAGE(cvp, (offset_t)0, (uint_t)0, B_INVAL, CRED(), NULL);
	VN_RELE(devvp);

	migp->size = test;
	if (test)
		return (EINVAL);
	return (0);
}
/*
 * TEST TSD
 */
#define	NKEYS		(7)
#define	NTSDTHREADS	(3)
struct tothread {
	int		test;
	int		error;
	int		exits;
	int		step;
	kmutex_t	lock;
	kcondvar_t	cv;
};
static uint_t		keys[NKEYS];
static struct tothread	tta[NTSDTHREADS];
static int		allocatorvalue;
static int		okdestructoralloc;

static void
trans_test_stepwait(struct tothread *tp, int step)
{
	/*
	 * wait for other thread
	 */
	mutex_enter(&tp->lock);
	while (tp->step < step)
		cv_wait(&tp->cv, &tp->lock);
	mutex_exit(&tp->lock);
}

static void
trans_test_step(struct tothread *tp, int step)
{
	/*
	 * wakeup other threads
	 */
	mutex_enter(&tp->lock);
	tp->step = step;
	cv_broadcast(&tp->cv);
	mutex_exit(&tp->lock);
}

static void
trans_test_destructor(void *voidp)
{
	int		exits;
	struct tothread	*tp	= voidp;

	/*
	 * check that threads clean up *all* TSD at exit
	 */
	mutex_enter(&tp->lock);
	exits = ++tp->exits;
	mutex_exit(&tp->lock);
	if (exits >= NKEYS)
		trans_test_step(tp, 3);
}

static void
trans_test_destructor_alloc(void *voidp)
{
	int	*value	= voidp;

	okdestructoralloc = 0;
	if (value) {
		if (*value == allocatorvalue)
			okdestructoralloc = 1;
		md_trans_free((caddr_t)value, sizeof (value));
	}
}

static void *
trans_test_allocator(void)
{
	int	*value;

	value = (int *)md_trans_zalloc(sizeof (value));
	*value = allocatorvalue;
	return ((void *)value);
}

/*
 * thread used to test TSD destroy functionality
 */
static void
trans_test_thread(struct tothread *tp)
{
	int	i;
	callb_cpr_t	cprinfo;

	/*
	 * Register cpr callback
	 */
	CALLB_CPR_INIT(&cprinfo, &tp->lock, callb_generic_cpr,
	    "trans_test_thread");

	/*
	 * get some TSD
	 */
	for (i = NKEYS - 1; i >= 0; --i)
		if (tsd_set(keys[i], tp)) {
			tp->error = 500;
			goto errout;
		}
	/*
	 * tell parent that we have TSD
	 */
	trans_test_step(tp, 1);

	/*
	 * wait for parent to destroy some of our TSD
	 */
	trans_test_stepwait(tp, 2);

	/*
	 * make sure that the appropriate TSD was destroyed
	 */
	if ((tsd_get(keys[0]) != NULL) ||
	    (tsd_get(keys[NKEYS-1]) != NULL) ||
	    (tsd_get(keys[NKEYS>>1]) != NULL)) {
		tp->error = 510;
		goto errout;
	}
	for (i = 0; i < NKEYS; ++i)
		if (tsd_get(keys[i]) != tp)
			if (i != 0 && i != NKEYS - 1 && i != NKEYS >> 1) {
				tp->error = 520;
				goto errout;
			}

	/*
	 * set up cpr exit
	 */
	mutex_enter(&tp->lock);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
errout:
	/*
	 * error -- make sure the parent will wake up (error code in tp)
	 */
	trans_test_step(tp, 3);

	/*
	 * set up cpr exit
	 */
	mutex_enter(&tp->lock);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

static void
trans_test_threadcreate(struct tothread *tp)
{
	/*
	 * initialize the per thread struct and make a thread
	 */
	bzero((caddr_t)tp, sizeof (struct tothread));

	mutex_init(&tp->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&tp->cv, NULL, CV_DEFAULT, NULL);

	(void) thread_create(NULL, 0, trans_test_thread, tp, 0, &p0,
	    TS_RUN, minclsyspri);
}
/*
 * driver for TSD tests -- *NOT REENTRANT*
 */
/*ARGSUSED1*/
static int
trans_test_tsd(void *d, int mode)
{
	int		test;
	uint_t		rekeys[NKEYS];
	int		i;
	uint_t		key;
	int		error;

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);
	migp->size = 0;

	/*
	 * destroy old keys, if any
	 */
	for (i = 0; i < NKEYS; ++i)
		tsd_destroy(&keys[i]);
	/*
	 * test 1 -- simple create and destroy keys tests
	 */
	test = 1;
	error = 0;
	for (i = 0; i < NKEYS; ++i) {
		tsd_create(&keys[i], NULL);

		/* get with no set should return NULL */
		if (tsd_get(keys[i]) != NULL) {
			error = 100;
			goto errout;
		}

		/* destroyed key should be 0 */
		key = keys[i];
		tsd_destroy(&keys[i]);
		if (keys[i]) {
			error = 110;
			goto errout;
		}

		/* destroy the key twice */
		keys[i] = key;
		tsd_destroy(&keys[i]);

		/* destroyed key should be 0 */
		if (keys[i]) {
			error = 120;
			goto errout;
		}

		/* getting a destroyed key should return NULL */
		if (tsd_get(keys[i]) != NULL) {
			error = 130;
			goto errout;
		}
		/* recreate the key */
		tsd_create(&keys[i], NULL);

		/* should be the same key as before */
		if (key != keys[i]) {
			error = 140;
			goto errout;
		}

		/* initial value should be NULL */
		if (tsd_get(keys[i]) != NULL) {
			error = 150;
			goto errout;
		}

		/* cleanup */
		tsd_destroy(&keys[i]);
	}

	/*
	 * test 2 -- recreate keys
	 */
	test = 2;
	error = 0;
	for (i = 0; i < NKEYS; ++i)
		tsd_create(&keys[i], NULL);
	for (i = 0; i < NKEYS; ++i) {
		/* make sure the keys were created */
		if (keys[i] == 0) {
			error = 200;
			goto errout;
		}

		/* make sure that recreating key doesn't change it */
		rekeys[i] = keys[i];
		tsd_create(&rekeys[i], NULL);
		if (rekeys[i] != keys[i]) {
			error = 210;
			goto errout;
		}
	}
	for (i = 0; i < NKEYS; ++i)
		tsd_destroy(&keys[i]);

	/*
	 * test 3 -- check processing for unset and destroyed keys
	 */
	test = 3;
	error = 0;

	/* getting a 0 key returns NULL */
	if (tsd_get(0) != NULL) {
		error = 300;
		goto errout;
	}

	/* setting a 0 key returns error */
	if (tsd_set(0, NULL) != EINVAL) {
		error = 310;
		goto errout;
	}
	tsd_create(&key, NULL);

	/* setting a created key returns no error */
	if (tsd_set(key, NULL) == EINVAL) {
		error = 320;
		goto errout;
	}
	tsd_destroy(&key);

	/* setting a destroyed key returns error */
	if (tsd_set(key, NULL) != EINVAL) {
		error = 330;
		goto errout;
	}

	/*
	 * test 4 -- make sure that set and get work
	 */
	test = 4;
	error = 0;

	for (i = 0; i < NKEYS; ++i) {
		tsd_create(&keys[i], NULL);

		/* set a value */
		(void) tsd_set(keys[i], &key);

		/* get the value */
		if (tsd_get(keys[i]) != &key) {
			error = 400;
			goto errout;
		}

		/* set the value to NULL */
		(void) tsd_set(keys[i], NULL);

		/* get the NULL */
		if (tsd_get(keys[i]) != NULL) {
			error = 410;
			goto errout;
		}
	}
	/* cleanup */
	for (i = 0; i < NKEYS; ++i)
		tsd_destroy(&keys[i]);

	/*
	 * test 5 -- destroying keys w/multiple threads
	 */
	test = 5;
	error = 0;

	/* create the keys */
	for (i = 0; i < NKEYS; ++i)
		tsd_create(&keys[i], trans_test_destructor);

	/* create some threads */
	for (i = 0; i < NTSDTHREADS; ++i)
		trans_test_threadcreate(&tta[i]);

	/* wait for the threads to assign TSD */
	for (i = 0; i < NTSDTHREADS; ++i)
		trans_test_stepwait(&tta[i], 1);

	/* destroy some of the keys */
	tsd_destroy(&keys[0]);
	tsd_destroy(&keys[NKEYS - 1]);
	tsd_destroy(&keys[NKEYS >> 1]);
	tsd_destroy(&keys[NKEYS >> 1]);

	/* wakeup the threads -- they check that the destroy took */
	for (i = 0; i < NTSDTHREADS; ++i)
		trans_test_step(&tta[i], 2);

	/* wait for the threads to exit (also checks for TSD cleanup) */
	for (i = 0; i < NTSDTHREADS; ++i)
		trans_test_stepwait(&tta[i], 3);

	/* destroy the rest of the keys */
	for (i = 0; i < NKEYS; ++i)
		tsd_destroy(&keys[i]);

	/* check for error */
	for (i = 0; i < NTSDTHREADS; ++i) {
		if (!error)
			error = tta[i].error;
		mutex_destroy(&tta[i].lock);
		cv_destroy(&tta[i].cv);
	}

	/*
	 * test 6 -- test getcreate
	 */
	test = 6;
	error = 0;

	/* make sure the keys are destroyed */
	for (i = 0; i < NKEYS; ++i)
		tsd_destroy(&keys[i]);

	/* get w/create */
	for (i = 0; i < NKEYS; ++i) {
		allocatorvalue = i;
		if (*(int *)tsd_getcreate(&keys[i], trans_test_destructor_alloc,
		    trans_test_allocator) != allocatorvalue) {
			error = 600;
			goto errout;
		}
	}
	for (i = 0; i < NKEYS; ++i) {
		allocatorvalue = i;
		if (*(int *)tsd_get(keys[i]) != allocatorvalue) {
			error = 610;
			goto errout;
		}
	}
	/* make sure destructor gets called when we destroy the keys */
	for (i = 0; i < NKEYS; ++i) {
		allocatorvalue = i;
		okdestructoralloc = 0;
		tsd_destroy(&keys[i]);
		if (okdestructoralloc == 0) {
			error = 620;
			goto errout;
		}
	}

errout:
	/* make sure the keys are destroyed */
	for (i = 0; i < NKEYS; ++i)
		tsd_destroy(&keys[i]);

	/* return test # and error code (if any) */
	migp->size = test;
	return (error);
}

/*
 * Error Injection Structures, Data, and Functions:
 *
 * Error injection is used to test the Harpy error recovery system.  The
 * MD_IOC_INJECTERRORS ioctl is used to start or continue error injection on a
 * unit, and MD_IOC_STOPERRORS turns it off.  An mt_error structure is
 * associated with every trans device for which we are injecting errors.  When
 * MD_IOC_INJECTERRORS is issued, mdv_strategy_tstpnt is set to point to
 * trans_error_injector(), so that it gets called for every MDD I/O operation.
 *
 * The trans unit can be in one of three states:
 *
 *	count down -	Each I/O causes er_count_down to be decremented.
 *			When er_count_down reaches 0, an error is injected,
 *			the block number is remembered.  Without makeing
 *			special provisions, the log area would receive a
 *			small percentage of the injected errors.  Thus,
 *			trans_check_error() will be written, so that every
 *			other error is injected on the log.
 *
 *	suspend -	No errors are generated and the counters are not
 *			modified.  This is so that fsck/mkfs can do their thing
 *			(we're not testing them) and so that the test script can
 *			set up another test.  The transition back to the count
 *			down state occurs when MD_IOC_INJECTERRORS is invoked
 *			again.
 */

typedef enum {
	mte_count_down,
	mte_suspend,
	mte_watch_block
} mte_state;

typedef struct mt_error {
	struct mt_error	*er_next;	/* next error unit in list. */
	mte_state	er_state;
	mt_unit_t	*er_unitp;	/* unit to force errors on. */
	size_t		er_count_down;	/* i/o transactions until error. */
	size_t		er_increment;	/* increment for reset_count. */
	size_t		er_reset_count;	/* used to reset er_count_down */
	size_t		er_total_errors; /* count generated errors. */
	/* Following fields describe error we are injecting. */
	dev_t		er_bad_unit;	/* Unit associated with block in */
					/* error. */
	off_t		er_bad_block;	/* Block in error. */
} mt_error_t;

#define	ERROR_INCREMENT	(1)
#define	INITIAL_COUNT	(1)

static int		default_increment	= ERROR_INCREMENT;
static kmutex_t		error_mutex;	/* protects error_list */
static mt_error_t	error_list_head;
static int		initial_count		= INITIAL_COUNT;
static int		(*tstpnt_save)(buf_t *, int, void*) = NULL;

static mt_error_t *
find_by_mtunit(mt_unit_t *un, mt_error_t **pred_errp)
{
	mt_error_t	*errp	= (mt_error_t *)NULL;

	ASSERT(mutex_owned(&error_mutex) != 0);
	*pred_errp = &error_list_head;
	while ((errp = (*pred_errp)->er_next) != (mt_error_t *)NULL) {
		if (errp->er_unitp == un)
			break;
		*pred_errp = errp;
	}
	return (errp);
}

static mt_error_t *
find_by_dev(md_dev64_t dev)
{
	mt_error_t	*errp	= &error_list_head;

	ASSERT(mutex_owned(&error_mutex) != 0);
	while ((errp = errp->er_next) != (mt_error_t *)NULL) {
		if ((errp->er_unitp->un_m_dev == dev) ||
		    (errp->er_unitp->un_l_dev == dev))
			break;
	}
	return (errp);
}

static int
trans_check_error(buf_t *bp, mt_error_t *errp)
{
	int		rv	= 0;
	md_dev64_t	target	= md_expldev(bp->b_edev);

	ASSERT(mutex_owned(&error_mutex) != 0);
	switch (errp->er_state) {
	case mte_count_down:
		errp->er_count_down--;
		if (errp->er_count_down == 0) {
			/*
			 * Every other error that we inject should be on
			 * the log device.  Errors will be injected on the
			 * log device when errp->er_total_errors is even
			 * and on the master device when it is odd.  If
			 * this I/O is not for the appropriate device, we
			 * will set errp->er_count_down to 1, so that we
			 * can try again later.
			 */
			if ((((errp->er_total_errors % 2) == 0) &&
			    (errp->er_unitp->un_l_dev == target)) ||
			    (((errp->er_total_errors % 2) != 0) &&
			    (errp->er_unitp->un_m_dev == target))) {
				/* simulate an error */
				bp->b_flags |= B_ERROR;
				bp->b_error = EIO;
				/* remember the error. */
				errp->er_total_errors++;
				errp->er_bad_unit = bp->b_edev;
				errp->er_bad_block = bp->b_blkno;
				/* reset counters. */
				errp->er_count_down = errp->er_reset_count;
				errp->er_reset_count += errp->er_increment;
				rv = 1;
			} else {
				/* Try again next time. */
				errp->er_count_down = 1;
			}
		}
		break;

	case mte_suspend:
		/* No errors while suspended. */
		break;

	case mte_watch_block:
		if ((bp->b_edev == errp->er_bad_unit) &&
		    (bp->b_blkno == errp->er_bad_block)) {
			bp->b_flags |= B_ERROR;
			bp->b_error = EIO;
			rv = 1;
		}
		break;
	}
	return (rv);
}

static int
trans_error_injector(buf_t *bp, int flag, void* private)
{
	mt_error_t	*errp	= (mt_error_t *)NULL;
	int		(*tstpnt)(buf_t *, int, void*) = NULL;
	int		rv	= 0;
	md_dev64_t	target	= md_expldev(bp->b_edev);
	int		trv	= 0;
	mt_unit_t	*un;

	mutex_enter(&error_mutex);
	errp = find_by_dev(target);
	if (errp != (mt_error_t *)NULL) {
		un = errp->er_unitp;
		if (target == un->un_m_dev) {
			/* Target is our master device. */
			rv = trans_check_error(bp, errp);
		}
		if (target == un->un_l_dev) {
			/*
			 * Target is our log device.  Unfortunately, the same
			 * device may also be used for the MDD database.
			 * Therefore, we need to make sure that the I/O is for
			 * the range of blocks designated as our log.
			 */
			if ((bp->b_blkno >= un->un_l_pwsblk) &&
			    ((bp->b_blkno + btodb(bp->b_bcount)) <=
			    (un->un_l_sblk + un->un_l_tblks))) {
				rv = trans_check_error(bp, errp);
			}
		}
	}
	tstpnt = tstpnt_save;
	mutex_exit(&error_mutex);

	if (tstpnt != NULL)
		trv = (*tstpnt)(bp, flag, private);

	/*
	 * If we are producing an error (rv != 0) we need to make sure that
	 * biodone gets called.  If the tstpnt returned non-zero,
	 * we'll assume that it called biodone.
	 */
	if ((rv != 0) && (trv == 0)) {
		md_biodone(bp);
	}
	rv = ((rv == 0) && (trv == 0)) ? 0 : 1;
	return (rv);
}

/*
 * Prepare to inject errors on the master and log devices associated with the
 * unit specified in migp.  The first time that trans_inject_errors() is called
 * for a unit, an mt_error_t structure is allocated and initialized for the
 * unit.  Subsequent calls for the unit will just insure that the unit is in the
 * count down state.
 *
 * If an mt_error structure is allocated and it is the first one to be put in
 * the list, mdv_strategy_tstpnt (which is referenced in md_call_strategy()) is
 * set to trans_error_injector so that it will be called to see if an I/O
 * request should be treated as an error.
 */

/*ARGSUSED1*/
static int
trans_inject_errors(void *d, int mode, IOLOCK *lock)
{
	mt_error_t	*errp;
	mt_error_t	*do_not_care;
	mt_unit_t	*un;
	int		rv = 0;

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);

	un = trans_getun(migp->id, &migp->mde,
	    RD_LOCK, lock);
	if (un == NULL)
		return (EINVAL);

	/*
	 * If there is already a an error structure for the unit make sure that
	 * it is in count down mode.
	 */

	mutex_enter(&error_mutex);
	errp = find_by_mtunit(un, &do_not_care);
	if (errp != (mt_error_t *)NULL) {
		errp->er_state = mte_count_down;
	} else {

		/*
		 * Initialize error structure.
		 */

		errp = (mt_error_t *)md_trans_zalloc(sizeof (mt_error_t));
		errp->er_state = mte_count_down;
		errp->er_unitp = un;
		errp->er_count_down = initial_count;
		errp->er_increment = default_increment;
		errp->er_reset_count = initial_count;
		errp->er_total_errors = 0;
		errp->er_bad_unit = 0;
		errp->er_bad_block = 0;

		/* Insert it into the list. */

		errp->er_next = error_list_head.er_next;
		error_list_head.er_next = errp;

		/*
		 * Set up md_call_strategy to call our error injector.
		 */

		if (mdv_strategy_tstpnt != trans_error_injector) {
			tstpnt_save = mdv_strategy_tstpnt;
			mdv_strategy_tstpnt = trans_error_injector;
		}
	}
	mutex_exit(&error_mutex);
	return (rv);
}

/*ARGSUSED1*/
static int
trans_stop_errors(void *d, int mode, IOLOCK *lock)
{
	mt_error_t	*errp	= (mt_error_t *)NULL;
	mt_error_t	*pred_errp;
	mt_unit_t	*un;
	int		rv	= 0;

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);

	un = trans_getun(migp->id, &migp->mde,
	    RD_LOCK, lock);
	if (un == NULL)
		return (EINVAL);

	mutex_enter(&error_mutex);
	errp = find_by_mtunit(un, &pred_errp);
	if (errp != (mt_error_t *)NULL) {
		/* Remove from list. */
		pred_errp->er_next = errp->er_next;
		if ((error_list_head.er_next == (mt_error_t *)NULL) &&
		    (mdv_strategy_tstpnt == trans_error_injector)) {
			mdv_strategy_tstpnt = tstpnt_save;
		}
	} else {
		/* unit not set up for errors. */
		rv = ENXIO;
	}
	mutex_exit(&error_mutex);

	/* Free memory. */

	if (errp != (mt_error_t *)NULL) {
		md_trans_free((void *)errp, sizeof (*errp));
	}
	return (rv);
}

int
_init_ioctl()
{
	mutex_init(&error_mutex, NULL, MUTEX_DRIVER, (void *)NULL);
	return (1);
}

int
_fini_ioctl()
{
	mutex_destroy(&error_mutex);
	return (1);
}

/*
 * END OF DEBUG ROUTINES
 */
#endif	/* DEBUG */
/*
 * BEGIN RELEASE DEBUG
 *	The following routines remain in the released product for testability
 */

/*
 * ufs error injection remains in the released product
 */
/*ARGSUSED1*/
static int
trans_ufserror(void *d, int mode, IOLOCK *lock)
{
	mt_unit_t	*un;

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);

	un = trans_getun(migp->id, &migp->mde,
	    RD_LOCK, lock);
	if (un == NULL || un->un_ut == NULL)
		return (EINVAL);

	return (0);
}
/*
 * shadow test remains in the released product
 */
static int
trans_set_shadow(void *d, int mode, IOLOCK *lock)
{
	dev32_t		device;			/* shadow device */
	mt_unit_t 	*un;

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);

	un = trans_getun(migp->id, &migp->mde,
	    WR_LOCK, lock);
	if (un == NULL)
		return (EINVAL);

	if ((un->un_debug & MT_SHADOW) == 0)
		return (EINVAL);

	/* Get shadow device.  User always passes down 32 bit devt */

	if (ddi_copyin((caddr_t)(uintptr_t)migp->mdp,
	    &device, sizeof (device), mode)) {
		return (EFAULT);
	}

	/* Save shadow device designator. */
	un->un_s_dev = md_expldev((md_dev64_t)device);
	return (0);
}

/*
 * END RELEASE DEBUG
 */

static int
trans_get(void *d, int mode, IOLOCK *lock)
{
	mt_unit_t	*un;
	ml_unit_t	*ul;

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);

	un = trans_getun(migp->id, &migp->mde,
	    RD_LOCK, lock);
	if (un == NULL)
		return (0);

	if (migp->size == 0) {
		migp->size = un->c.un_size;
		return (0);
	}

	if (migp->size < un->c.un_size)
		return (EFAULT);

log:
	ul = un->un_l_unit;
	if (ul == NULL)
		goto master;

	/*
	 * refresh log fields in case log was metattach'ed
	 */
	un->un_l_head = (daddr32_t)btodb(ul->un_head_lof);
	un->un_l_sblk = un->un_l_head;
	un->un_l_pwsblk = ul->un_pwsblk;
	un->un_l_maxtransfer = (uint_t)btodb(ul->un_maxtransfer);
	un->un_l_nblks = ul->un_nblks;
	un->un_l_tblks = ul->un_tblks;
	un->un_l_tail = (daddr32_t)btodb(ul->un_tail_lof);
	un->un_l_resv = ul->un_resv;
	un->un_l_maxresv = ul->un_maxresv;
	un->un_l_error = ul->un_error;
	un->un_l_timestamp = ul->un_timestamp;

	/*
	 * check for log dev dynconcat; can only pick up extra space when the
	 * tail physically follows the head in the circular log
	 */
	if (un->un_l_head <= un->un_l_tail)
		if (ul->un_status & LDL_METADEVICE) {
			struct mdc_unit	*c = MD_UNIT(md_getminor(ul->un_dev));

			if (c->un_total_blocks > un->un_l_tblks) {
				un->un_l_tblks = c->un_total_blocks;
				un->un_l_nblks = un->un_l_tblks - un->un_l_sblk;
				if (un->un_l_nblks > btodb(LDL_MAXLOGSIZE))
					un->un_l_nblks = btodb(LDL_MAXLOGSIZE);
				un->un_l_maxresv = (uint_t)(un->un_l_nblks *
				    LDL_USABLE_BSIZE);
			}
	}

master:

	if (ddi_copyout(un, (void *)(uintptr_t)migp->mdp, un->c.un_size, mode))
		return (EFAULT);
	return (0);
}

static int
trans_replace(replace_params_t *params)
{
	minor_t		mnum = params->mnum;
	mt_unit_t	*un;
	mdi_unit_t	*ui;
	md_dev64_t	cmp_dev;
	md_dev64_t	ldev;
	md_dev64_t	mdev;

	mdclrerror(&params->mde);

	ui = MDI_UNIT(mnum);
	un = md_unit_writerlock(ui);

	if (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE) {
		return (mdmderror(&params->mde, MDE_RESYNC_ACTIVE, mnum));
	}

	cmp_dev = params->old_dev;
	mdev = un->un_m_dev;
	ldev = un->un_l_dev;
	if (cmp_dev == mdev) {
		un->un_m_key = params->new_key;
		un->un_m_dev = params->new_dev;
	} else if (cmp_dev == ldev) {
		un->un_l_key = params->new_key;
		un->un_l_dev = params->new_dev;
	}

	trans_commit(un, 1);
	md_unit_writerexit(ui);
	return (0);
}

/*ARGSUSED1*/
static int
trans_grow(void *d, int mode, IOLOCK  *lock)
{
	mt_unit_t		*un;

	md_grow_params_t *mgp = d;

	mdclrerror(&mgp->mde);

	un = trans_getun(mgp->mnum, &mgp->mde,
	    RD_LOCK, lock);
	if (un == NULL)
		return (0);

	/*
	 * check for master dev dynconcat
	 */
	if (md_getmajor(un->un_m_dev) == md_major) {
		struct mdc_unit	*c;

		c = MD_UNIT(md_getminor(un->un_m_dev));
		if (c->un_total_blocks > MD_MAX_BLKS_FOR_SMALL_DEVS) {
			un->c.un_total_blocks = MD_MAX_BLKS_FOR_SMALL_DEVS;
		} else {
			un->c.un_total_blocks = c->un_total_blocks;
		}
		md_nblocks_set(MD_SID(un), un->c.un_total_blocks);
	}

	return (0);
}

/*ARGSUSED1*/
static int
trans_detach_ioctl(void *d, int mode, IOLOCK *lock)
{
	mt_unit_t	*un;
	int		error;

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);

	/* acquire both md_unit_array_rw, and unit_reader lock */
	un = trans_getun(migp->id, &migp->mde,
	    READERS, lock);
	if (un == NULL)
		return (0);

	/*
	 * simply too much work to make debug modes w/out a log
	 */
	if (un->un_debug)
		return (EACCES);

	/*
	 * detach the log
	 */
	error = trans_detach(un, migp->size);

	return (error);
}

static int
trans_get_log(void *d, int mode, IOLOCK	*lock)
{
	mt_unit_t	*un;
	ml_unit_t	*ul;

	md_i_get_t *migp = d;

	mdclrerror(&migp->mde);

	un = trans_getun(migp->id, &migp->mde, RD_LOCK, lock);

	if (un == NULL)
		return (0);

	ul = un->un_l_unit;

	if (migp->size == 0) {
		migp->size = ML_UNIT_ONDSZ;
		return (0);
	}

	if (migp->size < ML_UNIT_ONDSZ)
		return (EFAULT);

	if (ddi_copyout(ul, (void *)(uintptr_t)migp->mdp, ML_UNIT_ONDSZ,
	    mode))
		return (EFAULT);
	return (0);
}

static int
trans_getdevs(void *d, int mode, IOLOCK	*lock)
{
	int			ndev;
	mt_unit_t		*un;
	md_dev64_t		*udevs;
	md_dev64_t		unit_dev;

	md_getdevs_params_t *mgdp = d;

	mdclrerror(&mgdp->mde);

	un = trans_getun(mgdp->mnum, &mgdp->mde, RD_LOCK, lock);
	if (un == NULL)
		return (0);

	ndev = (un->un_flags & (TRANS_DETACHED | TRANS_ATTACHING)) ? 1 : 2;

	if (mgdp->cnt == 0) {
		mgdp->cnt = ndev;
		return (0);
	}

	if (mgdp->cnt > 2)
		mgdp->cnt = ndev;

	udevs = (md_dev64_t *)(uintptr_t)mgdp->devs;
	unit_dev = un->un_m_dev;

	if (md_getmajor(unit_dev) != md_major) {
		if ((unit_dev = md_xlate_mini_2_targ(unit_dev)) == NODEV64)
			return (ENODEV);
	}

	if (mgdp->cnt >= 1)
		if (ddi_copyout(&unit_dev, (caddr_t)&udevs[0],
		    sizeof (*udevs), mode) != 0)
			return (EFAULT);

	unit_dev = un->un_l_dev;
	if (md_getmajor(unit_dev) != md_major) {
		if ((unit_dev = md_xlate_mini_2_targ(unit_dev)) == NODEV64)
			return (ENODEV);
	}

	if (mgdp->cnt >= 2)
		if (ddi_copyout(&unit_dev, (caddr_t)&udevs[1],
		    sizeof (*udevs), mode) != 0)
			return (EFAULT);

	return (0);
}

static int
trans_reset_ioctl(md_i_reset_t *mirp, IOLOCK *lock)
{
	minor_t		mnum = mirp->mnum;
	mt_unit_t	*un;
	int		error;

	mdclrerror(&mirp->mde);

	un = trans_getun(mnum, &mirp->mde, NO_LOCK, lock);
	if (un == NULL)
		return (0);


	/* This prevents new opens */
	rw_enter(&md_unit_array_rw.lock, RW_WRITER);

	if (MD_HAS_PARENT(MD_PARENT(un))) {
		rw_exit(&md_unit_array_rw.lock);
		return (mdmderror(&mirp->mde, MDE_IN_USE, mnum));
	}

	if (md_unit_isopen(MDI_UNIT(mnum))) {
		rw_exit(&md_unit_array_rw.lock);
		return (mdmderror(&mirp->mde, MDE_IS_OPEN, mnum));
	}
	/*
	 * detach the log
	 */
	error = trans_detach(un, mirp->force);

	/*
	 * reset (aka remove; aka delete) the trans device
	 */
	if (error == 0)
		error = trans_reset(un, mnum, 1, mirp->force);

	rw_exit(&md_unit_array_rw.lock);
	return (error);
}

static int
trans_get_geom(mt_unit_t *un, struct dk_geom *geomp)
{
	md_get_geom((md_unit_t *)un, geomp);

	return (0);
}

static int
trans_get_vtoc(mt_unit_t *un, struct vtoc *vtocp)
{
	md_get_vtoc((md_unit_t *)un, vtocp);

	return (0);
}

static int
trans_get_extvtoc(mt_unit_t *un, struct extvtoc *vtocp)
{
	md_get_extvtoc((md_unit_t *)un, vtocp);

	return (0);
}

static int
trans_islog(mt_unit_t *un)
{
	if (un->un_l_unit == NULL)
		return (ENXIO);
	return (0);
}

static int
trans_set_vtoc(
	mt_unit_t	*un,
	struct vtoc	*vtocp
)
{
	return (md_set_vtoc((md_unit_t *)un, vtocp));
}

static int
trans_set_extvtoc(mt_unit_t *un, struct extvtoc *vtocp)
{
	return (md_set_extvtoc((md_unit_t *)un, vtocp));
}

static int
trans_get_cgapart(
	mt_unit_t	*un,
	struct dk_map	*dkmapp
)
{
	md_get_cgapart((md_unit_t *)un, dkmapp);
	return (0);
}

static int
trans_admin_ioctl(int cmd, void *data, int mode, IOLOCK *lockp)
{
	size_t	sz = 0;
	void	*d = NULL;
	int	err = 0;

	/* We can only handle 32-bit clients for internal commands */
	if ((mode & DATAMODEL_MASK) != DATAMODEL_ILP32) {
		return (EINVAL);
	}

	switch (cmd) {

	case MD_IOCGET:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_get(d, mode, lockp);
		break;
	}

	case MD_IOCGET_LOG:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_get_log(d, mode, lockp);
		break;
	}

	case MD_IOCRESET:
	{
		md_i_reset_t	*p;

		if (! (mode & FWRITE))
			return (EACCES);

		if ((d = p = md_trans_zalloc((sz = sizeof (*p)))) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_reset_ioctl(p, lockp);
		break;
	}

	case MD_IOCGROW:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_grow_params_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_grow(d, mode, lockp);
		break;
	}

	case MD_IOC_TRANS_DETACH:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_detach_ioctl(d, mode, lockp);
		break;
	}

	case MD_IOCREPLACE:
	{
		replace_params_t	*p;

		if (! (mode & FWRITE))
			return (EACCES);

		if ((d = p = kmem_alloc((sz = sizeof (*p)), KM_SLEEP)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_replace(p);
		break;
	}


	case MD_IOCGET_DEVS:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_getdevs_params_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_getdevs(d, mode, lockp);
		break;
	}

/*
 * debug ioctls
 */
#ifdef	DEBUG


	case MD_IOCGET_TRANSSTATS:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_get_transstats(d, mode);
		break;
	}

	case MD_IOC_DEBUG:
	{
		md_i_get_t *mdigp;

		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		mdigp = d;

		mdclrerror(&mdigp->mde);
		mt_debug = mdigp->size;
		break;
	}

	case MD_IOC_TSD:
	{
		if (! (mode & FWRITE))
			return (EACCES);


		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_test_tsd(d, mode);
		break;
	}

	case MD_IOC_TRYGETBLK:
	{
		if (! (mode & FWRITE))
			return (EACCES);


		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_test_trygetblk(d, mode, lockp);
		break;
	}

	case MD_IOC_TRYPAGE:
	{
		if (! (mode & FWRITE))
			return (EACCES);


		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_test_trypage(d, mode, lockp);
		break;
	}


	case MD_IOC_INJECTERRORS:
	{
		if (! (mode & FWRITE))
			return (EACCES);


		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_inject_errors(d, mode, lockp);
		break;
	}

	case MD_IOC_STOPERRORS:
	{
		if (! (mode & FWRITE))
			return (EACCES);


		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_stop_errors(d, mode, lockp);
		break;
	}

	case MD_IOC_ISDEBUG:
		break;

#else	/* ! DEBUG */

	case MD_IOC_ISDEBUG:
	case MD_IOCGET_TRANSSTATS:
	case MD_IOC_STOPERRORS:
	case MD_IOC_TSD:
	case MD_IOC_TRYGETBLK:
	case MD_IOC_TRYPAGE:
		break;

	/*
	 * error injection behaves like MD_IOC_UFSERROR in released product
	 */
	case MD_IOC_INJECTERRORS:
	{
		if (! (mode & FWRITE))
			return (EACCES);


		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_ufserror(d, mode, lockp);
		break;
	}

	/*
	 * only the shadow test is allowed in the released product
	 */
	case MD_IOC_DEBUG:
	{
		md_i_get_t *mdigp;

		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		mdigp = d;

		mdclrerror(&mdigp->mde);
		mt_debug = mdigp->size & MT_SHADOW;
		break;
	}

#endif	/* ! DEBUG */

/*
 * BEGIN RELEASE DEBUG
 *	The following routines remain in the released product for testability
 */

	case MD_IOC_UFSERROR:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_ufserror(d, mode, lockp);
		break;
	}

	case MD_IOC_SETSHADOW:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_i_get_t);

		if ((d = md_trans_zalloc(sz)) == NULL)
			return (ENOMEM);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = trans_set_shadow(d, mode, lockp);
		break;
	}

/*
 * END RELEASE DEBUG
 */


	default:
		return (ENOTTY);
	}

	/*
	 * copyout and free any args
	 */
	if (sz != 0) {
		if (err == 0) {
			if (ddi_copyout(d, data, sz, mode) != 0) {
				err = EFAULT;
			}
		}
		md_trans_free(d, sz);
	}
	return (err);
}

int
md_trans_ioctl(dev_t dev, int cmd, void *data, int mode, IOLOCK *lockp)
{
	minor_t		mnum = getminor(dev);
	mt_unit_t	*un;
	md_error_t	mde = mdnullerror;
	int		err = 0;

	/* handle admin ioctls */
	if (mnum == MD_ADM_MINOR)
		return (trans_admin_ioctl(cmd, data, mode, lockp));

	/* check unit */
	if ((MD_MIN2SET(mnum) >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((un = trans_getun(mnum, &mde, RD_LOCK, lockp)) == NULL))
		return (ENXIO);

	/* dispatch ioctl */
	switch (cmd) {

	case DKIOCINFO:
	{
		struct dk_cinfo	*p;

		if (! (mode & FREAD))
			return (EACCES);

		if ((p = md_trans_zalloc(sizeof (*p))) == NULL)
			return (ENOMEM);

		get_info(p, mnum);
		if (ddi_copyout((caddr_t)p, data, sizeof (*p), mode) != 0)
			err = EFAULT;

		md_trans_free(p, sizeof (*p));
		return (err);
	}

	case DKIOCGGEOM:
	{
		struct dk_geom	*p;

		if (! (mode & FREAD))
			return (EACCES);

		if ((p = md_trans_zalloc(sizeof (*p))) == NULL)
			return (ENOMEM);

		if ((err = trans_get_geom(un, p)) == 0) {
			if (ddi_copyout((caddr_t)p, data, sizeof (*p),
			    mode) != 0)
				err = EFAULT;
		}

		md_trans_free(p, sizeof (*p));
		return (err);
	}

	case DKIOCGVTOC:
	{
		struct vtoc	*vtoc;

		if (! (mode & FREAD))
			return (EACCES);

		vtoc = kmem_zalloc(sizeof (*vtoc), KM_SLEEP);
		if ((err = trans_get_vtoc(un, vtoc)) != 0) {
			kmem_free(vtoc, sizeof (*vtoc));
			return (err);
		}

		if ((mode & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
			if (ddi_copyout(vtoc, data, sizeof (*vtoc), mode))
				err = EFAULT;
		}
#ifdef _SYSCALL32
		else {
			struct vtoc32	*vtoc32;

			vtoc32 = kmem_zalloc(sizeof (*vtoc32), KM_SLEEP);

			vtoctovtoc32((*vtoc), (*vtoc32));
			if (ddi_copyout(vtoc32, data, sizeof (*vtoc32), mode))
				err = EFAULT;
			kmem_free(vtoc32, sizeof (*vtoc32));
		}
#endif /* _SYSCALL32 */

		kmem_free(vtoc, sizeof (*vtoc));
		return (err);
	}

	case DKIOCSVTOC:
	{
		struct vtoc	*vtoc;

		if (! (mode & FWRITE))
			return (EACCES);

		vtoc = kmem_zalloc(sizeof (*vtoc), KM_SLEEP);
		if ((mode & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
			if (ddi_copyin(data, vtoc, sizeof (*vtoc), mode)) {
				err = EFAULT;
			}
		}
#ifdef _SYSCALL32
		else {
			struct vtoc32	*vtoc32;

			vtoc32 = kmem_zalloc(sizeof (*vtoc32), KM_SLEEP);

			if (ddi_copyin(data, vtoc32, sizeof (*vtoc32), mode)) {
				err = EFAULT;
			} else {
				vtoc32tovtoc((*vtoc32), (*vtoc));
			}
			kmem_free(vtoc32, sizeof (*vtoc32));
		}
#endif /* _SYSCALL32 */

		if (err == 0)
			err = trans_set_vtoc(un, vtoc);

		kmem_free(vtoc, sizeof (*vtoc));
		return (err);
	}


	case DKIOCGEXTVTOC:
	{
		struct extvtoc	*extvtoc;

		if (! (mode & FREAD))
			return (EACCES);

		extvtoc = kmem_zalloc(sizeof (*extvtoc), KM_SLEEP);
		if ((err = trans_get_extvtoc(un, extvtoc)) != 0) {
			return (err);
		}

		if (ddi_copyout(extvtoc, data, sizeof (*extvtoc), mode))
			err = EFAULT;

		kmem_free(extvtoc, sizeof (*extvtoc));
		return (err);
	}

	case DKIOCSEXTVTOC:
	{
		struct extvtoc	*extvtoc;

		if (! (mode & FWRITE))
			return (EACCES);

		extvtoc = kmem_zalloc(sizeof (*extvtoc), KM_SLEEP);
		if (ddi_copyin(data, extvtoc, sizeof (*extvtoc), mode)) {
			err = EFAULT;
		}

		if (err == 0)
			err = trans_set_extvtoc(un, extvtoc);

		kmem_free(extvtoc, sizeof (*extvtoc));
		return (err);
	}

	case DKIOCGAPART:
	{
		struct dk_map	dmp;

		if ((err = trans_get_cgapart(un, &dmp)) != 0) {
			return (err);
		}

		if ((mode & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
			if (ddi_copyout((caddr_t)&dmp, data, sizeof (dmp),
			    mode) != 0)
				err = EFAULT;
		}
#ifdef _SYSCALL32
		else {
			struct dk_map32 dmp32;

			dmp32.dkl_cylno = dmp.dkl_cylno;
			dmp32.dkl_nblk = dmp.dkl_nblk;

			if (ddi_copyout((caddr_t)&dmp32, data, sizeof (dmp32),
			    mode) != 0)
				err = EFAULT;
		}
#endif /* _SYSCALL32 */

		return (err);
	}

	/*
	 * _FIOISLOG, _FIOISLOGOK, _FIOLOGRESET are used by fsck/mkfs
	 * after opening the device.  fsck/mkfs use these ioctls for
	 * error recovery.
	 */
	case _FIOISLOG:
		return (trans_islog(un));

	default:
		return (ENOTTY);
	}
}

/*
 * rename named service entry points and support functions
 */

/* rename/exchange role swap functions */

/*
 * MDRNM_UPDATE_SELF
 * This role swap function is identical for all unit types,
 * so keep it here. It's also the best example because it
 * touches all the modified portions of the relevant
 * in-common structures.
 */
void
trans_rename_update_self(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	minor_t		 from_min, to_min;
	sv_dev_t	 sv;
	mt_unit_t	*un;

	ASSERT(rtxnp);
	ASSERT(rtxnp->op == MDRNOP_RENAME);
	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(rtxnp->recids);
	ASSERT(delta->old_role == MDRR_SELF);
	ASSERT(delta->new_role == MDRR_SELF);

	from_min = rtxnp->from.mnum;
	to_min   = rtxnp->to.mnum;
	un	 = (mt_unit_t *)delta->unp;

	/*
	 * self id changes in our own unit struct
	 * both mechanisms for identifying the trans must be reset.
	 */

	MD_SID(delta->unp) = to_min;
	un->un_dev = makedevice(md_major, to_min);

	/*
	 * clear old array pointers to unit in-core and unit
	 */

	MDI_VOIDUNIT(from_min) = NULL;
	MD_VOIDUNIT(from_min) = NULL;

	/*
	 * and point the new slots at the unit in-core and unit structs
	 */

	MDI_VOIDUNIT(to_min) = delta->uip;
	MD_VOIDUNIT(to_min) = delta->unp;

	/*
	 * recreate kstats
	 */
	md_kstat_destroy_ui(delta->uip);
	md_kstat_init_ui(to_min, delta->uip);

	/*
	 * the unit in-core reference to the get next link's id changes
	 */

	delta->uip->ui_link.ln_id = to_min;

	/*
	 * name space addition of new key was done from user-level
	 * remove the old name's key here
	 */

	sv.setno = MD_MIN2SET(from_min);
	sv.key	 = rtxnp->from.key;

	md_rem_names(&sv, 1);


	/*
	 * and store the record id (from the unit struct) into recids
	 * for later commitment by md_rename()
	 */

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * MDRNM_UPDATE_KIDS
 * rename/exchange of our child or grandchild
 */
void
trans_renexch_update_kids(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	mt_unit_t	*un;
	minor_t		 from_min, to_min, log_min, master_min;

	ASSERT(delta);
	ASSERT(rtxnp);
	ASSERT((rtxnp->op == MDRNOP_RENAME) || (rtxnp->op == MDRNOP_EXCHANGE));
	ASSERT(delta->unp);
	ASSERT(rtxnp->recids);
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(delta->old_role == MDRR_PARENT);
	ASSERT(delta->new_role == MDRR_PARENT);

	un		= (mt_unit_t *)delta->unp;
	from_min	= rtxnp->from.mnum;
	to_min		= rtxnp->to.mnum;
	log_min		= md_getminor(un->un_l_dev);
	master_min	= md_getminor(un->un_m_dev);

	/*
	 * since our role isn't changing (parent->parent)
	 * one of our children must be changing; which one is it?
	 * find the child being modified, and update
	 * our notion of it
	 */

	/* both devices must be metadevices in order to be updated */
	ASSERT(md_getmajor(un->un_m_dev) == md_major);
	ASSERT(!(un->un_l_unit && (md_getmajor(un->un_l_dev) != md_major)));

	if ((md_getmajor(un->un_m_dev) == md_major) &&
	    (master_min == from_min)) {

		ASSERT(!(un->un_l_unit && (log_min == from_min)));

		un->un_m_dev = makedevice(md_major, to_min);
		un->un_m_key = rtxnp->to.key;

	} else if ((md_getmajor(un->un_m_dev) == md_major) &&
	    un->un_l_unit && (log_min == from_min)) {

		ASSERT(master_min != from_min);

		un->un_l_dev = makedevice(md_major, to_min);
		un->un_l_key = rtxnp->to.key;

	} else {
		ASSERT(FALSE);
		panic("trans_renexch_update_kids: not a metadevice");
		/*NOTREACHED*/
	}

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * MDRNM_SELF_UPDATE_FROM (exchange down) [self->child]
 */
void
trans_exchange_self_update_from_down(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	mt_unit_t	*un;
	minor_t		from_min, to_min, master_min, log_min;
	sv_dev_t	sv;

	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT(rtxnp);
	ASSERT(MDRNOP_EXCHANGE == rtxnp->op);
	ASSERT(rtxnp->from.uip);
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(rtxnp->recids);
	ASSERT(delta->old_role == MDRR_SELF);
	ASSERT(delta->new_role == MDRR_CHILD);
	ASSERT(md_getminor(delta->dev) == rtxnp->from.mnum);

	un = (mt_unit_t *)delta->unp;

	/*
	 * if we're exchanging a trans, it had better be a metadevice
	 */
	ASSERT(md_getmajor(un->un_m_dev) == md_major);

	to_min		= rtxnp->to.mnum;
	from_min	= rtxnp->from.mnum;
	master_min	= md_getminor(un->un_m_dev);
	log_min		= md_getminor(un->un_l_dev);

	/*
	 * both mechanisms for identifying a trans must be updated
	 */

	MD_SID(delta->unp) = to_min;
	un->un_dev = makedevice(md_major, to_min);

	/*
	 * parent identifier need not change
	 */

	/*
	 * point the set array pointers at the "new" unit and unit in-cores
	 * Note: the other half of this transfer is done in the "update to"
	 * rename/exchange named service.
	 */

	MDI_VOIDUNIT(to_min) = delta->uip;
	MD_VOIDUNIT(to_min) = delta->unp;

	/*
	 * transfer kstats
	 */

	delta->uip->ui_kstat = rtxnp->to.kstatp;

	/*
	 * the unit in-core reference to the get next link's id changes
	 */

	delta->uip->ui_link.ln_id = to_min;

	/*
	 * which one of our children is changing?
	 *
	 * Note that the check routines forbid changing the log (for now)
	 * because there's no lockfs-like trans-ufs "freeze and remount"
	 * or "freeze and bobbit the log."
	 */

	/* both devices must be metadevices in order to be updated */
	ASSERT(md_getmajor(un->un_m_dev) == md_major);
	ASSERT(!(un->un_l_unit && (md_getmajor(un->un_l_dev) != md_major)));

	if ((md_getmajor(un->un_m_dev) == md_major) &&
	    (master_min == to_min)) {

		/* master and log can't both be changed */
		ASSERT(!(un->un_l_unit && (log_min == to_min)));

		un->un_m_dev = makedevice(md_major, from_min);
		sv.key = un->un_m_key;
		un->un_m_key = rtxnp->from.key;

	} else if ((md_getmajor(un->un_m_dev) == md_major) &&
	    un->un_l_unit && (log_min == to_min)) {

		/* master and log can't both be changed */
		ASSERT(!(master_min == to_min));

		un->un_l_dev = makedevice(md_major, from_min);
		sv.key = un->un_l_key;
		un->un_l_key = rtxnp->from.key;

	} else {
		ASSERT(FALSE);
		panic("trans_exchange_self_update_from_down: not a metadevice");
		/*NOTREACHED*/
	}

	/*
	 * the new master must exist in the name space
	 */
	ASSERT(rtxnp->from.key != MD_KEYWILD);
	ASSERT(rtxnp->from.key != MD_KEYBAD);

	/*
	 * delete the key for the changed child from the namespace
	 */

	sv.setno = MD_MIN2SET(from_min);
	md_rem_names(&sv, 1);

	/*
	 * and store the record id (from the unit struct) into recids
	 */

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * MDRNM_PARENT_UPDATE_TO (exchange down) [parent->self]
 */
void
trans_exchange_parent_update_to(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	mt_unit_t	*un;
	minor_t		from_min, to_min, master_min, log_min;
	sv_dev_t	sv;

	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT(rtxnp);
	ASSERT(MDRNOP_EXCHANGE == rtxnp->op);
	ASSERT(rtxnp->from.uip);
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(rtxnp->recids);
	ASSERT(delta->old_role == MDRR_PARENT);
	ASSERT(delta->new_role == MDRR_SELF);
	ASSERT(md_getminor(delta->dev) == rtxnp->to.mnum);

	un = (mt_unit_t *)delta->unp;

	ASSERT(md_getmajor(un->un_m_dev) == md_major);

	to_min		= rtxnp->to.mnum;
	from_min	= rtxnp->from.mnum;
	master_min	= md_getminor(un->un_m_dev);
	log_min		= md_getminor(un->un_l_dev);

	/*
	 * both mechanisms for identifying a trans must be updated
	 */

	MD_SID(delta->unp) = from_min;
	un->un_dev = makedevice(md_major, from_min);

	/*
	 * parent identifier need not change
	 */

	/*
	 * point the set array pointers at the "new" unit and unit in-cores
	 * Note: the other half of this transfer is done in the "update to"
	 * rename/exchange named service.
	 */

	MDI_VOIDUNIT(from_min) = delta->uip;
	MD_VOIDUNIT(from_min) = delta->unp;

	/*
	 * transfer kstats
	 */

	delta->uip->ui_kstat = rtxnp->from.kstatp;

	/*
	 * the unit in-core reference to the get next link's id changes
	 */

	delta->uip->ui_link.ln_id = from_min;

	/*
	 * which one of our children is changing?
	 */

	/* both devices must be metadevices in order to be updated */
	ASSERT(md_getmajor(un->un_m_dev) == md_major);
	ASSERT(!(un->un_l_unit && (md_getmajor(un->un_l_dev) != md_major)));

	if ((md_getmajor(un->un_m_dev) == md_major) &&
	    (master_min == from_min)) {

		/* can't be changing log and master */
		ASSERT(!(un->un_l_unit && (log_min == to_min)));

		un->un_m_dev = makedevice(md_major, to_min);
		sv.key = un->un_m_key;
		un->un_m_key = rtxnp->to.key;

	} else if (un->un_l_unit &&
	    ((md_getmajor(un->un_l_dev) == md_major) && log_min == to_min)) {

		/* can't be changing log and master */
		ASSERT(master_min != from_min);

		un->un_l_dev = makedevice(md_major, to_min);
		sv.key = un->un_l_key;
		un->un_l_key = rtxnp->to.key;

	} else {
		ASSERT(FALSE);
		panic("trans_exchange_parent_update_to: not a metadevice");
		/*NOTREACHED*/
	}

	/*
	 * delete the key for the changed child from the namespace
	 */

	sv.setno = MD_MIN2SET(from_min);
	md_rem_names(&sv, 1);

	/*
	 * and store the record id (from the unit struct) into recids
	 */

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * MDRNM_LIST_URKIDS: named svc entry point
 * all all delta entries appropriate for our children onto the
 * deltalist pointd to by dlpp
 */
int
trans_rename_listkids(
	md_rendelta_t	**dlpp,
	md_rentxn_t	 *rtxnp)
{
	minor_t		 from_min, to_min, master_min, log_min;
	mt_unit_t	*from_un;
	md_rendelta_t	*new, *p;
	int		 n_children;

	ASSERT(rtxnp);
	ASSERT(dlpp);
	ASSERT((rtxnp->op == MDRNOP_EXCHANGE) || (rtxnp->op == MDRNOP_RENAME));

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;
	n_children = 0;

	if (!MDI_UNIT(from_min) || !(from_un = MD_UNIT(from_min))) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP, from_min);
		return (-1);
	}

	for (p = *dlpp; p && p->next != NULL; p = p->next) {
		/* NULL */
	}

	if (md_getmajor(from_un->un_m_dev) == md_major) {

		master_min = md_getminor(from_un->un_m_dev);

		p = new = md_build_rendelta(MDRR_CHILD,
		    to_min == master_min? MDRR_SELF: MDRR_CHILD,
		    from_un->un_m_dev, p, MD_UNIT(master_min),
		    MDI_UNIT(master_min), &rtxnp->mde);

		if (!new) {
			if (mdisok(&rtxnp->mde)) {
				(void) mdsyserror(&rtxnp->mde, ENOMEM);
			}
			return (-1);
		}
		++n_children;
	}

	if (from_un->un_l_unit &&
	    (md_getmajor(from_un->un_l_dev) == md_major)) {

		log_min = md_getminor(from_un->un_l_dev);

		new = md_build_rendelta(MDRR_CHILD,
		    to_min == log_min? MDRR_SELF: MDRR_CHILD,
		    from_un->un_l_dev, p, MD_UNIT(log_min),
		    MDI_UNIT(log_min), &rtxnp->mde);
		if (!new) {
			if (mdisok(&rtxnp->mde)) {
				(void) mdsyserror(&rtxnp->mde, ENOMEM);
			}
			return (-1);
		}
		++n_children;
	}

	return (n_children);
}

/*
 * support routine for MDRNM_CHECK
 */
static int
trans_may_renexch_self(
	mt_unit_t	*un,
	mdi_unit_t	*ui,
	md_rentxn_t	*rtxnp)
{
	minor_t			from_min;
	minor_t			to_min;

	ASSERT(rtxnp);
	ASSERT((rtxnp->op == MDRNOP_RENAME) || (rtxnp->op == MDRNOP_EXCHANGE));

	from_min = rtxnp->from.mnum;
	to_min	 = rtxnp->to.mnum;

	if (!un || !ui) {
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
		    from_min);
		return (EINVAL);
	}

	ASSERT(MD_CAPAB(un) & MD_CAN_META_CHILD);

	if (!(MD_CAPAB(un) & MD_CAN_META_CHILD)) {
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_SOURCE_BAD, from_min);
		return (EINVAL);
	}

	if (MD_PARENT(un) == MD_MULTI_PARENT) {
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_SOURCE_BAD, from_min);
		return (EINVAL);
	}

	switch (rtxnp->op) {
	case MDRNOP_EXCHANGE:
		/*
		 * may only swap with our child (master) if it is a metadevice
		 */
		if (md_getmajor(un->un_m_dev) != md_major) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_TARGET_BAD,
			    to_min);
			return (EINVAL);
		}

		if (un->un_l_unit &&
		    (md_getmajor(un->un_l_dev) != md_major)) {

			(void) mdmderror(&rtxnp->mde, MDE_RENAME_TARGET_BAD,
			    to_min);
			return (EINVAL);
		}

		if (md_getminor(un->un_m_dev) != to_min) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_TARGET_BAD,
			    to_min);
			return (EINVAL);
		}

		break;

	case MDRNOP_RENAME:
		break;

	default:
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
		    from_min);
		return (EINVAL);
	}

	return (0);	/* ok */
}

/*
 * Named service entry point: MDRNM_CHECK
 */
intptr_t
trans_rename_check(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	int		 err = 0;
	mt_unit_t	*un;

	ASSERT(delta);
	ASSERT(rtxnp);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT((rtxnp->op == MDRNOP_RENAME) || (rtxnp->op == MDRNOP_EXCHANGE));

	if (!delta || !rtxnp || !delta->unp || !delta->uip) {
		(void) mdsyserror(&rtxnp->mde, EINVAL);
		return (EINVAL);
	}

	un = (mt_unit_t *)delta->unp;

	if (rtxnp->revision == MD_RENAME_VERSION_OFFLINE) {
	/*
	 * trans' may not be open, if it is being modified in the exchange
	 * or rename; trans-UFS hasn't been verified to handle the change
	 * out from underneath it.
	 */
		if ((md_unit_isopen(delta->uip)) &&
		    ((md_getminor(delta->dev) == rtxnp->from.mnum) ||
		    (md_getminor(delta->dev) == rtxnp->to.mnum))) {
			(void) mdmderror(&rtxnp->mde,
			    MDE_RENAME_BUSY, rtxnp->from.mnum);
			return (EBUSY);
		}
	}

	/*
	 * can't rename or exchange with a log attached
	 */

	if (un->un_l_unit) {
		(void) mdmderror(&rtxnp->mde,
		    MDE_RENAME_BUSY, rtxnp->from.mnum);
		return (EBUSY);
	}

	switch (delta->old_role) {
	case MDRR_SELF:
		/*
		 * self does additional checks
		 */
		err = trans_may_renexch_self((mt_unit_t *)delta->unp,
		    delta->uip, rtxnp);
		if (err != 0) {
			goto out;
		}
		/* FALLTHROUGH */

	case MDRR_PARENT:
		/*
		 * top_is_trans is only used to check for online
		 * rename/exchange when MD_RENAME_VERSION == OFFLINE
		 * since trans holds the sub-devices open
		 */
		rtxnp->stat.trans_in_stack = TRUE;
		break;
	default:
		break;
	}
out:
	return (err);
}

/* end of rename/exchange */
