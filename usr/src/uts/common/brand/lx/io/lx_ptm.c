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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */


/*
 * This driver attempts to emulate some of the the behaviors of
 * Linux terminal devices (/dev/ptmx and /dev/pts/[0-9][0-9]*) on Solaris
 *
 * It does this by layering over the /dev/ptmx device and intercepting
 * opens to it.
 *
 * This driver makes the following assumptions about the way the ptm/pts
 * drivers on Solaris work:
 *
 *    - all opens of the /dev/ptmx device node return a unique dev_t.
 *
 *    - the dev_t minor node value for each open ptm instance corrospondes
 *      to it's associated slave terminal device number.  ie. the path to
 *      the slave terminal device associated with an open ptm instance
 *      who's dev_t minor node vaue is 5, is /dev/pts/5.
 *
 *    - the ptm driver always allocates the lowest numbered slave terminal
 *      device possible.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/kstr.h>
#include <sys/lx_ptm.h>
#include <sys/modctl.h>
#include <sys/pathname.h>
#include <sys/ptms.h>
#include <sys/ptyvar.h>
#include <sys/stat.h>
#include <sys/stropts.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#define	LP_PTM_PATH		"/dev/ptmx"
#define	LP_PTS_PATH		"/dev/pts/"
#define	LP_PTS_DRV_NAME		"pts"
#define	LP_PTS_USEC_DELAY	(5 * 1000)	/* 5 ms */
#define	LP_PTS_USEC_DELAY_MAX	(5 * MILLISEC)	/* 5 ms */

/*
 * this driver is layered on top of the ptm driver.  we'd like to
 * make this drivers minor name space a mirror of the ptm drivers
 * namespace, but we can't actually do this.  the reason is that the
 * ptm driver is opened via the clone driver.  there for no minor nodes
 * of the ptm driver are actually accessible via the filesystem.
 * since we're not a streams device we can't be opened by the clone
 * driver.  there for we need to have at least minor node accessible
 * via the filesystem so that consumers can open it.  we use the device
 * node with a minor number of 0 for this purpose.  what this means is
 * that minor node 0 can't be used to map ptm minor node 0.  since this
 * minor node is now reserved we need to shift our ptm minor node
 * mappings by one.  ie. a ptm minor node with a value of 0 will
 * corrospond to our minor node with a value of 1.  these mappings are
 * managed with the following macros.
 */
#define	DEVT_TO_INDEX(x)	LX_PTM_DEV_TO_PTS(x)
#define	INDEX_TO_MINOR(x)	((x) + 1)

/*
 * grow our layered handle array by the same size increment that the ptm
 * driver uses to grow the pty device space - PTY_MAXDELTA
 */
#define	LP_PTY_INC	128

/*
 * lx_ptm_ops contains state information about outstanding operations on the
 * underlying master terminal device.  Currently we only track information
 * for read operations.
 *
 * Note that this data has not been rolled directly into the lx_ptm_handle
 * structure because we can't put mutex's of condition variables into
 * lx_ptm_handle structure.  The reason is that the array of lx_ptm_handle
 * structures linked to from the global lx_ptm state can be resized
 * dynamically, and when it's resized, the new array is at a different
 * memory location and the old array memory is discarded.  Mutexs and cvs
 * are accessed based off their address, so if this array was re-sized while
 * there were outstanding operations on any mutexs or cvs in the array
 * then the system would tip over.  In the future the lx_ptm_handle structure
 * array should probably be replaced with either an array of pointers to
 * lx_ptm_handle structures or some other kind of data structure containing
 * pointers to lx_ptm_handle structures.  Then the lx_ptm_ops structure
 * could be folded directly into the lx_ptm_handle structures.  (This will
 * also require the definition of a new locking mechanism to protect the
 * contents of lx_ptm_handle structures.)
 */
typedef struct lx_ptm_ops {
	int			lpo_rops;
	kcondvar_t		lpo_rops_cv;
	kmutex_t		lpo_rops_lock;
} lx_ptm_ops_t;

/*
 * Every open of the master terminal device in a zone results in a new
 * lx_ptm_handle handle allocation.  These handles are stored in an array
 * hanging off the lx_ptm_state structure.
 */
typedef struct lx_ptm_handle {
	/* Device handle to the underlying real /dev/ptmx master terminal. */
	ldi_handle_t		lph_handle;

	/* Flag to indicate if TIOCPKT mode has been enabled. */
	int			lph_pktio;

	/* Number of times the slave device has been opened/closed. */
	int			lph_eofed;

	/* Callback handler in the ptm driver to check if slave is open. */
	ptmptsopencb_t		lph_ppocb;

	/* Pointer to state for operations on underlying device. */
	lx_ptm_ops_t		*lph_lpo;
} lx_ptm_handle_t;

/*
 * Global state for the lx_ptm driver.
 */
typedef struct lx_ptm_state {
	/* lx_ptm device devinfo pointer */
	dev_info_t		*lps_dip;

	/* LDI ident used to open underlying real /dev/ptmx master terminals. */
	ldi_ident_t		lps_li;

	/* pts drivers major number */
	major_t			lps_pts_major;

	/* rw lock used to manage access and growth of lps_lh_array */
	krwlock_t		lps_lh_rwlock;

	/* number of elements in lps_lh_array */
	uint_t			lps_lh_count;

	/* Array of handles to underlying real /dev/ptmx master terminals. */
	lx_ptm_handle_t		*lps_lh_array;
} lx_ptm_state_t;

/* Pointer to the lx_ptm global state structure. */
static lx_ptm_state_t	lps;

/*
 * List of modules to be autopushed onto slave terminal devices when they
 * are opened in an lx branded zone.
 */
static char *lx_pts_mods[] = {
	"ptem",
	"ldterm",
	"ttcompat",
	NULL
};

static void
lx_ptm_lh_grow(uint_t index)
{
	uint_t			new_lh_count, old_lh_count;
	lx_ptm_handle_t		*new_lh_array, *old_lh_array;

	/*
	 * allocate a new array.  we drop the rw lock on the array so that
	 * readers can still access devices in case our memory allocation
	 * blocks.
	 */
	new_lh_count = MAX(lps.lps_lh_count + LP_PTY_INC, index + 1);
	new_lh_array =
	    kmem_zalloc(sizeof (lx_ptm_handle_t) * new_lh_count, KM_SLEEP);

	/*
	 * double check that we still actually need to increase the size
	 * of the array
	 */
	rw_enter(&lps.lps_lh_rwlock, RW_WRITER);
	if (index < lps.lps_lh_count) {
		/* someone beat us to it so there's nothing more to do */
		rw_exit(&lps.lps_lh_rwlock);
		kmem_free(new_lh_array,
		    sizeof (lx_ptm_handle_t) * new_lh_count);
		return;
	}

	/* copy the existing data into the new array */
	ASSERT((lps.lps_lh_count != 0) || (lps.lps_lh_array == NULL));
	ASSERT((lps.lps_lh_count == 0) || (lps.lps_lh_array != NULL));
	if (lps.lps_lh_count != 0) {
		bcopy(lps.lps_lh_array, new_lh_array,
		    sizeof (lx_ptm_handle_t) * lps.lps_lh_count);
	}

	/* save info on the old array */
	old_lh_array = lps.lps_lh_array;
	old_lh_count = lps.lps_lh_count;

	/* install the new array */
	lps.lps_lh_array = new_lh_array;
	lps.lps_lh_count = new_lh_count;

	rw_exit(&lps.lps_lh_rwlock);

	/* free the old array */
	if (old_lh_array != NULL) {
		kmem_free(old_lh_array,
		    sizeof (lx_ptm_handle_t) * old_lh_count);
	}
}

static void
lx_ptm_lh_insert(uint_t index, ldi_handle_t lh)
{
	lx_ptm_ops_t *lpo;

	ASSERT(lh != NULL);

	/* Allocate and initialize the ops structure */
	lpo = kmem_zalloc(sizeof (lx_ptm_ops_t), KM_SLEEP);
	mutex_init(&lpo->lpo_rops_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&lpo->lpo_rops_cv, NULL, CV_DEFAULT, NULL);

	rw_enter(&lps.lps_lh_rwlock, RW_WRITER);

	/* check if we need to grow the size of the layered handle array */
	if (index >= lps.lps_lh_count) {
		rw_exit(&lps.lps_lh_rwlock);
		lx_ptm_lh_grow(index);
		rw_enter(&lps.lps_lh_rwlock, RW_WRITER);
	}

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_handle == NULL);
	ASSERT(lps.lps_lh_array[index].lph_pktio == 0);
	ASSERT(lps.lps_lh_array[index].lph_eofed == 0);
	ASSERT(lps.lps_lh_array[index].lph_lpo == NULL);

	/* insert the new handle and return */
	lps.lps_lh_array[index].lph_handle = lh;
	lps.lps_lh_array[index].lph_pktio = 0;
	lps.lps_lh_array[index].lph_eofed = 0;
	lps.lps_lh_array[index].lph_lpo = lpo;

	rw_exit(&lps.lps_lh_rwlock);
}

static ldi_handle_t
lx_ptm_lh_remove(uint_t index)
{
	ldi_handle_t	lh;

	rw_enter(&lps.lps_lh_rwlock, RW_WRITER);

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_handle != NULL);
	ASSERT(lps.lps_lh_array[index].lph_lpo->lpo_rops == 0);
	ASSERT(!MUTEX_HELD(&lps.lps_lh_array[index].lph_lpo->lpo_rops_lock));

	/* free the write handle */
	kmem_free(lps.lps_lh_array[index].lph_lpo, sizeof (lx_ptm_ops_t));
	lps.lps_lh_array[index].lph_lpo = NULL;

	/* remove the handle and return it */
	lh = lps.lps_lh_array[index].lph_handle;
	lps.lps_lh_array[index].lph_handle = NULL;
	lps.lps_lh_array[index].lph_pktio = 0;
	lps.lps_lh_array[index].lph_eofed = 0;
	rw_exit(&lps.lps_lh_rwlock);
	return (lh);
}

static void
lx_ptm_lh_get_ppocb(uint_t index, ptmptsopencb_t *ppocb)
{
	rw_enter(&lps.lps_lh_rwlock, RW_WRITER);

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_handle != NULL);

	*ppocb = lps.lps_lh_array[index].lph_ppocb;
	rw_exit(&lps.lps_lh_rwlock);
}

static void
lx_ptm_lh_set_ppocb(uint_t index, ptmptsopencb_t *ppocb)
{
	rw_enter(&lps.lps_lh_rwlock, RW_WRITER);

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_handle != NULL);

	lps.lps_lh_array[index].lph_ppocb = *ppocb;
	rw_exit(&lps.lps_lh_rwlock);
}

static ldi_handle_t
lx_ptm_lh_lookup(uint_t index)
{
	ldi_handle_t	lh;

	rw_enter(&lps.lps_lh_rwlock, RW_READER);

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_handle != NULL);

	/* return the handle */
	lh = lps.lps_lh_array[index].lph_handle;
	rw_exit(&lps.lps_lh_rwlock);
	return (lh);
}

static lx_ptm_ops_t *
lx_ptm_lpo_lookup(uint_t index)
{
	lx_ptm_ops_t	*lpo;

	rw_enter(&lps.lps_lh_rwlock, RW_READER);

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_lpo != NULL);

	/* return the handle */
	lpo = lps.lps_lh_array[index].lph_lpo;
	rw_exit(&lps.lps_lh_rwlock);
	return (lpo);
}

static int
lx_ptm_lh_pktio_get(uint_t index)
{
	int		pktio;

	rw_enter(&lps.lps_lh_rwlock, RW_READER);

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_handle != NULL);

	/* return the pktio state */
	pktio = lps.lps_lh_array[index].lph_pktio;
	rw_exit(&lps.lps_lh_rwlock);
	return (pktio);
}

static void
lx_ptm_lh_pktio_set(uint_t index, int pktio)
{
	rw_enter(&lps.lps_lh_rwlock, RW_WRITER);

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_handle != NULL);

	/* set the pktio state */
	lps.lps_lh_array[index].lph_pktio = pktio;
	rw_exit(&lps.lps_lh_rwlock);
}

static int
lx_ptm_lh_eofed_get(uint_t index)
{
	int		eofed;

	rw_enter(&lps.lps_lh_rwlock, RW_READER);

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_handle != NULL);

	/* return the eofed state */
	eofed = lps.lps_lh_array[index].lph_eofed;
	rw_exit(&lps.lps_lh_rwlock);
	return (eofed);
}

static void
lx_ptm_lh_eofed_set(uint_t index)
{
	rw_enter(&lps.lps_lh_rwlock, RW_WRITER);

	ASSERT(index < lps.lps_lh_count);
	ASSERT(lps.lps_lh_array[index].lph_handle != NULL);

	/* set the eofed state */
	lps.lps_lh_array[index].lph_eofed++;
	rw_exit(&lps.lps_lh_rwlock);
}

static int
lx_ptm_read_start(dev_t dev)
{
	lx_ptm_ops_t	*lpo = lx_ptm_lpo_lookup(DEVT_TO_INDEX(dev));

	mutex_enter(&lpo->lpo_rops_lock);
	ASSERT(lpo->lpo_rops >= 0);

	/* Wait for other read operations to finish */
	while (lpo->lpo_rops != 0) {
		if (cv_wait_sig(&lpo->lpo_rops_cv, &lpo->lpo_rops_lock) == 0) {
			mutex_exit(&lpo->lpo_rops_lock);
			return (-1);
		}
	}

	/* Start a read operation */
	VERIFY(++lpo->lpo_rops == 1);
	mutex_exit(&lpo->lpo_rops_lock);
	return (0);
}

static void
lx_ptm_read_end(dev_t dev)
{
	lx_ptm_ops_t	*lpo = lx_ptm_lpo_lookup(DEVT_TO_INDEX(dev));

	mutex_enter(&lpo->lpo_rops_lock);
	ASSERT(lpo->lpo_rops >= 0);

	/* End a read operation */
	VERIFY(--lpo->lpo_rops == 0);
	cv_signal(&lpo->lpo_rops_cv);

	mutex_exit(&lpo->lpo_rops_lock);
}

static int
lx_ptm_pts_isopen(dev_t dev)
{
	ptmptsopencb_t	ppocb;

	lx_ptm_lh_get_ppocb(DEVT_TO_INDEX(dev), &ppocb);
	return (ppocb.ppocb_func(ppocb.ppocb_arg));
}

static void
lx_ptm_eof_read(ldi_handle_t lh)
{
	struct uio	uio;
	iovec_t		iov;
	char		junk[1];

	/*
	 * We can remove any EOF message from the head of the stream by
	 * doing a zero byte read from the stream.
	 */
	iov.iov_len = 0;
	iov.iov_base = junk;
	uio.uio_iovcnt = 1;
	uio.uio_iov = &iov;
	uio.uio_resid = iov.iov_len;
	uio.uio_offset = 0;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_extflg = 0;
	uio.uio_llimit = MAXOFFSET_T;
	(void) ldi_read(lh, &uio, kcred);
}

static int
lx_ptm_eof_drop_1(dev_t dev, int *rvalp)
{
	ldi_handle_t	lh = lx_ptm_lh_lookup(DEVT_TO_INDEX(dev));
	int		err, msg_size, msg_count;

	*rvalp = 0;

	/*
	 * Check if there is an EOF message (represented by a zero length
	 * data message) at the head of the stream.  Note that the
	 * I_NREAD ioctl is a streams framework ioctl so it will succeed
	 * even if there have been previous write errors on this stream.
	 */
	if ((err = ldi_ioctl(lh, I_NREAD, (intptr_t)&msg_size,
	    FKIOCTL, kcred, &msg_count)) != 0)
		return (err);

	if ((msg_count == 0) || (msg_size != 0)) {
		/* No EOF message found */
		return (0);
	}

	/* Record the fact that the slave device has been closed. */
	lx_ptm_lh_eofed_set(DEVT_TO_INDEX(dev));

	/* drop the EOF */
	lx_ptm_eof_read(lh);
	*rvalp = 1;
	return (0);
}

static int
lx_ptm_eof_drop(dev_t dev, int *rvalp)
{
	int rval, err;

	if (rvalp != NULL)
		*rvalp = 0;
	for (;;) {
		if ((err = lx_ptm_eof_drop_1(dev, &rval)) != 0)
			return (err);
		if (rval == 0)
			return (0);
		if (rvalp != NULL)
			*rvalp = 1;
	}
}

static int
lx_ptm_data_check(dev_t dev, int ignore_eof, int *rvalp)
{
	ldi_handle_t	lh = lx_ptm_lh_lookup(DEVT_TO_INDEX(dev));
	int		err;

	*rvalp = 0;
	if (ignore_eof) {
		int	size, rval;

		if ((err = ldi_ioctl(lh, FIONREAD, (intptr_t)&size,
		    FKIOCTL, kcred, &rval)) != 0)
			return (err);
		if (size != 0)
			*rvalp = 1;
	} else {
		int	msg_size, msg_count;

		if ((err = ldi_ioctl(lh, I_NREAD, (intptr_t)&msg_size,
		    FKIOCTL, kcred, &msg_count)) != 0)
			return (err);
		if (msg_count != 0)
			*rvalp = 1;
	}
	return (0);
}

static int
lx_ptm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int err;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, LX_PTM_MINOR_NODE, S_IFCHR,
	    ddi_get_instance(dip), DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	err = ldi_ident_from_dip(dip, &lps.lps_li);
	if (err != 0) {
		ddi_remove_minor_node(dip, ddi_get_name(dip));
		return (DDI_FAILURE);
	}

	lps.lps_dip = dip;
	lps.lps_pts_major = ddi_name_to_major(LP_PTS_DRV_NAME);

	rw_init(&lps.lps_lh_rwlock, NULL, RW_DRIVER, NULL);
	lps.lps_lh_count = 0;
	lps.lps_lh_array = NULL;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
lx_ptm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ldi_ident_release(lps.lps_li);
	lps.lps_dip = NULL;

	ASSERT((lps.lps_lh_count != 0) || (lps.lps_lh_array == NULL));
	ASSERT((lps.lps_lh_count == 0) || (lps.lps_lh_array != NULL));
	if (lps.lps_lh_array != NULL) {
		kmem_free(lps.lps_lh_array,
		    sizeof (lx_ptm_handle_t) * lps.lps_lh_count);
		lps.lps_lh_array = NULL;
		lps.lps_lh_count = 0;
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
lx_ptm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	struct strioctl	iocb;
	ptmptsopencb_t	ppocb = { NULL, NULL };
	ldi_handle_t	lh;
	major_t		maj, our_major = getmajor(*devp);
	minor_t		min, lastmin;
	uint_t		index, anchor = 1;
	dev_t		ptm_dev;
	int		err, rval = 0;

	/*
	 * Don't support the FNDELAY flag and FNONBLOCK until we either
	 * find a Linux app that opens /dev/ptmx with the O_NDELAY
	 * or O_NONBLOCK flags explicitly, or until we create test cases
	 * to determine how reads of master terminal devices opened with
	 * these flags behave in different situations on Linux.  Supporting
	 * these flags will involve enhancing our read implementation
	 * and changing the way it deals with EOF notifications.
	 */
	if (flag & (FNDELAY | FNONBLOCK))
		return (ENOTSUP);

	/*
	 * we're layered on top of the ptm driver so open that driver
	 * first.  (note that we're opening /dev/ptmx in the global
	 * zone, not ourselves in the Linux zone.)
	 */
	err = ldi_open_by_name(LP_PTM_PATH, flag, credp, &lh, lps.lps_li);
	if (err != 0)
		return (err);

	/* get the devt returned by the ptmx open */
	err = ldi_get_dev(lh, &ptm_dev);
	if (err != 0) {
		(void) ldi_close(lh, flag, credp);
		return (err);
	}

	/*
	 * we're a cloning driver so here's well change the devt that we
	 * return.  the ptmx is also a cloning driver so we'll just use
	 * it's minor number as our minor number (it already manages it's
	 * minor name space so no reason to duplicate the effort.)
	 */
	index = getminor(ptm_dev);
	*devp = makedevice(our_major, INDEX_TO_MINOR(index));

	/* Get a callback function to query if the pts device is open. */
	iocb.ic_cmd = PTMPTSOPENCB;
	iocb.ic_timout = 0;
	iocb.ic_len = sizeof (ppocb);
	iocb.ic_dp = (char *)&ppocb;

	err = ldi_ioctl(lh, I_STR, (intptr_t)&iocb, FKIOCTL, kcred, &rval);
	if ((err != 0) || (rval != 0)) {
		(void) ldi_close(lh, flag, credp);
		return (EIO); /* XXX return something else here? */
	}
	ASSERT(ppocb.ppocb_func != NULL);

	/*
	 * now setup autopush for the terminal slave device.  this is
	 * necessary so that when a Linux program opens the device we
	 * can push required strmod modules onto the stream.  in Solaris
	 * this is normally done by the application that actually
	 * allocates the terminal.
	 */
	maj = lps.lps_pts_major;
	min = index;
	lastmin = 0;
	err = kstr_autopush(SET_AUTOPUSH, &maj, &min, &lastmin,
	    &anchor, lx_pts_mods);
	if (err != 0) {
		(void) ldi_close(lh, flag, credp);
		return (EIO); /* XXX return something else here? */
	}

	/* save off this layered handle for future accesses */
	lx_ptm_lh_insert(index, lh);
	lx_ptm_lh_set_ppocb(index, &ppocb);
	return (0);
}

/*ARGSUSED*/
static int
lx_ptm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	ldi_handle_t	lh;
	major_t		maj;
	minor_t		min, lastmin;
	uint_t		index;
	int		err;
	int		i;

	index = DEVT_TO_INDEX(dev);

	/*
	 * we must cleanup all the state associated with this major/minor
	 * terminal pair before actually closing the ptm master device.
	 * this is required because once the close of the ptm device is
	 * complete major/minor terminal pair is immediatly available for
	 * re-use in any zone.
	 */

	/* free up our saved reference for this layered handle */
	lh = lx_ptm_lh_remove(index);

	/* unconfigure autopush for the associated terminal slave device */
	maj = lps.lps_pts_major;
	min = index;
	lastmin = 0;
	for (i = 0; i < 5; i++) {
		/*
		 * we loop here because we don't want to release this ptm
		 * node if autopush can't be disabled on the associated
		 * slave device because then bad things could happen if
		 * another brand were to get this terminal allocated
		 * to them. If we keep failing we eventually drive on so that
		 * things don't hang.
		 */
		err = kstr_autopush(CLR_AUTOPUSH, &maj, &min, &lastmin,
		    0, NULL);
		if (err == 0)
			break;

		cmn_err(CE_WARN, "lx zoneid %d: error %d on kstr_autopush",
		    getzoneid(), err);

		/* wait one second and try again */
		delay(drv_usectohz(1000000));
	}

	err = ldi_close(lh, flag, credp);

	/*
	 * note that we don't have to bother with changing the permissions
	 * on the associated slave device here.  the reason is that no one
	 * can actually open the device untill it's associated master
	 * device is re-opened, which will result in the permissions on
	 * it being reset.
	 */
	return (err);
}

static int
lx_ptm_read_loop(dev_t dev, struct uio *uiop, cred_t *credp, int *loop)
{
	ldi_handle_t	lh = lx_ptm_lh_lookup(DEVT_TO_INDEX(dev));
	int		err, rval;
	struct uio	uio = *uiop;

	*loop = 0;

	/*
	 * Here's another way that Linux master terminals behave differently
	 * from Solaris master terminals.  If you do a read on a Linux
	 * master terminal (that was opened witout NDELAY and NONBLOCK)
	 * who's corrosponding slave terminal is currently closed and
	 * has been opened and closed at least once, Linux return -1 and
	 * set errno to EIO where as Solaris blocks.
	 */
	if (lx_ptm_lh_eofed_get(DEVT_TO_INDEX(dev))) {
		/* Slave has been opened and closed at least once. */
		if (lx_ptm_pts_isopen(dev) == 0) {
			/*
			 * Slave is closed.  Make sure that data is avaliable
			 * before attempting a read.
			 */
			if ((err = lx_ptm_data_check(dev, 0, &rval)) != 0)
				return (err);

			/* If there is no data available then return. */
			if (rval == 0)
				return (EIO);
		}
	}

	/* Actually do the read operation. */
	if ((err = ldi_read(lh, uiop, credp)) != 0)
		return (err);

	/* If read returned actual data then return. */
	if (uio.uio_resid != uiop->uio_resid)
		return (0);

	/*
	 * This was a zero byte read (ie, an EOF).  This indicates
	 * that the slave terinal device has been closed.  Record
	 * the fact that the slave device has been closed and retry
	 * the read operation.
	 */
	lx_ptm_lh_eofed_set(DEVT_TO_INDEX(dev));
	*loop = 1;
	return (0);
}

static int
lx_ptm_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int		pktio = lx_ptm_lh_pktio_get(DEVT_TO_INDEX(dev));
	int		err, loop;
	struct uio	uio;
	struct iovec	iovp;

	ASSERT(uiop->uio_iovcnt > 0);

	/*
	 * If packet mode has been enabled (via TIOCPKT) we need to pad
	 * all read requests with a leading byte that indicates any
	 * relevant control status information.
	 */
	if (pktio != 0) {
		/*
		 * We'd like to write the control information into
		 * the current buffer but we can't yet.  We don't
		 * want to modify userspace memory here only to have
		 * the read operation fail later.  So instead
		 * what we'll do here is read one character from the
		 * beginning of the memory pointed to by the uio
		 * structure.  This will advance the output pointer
		 * by one.  Then when the read completes successfully
		 * we can update the byte that we passed over.  Before
		 * we do the read make a copy of the current uiop and
		 * iovec structs so we can write to them later.
		 */
		uio = *uiop;
		iovp = *uiop->uio_iov;
		uio.uio_iov = &iovp;

		if (uwritec(uiop) == -1)
			return (EFAULT);
	}

	do {
		/*
		 * Before we actually attempt a read operation we need
		 * to make sure there's some buffer space to actually
		 * read in some data.  We do this because if we're in
		 * pktio mode and the caller only requested one byte,
		 * then we've already used up that one byte and we
		 * don't want to pass this read request.  Doing a 0
		 * byte read (unless there is a problem with the stream
		 * head) always returns succcess.  Normally when a streams
		 * read returns 0 bytes we interpret that as an EOF on
		 * the stream (ie, the slave side has been opened and
		 * closed) and we ignore it and re-try the read operation.
		 * So if we pass on a 0 byte read here lx_ptm_read_loop()
		 * will tell us to loop around and we'll end up in an
		 * infinite loop.
		 */
		if (uiop->uio_resid == 0)
			break;

		/*
		 * Serialize all reads.  We need to do this so that we can
		 * properly emulate the behavior of master terminals on Linux.
		 * In reality this serializaion should not pose any kind of
		 * performance problem since it would be very strange to have
		 * multiple threads trying to read from the same master
		 * terminal device concurrently.
		 */
		if (lx_ptm_read_start(dev) != 0)
			return (EINTR);

		err = lx_ptm_read_loop(dev, uiop, credp, &loop);
		lx_ptm_read_end(dev);
		if (err != 0)
			return (err);
	} while (loop != 0);

	if (pktio != 0) {
		uint8_t		pktio_data = TIOCPKT_DATA;

		/*
		 * Note that the control status information we
		 * pass back is faked up in the sense that we
		 * don't actually report any events, we always
		 * report a status of 0.
		 */
		if (uiomove(&pktio_data, 1, UIO_READ, &uio) != 0)
			return (EFAULT);
	}

	return (0);
}

static int
lx_ptm_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	ldi_handle_t		lh = lx_ptm_lh_lookup(DEVT_TO_INDEX(dev));
	int		err;

	err = ldi_write(lh, uiop, credp);

	return (err);
}

static int
lx_ptm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	ldi_handle_t	lh = lx_ptm_lh_lookup(DEVT_TO_INDEX(dev));
	int		err;

	/*
	 * here we need to make sure that we never allow the
	 * I_SETSIG and I_ESETSIG ioctls to pass through.  we
	 * do this because we can't support them.
	 *
	 * the native Solaris ptm device supports these ioctls because
	 * they are streams framework ioctls and all streams devices
	 * support them by default.  these ioctls cause the current
	 * process to be registered with a stream and receive signals
	 * when certain stream events occur.
	 *
	 * a problem arises with cleanup of these registrations
	 * for layered drivers.
	 *
	 * normally the streams framework is notified whenever a
	 * process closes any reference to a stream and it goes ahead
	 * and cleans up these registrations.  but actual device drivers
	 * are not notified when a process performs a close operation
	 * unless the process is closing the last opened reference to
	 * the device on the entire system.
	 *
	 * so while we could pass these ioctls on and allow processes
	 * to register for signal delivery, we would never receive
	 * any notification when those processes exit (or close a
	 * stream) and we wouldn't be able to unregister them.
	 *
	 * luckily these operations are streams specific and Linux
	 * doesn't support streams devices.  so it doesn't actually
	 * seem like we need to support these ioctls.  if it turns
	 * out that we do need to support them for some reason in
	 * the future, the current driver model will have to be
	 * enhanced to better support streams device layering.
	 */
	if ((cmd == I_SETSIG) || (cmd == I_ESETSIG))
		return (EINVAL);

	/*
	 * here we fake up support for TIOCPKT.  Linux applications expect
	 * /etc/ptmx to support this ioctl, but on Solaris it doesn't.
	 * (it is supported on older bsd style ptys.)  so we'll fake
	 * up support for it here.
	 *
	 * the reason that this ioctl is emulated here instead of in
	 * userland is that this ioctl affects the results returned
	 * from read() operations.  if this ioctl was emulated in
	 * userland the brand library would need to intercept all
	 * read operations and check to see if pktio was enabled
	 * for the fd being read from.  since this ioctl only needs
	 * to be supported on the ptmx device it makes more sense
	 * to support it here where we can easily update the results
	 * returned for read() operations performed on ourselves.
	 */
	if (cmd == TIOCPKT) {
		int	pktio;

		if (ddi_copyin((void *)arg, &pktio, sizeof (pktio),
		    mode) != DDI_SUCCESS)
			return (EFAULT);

		if (pktio == 0)
			lx_ptm_lh_pktio_set(DEVT_TO_INDEX(dev), 0);
		else
			lx_ptm_lh_pktio_set(DEVT_TO_INDEX(dev), 1);

		return (0);
	}

	err = ldi_ioctl(lh, cmd, arg, mode, credp, rvalp);

	return (err);
}

static int
lx_ptm_poll_loop(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp, int *loop)
{
	ldi_handle_t	lh = lx_ptm_lh_lookup(DEVT_TO_INDEX(dev));
	short		reventsp2;
	int		err, rval;

	*loop = 0;

	/*
	 * If the slave device has been opened and closed at least
	 * once and the slave device is currently closed, then poll
	 * always needs to returns immediatly.
	 */
	if ((lx_ptm_lh_eofed_get(DEVT_TO_INDEX(dev)) != 0) &&
	    (lx_ptm_pts_isopen(dev) == 0)) {
		/* In this case always return POLLHUP */
		*reventsp = POLLHUP;

		/*
		 * Check if there really is data on the stream.
		 * If so set the correct return flags.
		 */
		if ((err = lx_ptm_data_check(dev, 1, &rval)) != 0) {
			/* Something went wrong. */
			return (err);
		}
		if (rval != 0)
			*reventsp |= (events & (POLLIN | POLLRDNORM));

		/*
		 * Is the user checking for writability?  Note that for ptm
		 * devices Linux seems to ignore the POLLWRBAND write flag.
		 */
		if ((events & POLLWRNORM) == 0)
			return (0);

		/*
		 * To check if the stream is writable we have to actually
		 * call poll, but make sure to set anyyet to 1 to prevent
		 * the streams framework from setting up callbacks.
		 */
		if ((err = ldi_poll(lh, POLLWRNORM, 1, &reventsp2, NULL)) != 0)
			return (err);

		*reventsp |= (reventsp2 & POLLWRNORM);
	} else {
		int lockstate;

		/* The slave device is open, do the poll */
		if ((err = ldi_poll(lh, events, anyyet, reventsp, phpp)) != 0)
			return (err);

		/*
		 * Drop any leading EOFs on the stream.
		 *
		 * Note that we have to use pollunlock() here to avoid
		 * recursive mutex enters in the poll framework.  The
		 * reason is that if there is an EOF message on the stream
		 * then the act of reading from the queue to remove the
		 * message can cause the ptm drivers event service
		 * routine to be invoked, and if there is no open
		 * slave device then the ptm driver may generate
		 * error messages and put them on the stream.  This
		 * in turn will generate a poll event and the poll
		 * framework will try to invoke any poll callbacks
		 * associated with the stream.  In the process of
		 * doing that the poll framework will try to aquire
		 * locks that we are already holding.  So we need to
		 * drop those locks here before we do our read.
		 */
		lockstate = pollunlock();
		err = lx_ptm_eof_drop(dev, &rval);
		pollrelock(lockstate);
		if (err)
			return (err);

		/* If no EOF was dropped then return */
		if (rval == 0)
			return (0);

		/*
		 * An EOF was removed from the stream.  Retry the entire
		 * poll operation from the top because polls on the ptm
		 * device should behave differently now.
		 */
		*loop = 1;
	}
	return (0);
}

static int
lx_ptm_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	int loop, err;

	do {
		/* Serialize ourself wrt read operations. */
		if (lx_ptm_read_start(dev) != 0)
			return (EINTR);

		err = lx_ptm_poll_loop(dev,
		    events, anyyet, reventsp, phpp, &loop);
		lx_ptm_read_end(dev);
		if (err != 0)
			return (err);
	} while (loop != 0);
	return (0);
}

static struct cb_ops lx_ptm_cb_ops = {
	lx_ptm_open,		/* open */
	lx_ptm_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	lx_ptm_read,		/* read */
	lx_ptm_write,		/* write */
	lx_ptm_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	lx_ptm_poll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* cb_str */
	D_NEW | D_MP,
	CB_REV,
	NULL,
	NULL
};

static struct dev_ops lx_ptm_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,
	nulldev,
	lx_ptm_attach,
	lx_ptm_detach,
	nodev,
	&lx_ptm_cb_ops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* type of module */
	"Linux master terminal driver",	/* description of module */
	&lx_ptm_ops			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
