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
 *
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * Storage Volume Character and Block Driver (SV)
 *
 * This driver implements a simplistic /dev/{r}dsk/ interface to a
 * specified disk volume that is otherwise managed by the Prism
 * software.  The SV driver layers itself onto the underlying disk
 * device driver by changing function pointers in the cb_ops
 * structure.
 *
 * CONFIGURATION:
 *
 * 1. Configure the driver using the svadm utility.
 * 2. Access the device as before through /dev/rdsk/c?t?d?s?
 *
 * LIMITATIONS:
 *
 * This driver should NOT be used to share a device between another
 * DataServices user interface module (e.g., STE) and a user accessing
 * the device through the block device in O_WRITE mode.  This is because
 * writes through the block device are asynchronous (due to the page
 * cache) and so consistency between the block device user and the
 * STE user cannot be guaranteed.
 *
 * Data is copied between system struct buf(9s) and nsc_vec_t.  This is
 * wasteful and slow.
 */

#include <sys/debug.h>
#include <sys/types.h>

#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/varargs.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/buf.h>
#include <sys/uio.h>
#ifndef DS_DDICT
#include <sys/pathname.h>
#endif
#include <sys/aio_req.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/nsctl/nsvers.h>

#include <sys/nsc_thread.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>

#ifdef DS_DDICT
#include "../contract.h"
#endif

#include "../nsctl.h"


#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "sv.h"
#include "sv_impl.h"
#include "sv_efi.h"

#define	MAX_EINTR_COUNT 1000

/*
 * sv_mod_status
 */
#define	SV_PREVENT_UNLOAD 1
#define	SV_ALLOW_UNLOAD	2

static const int sv_major_rev = ISS_VERSION_MAJ;	/* Major number */
static const int sv_minor_rev = ISS_VERSION_MIN;	/* Minor number */
static const int sv_micro_rev = ISS_VERSION_MIC;	/* Micro number */
static const int sv_baseline_rev = ISS_VERSION_NUM;	/* Baseline number */

#ifdef DKIOCPARTITION
/*
 * CRC32 polynomial table needed for computing the checksums
 * in an EFI vtoc.
 */
static const uint32_t sv_crc32_table[256] = { CRC32_TABLE };
#endif

static clock_t sv_config_time;		/* Time of successful {en,dis}able */
static int sv_debug;			/* Set non-zero for debug to syslog */
static int sv_mod_status;		/* Set to prevent modunload */

static dev_info_t *sv_dip;		/* Single DIP for driver */
static kmutex_t sv_mutex;		/* Protect global lists, etc. */

static nsc_mem_t	*sv_mem;	/* nsctl memory allocator token */


/*
 * Per device and per major state.
 */

#ifndef _SunOS_5_6
#define	UNSAFE_ENTER()
#define	UNSAFE_EXIT()
#else
#define	UNSAFE_ENTER()	mutex_enter(&unsafe_driver)
#define	UNSAFE_EXIT()	mutex_exit(&unsafe_driver)
#endif

					/* hash table of major dev structures */
static sv_maj_t *sv_majors[SV_MAJOR_HASH_CNT] = {0};
static sv_dev_t *sv_devs;		/* array of per device structures */
static int sv_max_devices;		/* SV version of nsc_max_devices() */
static int sv_ndevices;			/* number of SV enabled devices */

/*
 * Threading.
 */

int sv_threads_max = 1024;		/* maximum # to dynamically alloc */
int sv_threads = 32;			/* # to pre-allocate (see sv.conf) */
int sv_threads_extra = 0;		/* addl # we would have alloc'ed */

static nstset_t *sv_tset;		/* the threadset pointer */

static int sv_threads_hysteresis = 4;	/* hysteresis for threadset resizing */
static int sv_threads_dev = 2;		/* # of threads to alloc per device */
static int sv_threads_inc = 8;		/* increment for changing the set */
static int sv_threads_needed;		/* number of threads needed */
static int sv_no_threads;		/* number of nsc_create errors */
static int sv_max_nlive;		/* max number of threads running */



/*
 * nsctl fd callbacks.
 */

static int svattach_fd(blind_t);
static int svdetach_fd(blind_t);

static nsc_def_t sv_fd_def[] = {
	{ "Attach",	(uintptr_t)svattach_fd, },
	{ "Detach",	(uintptr_t)svdetach_fd, },
	{ 0, 0, }
};

/*
 * cb_ops functions.
 */

static int svopen(dev_t *, int, int, cred_t *);
static int svclose(dev_t, int, int, cred_t *);
static int svioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int svprint(dev_t, char *);

/*
 * These next functions are layered into the underlying driver's devops.
 */

static int sv_lyr_open(dev_t *, int, int, cred_t *);
static int sv_lyr_close(dev_t, int, int, cred_t *);
static int sv_lyr_strategy(struct buf *);
static int sv_lyr_read(dev_t, struct uio *, cred_t *);
static int sv_lyr_write(dev_t, struct uio *, cred_t *);
static int sv_lyr_aread(dev_t, struct aio_req *, cred_t *);
static int sv_lyr_awrite(dev_t, struct aio_req *, cred_t *);
static int sv_lyr_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops sv_cb_ops = {
	svopen,		/* open */
	svclose,	/* close */
	nulldev,	/* strategy */
	svprint,
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	svioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,		/* NOT a stream */
	D_NEW | D_MP | D_64BIT,
	CB_REV,
	nodev,		/* aread */
	nodev,		/* awrite */
};


/*
 * dev_ops functions.
 */

static int sv_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sv_attach(dev_info_t *, ddi_attach_cmd_t);
static int sv_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops sv_ops = {
	DEVO_REV,
	0,
	sv_getinfo,
	nulldev,	/* identify */
	nulldev,	/* probe */
	sv_attach,
	sv_detach,
	nodev,		/* reset */
	&sv_cb_ops,
	(struct bus_ops *)0
};

/*
 * Module linkage.
 */

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"nws:Storage Volume:" ISS_VERSION_STR,
	&sv_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	0
};


int
_init(void)
{
	int error;

	mutex_init(&sv_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((error = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&sv_mutex);
		return (error);
	}

#ifdef DEBUG
	cmn_err(CE_CONT, "!sv (revision %d.%d.%d.%d, %s, %s)\n",
	    sv_major_rev, sv_minor_rev, sv_micro_rev, sv_baseline_rev,
	    ISS_VERSION_STR, BUILD_DATE_STR);
#else
	if (sv_micro_rev) {
		cmn_err(CE_CONT, "!sv (revision %d.%d.%d, %s, %s)\n",
		    sv_major_rev, sv_minor_rev, sv_micro_rev,
		    ISS_VERSION_STR, BUILD_DATE_STR);
	} else {
		cmn_err(CE_CONT, "!sv (revision %d.%d, %s, %s)\n",
		    sv_major_rev, sv_minor_rev,
		    ISS_VERSION_STR, BUILD_DATE_STR);
	}
#endif

	return (error);
}


int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	mutex_destroy(&sv_mutex);

	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Locking & State.
 *
 * sv_mutex protects config information - sv_maj_t and sv_dev_t lists;
 * threadset creation and sizing; sv_ndevices.
 *
 * If we need to hold both sv_mutex and sv_lock, then the sv_mutex
 * must be acquired first.
 *
 * sv_lock protects the sv_dev_t structure for an individual device.
 *
 * sv_olock protects the otyp/open members of the sv_dev_t.  If we need
 * to hold both sv_lock and sv_olock, then the sv_lock must be acquired
 * first.
 *
 * nsc_reserve/nsc_release are used in NSC_MULTI mode to allow multiple
 * I/O operations to a device simultaneously, as above.
 *
 * All nsc_open/nsc_close/nsc_reserve/nsc_release operations that occur
 * with sv_lock write-locked must be done with (sv_state == SV_PENDING)
 * and (sv_pending == curthread) so that any recursion through
 * sv_lyr_open/sv_lyr_close can be detected.
 */


static int
sv_init_devs(void)
{
	int i;

	ASSERT(MUTEX_HELD(&sv_mutex));

	if (sv_max_devices > 0)
		return (0);

	sv_max_devices = nsc_max_devices();

	if (sv_max_devices <= 0) {
		/* nsctl is not attached (nskernd not running) */
		if (sv_debug > 0)
			cmn_err(CE_CONT, "!sv: nsc_max_devices = 0\n");
		return (EAGAIN);
	}

	sv_devs = nsc_kmem_zalloc((sv_max_devices * sizeof (*sv_devs)),
	    KM_NOSLEEP, sv_mem);

	if (sv_devs == NULL) {
		cmn_err(CE_WARN, "!sv: could not allocate sv_devs array");
		return (ENOMEM);
	}

	for (i = 0; i < sv_max_devices; i++) {
		mutex_init(&sv_devs[i].sv_olock, NULL, MUTEX_DRIVER, NULL);
		rw_init(&sv_devs[i].sv_lock, NULL, RW_DRIVER, NULL);
	}

	if (sv_debug > 0)
		cmn_err(CE_CONT, "!sv: sv_init_devs successful\n");

	return (0);
}


static int
sv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int rc;

	switch (cmd) {

	case DDI_ATTACH:
		sv_dip = dip;

		if (ddi_create_minor_node(dip, "sv", S_IFCHR,
		    0, DDI_PSEUDO, 0) != DDI_SUCCESS)
			goto failed;

		mutex_enter(&sv_mutex);

		sv_mem = nsc_register_mem("SV", NSC_MEM_LOCAL, 0);
		if (sv_mem == NULL) {
			mutex_exit(&sv_mutex);
			goto failed;
		}

		rc = sv_init_devs();
		if (rc != 0 && rc != EAGAIN) {
			mutex_exit(&sv_mutex);
			goto failed;
		}

		mutex_exit(&sv_mutex);


		ddi_report_dev(dip);

		sv_threads = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    "sv_threads", sv_threads);

		if (sv_debug > 0)
			cmn_err(CE_CONT, "!sv: sv_threads=%d\n", sv_threads);

		if (sv_threads > sv_threads_max)
			sv_threads_max = sv_threads;

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

failed:
	DTRACE_PROBE(sv_attach_failed);
	(void) sv_detach(dip, DDI_DETACH);
	return (DDI_FAILURE);
}


static int
sv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	sv_dev_t *svp;
	int i;

	switch (cmd) {

	case DDI_DETACH:

		/*
		 * Check that everything is disabled.
		 */

		mutex_enter(&sv_mutex);

		if (sv_mod_status == SV_PREVENT_UNLOAD) {
			mutex_exit(&sv_mutex);
			DTRACE_PROBE(sv_detach_err_prevent);
			return (DDI_FAILURE);
		}

		for (i = 0; sv_devs && i < sv_max_devices; i++) {
			svp = &sv_devs[i];

			if (svp->sv_state != SV_DISABLE) {
				mutex_exit(&sv_mutex);
				DTRACE_PROBE(sv_detach_err_busy);
				return (DDI_FAILURE);
			}
		}


		for (i = 0; sv_devs && i < sv_max_devices; i++) {
			mutex_destroy(&sv_devs[i].sv_olock);
			rw_destroy(&sv_devs[i].sv_lock);
		}

		if (sv_devs) {
			nsc_kmem_free(sv_devs,
			    (sv_max_devices * sizeof (*sv_devs)));
			sv_devs = NULL;
		}
		sv_max_devices = 0;

		if (sv_mem) {
			nsc_unregister_mem(sv_mem);
			sv_mem = NULL;
		}

		mutex_exit(&sv_mutex);

		/*
		 * Remove all minor nodes.
		 */

		ddi_remove_minor_node(dip, NULL);
		sv_dip = NULL;

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static sv_maj_t *
sv_getmajor(const dev_t dev)
{
	sv_maj_t **insert, *maj;
	major_t umaj = getmajor(dev);

	/*
	 * See if the hash table entry, or one of the hash chains
	 * is already allocated for this major number
	 */
	if ((maj = sv_majors[SV_MAJOR_HASH(umaj)]) != 0) {
		do {
			if (maj->sm_major == umaj)
				return (maj);
		} while ((maj = maj->sm_next) != 0);
	}

	/*
	 * If the sv_mutex is held, there is design flaw, as the only non-mutex
	 * held callers can be sv_enable() or sv_dev_to_sv()
	 * Return an error, instead of panicing the system
	 */
	if (MUTEX_HELD(&sv_mutex)) {
		cmn_err(CE_WARN, "!sv: could not allocate sv_maj_t");
		return (NULL);
	}

	/*
	 * Determine where to allocate a new element in the hash table
	 */
	mutex_enter(&sv_mutex);
	insert = &(sv_majors[SV_MAJOR_HASH(umaj)]);
	for (maj = *insert; maj; maj = maj->sm_next) {

		/* Did another thread beat us to it? */
		if (maj->sm_major == umaj)
			return (maj);

		/* Find a NULL insert point? */
		if (maj->sm_next == NULL)
			insert = &maj->sm_next;
	}

	/*
	 * Located the new insert point
	 */
	*insert = nsc_kmem_zalloc(sizeof (*maj), KM_NOSLEEP, sv_mem);
	if ((maj = *insert) != 0)
		maj->sm_major = umaj;
	else
		cmn_err(CE_WARN, "!sv: could not allocate sv_maj_t");

	mutex_exit(&sv_mutex);

	return (maj);
}

/* ARGSUSED */

static int
sv_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int rc = DDI_FAILURE;

	switch (infocmd) {

	case DDI_INFO_DEVT2DEVINFO:
		*result = sv_dip;
		rc = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		/*
		 * We only have a single instance.
		 */
		*result = 0;
		rc = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (rc);
}


/*
 * Hashing of devices onto major device structures.
 *
 * Individual device structures are hashed onto one of the sm_hash[]
 * buckets in the relevant major device structure.
 *
 * Hash insertion and deletion -must- be done with sv_mutex held.  Hash
 * searching does not require the mutex because of the sm_seq member.
 * sm_seq is incremented on each insertion (-after- hash chain pointer
 * manipulation) and each deletion (-before- hash chain pointer
 * manipulation).  When searching the hash chain, the seq number is
 * checked before accessing each device structure, if the seq number has
 * changed, then we restart the search from the top of the hash chain.
 * If we restart more than SV_HASH_RETRY times, we take sv_mutex and search
 * the hash chain (we are guaranteed that this search cannot be
 * interrupted).
 */

#define	SV_HASH_RETRY	16

static sv_dev_t *
sv_dev_to_sv(const dev_t dev, sv_maj_t **majpp)
{
	minor_t umin = getminor(dev);
	sv_dev_t **hb, *next, *svp;
	sv_maj_t *maj;
	int seq;
	int try;

	/* Get major hash table */
	maj = sv_getmajor(dev);
	if (majpp)
		*majpp = maj;
	if (maj == NULL)
		return (NULL);

	if (maj->sm_inuse == 0) {
		DTRACE_PROBE1(
		    sv_dev_to_sv_end,
		    dev_t, dev);
		return (NULL);
	}

	hb = &(maj->sm_hash[SV_MINOR_HASH(umin)]);
	try = 0;

retry:
	if (try > SV_HASH_RETRY)
		mutex_enter(&sv_mutex);

	seq = maj->sm_seq;
	for (svp = *hb; svp; svp = next) {
		next = svp->sv_hash;

		nsc_membar_stld();	/* preserve register load order */

		if (maj->sm_seq != seq) {
			DTRACE_PROBE1(sv_dev_to_sv_retry, dev_t, dev);
			try++;
			goto retry;
		}

		if (svp->sv_dev == dev)
			break;
	}

	if (try > SV_HASH_RETRY)
		mutex_exit(&sv_mutex);

	return (svp);
}


/*
 * Must be called with sv_mutex held.
 */

static int
sv_get_state(const dev_t udev, sv_dev_t **svpp)
{
	sv_dev_t **hb, **insert, *svp;
	sv_maj_t *maj;
	minor_t umin;
	int i;

	/* Get major hash table */
	if ((maj = sv_getmajor(udev)) == NULL)
		return (NULL);

	/* Determine which minor hash table */
	umin = getminor(udev);
	hb = &(maj->sm_hash[SV_MINOR_HASH(umin)]);

	/* look for clash */

	insert = hb;

	for (svp = *hb; svp; svp = svp->sv_hash) {
		if (svp->sv_dev == udev)
			break;

		if (svp->sv_hash == NULL)
			insert = &svp->sv_hash;
	}

	if (svp) {
		DTRACE_PROBE1(
		    sv_get_state_enabled,
		    dev_t, udev);
		return (SV_EENABLED);
	}

	/* look for spare sv_devs slot */

	for (i = 0; i < sv_max_devices; i++) {
		svp = &sv_devs[i];

		if (svp->sv_state == SV_DISABLE)
			break;
	}

	if (i >= sv_max_devices) {
		DTRACE_PROBE1(
		    sv_get_state_noslots,
		    dev_t, udev);
		return (SV_ENOSLOTS);
	}

	svp->sv_state = SV_PENDING;
	svp->sv_pending = curthread;

	*insert = svp;
	svp->sv_hash = NULL;
	maj->sm_seq++;		/* must be after the store to the hash chain */

	*svpp = svp;

	/*
	 * We do not know the size of the underlying device at
	 * this stage, so initialise "nblocks" property to
	 * zero, and update it whenever we succeed in
	 * nsc_reserve'ing the underlying nsc_fd_t.
	 */

	svp->sv_nblocks = 0;

	return (0);
}


/*
 * Remove a device structure from it's hash chain.
 * Must be called with sv_mutex held.
 */

static void
sv_rm_hash(sv_dev_t *svp)
{
	sv_dev_t **svpp;
	sv_maj_t *maj;

	/* Get major hash table */
	if ((maj = sv_getmajor(svp->sv_dev)) == NULL)
		return;

	/* remove svp from hash chain */

	svpp = &(maj->sm_hash[SV_MINOR_HASH(getminor(svp->sv_dev))]);
	while (*svpp) {
		if (*svpp == svp) {
			/*
			 * increment of sm_seq must be before the
			 * removal from the hash chain
			 */
			maj->sm_seq++;
			*svpp = svp->sv_hash;
			break;
		}

		svpp = &(*svpp)->sv_hash;
	}

	svp->sv_hash = NULL;
}

/*
 * Free (disable) a device structure.
 * Must be called with sv_lock(RW_WRITER) and sv_mutex held, and will
 * perform the exits during its processing.
 */

static int
sv_free(sv_dev_t *svp, const int error)
{
	struct cb_ops *cb_ops;
	sv_maj_t *maj;

	/* Get major hash table */
	if ((maj = sv_getmajor(svp->sv_dev)) == NULL)
		return (NULL);

	svp->sv_state = SV_PENDING;
	svp->sv_pending = curthread;

	/*
	 * Close the fd's before removing from the hash or swapping
	 * back the cb_ops pointers so that the cache flushes before new
	 * io can come in.
	 */

	if (svp->sv_fd) {
		(void) nsc_close(svp->sv_fd);
		svp->sv_fd = 0;
	}

	sv_rm_hash(svp);

	if (error != SV_ESDOPEN &&
	    error != SV_ELYROPEN && --maj->sm_inuse == 0) {

		if (maj->sm_dev_ops)
			cb_ops = maj->sm_dev_ops->devo_cb_ops;
		else
			cb_ops = NULL;

		if (cb_ops && maj->sm_strategy != NULL) {
			cb_ops->cb_strategy = maj->sm_strategy;
			cb_ops->cb_close = maj->sm_close;
			cb_ops->cb_ioctl = maj->sm_ioctl;
			cb_ops->cb_write = maj->sm_write;
			cb_ops->cb_open = maj->sm_open;
			cb_ops->cb_read = maj->sm_read;
			cb_ops->cb_flag = maj->sm_flag;

			if (maj->sm_awrite)
				cb_ops->cb_awrite = maj->sm_awrite;

			if (maj->sm_aread)
				cb_ops->cb_aread = maj->sm_aread;

			/*
			 * corbin XXX
			 * Leave backing device ops in maj->sm_*
			 * to handle any requests that might come
			 * in during the disable.  This could be
			 * a problem however if the backing device
			 * driver is changed while we process these
			 * requests.
			 *
			 * maj->sm_strategy = 0;
			 * maj->sm_awrite = 0;
			 * maj->sm_write = 0;
			 * maj->sm_ioctl = 0;
			 * maj->sm_close = 0;
			 * maj->sm_aread = 0;
			 * maj->sm_read = 0;
			 * maj->sm_open = 0;
			 * maj->sm_flag = 0;
			 *
			 */
		}

		if (maj->sm_dev_ops) {
			maj->sm_dev_ops = 0;
		}
	}

	if (svp->sv_lh) {
		cred_t *crp = ddi_get_cred();

		/*
		 * Close the protective layered driver open using the
		 * Sun Private layered driver i/f.
		 */

		(void) ldi_close(svp->sv_lh, FREAD|FWRITE, crp);
		svp->sv_lh = NULL;
	}

	svp->sv_timestamp = nsc_lbolt();
	svp->sv_state = SV_DISABLE;
	svp->sv_pending = NULL;
	rw_exit(&svp->sv_lock);
	mutex_exit(&sv_mutex);

	return (error);
}

/*
 * Reserve the device, taking into account the possibility that
 * the reserve might have to be retried.
 */
static int
sv_reserve(nsc_fd_t *fd, int flags)
{
	int eintr_count;
	int rc;

	eintr_count = 0;
	do {
		rc = nsc_reserve(fd, flags);
		if (rc == EINTR) {
			++eintr_count;
			delay(2);
		}
	} while ((rc == EINTR) && (eintr_count < MAX_EINTR_COUNT));

	return (rc);
}

static int
sv_enable(const caddr_t path, const int flag,
    const dev_t udev, spcs_s_info_t kstatus)
{
	struct dev_ops *dev_ops;
	struct cb_ops *cb_ops;
	sv_dev_t *svp;
	sv_maj_t *maj;
	nsc_size_t nblocks;
	int rc;
	cred_t *crp;
	ldi_ident_t	li;

	if (udev == (dev_t)-1 || udev == 0) {
		DTRACE_PROBE1(
		    sv_enable_err_baddev,
		    dev_t, udev);
		return (SV_EBADDEV);
	}

	if ((flag & ~(NSC_CACHE|NSC_DEVICE)) != 0) {
		DTRACE_PROBE1(sv_enable_err_amode, dev_t, udev);
		return (SV_EAMODE);
	}

	/* Get major hash table */
	if ((maj = sv_getmajor(udev)) == NULL)
		return (SV_EBADDEV);

	mutex_enter(&sv_mutex);

	rc = sv_get_state(udev, &svp);
	if (rc) {
		mutex_exit(&sv_mutex);
		DTRACE_PROBE1(sv_enable_err_state, dev_t, udev);
		return (rc);
	}

	rw_enter(&svp->sv_lock, RW_WRITER);

	/*
	 * Get real fd used for io
	 */

	svp->sv_dev = udev;
	svp->sv_flag = flag;

	/*
	 * OR in NSC_DEVICE to ensure that nskern grabs the real strategy
	 * function pointer before sv swaps them out.
	 */

	svp->sv_fd = nsc_open(path, (svp->sv_flag | NSC_DEVICE),
	    sv_fd_def, (blind_t)udev, &rc);

	if (svp->sv_fd == NULL) {
		if (kstatus)
			spcs_s_add(kstatus, rc);
		DTRACE_PROBE1(sv_enable_err_fd, dev_t, udev);
		return (sv_free(svp, SV_ESDOPEN));
	}

	/*
	 * Perform a layered driver open using the Sun Private layered
	 * driver i/f to ensure that the cb_ops structure for the driver
	 * is not detached out from under us whilst sv is enabled.
	 *
	 */

	crp = ddi_get_cred();
	svp->sv_lh = NULL;

	if ((rc = ldi_ident_from_dev(svp->sv_dev, &li)) == 0) {
		rc = ldi_open_by_dev(&svp->sv_dev,
		    OTYP_BLK, FREAD|FWRITE, crp, &svp->sv_lh, li);
	}

	if (rc != 0) {
		if (kstatus)
			spcs_s_add(kstatus, rc);
		DTRACE_PROBE1(sv_enable_err_lyr_open, dev_t, udev);
		return (sv_free(svp, SV_ELYROPEN));
	}

	/*
	 * Do layering if required - must happen after nsc_open().
	 */

	if (maj->sm_inuse++ == 0) {
		maj->sm_dev_ops = nsc_get_devops(getmajor(udev));

		if (maj->sm_dev_ops == NULL ||
		    maj->sm_dev_ops->devo_cb_ops == NULL) {
			DTRACE_PROBE1(sv_enable_err_load, dev_t, udev);
			return (sv_free(svp, SV_ELOAD));
		}

		dev_ops = maj->sm_dev_ops;
		cb_ops = dev_ops->devo_cb_ops;

		if (cb_ops->cb_strategy == NULL ||
		    cb_ops->cb_strategy == nodev ||
		    cb_ops->cb_strategy == nulldev) {
			DTRACE_PROBE1(sv_enable_err_nostrategy, dev_t, udev);
			return (sv_free(svp, SV_ELOAD));
		}

		if (cb_ops->cb_strategy == sv_lyr_strategy) {
			DTRACE_PROBE1(sv_enable_err_svstrategy, dev_t, udev);
			return (sv_free(svp, SV_ESTRATEGY));
		}

		maj->sm_strategy = cb_ops->cb_strategy;
		maj->sm_close = cb_ops->cb_close;
		maj->sm_ioctl = cb_ops->cb_ioctl;
		maj->sm_write = cb_ops->cb_write;
		maj->sm_open = cb_ops->cb_open;
		maj->sm_read = cb_ops->cb_read;
		maj->sm_flag = cb_ops->cb_flag;

		cb_ops->cb_flag = cb_ops->cb_flag | D_MP;
		cb_ops->cb_strategy = sv_lyr_strategy;
		cb_ops->cb_close = sv_lyr_close;
		cb_ops->cb_ioctl = sv_lyr_ioctl;
		cb_ops->cb_write = sv_lyr_write;
		cb_ops->cb_open = sv_lyr_open;
		cb_ops->cb_read = sv_lyr_read;

		/*
		 * Check that the driver has async I/O entry points
		 * before changing them.
		 */

		if (dev_ops->devo_rev < 3 || cb_ops->cb_rev < 1) {
			maj->sm_awrite = 0;
			maj->sm_aread = 0;
		} else {
			maj->sm_awrite = cb_ops->cb_awrite;
			maj->sm_aread = cb_ops->cb_aread;

			cb_ops->cb_awrite = sv_lyr_awrite;
			cb_ops->cb_aread = sv_lyr_aread;
		}

		/*
		 * Bug 4645743
		 *
		 * Prevent sv from ever unloading after it has interposed
		 * on a major device because there is a race between
		 * sv removing its layered entry points from the target
		 * dev_ops, a client coming in and accessing the driver,
		 * and the kernel modunloading the sv text.
		 *
		 * To allow unload, do svboot -u, which only happens in
		 * pkgrm time.
		 */
		ASSERT(MUTEX_HELD(&sv_mutex));
		sv_mod_status = SV_PREVENT_UNLOAD;
	}


	svp->sv_timestamp = nsc_lbolt();
	svp->sv_state = SV_ENABLE;
	svp->sv_pending = NULL;
	rw_exit(&svp->sv_lock);

	sv_ndevices++;
	mutex_exit(&sv_mutex);

	nblocks = 0;
	if (sv_reserve(svp->sv_fd, NSC_READ|NSC_MULTI|NSC_PCATCH) == 0) {
		nblocks = svp->sv_nblocks;
		nsc_release(svp->sv_fd);
	}

	cmn_err(CE_CONT, "!sv: rdev 0x%lx, nblocks %" NSC_SZFMT "\n",
	    svp->sv_dev, nblocks);

	return (0);
}


static int
sv_prepare_unload()
{
	int rc = 0;

	mutex_enter(&sv_mutex);

	if (sv_mod_status == SV_PREVENT_UNLOAD) {
		if ((sv_ndevices != 0) || (sv_tset != NULL)) {
			rc = EBUSY;
		} else {
			sv_mod_status = SV_ALLOW_UNLOAD;
			delay(SV_WAIT_UNLOAD * drv_usectohz(1000000));
		}
	}

	mutex_exit(&sv_mutex);
	return (rc);
}

static int
svattach_fd(blind_t arg)
{
	dev_t dev = (dev_t)arg;
	sv_dev_t *svp = sv_dev_to_sv(dev, NULL);
	int rc;

	if (sv_debug > 0)
		cmn_err(CE_CONT, "!svattach_fd(%p, %p)\n", arg, (void *)svp);

	if (svp == NULL) {
		cmn_err(CE_WARN, "!svattach_fd: no state (arg %p)", arg);
		return (0);
	}

	if ((rc = nsc_partsize(svp->sv_fd, &svp->sv_nblocks)) != 0) {
		cmn_err(CE_WARN,
		    "!svattach_fd: nsc_partsize() failed, rc %d", rc);
		svp->sv_nblocks = 0;
	}

	if ((rc = nsc_maxfbas(svp->sv_fd, 0, &svp->sv_maxfbas)) != 0) {
		cmn_err(CE_WARN,
		    "!svattach_fd: nsc_maxfbas() failed, rc %d", rc);
		svp->sv_maxfbas = 0;
	}

	if (sv_debug > 0) {
		cmn_err(CE_CONT,
		    "!svattach_fd(%p): size %" NSC_SZFMT ", "
		    "maxfbas %" NSC_SZFMT "\n",
		    arg, svp->sv_nblocks, svp->sv_maxfbas);
	}

	return (0);
}


static int
svdetach_fd(blind_t arg)
{
	dev_t dev = (dev_t)arg;
	sv_dev_t *svp = sv_dev_to_sv(dev, NULL);

	if (sv_debug > 0)
		cmn_err(CE_CONT, "!svdetach_fd(%p, %p)\n", arg, (void *)svp);

	/* svp can be NULL during disable of an sv */
	if (svp == NULL)
		return (0);

	svp->sv_maxfbas = 0;
	svp->sv_nblocks = 0;
	return (0);
}


/*
 * Side effect: if called with (guard != 0), then expects both sv_mutex
 * and sv_lock(RW_WRITER) to be held, and will release them before returning.
 */

/* ARGSUSED */
static int
sv_disable(dev_t dev, spcs_s_info_t kstatus)
{
	sv_dev_t *svp = sv_dev_to_sv(dev, NULL);

	if (svp == NULL) {

		DTRACE_PROBE1(sv_disable_err_nodev, sv_dev_t *, svp);
		return (SV_ENODEV);
	}

	mutex_enter(&sv_mutex);
	rw_enter(&svp->sv_lock, RW_WRITER);

	if (svp->sv_fd == NULL || svp->sv_state != SV_ENABLE) {
		rw_exit(&svp->sv_lock);
		mutex_exit(&sv_mutex);

		DTRACE_PROBE1(sv_disable_err_disabled, sv_dev_t *, svp);
		return (SV_EDISABLED);
	}


	sv_ndevices--;
	return (sv_free(svp, 0));
}



static int
sv_lyr_open(dev_t *devp, int flag, int otyp, cred_t *crp)
{
	nsc_buf_t *tmph;
	sv_dev_t *svp;
	sv_maj_t *maj;
	int (*fn)();
	dev_t odev;
	int ret;
	int rc;

	svp = sv_dev_to_sv(*devp, &maj);

	if (svp) {
		if (svp->sv_state == SV_PENDING &&
		    svp->sv_pending == curthread) {
			/*
			 * This is a recursive open from a call to
			 * ddi_lyr_open_by_devt and so we just want
			 * to pass it straight through to the
			 * underlying driver.
			 */
			DTRACE_PROBE2(sv_lyr_open_recursive,
			    sv_dev_t *, svp,
			    dev_t, *devp);
			svp = NULL;
		} else
			rw_enter(&svp->sv_lock, RW_READER);
	}

	odev = *devp;

	if (maj && (fn = maj->sm_open) != 0) {
		if (!(maj->sm_flag & D_MP)) {
			UNSAFE_ENTER();
			ret = (*fn)(devp, flag, otyp, crp);
			UNSAFE_EXIT();
		} else {
			ret = (*fn)(devp, flag, otyp, crp);
		}

		if (ret == 0) {
			/*
			 * Re-acquire svp if the driver changed *devp.
			 */

			if (*devp != odev) {
				if (svp != NULL)
					rw_exit(&svp->sv_lock);

				svp = sv_dev_to_sv(*devp, NULL);

				if (svp) {
					rw_enter(&svp->sv_lock, RW_READER);
				}
			}
		}
	} else {
		ret = ENODEV;
	}

	if (svp && ret != 0 && svp->sv_state == SV_ENABLE) {
		/*
		 * Underlying DDI open failed, but we have this
		 * device SV enabled.  If we can read some data
		 * from the device, fake a successful open (this
		 * probably means that this device is RDC'd and we
		 * are getting the data from the secondary node).
		 *
		 * The reserve must be done with NSC_TRY|NSC_NOWAIT to
		 * ensure that it does not deadlock if this open is
		 * coming from nskernd:get_bsize().
		 */
		rc = sv_reserve(svp->sv_fd,
		    NSC_TRY | NSC_NOWAIT | NSC_MULTI | NSC_PCATCH);
		if (rc == 0) {
			tmph = NULL;

			rc = nsc_alloc_buf(svp->sv_fd, 0, 1, NSC_READ, &tmph);
			if (rc <= 0) {
				/* success */
				ret = 0;
			}

			if (tmph) {
				(void) nsc_free_buf(tmph);
				tmph = NULL;
			}

			nsc_release(svp->sv_fd);

			/*
			 * Count the number of layered opens that we
			 * fake since we have to fake a matching number
			 * of closes (OTYP_LYR open/close calls must be
			 * paired).
			 */

			if (ret == 0 && otyp == OTYP_LYR) {
				mutex_enter(&svp->sv_olock);
				svp->sv_openlcnt++;
				mutex_exit(&svp->sv_olock);
			}
		}
	}

	if (svp) {
		rw_exit(&svp->sv_lock);
	}

	return (ret);
}


static int
sv_lyr_close(dev_t dev, int flag, int otyp, cred_t *crp)
{
	sv_dev_t *svp;
	sv_maj_t *maj;
	int (*fn)();
	int ret;

	svp = sv_dev_to_sv(dev, &maj);

	if (svp &&
	    svp->sv_state == SV_PENDING &&
	    svp->sv_pending == curthread) {
		/*
		 * This is a recursive open from a call to
		 * ddi_lyr_close and so we just want
		 * to pass it straight through to the
		 * underlying driver.
		 */
		DTRACE_PROBE2(sv_lyr_close_recursive, sv_dev_t *, svp,
		    dev_t, dev);
		svp = NULL;
	}

	if (svp) {
		rw_enter(&svp->sv_lock, RW_READER);

		if (otyp == OTYP_LYR) {
			mutex_enter(&svp->sv_olock);

			if (svp->sv_openlcnt) {
				/*
				 * Consume sufficient layered closes to
				 * account for the opens that we faked
				 * whilst the device was failed.
				 */
				svp->sv_openlcnt--;
				mutex_exit(&svp->sv_olock);
				rw_exit(&svp->sv_lock);

				DTRACE_PROBE1(sv_lyr_close_end, dev_t, dev);

				return (0);
			}

			mutex_exit(&svp->sv_olock);
		}
	}

	if (maj && (fn = maj->sm_close) != 0) {
		if (!(maj->sm_flag & D_MP)) {
			UNSAFE_ENTER();
			ret = (*fn)(dev, flag, otyp, crp);
			UNSAFE_EXIT();
		} else {
			ret = (*fn)(dev, flag, otyp, crp);
		}
	} else {
		ret = ENODEV;
	}

	if (svp) {
		rw_exit(&svp->sv_lock);
	}

	return (ret);
}


/*
 * Convert the specified dev_t into a locked and enabled sv_dev_t, or
 * return NULL.
 */
static sv_dev_t *
sv_find_enabled(const dev_t dev, sv_maj_t **majpp)
{
	sv_dev_t *svp;

	while ((svp = sv_dev_to_sv(dev, majpp)) != NULL) {
		rw_enter(&svp->sv_lock, RW_READER);

		if (svp->sv_state == SV_ENABLE) {
			/* locked and enabled */
			break;
		}

		/*
		 * State was changed while waiting on the lock.
		 * Wait for a stable state.
		 */
		rw_exit(&svp->sv_lock);

		DTRACE_PROBE1(sv_find_enabled_retry, dev_t, dev);

		delay(2);
	}

	return (svp);
}


static int
sv_lyr_uio(dev_t dev, uio_t *uiop, cred_t *crp, int rw)
{
	sv_dev_t *svp;
	sv_maj_t *maj;
	int (*fn)();
	int rc;

	svp = sv_find_enabled(dev, &maj);
	if (svp == NULL) {
		if (maj) {
			if (rw == NSC_READ)
				fn = maj->sm_read;
			else
				fn = maj->sm_write;

			if (fn != 0) {
				if (!(maj->sm_flag & D_MP)) {
					UNSAFE_ENTER();
					rc = (*fn)(dev, uiop, crp);
					UNSAFE_EXIT();
				} else {
					rc = (*fn)(dev, uiop, crp);
				}
			}

			return (rc);
		} else {
			return (ENODEV);
		}
	}

	ASSERT(RW_READ_HELD(&svp->sv_lock));

	if (svp->sv_flag == 0) {
		/*
		 * guard access mode
		 * - prevent user level access to the device
		 */
		DTRACE_PROBE1(sv_lyr_uio_err_guard, uio_t *, uiop);
		rc = EPERM;
		goto out;
	}

	if ((rc = sv_reserve(svp->sv_fd, NSC_MULTI|NSC_PCATCH)) != 0) {
		DTRACE_PROBE1(sv_lyr_uio_err_rsrv, uio_t *, uiop);
		goto out;
	}

	if (rw == NSC_READ)
		rc = nsc_uread(svp->sv_fd, uiop, crp);
	else
		rc = nsc_uwrite(svp->sv_fd, uiop, crp);

	nsc_release(svp->sv_fd);

out:
	rw_exit(&svp->sv_lock);

	return (rc);
}


static int
sv_lyr_read(dev_t dev, uio_t *uiop, cred_t *crp)
{
	return (sv_lyr_uio(dev, uiop, crp, NSC_READ));
}


static int
sv_lyr_write(dev_t dev, uio_t *uiop, cred_t *crp)
{
	return (sv_lyr_uio(dev, uiop, crp, NSC_WRITE));
}


/* ARGSUSED */

static int
sv_lyr_aread(dev_t dev, struct aio_req *aio, cred_t *crp)
{
	return (aphysio(sv_lyr_strategy,
	    anocancel, dev, B_READ, minphys, aio));
}


/* ARGSUSED */

static int
sv_lyr_awrite(dev_t dev, struct aio_req *aio, cred_t *crp)
{
	return (aphysio(sv_lyr_strategy,
	    anocancel, dev, B_WRITE, minphys, aio));
}


/*
 * Set up an array containing the list of raw path names
 * The array for the paths is svl and the size of the array is
 * in size.
 *
 * If there are more layered devices than will fit in the array,
 * the number of extra layered devices is returned.  Otherwise
 * zero is return.
 *
 * Input:
 *	svn	: array for paths
 *	size	: size of the array
 *
 * Output (extra):
 *	zero	: All paths fit in array
 *	>0	: Number of defined layered devices don't fit in array
 */

static int
sv_list(void *ptr, const int size, int *extra, const int ilp32)
{
	sv_name32_t *svn32;
	sv_name_t *svn;
	sv_dev_t *svp;
	int *mode, *nblocks;
	int i, index;
	char *path;

	*extra = 0;
	index = 0;

	if (ilp32)
		svn32 = ptr;
	else
		svn = ptr;

	mutex_enter(&sv_mutex);
	for (i = 0; i < sv_max_devices; i++) {
		svp = &sv_devs[i];

		rw_enter(&svp->sv_lock, RW_READER);

		if (svp->sv_state != SV_ENABLE) {
			rw_exit(&svp->sv_lock);
			continue;
		}

		if ((*extra) != 0 || ptr == NULL) {
			/* Another overflow entry */
			rw_exit(&svp->sv_lock);
			(*extra)++;
			continue;
		}

		if (ilp32) {
			nblocks = &svn32->svn_nblocks;
			mode = &svn32->svn_mode;
			path = svn32->svn_path;

			svn32->svn_timestamp = (uint32_t)svp->sv_timestamp;
			svn32++;
		} else {
			nblocks = &svn->svn_nblocks;
			mode = &svn->svn_mode;
			path = svn->svn_path;

			svn->svn_timestamp = svp->sv_timestamp;
			svn++;
		}

		(void) strcpy(path, nsc_pathname(svp->sv_fd));
		*nblocks = svp->sv_nblocks;
		*mode = svp->sv_flag;

		if (*nblocks == 0) {
			if (sv_debug > 3)
				cmn_err(CE_CONT, "!sv_list: need to reserve\n");

			if (sv_reserve(svp->sv_fd, NSC_MULTI|NSC_PCATCH) == 0) {
				*nblocks = svp->sv_nblocks;
				nsc_release(svp->sv_fd);
			}
		}

		if (++index >= size) {
			/* Out of space */
			(*extra)++;
		}

		rw_exit(&svp->sv_lock);
	}
	mutex_exit(&sv_mutex);

	if (index < size) {
		/* NULL terminated list */
		if (ilp32)
			svn32->svn_path[0] = '\0';
		else
			svn->svn_path[0] = '\0';
	}

	return (0);
}


static void
sv_thread_tune(int threads)
{
	int incr = (threads > 0) ? 1 : -1;
	int change = 0;
	int nthreads;

	ASSERT(MUTEX_HELD(&sv_mutex));

	if (sv_threads_extra) {
		/* keep track of any additional threads requested */
		if (threads > 0) {
			sv_threads_extra += threads;
			return;
		}
		threads = -threads;
		if (threads >= sv_threads_extra) {
			threads -= sv_threads_extra;
			sv_threads_extra = 0;
			/* fall through to while loop */
		} else {
			sv_threads_extra -= threads;
			return;
		}
	} else if (threads > 0) {
		/*
		 * do not increase the number of threads beyond
		 * sv_threads_max when doing dynamic thread tuning
		 */
		nthreads = nst_nthread(sv_tset);
		if ((nthreads + threads) > sv_threads_max) {
			sv_threads_extra = nthreads + threads - sv_threads_max;
			threads = sv_threads_max - nthreads;
			if (threads <= 0)
				return;
		}
	}

	if (threads < 0)
		threads = -threads;

	while (threads--) {
		nthreads = nst_nthread(sv_tset);
		sv_threads_needed += incr;

		if (sv_threads_needed >= nthreads)
			change += nst_add_thread(sv_tset, sv_threads_inc);
		else if ((sv_threads_needed <
		    (nthreads - (sv_threads_inc + sv_threads_hysteresis))) &&
		    ((nthreads - sv_threads_inc) >= sv_threads))
			change -= nst_del_thread(sv_tset, sv_threads_inc);
	}

#ifdef DEBUG
	if (change) {
		cmn_err(CE_NOTE,
		    "!sv_thread_tune: threads needed %d, nthreads %d, "
		    "nthreads change %d",
		    sv_threads_needed, nst_nthread(sv_tset), change);
	}
#endif
}


/* ARGSUSED */
static int
svopen(dev_t *devp, int flag, int otyp, cred_t *crp)
{
	int rc;

	mutex_enter(&sv_mutex);
	rc = sv_init_devs();
	mutex_exit(&sv_mutex);

	return (rc);
}


/* ARGSUSED */
static int
svclose(dev_t dev, int flag, int otyp, cred_t *crp)
{
	const int secs = HZ * 5;
	const int ticks = HZ / 10;
	int loops = secs / ticks;

	mutex_enter(&sv_mutex);
	while (sv_ndevices <= 0 && sv_tset != NULL && loops > 0) {
		if (nst_nlive(sv_tset) <= 0) {
			nst_destroy(sv_tset);
			sv_tset = NULL;
			break;
		}

		/* threads still active - wait for them to exit */
		mutex_exit(&sv_mutex);
		delay(ticks);
		loops--;
		mutex_enter(&sv_mutex);
	}
	mutex_exit(&sv_mutex);

	if (loops <= 0) {
		cmn_err(CE_WARN,
#ifndef DEBUG
		    /* do not write to console when non-DEBUG */
		    "!"
#endif
		    "sv:svclose: threads still active "
		    "after %d sec - leaking thread set", secs);
	}

	return (0);
}


static int
svioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *crp, int *rvalp)
{
	char itmp1[12], itmp2[12]; /* temp char array for editing ints */
	spcs_s_info_t kstatus;	/* Kernel version of spcs status */
	spcs_s_info_t ustatus;	/* Address of user version of spcs status */
	sv_list32_t svl32;	/* 32 bit Initial structure for SVIOC_LIST */
	sv_version_t svv;	/* Version structure */
	sv_conf_t svc;		/* User config structure */
	sv_list_t svl;		/* Initial structure for SVIOC_LIST */
	void *usvn;		/* Address of user sv_name_t */
	void *svn = NULL;	/* Array for SVIOC_LIST */
	uint64_t phash;		/* pathname hash */
	int rc = 0;		/* Return code -- errno */
	int size;		/* Number of items in array */
	int bytes;		/* Byte size of array */
	int ilp32;		/* Convert data structures for ilp32 userland */

	*rvalp = 0;

	/*
	 * If sv_mod_status is 0 or SV_PREVENT_UNLOAD, then it will continue.
	 * else it means it previously was SV_PREVENT_UNLOAD, and now it's
	 * SV_ALLOW_UNLOAD, expecting the driver to eventually unload.
	 *
	 * SV_ALLOW_UNLOAD is final state, so no need to grab sv_mutex.
	 */
	if (sv_mod_status == SV_ALLOW_UNLOAD) {
		return (EBUSY);
	}

	if ((cmd != SVIOC_LIST) && ((rc = drv_priv(crp)) != 0))
		return (rc);

	kstatus = spcs_s_kcreate();
	if (!kstatus) {
		DTRACE_PROBE1(sv_ioctl_err_kcreate, dev_t, dev);
		return (ENOMEM);
	}

	ilp32 = (ddi_model_convert_from((mode & FMODELS)) == DDI_MODEL_ILP32);

	switch (cmd) {

	case SVIOC_ENABLE:

		if (ilp32) {
			sv_conf32_t svc32;

			if (ddi_copyin((void *)arg, &svc32,
			    sizeof (svc32), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}

			svc.svc_error = (spcs_s_info_t)svc32.svc_error;
			(void) strcpy(svc.svc_path, svc32.svc_path);
			svc.svc_flag  = svc32.svc_flag;
			svc.svc_major = svc32.svc_major;
			svc.svc_minor = svc32.svc_minor;
		} else {
			if (ddi_copyin((void *)arg, &svc,
			    sizeof (svc), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}
		}

		/* force to raw access */
		svc.svc_flag = NSC_DEVICE;

		if (sv_tset == NULL) {
			mutex_enter(&sv_mutex);

			if (sv_tset == NULL) {
				sv_tset = nst_init("sv_thr", sv_threads);
			}

			mutex_exit(&sv_mutex);

			if (sv_tset == NULL) {
				cmn_err(CE_WARN,
				    "!sv: could not allocate %d threads",
				    sv_threads);
			}
		}

		rc = sv_enable(svc.svc_path, svc.svc_flag,
		    makedevice(svc.svc_major, svc.svc_minor), kstatus);

		if (rc == 0) {
			sv_config_time = nsc_lbolt();

			mutex_enter(&sv_mutex);
			sv_thread_tune(sv_threads_dev);
			mutex_exit(&sv_mutex);
		}

		DTRACE_PROBE3(sv_ioctl_end, dev_t, dev, int, *rvalp, int, rc);

		return (spcs_s_ocopyoutf(&kstatus, svc.svc_error, rc));
		/* NOTREACHED */

	case SVIOC_DISABLE:

		if (ilp32) {
			sv_conf32_t svc32;

			if (ddi_copyin((void *)arg, &svc32,
			    sizeof (svc32), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}

			svc.svc_error = (spcs_s_info_t)svc32.svc_error;
			svc.svc_major = svc32.svc_major;
			svc.svc_minor = svc32.svc_minor;
			(void) strcpy(svc.svc_path, svc32.svc_path);
			svc.svc_flag  = svc32.svc_flag;
		} else {
			if (ddi_copyin((void *)arg, &svc,
			    sizeof (svc), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}
		}

		if (svc.svc_major == (major_t)-1 &&
		    svc.svc_minor == (minor_t)-1) {
			sv_dev_t *svp;
			int i;

			/*
			 * User level could not find the minor device
			 * node, so do this the slow way by searching
			 * the entire sv config for a matching pathname.
			 */

			phash = nsc_strhash(svc.svc_path);

			mutex_enter(&sv_mutex);

			for (i = 0; i < sv_max_devices; i++) {
				svp = &sv_devs[i];

				if (svp->sv_state == SV_DISABLE ||
				    svp->sv_fd == NULL)
					continue;

				if (nsc_fdpathcmp(svp->sv_fd, phash,
				    svc.svc_path) == 0) {
					svc.svc_major = getmajor(svp->sv_dev);
					svc.svc_minor = getminor(svp->sv_dev);
					break;
				}
			}

			mutex_exit(&sv_mutex);

			if (svc.svc_major == (major_t)-1 &&
			    svc.svc_minor == (minor_t)-1)
				return (spcs_s_ocopyoutf(&kstatus,
				    svc.svc_error, SV_ENODEV));
		}

		rc = sv_disable(makedevice(svc.svc_major, svc.svc_minor),
		    kstatus);

		if (rc == 0) {
			sv_config_time = nsc_lbolt();

			mutex_enter(&sv_mutex);
			sv_thread_tune(-sv_threads_dev);
			mutex_exit(&sv_mutex);
		}

		DTRACE_PROBE3(sv_ioctl_2, dev_t, dev, int, *rvalp, int, rc);

		return (spcs_s_ocopyoutf(&kstatus, svc.svc_error, rc));
		/* NOTREACHED */

	case SVIOC_LIST:

		if (ilp32) {
			if (ddi_copyin((void *)arg, &svl32,
			    sizeof (svl32), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}

			ustatus = (spcs_s_info_t)svl32.svl_error;
			size = svl32.svl_count;
			usvn = (void *)(unsigned long)svl32.svl_names;
		} else {
			if (ddi_copyin((void *)arg, &svl,
			    sizeof (svl), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}

			ustatus = svl.svl_error;
			size = svl.svl_count;
			usvn = svl.svl_names;
		}

		/* Do some boundary checking */
		if ((size < 0) || (size > sv_max_devices)) {
			/* Array size is out of range */
			return (spcs_s_ocopyoutf(&kstatus, ustatus,
			    SV_EARRBOUNDS, "0",
			    spcs_s_inttostring(sv_max_devices, itmp1,
			    sizeof (itmp1), 0),
			    spcs_s_inttostring(size, itmp2,
			    sizeof (itmp2), 0)));
		}

		if (ilp32)
			bytes = size * sizeof (sv_name32_t);
		else
			bytes = size * sizeof (sv_name_t);

		/* Allocate memory for the array of structures */
		if (bytes != 0) {
			svn = kmem_zalloc(bytes, KM_SLEEP);
			if (!svn) {
				return (spcs_s_ocopyoutf(&kstatus,
				    ustatus, ENOMEM));
			}
		}

		rc = sv_list(svn, size, rvalp, ilp32);
		if (rc) {
			if (svn != NULL)
				kmem_free(svn, bytes);
			return (spcs_s_ocopyoutf(&kstatus, ustatus, rc));
		}

		if (ilp32) {
			svl32.svl_timestamp = (uint32_t)sv_config_time;
			svl32.svl_maxdevs = (int32_t)sv_max_devices;

			/* Return the list structure */
			if (ddi_copyout(&svl32, (void *)arg,
			    sizeof (svl32), mode) < 0) {
				spcs_s_kfree(kstatus);
				if (svn != NULL)
					kmem_free(svn, bytes);
				return (EFAULT);
			}
		} else {
			svl.svl_timestamp = sv_config_time;
			svl.svl_maxdevs = sv_max_devices;

			/* Return the list structure */
			if (ddi_copyout(&svl, (void *)arg,
			    sizeof (svl), mode) < 0) {
				spcs_s_kfree(kstatus);
				if (svn != NULL)
					kmem_free(svn, bytes);
				return (EFAULT);
			}
		}

		/* Return the array */
		if (svn != NULL) {
			if (ddi_copyout(svn, usvn, bytes, mode) < 0) {
				kmem_free(svn, bytes);
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}
			kmem_free(svn, bytes);
		}

		DTRACE_PROBE3(sv_ioctl_3, dev_t, dev, int, *rvalp, int, 0);

		return (spcs_s_ocopyoutf(&kstatus, ustatus, 0));
		/* NOTREACHED */

	case SVIOC_VERSION:

		if (ilp32) {
			sv_version32_t svv32;

			if (ddi_copyin((void *)arg, &svv32,
			    sizeof (svv32), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}

			svv32.svv_major_rev = sv_major_rev;
			svv32.svv_minor_rev = sv_minor_rev;
			svv32.svv_micro_rev = sv_micro_rev;
			svv32.svv_baseline_rev = sv_baseline_rev;

			if (ddi_copyout(&svv32, (void *)arg,
			    sizeof (svv32), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}

			ustatus = (spcs_s_info_t)svv32.svv_error;
		} else {
			if (ddi_copyin((void *)arg, &svv,
			    sizeof (svv), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}

			svv.svv_major_rev = sv_major_rev;
			svv.svv_minor_rev = sv_minor_rev;
			svv.svv_micro_rev = sv_micro_rev;
			svv.svv_baseline_rev = sv_baseline_rev;

			if (ddi_copyout(&svv, (void *)arg,
			    sizeof (svv), mode) < 0) {
				spcs_s_kfree(kstatus);
				return (EFAULT);
			}

			ustatus = svv.svv_error;
		}

		DTRACE_PROBE3(sv_ioctl_4, dev_t, dev, int, *rvalp, int, 0);

		return (spcs_s_ocopyoutf(&kstatus, ustatus, 0));
		/* NOTREACHED */

	case SVIOC_UNLOAD:
		rc = sv_prepare_unload();

		if (ddi_copyout(&rc, (void *)arg, sizeof (rc), mode) < 0) {
			rc = EFAULT;
		}

		spcs_s_kfree(kstatus);
		return (rc);

	default:
		spcs_s_kfree(kstatus);

		DTRACE_PROBE3(sv_ioctl_4, dev_t, dev, int, *rvalp, int, EINVAL);

		return (EINVAL);
		/* NOTREACHED */
	}

	/* NOTREACHED */
}


/* ARGSUSED */
static int
svprint(dev_t dev, char *str)
{
	int instance = ddi_get_instance(sv_dip);
	cmn_err(CE_WARN, "!%s%d: %s", ddi_get_name(sv_dip), instance, str);
	return (0);
}


static void
_sv_lyr_strategy(struct buf *bp)
{
	caddr_t buf_addr;		/* pointer to linear buffer in bp */
	nsc_buf_t *bufh = NULL;
	nsc_buf_t *hndl = NULL;
	sv_dev_t *svp;
	nsc_vec_t *v;
	sv_maj_t *maj;
	nsc_size_t fba_req, fba_len;	/* FBA lengths */
	nsc_off_t fba_off;		/* FBA offset */
	size_t tocopy, nbytes;		/* byte lengths */
	int rw, rc;			/* flags and return codes */
	int (*fn)();

	rc = 0;

	if (sv_debug > 5)
		cmn_err(CE_CONT, "!_sv_lyr_strategy(%p)\n", (void *)bp);

	svp = sv_find_enabled(bp->b_edev, &maj);
	if (svp == NULL) {
		if (maj && (fn = maj->sm_strategy) != 0) {
			if (!(maj->sm_flag & D_MP)) {
				UNSAFE_ENTER();
				rc = (*fn)(bp);
				UNSAFE_EXIT();
			} else {
				rc = (*fn)(bp);
			}
			return;
		} else {
			bioerror(bp, ENODEV);
			biodone(bp);
			return;
		}
	}

	ASSERT(RW_READ_HELD(&svp->sv_lock));

	if (svp->sv_flag == 0) {
		/*
		 * guard access mode
		 * - prevent user level access to the device
		 */
		DTRACE_PROBE1(sv_lyr_strategy_err_guard, struct buf *, bp);
		bioerror(bp, EPERM);
		goto out;
	}

	if ((rc = sv_reserve(svp->sv_fd, NSC_MULTI|NSC_PCATCH)) != 0) {
		DTRACE_PROBE1(sv_lyr_strategy_err_rsrv, struct buf *, bp);

		if (rc == EINTR)
			cmn_err(CE_WARN, "!nsc_reserve() returned EINTR");
		bioerror(bp, rc);
		goto out;
	}

	if (bp->b_lblkno >= (diskaddr_t)svp->sv_nblocks) {
		DTRACE_PROBE1(sv_lyr_strategy_eof, struct buf *, bp);

		if (bp->b_flags & B_READ) {
			/* return EOF, not an error */
			bp->b_resid = bp->b_bcount;
			bioerror(bp, 0);
		} else
			bioerror(bp, EINVAL);

		goto done;
	}

	/*
	 * Preallocate a handle once per call to strategy.
	 * If this fails, then the nsc_alloc_buf() will allocate
	 * a temporary handle per allocation/free pair.
	 */

	DTRACE_PROBE1(sv_dbg_alloch_start, sv_dev_t *, svp);

	bufh = nsc_alloc_handle(svp->sv_fd, NULL, NULL, NULL);

	DTRACE_PROBE1(sv_dbg_alloch_end, sv_dev_t *, svp);

	if (bufh && (bufh->sb_flag & NSC_HACTIVE) != 0) {
		DTRACE_PROBE1(sv_lyr_strategy_err_hactive, struct buf *, bp);

		cmn_err(CE_WARN,
		    "!sv: allocated active handle (bufh %p, flags %x)",
		    (void *)bufh, bufh->sb_flag);

		bioerror(bp, ENXIO);
		goto done;
	}

	fba_req = FBA_LEN(bp->b_bcount);
	if (fba_req + bp->b_lblkno > (diskaddr_t)svp->sv_nblocks)
		fba_req = (nsc_size_t)(svp->sv_nblocks - bp->b_lblkno);

	rw = (bp->b_flags & B_READ) ? NSC_READ : NSC_WRITE;

	bp_mapin(bp);

	bp->b_resid = bp->b_bcount;
	buf_addr = bp->b_un.b_addr;
	fba_off = 0;

	/*
	 * fba_req  - requested size of transfer in FBAs after
	 *		truncation to device extent, and allowing for
	 *		possible non-FBA bounded final chunk.
	 * fba_off  - offset of start of chunk from start of bp in FBAs.
	 * fba_len  - size of this chunk in FBAs.
	 */

loop:
	fba_len = min(fba_req, svp->sv_maxfbas);
	hndl = bufh;

	DTRACE_PROBE4(sv_dbg_allocb_start,
	    sv_dev_t *, svp,
	    uint64_t, (uint64_t)(bp->b_lblkno + fba_off),
	    uint64_t, (uint64_t)fba_len,
	    int, rw);

	rc = nsc_alloc_buf(svp->sv_fd, (nsc_off_t)(bp->b_lblkno + fba_off),
	    fba_len, rw, &hndl);

	DTRACE_PROBE1(sv_dbg_allocb_end, sv_dev_t *, svp);

	if (rc > 0) {
		DTRACE_PROBE1(sv_lyr_strategy_err_alloc, struct buf *, bp);
		bioerror(bp, rc);
		if (hndl != bufh)
			(void) nsc_free_buf(hndl);
		hndl = NULL;
		goto done;
	}

	tocopy = min(FBA_SIZE(fba_len), bp->b_resid);
	v = hndl->sb_vec;

	if (rw == NSC_WRITE && FBA_OFF(tocopy) != 0) {
		/*
		 * Not overwriting all of the last FBA, so read in the
		 * old contents now before we overwrite it with the new
		 * data.
		 */

		DTRACE_PROBE2(sv_dbg_read_start, sv_dev_t *, svp,
		    uint64_t, (uint64_t)(hndl->sb_pos + hndl->sb_len - 1));

		rc = nsc_read(hndl, (hndl->sb_pos + hndl->sb_len - 1), 1, 0);
		if (rc > 0) {
			bioerror(bp, rc);
			goto done;
		}

		DTRACE_PROBE1(sv_dbg_read_end, sv_dev_t *, svp);
	}

	DTRACE_PROBE1(sv_dbg_bcopy_start, sv_dev_t *, svp);

	while (tocopy > 0) {
		nbytes = min(tocopy, (nsc_size_t)v->sv_len);

		if (bp->b_flags & B_READ)
			(void) bcopy(v->sv_addr, buf_addr, nbytes);
		else
			(void) bcopy(buf_addr, v->sv_addr, nbytes);

		bp->b_resid -= nbytes;
		buf_addr += nbytes;
		tocopy -= nbytes;
		v++;
	}

	DTRACE_PROBE1(sv_dbg_bcopy_end, sv_dev_t *, svp);

	if ((bp->b_flags & B_READ) == 0) {
		DTRACE_PROBE3(sv_dbg_write_start, sv_dev_t *, svp,
		    uint64_t, (uint64_t)hndl->sb_pos,
		    uint64_t, (uint64_t)hndl->sb_len);

		rc = nsc_write(hndl, hndl->sb_pos, hndl->sb_len, 0);

		DTRACE_PROBE1(sv_dbg_write_end, sv_dev_t *, svp);

		if (rc > 0) {
			bioerror(bp, rc);
			goto done;
		}
	}

	/*
	 * Adjust FBA offset and requested (ie. remaining) length,
	 * loop if more data to transfer.
	 */

	fba_off += fba_len;
	fba_req -= fba_len;

	if (fba_req > 0) {
		DTRACE_PROBE1(sv_dbg_freeb_start, sv_dev_t *, svp);

		rc = nsc_free_buf(hndl);

		DTRACE_PROBE1(sv_dbg_freeb_end, sv_dev_t *, svp);

		if (rc > 0) {
			DTRACE_PROBE1(sv_lyr_strategy_err_free,
			    struct buf *, bp);
			bioerror(bp, rc);
		}

		hndl = NULL;

		if (rc <= 0)
			goto loop;
	}

done:
	if (hndl != NULL) {
		DTRACE_PROBE1(sv_dbg_freeb_start, sv_dev_t *, svp);

		rc = nsc_free_buf(hndl);

		DTRACE_PROBE1(sv_dbg_freeb_end, sv_dev_t *, svp);

		if (rc > 0) {
			DTRACE_PROBE1(sv_lyr_strategy_err_free,
			    struct buf *, bp);
			bioerror(bp, rc);
		}

		hndl = NULL;
	}

	if (bufh)
		(void) nsc_free_handle(bufh);

	DTRACE_PROBE1(sv_dbg_rlse_start, sv_dev_t *, svp);

	nsc_release(svp->sv_fd);

	DTRACE_PROBE1(sv_dbg_rlse_end, sv_dev_t *, svp);

out:
	if (sv_debug > 5) {
		cmn_err(CE_CONT,
		    "!_sv_lyr_strategy: bp %p, bufh %p, bp->b_error %d\n",
		    (void *)bp, (void *)bufh, bp->b_error);
	}

	DTRACE_PROBE2(sv_lyr_strategy_end, struct buf *, bp, int, bp->b_error);

	rw_exit(&svp->sv_lock);
	biodone(bp);
}


static void
sv_async_strategy(blind_t arg)
{
	struct buf *bp = (struct buf *)arg;
	_sv_lyr_strategy(bp);
}


static int
sv_lyr_strategy(struct buf *bp)
{
	nsthread_t *tp;
	int nlive;

	/*
	 * If B_ASYNC was part of the DDI we could use it as a hint to
	 * not create a thread for synchronous i/o.
	 */
	if (sv_dev_to_sv(bp->b_edev, NULL) == NULL) {
		/* not sv enabled - just pass through */
		DTRACE_PROBE1(sv_lyr_strategy_notsv, struct buf *, bp);
		_sv_lyr_strategy(bp);
		return (0);
	}

	if (sv_debug > 4) {
		cmn_err(CE_CONT, "!sv_lyr_strategy: nthread %d nlive %d\n",
		    nst_nthread(sv_tset), nst_nlive(sv_tset));
	}

	/*
	 * If there are only guard devices enabled there
	 * won't be a threadset, so don't try and use it.
	 */
	tp = NULL;
	if (sv_tset != NULL) {
		tp = nst_create(sv_tset, sv_async_strategy, (blind_t)bp, 0);
	}

	if (tp == NULL) {
		/*
		 * out of threads, so fall back to synchronous io.
		 */
		if (sv_debug > 0) {
			cmn_err(CE_CONT,
			    "!sv_lyr_strategy: thread alloc failed\n");
		}

		DTRACE_PROBE1(sv_lyr_strategy_no_thread,
		    struct buf *, bp);

		_sv_lyr_strategy(bp);
		sv_no_threads++;
	} else {
		nlive = nst_nlive(sv_tset);
		if (nlive > sv_max_nlive) {
			if (sv_debug > 0) {
				cmn_err(CE_CONT,
				    "!sv_lyr_strategy: "
				    "new max nlive %d (nthread %d)\n",
				    nlive, nst_nthread(sv_tset));
			}

			sv_max_nlive = nlive;
		}
	}

	return (0);
}

/*
 * re-write the size of the current partition
 */
static int
sv_fix_dkiocgvtoc(const intptr_t arg, const int mode, sv_dev_t *svp)
{
	size_t offset;
	int ilp32;
	int pnum;
	int rc;

	ilp32 = (ddi_model_convert_from((mode & FMODELS)) == DDI_MODEL_ILP32);

	rc = nskern_partition(svp->sv_dev, &pnum);
	if (rc != 0) {
		return (rc);
	}

	if (pnum < 0 || pnum >= V_NUMPAR) {
		cmn_err(CE_WARN,
		    "!sv_gvtoc: unable to determine partition number "
		    "for dev %lx", svp->sv_dev);
		return (EINVAL);
	}

	if (ilp32) {
		int32_t p_size;

#ifdef _SunOS_5_6
		offset = offsetof(struct vtoc, v_part);
		offset += sizeof (struct partition) * pnum;
		offset += offsetof(struct partition, p_size);
#else
		offset = offsetof(struct vtoc32, v_part);
		offset += sizeof (struct partition32) * pnum;
		offset += offsetof(struct partition32, p_size);
#endif

		p_size = (int32_t)svp->sv_nblocks;
		if (p_size == 0) {
			if (sv_reserve(svp->sv_fd,
			    NSC_MULTI|NSC_PCATCH) == 0) {
				p_size = (int32_t)svp->sv_nblocks;
				nsc_release(svp->sv_fd);
			} else {
				rc = EINTR;
			}
		}

		if ((rc == 0) && ddi_copyout(&p_size, (void *)(arg + offset),
		    sizeof (p_size), mode) != 0) {
			rc = EFAULT;
		}
	} else {
		long p_size;

		offset = offsetof(struct vtoc, v_part);
		offset += sizeof (struct partition) * pnum;
		offset += offsetof(struct partition, p_size);

		p_size = (long)svp->sv_nblocks;
		if (p_size == 0) {
			if (sv_reserve(svp->sv_fd,
			    NSC_MULTI|NSC_PCATCH) == 0) {
				p_size = (long)svp->sv_nblocks;
				nsc_release(svp->sv_fd);
			} else {
				rc = EINTR;
			}
		}

		if ((rc == 0) && ddi_copyout(&p_size, (void *)(arg + offset),
		    sizeof (p_size), mode) != 0) {
			rc = EFAULT;
		}
	}

	return (rc);
}


#ifdef DKIOCPARTITION
/*
 * re-write the size of the current partition
 *
 * arg is dk_efi_t.
 *
 * dk_efi_t->dki_data = (void *)(uintptr_t)efi.dki_data_64;
 *
 * dk_efi_t->dki_data --> efi_gpt_t (label header)
 * dk_efi_t->dki_data + 1 --> efi_gpe_t[] (array of partitions)
 *
 * efi_gpt_t->efi_gpt_PartitionEntryArrayCRC32 --> CRC32 of array of parts
 * efi_gpt_t->efi_gpt_HeaderCRC32 --> CRC32 of header itself
 *
 * This assumes that sizeof (efi_gpt_t) is the same as the size of a
 * logical block on the disk.
 *
 * Everything is little endian (i.e. disk format).
 */
static int
sv_fix_dkiocgetefi(const intptr_t arg, const int mode, sv_dev_t *svp)
{
	dk_efi_t efi;
	efi_gpt_t gpt;
	efi_gpe_t *gpe = NULL;
	size_t sgpe;
	uint64_t p_size;	/* virtual partition size from nsctl */
	uint32_t crc;
	int unparts;		/* number of parts in user's array */
	int pnum;
	int rc;

	rc = nskern_partition(svp->sv_dev, &pnum);
	if (rc != 0) {
		return (rc);
	}

	if (pnum < 0) {
		cmn_err(CE_WARN,
		    "!sv_efi: unable to determine partition number for dev %lx",
		    svp->sv_dev);
		return (EINVAL);
	}

	if (ddi_copyin((void *)arg, &efi, sizeof (efi), mode)) {
		return (EFAULT);
	}

	efi.dki_data = (void *)(uintptr_t)efi.dki_data_64;

	if (efi.dki_length < sizeof (gpt) + sizeof (gpe)) {
		return (EINVAL);
	}

	if (ddi_copyin((void *)efi.dki_data, &gpt, sizeof (gpt), mode)) {
		rc = EFAULT;
		goto out;
	}

	if ((unparts = LE_32(gpt.efi_gpt_NumberOfPartitionEntries)) == 0)
		unparts = 1;
	else if (pnum >= unparts) {
		cmn_err(CE_WARN,
		    "!sv_efi: partition# beyond end of user array (%d >= %d)",
		    pnum, unparts);
		return (EINVAL);
	}

	sgpe = sizeof (*gpe) * unparts;
	gpe = kmem_alloc(sgpe, KM_SLEEP);

	if (ddi_copyin((void *)(efi.dki_data + 1), gpe, sgpe, mode)) {
		rc = EFAULT;
		goto out;
	}

	p_size = svp->sv_nblocks;
	if (p_size == 0) {
		if (sv_reserve(svp->sv_fd, NSC_MULTI|NSC_PCATCH) == 0) {
			p_size = (diskaddr_t)svp->sv_nblocks;
			nsc_release(svp->sv_fd);
		} else {
			rc = EINTR;
		}
	}

	gpe[pnum].efi_gpe_EndingLBA = LE_64(
	    LE_64(gpe[pnum].efi_gpe_StartingLBA) + p_size - 1);

	gpt.efi_gpt_PartitionEntryArrayCRC32 = 0;
	CRC32(crc, gpe, sgpe, -1U, sv_crc32_table);
	gpt.efi_gpt_PartitionEntryArrayCRC32 = LE_32(~crc);

	gpt.efi_gpt_HeaderCRC32 = 0;
	CRC32(crc, &gpt, sizeof (gpt), -1U, sv_crc32_table);
	gpt.efi_gpt_HeaderCRC32 = LE_32(~crc);

	if ((rc == 0) && ddi_copyout(&gpt, efi.dki_data, sizeof (gpt), mode)) {
		rc = EFAULT;
		goto out;
	}

	if ((rc == 0) && ddi_copyout(gpe, efi.dki_data + 1, sgpe, mode)) {
		rc = EFAULT;
		goto out;
	}

out:
	if (gpe) {
		kmem_free(gpe, sgpe);
	}

	return (rc);
}


/*
 * Re-write the size of the partition specified by p_partno
 *
 * Note that if a DKIOCPARTITION is issued to an fd opened against a
 * non-sv'd device, but p_partno requests the size for a different
 * device that is sv'd, this function will *not* be called as sv is
 * not interposed on the original device (the fd).
 *
 * It would not be easy to change this as we cannot get the partition
 * number for the non-sv'd device, so cannot compute the dev_t of the
 * (sv'd) p_partno device, and so cannot find out if it is sv'd or get
 * its size from nsctl.
 *
 * See also the "Bug 4755783" comment in sv_lyr_ioctl().
 */
static int
sv_fix_dkiocpartition(const intptr_t arg, const int mode, sv_dev_t *svp)
{
	struct partition64 p64;
	sv_dev_t *nsvp = NULL;
	diskaddr_t p_size;
	minor_t nminor;
	int pnum, rc;
	dev_t ndev;

	rc = nskern_partition(svp->sv_dev, &pnum);
	if (rc != 0) {
		return (rc);
	}

	if (ddi_copyin((void *)arg, &p64, sizeof (p64), mode)) {
		return (EFAULT);
	}

	if (p64.p_partno != pnum) {
		/* switch to requested partition, not the current one */
		nminor = getminor(svp->sv_dev) + (p64.p_partno - pnum);
		ndev = makedevice(getmajor(svp->sv_dev), nminor);
		nsvp = sv_find_enabled(ndev, NULL);
		if (nsvp == NULL) {
			/* not sv device - just return */
			return (0);
		}

		svp = nsvp;
	}

	p_size = svp->sv_nblocks;
	if (p_size == 0) {
		if (sv_reserve(svp->sv_fd, NSC_MULTI|NSC_PCATCH) == 0) {
			p_size = (diskaddr_t)svp->sv_nblocks;
			nsc_release(svp->sv_fd);
		} else {
			rc = EINTR;
		}
	}

	if (nsvp != NULL) {
		rw_exit(&nsvp->sv_lock);
	}

	if ((rc == 0) && ddi_copyout(&p_size,
	    (void *)(arg + offsetof(struct partition64, p_size)),
	    sizeof (p_size), mode) != 0) {
		return (EFAULT);
	}

	return (rc);
}
#endif /* DKIOCPARTITION */


static int
sv_lyr_ioctl(const dev_t dev, const int cmd, const intptr_t arg,
    const int mode, cred_t *crp, int *rvalp)
{
	sv_dev_t *svp;
	sv_maj_t *maj;
	int (*fn)();
	int rc = 0;

	maj = 0;
	fn = 0;

	/*
	 * If sv_mod_status is 0 or SV_PREVENT_UNLOAD, then it will continue.
	 * else it means it previously was SV_PREVENT_UNLOAD, and now it's
	 * SV_ALLOW_UNLOAD, expecting the driver to eventually unload.
	 *
	 * SV_ALLOW_UNLOAD is final state, so no need to grab sv_mutex.
	 */
	if (sv_mod_status == SV_ALLOW_UNLOAD) {
		return (EBUSY);
	}

	svp = sv_find_enabled(dev, &maj);
	if (svp != NULL) {
		if (nskernd_isdaemon()) {
			/*
			 * This is nskernd which always needs to see
			 * the underlying disk device accurately.
			 *
			 * So just pass the ioctl straight through
			 * to the underlying driver as though the device
			 * was not sv enabled.
			 */
			DTRACE_PROBE2(sv_lyr_ioctl_nskernd, sv_dev_t *, svp,
			    dev_t, dev);

			rw_exit(&svp->sv_lock);
			svp = NULL;
		} else {
			ASSERT(RW_READ_HELD(&svp->sv_lock));
		}
	}

	/*
	 * We now have a locked and enabled SV device, or a non-SV device.
	 */

	switch (cmd) {
		/*
		 * DKIOCGVTOC, DKIOCSVTOC, DKIOCPARTITION, DKIOCGETEFI
		 * and DKIOCSETEFI are intercepted and faked up as some
		 * i/o providers emulate volumes of a different size to
		 * the underlying volume.
		 *
		 * Setting the size by rewriting the vtoc is not permitted.
		 */

	case DKIOCSVTOC:
#ifdef DKIOCPARTITION
	case DKIOCSETEFI:
#endif
		if (svp == NULL) {
			/* not intercepted -- allow ioctl through */
			break;
		}

		rw_exit(&svp->sv_lock);

		DTRACE_PROBE2(sv_lyr_ioctl_svtoc, dev_t, dev, int, EPERM);

		return (EPERM);

	default:
		break;
	}

	/*
	 * Pass through the real ioctl command.
	 */

	if (maj && (fn = maj->sm_ioctl) != 0) {
		if (!(maj->sm_flag & D_MP)) {
			UNSAFE_ENTER();
			rc = (*fn)(dev, cmd, arg, mode, crp, rvalp);
			UNSAFE_EXIT();
		} else {
			rc = (*fn)(dev, cmd, arg, mode, crp, rvalp);
		}
	} else {
		rc = ENODEV;
	}

	/*
	 * Bug 4755783
	 * Fix up the size of the current partition to allow
	 * for the virtual volume to be a different size to the
	 * physical volume (e.g. for II compact dependent shadows).
	 *
	 * Note that this only attempts to fix up the current partition
	 * - the one that the ioctl was issued against.  There could be
	 * other sv'd partitions in the same vtoc, but we cannot tell
	 * so we don't attempt to fix them up.
	 */

	if (svp != NULL && rc == 0) {
		switch (cmd) {
		case DKIOCGVTOC:
			rc = sv_fix_dkiocgvtoc(arg, mode, svp);
			break;

#ifdef DKIOCPARTITION
		case DKIOCGETEFI:
			rc = sv_fix_dkiocgetefi(arg, mode, svp);
			break;

		case DKIOCPARTITION:
			rc = sv_fix_dkiocpartition(arg, mode, svp);
			break;
#endif /* DKIOCPARTITION */
		}
	}

	if (svp != NULL) {
		rw_exit(&svp->sv_lock);
	}

	return (rc);
}
