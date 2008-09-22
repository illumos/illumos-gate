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
 * IOSRAM leaf driver to SBBC nexus driver.  This driver is used
 * by Starcat Domain SW to read/write from/to the IO sram.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>		/* req. by dev_ops flags MTSAFE etc. */
#include <sys/modctl.h>		/* for modldrv */
#include <sys/stat.h>		/* ddi_create_minor_node S_IFCHR */
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/debug.h>

#include <sys/axq.h>
#include <sys/iosramreg.h>
#include <sys/iosramio.h>
#include <sys/iosramvar.h>


#if defined(DEBUG)
int	iosram_debug = 0;
static void iosram_dprintf(const char *fmt, ...);
#define	DPRINTF(level, arg)	\
		{ if (iosram_debug >= level) iosram_dprintf arg; }
#else	/* !DEBUG */
#define	DPRINTF(level, arg)
#endif	/* !DEBUG */


/*
 * IOSRAM module global state
 */
static void	*iosramsoft_statep;	/* IOSRAM state pointer */
static kmutex_t	iosram_mutex;		/* mutex lock */

static iosram_chunk_t	*chunks = NULL;	/* array of TOC entries */
static int	nchunks = 0;		/* # of TOC entries */
static iosram_chunk_t	*iosram_hashtab[IOSRAM_HASHSZ];	/* key hash table */

static kcondvar_t	iosram_tswitch_wait;	/* tunnel switch wait cv */
static int	iosram_tswitch_wakeup = 0;	/* flag indicationg one or */
						/* more threads waiting on */
						/* iosram_tswitch_wait cv */
static int	iosram_tswitch_active = 0;	/* tunnel switch active flag */
static int	iosram_tswitch_aborted = 0;	/* tunnel switch abort flag */
static clock_t	iosram_tswitch_tstamp = 0;	/* lbolt of last tswitch end */
static kcondvar_t	iosram_rw_wait;		/* read/write wait cv */
static int	iosram_rw_wakeup = 0;		/* flag indicationg one or */
						/* more threads waiting on */
						/* iosram_rw_wait cv */
static int	iosram_rw_active = 0;		/* # threads accessing IOSRAM */
#if defined(DEBUG)
static int	iosram_rw_active_max = 0;
#endif

static struct iosramsoft *iosram_new_master = NULL;	/* new tunnel target */
static struct iosramsoft *iosram_master = NULL;		/* master tunnel */
static struct iosramsoft *iosram_instances = NULL;	/* list of softstates */

static ddi_acc_handle_t	iosram_handle = NULL;	/* master IOSRAM map handle */

static void	(*iosram_hdrchange_handler)() = NULL;

#if IOSRAM_STATS
static struct	iosram_stat iosram_stats;	/* IOSRAM statistics */
static void	iosram_print_stats();		/* forward declaration */
#endif /* IOSRAM_STATS */


#if IOSRAM_LOG
kmutex_t 	iosram_log_mutex;
int		iosram_log_level = 1;
int		iosram_log_print = 0;		/* print log when recorded */
uint32_t	iosram_logseq;
iosram_log_t	iosram_logbuf[IOSRAM_MAXLOG];
static void	iosram_print_log(int cnt);	/* forward declaration */
#endif	/* IOSRAM_LOG */


/* driver entry point fn definitions */
static int 	iosram_open(dev_t *, int, int, cred_t *);
static int	iosram_close(dev_t, int, int, cred_t *);
static int	iosram_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/* configuration entry point fn definitions */
static int 	iosram_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	iosram_attach(dev_info_t *, ddi_attach_cmd_t);
static int	iosram_detach(dev_info_t *, ddi_detach_cmd_t);


/* forward declaractions */
static iosram_chunk_t	*iosram_find_chunk(uint32_t key);
static void	iosram_set_master(struct iosramsoft *softp);
static int	iosram_is_chosen(struct iosramsoft *softp);
static int	iosram_tunnel_capable(struct iosramsoft *softp);
static int	iosram_read_toc(struct iosramsoft *softp);
static void	iosram_init_hashtab(void);
static void	iosram_update_addrs(struct iosramsoft *softp);

static int	iosram_setup_map(struct iosramsoft *softp);
static void	iosram_remove_map(struct iosramsoft *softp);
static int	iosram_add_intr(iosramsoft_t *);
static int	iosram_remove_intr(iosramsoft_t *);

static void	iosram_add_instance(struct iosramsoft *softp);
static void	iosram_remove_instance(int instance);
static int	iosram_switch_tunnel(iosramsoft_t *softp);
static void	iosram_abort_tswitch();

#if defined(DEBUG)
/* forward declaractions for debugging */
static int	iosram_get_keys(iosram_toc_entry_t *buf, uint32_t *len);
static void	iosram_print_cback();
static void	iosram_print_state(int);
static void	iosram_print_flags();
#endif



/*
 * cb_ops
 */
static struct cb_ops iosram_cb_ops = {
	iosram_open,		/* cb_open */
	iosram_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	iosram_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	(int)(D_NEW | D_MP | D_HOTPLUG)	/* cb_flag */
};

/*
 * Declare ops vectors for auto configuration.
 */
struct dev_ops  iosram_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	iosram_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	iosram_attach,		/* devo_attach */
	iosram_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&iosram_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	nulldev,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Loadable module support.
 */
extern struct mod_ops mod_driverops;

static struct modldrv iosrammodldrv = {
	&mod_driverops,		/* type of module - driver */
	"IOSRAM Leaf driver",
	&iosram_ops,
};

static struct modlinkage iosrammodlinkage = {
	MODREV_1,
	&iosrammodldrv,
	NULL
};


int
_init(void)
{
	int    error;
	int	i;

	mutex_init(&iosram_mutex, NULL, MUTEX_DRIVER, (void *)NULL);
	cv_init(&iosram_tswitch_wait, NULL, CV_DRIVER, NULL);
	cv_init(&iosram_rw_wait, NULL, CV_DRIVER, NULL);
#if defined(IOSRAM_LOG)
	mutex_init(&iosram_log_mutex, NULL, MUTEX_DRIVER, (void *)NULL);
#endif

	DPRINTF(1, ("_init:IOSRAM\n"));

	for (i = 0; i < IOSRAM_HASHSZ; i++) {
		iosram_hashtab[i] = NULL;
	}

	if ((error = ddi_soft_state_init(&iosramsoft_statep,
	    sizeof (struct iosramsoft), 1)) != 0) {
		goto failed;
	}
	if ((error = mod_install(&iosrammodlinkage)) != 0) {
		ddi_soft_state_fini(&iosramsoft_statep);
		goto failed;
	}

	IOSRAMLOG(0, "_init:IOSRAM ... error:%d  statep:%p\n",
	    error, iosramsoft_statep, NULL, NULL);

	return (error);

failed:
	cv_destroy(&iosram_tswitch_wait);
	cv_destroy(&iosram_rw_wait);
	mutex_destroy(&iosram_mutex);
#if defined(IOSRAM_LOG)
	mutex_destroy(&iosram_log_mutex);
#endif
	IOSRAMLOG(0, "_init:IOSRAM ... error:%d  statep:%p\n",
	    error, iosramsoft_statep, NULL, NULL);

	return (error);
}


int
_fini(void)
{
#ifndef DEBUG
	return (EBUSY);
#else /* !DEBUG */
	int    error;

	if ((error = mod_remove(&iosrammodlinkage)) == 0) {
		ddi_soft_state_fini(&iosramsoft_statep);

		cv_destroy(&iosram_tswitch_wait);
		cv_destroy(&iosram_rw_wait);
		mutex_destroy(&iosram_mutex);
#if defined(IOSRAM_LOG)
		mutex_destroy(&iosram_log_mutex);
#endif
	}
	DPRINTF(1, ("_fini:IOSRAM  error:%d\n", error));

	return (error);
#endif /* !DEBUG */
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&iosrammodlinkage, modinfop));
}


static int
iosram_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	instance;
	int	propval;
	int	length;
	char	name[32];
	struct	iosramsoft *softp;

	instance = ddi_get_instance(dip);

	DPRINTF(1, ("iosram(%d): attach dip:%p\n", instance));

	IOSRAMLOG(1, "ATTACH: dip:%p instance %d ... start\n",
	    dip, instance, NULL, NULL);
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		if (!(softp = ddi_get_soft_state(iosramsoft_statep,
		    instance))) {
			return (DDI_FAILURE);
		}
		mutex_enter(&iosram_mutex);
		mutex_enter(&softp->intr_mutex);
		if (!softp->suspended) {
			mutex_exit(&softp->intr_mutex);
			mutex_exit(&iosram_mutex);
			return (DDI_FAILURE);
		}
		softp->suspended = 0;

		/*
		 * enable SBBC interrupts if SBBC is mapped in
		 * restore the value saved during detach
		 */
		if (softp->sbbc_region) {
			ddi_put32(softp->sbbc_handle,
			    &(softp->sbbc_region->int_enable.reg),
			    softp->int_enable_sav);
		}

		/*
		 * Trigger soft interrupt handler to process any pending
		 * interrupts.
		 */
		if (softp->intr_pending && !softp->intr_busy &&
		    (softp->softintr_id != NULL)) {
			ddi_trigger_softintr(softp->softintr_id);
		}

		mutex_exit(&softp->intr_mutex);
		mutex_exit(&iosram_mutex);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(iosramsoft_statep, instance) != 0) {
		return (DDI_FAILURE);
	}

	if ((softp = ddi_get_soft_state(iosramsoft_statep, instance)) == NULL) {
			return (DDI_FAILURE);
	}
	softp->dip = dip;
	softp->instance = instance;
	softp->sbbc_region = NULL;

	/*
	 * If this instance is not tunnel capable, we don't attach it.
	 */
	if (iosram_tunnel_capable(softp) == 0) {
		DPRINTF(1, ("iosram(%d): not tunnel_capable\n", instance));
		IOSRAMLOG(1, "ATTACH(%d): not tunnel_capable\n", instance, NULL,
		    NULL, NULL);
		goto attach_fail;
	}

	/*
	 * Need to create an "interrupt-priorities" property to define the PIL
	 * to be used with the interrupt service routine.
	 */
	if (ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupt-priorities", &length) == DDI_PROP_NOT_FOUND) {
		DPRINTF(1, ("iosram(%d): creating interrupt priority property",
		    instance));
		propval = IOSRAM_PIL;
		if (ddi_prop_create(DDI_DEV_T_NONE, dip, 0,
		    "interrupt-priorities", (caddr_t)&propval, sizeof (propval))
		    != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN,
			    "iosram_attach: failed to create property");
			goto attach_fail;
		}
	}

	/*
	 * Get interrupts cookies and initialize per-instance mutexes
	 */
	if (ddi_get_iblock_cookie(softp->dip, 0, &softp->real_iblk)
	    != DDI_SUCCESS) {
		IOSRAMLOG(1, "ATTACH(%d): cannot get soft intr cookie\n",
		    instance, NULL, NULL, NULL);
		goto attach_fail;
	}
	mutex_init(&softp->intr_mutex, NULL, MUTEX_DRIVER,
	    (void *)softp->real_iblk);

	/*
	 * Add this instance to the iosram_instances list so that it can be used
	 * for tunnel in future.
	 */
	mutex_enter(&iosram_mutex);
	softp->state = IOSRAM_STATE_INIT;
	iosram_add_instance(softp);

	/*
	 * If this is the chosen IOSRAM and there is no master IOSRAM yet, then
	 * let's set this instance as the master.
	 */
	if (iosram_master == NULL && iosram_is_chosen(softp)) {
		iosram_switch_tunnel(softp);

		/*
		 * XXX Do we need to panic if unable to setup master IOSRAM?
		 */
		if (iosram_master == NULL) {
			cmn_err(CE_WARN,
			    "iosram(%d): can't setup master tunnel\n",
			    instance);
			softp->state = 0;
			iosram_remove_instance(softp->instance);
			mutex_exit(&iosram_mutex);
			mutex_destroy(&softp->intr_mutex);
			goto attach_fail;
		}
	}

	mutex_exit(&iosram_mutex);

	/*
	 * Create minor node
	 */
	(void) sprintf(name, "iosram%d", instance);
	if (ddi_create_minor_node(dip, name, S_IFCHR, instance, NULL, NULL) ==
	    DDI_FAILURE) {
		/*
		 * Minor node seems to be needed only for debugging purposes.
		 * Therefore, there is no need to fail this attach request.
		 * Simply print a message out.
		 */
		cmn_err(CE_NOTE, "!iosram(%d): can't create minor node\n",
		    instance);
	}
	ddi_report_dev(dip);

	DPRINTF(1, ("iosram_attach(%d): success.\n", instance));
	IOSRAMLOG(1, "ATTACH: dip:%p instance:%d ... success  softp:%p\n",
	    dip, instance, softp, NULL);

	return (DDI_SUCCESS);

attach_fail:
	DPRINTF(1, ("iosram_attach(%d):failed.\n", instance));
	IOSRAMLOG(1, "ATTACH: dip:%p instance:%d ... failed.\n",
	    dip, instance, NULL, NULL);

	ddi_soft_state_free(iosramsoft_statep, instance);
	return (DDI_FAILURE);
}


static int
iosram_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			instance;
	struct iosramsoft	*softp;

	instance = ddi_get_instance(dip);
	if (!(softp = ddi_get_soft_state(iosramsoft_statep, instance))) {
		return (DDI_FAILURE);
	}

	IOSRAMLOG(1, "DETACH: dip:%p instance %d softp:%p\n",
	    dip, instance, softp, NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		mutex_enter(&iosram_mutex);
		mutex_enter(&softp->intr_mutex);
		if (softp->suspended) {
			mutex_exit(&softp->intr_mutex);
			mutex_exit(&iosram_mutex);
			return (DDI_FAILURE);
		}
		softp->suspended = 1;
		/*
		 * Disable SBBC interrupts if SBBC is mapped in
		 */
		if (softp->sbbc_region) {
			/* save current interrupt enable register */
			softp->int_enable_sav = ddi_get32(softp->sbbc_handle,
			    &(softp->sbbc_region->int_enable.reg));
			ddi_put32(softp->sbbc_handle,
			    &(softp->sbbc_region->int_enable.reg), 0x0);
		}
		mutex_exit(&softp->intr_mutex);
		mutex_exit(&iosram_mutex);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}


	/*
	 * Indicate that this instance is being detached so that this instance
	 * does not become a target for tunnel switch in future.
	 */
	mutex_enter(&iosram_mutex);
	softp->state |= IOSRAM_STATE_DETACH;

	/*
	 * If this instance is currently the master or the target of the tunnel
	 * switch, then we need to wait and switch tunnel, if necessary.
	 */
	if (iosram_master == softp || (softp->state & IOSRAM_STATE_TSWITCH)) {
		mutex_exit(&iosram_mutex);
		iosram_switchfrom(instance);
		mutex_enter(&iosram_mutex);
	}

	/*
	 * If the tunnel switch is in progress and we are the master or target
	 * of tunnel relocation, then we can't detach this instance right now.
	 */
	if (softp->state & IOSRAM_STATE_TSWITCH) {
		softp->state &= ~IOSRAM_STATE_DETACH;
		mutex_exit(&iosram_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * We can't allow master IOSRAM to be detached as we won't be able to
	 * communicate otherwise.
	 */
	if (iosram_master == softp) {
		softp->state &= ~IOSRAM_STATE_DETACH;
		mutex_exit(&iosram_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * Now remove our instance from the iosram_instances list.
	 */
	iosram_remove_instance(instance);
	mutex_exit(&iosram_mutex);

	/*
	 * Instances should only ever be mapped if they are the master and/or
	 * participating in a tunnel switch.  Neither should be the case here.
	 */
	ASSERT((softp->state & IOSRAM_STATE_MAPPED) == 0);

	/*
	 * Destroy per-instance mutexes
	 */
	mutex_destroy(&softp->intr_mutex);

	ddi_remove_minor_node(dip, NULL);

	/*
	 * Finally remove our soft state structure
	 */
	ddi_soft_state_free(iosramsoft_statep, instance);

	return (DDI_SUCCESS);
}


/* ARGSUSED0 */
static int
iosram_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result)
{
	dev_t			dev = (dev_t)arg;
	struct iosramsoft	*softp;
	int			instance, ret;

	instance = getminor(dev);

	IOSRAMLOG(2, "GETINFO: dip:%x instance %d dev:%x infocmd:%x\n",
	    dip, instance, dev, infocmd);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			softp = ddi_get_soft_state(iosramsoft_statep, instance);
			if (softp == NULL) {
				*result = NULL;
				ret = DDI_FAILURE;
			} else {
				*result = softp->dip;
				ret = DDI_SUCCESS;
			}
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(uintptr_t)instance;
			ret = DDI_SUCCESS;
			break;
		default:
			ret = DDI_FAILURE;
			break;
	}

	return (ret);
}


/*ARGSUSED1*/
static int
iosram_open(dev_t *dev, int flag, int otype, cred_t *credp)
{
	struct iosramsoft	*softp;
	int			instance;

	instance = getminor(*dev);
	softp = ddi_get_soft_state(iosramsoft_statep, instance);

	if (softp == NULL) {
		return (ENXIO);
	}

	IOSRAMLOG(1, "OPEN: dev:%p otype:%x ... instance:%d softp:%p\n",
	    *dev, otype, softp->instance, softp);

	return (0);
}


/*ARGSUSED1*/
static int
iosram_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	struct iosramsoft	*softp;
	int			instance;

	instance = getminor(dev);
	softp = ddi_get_soft_state(iosramsoft_statep, instance);
	if (softp == NULL) {
		return (ENXIO);
	}

	IOSRAMLOG(1, "CLOSE: dev:%p otype:%x ... instance:%d softp:%p\n",
	    dev, otype, softp->instance, softp);

	return (0);
}


int
iosram_rd(uint32_t key, uint32_t off, uint32_t len, caddr_t dptr)
{
	iosram_chunk_t		*chunkp;
	uint32_t		chunk_len;
	uint8_t			*iosramp;
	ddi_acc_handle_t	handle;
	int			boff;
	union {
		uchar_t	cbuf[UINT32SZ];
		uint32_t  data;
	} word;

	int			error = 0;
	uint8_t			*buf = (uint8_t *)dptr;

	/*
	 * We try to read from the IOSRAM using double word or word access
	 * provided both "off" and "buf" are (or can be) double word or word
	 * aligned.  Othewise, we try to align the "off" to a word boundary and
	 * then try to read data from the IOSRAM using word access, but store it
	 * into buf buffer using byte access.
	 *
	 * If the leading/trailing portion of the IOSRAM data is not word
	 * aligned, it will always be copied using byte access.
	 */
	IOSRAMLOG(1, "RD: key: 0x%x off:%x len:%x buf:%p\n",
	    key, off, len, buf);

	/*
	 * Acquire lock and look for the requested chunk.  If it exists, make
	 * sure the requested read is within the chunk's bounds and no tunnel
	 * switch is active.
	 */
	mutex_enter(&iosram_mutex);
	chunkp = iosram_find_chunk(key);
	chunk_len = (chunkp != NULL) ? chunkp->toc_data.len : 0;

	if (iosram_master == NULL) {
		error = EIO;
	} else if (chunkp == NULL) {
		error = EINVAL;
	} else if ((off >= chunk_len) || (len > chunk_len) ||
	    ((off + len) > chunk_len)) {
		error = EMSGSIZE;
	} else if (iosram_tswitch_active) {
		error = EAGAIN;
	}

	if (error) {
		mutex_exit(&iosram_mutex);
		return (error);
	}

	/*
	 * Bump reference count to indicate #thread accessing IOSRAM and release
	 * the lock.
	 */
	iosram_rw_active++;
#if defined(DEBUG)
	if (iosram_rw_active > iosram_rw_active_max) {
		iosram_rw_active_max = iosram_rw_active;
	}
#endif
	mutex_exit(&iosram_mutex);

	IOSRAM_STAT(read);
	IOSRAM_STAT_ADD(bread, len);

	/* Get starting address and map handle */
	iosramp = chunkp->basep + off;
	handle = iosram_handle;

	/*
	 * Align the off to word boundary and then try reading/writing data
	 * using double word or word access.
	 */
	if ((boff = ((uintptr_t)iosramp & (UINT32SZ - 1))) != 0) {
		int	cnt = UINT32SZ - boff;

		if (cnt > len) {
			cnt = len;
		}
		IOSRAMLOG(2,
		    "RD: align rep_get8(buf:%p sramp:%p cnt:%x) len:%x\n",
		    buf, iosramp, cnt, len);
		ddi_rep_get8(handle, buf, iosramp, cnt, DDI_DEV_AUTOINCR);
		buf += cnt;
		iosramp += cnt;
		len -= cnt;
	}

	if ((len >= UINT64SZ) &&
	    ((((uintptr_t)iosramp | (uintptr_t)buf) & (UINT64SZ - 1)) == 0)) {
		/*
		 * Both source and destination are double word aligned
		 */
		int cnt = len/UINT64SZ;

		IOSRAMLOG(2,
		    "RD: rep_get64(buf:%p sramp:%p cnt:%x) len:%x\n",
		    buf, iosramp, cnt, len);
		ddi_rep_get64(handle, (uint64_t *)buf, (uint64_t *)iosramp,
		    cnt, DDI_DEV_AUTOINCR);
		iosramp += cnt * UINT64SZ;
		buf += cnt * UINT64SZ;
		len -= cnt * UINT64SZ;

		/*
		 * read remaining data using word and byte access
		 */
		if (len >= UINT32SZ) {
			IOSRAMLOG(2,
			    "RD: get32(buf:%p sramp:%p) len:%x\n",
			    buf, iosramp, len, NULL);
			*(uint32_t *)buf = ddi_get32(handle,
			    (uint32_t *)iosramp);
			iosramp += UINT32SZ;
			buf += UINT32SZ;
			len -= UINT32SZ;
		}

		if (len != 0) {
			ddi_rep_get8(handle, buf, iosramp, len,
			    DDI_DEV_AUTOINCR);
		}
	} else if ((len >= UINT32SZ) &&
	    ((((uintptr_t)iosramp | (uintptr_t)buf) & (UINT32SZ - 1)) == 0)) {
		/*
		 * Both source and destination are word aligned
		 */
		int cnt = len/UINT32SZ;

		IOSRAMLOG(2,
		    "RD: rep_get32(buf:%p sramp:%p cnt:%x) len:%x\n",
		    buf, iosramp, cnt, len);
		ddi_rep_get32(handle, (uint32_t *)buf, (uint32_t *)iosramp,
		    cnt, DDI_DEV_AUTOINCR);
		iosramp += cnt * UINT32SZ;
		buf += cnt * UINT32SZ;
		len -= cnt * UINT32SZ;

		/*
		 * copy the remainder using byte access
		 */
		if (len != 0) {
			ddi_rep_get8(handle, buf, iosramp, len,
			    DDI_DEV_AUTOINCR);
		}
	} else if (len != 0) {
		/*
		 * We know that the "off" (i.e. iosramp) is at least word
		 * aligned. We need to read IOSRAM word at a time and copy it
		 * byte at a time.
		 */
		ASSERT(((uintptr_t)iosramp & (UINT32SZ - 1)) == 0);

		IOSRAMLOG(2,
		    "RD: unaligned get32(buf:%p sramp:%p) len:%x\n",
		    buf, iosramp, len, NULL);
		for (; len >= UINT32SZ; len -= UINT32SZ, iosramp += UINT32SZ) {
			word.data =  ddi_get32(handle, (uint32_t *)iosramp);
			*buf++ = word.cbuf[0];
			*buf++ = word.cbuf[1];
			*buf++ = word.cbuf[2];
			*buf++ = word.cbuf[3];
		}

		/*
		 * copy the remaining data using byte access
		 */
		if (len != 0) {
			ddi_rep_get8(handle, buf, iosramp, len,
			    DDI_DEV_AUTOINCR);
		}
	}

	/*
	 * Reacquire mutex lock, decrement refcnt and if refcnt is 0 and any
	 * threads are waiting for r/w activity to complete, wake them up.
	 */
	mutex_enter(&iosram_mutex);
	ASSERT(iosram_rw_active > 0);

	if ((--iosram_rw_active == 0) && iosram_rw_wakeup) {
		iosram_rw_wakeup = 0;
		cv_broadcast(&iosram_rw_wait);
	}
	mutex_exit(&iosram_mutex);

	return (error);
}


/*
 * _iosram_write(key, off, len, dptr, force)
 *	Internal common routine to write to the IOSRAM.
 */
static int
_iosram_write(uint32_t key, uint32_t off, uint32_t len, caddr_t dptr, int force)
{
	iosram_chunk_t		*chunkp;
	uint32_t		chunk_len;
	uint8_t			*iosramp;
	ddi_acc_handle_t	handle;
	int			boff;
	union {
		uint8_t	cbuf[UINT32SZ];
		uint32_t data;
	} word;

	int			error = 0;
	uint8_t			*buf = (uint8_t *)dptr;

	/*
	 * We try to write to the IOSRAM using double word or word access
	 * provided both "off" and "buf" are (or can be) double word or word
	 * aligned.  Othewise, we try to align the "off" to a word boundary and
	 * then try to write data to the IOSRAM using word access, but read data
	 * from the buf buffer using byte access.
	 *
	 * If the leading/trailing portion of the IOSRAM data is not word
	 * aligned, it will always be written using byte access.
	 */
	IOSRAMLOG(1, "WR: key: 0x%x off:%x len:%x buf:%p\n",
	    key, off, len, buf);

	/*
	 * Acquire lock and look for the requested chunk.  If it exists, make
	 * sure the requested write is within the chunk's bounds and no tunnel
	 * switch is active.
	 */
	mutex_enter(&iosram_mutex);
	chunkp = iosram_find_chunk(key);
	chunk_len = (chunkp != NULL) ? chunkp->toc_data.len : 0;

	if (iosram_master == NULL) {
		error = EIO;
	} else if (chunkp == NULL) {
		error = EINVAL;
	} else if ((off >= chunk_len) || (len > chunk_len) ||
	    ((off+len) > chunk_len)) {
		error = EMSGSIZE;
	} else if (iosram_tswitch_active && !force) {
		error = EAGAIN;
	}

	if (error) {
		mutex_exit(&iosram_mutex);
		return (error);
	}

	/*
	 * If this is a forced write and there's a tunnel switch in progress,
	 * abort the switch.
	 */
	if (iosram_tswitch_active && force) {
		cmn_err(CE_NOTE, "!iosram: Aborting tswitch on force_write");
		iosram_abort_tswitch();
	}

	/*
	 * Bump reference count to indicate #thread accessing IOSRAM
	 * and release the lock.
	 */
	iosram_rw_active++;
#if defined(DEBUG)
	if (iosram_rw_active > iosram_rw_active_max) {
		iosram_rw_active_max = iosram_rw_active;
	}
#endif
	mutex_exit(&iosram_mutex);


	IOSRAM_STAT(write);
	IOSRAM_STAT_ADD(bwrite, len);

	/* Get starting address and map handle */
	iosramp = chunkp->basep + off;
	handle = iosram_handle;

	/*
	 * Align the off to word boundary and then try reading/writing
	 * data using double word or word access.
	 */
	if ((boff = ((uintptr_t)iosramp & (UINT32SZ - 1))) != 0) {
		int	cnt = UINT32SZ - boff;

		if (cnt > len) {
			cnt = len;
		}
		IOSRAMLOG(2,
		    "WR: align rep_put8(buf:%p sramp:%p cnt:%x) len:%x\n",
		    buf, iosramp, cnt, len);
		ddi_rep_put8(handle, buf, iosramp, cnt, DDI_DEV_AUTOINCR);
		buf += cnt;
		iosramp += cnt;
		len -= cnt;
	}

	if ((len >= UINT64SZ) &&
	    ((((uintptr_t)iosramp | (uintptr_t)buf) & (UINT64SZ - 1)) == 0)) {
		/*
		 * Both source and destination are double word aligned
		 */
		int cnt = len/UINT64SZ;

		IOSRAMLOG(2,
		    "WR: rep_put64(buf:%p sramp:%p cnt:%x) len:%x\n",
		    buf, iosramp, cnt, len);
		ddi_rep_put64(handle, (uint64_t *)buf, (uint64_t *)iosramp,
		    cnt, DDI_DEV_AUTOINCR);
		iosramp += cnt * UINT64SZ;
		buf += cnt * UINT64SZ;
		len -= cnt * UINT64SZ;

		/*
		 * Copy the remaining data using word & byte access
		 */
		if (len >= UINT32SZ) {
			IOSRAMLOG(2,
			    "WR: put32(buf:%p sramp:%p) len:%x\n", buf, iosramp,
			    len, NULL);
			ddi_put32(handle, (uint32_t *)iosramp,
			    *(uint32_t *)buf);
			iosramp += UINT32SZ;
			buf += UINT32SZ;
			len -= UINT32SZ;
		}

		if (len != 0) {
			ddi_rep_put8(handle, buf, iosramp, len,
			    DDI_DEV_AUTOINCR);
		}
	} else if ((len >= UINT32SZ) &&
	    ((((uintptr_t)iosramp | (uintptr_t)buf) & (UINT32SZ - 1)) == 0)) {
		/*
		 * Both source and destination are word aligned
		 */
		int cnt = len/UINT32SZ;

		IOSRAMLOG(2,
		    "WR: rep_put32(buf:%p sramp:%p cnt:%x) len:%x\n",
		    buf, iosramp, cnt, len);
		ddi_rep_put32(handle, (uint32_t *)buf, (uint32_t *)iosramp,
		    cnt, DDI_DEV_AUTOINCR);
		iosramp += cnt * UINT32SZ;
		buf += cnt * UINT32SZ;
		len -= cnt * UINT32SZ;

		/*
		 * copy the remainder using byte access
		 */
		if (len != 0) {
			ddi_rep_put8(handle, buf, iosramp, len,
			    DDI_DEV_AUTOINCR);
		}
	} else if (len != 0) {
		/*
		 * We know that the "off" is at least word aligned. We
		 * need to read data from buf buffer byte at a time, and
		 * write it to the IOSRAM word at a time.
		 */

		ASSERT(((uintptr_t)iosramp & (UINT32SZ - 1)) == 0);

		IOSRAMLOG(2,
		    "WR: unaligned put32(buf:%p sramp:%p) len:%x\n",
		    buf, iosramp, len, NULL);
		for (; len >= UINT32SZ; len -= UINT32SZ, iosramp += UINT32SZ) {
			word.cbuf[0] = *buf++;
			word.cbuf[1] = *buf++;
			word.cbuf[2] = *buf++;
			word.cbuf[3] = *buf++;
			ddi_put32(handle, (uint32_t *)iosramp, word.data);
		}

		/*
		 * copy the remaining data using byte access
		 */
		if (len != 0) {
			ddi_rep_put8(handle, buf, iosramp,
			    len, DDI_DEV_AUTOINCR);
		}
	}

	/*
	 * Reacquire mutex lock, decrement refcnt and if refcnt is 0 and
	 * any threads are waiting for r/w activity to complete, wake them up.
	 */
	mutex_enter(&iosram_mutex);
	ASSERT(iosram_rw_active > 0);

	if ((--iosram_rw_active == 0) && iosram_rw_wakeup) {
		iosram_rw_wakeup = 0;
		cv_broadcast(&iosram_rw_wait);
	}
	mutex_exit(&iosram_mutex);

	return (error);
}


int
iosram_force_write(uint32_t key, uint32_t off, uint32_t len, caddr_t dptr)
{
	return (_iosram_write(key, off, len, dptr, 1 /* force */));
}


int
iosram_wr(uint32_t key, uint32_t off, uint32_t len, caddr_t dptr)
{
	return (_iosram_write(key, off, len, dptr, 0));
}


/*
 * iosram_register(key, handler, arg)
 *	Register a handler and an arg for the specified chunk.  This handler
 *	will be invoked when an interrupt is received from the other side and
 *	the int_pending flag for the corresponding key is marked
 *	IOSRAM_INT_TO_DOM.
 */
/* ARGSUSED */
int
iosram_register(uint32_t key, void (*handler)(), void *arg)
{
	struct iosram_chunk	*chunkp;
	int			error = 0;

	/*
	 * Acquire lock and look for the requested chunk.  If it exists, and no
	 * other callback is registered, proceed with the registration.
	 */
	mutex_enter(&iosram_mutex);
	chunkp = iosram_find_chunk(key);

	if (iosram_master == NULL) {
		error = EIO;
	} else if (chunkp == NULL) {
		error = EINVAL;
	} else if (chunkp->cback.handler != NULL) {
		error = EBUSY;
	} else {
		chunkp->cback.busy = 0;
		chunkp->cback.unregister = 0;
		chunkp->cback.handler = handler;
		chunkp->cback.arg = arg;
	}
	mutex_exit(&iosram_mutex);

	IOSRAMLOG(1, "REG: key: 0x%x hdlr:%p arg:%p error:%d\n",
	    key, handler, arg, error);

	return (error);
}


/*
 * iosram_unregister()
 *	Unregister handler associated with the specified chunk.
 */
int
iosram_unregister(uint32_t key)
{
	struct iosram_chunk	*chunkp;
	int			error = 0;

	/*
	 * Acquire lock and look for the requested chunk.  If it exists and has
	 * a callback registered, unregister it.
	 */
	mutex_enter(&iosram_mutex);
	chunkp = iosram_find_chunk(key);

	if (iosram_master == NULL) {
		error = EIO;
	} else if (chunkp == NULL) {
		error = EINVAL;
	} else if (chunkp->cback.busy) {
		/*
		 * If the handler is already busy (being invoked), then we flag
		 * it so it will be unregistered after the invocation completes.
		 */
		DPRINTF(1, ("IOSRAM(%d): unregister: delaying unreg k:0x%08x\n",
		    iosram_master->instance, key));
		chunkp->cback.unregister = 1;
	} else if (chunkp->cback.handler != NULL) {
		chunkp->cback.handler = NULL;
		chunkp->cback.arg = NULL;
	}
	mutex_exit(&iosram_mutex);

	IOSRAMLOG(1, "UNREG: key:%x error:%d\n", key, error, NULL, NULL);
	return (error);
}


/*
 * iosram_get_flag():
 *	Get data_valid and/or int_pending flags associated with the
 *	specified key.
 */
int
iosram_get_flag(uint32_t key, uint8_t *data_valid, uint8_t *int_pending)
{
	iosram_chunk_t	*chunkp;
	iosram_flags_t	flags;
	int		error = 0;

	/*
	 * Acquire lock and look for the requested chunk.  If it exists, and no
	 * tunnel switch is in progress, read the chunk's flags.
	 */
	mutex_enter(&iosram_mutex);
	chunkp = iosram_find_chunk(key);

	if (iosram_master == NULL) {
		error = EIO;
	} else if (chunkp == NULL) {
		error = EINVAL;
	} else if (iosram_tswitch_active) {
		error = EAGAIN;
	} else {
		IOSRAM_STAT(getflag);

		/*
		 * Read the flags
		 */
		ddi_rep_get8(iosram_handle, (uint8_t *)&flags,
		    (uint8_t *)(chunkp->flagsp), sizeof (iosram_flags_t),
		    DDI_DEV_AUTOINCR);

		/*
		 * Get each flag value that the caller is interested in.
		 */
		if (data_valid != NULL) {
			*data_valid = flags.data_valid;
		}

		if (int_pending != NULL) {
			*int_pending = flags.int_pending;
		}
	}
	mutex_exit(&iosram_mutex);

	IOSRAMLOG(1, "GetFlag key:%x data_valid:%x int_pending:%x error:%d\n",
	    key, flags.data_valid, flags.int_pending, error);
	return (error);
}


/*
 * iosram_set_flag():
 *	Set data_valid and int_pending flags associated with the specified key.
 */
int
iosram_set_flag(uint32_t key, uint8_t data_valid, uint8_t int_pending)
{
	iosram_chunk_t	*chunkp;
	iosram_flags_t	flags;
	int		error = 0;

	/*
	 * Acquire lock and look for the requested chunk.  If it exists, and no
	 * tunnel switch is in progress, write the chunk's flags.
	 */
	mutex_enter(&iosram_mutex);
	chunkp = iosram_find_chunk(key);

	if (iosram_master == NULL) {
		error = EIO;
	} else if ((chunkp == NULL) ||
	    ((data_valid != IOSRAM_DATA_INVALID) &&
	    (data_valid != IOSRAM_DATA_VALID)) ||
	    ((int_pending != IOSRAM_INT_NONE) &&
	    (int_pending != IOSRAM_INT_TO_SSC) &&
	    (int_pending != IOSRAM_INT_TO_DOM))) {
		error = EINVAL;
	} else if (iosram_tswitch_active) {
		error = EAGAIN;
	} else {
		IOSRAM_STAT(setflag);
		flags.data_valid = data_valid;
		flags.int_pending = int_pending;
		ddi_rep_put8(iosram_handle, (uint8_t *)&flags,
		    (uint8_t *)(chunkp->flagsp), sizeof (iosram_flags_t),
		    DDI_DEV_AUTOINCR);
	}
	mutex_exit(&iosram_mutex);

	IOSRAMLOG(1, "SetFlag key:%x data_valid:%x int_pending:%x error:%d\n",
	    key, flags.data_valid, flags.int_pending, error);
	return (error);
}


/*
 * iosram_ctrl()
 *	This function provides access to a variety of services not available
 *	through the basic API.
 */
int
iosram_ctrl(uint32_t key, uint32_t cmd, void *arg)
{
	struct iosram_chunk	*chunkp;
	int			error = 0;

	/*
	 * Acquire lock and do some argument sanity checking.
	 */
	mutex_enter(&iosram_mutex);
	chunkp = iosram_find_chunk(key);

	if (iosram_master == NULL) {
		error = EIO;
	} else if (chunkp == NULL) {
		error = EINVAL;
	}

	if (error != 0) {
		mutex_exit(&iosram_mutex);
		return (error);
	}

	/*
	 * Arguments seem okay so far, so process the command.
	 */
	switch (cmd) {
		case IOSRAM_CMD_CHUNKLEN:
			/*
			 * Return the length of the chunk indicated by the key.
			 */
			if (arg == NULL) {
				error = EINVAL;
				break;
			}

			*(uint32_t *)arg = chunkp->toc_data.len;
			break;

		default:
			error = ENOTSUP;
			break;
	}

	mutex_exit(&iosram_mutex);
	return (error);
}


/*
 * iosram_hdr_ctrl()
 *	This function provides an interface for the Mailbox Protocol
 *	implementation to use when interacting with the IOSRAM header.
 */
int
iosram_hdr_ctrl(uint32_t cmd, void *arg)
{
	int	error = 0;

	/*
	 * Acquire lock and do some argument sanity checking.
	 */
	mutex_enter(&iosram_mutex);

	if (iosram_master == NULL) {
		error = EIO;
	}

	if (error != 0) {
		mutex_exit(&iosram_mutex);
		return (error);
	}

	switch (cmd) {
		case IOSRAM_HDRCMD_GET_SMS_MBOX_VER:
			/*
			 * Return the value of the sms_mbox_version field.
			 */
			if (arg == NULL) {
				error = EINVAL;
				break;
			}

			*(uint32_t *)arg = IOSRAM_GET_HDRFIELD32(iosram_master,
			    sms_mbox_version);
			break;

		case IOSRAM_HDRCMD_SET_OS_MBOX_VER:
			/*
			 * Set the value of the os_mbox_version field.
			 */
			IOSRAM_SET_HDRFIELD32(iosram_master, os_mbox_version,
			    (uint32_t)(uintptr_t)arg);
			IOSRAM_SET_HDRFIELD32(iosram_master, os_change_mask,
			    IOSRAM_HDRFIELD_OS_MBOX_VER);
			iosram_send_intr();
			break;

		case IOSRAM_HDRCMD_REG_CALLBACK:
			iosram_hdrchange_handler = (void (*)())arg;
			break;

		default:
			error = ENOTSUP;
			break;
	}

	mutex_exit(&iosram_mutex);
	return (error);
}


/*
 * iosram_softintr()
 *	IOSRAM soft interrupt handler
 */
static uint_t
iosram_softintr(caddr_t arg)
{
	uint32_t	hdr_changes;
	iosramsoft_t	*softp = (iosramsoft_t *)arg;
	iosram_chunk_t	*chunkp;
	void		(*handler)();
	int		i;
	uint8_t		flag;

	DPRINTF(1, ("iosram(%d): in iosram_softintr\n", softp->instance));

	IOSRAMLOG(2, "SINTR arg/softp:%p  pending:%d busy:%d\n",
	    arg, softp->intr_pending, softp->intr_busy, NULL);

	mutex_enter(&iosram_mutex);
	mutex_enter(&softp->intr_mutex);

	/*
	 * Do not process interrupt if interrupt handler is already running or
	 * no interrupts are pending.
	 */
	if (softp->intr_busy || !softp->intr_pending) {
		mutex_exit(&softp->intr_mutex);
		mutex_exit(&iosram_mutex);
		DPRINTF(1, ("IOSRAM(%d): softintr: busy=%d pending=%d\n",
		    softp->instance, softp->intr_busy, softp->intr_pending));
		return (softp->intr_pending ? DDI_INTR_CLAIMED :
		    DDI_INTR_UNCLAIMED);
	}

	/*
	 * It's possible for the SC to send an interrupt on the new master
	 * before we are able to set our internal state.  If so, we'll retrigger
	 * soft interrupt right after tunnel switch completion.
	 */
	if (softp->state & IOSRAM_STATE_TSWITCH) {
		mutex_exit(&softp->intr_mutex);
		mutex_exit(&iosram_mutex);
		DPRINTF(1, ("IOSRAM(%d): softintr: doing switch "
		    "state=0x%x\n", softp->instance, softp->state));
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Do not process interrupt if we are not the master.
	 */
	if (!(softp->state & IOSRAM_STATE_MASTER)) {
		mutex_exit(&softp->intr_mutex);
		mutex_exit(&iosram_mutex);
		DPRINTF(1, ("IOSRAM(%d): softintr: no master state=0x%x\n ",
		    softp->instance, softp->state));
		return (DDI_INTR_CLAIMED);
	}

	IOSRAM_STAT(sintr_recv);

	/*
	 * If the driver is suspended, then we should not process any
	 * interrupts.  Instead, we trigger a soft interrupt when the driver
	 * resumes.
	 */
	if (softp->suspended) {
		mutex_exit(&softp->intr_mutex);
		mutex_exit(&iosram_mutex);
		DPRINTF(1, ("IOSRAM(%d): softintr: suspended\n",
		    softp->instance));
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Indicate that the IOSRAM interrupt handler is busy.  Note that this
	 * includes incrementing the reader/writer count, since we don't want
	 * any tunnel switches to start up while we're processing callbacks.
	 */
	softp->intr_busy = 1;
	iosram_rw_active++;
#if defined(DEBUG)
	if (iosram_rw_active > iosram_rw_active_max) {
		iosram_rw_active_max = iosram_rw_active;
	}
#endif

	do {
		DPRINTF(1, ("IOSRAM(%d): softintr: processing interrupt\n",
		    softp->instance));

		softp->intr_pending = 0;

		mutex_exit(&softp->intr_mutex);

		/*
		 * Process changes to the IOSRAM header.
		 */
		hdr_changes = IOSRAM_GET_HDRFIELD32(iosram_master,
		    sms_change_mask);
		if (hdr_changes != 0) {
			int	error;

			IOSRAM_SET_HDRFIELD32(iosram_master, sms_change_mask,
			    0);
			if (hdr_changes & IOSRAM_HDRFIELD_TOC_INDEX) {
				/*
				 * XXX is it safe to temporarily release the
				 * iosram_mutex here?
				 */
				mutex_exit(&iosram_mutex);
				error = iosram_read_toc(iosram_master);
				mutex_enter(&iosram_mutex);
				if (error) {
					cmn_err(CE_WARN, "iosram_read_toc: new"
					    " TOC invalid; using old TOC.");
				}
				iosram_update_addrs(iosram_master);
			}

			if (iosram_hdrchange_handler != NULL) {
				mutex_exit(&iosram_mutex);
				iosram_hdrchange_handler();
				mutex_enter(&iosram_mutex);
			}
		}

		/*
		 * Get data_valid/int_pending flags and generate a callback if
		 * applicable.  For now, we read only those flags for which a
		 * callback has been registered.  We can optimize reading of
		 * flags by reading them all at once and then process them
		 * later.
		 */
		for (i = 0, chunkp = chunks; i < nchunks; i++,
		    chunkp++) {
#if DEBUG
			flag =  ddi_get8(iosram_handle,
			    &(chunkp->flagsp->int_pending));
			DPRINTF(1, ("IOSRAM(%d): softintr chunk #%d "
			    "flag=0x%x handler=%p\n",
			    softp->instance, i, (int)flag,
			    chunkp->cback.handler));
#endif
			if ((handler = chunkp->cback.handler) == NULL) {
				continue;
			}
			flag = ddi_get8(iosram_handle,
			    &(chunkp->flagsp->int_pending));
			if (flag == IOSRAM_INT_TO_DOM) {
				DPRINTF(1,
				    ("IOSRAM(%d): softintr: invoking handler\n",
				    softp->instance));
				IOSRAMLOG(1,
				    "SINTR invoking hdlr:%p arg:%p index:%d\n",
				    handler, chunkp->cback.arg, i, NULL);
				IOSRAM_STAT(callbacks);

				ddi_put8(iosram_handle,
				    &(chunkp->flagsp->int_pending),
				    IOSRAM_INT_NONE);
				chunkp->cback.busy = 1;
				mutex_exit(&iosram_mutex);
				(*handler)(chunkp->cback.arg);
				mutex_enter(&iosram_mutex);
				chunkp->cback.busy = 0;

				/*
				 * If iosram_unregister was called while the
				 * callback was being invoked, complete the
				 * unregistration here.
				 */
				if (chunkp->cback.unregister) {
					DPRINTF(1, ("IOSRAM(%d): softintr: "
					    "delayed unreg k:0x%08x\n",
					    softp->instance,
					    chunkp->toc_data.key));
					chunkp->cback.handler = NULL;
					chunkp->cback.arg = NULL;
					chunkp->cback.unregister = 0;
				}
			}

			/*
			 * If there's a tunnel switch waiting to run, give it
			 * higher priority than these callbacks by bailing out.
			 * They'll still be invoked on the new master iosram
			 * when the tunnel switch is done.
			 */
			if (iosram_tswitch_active) {
				break;
			}
		}

		mutex_enter(&softp->intr_mutex);

	} while (softp->intr_pending && !softp->suspended &&
	    !iosram_tswitch_active);

	/*
	 * Indicate IOSRAM interrupt handler is not BUSY any more
	 */
	softp->intr_busy = 0;

	ASSERT(iosram_rw_active > 0);
	if ((--iosram_rw_active == 0) && iosram_rw_wakeup) {
		iosram_rw_wakeup = 0;
		cv_broadcast(&iosram_rw_wait);
	}

	mutex_exit(&softp->intr_mutex);
	mutex_exit(&iosram_mutex);

	DPRINTF(1, ("iosram(%d): softintr exit\n", softp->instance));

	return (DDI_INTR_CLAIMED);
}


/*
 * iosram_intr()
 *	IOSRAM real interrupt handler
 */
static uint_t
iosram_intr(caddr_t arg)
{
	iosramsoft_t	*softp = (iosramsoft_t *)arg;
	int		result = DDI_INTR_UNCLAIMED;
	uint32_t	int_status;

	DPRINTF(2, ("iosram(%d): in iosram_intr\n", softp->instance));

	mutex_enter(&softp->intr_mutex);

	if (softp->sbbc_handle == NULL) {
		/*
		 * The SBBC registers region is not mapped in.
		 * Set the interrupt pending flag here, and process the
		 * interrupt after the tunnel switch.
		 */
		DPRINTF(1, ("IOSRAM(%d): iosram_intr: SBBC not mapped\n",
		    softp->instance));
		softp->intr_pending = 1;
		mutex_exit(&softp->intr_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	int_status = ddi_get32(softp->sbbc_handle,
	    &(softp->sbbc_region->int_status.reg));
	DPRINTF(1, ("iosram_intr: int_status = 0x%08x\n", int_status));

	if (int_status & IOSRAM_SBBC_INT0) {
		result = DDI_INTR_CLAIMED;
		DPRINTF(1, ("iosram_intr: int0 detected!\n"));
	}

	if (int_status & IOSRAM_SBBC_INT1) {
		result = DDI_INTR_CLAIMED;
		DPRINTF(1, ("iosram_intr: int1 detected!\n"));
	}

	if (result == DDI_INTR_CLAIMED) {
		ddi_put32(softp->sbbc_handle,
		    &(softp->sbbc_region->int_status.reg), int_status);
		int_status = ddi_get32(softp->sbbc_handle,
		    &(softp->sbbc_region->int_status.reg));
		DPRINTF(1, ("iosram_intr: int_status = 0x%08x\n",
		    int_status));

		softp->intr_pending = 1;
		/*
		 * Trigger soft interrupt if not executing and
		 * not suspended.
		 */
		if (!softp->intr_busy && !softp->suspended &&
		    (softp->softintr_id != NULL)) {
			DPRINTF(1, ("iosram(%d): trigger softint\n",
			    softp->instance));
			ddi_trigger_softintr(softp->softintr_id);
		}
	}

	IOSRAM_STAT(intr_recv);

	mutex_exit(&softp->intr_mutex);

	IOSRAMLOG(2, "INTR arg/softp:%p  pending:%d busy:%d\n",
	    arg, softp->intr_pending, softp->intr_busy, NULL);
	DPRINTF(1, ("iosram(%d): iosram_intr exit\n", softp->instance));

	return (result);
}


/*
 * iosram_send_intr()
 *	Send an interrupt to the SSP side via AXQ driver
 */
int
iosram_send_intr()
{
	IOSRAMLOG(1, "SendIntr called\n", NULL, NULL, NULL, NULL);
	IOSRAM_STAT(intr_send);
	DPRINTF(1, ("iosram iosram_send_intr invoked\n"));

	return (axq_cpu2ssc_intr(0));
}


#if defined(DEBUG)
static void
iosram_dummy_cback(void *arg)
{
	DPRINTF(1, ("iosram_dummy_cback invoked arg:%p\n", arg));
}
#endif /* DEBUG */


/*ARGSUSED1*/
static int
iosram_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
		int *rvalp)
{
	struct iosramsoft	*softp;
	int			error = DDI_SUCCESS;

	softp = ddi_get_soft_state(iosramsoft_statep, getminor(dev));
	if (softp == NULL) {
		return (ENXIO);
	}
	IOSRAMLOG(1, "IOCTL: dev:%p cmd:%x arg:%p ... instance %d\n",
	    dev, cmd, arg, softp->instance);

	switch (cmd) {
#if defined(DEBUG)
	case IOSRAM_GET_FLAG:
		{
		iosram_io_t	req;
		uint8_t		data_valid, int_pending;

		if (ddi_copyin((void *)arg, &req, sizeof (req), mode)) {
			return (EFAULT);
		}

		DPRINTF(2, ("IOSRAM_GET_FLAG(key:%x\n", req.key));

		req.retval = iosram_get_flag(req.key, &data_valid,
		    &int_pending);
		req.data_valid = (uint32_t)data_valid;
		req.int_pending = (uint32_t)int_pending;

		if (ddi_copyout(&req, (void *)arg, sizeof (req), mode)) {
			DPRINTF(1,
			    ("IOSRAM_GET_FLAG: can't copyout req.retval (%x)",
			    req.retval));
			error = EFAULT;
		}

		return (error);
		}

	case IOSRAM_SET_FLAG:
		{
		iosram_io_t	req;

		if (ddi_copyin((void *)arg, &req, sizeof (req), mode)) {
			return (EFAULT);
		}

		DPRINTF(2, ("IOSRAM_SET_FLAG(key:%x data_valid:%x "
		    "int_pending:%x\n", req.key, req.data_valid,
		    req.int_pending));

		req.retval = iosram_set_flag(req.key, req.data_valid,
		    req.int_pending);

		if (ddi_copyout(&req, (void *)arg, sizeof (req), mode)) {
			DPRINTF(1, ("IOSRAM_SET_FLAG: can't copyout req.retval"
			    " (%x)\n", req.retval));
			error = EFAULT;
		}

		return (error);
		}

	case IOSRAM_RD:
		{
		caddr_t		bufp;
		int		len;
		iosram_io_t	req;

		if (ddi_copyin((void *)arg, &req, sizeof (req), mode)) {
			return (EFAULT);
		}

		DPRINTF(2, ("IOSRAM_RD(k:%x o:%x len:%x bufp:%p\n", req.key,
		    req.off, req.len, (void *)(uintptr_t)req.bufp));

		len = req.len;
		bufp = kmem_alloc(len, KM_SLEEP);

		req.retval = iosram_rd(req.key, req.off, req.len, bufp);

		if (ddi_copyout(bufp, (void *)(uintptr_t)req.bufp, len, mode)) {
			DPRINTF(1, ("IOSRAM_RD: copyout(%p, %p,%x,%x) failed\n",
			    bufp, (void *)(uintptr_t)req.bufp, len, mode));
			error = EFAULT;
		} else if (ddi_copyout(&req, (void *)arg, sizeof (req), mode)) {
			DPRINTF(1, ("IOSRAM_RD: can't copyout retval (%x)\n",
			    req.retval));
			error = EFAULT;
		}

		kmem_free(bufp, len);
		return (error);
		}

	case IOSRAM_WR:
		{
		caddr_t		bufp;
		iosram_io_t	req;
		int		len;

		if (ddi_copyin((void *)arg, &req, sizeof (req), mode)) {
			return (EFAULT);
		}

		DPRINTF(2, ("IOSRAM_WR(k:%x o:%x len:%x bufp:%p\n",
		    req.key, req.off, req.len, req.bufp));
		len = req.len;
		bufp = kmem_alloc(len, KM_SLEEP);
		if (ddi_copyin((void *)(uintptr_t)req.bufp, bufp, len, mode)) {
			error = EFAULT;
		} else {
			req.retval = iosram_wr(req.key, req.off, req.len,
			    bufp);

			if (ddi_copyout(&req, (void *)arg, sizeof (req),
			    mode)) {
				error = EFAULT;
			}
		}
		kmem_free(bufp, len);
		return (error);
		}

	case IOSRAM_TOC:
		{
		caddr_t		bufp;
		int		len;
		iosram_io_t	req;

		if (ddi_copyin((void *)arg, &req, sizeof (req), mode)) {
			return (EFAULT);
		}

		DPRINTF(2, ("IOSRAM_TOC (req.bufp:%x req.len:%x) \n",
		    req.bufp, req.len));

		len = req.len;
		bufp = kmem_alloc(len, KM_SLEEP);

		req.retval = iosram_get_keys((iosram_toc_entry_t *)bufp,
		    &req.len);

		if (ddi_copyout(bufp, (void *)(uintptr_t)req.bufp, req.len,
		    mode)) {
			DPRINTF(1,
			    ("IOSRAM_TOC: copyout(%p, %p,%x,%x) failed\n",
			    bufp, (void *)(uintptr_t)req.bufp, req.len, mode));
			error = EFAULT;
		} else if (ddi_copyout(&req, (void *)arg, sizeof (req), mode)) {
			DPRINTF(1, ("IOSRAM_TOC: can't copyout retval (%x)\n",
			    req.retval));
			error = EFAULT;
		}
		kmem_free(bufp, len);
		return (error);
		}

	case IOSRAM_SEND_INTR:
		{
		DPRINTF(2, ("IOSRAM_SEND_INTR\n"));

		switch ((int)arg) {
		case 0x11:
		case 0x22:
		case 0x44:
		case 0x88:
			ddi_put32(softp->sbbc_handle,
			    &(softp->sbbc_region->int_enable.reg), (int)arg);
			DPRINTF(1, ("Wrote 0x%x to int_enable.reg\n",
			    (int)arg));
			break;
		case 0xBB:
			ddi_put32(softp->sbbc_handle,
			    &(softp->sbbc_region->p0_int_gen.reg), 1);
			DPRINTF(1, ("Wrote 1 to p0_int_gen.reg\n"));
			break;
		default:
			error = iosram_send_intr();
		}

		return (error);
		}

	case IOSRAM_PRINT_CBACK:
		iosram_print_cback();
		break;

	case IOSRAM_PRINT_STATE:
		iosram_print_state((int)arg);
		break;

#if IOSRAM_STATS
	case IOSRAM_PRINT_STATS:
		iosram_print_stats();
		break;
#endif

#if IOSRAM_LOG
	case IOSRAM_PRINT_LOG:
		iosram_print_log((int)arg);
		break;
#endif

	case IOSRAM_TUNNEL_SWITCH:
		error = iosram_switchfrom((int)arg);
		break;

	case IOSRAM_PRINT_FLAGS:
		iosram_print_flags();
		break;

	case IOSRAM_REG_CBACK:
		{
		iosram_io_t	req;

		if (ddi_copyin((void *)arg, &req, sizeof (req), mode)) {
			return (EFAULT);
		}

		DPRINTF(2, ("IOSRAM_REG_CBACK(k:%x)\n", req.key));

		req.retval = iosram_register(req.key, iosram_dummy_cback,
		    (void *)(uintptr_t)req.key);
		if (ddi_copyout(&req, (void *)arg, sizeof (req), mode)) {
			error = EFAULT;
		}

		return (error);
		}

	case IOSRAM_UNREG_CBACK:
		{
		iosram_io_t	req;

		if (ddi_copyin((void *)arg, &req, sizeof (req), mode)) {
			return (EFAULT);
		}

		DPRINTF(2, ("IOSRAM_REG_CBACK(k:%x)\n", req.key));

		req.retval = iosram_unregister(req.key);
		if (ddi_copyout(&req, (void *)arg, sizeof (req), mode)) {
			error = EFAULT;
		}

		return (error);
		}

	case IOSRAM_SEMA_ACQUIRE:
	{
		DPRINTF(1, ("IOSRAM_SEMA_ACQUIRE\n"));
		error = iosram_sema_acquire(NULL);
		return (error);
	}

	case IOSRAM_SEMA_RELEASE:
	{
		DPRINTF(1, ("IOSRAM_SEMA_RELEASE\n"));
		error = iosram_sema_release();
		return (error);
	}

#endif /* DEBUG */

	default:
		DPRINTF(1, ("iosram_ioctl: Illegal command %x\n", cmd));
		error = ENOTTY;
	}

	return (error);
}


/*
 * iosram_switch_tunnel(softp)
 *	Switch master tunnel to the specified instance
 *	Must be called while holding iosram_mutex
 */
/*ARGSUSED*/
static int
iosram_switch_tunnel(iosramsoft_t *softp)
{
#ifdef DEBUG
	int		instance = softp->instance;
#endif
	int		error = 0;
	iosramsoft_t	*prev_master;

	ASSERT(mutex_owned(&iosram_mutex));

	DPRINTF(1, ("tunnel switch new master:%p (%d) current master:%p (%d)\n",
	    softp, instance, iosram_master,
	    ((iosram_master) ? iosram_master->instance : -1)));
	IOSRAMLOG(1, "TSWTCH: new_master:%p (%p) iosram_master:%p (%d)\n",
	    softp, instance, iosram_master,
	    ((iosram_master) ? iosram_master->instance : -1));

	if (softp == NULL || (softp->state & IOSRAM_STATE_DETACH)) {
		return (ENXIO);
	}
	if (iosram_master == softp) {
		return (0);
	}


	/*
	 * We protect against the softp structure being deallocated by setting
	 * the IOSRAM_STATE_TSWITCH state flag. The detach routine will check
	 * for this flag and if set, it will wait for this flag to be reset or
	 * refuse the detach operation.
	 */
	iosram_new_master = softp;
	softp->state |= IOSRAM_STATE_TSWITCH;
	prev_master = iosram_master;
	if (prev_master) {
		prev_master->state |= IOSRAM_STATE_TSWITCH;
	}
	mutex_exit(&iosram_mutex);

	/*
	 * Map the target IOSRAM, read the TOC, and register interrupts if not
	 * already done.
	 */
	DPRINTF(1, ("iosram(%d): mapping IOSRAM and SBBC\n",
	    softp->instance));
	IOSRAMLOG(1, "TSWTCH: mapping instance:%d  softp:%p\n",
	    instance, softp, NULL, NULL);

	if (iosram_setup_map(softp) != DDI_SUCCESS) {
		error = ENXIO;
	} else if ((chunks == NULL) && (iosram_read_toc(softp) != 0)) {
		iosram_remove_map(softp);
		error = EINVAL;
	} else if (iosram_add_intr(softp) != DDI_SUCCESS) {
		/*
		 * If there was no previous master, purge the TOC data that
		 * iosram_read_toc() created.
		 */
		if ((prev_master == NULL) && (chunks != NULL)) {
			kmem_free(chunks, nchunks * sizeof (iosram_chunk_t));
			chunks = NULL;
			nchunks = 0;
			iosram_init_hashtab();
		}
		iosram_remove_map(softp);
		error = ENXIO;
	}

	/*
	 * If we are asked to abort tunnel switch, do so now, before invoking
	 * the OBP callback.
	 */
	if (iosram_tswitch_aborted) {

		/*
		 * Once the tunnel switch is aborted, this thread should not
		 * resume.  If it does, we simply log a message.  We can't unmap
		 * the new master IOSRAM as it may be accessed in
		 * iosram_abort_tswitch(). It will be unmapped when it is
		 * detached.
		 */
		IOSRAMLOG(1,
		    "TSWTCH: aborted (pre OBP cback). Thread resumed.\n",
		    NULL, NULL, NULL, NULL);
		error = EIO;
	}

	if (error) {
		IOSRAMLOG(1,
		    "TSWTCH: map failed instance:%d  softp:%p error:%x\n",
		    instance, softp, error, NULL);
		goto done;
	}

	if (prev_master != NULL) {
		int	result;

		/*
		 * Now invoke the OBP interface to do the tunnel switch.
		 */
		result = prom_starcat_switch_tunnel(softp->portid,
		    OBP_TSWITCH_REQREPLY);
		if (result != 0) {
			error = EIO;
		}
		IOSRAMLOG(1,
		    "TSWTCH: OBP tswitch portid:%x result:%x error:%x\n",
		    softp->portid, result, error, NULL);
		IOSRAM_STAT(tswitch);
		iosram_tswitch_tstamp = ddi_get_lbolt();
	}

	mutex_enter(&iosram_mutex);
	if (iosram_tswitch_aborted) {
		/*
		 * Tunnel switch aborted.  This thread should not resume.
		 * For now, we simply log a message, but don't unmap any
		 * IOSRAM at this stage as it may be accessed within the
		 * isoram_abort_tswitch(). The IOSRAM will be unmapped
		 * when that instance is detached.
		 */
		if (iosram_tswitch_aborted) {
			IOSRAMLOG(1,
			    "TSWTCH: aborted (post OBP cback). Thread"
			    " resumed.\n", NULL, NULL, NULL, NULL);
			error = EIO;
			mutex_exit(&iosram_mutex);
		}
	} else if (error) {
		/*
		 * Tunnel switch failed.  Continue using previous tunnel.
		 * However, unmap new (target) IOSRAM.
		 */
		iosram_new_master = NULL;
		mutex_exit(&iosram_mutex);
		iosram_remove_intr(softp);
		iosram_remove_map(softp);
	} else {
		/*
		 * Tunnel switch was successful.  Set the new master.
		 * Also unmap old master IOSRAM and remove any interrupts
		 * associated with that.
		 *
		 * Note that a call to iosram_force_write() allows access
		 * to the IOSRAM while tunnel switch is in progress.  That
		 * means we need to set the new master before unmapping
		 * the old master.
		 */
		iosram_set_master(softp);
		iosram_new_master = NULL;
		mutex_exit(&iosram_mutex);

		if (prev_master) {
			IOSRAMLOG(1, "TSWTCH: unmapping prev_master:%p (%d)\n",
			    prev_master, prev_master->instance, NULL, NULL);
			iosram_remove_intr(prev_master);
			iosram_remove_map(prev_master);
		}
	}

done:
	mutex_enter(&iosram_mutex);

	/*
	 * Clear the tunnel switch flag on the source and destination
	 * instances.
	 */
	if (prev_master) {
		prev_master->state &= ~IOSRAM_STATE_TSWITCH;
	}
	softp->state &= ~IOSRAM_STATE_TSWITCH;

	/*
	 * Since incoming interrupts could get lost during a tunnel switch,
	 * trigger a soft interrupt just in case.  No harm other than a bit
	 * of wasted effort will be caused if no interrupts were dropped.
	 */
	mutex_enter(&softp->intr_mutex);
	iosram_master->intr_pending = 1;
	if ((iosram_master->softintr_id != NULL) &&
	    (iosram_master->intr_busy == 0)) {
		ddi_trigger_softintr(iosram_master->softintr_id);
	}
	mutex_exit(&softp->intr_mutex);

	IOSRAMLOG(1, "TSWTCH: done error:%d iosram_master:%p instance:%d\n",
	    error, iosram_master,
	    (iosram_master) ? iosram_master->instance : -1, NULL);

	return (error);
}


/*
 * iosram_abort_tswitch()
 * Must be called while holding iosram_mutex.
 */
static void
iosram_abort_tswitch()
{
	uint32_t  master_valid, new_master_valid;

	ASSERT(mutex_owned(&iosram_mutex));

	if ((!iosram_tswitch_active) || iosram_tswitch_aborted) {
		return;
	}

	ASSERT(iosram_master != NULL);

	IOSRAMLOG(1, "ABORT: iosram_master:%p (%d) iosram_new_master:%p (%d)\n",
	    iosram_master, iosram_master->instance, iosram_new_master,
	    (iosram_new_master == NULL) ? -1 : iosram_new_master->instance);

	/*
	 * The first call to iosram_force_write() in the middle of tunnel switch
	 * will get here. We lookup IOSRAM VALID location and setup appropriate
	 * master, if one is still valid.  We also set iosram_tswitch_aborted to
	 * prevent reentering this code and to catch if the OBP callback thread
	 * somehow resumes.
	 */
	iosram_tswitch_aborted = 1;

	if ((iosram_new_master == NULL) ||
	    (iosram_new_master = iosram_master)) {
		/*
		 * New master hasn't been selected yet, or OBP callback
		 * succeeded and we already selected new IOSRAM as master, but
		 * system crashed in the middle of unmapping previous master or
		 * cleaning up state.  Use the existing master.
		 */
		ASSERT(iosram_master->iosramp != NULL);
		ASSERT(IOSRAM_GET_HDRFIELD32(iosram_master, status) ==
		    IOSRAM_VALID);
		IOSRAMLOG(1, "ABORT: master (%d) already determined.\n",
		    iosram_master->instance, NULL, NULL, NULL);

		return;
	}

	/*
	 * System crashed in the middle of tunnel switch and we know that the
	 * new target has not been marked master yet.  That means, the old
	 * master should still be mapped.  We need to abort the tunnel switch
	 * and setup a valid master, if possible, so that we can write to the
	 * IOSRAM.
	 *
	 * We select a new master based upon the IOSRAM header status fields in
	 * the previous master IOSRAM and the target IOSRAM as follows:
	 *
	 *	iosram_master	iosram-tswitch
	 * 	(Prev Master)	(New Target)	Decision
	 *	---------------	---------------	-----------
	 *	  VALID		  don't care	prev master
	 *	  INTRANSIT	  INVALID	prev master
	 *	  INTRANSIT	  INTRANSIT	prev master
	 *	  INTRANSIT	  VALID		new target
	 *	  INVALID	  INVALID	shouldn't ever happen
	 *	  INVALID	  INTRANSIT	shouldn't ever happen
	 *	  INVALID	  VALID		new target
	 */

	master_valid = (iosram_master->iosramp != NULL) ?
	    IOSRAM_GET_HDRFIELD32(iosram_master, status) : IOSRAM_INVALID;
	new_master_valid = (iosram_new_master->iosramp != NULL) ?
	    IOSRAM_GET_HDRFIELD32(iosram_new_master, status) : IOSRAM_INVALID;

	if (master_valid == IOSRAM_VALID) {
		/* EMPTY */
		/*
		 * OBP hasn't been called yet or, if it has, it hasn't started
		 * copying yet.  Use the existing master.  Note that the new
		 * master may not be mapped yet.
		 */
		IOSRAMLOG(1, "ABORT: prev master(%d) is VALID\n",
		    iosram_master->instance, NULL, NULL, NULL);
	} else if (master_valid == IOSRAM_INTRANSIT) {
		/*
		 * The system crashed after OBP started processing the tunnel
		 * switch but before the iosram driver determined that it was
		 * complete.  Use the new master if it has been marked valid,
		 * meaning that OBP finished copying data to it, or the old
		 * master otherwise.
		 */
		IOSRAMLOG(1, "ABORT: prev master(%d) is INTRANSIT\n",
		    iosram_master->instance, NULL, NULL, NULL);

		if (new_master_valid == IOSRAM_VALID) {
			iosram_set_master(iosram_new_master);
			IOSRAMLOG(1, "ABORT: new master(%d) is VALID\n",
			    iosram_new_master->instance, NULL, NULL,
			    NULL);
		} else {
			prom_starcat_switch_tunnel(iosram_master->portid,
			    OBP_TSWITCH_NOREPLY);

			IOSRAMLOG(1, "ABORT: new master(%d) is INVALID\n",
			    iosram_new_master->instance, NULL, NULL,
			    NULL);
		}
	} else {
		/*
		 * The system crashed after OBP marked the old master INVALID,
		 * which means the new master is the way to go.
		 */
		IOSRAMLOG(1, "ABORT: prev master(%d) is INVALID\n",
		    iosram_master->instance, NULL, NULL, NULL);

		ASSERT(new_master_valid == IOSRAM_VALID);

		iosram_set_master(iosram_new_master);
	}

	IOSRAMLOG(1, "ABORT: Instance %d selected as master\n",
	    iosram_master->instance, NULL, NULL, NULL);
}


/*
 * iosram_switchfrom(instance)
 *	Switch master tunnel away from the specified instance
 */
/*ARGSUSED*/
int
iosram_switchfrom(int instance)
{
	struct iosramsoft	*softp;
	int			error = 0;
	int			count;
	clock_t			current_tstamp;
	clock_t			tstamp_interval;
	struct iosramsoft	*last_master = NULL;
	static int		last_master_instance = -1;

	IOSRAMLOG(1, "SwtchFrom: instance:%d  iosram_master:%p (%d)\n",
	    instance, iosram_master,
	    ((iosram_master) ? iosram_master->instance : -1), NULL);

	mutex_enter(&iosram_mutex);

	/*
	 * Wait if another tunnel switch is in progress
	 */
	for (count = 0; iosram_tswitch_active && count < IOSRAM_TSWITCH_RETRY;
	    count++) {
		iosram_tswitch_wakeup = 1;
		cv_wait(&iosram_tswitch_wait, &iosram_mutex);
	}

	if (iosram_tswitch_active) {
		mutex_exit(&iosram_mutex);
		return (EAGAIN);
	}

	/*
	 * Check if the specified instance holds the tunnel. If not,
	 * then we are done.
	 */
	if ((iosram_master == NULL) || (iosram_master->instance != instance)) {
		mutex_exit(&iosram_mutex);
		return (0);
	}

	/*
	 * Before beginning the tunnel switch process, wait for any outstanding
	 * read/write activity to complete.
	 */
	iosram_tswitch_active = 1;
	while (iosram_rw_active) {
		iosram_rw_wakeup = 1;
		cv_wait(&iosram_rw_wait, &iosram_mutex);
	}

	/*
	 * If a previous tunnel switch just completed, we have to make sure
	 * HWAD has enough time to find the new tunnel before we switch
	 * away from it.  Otherwise, OBP's mailbox message to OSD will never
	 * get through.  Just to be paranoid about synchronization of lbolt
	 * across different CPUs, make sure the current attempt isn't noted
	 * as starting _before_ the last tunnel switch completed.
	 */
	current_tstamp = ddi_get_lbolt();
	if (current_tstamp > iosram_tswitch_tstamp) {
		tstamp_interval = current_tstamp - iosram_tswitch_tstamp;
	} else {
		tstamp_interval = 0;
	}
	if (drv_hztousec(tstamp_interval) < IOSRAM_TSWITCH_DELAY_US) {
		mutex_exit(&iosram_mutex);
		delay(drv_usectohz(IOSRAM_TSWITCH_DELAY_US) - tstamp_interval);
		mutex_enter(&iosram_mutex);
	}

	/*
	 * The specified instance holds the tunnel.  We need to move it to some
	 * other IOSRAM.  Try out all possible IOSRAMs listed in
	 * iosram_instances.  For now, we always search from the first entry.
	 * In future, it may be desirable to start where we left off.
	 */
	for (softp = iosram_instances; softp != NULL; softp = softp->next) {
		if (iosram_tswitch_aborted) {
			break;
		}

		/* we can't switch _to_ the instance we're switching _from_ */
		if (softp->instance == instance) {
			continue;
		}

		/* skip over instances being detached */
		if (softp->state & IOSRAM_STATE_DETACH) {
			continue;
		}

		/*
		 * Try to avoid reverting to the last instance we switched away
		 * from, as we expect that one to be detached eventually.  Keep
		 * track of it, though, so we can go ahead and try switching to
		 * it if no other viable candidates are found.
		 */
		if (softp->instance == last_master_instance) {
			last_master = softp;
			continue;
		}

		/*
		 * Do the tunnel switch.  If successful, record the instance of
		 * the master we just left behind so we can try to avoid
		 * reverting to it next time.
		 */
		if (iosram_switch_tunnel(softp) == 0) {
			last_master_instance = instance;
			break;
		}
	}

	/*
	 * If we failed to switch the tunnel, but we skipped over an instance
	 * that had previously been switched out of because we expected it to be
	 * detached, go ahead and try it anyway (unless the tswitch was aborted
	 * or the instance we skipped is finally being detached).
	 */
	if ((softp == NULL) && (last_master != NULL) &&
	    !iosram_tswitch_aborted &&
	    !(last_master->state & IOSRAM_STATE_DETACH)) {
		if (iosram_switch_tunnel(last_master) == 0) {
			softp = last_master;
			last_master_instance = instance;
		}
	}

	if ((softp == NULL) || (iosram_tswitch_aborted)) {
		error = EIO;
	}

	/*
	 * If there are additional tunnel switches queued up waiting for this
	 * one to complete, wake them up.
	 */
	if (iosram_tswitch_wakeup) {
		iosram_tswitch_wakeup = 0;
		cv_broadcast(&iosram_tswitch_wait);
	}
	iosram_tswitch_active = 0;
	mutex_exit(&iosram_mutex);
	return (error);
}


/*
 * iosram_tunnel_capable(softp)
 *	Check if this IOSRAM instance is tunnel-capable by looing at
 *	"tunnel-capable" property.
 */
static int
iosram_tunnel_capable(struct iosramsoft *softp)
{
	int	proplen;
	int	tunnel_capable;

	/*
	 * Look up IOSRAM_TUNNELOK_PROP property, if any.
	 */
	proplen = sizeof (tunnel_capable);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, softp->dip,
	    DDI_PROP_DONTPASS, IOSRAM_TUNNELOK_PROP, (caddr_t)&tunnel_capable,
	    &proplen) != DDI_PROP_SUCCESS) {
		tunnel_capable = 0;
	}
	return (tunnel_capable);
}


static int
iosram_sbbc_setup_map(struct iosramsoft *softp)
{
	int				rv;
	struct ddi_device_acc_attr	attr;
	dev_info_t			*dip = softp->dip;
	uint32_t			sema_val;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	mutex_enter(&iosram_mutex);
	mutex_enter(&softp->intr_mutex);

	/*
	 * Map SBBC region in
	 */
	if ((rv = ddi_regs_map_setup(dip, IOSRAM_SBBC_MAP_INDEX,
	    (caddr_t *)&softp->sbbc_region,
	    IOSRAM_SBBC_MAP_OFFSET, sizeof (iosram_sbbc_region_t),
	    &attr, &softp->sbbc_handle)) != DDI_SUCCESS) {
		DPRINTF(1, ("Failed to map SBBC region.\n"));
		mutex_exit(&softp->intr_mutex);
		mutex_exit(&iosram_mutex);
		return (rv);
	}

	/*
	 * Disable SBBC interrupts. SBBC interrupts are enabled
	 * once the interrupt handler is registered.
	 */
	ddi_put32(softp->sbbc_handle,
	    &(softp->sbbc_region->int_enable.reg), 0x0);

	/*
	 * Clear hardware semaphore value if appropriate.
	 * When the first SBBC is mapped in by the IOSRAM driver,
	 * the value of the semaphore should be initialized only
	 * if it is not held by SMS. For subsequent SBBC's, the
	 * semaphore will be always initialized.
	 */
	sema_val = IOSRAM_SEMA_RD(softp);

	if (!iosram_master) {
		/* the first SBBC is being mapped in */
		if (!(IOSRAM_SEMA_IS_HELD(sema_val) &&
		    IOSRAM_SEMA_GET_IDX(sema_val) == IOSRAM_SEMA_SMS_IDX)) {
			/* not held by SMS, we clear the semaphore */
			IOSRAM_SEMA_WR(softp, 0);
		}
	} else {
		/* not the first SBBC, we clear the semaphore */
		IOSRAM_SEMA_WR(softp, 0);
	}

	mutex_exit(&softp->intr_mutex);
	mutex_exit(&iosram_mutex);
	return (0);
}


static int
iosram_setup_map(struct iosramsoft *softp)
{
	int				instance = softp->instance;
	dev_info_t			*dip = softp->dip;
	int				portid;
	int				proplen;
	caddr_t				propvalue;
	struct ddi_device_acc_attr	attr;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	/*
	 * Lookup IOSRAM_REG_PROP property to find out our IOSRAM length
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, IOSRAM_REG_PROP, (caddr_t)&propvalue,
	    &proplen) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "iosram(%d): can't find register property.\n",
		    instance);
		return (DDI_FAILURE);
	} else {
		iosram_reg_t	*regprop = (iosram_reg_t *)propvalue;

		DPRINTF(1, ("SetupMap(%d): Got reg prop: %x %x %x\n",
		    instance, regprop->addr_hi,
		    regprop->addr_lo, regprop->size));

		softp->iosramlen = regprop->size;

		kmem_free(propvalue, proplen);
	}
	DPRINTF(1, ("SetupMap(%d): IOSRAM length: 0x%x\n", instance,
	    softp->iosramlen));
	softp->handle = NULL;

	/*
	 * To minimize boot time, we map the entire IOSRAM as opposed to
	 * mapping individual chunk via ddi_regs_map_setup() call.
	 */
	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&softp->iosramp,
	    0x0, softp->iosramlen, &attr, &softp->handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iosram(%d): failed to map IOSRAM len:%x\n",
		    instance, softp->iosramlen);
		iosram_remove_map(softp);
		return (DDI_FAILURE);
	}

	/*
	 * Lookup PORTID property on my parent hierarchy
	 */
	proplen = sizeof (portid);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    0, IOSRAM_PORTID_PROP, (caddr_t)&portid,
	    &proplen) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "iosram(%d): can't find portid property.\n",
		    instance);
		iosram_remove_map(softp);
		return (DDI_FAILURE);
	}
	softp->portid = portid;

	if (iosram_sbbc_setup_map(softp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iosram(%d): can't map SBBC region.\n",
		    instance);
		iosram_remove_map(softp);
		return (DDI_FAILURE);
	}

	mutex_enter(&iosram_mutex);
	softp->state |= IOSRAM_STATE_MAPPED;
	mutex_exit(&iosram_mutex);

	return (DDI_SUCCESS);
}


static void
iosram_remove_map(struct iosramsoft *softp)
{
	mutex_enter(&iosram_mutex);

	ASSERT((softp->state & IOSRAM_STATE_MASTER) == 0);

	if (softp->handle) {
		ddi_regs_map_free(&softp->handle);
		softp->handle = NULL;
	}
	softp->iosramp = NULL;

	/*
	 * Umap SBBC registers region. Shared with handler for SBBC
	 * interrupts, take intr_mutex.
	 */
	mutex_enter(&softp->intr_mutex);
	if (softp->sbbc_region) {
		ddi_regs_map_free(&softp->sbbc_handle);
		softp->sbbc_region = NULL;
	}
	mutex_exit(&softp->intr_mutex);

	softp->state &= ~IOSRAM_STATE_MAPPED;

	mutex_exit(&iosram_mutex);
}


/*
 * iosram_is_chosen(struct iosramsoft *softp)
 *
 *	Looks up "chosen" node property to
 *	determine if it is the chosen IOSRAM.
 */
static int
iosram_is_chosen(struct iosramsoft *softp)
{
	char		chosen_iosram[MAXNAMELEN];
	char		pn[MAXNAMELEN];
	int		nodeid;
	int		chosen;
	pnode_t		dnode;

	/*
	 * Get /chosen node info. prom interface will handle errors.
	 */
	dnode = prom_chosennode();

	/*
	 * Look for the "iosram" property on the chosen node with a prom
	 * interface as ddi_find_devinfo() couldn't be used (calls
	 * ddi_walk_devs() that creates one extra lock on the device tree).
	 */
	if (prom_getprop(dnode, IOSRAM_CHOSEN_PROP, (caddr_t)&nodeid) <= 0) {
		/*
		 * Can't find IOSRAM_CHOSEN_PROP property under chosen node
		 */
		cmn_err(CE_WARN,
		    "iosram(%d): can't find chosen iosram property\n",
		    softp->instance);
		return (0);
	}

	DPRINTF(1, ("iosram(%d): Got '%x' for chosen '%s' property\n",
	    softp->instance, nodeid, IOSRAM_CHOSEN_PROP));

	/*
	 * get the full OBP pathname of this node
	 */
	if (prom_phandle_to_path((phandle_t)nodeid, chosen_iosram,
	    sizeof (chosen_iosram)) < 0) {
		cmn_err(CE_NOTE, "prom_phandle_to_path(%x) failed\n", nodeid);
		return (0);
	}
	DPRINTF(1, ("iosram(%d): prom_phandle_to_path(%x) is '%s'\n",
	    softp->instance, nodeid, chosen_iosram));

	(void) ddi_pathname(softp->dip, pn);
	DPRINTF(1, ("iosram(%d): ddi_pathname(%p) is '%s'\n",
	    softp->instance, softp->dip, pn));

	chosen = (strcmp(chosen_iosram, pn) == 0) ? 1 : 0;
	DPRINTF(1, ("iosram(%d): ... %s\n", softp->instance,
	    chosen ? "MASTER" : "SLAVE"));
	IOSRAMLOG(1, "iosram(%d): ... %s\n", softp->instance,
	    (chosen ? "MASTER" : "SLAVE"), NULL, NULL);

	return (chosen);
}


/*
 * iosram_set_master(struct iosramsoft *softp)
 *
 *	Set master tunnel to the specified IOSRAM
 *	Must be called while holding iosram_mutex.
 */
static void
iosram_set_master(struct iosramsoft *softp)
{
	ASSERT(mutex_owned(&iosram_mutex));
	ASSERT(softp != NULL);
	ASSERT(softp->state & IOSRAM_STATE_MAPPED);
	ASSERT(IOSRAM_GET_HDRFIELD32(softp, status) == IOSRAM_VALID);

	/*
	 * Clear MASTER flag on any previous IOSRAM master, if any
	 */
	if (iosram_master && (iosram_master != softp)) {
		iosram_master->state &= ~IOSRAM_STATE_MASTER;
	}

	/*
	 * Setup new IOSRAM master
	 */
	iosram_update_addrs(softp);
	iosram_handle = softp->handle;
	softp->state |= IOSRAM_STATE_MASTER;
	softp->tswitch_ok++;
	iosram_master = softp;

	IOSRAMLOG(1, "SETMASTER: softp:%p instance:%d\n", softp,
	    softp->instance, NULL, NULL);
}


/*
 * iosram_read_toc()
 *
 *	Read the TOC from an IOSRAM instance that has been mapped in.
 *	If the TOC is flawed or the IOSRAM isn't valid, return an error.
 */
static int
iosram_read_toc(struct iosramsoft *softp)
{
	int			i;
	int			instance = softp->instance;
	uint8_t			*toc_entryp;
	iosram_flags_t		*flagsp = NULL;
	int			new_nchunks;
	iosram_chunk_t		*new_chunks;
	iosram_chunk_t		*chunkp;
	iosram_chunk_t		*old_chunkp;
	iosram_toc_entry_t	index;

	/*
	 * Never try to read the TOC out of an unmapped IOSRAM.
	 */
	ASSERT(softp->state & IOSRAM_STATE_MAPPED);

	mutex_enter(&iosram_mutex);

	/*
	 * Check to make sure this IOSRAM is marked valid.  Return
	 * an error if it isn't.
	 */
	if (IOSRAM_GET_HDRFIELD32(softp, status) != IOSRAM_VALID) {
		DPRINTF(1, ("iosram_read_toc(%d): IOSRAM not flagged valid\n",
		    instance));
		mutex_exit(&iosram_mutex);
		return (EINVAL);
	}

	/*
	 * Get the location of the TOC.
	 */
	toc_entryp = softp->iosramp + IOSRAM_GET_HDRFIELD32(softp, toc_offset);

	/*
	 * Read the index entry from the TOC and make sure it looks correct.
	 */
	ddi_rep_get8(softp->handle, (uint8_t *)&index, toc_entryp,
	    sizeof (iosram_toc_entry_t), DDI_DEV_AUTOINCR);
	if ((index.key != IOSRAM_INDEX_KEY) ||
	    (index.off != IOSRAM_INDEX_OFF)) {
		cmn_err(CE_WARN, "iosram(%d): invalid TOC index.\n", instance);
		mutex_exit(&iosram_mutex);
		return (EINVAL);
	}

	/*
	 * Allocate storage for the new chunks array and initialize it with data
	 * from the TOC and callback data from the corresponding old chunk, if
	 * it exists.
	 */
	new_nchunks = index.len - 1;
	new_chunks = (iosram_chunk_t *)kmem_zalloc(new_nchunks *
	    sizeof (iosram_chunk_t), KM_SLEEP);
	for (i = 0, chunkp = new_chunks; i < new_nchunks; i++, chunkp++) {
		toc_entryp += sizeof (iosram_toc_entry_t);
		ddi_rep_get8(softp->handle, (uint8_t *)&(chunkp->toc_data),
		    toc_entryp, sizeof (iosram_toc_entry_t), DDI_DEV_AUTOINCR);
		chunkp->hash = NULL;
		if ((chunkp->toc_data.off < softp->iosramlen) &&
		    (chunkp->toc_data.len <= softp->iosramlen) &&
		    ((chunkp->toc_data.off + chunkp->toc_data.len) <=
		    softp->iosramlen)) {
			chunkp->basep = softp->iosramp + chunkp->toc_data.off;
			DPRINTF(1,
			    ("iosram_read_toc(%d): k:%x o:%x l:%x p:%x\n",
			    instance, chunkp->toc_data.key,
			    chunkp->toc_data.off, chunkp->toc_data.len,
			    chunkp->basep));
		} else {
			cmn_err(CE_WARN, "iosram(%d): TOC entry %d"
			    "out of range... off:%x  len:%x\n",
			    instance, i + 1, chunkp->toc_data.off,
			    chunkp->toc_data.len);
			kmem_free(new_chunks, new_nchunks *
			    sizeof (iosram_chunk_t));
			mutex_exit(&iosram_mutex);
			return (EINVAL);
		}

		/*
		 * Note the existence of the flags chunk, which is required in
		 * a correct TOC.
		 */
		if (chunkp->toc_data.key == IOSRAM_FLAGS_KEY) {
			flagsp = (iosram_flags_t *)chunkp->basep;
		}

		/*
		 * If there was an entry for this chunk in the old list, copy
		 * the callback data from old to new storage.
		 */
		if ((nchunks > 0) &&
		    ((old_chunkp = iosram_find_chunk(chunkp->toc_data.key)) !=
		    NULL)) {
			bcopy(&(old_chunkp->cback), &(chunkp->cback),
			    sizeof (iosram_cback_t));
		}
	}
	/*
	 * The TOC is malformed if there is no entry for the flags chunk.
	 */
	if (flagsp == NULL) {
		kmem_free(new_chunks, new_nchunks * sizeof (iosram_chunk_t));
		mutex_exit(&iosram_mutex);
		return (EINVAL);
	}

	/*
	 * Free any memory that is no longer needed and install the new data
	 * as current data.
	 */
	if (chunks != NULL) {
		kmem_free(chunks, nchunks * sizeof (iosram_chunk_t));
	}
	chunks = new_chunks;
	nchunks = new_nchunks;
	iosram_init_hashtab();

	mutex_exit(&iosram_mutex);
	return (0);
}


/*
 * iosram_init_hashtab()
 *
 *	Initialize the hash table and populate it with the IOSRAM
 *	chunks previously read from the TOC.  The caller must hold the
 *	ioram_mutex lock.
 */
static void
iosram_init_hashtab(void)
{
	int		i, bucket;
	iosram_chunk_t	*chunkp;

	ASSERT(mutex_owned(&iosram_mutex));

	for (i = 0; i < IOSRAM_HASHSZ; i++) {
		iosram_hashtab[i] = NULL;
	}

	if (chunks) {
		for (i = 0, chunkp = chunks; i < nchunks; i++, chunkp++) {
			/*
			 * Hide the flags chunk by leaving it out of the hash
			 * table.
			 */
			if (chunkp->toc_data.key == IOSRAM_FLAGS_KEY) {
				continue;
			}

			/*
			 * Add the current chunk to the hash table.
			 */
			bucket = IOSRAM_HASH(chunkp->toc_data.key);
			chunkp->hash = iosram_hashtab[bucket];
			iosram_hashtab[bucket] = chunkp;
		}
	}
}


/*
 * iosram_update_addrs()
 *
 *	Process the chunk list, updating each chunk's basep, which is a pointer
 *	to the beginning of the chunk's memory in kvaddr space.  Record the
 *	basep value of the flags chunk to speed up flag access.  The caller
 *	must hold the iosram_mutex lock.
 */
static void
iosram_update_addrs(struct iosramsoft *softp)
{
	int		i;
	iosram_flags_t	*flagsp;
	iosram_chunk_t	*chunkp;

	ASSERT(mutex_owned(&iosram_mutex));

	/*
	 * First go through all of the chunks updating their base pointers and
	 * looking for the flags chunk.
	 */
	for (i = 0, chunkp = chunks; i < nchunks; i++, chunkp++) {
		chunkp->basep = softp->iosramp + chunkp->toc_data.off;
		if (chunkp->toc_data.key == IOSRAM_FLAGS_KEY) {
			flagsp = (iosram_flags_t *)(chunkp->basep);
			DPRINTF(1,
			    ("iosram_update_addrs flags: o:0x%08x p:%p",
			    chunkp->toc_data.off, flagsp));
		}
	}

	/*
	 * Now, go through and update each chunk's flags pointer.  This can't be
	 * done in the first loop because we don't have the address of the flags
	 * chunk yet.
	 */
	for (i = 0, chunkp = chunks; i < nchunks; i++, chunkp++) {
		chunkp->flagsp = flagsp++;
		DPRINTF(1, ("iosram_update_addrs: k:0x%x f:%p\n",
		    chunkp->toc_data.key, chunkp->flagsp));
	}
}

/*
 * iosram_find_chunk(key)
 *
 *	Return a pointer to iosram_chunk structure corresponding to the
 *	"key" IOSRAM chunk.  The caller must hold the iosram_mutex lock.
 */
static iosram_chunk_t *
iosram_find_chunk(uint32_t key)
{
	iosram_chunk_t	*chunkp;
	int		index = IOSRAM_HASH(key);

	ASSERT(mutex_owned(&iosram_mutex));

	for (chunkp = iosram_hashtab[index]; chunkp; chunkp = chunkp->hash) {
		if (chunkp->toc_data.key == key) {
			break;
		}
	}

	return (chunkp);
}


/*
 * iosram_add_intr(iosramsoft_t *)
 */
static int
iosram_add_intr(iosramsoft_t *softp)
{
	IOSRAMLOG(2, "ADDINTR: softp:%p  instance:%d\n",
	    softp, softp->instance, NULL, NULL);

	if (ddi_add_softintr(softp->dip, DDI_SOFTINT_MED,
	    &softp->softintr_id, &softp->soft_iblk, NULL,
	    iosram_softintr, (caddr_t)softp) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "iosram(%d): Can't register softintr.\n",
		    softp->instance);
		return (DDI_FAILURE);
	}

	if (ddi_add_intr(softp->dip, 0, &softp->real_iblk, NULL,
	    iosram_intr, (caddr_t)softp) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "iosram(%d): Can't register intr"
		    " handler.\n", softp->instance);
		ddi_remove_softintr(softp->softintr_id);
		return (DDI_FAILURE);
	}

	/*
	 * Enable SBBC interrupts
	 */
	ddi_put32(softp->sbbc_handle, &(softp->sbbc_region->int_enable.reg),
	    IOSRAM_SBBC_INT0|IOSRAM_SBBC_INT1);

	return (DDI_SUCCESS);
}


/*
 * iosram_remove_intr(iosramsoft_t *)
 */
static int
iosram_remove_intr(iosramsoft_t *softp)
{
	IOSRAMLOG(2, "REMINTR: softp:%p  instance:%d\n",
	    softp, softp->instance, NULL, NULL);

	/*
	 * Disable SBBC interrupts if SBBC is mapped in
	 */
	if (softp->sbbc_region) {
		ddi_put32(softp->sbbc_handle,
		    &(softp->sbbc_region->int_enable.reg), 0);
	}

	/*
	 * Remove SBBC interrupt handler
	 */
	ddi_remove_intr(softp->dip, 0, softp->real_iblk);

	/*
	 * Remove soft interrupt handler
	 */
	mutex_enter(&iosram_mutex);
	if (softp->softintr_id != NULL) {
		ddi_remove_softintr(softp->softintr_id);
		softp->softintr_id = NULL;
	}
	mutex_exit(&iosram_mutex);

	return (0);
}


/*
 * iosram_add_instance(iosramsoft_t *)
 * Must be called while holding iosram_mutex
 */
static void
iosram_add_instance(iosramsoft_t *new_softp)
{
#ifdef DEBUG
	int		instance = new_softp->instance;
	iosramsoft_t	*softp;
#endif

	ASSERT(mutex_owned(&iosram_mutex));

#if defined(DEBUG)
	/* Verify that this instance is not in the list */
	for (softp = iosram_instances; softp != NULL; softp = softp->next) {
		ASSERT(softp->instance != instance);
	}
#endif

	/*
	 * Add this instance to the list
	 */
	if (iosram_instances != NULL) {
		iosram_instances->prev = new_softp;
	}
	new_softp->next = iosram_instances;
	new_softp->prev = NULL;
	iosram_instances = new_softp;
}


/*
 * iosram_remove_instance(int instance)
 * Must be called while holding iosram_mutex
 */
static void
iosram_remove_instance(int instance)
{
	iosramsoft_t *softp;

	/*
	 * Remove specified instance from the iosram_instances list so that
	 * it can't be chosen for tunnel in future.
	 */
	ASSERT(mutex_owned(&iosram_mutex));

	for (softp = iosram_instances; softp != NULL; softp = softp->next) {
		if (softp->instance == instance) {
			if (softp->next != NULL) {
				softp->next->prev = softp->prev;
			}
			if (softp->prev != NULL) {
				softp->prev->next = softp->next;
			}
			if (iosram_instances == softp) {
				iosram_instances = softp->next;
			}

			return;
		}
	}
}


/*
 * iosram_sema_acquire: Acquire hardware semaphore.
 * Return 0 if the semaphore could be acquired, or one of the following
 * possible values:
 * EAGAIN: there is a tunnel switch in progress
 * EBUSY: the semaphore was already "held"
 * ENXIO:  an IO error occured (e.g. SBBC not mapped)
 * If old_value is not NULL, the location it points to will be updated
 * with the semaphore value read when attempting to acquire it.
 */
int
iosram_sema_acquire(uint32_t *old_value)
{
	struct iosramsoft	*softp;
	int			rv;
	uint32_t		sema_val;

	DPRINTF(2, ("IOSRAM: in iosram_sema_acquire\n"));

	mutex_enter(&iosram_mutex);

	/*
	 * Disallow access if there is a tunnel switch in progress.
	 */
	if (iosram_tswitch_active) {
		mutex_exit(&iosram_mutex);
		return (EAGAIN);
	}

	/*
	 * Use current master IOSRAM for operation, fail if none is
	 * currently active.
	 */
	if ((softp = iosram_master) == NULL) {
		mutex_exit(&iosram_mutex);
		DPRINTF(1, ("IOSRAM: iosram_sema_acquire: no master\n"));
		return (ENXIO);
	}

	mutex_enter(&softp->intr_mutex);

	/*
	 * Fail if SBBC region has not been mapped. This shouldn't
	 * happen if we have a master IOSRAM, but we double-check.
	 */
	if (softp->sbbc_region == NULL) {
		mutex_exit(&softp->intr_mutex);
		mutex_exit(&iosram_mutex);
		DPRINTF(1, ("IOSRAM(%d): iosram_sema_acquire: "
		    "SBBC not mapped\n", softp->instance));
		return (ENXIO);
	}

	/* read semaphore value */
	sema_val = IOSRAM_SEMA_RD(softp);
	if (old_value != NULL)
		*old_value = sema_val;

	if (IOSRAM_SEMA_IS_HELD(sema_val)) {
		/* semaphore was held by someone else */
		rv = EBUSY;
	} else {
		/* semaphore was not held, we just acquired it */
		rv = 0;
	}

	mutex_exit(&softp->intr_mutex);
	mutex_exit(&iosram_mutex);

	DPRINTF(1, ("IOSRAM(%d): iosram_sema_acquire: "
	    "old value=0x%x rv=%d\n", softp->instance, sema_val, rv));

	return (rv);
}


/*
 * iosram_sema_release: Release hardware semaphore.
 * This function will "release" the hardware semaphore, and return 0 on
 * success. If an error occured, one of the following values will be
 * returned:
 * EAGAIN: there is a tunnel switch in progress
 * ENXIO:  an IO error occured (e.g. SBBC not mapped)
 */
int
iosram_sema_release(void)
{
	struct iosramsoft	*softp;

	DPRINTF(2, ("IOSRAM: in iosram_sema_release\n"));

	mutex_enter(&iosram_mutex);

	/*
	 * Disallow access if there is a tunnel switch in progress.
	 */
	if (iosram_tswitch_active) {
		mutex_exit(&iosram_mutex);
		return (EAGAIN);
	}

	/*
	 * Use current master IOSRAM for operation, fail if none is
	 * currently active.
	 */
	if ((softp = iosram_master) == NULL) {
		mutex_exit(&iosram_mutex);
		DPRINTF(1, ("IOSRAM: iosram_sema_release: no master\n"));
		return (ENXIO);
	}

	mutex_enter(&softp->intr_mutex);

	/*
	 * Fail if SBBC region has not been mapped in. This shouldn't
	 * happen if we have a master IOSRAM, but we double-check.
	 */
	if (softp->sbbc_region == NULL) {
		mutex_exit(&softp->intr_mutex);
		mutex_exit(&iosram_mutex);
		DPRINTF(1, ("IOSRAM(%d): iosram_sema_release: "
		    "SBBC not mapped\n", softp->instance));
		return (ENXIO);
	}

	/* Release semaphore by clearing our semaphore register */
	IOSRAM_SEMA_WR(softp, 0);

	mutex_exit(&softp->intr_mutex);
	mutex_exit(&iosram_mutex);

	DPRINTF(1, ("IOSRAM(%d): iosram_sema_release: success\n",
	    softp->instance));

	return (0);
}


#if defined(IOSRAM_LOG)
void
iosram_log(caddr_t fmt, intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4)
{
	uint32_t	seq;
	iosram_log_t	*logp;

	mutex_enter(&iosram_log_mutex);

	seq = iosram_logseq++;
	logp = &iosram_logbuf[seq % IOSRAM_MAXLOG];
	logp->seq = seq;
	logp->tstamp = lbolt;
	logp->fmt = fmt;
	logp->arg1 = a1;
	logp->arg2 = a2;
	logp->arg3 = a3;
	logp->arg4 = a4;

	mutex_exit(&iosram_log_mutex);

	if (iosram_log_print) {
		cmn_err(CE_CONT, "#%x @%lx ", logp->seq, logp->tstamp);
		if (logp->fmt) {
			cmn_err(CE_CONT, logp->fmt, logp->arg1, logp->arg2,
			    logp->arg3, logp->arg4);
			if (logp->fmt[strlen(logp->fmt)-1] != '\n') {
				cmn_err(CE_CONT, "\n");
			}
		} else {
			cmn_err(CE_CONT, "fmt:%p args: %lx %lx %lx %lx\n",
			    logp->fmt, logp->arg1, logp->arg2, logp->arg3,
			    logp->arg4);
		}
	}
}
#endif /* IOSRAM_LOG */


#if defined(DEBUG)
/*
 * iosram_get_keys(buf, len)
 *	Return IOSRAM TOC in the specified buffer
 */
static int
iosram_get_keys(iosram_toc_entry_t *bufp, uint32_t *len)
{
	struct iosram_chunk	*chunkp;
	int			error = 0;
	int			i;
	int			cnt = (*len) / sizeof (iosram_toc_entry_t);

	IOSRAMLOG(2, "iosram_get_keys(bufp:%p *len:%x)\n", bufp, *len, NULL,
	    NULL);

	/*
	 * Copy data while holding the lock to prevent any data
	 * corruption or invalid pointer dereferencing.
	 */
	mutex_enter(&iosram_mutex);

	if (iosram_master == NULL) {
		error = EIO;
	} else {
		for (i = 0, chunkp = chunks; i < nchunks && i < cnt;
		    i++, chunkp++) {
			bufp[i].key = chunkp->toc_data.key;
			bufp[i].off = chunkp->toc_data.off;
			bufp[i].len = chunkp->toc_data.len;
			bufp[i].unused = chunkp->toc_data.unused;
		}
		*len = i * sizeof (iosram_toc_entry_t);
	}

	mutex_exit(&iosram_mutex);
	return (error);
}


/*
 * iosram_print_state(instance)
 */
static void
iosram_print_state(int instance)
{
	struct iosramsoft	*softp;
	char			pn[MAXNAMELEN];

	if (instance < 0) {
		softp = iosram_master;
	} else {
		softp = ddi_get_soft_state(iosramsoft_statep, instance);
	}

	if (softp == NULL) {
		cmn_err(CE_CONT, "iosram_print_state: Can't find instance %d\n",
		    instance);
		return;
	}
	instance = softp->instance;

	mutex_enter(&iosram_mutex);
	mutex_enter(&softp->intr_mutex);

	cmn_err(CE_CONT, "iosram_print_state(%d): ... %s\n", instance,
	    ((softp == iosram_master) ? "MASTER" : "SLAVE"));

	(void) ddi_pathname(softp->dip, pn);
	cmn_err(CE_CONT, "  pathname:%s\n", pn);
	cmn_err(CE_CONT, "  instance:%d  portid:%d iosramlen:0x%x\n",
	    softp->instance, softp->portid, softp->iosramlen);
	cmn_err(CE_CONT, "  softp:%p  handle:%p  iosramp:%p\n", softp,
	    softp->handle, softp->iosramp);
	cmn_err(CE_CONT, "  state:0x%x  tswitch_ok:%x  tswitch_fail:%x\n",
	    softp->state, softp->tswitch_ok, softp->tswitch_fail);
	cmn_err(CE_CONT, "  softintr_id:%p  intr_busy:%x  intr_pending:%x\n",
	    softp->softintr_id, softp->intr_busy, softp->intr_pending);

	mutex_exit(&softp->intr_mutex);
	mutex_exit(&iosram_mutex);
}


/*
 * iosram_print_stats()
 */
static void
iosram_print_stats()
{
	uint32_t	calls;

	cmn_err(CE_CONT, "iosram_stats:\n");
	calls = iosram_stats.read;
	cmn_err(CE_CONT, " read  ... calls:%x  bytes:%lx  avg_sz:%x\n",
	    calls, iosram_stats.bread,
	    (uint32_t)((calls != 0) ? (iosram_stats.bread/calls) : 0));

	calls = iosram_stats.write;
	cmn_err(CE_CONT, " write ... calls:%x  bytes:%lx  avg_sz:%x\n",
	    calls, iosram_stats.bwrite,
	    (uint32_t)((calls != 0) ? (iosram_stats.bwrite/calls) : 0));

	cmn_err(CE_CONT, " intr recv (real:%x  soft:%x)  sent:%x  cback:%x\n",
	    iosram_stats.intr_recv, iosram_stats.sintr_recv,
	    iosram_stats.intr_send, iosram_stats.callbacks);

	cmn_err(CE_CONT, " tswitch: %x  getflag:%x  setflag:%x\n",
	    iosram_stats.tswitch, iosram_stats.getflag,
	    iosram_stats.setflag);

	cmn_err(CE_CONT, " iosram_rw_active_max: %x\n", iosram_rw_active_max);
}


static void
iosram_print_cback()
{
	iosram_chunk_t	*chunkp;
	int		i;

	/*
	 * Print callback handlers
	 */
	mutex_enter(&iosram_mutex);

	cmn_err(CE_CONT, "IOSRAM callbacks:\n");
	for (i = 0, chunkp = chunks; i < nchunks; i++, chunkp++) {
		if (chunkp->cback.handler) {
			cmn_err(CE_CONT, "  %2d: key:0x%x  hdlr:%p  arg:%p "
			    "busy:%d unreg:%d\n", i, chunkp->toc_data.key,
			    chunkp->cback.handler, chunkp->cback.arg,
			    chunkp->cback.busy, chunkp->cback.unregister);
		}
	}
	mutex_exit(&iosram_mutex);
}


static void
iosram_print_flags()
{
	int		i;
	uint32_t	*keys;
	iosram_flags_t	*flags;

	mutex_enter(&iosram_mutex);

	if (iosram_master == NULL) {
		mutex_exit(&iosram_mutex);
		cmn_err(CE_CONT, "IOSRAM Flags: not accessible\n");
		return;
	}

	keys = kmem_alloc(nchunks * sizeof (uint32_t), KM_SLEEP);
	flags = kmem_alloc(nchunks * sizeof (iosram_flags_t), KM_SLEEP);

	for (i = 0; i < nchunks; i++) {
		keys[i] = chunks[i].toc_data.key;
		ddi_rep_get8(iosram_handle, (uint8_t *)&(flags[i]),
		    (uint8_t *)(chunks[i].flagsp), sizeof (iosram_flags_t),
		    DDI_DEV_AUTOINCR);
	}

	mutex_exit(&iosram_mutex);

	cmn_err(CE_CONT, "IOSRAM Flags:\n");
	for (i = 0; i < nchunks; i++) {
		cmn_err(CE_CONT,
		    "  %2d: key: 0x%x  data_valid:%x  int_pending:%x\n",
		    i, keys[i], flags[i].data_valid, flags[i].int_pending);
	}

	kmem_free(keys, nchunks * sizeof (uint32_t));
	kmem_free(flags, nchunks * sizeof (iosram_flags_t));
}


/*PRINTFLIKE1*/
static void
iosram_dprintf(const char *fmt, ...)
{
	char	msg_buf[256];
	va_list	adx;

	va_start(adx, fmt);
	vsprintf(msg_buf, fmt, adx);
	va_end(adx);

	cmn_err(CE_CONT, "%s", msg_buf);
}
#endif /* DEBUG */


#if IOSRAM_LOG
/*
 * iosram_print_log(int cnt)
 *	Print last few entries of the IOSRAM log in reverse order
 */
static void
iosram_print_log(int cnt)
{
	int	i;

	if (cnt <= 0) {
		cnt = 20;
	} else if (cnt > IOSRAM_MAXLOG) {
		cnt = IOSRAM_MAXLOG;
	}


	cmn_err(CE_CONT,
	    "\niosram_logseq: 0x%x  lbolt: %lx  iosram_log_level:%x\n",
	    iosram_logseq, lbolt, iosram_log_level);
	cmn_err(CE_CONT, "iosram_logbuf: %p  max entries:0x%x\n",
	    iosram_logbuf, IOSRAM_MAXLOG);
	for (i = iosram_logseq;  --i >= 0 && --cnt >= 0; ) {
		iosram_log_t	*logp;

		mutex_enter(&iosram_log_mutex);

		logp = &iosram_logbuf[i %IOSRAM_MAXLOG];
		cmn_err(CE_CONT, "#%x @%lx ", logp->seq, logp->tstamp);

		if (logp->fmt) {
			cmn_err(CE_CONT, logp->fmt, logp->arg1, logp->arg2,
			    logp->arg3, logp->arg4);
			if (logp->fmt[strlen(logp->fmt)-1] != '\n') {
				cmn_err(CE_CONT, "\n");
			}
		} else {
			cmn_err(CE_CONT, "fmt:%p args: %lx %lx %lx %lx\n",
			    logp->fmt, logp->arg1, logp->arg2,
			    logp->arg3, logp->arg4);
		}

		mutex_exit(&iosram_log_mutex);
	}
}
#endif	/* IOSRAM_LOG */
