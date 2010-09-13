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
 * pcf8584.c is the nexus driver for all pcf8584 controller
 * implementations.  It supports both interrupt and polled
 * mode operation, but defaults to interrupt.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/archsystm.h>
#include <sys/platform_module.h>

#include <sys/i2c/clients/i2c_client.h>
#include <sys/i2c/misc/i2c_svc.h>
#include <sys/i2c/misc/i2c_svc_impl.h>
#include <sys/i2c/nexus/pcf8584.h>

#include <sys/note.h>

/*
 * static function declarations
 */
static void pcf8584_resume(dev_info_t *dip);
static void pcf8584_suspend(dev_info_t *dip);
static int pcf8584_bus_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result);
static  void pcf8584_acquire(pcf8584_t *, dev_info_t *dip,
	i2c_transfer_t *tp, boolean_t force);
static  void pcf8584_release(pcf8584_t *, boolean_t force);
static int pcf8584_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pcf8584_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int pcf8584_open(dev_t *devp, int flag, int otyp,
    cred_t *cred_p);
static int pcf8584_close(dev_t dev, int flag, int otyp,
    cred_t *cred_p);
static int pcf8584_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static void pcf8584_select_bus(pcf8584_t *i2c);
static enum tran_state pcf8584_type_to_state(int i2c_flags);
static void pcf8584_put_s1(pcf8584_t *i2c, char cmd);
static void pcf8584_put_s0(pcf8584_t *i2c, char data);
static uint8_t pcf8584_get_s0(pcf8584_t *i2c);
static uint8_t pcf8584_get_s1(pcf8584_t *i2c);
static int pcf8584_bbn_ready(pcf8584_t *i2c);
static int pcf8584_error(int status, uint8_t rdwr, pcf8584_t *i2c);
static void pcf8584_monitor_mode(pcf8584_t *i2c);
static int pcf8584_initchild(dev_info_t *cdip);
static void pcf8584_uninitchild(dev_info_t *cdip);
static void pcf8584_init(pcf8584_t *i2c);
static int pcf8584_setup_regs(dev_info_t *dip, pcf8584_t *i2c);
static void pcf8584_free_regs(pcf8584_t *i2c);
static void pcf8584_reportdev(dev_info_t *dip, dev_info_t *rdip);
static int pcf8584_dip_to_addr(dev_info_t *dip);
static uint_t pcf8584_intr(caddr_t arg);
static int pcf8584_process(pcf8584_t *i2c, uint8_t s1);
int pcf8584_transfer(dev_info_t *dip, i2c_transfer_t *tp);

static void pcf8584_do_polled_io(pcf8584_t *i2c);
static void pcf8584_take_over(pcf8584_t *i2c, dev_info_t *dip,
    i2c_transfer_t *tp, kcondvar_t **waiter, int *saved_mode);
static void pcf8584_give_up(pcf8584_t *i2c, kcondvar_t *waiter, int saved_mode);

static struct bus_ops pcf8584_busops = {
	BUSO_REV,
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	NULL,				/* bus_map_fault */
	ddi_no_dma_map,			/* bus_dma_map */
	ddi_no_dma_allochdl,		/* bus_dma_allochdl */
	ddi_no_dma_freehdl,		/* bus_dma_freehdl */
	ddi_no_dma_bindhdl,		/* bus_dma_bindhdl */
	ddi_no_dma_unbindhdl,		/* bus_unbindhdl */
	ddi_no_dma_flush,		/* bus_dma_flush */
	ddi_no_dma_win,			/* bus_dma_win */
	ddi_no_dma_mctl,		/* bus_dma_ctl */
	pcf8584_bus_ctl,		/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	NULL,				/* bus_get_eventcookie */
	NULL,				/* bus_add_eventcall */
	NULL,				/* bus_remove_eventcall */
	NULL,				/* bus_post_event */
	0,				/* bus_intr_ctl */
	0,				/* bus_config		*/
	0,				/* bus_unconfig		*/
	0,				/* bus_fm_init		*/
	0,				/* bus_fm_fini		*/
	0,				/* bus_fm_access_enter	*/
	0,				/* bus_fm_access_exit	*/
	0,				/* bus_power		*/
	i_ddi_intr_ops			/* bus_intr_op		*/
};

struct cb_ops pcf8584_cb_ops = {
	pcf8584_open,		/* open */
	pcf8584_close,	/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	pcf8584_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_MP | D_NEW		/* Driver compatibility flag */
};

static struct dev_ops pcf8584_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,
	nulldev,
	pcf8584_attach,
	pcf8584_detach,
	nodev,
	&pcf8584_cb_ops,
	&pcf8584_busops,
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module. This one is a driver */
	"I2C Nexus Driver",	/* Name of the module. */
	&pcf8584_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * pcf8584 soft state
 */
static void	*pcf8584_state;

i2c_nexus_reg_t pcf8584_regvec = {
	I2C_NEXUS_REV,
	pcf8584_transfer,
};

/*
 * The "interrupt_priorities" property is how a driver can specify a SPARC
 * PIL level to associate with each of its interrupt properties.  Most
 * self-identifying busses have a better mechanism for managing this, but I2C
 * doesn't.
 */
int	pcf8584_pil = PCF8584_PIL;

#ifdef DEBUG
int pcf8584_print_lvl = 0;
static kmutex_t msg_buf_lock;
static char msg_buff[1024];
#define	PCF8584_DDB(command)	\
	do {			\
		{ command; }	\
		_NOTE(CONSTANTCONDITION)	\
	} while (0)

static void
pcf8584_print(int flags, const char *fmt, ...)
{
	if (flags & pcf8584_print_lvl) {
		va_list ap;

		va_start(ap, fmt);

		if (pcf8584_print_lvl & PRT_PROM) {
			prom_vprintf(fmt, ap);
		} else {
			mutex_enter(&msg_buf_lock);
			(void) vsprintf(msg_buff, fmt, ap);
			if (pcf8584_print_lvl & PRT_BUFFONLY) {
				cmn_err(CE_CONT, "?%s", msg_buff);
			} else {
				cmn_err(CE_CONT, "%s", msg_buff);
			}
			mutex_exit(&msg_buf_lock);
		}
		va_end(ap);
	}
}
#else
#define	PCF8584_DDB(command) \
	do {			\
		{ _NOTE(EMPTY); }	\
		_NOTE(CONSTANTCONDITION)	\
	} while (0)
#endif

#define	PCF8584_IMPL_DELAY(type, delay)	\
	if (type == PIC16F747) {	\
		drv_usecwait(delay);	\
	}

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&pcf8584_state, sizeof (pcf8584_t),
	    PCF8584_INITIAL_SOFT_SPACE);
	if (status != 0) {

		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&pcf8584_state);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	if ((status = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&pcf8584_state);
	}

	return (status);
}

/*
 * The loadable-module _info(9E) entry point
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
pcf8584_dodetach(dev_info_t *dip)
{
	pcf8584_t *i2c;
	int instance = ddi_get_instance(dip);

	i2c = (pcf8584_t *)ddi_get_soft_state(pcf8584_state, instance);

	if ((i2c->pcf8584_attachflags & ADD_INTR) != 0) {
		ddi_remove_intr(dip, 0, i2c->pcf8584_icookie);
	}

	cv_destroy(&i2c->pcf8584_cv);

	if ((i2c->pcf8584_attachflags & IMUTEX) != 0) {
		mutex_destroy(&i2c->pcf8584_imutex);
			cv_destroy(&i2c->pcf8584_icv);
	}
	if ((i2c->pcf8584_attachflags & SETUP_REGS) != 0) {
		pcf8584_free_regs(i2c);
	}
	if ((i2c->pcf8584_attachflags & NEXUS_REGISTER) != 0) {
		i2c_nexus_unregister(dip);
	}
	if ((i2c->pcf8584_attachflags & PROP_CREATE) != 0) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
		    "interrupt-priorities");
	}
	if ((i2c->pcf8584_attachflags & MINOR_NODE) != 0) {
		ddi_remove_minor_node(dip, NULL);
	}

	ddi_soft_state_free(pcf8584_state, instance);
}

static int
pcf8584_doattach(dev_info_t *dip)
{
	pcf8584_t *i2c;
	int instance = ddi_get_instance(dip);

	/*
	 * Allocate soft state structure.
	 */
	if (ddi_soft_state_zalloc(pcf8584_state, instance) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	i2c = (pcf8584_t *)ddi_get_soft_state(pcf8584_state, instance);

	i2c->pcf8584_dip = dip;

	(void) snprintf(i2c->pcf8584_name, sizeof (i2c->pcf8584_name),
	    "%s_%d", ddi_node_name(dip), instance);

	/*
	 * Identify which pcf8584 implementation is being attached to.
	 */
	if (strcmp(ddi_binding_name(i2c->pcf8584_dip), "SUNW,bbc-i2c") == 0) {
		i2c->pcf8584_impl_type = BBC;
		i2c->pcf8584_impl_delay = PCF8584_GENERIC_DELAY;
	} else if (strcmp(ddi_binding_name(i2c->pcf8584_dip),
	    "SUNW,i2c-pic16f747") == 0) {
		i2c->pcf8584_impl_type = PIC16F747;
		i2c->pcf8584_impl_delay = PCF8584_PIC16F747_DELAY;
	} else {
		i2c->pcf8584_impl_type = GENERIC;
		i2c->pcf8584_impl_delay = PCF8584_GENERIC_DELAY;
	}

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    "interrupt-priorities") != 1) {
		(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
		    DDI_PROP_CANSLEEP, "interrupt-priorities",
		    (caddr_t)&pcf8584_pil,
		    sizeof (pcf8584_pil));
		i2c->pcf8584_attachflags |= PROP_CREATE;
	}

	cv_init(&i2c->pcf8584_cv, NULL, CV_DRIVER, NULL);

	if (pcf8584_setup_regs(dip, i2c) != DDI_SUCCESS) {
		goto bad;
	}

	i2c->pcf8584_attachflags |= SETUP_REGS;

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS |
	    DDI_PROP_CANSLEEP, "poll-mode") == 1) {
		i2c->pcf8584_mode = PCF8584_POLL_MODE;
	} else {

		if (ddi_get_iblock_cookie(dip, 0,
		    &i2c->pcf8584_icookie) == DDI_SUCCESS) {
			mutex_init(&i2c->pcf8584_imutex, NULL, MUTEX_DRIVER,
			    (void *)i2c->pcf8584_icookie);
			cv_init(&i2c->pcf8584_icv, NULL, CV_DRIVER, NULL);
			i2c->pcf8584_attachflags |= IMUTEX;

			if (ddi_add_intr(dip, 0, NULL, NULL, pcf8584_intr,
			    (caddr_t)i2c) == DDI_SUCCESS) {
				i2c->pcf8584_attachflags |= ADD_INTR;
				i2c->pcf8584_mode = PCF8584_INTR_MODE;
			} else {
				cmn_err(CE_WARN, "%s failed to add interrupt",
				    i2c->pcf8584_name);
				i2c->pcf8584_mode = PCF8584_POLL_MODE;
			}
		} else {
			cmn_err(CE_WARN, "%s failed to retrieve iblock cookie. "
			    "Operating in POLL MODE only", i2c->pcf8584_name);
			i2c->pcf8584_mode = PCF8584_POLL_MODE;
		}
	}

	/*
	 * For polled mode, still initialize a cv and mutex
	 */
	if ((i2c->pcf8584_attachflags & IMUTEX) == 0) {
		cv_init(&i2c->pcf8584_icv, NULL, CV_DRIVER, NULL);
		mutex_init(&i2c->pcf8584_imutex, NULL, MUTEX_DRIVER, NULL);
		i2c->pcf8584_attachflags |= IMUTEX;
	}

	i2c_nexus_register(dip, &pcf8584_regvec);
	i2c->pcf8584_attachflags |= NEXUS_REGISTER;

	if (ddi_create_minor_node(dip, "devctl", S_IFCHR, instance,
	    DDI_NT_NEXUS, 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed",
		    i2c->pcf8584_name);
		goto bad;
	}

	i2c->pcf8584_attachflags |= MINOR_NODE;

	pcf8584_init(i2c);

	i2c->pcf8584_nexus_dip = dip;

	return (DDI_SUCCESS);

bad:
	pcf8584_dodetach(dip);

	return (DDI_FAILURE);
}

static int
pcf8584_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:

		return (pcf8584_doattach(dip));
	case DDI_RESUME:
		pcf8584_resume(dip);

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}
}

static int
pcf8584_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		pcf8584_dodetach(dip);

		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		pcf8584_suspend(dip);

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
pcf8584_open(dev_t  *devp,  int  flag,  int  otyp,  cred_t *cred_p)
{
	int instance;
	pcf8584_t *i2c;

	/*
	 * Make sure the open is for the right file type
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(*devp);
	i2c = (pcf8584_t *)ddi_get_soft_state(pcf8584_state, instance);
	if (i2c == NULL)
		return (ENXIO);

	/*
	 * Enforce exclusive access
	 */
	mutex_enter(&i2c->pcf8584_imutex);
	if (i2c->pcf8584_open) {
		mutex_exit(&i2c->pcf8584_imutex);

		return (EBUSY);
	} else
		i2c->pcf8584_open = 1;
	mutex_exit(&i2c->pcf8584_imutex);

	return (0);
}

/*ARGSUSED*/
static int
pcf8584_close(dev_t  dev,  int  flag,  int  otyp,  cred_t *cred_p)
{
	int instance;
	pcf8584_t *i2c;

	/*
	 * Make sure the close is for the right file type
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(dev);
	i2c = (pcf8584_t *)ddi_get_soft_state(pcf8584_state, instance);
	if (i2c == NULL)
		return (ENXIO);

	mutex_enter(&i2c->pcf8584_imutex);
	i2c->pcf8584_open = 0;
	mutex_exit(&i2c->pcf8584_imutex);

	return (0);
}

/*ARGSUSED*/
static int
pcf8584_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	pcf8584_t *i2c;
	dev_info_t *self;
	struct devctl_iocdata *dcp;
	int rv;

	i2c = (pcf8584_t *)ddi_get_soft_state(pcf8584_state, getminor(dev));
	if (i2c == NULL)
		return (ENXIO);

	self = (dev_info_t *)i2c->pcf8584_nexus_dip;

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS) {

		return (EFAULT);
	}

	switch (cmd) {
		case DEVCTL_BUS_DEV_CREATE:
			rv = ndi_dc_devi_create(dcp, self, 0, NULL);
			break;
		case DEVCTL_DEVICE_REMOVE:
			rv = ndi_devctl_device_remove(self, dcp, 0);
			break;
		default:
			rv = ENOTSUP;
	}

	ndi_dc_freehdl(dcp);

	return (rv);
}

static int
pcf8584_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op,
    void *arg, void *result)
{
	switch (op) {
	case DDI_CTLOPS_INITCHILD:

		return (pcf8584_initchild((dev_info_t *)arg));
	case DDI_CTLOPS_UNINITCHILD:
		pcf8584_uninitchild((dev_info_t *)arg);

		return (DDI_SUCCESS);
	case DDI_CTLOPS_REPORTDEV:
		pcf8584_reportdev(dip, rdip);

		return (DDI_SUCCESS);
	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
	case DDI_CTLOPS_IOMIN:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_SIDDEV:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_PTOB:
	case DDI_CTLOPS_BTOP:
	case DDI_CTLOPS_BTOPR:
	case DDI_CTLOPS_DVMAPAGESIZE:

		return (DDI_FAILURE);
	default:

		return (ddi_ctlops(dip, rdip, op, arg, result));
	}
}

/*
 * pcf8584_suspend() is called before the system suspends.  Existing
 * transfer in progress or waiting will complete, but new transfers are
 * effectively blocked by "acquiring" the bus.
 */
static void
pcf8584_suspend(dev_info_t *dip)
{
	pcf8584_t *i2c;
	int instance;

	instance = ddi_get_instance(dip);
	i2c = (pcf8584_t *)ddi_get_soft_state(pcf8584_state, instance);

	pcf8584_acquire(i2c, NULL, NULL, B_FALSE);
}

/*
 * pcf8584_resume() is called when the system resumes from CPR.  It releases
 * the hold that was placed on the i2c bus, which allows any real
 * transfers to continue.
 */
static void
pcf8584_resume(dev_info_t *dip)
{
	pcf8584_t *i2c;
	int instance;

	instance = ddi_get_instance(dip);
	i2c = (pcf8584_t *)ddi_get_soft_state(pcf8584_state, instance);

	pcf8584_release(i2c, B_FALSE);

	pcf8584_init(i2c);
}

/*
 * pcf8584_acquire() is called by a thread wishing to "own" the I2C bus.
 * It should not be held across multiple transfers. If the 'force' flag
 * is set, do not try to acquire mutex or do cv_wait.
 */
static void
pcf8584_acquire(pcf8584_t *i2c, dev_info_t *dip, i2c_transfer_t *tp,
    boolean_t force)
{
	if (force) {
		i2c->pcf8584_busy = 1;
		i2c->pcf8584_cur_tran = tp;
		i2c->pcf8584_cur_dip = dip;
		i2c->pcf8584_cur_status = PCF8584_TRANSFER_NEW;
		return;
	}

	mutex_enter(&i2c->pcf8584_imutex);
	while (i2c->pcf8584_busy) {
		cv_wait(&i2c->pcf8584_cv, &i2c->pcf8584_imutex);
	}
	i2c->pcf8584_busy = 1;
	mutex_exit(&i2c->pcf8584_imutex);
	/*
	 * On systems where OBP shares a pcf8584 controller with the
	 * OS, plat_shared_i2c_enter will serialize access to the
	 * pcf8584 controller.  Do not grab this lock during CPR
	 * suspend as the CPR thread also acquires this muxex
	 * through through prom_setprop which causes recursive
	 * mutex enter.
	 *
	 * dip == NULL during CPR.
	 */
	if ((&plat_shared_i2c_enter != NULL) && (dip != NULL)) {
		plat_shared_i2c_enter(i2c->pcf8584_dip);
	}

	mutex_enter(&i2c->pcf8584_imutex);
	i2c->pcf8584_cur_tran = tp;
	i2c->pcf8584_cur_dip = dip;
	mutex_exit(&i2c->pcf8584_imutex);
}

/*
 * pcf8584_release() is called to release a hold made by pcf8584_acquire().
 */
static void
pcf8584_release(pcf8584_t *i2c, boolean_t force)
{
	if (force) {
		i2c->pcf8584_busy = 0;
		i2c->pcf8584_cur_tran = NULL;
		i2c->pcf8584_cur_dip = NULL;
		i2c->pcf8584_cur_status = PCF8584_TRANSFER_OVER;
		cv_signal(&i2c->pcf8584_cv);
		return;
	}

	mutex_enter(&i2c->pcf8584_imutex);
	i2c->pcf8584_busy = 0;
	i2c->pcf8584_cur_tran = NULL;
	cv_signal(&i2c->pcf8584_cv);
	mutex_exit(&i2c->pcf8584_imutex);

	if ((&plat_shared_i2c_exit != NULL) && (i2c->pcf8584_cur_dip != NULL)) {
		plat_shared_i2c_exit(i2c->pcf8584_dip);
	}
}

/*
 * if pcf8584_b_reg exists, it means the current bus controller signals
 * are multiplexed into more than a single bus.  Select the bus needed
 * by writing to the mux register.
 */
static void
pcf8584_select_bus(pcf8584_t *i2c)
{
	int bus;
	pcf8584_ppvt_t *ppvt;

	/*
	 * The existence of pcf8584_b_reg means the bus registers
	 * are multiplexed.
	 */

	PCF8584_DDB(pcf8584_print(PRT_SELECT, "bus multiplex: %X\n",
	    i2c->pcf8584_b_reg));
	if (i2c->pcf8584_b_reg != NULL) {
		ppvt = ddi_get_parent_data(i2c->pcf8584_cur_dip);

		bus = ppvt->pcf8584_ppvt_bus;

		PCF8584_DDB(pcf8584_print(PRT_SELECT,
		    "transmitting bus number %d\n", bus));

		ddi_put8(i2c->pcf8584_b_rhandle, i2c->pcf8584_b_reg, bus);
	}
}

/*
 * pcf8584_type_to_state() converts a transfer type to the
 * next state of the I2C state machine based on the requested
 * transfer type.
 */
static enum tran_state
pcf8584_type_to_state(int i2c_flags)
{
	switch (i2c_flags) {
	case I2C_WR:

		return (TRAN_STATE_WR);
	case I2C_RD:

		return (TRAN_STATE_DUMMY_RD);
	case I2C_WR_RD:

		return (TRAN_STATE_WR_RD);
	}
	/*NOTREACHED*/
	return (TRAN_STATE_NULL);
}

/*
 * pcf8584_put_s1() writes out cmd to register S1.
 */
static void
pcf8584_put_s1(pcf8584_t *i2c, char cmd)
{
	ddi_acc_handle_t hp = i2c->pcf8584_rhandle;
	pcf8584_regs_t *rp = &i2c->pcf8584_regs;

	ddi_put8(hp, rp->pcf8584_regs_s1, cmd);
	PCF8584_IMPL_DELAY(i2c->pcf8584_impl_type,
	    i2c->pcf8584_impl_delay);
	/*
	 * read status to make sure write is flushed
	 */
	(void) ddi_get8(hp, rp->pcf8584_regs_s1);
	PCF8584_IMPL_DELAY(i2c->pcf8584_impl_type,
	    i2c->pcf8584_impl_delay);
}

/*
 * pcf8584_put_s0() writes out data to register S0.
 */
static void
pcf8584_put_s0(pcf8584_t *i2c, char data)
{
	ddi_acc_handle_t hp = i2c->pcf8584_rhandle;
	pcf8584_regs_t *rp = &i2c->pcf8584_regs;

	ddi_put8(hp, rp->pcf8584_regs_s0, data);
	PCF8584_IMPL_DELAY(i2c->pcf8584_impl_type,
	    i2c->pcf8584_impl_delay);
	/*
	 * read status to make sure write is flushed
	 */
	(void) ddi_get8(hp, rp->pcf8584_regs_s1);
	PCF8584_IMPL_DELAY(i2c->pcf8584_impl_type,
	    i2c->pcf8584_impl_delay);
}

/*
 * pcf8584_get_s0() reads from register S0.
 */
static uint8_t
pcf8584_get_s0(pcf8584_t *i2c)
{
	ddi_acc_handle_t hp = i2c->pcf8584_rhandle;
	pcf8584_regs_t *rp = &i2c->pcf8584_regs;
	uint8_t s0;

	s0 = ddi_get8(hp, rp->pcf8584_regs_s0);
	PCF8584_IMPL_DELAY(i2c->pcf8584_impl_type,
	    i2c->pcf8584_impl_delay);

	return (s0);
}

/*
 * pcf8584_get_s1() reads from register S1.
 */
static uint8_t
pcf8584_get_s1(pcf8584_t *i2c)
{
	ddi_acc_handle_t hp = i2c->pcf8584_rhandle;
	pcf8584_regs_t *rp = &i2c->pcf8584_regs;
	uint8_t s1;

	s1 = ddi_get8(hp, rp->pcf8584_regs_s1);
	PCF8584_IMPL_DELAY(i2c->pcf8584_impl_type,
	    i2c->pcf8584_impl_delay);

	return (s1);
}

/*
 * If the previous transaction was a write, the stop
 * bit may not make it out on the wire before
 * the next transaction startes.  And unfortunately, there
 * is no interrupt after the stop bit is written, so this
 * function will poll to make sure the BBC is ready.
 */
static int
pcf8584_bbn_ready(pcf8584_t *i2c)
{
	uint8_t s1;
	int usecwaits = 0;

	s1 = pcf8584_get_s1(i2c);

	while ((s1 & S1_BBN) == 0) {

		if (usecwaits++ == 100) {
			/* Try initializing the bus */
			pcf8584_monitor_mode(i2c);
			pcf8584_put_s1(i2c, S1_STOP);
			delay(1);
			pcf8584_init(i2c);
			(void) pcf8584_get_s0(i2c);
			s1 = pcf8584_get_s1(i2c);
			if (s1 & S1_BBN) {
				cmn_err(CE_WARN,
				    "!%s: cleared bus busy.   addr=0x%x",
				    i2c->pcf8584_name,
				    pcf8584_dip_to_addr(i2c->pcf8584_cur_dip));

				return (I2C_SUCCESS);
			} else {
				cmn_err(CE_WARN,
				    "!%s bus busy after init addr=0x%x",
				    i2c->pcf8584_name,
				    pcf8584_dip_to_addr(i2c->pcf8584_cur_dip));

				return (I2C_FAILURE);
			}
		}
		drv_usecwait(1);
		s1 = pcf8584_get_s1(i2c);
	}

	return (I2C_SUCCESS);
}

static int
pcf8584_error(int status, uint8_t rdwr, pcf8584_t *i2c)
{
	int addr = pcf8584_dip_to_addr(i2c->pcf8584_cur_dip);
	pcf8584_regs_t *rp = &i2c->pcf8584_regs;

	if (status & S1_BER) {
		cmn_err(CE_WARN,
		    "!%s bus error; Controller = 0x%p "
		    " addr = 0x%x", i2c->pcf8584_name,
		    (void *)rp->pcf8584_regs_s1, addr);
		pcf8584_init(i2c);

		return (I2C_FAILURE);
	} else if (status & S1_LAB) {
		cmn_err(CE_WARN, "!%s lost arbitration; Controller ="
		    " 0x%p addr = 0x%x", i2c->pcf8584_name,
		    (void *)rp->pcf8584_regs_s1, addr);
		pcf8584_init(i2c);

		return (I2C_FAILURE);
	} else if ((status & S1_LRB) && (rdwr == I2C_WR)) {
		/*
		 * No error logged here, because this may be benign.
		 * Cf. the "Alert Response Address" feature of SMBUS.
		 */
		pcf8584_put_s1(i2c, S1_STOP);

		return (I2C_FAILURE);
	}

	return (I2C_SUCCESS);
}

static void
pcf8584_monitor_mode(pcf8584_t *i2c)
{
	pcf8584_put_s1(i2c, S1_PIN);

	pcf8584_put_s0(i2c, MONITOR_ADDRESS);
}

static int
pcf8584_initchild(dev_info_t *cdip)
{
	int32_t cell_size;
	int len;
	int32_t regs[2];
	int err;
	pcf8584_ppvt_t *ppvt;
	char name[30];

	PCF8584_DDB(pcf8584_print(PRT_INIT, "pcf8584_initchild enter: %s\n",
	    ddi_node_name(cdip)));

	ppvt = kmem_alloc(sizeof (pcf8584_ppvt_t), KM_SLEEP);

	len = sizeof (cell_size);
	err = ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip,
	    DDI_PROP_CANSLEEP, "#address-cells",
	    (caddr_t)&cell_size, &len);
	if (err != DDI_PROP_SUCCESS || len != sizeof (cell_size)) {

		return (DDI_FAILURE);
	}

	len = sizeof (regs);
	err = ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP,
	    "reg", (caddr_t)regs, &len);
	if (err != DDI_PROP_SUCCESS ||
	    len != (cell_size * sizeof (int32_t))) {

		return (DDI_FAILURE);
	}

	if (cell_size == 1) {
		ppvt->pcf8584_ppvt_addr = regs[0];
		(void) sprintf(name, "%x", regs[0]);
	} else if (cell_size == 2) {
		ppvt->pcf8584_ppvt_bus = regs[0];
		ppvt->pcf8584_ppvt_addr = regs[1];
		(void) sprintf(name, "%x,%x", regs[0], regs[1]);
	} else {

		return (DDI_FAILURE);
	}

	ddi_set_parent_data(cdip, ppvt);

	ddi_set_name_addr(cdip, name);

	PCF8584_DDB(pcf8584_print(PRT_INIT,
	    "pcf8584_initchild SUCCESS: %s\n", ddi_node_name(cdip)));

	return (DDI_SUCCESS);
}

static void
pcf8584_uninitchild(dev_info_t *cdip)
{
	pcf8584_ppvt_t *ppvt;

	ppvt = ddi_get_parent_data(cdip);
	kmem_free(ppvt, sizeof (pcf8584_ppvt_t));

	ddi_set_parent_data(cdip, NULL);
	ddi_set_name_addr(cdip, NULL);

	PCF8584_DDB(pcf8584_print(PRT_INIT, "i2c_uninitchild: %s\n",
	    ddi_node_name(cdip)));
}

static void
pcf8584_init(pcf8584_t *i2c)
{
	uint8_t clk_div = 0x1C;

	pcf8584_put_s1(i2c, S1_PIN);

	pcf8584_put_s0(i2c, S0_OWN);

	pcf8584_put_s1(i2c, S1_PIN | S1_ES1);

	/*
	 * The default case is to set the clock divisor to the least common
	 * denominator to avoid over clocking the I2C bus.  Assume that
	 * BBC based systems are using the Safari clock as input, so select
	 * the clk divisor based on it.
	 */
	if (i2c->pcf8584_impl_type == BBC) {
		dev_info_t *root_node;
		int clock_freq;
		root_node = ddi_root_node();
		clock_freq = ddi_prop_get_int(DDI_DEV_T_ANY, root_node,
		    DDI_PROP_DONTPASS, "clock-frequency", 0);

		if (clock_freq < 105000000) {
			clk_div = 0x00;
		} else if (clock_freq < 160000000) {
			clk_div = 0x10;
		} else {
			clk_div = 0x1C;
		}
	}

	/* set I2C clock speed */
	pcf8584_put_s0(i2c, clk_div);

	pcf8584_put_s1(i2c, S1_PIN | S1_ESO | S1_ACK);

	/*
	 * Multi-Master: Wait for a period of time equal to the
	 * longest I2C message.  This accounts for the case
	 * where multiple controllers and, if this particular one
	 * is "lagging", misses the BB(bus busy) condition.
	 * We wait 200 ms since the longest transaction at this time
	 * on the i2c bus is a 256 byte read from the seprom which takes
	 * about 75 ms. Some additional buffer does no harm to the driver.
	 */

	delay(drv_usectohz(PCF8584_INIT_WAIT));
}

/*
 * pcf8584_setup_regs() is called to map in registers specific to
 * the pcf8584.
 */
static int
pcf8584_setup_regs(dev_info_t *dip, pcf8584_t *i2c)
{
	int nregs;
	ddi_device_acc_attr_t attr;
	caddr_t reg_base;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(dip, 0,
	    (caddr_t *)&reg_base, 0, 0, &attr,
	    &i2c->pcf8584_rhandle) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	/*
	 * If i2c controller is on BBC, then s1 comes before s0.
	 */
	if (i2c->pcf8584_impl_type == BBC) {
		i2c->pcf8584_regs.pcf8584_regs_s0 =
		    (uint8_t *)&reg_base[1];
		i2c->pcf8584_regs.pcf8584_regs_s1 =
		    (uint8_t *)&reg_base[0];
	} else {
		i2c->pcf8584_regs.pcf8584_regs_s0 =
		    (uint8_t *)&reg_base[0];
		i2c->pcf8584_regs.pcf8584_regs_s1 =
		    (uint8_t *)&reg_base[1];
	}

	if (nregs > 1) {
		if (ddi_regs_map_setup(dip,
		    1, (caddr_t *)&i2c->pcf8584_b_reg,
		    0, 0, &attr, &i2c->pcf8584_b_rhandle) !=
		    DDI_SUCCESS) {

			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * pcf8584_free_regs() frees any registers previously
 * allocated.
 */
static void
pcf8584_free_regs(pcf8584_t *i2c)
{
	if (i2c->pcf8584_regs.pcf8584_regs_s0 != NULL) {
		ddi_regs_map_free(&i2c->pcf8584_rhandle);
	}
	if (i2c->pcf8584_b_reg != NULL) {
		ddi_regs_map_free(&i2c->pcf8584_b_rhandle);
	}
}

static void
pcf8584_reportdev(dev_info_t *dip, dev_info_t *rdip)
{
	pcf8584_ppvt_t *ppvt;

	ppvt = ddi_get_parent_data(rdip);

	cmn_err(CE_CONT, "?%s%d at %s%d: addr 0x%x",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ppvt->pcf8584_ppvt_addr);
}

/*
 * i2_nexus_dip_to_addr() takes a dip and returns an I2C address.
 */
static int
pcf8584_dip_to_addr(dev_info_t *dip)
{
	pcf8584_ppvt_t *ppvt;

	ppvt = ddi_get_parent_data(dip);

	return (ppvt->pcf8584_ppvt_addr);
}

/*
 * pcf8584_intr() is the interrupt service routine registered during
 * attach, and remains registered even if the driver is in POLLED mode.  So if
 * this is called from POLLED mode, it needs to return without doing
 * any work to prevent the I2C bus from entering an unknown state.
 */
static uint_t
pcf8584_intr(caddr_t arg)
{
	pcf8584_t *i2c = (pcf8584_t *)arg;
	uint8_t s1;

	ASSERT(i2c->pcf8584_mode != PCF8584_POLL_MODE);
	PCF8584_DDB(pcf8584_print(PRT_INTR, "pcf8584_intr: enter\n"));

	mutex_enter(&i2c->pcf8584_imutex);

	/*
	 * It is necessary to check both whether the hardware is interrupting
	 * and that there is a current transaction for the bus in progress.
	 * Checking just one but not the other will lead to a panic on xcal
	 * since both controllers share the same ino, and also because OBP
	 * shares a controller with the kernel even while the kernel is running.
	 */

	if (i2c->pcf8584_cur_tran == NULL) {
		mutex_exit(&i2c->pcf8584_imutex);

		return (DDI_INTR_UNCLAIMED);
	}


	s1 = pcf8584_get_s1(i2c);
	if (s1 & S1_PIN) {
		mutex_exit(&i2c->pcf8584_imutex);

		return (DDI_INTR_UNCLAIMED);
	}

	if (pcf8584_process(i2c, s1) == I2C_COMPLETE) {
		i2c->pcf8584_tran_state = TRAN_STATE_NULL;
		i2c->pcf8584_cur_status = PCF8584_TRANSFER_OVER;
		cv_signal(&i2c->pcf8584_icv);
	} else
		i2c->pcf8584_cur_status = PCF8584_TRANSFER_ON;

	mutex_exit(&i2c->pcf8584_imutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * Interrupt occurs after a byte is transmitted or received, indicating
 * the device is ready to be serviced.
 */
static int
pcf8584_process(pcf8584_t *i2c, uint8_t s1)
{
	i2c_transfer_t *tp = i2c->pcf8584_cur_tran;
	int addr = pcf8584_dip_to_addr(i2c->pcf8584_cur_dip);
	int dummy_read;

	ASSERT(i2c->pcf8584_tran_state != TRAN_STATE_NULL);

	switch (i2c->pcf8584_tran_state) {
	case TRAN_STATE_DUMMY_DATA:
		PCF8584_DDB(pcf8584_print(PRT_TRAN,
		    "TRAN_STATE_DUMMY DATA: write dummy %x\n", DUMMY_DATA));
		if (pcf8584_error(s1, I2C_RD, i2c) != I2C_SUCCESS) {
			tp->i2c_result = I2C_FAILURE;

			return (I2C_COMPLETE);
		}
		i2c->pcf8584_tran_state = TRAN_STATE_START;
		pcf8584_put_s0(i2c, DUMMY_DATA);

		return (I2C_PENDING);
	case TRAN_STATE_START:
		if (pcf8584_error(s1, I2C_RD, i2c) != I2C_SUCCESS) {
			PCF8584_DDB(pcf8584_print(PRT_TRAN,
			    "TRAN_STATE_START failure\n"));
			tp->i2c_result = I2C_FAILURE;

			return (I2C_COMPLETE);
		}
		i2c->pcf8584_tran_state =
		    pcf8584_type_to_state(tp->i2c_flags);

		/* Set read bit if this is a read transaction */
		if (tp->i2c_flags == I2C_RD) {
			addr |= I2C_READ;
		}
		if (i2c->pcf8584_mode == PCF8584_POLL_MODE)
			pcf8584_put_s1(i2c, S1_START2);
		else
			pcf8584_put_s1(i2c, S1_START2 | S1_ENI);
		pcf8584_put_s0(i2c, addr);
		PCF8584_DDB(pcf8584_print(PRT_TRAN,
		    "TRAN_STATE_START: write addr: %x\n", addr));

		return (I2C_PENDING);
	case TRAN_STATE_WR:

		if (pcf8584_error(s1, I2C_WR, i2c) != I2C_SUCCESS) {
			PCF8584_DDB(pcf8584_print(PRT_TRAN,
			    "TRAN_STATE_WR failure\n"));
			tp->i2c_result = I2C_FAILURE;

			return (I2C_COMPLETE);
		}
		/* check to see if at end of buffer */
		if (tp->i2c_w_resid == 0) {
			pcf8584_put_s1(i2c, S1_STOP);
			PCF8584_DDB(pcf8584_print(PRT_TRAN,
			    "TRAN_STATE_WR: write STOP\n"));

			return (I2C_COMPLETE);
		}

		pcf8584_put_s0(i2c, tp->i2c_wbuf[tp->i2c_wlen -
		    tp->i2c_w_resid--]);
		PCF8584_DDB(pcf8584_print(PRT_TRAN,
		    "TRAN_STATE_WR:  write data %x\n",
		    tp->i2c_wbuf[tp->i2c_wlen - (tp->i2c_w_resid + 1)]));

		return (I2C_PENDING);
	case TRAN_STATE_DUMMY_RD:

		if (pcf8584_error(s1, I2C_WR, i2c) != I2C_SUCCESS) {
			tp->i2c_result = I2C_FAILURE;

			return (I2C_COMPLETE);
		}
		/*
		 * The first read is always a dummy read, because reading S0
		 * is what starts bit shifting and ACK on the I2c bus.
		 * This byte is accessed during the next read, which starts
		 * another 8 bit bus shift.
		 *
		 * special case for 1 byte reads:  Clear the ACK bit
		 * here since this read causes the last and only byte
		 * to be sent on the I2C bus.
		 */
		if (tp->i2c_r_resid  == 1) {
			if (i2c->pcf8584_mode == PCF8584_POLL_MODE)
				pcf8584_put_s1(i2c, S1_ESO);
			else
				pcf8584_put_s1(i2c, S1_ESO | S1_ENI);
		}

		/*
		 * dummy read
		 */
		dummy_read = pcf8584_get_s0(i2c);

		i2c->pcf8584_tran_state = TRAN_STATE_RD;
		PCF8584_DDB(pcf8584_print(PRT_TRAN,
		    "TRAN_STATE_DUMMY_RD: read dummy %d\n", dummy_read));

		return (I2C_PENDING);
	case TRAN_STATE_RD:
		if (pcf8584_error(s1, I2C_RD, i2c) != I2C_SUCCESS) {
			tp->i2c_result = I2C_FAILURE;
			PCF8584_DDB(pcf8584_print(PRT_TRAN,
			    "TRAN_STATE_RD failure\n"));

			return (I2C_COMPLETE);
		}

		/*
		 * If resid == 1, the last byte has already been shifted into
		 * the accumulator.  Send the stop bit.  This also prevents the
		 * last S0 read from shifting in another byte from the I2C bus.
		 */
		if (tp->i2c_r_resid  == 1) {
			pcf8584_put_s1(i2c, S1_STOP);
		}

		/*
		 * If resid == 2, then the next read will cause the I2C bus to
		 * start shifting in the last byte on the I2C bus, which we
		 * don't want to be ACK'd, so clear the ACK bit.
		 */
		if (tp->i2c_r_resid  == 2) {
			if (i2c->pcf8584_mode == PCF8584_POLL_MODE)
				pcf8584_put_s1(i2c, S1_ESO);
			else
				pcf8584_put_s1(i2c, S1_ESO | S1_ENI);
		}

		tp->i2c_rbuf[tp->i2c_rlen - tp->i2c_r_resid] =
		    pcf8584_get_s0(i2c);

		PCF8584_DDB(pcf8584_print(PRT_TRAN,
		    "TRAN_STATE_RD: returning. i2c_rlen = %d "
		    "i2c_r_resid = %d,  data =%x\n", tp->i2c_rlen,
		    tp->i2c_r_resid, tp->i2c_rbuf[tp->i2c_rlen -
		    tp->i2c_r_resid]));

		if (--tp->i2c_r_resid == 0) {

			return (I2C_COMPLETE);
		}

		return (I2C_PENDING);
	case TRAN_STATE_WR_RD:

		if (pcf8584_error(s1, I2C_WR, i2c) != I2C_SUCCESS) {
			tp->i2c_result = I2C_FAILURE;

			return (I2C_COMPLETE);
		}
		if ((s1 & S1_LRB)) {
			pcf8584_put_s1(i2c, S1_STOP);
			PCF8584_DDB(pcf8584_print(PRT_TRAN,
			    "TRAN_STATE_WR_RD sending STOP\n"));

			return (I2C_COMPLETE);
		}
		if (tp->i2c_w_resid != 0) {
			pcf8584_put_s0(i2c, tp->i2c_wbuf[tp->i2c_wlen -
			    tp->i2c_w_resid--]);
			PCF8584_DDB(pcf8584_print(PRT_TRAN,
			    "TRAN_STATE_WR_RD: write data %x\n",
			    tp->i2c_wbuf[tp->i2c_wlen -
			    (tp->i2c_w_resid + 1)]));
		} else {
			if (i2c->pcf8584_mode == PCF8584_POLL_MODE)
				pcf8584_put_s1(i2c, S1_START2);
			else
				pcf8584_put_s1(i2c, S1_START2 | S1_ENI);
			pcf8584_put_s0(i2c, addr | I2C_READ);
			i2c->pcf8584_tran_state =
			    TRAN_STATE_DUMMY_RD;
			PCF8584_DDB(pcf8584_print(PRT_TRAN,
			    "TRAN_STATE_WR_RD: write addr "
			    "%x\n", addr | I2C_READ));
		}

		return (I2C_PENDING);
	default:

		return (I2C_COMPLETE);
	}
}

/*
 * pcf8584_transfer() is the function that is registered with
 * I2C services to be called from pcf8584_transfer() for each transfer.
 *
 * This function starts the transfer, and then waits for the
 * interrupt or polled thread to signal that the transfer has
 * completed.
 */
int
pcf8584_transfer(dev_info_t *dip, i2c_transfer_t *tp)
{
	pcf8584_t *i2c;
	int saved_mode, took_over = 0;
	kcondvar_t *waiter = NULL;
	extern int do_polled_io;

	i2c = (pcf8584_t *)ddi_get_soft_state(pcf8584_state,
	    ddi_get_instance(ddi_get_parent(dip)));

	tp->i2c_r_resid = tp->i2c_rlen;
	tp->i2c_w_resid = tp->i2c_wlen;
	tp->i2c_result = I2C_SUCCESS;

begin:
	/*
	 * If we're explicitly asked to do polled io (or if we are panic'ing),
	 * we need to usurp ownership of the I2C bus, bypassing any other
	 * waiters.
	 */
	if (do_polled_io || ddi_in_panic()) {
		pcf8584_take_over(i2c, dip, tp, &waiter, &saved_mode);
		took_over = 1;
	} else {
		pcf8584_acquire(i2c, dip, tp, B_FALSE);
		mutex_enter(&i2c->pcf8584_imutex);

		/*
		 * See if someone else had intruded and taken over the bus
		 * between the 'pcf8584_acquire' and 'mutex_enter' above.
		 * If so, we'll have to start all over again.
		 */
		if (i2c->pcf8584_cur_tran != tp) {
			mutex_exit(&i2c->pcf8584_imutex);
			goto begin;
		}
	}

	if (pcf8584_bbn_ready(i2c) != I2C_SUCCESS) {
		if (took_over)
			pcf8584_give_up(i2c, waiter, saved_mode);
		else {
			mutex_exit(&i2c->pcf8584_imutex);
			pcf8584_release(i2c, B_FALSE);
		}

		return (tp->i2c_result = I2C_FAILURE);
	}

	/*
	 * Bus selection must be followed by pcf8584_bbn_ready(),
	 * otherwise the bus can be switched before the stop
	 * bit is written out, causing the stop bit to get
	 * sent to the wrong (new) bus.  This causes the
	 * previous bus to permanently hang waiting for the
	 * stop bit.
	 */
	pcf8584_select_bus(i2c);

	i2c->pcf8584_tran_state = TRAN_STATE_DUMMY_DATA;
	pcf8584_put_s0(i2c, DUMMY_ADDR);
	PCF8584_DDB(pcf8584_print(PRT_TRAN,
	    "FIRST WRITE DUMMY ADDR: write %x\n", DUMMY_ADDR));
	if (i2c->pcf8584_mode ==  PCF8584_POLL_MODE)
		pcf8584_put_s1(i2c, S1_START);
	else
		pcf8584_put_s1(i2c, S1_START | S1_ENI);

	/*
	 * Update transfer status so any polled i/o request coming in
	 * after this will complete this transfer for us, before issuing
	 * its own.
	 */
	i2c->pcf8584_cur_status = PCF8584_TRANSFER_ON;

	if (i2c->pcf8584_mode ==  PCF8584_POLL_MODE)
		pcf8584_do_polled_io(i2c);

	if (took_over)
		pcf8584_give_up(i2c, waiter, saved_mode);
	else {
		if (i2c->pcf8584_mode != PCF8584_POLL_MODE)
			cv_wait(&i2c->pcf8584_icv, &i2c->pcf8584_imutex);
		mutex_exit(&i2c->pcf8584_imutex);

		/*
		 * Release the I2C bus only if we still own it. If we don't
		 * own it (someone usurped it from us while we were waiting),
		 * we still need to drop the lock that serializes access to
		 * the pcf8584 controller on systems where OBP shares the
		 * controller with the OS.
		 */
		if (i2c->pcf8584_cur_tran == tp)
			pcf8584_release(i2c, B_FALSE);
		else if (&plat_shared_i2c_exit && dip)
			plat_shared_i2c_exit(i2c->pcf8584_dip);
	}

	return (tp->i2c_result);
}

static void
pcf8584_do_polled_io(pcf8584_t *i2c)
{
	int completed = I2C_PENDING;
	uint8_t s1;

	while (completed != I2C_COMPLETE) {
		s1 = pcf8584_get_s1(i2c);
		if (!(s1 & S1_PIN)) {
			ASSERT(i2c->pcf8584_cur_tran);
			completed = pcf8584_process(i2c, s1);
		}
		drv_usecwait(1);
	}

	i2c->pcf8584_cur_status = PCF8584_TRANSFER_OVER;
}

/*
 * pcf8584_take_over() grabs the I2C bus and other resources by force and
 * flushes any pending transaction. This is called if a polled i/o
 * request comes in.
 */
static void
pcf8584_take_over(pcf8584_t *i2c, dev_info_t *dip, i2c_transfer_t *tp,
    kcondvar_t **waiter, int *saved_mode)
{
	mutex_enter(&i2c->pcf8584_imutex);
	*saved_mode = i2c->pcf8584_mode;
	i2c->pcf8584_mode = PCF8584_POLL_MODE;

	/*
	 * We need to flush out any currently pending transaction before
	 * issuing ours.
	 */
	if (i2c->pcf8584_busy) {
		if (i2c->pcf8584_cur_tran &&
		    i2c->pcf8584_cur_status == PCF8584_TRANSFER_ON) {
			pcf8584_do_polled_io(i2c);
			*waiter = &i2c->pcf8584_icv;
		}
	}

	/*
	 * Since pcf8584_acquire() is by default a good citizen that
	 * will wait its turn to acquire the I2C bus, we need to set
	 * the 'force' flag on.
	 */
	pcf8584_acquire(i2c, dip, tp, B_TRUE);
}

/*
 * pcf8584_give_up() returns all resources that were taken over forcefully
 */
static void
pcf8584_give_up(pcf8584_t *i2c, kcondvar_t *waiter, int saved_mode)
{
	i2c->pcf8584_mode = saved_mode;

	/*
	 * Note that pcf8584_release only wakes up threads waiting to acquire
	 * the I2C bus. We still need to wake up the waiter from whom we
	 * usurped the bus.
	 */
	pcf8584_release(i2c, B_TRUE);
	if (waiter)
		cv_signal(waiter);

	mutex_exit(&i2c->pcf8584_imutex);
}
