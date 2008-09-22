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



#include <sys/param.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/termio.h>
#include <sys/termios.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stropts.h>
#include <sys/strtty.h>
#include <sys/debug.h>
#include <sys/eucioctl.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/kmem.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/obpdefs.h>
#include <sys/conf.h>		/* req. by dev_ops flags MTSAFE etc. */
#include <sys/modctl.h>		/* for modldrv */
#include <sys/stat.h>		/* ddi_create_minor_node S_IFCHR */
#include <sys/open.h>		/* for open params.	 */
#include <sys/uio.h>		/* for read/write */

#include <sys/i2c/misc/i2c_svc.h>
#include <sys/mct_topology.h>
#include <sys/envctrl_gen.h>	/* must be before netract_gen.h	*/
#include <sys/netract_gen.h>
#include <sys/pcf8574_nct.h>
#include <sys/scsb_cbi.h>

#ifdef DEBUG
#define	dbg_print(level, str) cmn_err(level, str);
	static int	pcf8574_debug = 0x00000102;
#else
#define	dbg_print(level, str) {; }
#endif

#define	CV_LOCK(retval)				\
{									\
	mutex_enter(&unitp->umutex);	\
	while (unitp->pcf8574_flags == PCF8574_BUSY) {	\
		if (cv_wait_sig(&unitp->pcf8574_cv,	\
					&unitp->umutex) <= 0) {	\
			mutex_exit(&unitp->umutex);		\
			return (retval);		\
		}							\
	}								\
	unitp->pcf8574_flags = PCF8574_BUSY;	\
	mutex_exit(&unitp->umutex);		\
}

#define	CV_UNLOCK					\
{									\
	mutex_enter(&unitp->umutex);	\
	unitp->pcf8574_flags = 0;		\
	cv_signal(&unitp->pcf8574_cv);	\
	mutex_exit(&unitp->umutex);		\
}

static int nct_p10fan_patch = 0;	/* Fan patch for P1.0 */
static void	*pcf8574_soft_statep;

/*
 * cb ops (only need open,close,read,write,ioctl)
 */
static int	pcf8574_open(dev_t *, int, int, cred_t *);
static int	pcf8574_close(dev_t, int, int, cred_t *);
static int	pcf8574_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	pcf8574_read(dev_t dev, struct uio *uiop, cred_t *cred_p);
static int	pcf8574_chpoll(dev_t, short, int, short *, struct pollhead **);
static uint_t	pcf8574_intr(caddr_t arg);
static int pcf8574_io(dev_t, struct uio *, int);

static struct cb_ops pcf8574_cbops = {
	pcf8574_open,		/* open */
	pcf8574_close,		/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	pcf8574_read,		/* read */
	nodev,				/* write */
	pcf8574_ioctl,		/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	pcf8574_chpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * dev ops
 */
static int pcf8574_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pcf8574_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/* kstat routines */
static int pcf8574_add_kstat(struct pcf8574_unit *, scsb_fru_status_t);
static void pcf8574_delete_kstat(struct pcf8574_unit *);
static int pcf8574_kstat_update(kstat_t *, int);
static int pcf8574_read_chip(struct pcf8574_unit *unitp,
	uint16_t size);
static int pcf8574_write_chip(struct pcf8574_unit *unitp,
	uint16_t size, uint8_t bitpattern);
static int pcf8574_read_props(struct pcf8574_unit *unitp);
static int pcf8574_init_chip(struct pcf8574_unit *unitp, int);
/*
 * SCSB callback function
 */
static void pcf8574_callback(void *, scsb_fru_event_t, scsb_fru_status_t);
extern int scsb_intr_register(uint_t (*intr_handler)(caddr_t), caddr_t,
		fru_id_t);
extern int scsb_intr_unregister(fru_id_t);

extern int nct_i2c_transfer(i2c_client_hdl_t i2c_hdl, i2c_transfer_t *i2c_tran);

static struct dev_ops pcf8574_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,
	nulldev,
	pcf8574_attach,
	pcf8574_detach,
	nodev,
	&pcf8574_cbops,
	NULL,				/* bus_ops */
	NULL,				/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv pcf8574_modldrv = {
	&mod_driverops,		/* type of module - driver */
	"Netract pcf8574 (gpio)",
	&pcf8574_ops,
};

static struct modlinkage pcf8574_modlinkage = {
	MODREV_1,
	&pcf8574_modldrv,
	0
};

/* char _depends_on[] = "misc/i2c_svc drv/scsb"; */

int
_init(void)
{
	register int    error;

	error = mod_install(&pcf8574_modlinkage);
	if (!error) {
		(void) ddi_soft_state_init(&pcf8574_soft_statep,
		    sizeof (struct pcf8574_unit), PCF8574_MAX_DEVS);
	}

	return (error);
}

int
_fini(void)
{
	register int    error;

	error = mod_remove(&pcf8574_modlinkage);
	if (!error)
		ddi_soft_state_fini(&pcf8574_soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pcf8574_modlinkage, modinfop));
}

/*ARGSUSED*/
static int
pcf8574_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	struct pcf8574_unit *unitp;
	register int    instance;
	int err = DDI_SUCCESS;

	instance = getminor(*devp);
	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pcf8574_unit *)
	    ddi_get_soft_state(pcf8574_soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->umutex);

	if (flags & FEXCL) {
		if (unitp->pcf8574_oflag != 0) {
			err = EBUSY;
		} else {
			unitp->pcf8574_oflag = FEXCL;
		}
	} else {
		if (unitp->pcf8574_oflag == FEXCL) {
			err = EBUSY;
		} else {
			unitp->pcf8574_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->umutex);

	return (err);
}

/*ARGSUSED*/
static int
pcf8574_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	struct pcf8574_unit *unitp;
	register int    instance;

#ifdef lint
	flags = flags;
	otyp = otyp;
#endif

	instance = getminor(dev);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pcf8574_unit *)
	    ddi_get_soft_state(pcf8574_soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->umutex);

	unitp->pcf8574_oflag = 0;

	mutex_exit(&unitp->umutex);

	return (DDI_SUCCESS);
}


/*ARGSUSED*/
static int
pcf8574_read(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	return (pcf8574_io(dev, uiop, B_READ));
}

static int
pcf8574_io(dev_t dev, struct uio *uiop, int rw)
{
	struct pcf8574_unit *unitp;
	register int    instance;
	uint16_t	bytes_to_rw;
	int	err = DDI_SUCCESS;

	err = 0;
	instance = getminor(dev);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pcf8574_unit *)
	    ddi_get_soft_state(pcf8574_soft_statep, instance);
	if (unitp == NULL) {
		return (ENXIO);
	}
	if ((bytes_to_rw = uiop->uio_resid) > PCF8574_TRAN_SIZE) {
		return (EINVAL);
	}

	CV_LOCK(EINTR)

	if (rw == B_WRITE) {
		err = uiomove(unitp->i2c_tran->i2c_wbuf,
		    bytes_to_rw, UIO_WRITE, uiop);

		if (!err) {
			err = pcf8574_write_chip(unitp, bytes_to_rw,
			    unitp->writemask);
		}

	} else {
			err = pcf8574_read_chip(unitp, bytes_to_rw);
			if (!err) {
				err = uiomove(unitp->i2c_tran->i2c_rbuf,
				    bytes_to_rw, UIO_READ, uiop);
			}
	}

	CV_UNLOCK
	if (err)
		err = EIO;

	return (err);
}

static int
pcf8574_do_resume(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	struct pcf8574_unit *unitp =
	    ddi_get_soft_state(pcf8574_soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	CV_UNLOCK

	return (DDI_SUCCESS);
}

static int
pcf8574_do_detach(dev_info_t *dip)
{
	struct pcf8574_unit *unitp;
	int instance;
	uint_t attach_flag;

	instance = ddi_get_instance(dip);
	unitp = ddi_get_soft_state(pcf8574_soft_statep, instance);

	attach_flag = unitp->attach_flag;

	if (attach_flag & PCF8574_INTR_ADDED) {
		scsb_intr_unregister((fru_id_t)unitp->props.slave_address);
	}

	if (attach_flag & PCF8574_KSTAT_INIT) {
		pcf8574_delete_kstat(unitp);
	}

	if (attach_flag & PCF8574_LOCK_INIT) {
		mutex_destroy(&unitp->umutex);
		cv_destroy(&unitp->pcf8574_cv);
	}

	scsb_fru_unregister((void *)unitp,
	    (fru_id_t)unitp->props.slave_address);

	if (attach_flag & PCF8574_ALLOC_TRANSFER) {
		/*
		 * restore the lengths to allocated lengths
		 * before freeing.
		 */
		unitp->i2c_tran->i2c_wlen = MAX_WLEN;
		unitp->i2c_tran->i2c_rlen = MAX_RLEN;
		i2c_transfer_free(unitp->pcf8574_hdl, unitp->i2c_tran);
	}

	if (attach_flag & PCF8574_REGISTER_CLIENT) {
		i2c_client_unregister(unitp->pcf8574_hdl);
	}

	if (attach_flag & PCF8574_MINORS_CREATED) {
		ddi_remove_minor_node(dip, NULL);
	}

	if (attach_flag & PCF8574_PROPS_READ) {
		if (unitp->pcf8574_type == PCF8574_ADR_CPUVOLTAGE &&
		    unitp->props.num_chans_used != 0) {
			ddi_prop_free(unitp->props.channels_in_use);
		} else {
			ddi_prop_remove(DDI_DEV_T_NONE, dip,
			    "interrupt-priorities");
		}
	}

	if (attach_flag & PCF8574_SOFT_STATE_ALLOC) {
		ddi_soft_state_free(pcf8574_soft_statep, instance);
	}

	return (DDI_SUCCESS);
}

/*
 * NOTE****
 * The OBP will create device tree node for all I2C devices which
 * may be present in a system. This means, even if the device is
 * not physically present, the device tree node exists. We also
 * will succeed the attach routine, since currently there is no
 * hotplug support in the I2C bus, and the FRUs need to be hot
 * swappable. Only during an I2C transaction we figure out whether
 * the particular I2C device is actually present in the system
 * by looking at the system controller board register. The fantray
 * and power-supply devices may be swapped any time after system
 * reboot, and the way we can make sure that the device is attached
 * to the driver, is by always keeping the driver loaded, and report
 * an error during the actual transaction.
 */
static int
pcf8574_do_attach(dev_info_t *dip)
{
	register struct pcf8574_unit *unitp;
	int instance;
	char name[MAXNAMELEN];
	int		i;
	pcf8574_channel_t *chp;
	scsb_fru_status_t	dev_presence;

	instance = ddi_get_instance(dip);
#ifdef DEBUG
	if (pcf8574_debug & 0x04)
		cmn_err(CE_NOTE, "pcf8574_attach: instance=%d\n",
		    instance);
#endif /* DEBUG */

	if (ddi_soft_state_zalloc(pcf8574_soft_statep, instance) !=
	    DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	unitp = ddi_get_soft_state(pcf8574_soft_statep, instance);

	if (unitp == NULL) {
		ddi_soft_state_free(pcf8574_soft_statep, instance);
		return (DDI_FAILURE);
	}

	unitp->dip = dip;

	unitp->attach_flag = PCF8574_SOFT_STATE_ALLOC;

	if (pcf8574_read_props(unitp) != DDI_PROP_SUCCESS) {
		ddi_soft_state_free(pcf8574_soft_statep, instance);
		return (DDI_FAILURE);
	}

	unitp->attach_flag |= PCF8574_PROPS_READ;

	/*
	 * Set the current operating mode to NORMAL_MODE.
	 */
	unitp->current_mode = ENVCTRL_NORMAL_MODE;

	snprintf(unitp->pcf8574_name, PCF8574_NAMELEN,
	    "%s%d", ddi_driver_name(dip), instance);

	if (unitp->pcf8574_type == PCF8574_TYPE_PWRSUPP) {
		(void) sprintf(name, "pwrsuppply");
		if (ddi_create_minor_node(dip, name, S_IFCHR, instance,
		    PCF8574_NODE_TYPE, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			pcf8574_do_detach(dip);

			return (DDI_FAILURE);
		}
	}
	else
	if (unitp->pcf8574_type == PCF8574_TYPE_FANTRAY) {
		(void) sprintf(name, "fantray");
		if (ddi_create_minor_node(dip, name, S_IFCHR, instance,
		    PCF8574_NODE_TYPE, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			pcf8574_do_detach(dip);

			return (DDI_FAILURE);
		}
	}
	else
	if (unitp->pcf8574_type == PCF8574_TYPE_CPUVOLTAGE) {
		(void) sprintf(name, "cpuvoltage");
		if (ddi_create_minor_node(dip, name, S_IFCHR, instance,
		    PCF8574_NODE_TYPE, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			pcf8574_do_detach(dip);

			return (DDI_FAILURE);
		}
	} else {
		return (DDI_FAILURE);
	}

	unitp->attach_flag |= PCF8574_MINORS_CREATED;

	/*
	 * Now we need read/write masks since all the 8574 bits can be either
	 * read/written, but some ports are intended to be RD/WR only, or RW
	 * If no channels-in-use propoerty, set default values.
	 */
	if (unitp->pcf8574_type == PCF8574_TYPE_FANTRAY) {
		unitp->readmask = PCF8574_FAN_READMASK;
		unitp->writemask = PCF8574_FAN_WRITEMASK;
	}
	if (unitp->pcf8574_type == PCF8574_TYPE_PWRSUPP) {
		unitp->readmask = PCF8574_PS_READMASK;
		unitp->writemask = PCF8574_PS_WRITEMASK;
	}

	for (i = unitp->props.num_chans_used,
	    chp = unitp->props.channels_in_use; i; --i, ++chp) {
		unitp->readmask |= (uint8_t)(
		    (chp->io_dir == I2C_PROP_IODIR_IN ||
		    chp->io_dir == I2C_PROP_IODIR_INOUT) << chp->port);
		unitp->writemask |= (uint8_t)(
		    (chp->io_dir == I2C_PROP_IODIR_OUT ||
		    chp->io_dir == I2C_PROP_IODIR_INOUT) << chp->port);
	}

#ifdef DEBUG
	cmn_err(CE_NOTE, "pcf8574_do_attach: readmask = 0x%x \
		writemask = 0x%x\n", unitp->readmask, unitp->writemask);
#endif /* DEBUG */

	if (i2c_client_register(dip, &unitp->pcf8574_hdl)
	    != I2C_SUCCESS) {
		pcf8574_do_detach(dip);

		return (DDI_FAILURE);
	}
	unitp->attach_flag |= PCF8574_REGISTER_CLIENT;

	/*
	 * Allocate the I2C_transfer structure. The same structure
	 * is used throughout the driver.
	 */
	if (i2c_transfer_alloc(unitp->pcf8574_hdl, &unitp->i2c_tran,
	    MAX_WLEN, MAX_RLEN, KM_SLEEP)
	    != I2C_SUCCESS) {
		pcf8574_do_detach(dip);
		return (DDI_FAILURE);
	}
	unitp->attach_flag |= PCF8574_ALLOC_TRANSFER;

	/*
	 * To begin with we set the mode to I2C_RD.
	 */
	unitp->i2c_tran->i2c_flags = I2C_RD;
	unitp->i2c_tran->i2c_version = I2C_XFER_REV;

	/*
	 * Set the busy flag and open flag to 0.
	 */
	unitp->pcf8574_flags = 0;
	unitp->pcf8574_oflag = 0;

	mutex_init(&unitp->umutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&unitp->pcf8574_cv, NULL, CV_DRIVER, NULL);

	unitp->attach_flag |= PCF8574_LOCK_INIT;

	/*
	 * Register out callback function with the SCSB driver, and save
	 * the returned value to check that the device instance exists.
	 */
	dev_presence = scsb_fru_register(pcf8574_callback, (void *)unitp,
	    (fru_id_t)unitp->props.slave_address);
	if (dev_presence == FRU_NOT_AVAILABLE) {
		scsb_fru_unregister((void *)unitp,
		    (fru_id_t)unitp->props.slave_address);
	}

	/*
	 * Add the kstats. First we need to get the property values
	 * depending on the device type. For example, for the fan
	 * tray there will be a different set of properties, and there
	 * will be another for the powersupplies, and another one for
	 * the CPU voltage monitor. Initialize the kstat structures with
	 * these values.
	 */

	if (pcf8574_add_kstat(unitp, dev_presence) != DDI_SUCCESS) {
		pcf8574_do_detach(dip);

		return (DDI_FAILURE);
	}

	unitp->attach_flag |= PCF8574_KSTAT_INIT;

	/*
	 * Due to observed behavior on Solaris 8, the handler must be
	 * registered before any interrupts are enabled,
	 * in spite of what the ddi_get_iblock_cookie() manual says.
	 * As per the HW/SW spec, by default interrupts are disabled.
	 */

	if (dev_presence == FRU_PRESENT) { /* program the chip */
		pcf8574_init_chip(unitp, 0);   /* Disable intr first */
	}

	if (unitp->pcf8574_canintr == PCF8574_INTR_ON) {
#ifdef DEBUG
		if (pcf8574_debug & 0x0004)
			cmn_err(CE_NOTE, "registering pcf9574 interrupt "
			    "handler");
#endif /* DEBUG */
		if (scsb_intr_register(pcf8574_intr, (void *)unitp,
		    (fru_id_t)unitp->props.slave_address) == DDI_SUCCESS) {
			unitp->pcf8574_canintr |= PCF8574_INTR_ENABLED;
			unitp->attach_flag |= PCF8574_INTR_ADDED;
		} else {
			pcf8574_do_detach(dip);

			return (DDI_FAILURE);
		}
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
pcf8574_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (pcf8574_do_attach(dip));
	case DDI_RESUME:
		return (pcf8574_do_resume(dip));
	default:
		return (DDI_FAILURE);
	}
}

static int
pcf8574_do_suspend(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	struct pcf8574_unit *unitp =
	    ddi_get_soft_state(pcf8574_soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	/*
	 * Set the busy flag so that future transactions block
	 * until resume.
	 */
	CV_LOCK(ENXIO)

	return (DDI_SUCCESS);
}

static int
pcf8574_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (pcf8574_do_detach(dip));
	case DDI_SUSPEND:
		return (pcf8574_do_suspend(dip));
	default:
		return (DDI_FAILURE);
	}
}

static int
pcf8574_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	struct pcf8574_unit	*unitp;
	int		instance;

	instance = getminor(dev);
	if ((unitp = (struct pcf8574_unit *)ddi_get_soft_state(
	    pcf8574_soft_statep, instance)) == NULL) {
		return (ENXIO);
	}
	*reventsp = 0;
	mutex_enter(&unitp->umutex);
	if (unitp->poll_event) {
		*reventsp = unitp->poll_event;
		unitp->poll_event = 0;
	} else if ((events & POLLIN) && !anyyet)
		*phpp = &unitp->poll;
	mutex_exit(&unitp->umutex);
	return (0);
}

/*
 * In normal scenarios, this function should never get called.
 * But, we will still come back and call this function if scsb
 * interrupt sources does not indicate an scsb interrupt. We may
 * come to this situation when SunVTS env4test is independently
 * changing the device registers.
 */
uint_t
pcf8574_intr(caddr_t arg)
{
	int			ic;
	uint8_t value;
	struct pcf8574_unit	*unitp = (struct pcf8574_unit *)(void *)arg;
	scsb_fru_status_t	dev_presence;
	i2c_transfer_t *tp = unitp->i2c_tran;

	ic = DDI_INTR_CLAIMED;
#ifdef DEBUG
	cmn_err(CE_NOTE, " In the interrupt service routine, %x",
	    unitp->props.slave_address);
#endif

	/*
	 * Initiate an I2C transaction to find out
	 * whether this is the device which interrupted.
	 */
	mutex_enter(&unitp->umutex);
	while (unitp->pcf8574_flags == PCF8574_BUSY) {
		if (cv_wait_sig(&unitp->pcf8574_cv, &unitp->umutex) <= 0) {
			mutex_exit(&unitp->umutex);
			return (DDI_INTR_UNCLAIMED);
		}
	}

	unitp->pcf8574_flags = PCF8574_BUSY;
	mutex_exit(&unitp->umutex);

	switch (unitp->pcf8574_type) {
		case PCF8574_TYPE_CPUVOLTAGE: {
			dev_presence = FRU_PRESENT;
			break;
		}
		case PCF8574_TYPE_PWRSUPP: {
			envctrl_pwrsupp_t *envp =
			    (envctrl_pwrsupp_t *)unitp->envctrl_kstat;
			dev_presence = envp->ps_present;
			break;
		}
		case PCF8574_TYPE_FANTRAY: {
			envctrl_fantray_t *envp =
			    (envctrl_fantray_t *)unitp->envctrl_kstat;
			dev_presence = envp->fan_present;
			break;
		}
	}
	if (dev_presence != FRU_PRESENT) {
		ic = DDI_INTR_UNCLAIMED;
		goto intr_exit;
	}
	if (pcf8574_read_chip(unitp, 1) != I2C_SUCCESS) {
		ic = DDI_INTR_UNCLAIMED;
		goto intr_exit;
	}
	value = unitp->i2c_tran->i2c_rbuf[0];
	/*
	 * If interrupt is already masked, return
	 */
	if (value & PCF8574_INTRMASK_BIT) {
		ic = DDI_INTR_UNCLAIMED;
		goto intr_exit;
	}

	/*
	 * In case a fault bit is set, claim the interrupt.
	 */
	switch (unitp->pcf8574_type) {
	case PCF8574_TYPE_PWRSUPP:
	{
		envctrl_pwrsupp_t *envp =
		    (envctrl_pwrsupp_t *)unitp->envctrl_kstat;

		if (PCF8574_PS_FAULT(value) ||
		    PCF8574_PS_TEMPOK(value) ||
		    PCF8574_PS_ONOFF(value) ||
		    PCF8574_PS_FANOK(value)) {

			envp->ps_ok =		PCF8574_PS_FAULT(value);
			envp->temp_ok =		PCF8574_PS_TEMPOK(value);
			envp->psfan_ok =	PCF8574_PS_FANOK(value);
			envp->on_state =	PCF8574_PS_ONOFF(value);
			envp->ps_ver =		PCF8574_PS_TYPE(value);

			tp->i2c_wbuf[0] =
			    PCF8574_PS_DEFAULT | PCF8574_PS_MASKINTR;
			tp->i2c_wlen = 1;
			tp->i2c_rlen = 0;
			tp->i2c_flags = I2C_WR;

			unitp->i2c_status =
			    nct_i2c_transfer(unitp->pcf8574_hdl, tp);

			unitp->poll_event = POLLIN;
			pollwakeup(&unitp->poll, POLLIN);
		} else {
			ic = DDI_INTR_UNCLAIMED;
		}
	}
	break;

	case PCF8574_TYPE_FANTRAY:
	{
		envctrl_fantray_t *envp =
		    (envctrl_fantray_t *)unitp->envctrl_kstat;

		if (!PCF8574_FAN_FAULT(value)) {

			envp->fan_ver = 	PCF8574_FAN_TYPE(value);
			envp->fan_ok = 		PCF8574_FAN_FAULT(value);
			envp->fanspeed =  	PCF8574_FAN_FANSPD(value);

			tp->i2c_wbuf[0] =
			    PCF8574_FAN_DEFAULT | PCF8574_FAN_MASKINTR;
			tp->i2c_wlen = 1;
			tp->i2c_rlen = 0;
			tp->i2c_flags = I2C_WR;

			unitp->i2c_status =
			    nct_i2c_transfer(unitp->pcf8574_hdl, tp);

			unitp->poll_event = POLLIN;
			pollwakeup(&unitp->poll, POLLIN);

		} else {
			ic = DDI_INTR_UNCLAIMED;
		}
	}
	break;

	default:
		ic = DDI_INTR_UNCLAIMED;
	} /* switch */

intr_exit:
	mutex_enter(&unitp->umutex);
	unitp->pcf8574_flags = 0;
	cv_signal(&unitp->pcf8574_cv);
	mutex_exit(&unitp->umutex);

	return (ic);
}

static int
call_copyin(caddr_t arg, struct pcf8574_unit *unitp, int mode)
{
	uchar_t *wbuf;
	uchar_t *rbuf;
	i2c_transfer_t i2ct;
	i2c_transfer_t *i2ctp = unitp->i2c_tran;


	if (ddi_copyin((void *)arg, (caddr_t)&i2ct,
	    sizeof (i2c_transfer_t), mode) != DDI_SUCCESS) {
		return (I2C_FAILURE);
	}

	/*
	 * Save the read and write buffer pointers in the transfer
	 * structure, otherwise these will get overwritten when we
	 * do a bcopy. Restore once done.
	 */

	wbuf = i2ctp->i2c_wbuf;
	rbuf = i2ctp->i2c_rbuf;

	bcopy(&i2ct, i2ctp, sizeof (i2c_transfer_t));

	i2ctp->i2c_wbuf = wbuf;
	i2ctp->i2c_rbuf = rbuf;

	/*
	 * copyin the read and write buffers to the saved buffers.
	 */

	if (i2ct.i2c_wlen != 0) {
		if (ddi_copyin(i2ct.i2c_wbuf, (caddr_t)i2ctp->i2c_wbuf,
		    i2ct.i2c_wlen, mode) != DDI_SUCCESS) {
				return (I2C_FAILURE);
		}
	}

	return (I2C_SUCCESS);
}

static int
call_copyout(caddr_t arg, struct pcf8574_unit *unitp, int mode)
{
	i2c_transfer_t i2ct;
	i2c_transfer_t *i2ctp = unitp->i2c_tran;

	/*
	 * We will copyout the last three fields only, skipping
	 * the remaining ones, before copying the rbuf to the
	 * user buffer.
	 */

	int uskip = sizeof (i2c_transfer_t) - 3*sizeof (int16_t),
	    kskip = sizeof (i2c_transfer_t) - 3*sizeof (int16_t);

	/*
	 * First copyin the user structure to the temporary i2ct,
	 * so that we have the wbuf and rbuf addresses in it.
	 */

	uskip = sizeof (i2c_transfer_t) - 3 * (sizeof (uint16_t));

	/*
	 * copyout the last three out fields now.
	 */

	if (ddi_copyout((void *)((intptr_t)i2ctp+kskip), (void *)
	    ((intptr_t)arg + uskip), 3*sizeof (uint16_t), mode)
	    != DDI_SUCCESS) {
		return (I2C_FAILURE);
		}

	/*
	 * In case we have something to write, get the address of the read
	 * buffer.
	 */

	if (i2ctp->i2c_rlen > i2ctp->i2c_r_resid) {

		if (ddi_copyin((void *)arg, &i2ct,
		    sizeof (i2c_transfer_t), mode) != DDI_SUCCESS) {
			return (I2C_FAILURE);
		}

		/*
		 * copyout the read buffer to the saved user buffer in i2ct.
		 */

		if (ddi_copyout(i2ctp->i2c_rbuf, i2ct.i2c_rbuf,
		    i2ctp->i2c_rlen - i2ctp->i2c_r_resid, mode)
		    != DDI_SUCCESS) {
			return (I2C_FAILURE);
		}
	}

	return (I2C_SUCCESS);
}

/*ARGSUSED*/
static int
pcf8574_ioctl(dev_t dev, int cmd, intptr_t arg,
		int mode, cred_t *credp, int *rvalp)
{
	struct pcf8574_unit *unitp;
	register int    instance;
	int err = 0;
	uint8_t value, inval, outval;
	scsb_fru_status_t dev_presence;

	instance = getminor(dev);

	if (instance < 0) {
		return (ENXIO);
	}
	unitp = (struct pcf8574_unit *)
	    ddi_get_soft_state(pcf8574_soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	dev_presence =
	    scsb_fru_status((uchar_t)unitp->props.slave_address);

	CV_LOCK(EINTR)

	switch (cmd) {
	case ENVC_IOC_INTRMASK:
	if (dev_presence == FRU_NOT_PRESENT) {
		break;
	}

	if (ddi_copyin((caddr_t)arg, (caddr_t)&inval,
	    sizeof (uint8_t), mode) != DDI_SUCCESS) {
		err = EFAULT;
		break;
	}

	if (inval != 0 && inval != 1) {
		err = EINVAL;
	} else {
		unitp->i2c_tran->i2c_wbuf[0] =
		    PCF8574_INT_MASK(inval);
		if (pcf8574_write_chip(unitp, 1, PCF8574_INTRMASK_BIT)
		    != I2C_SUCCESS) {
			err = EFAULT;
		}
	}
	break;

	case ENVC_IOC_SETFAN:
	if (unitp->pcf8574_type != PCF8574_TYPE_FANTRAY) {
		err = EINVAL;
		break;
	}
	if (dev_presence == FRU_NOT_PRESENT) {
		err = EINVAL;
		break;
	}
	if (ddi_copyin((caddr_t)arg, (caddr_t)&inval, sizeof (uint8_t),
	    mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
	}
	if (inval != PCF8574_FAN_SPEED_LOW &&
	    inval != PCF8574_FAN_SPEED_HIGH) {
		err = EINVAL;
		break;
	}

	unitp->i2c_tran->i2c_wbuf[0] = PCF8574_FAN_SPEED(inval);

	if (pcf8574_write_chip(unitp, 1, PCF8574_FANSPEED_BIT)
	    != I2C_SUCCESS) {
		err = EFAULT;
	}
	break;

	case ENVC_IOC_SETSTATUS:
	/*
	 * Allow this ioctl only in DIAG mode.
	 */
	if (unitp->current_mode != ENVCTRL_DIAG_MODE) {
		err = EINVAL;
	} else {
		if (dev_presence == FRU_NOT_PRESENT) {
			err = EINVAL;
			break;
		}
		if (ddi_copyin((caddr_t)arg, (caddr_t)&inval,
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
		} else {
			unitp->i2c_tran->i2c_wbuf[0] = inval & 0xff;
			if (pcf8574_write_chip(unitp, 1, 0xff)
			    != I2C_SUCCESS) {
				err = EFAULT;
			}
		}
	}
	break;

	case ENVC_IOC_GETFAN:
	case ENVC_IOC_GETSTATUS:
	case ENVC_IOC_GETTYPE:
	case ENVC_IOC_GETFAULT:
	case ENVC_IOC_PSTEMPOK:
	case ENVC_IOC_PSFANOK:
	case ENVC_IOC_PSONOFF: {
		if (dev_presence == FRU_NOT_PRESENT) {
			err = EINVAL;
			break;
		}
		if (pcf8574_read_chip(unitp, 1)
		    != I2C_SUCCESS) {
			err = EFAULT;
			break;
		}
		value = unitp->i2c_tran->i2c_rbuf[0];
		if (cmd == ENVC_IOC_GETFAN) {
			if (unitp->pcf8574_type != PCF8574_TYPE_FANTRAY) {
				err = EINVAL;
				break;
			} else {
				outval = PCF8574_FAN_FANSPD(value);
			}
		}
		else
		if (cmd == ENVC_IOC_GETSTATUS) {
			outval = value;
		}
		else
		if (cmd == ENVC_IOC_GETTYPE) {
			if (unitp->pcf8574_type == PCF8574_TYPE_PWRSUPP)
				outval = PCF8574_PS_TYPE(value);
			if (unitp->pcf8574_type == PCF8574_TYPE_FANTRAY)
				outval = PCF8574_FAN_TYPE(value);
		}
		else
		if (cmd == ENVC_IOC_GETFAULT) {
			if (unitp->pcf8574_type == PCF8574_TYPE_PWRSUPP)
				outval = PCF8574_PS_FAULT(value);
			if (unitp->pcf8574_type == PCF8574_TYPE_FANTRAY)
				outval = PCF8574_PS_FAULT(value);
		}
		else
		if (cmd == ENVC_IOC_PSTEMPOK) {
			outval = PCF8574_PS_TEMPOK(value);
		}
		else
		if (cmd == ENVC_IOC_PSFANOK) {
			outval = PCF8574_PS_FANOK(value);
		}
		else
		if (cmd == ENVC_IOC_PSONOFF) {
			outval = PCF8574_PS_ONOFF(value);
		} else {
			outval = 0;
		}

		if (ddi_copyout((caddr_t)&outval, (caddr_t)arg,
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
		}
	}
	break;

	case ENVC_IOC_GETMODE: {
		uint8_t curr_mode = unitp->current_mode;

		if (ddi_copyout((caddr_t)&curr_mode, (caddr_t)arg,
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
		}
		break;
	}

	case ENVC_IOC_SETMODE: {
		uint8_t curr_mode;
		if (ddi_copyin((caddr_t)arg, (caddr_t)&curr_mode,
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
				err = EFAULT;
				break;
		}
		if (curr_mode == ENVCTRL_DIAG_MODE ||
		    curr_mode == ENVCTRL_NORMAL_MODE) {
			unitp->current_mode = curr_mode; /* Don't do anything */
		}
		break;
	}


	case I2CDEV_TRAN:
		if (call_copyin((caddr_t)arg, unitp, mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}
		unitp->i2c_status = err =
		    nct_i2c_transfer(unitp->pcf8574_hdl, unitp->i2c_tran);

		if (err != I2C_SUCCESS) {
			err = EIO;
		} else {
			if (call_copyout((caddr_t)arg, unitp, mode)
			    != DDI_SUCCESS) {
				err = EFAULT;
				break;
			}
		}
		break;

	default:
		err = EINVAL;
	}

	CV_UNLOCK

	return (err);
}

static int
pcf8574_add_kstat(struct pcf8574_unit *unitp, scsb_fru_status_t dev_presence)
{
	char ksname[50];
	int id;
	uint8_t i2c_address = unitp->props.slave_address;

	/*
	 * We create the kstat depending on the device function,
	 * allocate the kstat placeholder and initialize the
	 * values.
	 */
	unitp->envctrl_kstat = NULL;
	switch (unitp->pcf8574_type) {
	case PCF8574_TYPE_CPUVOLTAGE:
	{
		if ((unitp->kstatp = kstat_create(I2C_PCF8574_NAME,
		    unitp->instance, I2C_KSTAT_CPUVOLTAGE, "misc",
		    KSTAT_TYPE_RAW, sizeof (envctrl_cpuvoltage_t),
		    KSTAT_FLAG_PERSISTENT)) != NULL) {

			if ((unitp->envctrl_kstat = kmem_zalloc(
			    sizeof (envctrl_cpuvoltage_t), KM_NOSLEEP)) ==
			    NULL) {
				kstat_delete(unitp->kstatp);
				return (DDI_FAILURE);
			}
		} else {
			return (DDI_FAILURE);
		}

		break;
	}
	case PCF8574_TYPE_PWRSUPP:
	{
		envctrl_pwrsupp_t *envp;
		if (i2c_address == PCF8574_ADR_PWRSUPPLY1) {
			id = 1;
		} else if (i2c_address == PCF8574_ADR_PWRSUPPLY2) {
			id = 2;
		} else  {
			id = i2c_address - PCF8574_ADR_PWRSUPPLY1;
		}
		sprintf(ksname, "%s%d", I2C_KSTAT_PWRSUPPLY, id);
		if ((unitp->kstatp = kstat_create(I2C_PCF8574_NAME,
		    unitp->instance, ksname, "misc",
		    KSTAT_TYPE_RAW, sizeof (envctrl_pwrsupp_t),
		    KSTAT_FLAG_PERSISTENT)) != NULL) {

			if ((unitp->envctrl_kstat = kmem_zalloc(
			    sizeof (envctrl_pwrsupp_t), KM_NOSLEEP)) ==
			    NULL) {
				kstat_delete(unitp->kstatp);
				return (DDI_FAILURE);
			}
			/*
			 * Initialize the kstat fields. Need to initialize
			 * the present field from SCSB info (dev_presence)
			 */
			envp = (envctrl_pwrsupp_t *)unitp->envctrl_kstat;

			envp->ps_present = dev_presence;
			envp->ps_ok = 0;
			envp->temp_ok = 0;
			envp->psfan_ok = 0;
			envp->on_state = 0;
			envp->ps_ver = 0;
		} else {
			return (DDI_FAILURE);
		}

		break;
	}
	case PCF8574_TYPE_FANTRAY:
	{
		envctrl_fantray_t *envp;
		if (i2c_address == PCF8574_ADR_FANTRAY1) {
			id = 1;
		} else if (i2c_address == PCF8574_ADR_FANTRAY2) {
			id = 2;
		} else  {
			id = i2c_address - PCF8574_ADR_FANTRAY1;
		}
		sprintf(ksname, "%s%d", I2C_KSTAT_FANTRAY, id);
		if ((unitp->kstatp = kstat_create(I2C_PCF8574_NAME,
		    unitp->instance, ksname, "misc",
		    KSTAT_TYPE_RAW, sizeof (envctrl_fantray_t),
		    KSTAT_FLAG_PERSISTENT | KSTAT_FLAG_WRITABLE)) != NULL) {

			if ((unitp->envctrl_kstat = kmem_zalloc(
			    sizeof (envctrl_fantray_t), KM_NOSLEEP)) ==
			    NULL) {
				kstat_delete(unitp->kstatp);
				return (DDI_FAILURE);
			}

			/*
			 * Initialize the kstat fields. Need to initialize
			 * the present field from SCSB info (dev_presence)
			 */
			envp = (envctrl_fantray_t *)unitp->envctrl_kstat;

			envp->fan_present = dev_presence;
			envp->fan_ok = 0;
			envp->fanspeed =  PCF8574_FAN_SPEED60;
			envp->fan_ver = 0;
		} else {
			return (DDI_FAILURE);
		}

		break;
	}
	default:
		return (DDI_FAILURE);
	}

	unitp->kstatp->ks_private = (void *)unitp;
	unitp->kstatp->ks_update = pcf8574_kstat_update;

	kstat_install(unitp->kstatp);

	return (DDI_SUCCESS);
}

/*
 * This function reads a single byte from the pcf8574 chip, for use by the
 * kstat routines. The protocol for read will depend on the function.
 */

static int
pcf8574_read_chip(struct pcf8574_unit *unitp, uint16_t size)
{
	int retval, i;
	i2c_transfer_t *tp = unitp->i2c_tran;


	tp->i2c_flags = I2C_RD;
	tp->i2c_rlen = size;
	tp->i2c_wlen = 0;

	/*
	 * Read the bytes from the pcf8574, mask off the
	 * non-read bits and return the value. Block with
	 * the driverwide lock.
	 */
	unitp->i2c_status = retval =
	    nct_i2c_transfer(unitp->pcf8574_hdl, unitp->i2c_tran);

	if (retval != I2C_SUCCESS) {
		return (retval);
	}

	for (i = 0; i < size; i++) {
		tp->i2c_rbuf[i] &= unitp->readmask;
	}

	return (I2C_SUCCESS);
}

/*
 * This function writes a single byte to the pcf8574 chip, for use by the
 * ioctl routines. The protocol for write will depend on the function.
 * The bitpattern tells which bits are being modified, by setting these
 * bits in bitpattern to 1, e.g for fanspeed, bitpattern = 0x08, fanspeed
 * and intr 0x0c, only intr 0x04.
 */

static int
pcf8574_write_chip(struct pcf8574_unit *unitp,
		uint16_t size, uint8_t bitpattern)
{
	i2c_transfer_t *tp = unitp->i2c_tran;
	int i;

		/*
		 * pcf8574_write
		 *
		 * First read the byte, modify only the writable
		 * ports, then write back the modified data.
		 */
		tp->i2c_wlen = 0;
		tp->i2c_rlen = size;
		tp->i2c_flags = I2C_RD;

		unitp->i2c_status = nct_i2c_transfer(unitp->pcf8574_hdl, tp);

		if (unitp->i2c_status != I2C_SUCCESS) {
			return (I2C_FAILURE);
		}

		/*
		 * Our concern is when we have to write only a few bits.
		 * We need to make sure we write the same value to those
		 * bit positions which does not appear in bitpattern.
		 */

		/*
		 * 1) Ignore all bits than the one we are writing
		 * 2) Now 0 the bits we intend to modify in the value
		 * read from the chip, preserving all others.
		 * 3) Now turn all non-writable ( read only/reserved )
		 * bits to 1. The value now should contain:
		 * 1 			in all non-writable bits.
		 * 0 			in the bis(s) we intend to modify.
		 * no change 	in the writable bits we don't modify.
		 * 4) Now OR it with the bits we got before, i.e. after
		 * ignoring all bits other than one we are writing.
		 */

		for (i = 0; i < size; i++) {
			tp->i2c_rbuf[i] &= ~(bitpattern);

			tp->i2c_rbuf[i] |= ~(unitp->writemask);

			tp->i2c_wbuf[i] = tp->i2c_rbuf[i] |
			    (tp->i2c_wbuf[i] & bitpattern);
		}

		tp->i2c_rlen = 0;
		tp->i2c_wlen = size;
		tp->i2c_flags = I2C_WR;

		unitp->i2c_status = nct_i2c_transfer(unitp->pcf8574_hdl, tp);

		return (unitp->i2c_status);
}

static int
pcf8574_kstat_update(kstat_t *ksp, int rw)
{
	struct pcf8574_unit *unitp;
	char *kstatp;
	uint8_t value;
	int err = DDI_SUCCESS;
	scsb_fru_status_t	dev_presence;

	unitp = (struct pcf8574_unit *)ksp->ks_private;
	if (unitp->envctrl_kstat == NULL) { /* May be detaching */
		return (err);
	}

	CV_LOCK(EINTR)

	/*
	 * Need to call scsb to find whether device is present.
	 * For I2C devices, the I2C address is used as a FRU ID.
	 */
	if (unitp->pcf8574_type == PCF8574_TYPE_CPUVOLTAGE) {
		dev_presence = FRU_PRESENT;
	} else {
		dev_presence =
		    scsb_fru_status((uchar_t)unitp->props.slave_address);
	}

	kstatp = (char *)ksp->ks_data;

	/*
	 * We could have write on the power supply and the fantray
	 * pcf8574 chips. For masking the interrupt on both, or
	 * controlling the fan speed on the fantray. But write
	 * will not be allowed through the kstat interface. For
	 * the present field, call SCSB.
	 */

	if (rw == KSTAT_WRITE) {
		if (unitp->pcf8574_type != PCF8574_TYPE_FANTRAY) {
			err = EACCES;
			goto kstat_exit;
		}
		value = ((envctrl_fantray_t *)kstatp)->fanspeed;
		if (value != PCF8574_FAN_SPEED_LOW &&
		    value != PCF8574_FAN_SPEED_HIGH) {
			err = EINVAL;
			goto kstat_exit;
		}

		unitp->i2c_tran->i2c_wbuf[0] = PCF8574_FAN_SPEED(value);

		if (dev_presence == FRU_PRESENT &&
		    pcf8574_write_chip(unitp, 1, PCF8574_FANSPEED_BIT)
		    != I2C_SUCCESS) {
			err = EFAULT;
			goto kstat_exit;
		}

	} else {
		/*
		 * First make sure that the FRU exists by checking the SCSB
		 * dev_presence info.  If not present, set the change field,
		 * clear the kstat fields and make sure the kstat *_present
		 * field is set to dev_presence from the SCSB driver.
		 */
		if (dev_presence == FRU_PRESENT &&
		    pcf8574_read_chip(unitp, 1) != I2C_SUCCESS) {
			/*
			 * Looks like a real IO error.
			 */
			err = EIO;
			CV_UNLOCK

			return (err);
		}
		if (dev_presence == FRU_PRESENT)
			value = unitp->i2c_tran->i2c_rbuf[0];
		else
			value = 0;

		switch (unitp->pcf8574_type) {
		case PCF8574_TYPE_CPUVOLTAGE: {
			envctrl_cpuvoltage_t *envp =
			    (envctrl_cpuvoltage_t *)unitp->envctrl_kstat;
			envp->value = value;
			bcopy((caddr_t)envp, kstatp,
			    sizeof (envctrl_cpuvoltage_t));

			break;
		}
		case PCF8574_TYPE_PWRSUPP: {
			envctrl_pwrsupp_t *envp =
			    (envctrl_pwrsupp_t *)unitp->envctrl_kstat;

			envp->ps_present = 	dev_presence;
			envp->ps_ok =		PCF8574_PS_FAULT(value);
			envp->temp_ok =		PCF8574_PS_TEMPOK(value);
			envp->psfan_ok =	PCF8574_PS_FANOK(value);
			envp->on_state =	PCF8574_PS_ONOFF(value);
			envp->ps_ver =		PCF8574_PS_TYPE(value);

			bcopy((caddr_t)envp, kstatp,
			    sizeof (envctrl_pwrsupp_t));

			break;
		}
		case PCF8574_TYPE_FANTRAY: {
			envctrl_fantray_t *envp =
			    (envctrl_fantray_t *)unitp->envctrl_kstat;

			envp->fan_present = dev_presence;
			envp->fan_ver = 	PCF8574_FAN_TYPE(value);
			envp->fan_ok = 		PCF8574_FAN_FAULT(value);
			envp->fanspeed =  	PCF8574_FAN_FANSPD(value);

			bcopy((caddr_t)unitp->envctrl_kstat, kstatp,
			    sizeof (envctrl_fantray_t));

			break;
		}

		default:
			break;
		}
	}

kstat_exit:

	CV_UNLOCK

	return (err);
}

static void
pcf8574_delete_kstat(struct pcf8574_unit *unitp)
{
	/*
	 * Depending on the function, deallocate the correct
	 * kernel allocated memory.
	 */
	if (unitp->kstatp != NULL) {
		kstat_delete(unitp->kstatp);
	}

	switch (unitp->pcf8574_type) {
	case PCF8574_TYPE_CPUVOLTAGE: {
		if (unitp->envctrl_kstat != NULL) {
			kmem_free(unitp->envctrl_kstat,
			    sizeof (envctrl_cpuvoltage_t));
		}
		break;
	}
	case PCF8574_TYPE_PWRSUPP: {
		if (unitp->envctrl_kstat != NULL) {
			kmem_free(unitp->envctrl_kstat,
			    sizeof (envctrl_pwrsupp_t));
		}

		break;
	}
	case PCF8574_TYPE_FANTRAY: {
		if (unitp->envctrl_kstat != NULL) {
			kmem_free(unitp->envctrl_kstat,
			    sizeof (envctrl_fantray_t));
		}
		break;
	}
	default:
		break;
	}

	unitp->envctrl_kstat = NULL;
}

static int
pcf8574_read_props(struct pcf8574_unit *unitp)
{
	dev_info_t *dip = unitp->dip;
	int retval = 0, prop_len;
	uint32_t  *prop_value = NULL;
	uint8_t i2c_address;
	char *function;

	/*
	 * read the pcf8574_function property. If this property is not
	 * found, return ERROR. Else, make sure it's either powersupply
	 * or fantray.
	 */

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "pcf8574_function", &function) != DDI_SUCCESS) {
		dbg_print(CE_WARN, "Couldn't find pcf8574_function property");

		return (DDI_FAILURE);
	}

	if (strcmp(function, "fantray") == 0) {
		unitp->pcf8574_type = PCF8574_TYPE_FANTRAY;
		/*
		 * Will fail the fantray attach if patch - 1.
		 */
		if (nct_p10fan_patch) {
#ifdef DEBUG
		cmn_err(CE_WARN, "nct_p10fan_patch set: will not load "
		    "fantary:address %x,%x", unitp->props.i2c_bus,
		    unitp->props.slave_address);
#endif
			ddi_prop_free(function);
			return (DDI_FAILURE);
		}
	} else
	if (strcmp(function, "powersupply") == 0) {
		unitp->pcf8574_type = PCF8574_TYPE_PWRSUPP;
	} else {
		dbg_print(CE_WARN, "Neither powersupply nor fantray");
		ddi_prop_free(function);

		return (DDI_FAILURE);
	}

	ddi_prop_free(function);

	retval = ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP,
	    "reg", (caddr_t)&prop_value, &prop_len);
	if (retval == DDI_PROP_SUCCESS) {
		unitp->props.i2c_bus		= (uint16_t)prop_value[0];
		unitp->props.slave_address	= i2c_address =
		    (uint8_t)prop_value[1];
		kmem_free(prop_value, prop_len);

		if (i2c_address>>4 == 7)
			unitp->sensor_type = PCF8574A;
		else if (i2c_address>>4 == 4)
			unitp->sensor_type = PCF8574;
		else {
			unitp->sensor_type = PCF8574A;
			dbg_print(CE_WARN, "Not a pcf8574/a device");
		}

	} else {
		unitp->props.i2c_bus		= (uint16_t)-1;
		unitp->props.slave_address	= (uint16_t)-1;
	}

	/*
	 * Get the Property information that the driver will be using
	 * see typedef struct pcf8574_properties_t;
	 */

	unitp->pcf8574_canintr = 0;
	retval = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupts", -1);
	if (retval >= 0) {
		int prop_len, intr_pri = 4;
		unitp->pcf8574_canintr |= PCF8574_INTR_ON;
		if (ddi_getproplen(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "interrupt-priorities",
		    &prop_len) == DDI_PROP_NOT_FOUND) {
			retval = ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, "interrupt-priorities",
			    (caddr_t)&intr_pri, sizeof (int));
#ifdef DEBUG
			if (retval != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "Failed to create interrupt- \
				priorities property, retval %d", retval);
			}
#endif /* DEBUG */
		}
	}

	/*
	 * No channels-in-use property for the fan and powersupplies.
	 */
	unitp->props.num_chans_used = 0;
	if (i2c_address == PCF8574_ADR_CPUVOLTAGE) {
		if (ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "channels-in-use", &prop_len) == DDI_PROP_SUCCESS) {
			retval = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY,
			    dip, DDI_PROP_DONTPASS,
			    "channels-in-use",
			    (uchar_t **)&unitp->props.channels_in_use,
			    &unitp->props.num_chans_used);
			if (retval != DDI_PROP_SUCCESS) {
				unitp->props.num_chans_used = 0;
			} else {
				unitp->props.num_chans_used /=
				    sizeof (pcf8574_channel_t);
			}
		}
	}

	return (DDI_PROP_SUCCESS);
}

/*
 * callback function to register with the SCSB driver in order to be
 * informed about changes in device instance presence.
 */
/*ARGSUSED*/
void
pcf8574_callback(void *softstate, scsb_fru_event_t cb_event,
		scsb_fru_status_t dev_presence)
{
	struct pcf8574_unit *unitp = (struct pcf8574_unit *)softstate;
#ifdef DEBUG
		if (pcf8574_debug & 0x00800001)
			cmn_err(CE_NOTE, "pcf8574_callback(unitp,%d,%d)",
			    (int)cb_event, (int)dev_presence);
#endif /* DEBUG */

	switch (unitp->pcf8574_type) {
		case PCF8574_TYPE_CPUVOLTAGE: {
			/*
			 * This Unit is not Field Replacable and will not
			 * generate any events at the SCB.
			 */
			break;
		}
		case PCF8574_TYPE_PWRSUPP: {
			envctrl_pwrsupp_t *envp;

			envp = (envctrl_pwrsupp_t *)unitp->envctrl_kstat;
			if (dev_presence == FRU_NOT_PRESENT) {
				envp->ps_ok = 0;
				envp->temp_ok = 0;
				envp->psfan_ok = 0;
				envp->on_state = 0;
				envp->ps_ver = 0;
			} else
			if (dev_presence == FRU_PRESENT &&
			    envp->ps_present == FRU_NOT_PRESENT) {
				pcf8574_init_chip(unitp, 0);
			}
			envp->ps_present = dev_presence;
			unitp->poll_event = POLLIN;
			pollwakeup(&unitp->poll, POLLIN);
			break;
		}
		case PCF8574_TYPE_FANTRAY: {
			envctrl_fantray_t *envp;

			envp = (envctrl_fantray_t *)unitp->envctrl_kstat;

			if (dev_presence == FRU_NOT_PRESENT) {
				envp->fan_ok = 0;
				envp->fanspeed =  PCF8574_FAN_SPEED60;
				envp->fan_ver = 0;
			} else
			if (dev_presence == FRU_PRESENT &&
			    envp->fan_present == FRU_NOT_PRESENT) {
				pcf8574_init_chip(unitp, 0);
			}
			envp->fan_present = dev_presence;
			unitp->poll_event = POLLIN;
			pollwakeup(&unitp->poll, POLLIN);
			break;
		}
	}
}

/*
 * Initializes the chip after attach or after being inserted.
 * intron = 0 => disable interrupt.
 * intron = 1 => read register, enable interrupt if no fault.
 */

static int
pcf8574_init_chip(struct pcf8574_unit *unitp, int intron)
{
	int ret = I2C_SUCCESS;
	i2c_transfer_t *tp = unitp->i2c_tran;
	uint8_t value = 0;
	boolean_t device_faulty = B_FALSE; /* true is faulty */

	if (unitp->pcf8574_type != PCF8574_TYPE_PWRSUPP &&
	    unitp->pcf8574_type != PCF8574_TYPE_FANTRAY) {
		return (ret);
	}
	switch (unitp->pcf8574_type) {
	case PCF8574_TYPE_PWRSUPP:
		tp->i2c_wbuf[0] = PCF8574_PS_DEFAULT;

		break;
	case PCF8574_TYPE_FANTRAY:
			tp->i2c_wbuf[0] = PCF8574_FAN_DEFAULT;

		break;
	default:
		break;
	}

	/*
	 * First, read the device. If the device is faulty, it does
	 * not make sense to enable the interrupt, so in this case
	 * keep interrupt maskked inspite of what "intron" says.
	 */

	tp->i2c_wlen = 0;
	tp->i2c_rlen = 1;
	tp->i2c_flags = I2C_RD;

	unitp->i2c_status = ret = nct_i2c_transfer(unitp->pcf8574_hdl, tp);

	if (ret != I2C_SUCCESS) {
		return (ret);
	}

	value = tp->i2c_rbuf[0];

	switch (unitp->pcf8574_type) {
	case PCF8574_TYPE_PWRSUPP:
	{
		envctrl_pwrsupp_t *envp =
		    (envctrl_pwrsupp_t *)unitp->envctrl_kstat;

		envp->ps_ok    = PCF8574_PS_FAULT(value);
		envp->temp_ok  = PCF8574_PS_TEMPOK(value);
		envp->psfan_ok = PCF8574_PS_FANOK(value);
		envp->on_state = PCF8574_PS_ONOFF(value);
		envp->ps_ver   = PCF8574_PS_TYPE(value);

		if (envp->ps_ok || envp->temp_ok ||
		    envp->psfan_ok || envp->on_state)
			device_faulty = B_TRUE;

		break;
	}
	case PCF8574_TYPE_FANTRAY:
	{
		envctrl_fantray_t *envp =
		    (envctrl_fantray_t *)unitp->envctrl_kstat;

		envp->fan_ver  = PCF8574_FAN_TYPE(value);
		envp->fan_ok   = PCF8574_FAN_FAULT(value);
		envp->fanspeed = PCF8574_FAN_FANSPD(value);

		if (!envp->fan_ok)
			device_faulty = B_TRUE; /* remember, 0 is faulty */

		break;
	}
	default:
		break;
	}
	/*
	 * Mask interrupt, if intron = 0.
	 */
	if (!intron || device_faulty == B_TRUE) {
		tp->i2c_wbuf[0] |= PCF8574_INTRMASK_BIT;
	}

	tp->i2c_wlen = 1;
	tp->i2c_rlen = 0;
	tp->i2c_flags = I2C_WR;

	unitp->i2c_status = nct_i2c_transfer(unitp->pcf8574_hdl, tp);

	return (unitp->i2c_status);
}
