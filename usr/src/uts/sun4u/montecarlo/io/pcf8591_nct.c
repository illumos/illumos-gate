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
 * I2C leaf driver for the PCF8591
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
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/uio.h>

#include <sys/i2c/misc/i2c_svc.h>
#include <sys/envctrl_gen.h>
#include <sys/netract_gen.h>
#include <sys/pcf8591_nct.h>


/*
 * 		CONTROL OF CHIP
 * PCF8591 Temp sensing control register definitions
 *
 * ---------------------------------------------
 * | 0 | AOE | X | X | 0 | AIF | X | X |
 * ---------------------------------------------
 * AOE = Analog out enable.. not used on out implementation
 * 5 & 4 = Analog Input Programming.. see data sheet for bits..
 *
 * AIF = Auto increment flag
 * bits 1 & 0 are for the Chennel number.
 */


#define	I2CTRANS_DATA	0
#define	I2CRAW_DATA	1
#define	TEMP_TABLE_SIZE	256

#define	SHUTDOWN_TEMP_MIN	55
#define	SHUTDOWN_TEMP_MAX	85

#ifdef DEBUG
#define	dbg_print(level, str) cmn_err(level, str);
#else
#define	dbg_print(level, str) {; }
#endif


extern int nct_i2c_transfer(i2c_client_hdl_t i2c_hdl, i2c_transfer_t *i2c_tran);
static uchar_t _cpu_temps[TEMP_TABLE_SIZE + 4];	/* see attach */

static void *pcf8591_soft_statep;

/*
 * cb ops (only need ioctl)
 */
static int pcf8591_open(dev_t *, int, int, cred_t *);
static int pcf8591_close(dev_t, int, int, cred_t *);
static int pcf8591_read(dev_t dev, struct uio *uiop, cred_t *cred_p);
static int pcf8591_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops pcf8591_cbops = {
	pcf8591_open,			/* open */
	pcf8591_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	pcf8591_read,			/* read */
	nodev,				/* write */
	pcf8591_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * dev ops
 */
static int pcf8591_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int pcf8591_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pcf8591_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/* kstat routines */
static int pcf8591_add_kstats(struct pcf8591_unit *);
static void pcf8591_delete_kstats(struct pcf8591_unit *);
static int pcf8591_temp_kstat_update(kstat_t *, int);
static int pcf8591_read_chip(struct pcf8591_unit *, uint8_t, int);
static int pcf8591_read_props(struct pcf8591_unit *unitp);

static struct dev_ops pcf8591_ops = {
	DEVO_REV,
	0,
	pcf8591_info,
	nulldev,
	nulldev,
	pcf8591_attach,
	pcf8591_detach,
	nodev,
	&pcf8591_cbops,
	NULL,
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv pcf8591_modldrv = {
	&mod_driverops,		/* type of module - driver */
	"Netract pcf8591 (adio)",
	&pcf8591_ops,
};

static struct modlinkage pcf8591_modlinkage = {
	MODREV_1,
	&pcf8591_modldrv,
	0
};

char	_depends_on[] = "misc/i2c_svc";

int	pcf8591_debug = 0x02;
static uint8_t translate_cputemp(uint8_t value);

int
_init(void)
{
	register int    error;

	error = mod_install(&pcf8591_modlinkage);
	if (error == 0) {
		(void) ddi_soft_state_init(&pcf8591_soft_statep,
		    sizeof (struct pcf8591_unit), PCF8591_MAX_DEVS);
	}

	return (error);
}

int
_fini(void)
{
	register int    error;

	error = mod_remove(&pcf8591_modlinkage);
	if (error == 0) {
		ddi_soft_state_fini(&pcf8591_soft_statep);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pcf8591_modlinkage, modinfop));
}

/*ARGSUSED*/
static int
pcf8591_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int err = 0;
	struct pcf8591_unit *unitp;
	minor_t minor = getminor(*devp);

	int instance = PCF8591_MINOR_TO_DEVINST(minor);
	int channel = PCF8591_MINOR_TO_CHANNEL(minor);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pcf8591_unit *)
	    ddi_get_soft_state(pcf8591_soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->umutex);

	if (flags & FEXCL) {
		if (unitp->pcf8591_oflag[channel] != 0) {
			err = EBUSY;
		} else {
			unitp->pcf8591_oflag[channel] = FEXCL;
		}
	} else {
		if (unitp->pcf8591_oflag[channel] == FEXCL) {
			err = EBUSY;
		} else {
			unitp->pcf8591_oflag[channel] = FOPEN;
		}
	}

	mutex_exit(&unitp->umutex);

	return (err);
}

/*ARGSUSED*/
static int
pcf8591_close(dev_t devp, int flags, int otyp, cred_t *credp)
{
	struct pcf8591_unit *unitp;
	minor_t minor = getminor(devp);

	int instance = PCF8591_MINOR_TO_DEVINST(minor);
	int channel = PCF8591_MINOR_TO_CHANNEL(minor);

#ifdef lint
	flags = flags;
	otyp = otyp;
#endif

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pcf8591_unit *)
	    ddi_get_soft_state(pcf8591_soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->umutex);

	unitp->pcf8591_oflag[channel] = 0;

	mutex_exit(&unitp->umutex);

	return (DDI_SUCCESS);
}

static int
pcf8591_io(dev_t dev, struct uio *uiop, int rw)
{
	int err = 0;
	struct pcf8591_unit *unitp;
	minor_t minor = getminor(dev);

	int instance = PCF8591_MINOR_TO_DEVINST(minor);
	int channel = PCF8591_MINOR_TO_CHANNEL(minor);

	int		bytes_to_rw;
	int		translate = 0;

	/*
	 * At this point we don't have a write operation to pcf8591.
	 */
	if (rw == B_WRITE) {
		return (EACCES);
	}

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pcf8591_unit *)
	    ddi_get_soft_state(pcf8591_soft_statep, instance);
	if (unitp == NULL) {
		return (ENXIO);
	}

	if ((bytes_to_rw = uiop->uio_resid) > PCF8591_TRAN_SIZE) {
		return (EINVAL);
	}

	/*
	 * Need to serialize all read operations, since there is a single
	 * i2c_transfer_t structure allocated for all read and write ops.
	 * We can't share the i2c bus among multiple transactions anyway,
	 * so this does not affect performance.
	 */
	mutex_enter(&unitp->umutex);
	while (unitp->pcf8591_flags == PCF8591_BUSY) {
		if (cv_wait_sig(&unitp->pcf8591_cv, &unitp->umutex) <= 0) {
			mutex_exit(&unitp->umutex);

			return (EINTR);
		}
	}
	unitp->pcf8591_flags = PCF8591_BUSY;
	mutex_exit(&unitp->umutex);

	if (bytes_to_rw == 1)
		translate = 1;
	/*
	 * Event sequence:
	 * 1. set up the control register write, for now we'll always read
	 *    channel 0, which is the only active 8591 port on the Nordica
	 *    TODO: We'll need a minor node for each port that is used.
	 * 2. increment read count to read the throw-away byte
	 * 3. start the write/read of control/data registers
	 * 4. throw the first byte away
	 * 5. then return the data
	 */

	unitp->i2c_tran->i2c_flags = I2C_WR_RD;
	unitp->i2c_tran->i2c_wlen = 1;
	unitp->i2c_tran->i2c_wbuf[0] = (unitp->pcf8591_inprog |
	    channel);
	/*
	 * read extra byte to throw away the first, (PCF8591 datasheet)
	 */
	unitp->i2c_tran->i2c_rlen = bytes_to_rw + 1;

	if (nct_i2c_transfer(unitp->pcf8591_hdl,
	    unitp->i2c_tran) != I2C_SUCCESS) {
		err = EIO;
	} else {
		/*
		 * Throw away the first byte according to PCF8591 datasheet
		 * If translating, use the second byte.
		 */
		if (translate) {
			unitp->i2c_tran->i2c_rbuf[0] =
			    translate_cputemp(unitp->i2c_tran->i2c_rbuf[1]);
		} else {
			unitp->i2c_tran->i2c_rbuf[0] =
			    unitp->i2c_tran->i2c_rbuf[1];
			unitp->i2c_tran->i2c_rbuf[1] = 0;
		}

		err = uiomove(unitp->i2c_tran->i2c_rbuf,
		    bytes_to_rw,
		    UIO_READ,
		    uiop);
	}
	mutex_enter(&unitp->umutex);
	unitp->pcf8591_flags = 0;
	cv_signal(&unitp->pcf8591_cv);
	mutex_exit(&unitp->umutex);

	return (err);
}

/*ARGSUSED*/
static int
pcf8591_read(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	return (pcf8591_io(dev, uiop, B_READ));
}

static int
call_copyin(caddr_t arg, struct pcf8591_unit *unitp, int mode)
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
call_copyout(caddr_t arg, struct pcf8591_unit *unitp, int mode)
{
	i2c_transfer_t i2ct;
	i2c_transfer_t *i2ctp = unitp->i2c_tran;
	uint16_t  i2c_actlen;

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

	if (i2ctp->i2c_rlen - i2ctp->i2c_r_resid > 0) {

	if (ddi_copyin((void *)arg, &i2ct,
	    sizeof (i2c_transfer_t), mode) != DDI_SUCCESS) {
		return (I2C_FAILURE);
	}

	/*
	 * copyout the read buffer to the saved user buffer in i2ct.
	 */

		i2c_actlen = i2ctp->i2c_rlen - i2ctp->i2c_r_resid;
		if (ddi_copyout(i2ctp->i2c_rbuf, i2ct.i2c_rbuf,
		    i2c_actlen, mode) != DDI_SUCCESS) {
				return (I2C_FAILURE);
			}
		}

	return (I2C_SUCCESS);
}

/*
 * The ioctls will use the same name as the Javelin ioctls. We
 * will have a very restricted set for MC, and unlike Javelin
 * will not have a envctrl_chip structure to return values
 * from the driver. All we will have is a uint8_t value to
 * get or set values from the driver. Also, unlike the Javelin,
 * where 'index' is used to specify the input port from where
 * temperature is collected, here different minor nodes will be
 * created by the driver for each port, eliminating the need for
 * 'index' - leaving us with only the value to pass.
 */

/*ARGSUSED*/
static int
pcf8591_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
		cred_t *credp, int *rvalp)
{
	int err = 0;
	struct pcf8591_unit *unitp;
	minor_t minor = getminor(dev);

	int instance = PCF8591_MINOR_TO_DEVINST(minor);
	int channel = PCF8591_MINOR_TO_CHANNEL(minor);

	unitp = (struct pcf8591_unit *)
	    ddi_get_soft_state(pcf8591_soft_statep, instance);

	mutex_enter(&unitp->umutex);
	while (unitp->pcf8591_flags == PCF8591_BUSY) {
		if (cv_wait_sig(&unitp->pcf8591_cv, &unitp->umutex) <= 0) {
			mutex_exit(&unitp->umutex);

			return (EINTR);
		}
	}
	unitp->pcf8591_flags = PCF8591_BUSY;
	mutex_exit(&unitp->umutex);

	switch (cmd) {

	case ENVC_IOC_GETTEMP: {
		/*
		 * Read the status byte from pcf8591 chip. The value will
		 * be already converted to Celcius by translate_cputemp.
		 */
		pcf8591_read_chip(unitp, channel, 1);
		if (ddi_copyout(unitp->i2c_tran->i2c_rbuf,
		    (caddr_t)arg, sizeof (uint8_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
		}
		break;
	}

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

	/* Testing, may be removed */
	case I2CDEV_TRAN:
		if (call_copyin((caddr_t)arg, unitp, mode) != I2C_SUCCESS) {
			err = EFAULT;
			break;
		}
		if (nct_i2c_transfer(unitp->pcf8591_hdl, unitp->i2c_tran)
		    != I2C_SUCCESS) {
			err = EFAULT;
			break;
		}
		if (call_copyout((caddr_t)arg, unitp, mode) != I2C_SUCCESS) {
			err = EFAULT;
			break;
		}
		break;

	/*
	 * TESTING TRANSLATION from "adc" "table" property
	 * translate thermistor index into temp Celcius
	 */
	case I2CDEV_GETTEMP: {
		struct i2c_transfer *tp;
		if (call_copyin((caddr_t)arg, unitp, mode) != I2C_SUCCESS) {
			err = EFAULT;
			break;
		}
		tp = unitp->i2c_tran;
		if (tp->i2c_rlen != 1) {
			err = EINVAL;
			break;
		}
		/*
		 * Throw away the first byte according to PCF8591 datasheet,
		 * so read two bytes
		 */
		tp->i2c_rlen = 2;
		if (nct_i2c_transfer(unitp->pcf8591_hdl, unitp->i2c_tran)
		    != I2C_SUCCESS) {
			err = EFAULT;
			break;
		}
#ifdef DEBUG
		if (pcf8591_debug & 0x0010)
			cmn_err(CE_NOTE,
			    "pcf8591_ioctl: i2c_rlen=%d; "
			    "i2c_rbuf[0,1]=0x%x,0x%x\n",
			    tp->i2c_rlen, tp->i2c_rbuf[0], tp->i2c_rbuf[1]);
#endif /* DEBUG */
		/*
		 * Throw away the first byte according to PCF8591 datasheet
		 */
		if ((tp->i2c_rbuf[0] = translate_cputemp(tp->i2c_rbuf[1]))
		    == 0) {
			err = EINVAL;
			break;
		}
		tp->i2c_rbuf[1] = 0;

		if (call_copyout((caddr_t)arg, unitp, mode) != I2C_SUCCESS) {
			err = EFAULT;
			break;
		}
		break;
	}

	case I2CDEV_GETTABLES: {
		break;
	}
	default:
		err = EINVAL;
	}

	mutex_enter(&unitp->umutex);
	unitp->pcf8591_flags = 0;
	cv_signal(&unitp->pcf8591_cv);
	mutex_exit(&unitp->umutex);

	return (err);
}

static int
pcf8591_do_detach(dev_info_t *dip)
{
	register struct pcf8591_unit *unitp;
	int instance;
	uint_t attach_flag;

	instance = ddi_get_instance(dip);
	unitp = ddi_get_soft_state(pcf8591_soft_statep, instance);
	attach_flag = unitp->attach_flag;

	if (attach_flag & PCF8591_KSTAT_INIT) {
		pcf8591_delete_kstats(unitp);
	}

	if (attach_flag & PCF8591_LOCK_INIT) {
		mutex_destroy(&unitp->umutex);
		cv_destroy(&unitp->pcf8591_cv);
	}

	/*
	 * Restore the lengths of the rbuf and wbuf, which was originally
	 * allocated so that the appropriate amount of rbuf and wbuf are
	 * freed.
	 */
	if (attach_flag & PCF8591_ALLOC_TRANSFER) {
		unitp->i2c_tran->i2c_wlen = MAX_WLEN;
		unitp->i2c_tran->i2c_rlen = MAX_RLEN;
		i2c_transfer_free(unitp->pcf8591_hdl, unitp->i2c_tran);
	}

	if (attach_flag & PCF8591_REGISTER_CLIENT) {
		i2c_client_unregister(unitp->pcf8591_hdl);
	}

	if (attach_flag & PCF8591_MINORS_CREATED) {
		ddi_remove_minor_node(dip, NULL);
	}

	/*
	 * Free the memory allocated for the properties.
	 */
	if (attach_flag & PCF8591_PROPS_READ) {
		ddi_prop_free(unitp->props.name);
		if (unitp->props.num_chans_used) {
			ddi_prop_free(unitp->props.channels_in_use);
		}

		if (unitp->props.channels_description) {
			ddi_prop_free(unitp->props.channels_description);
		}
	}

	if (attach_flag & PCF8591_SOFT_STATE_ALLOC) {
		ddi_soft_state_free(pcf8591_soft_statep, instance);
	}

	return (DDI_SUCCESS);
}

static int
pcf8591_do_suspend(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	struct pcf8591_unit *unitp = (struct pcf8591_unit *)
	    ddi_get_soft_state(pcf8591_soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	/*
	 * Set the busy flag so that future transactions block
	 * until resume.
	 */
	mutex_enter(&unitp->umutex);
	while (unitp->pcf8591_flags == PCF8591_BUSY) {
		if (cv_wait_sig(&unitp->pcf8591_cv,
		    &unitp->umutex) <= 0) {
			mutex_exit(&unitp->umutex);

			return (DDI_FAILURE);
		}
	}
	unitp->pcf8591_flags = PCF8591_BUSY;
	mutex_exit(&unitp->umutex);

	return (DDI_SUCCESS);
}

static int
pcf8591_do_resume(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	struct pcf8591_unit *unitp = (struct pcf8591_unit *)
	    ddi_get_soft_state(pcf8591_soft_statep, instance);
	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->umutex);
	unitp->pcf8591_flags = 0;
	cv_signal(&unitp->pcf8591_cv);
	mutex_exit(&unitp->umutex);

	return (DDI_SUCCESS);
}

static int
pcf8591_do_attach(dev_info_t *dip)
{
	register struct pcf8591_unit *unitp;
	int i, instance;
	char name[MAXNAMELEN];
	minor_t minor;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(pcf8591_soft_statep, instance) != 0) {
		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(pcf8591_soft_statep, instance);

	if (unitp == NULL) {
		return (DDI_FAILURE);
	}

	unitp->dip = dip;

	unitp->attach_flag = PCF8591_SOFT_STATE_ALLOC;

	if (pcf8591_read_props(unitp) != DDI_PROP_SUCCESS) {
		pcf8591_do_detach(dip);

		return (DDI_FAILURE);
	}

	unitp->attach_flag |= PCF8591_PROPS_READ;

	/*
	 * Set the current operating mode to NORMAL_MODE.
	 */
	unitp->current_mode = ENVCTRL_NORMAL_MODE; /* normal mode */

	snprintf(unitp->pcf8591_name, PCF8591_NAMELEN,
	    "%s%d", ddi_driver_name(dip), instance);

	/*
	 * Create a minor node corresponding to channel 0 to 3
	 */
	for (i = 0; i < PCF8591_MAX_CHANS; i++) {
	if (i == 0) {
		(void) sprintf(name, "cputemp");
	} else {
		(void) sprintf(name, "%d", i);
	}
	minor = PCF8591_MINOR_NUM(instance, i);
	if (ddi_create_minor_node(dip, name, S_IFCHR, minor,
	    PCF8591_NODE_TYPE, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			pcf8591_do_detach(dip);

			return (DDI_FAILURE);
		}
	}

	unitp->attach_flag |= PCF8591_MINORS_CREATED;

	if (i2c_client_register(dip, &unitp->pcf8591_hdl)
	    != I2C_SUCCESS) {
		pcf8591_do_detach(dip);

		return (DDI_FAILURE);
	}

	unitp->attach_flag |= PCF8591_REGISTER_CLIENT;

	/*
	 * We allocate a single i2c_transfer_t structure for all
	 * i2c transactions.
	 */
	if (i2c_transfer_alloc(unitp->pcf8591_hdl, &unitp->i2c_tran,
	    MAX_WLEN, MAX_RLEN, KM_SLEEP) != I2C_SUCCESS) {
		pcf8591_do_detach(dip);

		return (DDI_FAILURE);
	}

	unitp->attach_flag |= PCF8591_ALLOC_TRANSFER;

	/*
	 * The flags will be set to I2C_WR because for all reads from
	 * the 8591 we need to also write the control byte.
	 */
	unitp->i2c_tran->i2c_flags = I2C_WR;
	unitp->i2c_tran->i2c_version = I2C_XFER_REV;


	/*
	 * Set the analog programming mode to default. Upper nibble
	 * in control byte. Four single ended inputs, output not enabled.
	 */
	unitp->pcf8591_inprog = PCF8591_4SINGLE | PCF8591_ANALOG_INPUT_EN;

	/*
	 * Set the open flag for each channel to 0.
	 */
	for (i = 0; i < PCF8591_MAX_CHANS; i++) {
		unitp->pcf8591_oflag[i] = 0;
	}

	/*
	 * Set the busy flag to 0.
	 */
	unitp->pcf8591_flags = 0;

	mutex_init(&unitp->umutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&unitp->pcf8591_cv, NULL, CV_DRIVER, NULL);

	unitp->attach_flag |= PCF8591_LOCK_INIT;

	if (pcf8591_add_kstats(unitp) != DDI_SUCCESS) {
		pcf8591_do_detach(dip);

		return (DDI_FAILURE);
	}

	unitp->attach_flag |= PCF8591_KSTAT_INIT;

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
pcf8591_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = PCF8591_MINOR_TO_DEVINST(getminor(dev));
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
pcf8591_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (pcf8591_do_attach(dip));
	case DDI_RESUME:
		return (pcf8591_do_resume(dip));
	default:
		return (DDI_FAILURE);
	}
}

static int
pcf8591_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (pcf8591_do_detach(dip));
	case DDI_SUSPEND:
		return (pcf8591_do_suspend(dip));
	default:
		return (DDI_FAILURE);
	}
}

static uint8_t
translate_cputemp(uint8_t value)
{
	return (_cpu_temps[value]);
}

static int
pcf8591_add_kstats(struct pcf8591_unit *unitp)
{
	if ((unitp->tempksp = kstat_create(I2C_PCF8591_NAME,
	    unitp->instance, I2C_KSTAT_CPUTEMP, "misc",
	    KSTAT_TYPE_RAW, sizeof (unitp->temp_kstats),
	    KSTAT_FLAG_PERSISTENT | KSTAT_FLAG_WRITABLE)) == NULL) {

		return (DDI_FAILURE);
	}

	/*
	 * The kstat fields are already initialized in the attach routine..
	 */

	unitp->tempksp->ks_update = pcf8591_temp_kstat_update;
	unitp->tempksp->ks_private = (void *)unitp;

	strcpy(unitp->temp_kstats.label,
	    unitp->props.channels_description[0]);
	unitp->temp_kstats.type = ENVC_NETRACT_CPU_SENSOR;

	kstat_install(unitp->tempksp);

	return (DDI_SUCCESS);
}

static void
pcf8591_delete_kstats(struct pcf8591_unit *unitp)
{
	kstat_delete(unitp->tempksp);
}

static int
pcf8591_temp_kstat_update(kstat_t *ksp, int rw)
{
	struct pcf8591_unit *unitp;
	char *kstatp;
	int err = 0;
	int channel = 0;
	int warn_temp = 0;
	int shutdown_temp = 0;

	unitp = (struct pcf8591_unit *)ksp->ks_private;

	mutex_enter(&unitp->umutex);
	while (unitp->pcf8591_flags == PCF8591_BUSY) {
		if (cv_wait_sig(&unitp->pcf8591_cv,
		    &unitp->umutex) <= 0) {
			mutex_exit(&unitp->umutex);

			return (EINTR);
		}
	}

	unitp->pcf8591_flags = PCF8591_BUSY;
	mutex_exit(&unitp->umutex);

	kstatp = (char *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {

		/* check for the size of buffer */
		if (ksp->ks_data_size != sizeof (unitp->temp_kstats)) {
			err = EIO;
			goto bail;
		}

		warn_temp = ((envctrl_temp_t *)kstatp)->warning_threshold;
		shutdown_temp = ((envctrl_temp_t *)kstatp)->shutdown_threshold;

		if (shutdown_temp < SHUTDOWN_TEMP_MIN || shutdown_temp >
		    SHUTDOWN_TEMP_MAX) {
			err = EIO;
			goto bail;
		}

		if (warn_temp < 0 || shutdown_temp <= warn_temp) {
			err = EIO;
			goto bail;
		}

		/* write into kstat fields */
		unitp->temp_kstats.warning_threshold = warn_temp;
		unitp->temp_kstats.shutdown_threshold = shutdown_temp;

	} else {

		pcf8591_read_chip(unitp, channel, 1);
		unitp->temp_kstats.value =
		    unitp->i2c_tran->i2c_rbuf[0];
		bcopy((caddr_t)&unitp->temp_kstats, kstatp,
		    sizeof (unitp->temp_kstats));
	}

bail:

	mutex_enter(&unitp->umutex);
	unitp->pcf8591_flags = 0;
	cv_signal(&unitp->pcf8591_cv);
	mutex_exit(&unitp->umutex);

	return (err);
}

static int
pcf8591_read_chip(struct pcf8591_unit *unitp, uint8_t channel,
int size)
{
	int retval = I2C_SUCCESS;

	/*
	 * We need to read an extra byte, since as per specification
	 * the first byte read should be discarded.
	 */
	i2c_transfer_t *tp = unitp->i2c_tran;
	tp->i2c_flags = I2C_WR_RD;
	tp->i2c_rlen = size+1;
	tp->i2c_wlen = 1;
	tp->i2c_wbuf[0] = (unitp->pcf8591_inprog |
	    channel);

	retval = nct_i2c_transfer(unitp->pcf8591_hdl, tp);
	if (retval == I2C_SUCCESS) {
		tp->i2c_rbuf[0] = translate_cputemp(tp->i2c_rbuf[1]);
	}

	if (tp->i2c_rbuf[0] == 0) {
		retval = I2C_FAILURE;
	}

	return (retval);
}

/*
 * Reads the properties of the pcf8591 device.
 */
static int
pcf8591_read_props(struct pcf8591_unit *unitp)
{
	dev_info_t *dip = unitp->dip;
	int i, retval = 0, prop_len;
	int instance = ddi_get_instance(dip);
	int warning_temp, shutdown_temp;
	uint32_t *prop_value = NULL;
	uchar_t *creg_prop;
	char *function;
	uint_t		tblsz;

#ifdef lint
	instance = instance;
#endif
	/*
	 * Check for the pcf8591_function property, and make sure it's
	 * cputemp.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "pcf8591_function", &function) != DDI_SUCCESS) {
		dbg_print(CE_WARN, "Couldn't find pcf8591_function property");

		return (DDI_FAILURE);
	}

	if (strcmp(function, "cputemp") != 0) {
		dbg_print(CE_WARN, "pcf8591_function is not cputemp");
		ddi_prop_free(function);

		return (DDI_FAILURE);
	}

	ddi_prop_free(function);

	retval = ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "name", &unitp->props.name);
	if (retval != DDI_PROP_SUCCESS) {

		return (retval);
	}
#ifdef DEBUG
	else if (pcf8591_debug & 0x02)
		cmn_err(CE_NOTE,
		    "pcf8591_read_props:ddi_prop_lookup_string(%s): \
			found  %s ", "name", unitp->props.name);
#endif /* DEBUG */

	retval = ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP,
	    "reg", (caddr_t)&prop_value, &prop_len);
	if (retval == DDI_PROP_SUCCESS) {
		unitp->props.i2c_bus		= (uint16_t)prop_value[0];
		unitp->props.slave_address	= (uint16_t)prop_value[1];
		kmem_free(prop_value, prop_len);
#ifdef DEBUG
		if (pcf8591_debug & 0x02)
			cmn_err(CE_NOTE,
			    "pcf8591:ddi_getlongprop(%s) returns %d,"
			    " i2c_bus,slave=0x%x,0x%x",
			    "reg", retval,  unitp->props.i2c_bus,
			    unitp->props.slave_address);
#endif /* DEBUG */
	} else {
		unitp->props.i2c_bus		= (uint16_t)-1;
		unitp->props.slave_address	= (uint16_t)-1;
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "pcf8591_read_props:ddi_getlongprop(%s) returns %d,"
		    " default it to 0x%x:0x%X",
		    "reg", retval,  unitp->props.i2c_bus,
		    unitp->props.slave_address);
#endif /* DEBUG */
	}
	ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "channels-in-use", &prop_len);
	retval = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS,
	    "channels-in-use",
	    (uchar_t **)&unitp->props.channels_in_use,
	    &unitp->props.num_chans_used);
	if (retval == DDI_PROP_SUCCESS) {
		unitp->props.num_chans_used /= sizeof (pcf8591_channel_t);
	} else {
		unitp->props.num_chans_used = 0;
	}

#ifdef DEBUG
	if (pcf8591_debug & 0x0002)
		cmn_err(CE_NOTE,
		    "pcf8591_read_props:ddi_prop_lookup_byte_array(%s)"
		    "returns %d\n"
		    "\t\tlength=%d, #elements=%d",
		    "channels-in-use", retval,
		    prop_len, unitp->props.num_chans_used);
#endif /* DEBUG */

	retval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "channels-description",
	    (char ***)&unitp->props.channels_description,
	    (uint_t *)&prop_len);

	if (retval != DDI_PROP_SUCCESS) {
		prop_len = 0;
		unitp->props.channels_description = NULL;
	}

#ifdef DEBUG
	if (pcf8591_debug & 0x0002) {
		cmn_err(CE_NOTE,
		    "pcf8591_read_props:ddi_prop_lookup_string_array(%s)"
		    "returns %d, length=%d",
		    "channels-description", retval, prop_len);
		for (i = 0; i < prop_len; ++i) {
			cmn_err(CE_NOTE, "channels-description[%d]=<%s>",
			    i, unitp->props.channels_description[i]);
		}
	}
#endif /* DEBUG */

	/*
	 * The following code was borrowed from envctrltwo.c
	 * I haven't yet investigated why the copy target is index + 2
	 */
	retval = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "tables", &creg_prop, (uint_t *)&prop_len);

	if (retval != DDI_PROP_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "%s%d: Unable to read pcf8591 tables property",
		    ddi_get_name(dip), instance);
#endif /* DEBUG */

		return (DDI_NOT_WELL_FORMED);
	}

	tblsz = (sizeof (_cpu_temps) / sizeof (uchar_t));
	if (prop_len <= tblsz) {
		for (i = 0; i < prop_len; i++) {
			_cpu_temps[i] = creg_prop[i];
		}
	}
#ifdef DEBUG
	if (pcf8591_debug & 0x0002)
		cmn_err(CE_NOTE, "pcf8591_read_props: _cpu_temps size=%d; "
		    "tables prop_len=%d\n", tblsz, prop_len);
#endif /* DEBUG */

	ddi_prop_free(creg_prop);

	/*
	 * Read shutdown temp and warning temp properties.
	 */
	warning_temp = (int)ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "warning-temp", PCF8591_WARNING_TEMP);

	shutdown_temp = (int)ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "shutdown-temp", PCF8591_SHUTDOWN_TEMP);

	/*
	 * Fill up the warning and shutdown temp values in kstat structure.
	 */
	unitp->temp_kstats.warning_threshold = warning_temp;
	unitp->temp_kstats.shutdown_threshold = shutdown_temp;

	return (DDI_PROP_SUCCESS);
}
