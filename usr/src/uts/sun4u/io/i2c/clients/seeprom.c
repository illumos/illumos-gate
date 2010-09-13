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


#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/note.h>
#include <sys/i2c/misc/i2c_svc.h>
#include <sys/i2c/clients/seeprom_impl.h>

/*
 * cb ops
 */
static int seeprom_open(dev_t *, int, int, cred_t *);
static int seeprom_close(dev_t, int, int, cred_t *);
static int seeprom_read(dev_t, struct uio *, cred_t *);
static int seeprom_write(dev_t, struct uio *, cred_t *);
static int seeprom_io(dev_t, struct uio *, int);

/*
 * dev ops
 */
static int seeprom_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int seeprom_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int seeprom_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

static struct cb_ops seeprom_cbops = {
	seeprom_open,			/* open */
	seeprom_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	seeprom_read,			/* read */
	seeprom_write,			/* write */
	nodev,				/* ioctl */
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

static struct dev_ops seeprom_ops = {
	DEVO_REV,
	0,
	seeprom_info,
	nulldev,
	nulldev,
	seeprom_attach,
	seeprom_detach,
	nodev,
	&seeprom_cbops,
	NULL,
	nulldev,
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv seeprom_modldrv = {
	&mod_driverops,	 /* type of module - driver */
	"I2C serial EEPROM device driver",
	&seeprom_ops,
};

static struct modlinkage seeprom_modlinkage = {
	MODREV_1,
	&seeprom_modldrv,
	0
};

/*
 * globals
 */

static void *seepromsoft_statep;

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&seepromsoft_statep,
	    sizeof (struct seepromunit), 1)) != 0)
		return (error);

	if ((error = mod_install(&seeprom_modlinkage)) != 0) {
		ddi_soft_state_fini(&seepromsoft_statep);
		return (error);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&seeprom_modlinkage);
	if (error == 0) {
		ddi_soft_state_fini(&seepromsoft_statep);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&seeprom_modlinkage, modinfop));
}

static int
seeprom_do_attach(dev_info_t *dip)
{
	struct seepromunit *unitp;
	int instance;
	dev_t	dev;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(seepromsoft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s_%d: failed to zalloc softstate",
		    ddi_node_name(dip), instance);

		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(seepromsoft_statep, instance);

	unitp->seeprom_dip = dip;

	(void) snprintf(unitp->seeprom_name, sizeof (unitp->seeprom_name),
	    "%s%d", ddi_driver_name(dip), instance);

	if (ddi_create_minor_node(dip, ddi_node_name(dip), S_IFCHR,
	    instance, SEEPROM_NODE_TYPE, NULL) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed for '%s'",
		    unitp->seeprom_name, ddi_node_name(dip));
		ddi_soft_state_free(seepromsoft_statep, instance);

		return (DDI_FAILURE);
	}

	if (i2c_client_register(dip, &unitp->seeprom_hdl) != I2C_SUCCESS) {
		cmn_err(CE_WARN, "i2c_client_register failed\n");
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(seepromsoft_statep, instance);

		return (DDI_FAILURE);
	}

	if (strcmp(ddi_binding_name(dip), "i2c-at34c02") == 0) {
		unitp->seeprom_addrsize = AT34C02_ADDRSIZE;
		unitp->seeprom_memsize = AT34C02_MEMSIZE;
		unitp->seeprom_pagesize = AT34C02_PAGESIZE;
		unitp->seeprom_pagemask = AT34C02_PAGEMASK;
	} else {
		/*
		 * Default is i2c-at24c64
		 */
		unitp->seeprom_addrsize = AT24C64_ADDRSIZE;
		unitp->seeprom_memsize = AT24C64_MEMSIZE;
		unitp->seeprom_pagesize = AT24C64_PAGESIZE;
		unitp->seeprom_pagemask = AT24C64_PAGEMASK;
	}
	dev = makedevice(DDI_MAJOR_T_UNKNOWN, instance);

	(void) ddi_prop_create(dev, dip, DDI_PROP_CANSLEEP, "size",
	    (caddr_t)&unitp->seeprom_memsize, sizeof (unitp->seeprom_memsize));

	mutex_init(&unitp->seeprom_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&unitp->seeprom_cv, NULL, CV_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
seeprom_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:

		return (seeprom_do_attach(dip));
	case DDI_RESUME:
		/*
		 * No state to restore.
		 */
		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}
}

static int
seeprom_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip))
	struct seepromunit *unitp;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		unitp = ddi_get_soft_state(seepromsoft_statep,
		    getminor((dev_t)arg));
		if (unitp == NULL) {

			return (DDI_FAILURE);
		}
		*result = (void *)unitp->seeprom_dip;

		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)getminor((dev_t)arg);

		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

}

static int
seeprom_do_detach(dev_info_t *dip)
{
	struct seepromunit *unitp;
	int instance;

	instance = ddi_get_instance(dip);
	unitp = ddi_get_soft_state(seepromsoft_statep, instance);
	i2c_client_unregister(unitp->seeprom_hdl);
	ddi_remove_minor_node(dip, NULL);
	mutex_destroy(&unitp->seeprom_mutex);
	cv_destroy(&unitp->seeprom_cv);

	ddi_soft_state_free(seepromsoft_statep, instance);

	return (DDI_SUCCESS);
}

static int
seeprom_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:

		return (seeprom_do_detach(dip));
	case DDI_SUSPEND:
		/*
		 * No state to save.  IO will be blocked by nexus.
		 */
		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}
}

static int
seeprom_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))
	struct seepromunit *unitp;
	int instance;
	int err = 0;

	if (otyp != OTYP_CHR) {

		return (EINVAL);
	}

	instance = getminor(*devp);

	unitp = (struct seepromunit *)
	    ddi_get_soft_state(seepromsoft_statep, instance);

	if (unitp == NULL) {

		return (ENXIO);
	}

	mutex_enter(&unitp->seeprom_mutex);

	if (flags & FEXCL) {
		if (unitp->seeprom_oflag != 0) {
			err = EBUSY;
		} else {
			unitp->seeprom_oflag = FEXCL;
		}
	} else {
		if (unitp->seeprom_oflag == FEXCL) {
			err = EBUSY;
		} else {
			unitp->seeprom_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->seeprom_mutex);

	return (err);
}

static int
seeprom_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))
	struct seepromunit *unitp;
	int instance;

	instance = getminor(dev);

	unitp = (struct seepromunit *)
	    ddi_get_soft_state(seepromsoft_statep, instance);

	if (unitp == NULL) {

		return (ENXIO);
	}

	mutex_enter(&unitp->seeprom_mutex);

	unitp->seeprom_oflag = 0;

	mutex_exit(&unitp->seeprom_mutex);

	return (DDI_SUCCESS);
}

static int
seeprom_read(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	_NOTE(ARGUNUSED(cred_p))
	return (seeprom_io(dev, uiop, B_READ));
}

static int
seeprom_write(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	_NOTE(ARGUNUSED(cred_p))
	return (seeprom_io(dev, uiop, B_WRITE));
}

static int
seeprom_io(dev_t dev, struct uio *uiop, int rw)
{
	struct seepromunit *unitp;
	int instance = getminor(dev);
	int	seeprom_addr;
	int	bytes_to_rw;
	int	err = 0;
	int	current_xfer_len;
	int	actual_data_xfer;
	i2c_transfer_t *i2ctp = NULL;

	unitp = (struct seepromunit *)
	    ddi_get_soft_state(seepromsoft_statep, instance);


	if (unitp == NULL) {
		return (ENXIO);
	}

	if (uiop->uio_offset >= unitp->seeprom_memsize) {
		/*
		 * Exceeded seeprom size.
		 */

		return (ENXIO);
	}

	seeprom_addr = uiop->uio_offset;

	if (uiop->uio_resid == 0) {
		return (0);
	}

	bytes_to_rw = min(uiop->uio_resid,
	    unitp->seeprom_memsize - uiop->uio_offset);
	/*
	 * Serialize access here to prevent a transaction starting
	 * until after 20 ms delay if last operation was a write.
	 */
	mutex_enter(&unitp->seeprom_mutex);
	while ((unitp->seeprom_flags & SEEPROM_BUSY) == SEEPROM_BUSY) {
		if (cv_wait_sig(&unitp->seeprom_cv,
		    &unitp->seeprom_mutex) <= 0) {
			mutex_exit(&unitp->seeprom_mutex);

			return (EINTR);
		}
	}
	unitp->seeprom_flags |= SEEPROM_BUSY;
	mutex_exit(&unitp->seeprom_mutex);

	while ((bytes_to_rw != 0) && (err == 0)) {
		current_xfer_len = min(bytes_to_rw, unitp->seeprom_pagesize -
		    (seeprom_addr & unitp->seeprom_pagemask));

		if (rw == B_WRITE) {
			if (i2ctp == NULL) {
				(void) i2c_transfer_alloc(unitp->seeprom_hdl,
				    &i2ctp,
				    unitp->seeprom_addrsize + current_xfer_len,
				    0,
				    I2C_SLEEP);

				if ((err = uiomove(&i2ctp->i2c_wbuf[
				    unitp->seeprom_addrsize],
				    current_xfer_len, UIO_WRITE, uiop)) != 0) {
					i2c_transfer_free(unitp->seeprom_hdl,
					    i2ctp);
					break;
				}
				i2ctp->i2c_version = I2C_XFER_REV;
				i2ctp->i2c_flags = I2C_WR;
			} else {

				/*
				 * not all bytes were sent in previous attempt.
				 * Adjust the write pointer to the unsent data.
				 */
				/*LINTED*/
				i2ctp->i2c_wbuf += actual_data_xfer;
				/*LINTED*/
				i2ctp->i2c_wlen -= actual_data_xfer;
			}

			if (unitp->seeprom_addrsize == 2) {
				i2ctp->i2c_wbuf[0] = (seeprom_addr >> 8);
				i2ctp->i2c_wbuf[1] = (uchar_t)seeprom_addr;
			} else {
				i2ctp->i2c_wbuf[0] = (uchar_t)seeprom_addr;
			}

			if ((err = i2c_transfer(unitp->seeprom_hdl, i2ctp)) !=
			    I2C_SUCCESS) {
				i2c_transfer_free(unitp->seeprom_hdl, i2ctp);
				break;
			}

			actual_data_xfer = i2ctp->i2c_wlen -
			    i2ctp->i2c_w_resid - unitp->seeprom_addrsize;

			if (i2ctp->i2c_w_resid == 0) {
				i2c_transfer_free(unitp->seeprom_hdl, i2ctp);
				i2ctp = NULL;
			}
			/*
			 * 20 ms(20000 Microsec) delay is required before
			 * issuing another transaction.  This enforces that
			 * wait.
			 */
			delay(drv_usectohz(20000));
		} else {
			/*
			 * SEEPROM read.  First write out the address to read.
			 */
			(void) i2c_transfer_alloc(unitp->seeprom_hdl, &i2ctp,
			    unitp->seeprom_addrsize, current_xfer_len,
			    I2C_SLEEP);
			i2ctp->i2c_version = I2C_XFER_REV;

			if (unitp->seeprom_addrsize == 2) {
				i2ctp->i2c_wbuf[0] = (seeprom_addr >> 8);
				i2ctp->i2c_wbuf[1] = (uchar_t)seeprom_addr;
			} else {
				i2ctp->i2c_wbuf[0] = (uchar_t)seeprom_addr;
			}

			i2ctp->i2c_flags = I2C_WR_RD;

			if ((err = i2c_transfer(unitp->seeprom_hdl, i2ctp)) !=
			    I2C_SUCCESS) {
				i2c_transfer_free(unitp->seeprom_hdl, i2ctp);
				break;
			}

			actual_data_xfer = i2ctp->i2c_rlen - i2ctp->i2c_r_resid;

			err = uiomove(i2ctp->i2c_rbuf, actual_data_xfer,
			    UIO_READ, uiop);
			i2c_transfer_free(unitp->seeprom_hdl, i2ctp);
		}

		bytes_to_rw -= actual_data_xfer;
		seeprom_addr += actual_data_xfer;
	}

	mutex_enter(&unitp->seeprom_mutex);
	unitp->seeprom_flags = 0;
	cv_signal(&unitp->seeprom_cv);
	mutex_exit(&unitp->seeprom_mutex);

	return (err);
}
