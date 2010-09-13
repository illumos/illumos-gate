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
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/mode.h>
#include <sys/note.h>
#include <sys/i2c/clients/i2c_gpio.h>
#include <sys/i2c/clients/pca9556_impl.h>

/*
 * The PCA9556 is a gpio chip with 8 I/O ports.  The ports may be controlled by
 * an 8 bit input  port register, 8 bit output port register, 8 bit polarity
 * inversion register and an 8 bit configuration register.
 *
 * The input port register is a read only port and writes to this register
 * will have no effect regardless of whether the pin is an input or output.
 *
 * The output port register reflects the outgoing logic levels of the pins
 * defined as outputs by the configuration register.  Bit values in this
 * register have no effect on pins defined as inputs.
 *
 * The polarity register enables polarity inversion of pins defined as inputs by
 * the configuration register.  A set bit inverts the corresponding port's
 * polarity.
 *
 * The configuration register configures the directions of the I/O pins.  If a
 * bit is set the corresponding port is enabled as an input and if cleared,
 * as an output.
 *
 * The commands supported in the ioctl routine are:
 * GPIO_GET_INPUT	-- Read bits in the input port register.
 * GPIO_GET_OUTPUT	-- Read bits in the output port register.
 * GPIO_SET_OUPUT	-- Modify bits in the output port register.
 * GPIO_GET_POLARITY    -- Read bits in the polarity register.
 * GPIO_SET_POLARITY    -- Modify bits in the polarity register.
 * GPIO_GET_CONFIG	-- Read bits in the configuration register.
 * GPIO_SET_CONFIG	-- Modify bits in the configuration register.
 *
 * A pointer to the i2c_gpio_t data structure is sent as the third argument
 * in the ioctl call.  The reg_mask member identifies the bits that the user
 * wants to read or modify and reg_val has the actual value of the
 * corresponding bits set in reg_mask.
 *
 * To read a whole register the user has to set all the  bits in reg_mask
 * and the values will be copied into reg_val.
 *
 * In addition the pca9555 device has been added to this driver.  It is similar
 * to the pca9556 except that it has 2 8 bit I/O ports.
 */

/*
 * cb ops
 */
static int pca9556_open(dev_t *, int, int, cred_t *);
static int pca9556_close(dev_t, int, int, cred_t *);
static int pca9556_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * dev ops
 */
static int pca9556_s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pca9556_s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int pca9556_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

static struct cb_ops pca9556_cb_ops = {
	pca9556_open,			/* open */
	pca9556_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pca9556_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
};

static struct dev_ops pca9556_dev_ops = {
	DEVO_REV,
	0,
	pca9556_info,
	nulldev,
	nulldev,
	pca9556_s_attach,
	pca9556_s_detach,
	nodev,
	&pca9556_cb_ops,
	NULL,
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv pca9556_modldrv = {
	&mod_driverops,		/* type of module - driver */
	"pca9556 device driver",
	&pca9556_dev_ops,
};

static struct modlinkage pca9556_modlinkage = {
	MODREV_1,
	&pca9556_modldrv,
	0
};

static void *pca9556_soft_statep;
int pca9556_debug;

int
_init(void)
{
	int    err;

	err = mod_install(&pca9556_modlinkage);
	if (err == 0) {
		(void) ddi_soft_state_init(&pca9556_soft_statep,
		    sizeof (pca9556_unit_t), PCA9556_MAX_SIZE);
	}
	return (err);
}

int
_fini(void)
{
	int    err;

	err = mod_remove(&pca9556_modlinkage);
	if (err == 0) {
		ddi_soft_state_fini(&pca9556_soft_statep);
	}
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pca9556_modlinkage, modinfop));
}

static int
pca9556_resume(dev_info_t *dip)
{
	int 		instance = ddi_get_instance(dip);
	pca9556_unit_t	*pcap;
	int 		err = DDI_SUCCESS;
	int		reg_offset, num_of_ports;
	int		i, j;
	uint8_t		reg, reg_num = 0;
	extern int	do_polled_io;
	int		saved_pio;

	pcap = (pca9556_unit_t *)
	    ddi_get_soft_state(pca9556_soft_statep, instance);

	if (pcap == NULL)
		return (ENXIO);

	/*
	 * Restore registers to status existing before cpr
	 */
	pcap->pca9556_transfer->i2c_flags = I2C_WR;
	pcap->pca9556_transfer->i2c_wlen = 2;
	pcap->pca9556_transfer->i2c_rlen = 0;

	if (pcap->pca9555_device) {
		reg_offset = 2;
		num_of_ports = PCA9555_NUM_PORTS;
	} else {
		reg_offset = 1;
		num_of_ports = PCA9556_NUM_PORTS;
	}

	/*
	 * Since the parent node that handles interrupts may have already
	 * been suspended, perform the following i2c transfers in poll-mode.
	 */
	saved_pio = do_polled_io;
	do_polled_io = 1;

	for (i = 0; i < num_of_ports; i++) {
		if (pcap->pca9555_device)
			reg = PCA9555_OUTPUT_REG;
		else
			reg = PCA9556_OUTPUT_REG;

		for (j = 0; j < PCA9556_NUM_REG; j++) {
			pcap->pca9556_transfer->i2c_wbuf[0] = reg + i;
			pcap->pca9556_transfer->i2c_wbuf[1] =
			    pcap->pca9556_cpr_state[reg_num++];

			if (i2c_transfer(pcap->pca9556_hdl,
			    pcap->pca9556_transfer) != DDI_SUCCESS) {
				err = EIO;

				goto done;
			}

			reg = reg + reg_offset;
		}
	}

done:
	do_polled_io = saved_pio;
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s Unable to restore registers",
		    pcap->pca9556_name);
	}

	/*
	 * Clear busy flag so that transactions may continue
	 */
	mutex_enter(&pcap->pca9556_mutex);
	pcap->pca9556_flags = pcap->pca9556_flags & ~PCA9556_BUSYFLAG;
	cv_broadcast(&pcap->pca9556_cv);
	mutex_exit(&pcap->pca9556_mutex);
	return (err);
}

static void
pca9556_detach(dev_info_t *dip)
{
	pca9556_unit_t *pcap;
	int 		instance = ddi_get_instance(dip);

	pcap = ddi_get_soft_state(pca9556_soft_statep, instance);

	if ((pcap->pca9556_flags & PCA9556_REGFLAG) == PCA9556_REGFLAG) {
		i2c_client_unregister(pcap->pca9556_hdl);
	}
	if ((pcap->pca9556_flags & PCA9556_TBUFFLAG) == PCA9556_TBUFFLAG) {
		i2c_transfer_free(pcap->pca9556_hdl, pcap->pca9556_transfer);
	}
	if ((pcap->pca9556_flags & PCA9556_MINORFLAG) == PCA9556_MINORFLAG) {
		ddi_remove_minor_node(dip, NULL);
	}
	cv_destroy(&pcap->pca9556_cv);
	mutex_destroy(&pcap->pca9556_mutex);
	ddi_soft_state_free(pca9556_soft_statep, instance);

}

static int
pca9556_attach(dev_info_t *dip)
{
	pca9556_unit_t 		*pcap;
	int 			instance = ddi_get_instance(dip);
	char			name[MAXNAMELEN];
	char *device_name;
	minor_t 		minor;
	int			i, num_ports;

	if (ddi_soft_state_zalloc(pca9556_soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d failed to zalloc softstate",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	pcap = ddi_get_soft_state(pca9556_soft_statep, instance);

	if (pcap == NULL)
		return (DDI_FAILURE);

	mutex_init(&pcap->pca9556_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&pcap->pca9556_cv, NULL, CV_DRIVER, NULL);

	(void) snprintf(pcap->pca9556_name, sizeof (pcap->pca9556_name),
	    "%s_%d", ddi_driver_name(dip), instance);

	device_name = ddi_get_name(dip);

	if (strcmp(device_name, "i2c-pca9555") == 0) {
		num_ports = PCA9555_NUM_PORTS;
		pcap->pca9555_device = B_TRUE;
	} else {
		num_ports = PCA9556_NUM_PORTS;
		pcap->pca9555_device = B_FALSE;
		minor = INST_TO_MINOR(instance);
	}

	for (i = 0; i < num_ports; i++) {
		if (!(pcap->pca9555_device)) {
			(void) snprintf(pcap->pca9556_name,
			    sizeof (pcap->pca9556_name), "%s_%d",
			    ddi_driver_name(dip), instance);
			(void) snprintf(name, sizeof (name), "%s",
			    pcap->pca9556_name);
		} else {
			(void) sprintf(name, "port_%d", i);
			minor = INST_TO_MINOR(instance) |
			    PORT_TO_MINOR(I2C_PORT(i));
		}

		if (ddi_create_minor_node(dip, name, S_IFCHR, minor,
		    PCA9556_NODE_TYPE, NULL) == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s: failed to create node for %s",
			    pcap->pca9556_name, name);
			pca9556_detach(dip);
			return (DDI_FAILURE);
		}
	}
	pcap->pca9556_flags |= PCA9556_MINORFLAG;

	/*
	 * Add a zero-length attribute to tell the world we support
	 * kernel ioctls (for layered drivers)
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);


	/*
	 * preallocate a single buffer for all reads and writes
	 */
	if (i2c_transfer_alloc(pcap->pca9556_hdl, &pcap->pca9556_transfer,
	    2, 2, I2C_SLEEP) != I2C_SUCCESS) {
		cmn_err(CE_WARN, "%s i2c_transfer_alloc failed",
		    pcap->pca9556_name);
		pca9556_detach(dip);
		return (DDI_FAILURE);
	}
	pcap->pca9556_flags |= PCA9556_TBUFFLAG;
	pcap->pca9556_transfer->i2c_version = I2C_XFER_REV;

	if (i2c_client_register(dip, &pcap->pca9556_hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		cmn_err(CE_WARN, "%s i2c_client_register failed",
		    pcap->pca9556_name);
		pca9556_detach(dip);
		return (DDI_FAILURE);
	}
	pcap->pca9556_flags |= PCA9556_REGFLAG;

	/*
	 * Store the dip for future dip.
	 */
	pcap->pca9556_dip = dip;
	return (DDI_SUCCESS);
}


static int
pca9556_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip))

	pca9556_unit_t	*pcap;
	int		instance = MINOR_TO_INST(getminor((dev_t)arg));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		pcap = ddi_get_soft_state(pca9556_soft_statep, instance);
		if (pcap == NULL)
			return (DDI_FAILURE);
		*result = (void *)pcap->pca9556_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
pca9556_s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (pca9556_attach(dip));
	case DDI_RESUME:
		return (pca9556_resume(dip));
	default:
		return (DDI_FAILURE);
	}
}

static int
pca9556_suspend(dev_info_t *dip)
{
	pca9556_unit_t 	*pcap;
	int 		instance = ddi_get_instance(dip);
	int		err = DDI_SUCCESS;
	int		reg_offset, num_of_ports;
	int		i, j;
	uint8_t		reg, reg_num = 0;
	extern int	do_polled_io;
	int		saved_pio;

	pcap = ddi_get_soft_state(pca9556_soft_statep, instance);

	mutex_enter(&pcap->pca9556_mutex);
	while ((pcap->pca9556_flags & PCA9556_BUSYFLAG) == PCA9556_BUSYFLAG) {
		if (cv_wait_sig(&pcap->pca9556_cv,
		    &pcap->pca9556_mutex) <= 0) {
			mutex_exit(&pcap->pca9556_mutex);
			return (DDI_FAILURE);
		}
	}
	pcap->pca9556_flags |= PCA9556_BUSYFLAG;
	mutex_exit(&pcap->pca9556_mutex);

	/*
	 * A pca9555 devices command registers are offset by 2 and it has 2
	 * ports to save. A pca9556 devices command registers are offset by 1
	 * while it only has one "port"
	 */
	if (pcap->pca9555_device) {
		reg_offset = 2;
		num_of_ports = PCA9555_NUM_PORTS;
	} else {
		reg_offset = 1;
		num_of_ports = PCA9556_NUM_PORTS;
	}
	/*
	 * Save the state of the registers
	 */
	pcap->pca9556_transfer->i2c_flags = I2C_WR_RD;
	pcap->pca9556_transfer->i2c_wlen = 1;
	pcap->pca9556_transfer->i2c_rlen = 1;

	/*
	 * Since the parent node that handles interrupts may have not been
	 * resumed yet, perform the following i2c transfers in poll-mode.
	 */
	saved_pio = do_polled_io;
	do_polled_io = 1;

	/*
	 * The following for loop will run through once for a pca9556 device
	 * and twice for a pca9555 device. i will represent the port number
	 * for the pca9555.
	 */
	for (i = 0; i < num_of_ports; i++) {
		/*
		 * We set the first Register here so it can be reset if we
		 * loop through (pca9555 device).
		 */
		if (pcap->pca9555_device)
			reg = PCA9555_OUTPUT_REG;
		else
			reg = PCA9556_OUTPUT_REG;

		/* We run through this loop 3 times. Once for each register */
		for (j = 0; j < PCA9556_NUM_REG; j++) {

			/*
			 * We add the port number (0 for pca9556, 0 or 1 for
			 * a pca9555) to the register.
			 */
			pcap->pca9556_transfer->i2c_wbuf[0] = reg + i;
			if (i2c_transfer(pcap->pca9556_hdl,
			    pcap->pca9556_transfer) != DDI_SUCCESS) {
				err = EIO;
				goto done;
			}

			pcap->pca9556_cpr_state[reg_num++] =
			    pcap->pca9556_transfer->i2c_rbuf[0];
			/*
			 * The register is then added to the offset and saved
			 * to go and read the next command register.
			 */
			reg = reg + reg_offset;
		}
	}

done:
	do_polled_io = saved_pio;
	if (err != DDI_SUCCESS) {
		mutex_enter(&pcap->pca9556_mutex);
		pcap->pca9556_flags = pcap->pca9556_flags & ~PCA9556_BUSYFLAG;
		cv_broadcast(&pcap->pca9556_cv);
		mutex_exit(&pcap->pca9556_mutex);
		cmn_err(CE_WARN, "%s Suspend failed, unable to save registers",
		    pcap->pca9556_name);
		return (err);
	}
	return (DDI_SUCCESS);
}

static int
pca9556_s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		pca9556_detach(dip);
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (pca9556_suspend(dip));
	default:
		return (DDI_FAILURE);
	}
}

static int
pca9556_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int			instance;
	pca9556_unit_t		*pcap;
	int			err = EBUSY;

	/*
	 * Make sure the open is for the right file type
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = MINOR_TO_INST(getminor(*devp));

	pcap = (pca9556_unit_t *)
	    ddi_get_soft_state(pca9556_soft_statep, instance);
	if (pcap == NULL)
		return (ENXIO);

	/* must be privileged to access this device */
	if (drv_priv(credp) != 0)
		return (EPERM);

	/*
	 * Enforce exclusive access if required
	 */
	mutex_enter(&pcap->pca9556_mutex);
	if (flags & FEXCL) {
		if (pcap->pca9556_oflag == 0) {
			pcap->pca9556_oflag = FEXCL;
			err = DDI_SUCCESS;
		}
	} else if (pcap->pca9556_oflag != FEXCL) {
		pcap->pca9556_oflag = (uint16_t)FOPEN;
		err = DDI_SUCCESS;
	}
	mutex_exit(&pcap->pca9556_mutex);
	return (err);
}

static int
pca9556_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	int		instance;
	pca9556_unit_t 	*pcap;

	_NOTE(ARGUNUSED(flags, credp))

	/*
	 * Make sure the close is for the right file type
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = MINOR_TO_INST(getminor(dev));

	pcap = (pca9556_unit_t *)
	    ddi_get_soft_state(pca9556_soft_statep, instance);
	if (pcap == NULL)
		return (ENXIO);

	mutex_enter(&pcap->pca9556_mutex);
	pcap->pca9556_oflag = 0;
	mutex_exit(&pcap->pca9556_mutex);
	return (0);
}

static int
pca9556_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	pca9556_unit_t		*pcap;
	int			err = 0;
	int			instance = MINOR_TO_INST(getminor(dev));
	int			port;
	i2c_gpio_t		g_buf;
	uchar_t			temp;
	boolean_t		write_io = B_FALSE;

	_NOTE(ARGUNUSED(credp, rvalp))

	pcap = (pca9556_unit_t *)
	    ddi_get_soft_state(pca9556_soft_statep, instance);

	if (pcap->pca9555_device) {
		port =  MINOR_TO_PORT(getminor(dev));
	}
	if (pca9556_debug) {
		prom_printf("pca9556_ioctl: instance=%d\n", instance);
	}

	/*
	 * We serialize here and  block any pending transacations.
	 */
	mutex_enter(&pcap->pca9556_mutex);
	while ((pcap->pca9556_flags & PCA9556_BUSYFLAG) == PCA9556_BUSYFLAG) {
		if (cv_wait_sig(&pcap->pca9556_cv,
		    &pcap->pca9556_mutex) <= 0) {
			mutex_exit(&pcap->pca9556_mutex);
			return (EINTR);
		}
	}
	pcap->pca9556_flags |= PCA9556_BUSYFLAG;
	mutex_exit(&pcap->pca9556_mutex);
	if (ddi_copyin((caddr_t)arg, &g_buf,
	    sizeof (i2c_gpio_t), mode) != DDI_SUCCESS) {

		err = EFAULT;

		goto cleanup;
	}
	pcap->pca9556_transfer->i2c_flags = I2C_WR_RD;
	pcap->pca9556_transfer->i2c_wlen = 1;
	pcap->pca9556_transfer->i2c_rlen = 1;

	/*
	 * Evaluate which register is to be read or modified
	 */

	switch (cmd) {
	case GPIO_GET_INPUT:
		if (pcap->pca9555_device)
			pcap->pca9556_transfer->i2c_wbuf[0] =
			    PCA9555_INPUT_REG + port;
		else
			pcap->pca9556_transfer->i2c_wbuf[0] =
			    PCA9556_INPUT_REG;
		break;

	case GPIO_SET_OUTPUT:
		write_io = B_TRUE;
		/*FALLTHROUGH*/

	case GPIO_GET_OUTPUT:
		if (pcap->pca9555_device)
			pcap->pca9556_transfer->i2c_wbuf[0] =
			    PCA9555_OUTPUT_REG + port;
		else
			pcap->pca9556_transfer->i2c_wbuf[0] =
			    PCA9556_OUTPUT_REG;
		break;

	case GPIO_SET_POLARITY:
		write_io = B_TRUE;
		/*FALLTHROUGH*/

	case GPIO_GET_POLARITY:
		if (pcap->pca9555_device)
			pcap->pca9556_transfer->i2c_wbuf[0] =
			    PCA9555_POLARITY_REG + port;
		else
			pcap->pca9556_transfer->i2c_wbuf[0] =
			    PCA9556_POLARITY_REG;
		break;

	case GPIO_SET_CONFIG:
		write_io = B_TRUE;
		/*FALLTHROUGH*/

	case GPIO_GET_CONFIG:
		if (pcap->pca9555_device)
			pcap->pca9556_transfer->i2c_wbuf[0] =
			    PCA9555_CONFIG_REG + port;
		else
			pcap->pca9556_transfer->i2c_wbuf[0] =
			    PCA9556_CONFIG_REG;
		break;
	}

	/*
	 * Read the required register
	 */
	if (i2c_transfer(pcap->pca9556_hdl, pcap->pca9556_transfer)
	    != I2C_SUCCESS) {
		err = EIO;

		goto cleanup;
	}
	/*
	 * Evaluate whether the register is to be read or modified
	 */
	if (!write_io) {
		g_buf.reg_val = g_buf.reg_mask &
		    pcap->pca9556_transfer->i2c_rbuf[0];
		err = ddi_copyout(&g_buf, (caddr_t)arg,
		    sizeof (i2c_gpio_t), mode);
	} else {
		pcap->pca9556_transfer->i2c_flags = I2C_WR;
		pcap->pca9556_transfer->i2c_wlen = 2;
		pcap->pca9556_transfer->i2c_rlen = 0;

		/*
		 * Modify register without overwriting existing contents
		 */

		temp = pcap->pca9556_transfer->i2c_rbuf[0] & (~g_buf.reg_mask);
		pcap->pca9556_transfer->i2c_wbuf[1] = temp|
		    (g_buf.reg_val & g_buf.reg_mask);
		if (i2c_transfer(pcap->pca9556_hdl, pcap->pca9556_transfer)
		    != I2C_SUCCESS) {
				err = EIO;
		}

	}
cleanup:
	mutex_enter(&pcap->pca9556_mutex);
	pcap->pca9556_flags  = pcap->pca9556_flags & ~PCA9556_BUSYFLAG;
	cv_signal(&pcap->pca9556_cv);
	mutex_exit(&pcap->pca9556_mutex);
	return (err);
	}
