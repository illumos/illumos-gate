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

#include <sys/stat.h>		/* ddi_create_minor_node S_IFCHR */
#include <sys/modctl.h>		/* for modldrv */
#include <sys/open.h>		/* for open params.	 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/conf.h>		/* req. by dev_ops flags MTSAFE etc. */
#include <sys/ddi.h>
#include <sys/file.h>
#include <sys/note.h>
#include <sys/i2c/clients/i2c_gpio.h>
#include <sys/i2c/clients/adm1026_impl.h>

/*
 * This driver supports the GPIO subset of the full ADM1026 register set.
 * The driver is designed to allow modifying and reading the Polarity and
 * Direction bits of the ADM1026's 16 GPIO pins via the 4 GPIO Config
 * registers.  In addition, the driver supports modifying and reading
 * the 16 GPIO pins via the 2 GPIO input/output registers.
 *
 * The 4 GPIO Config registers configure the direction and polarity of
 * the 16 GPIO pins.  When a Polarity bit is set to 0, the GPIO pin is
 * active low, otherwise, it is active high.  When a Direction bit is set
 * to 0, the GPIO pin configured as an input; otherwise, it is an output.
 *
 * The 2 GPIO input/output registers (Status Register 5 & 6 ) behave as follows.
 * When a GPIO pin is configured as an input, the bit is set when its GPIO
 * pin is asserted.  When a GPIO pin is configured as an output, the bit
 * asserts the GPIO pin.
 *
 * The commands supported in the ioctl routine are:
 * GPIO_GET_OUTPUT   -- Read GPIO0-GPIO15 bits in Status Register 5 & 6
 * GPIO_SET_OUTPUT   -- Modify GPIO0-GPIO15 bits in Status Register 5 & 6
 * GPIO_GET_POLARITY -- Read GPIO0-GPIO15 Polarity bits in GPIO Config 1-4
 * GPIO_SET_POLARITY -- Modify GPIO0-GPIO15 Polarity bits in GPIO Config 1-4
 * GPIO_GET_CONFIG   -- Read GPIO0-GPIO15 Direction bits in GPIO Config 1-4
 * GPIO_SET_CONFIG   -- Modify GPIO0-GPIO15 Direction bits in GPIO Config 1-4
 *
 * A pointer to the i2c_gpio_t data structure is sent as the third argument
 * in the ioctl call.  The reg_mask and reg_val members of i2c_gpio_t are
 * used to logically represent the 16 GPIO pins, thus only the lower 16 bits
 * of each member is used.  The reg_mask member identifies the GPIO pin(s)
 * that the user wants to read or modify and reg_val has the actual value of
 * what the corresponding GPIO pin should be set to.
 *
 * For example, a reg_mask of 0x8001 indicates that the ioctl should only
 * access GPIO15 and GPIO0.
 */

static void *adm1026soft_statep;

static int adm1026_do_attach(dev_info_t *);
static int adm1026_do_detach(dev_info_t *);
static int adm1026_do_resume(void);
static int adm1026_do_suspend(void);
static int adm1026_get8(adm1026_unit_t *unitp, uint8_t reg, uint8_t *val);
static int adm1026_put8(adm1026_unit_t *unitp, uint8_t reg, uint8_t val);

/*
 * cb ops (only need ioctl)
 */
static int adm1026_open(dev_t *, int, int, cred_t *);
static int adm1026_close(dev_t, int, int, cred_t *);
static int adm1026_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops adm1026_cbops = {
	adm1026_open,			/* open  */
	adm1026_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	adm1026_ioctl,			/* ioctl */
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
static int adm1026_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int adm1026_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops adm1026_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,
	nulldev,
	adm1026_attach,
	adm1026_detach,
	nodev,
	&adm1026_cbops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv adm1026_modldrv = {
	&mod_driverops,			/* type of module - driver */
	"ADM1026 i2c device driver",
	&adm1026_ops
};

static struct modlinkage adm1026_modlinkage = {
	MODREV_1,
	&adm1026_modldrv,
	0
};


int
_init(void)
{
	int error;

	error = mod_install(&adm1026_modlinkage);

	if (!error)
		(void) ddi_soft_state_init(&adm1026soft_statep,
		    sizeof (struct adm1026_unit), 1);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&adm1026_modlinkage);
	if (!error)
		ddi_soft_state_fini(&adm1026soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&adm1026_modlinkage, modinfop));
}

static int
adm1026_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	adm1026_unit_t *unitp;
	int instance;
	int error = 0;

	instance = getminor(*devp);

	D2CMN_ERR((CE_WARN, "adm1026_open: instance=%d\n", instance));

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct adm1026_unit *)
	    ddi_get_soft_state(adm1026soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->adm1026_mutex);

	if (flags & FEXCL) {
		if (unitp->adm1026_oflag != 0) {
			error = EBUSY;
		} else {
			unitp->adm1026_oflag = FEXCL;
		}
	} else {
		if (unitp->adm1026_oflag == FEXCL) {
			error = EBUSY;
		} else {
			unitp->adm1026_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->adm1026_mutex);

	return (error);
}

static int
adm1026_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))

	adm1026_unit_t *unitp;
	int instance;

	instance = getminor(dev);

	D2CMN_ERR((CE_WARN, "adm1026_close: instance=%d\n", instance));

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct adm1026_unit *)
	    ddi_get_soft_state(adm1026soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->adm1026_mutex);

	unitp->adm1026_oflag = 0;

	mutex_exit(&unitp->adm1026_mutex);
	return (DDI_SUCCESS);
}

static int
adm1026_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	D2CMN_ERR((CE_WARN, "adm1026_attach: cmd=%x\n", cmd));

	switch (cmd) {
	case DDI_ATTACH:
		return (adm1026_do_attach(dip));
	case DDI_RESUME:
		return (adm1026_do_resume());
	default:
		return (DDI_FAILURE);
	}
}

static int
adm1026_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	D2CMN_ERR((CE_WARN, "adm1026_detach: cmd=%x\n", cmd));
	switch (cmd) {
	case DDI_DETACH:
		return (adm1026_do_detach(dip));
	case DDI_SUSPEND:
		return (adm1026_do_suspend());
	default:
		return (DDI_FAILURE);
	}
}

static int
adm1026_do_attach(dev_info_t *dip)
{
	adm1026_unit_t *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	D2CMN_ERR((CE_WARN, "adm1026_do_attach: instance=%d, dip=%p",
	    instance, (void *)dip));

	if (ddi_soft_state_zalloc(adm1026soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d: ddi_soft_state_zalloc() failed",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(adm1026soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: ddi_get_soft_state(), no memory",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	D2CMN_ERR((CE_WARN, "adm1026_do_attach: ddi_create_minor_node"));
	if (ddi_create_minor_node(dip, "adm1026", S_IFCHR, instance,
	"ddi_i2c:led_control", 0) == DDI_FAILURE) {
		cmn_err(CE_WARN,
		    "adm1026_do_attach: ddi_create_minor_node failed");
		ddi_soft_state_free(adm1026soft_statep, instance);

		return (DDI_FAILURE);
	}

	D2CMN_ERR((CE_WARN, "adm1026_do_attach: i2c_client_register"));
	if (i2c_client_register(dip, &unitp->adm1026_hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(adm1026soft_statep, instance);
		cmn_err(CE_WARN,
		    "adm1026_do_attach: i2c_client_register failed");

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->adm1026_mutex, NULL, MUTEX_DRIVER, NULL);

	D2CMN_ERR((CE_WARN, "adm1026_do_attach: DDI_SUCCESS"));
	return (DDI_SUCCESS);
}

static int
adm1026_do_resume(void)
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
adm1026_do_suspend()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
adm1026_do_detach(dev_info_t *dip)
{
	adm1026_unit_t *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	unitp = ddi_get_soft_state(adm1026soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN,
		    "adm1026_do_detach: ddi_get_soft_state failed");
		return (ENOMEM);
	}

	i2c_client_unregister(unitp->adm1026_hdl);

	ddi_remove_minor_node(dip, NULL);

	mutex_destroy(&unitp->adm1026_mutex);
	ddi_soft_state_free(adm1026soft_statep, instance);

	return (DDI_SUCCESS);
}

static int
adm1026_get8(adm1026_unit_t *unitp, uint8_t reg, uint8_t *val)
{
	i2c_transfer_t		*i2c_tran_pointer = NULL;
	int			err = DDI_SUCCESS;

	(void) i2c_transfer_alloc(unitp->adm1026_hdl, &i2c_tran_pointer,
	    1, 1, I2C_SLEEP);
	if (i2c_tran_pointer == NULL)
		return (ENOMEM);

	i2c_tran_pointer->i2c_flags = I2C_WR_RD;
	i2c_tran_pointer->i2c_wbuf[0] = (uchar_t)reg;
	err = i2c_transfer(unitp->adm1026_hdl, i2c_tran_pointer);
	if (err) {
		D1CMN_ERR((CE_WARN,
		    "adm1026_get8: I2C_WR_RD reg=0x%x failed", reg));
	} else {
		*val = i2c_tran_pointer->i2c_rbuf[0];
		D1CMN_ERR((CE_WARN, "adm1026_get8: reg=%02x, val=%02x",
		    reg, *val));
	}
	i2c_transfer_free(unitp->adm1026_hdl, i2c_tran_pointer);

	return (err);
}

static int
adm1026_put8(adm1026_unit_t *unitp, uint8_t reg, uint8_t val)
{
	i2c_transfer_t		*i2c_tran_pointer = NULL;
	int			err = DDI_SUCCESS;

	D1CMN_ERR((CE_WARN, "adm1026_put8: reg=%02x, val=%02x\n", reg, val));

	(void) i2c_transfer_alloc(unitp->adm1026_hdl, &i2c_tran_pointer,
	    2, 0, I2C_SLEEP);
	if (i2c_tran_pointer == NULL)
		return (ENOMEM);

	i2c_tran_pointer->i2c_flags = I2C_WR;
	i2c_tran_pointer->i2c_wbuf[0] = reg;
	i2c_tran_pointer->i2c_wbuf[1] = val;

	err = i2c_transfer(unitp->adm1026_hdl, i2c_tran_pointer);
	if (err)
		D2CMN_ERR((CE_WARN, "adm1026_put8: return=%x", err));

	i2c_transfer_free(unitp->adm1026_hdl, i2c_tran_pointer);

	return (err);
}

/*
 * adm1026_send8:
 * Read the i2c register, apply the mask to contents so that only
 * bits in mask affected. Or in value and write it back to the i2c register.
 */
static int
adm1026_send8(adm1026_unit_t *unitp, uint8_t reg, uint8_t reg_val,
    uint8_t reg_mask)
{
	uint8_t val = 0;
	int err;

	if ((err = adm1026_get8(unitp, reg, &val)) != I2C_SUCCESS)
		return (err);
	val &= ~reg_mask;
	val |= (reg_val & reg_mask);

	return (adm1026_put8(unitp, reg, val));
}

/*
 * adm1026_set_output:
 * The low 16 bits of the mask is a 1:1 mask indicating which of the
 * 16 GPIO pin(s) to set.
 */
static int
adm1026_set_output(adm1026_unit_t *unitp, uint32_t val, uint32_t mask)
{
	int err = I2C_SUCCESS;

	if (mask & 0xff)
		err = adm1026_send8(unitp, ADM1026_STS_REG5, (uint8_t)val,
		    (uint8_t)mask);

	if ((err == I2C_SUCCESS) && (mask & 0xff00))
		err = adm1026_send8(unitp, ADM1026_STS_REG6,
		    (uint8_t)(val >> OUTPUT_SHIFT),
		    (uint8_t)(mask >> OUTPUT_SHIFT));

	return (err);
}

/*
 * adm1026_get_output:
 * The low 16 bits of the mask is a 1:1 mask indicating which of the
 * 16 GPIO pin(s) to get.
 */
static int
adm1026_get_output(adm1026_unit_t *unitp, uint32_t mask, uint32_t *val)
{
	uint8_t reg_val = 0;
	int err = I2C_SUCCESS;

	if (mask & 0xff) {
		err = adm1026_get8(unitp, ADM1026_STS_REG5, &reg_val);
		if (err != I2C_SUCCESS)
			return (err);

		*val = reg_val;
	}

	if (mask & 0xff00) {
		err = adm1026_get8(unitp, ADM1026_STS_REG6, &reg_val);
		if (err != I2C_SUCCESS)
			return (err);

		*val |= ((reg_val << OUTPUT_SHIFT) & (mask & 0xff00));
	}

	return (err);
}

/*
 * adm1026_set_config:
 * The low 16 bits of the mask is a 1:1 mask indicating which of the
 * 16 GPIO pin(s) to set the polarity or direction configuration for.
 * Each GPIO pin has 2 bits of configuration - 1 polarity bit and 1
 * direction bit.  Traverse the mask 4 bits at a time to determine
 * which of the 4 GPIO Config registers to access and apply the value
 * based on whether cmd is GPIO_SET_CONFIG (set Direction) or
 * GPIO_SET_POLARITY.
 */
static int
adm1026_set_config(adm1026_unit_t *unitp, int cmd, uint32_t val, uint32_t mask)
{
	int i;
	uint8_t r;
	uint32_t m = mask, v = val;
	int err = I2C_SUCCESS;

	for (i = 0, r = ADM1026_GPIO_CFG1; i < BYTES_PER_CONFIG; i++, r++) {
		if (m & GPIO_CFG_MASK) {
			int j;
			uint8_t mm = 0, vv = 0;
			uint8_t bit = (cmd == GPIO_SET_CONFIG) ?
			    DIR_BIT : POLARITY_BIT;

			for (j = 0; j < GPIOS_PER_CFG_BYTE; j++) {
				if (m & (1 << j)) {
					mm |= (bit << (j * BITSPERCFG));
				}
				if (v & (1 << j)) {
					vv |= (bit << (j * BITSPERCFG));
				}
			}
			D2CMN_ERR((CE_WARN, "adm1026_set_config: r=%02x, "
			    "vv=%02x, mm=%02x, m=%02x", r, vv, mm, m));
			err = adm1026_send8(unitp, r, vv, mm);
			if (err != I2C_SUCCESS)
				return (err);
		}
		m >>= GPIOS_PER_CFG_BYTE;
		v >>= GPIOS_PER_CFG_BYTE;
	}
	return (err);
}

/*
 * adm1026_get_config:
 * The low 16 bits of the mask is a 1:1 mask indicating which of the
 * 16 GPIO pin(s) to get the polarity or direction configuration for.
 * Each GPIO pin has 2 bits of configuration - 1 polarity bit and 1
 * direction bit.  Traverse the mask 4 bits at a time to determine
 * which of the 4 GPIO Config registers to access and build the return
 * value based on whether cmd is GPIO_GET_CONFIG (get Direction) or
 * GPIO_GET_POLARITY.
 */
static int
adm1026_get_config(adm1026_unit_t *unitp, int cmd, uint32_t mask, uint32_t *val)
{
	int i, j;
	uint8_t r;
	int err = I2C_SUCCESS;

	*val = 0;

	for (i = 0, r = ADM1026_GPIO_CFG1; i < BYTES_PER_CONFIG; i++, r++) {
		if (mask & GPIO_CFG_MASK) {
			uint8_t newval = 0, x;
			uint8_t bit = (cmd == GPIO_GET_CONFIG) ?
			    DIR_BIT : POLARITY_BIT;

			err = adm1026_get8(unitp, r, &x);
			if (err != I2C_SUCCESS)
				return (err);
			for (j = 0; j < GPIOS_PER_CFG_BYTE; j++) {
				if (mask & (1 << j)) {
					if (x & (bit << (j * BITSPERCFG)))
						newval |= (1 << j);
				}
			}
			*val |= (newval << (i * GPIOS_PER_CFG_BYTE));
		} else
			*val <<= GPIOS_PER_CFG_BYTE;

		mask >>= GPIOS_PER_CFG_BYTE;
	}
	return (err);
}

static int
adm1026_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	adm1026_unit_t		*unitp;
	int			instance;
	int			err = DDI_SUCCESS;
	i2c_gpio_t		g_buf;

	instance = getminor(dev);

	D2CMN_ERR((CE_WARN, "adm1026_ioctl: instance=%d, cmd=%x\n",
	    instance, cmd));

	unitp = (struct adm1026_unit *)
	    ddi_get_soft_state(adm1026soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "adm1026_ioctl: ddi_get_soft_state failed");
		err = ENOMEM;
		return (err);
	}

	mutex_enter(&unitp->adm1026_mutex);

	if (ddi_copyin((caddr_t)arg, &g_buf,
	    sizeof (i2c_gpio_t), mode) != DDI_SUCCESS) {

		mutex_exit(&unitp->adm1026_mutex);
		return (EFAULT);
	}
	if (g_buf.reg_mask & 0xffff0000) {
		cmn_err(CE_WARN,
		    "adm1026_ioctl: reg_mask too large. "
		    "Only bits 15-0 supported");
		mutex_exit(&unitp->adm1026_mutex);
		return (EINVAL);
	}
	switch (cmd) {
	case GPIO_SET_OUTPUT:
		err = adm1026_set_output(unitp, g_buf.reg_val, g_buf.reg_mask);
		break;

	case GPIO_GET_OUTPUT:
		err = adm1026_get_output(unitp, g_buf.reg_mask, &g_buf.reg_val);
		if (err == DDI_SUCCESS)
			err = ddi_copyout(&g_buf, (caddr_t)arg,
			    sizeof (i2c_gpio_t), mode);
		break;

	case GPIO_SET_CONFIG:
	case GPIO_SET_POLARITY:
		err = adm1026_set_config(unitp, cmd, g_buf.reg_val,
		    g_buf.reg_mask);
		break;

	case GPIO_GET_CONFIG:
	case GPIO_GET_POLARITY:
		err = adm1026_get_config(unitp, cmd, g_buf.reg_mask,
		    &g_buf.reg_val);
		if (err == DDI_SUCCESS)
			err = ddi_copyout(&g_buf, (caddr_t)arg,
			    sizeof (i2c_gpio_t), mode);
		break;
	default:
		D2CMN_ERR((CE_WARN,
		    "adm1026_ioctl: Invalid ioctl cmd %x\n", cmd));
		err = EINVAL;
	}
	mutex_exit(&unitp->adm1026_mutex);

	if (err) {
		D2CMN_ERR((CE_WARN,
		    "adm1026_ioctl: failed, err=%x\n", err));
		if (err == DDI_FAILURE)
			err = EIO;
	}

	return (err);
}
