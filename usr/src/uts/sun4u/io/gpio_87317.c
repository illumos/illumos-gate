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


#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/clock.h>
#include <sys/gpio_87317.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#ifdef DEBUG
#include <sys/promif.h>
#endif


/* a non zero value causes debug info to be displayed */
uint_t gpio_debug_flag = 0;


#ifdef DEBUG
static void gpio_debug(dev_info_t *dip, char *format, uint_t arg1, uint_t arg2,
    uint_t arg3, uint_t arg4, uint_t arg5);

#define	DBG(dip, format, arg1, arg2, arg3, arg4, arg5) \
	gpio_debug(dip, format, (uint_t)arg1, (uint_t)arg2, (uint_t)arg3, \
	    (uint_t)arg4, (uint_t)arg5)
#else
#define	DBG(dip, format, arg1, arg2, arg3, arg4, arg5)
#endif


/* Driver soft state structure */
struct gpio_softc {
	dev_info_t		*gp_dip;
	kmutex_t		gp_mutex;
	int			gp_state;
	ddi_acc_handle_t	gp_handle;
	uint8_t			*gp_regs;
};

#define	getsoftc(minor)	\
	((struct gpio_softc *)ddi_get_soft_state(statep, (minor)))

/* dev_ops and cb_ops entry point function declarations */
static int gpio_attach(dev_info_t *, ddi_attach_cmd_t);
static int gpio_detach(dev_info_t *, ddi_detach_cmd_t);
static int gpio_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int gpio_open(dev_t *, int, int, cred_t *);
static int gpio_close(dev_t, int, int, cred_t *);
static int gpio_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

struct cb_ops gpio_cb_ops = {
	gpio_open,
	gpio_close,
	nodev,
	nodev,
	nodev,			/* dump */
	nodev,
	nodev,
	gpio_ioctl,
	nodev,			/* devmap */
	nodev,
	nodev,
	nochpoll,
	ddi_prop_op,
	NULL,			/* for STREAMS drivers */
	D_NEW | D_MP,		/* driver compatibility flag */
	CB_REV,
	nodev,
	nodev
};

static struct dev_ops gpio_dev_ops = {
	DEVO_REV,			/* driver build version */
	0,				/* device reference count */
	gpio_getinfo,
	nulldev,
	nulldev,			/* probe */
	gpio_attach,
	gpio_detach,
	nulldev,			/* reset */
	&gpio_cb_ops,
	(struct bus_ops *)NULL,
	nulldev,			/* power */
	ddi_quiesce_not_needed,			/* quiesce */
};

/* module configuration stuff */
static void *statep;
extern struct mod_ops mod_driverops;
static struct modldrv modldrv = {
	&mod_driverops,
	"gpio driver",
	&gpio_dev_ops
};
static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	0
};


int
_init(void)
{
	int e;

	if (e = ddi_soft_state_init(&statep, sizeof (struct gpio_softc), 1)) {
		return (e);
	}
	if ((e = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&statep);
	}

	return (e);
}


int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0) {
		return (e);
	}
	ddi_soft_state_fini(&statep);

	return (DDI_SUCCESS);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/* ARGSUSED */
static int
gpio_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int instance = getminor((dev_t)arg);
	int retval = DDI_SUCCESS;
	struct gpio_softc *softc;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((softc = getsoftc(instance)) == NULL) {
			*result = (void *)NULL;
			retval = DDI_FAILURE;
		} else
		*result = (void *)softc->gp_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		break;

	default:
		retval = DDI_FAILURE;
	}

	return (retval);
}


static int
gpio_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{

	int instance;
	struct gpio_softc *softc = NULL;
	ddi_device_acc_attr_t dev_attr;

	switch (cmd) {

	case DDI_ATTACH:

	    /* Allocate and get the soft state structure for this instance. */

		instance = ddi_get_instance(dip);
		DBG(dip, "attach: instance is %d", instance, 0, 0, 0, 0);
		if (ddi_soft_state_zalloc(statep, instance) != DDI_SUCCESS)
			goto attach_failed;
		softc = getsoftc(instance);
		softc->gp_dip = dip;
		softc->gp_state = 0;
		mutex_init(&softc->gp_mutex, NULL, MUTEX_DRIVER, NULL);

	    /* Map in the gpio device registers. */

		dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
		dev_attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
		dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
		if (ddi_regs_map_setup(dip, 0, (caddr_t *)&softc->gp_regs, 0, 0,
		    &dev_attr, &softc->gp_handle) != DDI_SUCCESS)
			goto attach_failed;
		DBG(dip, "attach: regs=0x%p", (uintptr_t)softc->gp_regs,
		    0, 0, 0, 0);
		DBG(dip, "attach: port 1 data is %x",
		    (uintptr_t)ddi_get8(softc->gp_handle, &softc->gp_regs[0]),
		    0, 0, 0, 0);
		DBG(dip, "attach: port 1 direction is %x",
		    (uintptr_t)ddi_get8(softc->gp_handle, &softc->gp_regs[1]),
		    0, 0, 0, 0);
		DBG(dip, "attach: port 1 output type is %x",
		    (uintptr_t)ddi_get8(softc->gp_handle, &softc->gp_regs[2]),
		    0, 0, 0, 0);
		DBG(dip, "attach: port 1 pull up control type is %x",
		    (uintptr_t)ddi_get8(softc->gp_handle, &softc->gp_regs[3]),
		    0, 0, 0, 0);
		DBG(dip, "attach: port 2 data is %x",
		    (uintptr_t)ddi_get8(softc->gp_handle, &softc->gp_regs[4]),
		    0, 0, 0, 0);
		DBG(dip, "attach: port 2 direction is %x",
		    (uintptr_t)ddi_get8(softc->gp_handle, &softc->gp_regs[5]),
		    0, 0, 0, 0);
		DBG(dip, "attach: port 2 output type is %x",
		    (uintptr_t)ddi_get8(softc->gp_handle, &softc->gp_regs[6]),
		    0, 0, 0, 0);
		DBG(dip, "attach: port 2 pull up control type is %x",
		    (uintptr_t)ddi_get8(softc->gp_handle, &softc->gp_regs[7]),
		    0, 0, 0, 0);

		/* Create device minor nodes. */

		if (ddi_create_minor_node(dip, "gpio", S_IFCHR,
		    instance, NULL, 0) == DDI_FAILURE) {
			ddi_regs_map_free(&softc->gp_handle);
			goto attach_failed;
		}

		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:

		/* Nothing to do for a resume. */

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

attach_failed:
	if (softc) {
		mutex_destroy(&softc->gp_mutex);
		if (softc->gp_handle)
			ddi_regs_map_free(&softc->gp_handle);
		ddi_soft_state_free(statep, instance);
		ddi_remove_minor_node(dip, NULL);
	}
	return (DDI_FAILURE);
}


static int
gpio_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	struct gpio_softc *softc;

	switch (cmd) {
	case DDI_DETACH:
		instance = ddi_get_instance(dip);
		DBG(dip, "detach: instance is %d", instance, 0, 0, 0, 0);
		if ((softc = getsoftc(instance)) == NULL)
			return (ENXIO);
		mutex_destroy(&softc->gp_mutex);
		ddi_regs_map_free(&softc->gp_handle);
		ddi_soft_state_free(statep, instance);
		ddi_remove_minor_node(dip, NULL);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/* Nothing to do in the suspend case. */
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
static int
gpio_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int instance = getminor(*devp);

	DBG(NULL, "open: instance is %d", instance, 0, 0, 0, 0);
	return (getsoftc(instance) == NULL ? ENXIO : 0);
}


/* ARGSUSED */
static int
gpio_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int instance = getminor(dev);

	DBG(NULL, "close: instance is %d", instance, 0, 0, 0, 0);
	return (getsoftc(instance) == NULL ? ENXIO : 0);
}


/* ARGSUSED */
static int
gpio_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int instance = getminor(dev);
	struct gpio_softc *softc = getsoftc(instance);
	gpio_87317_op_t info;
	uint8_t byte;

	DBG(softc->gp_dip, "ioctl: instance is %d", instance, 0, 0, 0, 0);

	if (softc == NULL)
		return (ENXIO);

	/* Copy the command from user space. */
	if (ddi_copyin((caddr_t)arg, (caddr_t)&info, sizeof (gpio_87317_op_t),
	    mode) != 0)
		return (EFAULT);

	/* Check the command arguments.  We only support port 1 in bank 0. */
	if ((info.gpio_bank != 0) ||
	    (info.gpio_offset != GPIO_87317_PORT1_DATA)) {
		return (EINVAL);
	}

	/* Grap the instance's mutex to insure exclusive access. */
	mutex_enter(&softc->gp_mutex);

	/* Get the contents of the GPIO register we're suppose to modify. */
	byte = ddi_get8(softc->gp_handle, &softc->gp_regs[info.gpio_offset]);

	switch (cmd) {
	case GPIO_CMD_SET_BITS:
		DBG(softc->gp_dip, "ioctl: SET_BITS, byte is %x", byte, 0, 0,
		    0, 0);
		byte |= info.gpio_data;
		ddi_put8(softc->gp_handle, &softc->gp_regs[info.gpio_offset],
		    byte);
		byte = ddi_get8(softc->gp_handle,
		    &softc->gp_regs[info.gpio_offset]);
		DBG(softc->gp_dip, "ioctl: SET_BITS, byte is %x", byte, 0, 0,
		    0, 0);
		break;

	case GPIO_CMD_CLR_BITS:
		DBG(softc->gp_dip, "ioctl: CLR_BITS, byte is %x", byte, 0, 0,
		    0, 0);
		byte &= ~info.gpio_data;
		ddi_put8(softc->gp_handle, &softc->gp_regs[info.gpio_offset],
		    byte);
		byte = ddi_get8(softc->gp_handle,
		    &softc->gp_regs[info.gpio_offset]);
		DBG(softc->gp_dip, "ioctl: CLR_BITS, byte is %x", byte, 0, 0,
		    0, 0);
		break;

	case GPIO_CMD_GET:
		DBG(softc->gp_dip, "ioctl: GPIO_CMD_GET", 0, 0, 0, 0, 0);
		info.gpio_data = byte;
		if (ddi_copyout((caddr_t)&info, (caddr_t)arg,
		    sizeof (gpio_87317_op_t), mode) != 0) {
			mutex_exit(&softc->gp_mutex);
			return (EFAULT);
		}
		break;

	case GPIO_CMD_SET:
		DBG(softc->gp_dip, "ioctl: GPIO_CMD_SET", 0, 0, 0, 0, 0);
		ddi_put8(softc->gp_handle, &softc->gp_regs[info.gpio_offset],
		    info.gpio_data);
		break;

	default:
		mutex_exit(&softc->gp_mutex);
		return (EINVAL);
	}

	mutex_exit(&softc->gp_mutex);
	return (0);
}


#ifdef DEBUG
void
gpio_debug(dev_info_t *dip, char *format, uint_t arg1, uint_t arg2, uint_t arg3,
    uint_t arg4, uint_t arg5)
{
	if (gpio_debug_flag == 0) {
		return;
	}

	if (dip == NULL) {
		prom_printf("gpio: ");
	} else {
		prom_printf("%s%d: ", ddi_driver_name(dip),
		    ddi_get_instance(dip));
	}
	prom_printf(format, arg1, arg2, arg3, arg4, arg5);
	prom_printf("\n");
}
#endif
