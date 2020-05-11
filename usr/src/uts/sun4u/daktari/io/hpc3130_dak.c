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
 */

/*
 * Daktari platform specific hotplug controller. This
 * driver exports the same interfaces to user space
 * as the generic hpc3130 driver.  It adds specific
 * functionality found on Daktari, such as slot button
 * and platform specific LED displays.  Placed in
 * the daktari specific platform directory, it will
 * be loaded instead of the generic module.
 */


#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/cpuvar.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/note.h>
#include <sys/hotplug/hpctrl.h>
#include <sys/hotplug/hpcsvc.h>
#include <sys/i2c/clients/hpc3130.h>
#include <sys/hpc3130_events.h>
#include <sys/daktari.h>
#include <sys/hpc3130_dak.h>

#ifdef DEBUG
static int hpc3130debug = 0;

#define	D1CMN_ERR(ARGS) if (hpc3130debug & 0x1) cmn_err ARGS;
#define	D2CMN_ERR(ARGS) if (hpc3130debug & 0x2) cmn_err ARGS;

#else

#define	D1CMN_ERR(ARGS)
#define	D2CMN_ERR(ARGS)

#endif /* DEBUG */

#define	HPC3130_REG(offset, slot) ((offset) + ((slot)*8))
#define	HPC3130_PIL	1
struct tuple {
	uint8_t reg;
	uint8_t val;
};

struct connect_command {
	boolean_t set_bit;
	uint8_t value;
};

struct tuple pci_sequence [] =
{
	{HPC3130_GCR, HPC3130_AUTO2_SEQ},
	{HPC3130_INTERRUPT, HPC3130_PWRGOOD |
		HPC3130_DETECT0 | HPC3130_PRSNT1 | HPC3130_PRSNT2},
	{HPC3130_EVENT_STATUS, 0xff},
	{HPC3130_NO_REGISTER, 0},
};

struct tuple cpu_sequence [] =
{
	{HPC3130_INTERRUPT,
		HPC3130_PRSNT1 | HPC3130_DETECT0},
	{HPC3130_EVENT_STATUS, 0xff},
	{HPC3130_NO_REGISTER, 0},
};

struct connect_command connect_sequence [] =
{
	{B_TRUE,  HPC3130_SLOTREQ64},
	{B_FALSE, HPC3130_SLOTRST},
	{B_FALSE, HPC3130_CLKON},
	{B_FALSE, HPC3130_REQ64},
	{B_FALSE, HPC3130_SLOTREQ64},
	{B_TRUE,  HPC3130_SLOTRST},
	{B_FALSE, HPC3130_BUS_CTL},
};

#define	HPC3130_CONNECT_SEQ_COUNT (sizeof (connect_sequence)/ \
	sizeof (struct connect_command))

struct xlate_entry {
	char	*nexus;
	int	pcidev;
};
/*
 * The order here is significant.  Its the order
 * of appearance of slots from bottom to top
 * on a Sun-Fire-880
 */
static struct xlate_entry slot_translate[] =
{
	{"/pci@8,700000", 5},	/* PCI0 */
	{"/pci@8,700000", 4},	/* PCI1 */
	{"/pci@8,700000", 3},	/* PCI2 */
	{"/pci@8,700000", 2},	/* PCI3 */

	{"/pci@9,700000", 4},	/* PCI4 */
	{"/pci@9,700000", 3},	/* PCI5 */
	{"/pci@9,700000", 2},	/* PCI6 */

	{"/pci@9,600000", 2},	/* PCI7 */
	{"/pci@9,600000", 1}	/* PCI8 */
};

#define	HPC3130_LOOKUP_SLOTS (sizeof (slot_translate)/ \
	sizeof (struct xlate_entry))

static int control_slot_control = HPC3130_SLOT_CONTROL_ENABLE;

hpc3130_unit_t *hpc3130soft_statep;

static int hpc3130_atoi(const char *);
int hpc3130_lookup_slot(char *, int);

static int hpc3130_init(dev_info_t *, struct tuple *);
static uint_t hpc3130_hard_intr(caddr_t);

static int hpc3130_cpu_init(hpc3130_unit_t *, int, i2c_client_hdl_t);
static int hpc3130_debounce_status(i2c_client_hdl_t, int, uint8_t *);
static int hpc3130_read(i2c_client_hdl_t, uint8_t, uint8_t, uint8_t *);
static int hpc3130_write(i2c_client_hdl_t, uint8_t, uint8_t, uint8_t);
static int hpc3130_rw(i2c_client_hdl_t, uint8_t, boolean_t, uint8_t *);

static int hpc3130_do_attach(dev_info_t *);
static int hpc3130_do_detach(dev_info_t *);
static int hpc3130_do_resume(void);
static int hpc3130_do_suspend();
static int hpc3130_get(intptr_t, int, hpc3130_unit_t *, int);
static int hpc3130_set(intptr_t, int, hpc3130_unit_t *, int);

static int hpc3130_slot_connect(caddr_t, hpc_slot_t, void *, uint_t);
static int hpc3130_slot_disconnect(caddr_t, hpc_slot_t, void *, uint_t);
static int hpc3130_verify_slot_power(hpc3130_unit_t *, i2c_client_hdl_t,
					uint8_t, char *, boolean_t);
static int hpc3130_slot_insert(caddr_t, hpc_slot_t, void *, uint_t);
static int hpc3130_slot_remove(caddr_t, hpc_slot_t, void *, uint_t);
static int hpc3130_slot_control(caddr_t, hpc_slot_t, int, caddr_t);
/*
 * cb ops
 */
static int hpc3130_open(dev_t *, int, int, cred_t *);
static int hpc3130_close(dev_t, int, int, cred_t *);
static int hpc3130_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int hpc3130_poll(dev_t dev, short events, int anyyet,  short
			*reventsp, struct pollhead **phpp);

static struct cb_ops hpc3130_cbops = {
	hpc3130_open,			/* open  */
	hpc3130_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	hpc3130_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	hpc3130_poll,			/* poll */
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
static int hpc3130_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int hpc3130_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int hpc3130_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops hpc3130_ops = {
	DEVO_REV,
	0,
	hpc3130_info,
	nulldev,
	nulldev,
	hpc3130_attach,
	hpc3130_detach,
	nodev,
	&hpc3130_cbops,
	NULL,			/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv hpc3130_modldrv = {
	&mod_driverops,			/* type of module - driver */
	"Hotplug controller driver",
	&hpc3130_ops
};

static struct modlinkage hpc3130_modlinkage = {
	MODREV_1,
	&hpc3130_modldrv,
	0
};

int
_init(void)
{
	int error;

	error = mod_install(&hpc3130_modlinkage);

	if (!error)
		(void) ddi_soft_state_init((void *)&hpc3130soft_statep,
		    sizeof (hpc3130_unit_t), 4);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&hpc3130_modlinkage);
	if (!error)
		ddi_soft_state_fini((void *)&hpc3130soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&hpc3130_modlinkage, modinfop));
}

static int
hpc3130_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))
	hpc3130_unit_t *unitp;
	int instance;
	int error = 0;

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	instance = MINOR_TO_INST(getminor(*devp));

	unitp = (hpc3130_unit_t *)
	    ddi_get_soft_state(hpc3130soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->hpc3130_mutex);

	if (flags & FEXCL) {
		if (unitp->hpc3130_oflag != 0) {
			error = EBUSY;
		} else {
			unitp->hpc3130_oflag = FEXCL;
		}
	} else {
		if (unitp->hpc3130_oflag == FEXCL) {
			error = EBUSY;
		} else {
			unitp->hpc3130_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->hpc3130_mutex);

	return (error);
}

static int
hpc3130_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))
	hpc3130_unit_t *unitp;
	int instance;

	instance = MINOR_TO_INST(getminor(dev));

	unitp = (hpc3130_unit_t *)
	    ddi_get_soft_state(hpc3130soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->hpc3130_mutex);

	unitp->hpc3130_oflag = 0;

	mutex_exit(&unitp->hpc3130_mutex);
	return (DDI_SUCCESS);
}

static int
hpc3130_get(intptr_t arg, int reg, hpc3130_unit_t *unitp, int mode)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int err = DDI_SUCCESS;

	if (arg == (intptr_t)NULL) {
		D2CMN_ERR((CE_WARN, "ioctl: arg passed in to "
		    "ioctl = NULL"));
		return (EINVAL);
	}
	(void) i2c_transfer_alloc(unitp->hpc3130_hdl, &i2c_tran_pointer,
	    1, 1, I2C_SLEEP);
	if (i2c_tran_pointer == NULL) {
		D2CMN_ERR((CE_WARN, "Failed in HPC3130_GET_STATUS"
		    " i2c_tran_pointer not allocated"));
		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = I2C_WR_RD;
	i2c_tran_pointer->i2c_wbuf[0] = (uchar_t)reg;

	err = i2c_transfer(unitp->hpc3130_hdl, i2c_tran_pointer);
	if (err) {
		D2CMN_ERR((CE_WARN, "Failed in HPC3130_GET_STATUS"
		    " i2c_trasfer routine"));
		i2c_transfer_free(unitp->hpc3130_hdl, i2c_tran_pointer);
		return (err);
	}
	D1CMN_ERR((CE_NOTE, "The i2c_rbuf contains %x",
	    i2c_tran_pointer->i2c_rbuf[0]));

	if (ddi_copyout((caddr_t)i2c_tran_pointer->i2c_rbuf,
	    (caddr_t)arg,
	    sizeof (uint8_t), mode) != DDI_SUCCESS) {
		D2CMN_ERR((CE_WARN, "Failed in HPC3130_GET_STATUS"
		    " ddi_copyout routine"));
		err = EFAULT;
	}
	i2c_transfer_free(unitp->hpc3130_hdl, i2c_tran_pointer);
	return (err);
}

static int
hpc3130_set(intptr_t arg, int reg, hpc3130_unit_t *unitp, int mode)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int err = DDI_SUCCESS;
	uint8_t passin_byte;

	if (arg == (intptr_t)NULL) {
		D2CMN_ERR((CE_WARN, "ioctl: arg passed in to "
		    "ioctl = NULL"));
		return (EINVAL);
	}
	if (ddi_copyin((caddr_t)arg, (caddr_t)&passin_byte,
	    sizeof (uint8_t), mode) != DDI_SUCCESS) {
		D2CMN_ERR((CE_WARN, "Failed in HPC3130_SET_CONTROL "
		    "ddi_copyin routine"));

		return (EFAULT);
	}
	(void) i2c_transfer_alloc(unitp->hpc3130_hdl, &i2c_tran_pointer,
	    2, 0, I2C_SLEEP);
	if (i2c_tran_pointer == NULL) {
		D2CMN_ERR((CE_WARN, "Failed in "
		    "HPC3130_SET_CONTROL i2c_tran_pointer not allocated"));

		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = I2C_WR;
	i2c_tran_pointer->i2c_wbuf[0] = (uchar_t)reg;
	i2c_tran_pointer->i2c_wbuf[1] = passin_byte;

	err = i2c_transfer(unitp->hpc3130_hdl, i2c_tran_pointer);
	i2c_transfer_free(unitp->hpc3130_hdl, i2c_tran_pointer);

	return (err);
}

static int
hpc3130_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))
	hpc3130_unit_t		*unitp;
	int			err = DDI_SUCCESS;
	i2c_transfer_t		*i2c_tran_pointer;
	i2c_reg_t		ioctl_reg;
	int port = MINOR_TO_PORT(getminor(dev));
	int instance = MINOR_TO_INST(getminor(dev));
	hpc3130_slot_table_entry_t *ste;

	unitp = (hpc3130_unit_t *)
	    ddi_get_soft_state(hpc3130soft_statep, instance);

	if (unitp == NULL) {
		D1CMN_ERR((CE_WARN, "unitp not filled"));
		return (ENOMEM);
	}

	/*
	 * It should be the case that the port number is a valid
	 * index in the per instance slot table. If it is not
	 * then we should fail out.
	 */
	if (!(port >= 0 && port < unitp->hpc3130_slot_table_length)) {
		return (EINVAL);
	}

	mutex_enter(&unitp->hpc3130_mutex);

	ste = &unitp->hpc3130_slot_table[port];

	D2CMN_ERR((CE_NOTE, "ioctl: port = %d  instance = %d",
	    port, instance));

	switch (cmd) {
	case HPC3130_GET_STATUS:
		err = hpc3130_get(arg, HPC3130_HP_STATUS_REG(port), unitp,
		    mode);
		break;

	case HPC3130_GET_CONTROL:
		err = hpc3130_get(arg, HPC3130_HP_CONTROL_REG(port), unitp,
		    mode);
		break;

	case HPC3130_SET_CONTROL:
		if (control_slot_control == HPC3130_SLOT_CONTROL_DISABLE) {
			cmn_err(CE_WARN, "Cannot change control register.");
			err = EINVAL;
			break;
		}
		err = hpc3130_set(arg, HPC3130_HP_CONTROL_REG(port), unitp,
		    mode);
		break;

	case HPC3130_GET_EVENT_STATUS:
		err = hpc3130_get(arg, HPC3130_INTERRUPT_STATUS_REG(port),
		    unitp, mode);
		break;

	case HPC3130_SET_EVENT_STATUS:
		err = hpc3130_set(arg, HPC3130_INTERRUPT_STATUS_REG(port),
		    unitp, mode);
		break;

	case HPC3130_GET_GENERAL_CONFIG:
		err = hpc3130_get(arg, HPC3130_GENERAL_CONFIG_REG(port),
		    unitp, mode);
		break;

	case HPC3130_SET_GENERAL_CONFIG:
		err = hpc3130_set(arg, HPC3130_GENERAL_CONFIG_REG(port),
		    unitp, mode);
		break;

	case HPC3130_GET_INDICATOR_CONTROL:
		err = hpc3130_get(arg, HPC3130_ATTENTION_INDICATOR(port),
		    unitp, mode);
		break;

	case HPC3130_SET_INDICATOR_CONTROL:
		err = hpc3130_set(arg, HPC3130_ATTENTION_INDICATOR(port),
		    unitp, mode);
		break;

	case HPC3130_GET_EVENT_ENABLE:
		err = hpc3130_get(arg, HPC3130_INTERRUPT_ENABLE_REG(port),
		    unitp, mode);
		break;

	case HPC3130_SET_EVENT_ENABLE:
		err = hpc3130_set(arg, HPC3130_INTERRUPT_ENABLE_REG(port),
		    unitp, mode);
		break;

	case HPC3130_ENABLE_SLOT_CONTROL:
		control_slot_control = HPC3130_SLOT_CONTROL_ENABLE;
		D2CMN_ERR((CE_NOTE, "Set the control_slot_control variable to"
		    "HPC3130_SLOT_CONTROL_ENABLE"));
		break;

	case HPC3130_DISABLE_SLOT_CONTROL:
		control_slot_control = HPC3130_SLOT_CONTROL_DISABLE;
		D2CMN_ERR((CE_NOTE, "Set the control_slot_control variable to"
		    "HPC3130_SLOT_CONTROL_DISABLE"));
		break;

	case I2C_GET_REG:
		if (arg == (intptr_t)NULL) {
			D2CMN_ERR((CE_WARN, "ioctl: arg passed in to "
			    "ioctl = NULL"));
			err = EINVAL;
			break;
		}
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_reg,
		    sizeof (i2c_reg_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "Failed in I2C_GET_REG "
			    "ddi_copyin routine"));
			err = EFAULT;
			break;
		}
		(void) i2c_transfer_alloc(unitp->hpc3130_hdl, &i2c_tran_pointer,
		    1, 1, I2C_SLEEP);
		if (i2c_tran_pointer == NULL) {
			D2CMN_ERR((CE_WARN, "Failed in I2C_GET_REG "
			    "i2c_tran_pointer not allocated"));
			err = ENOMEM;
			break;
		}

		i2c_tran_pointer->i2c_flags = I2C_WR_RD;
		i2c_tran_pointer->i2c_wbuf[0] = ioctl_reg.reg_num;

		err = i2c_transfer(unitp->hpc3130_hdl, i2c_tran_pointer);
		if (err) {
			D2CMN_ERR((CE_WARN, "Failed in I2C_GET_REG "
			    "i2c_transfer routine"));
			i2c_transfer_free(unitp->hpc3130_hdl, i2c_tran_pointer);
			break;
		}
		ioctl_reg.reg_value = i2c_tran_pointer->i2c_rbuf[0];
		if (ddi_copyout((caddr_t)&ioctl_reg, (caddr_t)arg,
		    sizeof (i2c_reg_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "Failed in I2C_GET_REG "
			    "ddi_copyout routine"));
			err = EFAULT;
		}

		i2c_transfer_free(unitp->hpc3130_hdl, i2c_tran_pointer);
		break;

	case I2C_SET_REG:
		if (arg == (intptr_t)NULL) {
			D2CMN_ERR((CE_WARN, "ioctl: arg passed in to "
			    "ioctl = NULL"));
			err = EINVAL;
			break;
		}
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_reg,
		    sizeof (i2c_reg_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "Failed in I2C_SET_REG "
			    "ddi_copyin routine"));
			err = EFAULT;
			break;
		}
		(void) i2c_transfer_alloc(unitp->hpc3130_hdl, &i2c_tran_pointer,
		    2, 0, I2C_SLEEP);
		if (i2c_tran_pointer == NULL) {
			D2CMN_ERR((CE_WARN, "Failed in I2C_GET_REG "
			    "i2c_tran_pointer not allocated"));
			err = ENOMEM;
			break;
		}

		i2c_tran_pointer->i2c_flags = I2C_WR;
		i2c_tran_pointer->i2c_wbuf[0] = ioctl_reg.reg_num;
		i2c_tran_pointer->i2c_wbuf[1] = (uchar_t)ioctl_reg.reg_value;

		err = i2c_transfer(unitp->hpc3130_hdl, i2c_tran_pointer);
		if (err) {
			D2CMN_ERR((CE_WARN, "Failed in I2C_SET_REG "
			    "i2c_transfer routine"));
			i2c_transfer_free(unitp->hpc3130_hdl, i2c_tran_pointer);
			break;
		}

		i2c_transfer_free(unitp->hpc3130_hdl, i2c_tran_pointer);
		break;

	case HPC3130_GET_EVENT: {
		struct hpc3130_event ev;

		bzero(&ev, sizeof (struct hpc3130_event));

		if (unitp->slots_are == HPC3130_SLOT_TYPE_SBD) {
			DAK_GET_SBD_APID(ev.name, sizeof (ev.name), port);
		} else {
			(void) snprintf(ev.name, HPC3130_NAME_MAX,
			    "/devices%s:", ste->nexus);
			ASSERT(strlen(ev.name) < HPC3130_NAME_MAX - 1);
			DAK_GET_PCI_APID(ev.name + strlen(ev.name),
			    HPC3130_NAME_MAX - strlen(ev.name),
			    hpc3130_lookup_slot(ste->nexus,
			    ste->hpc3130_slot_info.pci_dev_num));
		}

		if (unitp->events[port] & HPC3130_IEVENT_OCCUPANCY) {
			unitp->events[port] &= ~HPC3130_IEVENT_OCCUPANCY;
			ev.id = (unitp->present[port] == B_FALSE ?
			    HPC3130_EVENT_REMOVAL :
			    HPC3130_EVENT_INSERTION);
		} else if (unitp->events[port] & HPC3130_IEVENT_POWER) {
			unitp->events[port] &= ~HPC3130_IEVENT_POWER;
			ev.id = (unitp->power[port] == B_TRUE ?
			    HPC3130_EVENT_POWERON :
			    HPC3130_EVENT_POWEROFF);
		} else if (unitp->events[port] & HPC3130_IEVENT_BUTTON) {
			unitp->events[port] &= ~HPC3130_IEVENT_BUTTON;
			ev.id = HPC3130_EVENT_BUTTON;
		} else if (unitp->events[port] & HPC3130_IEVENT_FAULT) {
			unitp->events[port] &= ~HPC3130_IEVENT_FAULT;
			ev.id = (unitp->fault_led[port] == HPC3130_ATTN_ON ?
			    HPC3130_LED_FAULT_ON :
			    HPC3130_LED_FAULT_OFF);
		} else if (unitp->events[port] & HPC3130_IEVENT_OK2REM) {
			unitp->events[port] &= ~HPC3130_IEVENT_OK2REM;
			ev.id = (unitp->ok2rem_led[port] == HPC3130_ATTN_ON ?
			    HPC3130_LED_REMOVABLE_ON :
			    HPC3130_LED_REMOVABLE_OFF);
		}

		D1CMN_ERR((CE_NOTE,
		    "sending EVENT: ap_id=%s, event=%d", ev.name, ev.id));

		if (ddi_copyout((caddr_t)&ev, (caddr_t)arg,
			sizeof (struct hpc3130_event), mode) != DDI_SUCCESS) {
			D1CMN_ERR((CE_WARN, "Failed in hpc3130_ioctl"
			    " ddi_copyout routine"));
			err = EFAULT;
		}
		break;
	}
	case HPC3130_CONF_DR: {
		uint8_t offset;
		int dr_conf;

		if (ddi_copyin((caddr_t)arg, (caddr_t)&dr_conf,
		    sizeof (int), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "Failed in HPC3130_CONF_DR "
			    "ddi_copyin routine"))
			err = EFAULT;
			break;
		}

		offset = ste->callback_info.offset;

		unitp->enabled[offset] =
		    (dr_conf == HPC3130_DR_DISABLE ? B_FALSE : B_TRUE);

		break;
	}
	default:
		D2CMN_ERR((CE_WARN, "Invalid IOCTL cmd: %x", cmd));
		err = EINVAL;
	}

	mutex_exit(&unitp->hpc3130_mutex);
	return (err);
}

static int
hpc3130_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	_NOTE(ARGUNUSED(events))
	hpc3130_unit_t *unitp;
	int port = MINOR_TO_PORT(getminor(dev));
	int instance = MINOR_TO_INST(getminor(dev));

	if (!(port >= 0 && port < HPC3130_MAX_SLOT)) {
		return (EINVAL);
	}
	unitp = (hpc3130_unit_t *)
	    ddi_get_soft_state(hpc3130soft_statep, instance);

	mutex_enter(&unitp->hpc3130_mutex);
	if (unitp->events[port]) {
		*reventsp = POLLIN;
	} else {
		*reventsp = 0;
		if (!anyyet)
			*phpp = &unitp->pollhead[port];
	}
	mutex_exit(&unitp->hpc3130_mutex);
	return (0);
}

/* ARGSUSED */
static int
hpc3130_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = MINOR_TO_INST(getminor(dev));
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
hpc3130_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (hpc3130_do_attach(dip));
	case DDI_RESUME:
		return (hpc3130_do_resume());
	default:
		return (DDI_FAILURE);
	}
}

static int
hpc3130_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (hpc3130_do_detach(dip));
	case DDI_SUSPEND:
		return (hpc3130_do_suspend());
	default:
		return (DDI_FAILURE);
	}
}

static int
hpc3130_do_attach(dev_info_t *dip)
{
	hpc3130_unit_t	*hpc3130_p;
	char		*s;
	char		*nexus;
	char		*pcidev;
	char		*reg_offset;
	int		r, i, n, j;
	char		name[MAXNAMELEN];
	minor_t		minor_number;
	int		hpc3130_pil = HPC3130_PIL;
	int		instance = ddi_get_instance(dip);

	/*
	 * Allocate the soft state structure for this instance.
	 */
	r = ddi_soft_state_zalloc(hpc3130soft_statep, instance);
	if (r != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	hpc3130_p =
	    (hpc3130_unit_t *)ddi_get_soft_state(hpc3130soft_statep, instance);
	ASSERT(hpc3130_p);

	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    "interrupt-priorities", (caddr_t)&hpc3130_pil,
	    sizeof (hpc3130_pil)) != DDI_PROP_SUCCESS) {
		goto failout0;
	}

	if (ddi_intr_hilevel(dip, 0)) {
		cmn_err(CE_WARN, "High level interrupt not supported");
		goto failout0;
	}

	/*
	 * Get the "slot-table" property which defines the list of
	 * hot-pluggable slots for this controller along with the
	 * corresponding bus nexus node and device identification
	 * for each slot.
	 */
	r = ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "slot-table", (caddr_t)&hpc3130_p->hpc3130_slot_table_data,
	    &hpc3130_p->hpc3130_slot_table_size);

	switch (r) {
	case DDI_PROP_SUCCESS:
		break;
	case DDI_PROP_NOT_FOUND:
		cmn_err(CE_WARN,
		    "couldn't find slot-table property");
		return (DDI_FAILURE);
	case DDI_PROP_UNDEFINED:
		cmn_err(CE_WARN,
		    "slot-table undefined");
		return (DDI_FAILURE);
	case DDI_PROP_NO_MEMORY:
		cmn_err(CE_WARN,
		    "can't allocate memory for slot-table");
		return (DDI_FAILURE);
	}

	/*
	 * Determine the size of the slot table from the OBP property and
	 * allocate the slot table arrary..
	 */
	for (i = 0, n = 0; i < hpc3130_p->hpc3130_slot_table_size; i++) {
		if (hpc3130_p->hpc3130_slot_table_data[i] == 0) {
			n++;
		}
	}

	D1CMN_ERR((CE_NOTE, "hpc3130_attach(): slot table has %d entries", n));

	/*
	 * There should be HPC3130_TABLE_COLUMNS elements per entry
	 */
	if (n % HPC3130_TABLE_COLUMNS) {
		cmn_err(CE_WARN, "bad format in slot-table");
		goto failout1;
	}

	hpc3130_p->dip = dip;
	hpc3130_p->hpc3130_slot_table_length = n / HPC3130_TABLE_COLUMNS;

	if (ddi_get_iblock_cookie(dip, 0, &hpc3130_p->ic_trap_cookie) !=
	    DDI_SUCCESS)  {
		cmn_err(CE_WARN, "ddi_get_iblock_cookie FAILED");
		goto failout1;
	}

	mutex_init(&hpc3130_p->hpc3130_mutex, NULL, MUTEX_DRIVER,
	    (void *)hpc3130_p->ic_trap_cookie);
	/*
	 * Create enough space for each slot table entry
	 * based on how many entries in the property
	 */
	hpc3130_p->hpc3130_slot_table = (hpc3130_slot_table_entry_t *)
	    kmem_zalloc(hpc3130_p->hpc3130_slot_table_length *
	    sizeof (hpc3130_slot_table_entry_t), KM_SLEEP);

	/*
	 * Setup to talk to the i2c nexus
	 */
	if (i2c_client_register(dip, &hpc3130_p->hpc3130_hdl) != I2C_SUCCESS) {
		cmn_err(CE_WARN, "failed to register as i2c client");
		goto failout2;
	}

	s = hpc3130_p->hpc3130_slot_table_data;
	for (i = 0; i < hpc3130_p->hpc3130_slot_table_length; i++) {
		hpc3130_slot_table_entry_t *ste;

		/* Pick off pointer to nexus path */
		nexus = s;
		s = s + strlen(s) + 1;

		/* Pick off pointer to 3130 register offset */
		reg_offset = s;
		s = s + strlen(s) + 1;

		/* Pick off pointer to the device number */
		pcidev = s;

		s = s + strlen(s) + 1;

		j = hpc3130_atoi(reg_offset);

		if (j < 0 || j >= HPC3130_MAX_SLOT) {
			cmn_err(CE_WARN,
			    "invalid register offset value");
			goto failout3;
		}

		ste = &hpc3130_p->hpc3130_slot_table[j];

		(void) strcpy(ste->nexus, nexus);

		if (strncmp(ste->nexus, "/pci", 4) == 0) {

			ste->hpc3130_slot_info.pci_dev_num =
			    hpc3130_atoi(pcidev);

			DAK_GET_PCI_APID(ste->hpc3130_slot_info.pci_slot_name,
			    PCI_SLOT_NAME_LEN,
			    hpc3130_lookup_slot(ste->nexus,
			    hpc3130_atoi(pcidev)));

			ste->hpc3130_slot_info.slot_type = HPC_SLOT_TYPE_PCI;
			ste->hpc3130_slot_info.slot_flags =
			    HPC_SLOT_CREATE_DEVLINK;
			hpc3130_p->slots_are = HPC3130_SLOT_TYPE_PCI;

		} else {

			ste->hpc3130_slot_info.sbd_slot_num =
			    hpc3130_atoi(reg_offset);

			ste->hpc3130_slot_info.slot_type = HPC_SLOT_TYPE_SBD;

			hpc3130_p->slots_are = HPC3130_SLOT_TYPE_SBD;
		}

		hpc3130_p->present[j] = B_FALSE;
		hpc3130_p->enabled[j] = B_TRUE;

		/*
		 * The "callback_info" structure of the slot_table is what gets
		 * passed back in the callback routines.  All that is needed
		 * at that point is the device handle  and the register offset
		 * within it the chip it represents.
		 */
		ste->callback_info.handle = (caddr_t)hpc3130_p->hpc3130_hdl;

		ste->callback_info.offset = hpc3130_atoi(reg_offset);

		ste->callback_info.statep = (caddr_t)hpc3130_p;
	}

	hpc3130_p->hpc3130_slot_ops = hpc_alloc_slot_ops(KM_SLEEP);
	hpc3130_p->hpc3130_slot_ops->hpc_version = 0;

	hpc3130_p->hpc3130_slot_ops->hpc_op_connect = hpc3130_slot_connect;
	hpc3130_p->hpc3130_slot_ops->hpc_op_disconnect =
	    hpc3130_slot_disconnect;
	hpc3130_p->hpc3130_slot_ops->hpc_op_insert = hpc3130_slot_insert;
	hpc3130_p->hpc3130_slot_ops->hpc_op_remove = hpc3130_slot_remove;
	hpc3130_p->hpc3130_slot_ops->hpc_op_control = hpc3130_slot_control;

	cv_init(&hpc3130_p->hpc3130_cond, NULL, CV_DEFAULT, NULL);

	if (hpc3130_init(dip, (hpc3130_p->slots_are == HPC3130_SLOT_TYPE_SBD) ?
	    cpu_sequence : pci_sequence) != DDI_SUCCESS) {
			goto failout4;
	}

	if (ddi_add_intr(dip, 0, &hpc3130_p->ic_trap_cookie,
	    NULL, hpc3130_hard_intr,
	    (caddr_t)hpc3130_p) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed to add interrupt");
		goto failout4;
	}

	/*
	 * Register with the "services" module
	 */
	for (i = 0; i < hpc3130_p->hpc3130_slot_table_length; i++) {
		hpc3130_slot_table_entry_t *ste =
		    &hpc3130_p->hpc3130_slot_table[i];
		hpc3130_p->power[i] = B_TRUE;
		if (ste->callback_info.handle != NULL) {
			(void) hpc_slot_register(dip, ste->nexus,
			    &ste->hpc3130_slot_info,
			    &ste->hpc3130_slot_handle,
			    hpc3130_p->hpc3130_slot_ops,
			    (caddr_t)&ste->callback_info, 0);
		}
	}

	(void) snprintf(hpc3130_p->hpc3130_name,
	    sizeof (hpc3130_p->hpc3130_name),
	    "%s%d", ddi_node_name(dip), instance);

	for (i = 0; i < HPC3130_MAX_SLOT; i++) {
		(void) snprintf(name, MAXNAMELEN, "port_%d", i);
		minor_number = INST_TO_MINOR(instance) |
		    PORT_TO_MINOR(I2C_PORT(i));
		if (ddi_create_minor_node(dip, name, S_IFCHR, minor_number,
		    "ddi_i2c:controller", 0) == DDI_FAILURE) {
			D1CMN_ERR((CE_WARN, "ddi_create_minor_node failed "
			    "for %s", name));
			ddi_remove_intr(dip, 0u,
			    hpc3130_p->ic_trap_cookie);
			goto failout4;
		}
	}

	return (DDI_SUCCESS);

failout4:
	hpc_free_slot_ops(hpc3130_p->hpc3130_slot_ops);
failout3:
	i2c_client_unregister(hpc3130_p->hpc3130_hdl);
failout2:
	mutex_destroy(&hpc3130_p->hpc3130_mutex);
	kmem_free(hpc3130_p->hpc3130_slot_table,
	    hpc3130_p->hpc3130_slot_table_length *
	    sizeof (hpc3130_slot_table_entry_t));
failout1:
	kmem_free(hpc3130_p->hpc3130_slot_table_data,
	    hpc3130_p->hpc3130_slot_table_size);
failout0:
	ddi_soft_state_free(hpc3130soft_statep, instance);

	return (DDI_FAILURE);
}

static int
hpc3130_do_resume()
{
	return (DDI_SUCCESS);
}

static int
hpc3130_do_suspend()
{
	return (DDI_SUCCESS);
}

static int
hpc3130_do_detach(dev_info_t *dip)
{
	int i;
	int instance = ddi_get_instance(dip);
	hpc3130_unit_t *hpc3130_p;

	hpc3130_p = (hpc3130_unit_t *)ddi_get_soft_state(hpc3130soft_statep,
	    instance);
	if (hpc3130_p == NULL)
		return (ENXIO);

	i2c_client_unregister(hpc3130_p->hpc3130_hdl);

	ddi_remove_intr(dip, 0u, hpc3130_p->ic_trap_cookie);

	cv_destroy(&hpc3130_p->hpc3130_cond);

	for (i = 0; i < hpc3130_p->hpc3130_slot_table_length; i++) {
		(void) hpc_slot_unregister(
		    &hpc3130_p->hpc3130_slot_table[i].hpc3130_slot_handle);
	}

	kmem_free(hpc3130_p->hpc3130_slot_table,
	    hpc3130_p->hpc3130_slot_table_length *
	    sizeof (hpc3130_slot_table_entry_t));

	kmem_free(hpc3130_p->hpc3130_slot_table_data,
	    hpc3130_p->hpc3130_slot_table_size);

	hpc_free_slot_ops(hpc3130_p->hpc3130_slot_ops);

	mutex_destroy(&hpc3130_p->hpc3130_mutex);

	ddi_soft_state_free(hpc3130soft_statep, instance);

	return (DDI_SUCCESS);
}

int
hpc3130_set_led(hpc3130_unit_t *unitp, int slot, int led, uint8_t value)
{
	i2c_client_hdl_t handle = unitp->hpc3130_hdl;
	uint8_t old;
	uint8_t	new;

	if (hpc3130_read(handle, HPC3130_ATTEN, slot, &old) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	new = (old & ~HPC3130_ATTN_MASK(led)) |
	    value << HPC3130_ATTN_SHIFT(led);

	D1CMN_ERR((CE_NOTE, "setting led %d to %x", led, value));

	if (hpc3130_write(handle, HPC3130_ATTEN, slot, new) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if ((value == HPC3130_ATTN_OFF || value == HPC3130_ATTN_ON) &&
	    ((old & HPC3130_ATTN_MASK(led)) !=
	    (new & HPC3130_ATTN_MASK(led)))) {
		/*
		 * We're turning a LED on or off (i.e., not blinking), and
		 * the value actually did change.
		 */
		if (led == HPC3130_LED_OK2REM) {
			unitp->events[slot] |= HPC3130_IEVENT_OK2REM;
			unitp->ok2rem_led[slot] = value;
			D1CMN_ERR((CE_NOTE,
			    "recording IEVENT_OK2REM slot=%d, val=%d",
			    slot, value));
		} else {
			unitp->events[slot] |= HPC3130_IEVENT_FAULT;
			unitp->fault_led[slot] = value;
			D1CMN_ERR((CE_NOTE,
			    "recording IEVENT_FAULT slot=%d, val=%d",
			    slot, value));
		}
		ASSERT(MUTEX_HELD(&unitp->hpc3130_mutex));
		mutex_exit(&unitp->hpc3130_mutex);
		pollwakeup(&unitp->pollhead[slot], POLLIN);
		mutex_enter(&unitp->hpc3130_mutex);
	}
	return (DDI_SUCCESS);
}

int
hpc3130_get_led(i2c_client_hdl_t handle, int slot,
    int led, uint8_t *value)
{
	uint8_t	temp;

	if (hpc3130_read(handle, HPC3130_ATTEN, slot, &temp) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	*value = (temp & HPC3130_ATTN_MASK(led)) >> HPC3130_ATTN_SHIFT(led);
	return (DDI_SUCCESS);
}

static int
hpc3130_write(i2c_client_hdl_t handle, uint8_t offset,
    uint8_t port, uint8_t data)
{
	ASSERT(port < HPC3130_MAX_SLOT);
	ASSERT(handle);

	return (hpc3130_rw(handle,
	    HPC3130_REG(offset, port), B_TRUE, &data));
}

static int
hpc3130_read(i2c_client_hdl_t handle, uint8_t offset,
    uint8_t port, uint8_t *data)
{
	ASSERT(port < HPC3130_MAX_SLOT);
	ASSERT(handle);

	return (hpc3130_rw(handle,
	    HPC3130_REG(offset, port), B_FALSE, data));
}

static int
hpc3130_rw(i2c_client_hdl_t handle, uint8_t reg,
    boolean_t write, uint8_t *data)
{
	i2c_transfer_t	*i2c_tran_pointer;
	int		err;
	int		rlen;
	int		wlen;

	if (write == B_TRUE) {
		wlen = 2;
		rlen = 0;
	} else {
		wlen = 1;
		rlen = 1;
	}

	(void) i2c_transfer_alloc(handle,
	    &i2c_tran_pointer, wlen, rlen, I2C_SLEEP);

	if (i2c_tran_pointer == NULL) {
		D1CMN_ERR((CE_WARN, "Failed in hpc3130_rw: "
		    "no transfer structure 0x%x", reg));
		return (DDI_FAILURE);
	}
	i2c_tran_pointer->i2c_wbuf[0] = reg;
	if (write == B_TRUE) {
		i2c_tran_pointer->i2c_flags = I2C_WR;
		i2c_tran_pointer->i2c_wbuf[1] = *data;
	} else {
		i2c_tran_pointer->i2c_flags = I2C_WR_RD;
	}

	err = i2c_transfer(handle, i2c_tran_pointer);
	if (err) {
		D1CMN_ERR((CE_WARN, "Failed in hpc3130_rw: "
		    "no I2C data transfered 0x%x", reg));
		(void) i2c_transfer_free(handle, i2c_tran_pointer);
		return (DDI_FAILURE);
	}

	if (write == B_FALSE)
		*data = i2c_tran_pointer->i2c_rbuf[0];

	(void) i2c_transfer_free(handle, i2c_tran_pointer);

	return (DDI_SUCCESS);
}

/*
 * Put the hot plug controller(s) in proper mode for further
 * operations.
 */
static int
hpc3130_init(dev_info_t *dip,
    struct tuple *init_sequence)
{

	int			slot;
	i2c_client_hdl_t	handle;
	hpc3130_unit_t		*hpc3130_p;
	int			instance = ddi_get_instance(dip);
	int			error = DDI_FAILURE;
	struct tuple		*tp;

	hpc3130_p =
	    (hpc3130_unit_t *)ddi_get_soft_state(hpc3130soft_statep,
	    instance);
	ASSERT(hpc3130_p);

	mutex_enter(&hpc3130_p->hpc3130_mutex);

	handle = hpc3130_p->hpc3130_hdl;

	for (slot = 0; slot < HPC3130_MAX_SLOT; slot++) {
		tp = init_sequence;
		while (tp->reg != HPC3130_NO_REGISTER) {
			if (hpc3130_write(handle, tp->reg, slot,
			    tp->val) != DDI_SUCCESS) {
				goto out;
			}
			tp++;
		}
		/*
		 * CPU slots need some special initialization
		 * attention.
		 */
		if (hpc3130_p->slots_are == HPC3130_SLOT_TYPE_SBD) {
			if (hpc3130_cpu_init(hpc3130_p, slot, handle)
			    != DDI_SUCCESS) {
				goto out;
			}
		}
	}
	error = DDI_SUCCESS;
out:
	mutex_exit(&hpc3130_p->hpc3130_mutex);

	return (error);
}

/*
 * When the TI 3130 produces an interrupt,
 * this routine is called to sort it out.
 */
static uint_t
hpc3130_hard_intr(caddr_t arg)
{
	uint8_t			interrupt;
	uint8_t			status;
	uint8_t			slot;
	i2c_client_hdl_t	handle;
	hpc3130_slot_type_t	slot_type;
	uint_t			rc = DDI_INTR_UNCLAIMED;

	hpc3130_unit_t		*hpc3130_p = (hpc3130_unit_t *)arg;
	ASSERT(hpc3130_p);

	mutex_enter(&hpc3130_p->hpc3130_mutex);

	slot_type = hpc3130_p->slots_are;
	handle = hpc3130_p->hpc3130_hdl;

	for (slot = 0; slot < HPC3130_MAX_SLOT; slot++) {

		/*
		 * Read the interrupt event register - see
		 * which event(s) took place.
		 */
		if (hpc3130_read(handle, HPC3130_EVENT_STATUS, slot,
		    &interrupt)) {
			continue;
		}

		if (interrupt == 0)
			continue;

		rc = DDI_INTR_CLAIMED;

		if (hpc3130_debounce_status(handle,
		    slot, &status) != DDI_SUCCESS) {
			continue;
		}

		if (interrupt & HPC3130_PWRGOOD) {
			hpc3130_p->power[slot] = B_FALSE;
			if (!(status & HPC3130_PWRGOOD)) {
				hpc3130_p->power[slot] = B_TRUE;
			}
			cv_signal(&hpc3130_p->hpc3130_cond);
			hpc3130_p->events[slot] |= HPC3130_IEVENT_POWER;
		}

		if (interrupt & HPC3130_DETECT0) {
			if (slot_type == HPC3130_SLOT_TYPE_SBD) {
				boolean_t present = !(status&HPC3130_DETECT0);

				/* Turn ON/OFF OK-to-remove LED */
				(void) hpc3130_set_led(hpc3130_p,
				    slot,
				    HPC3130_LED_OK2REM,
				    (present ? HPC3130_ATTN_ON :
				    HPC3130_ATTN_OFF));
				if (!present) {
					/* Clear the FAULT LED on removal */
					(void) hpc3130_set_led(hpc3130_p,
					    slot,
					    HPC3130_LED_FAULT,
					    HPC3130_ATTN_OFF);
				}

				hpc3130_p->present[slot] = present;
				hpc3130_p->events[slot] |=
				    HPC3130_IEVENT_OCCUPANCY;
			} else {
				ASSERT(slot_type == HPC3130_SLOT_TYPE_PCI);

				if (!(status & HPC3130_DETECT0)) {
					/*
					 * Event on the downward
					 * stroke of the button.
					 */
					hpc3130_p->events[slot] |=
					    HPC3130_IEVENT_BUTTON;
				}
			}
		}

		if (interrupt & (HPC3130_PRSNT1 | HPC3130_PRSNT2)) {
			if (slot_type == HPC3130_SLOT_TYPE_SBD) {
				if (!(status & HPC3130_PRSNT1)) {
					/*
					 * Event only on the downward
					 * stroke of the button.
					 */
					hpc3130_p->events[slot] |=
					    HPC3130_IEVENT_BUTTON;
				}
			} else {
				ASSERT(slot_type == HPC3130_SLOT_TYPE_PCI);
				if ((status & (HPC3130_PRSNT1 |
				    HPC3130_PRSNT2)) ==
				    (HPC3130_PRSNT1 | HPC3130_PRSNT2)) {

					hpc3130_p->present[slot] = B_FALSE;

					/* Turn OFF Fault LED */
					(void) hpc3130_set_led(hpc3130_p,
					    slot,
					    HPC3130_LED_FAULT,
					    HPC3130_ATTN_OFF);
					/* Turn OFF OK-to-remove LED */
					(void) hpc3130_set_led(hpc3130_p,
					    slot,
					    HPC3130_LED_OK2REM,
					    HPC3130_ATTN_OFF);
				} else {

					hpc3130_p->present[slot] = B_TRUE;

					/* Turn ON OK-to-remove LED */
					(void) hpc3130_set_led(hpc3130_p,
					    slot,
					    HPC3130_LED_OK2REM,
					    HPC3130_ATTN_ON);
				}

				hpc3130_p->events[slot] |=
				    HPC3130_IEVENT_OCCUPANCY;
			}
		}
		if (hpc3130_p->events[slot] &&
		    (hpc3130_p->present[slot] == B_TRUE)) {
			mutex_exit(&hpc3130_p->hpc3130_mutex);
			pollwakeup(&hpc3130_p->pollhead[slot], POLLIN);
			mutex_enter(&hpc3130_p->hpc3130_mutex);
		}
		(void) hpc3130_write(handle, HPC3130_EVENT_STATUS,
		    slot, interrupt);
	}

	mutex_exit(&hpc3130_p->hpc3130_mutex);

	return (rc);
}

static int
hpc3130_cpu_init(hpc3130_unit_t *hpc3130_p, int slot, i2c_client_hdl_t handle)
{
	uint8_t	slot_status;
	uint8_t	control_reg;

	int	result = HPC_ERR_FAILED;

	if (hpc3130_read(handle, HPC3130_STATUS, slot,
	    &slot_status)) {
		goto out;
	}

	if (hpc3130_read(handle, HPC3130_CONTROL, slot,
	    &control_reg)) {
		goto out;
	}

	/*
	 * For the CPU slots, the DETECT[0] pin on the HPC3130
	 * goes low when a CPU module is in the slot. Pulled
	 * high otherwise.
	 */
	if (slot_status & HPC3130_DETECT0) {
		D1CMN_ERR((CE_NOTE, "hpc3130_cpu_init(): "
		    "[0x%x]Power off....[%d]",
		    slot_status, slot));
		control_reg = control_reg & ~HPC3130_SLTPWRCTL;
	} else {
		D1CMN_ERR((CE_NOTE, "hpc3130_cpu_init(): "
		    "[0x%x]Power LEFT on!!!....[%d]",
		    slot_status, slot));
		hpc3130_p->present[slot] = B_TRUE;
		control_reg = control_reg | HPC3130_SLTPWRCTL;

	}

	/*
	 * Set the control register accordingly
	 */
	if (hpc3130_write(handle, HPC3130_CONTROL,
	    slot, control_reg) != DDI_SUCCESS) {
		goto out;
	}

	result = DDI_SUCCESS;
out:

	return (result);
}

static int
hpc3130_debounce_status(i2c_client_hdl_t handle,
    int slot, uint8_t *status)
{
	int	count, limit;
	uint8_t	old;

	ASSERT(status);

	/*
	 * Get HPC3130_DEBOUNCE_COUNT consecutive equal
	 * readings from the status register
	 */

	count = 0; limit = 0; old = 0xff;
	do {
		if (hpc3130_read(handle, HPC3130_STATUS,
		    slot, status)) {
			return (DDI_FAILURE);
		}
		if (old != *status) {
			count = 0;
		} else {
			count += 1;
		}

		limit += 1;
		old = *status;

	} while (count < HPC3130_DEBOUNCE_COUNT &&
	    limit < HPC3130_DEBOUNCE_LIMIT);

	if (limit == HPC3130_DEBOUNCE_LIMIT) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
hpc3130_slot_connect(caddr_t ops_arg, hpc_slot_t slot_hdl,
    void *data, uint_t flags)
{
	_NOTE(ARGUNUSED(slot_hdl, data, flags))
	uint8_t			control;
	uint8_t			offset;
	uint8_t			config;
	uint8_t			status;
	hpc3130_unit_t		*hpc3130_p;
	i2c_client_hdl_t	handle;
	int			i;
	int			result = HPC_ERR_FAILED;
	hpc3130_slot_type_t	slot_type;
	hpc3130_slot_table_entry_t *ste;
	char			phys_slot[MAXPATHLEN];
	boolean_t		needs_to_be_powered_off = B_FALSE;

	hpc3130_callback_arg_t	*info_p = (hpc3130_callback_arg_t *)ops_arg;

	/*
	 * Callback parameter has specific device handle and offset
	 * information in it.
	 */

	hpc3130_p = (hpc3130_unit_t *)info_p->statep;
	ASSERT(hpc3130_p);

	mutex_enter(&hpc3130_p->hpc3130_mutex);

	handle = (i2c_client_hdl_t)info_p->handle;
	offset = info_p->offset;

	ste = &hpc3130_p->hpc3130_slot_table[offset];

	if (hpc3130_p->slots_are == HPC3130_SLOT_TYPE_SBD) {
		DAK_GET_SBD_APID(phys_slot, MAXPATHLEN, offset);
	} else {
		DAK_GET_PCI_APID(phys_slot, MAXPATHLEN,
		    hpc3130_lookup_slot(ste->nexus,
		    ste->hpc3130_slot_info.pci_dev_num));
	}

	ASSERT(ste->hpc3130_slot_handle != NULL);

	slot_type = hpc3130_p->slots_are;

	if (hpc3130_p->enabled[offset] == B_FALSE) {
		cmn_err(CE_WARN, "hot-plug disabled on %s", phys_slot);
		goto out;
	}

	/* Return (do nothing) if power already applied */
	if (hpc3130_p->power[offset] == B_TRUE) {
		D1CMN_ERR((CE_NOTE, "Slot power already on %s", phys_slot));
		mutex_exit(&hpc3130_p->hpc3130_mutex);
		return (HPC_SUCCESS);
	}

	if (hpc3130_read(handle, HPC3130_STATUS, offset,
	    &status)) {
		goto out;
	}

	/* Read the slot control register to get current value */
	if (hpc3130_read(handle, HPC3130_CONTROL, offset,
	    &control)) {
		goto out;
	}

	if (slot_type == HPC3130_SLOT_TYPE_SBD) {

		D1CMN_ERR((CE_NOTE, "CPU connect %d control=%x status=%x",
		    offset, control, status));

		control = control | HPC3130_SLTPWRCTL;
		if (hpc3130_write(handle, HPC3130_CONTROL, offset,
		    control) != DDI_SUCCESS) {
			goto out;
		}

	} else {

		D1CMN_ERR((CE_NOTE, "PCI connect %d", offset));

		/*
		 * PCI needs special sequencing of the control signals.
		 */

		if (hpc3130_read(handle, HPC3130_GCR, offset,
		    &config)) {
			goto out;
		}

		/* Assert RST to comply with PCI spec. */
		control &= ~HPC3130_SLOTRST;
		if (hpc3130_write(handle, HPC3130_CONTROL, offset,
		    control) != DDI_SUCCESS) {
			goto out;
		}
		drv_usecwait(HPC3130_ADEQUATE_PAUSE);

		/* Send the power on signal and verify the result */
		control = control | HPC3130_SLTPWRCTL;
		if ((hpc3130_write(handle, HPC3130_CONTROL, offset,
		    control) != DDI_SUCCESS) ||
		    (hpc3130_verify_slot_power(hpc3130_p, handle, offset,
		    phys_slot, B_TRUE) == HPC_ERR_FAILED)) {
			goto out;
		}

		/* The slot is now powered on. */

		drv_usecwait(HPC3130_ADEQUATE_PAUSE);

		/* Extinguish the "OK-to-remove" indicator */
		(void) hpc3130_set_led(hpc3130_p, offset, HPC3130_LED_OK2REM,
		    HPC3130_ATTN_OFF);

		/*
		 * Perform bus/card speed check functions.
		 */
		if (hpc3130_read(handle, HPC3130_STATUS, offset, &status)) {
			goto out;
		}
		if ((config & HPC3130_SYSM66STAT) &&
		    !(status & HPC3130_M66EN)) {
			cmn_err(CE_WARN, "66Mhz bus can't accept "
			    "33Mhz card in %s", phys_slot);
			needs_to_be_powered_off = B_TRUE;
			goto out;
		}
		if (!(config & HPC3130_SYSM66STAT) &&
		    (status & HPC3130_M66EN)) {
			cmn_err(CE_NOTE, "66Mhz capable card throttled "
			    "back to 33Mhz in %s", phys_slot);
		}

		/*
		 * Send the connect sequence (see struct connect_sequence)
		 */
		for (i = 0; i < HPC3130_CONNECT_SEQ_COUNT; i++) {
			if (connect_sequence[i].set_bit == B_TRUE) {
				control |= connect_sequence[i].value;
			} else {
				control &= ~connect_sequence[i].value;
			}
			if (hpc3130_write(handle, HPC3130_CONTROL, offset,
			    control) != DDI_SUCCESS) {
				goto out;
			}
			drv_usecwait(HPC3130_ADEQUATE_PAUSE);
		}
	}

	(void) hpc_slot_event_notify(ste->hpc3130_slot_handle,
	    HPC_EVENT_SLOT_POWER_ON, 0);

	/* Flash the "fault" indicator */
	(void) hpc3130_set_led(hpc3130_p, offset, HPC3130_LED_FAULT,
	    HPC3130_ATTN_SLO);

	result = HPC_SUCCESS;

out:
	if (needs_to_be_powered_off == B_TRUE) {
		/*
		 * We are in an error state where the slot is powered on, and
		 * it must be powered off.
		 */

		/* Send the power off signal and verify the result */
		control = control & ~HPC3130_SLTPWRCTL;
		if ((hpc3130_write(handle, HPC3130_CONTROL, offset,
		    control) == DDI_SUCCESS) &&
		    (hpc3130_verify_slot_power(hpc3130_p, handle, offset,
		    phys_slot, B_FALSE) == HPC_SUCCESS)) {
			/* Re-light "OK-to-remove" LED */
			(void) hpc3130_set_led(hpc3130_p, offset,
			    HPC3130_LED_OK2REM, HPC3130_ATTN_ON);
		}
	}

	mutex_exit(&hpc3130_p->hpc3130_mutex);

	return (result);
}


static int
hpc3130_slot_disconnect(caddr_t ops_arg, hpc_slot_t slot_hdl,
    void *data, uint_t flags)
{
	_NOTE(ARGUNUSED(slot_hdl, data, flags))
	uint8_t			control;
	uint8_t			offset;
	i2c_client_hdl_t	handle;
	hpc3130_unit_t		*hpc3130_p;
	int			result = HPC_ERR_FAILED;
	hpc3130_slot_type_t	slot_type;
	hpc3130_slot_table_entry_t *ste;
	char			phys_slot[MAXPATHLEN];

	hpc3130_callback_arg_t	*info_p = (hpc3130_callback_arg_t *)ops_arg;

	/*
	 * Callback parameter has specific device handle and offset
	 * information in it.
	 */
	hpc3130_p = (hpc3130_unit_t *)info_p->statep;
	ASSERT(hpc3130_p);

	mutex_enter(&hpc3130_p->hpc3130_mutex);

	handle = (i2c_client_hdl_t)info_p->handle;
	offset = info_p->offset;

	ASSERT(handle == hpc3130_p->hpc3130_hdl);

	ste = &hpc3130_p->hpc3130_slot_table[offset];

	if (hpc3130_p->slots_are == HPC3130_SLOT_TYPE_SBD) {
		DAK_GET_SBD_APID(phys_slot, MAXPATHLEN, offset);
	} else {
		DAK_GET_PCI_APID(phys_slot, MAXPATHLEN,
		    hpc3130_lookup_slot(ste->nexus,
		    ste->hpc3130_slot_info.pci_dev_num));
	}

	ASSERT(ste->hpc3130_slot_handle != NULL);

	slot_type = hpc3130_p->slots_are;

	/*
	 * Read the slot control register to get current value
	 */
	if (hpc3130_read(handle, HPC3130_CONTROL, offset,
	    &control)) {
		goto out;
	}

	if (slot_type == HPC3130_SLOT_TYPE_SBD) {

		D1CMN_ERR((CE_NOTE, "CPU disconnect %d", offset));

		control = control & ~HPC3130_SLTPWRCTL;
		/*
		 * Write out the modified control register
		 */
		if (hpc3130_write(handle, HPC3130_CONTROL, offset,
		    control) != DDI_SUCCESS) {
			goto out;
		}
	} else {

		D1CMN_ERR((CE_NOTE, "PCI disconnect %d", offset));

		control &= ~HPC3130_SLOTRST;
		if (hpc3130_write(handle, HPC3130_CONTROL, offset,
		    control) != DDI_SUCCESS) {
			goto out;
		}

		control |= HPC3130_BUS_CTL;
		if (hpc3130_write(handle, HPC3130_CONTROL, offset,
		    control) != DDI_SUCCESS) {
			goto out;
		}
	}

	D1CMN_ERR((CE_WARN, "disconnect present[%d]==%d",
	    offset, hpc3130_p->present[offset]));

	if (hpc3130_verify_slot_power(hpc3130_p, handle, offset,
	    phys_slot, B_FALSE) == HPC_ERR_FAILED) {
		goto out;
	}

	(void) hpc_slot_event_notify(ste->hpc3130_slot_handle,
	    HPC_EVENT_SLOT_POWER_OFF, 0);

	if (hpc3130_p->present[offset] == B_TRUE) {
		/*
		 * Illuminate the "OK-to-remove" indicator
		 * if there is a card in the slot.
		 */

		(void) hpc3130_set_led(hpc3130_p, offset, HPC3130_LED_OK2REM,
		    HPC3130_ATTN_ON);

		/*
		 * Turn off the "fault" indicator
		 */
		(void) hpc3130_set_led(hpc3130_p, offset, HPC3130_LED_FAULT,
		    HPC3130_ATTN_OFF);
	} else {
		/*
		 * If the slot is being powered off with
		 * no cards in there, its at "boot time",
		 * put the LEDs in a sane state
		 */
		if (slot_type == HPC3130_SLOT_TYPE_PCI) {
			(void) hpc3130_set_led(hpc3130_p, offset,
			    HPC3130_LED_FAULT, HPC3130_ATTN_OFF);
			(void) hpc3130_set_led(hpc3130_p, offset,
			    HPC3130_LED_OK2REM, HPC3130_ATTN_OFF);
		}
	}

	result = HPC_SUCCESS;
out:
	mutex_exit(&hpc3130_p->hpc3130_mutex);

	return (result);
}

static int
hpc3130_verify_slot_power(hpc3130_unit_t *hpc3130_p, i2c_client_hdl_t handle,
    uint8_t offset, char *phys_slot, boolean_t slot_target_state)
{
	uint8_t			tries = 0;
	uint8_t			status;
	int			result = HPC_SUCCESS;
	clock_t			timeleft;
	clock_t			tm = drv_usectohz(300000);
	boolean_t		slot_actual_state;
	boolean_t		failure = B_FALSE;
	hpc3130_slot_table_entry_t *ste;

	/* This function is called while holding the hpc3130 mutex. */

	/*
	 * For slot_target_state and slot_actual_state:
	 *    B_TRUE  == the slot is powered on
	 *    B_FALSE == the slot is powered off
	 */

	ste = &hpc3130_p->hpc3130_slot_table[offset];
	slot_actual_state = hpc3130_p->power[offset];

	while ((slot_actual_state != slot_target_state) &&
	    (failure != B_TRUE)) {
		timeleft = cv_reltimedwait(&hpc3130_p->hpc3130_cond,
		    &hpc3130_p->hpc3130_mutex, tm, TR_CLOCK_TICK);
		if (timeleft == -1) {
			if (tries++ < HPC3130_POWER_TRIES) {
				/*
				 * The interrupt was missed - explicitly
				 * check the status.
				 */
				if (hpc3130_read(handle,
				    HPC3130_STATUS, offset, &status)) {
					failure = B_TRUE;
					continue;
				}
				if (status & HPC3130_PWRGOOD) {
					slot_actual_state = B_FALSE;
				} else {
					slot_actual_state = B_TRUE;
				}
				hpc3130_p->power[offset] = slot_actual_state;
			} else {
				/* Too many tries.  We failed. */
				failure = B_TRUE;
			}
		}
	}

	if (failure == B_TRUE) {
		result = HPC_ERR_FAILED;
		if (slot_target_state == B_TRUE) {
			cmn_err(CE_WARN,
			    "Could not power on slot %s", phys_slot);
		} else {
			cmn_err(CE_WARN,
			    "Could not power off slot %s", phys_slot);
		}
		(void) hpc3130_set_led(hpc3130_p, offset, HPC3130_LED_FAULT,
		    HPC3130_ATTN_ON);
		(void) hpc_slot_event_notify(ste->hpc3130_slot_handle,
		    HPC_EVENT_SLOT_NOT_HEALTHY, 0);
	}

	return (result);
}

static int
hpc3130_slot_insert(caddr_t ops_arg, hpc_slot_t slot_hdl,
    void *data, uint_t flags)
{
	_NOTE(ARGUNUSED(ops_arg, slot_hdl, data, flags))
	return (HPC_ERR_NOTSUPPORTED);
}

static int
hpc3130_slot_remove(caddr_t ops_arg, hpc_slot_t slot_hdl,
    void *data, uint_t flags)
{
	_NOTE(ARGUNUSED(ops_arg, slot_hdl, data, flags))
	return (HPC_ERR_NOTSUPPORTED);
}

static int
hpc3130_slot_control(caddr_t ops_arg, hpc_slot_t slot_hdl,
    int request, caddr_t arg)
{
	_NOTE(ARGUNUSED(slot_hdl))
	i2c_client_hdl_t	handle;
	uint8_t			offset;
	uint8_t			state;
	hpc_led_info_t		*led_info;
	hpc3130_unit_t		*hpc3130_p;
	hpc3130_slot_type_t	slot_type;

	hpc3130_callback_arg_t	*info_p = (hpc3130_callback_arg_t *)ops_arg;

	/*
	 * Callback parameter has specific device handle and offset
	 * information in it.
	 */

	hpc3130_p = (hpc3130_unit_t *)info_p->statep;
	ASSERT(hpc3130_p);

	mutex_enter(&hpc3130_p->hpc3130_mutex);

	handle = (i2c_client_hdl_t)info_p->handle;
	offset = info_p->offset;

	ASSERT(handle == hpc3130_p->hpc3130_hdl);

	slot_type = hpc3130_p->slots_are;

	switch (request) {
		case HPC_CTRL_GET_LED_STATE: {
			int led;

			led_info = (hpc_led_info_t *)arg;
			if (led_info->led != HPC_FAULT_LED &&
			    led_info->led != HPC_ATTN_LED) {
				D1CMN_ERR((CE_WARN,
				    "Only FAULT and ATTN leds allowed"));
				mutex_exit(&hpc3130_p->hpc3130_mutex);
				return (HPC_ERR_INVALID);
			}

			if (led_info->led == HPC_FAULT_LED)
				led = HPC3130_LED_FAULT;
			else
				led = HPC3130_LED_OK2REM;

			if (hpc3130_get_led(handle, offset, led, &state) !=
			    DDI_SUCCESS) {
				mutex_exit(&hpc3130_p->hpc3130_mutex);
				return (HPC_ERR_FAILED);
			}

			/* Make sure that no one broke the conversion macros */
			ASSERT(state < sizeof (hpc3130_to_hpc_led_map));
			ASSERT(state ==
			    HPC3130_FROM_HPC_LED(HPC3130_TO_HPC_LED(state)));

			led_info->state = HPC3130_TO_HPC_LED(state);
		}
		break;
		case HPC_CTRL_SET_LED_STATE: {
			int led;

			/*
			 * The HPC3130 support modifications to the Fault and
			 * Ok-to-remove LEDs.
			 */
			led_info = (hpc_led_info_t *)arg;
			if (led_info->led != HPC_FAULT_LED &&
			    led_info->led != HPC_ATTN_LED) {
				D1CMN_ERR((CE_WARN,
				    "Only FAULT and ATTN leds allowed"));
				mutex_exit(&hpc3130_p->hpc3130_mutex);
				return (HPC_ERR_INVALID);
			}

			if (led_info->led == HPC_FAULT_LED)
				led = HPC3130_LED_FAULT;
			else
				led = HPC3130_LED_OK2REM;

			state = led_info->state;
			if (state >= sizeof (hpc3130_from_hpc_led_map) ||
			    (state != HPC3130_TO_HPC_LED(
			    HPC3130_FROM_HPC_LED(state)))) {
				D1CMN_ERR((CE_WARN,
				    "Improper LED value: %d %d", state,
				    HPC3130_TO_HPC_LED(
				    HPC3130_FROM_HPC_LED(state))));
				mutex_exit(&hpc3130_p->hpc3130_mutex);
				return (HPC_ERR_INVALID);
			}

			(void) hpc3130_set_led(hpc3130_p, offset, led,
			    HPC3130_FROM_HPC_LED(state));
		}
		break;
		case HPC_CTRL_GET_SLOT_STATE: {
			if (hpc3130_p->power[offset] == B_FALSE) {
				if (hpc3130_p->present[offset] == B_FALSE) {
					*(ap_rstate_t *)arg =
					    AP_RSTATE_EMPTY;
				} else {
					*(ap_rstate_t *)arg =
					    AP_RSTATE_DISCONNECTED;
				}
			} else {
				*(ap_rstate_t *)arg =
				    AP_RSTATE_CONNECTED;
			}
		}
		break;
		case HPC_CTRL_GET_BOARD_TYPE: {
			*(hpc_board_type_t *)arg =
			    (slot_type == HPC3130_SLOT_TYPE_SBD ?
			    HPC_BOARD_UNKNOWN : HPC_BOARD_PCI_HOTPLUG);
		}
		break;
		case HPC_CTRL_DEV_CONFIG_START:
		case HPC_CTRL_DEV_UNCONFIG_START:
			(void) hpc3130_set_led(hpc3130_p, offset,
			    HPC3130_LED_FAULT, HPC3130_ATTN_SLO);
		break;
		case HPC_CTRL_DEV_CONFIG_FAILURE:
			(void) hpc3130_set_led(hpc3130_p, offset,
			    HPC3130_LED_FAULT, HPC3130_ATTN_ON);
		break;
		case HPC_CTRL_DEV_CONFIGURED:
			(void) hpc3130_set_led(hpc3130_p, offset,
			    HPC3130_LED_FAULT, HPC3130_ATTN_OFF);
			hpc3130_p->present[offset] = B_TRUE;
		break;
		case HPC_CTRL_DEV_UNCONFIGURED:
			if (hpc3130_p->power[offset] == B_TRUE) {
				(void) hpc3130_set_led(hpc3130_p, offset,
				    HPC3130_LED_FAULT, HPC3130_ATTN_SLO);
			} else {
				(void) hpc3130_set_led(hpc3130_p, offset,
				    HPC3130_LED_FAULT, HPC3130_ATTN_OFF);
			}
		break;
		case HPC_CTRL_DISABLE_SLOT: {
			hpc3130_p->enabled[offset] = B_FALSE;
		}
		break;
		case HPC_CTRL_ENABLE_SLOT: {
			hpc3130_p->enabled[offset] = B_TRUE;
		}
		break;
		default:
			mutex_exit(&hpc3130_p->hpc3130_mutex);
			return (HPC_ERR_FAILED);
	}
	mutex_exit(&hpc3130_p->hpc3130_mutex);
	return (HPC_SUCCESS);
}

int
hpc3130_lookup_slot(char *nexus, int pcidev)
{
	int	i = 0;

	while (i < HPC3130_LOOKUP_SLOTS &&
	    (slot_translate[i].pcidev != pcidev ||
	    strcmp(nexus, slot_translate[i].nexus) != 0))
		i++;
	ASSERT(i != HPC3130_LOOKUP_SLOTS);
	return (i);
}

/*
 * A routine to convert a number (represented as a string) to
 * the integer value it represents.
 */

static int
isdigit(int ch)
{
	return (ch >= '0' && ch <= '9');
}

#define	isspace(c)	((c) == ' ' || (c) == '\t' || (c) == '\n')
#define	bad(val)	(val == NULL || !isdigit(*val))

static int
hpc3130_atoi(const char *p)
{
	int n;
	int c, neg = 0;

	if (!isdigit(c = *p)) {
		while (isspace(c))
			c = *++p;
		switch (c) {
		case '-':
			neg++;
			/* FALLTHROUGH */
		case '+':
			c = *++p;
		}
		if (!isdigit(c))
			return (0);
	}
	for (n = '0' - c; isdigit(c = *++p); ) {
		n *= 10; /* two steps to avoid unnecessary overflow */
		n += '0' - c; /* accum neg to avoid surprises at MAX */
	}
	return (neg ? n : -n);
}
