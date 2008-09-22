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
 * Driver to control Alert and Power LEDs  for the Seattle platform.
 * Alert LED is also known as Service (required).
 * Power LED is also known as Activity.
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
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/note.h>
#include <sys/epic.h>


/*
 * Some #defs that must be here as they differ for power.c
 * and epic.c
 */
#define	EPIC_REGS_OFFSET	0x00
#define	EPIC_REGS_LEN		0x80

#define	EPIC_IND_DATA		0x40
#define	EPIC_IND_ADDR		0x41
#define	EPIC_WRITE_MASK		0x80

/* dev_ops and cb_ops entry point function declarations */
static int	epic_attach(dev_info_t *, ddi_attach_cmd_t);
static int	epic_detach(dev_info_t *, ddi_detach_cmd_t);
static int	epic_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	epic_open(dev_t *, int, int, cred_t *);
static int	epic_close(dev_t, int, int, cred_t *);
static int	epic_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

struct cb_ops epic_cb_ops = {
	epic_open,		/* open */
	epic_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	epic_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	ddi_segmap,		/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab - for STREAMS drivers */
	D_NEW | D_MP		/* driver compatibility flag */
};

static struct dev_ops epic_dev_ops = {
	DEVO_REV,		/* driver build version */
	0,			/* device reference count */
	epic_getinfo,
	nulldev,
	nulldev,		/* probe */
	epic_attach,
	epic_detach,
	nulldev,		/* reset */
	&epic_cb_ops,
	(struct bus_ops *)NULL,
	nulldev,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


/*
 * Soft state
 */
struct epic_softc {
	dev_info_t	*dip;
	kmutex_t	mutex;
	uint8_t		*cmd_reg;
	ddi_acc_handle_t cmd_handle;
};

#define	getsoftc(inst)	((struct epic_softc *)ddi_get_soft_state(statep, \
(inst)))

/* module configuration stuff */
static void    *statep;
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"epic_client driver",
	&epic_dev_ops
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

	if ((e = ddi_soft_state_init(&statep,
		sizeof (struct epic_softc), 0)) != 0) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&statep);

	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0)
		return (e);

	ddi_soft_state_fini(&statep);

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
epic_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int	inst;
	int	retval = DDI_SUCCESS;
	struct epic_softc *softc;

	inst = (getminor((dev_t)arg));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((softc = getsoftc(inst)) == NULL) {
			*result = (void *)NULL;
			retval = DDI_FAILURE;
		} else
			*result = (void *)softc->dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)inst;
		break;

	default:
		retval = DDI_FAILURE;
	}

	return (retval);
}

static int
epic_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int inst;
	struct epic_softc *softc = NULL;
	int minor;
	char name[MAXNAMELEN];
	ddi_device_acc_attr_t dev_attr;
	int res;

	switch (cmd) {
	case DDI_ATTACH:
		inst = ddi_get_instance(dip);
		(void) sprintf(name, "env-monitor%d", inst);
		minor = inst;
		if (ddi_create_minor_node(dip, name, S_IFCHR, minor,
		    DDI_PSEUDO, NULL) == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "ddi_create_minor_node() failed for inst %d\n",
			    inst);
			return (DDI_FAILURE);
		}

		/* Allocate a soft state structure for this instance */
		if (ddi_soft_state_zalloc(statep, inst) != DDI_SUCCESS) {
			cmn_err(CE_WARN, " ddi_soft_state_zalloc() failed "
			    "for inst %d\n", inst);
			break;
		}

		/* Setup soft state */
		if ((softc = getsoftc(inst)) == NULL) {
			break;
		}
		softc->dip = dip;
		mutex_init(&softc->mutex, NULL, MUTEX_DRIVER, NULL);

		/* Setup device attributes */
		dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
		dev_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
		dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

		res = ddi_regs_map_setup(dip, 0, (caddr_t *)&softc->cmd_reg,
		    EPIC_REGS_OFFSET, EPIC_REGS_LEN, &dev_attr,
		    &softc->cmd_handle);

		if (res != DDI_SUCCESS) {
			cmn_err(CE_WARN, "ddi_regs_map_setup() failed\n");
			break;
		}

		ddi_report_dev(dip);


		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* Attach failed */
	/* Free soft state, if allocated. remove minor node if added earlier */
	if (softc)
		ddi_soft_state_free(statep, inst);

	ddi_remove_minor_node(dip, NULL);

	return (DDI_FAILURE);
}

static int
epic_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst;
	struct epic_softc *softc;

	switch (cmd) {
	case DDI_DETACH:
		inst = ddi_get_instance(dip);
		if ((softc = getsoftc(inst)) == NULL)
			return (ENXIO);

		(void) ddi_regs_map_free(&softc->cmd_handle);


		/* Free the soft state and remove minor node added earlier */
		mutex_destroy(&softc->mutex);
		ddi_soft_state_free(statep, inst);
		ddi_remove_minor_node(dip, NULL);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
epic_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flag))
	_NOTE(ARGUNUSED(otyp))
	_NOTE(ARGUNUSED(credp))

	int	inst = getminor(*devp);

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}

/*ARGSUSED*/
static int
epic_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flag))
	_NOTE(ARGUNUSED(otyp))
	_NOTE(ARGUNUSED(credp))

	int	inst = getminor(dev);

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}

/*ARGSUSED*/
static int
epic_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
int *rvalp)
{
	_NOTE(ARGUNUSED(credp))

	int	inst;
	struct epic_softc *softc;
	uint8_t	in_command;

	inst = getminor(dev);
	if ((softc = getsoftc(inst)) == NULL)
		return (ENXIO);

	mutex_enter(&softc->mutex);

	switch (cmd) {
	case EPIC_SET_POWER_LED:
		EPIC_WRITE(softc->cmd_handle, softc->cmd_reg,
		    EPIC_IND_LED_STATE0, EPIC_POWER_LED_MASK,
		    EPIC_POWER_LED_ON);
		break;
	case EPIC_RESET_POWER_LED:
		EPIC_WRITE(softc->cmd_handle, softc->cmd_reg,
		    EPIC_IND_LED_STATE0, EPIC_POWER_LED_MASK,
		    EPIC_POWER_LED_OFF);
		break;
	case EPIC_SB_BL_POWER_LED:
		EPIC_WRITE(softc->cmd_handle, softc->cmd_reg,
		    EPIC_IND_LED_STATE0, EPIC_POWER_LED_MASK,
		    EPIC_POWER_LED_SB_BLINK);
		break;
	case EPIC_FAST_BL_POWER_LED:
		EPIC_WRITE(softc->cmd_handle, softc->cmd_reg,
		    EPIC_IND_LED_STATE0, EPIC_POWER_LED_MASK,
		    EPIC_POWER_LED_FAST_BLINK);
		break;
	case EPIC_SET_ALERT_LED:
		EPIC_WRITE(softc->cmd_handle, softc->cmd_reg,
		    EPIC_IND_LED_STATE0, EPIC_ALERT_LED_MASK,
		    EPIC_ALERT_LED_ON);
		break;
	case EPIC_RESET_ALERT_LED:
		EPIC_WRITE(softc->cmd_handle, softc->cmd_reg,
		    EPIC_IND_LED_STATE0, EPIC_ALERT_LED_MASK,
		    EPIC_ALERT_LED_OFF);
		break;
	case EPIC_GET_FW:
		EPIC_READ(softc->cmd_handle, softc->cmd_reg,
		    in_command, EPIC_IND_FW_VERSION);
		if (ddi_copyout((void *)(&in_command), (void *)arg,
		    sizeof (in_command), mode) != DDI_SUCCESS) {
			mutex_exit(&softc->mutex);
			return (EFAULT);
		}
		break;
	default:
		mutex_exit(&softc->mutex);
		cmn_err(CE_WARN, "epic: cmd %d is not valid", cmd);
		return (EINVAL);
	}

	mutex_exit(&softc->mutex);
	return (0);
}
