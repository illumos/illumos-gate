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
 * Driver to map the PIC for the chicago platform.
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
#include <sys/pic.h>
#include <sys/pic16f747.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>

/* dev_ops and cb_ops entry point function declarations */
static int	pic_attach(dev_info_t *, ddi_attach_cmd_t);
static int	pic_detach(dev_info_t *, ddi_detach_cmd_t);
static int	pic_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	pic_open(dev_t *, int, int, cred_t *);
static int	pic_close(dev_t, int, int, cred_t *);
static int	pic_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

struct cb_ops pic_cb_ops = {
	pic_open,
	pic_close,
	nodev,
	nodev,
	nodev,			/* dump */
	nodev,
	nodev,
	pic_ioctl,
	nodev,			/* devmap */
	nodev,
	ddi_segmap,		/* segmap */
	nochpoll,
	ddi_prop_op,
	NULL,			/* for STREAMS drivers */
	D_NEW | D_MP		/* driver compatibility flag */
};

static struct dev_ops pic_dev_ops = {
	DEVO_REV,		/* driver build version */
	0,			/* device reference count */
	pic_getinfo,
	nulldev,
	nulldev,		/* probe */
	pic_attach,
	pic_detach,
	nulldev,		/* reset */
	&pic_cb_ops,
	(struct bus_ops *)NULL,
	nulldev,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Fans' and sensors' node names and register offsets
 */
static struct minor_node_info pic_nodes[N_PIC_NODES] = {
	{NULL, 0, 0},				/* Reserved */
	{"fan_0", RF_FAN0_PERIOD, F0_FLT_BIT},	/* System Fan 0 */
	{"fan_1", RF_FAN1_PERIOD, F1_FLT_BIT},	/* System Fan 1 */
	{"fan_2", RF_FAN2_PERIOD, F2_FLT_BIT},	/* System Fan 2 */
	{"fan_3", RF_FAN3_PERIOD, F3_FLT_BIT},	/* System Fan 3 */
	{"fan_4", RF_FAN4_PERIOD, F4_FLT_BIT},	/* System Fan 4 */
	{"adt7462", RF_LOCAL_TEMP, 0},		/* ADT7462 Local Temperature */
	{"cpu_0", RF_REMOTE1_TEMP, 0},		/* CPU 0 temp */
	{"cpu_1", RF_REMOTE2_TEMP, 0},		/* CPU 1 temp */
	{"mb", RF_REMOTE3_TEMP, 0},		/* Motherboard temp */
	{"lm95221", RF_LM95221_TEMP, 0},	/* LM95221 Local Temperature */
	{"fire", RF_FIRE_TEMP, 0},		/* FIRE Temp */
	{"lsi1064", RF_LSI1064_TEMP, 0},	/* LSI1064 Temp */
	{"front_panel", RF_FRONT_TEMP, 0},	/* Front Panel Temperature */
	{"psu", RF_PSU_TEMP, PSUF_FLT_BIT}	/* PSU Temp (and ffault) */
};

/*
 * Soft state
 */
struct pic_softc {
	dev_info_t	*dip;
	kmutex_t	mutex;
	uint8_t		*cmd_reg;
	ddi_acc_handle_t cmd_handle;
};
#define	getsoftc(inst)	((struct pic_softc *)ddi_get_soft_state(statep, (inst)))

/* module configuration stuff */
static void    *statep;
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"pic_client driver",
	&pic_dev_ops
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

	if (e = ddi_soft_state_init(&statep, sizeof (struct pic_softc),
	    MAX_PIC_INSTANCES)) {
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
pic_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int	inst;
	int	retval = DDI_SUCCESS;
	struct pic_softc *softc;

	inst = PIC_MINOR_TO_INST(getminor((dev_t)arg));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((softc = getsoftc(inst)) == NULL) {
			*result = (void *)NULL;
			retval = DDI_FAILURE;
		} else
			*result = (void *)softc->dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)((uintptr_t)inst);
		break;

	default:
		retval = DDI_FAILURE;
	}

	return (retval);
}

static int
pic_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int inst;
	int i;
	struct pic_softc *softc = NULL;
	char		*minor_name;
	int minor;
	char name[80];
	ddi_device_acc_attr_t dev_attr;
	int res;

	switch (cmd) {
	case DDI_ATTACH:
		inst = ddi_get_instance(dip);
		if (inst >= MAX_PIC_INSTANCES) {
			cmn_err(CE_WARN, "attach failed, too many instances\n");
			return (DDI_FAILURE);
		}

		(void) sprintf(name, "env-monitor%d", inst);
		minor = PIC_INST_TO_MINOR(inst) | PIC_UNIT_TO_MINOR(0);
		if (ddi_create_minor_node(dip, name, S_IFCHR, minor,
		    DDI_PSEUDO, 0) == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "ddi_create_minor_node() failed for inst %d\n",
			    inst);
			return (DDI_FAILURE);
		}

		/* Allocate a soft state structure for this instance */
		if (ddi_soft_state_zalloc(statep, inst) != DDI_SUCCESS) {
			cmn_err(CE_WARN, " ddi_soft_state_zalloc() failed "
			    "for inst %d\n", inst);
			goto attach_failed;
		}

		/* Setup soft state */
		softc = getsoftc(inst);
		softc->dip = dip;
		mutex_init(&softc->mutex, NULL, MUTEX_DRIVER, NULL);

		/* Setup device attributes */
		dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
		dev_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
		dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

		/*
		 * The RF_COMMAND/RF_STATUS and RF_IND_DATA/RF_IND_ADDR
		 * register pairs are mapped as one register set starting
		 * from 0x0 and length 0x42.
		 */
		res = ddi_regs_map_setup(dip, 0, (caddr_t *)&softc->cmd_reg,
		    0, 0x42, &dev_attr, &softc->cmd_handle);
		if (res != DDI_SUCCESS) {
			cmn_err(CE_WARN, "ddi_regs_map_setup() failed\n");
			goto attach_failed;
		}

		/* Set up fans' and sensors' device minor nodes */
		for (i = 1; i < N_PIC_NODES; i++) {
			minor_name = pic_nodes[i].minor_name;
			minor = PIC_INST_TO_MINOR(inst) | PIC_UNIT_TO_MINOR(i);
			if (ddi_create_minor_node(dip, minor_name, S_IFCHR,
			    minor, PICDEV_NODE_TYPE, 0) == DDI_FAILURE) {
				cmn_err(CE_WARN,
				    "%s:%d ddi_create_minor_node failed",
				    ddi_driver_name(dip), inst);
				(void) pic_detach(dip, DDI_DETACH);
				return (DDI_FAILURE);
			}
		}

		/* Create main environmental node */
		ddi_report_dev(dip);

		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

attach_failed:

	/* Free soft state, if allocated. remove minor node if added earlier */
	if (softc)
		ddi_soft_state_free(statep, inst);

	ddi_remove_minor_node(dip, NULL);

	return (DDI_FAILURE);
}

static int
pic_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst;
	struct pic_softc *softc;

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
pic_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int	inst = PIC_MINOR_TO_INST(getminor(*devp));

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}

/*ARGSUSED*/
static int
pic_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int	inst = PIC_MINOR_TO_INST(getminor(dev));

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}

/*ARGSUSED*/
static int
pic_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	int	inst;
	int	node;
	struct pic_softc *softc;
	uint8_t	in_command;
	int16_t	tempr;

	inst = PIC_MINOR_TO_INST(getminor(dev));
	if ((softc = getsoftc(inst)) == NULL)
		return (ENXIO);

	mutex_enter(&softc->mutex);

	if (ddi_copyin((caddr_t)arg, &in_command, sizeof (in_command),
	    mode) != DDI_SUCCESS) {
		mutex_exit(&softc->mutex);
		return (EFAULT);
	}

	node = PIC_MINOR_TO_UNIT(getminor(dev));
	if ((node >= N_PIC_NODES) || (node < 1)) {
		mutex_exit(&softc->mutex);
		return (ENXIO);
	}

	switch (cmd) {
	case PIC_GET_TEMPERATURE:
		drv_usecwait(10);

		/* select the temp sensor */
		(void) ddi_put8(softc->cmd_handle, (uint8_t *)softc->cmd_reg +
		    RF_IND_ADDR, pic_nodes[node].reg_offset);

		/* retrieve temperature data */
		tempr =  (int16_t)ddi_get8(softc->cmd_handle,
		    (uint8_t *)softc->cmd_reg + RF_IND_DATA);
		mutex_exit(&softc->mutex);

		if (tempr == 0xff)
			return (EIO);

		/*
		 * The temp is passed in as a uint8 value, we need to convert
		 * it to a signed 16 bit value to be able to handle the range
		 * of -64 to 190 degrees.
		 */
		tempr -= 64;
		(void) ddi_copyout(&tempr, (caddr_t)arg, sizeof (tempr), mode);
		return (0);

	case PIC_GET_FAN_SPEED:
		drv_usecwait(10);

		/* select fan */
		(void) ddi_put8(softc->cmd_handle, (uint8_t *)softc->cmd_reg +
		    RF_IND_ADDR, pic_nodes[node].reg_offset);

		/* retrieve fan data */
		in_command =  ddi_get8(softc->cmd_handle,
		    (uint8_t *)softc->cmd_reg + RF_IND_DATA);
		mutex_exit(&softc->mutex);

		if (in_command == 0xff)
			return (EIO);

		(void) ddi_copyout(&in_command, (caddr_t)arg, 1, mode);
		return (0);

	case PIC_SET_FAN_SPEED:
		/* select fan */
		(void) ddi_put8(softc->cmd_handle, (uint8_t *)softc->cmd_reg +
		    RF_IND_ADDR, pic_nodes[node].reg_offset);

		/* send the fan data */
		(void) ddi_put8(softc->cmd_handle,
		    (uint8_t *)softc->cmd_reg + RF_IND_DATA, in_command);

		mutex_exit(&softc->mutex);
		return (0);

	case PIC_GET_STATUS:
		mutex_exit(&softc->mutex);

		/* we don't read the status reg anymore */
		in_command = 0;
		(void) ddi_copyout(&in_command, (caddr_t)arg, 1, mode);

		return (0);

	case PIC_GET_FAN_STATUS:
		drv_usecwait(10);

		/* read ffault register */
		(void) ddi_put8(softc->cmd_handle, (uint8_t *)softc->cmd_reg +
		    RF_IND_ADDR, RF_FAN_STATUS);

		/* retrieve fan failure status */
		in_command = ddi_get8(softc->cmd_handle,
		    (uint8_t *)softc->cmd_reg + RF_IND_DATA);
		mutex_exit(&softc->mutex);

		if (in_command == 0xff)
			return (EIO);

		in_command = (in_command >> pic_nodes[node].ff_shift) & 0x1;
		(void) ddi_copyout(&in_command, (caddr_t)arg, 1, mode);
		return (0);

	case PIC_SET_ESTAR_MODE:
		(void) ddi_put8(softc->cmd_handle,
		    (uint8_t *)softc->cmd_reg + RF_COMMAND, CMD_TO_ESTAR);
		mutex_exit(&softc->mutex);
		return (0);

	default:
		mutex_exit(&softc->mutex);
		cmn_err(CE_NOTE, "cmd %d isnt valid", cmd);
		return (EINVAL);
	}
}
