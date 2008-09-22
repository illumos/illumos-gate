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
 * This is the nexus driver for SMBUS devices.  It mostly does not use
 * the SMBUS protocol so that it fits better into the solaris i2c
 * framework.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/archsystm.h>
#include <sys/platform_module.h>

#include <sys/i2c/clients/i2c_client.h>
#include <sys/i2c/misc/i2c_svc.h>
#include <sys/i2c/misc/i2c_svc_impl.h>
#include <sys/i2c/nexus/smbus.h>

/*
 * static function declarations
 */
static uint_t smbus_intr_cmn(smbus_t *smbus, char *src);
static void smbus_intr_timeout(void *arg);
static void smbus_resume(dev_info_t *dip);
static void smbus_suspend(dev_info_t *dip);
static int smbus_bus_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result);
static  int smbus_acquire(smbus_t *, dev_info_t *dip,
	i2c_transfer_t *tp);
static  void smbus_release(smbus_t *);
static int smbus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int smbus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static void smbus_free_regs(smbus_t *smbus);
static int smbus_setup_regs(dev_info_t *dip, smbus_t *smbus);
static void smbus_reportdev(dev_info_t *dip, dev_info_t *rdip);
static void smbus_uninitchild(dev_info_t *cdip);
static int smbus_initchild(dev_info_t *cdip);
static int smbus_rd(smbus_t *smbus);
static int smbus_wr(smbus_t *smbus);
static void smbus_put(smbus_t *smbus, uint8_t reg, uint8_t data, uint8_t flags);
static uint8_t smbus_get(smbus_t *smbus, uint8_t reg);
static int smbus_dip_to_addr(dev_info_t *dip);
static uint_t smbus_intr(caddr_t arg);
static int smbus_switch(smbus_t *smbus);

static struct bus_ops smbus_busops = {
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
	smbus_bus_ctl,			/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	NULL,				/* bus_get_eventcookie */
	NULL,				/* bus_add_eventcall */
	NULL,				/* bus_remove_eventcall */
	NULL,				/* bus_post_event */
	0,				/* bus_intr_ctl 	*/
	0,				/* bus_config		*/
	0,				/* bus_unconfig		*/
	0,				/* bus_fm_init		*/
	0,				/* bus_fm_fini		*/
	0,				/* bus_fm_access_enter	*/
	0,				/* bus_fm_access_exit	*/
	0,				/* bus_power		*/
	i_ddi_intr_ops			/* bus_intr_op		*/
};

struct cb_ops smbus_cb_ops = {
	nodev,			/* open */
	nodev,			/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_MP | D_NEW		/* Driver compatibility flag */
};

static struct dev_ops smbus_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,
	nulldev,
	smbus_attach,
	smbus_detach,
	nodev,
	&smbus_cb_ops,
	&smbus_busops,
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module. This one is a driver */
	"SMBUS nexus Driver",	/* Name of the module. */
	&smbus_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Globals
 */
static void	*smbus_state;

static int intr_timeout = INTR_TIMEOUT;

/*
 * The "interrupt-priorities" property is how a driver can specify a SPARC
 * PIL level to associate with each of its interrupt properties.  Most
 * self-identifying busses have a better mechanism for managing this, but I2C
 * doesn't.
 */
int smbus_pil = SMBUS_PIL;

i2c_nexus_reg_t smbus_regvec = {
	I2C_NEXUS_REV,
	smbus_transfer,
};

#ifdef DEBUG

static int smbus_print_lvl = 0;
static char msg_buff[1024];
static kmutex_t msg_buf_lock;

void
smbus_print(int flags, const char *fmt, ...)
{
	if (flags & smbus_print_lvl) {
		va_list ap;

		va_start(ap, fmt);

		if (smbus_print_lvl & PRT_PROM) {
			prom_vprintf(fmt, ap);
		} else {

			mutex_enter(&msg_buf_lock);
			(void) vsprintf(msg_buff, fmt, ap);
			if (smbus_print_lvl & PRT_BUFFONLY) {
				cmn_err(CE_CONT, "?%s", msg_buff);
			} else {
				cmn_err(CE_CONT, "%s", msg_buff);
			}
			mutex_exit(&msg_buf_lock);
		}
		va_end(ap);
	}
}
#endif /* DEBUG */

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&smbus_state, sizeof (smbus_t),
	    1);
	if (status != 0) {

		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&smbus_state);
	} else {
#ifdef DEBUG
		mutex_init(&msg_buf_lock, NULL, MUTEX_DRIVER, NULL);
#endif
	}
	return (status);
}

int
_fini(void)
{
	int status;

	if ((status = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&smbus_state);
#ifdef DEBUG
		mutex_destroy(&msg_buf_lock);
#endif
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
smbus_interrupts_on(smbus_t *smbus)
{
	int src_enable;

	src_enable = ddi_get32(smbus->smbus_confighandle,
	    (uint32_t *)&smbus->smbus_configregaddr[SMBUS_SRC_ENA]);
	src_enable |= SMBUS_SMI;
	ddi_put32(smbus->smbus_confighandle,
	    (uint32_t *)&smbus->smbus_configregaddr[SMBUS_SRC_ENA],
	    src_enable);
	(void) ddi_get32(smbus->smbus_confighandle,
	    (uint32_t *)&smbus->smbus_configregaddr[SMBUS_SRC_ENA]);
}

static void
smbus_interrupts_off(smbus_t *smbus)
{
	int src_enable;

	src_enable = ddi_get32(smbus->smbus_confighandle,
	    (uint32_t *)&smbus->smbus_configregaddr[SMBUS_SRC_ENA]);
	src_enable &= ~SMBUS_SMI;
	ddi_put32(smbus->smbus_confighandle,
	    (uint32_t *)&smbus->smbus_configregaddr[SMBUS_SRC_ENA],
	    src_enable);
	(void) ddi_get32(smbus->smbus_confighandle,
	    (uint32_t *)&smbus->smbus_configregaddr[SMBUS_SRC_ENA]);
}

static void
smbus_dodetach(dev_info_t *dip)
{
	smbus_t *smbus;
	int instance = ddi_get_instance(dip);

	smbus = ddi_get_soft_state(smbus_state, instance);

	if (smbus == NULL) {

		return;
	}

	cv_destroy(&smbus->smbus_cv);
	mutex_destroy(&smbus->smbus_mutex);

	if ((smbus->smbus_attachflags & INTERRUPT_PRI) != 0) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
		    "interrupt-priorities");
	}

	smbus_free_regs(smbus);

	if ((smbus->smbus_attachflags & NEXUS_REGISTER) != 0) {
		i2c_nexus_unregister(dip);
	}
	if ((smbus->smbus_attachflags & IMUTEX) != 0) {
		mutex_destroy(&smbus->smbus_imutex);
		cv_destroy(&smbus->smbus_icv);
	}

	if (smbus->smbus_timeout != 0) {
		(void) untimeout(smbus->smbus_timeout);
	}

	if ((smbus->smbus_attachflags & ADD_INTR) != 0) {
		ddi_remove_intr(dip, 0, smbus->smbus_icookie);
	}

	ddi_soft_state_free(smbus_state, instance);
}

static int
smbus_doattach(dev_info_t *dip)
{
	smbus_t *smbus;
	int instance = ddi_get_instance(dip);

	/*
	 * Allocate soft state structure.
	 */
	if (ddi_soft_state_zalloc(smbus_state, instance) != DDI_SUCCESS) {

		goto bad;
	}

	smbus = ddi_get_soft_state(smbus_state, instance);

	(void) snprintf(smbus->smbus_name, sizeof (smbus->smbus_name),
	    "%s%d", ddi_node_name(dip), instance);

	smbus->smbus_dip = dip;

	mutex_init(&smbus->smbus_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&smbus->smbus_imutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&smbus->smbus_cv, NULL, CV_DRIVER, NULL);
	cv_init(&smbus->smbus_intr_cv, NULL, CV_DRIVER, NULL);

	if (smbus_setup_regs(dip, smbus) != DDI_SUCCESS) {
		goto bad;
	}

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip,  DDI_PROP_DONTPASS,
	    "interrupts") == 1) {
		smbus->smbus_polling = 0;
		/*
		 * The "interrupt-priorities" property is how a driver can
		 * specify a SPARC PIL level to associate with each of its
		 * interrupt properties.  Most self-identifying busses have
		 * a better mechanism for managing this, but I2C doesn't.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, dip,
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
		    "interrupt-priorities") != 1) {
			(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, "interrupt-priorities",
			    (caddr_t)&smbus_pil,
			    sizeof (smbus_pil));
			smbus->smbus_attachflags |= INTERRUPT_PRI;
		}

		/*
		 * Clear status to clear any possible interrupt
		 */
		smbus_put(smbus, SMB_STS, 0xff, SMBUS_FLUSH);

		if (ddi_get_iblock_cookie(dip, 0, &smbus->smbus_icookie) !=
		    DDI_SUCCESS) {
			goto bad;
		}

		if (ddi_add_intr(dip, 0, NULL, NULL, smbus_intr,
		    (caddr_t)smbus) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s failed to add interrupt",
			    smbus->smbus_name);
			goto bad;
		}
		smbus->smbus_attachflags |= ADD_INTR;
	} else {
		smbus->smbus_polling = 1;
		/* Clear status */
		smbus_put(smbus, SMB_STS, 0xff, SMBUS_FLUSH);
	}

	/*
	 * initialize a cv and mutex
	 */
	cv_init(&smbus->smbus_icv, NULL, CV_DRIVER, NULL);
	mutex_init(&smbus->smbus_imutex, NULL, MUTEX_DRIVER,
	    (void *)smbus->smbus_icookie);
	smbus->smbus_attachflags |= IMUTEX;

	/*
	 * Register with the i2c framework
	 */
	i2c_nexus_register(dip, &smbus_regvec);
	smbus->smbus_attachflags |= NEXUS_REGISTER;

	return (DDI_SUCCESS);

bad:
	smbus_dodetach(dip);

	return (DDI_FAILURE);
}

static int
smbus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:

		return (smbus_doattach(dip));
	case DDI_RESUME:
		smbus_resume(dip);

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}
}

static int
smbus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		smbus_dodetach(dip);

		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		smbus_suspend(dip);

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}
}

static int
smbus_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op,
    void *arg, void *result)
{
	switch (op) {
	case DDI_CTLOPS_INITCHILD:

		return (smbus_initchild((dev_info_t *)arg));
	case DDI_CTLOPS_UNINITCHILD:
		smbus_uninitchild((dev_info_t *)arg);

		return (DDI_SUCCESS);
	case DDI_CTLOPS_REPORTDEV:
		smbus_reportdev(dip, rdip);

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

static int
smbus_initchild(dev_info_t *cdip)
{
	int32_t cell_size;
	int len;
	int32_t regs[2];
	int err;
	smbus_ppvt_t *ppvt;
	char name[30];

	SMBUS_PRINT((PRT_INIT, "smbus_initchild ENTER: %s\n",
	    ddi_node_name(cdip)));

	len = sizeof (cell_size);
	err = ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip,
	    DDI_PROP_CANSLEEP, "#address-cells",
	    (caddr_t)&cell_size, &len);
	if (err != DDI_PROP_SUCCESS || len != sizeof (cell_size)) {
		cmn_err(CE_WARN, "cannot find address-cells");

		return (DDI_FAILURE);
	}

	len = sizeof (regs);
	err = ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP,
	    "reg", (caddr_t)regs, &len);

	if (err != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "cannot get reg property");

		return (DDI_FAILURE);
	}

	ppvt = kmem_zalloc(sizeof (smbus_ppvt_t), KM_SLEEP);
	ddi_set_parent_data(cdip, ppvt);

	/*
	 * The reg property contains an unused first element (which is
	 * the mux addr on xcal), and the second element is the i2c bus
	 * address of the device.
	 */
	ppvt->smbus_ppvt_addr = regs[1];
	(void) sprintf(name, "%x", regs[1]);

	ddi_set_name_addr(cdip, name);

	SMBUS_PRINT((PRT_INIT, "smbus_initchild SUCCESS: %s\n",
	    ddi_node_name(cdip)));

	return (DDI_SUCCESS);
}

static void
smbus_uninitchild(dev_info_t *cdip)
{
	smbus_ppvt_t *ppvt;

	ppvt = ddi_get_parent_data(cdip);
	ddi_set_parent_data(cdip, NULL);

	ddi_set_name_addr(cdip, NULL);

	kmem_free(ppvt, sizeof (smbus_ppvt_t));

	SMBUS_PRINT((PRT_INIT, "smbus_uninitchild: %s\n", ddi_node_name(cdip)));
}

static void
smbus_reportdev(dev_info_t *dip, dev_info_t *rdip)
{
	smbus_ppvt_t *ppvt;

	ppvt = ddi_get_parent_data(rdip);

	cmn_err(CE_CONT, "?%s%d at %s%d: addr 0x%x",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ppvt->smbus_ppvt_addr);
}

/*
 * smbus_setup_regs() is called to map in the registers
 * specific to the smbus.
 */
static int
smbus_setup_regs(dev_info_t *dip, smbus_t *smbus)
{
	ddi_device_acc_attr_t attr;
	int ret;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	ret = ddi_regs_map_setup(dip, 1, (caddr_t *)&smbus->smbus_regaddr,
	    0, 0, &attr, &smbus->smbus_rhandle);

	if (ret == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s unable to map regs", smbus->smbus_name);

	} else if (ret == DDI_REGS_ACC_CONFLICT) {
		cmn_err(CE_WARN,
		    "%s unable to map regs because of conflict",
		    smbus->smbus_name);
		ret = DDI_FAILURE;
	}

	if (ret == DDI_FAILURE) {

		return (ret);
	}

	ret = ddi_regs_map_setup(dip, 0, (caddr_t *)&smbus->smbus_configregaddr,
	    0, 0, &attr, &smbus->smbus_confighandle);

	if (ret == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s unable to map config regs",
		    smbus->smbus_name);

	} else if (ret == DDI_REGS_ACC_CONFLICT) {
		cmn_err(CE_WARN,
		    "%s unable to map config regs because of conflict",
		    smbus->smbus_name);
		ret = DDI_FAILURE;
	}

	return (ret);
}

/*
 * smbus_free_regs() frees any registers previously allocated.
 */
static void
smbus_free_regs(smbus_t *smbus)
{
	if (smbus->smbus_regaddr != NULL) {
		ddi_regs_map_free(&smbus->smbus_rhandle);
	}

	if (smbus->smbus_configregaddr != NULL) {
		ddi_regs_map_free(&smbus->smbus_confighandle);
	}
}

/*
 * smbus_dip_to_addr() takes a dip and returns an I2C address.
 */
static int
smbus_dip_to_addr(dev_info_t *cdip)
{
	smbus_ppvt_t *ppvt;

	ppvt = ddi_get_parent_data(cdip);

	return (ppvt->smbus_ppvt_addr);
}

/*
 * smbus_suspend() is called before the system suspends.  Existing
 * transfer in progress or waiting will complete, but new transfers are
 * effectively blocked by "acquiring" the bus.
 */
static void
smbus_suspend(dev_info_t *dip)
{
	smbus_t *smbus;
	int instance;

	instance = ddi_get_instance(dip);
	smbus = ddi_get_soft_state(smbus_state, instance);

	(void) smbus_acquire(smbus, NULL, NULL);
}

/*
 * smbus_resume() is called when the system resumes from CPR.  It releases
 * the hold that was placed on the i2c bus, which allows any real
 * transfers to continue.
 */
static void
smbus_resume(dev_info_t *dip)
{
	smbus_t *smbus;
	int instance;

	instance = ddi_get_instance(dip);
	smbus = ddi_get_soft_state(smbus_state, instance);

	smbus_release(smbus);
}

/*
 * smbus_acquire() is called by a thread wishing to "own" the SMbus.
 * It should not be held across multiple transfers.
 */
static int
smbus_acquire(smbus_t *smbus, dev_info_t *dip, i2c_transfer_t *tp)
{
	mutex_enter(&smbus->smbus_mutex);
	while (smbus->smbus_busy) {
		cv_wait(&smbus->smbus_cv, &smbus->smbus_mutex);
	}
	smbus->smbus_busy = 1;
	mutex_exit(&smbus->smbus_mutex);

	/*
	 * On systems where OBP shares a smbus controller with the
	 * OS, plat_shared_i2c_enter will serialize access to the
	 * smbus controller.  Do not grab this lock during CPR
	 * suspend as the CPR thread also acquires this muxex
	 * through through prom_setprop which causes recursive
	 * mutex enter.
	 *
	 * dip == NULL during CPR.
	 */
	if ((&plat_shared_i2c_enter != NULL) && (dip != NULL)) {
		plat_shared_i2c_enter(smbus->smbus_dip);
	}

	smbus->smbus_cur_tran = tp;
	smbus->smbus_cur_dip = dip;

	return (SMBUS_SUCCESS);
}

/*
 * smbus_release() is called to release a hold made by smbus_acquire().
 */
static void
smbus_release(smbus_t *smbus)
{
	mutex_enter(&smbus->smbus_mutex);
	smbus->smbus_busy = 0;
	cv_signal(&smbus->smbus_cv);
	smbus->smbus_cur_tran = NULL;
	smbus->smbus_cur_dip = NULL;
	mutex_exit(&smbus->smbus_mutex);

	if ((&plat_shared_i2c_exit != NULL) && (smbus->smbus_cur_dip != NULL)) {
		plat_shared_i2c_exit(smbus->smbus_dip);
	}
}

static void
smbus_put(smbus_t *smbus, uint8_t reg, uint8_t data, uint8_t flags)
{
	ddi_acc_handle_t hp = smbus->smbus_rhandle;
	uint8_t *reg_addr = smbus->smbus_regaddr;
	uint8_t *config_addr = smbus->smbus_configregaddr;
	ddi_acc_handle_t config_handle = smbus->smbus_confighandle;

	ddi_put8(hp, &reg_addr[reg], data);

	SMBUS_PRINT((PRT_PUT, "smbus_put:  addr = %p data = %x\n",
	    &reg_addr[reg], data));

	/*
	 * if FLUSH flag is passed, read a config regs to make sure
	 * data written is flushed.
	 */
	if (flags & SMBUS_FLUSH) {
		(void) ddi_get8(config_handle, &config_addr[0]);
	}
}

static uint8_t
smbus_get(smbus_t *smbus, uint8_t reg)
{

	ddi_acc_handle_t hp = smbus->smbus_rhandle;
	uint8_t *regaddr = smbus->smbus_regaddr;
	uint8_t data;

	data = ddi_get8(hp, &regaddr[reg]);

	SMBUS_PRINT((PRT_GET, "smbus_get: data = %x\n", data));

	return (data);
}


/*
 * The southbridge smbus device appears to have a feature where
 * reads from the status register return 0 for a few microseconds
 * after clearing the status.
 *
 * "status_wait_idle" allows for this by retrying until
 * it gets the right answer or times out.  The loop count
 * and the delay are empirical. The routine uses up
 * 400 us if it fails.
 *
 * The fact that this routine waits for 10 us before the
 * first check is deliberate.
 */
static int
smbus_wait_idle(smbus_t *smbus)
{
	int retries = 40;
	int status;

	smbus_put(smbus, SMB_STS, 0xff, SMBUS_FLUSH);
	do {
		drv_usecwait(10);
		status = smbus_get(smbus, SMB_STS);
	} while (status != IDLE && --retries > 0);
	return (status);
}
/*
 * smbus_transfer is the function that is registered with
 * I2C services to be called for each i2c transaction.
 */
int
smbus_transfer(dev_info_t *dip, i2c_transfer_t *tp)
{
	smbus_t *smbus;
	uint8_t status;
	clock_t ctime;

	smbus = ddi_get_soft_state(smbus_state,
	    ddi_get_instance(ddi_get_parent(dip)));

	if (smbus_acquire(smbus, dip, tp) == SMBUS_FAILURE) {
		tp->i2c_result = I2C_FAILURE;

		return (I2C_FAILURE);
	}

	tp->i2c_r_resid = tp->i2c_rlen;
	tp->i2c_w_resid = tp->i2c_wlen;
	tp->i2c_result = I2C_SUCCESS;
	smbus->smbus_retries = 0;
	smbus->smbus_bytes_to_read = 0;

	mutex_enter(&smbus->smbus_imutex);

	SMBUS_PRINT((PRT_TRANS, "smbus_transfer: rlen=%d wlen=%d flags=%d",
	    tp->i2c_r_resid, tp->i2c_w_resid, tp->i2c_flags));

	/*
	 * First clear the status bits, then read them back to determine
	 * the current state.
	 */
	status = smbus_wait_idle(smbus);

	if (status != IDLE) {
		/*
		 * Try to issue bus reset
		 * First reset the state machine.
		 */
		smbus_put(smbus, SMB_TYP, KILL, SMBUS_FLUSH);
		status = smbus_wait_idle(smbus);

		if (status != IDLE) {

			smbus_put(smbus, SMB_TYP, T_OUT, SMBUS_FLUSH);
			status = smbus_wait_idle(smbus);
			if (status != IDLE) {
				cmn_err(CE_WARN,
				    "%s smbus not idle.  Unable to reset %x",
				    smbus->smbus_name, status);
				smbus->smbus_cur_tran->i2c_result = I2C_FAILURE;
				mutex_exit(&smbus->smbus_imutex);
				smbus_release(smbus);

				return (I2C_FAILURE);
			} else {
				cmn_err(CE_WARN, "%s T_OUT reset required",
				    smbus->smbus_name);
			}
		}
	}

	if (smbus_switch(smbus) != SMBUS_COMPLETE) {
		if (smbus->smbus_polling) {
			smbus->smbus_poll_complete = 0;
			smbus->smbus_poll_retries = 0;
			do {
				drv_usecwait(SMBUS_POLL_INTERVAL);
				(void) smbus_intr_cmn(smbus, SMBUS_POLL);
			} while (!smbus->smbus_poll_complete);
		} else {
			/*
			 * Start a timeout as there is a bug in southbridge
			 * smbus where sometimes a transaction never starts,
			 * and needs to be reinitiated.
			 */

			smbus->smbus_timeout = timeout(smbus_intr_timeout,
			    smbus, drv_usectohz(intr_timeout));
			SMBUS_PRINT((PRT_TRANS,
			    "starting timeout in smbus_transfer %p",
			    smbus->smbus_timeout));

			ctime = ddi_get_lbolt();
			ctime += drv_usectohz(SMBUS_TRANS_TIMEOUT);

			smbus_interrupts_on(smbus);


			cv_wait(&smbus->smbus_icv, &smbus->smbus_imutex);
		}
	}


	mutex_exit(&smbus->smbus_imutex);
	smbus_release(smbus);

	return (tp->i2c_result);
}

/*
 * This is called by smbus_intr_cmn() to figure out whether to call
 * smbus_wr or smbus_rd depending on the command and current state.
 */
static int
smbus_switch(smbus_t *smbus)
{
	int ret;
	i2c_transfer_t *tp = smbus->smbus_cur_tran;

	if (tp == NULL) {
		cmn_err(CE_WARN,
		    "%s smbus_cur_tran is NULL. Transaction failed",
		    smbus->smbus_name);

		return (SMBUS_FAILURE);
	}

	smbus->smbus_saved_w_resid = tp->i2c_w_resid;

	switch (tp->i2c_flags) {
	case I2C_WR:
		ret = smbus_wr(smbus);
		break;
	case I2C_RD:
		ret = smbus_rd(smbus);
		break;
	case I2C_WR_RD:
		/*
		 * We could do a bit more decoding here,
		 * to allow the transactions that would
		 * work as a single smbus command to
		 * be done as such.  It's not really
		 * worth the trouble.
		 */
		if (tp->i2c_w_resid > 0) {
			ret = smbus_wr(smbus);
		} else {
			ret = smbus_rd(smbus);
		}
		break;
	default:
		tp->i2c_result = I2C_FAILURE;
		ret = SMBUS_COMPLETE;
		break;
	}

	return (ret);
}

/*
 *
 */
static void
smbus_intr_timeout(void *arg)
{
	smbus_t *smbus = (smbus_t *)arg;

	mutex_enter(&smbus->smbus_imutex);
	/*
	 * If timeout is already cleared, it means interrupt arrived
	 * while timeout fired.  In this case, just return from here.
	 */
	if (smbus->smbus_timeout == 0) {

		mutex_exit(&smbus->smbus_imutex);

		return;
	}

	(void) smbus_intr_cmn(smbus, SMBUS_TIMEOUT);
	mutex_exit(&smbus->smbus_imutex);
}

/*
 * smbus_intr() is the interrupt handler for smbus.
 */
static uint_t
smbus_intr(caddr_t arg)
{
	smbus_t *smbus = (smbus_t *)arg;
	uint32_t intr_status;
	uint_t result;

	/*
	 * Check to see if intr is really from smbus
	 */
	intr_status = ddi_get32(smbus->smbus_confighandle,
	    (uint32_t *)&smbus->smbus_configregaddr[SMBUS_SRC_STATUS]);


	if ((intr_status & SMBUS_SMB_INTR_STATUS) == 0) {
		SMBUS_PRINT((PRT_INTR, "smbus_intr: intr not from smbus\n"));

		return (DDI_INTR_UNCLAIMED);
	}

	mutex_enter(&smbus->smbus_imutex);

	/*
	 * If timeout is already cleared, it means it arrived before the intr.
	 * In that case, just return from here.
	 */
	if (smbus->smbus_timeout == 0) {

		mutex_exit(&smbus->smbus_imutex);

		return (DDI_INTR_CLAIMED);
	}

	result = smbus_intr_cmn(smbus, SMBUS_INTR);
	mutex_exit(&smbus->smbus_imutex);
	return (result);
}

/*
 * smbus_intr() is the interrupt handler for smbus.
 */
static uint_t
smbus_intr_cmn(smbus_t *smbus, char *src)
{
	i2c_transfer_t *tp;
	char error_str[128];
	uint8_t status;
	int ret = SMBUS_SUCCESS;
	timeout_id_t timer_id;

	ASSERT(mutex_owned(&smbus->smbus_imutex));
	error_str[0] = '\0';

	smbus_interrupts_off(smbus);

	tp = smbus->smbus_cur_tran;
	/*
	 * This only happens when top half is interrupted or
	 * times out, then the interrupt arrives.  Interrupt
	 * was already disabled by top half, so just exit.
	 */
	if (tp == NULL) {
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * This wait is required before reading the status, otherwise
	 * a parity error can occur which causes a panic.  A bug with
	 * southbridge SMBUS.
	 */
	drv_usecwait(15);
	status = smbus_get(smbus, SMB_STS);
	if (smbus->smbus_polling) {
		/*
		 * If we are polling, then we expect not to
		 * get the right answer for a while,
		 * so we don't go on to that error stuff
		 * until we've polled the status for a
		 * few times. We check for errors here to save time,
		 * otherwise we would have to wait for the full
		 * poll timeout before dealing with them.
		 */
		if (status != (CMD_CMPL|IDLE) &&
		    (status & (FAILED|BUS_ERR|DRV_ERR)) == 0 &&
		    smbus->smbus_poll_retries++ < SMBUS_POLL_MAX_RETRIES) {
				return (DDI_INTR_CLAIMED);
		}
		/*
		 * else either ...
		 * [] the command has completed, or;
		 * [] There has been an error, or;
		 * [] we timed out waiting for something useful
		 * to happen, so we go on to  to the error handling bit that
		 * follows, * which will reset the controller then restart the
		 * whole transaction.
		 *
		 * In all cases, clear "poll_retries" for the next command or
		 * retry
		 */
		smbus->smbus_poll_retries = 0;
	}

	/*
	 * A bug in southbridge SMBUS sometimes requires a reset.  Status
	 * should NOT be IDLE without any other bit set.  If it is, the
	 * transaction should be restarted.
	 */

	if (status == IDLE) {
		(void) sprintf(error_str, "%s bus is idle, ", error_str);
	}

	if ((status & CMD_CMPL) == 0) {
		(void) sprintf(error_str, "%s command failed to complete, ",
		    error_str);
	}
	if (status & BUS_ERR) {
		(void) sprintf(error_str, "%s bus error, ", error_str);
	}
	if (status & FAILED) {
		(void) sprintf(error_str, "%s failed transaction, ", error_str);
	}
	if (status & DRV_ERR) {
		(void) sprintf(error_str, "%s timeout or bus reset", error_str);
	}

	if (error_str[0] != '\0') {
		(void) sprintf(error_str, "%s %s ", error_str, src);
	}

	/*
	 * Clear status to clear the interrupt.
	 */
	smbus_put(smbus, SMB_STS, 0xff, SMBUS_FLUSH);
	if (error_str[0] != '\0') {
		smbus_put(smbus, SMB_TYP, KILL, SMBUS_FLUSH);
		if (smbus->smbus_retries++ < SMBUS_MAX_RETRIES) {
			/*
			 * XXXX There was a panic here when the
			 * intr timeout was greater than the timeout
			 * for the entire transfer.
			 *
			 * Restore the value of w_resid before the
			 * last transaction.  r_resid doesn't need to
			 * be restored because it is only decremented
			 * after a successful read.  Need to do this
			 * here since smbus_switch() keys off of a
			 * resid to know whether to call smbus_rd() or
			 * smbus_wr().
			 */
			tp->i2c_w_resid = smbus->smbus_saved_w_resid;
			smbus->smbus_bytes_to_read = 0;

			SMBUS_PRINT((PRT_INTR_ERR,
			    "retrying: %s %s w_resid=%d\n", error_str,
			    src, tp->i2c_w_resid));
		} else {
			cmn_err(CE_WARN, "%s max retries exceeded: %s",
			    smbus->smbus_name, error_str);
			/*
			 * bailing, but first will reset the bus.
			 */
			smbus_put(smbus, SMB_TYP, KILL, SMBUS_FLUSH);
			smbus_put(smbus, SMB_STS, 0xff, SMBUS_FLUSH);
			smbus->smbus_cur_tran->i2c_result = I2C_FAILURE;

			ret = SMBUS_FAILURE;
		}
	} else {
		smbus->smbus_retries = 0;
	}

	if (tp != NULL) {
		SMBUS_PRINT((PRT_INTR, "flags=%d  wresid=%d r_resid=%d %s\n",
		    tp->i2c_flags, tp->i2c_w_resid, tp->i2c_r_resid, src));
	}

	if (ret != SMBUS_FAILURE) {
		ret = smbus_switch(smbus);
	}

	if (smbus->smbus_polling) {
		if (ret == SMBUS_COMPLETE || ret == SMBUS_FAILURE) {
			smbus->smbus_poll_complete = 1;
		}
	} else {
		/*
		 * Disable previous timeout.  In case it was about to fire this
		 * will let it exit without doing anything.
		 */
		timer_id = smbus->smbus_timeout;
		smbus->smbus_timeout = 0;
		mutex_exit(&smbus->smbus_imutex);
		(void) untimeout(timer_id);
		mutex_enter(&smbus->smbus_imutex);
		if (ret == SMBUS_COMPLETE || ret == SMBUS_FAILURE) {
			cv_signal(&smbus->smbus_icv);
		} else {
			smbus_interrupts_on(smbus);
			smbus->smbus_timeout = timeout(smbus_intr_timeout,
			    smbus, drv_usectohz(intr_timeout));
			SMBUS_PRINT((PRT_INTR, "smbus_intr starting timeout %p "
			    "%s", smbus->smbus_timeout, src));
		}
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * smbus_wr handles writes to the smbus.  Unlike true I2C busses
 * such as provided by pcf8584, smbus attaches a start and stop bit for each
 * transaction, so this limits writes to the maximum number of bytes
 * in a single transaction, which is 33.
 *
 * If more than 33 bytes are contained in the transfer, a non-zero
 * residual has to be returned, and the calling driver has to restart
 * another transaction to complete writing out any remaining data.  The
 * reason for this is that most devices require a register/offset as the
 * first byte to be written for each SMBUS transaction.
 */
static int
smbus_wr(smbus_t *smbus)
{
	i2c_transfer_t *tp = smbus->smbus_cur_tran;
	uint8_t addr = smbus_dip_to_addr(smbus->smbus_cur_dip);
	int bytes_written = 0;
	uint8_t a;
	uint8_t b;

	if (tp->i2c_w_resid != tp->i2c_wlen) {
		return (SMBUS_COMPLETE);
	}

	SMBUS_PRINT((PRT_WR, "smbus_wr:  addr = %x resid = %d\n",
	    addr, tp->i2c_w_resid));

	smbus_put(smbus, SMB_STS, 0xff, 0);

	/*
	 * Address must be re-written for each command and it has to
	 * be written before SMB_TYP.
	 */
	smbus_put(smbus, DEV_ADDR, addr, 0);

	switch (tp->i2c_w_resid) {

	case 1:
		a = tp->i2c_wbuf[tp->i2c_wlen - tp->i2c_w_resid--];
		smbus_put(smbus, SMB_CMD, a, 0);
		smbus_put(smbus, SMB_TYP, SEND_BYTE, 0);
		SMBUS_PRINT((PRT_WR, "smbus_wr: send one byte:"
		    " %d\n", a));
		break;
	case 2:
		a = tp->i2c_wbuf[tp->i2c_wlen - tp->i2c_w_resid--];
		smbus_put(smbus, SMB_CMD, a, 0);

		b = tp->i2c_wbuf[tp->i2c_wlen - tp->i2c_w_resid--];
		smbus_put(smbus, DEV_DATA0, b, 0);
		smbus_put(smbus, SMB_TYP, WR_BYTE, 0);
		SMBUS_PRINT((PRT_WR, "smbus_wr: send two bytes:"
		    " %d %d\n", a, b));
		break;

	default:
		/*
		 * Write out as many bytes as possible in a single command.
		 * Note that BLK_DATA just creats a byte stream.  ie, the
		 * smbus protocol is not used or interpreted by this driver.
		 */
		smbus_put(smbus, SMB_TYP, WR_BLK, 0);
		a = tp->i2c_wbuf[tp->i2c_wlen - tp->i2c_w_resid--];

		smbus_put(smbus, SMB_CMD, a, 0);

		SMBUS_PRINT((PRT_WR, "smbus_wr: send multiple bytes: "));
		SMBUS_PRINT((PRT_WR, "%x ", a));

		while (tp->i2c_w_resid != 0) {
			a = tp->i2c_wbuf[tp->i2c_wlen - tp->i2c_w_resid--];
			smbus_put(smbus, BLK_DATA, a, 0);
			SMBUS_PRINT((PRT_WR, "%x ", a));
			/*
			 * Note that MAX_BLK_SEND defines how many bytes may
			 * be sent to the BLK_DATA register. The leading byte
			 * already sent to the SMB_CMD register doesn't count
			 * But ALL the BLK_DATA bytes count so pre-increment
			 * bytes_written before testing.
			 */
			if (++bytes_written == MAX_BLK_SEND) {
				break;
			}
		}
		SMBUS_PRINT((PRT_WR, "\n"));
		smbus_put(smbus, DEV_DATA0, bytes_written, 0);
		break;
	}

	/*
	 * writing anything to port reg starts transfer
	 */
	smbus_put(smbus, STR_PORT, 0, SMBUS_FLUSH);

	return (SMBUS_PENDING);
}

/*
 * smbus_rd handles reads to the smbus.  Unlike a true I2C bus
 * such as provided by pcf8584, smbus attaches a start and stop bit
 * for each transaction, which limits reads to the maximum number of
 * bytes in a single SMBUS transaction.  (Block reads don't
 * seem to work on smbus, and the southbridge documentation is poor).
 *
 * It doesn't appear that reads spanning multiple I2C transactions
 * (ie each with a start-stop) affects the transfer when reading
 * multiple bytes from devices with internal counters.  The counter
 * is correctly maintained.
 *
 * RD_WORD and RD_BYTE write out the byte in the SMB_CMD register
 * before reading, so RCV_BYTE is used instead.
 *
 * Multi-byte reads iniatiate a SMBUS transaction for each byte to be
 * received.  Because register/offset information doesn't need to
 * be resent for each I2C transaction (as opposed to when writing data),
 * the driver can continue reading data in separate SMBUS transactions
 * until the requested buffer is filled.
 */
static int
smbus_rd(smbus_t *smbus)
{
	i2c_transfer_t *tp = smbus->smbus_cur_tran;
	uint8_t addr = smbus_dip_to_addr(smbus->smbus_cur_dip);

	if (smbus->smbus_bytes_to_read == 1) {
		tp->i2c_rbuf[tp->i2c_rlen - tp->i2c_r_resid] =
		    smbus_get(smbus, DEV_DATA0);
		SMBUS_PRINT((PRT_RD, "smbus_rd: data in = %d\n",
		    tp->i2c_rbuf[tp->i2c_rlen - tp->i2c_r_resid]));
		tp->i2c_r_resid--;
		smbus->smbus_bytes_to_read = 0;

		if (tp->i2c_r_resid == 0) {
			return (SMBUS_COMPLETE);
		}
	}

	/*
	 * Address must be re-written for each command.  It must
	 * be written before SMB_TYP.
	 */
	smbus_put(smbus, DEV_ADDR, addr | I2C_READ, 0);

	if (tp->i2c_r_resid == 0) {
		smbus->smbus_bytes_to_read = 0;

		return (SMBUS_COMPLETE);
	}

	smbus->smbus_bytes_to_read = 1;
	smbus_put(smbus, SMB_TYP, RCV_BYTE, 0);

	smbus_put(smbus, SMB_STS, 0xff, 0);

	SMBUS_PRINT((PRT_RD, "smbus_rd: starting a read addr = %x resid = %d "
	    "bytes_to_read=%d\n", addr, tp->i2c_r_resid,
	    smbus->smbus_bytes_to_read));

	smbus_put(smbus, STR_PORT, 0, SMBUS_FLUSH);

	return (SMBUS_PENDING);
}
