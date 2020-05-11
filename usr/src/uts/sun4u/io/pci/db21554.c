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
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */


/*
 *	Intel 21554 PCI to PCI bus bridge nexus driver for sun4u platforms.
 *	Please note that 21554 is not a transparent bridge.
 *	This driver can be used when the 21554 bridge is used like a
 *	transparent bridge. The host OBP or the OS PCI Resource Allocator
 *	(during a hotplug/hotswap operation) must represent this device
 *	as a nexus and do the device tree representation of the child
 *	nodes underneath.
 *	Interrupt routing of the children must be done as per the PCI
 *	specifications recommendation similar to that of a transparent
 *	bridge.
 *	Address translations from secondary across primary can be 1:1
 *	or non 1:1. Currently only 1:1 translations are supported.
 *	Configuration cycles are indirect. Memory and IO cycles are direct.
 */

/*
 * INCLUDES
 */
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/pci.h>
#include <sys/pci/pci_nexus.h>
#include <sys/pci/pci_regs.h>
#include <sys/pci/db21554_config.h> /* 21554 configuration space registers */
#include <sys/pci/db21554_csr.h> /* 21554 control status register layout */
#include <sys/pci/db21554_ctrl.h> /* driver private control structure	*/
#include <sys/pci/db21554_debug.h> /* driver debug declarations		*/
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/fm/protocol.h>
#include <sys/ddifm.h>
#include <sys/promif.h>
#include <sys/file.h>
#include <sys/hotplug/pci/pcihp.h>

/*
 * DEFINES.
 */
#define	DB_DEBUG
#define	DB_MODINFO_DESCRIPTION	"Intel/21554 pci-pci nexus"
#define	DB_DVMA_START		0xc0000000
#define	DB_DVMA_LEN		0x20000000

#ifdef	DB_DEBUG
/* ioctl definitions */
#define	DB_PCI_READ_CONF_HEADER		1
#define	DEF_INVALID_REG_VAL		-1

/* Default values for secondary cache line and latency timer */
#define	DB_SEC_LATENCY_TIMER_VAL	0x40
#define	DB_SEC_CACHELN_SIZE_VAL		0x10

/* complete chip status information */
typedef struct db_pci_data {
	char		name[256];
	uint32_t	instance;
	db_pci_header_t pri_hdr;
	db_pci_header_t sec_hdr;
	db_conf_regs_t	conf_regs;
} db_pci_data_t;
#endif

/*
 * LOCALS
 */

/*
 * The next set of variables are control parameters for debug purposes only.
 * Changing the default values as assigned below are not recommended.
 * In some cases, the non-default values are mostly application specific and
 * hence may not have been tested yet.
 *
 *	db_conf_map_mode : specifies the access method used for generating
 *			   configuration cycles. Default value indicates
 *			   the indirect configuration method.
 *	db_io_map_mode	 : specifies the access method used for generating
 *			   IO cycles. Default value indicates the direct
 *			   method.
 *	db_pci_own_wait	 : For indirect cycles, indicates the wait period
 *			   for acquiring the bus, when the bus is busy.
 *	db_pci_release_wait:For indirect cycles, indicates the wait period
 *			    for releasing the bus when the bus is busy.
 *	db_pci_max_wait  : max. wait time when bus is busy for indirect cycles
 *	db_set_latency_timer_register :
 *			   when 1, the driver overwrites the OBP assigned
 *			   latency timer register setting for every child
 *			   device during child initialization.
 *	db_set_cache_line_size_register :
 *			   when 1, the driver overwrites the OBP assigned
 *			   cache line register setting for every child
 *			   device during child initialization.
 *	db_use_config_own_bit:
 *			   when 1, the driver will use the "config own bit"
 *			   for accessing the configuration address and data
 *			   registers.
 */
static uint32_t	db_pci_own_wait = DB_PCI_WAIT_MS;
static uint32_t	db_pci_release_wait = DB_PCI_WAIT_MS;
static uint32_t	db_pci_max_wait = DB_PCI_TIMEOUT;
static uint32_t	db_conf_map_mode = DB_CONF_MAP_INDIRECT_CONF;
static uint32_t	db_io_map_mode = DB_IO_MAP_DIRECT;
static uint32_t	db_set_latency_timer_register = 1;
static uint32_t	db_set_cache_line_size_register = 1;
static uint32_t	db_use_config_own_bit = 0;

/*
 * Properties that can be set via .conf files.
 */

/*
 * By default, we forward SERR# from secondary to primary. This behavior
 * can be controlled via a property "serr-fwd-enable", type integer.
 * Values are 0 or 1.
 * 0 means 'do not forward SERR#'.
 * 1 means forwards SERR# to the host. Should be the default.
 */
static uint32_t	db_serr_fwd_enable = 1;

/*
 * The next set of parameters are performance tuning parameters.
 * These are in the form of properties settable through a .conf file.
 * In case if the properties are absent the following defaults are assumed.
 * These initial default values can be overwritten via /etc/system also.
 *
 * -1 means no setting is done ie. we either get OBP assigned value
 * or reset values (at hotplug time for example).
 */

/* primary latency timer: property "p-latency-timer" : type integer */
static int8_t	p_latency_timer = DEF_INVALID_REG_VAL;

/* secondary latency timer: property "s-latency-timer": type integer */
/*
 * Currently on the secondary side the latency timer  is not
 * set by the serial PROM which causes performance degradation.
 * Set the secondary latency timer register.
 */
static int8_t	s_latency_timer = DB_SEC_LATENCY_TIMER_VAL;

/* primary cache line size: property "p-cache-line-size" : type integer */
static int8_t	p_cache_line_size = DEF_INVALID_REG_VAL;

/* secondary cache line size: property "s-cache-line-size" : type integer */
/*
 * Currently on the secondary side the cache line size is not
 * set by the serial PROM which causes performance degradation.
 * Set the secondary cache line size register.
 */
static int8_t	s_cache_line_size = DB_SEC_CACHELN_SIZE_VAL;

/*
 * control primary posted write queue threshold limit:
 * property "p-pwrite-threshold" : type integer : values are 0 or 1.
 * 1 enables control. 0 does not, and is the default reset value.
 */
static int8_t	p_pwrite_threshold = DEF_INVALID_REG_VAL;

/*
 * control secondary posted write queue threshold limit:
 * property "s-pwrite-threshold" : type integer : values are 0 or 1.
 * 1 enables control. 0 does not, and is the default reset value.
 */
static int8_t	s_pwrite_threshold = DEF_INVALID_REG_VAL;

/*
 * control read queue threshold for initiating delayed read transaction
 * on primary bus.
 * property "p-dread-threshold" : type integer: values are
 *
 * 0 : reset value, default behavior: at least 8DWords free for all MR
 * 1 : reserved
 * 2 : at least one cache line free for MRL and MRM, 8 DWords free for MR
 * 3 : at least one cache line free for all MR
 */
static int8_t	p_dread_threshold = DEF_INVALID_REG_VAL;

/*
 * control read queue threshold for initiating delayed read transaction
 * on secondary bus.
 * property "s-dread-threshold" : type integer: values are
 *
 * 0 : reset value, default behavior: at least 8DWords free for all MR
 * 1 : reserved
 * 2 : at least one cache line free for MRL and MRM, 8 DWords free for MR
 * 3 : at least one cache line free for all MR
 */
static int8_t	s_dread_threshold = DEF_INVALID_REG_VAL;

/*
 * control how 21554 issues delayed transactions on the target bus.
 * property "delayed-trans-order" : type integer: values are 0 or 1.
 * 1 means repeat transaction on same target on target retries.
 * 0 is the reset/default value, and means enable round robin based
 * reads on  other targets in read queue on any target retries.
 */
static int8_t	delayed_trans_order = DEF_INVALID_REG_VAL;

/*
 * In case if the system DVMA information is not available, as it is
 * prior to s28q1, the system dvma range can be set via these parameters.
 */
static uint32_t	db_dvma_start = DB_DVMA_START;
static uint32_t	db_dvma_len = DB_DVMA_LEN;

/*
 * Default command register settings for all PCI nodes this nexus initializes.
 */
static uint16_t	db_command_default =
			PCI_COMM_SERR_ENABLE |
			PCI_COMM_PARITY_DETECT |
			PCI_COMM_ME |
			PCI_COMM_MAE |
			PCI_COMM_IO |
			PCI_COMM_BACK2BACK_ENAB |
			PCI_COMM_MEMWR_INVAL;

static int	db_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	db_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static void	db_get_perf_parameters(db_ctrl_t *dbp);
static void	db_set_perf_parameters(db_ctrl_t *dbp);
static void	db_enable_io(db_ctrl_t *dbp);
static void	db_orientation(db_ctrl_t *dbp);
static void	db_set_dvma_range(db_ctrl_t *dbp);
static int	db_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
			void **result);
static int	db_pci_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
			off_t, off_t, caddr_t *);
static int	db_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
			void *, void *);
static int	db_intr_ops(dev_info_t *dip, dev_info_t *rdip,
			ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp,
			void *result);
static dev_info_t *db_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip);
static int db_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
		ddi_iblock_cookie_t *ibc);
static void db_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle);
static void db_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle);

struct bus_ops db_bus_ops = {
	BUSO_REV,
	db_pci_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	0,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	db_ctlops,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,
	ndi_busop_add_eventcall,
	ndi_busop_remove_eventcall,
	ndi_post_event,
	0,
	0,
	0,
	db_fm_init_child,
	NULL,
	db_bus_enter,
	db_bus_exit,
	0,
	db_intr_ops
};

static int	db_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
static int	db_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int	db_ioctl(dev_t dev, int cmd, intptr_t arg, int flag,
			cred_t *cred_p, int *rval_p);
#ifdef	DB_DEBUG
static dev_info_t *db_lookup_child_name(db_ctrl_t *dbp, char *name,
			int instance);
static void	db_pci_get_header(ddi_acc_handle_t config_handle,
			db_pci_header_t *ph, off_t hdr_off);
static void	db_pci_get_conf_regs(ddi_acc_handle_t config_handle,
			db_conf_regs_t *cr);
#endif	/* DB_DEBUG */

#ifdef DEBUG
static void
db_debug(uint64_t func_id, dev_info_t *dip, char *fmt,
    uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5);
#endif

static int db_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);

static struct cb_ops db_cb_ops = {
	db_open,			/* open */
	db_close,			/* close */
	nulldev,			/* strategy */
	nulldev,			/* print */
	nulldev,			/* dump */
	nulldev,			/* read */
	nulldev,			/* write */
	db_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	db_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static uint8_t	db_ddi_get8(ddi_acc_impl_t *handle, uint8_t *addr);
static uint16_t db_ddi_get16(ddi_acc_impl_t *handle, uint16_t *addr);
static uint32_t db_ddi_get32(ddi_acc_impl_t *handle, uint32_t *addr);
static uint64_t db_ddi_get64(ddi_acc_impl_t *handle, uint64_t *addr);
static void	db_ddi_put8(ddi_acc_impl_t *handle, uint8_t *addr,
    uint8_t data);
static void	db_ddi_put16(ddi_acc_impl_t *handle, uint16_t *addr,
    uint16_t data);
static void	db_ddi_put32(ddi_acc_impl_t *handle, uint32_t *addr,
    uint32_t data);
static void	db_ddi_put64(ddi_acc_impl_t *handle, uint64_t *addr,
    uint64_t data);
static void	db_ddi_rep_get8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
static void	db_ddi_rep_get16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
static void	db_ddi_rep_get32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
static void	db_ddi_rep_get64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);
static void	db_ddi_rep_put8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
static void	db_ddi_rep_put16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
static void	db_ddi_rep_put32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
static void	db_ddi_rep_put64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

static struct dev_ops db_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	db_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	db_attach,		/* attach */
	db_detach,		/* detach */
	nulldev,		/* reset */
	&db_cb_ops,		/* driver operations */
	&db_bus_ops,		/* bus operations */
	ddi_power,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	DB_MODINFO_DESCRIPTION,
	&db_dev_ops	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/* soft state pointer and structure template. */
static void	*db_state;

/*
 * forward function declarations:
 */
static void	db_uninitchild(dev_info_t *);
static int	db_initchild(dev_info_t *child);
static int	db_create_pci_prop(dev_info_t *child);
static int	db_save_config_regs(db_ctrl_t *dbp);
static int	db_restore_config_regs(db_ctrl_t *dbp);

/*
 * FMA error callback
 * Register error handling callback with our parent. We will just call
 * our children's error callbacks and return their status.
 */
static int db_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
		const void *impl_data);

/*
 * init/fini routines to alloc/dealloc fm structures and
 * register/unregister our callback.
 */
static void db_fm_init(db_ctrl_t *db_p);
static void db_fm_fini(db_ctrl_t *db_p);

int
_init(void)
{
	int rc;

	DB_DEBUG0(DB_INIT|DB_DONT_DISPLAY_DIP, NULL, "enter\n");
	if (((rc = ddi_soft_state_init(&db_state,
	    sizeof (db_ctrl_t), 1)) == 0) &&
	    ((rc = mod_install(&modlinkage)) != 0))
		ddi_soft_state_fini(&db_state);
	DB_DEBUG1(DB_INIT|DB_DONT_DISPLAY_DIP, NULL, "exit rc=%d\n", rc);
	return (rc);
}


int
_fini(void)
{
	int rc;

	DB_DEBUG0(DB_FINI|DB_DONT_DISPLAY_DIP, NULL, "enter\n");
	if ((rc = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&db_state);
	DB_DEBUG1(DB_FINI|DB_DONT_DISPLAY_DIP, NULL, "exit rc=%d\n", rc);
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	int rc;
	rc = mod_info(&modlinkage, modinfop);
	DB_DEBUG1(DB_INFO|DB_DONT_DISPLAY_DIP, NULL, "exit rc=%d\n", rc);
	return (rc);
}

/*ARGSUSED*/
static int
db_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	db_ctrl_t *dbp;
	int rc = DDI_FAILURE;
	minor_t		minor = getminor((dev_t)arg);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);

	DB_DEBUG1(DB_GETINFO|DB_DONT_DISPLAY_DIP, dip, "enter:cmd=%d\n",
	    infocmd);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:

			if ((dbp = ddi_get_soft_state(db_state,
			    instance)) != NULL) {
				*result = dbp->dip;
				rc = DDI_SUCCESS;
			} else
				*result = NULL;
			break;

		case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(uintptr_t)instance;
			rc = DDI_SUCCESS;
			break;

		default:
			break;
	}
	DB_DEBUG2(DB_GETINFO|DB_DONT_DISPLAY_DIP, dip,
	    "exit: result=%x, rc=%d\n", *result, rc);

	return (rc);
}

static int
db_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	db_ctrl_t	*dbp;
	int		rc = DDI_SUCCESS;
	ddi_device_acc_attr_t db_csr_attr = {	/* CSR map attributes */
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_LE_ACC,
		DDI_STRICTORDER_ACC
	};
	off_t bar_size;
	int range_size;
	char name[32];

	DB_DEBUG1(DB_ATTACH, dip, "enter: cmd=%d\n", cmd);
	switch (cmd) {

	case DDI_ATTACH:
		if (ddi_soft_state_zalloc(db_state, instance) != DDI_SUCCESS) {
			rc = DDI_FAILURE;
			break;
		}

		dbp = (db_ctrl_t *)ddi_get_soft_state(db_state, instance);

		dbp->dip = dip;
		mutex_init(&dbp->db_mutex, NULL, MUTEX_DRIVER, NULL);
		dbp->db_soft_state = DB_SOFT_STATE_CLOSED;

		/*
		 * Cannot use pci_config_setup here as we'd need
		 * to get a pointer to the address map to be able
		 * to set the bus private handle during child map
		 * operation.
		 */
		if ((rc = ddi_regs_map_setup(dip, DB_PCI_CONF_RNUMBER,
		    (caddr_t *)&dbp->conf_io, DB_PCI_CONF_OFFSET,
		    PCI_CONF_HDR_SIZE, &db_csr_attr, &dbp->conf_handle))
		    != DDI_SUCCESS) {

			cmn_err(CE_WARN,
			    "%s#%d: cannot map configuration space",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			mutex_destroy(&dbp->db_mutex);
			ddi_soft_state_free(db_state, instance);
			rc = DDI_FAILURE;
			break;
		}

		db_get_perf_parameters(dbp);

		if (ddi_dev_regsize(dip, DB_CSR_MEMBAR_RNUMBER, &bar_size)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s#%d: cannot get memory CSR size",
			    ddi_driver_name(dbp->dip),
			    ddi_get_instance(dbp->dip));
			ddi_regs_map_free(&dbp->conf_handle);
			mutex_destroy(&dbp->db_mutex);
			ddi_soft_state_free(db_state, instance);
			rc = DDI_FAILURE;
			break;
		}

		/* map memory CSR space */
		if (ddi_regs_map_setup(dip, DB_CSR_MEMBAR_RNUMBER,
		    (caddr_t *)&dbp->csr_mem, DB_CSR_MEM_OFFSET, bar_size,
		    &db_csr_attr, &dbp->csr_mem_handle) != DDI_SUCCESS) {

			cmn_err(CE_WARN, "%s#%d: cannot map memory CSR space",
			    ddi_driver_name(dbp->dip),
			    ddi_get_instance(dbp->dip));
			ddi_regs_map_free(&dbp->conf_handle);
			mutex_destroy(&dbp->db_mutex);
			ddi_soft_state_free(db_state, instance);
			rc = DDI_FAILURE;
			break;
		}

		if (ddi_dev_regsize(dip, DB_CSR_IOBAR_RNUMBER, &bar_size)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s#%d: cannot get IO CSR size",
			    ddi_driver_name(dbp->dip),
			    ddi_get_instance(dbp->dip));
			ddi_regs_map_free(&dbp->csr_mem_handle);
			ddi_regs_map_free(&dbp->conf_handle);
			mutex_destroy(&dbp->db_mutex);
			ddi_soft_state_free(db_state, instance);
			rc = DDI_FAILURE;
			break;
		}

		/*
		 * map IO CSR space. We need this map to initiate
		 * indirect configuration transactions as this is a better
		 * option than doing through configuration space map.
		 */
		if (ddi_regs_map_setup(dip, DB_CSR_IOBAR_RNUMBER,
		    (caddr_t *)&dbp->csr_io, DB_CSR_IO_OFFSET, bar_size,
		    &db_csr_attr, &dbp->csr_io_handle) != DDI_SUCCESS) {

			cmn_err(CE_WARN, "%s#%d: cannot map IO CSR space",
			    ddi_driver_name(dbp->dip),
			    ddi_get_instance(dbp->dip));
			ddi_regs_map_free(&dbp->csr_mem_handle);
			ddi_regs_map_free(&dbp->conf_handle);
			mutex_destroy(&dbp->db_mutex);
			ddi_soft_state_free(db_state, instance);
			rc = DDI_FAILURE;
			break;
		}

		db_orientation(dbp);

		if (dbp->dev_state & DB_SECONDARY_NEXUS) {
			if (pcihp_init(dip) != DDI_SUCCESS)
				cmn_err(CE_WARN,
				    "%s#%d: could not register with hotplug",
				    ddi_driver_name(dbp->dip),
				    ddi_get_instance(dbp->dip));
		} else {
			/*
			 * create minor node for devctl interfaces
			 */
			if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
			    PCIHP_AP_MINOR_NUM(instance, PCIHP_DEVCTL_MINOR),
			    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
				ddi_regs_map_free(&dbp->csr_io_handle);
				ddi_regs_map_free(&dbp->csr_mem_handle);
				ddi_regs_map_free(&dbp->conf_handle);
				mutex_destroy(&dbp->db_mutex);
				ddi_soft_state_free(db_state, instance);
				rc = DDI_FAILURE;
				break;
			}
		}

		db_enable_io(dbp);

		range_size = sizeof (dbp->range);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "bus-range", (caddr_t)&dbp->range,
		    &range_size) != DDI_SUCCESS) {

			cmn_err(CE_WARN,
			    "%s#%d: cannot get bus-range property",
			    ddi_driver_name(dip), ddi_get_instance(dip));

			if (dbp->dev_state & DB_SECONDARY_NEXUS)
				(void) pcihp_uninit(dip);
			else
				ddi_remove_minor_node(dip, "devctl");

			ddi_regs_map_free(&dbp->csr_mem_handle);
			ddi_regs_map_free(&dbp->csr_io_handle);
			ddi_regs_map_free(&dbp->conf_handle);
			mutex_destroy(&dbp->db_mutex);
			ddi_soft_state_free(db_state, instance);
			rc = DDI_FAILURE;
			break;
		}

		(void) sprintf(name, "%d", instance);

		if (ddi_create_minor_node(dip, name, S_IFCHR,
		    PCIHP_AP_MINOR_NUM(instance, PCIHP_DEBUG_MINOR),
		    NULL, 0) == DDI_FAILURE) {
			cmn_err(CE_NOTE, "%s#%d: node creation failure",
			    ddi_driver_name(dbp->dip), instance);
		}

		mutex_init(&dbp->db_busown, NULL, MUTEX_DRIVER, NULL);

		db_fm_init(dbp);
		ddi_report_dev(dip);
		dbp->dev_state |= DB_ATTACHED;

		break;

	case DDI_RESUME:

		/*
		 * Get the soft state structure for the bridge.
		 */
		dbp = (db_ctrl_t *)ddi_get_soft_state(db_state, instance);
		db_enable_io(dbp);
		(void) db_restore_config_regs(dbp);
		dbp->dev_state &= ~DB_SUSPENDED;
		break;

	default:
		rc = DDI_FAILURE;	/* not supported yet */
		break;
	}

	DB_DEBUG1(DB_ATTACH, dip, "exit: rc=%d\n", rc);
	return (rc);
}

static int
db_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	db_ctrl_t	*dbp;
	int		rc = DDI_SUCCESS;
	char		name[32];

	dbp = (db_ctrl_t *)ddi_get_soft_state(db_state, instance);

	DB_DEBUG1(DB_DETACH, dip, "enter: cmd=%d\n", cmd);

	switch (cmd) {

	case DDI_DETACH :
		db_fm_fini(dbp);
		if (dbp->dev_state & DB_SECONDARY_NEXUS)
			if (pcihp_uninit(dip) == DDI_FAILURE)
				return (DDI_FAILURE);
		else
			ddi_remove_minor_node(dip, "devctl");

		mutex_destroy(&dbp->db_busown);
		ddi_regs_map_free(&dbp->csr_mem_handle);
		ddi_regs_map_free(&dbp->csr_io_handle);

		ddi_regs_map_free(&dbp->conf_handle);
		dbp->dev_state &= ~DB_ATTACHED;
		(void) sprintf(name, "%d", instance);
		ddi_remove_minor_node(dip, name);
		mutex_destroy(&dbp->db_mutex);
		ddi_soft_state_free(db_state, instance);
		break;

	case DDI_SUSPEND :
		if (db_save_config_regs(dbp) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s#%d: Ignoring Child state Suspend Error",
			    ddi_driver_name(dbp->dip),
			    ddi_get_instance(dbp->dip));
		}
		dbp->dev_state |= DB_SUSPENDED;
		break;

	default :
		rc = DDI_FAILURE;
		break;
	}

	DB_DEBUG1(DB_DETACH, dip, "exit: rc=%d\n", rc);
	return (rc);
}

static void
db_get_perf_parameters(db_ctrl_t *dbp)
{
	dbp->p_latency_timer = (int8_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    dbp->dip, 0, "p-latency-timer", p_latency_timer);
	dbp->s_latency_timer = (int8_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    dbp->dip, 0, "s-latency-timer", s_latency_timer);
	dbp->p_cache_line_size = (int8_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    dbp->dip, 0, "p-cache-line-size", p_cache_line_size);
	dbp->s_cache_line_size = (int8_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    dbp->dip, 0, "s-cache-line-size", s_cache_line_size);
	dbp->p_pwrite_threshold = (int8_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    dbp->dip, 0, "p-pwrite-threshold", p_pwrite_threshold);
	dbp->s_pwrite_threshold = (int8_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    dbp->dip, 0, "s-pwrite-threshold", s_pwrite_threshold);
	dbp->p_dread_threshold = (int8_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    dbp->dip, 0, "p-dread-threshold", p_dread_threshold);
	dbp->s_dread_threshold = (int8_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    dbp->dip, 0, "s-dread-threshold", s_dread_threshold);
	dbp->delayed_trans_order = (int8_t)ddi_prop_get_int(DDI_DEV_T_ANY,
	    dbp->dip, 0, "delayed-trans-order", delayed_trans_order);
}

static void
db_set_perf_parameters(db_ctrl_t *dbp)
{
	uint_t	poffset = 0, soffset = 0;

	if (dbp->dev_state & DB_SECONDARY_NEXUS)
		poffset = DB_SCONF_PRI_HDR_OFF;
	else
		soffset = DB_PCONF_SEC_HDR_OFF;

	if ((dbp->p_latency_timer != (int8_t)DEF_INVALID_REG_VAL) &&
	    (dbp->p_latency_timer != -1))
		ddi_put8(dbp->conf_handle,
		    (uint8_t *)dbp->conf_io+poffset+PCI_CONF_LATENCY_TIMER,
		    dbp->p_latency_timer);
	if ((dbp->s_latency_timer != (int8_t)DEF_INVALID_REG_VAL) &&
	    (dbp->s_latency_timer != -1))
		ddi_put8(dbp->conf_handle,
		    (uint8_t *)dbp->conf_io+soffset+PCI_CONF_LATENCY_TIMER,
		    dbp->s_latency_timer);
	if ((dbp->p_cache_line_size != (int8_t)DEF_INVALID_REG_VAL) &&
	    (dbp->p_cache_line_size != -1))
		ddi_put8(dbp->conf_handle,
		    (uint8_t *)dbp->conf_io+poffset+PCI_CONF_CACHE_LINESZ,
		    dbp->p_cache_line_size);
	if ((dbp->s_cache_line_size != (int8_t)DEF_INVALID_REG_VAL) &&
	    (dbp->s_cache_line_size != -1))
		ddi_put8(dbp->conf_handle,
		    (uint8_t *)dbp->conf_io+soffset+PCI_CONF_CACHE_LINESZ,
		    dbp->s_cache_line_size);
	if ((dbp->p_pwrite_threshold != (int8_t)DEF_INVALID_REG_VAL) &&
	    (dbp->p_pwrite_threshold != -1))
		ddi_put16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL1),
		    (ddi_get16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL1)) &
		    ~P_PW_THRESHOLD) |
		    (dbp->p_pwrite_threshold?P_PW_THRESHOLD:0));
	if ((dbp->s_pwrite_threshold != (int8_t)DEF_INVALID_REG_VAL) &&
	    (dbp->s_pwrite_threshold != -1))
		ddi_put16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL1),
		    (ddi_get16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL1)) &
		    ~S_PW_THRESHOLD) |
		    (dbp->s_pwrite_threshold?S_PW_THRESHOLD:0));
	/* primary delayed read threshold. 0x01 is reserved ?. */
	if ((dbp->p_dread_threshold != (int8_t)DEF_INVALID_REG_VAL) &&
	    (dbp->p_dread_threshold != -1))
		ddi_put16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL1),
		    ((ddi_get16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL1)) &
		    ~P_DREAD_THRESHOLD_MASK) |
		    ((dbp->p_dread_threshold &
		    DREAD_THRESHOLD_VALBITS)<<2)));
	/* secondary delayed read threshold. 0x01 is reserved ?. */
	if ((dbp->s_dread_threshold != (int8_t)DEF_INVALID_REG_VAL) &&
	    (dbp->s_dread_threshold != -1))
		ddi_put16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL1),
		    ((ddi_get16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL1)) &
		    ~S_DREAD_THRESHOLD_MASK) |
		    ((dbp->s_dread_threshold &
		    DREAD_THRESHOLD_VALBITS)<<4)));
	if ((dbp->delayed_trans_order != (int8_t)DEF_INVALID_REG_VAL) &&
	    (dbp->delayed_trans_order != -1))
		ddi_put16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL0),
		    (ddi_get16(dbp->conf_handle, (uint16_t *)
		    ((uchar_t *)dbp->conf_io+DB_CONF_CHIP_CTRL0)) &
		    ~DELAYED_TRANS_ORDER) |
		    (dbp->delayed_trans_order?DELAYED_TRANS_ORDER:0));
}

static void
db_orientation(db_ctrl_t *dbp)
{
	dev_info_t	*dip = dbp->dip;
	uint8_t		pif;
	uint32_t	mem1;
	uint32_t	newval;

	/*
	 * determine orientation of drawbridge and enable
	 * Upstream or Downstream path.
	 */

	/*
	 * if PIF is set correctly, use it to determine orientation
	 */
	pif = ddi_get8(dbp->conf_handle, (uchar_t *)dbp->conf_io +
	    PCI_CONF_PROGCLASS);
	if (pif & 0xff) {
		if (pif & DB_PIF_SECONDARY_TO_HOST) {
			dbp->dev_state = DB_SECONDARY_NEXUS;
			DB_DEBUG0(DB_ATTACH, dip,
			    "db_orientation: pif secondary\n");
			return;
		}
		if (pif & DB_PIF_PRIMARY_TO_HOST) {
			dbp->dev_state = DB_PRIMARY_NEXUS;
			DB_DEBUG0(DB_ATTACH, dip,
			    "db_orientation: pif primary\n");
			return;
		}
		/* otherwise, fall through */
	}

	/*
	 * otherwise, test the chip directly by trying to write
	 * downstream mem1 setup register, only writeable from
	 * secondary.
	 */
	mem1 = ddi_get32(dbp->conf_handle,
	    (uint32_t *)((uchar_t *)dbp->conf_io +
	    DB_CONF_DS_IO_MEM1_SETUP));

	ddi_put32(dbp->conf_handle,
	    (uint32_t *)((uchar_t *)(dbp->conf_io +
	    DB_CONF_DS_IO_MEM1_SETUP)), ~mem1);

	newval = ddi_get32(dbp->conf_handle,
	    (uint32_t *)((uchar_t *)dbp->conf_io +
	    DB_CONF_DS_IO_MEM1_SETUP));

	if (newval == mem1)
		/* we couldn't write it, orientation is primary */
		dbp->dev_state =  DB_PRIMARY_NEXUS;
	else {
		/*
		 * we could write it, therefore orientation secondary.
		 * restore mem1 value.
		 */
		dbp->dev_state =  DB_SECONDARY_NEXUS;
		ddi_put32(dbp->conf_handle,
		    (uint32_t *)((uchar_t *)(dbp->conf_io +
		    DB_CONF_DS_IO_MEM1_SETUP)), mem1);
	}


	if (dbp->dev_state & DB_PRIMARY_NEXUS) {
		DB_DEBUG0(DB_ATTACH, dip, "db_orientation: chip primary\n");
	} else  {
		DB_DEBUG0(DB_ATTACH, dip, "db_orientation: chip secondary\n");
	}
}

static void
db_enable_io(db_ctrl_t *dbp)
{
	dev_info_t	*dip = dbp->dip;
	pci_regspec_t	*reg;
	int		rcount, length, i;
	uint32_t	offset;
	uint32_t	p_offset, s_offset;
	uint16_t	regval;
	uint16_t	enable;

	/*
	 * Step 0:
	 *	setup the primary and secondary offset and enable
	 *	values based on the orientation of 21554.
	 */
	if (dbp->dev_state & DB_PRIMARY_NEXUS) {
		DB_DEBUG0(DB_ATTACH, dip, "db_enable_io: primary\n");
		p_offset = 0;
		s_offset = DB_SCONF_HDR_OFF;
		enable = DS_ENABLE;
	} else {
		DB_DEBUG0(DB_ATTACH, dip, "db_enable_io: secondary\n");
		p_offset = DB_SCONF_HDR_OFF;
		s_offset = 0;
		enable = US_ENABLE;
	}

	db_set_perf_parameters(dbp);
	db_set_dvma_range(dbp);

	/*
	 * Step 1:
	 *	setup latency timer and cache line size parameters
	 *	which are used for child initialization.
	 */
	dbp->latency_timer = ddi_get8(dbp->conf_handle, (uint8_t *)
	    ((caddr_t)dbp->conf_io+PCI_CONF_LATENCY_TIMER));

	dbp->cache_line_size = ddi_get8(dbp->conf_handle, (uint8_t *)
	    ((caddr_t)dbp->conf_io+PCI_CONF_CACHE_LINESZ));

	DB_DEBUG2(DB_ATTACH, dip,
	    "db_enable_io: latency %d, cache line size %d\n",
	    dbp->latency_timer, dbp->cache_line_size);

	/*
	 * Step 2: program command reg on both primary and secondary
	 *	   interfaces.
	 */
	ddi_put16(dbp->conf_handle, (uint16_t *)((caddr_t)dbp->conf_io +
	    (off_t)(p_offset + PCI_CONF_COMM)), db_command_default);

	ddi_put16(dbp->conf_handle, (uint16_t *)((caddr_t)dbp->conf_io +
	    (off_t)(s_offset + PCI_CONF_COMM)), db_command_default);

	/*
	 * Step 3:
	 *	set up translated base registers, using the primary/
	 *  secondary interface pci configuration Base Address
	 *  Registers (BAR's).
	 */

	/* mem0 translated base is setup for primary orientation only. */
	if (dbp->dev_state & DB_PRIMARY_NEXUS) {
		/*
		 * And only if the 21554 device node property indicates
		 * the size of base0 register to be larger than csr map
		 * space, DB_CSR_SIZE=4K.
		 *
		 * Note : Setting up 1:1 translations only (for now:), i.e.
		 *	  no look up table.
		 */
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "reg", (caddr_t)&reg,
		    &length) != DDI_PROP_SUCCESS) {
			DB_DEBUG0(DB_ATTACH, dip,
			    "Failed to read reg property\n");
			return;
		}

		/* Find device node's base0 reg property and check its size */
		rcount = length / sizeof (pci_regspec_t);
		for (i = 0; i < rcount; i++) {
			offset = PCI_REG_REG_G(reg[i].pci_phys_hi);
			if ((offset == PCI_CONF_BASE0) &&
			    (reg[i].pci_size_low > DB_CSR_SIZE))
					break;
		}

		/*
		 * set up mem0 translated base, if base0 register was
		 * found and its size was larger than csr map space.
		 */
		if (i != rcount) {
			DB_DEBUG0(DB_ATTACH, dip,
			    "db_enable_io: setting up MEM0_TR_BASE\n");
			DB_DEBUG1(DB_ATTACH, dip, "BASE0 register = %x\n",
			    pci_config_get32(dbp->conf_handle,
			    (off_t)(p_offset + PCI_CONF_BASE0)));

			pci_config_put32(dbp->conf_handle,
			    (off_t)DB_CONF_DS_MEM0_TR_BASE,
			    pci_config_get32(dbp->conf_handle,
			    (off_t)(p_offset + PCI_CONF_BASE0)));

			DB_DEBUG1(DB_ATTACH, dip,
			    "db_enable_io: MEM0_TR_BASE set value = %x\n",
			    pci_config_get32(dbp->conf_handle,
			    (off_t)DB_CONF_DS_MEM0_TR_BASE));
		}
		kmem_free(reg, length);
	}

	pci_config_put32(dbp->conf_handle, (off_t)DB_CONF_DS_IO_MEM1_TR_BASE,
	    ((pci_config_get32(dbp->conf_handle,
	    (off_t)(p_offset + PCI_CONF_BASE2))) & ~DB_IO_BIT));

	pci_config_put32(dbp->conf_handle, (off_t)DB_CONF_DS_MEM2_TR_BASE,
	    ((pci_config_get32(dbp->conf_handle,
	    (off_t)(p_offset + PCI_CONF_BASE3))) & ~DB_IO_BIT));

	pci_config_put32(dbp->conf_handle, (off_t)DB_CONF_DS_MEM3_TR_BASE,
	    ((pci_config_get32(dbp->conf_handle,
	    (off_t)(p_offset + PCI_CONF_BASE4))) & ~DB_IO_BIT));

	pci_config_put32(dbp->conf_handle, (off_t)DB_CONF_US_IO_MEM0_TR_BASE,
	    ((pci_config_get32(dbp->conf_handle,
	    (off_t)(s_offset + PCI_CONF_BASE2))) & ~DB_IO_BIT));

	pci_config_put32(dbp->conf_handle, (off_t)DB_CONF_US_MEM1_TR_BASE,
	    ((pci_config_get32(dbp->conf_handle,
	    (off_t)(s_offset + PCI_CONF_BASE3))) & ~DB_IO_BIT));

	/*
	 * Step 4: enable downstream (for primary orientation) or upstream
	 *	   (for secondary orientation) bits in Configuration Control
	 *	   and Status register, if not already enabled.
	 */
	regval = pci_config_get16(dbp->conf_handle, (off_t)DB_CONF_CONF_CSR);

	DB_DEBUG1(DB_ATTACH, dip, "db_enable_io: CSR value before: %x\n",
	    regval);

	if (!(regval & enable)) {
		/* enable down/upstream configuration transactions */
		regval |= enable;
		pci_config_put16(dbp->conf_handle, (off_t)DB_CONF_CONF_CSR,
		    regval);
		regval = pci_config_get16(dbp->conf_handle,
		    (off_t)DB_CONF_CONF_CSR);
	}
	DB_DEBUG1(DB_ATTACH, dip, "db_enable_io: CSR value after: %x\n",
	    regval);

	/*
	 * Step 5: enable downstream/upstream I/O (through CSR space)
	 */
	regval = ddi_get16(dbp->csr_mem_handle,
	    (uint16_t *)((uchar_t *)dbp->csr_mem + DB_CSR_IO_CSR));

	DB_DEBUG1(DB_ATTACH, dip, "db_enable_io: IO_CSR value before: %x\n",
	    regval);
	if (!(regval & enable)) {
		regval |= enable;
		ddi_put16(dbp->csr_mem_handle,
		    (uint16_t *)((uchar_t *)dbp->csr_mem +
		    DB_CSR_IO_CSR), regval);

		regval = ddi_get16(dbp->csr_mem_handle,
		    (uint16_t *)((uchar_t *)dbp->csr_mem + DB_CSR_IO_CSR));
	}
	DB_DEBUG1(DB_ATTACH, dip, "db_enable_io: IO_CSR value after: %x\n",
	    regval);

	/*
	 * Step 6: if 21554 orientation is primary to host,
	 *	   forward SERR# to host.
	 */
	if (dbp->dev_state & DB_PRIMARY_NEXUS) {
		dbp->serr_fwd_enable = ddi_prop_get_int(DDI_DEV_T_ANY,
		    dbp->dip, 0, "serr-fwd-enable", db_serr_fwd_enable);

		regval = ddi_get16(dbp->conf_handle,
		    (uint16_t *)((uchar_t *)dbp->conf_io +
		    DB_CONF_CHIP_CTRL0));

		DB_DEBUG1(DB_ATTACH, dip,
		    "db_enable_io: CHIP_CTRL0 value before: %x\n", regval);

		ddi_put16(dbp->conf_handle,
		    (uint16_t *)((uchar_t *)dbp->conf_io +
		    DB_CONF_CHIP_CTRL0),
		    (regval & ~SERR_FWD) |
		    (dbp->serr_fwd_enable?SERR_FWD:0));

		regval = ddi_get16(dbp->conf_handle,
		    (uint16_t *)((uchar_t *)dbp->conf_io +
		    DB_CONF_CHIP_CTRL0));

		DB_DEBUG1(DB_ATTACH, dip,
		    "db_enable_io: CHIP_CTRL0 value after: %x\n", regval);
	}

	/*
	 * Step 7: if orientation is secondary, make sure primary lockout
	 *	   disable is reset.
	 */

	if (dbp->dev_state & DB_SECONDARY_NEXUS) {
		regval = pci_config_get16(dbp->conf_handle,
		    (off_t)DB_CONF_CHIP_CTRL0);
		DB_DEBUG1(DB_ATTACH, dip,
		    "db_enable_io: chip ctrl (0x%x) before\n", regval);
		if (regval & PLOCKOUT)
			pci_config_put16(dbp->conf_handle,
			    (off_t)DB_CONF_CHIP_CTRL0,
			    (regval & ~PLOCKOUT));
		regval = pci_config_get16(dbp->conf_handle,
		    (off_t)DB_CONF_CHIP_CTRL0);
		DB_DEBUG1(DB_ATTACH, dip,
		    "db_enable_io: chip ctrl (0x%x) after\n", regval);
	}
}

/*
 * Set DVMA Address Range.
 * This code is common to both orientations of the nexus driver.
 */
static void
db_set_dvma_range(db_ctrl_t *dbp)
{
	uint32_t	dvma_start = 0;
	uint32_t	dvma_len = 0;
	uint64_t	db_allocd = 0;
	uint32_t	*dvma_prop;
	uint32_t	dvma_size[2];	/* dvma size may span over 2 BARs */
	uint32_t	dvma_bar[2];	/* dvma range may span over 2 BARs */
	int		dvma_prop_len;
	uint64_t	new_dvma_start, new_dvma_len, new_dvma_end;

	/*
	 * Need to traverse up the tree looking for a
	 * "virtual-dma" property that specifies the
	 * HPB DVMA range.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_get_parent(dbp->dip), 0,
	    "virtual-dma", (caddr_t)&dvma_prop, &dvma_prop_len)
	    == DDI_SUCCESS) {
		dvma_start = dvma_prop[0];
		dvma_len = dvma_prop[1];
		kmem_free((caddr_t)dvma_prop, dvma_prop_len);
	} else {
		/*
		 * For initial implementation, lets avoid a warning since this
		 * change has not been implemented in the host-pci nexus
		 * driver.
		 */
		cmn_err(CE_WARN,
		    "%s#%d: Could not get \"virtual-dma\" property",
		    ddi_driver_name(dbp->dip),
		    ddi_get_instance(dbp->dip));
		dvma_start = db_dvma_start;
		dvma_len = db_dvma_len;
	}

	DB_DEBUG2(DB_DVMA, dbp->dip,
	    "DVMA Range is %lx,%lx\n", dvma_start, dvma_len);

	dvma_size[0] = dvma_size[1] = 0;
	/* Validate DVMA size programming and system requirements. */
	if (dbp->dev_state & DB_SECONDARY_NEXUS) {
		dvma_size[0] = pci_config_get32(dbp->conf_handle,
		    DB_CONF_DS_IO_MEM1_SETUP);
		if (!(dvma_size[0] & 1)) /* make sure it is not a IO BAR */
			dvma_size[0] = ((~dvma_size[0]) + 1) & 0xfffff000;
		else
			dvma_size[0] = 0;
		dvma_size[1] = db_dvma_len;
	} else {
		dvma_size[0] = pci_config_get32(dbp->conf_handle,
		    DB_CONF_US_IO_MEM0_SETUP);
		if (!(dvma_size[0] & 1)) /* make sure it is not a IO BAR */
			dvma_size[0] = ((~dvma_size[0]) + 1) & 0xfffff000;
		else
			dvma_size[0] = 0;
		dvma_size[1] = ((~(pci_config_get32(dbp->conf_handle,
		    DB_CONF_US_MEM1_SETUP))) + 1) & 0xfffff000;
	}
	DB_DEBUG2(DB_DVMA, dbp->dip, "DVMA size register pair %lx, %lx\n",
	    dvma_size[0], dvma_size[1]);

#ifdef	DEBUG
	if ((dvma_size[0] + dvma_size[1]) < dvma_len)
		cmn_err(CE_WARN, "%s#%d: DVMA window (%u) does not coincide"
		    " with system requirements",
		    ddi_driver_name(dbp->dip), ddi_get_instance(dbp->dip),
		    (dvma_size[0] + dvma_size[1]));
#endif
	dvma_bar[0] = dvma_bar[1] = 0xFFFFFFFF;
	db_allocd = 0;
	new_dvma_start = dvma_start;
	new_dvma_len = dvma_len;

	/* now, program the correct DVMA range over the 2 BARs. Max 4GB */
	if (dvma_size[0]) {
		dvma_bar[0] = (uint32_t)(dvma_start & (~(dvma_size[0] - 1)));
		new_dvma_end =  (uint64_t)((uint64_t)dvma_bar[0] +
		    (uint64_t)dvma_size[0]);
		if (new_dvma_end > (new_dvma_start + new_dvma_len))
			new_dvma_end = new_dvma_start + new_dvma_len;
		db_allocd += (new_dvma_end - new_dvma_start);
		new_dvma_start = new_dvma_end;
		new_dvma_len = dvma_len - db_allocd;
	}
	/*
	 * It does not serve any purpose to set the other DVMA register
	 * when we have already met the memory requirements so leave it
	 * disabled.
	 */
	if ((db_allocd != dvma_len) && dvma_size[1]) {
		dvma_bar[1] = (uint32_t)((dvma_start + db_allocd) &
		    (~(dvma_size[1] - 1)));
		new_dvma_end =  (uint64_t)((uint64_t)dvma_bar[1] +
		    (uint64_t)dvma_size[1]);
		if (new_dvma_end > (new_dvma_start + new_dvma_len))
			new_dvma_end = new_dvma_start + new_dvma_len;
		db_allocd += (new_dvma_end - new_dvma_start);
	}

	/* In case of secondary orientation, DVMA BAR0 is 0. */
	if (dbp->dev_state & DB_SECONDARY_NEXUS)
		dvma_bar[0] = 0;

	if (db_allocd != dvma_len) {
		cmn_err(CE_WARN, "%s#%d: dvma range error!",
		    ddi_driver_name(dbp->dip), ddi_get_instance(dbp->dip));
	}

	DB_DEBUG2(DB_DVMA, dbp->dip, "DVMA BARs set as %x, %x\n",
	    dvma_bar[0], dvma_bar[1]);

	/* configure the setup register and DVMA BARs. */
	if (dbp->dev_state & DB_SECONDARY_NEXUS) {
		if (dvma_bar[0] != 0xFFFFFFFF) {
#ifdef	DB_SEC_SETUP_WRITE
			/*
			 * No need to program the setup register
			 * as the PROM would have done it.
			 */
			pci_config_put32(dbp->conf_handle,
			    DB_CONF_DS_MEM1_SETUP,
			    (uint32_t)(((~(dvma_size[0] - 1)) |
			    (pci_config_get32(dbp->conf_handle,
			    DB_CONF_DS_MEM1_SETUP) & 0xF)) | 0x80000000));
#endif
			/*
			 * when translations are to be provided, this will
			 * change.
			 */
			pci_config_put32(dbp->conf_handle,
			    DB_CONF_DS_IO_MEM1_TR_BASE,
			    (uint32_t)dvma_bar[0]);
			pci_config_put32(dbp->conf_handle,
			    DB_SCONF_DS_IO_MEM1, dvma_bar[0]);
		}
		if (dvma_bar[1] != 0xFFFFFFFF) {
#ifdef	DB_SEC_SETUP_WRITE
			/*
			 * No need to program the setup register
			 * as the PROM would have done it.
			 */
			pci_config_put32(dbp->conf_handle,
			    DB_CONF_DS_MEM2_SETUP,
			    (uint32_t)(((~(dvma_size[1] - 1)) |
			    (pci_config_get32(dbp->conf_handle,
			    DB_CONF_DS_MEM2_SETUP) & 0xF)) | 0x80000000));
#endif
			/*
			 * when translations are to be provided, this will
			 * change.
			 */
			pci_config_put32(dbp->conf_handle,
			    DB_CONF_DS_MEM2_TR_BASE, (uint32_t)dvma_bar[1]);
			pci_config_put32(dbp->conf_handle,
			    DB_SCONF_DS_MEM2, dvma_bar[1]);
		}

	} else {
		if (dvma_bar[0] != 0xFFFFFFFF) {
#ifdef DB_CONF_P2S_WRITE_ENABLED	/* primary to secondary write enabled */
			/*
			 * We have a problem with this setup, because the
			 * US_MEM1 setup register cannot be written from the
			 * primary interface...!!! Hence in this configuration,
			 * we cannot dynamically program the DVMA range!
			 */
			pci_config_put32(dbp->conf_handle,
			    DB_CONF_US_IO_MEM0_SETUP,
			    (uint32_t)(((~(dvma_size[0] - 1)) |
			    (pci_config_get32(dbp->conf_handle,
			    DB_CONF_US_IO_MEM0_SETUP) & 0xF)) |
			    0x80000000));
#endif
			/*
			 * when translations are to be provided, this will
			 * change.
			 */
			pci_config_put32(dbp->conf_handle,
			    DB_CONF_US_IO_MEM0_TR_BASE,
			    (uint32_t)dvma_bar[0]);
			pci_config_put32(dbp->conf_handle,
			    DB_PCONF_US_IO_MEM0, dvma_bar[0]);
		}
		if (dvma_bar[1] != 0xFFFFFFFF) {
#ifdef DB_CONF_P2S_WRITE_ENABLED	/* primary to secondary write enabled */
			/*
			 * We have a problem with this setup, because the
			 * US_MEM1 setup register cannot be written from the
			 * primary interface...!!! Hence in this configuration,
			 * we cannot dynamically program the DVMA range!
			 */
			pci_config_put32(dbp->conf_handle,
			    DB_CONF_US_MEM1_SETUP,
			    (uint32_t)(((~(dvma_size[1] - 1)) |
			    (pci_config_get32(dbp->conf_handle,
			    DB_CONF_US_MEM1_SETUP) & 0xF)) | 0x80000000));
#endif
			/*
			 * when translations are to be provided, this will
			 * change.
			 */
			pci_config_put32(dbp->conf_handle,
			    DB_CONF_US_MEM1_TR_BASE, (uint32_t)dvma_bar[1]);
			pci_config_put32(dbp->conf_handle,
			    DB_PCONF_US_MEM1, dvma_bar[1]);
		}
	}
}

/*ARGSUSED*/
static int
db_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	minor_t		minor = getminor(*dev_p);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);
	db_ctrl_t *dbp = (db_ctrl_t *)ddi_get_soft_state(db_state, instance);

	if (dbp == (db_ctrl_t *)NULL)
		return (ENXIO);

	/*
	 * check for debug node
	 */
	if ((minor & 0xff) == 0xfe)
		return (0);

	if (dbp->dev_state & DB_SECONDARY_NEXUS)
		return ((pcihp_get_cb_ops())->cb_open(dev_p, flag,
		    otyp, cred_p));
	/*
	 * Handle the open by tracking the device state.
	 */
	mutex_enter(&dbp->db_mutex);
	if (flag & FEXCL) {
		if (dbp->db_soft_state != DB_SOFT_STATE_CLOSED) {
			mutex_exit(&dbp->db_mutex);
			return (EBUSY);
		}
		dbp->db_soft_state = DB_SOFT_STATE_OPEN_EXCL;
	} else {
		if (dbp->db_soft_state == DB_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&dbp->db_mutex);
			return (EBUSY);
		}
		dbp->db_soft_state = DB_SOFT_STATE_OPEN;
	}
	mutex_exit(&dbp->db_mutex);
	return (0);
}

/*ARGSUSED*/
static int
db_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	minor_t		minor = getminor(dev);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);
	db_ctrl_t *dbp = (db_ctrl_t *)ddi_get_soft_state(db_state, instance);

	if (dbp == (db_ctrl_t *)NULL)
		return (ENXIO);

	/*
	 * check for debug node
	 */
	if ((minor & 0xff) == 0xfe)
		return (0);

	if (dbp->dev_state & DB_SECONDARY_NEXUS)
		return ((pcihp_get_cb_ops())->cb_close(dev, flag,
		    otyp, cred_p));
	mutex_enter(&dbp->db_mutex);
	dbp->db_soft_state = DB_SOFT_STATE_CLOSED;
	mutex_exit(&dbp->db_mutex);
	return (0);
}

/*ARGSUSED*/
static int
db_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
	int		rc = DDI_SUCCESS;
#ifdef	DB_DEBUG
	ddi_acc_handle_t	config_handle;
	db_pci_data_t	pci_data;
	dev_info_t	*child_dip;
#endif
	dev_info_t	*self;
	minor_t		minor = getminor(dev);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);
	struct devctl_iocdata *dcp;
	uint_t		bus_state;
	db_ctrl_t *dbp = (db_ctrl_t *)ddi_get_soft_state(db_state, instance);

#ifdef	DB_DEBUG
	/*
	 * try this first whether were SECONDARY_NEXUS or not
	 */
	if (cmd == DB_PCI_READ_CONF_HEADER) {
		if (ddi_copyin((caddr_t)arg, (caddr_t)&pci_data,
		    sizeof (db_pci_data_t), mode)) {
			rc = EFAULT;
			return (rc);
		}

		if (strcmp(pci_data.name, "") == 0) {
			child_dip = dbp->dip;
			(void) strcpy(pci_data.name,
			    ddi_get_name(dbp->dip));
		} else {

			if ((child_dip = db_lookup_child_name(dbp,
			    pci_data.name, pci_data.instance))
			    == (dev_info_t *)NULL) {
				rc = ENXIO;
				return (rc);
			} else {
				if (ddi_getprop(DDI_DEV_T_ANY,
				    child_dip, DDI_PROP_DONTPASS,
				    "vendor-id", DB_INVAL_VEND)
				    == DB_INVAL_VEND) {
					/* non PCI device */
					rc = EINVAL;
					return (rc);
				}
			}
		}
		pci_data.instance = ddi_get_instance(child_dip);
		(void) pci_config_setup(child_dip, &config_handle);
		db_pci_get_header(config_handle, &pci_data.pri_hdr, 0);

		/* if it is the drawbridge itself, read sec header */
		if (child_dip == dbp->dip) {
			db_pci_get_header(config_handle,
			    &pci_data.sec_hdr, DB_PCONF_SEC_HDR_OFF);
			db_pci_get_conf_regs(config_handle,
			    &pci_data.conf_regs);
		}
		pci_config_teardown(&config_handle);

		if (ddi_copyout((caddr_t)&pci_data, (caddr_t)arg,
		    sizeof (db_pci_data_t), mode)) {
			rc = EFAULT;
			return (rc);
		}

		return (rc);
	}
#endif	/* DB_DEBUG */

	/*
	 * if secondary nexus (hotplug), then use pcihp_ioctl to do everything
	 */
	if (dbp->dev_state & DB_SECONDARY_NEXUS)
		return ((pcihp_get_cb_ops())->cb_ioctl(dev, cmd,
		    arg, mode, cred_p, rval_p));

	/*
	 * if not secondary nexus, we do DEVCTL_DEVICE and DEVCTL_BUS ourselves
	 */
	self = dbp->dip;

	/*
	 * We can use the generic implementation for these ioctls
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(self, cmd, arg, mode, 0));
	}

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
		rc = ENOTSUP;
		break;


	case DEVCTL_BUS_QUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_QUIESCED)
				break;
		(void) ndi_set_bus_state(self, BUS_QUIESCED);
		break;

	case DEVCTL_BUS_UNQUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_ACTIVE)
				break;
		(void) ndi_set_bus_state(self, BUS_ACTIVE);
		break;

	case DEVCTL_BUS_RESET:
		rc = ENOTSUP;
		break;

	case DEVCTL_BUS_RESETALL:
		rc = ENOTSUP;
		break;

	default:
		rc = ENOTTY;
	}

	ndi_dc_freehdl(dcp);
	return (rc);
}

#ifdef	DB_DEBUG
static dev_info_t *
db_lookup_child_name(db_ctrl_t *dbp, char *name, int instance)
{
	dev_info_t *cdip, *pdip = dbp->dip;

	for (cdip = ddi_get_child(pdip); cdip;
	    cdip = ddi_get_next_sibling(pdip)) {

		do {
			if (strcmp(ddi_node_name(cdip), name) == 0) {
				if (instance != -1) {
					if (ddi_get_instance(cdip) == instance)
						return (cdip);
				} else
					return (cdip);
			}
			pdip = cdip;
		} while ((cdip = ddi_get_child(pdip)));
		cdip = ddi_get_next_sibling(pdip);
		if (cdip == NULL) {
			pdip = ddi_get_parent(pdip);
			if (pdip == dbp->dip)
				break;
		}
	}
	return (NULL);
}

static void
db_pci_get_header(ddi_acc_handle_t config_handle, db_pci_header_t *ph,
    off_t hdr_off)
{
	ph->venid = pci_config_get16(config_handle, hdr_off + PCI_CONF_VENID);
	ph->devid = pci_config_get16(config_handle, hdr_off + PCI_CONF_DEVID);
	ph->command = pci_config_get16(config_handle, hdr_off + PCI_CONF_COMM);
	ph->status = pci_config_get16(config_handle, hdr_off + PCI_CONF_STAT);
	ph->revid = pci_config_get8(config_handle, hdr_off + PCI_CONF_REVID);
	ph->pif = pci_config_get8(config_handle, hdr_off + PCI_CONF_PROGCLASS);
	ph->subclass = pci_config_get8(config_handle,
	    hdr_off + PCI_CONF_SUBCLASS);
	ph->class = pci_config_get8(config_handle,
	    hdr_off + PCI_CONF_BASCLASS);
	ph->cacheline = pci_config_get8(config_handle,
	    hdr_off + PCI_CONF_CACHE_LINESZ);
	ph->lat = pci_config_get8(config_handle,
	    hdr_off + PCI_CONF_LATENCY_TIMER);
	ph->hdr_type = pci_config_get8(config_handle,
	    hdr_off + PCI_CONF_HEADER);
	ph->bist = pci_config_get8(config_handle, hdr_off + PCI_CONF_BIST);
	ph->bar0 = pci_config_get32(config_handle, hdr_off + PCI_CONF_BASE0);
	ph->bar1 = pci_config_get32(config_handle, hdr_off + PCI_CONF_BASE1);
	ph->bar2 = pci_config_get32(config_handle, hdr_off + PCI_CONF_BASE2);
	ph->bar3 = pci_config_get32(config_handle, hdr_off + PCI_CONF_BASE3);
	ph->bar4 = pci_config_get32(config_handle, hdr_off + PCI_CONF_BASE4);
	ph->bar5 = pci_config_get32(config_handle, hdr_off + PCI_CONF_BASE5);
	ph->cardbus_cisp = pci_config_get32(config_handle,
	    hdr_off + PCI_CONF_CIS);
	ph->sub_venid = pci_config_get16(config_handle,
	    hdr_off + PCI_CONF_SUBVENID);
	ph->sub_devid = pci_config_get16(config_handle,
	    hdr_off + PCI_CONF_SUBSYSID);
	ph->exprom_bar = pci_config_get32(config_handle,
	    hdr_off + PCI_CONF_ROM);
	ph->int_line = pci_config_get8(config_handle, hdr_off + PCI_CONF_ILINE);
	ph->int_pin = pci_config_get8(config_handle, hdr_off + PCI_CONF_IPIN);
	ph->min_gnt = pci_config_get8(config_handle, hdr_off + PCI_CONF_MIN_G);
	ph->max_lat = pci_config_get8(config_handle, hdr_off + PCI_CONF_MAX_L);
}

static void
db_pci_get_conf_regs(ddi_acc_handle_t config_handle, db_conf_regs_t *cr)
{
	cr->ds_mem0_tr_base = pci_config_get32(config_handle,
	    DB_CONF_DS_MEM0_TR_BASE);
	cr->ds_io_mem1_tr_base = pci_config_get32(config_handle,
	    DB_CONF_DS_IO_MEM1_TR_BASE);
	cr->ds_mem2_tr_base = pci_config_get32(config_handle,
	    DB_CONF_DS_MEM2_TR_BASE);
	cr->ds_mem3_tr_base = pci_config_get32(config_handle,
	    DB_CONF_DS_MEM3_TR_BASE);
	cr->us_io_mem0_tr_base = pci_config_get32(config_handle,
	    DB_CONF_US_IO_MEM0_TR_BASE);
	cr->us_mem1_tr_base = pci_config_get32(config_handle,
	    DB_CONF_US_MEM1_TR_BASE);
	cr->ds_mem0_setup_reg = pci_config_get32(config_handle,
	    DB_CONF_DS_MEM0_SETUP);
	cr->ds_io_mem1_setup_reg = pci_config_get32(config_handle,
	    DB_CONF_DS_IO_MEM1_SETUP);
	cr->ds_mem2_setup_reg = pci_config_get32(config_handle,
	    DB_CONF_DS_MEM2_SETUP);
	cr->ds_mem3_setup_reg = pci_config_get64(config_handle,
	    DB_CONF_DS_MEM3_SETUP);
	cr->p_exp_rom_setup = pci_config_get32(config_handle,
	    DB_CONF_PRIM_EXP_ROM_SETUP);
	cr->us_io_mem0_setup_reg = pci_config_get32(config_handle,
	    DB_CONF_US_IO_MEM0_SETUP);
	cr->us_mem1_setup_reg = pci_config_get32(config_handle,
	    DB_CONF_US_MEM1_SETUP);
	cr->chip_control0 = pci_config_get16(config_handle, DB_CONF_CHIP_CTRL0);
	cr->chip_control1 = pci_config_get16(config_handle, DB_CONF_CHIP_CTRL1);
	cr->chip_status = pci_config_get16(config_handle, DB_CONF_STATUS);
	cr->arb_control = pci_config_get16(config_handle, DB_CONF_ARBITER_CTRL);
	cr->p_serr_disables = pci_config_get8(config_handle,
	    DB_CONF_PRIM_SERR_DISABLES);
	cr->s_serr_disables = pci_config_get8(config_handle,
	    DB_CONF_PRIM_SERR_DISABLES);
	cr->config_csr = pci_config_get16(config_handle, DB_CONF_CONF_CSR);
	cr->reset_control = pci_config_get32(config_handle, DB_CONF_RESET_CTRL);
	cr->pm_cap = pci_config_get16(config_handle, DB_CONF_PM_CAP);
	cr->pm_csr = pci_config_get16(config_handle, DB_CONF_PM_CSR);
	cr->hs_csr = pci_config_get8(config_handle, DB_CONF_HS_CSR);
}
#endif	/* DB_DEBUG */

/*
 * Function: db_pci_map
 *
 * Note:	Only memory accesses are direct. IO could be direct
 *		or indirect. Config accesses are always indirect.
 *		The question here is, does the "assigned-addresses"
 *		property entry represents the addresses in the
 *		local domain or the host domain itself.
 *		Strictly speaking, the assumption should be that
 *		it is in the local domain, as the transactions
 *		upstream or downstream are automatically
 *		translated by the bridge chip anyway.
 *
 * Return values:
 *		DDI_SUCCESS: map call by child device success
 *		DDI_FAILURE: map operation failed.
 */

static int
db_pci_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *addrp)
{
	register dev_info_t *pdip;
	int reg_proplen, num_regs, rnumber;
	uint_t	addr_space_type;
	pci_regspec_t *pci_regsetp, pci_reg;
	db_ctrl_t *dbp;
	db_acc_pvt_t	*db_pvt;
	ddi_acc_impl_t *ap;
	ddi_acc_hdl_t *hp;
	db_acc_cfg_addr_t *pci_addr;
	int instance = ddi_get_instance(dip);

	DB_DEBUG0(DB_PCI_MAP, dip, "enter\n");

	/* get map type. check for config space */
	switch (mp->map_type) {

		case DDI_MT_RNUMBER :
			/* get the reg number */
			rnumber = mp->map_obj.rnumber;

			if (ddi_getlongprop(DDI_DEV_T_ANY, rdip,
			    DDI_PROP_DONTPASS, "reg",
			    (caddr_t)&pci_regsetp, &reg_proplen)
			    != DDI_SUCCESS)
					return (DDI_FAILURE);

			num_regs = reg_proplen / (int)sizeof (pci_regspec_t);
			if (rnumber >= num_regs) {
				/* this is a DDI_ME_RNUMBER_RANGE error */
				kmem_free(pci_regsetp, reg_proplen);
				return (DDI_FAILURE);
			}

			pci_reg = pci_regsetp[rnumber];
			kmem_free(pci_regsetp, reg_proplen);
			/* FALLTHROUGH */
		case DDI_MT_REGSPEC :
			if (mp->map_type == DDI_MT_REGSPEC)
				pci_reg = *(pci_regspec_t *)mp->map_obj.rp;

			/*
			 * Intercept config space accesses only. All other
			 * requests go to the parent.
			 */
			addr_space_type = pci_reg.pci_phys_hi & PCI_ADDR_MASK;

			DB_DEBUG3(DB_PCI_MAP, dip, "rdip=%lx, rnum=%d(%d)\n",
			    rdip, rnumber, num_regs);

			/* if we do direct map IO, then lets break here */
			if ((db_io_map_mode & DB_IO_MAP_DIRECT) &&
			    (addr_space_type == PCI_ADDR_IO))
					break;

			if ((addr_space_type != PCI_ADDR_CONFIG) &&
			    (addr_space_type != PCI_ADDR_IO))
				break;

			/*
			 * User mapping requests not legal for indirect
			 * IO/Config Space
			 */
			if (mp->map_op == DDI_MO_MAP_HANDLE)
				return (DDI_FAILURE);

			dbp = (db_ctrl_t *)ddi_get_soft_state(db_state,
			    instance);
			/* get our common access handle */
			hp = (ddi_acc_hdl_t *)mp->map_handlep;

			/* Check for unmap operation */
			if ((mp->map_op == DDI_MO_UNMAP) ||
			    (mp->map_op == DDI_MO_UNLOCK)) {
					/*
					 * free up memory allocated for our
					 * private access handle.
					 */
					db_pvt = (db_acc_pvt_t *)
					    hp->ah_bus_private;
					DB_DEBUG1(DB_PCI_MAP, dip,
					    "unmap rdip=%lx\n", rdip);
					kmem_free((void *)db_pvt,
					    sizeof (db_acc_pvt_t));

					/*
					 * unmap operation of PCI IO/config
					 * space.
					 */
					return (DDI_SUCCESS);
			}

			if (addr_space_type == PCI_ADDR_CONFIG) {
				/* Config space access range check */
				if ((offset >= PCI_CONF_HDR_SIZE) ||
				    (len > PCI_CONF_HDR_SIZE) ||
				    (offset + len > PCI_CONF_HDR_SIZE)) {

					return (DDI_FAILURE);
				}
			}

			/* define the complete access handle */
			hp = (ddi_acc_hdl_t *)mp->map_handlep;

			ap = (ddi_acc_impl_t *)hp->ah_platform_private;

			ap->ahi_get8 = db_ddi_get8;
			ap->ahi_get16 = db_ddi_get16;
			ap->ahi_get32 = db_ddi_get32;
			ap->ahi_get64 = db_ddi_get64;
			ap->ahi_put8 = db_ddi_put8;
			ap->ahi_put16 = db_ddi_put16;
			ap->ahi_put32 = db_ddi_put32;
			ap->ahi_put64 = db_ddi_put64;
			ap->ahi_rep_get8 = db_ddi_rep_get8;
			ap->ahi_rep_get16 = db_ddi_rep_get16;
			ap->ahi_rep_get32 = db_ddi_rep_get32;
			ap->ahi_rep_get64 = db_ddi_rep_get64;
			ap->ahi_rep_put8 = db_ddi_rep_put8;
			ap->ahi_rep_put16 = db_ddi_rep_put16;
			ap->ahi_rep_put32 = db_ddi_rep_put32;
			ap->ahi_rep_put64 = db_ddi_rep_put64;

			/* Initialize to default check/notify functions */
			ap->ahi_fault = 0;
			ap->ahi_fault_check = i_ddi_acc_fault_check;
			ap->ahi_fault_notify = i_ddi_acc_fault_notify;

			/* allocate memory for our private handle */
			db_pvt = kmem_zalloc(sizeof (db_acc_pvt_t), KM_SLEEP);
			hp->ah_bus_private = (void *)db_pvt;
			db_pvt->dbp = dbp;

			/* record the device address for future use */
			pci_addr = &db_pvt->dev_addr;
			pci_addr->c_busnum =
			    PCI_REG_BUS_G(pci_reg.pci_phys_hi);
			pci_addr->c_devnum =
			    PCI_REG_DEV_G(pci_reg.pci_phys_hi);
			pci_addr->c_funcnum =
			    PCI_REG_FUNC_G(pci_reg.pci_phys_hi);
			/*
			 * We should keep the upstream or
			 * downstream info in our own ah_bus_private
			 * structure, so that we do not waste our
			 * time in the actual IO routines, figuring out
			 * if we should use upstream or downstream
			 * configuration addr/data register.
			 * So, check orientation and setup registers
			 * right now.
			 */
			switch (addr_space_type) {

			case PCI_ADDR_CONFIG :
				if (dbp->dev_state & DB_PRIMARY_NEXUS) {
					DB_DEBUG0(DB_PCI_MAP, dip, "primary\n");
					db_pvt->mask = DS8_CONF_OWN;
					if (db_conf_map_mode &
					    DB_CONF_MAP_INDIRECT_IO) {
						DB_DEBUG0(DB_PCI_MAP, dip,
						    "INDIRECT_CONF\n");

						db_pvt->handle =
						    dbp->csr_io_handle;
						db_pvt->addr =
						    (uint32_t *)
						    ((uchar_t *)dbp->csr_io
						    + DB_CSR_DS_CONF_ADDR);
						db_pvt->data =
						    (uint32_t *)
						    ((uchar_t *)dbp->csr_io
						    + DB_CSR_DS_CONF_DATA);
						db_pvt->bus_own =
						    (uint8_t *)
						    ((uchar_t *)dbp->csr_io
						    + DB_CSR8_DS_CONF_OWN);
						db_pvt->bus_release =
						    (uint8_t *)
						    ((uchar_t *)dbp->csr_io
						    + DB_CSR8_DS_CONF_CSR);
					} else {
						DB_DEBUG0(DB_PCI_MAP, dip,
						    "DIRECT_CONF\n");

						db_pvt->handle =
						    dbp->conf_handle;
						db_pvt->addr =
						    (uint32_t *)
						    ((uchar_t *)dbp->conf_io
						    + DB_CONF_DS_CONF_ADDR);
						db_pvt->data = (uint32_t *)
						    ((uchar_t *)dbp->conf_io
						    + DB_CONF_DS_CONF_DATA);
						db_pvt->bus_own =
						    (uint8_t *)
						    ((uchar_t *)dbp->conf_io
						    + DB_CONF8_DS_CONF_OWN);
						db_pvt->bus_release =
						    (uint8_t *)
						    ((uchar_t *)dbp->conf_io
						    + DB_CONF8_DS_CONF_CSR);
					}
				} else {
					DB_DEBUG0(DB_PCI_MAP, dip,
					    "secondary\n");
					db_pvt->mask = US8_CONF_OWN;
					if (db_conf_map_mode &
					    DB_CONF_MAP_INDIRECT_IO) {
						DB_DEBUG0(DB_PCI_MAP, dip,
						    "INDIRECT_CONF\n");

						db_pvt->handle =
						    dbp->csr_io_handle;
						db_pvt->addr =
						    (uint32_t *)
						    ((uchar_t *)dbp->csr_io
						    + DB_CSR_US_CONF_ADDR);
						db_pvt->data =
						    (uint32_t *)
						    ((uchar_t *)dbp->csr_io
						    + DB_CSR_US_CONF_DATA);
						db_pvt->bus_own =
						    (uint8_t *)
						    ((uchar_t *)dbp->csr_io
						    + DB_CSR8_US_CONF_OWN);
						db_pvt->bus_release =
						    (uint8_t *)
						    ((uchar_t *)dbp->csr_io
						    + DB_CSR8_US_CONF_CSR);
					} else {
						DB_DEBUG0(DB_PCI_MAP, dip,
						    "DIRECT_CONF\n");

						db_pvt->handle =
						    dbp->conf_handle;
						db_pvt->addr =
						    (uint32_t *)
						    ((uchar_t *)dbp->conf_io
						    + DB_CONF_US_CONF_ADDR);
						db_pvt->data =
						    (uint32_t *)
						    ((uchar_t *)dbp->conf_io
						    + DB_CONF_US_CONF_DATA);
						db_pvt->bus_own =
						    (uint8_t *)
						    ((uchar_t *)dbp->conf_io
						    + DB_CONF8_US_CONF_OWN);
						db_pvt->bus_release =
						    (uint8_t *)
						    ((uchar_t *)dbp->conf_io
						    + DB_CONF8_US_CONF_CSR);
					}
				}
				break;

			case PCI_ADDR_IO :
				DB_DEBUG0(DB_PCI_MAP, dip, "PCI_ADDR_IO\n");

				/* ap->ahi_acc_attr |= DDI_ACCATTR_IO_SPACE; */
				db_pvt->handle = dbp->csr_io_handle;
				if (dbp->dev_state & DB_PRIMARY_NEXUS) {
					DB_DEBUG0(DB_PCI_MAP, dip, "primary\n");
					db_pvt->addr = (uint32_t *)
					    ((uchar_t *)dbp->csr_io
					    + DB_CSR_DS_IO_ADDR);
					db_pvt->data = (uint32_t *)
					    ((uchar_t *)dbp->csr_io
					    + DB_CSR_DS_IO_DATA);
					db_pvt->bus_own = (uint8_t *)
					    ((uchar_t *)dbp->csr_io
					    + DB_CSR8_DS_IO_OWN);
					db_pvt->bus_release = (uint8_t *)
					    ((uchar_t *)dbp->csr_io
					    + DB_CSR8_DS_IO_CSR);
					db_pvt->mask = DS8_IO_OWN;
				} else {
					DB_DEBUG0(DB_PCI_MAP, dip,
					    "secondary\n");
					db_pvt->addr = (uint32_t *)
					    ((uchar_t *)dbp->csr_io
					    + DB_CSR_US_IO_ADDR);
					db_pvt->data = (uint32_t *)
					    ((uchar_t *)dbp->csr_io
					    + DB_CSR_US_IO_DATA);
					db_pvt->bus_own = (uint8_t *)
					    ((uchar_t *)dbp->csr_io
					    + DB_CSR8_US_IO_OWN);
					db_pvt->bus_release = (uint8_t *)
					    ((uchar_t *)dbp->csr_io
					    + DB_CSR8_US_IO_CSR);
					db_pvt->mask = US8_IO_OWN;
				}
				break;

			default :
				DB_DEBUG0(DB_PCI_MAP, dip,
				    "PCI_ADDR unknown\n");
				break;
			}

			/* make and store a type 0/1 address in the *addrp */
			if (pci_addr->c_busnum == dbp->range.lo) {
				*addrp = (caddr_t)DB_PCI_REG_ADDR_TYPE0(
				    pci_addr->c_busnum,
				    pci_addr->c_devnum,
				    pci_addr->c_funcnum,
				    offset);
				db_pvt->access_mode |= DB_PCI_CONF_CYCLE_TYPE0;
				DB_DEBUG0(DB_PCI_MAP, dip,
				    "access mode type 0\n");
			} else {
				*addrp = (caddr_t)DB_PCI_REG_ADDR_TYPE1(
				    pci_addr->c_busnum,
				    pci_addr->c_devnum,
				    pci_addr->c_funcnum,
				    offset);
				db_pvt->access_mode |= DB_PCI_CONF_CYCLE_TYPE1;
				DB_DEBUG0(DB_PCI_MAP, dip,
				    "access mode type 1\n");
			}
			DB_DEBUG4(DB_PCI_MAP, dip, "addrp<%x,%x,%x> = %lx\n",
			    pci_addr->c_busnum, pci_addr->c_devnum,
			    pci_addr->c_funcnum, *addrp);

			return (DDI_SUCCESS);

		default :
				DB_DEBUG1(DB_PCI_MAP, dip, "DDI other %x\n",
				    mp->map_type);
				break;
	}
	DB_DEBUG0(DB_PCI_MAP, dip, "exit\n");

	pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)
	    (pdip, rdip, mp, offset, len, addrp));
}

#ifdef DB_DEBUG
char *db_ctlop_name[] = {
	"DDI_CTLOPS_DMAPMAPC",
	"DDI_CTLOPS_INITCHILD",
	"DDI_CTLOPS_UNINITCHILD",
	"DDI_CTLOPS_REPORTDEV",
	"DDI_CTLOPS_REPORTINT",
	"DDI_CTLOPS_REGSIZE",
	"DDI_CTLOPS_NREGS",
	"DDI_CTLOPS_RESERVED0",
	"DDI_CTLOPS_SIDDEV",
	"DDI_CTLOPS_SLAVEONLY",
	"DDI_CTLOPS_AFFINITY",
	"DDI_CTLOPS_IOMIN",
	"DDI_CTLOPS_PTOB",
	"DDI_CTLOPS_BTOP",
	"DDI_CTLOPS_BTOPR",
	"DDI_CTLOPS_RESERVED1",
	"DDI_CTLOPS_RESERVED2",
	"DDI_CTLOPS_RESERVED3",
	"DDI_CTLOPS_RESERVED4",
	"DDI_CTLOPS_RESERVED5",
	"DDI_CTLOPS_DVMAPAGESIZE",
	"DDI_CTLOPS_POWER",
	"DDI_CTLOPS_ATTACH",
	"DDI_CTLOPS_DETACH",
	"DDI_CTLOPS_POKE",
	"DDI_CTLOPS_PEEK"
};
#endif

static int
db_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{

	if ((ctlop >= DDI_CTLOPS_DMAPMAPC) &&
	    (ctlop <= DDI_CTLOPS_DETACH)) {
		DB_DEBUG1(DB_CTLOPS, dip, "ctlop=%s\n", db_ctlop_name[ctlop]);
	} else {
		DB_DEBUG1(DB_CTLOPS, dip, "ctlop=%d\n", ctlop);
	}

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV :
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?PCI-device: %s@%s, %s#%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD :
		return (db_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD :
		db_uninitchild((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SIDDEV :
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE :
	case DDI_CTLOPS_NREGS :
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		/* fall through */

	default :
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

}

static dev_info_t *
db_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t *cdip = rdip;

	for (; ddi_get_parent(cdip) != dip; cdip = ddi_get_parent(cdip))
		;

	return (cdip);
}

static int
db_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	dev_info_t	*cdip = rdip;
	pci_regspec_t	*pci_rp;
	int		reglen, len;
	uint32_t	d, intr;

	DB_DEBUG1(DB_INTR_OPS, dip, "intr_op=%d\n",  intr_op);

	if ((intr_op == DDI_INTROP_SUPPORTED_TYPES) ||
	    (hdlp->ih_type != DDI_INTR_TYPE_FIXED))
		goto done;

	/*
	 * If the interrupt-map property is defined at this
	 * node, it will have performed the interrupt
	 * translation as part of the property, so no
	 * rotation needs to be done.
	 */

	if (ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupt-map", &len) == DDI_PROP_SUCCESS)
		goto done;

	cdip = db_get_my_childs_dip(dip, rdip);

	/*
	 * Use the devices reg property to determine it's
	 * PCI bus number and device number.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&pci_rp, &reglen) != DDI_SUCCESS)
		return (DDI_FAILURE);

	intr = hdlp->ih_vector;

	/* Spin the interrupt */
	d = PCI_REG_DEV_G(pci_rp[0].pci_phys_hi);

	if ((intr >= PCI_INTA) && (intr <= PCI_INTD))
		hdlp->ih_vector = ((intr - 1 + (d % 4)) % 4 + 1);
	else
		cmn_err(CE_WARN, "%s#%d: %s: PCI intr=%x out of range",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    ddi_driver_name(dip), intr);

	DB_DEBUG3(DB_INTR_OPS, dip, "intr=%d, d=%d, is_intr=%d\n",
	    intr, d, hdlp->ih_vector);

	kmem_free(pci_rp, reglen);

done:
	/* Pass up the request to our parent. */
	return (i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result));
}

static int
db_name_child(dev_info_t *child, char *name, int namelen)
{
	uint_t n, slot, func;
	pci_regspec_t *pci_rp;

	if (ndi_dev_is_persistent_node(child) == 0) {
		char **unit_addr;

		/* name .conf nodes by "unit-address" property" */
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "unit-address", &unit_addr, &n) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "cannot name node from %s.conf",
			    ddi_driver_name(child));
			return (DDI_FAILURE);
		}
		if (n != 1 || *unit_addr == NULL || **unit_addr == 0) {
			cmn_err(CE_WARN, "unit-address property in %s.conf"
			    " not well-formed", ddi_driver_name(child));
			ddi_prop_free(unit_addr);
			return (DDI_FAILURE);
		}

		(void) snprintf(name, namelen, "%s", *unit_addr);
		ddi_prop_free(unit_addr);
		return (DDI_SUCCESS);
	}

	/* name hardware nodes by "reg" property */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child, 0, "reg",
	    (int **)&pci_rp, &n) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* get the device identifications */
	slot = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	if (func != 0)
		(void) snprintf(name, namelen, "%x,%x", slot, func);
	else
		(void) snprintf(name, namelen, "%x", slot);

	ddi_prop_free(pci_rp);
	return (DDI_SUCCESS);
}

static int
db_initchild(dev_info_t *child)
{
	char name[MAXNAMELEN];
	ddi_acc_handle_t config_handle;
	ushort_t command_preserve, command;
	uint_t n;
	ushort_t bcr;
	uchar_t header_type, min_gnt, latency_timer;
	db_ctrl_t *dbp;

	if (db_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS)
		return (DDI_FAILURE);

	ddi_set_name_addr(child, name);
	ddi_set_parent_data(child, NULL);

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 * The interpretation of the unit-address is DD[,F]
	 * where DD is the device id and F is the function.
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		extern int pci_allow_pseudo_children;

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, db_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			return (DDI_FAILURE);
		}

		/* workaround for ddivs to run under PCI */
		if (pci_allow_pseudo_children) {
			return (DDI_SUCCESS);
		}

		/*
		 * The child was not merged into a h/w node,
		 * but there's not much we can do with it other
		 * than return failure to cause the node to be removed.
		 */
		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_driver_name(child), ddi_get_name_addr(child),
		    ddi_driver_name(child));
		return (DDI_NOT_WELL_FORMED);
	}


	if ((db_create_pci_prop(child) != DDI_SUCCESS) ||
	    (pci_config_setup(child, &config_handle) != DDI_SUCCESS)) {
		db_uninitchild(child);
		return (DDI_FAILURE);
	}

	/*
	 * Determine the configuration header type.
	 */
	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);

	/*
	 * Support for the "command-preserve" property.
	 */
	command_preserve = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "command-preserve", 0);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);
	command &= (command_preserve | PCI_COMM_BACK2BACK_ENAB);
	command |= (db_command_default & ~command_preserve);
	pci_config_put16(config_handle, PCI_CONF_COMM, command);

	DB_DEBUG2(DB_INITCHILD, ddi_get_parent(child),
	    "initializing device vend=%x, devid=%x\n",
	    pci_config_get16(config_handle, PCI_CONF_VENID),
	    pci_config_get16(config_handle, PCI_CONF_DEVID));
	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		bcr = pci_config_get8(config_handle, PCI_BCNF_BCNTRL);
		if (db_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (db_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(config_handle, PCI_BCNF_BCNTRL, bcr);
	}

	dbp = (db_ctrl_t *)ddi_get_soft_state(db_state,
	    ddi_get_instance(ddi_get_parent(child)));

	/*
	 * Initialize cache-line-size configuration register if needed.
	 */
	if (db_set_cache_line_size_register &&
	    ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "cache-line-size", 0) == 0) {
		pci_config_put8(config_handle, PCI_CONF_CACHE_LINESZ,
		    dbp->cache_line_size);
		n = pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		if (n != 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
			    "cache-line-size", n);
		}
		DB_DEBUG1(DB_INITCHILD, ddi_get_parent(child),
		    "\nChild Device Cache Size %x\n", dbp->cache_line_size);
	}

	/*
	 * Initialize latency timer configuration registers if needed.
	 */
	if (db_set_latency_timer_register &&
	    ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "latency-timer", 0) == 0) {

		if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
			latency_timer = dbp->p_latency_timer;
			pci_config_put8(config_handle, PCI_BCNF_LATENCY_TIMER,
			    dbp->latency_timer);
		} else {
			min_gnt = pci_config_get8(config_handle,
			    PCI_CONF_MIN_G);
			latency_timer = min_gnt * 8;
		}
		pci_config_put8(config_handle, PCI_CONF_LATENCY_TIMER,
		    latency_timer);
		n = pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);
		if (n != 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
			    "latency-timer", n);
		}
		DB_DEBUG1(DB_INITCHILD, ddi_get_parent(child),
		    "\nChild Device latency %x\n", latency_timer);
	}

	pci_config_teardown(&config_handle);
	return (DDI_SUCCESS);
}

static void
db_uninitchild(dev_info_t *dip)
{
	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	impl_rem_dev_props(dip);
}

static int
db_create_pci_prop(dev_info_t *child)
{
	pci_regspec_t *pci_rp;
	int	length;
	int	value;

	/* get child "reg" property */
	value = ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_CANSLEEP,
	    "reg", (caddr_t)&pci_rp, &length);
	if (value != DDI_SUCCESS)
		return (value);

	(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE, child, "reg",
	    (uchar_t *)pci_rp, length);

	/*
	 * free the memory allocated by ddi_getlongprop ().
	 */
	kmem_free(pci_rp, length);

	/*
	 * No need to create any 1275 properties here, because either
	 * the OBP creates them or the hotplug framework creates it
	 * during a hotplug operation. So lets return here.
	 */
	return (DDI_SUCCESS);
}

/*
 * db_save_config_regs
 *
 * This routine saves the state of the configuration registers of all
 * immediate child nodes.
 *
 * used by: db_detach() on suspends
 *
 * return value: DDI_SUCCESS: ALl children state saved.
 *		 DDI_FAILURE: Child device state could not be saved.
 */
static int
db_save_config_regs(db_ctrl_t *dbp)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t config_handle;
	db_cfg_state_t *statep;

	for (i = 0, dip = ddi_get_child(dbp->dip); dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {
		if (i_ddi_devi_attached(dip))
			i++;
	}
	dbp->config_state_index = i;

	if (!i) {
		/* no children */
		dbp->db_config_state_p = NULL;
		return (DDI_SUCCESS);
	}

	/* i now equals the total number of child devices */
	dbp->db_config_state_p =
	    kmem_zalloc(i * sizeof (db_cfg_state_t), KM_NOSLEEP);
	if (!dbp->db_config_state_p) {
		cmn_err(CE_WARN,
		    "%s#%d: No memory to save state for child %s#%d\n",
		    ddi_driver_name(dbp->dip),
		    ddi_get_instance(dbp->dip),
		    ddi_get_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	for (statep = dbp->db_config_state_p,
	    dip = ddi_get_child(dbp->dip);
	    dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {

		if (!i_ddi_devi_attached(dip))
			continue;

		if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s#%d: can't config space for %s#%d",
			    ddi_driver_name(dbp->dip),
			    ddi_get_instance(dbp->dip),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			continue;
		}

		statep->dip = dip;
		statep->command =
		    pci_config_get16(config_handle, PCI_CONF_COMM);
		statep->header_type =
		    pci_config_get8(config_handle, PCI_CONF_HEADER);
		if ((statep->header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			statep->bridge_control =
			    pci_config_get16(config_handle, PCI_BCNF_BCNTRL);
		statep->cache_line_size =
		    pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		statep->latency_timer =
		    pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);
		if ((statep->header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			statep->sec_latency_timer =
			    pci_config_get8(config_handle,
			    PCI_BCNF_LATENCY_TIMER);
		pci_config_teardown(&config_handle);
		statep++;
	}
	return (DDI_SUCCESS);
}


/*
 * db_restore_config_regs
 *
 * This routine restores the state of the configuration registers of
 * all immediate child nodes.
 *
 * used by: db_attach() on resume
 *
 * return value: none
 */
static int
db_restore_config_regs(db_ctrl_t *dbp)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t config_handle;
	db_cfg_state_t *statep = dbp->db_config_state_p;

	for (i = 0; i < dbp->config_state_index; i++, statep++) {
		dip = statep->dip;
		if (!dip) {
			cmn_err(CE_WARN,
			    "%s#%d: skipping bad dev info (index %d)",
			    ddi_driver_name(dbp->dip),
			    ddi_get_instance(dbp->dip), i);
			continue;
		}
		if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s#%d: can't config space for %s#%d",
			    ddi_driver_name(dbp->dip),
			    ddi_get_instance(dbp->dip),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			continue;
		}
		pci_config_put16(config_handle, PCI_CONF_COMM, statep->command);
		if ((statep->header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			pci_config_put16(config_handle, PCI_BCNF_BCNTRL,
			    statep->bridge_control);
		pci_config_put8(config_handle, PCI_CONF_CACHE_LINESZ,
		    statep->cache_line_size);
		pci_config_put8(config_handle, PCI_CONF_LATENCY_TIMER,
		    statep->latency_timer);
		if ((statep->header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			pci_config_put8(config_handle, PCI_BCNF_LATENCY_TIMER,
			    statep->sec_latency_timer);
		pci_config_teardown(&config_handle);
	}

	kmem_free(dbp->db_config_state_p,
	    dbp->config_state_index * sizeof (db_cfg_state_t));
	dbp->db_config_state_p = NULL;
	dbp->config_state_index = 0;

	return (DDI_SUCCESS);
}

/* put a type 0/1 address on the bus */
static void
db_put_reg_conf_addr(db_acc_pvt_t *db_pvt, uint32_t conf_addr)
{
	if (db_pvt->access_mode & DB_PCI_CONF_CYCLE_TYPE0)\
		ddi_put32(db_pvt->handle, db_pvt->addr, (uint32_t)\
		    DB_PCI_CONF_CYCLE_TYPE0_ADDR((conf_addr)));\
	else	/* type 1 cycle */\
		ddi_put32(db_pvt->handle, db_pvt->addr, (uint32_t)\
		    DB_PCI_CONF_CYCLE_TYPE1_ADDR((conf_addr)));
}

/* Get 8bits data off the 32bit data */
static uint8_t
db_get_data8(uint32_t addr, uint32_t data)
{
	return (((data) >> (((addr) & 3) * 8)) & 0xff);
}

/* Get 16bits data off the 32bit data */
static uint16_t
db_get_data16(uint32_t addr, uint32_t data)
{
	return (((data) >> (((addr) & 3) * 8)) & 0xffff);
}

/* merge 8bit data into the 32bit data */
static uint32_t
db_put_data8(uint32_t addr, uint32_t rdata, uint8_t wdata)
{
	return ((rdata & (~((0xff << ((((addr) & 3) * 8))) & 0xffffffff))) |
	    (((wdata) & 0xff)<<((((addr) & 3))*8)));
}

/* merge 16bit data into the 32bit data */
static uint32_t
db_put_data16(uint32_t addr, uint32_t rdata, uint16_t wdata)
{
	return ((rdata & (~((0xffff << ((((addr) & 3) * 8))) & 0xffffffff))) |
	    (((wdata) & 0xffff) << ((((addr) & 3))*8)));
}


/*
 * For the next set of PCI configuration IO calls, we need
 * to make sure we own the bus before generating the config cycles,
 * using the drawbridge's semaphore method.
 */

/*
 * Function to read 8 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static uint8_t
db_ddi_get8(ddi_acc_impl_t *handle, uint8_t *addr)
{
	uint32_t data;

	data = db_ddi_get32(handle, (uint32_t *)addr);
	return (db_get_data8((uint32_t)(uintptr_t)addr, data));
}

/*
 * Function to read 16 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static uint16_t
db_ddi_get16(ddi_acc_impl_t *handle, uint16_t *addr)
{
	uint32_t data;

	data = db_ddi_get32(handle, (uint32_t *)addr);
	return (db_get_data16((uint32_t)(uintptr_t)addr, data));
}

/*
 * Function to read 32 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static uint32_t
db_ddi_get32(ddi_acc_impl_t *handle, uint32_t *addr)
{
	db_acc_pvt_t	*db_pvt = (db_acc_pvt_t *)
	    handle->ahi_common.ah_bus_private;
	uint32_t	wait_count = 0;
	uint32_t	data;
	db_ctrl_t	*dbp;

	dbp = db_pvt->dbp;

	mutex_enter(&dbp->db_busown);

	if (db_use_config_own_bit) {
		/*
		 * check if (upstream/downstream)configuration address own
		 * bit set. With this set, we cannot proceed.
		 */
		while (((ddi_get8(db_pvt->handle, db_pvt->bus_own)) &
		    db_pvt->mask) == db_pvt->mask) {
#ifdef DEBUG
			if (dbp->db_pci_max_wait_count < wait_count)
				dbp->db_pci_max_wait_count = wait_count;
#endif
			drv_usecwait(db_pci_own_wait);
			if (++wait_count == db_pci_max_wait) {
				/*
				 * the man page for pci_config_* routines do
				 * Not specify any error condition values.
				 */
				cmn_err(CE_WARN,
				    "%s#%d: pci config bus own error",
				    ddi_driver_name(dbp->dip),
				    ddi_get_instance(dbp->dip));
				dbp->db_pci_err_count++;
				mutex_exit(&dbp->db_busown);
				return ((uint32_t)DB_CONF_FAILURE);
			}
		}
		wait_count = 0;
	}

	db_put_reg_conf_addr(db_pvt, (uint32_t)(uintptr_t)addr);
	data = ddi_get32(db_pvt->handle, (uint32_t *)db_pvt->data);

	if (db_use_config_own_bit) {
		while (((ddi_get8(db_pvt->handle, db_pvt->bus_release)) &
		    db_pvt->mask) == db_pvt->mask) {
#ifdef DEBUG
			if (dbp->db_pci_max_wait_count < wait_count)
				dbp->db_pci_max_wait_count = wait_count;
#endif
			drv_usecwait(db_pci_release_wait);
			if (++wait_count == db_pci_max_wait) {
				/*
				 * the man page for pci_config_* routines do
				 * not specify any error condition values.
				 */
				cmn_err(CE_WARN,
				    "%s#%d: pci config bus release error",
				    ddi_driver_name(dbp->dip),
				    ddi_get_instance(dbp->dip));
				dbp->db_pci_err_count++;
				mutex_exit(&dbp->db_busown);
				return ((uint32_t)DB_CONF_FAILURE);
			}
			data = ddi_get32(db_pvt->handle,
			    (uint32_t *)db_pvt->data);
		}
	}

	mutex_exit(&dbp->db_busown);

	return (data);
}

/*
 * Function to read 64 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static uint64_t
db_ddi_get64(ddi_acc_impl_t *handle, uint64_t *addr)
{
	uint64_t udata, ldata;

	ldata = (uint32_t)db_ddi_get32(handle, (uint32_t *)addr);
	udata = (uint32_t)db_ddi_get32(handle, (uint32_t *)addr + 1);
	return (ldata | (udata << 32));
}

/*
 * Function to write 8 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_put8(ddi_acc_impl_t *handle, uint8_t *addr, uint8_t data)
{
	uint32_t rdata;

	rdata = db_ddi_get32(handle, (uint32_t *)addr);
	db_ddi_put32(handle, (uint32_t *)addr,
	    db_put_data8((uint32_t)(uintptr_t)addr, rdata, data));
}

/*
 * Function to write 16 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_put16(ddi_acc_impl_t *handle, uint16_t *addr, uint16_t data)
{
	uint32_t rdata;

	rdata = db_ddi_get32(handle, (uint32_t *)addr);
	db_ddi_put32(handle, (uint32_t *)addr,
	    db_put_data16((uint32_t)(uintptr_t)addr, rdata, data));
}

/*
 * Function to write 32 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_put32(ddi_acc_impl_t *handle, uint32_t *addr, uint32_t data)
{
	db_acc_pvt_t	*db_pvt = (db_acc_pvt_t *)
	    handle->ahi_common.ah_bus_private;
	db_ctrl_t	*dbp;
	uint32_t	wait_count = 0;

	dbp = db_pvt->dbp;

	mutex_enter(&dbp->db_busown);

	if (db_use_config_own_bit) {
		/*
		 * check if (upstream/downstream)configuration address own
		 * bit set. with this set, we cannot proceed.
		 */
		while (((ddi_get8(db_pvt->handle, db_pvt->bus_own)) &
		    db_pvt->mask) == db_pvt->mask) {
#ifdef DEBUG
			if (dbp->db_pci_max_wait_count < wait_count)
				dbp->db_pci_max_wait_count = wait_count;
#endif
			drv_usecwait(db_pci_own_wait);
			if (++wait_count == db_pci_max_wait) {
				/*
				 * Since the return value is void here,
				 * we may need to print a message, as this
				 * could be a serious situation.
				 */
				cmn_err(CE_WARN,
				    "%s#%d: pci config bus own error",
				    ddi_driver_name(dbp->dip),
				    ddi_get_instance(dbp->dip));
				dbp->db_pci_err_count++;
				mutex_exit(&dbp->db_busown);
				return;
			}
		}
		wait_count = 0;
	}

	db_put_reg_conf_addr(db_pvt, (uint32_t)(uintptr_t)addr);
	ddi_put32(db_pvt->handle, (uint32_t *)db_pvt->data, data);

	if (db_use_config_own_bit) {
		while (((ddi_get8(db_pvt->handle, db_pvt->bus_release)) &
		    db_pvt->mask) == db_pvt->mask) {
#ifdef DEBUG
			if (dbp->db_pci_max_wait_count < wait_count)
				dbp->db_pci_max_wait_count = wait_count;
#endif
			drv_usecwait(db_pci_release_wait);
			if (++wait_count == db_pci_max_wait) {
				/*
				 * the man page for pci_config_* routines do
				 * Not specify any error condition values.
				 */
				cmn_err(CE_WARN,
				    "%s#%d: pci config bus release error",
				    ddi_driver_name(dbp->dip),
				    ddi_get_instance(dbp->dip));
				dbp->db_pci_err_count++;
				mutex_exit(&dbp->db_busown);
				return;
			}
			ddi_put32(db_pvt->handle, (uint32_t *)db_pvt->data,
			    data);
		}
	}

	mutex_exit(&dbp->db_busown);
}

/*
 * Function to write 64 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_put64(ddi_acc_impl_t *handle, uint64_t *addr, uint64_t data)
{
	db_ddi_put32(handle, (uint32_t *)addr, (uint32_t)(data & 0xffffffff));
	db_ddi_put32(handle, (uint32_t *)addr + 1, (uint32_t)(data >> 32));
}

/*
 * Function to rep read 8 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_rep_get8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*host_addr++ = db_ddi_get8(handle, dev_addr++);
	else
		for (; repcount; repcount--)
			*host_addr++ = db_ddi_get8(handle, dev_addr);
}

/*
 * Function to rep read 16 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_rep_get16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*host_addr++ = db_ddi_get16(handle, dev_addr++);
	else
		for (; repcount; repcount--)
			*host_addr++ = db_ddi_get16(handle, dev_addr);
}

/*
 * Function to rep read 32 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_rep_get32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*host_addr++ = db_ddi_get32(handle, dev_addr++);
	else
		for (; repcount; repcount--)
			*host_addr++ = db_ddi_get32(handle, dev_addr);
}

/*
 * Function to rep read 64 bit data off the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_rep_get64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*host_addr++ = db_ddi_get64(handle, dev_addr++);
	else
		for (; repcount; repcount--)
			*host_addr++ = db_ddi_get64(handle, dev_addr);
}

/*
 * Function to rep write 8 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_rep_put8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			db_ddi_put8(handle, dev_addr++, *host_addr++);
	else
		for (; repcount; repcount--)
			db_ddi_put8(handle, dev_addr, *host_addr++);
}

/*
 * Function to rep write 16 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_rep_put16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			db_ddi_put16(handle, dev_addr++, *host_addr++);
	else
		for (; repcount; repcount--)
			db_ddi_put16(handle, dev_addr, *host_addr++);
}

/*
 * Function to rep write 32 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_rep_put32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			db_ddi_put32(handle, dev_addr++, *host_addr++);
	else
		for (; repcount; repcount--)
			db_ddi_put32(handle, dev_addr, *host_addr++);
}

/*
 * Function to rep write 64 bit data into the PCI configuration space behind
 * the 21554's host interface.
 */
static void
db_ddi_rep_put64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			db_ddi_put64(handle, dev_addr++, *host_addr++);
	else
		for (; repcount; repcount--)
			db_ddi_put64(handle, dev_addr, *host_addr++);
}

#ifdef DEBUG

static void
db_debug(uint64_t func_id, dev_info_t *dip, char *fmt,
    uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	char *s = NULL;
	uint_t dip_no_disp = 0;

	if (func_id & DB_DONT_DISPLAY_DIP) {
		dip_no_disp = 1;
	}
	if (db_debug_funcs & func_id) {
		switch (func_id) {
		case DB_INIT:		s = "_init";			break;
		case DB_FINI:		s = "_fini";			break;
		case DB_INFO:		s = "_info";			break;
		case DB_GETINFO:	s = "getinfo";			break;
		case DB_ATTACH:		s = "attach";			break;
		case DB_DETACH:		s = "detach";			break;
		case DB_CTLOPS:		s = "ctlops";			break;
		case DB_INITCHILD:	s = "initchild";		break;
		case DB_REMOVECHILD:	s = "removechild";		break;
		case DB_INTR_OPS:	s = "intr_ops";			break;
		case DB_PCI_MAP:	s = "map";			break;
		case DB_SAVE_CONF_REGS:	s = "save_conf_regs";		break;
		case DB_REST_CONF_REGS:	s = "restore_conf_regs";	break;
		case DB_INTR:		s = "intr";			break;
		case DB_OPEN:		s = "open";			break;
		case DB_CLOSE:		s = "close";			break;
		case DB_IOCTL:		s = "ioctl";			break;
		case DB_DVMA:		s = "set_dvma_range";		break;

		default:		s = "PCI debug unknown";	break;
		}

		if (s && !dip_no_disp) {
			prom_printf("%s(%d): %s: ", ddi_driver_name(dip),
			    ddi_get_instance(dip), s);
		}
		prom_printf(fmt, a1, a2, a3, a4, a5);
	}
}
#endif

static int db_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	minor_t minor = getminor(dev);
	int	instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);

	db_ctrl_t *dbp = (db_ctrl_t *)ddi_get_soft_state(db_state, instance);


	if (dbp == NULL)
		return (ENXIO);

	if (dbp->dev_state & DB_SECONDARY_NEXUS)
		return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip,
		    prop_op, flags, name, valuep, lengthp));

	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}

/*
 * Initialize our FMA resources
 */
static void
db_fm_init(db_ctrl_t *db_p)
{
	db_p->fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;

	/*
	 * Request our capability level and get our parents capability
	 * and ibc.
	 */
	ddi_fm_init(db_p->dip, &db_p->fm_cap, &db_p->fm_ibc);
	ASSERT((db_p->fm_cap & DDI_FM_EREPORT_CAPABLE) &&
	    (db_p->fm_cap & DDI_FM_ERRCB_CAPABLE));

	pci_ereport_setup(db_p->dip);

	/*
	 * Register error callback with our parent.
	 */
	ddi_fm_handler_register(db_p->dip, db_err_callback, NULL);
}

/*
 * Breakdown our FMA resources
 */
static void
db_fm_fini(db_ctrl_t *db_p)
{
	/*
	 * Clean up allocated fm structures
	 */
	ddi_fm_handler_unregister(db_p->dip);
	pci_ereport_teardown(db_p->dip);
	ddi_fm_fini(db_p->dip);
}

/*
 * Initialize FMA resources for children devices. Called when
 * child calls ddi_fm_init().
 */
/*ARGSUSED*/
static int
db_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	db_ctrl_t *db_p = (db_ctrl_t *)ddi_get_soft_state(db_state,
	    ddi_get_instance(dip));
	*ibc = db_p->fm_ibc;
	return (db_p->fm_cap);
}

/*
 * FMA registered error callback
 */
static int
db_err_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *impl_data)
{
	ASSERT(impl_data == NULL);
	pci_ereport_post(dip, derr, NULL);
	return (derr->fme_status);
}

static void
db_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle)
{
	i_ndi_busop_access_enter(dip, handle);
}

/* ARGSUSED */
static void
db_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle)
{
	i_ndi_busop_access_exit(dip, handle);
}
