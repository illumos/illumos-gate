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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/promif.h>
#include <sys/disp.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/pci_cap.h>
#include <sys/pci_impl.h>
#include <sys/pcie_impl.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/hotplug/pci/pciehpc.h>
#include <sys/hotplug/pci/pcishpc.h>
#include <sys/hotplug/pci/pcicfg.h>
#include <sys/pci_cfgacc.h>

/* Local functions prototypes */
static void pcie_init_pfd(dev_info_t *);
static void pcie_fini_pfd(dev_info_t *);

#if defined(__i386) || defined(__amd64)
static void pcie_check_io_mem_range(ddi_acc_handle_t, boolean_t *, boolean_t *);
#endif /* defined(__i386) || defined(__amd64) */

#ifdef DEBUG
uint_t pcie_debug_flags = 0;
static void pcie_print_bus(pcie_bus_t *bus_p);
void pcie_dbg(char *fmt, ...);
#endif /* DEBUG */

/* Variable to control default PCI-Express config settings */
ushort_t pcie_command_default =
    PCI_COMM_SERR_ENABLE |
    PCI_COMM_WAIT_CYC_ENAB |
    PCI_COMM_PARITY_DETECT |
    PCI_COMM_ME |
    PCI_COMM_MAE |
    PCI_COMM_IO;

/* xxx_fw are bits that are controlled by FW and should not be modified */
ushort_t pcie_command_default_fw =
    PCI_COMM_SPEC_CYC |
    PCI_COMM_MEMWR_INVAL |
    PCI_COMM_PALETTE_SNOOP |
    PCI_COMM_WAIT_CYC_ENAB |
    0xF800; /* Reserved Bits */

ushort_t pcie_bdg_command_default_fw =
    PCI_BCNF_BCNTRL_ISA_ENABLE |
    PCI_BCNF_BCNTRL_VGA_ENABLE |
    0xF000; /* Reserved Bits */

/* PCI-Express Base error defaults */
ushort_t pcie_base_err_default =
    PCIE_DEVCTL_CE_REPORTING_EN |
    PCIE_DEVCTL_NFE_REPORTING_EN |
    PCIE_DEVCTL_FE_REPORTING_EN |
    PCIE_DEVCTL_UR_REPORTING_EN;

/* PCI-Express Device Control Register */
uint16_t pcie_devctl_default = PCIE_DEVCTL_RO_EN |
    PCIE_DEVCTL_MAX_READ_REQ_512;

/* PCI-Express AER Root Control Register */
#define	PCIE_ROOT_SYS_ERR	(PCIE_ROOTCTL_SYS_ERR_ON_CE_EN | \
				PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN | \
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN)

ushort_t pcie_root_ctrl_default =
    PCIE_ROOTCTL_SYS_ERR_ON_CE_EN |
    PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN;

/* PCI-Express Root Error Command Register */
ushort_t pcie_root_error_cmd_default =
    PCIE_AER_RE_CMD_CE_REP_EN |
    PCIE_AER_RE_CMD_NFE_REP_EN |
    PCIE_AER_RE_CMD_FE_REP_EN;

/* ECRC settings in the PCIe AER Control Register */
uint32_t pcie_ecrc_value =
    PCIE_AER_CTL_ECRC_GEN_ENA |
    PCIE_AER_CTL_ECRC_CHECK_ENA;

/*
 * If a particular platform wants to disable certain errors such as UR/MA,
 * instead of using #defines have the platform's PCIe Root Complex driver set
 * these masks using the pcie_get_XXX_mask and pcie_set_XXX_mask functions.  For
 * x86 the closest thing to a PCIe root complex driver is NPE.	For SPARC the
 * closest PCIe root complex driver is PX.
 *
 * pcie_serr_disable_flag : disable SERR only (in RCR and command reg) x86
 * systems may want to disable SERR in general.  For root ports, enabling SERR
 * causes NMIs which are not handled and results in a watchdog timeout error.
 */
uint32_t pcie_aer_uce_mask = 0;		/* AER UE Mask */
uint32_t pcie_aer_ce_mask = 0;		/* AER CE Mask */
uint32_t pcie_aer_suce_mask = 0;	/* AER Secondary UE Mask */
uint32_t pcie_serr_disable_flag = 0;	/* Disable SERR */

/* Default severities needed for eversholt.  Error handling doesn't care */
uint32_t pcie_aer_uce_severity = PCIE_AER_UCE_MTLP | PCIE_AER_UCE_RO | \
    PCIE_AER_UCE_FCP | PCIE_AER_UCE_SD | PCIE_AER_UCE_DLP | \
    PCIE_AER_UCE_TRAINING;
uint32_t pcie_aer_suce_severity = PCIE_AER_SUCE_SERR_ASSERT | \
    PCIE_AER_SUCE_UC_ADDR_ERR | PCIE_AER_SUCE_UC_ATTR_ERR | \
    PCIE_AER_SUCE_USC_MSG_DATA_ERR;

int pcie_max_mps = PCIE_DEVCTL_MAX_PAYLOAD_4096 >> 5;
int pcie_disable_ari = 0;

static void pcie_scan_mps(dev_info_t *rc_dip, dev_info_t *dip,
	int *max_supported);
static int pcie_get_max_supported(dev_info_t *dip, void *arg);
static int pcie_map_phys(dev_info_t *dip, pci_regspec_t *phys_spec,
    caddr_t *addrp, ddi_acc_handle_t *handlep);
static void pcie_unmap_phys(ddi_acc_handle_t *handlep,	pci_regspec_t *ph);

dev_info_t *pcie_get_rc_dip(dev_info_t *dip);

/*
 * modload support
 */

static struct modlmisc modlmisc	= {
	&mod_miscops,	/* Type	of module */
	"PCI Express Framework Module"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void	*)&modlmisc,
	NULL
};

/*
 * Global Variables needed for a non-atomic version of ddi_fm_ereport_post.
 * Currently used to send the pci.fabric ereports whose payload depends on the
 * type of PCI device it is being sent for.
 */
char		*pcie_nv_buf;
nv_alloc_t	*pcie_nvap;
nvlist_t	*pcie_nvl;

int
_init(void)
{
	int rval;

	pcie_nv_buf = kmem_alloc(ERPT_DATA_SZ, KM_SLEEP);
	pcie_nvap = fm_nva_xcreate(pcie_nv_buf, ERPT_DATA_SZ);
	pcie_nvl = fm_nvlist_create(pcie_nvap);

	if ((rval = mod_install(&modlinkage)) != 0) {
		fm_nvlist_destroy(pcie_nvl, FM_NVA_RETAIN);
		fm_nva_xdestroy(pcie_nvap);
		kmem_free(pcie_nv_buf, ERPT_DATA_SZ);
	}
	return (rval);
}

int
_fini()
{
	int		rval;

	if ((rval = mod_remove(&modlinkage)) == 0) {
		fm_nvlist_destroy(pcie_nvl, FM_NVA_RETAIN);
		fm_nva_xdestroy(pcie_nvap);
		kmem_free(pcie_nv_buf, ERPT_DATA_SZ);
	}
	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
int
pcie_init(dev_info_t *dip, caddr_t arg)
{
	int	ret = DDI_SUCCESS;

	/*
	 * Create a "devctl" minor node to support DEVCTL_DEVICE_*
	 * and DEVCTL_BUS_* ioctls to this bus.
	 */
	if ((ret = ddi_create_minor_node(dip, "devctl", S_IFCHR,
	    PCI_MINOR_NUM(ddi_get_instance(dip), PCI_DEVCTL_MINOR),
	    DDI_NT_NEXUS, 0)) != DDI_SUCCESS) {
		PCIE_DBG("Failed to create devctl minor node for %s%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		return (ret);
	}

	if ((ret = pcie_hp_init(dip, arg)) != DDI_SUCCESS) {
		/*
		 * On some x86 platforms, we observed unexpected hotplug
		 * initialization failures in recent years. The known cause
		 * is a hardware issue: while the problem PCI bridges have
		 * the Hotplug Capable registers set, the machine actually
		 * does not implement the expected ACPI object.
		 *
		 * We don't want to stop PCI driver attach and system boot
		 * just because of this hotplug initialization failure.
		 * Continue with a debug message printed.
		 */
		PCIE_DBG("%s%d: Failed setting hotplug framework\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

#if defined(__sparc)
		ddi_remove_minor_node(dip, "devctl");

		return (ret);
#endif /* defined(__sparc) */
	}

	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
pcie_uninit(dev_info_t *dip)
{
	int	ret = DDI_SUCCESS;

	if (pcie_ari_is_enabled(dip) == PCIE_ARI_FORW_ENABLED)
		(void) pcie_ari_disable(dip);

	if ((ret = pcie_hp_uninit(dip)) != DDI_SUCCESS) {
		PCIE_DBG("Failed to uninitialize hotplug for %s%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		return (ret);
	}

	ddi_remove_minor_node(dip, "devctl");

	return (ret);
}

/*
 * PCIe module interface for enabling hotplug interrupt.
 *
 * It should be called after pcie_init() is done and bus driver's
 * interrupt handlers have being attached.
 */
int
pcie_hpintr_enable(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	pcie_hp_ctrl_t	*ctrl_p = PCIE_GET_HP_CTRL(dip);

	if (PCIE_IS_PCIE_HOTPLUG_ENABLED(bus_p)) {
		(void) (ctrl_p->hc_ops.enable_hpc_intr)(ctrl_p);
	} else if (PCIE_IS_PCI_HOTPLUG_ENABLED(bus_p)) {
		(void) pcishpc_enable_irqs(ctrl_p);
	}
	return (DDI_SUCCESS);
}

/*
 * PCIe module interface for disabling hotplug interrupt.
 *
 * It should be called before pcie_uninit() is called and bus driver's
 * interrupt handlers is dettached.
 */
int
pcie_hpintr_disable(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	pcie_hp_ctrl_t	*ctrl_p = PCIE_GET_HP_CTRL(dip);

	if (PCIE_IS_PCIE_HOTPLUG_ENABLED(bus_p)) {
		(void) (ctrl_p->hc_ops.disable_hpc_intr)(ctrl_p);
	} else if (PCIE_IS_PCI_HOTPLUG_ENABLED(bus_p)) {
		(void) pcishpc_disable_irqs(ctrl_p);
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
pcie_intr(dev_info_t *dip)
{
	return (pcie_hp_intr(dip));
}

/* ARGSUSED */
int
pcie_open(dev_info_t *dip, dev_t *devp, int flags, int otyp, cred_t *credp)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Handle the open by tracking the device state.
	 */
	if ((bus_p->bus_soft_state == PCI_SOFT_STATE_OPEN_EXCL) ||
	    ((flags & FEXCL) &&
	    (bus_p->bus_soft_state != PCI_SOFT_STATE_CLOSED))) {
		return (EBUSY);
	}

	if (flags & FEXCL)
		bus_p->bus_soft_state = PCI_SOFT_STATE_OPEN_EXCL;
	else
		bus_p->bus_soft_state = PCI_SOFT_STATE_OPEN;

	return (0);
}

/* ARGSUSED */
int
pcie_close(dev_info_t *dip, dev_t dev, int flags, int otyp, cred_t *credp)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	bus_p->bus_soft_state = PCI_SOFT_STATE_CLOSED;

	return (0);
}

/* ARGSUSED */
int
pcie_ioctl(dev_info_t *dip, dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	struct devctl_iocdata	*dcp;
	uint_t			bus_state;
	int			rv = DDI_SUCCESS;

	/*
	 * We can use the generic implementation for devctl ioctl
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(dip, cmd, arg, mode, 0));
	default:
		break;
	}

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {
	case DEVCTL_BUS_QUIESCE:
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_QUIESCED)
				break;
		(void) ndi_set_bus_state(dip, BUS_QUIESCED);
		break;
	case DEVCTL_BUS_UNQUIESCE:
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_ACTIVE)
				break;
		(void) ndi_set_bus_state(dip, BUS_ACTIVE);
		break;
	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:
	case DEVCTL_DEVICE_RESET:
		rv = ENOTSUP;
		break;
	default:
		rv = ENOTTY;
	}

	ndi_dc_freehdl(dcp);
	return (rv);
}

/* ARGSUSED */
int
pcie_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	if (dev == DDI_DEV_T_ANY)
		goto skip;

	if (PCIE_IS_HOTPLUG_CAPABLE(dip) &&
	    strcmp(name, "pci-occupant") == 0) {
		int	pci_dev = PCI_MINOR_NUM_TO_PCI_DEVNUM(getminor(dev));

		pcie_hp_create_occupant_props(dip, dev, pci_dev);
	}

skip:
	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}

int
pcie_init_cfghdl(dev_info_t *cdip)
{
	pcie_bus_t		*bus_p;
	ddi_acc_handle_t	eh = NULL;

	bus_p = PCIE_DIP2BUS(cdip);
	if (bus_p == NULL)
		return (DDI_FAILURE);

	/* Create an config access special to error handling */
	if (pci_config_setup(cdip, &eh) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Cannot setup config access"
		    " for BDF 0x%x\n", bus_p->bus_bdf);
		return (DDI_FAILURE);
	}

	bus_p->bus_cfg_hdl = eh;
	return (DDI_SUCCESS);
}

void
pcie_fini_cfghdl(dev_info_t *cdip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(cdip);

	pci_config_teardown(&bus_p->bus_cfg_hdl);
}

void
pcie_determine_serial(dev_info_t *dip)
{
	pcie_bus_t		*bus_p = PCIE_DIP2BUS(dip);
	ddi_acc_handle_t	h;
	uint16_t		cap;
	uchar_t			serial[8];
	uint32_t		low, high;

	if (!PCIE_IS_PCIE(bus_p))
		return;

	h = bus_p->bus_cfg_hdl;

	if ((PCI_CAP_LOCATE(h, PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_SER), &cap)) ==
	    DDI_FAILURE)
		return;

	high = PCI_XCAP_GET32(h, 0, cap, PCIE_SER_SID_UPPER_DW);
	low = PCI_XCAP_GET32(h, 0, cap, PCIE_SER_SID_LOWER_DW);

	/*
	 * Here, we're trying to figure out if we had an invalid PCIe read. From
	 * looking at the contents of the value, it can be hard to tell the
	 * difference between a value that has all 1s correctly versus if we had
	 * an error. In this case, we only assume it's invalid if both register
	 * reads are invalid. We also only use 32-bit reads as we're not sure if
	 * all devices will support these as 64-bit reads, while we know that
	 * they'll support these as 32-bit reads.
	 */
	if (high == PCI_EINVAL32 && low == PCI_EINVAL32)
		return;

	serial[0] = low & 0xff;
	serial[1] = (low >> 8) & 0xff;
	serial[2] = (low >> 16) & 0xff;
	serial[3] = (low >> 24) & 0xff;
	serial[4] = high & 0xff;
	serial[5] = (high >> 8) & 0xff;
	serial[6] = (high >> 16) & 0xff;
	serial[7] = (high >> 24) & 0xff;

	(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip, "pcie-serial",
	    serial, sizeof (serial));
}

/*
 * PCI-Express child device initialization.
 * This function enables generic pci-express interrupts and error
 * handling.
 *
 * @param pdip		root dip (root nexus's dip)
 * @param cdip		child's dip (device's dip)
 * @return		DDI_SUCCESS or DDI_FAILURE
 */
/* ARGSUSED */
int
pcie_initchild(dev_info_t *cdip)
{
	uint16_t		tmp16, reg16;
	pcie_bus_t		*bus_p;
	uint32_t		devid, venid;

	bus_p = PCIE_DIP2BUS(cdip);
	if (bus_p == NULL) {
		PCIE_DBG("%s: BUS not found.\n",
		    ddi_driver_name(cdip));

		return (DDI_FAILURE);
	}

	if (pcie_init_cfghdl(cdip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Update pcie_bus_t with real Vendor Id Device Id.
	 *
	 * For assigned devices in IOV environment, the OBP will return
	 * faked device id/vendor id on configration read and for both
	 * properties in root domain. translate_devid() function will
	 * update the properties with real device-id/vendor-id on such
	 * platforms, so that we can utilize the properties here to get
	 * real device-id/vendor-id and overwrite the faked ids.
	 *
	 * For unassigned devices or devices in non-IOV environment, the
	 * operation below won't make a difference.
	 *
	 * The IOV implementation only supports assignment of PCIE
	 * endpoint devices. Devices under pci-pci bridges don't need
	 * operation like this.
	 */
	devid = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "device-id", -1);
	venid = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "vendor-id", -1);
	bus_p->bus_dev_ven_id = (devid << 16) | (venid & 0xffff);

	/* Clear the device's status register */
	reg16 = PCIE_GET(16, bus_p, PCI_CONF_STAT);
	PCIE_PUT(16, bus_p, PCI_CONF_STAT, reg16);

	/* Setup the device's command register */
	reg16 = PCIE_GET(16, bus_p, PCI_CONF_COMM);
	tmp16 = (reg16 & pcie_command_default_fw) | pcie_command_default;

#if defined(__i386) || defined(__amd64)
	boolean_t empty_io_range = B_FALSE;
	boolean_t empty_mem_range = B_FALSE;
	/*
	 * Check for empty IO and Mem ranges on bridges. If so disable IO/Mem
	 * access as it can cause a hang if enabled.
	 */
	pcie_check_io_mem_range(bus_p->bus_cfg_hdl, &empty_io_range,
	    &empty_mem_range);
	if ((empty_io_range == B_TRUE) &&
	    (pcie_command_default & PCI_COMM_IO)) {
		tmp16 &= ~PCI_COMM_IO;
		PCIE_DBG("No I/O range found for %s, bdf 0x%x\n",
		    ddi_driver_name(cdip), bus_p->bus_bdf);
	}
	if ((empty_mem_range == B_TRUE) &&
	    (pcie_command_default & PCI_COMM_MAE)) {
		tmp16 &= ~PCI_COMM_MAE;
		PCIE_DBG("No Mem range found for %s, bdf 0x%x\n",
		    ddi_driver_name(cdip), bus_p->bus_bdf);
	}
#endif /* defined(__i386) || defined(__amd64) */

	if (pcie_serr_disable_flag && PCIE_IS_PCIE(bus_p))
		tmp16 &= ~PCI_COMM_SERR_ENABLE;

	PCIE_PUT(16, bus_p, PCI_CONF_COMM, tmp16);
	PCIE_DBG_CFG(cdip, bus_p, "COMMAND", 16, PCI_CONF_COMM, reg16);

	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if (PCIE_IS_BDG(bus_p)) {
		/* Clear the device's secondary status register */
		reg16 = PCIE_GET(16, bus_p, PCI_BCNF_SEC_STATUS);
		PCIE_PUT(16, bus_p, PCI_BCNF_SEC_STATUS, reg16);

		/* Setup the device's secondary command register */
		reg16 = PCIE_GET(16, bus_p, PCI_BCNF_BCNTRL);
		tmp16 = (reg16 & pcie_bdg_command_default_fw);

		tmp16 |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		/*
		 * Workaround for this Nvidia bridge. Don't enable the SERR
		 * enable bit in the bridge control register as it could lead to
		 * bogus NMIs.
		 */
		if (bus_p->bus_dev_ven_id == 0x037010DE)
			tmp16 &= ~PCI_BCNF_BCNTRL_SERR_ENABLE;

		if (pcie_command_default & PCI_COMM_PARITY_DETECT)
			tmp16 |= PCI_BCNF_BCNTRL_PARITY_ENABLE;

		/*
		 * Enable Master Abort Mode only if URs have not been masked.
		 * For PCI and PCIe-PCI bridges, enabling this bit causes a
		 * Master Aborts/UR to be forwarded as a UR/TA or SERR.  If this
		 * bit is masked, posted requests are dropped and non-posted
		 * requests are returned with -1.
		 */
		if (pcie_aer_uce_mask & PCIE_AER_UCE_UR)
			tmp16 &= ~PCI_BCNF_BCNTRL_MAST_AB_MODE;
		else
			tmp16 |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		PCIE_PUT(16, bus_p, PCI_BCNF_BCNTRL, tmp16);
		PCIE_DBG_CFG(cdip, bus_p, "SEC CMD", 16, PCI_BCNF_BCNTRL,
		    reg16);
	}

	if (PCIE_IS_PCIE(bus_p)) {
		/* Setup PCIe device control register */
		reg16 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
		/* note: MPS/MRRS are initialized in pcie_initchild_mps() */
		tmp16 = (reg16 & (PCIE_DEVCTL_MAX_READ_REQ_MASK |
		    PCIE_DEVCTL_MAX_PAYLOAD_MASK)) |
		    (pcie_devctl_default & ~(PCIE_DEVCTL_MAX_READ_REQ_MASK |
		    PCIE_DEVCTL_MAX_PAYLOAD_MASK));
		PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, tmp16);
		PCIE_DBG_CAP(cdip, bus_p, "DEVCTL", 16, PCIE_DEVCTL, reg16);

		/* Enable PCIe errors */
		pcie_enable_errors(cdip);

		pcie_determine_serial(cdip);
	}

	bus_p->bus_ari = B_FALSE;
	if ((pcie_ari_is_enabled(ddi_get_parent(cdip))
	    == PCIE_ARI_FORW_ENABLED) && (pcie_ari_device(cdip)
	    == PCIE_ARI_DEVICE)) {
		bus_p->bus_ari = B_TRUE;
	}

	if (pcie_initchild_mps(cdip) == DDI_FAILURE) {
		pcie_fini_cfghdl(cdip);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
pcie_init_pfd(dev_info_t *dip)
{
	pf_data_t	*pfd_p = PCIE_ZALLOC(pf_data_t);
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	PCIE_DIP2PFD(dip) = pfd_p;

	pfd_p->pe_bus_p = bus_p;
	pfd_p->pe_severity_flags = 0;
	pfd_p->pe_orig_severity_flags = 0;
	pfd_p->pe_lock = B_FALSE;
	pfd_p->pe_valid = B_FALSE;

	/* Allocate the root fault struct for both RC and RP */
	if (PCIE_IS_ROOT(bus_p)) {
		PCIE_ROOT_FAULT(pfd_p) = PCIE_ZALLOC(pf_root_fault_t);
		PCIE_ROOT_FAULT(pfd_p)->scan_bdf = PCIE_INVALID_BDF;
		PCIE_ROOT_EH_SRC(pfd_p) = PCIE_ZALLOC(pf_root_eh_src_t);
	}

	PCI_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_err_regs_t);
	PFD_AFFECTED_DEV(pfd_p) = PCIE_ZALLOC(pf_affected_dev_t);
	PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf = PCIE_INVALID_BDF;

	if (PCIE_IS_BDG(bus_p))
		PCI_BDG_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_bdg_err_regs_t);

	if (PCIE_IS_PCIE(bus_p)) {
		PCIE_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_err_regs_t);

		if (PCIE_IS_RP(bus_p))
			PCIE_RP_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcie_rp_err_regs_t);

		PCIE_ADV_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_adv_err_regs_t);
		PCIE_ADV_REG(pfd_p)->pcie_ue_tgt_bdf = PCIE_INVALID_BDF;

		if (PCIE_IS_RP(bus_p)) {
			PCIE_ADV_RP_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcie_adv_rp_err_regs_t);
			PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ce_src_id =
			    PCIE_INVALID_BDF;
			PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ue_src_id =
			    PCIE_INVALID_BDF;
		} else if (PCIE_IS_PCIE_BDG(bus_p)) {
			PCIE_ADV_BDG_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcie_adv_bdg_err_regs_t);
			PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_tgt_bdf =
			    PCIE_INVALID_BDF;
		}

		if (PCIE_IS_PCIE_BDG(bus_p) && PCIE_IS_PCIX(bus_p)) {
			PCIX_BDG_ERR_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcix_bdg_err_regs_t);

			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				PCIX_BDG_ECC_REG(pfd_p, 0) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
				PCIX_BDG_ECC_REG(pfd_p, 1) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
			}
		}
	} else if (PCIE_IS_PCIX(bus_p)) {
		if (PCIE_IS_BDG(bus_p)) {
			PCIX_BDG_ERR_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcix_bdg_err_regs_t);

			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				PCIX_BDG_ECC_REG(pfd_p, 0) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
				PCIX_BDG_ECC_REG(pfd_p, 1) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
			}
		} else {
			PCIX_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pcix_err_regs_t);

			if (PCIX_ECC_VERSION_CHECK(bus_p))
				PCIX_ECC_REG(pfd_p) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
		}
	}
}

static void
pcie_fini_pfd(dev_info_t *dip)
{
	pf_data_t	*pfd_p = PCIE_DIP2PFD(dip);
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_PCIE(bus_p)) {
		if (PCIE_IS_PCIE_BDG(bus_p) && PCIE_IS_PCIX(bus_p)) {
			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 0),
				    sizeof (pf_pcix_ecc_regs_t));
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 1),
				    sizeof (pf_pcix_ecc_regs_t));
			}

			kmem_free(PCIX_BDG_ERR_REG(pfd_p),
			    sizeof (pf_pcix_bdg_err_regs_t));
		}

		if (PCIE_IS_RP(bus_p))
			kmem_free(PCIE_ADV_RP_REG(pfd_p),
			    sizeof (pf_pcie_adv_rp_err_regs_t));
		else if (PCIE_IS_PCIE_BDG(bus_p))
			kmem_free(PCIE_ADV_BDG_REG(pfd_p),
			    sizeof (pf_pcie_adv_bdg_err_regs_t));

		kmem_free(PCIE_ADV_REG(pfd_p),
		    sizeof (pf_pcie_adv_err_regs_t));

		if (PCIE_IS_RP(bus_p))
			kmem_free(PCIE_RP_REG(pfd_p),
			    sizeof (pf_pcie_rp_err_regs_t));

		kmem_free(PCIE_ERR_REG(pfd_p), sizeof (pf_pcie_err_regs_t));
	} else if (PCIE_IS_PCIX(bus_p)) {
		if (PCIE_IS_BDG(bus_p)) {
			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 0),
				    sizeof (pf_pcix_ecc_regs_t));
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 1),
				    sizeof (pf_pcix_ecc_regs_t));
			}

			kmem_free(PCIX_BDG_ERR_REG(pfd_p),
			    sizeof (pf_pcix_bdg_err_regs_t));
		} else {
			if (PCIX_ECC_VERSION_CHECK(bus_p))
				kmem_free(PCIX_ECC_REG(pfd_p),
				    sizeof (pf_pcix_ecc_regs_t));

			kmem_free(PCIX_ERR_REG(pfd_p),
			    sizeof (pf_pcix_err_regs_t));
		}
	}

	if (PCIE_IS_BDG(bus_p))
		kmem_free(PCI_BDG_ERR_REG(pfd_p),
		    sizeof (pf_pci_bdg_err_regs_t));

	kmem_free(PFD_AFFECTED_DEV(pfd_p), sizeof (pf_affected_dev_t));
	kmem_free(PCI_ERR_REG(pfd_p), sizeof (pf_pci_err_regs_t));

	if (PCIE_IS_ROOT(bus_p)) {
		kmem_free(PCIE_ROOT_FAULT(pfd_p), sizeof (pf_root_fault_t));
		kmem_free(PCIE_ROOT_EH_SRC(pfd_p), sizeof (pf_root_eh_src_t));
	}

	kmem_free(PCIE_DIP2PFD(dip), sizeof (pf_data_t));

	PCIE_DIP2PFD(dip) = NULL;
}


/*
 * Special functions to allocate pf_data_t's for PCIe root complexes.
 * Note: Root Complex not Root Port
 */
void
pcie_rc_init_pfd(dev_info_t *dip, pf_data_t *pfd_p)
{
	pfd_p->pe_bus_p = PCIE_DIP2DOWNBUS(dip);
	pfd_p->pe_severity_flags = 0;
	pfd_p->pe_orig_severity_flags = 0;
	pfd_p->pe_lock = B_FALSE;
	pfd_p->pe_valid = B_FALSE;

	PCIE_ROOT_FAULT(pfd_p) = PCIE_ZALLOC(pf_root_fault_t);
	PCIE_ROOT_FAULT(pfd_p)->scan_bdf = PCIE_INVALID_BDF;
	PCIE_ROOT_EH_SRC(pfd_p) = PCIE_ZALLOC(pf_root_eh_src_t);
	PCI_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_err_regs_t);
	PFD_AFFECTED_DEV(pfd_p) = PCIE_ZALLOC(pf_affected_dev_t);
	PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf = PCIE_INVALID_BDF;
	PCI_BDG_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_bdg_err_regs_t);
	PCIE_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_err_regs_t);
	PCIE_RP_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_rp_err_regs_t);
	PCIE_ADV_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_adv_err_regs_t);
	PCIE_ADV_RP_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_adv_rp_err_regs_t);
	PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ce_src_id = PCIE_INVALID_BDF;
	PCIE_ADV_RP_REG(pfd_p)->pcie_rp_ue_src_id = PCIE_INVALID_BDF;

	PCIE_ADV_REG(pfd_p)->pcie_ue_sev = pcie_aer_uce_severity;
}

void
pcie_rc_fini_pfd(pf_data_t *pfd_p)
{
	kmem_free(PCIE_ADV_RP_REG(pfd_p), sizeof (pf_pcie_adv_rp_err_regs_t));
	kmem_free(PCIE_ADV_REG(pfd_p), sizeof (pf_pcie_adv_err_regs_t));
	kmem_free(PCIE_RP_REG(pfd_p), sizeof (pf_pcie_rp_err_regs_t));
	kmem_free(PCIE_ERR_REG(pfd_p), sizeof (pf_pcie_err_regs_t));
	kmem_free(PCI_BDG_ERR_REG(pfd_p), sizeof (pf_pci_bdg_err_regs_t));
	kmem_free(PFD_AFFECTED_DEV(pfd_p), sizeof (pf_affected_dev_t));
	kmem_free(PCI_ERR_REG(pfd_p), sizeof (pf_pci_err_regs_t));
	kmem_free(PCIE_ROOT_FAULT(pfd_p), sizeof (pf_root_fault_t));
	kmem_free(PCIE_ROOT_EH_SRC(pfd_p), sizeof (pf_root_eh_src_t));
}

/*
 * init pcie_bus_t for root complex
 *
 * Only a few of the fields in bus_t is valid for root complex.
 * The fields that are bracketed are initialized in this routine:
 *
 * dev_info_t *		<bus_dip>
 * dev_info_t *		bus_rp_dip
 * ddi_acc_handle_t	bus_cfg_hdl
 * uint_t		<bus_fm_flags>
 * pcie_req_id_t	bus_bdf
 * pcie_req_id_t	bus_rp_bdf
 * uint32_t		bus_dev_ven_id
 * uint8_t		bus_rev_id
 * uint8_t		<bus_hdr_type>
 * uint16_t		<bus_dev_type>
 * uint8_t		bus_bdg_secbus
 * uint16_t		bus_pcie_off
 * uint16_t		<bus_aer_off>
 * uint16_t		bus_pcix_off
 * uint16_t		bus_ecc_ver
 * pci_bus_range_t	bus_bus_range
 * ppb_ranges_t	*	bus_addr_ranges
 * int			bus_addr_entries
 * pci_regspec_t *	bus_assigned_addr
 * int			bus_assigned_entries
 * pf_data_t *		bus_pfd
 * pcie_domain_t *	<bus_dom>
 * int			bus_mps
 * uint64_t		bus_cfgacc_base
 * void	*		bus_plat_private
 */
void
pcie_rc_init_bus(dev_info_t *dip)
{
	pcie_bus_t *bus_p;

	bus_p = (pcie_bus_t *)kmem_zalloc(sizeof (pcie_bus_t), KM_SLEEP);
	bus_p->bus_dip = dip;
	bus_p->bus_dev_type = PCIE_PCIECAP_DEV_TYPE_RC_PSEUDO;
	bus_p->bus_hdr_type = PCI_HEADER_ONE;

	/* Fake that there are AER logs */
	bus_p->bus_aer_off = (uint16_t)-1;

	/* Needed only for handle lookup */
	bus_p->bus_fm_flags |= PF_FM_READY;

	ndi_set_bus_private(dip, B_FALSE, DEVI_PORT_TYPE_PCI, bus_p);

	PCIE_BUS2DOM(bus_p) = PCIE_ZALLOC(pcie_domain_t);
}

void
pcie_rc_fini_bus(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2DOWNBUS(dip);
	ndi_set_bus_private(dip, B_FALSE, NULL, NULL);
	kmem_free(PCIE_BUS2DOM(bus_p), sizeof (pcie_domain_t));
	kmem_free(bus_p, sizeof (pcie_bus_t));
}

/*
 * partially init pcie_bus_t for device (dip,bdf) for accessing pci
 * config space
 *
 * This routine is invoked during boot, either after creating a devinfo node
 * (x86 case) or during px driver attach (sparc case); it is also invoked
 * in hotplug context after a devinfo node is created.
 *
 * The fields that are bracketed are initialized if flag PCIE_BUS_INITIAL
 * is set:
 *
 * dev_info_t *		<bus_dip>
 * dev_info_t *		<bus_rp_dip>
 * ddi_acc_handle_t	bus_cfg_hdl
 * uint_t		bus_fm_flags
 * pcie_req_id_t	<bus_bdf>
 * pcie_req_id_t	<bus_rp_bdf>
 * uint32_t		<bus_dev_ven_id>
 * uint8_t		<bus_rev_id>
 * uint8_t		<bus_hdr_type>
 * uint16_t		<bus_dev_type>
 * uint8_t		<bus_bdg_secbus
 * uint16_t		<bus_pcie_off>
 * uint16_t		<bus_aer_off>
 * uint16_t		<bus_pcix_off>
 * uint16_t		<bus_ecc_ver>
 * pci_bus_range_t	bus_bus_range
 * ppb_ranges_t	*	bus_addr_ranges
 * int			bus_addr_entries
 * pci_regspec_t *	bus_assigned_addr
 * int			bus_assigned_entries
 * pf_data_t *		bus_pfd
 * pcie_domain_t *	bus_dom
 * int			bus_mps
 * uint64_t		bus_cfgacc_base
 * void	*		bus_plat_private
 *
 * The fields that are bracketed are initialized if flag PCIE_BUS_FINAL
 * is set:
 *
 * dev_info_t *		bus_dip
 * dev_info_t *		bus_rp_dip
 * ddi_acc_handle_t	bus_cfg_hdl
 * uint_t		bus_fm_flags
 * pcie_req_id_t	bus_bdf
 * pcie_req_id_t	bus_rp_bdf
 * uint32_t		bus_dev_ven_id
 * uint8_t		bus_rev_id
 * uint8_t		bus_hdr_type
 * uint16_t		bus_dev_type
 * uint8_t		<bus_bdg_secbus>
 * uint16_t		bus_pcie_off
 * uint16_t		bus_aer_off
 * uint16_t		bus_pcix_off
 * uint16_t		bus_ecc_ver
 * pci_bus_range_t	<bus_bus_range>
 * ppb_ranges_t	*	<bus_addr_ranges>
 * int			<bus_addr_entries>
 * pci_regspec_t *	<bus_assigned_addr>
 * int			<bus_assigned_entries>
 * pf_data_t *		<bus_pfd>
 * pcie_domain_t *	bus_dom
 * int			bus_mps
 * uint64_t		bus_cfgacc_base
 * void	*		<bus_plat_private>
 */

pcie_bus_t *
pcie_init_bus(dev_info_t *dip, pcie_req_id_t bdf, uint8_t flags)
{
	uint16_t	status, base, baseptr, num_cap;
	uint32_t	capid;
	int		range_size;
	pcie_bus_t	*bus_p;
	dev_info_t	*rcdip;
	dev_info_t	*pdip;
	const char	*errstr = NULL;

	if (!(flags & PCIE_BUS_INITIAL))
		goto initial_done;

	bus_p = kmem_zalloc(sizeof (pcie_bus_t), KM_SLEEP);

	bus_p->bus_dip = dip;
	bus_p->bus_bdf = bdf;

	rcdip = pcie_get_rc_dip(dip);
	ASSERT(rcdip != NULL);

	/* Save the Vendor ID, Device ID and revision ID */
	bus_p->bus_dev_ven_id = pci_cfgacc_get32(rcdip, bdf, PCI_CONF_VENID);
	bus_p->bus_rev_id = pci_cfgacc_get8(rcdip, bdf, PCI_CONF_REVID);
	/* Save the Header Type */
	bus_p->bus_hdr_type = pci_cfgacc_get8(rcdip, bdf, PCI_CONF_HEADER);
	bus_p->bus_hdr_type &= PCI_HEADER_TYPE_M;

	/*
	 * Figure out the device type and all the relavant capability offsets
	 */
	/* set default value */
	bus_p->bus_dev_type = PCIE_PCIECAP_DEV_TYPE_PCI_PSEUDO;

	status = pci_cfgacc_get16(rcdip, bdf, PCI_CONF_STAT);
	if (status == PCI_CAP_EINVAL16 || !(status & PCI_STAT_CAP))
		goto caps_done; /* capability not supported */

	/* Relevant conventional capabilities first */

	/* Conventional caps: PCI_CAP_ID_PCI_E, PCI_CAP_ID_PCIX */
	num_cap = 2;

	switch (bus_p->bus_hdr_type) {
	case PCI_HEADER_ZERO:
		baseptr = PCI_CONF_CAP_PTR;
		break;
	case PCI_HEADER_PPB:
		baseptr = PCI_BCNF_CAP_PTR;
		break;
	case PCI_HEADER_CARDBUS:
		baseptr = PCI_CBUS_CAP_PTR;
		break;
	default:
		cmn_err(CE_WARN, "%s: unexpected pci header type:%x",
		    __func__, bus_p->bus_hdr_type);
		goto caps_done;
	}

	base = baseptr;
	for (base = pci_cfgacc_get8(rcdip, bdf, base); base && num_cap;
	    base = pci_cfgacc_get8(rcdip, bdf, base + PCI_CAP_NEXT_PTR)) {
		capid = pci_cfgacc_get8(rcdip, bdf, base);
		switch (capid) {
		case PCI_CAP_ID_PCI_E:
			bus_p->bus_pcie_off = base;
			bus_p->bus_dev_type = pci_cfgacc_get16(rcdip, bdf,
			    base + PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;

			/* Check and save PCIe hotplug capability information */
			if ((PCIE_IS_RP(bus_p) || PCIE_IS_SWD(bus_p)) &&
			    (pci_cfgacc_get16(rcdip, bdf, base + PCIE_PCIECAP)
			    & PCIE_PCIECAP_SLOT_IMPL) &&
			    (pci_cfgacc_get32(rcdip, bdf, base + PCIE_SLOTCAP)
			    & PCIE_SLOTCAP_HP_CAPABLE))
				bus_p->bus_hp_sup_modes |= PCIE_NATIVE_HP_MODE;

			num_cap--;
			break;
		case PCI_CAP_ID_PCIX:
			bus_p->bus_pcix_off = base;
			if (PCIE_IS_BDG(bus_p))
				bus_p->bus_ecc_ver =
				    pci_cfgacc_get16(rcdip, bdf, base +
				    PCI_PCIX_SEC_STATUS) & PCI_PCIX_VER_MASK;
			else
				bus_p->bus_ecc_ver =
				    pci_cfgacc_get16(rcdip, bdf, base +
				    PCI_PCIX_COMMAND) & PCI_PCIX_VER_MASK;
			num_cap--;
			break;
		default:
			break;
		}
	}

	/* Check and save PCI hotplug (SHPC) capability information */
	if (PCIE_IS_BDG(bus_p)) {
		base = baseptr;
		for (base = pci_cfgacc_get8(rcdip, bdf, base);
		    base; base = pci_cfgacc_get8(rcdip, bdf,
		    base + PCI_CAP_NEXT_PTR)) {
			capid = pci_cfgacc_get8(rcdip, bdf, base);
			if (capid == PCI_CAP_ID_PCI_HOTPLUG) {
				bus_p->bus_pci_hp_off = base;
				bus_p->bus_hp_sup_modes |= PCIE_PCI_HP_MODE;
				break;
			}
		}
	}

	/* Then, relevant extended capabilities */

	if (!PCIE_IS_PCIE(bus_p))
		goto caps_done;

	/* Extended caps: PCIE_EXT_CAP_ID_AER */
	for (base = PCIE_EXT_CAP; base; base = (capid >>
	    PCIE_EXT_CAP_NEXT_PTR_SHIFT) & PCIE_EXT_CAP_NEXT_PTR_MASK) {
		capid = pci_cfgacc_get32(rcdip, bdf, base);
		if (capid == PCI_CAP_EINVAL32)
			break;
		if (((capid >> PCIE_EXT_CAP_ID_SHIFT) & PCIE_EXT_CAP_ID_MASK)
		    == PCIE_EXT_CAP_ID_AER) {
			bus_p->bus_aer_off = base;
			break;
		}
	}

caps_done:
	/* save RP dip and RP bdf */
	if (PCIE_IS_RP(bus_p)) {
		bus_p->bus_rp_dip = dip;
		bus_p->bus_rp_bdf = bus_p->bus_bdf;
	} else {
		for (pdip = ddi_get_parent(dip); pdip;
		    pdip = ddi_get_parent(pdip)) {
			pcie_bus_t *parent_bus_p = PCIE_DIP2BUS(pdip);

			/*
			 * If RP dip and RP bdf in parent's bus_t have
			 * been initialized, simply use these instead of
			 * continuing up to the RC.
			 */
			if (parent_bus_p->bus_rp_dip != NULL) {
				bus_p->bus_rp_dip = parent_bus_p->bus_rp_dip;
				bus_p->bus_rp_bdf = parent_bus_p->bus_rp_bdf;
				break;
			}

			/*
			 * When debugging be aware that some NVIDIA x86
			 * architectures have 2 nodes for each RP, One at Bus
			 * 0x0 and one at Bus 0x80.  The requester is from Bus
			 * 0x80
			 */
			if (PCIE_IS_ROOT(parent_bus_p)) {
				bus_p->bus_rp_dip = pdip;
				bus_p->bus_rp_bdf = parent_bus_p->bus_bdf;
				break;
			}
		}
	}

	bus_p->bus_soft_state = PCI_SOFT_STATE_CLOSED;
	bus_p->bus_fm_flags = 0;
	bus_p->bus_mps = 0;

	ndi_set_bus_private(dip, B_TRUE, DEVI_PORT_TYPE_PCI, (void *)bus_p);

	if (PCIE_IS_HOTPLUG_CAPABLE(dip))
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "hotplug-capable");

initial_done:
	if (!(flags & PCIE_BUS_FINAL))
		goto final_done;

	/* already initialized? */
	bus_p = PCIE_DIP2BUS(dip);

	/* Save the Range information if device is a switch/bridge */
	if (PCIE_IS_BDG(bus_p)) {
		/* get "bus_range" property */
		range_size = sizeof (pci_bus_range_t);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "bus-range", (caddr_t)&bus_p->bus_bus_range, &range_size)
		    != DDI_PROP_SUCCESS) {
			errstr = "Cannot find \"bus-range\" property";
			cmn_err(CE_WARN,
			    "PCIE init err info failed BDF 0x%x:%s\n",
			    bus_p->bus_bdf, errstr);
		}

		/* get secondary bus number */
		rcdip = pcie_get_rc_dip(dip);
		ASSERT(rcdip != NULL);

		bus_p->bus_bdg_secbus = pci_cfgacc_get8(rcdip,
		    bus_p->bus_bdf, PCI_BCNF_SECBUS);

		/* Get "ranges" property */
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "ranges", (caddr_t)&bus_p->bus_addr_ranges,
		    &bus_p->bus_addr_entries) != DDI_PROP_SUCCESS)
			bus_p->bus_addr_entries = 0;
		bus_p->bus_addr_entries /= sizeof (ppb_ranges_t);
	}

	/* save "assigned-addresses" property array, ignore failues */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&bus_p->bus_assigned_addr,
	    &bus_p->bus_assigned_entries) == DDI_PROP_SUCCESS)
		bus_p->bus_assigned_entries /= sizeof (pci_regspec_t);
	else
		bus_p->bus_assigned_entries = 0;

	pcie_init_pfd(dip);

	pcie_init_plat(dip);

final_done:

	PCIE_DBG("Add %s(dip 0x%p, bdf 0x%x, secbus 0x%x)\n",
	    ddi_driver_name(dip), (void *)dip, bus_p->bus_bdf,
	    bus_p->bus_bdg_secbus);
#ifdef DEBUG
	pcie_print_bus(bus_p);
#endif

	return (bus_p);
}

/*
 * Invoked before destroying devinfo node, mostly during hotplug
 * operation to free pcie_bus_t data structure
 */
/* ARGSUSED */
void
pcie_fini_bus(dev_info_t *dip, uint8_t flags)
{
	pcie_bus_t *bus_p = PCIE_DIP2UPBUS(dip);
	ASSERT(bus_p);

	if (flags & PCIE_BUS_INITIAL) {
		pcie_fini_plat(dip);
		pcie_fini_pfd(dip);

		kmem_free(bus_p->bus_assigned_addr,
		    (sizeof (pci_regspec_t) * bus_p->bus_assigned_entries));
		kmem_free(bus_p->bus_addr_ranges,
		    (sizeof (ppb_ranges_t) * bus_p->bus_addr_entries));
		/* zero out the fields that have been destroyed */
		bus_p->bus_assigned_addr = NULL;
		bus_p->bus_addr_ranges = NULL;
		bus_p->bus_assigned_entries = 0;
		bus_p->bus_addr_entries = 0;
	}

	if (flags & PCIE_BUS_FINAL) {
		if (PCIE_IS_HOTPLUG_CAPABLE(dip)) {
			(void) ndi_prop_remove(DDI_DEV_T_NONE, dip,
			    "hotplug-capable");
		}

		ndi_set_bus_private(dip, B_TRUE, NULL, NULL);
		kmem_free(bus_p, sizeof (pcie_bus_t));
	}
}

int
pcie_postattach_child(dev_info_t *cdip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(cdip);

	if (!bus_p)
		return (DDI_FAILURE);

	return (pcie_enable_ce(cdip));
}

/*
 * PCI-Express child device de-initialization.
 * This function disables generic pci-express interrupts and error
 * handling.
 */
void
pcie_uninitchild(dev_info_t *cdip)
{
	pcie_disable_errors(cdip);
	pcie_fini_cfghdl(cdip);
	pcie_fini_dom(cdip);
}

/*
 * find the root complex dip
 */
dev_info_t *
pcie_get_rc_dip(dev_info_t *dip)
{
	dev_info_t *rcdip;
	pcie_bus_t *rc_bus_p;

	for (rcdip = ddi_get_parent(dip); rcdip;
	    rcdip = ddi_get_parent(rcdip)) {
		rc_bus_p = PCIE_DIP2BUS(rcdip);
		if (rc_bus_p && PCIE_IS_RC(rc_bus_p))
			break;
	}

	return (rcdip);
}

static boolean_t
pcie_is_pci_device(dev_info_t *dip)
{
	dev_info_t	*pdip;
	char		*device_type;

	pdip = ddi_get_parent(dip);
	ASSERT(pdip);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS,
	    "device_type", &device_type) != DDI_PROP_SUCCESS)
		return (B_FALSE);

	if (strcmp(device_type, "pciex") != 0 &&
	    strcmp(device_type, "pci") != 0) {
		ddi_prop_free(device_type);
		return (B_FALSE);
	}

	ddi_prop_free(device_type);
	return (B_TRUE);
}

typedef struct {
	boolean_t	init;
	uint8_t		flags;
} pcie_bus_arg_t;

/*ARGSUSED*/
static int
pcie_fab_do_init_fini(dev_info_t *dip, void *arg)
{
	pcie_req_id_t	bdf;
	pcie_bus_arg_t	*bus_arg = (pcie_bus_arg_t *)arg;

	if (!pcie_is_pci_device(dip))
		goto out;

	if (bus_arg->init) {
		if (pcie_get_bdf_from_dip(dip, &bdf) != DDI_SUCCESS)
			goto out;

		(void) pcie_init_bus(dip, bdf, bus_arg->flags);
	} else {
		(void) pcie_fini_bus(dip, bus_arg->flags);
	}

	return (DDI_WALK_CONTINUE);

out:
	return (DDI_WALK_PRUNECHILD);
}

void
pcie_fab_init_bus(dev_info_t *rcdip, uint8_t flags)
{
	int		circular_count;
	dev_info_t	*dip = ddi_get_child(rcdip);
	pcie_bus_arg_t	arg;

	arg.init = B_TRUE;
	arg.flags = flags;

	ndi_devi_enter(rcdip, &circular_count);
	ddi_walk_devs(dip, pcie_fab_do_init_fini, &arg);
	ndi_devi_exit(rcdip, circular_count);
}

void
pcie_fab_fini_bus(dev_info_t *rcdip, uint8_t flags)
{
	int		circular_count;
	dev_info_t	*dip = ddi_get_child(rcdip);
	pcie_bus_arg_t	arg;

	arg.init = B_FALSE;
	arg.flags = flags;

	ndi_devi_enter(rcdip, &circular_count);
	ddi_walk_devs(dip, pcie_fab_do_init_fini, &arg);
	ndi_devi_exit(rcdip, circular_count);
}

void
pcie_enable_errors(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	reg16, tmp16;
	uint32_t	reg32, tmp32;

	ASSERT(bus_p);

	/*
	 * Clear any pending errors
	 */
	pcie_clear_errors(dip);

	if (!PCIE_IS_PCIE(bus_p))
		return;

	/*
	 * Enable Baseline Error Handling but leave CE reporting off (poweron
	 * default).
	 */
	if ((reg16 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL)) !=
	    PCI_CAP_EINVAL16) {
		tmp16 = (reg16 & (PCIE_DEVCTL_MAX_READ_REQ_MASK |
		    PCIE_DEVCTL_MAX_PAYLOAD_MASK)) |
		    (pcie_devctl_default & ~(PCIE_DEVCTL_MAX_READ_REQ_MASK |
		    PCIE_DEVCTL_MAX_PAYLOAD_MASK)) |
		    (pcie_base_err_default & (~PCIE_DEVCTL_CE_REPORTING_EN));

		PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, tmp16);
		PCIE_DBG_CAP(dip, bus_p, "DEVCTL", 16, PCIE_DEVCTL, reg16);
	}

	/* Enable Root Port Baseline Error Receiving */
	if (PCIE_IS_ROOT(bus_p) &&
	    (reg16 = PCIE_CAP_GET(16, bus_p, PCIE_ROOTCTL)) !=
	    PCI_CAP_EINVAL16) {

		tmp16 = pcie_serr_disable_flag ?
		    (pcie_root_ctrl_default & ~PCIE_ROOT_SYS_ERR) :
		    pcie_root_ctrl_default;
		PCIE_CAP_PUT(16, bus_p, PCIE_ROOTCTL, tmp16);
		PCIE_DBG_CAP(dip, bus_p, "ROOT DEVCTL", 16, PCIE_ROOTCTL,
		    reg16);
	}

	/*
	 * Enable PCI-Express Advanced Error Handling if Exists
	 */
	if (!PCIE_HAS_AER(bus_p))
		return;

	/* Set Uncorrectable Severity */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_UCE_SERV)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = pcie_aer_uce_severity;

		PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_SERV, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER UCE SEV", 32, PCIE_AER_UCE_SERV,
		    reg32);
	}

	/* Enable Uncorrectable errors */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_UCE_MASK)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = pcie_aer_uce_mask;

		PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_MASK, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER UCE MASK", 32, PCIE_AER_UCE_MASK,
		    reg32);
	}

	/* Enable ECRC generation and checking */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_CTL)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = reg32 | pcie_ecrc_value;
		PCIE_AER_PUT(32, bus_p, PCIE_AER_CTL, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER CTL", 32, PCIE_AER_CTL, reg32);
	}

	/* Enable Secondary Uncorrectable errors if this is a bridge */
	if (!PCIE_IS_PCIE_BDG(bus_p))
		goto root;

	/* Set Uncorrectable Severity */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_SUCE_SERV)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = pcie_aer_suce_severity;

		PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_SERV, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER SUCE SEV", 32, PCIE_AER_SUCE_SERV,
		    reg32);
	}

	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_SUCE_MASK)) !=
	    PCI_CAP_EINVAL32) {
		PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_MASK, pcie_aer_suce_mask);
		PCIE_DBG_AER(dip, bus_p, "AER SUCE MASK", 32,
		    PCIE_AER_SUCE_MASK, reg32);
	}

root:
	/*
	 * Enable Root Control this is a Root device
	 */
	if (!PCIE_IS_ROOT(bus_p))
		return;

	if ((reg16 = PCIE_AER_GET(16, bus_p, PCIE_AER_RE_CMD)) !=
	    PCI_CAP_EINVAL16) {
		PCIE_AER_PUT(16, bus_p, PCIE_AER_RE_CMD,
		    pcie_root_error_cmd_default);
		PCIE_DBG_AER(dip, bus_p, "AER Root Err Cmd", 16,
		    PCIE_AER_RE_CMD, reg16);
	}
}

/*
 * This function is used for enabling CE reporting and setting the AER CE mask.
 * When called from outside the pcie module it should always be preceded by
 * a call to pcie_enable_errors.
 */
int
pcie_enable_ce(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	device_sts, device_ctl;
	uint32_t	tmp_pcie_aer_ce_mask;

	if (!PCIE_IS_PCIE(bus_p))
		return (DDI_SUCCESS);

	/*
	 * The "pcie_ce_mask" property is used to control both the CE reporting
	 * enable field in the device control register and the AER CE mask. We
	 * leave CE reporting disabled if pcie_ce_mask is set to -1.
	 */

	tmp_pcie_aer_ce_mask = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie_ce_mask", pcie_aer_ce_mask);

	if (tmp_pcie_aer_ce_mask == (uint32_t)-1) {
		/*
		 * Nothing to do since CE reporting has already been disabled.
		 */
		return (DDI_SUCCESS);
	}

	if (PCIE_HAS_AER(bus_p)) {
		/* Enable AER CE */
		PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_MASK, tmp_pcie_aer_ce_mask);
		PCIE_DBG_AER(dip, bus_p, "AER CE MASK", 32, PCIE_AER_CE_MASK,
		    0);

		/* Clear any pending AER CE errors */
		PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_STS, -1);
	}

	/* clear any pending CE errors */
	if ((device_sts = PCIE_CAP_GET(16, bus_p, PCIE_DEVSTS)) !=
	    PCI_CAP_EINVAL16)
		PCIE_CAP_PUT(16, bus_p, PCIE_DEVSTS,
		    device_sts & (~PCIE_DEVSTS_CE_DETECTED));

	/* Enable CE reporting */
	device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL,
	    (device_ctl & (~PCIE_DEVCTL_ERR_MASK)) | pcie_base_err_default);
	PCIE_DBG_CAP(dip, bus_p, "DEVCTL", 16, PCIE_DEVCTL, device_ctl);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
void
pcie_disable_errors(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	device_ctl;
	uint32_t	aer_reg;

	if (!PCIE_IS_PCIE(bus_p))
		return;

	/*
	 * Disable PCI-Express Baseline Error Handling
	 */
	device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
	device_ctl &= ~PCIE_DEVCTL_ERR_MASK;
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, device_ctl);

	/*
	 * Disable PCI-Express Advanced Error Handling if Exists
	 */
	if (!PCIE_HAS_AER(bus_p))
		goto root;

	/* Disable Uncorrectable errors */
	PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_MASK, PCIE_AER_UCE_BITS);

	/* Disable Correctable errors */
	PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_MASK, PCIE_AER_CE_BITS);

	/* Disable ECRC generation and checking */
	if ((aer_reg = PCIE_AER_GET(32, bus_p, PCIE_AER_CTL)) !=
	    PCI_CAP_EINVAL32) {
		aer_reg &= ~(PCIE_AER_CTL_ECRC_GEN_ENA |
		    PCIE_AER_CTL_ECRC_CHECK_ENA);

		PCIE_AER_PUT(32, bus_p, PCIE_AER_CTL, aer_reg);
	}
	/*
	 * Disable Secondary Uncorrectable errors if this is a bridge
	 */
	if (!PCIE_IS_PCIE_BDG(bus_p))
		goto root;

	PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_MASK, PCIE_AER_SUCE_BITS);

root:
	/*
	 * disable Root Control this is a Root device
	 */
	if (!PCIE_IS_ROOT(bus_p))
		return;

	if (!pcie_serr_disable_flag) {
		device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_ROOTCTL);
		device_ctl &= ~PCIE_ROOT_SYS_ERR;
		PCIE_CAP_PUT(16, bus_p, PCIE_ROOTCTL, device_ctl);
	}

	if (!PCIE_HAS_AER(bus_p))
		return;

	if ((device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_AER_RE_CMD)) !=
	    PCI_CAP_EINVAL16) {
		device_ctl &= ~pcie_root_error_cmd_default;
		PCIE_CAP_PUT(16, bus_p, PCIE_AER_RE_CMD, device_ctl);
	}
}

/*
 * Extract bdf from "reg" property.
 */
int
pcie_get_bdf_from_dip(dev_info_t *dip, pcie_req_id_t *bdf)
{
	pci_regspec_t	*regspec;
	int		reglen;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&regspec, (uint_t *)&reglen) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (reglen < (sizeof (pci_regspec_t) / sizeof (int))) {
		ddi_prop_free(regspec);
		return (DDI_FAILURE);
	}

	/* Get phys_hi from first element.  All have same bdf. */
	*bdf = (regspec->pci_phys_hi & (PCI_REG_BDFR_M ^ PCI_REG_REG_M)) >> 8;

	ddi_prop_free(regspec);
	return (DDI_SUCCESS);
}

dev_info_t *
pcie_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t *cdip = rdip;

	for (; ddi_get_parent(cdip) != dip; cdip = ddi_get_parent(cdip))
		;

	return (cdip);
}

uint32_t
pcie_get_bdf_for_dma_xfer(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t *cdip;

	/*
	 * As part of the probing, the PCI fcode interpreter may setup a DMA
	 * request if a given card has a fcode on it using dip and rdip of the
	 * hotplug connector i.e, dip and rdip of px/pcieb driver. In this
	 * case, return a invalid value for the bdf since we cannot get to the
	 * bdf value of the actual device which will be initiating this DMA.
	 */
	if (rdip == dip)
		return (PCIE_INVALID_BDF);

	cdip = pcie_get_my_childs_dip(dip, rdip);

	/*
	 * For a given rdip, return the bdf value of dip's (px or pcieb)
	 * immediate child or secondary bus-id if dip is a PCIe2PCI bridge.
	 *
	 * XXX - For now, return a invalid bdf value for all PCI and PCI-X
	 * devices since this needs more work.
	 */
	return (PCI_GET_PCIE2PCI_SECBUS(cdip) ?
	    PCIE_INVALID_BDF : PCI_GET_BDF(cdip));
}

uint32_t
pcie_get_aer_uce_mask()
{
	return (pcie_aer_uce_mask);
}
uint32_t
pcie_get_aer_ce_mask()
{
	return (pcie_aer_ce_mask);
}
uint32_t
pcie_get_aer_suce_mask()
{
	return (pcie_aer_suce_mask);
}
uint32_t
pcie_get_serr_mask()
{
	return (pcie_serr_disable_flag);
}

void
pcie_set_aer_uce_mask(uint32_t mask)
{
	pcie_aer_uce_mask = mask;
	if (mask & PCIE_AER_UCE_UR)
		pcie_base_err_default &= ~PCIE_DEVCTL_UR_REPORTING_EN;
	else
		pcie_base_err_default |= PCIE_DEVCTL_UR_REPORTING_EN;

	if (mask & PCIE_AER_UCE_ECRC)
		pcie_ecrc_value = 0;
}

void
pcie_set_aer_ce_mask(uint32_t mask)
{
	pcie_aer_ce_mask = mask;
}
void
pcie_set_aer_suce_mask(uint32_t mask)
{
	pcie_aer_suce_mask = mask;
}
void
pcie_set_serr_mask(uint32_t mask)
{
	pcie_serr_disable_flag = mask;
}

/*
 * Is the rdip a child of dip.	Used for checking certain CTLOPS from bubbling
 * up erronously.  Ex.	ISA ctlops to a PCI-PCI Bridge.
 */
boolean_t
pcie_is_child(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t	*cdip = ddi_get_child(dip);
	for (; cdip; cdip = ddi_get_next_sibling(cdip))
		if (cdip == rdip)
			break;
	return (cdip != NULL);
}

boolean_t
pcie_is_link_disabled(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_PCIE(bus_p)) {
		if (PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL) &
		    PCIE_LINKCTL_LINK_DISABLE)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Initialize the MPS for a root port.
 *
 * dip - dip of root port device.
 */
void
pcie_init_root_port_mps(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	int rp_cap, max_supported = pcie_max_mps;

	(void) pcie_get_fabric_mps(ddi_get_parent(dip),
	    ddi_get_child(dip), &max_supported);

	rp_cap = PCI_CAP_GET16(bus_p->bus_cfg_hdl, NULL,
	    bus_p->bus_pcie_off, PCIE_DEVCAP) &
	    PCIE_DEVCAP_MAX_PAYLOAD_MASK;

	if (rp_cap < max_supported)
		max_supported = rp_cap;

	bus_p->bus_mps = max_supported;
	(void) pcie_initchild_mps(dip);
}

/*
 * Initialize the Maximum Payload Size of a device.
 *
 * cdip - dip of device.
 *
 * returns - DDI_SUCCESS or DDI_FAILURE
 */
int
pcie_initchild_mps(dev_info_t *cdip)
{
	pcie_bus_t	*bus_p;
	dev_info_t	*pdip = ddi_get_parent(cdip);
	uint8_t		dev_type;

	bus_p = PCIE_DIP2BUS(cdip);
	if (bus_p == NULL) {
		PCIE_DBG("%s: BUS not found.\n",
		    ddi_driver_name(cdip));
		return (DDI_FAILURE);
	}

	dev_type = bus_p->bus_dev_type;

	/*
	 * For ARI Devices, only function zero's MPS needs to be set.
	 */
	if ((dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) &&
	    (pcie_ari_is_enabled(pdip) == PCIE_ARI_FORW_ENABLED)) {
		pcie_req_id_t child_bdf;

		if (pcie_get_bdf_from_dip(cdip, &child_bdf) == DDI_FAILURE)
			return (DDI_FAILURE);
		if ((child_bdf & PCIE_REQ_ID_ARI_FUNC_MASK) != 0)
			return (DDI_SUCCESS);
	}

	if (PCIE_IS_PCIE(bus_p)) {
		int suggested_mrrs, fabric_mps;
		uint16_t device_mps, device_mps_cap, device_mrrs, dev_ctrl;

		dev_ctrl = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
		if ((fabric_mps = (PCIE_IS_RP(bus_p) ? bus_p :
		    PCIE_DIP2BUS(pdip))->bus_mps) < 0) {
			dev_ctrl = (dev_ctrl & ~(PCIE_DEVCTL_MAX_READ_REQ_MASK |
			    PCIE_DEVCTL_MAX_PAYLOAD_MASK)) |
			    (pcie_devctl_default &
			    (PCIE_DEVCTL_MAX_READ_REQ_MASK |
			    PCIE_DEVCTL_MAX_PAYLOAD_MASK));

			PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, dev_ctrl);
			return (DDI_SUCCESS);
		}

		device_mps_cap = PCIE_CAP_GET(16, bus_p, PCIE_DEVCAP) &
		    PCIE_DEVCAP_MAX_PAYLOAD_MASK;

		device_mrrs = (dev_ctrl & PCIE_DEVCTL_MAX_READ_REQ_MASK) >>
		    PCIE_DEVCTL_MAX_READ_REQ_SHIFT;

		if (device_mps_cap < fabric_mps)
			device_mrrs = device_mps = device_mps_cap;
		else
			device_mps = (uint16_t)fabric_mps;

		suggested_mrrs = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY,
		    cdip, DDI_PROP_DONTPASS, "suggested-mrrs", device_mrrs);

		if ((device_mps == fabric_mps) ||
		    (suggested_mrrs < device_mrrs))
			device_mrrs = (uint16_t)suggested_mrrs;

		/*
		 * Replace MPS and MRRS settings.
		 */
		dev_ctrl &= ~(PCIE_DEVCTL_MAX_READ_REQ_MASK |
		    PCIE_DEVCTL_MAX_PAYLOAD_MASK);

		dev_ctrl |= ((device_mrrs << PCIE_DEVCTL_MAX_READ_REQ_SHIFT) |
		    device_mps << PCIE_DEVCTL_MAX_PAYLOAD_SHIFT);

		PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, dev_ctrl);

		bus_p->bus_mps = device_mps;
	}

	return (DDI_SUCCESS);
}

/*
 * Scans a device tree/branch for a maximum payload size capabilities.
 *
 * rc_dip - dip of Root Complex.
 * dip - dip of device where scan will begin.
 * max_supported (IN) - maximum allowable MPS.
 * max_supported (OUT) - maximum payload size capability of fabric.
 */
void
pcie_get_fabric_mps(dev_info_t *rc_dip, dev_info_t *dip, int *max_supported)
{
	if (dip == NULL)
		return;

	/*
	 * Perform a fabric scan to obtain Maximum Payload Capabilities
	 */
	(void) pcie_scan_mps(rc_dip, dip, max_supported);

	PCIE_DBG("MPS: Highest Common MPS= %x\n", max_supported);
}

/*
 * Scans fabric and determines Maximum Payload Size based on
 * highest common denominator alogorithm
 */
static void
pcie_scan_mps(dev_info_t *rc_dip, dev_info_t *dip, int *max_supported)
{
	int circular_count;
	pcie_max_supported_t max_pay_load_supported;

	max_pay_load_supported.dip = rc_dip;
	max_pay_load_supported.highest_common_mps = *max_supported;

	ndi_devi_enter(ddi_get_parent(dip), &circular_count);
	ddi_walk_devs(dip, pcie_get_max_supported,
	    (void *)&max_pay_load_supported);
	ndi_devi_exit(ddi_get_parent(dip), circular_count);

	*max_supported = max_pay_load_supported.highest_common_mps;
}

/*
 * Called as part of the Maximum Payload Size scan.
 */
static int
pcie_get_max_supported(dev_info_t *dip, void *arg)
{
	uint32_t max_supported;
	uint16_t cap_ptr;
	pcie_max_supported_t *current = (pcie_max_supported_t *)arg;
	pci_regspec_t *reg;
	int rlen;
	caddr_t virt;
	ddi_acc_handle_t config_handle;

	if (ddi_get_child(current->dip) == NULL) {
		goto fail1;
	}

	if (pcie_dev(dip) == DDI_FAILURE) {
		PCIE_DBG("MPS: pcie_get_max_supported: %s:  "
		    "Not a PCIe dev\n", ddi_driver_name(dip));
		goto fail1;
	}

	/*
	 * If the suggested-mrrs property exists, then don't include this
	 * device in the MPS capabilities scan.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "suggested-mrrs") != 0)
		goto fail1;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&reg, &rlen) != DDI_PROP_SUCCESS) {
		PCIE_DBG("MPS: pcie_get_max_supported: %s:  "
		    "Can not read reg\n", ddi_driver_name(dip));
		goto fail1;
	}

	if (pcie_map_phys(ddi_get_child(current->dip), reg, &virt,
	    &config_handle) != DDI_SUCCESS) {
		PCIE_DBG("MPS: pcie_get_max_supported: %s:  pcie_map_phys "
		    "failed\n", ddi_driver_name(dip));
		goto fail2;
	}

	if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_E, &cap_ptr)) ==
	    DDI_FAILURE) {
		goto fail3;
	}

	max_supported = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
	    PCIE_DEVCAP) & PCIE_DEVCAP_MAX_PAYLOAD_MASK;

	PCIE_DBG("PCIE MPS: %s: MPS Capabilities %x\n", ddi_driver_name(dip),
	    max_supported);

	if (max_supported < current->highest_common_mps)
		current->highest_common_mps = max_supported;

fail3:
	pcie_unmap_phys(&config_handle, reg);
fail2:
	kmem_free(reg, rlen);
fail1:
	return (DDI_WALK_CONTINUE);
}

/*
 * Determines if there are any root ports attached to a root complex.
 *
 * dip - dip of root complex
 *
 * Returns - DDI_SUCCESS if there is at least one root port otherwise
 *	     DDI_FAILURE.
 */
int
pcie_root_port(dev_info_t *dip)
{
	int port_type;
	uint16_t cap_ptr;
	ddi_acc_handle_t config_handle;
	dev_info_t *cdip = ddi_get_child(dip);

	/*
	 * Determine if any of the children of the passed in dip
	 * are root ports.
	 */
	for (; cdip; cdip = ddi_get_next_sibling(cdip)) {

		if (pci_config_setup(cdip, &config_handle) != DDI_SUCCESS)
			continue;

		if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_E,
		    &cap_ptr)) == DDI_FAILURE) {
			pci_config_teardown(&config_handle);
			continue;
		}

		port_type = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
		    PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;

		pci_config_teardown(&config_handle);

		if (port_type == PCIE_PCIECAP_DEV_TYPE_ROOT)
			return (DDI_SUCCESS);
	}

	/* No root ports were found */

	return (DDI_FAILURE);
}

/*
 * Function that determines if a device a PCIe device.
 *
 * dip - dip of device.
 *
 * returns - DDI_SUCCESS if device is a PCIe device, otherwise DDI_FAILURE.
 */
int
pcie_dev(dev_info_t *dip)
{
	/* get parent device's device_type property */
	char *device_type;
	int rc = DDI_FAILURE;
	dev_info_t *pdip = ddi_get_parent(dip);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip,
	    DDI_PROP_DONTPASS, "device_type", &device_type)
	    != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (strcmp(device_type, "pciex") == 0)
		rc = DDI_SUCCESS;
	else
		rc = DDI_FAILURE;

	ddi_prop_free(device_type);
	return (rc);
}

/*
 * Function to map in a device's memory space.
 */
static int
pcie_map_phys(dev_info_t *dip, pci_regspec_t *phys_spec,
    caddr_t *addrp, ddi_acc_handle_t *handlep)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	int result;
	ddi_device_acc_attr_t attr;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_access = DDI_CAUTIOUS_ACC;

	*handlep = impl_acc_hdl_alloc(KM_SLEEP, NULL);
	hp = impl_acc_hdl_get(*handlep);
	hp->ah_vers = VERS_ACCHDL;
	hp->ah_dip = dip;
	hp->ah_rnumber = 0;
	hp->ah_offset = 0;
	hp->ah_len = 0;
	hp->ah_acc = attr;

	mr.map_op = DDI_MO_MAP_LOCKED;
	mr.map_type = DDI_MT_REGSPEC;
	mr.map_obj.rp = (struct regspec *)phys_spec;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;

	result = ddi_map(dip, &mr, 0, 0, addrp);

	if (result != DDI_SUCCESS) {
		impl_acc_hdl_free(*handlep);
		*handlep = (ddi_acc_handle_t)NULL;
	} else {
		hp->ah_addr = *addrp;
	}

	return (result);
}

/*
 * Map out memory that was mapped in with pcie_map_phys();
 */
static void
pcie_unmap_phys(ddi_acc_handle_t *handlep,  pci_regspec_t *ph)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(*handlep);
	ASSERT(hp);

	mr.map_op = DDI_MO_UNMAP;
	mr.map_type = DDI_MT_REGSPEC;
	mr.map_obj.rp = (struct regspec *)ph;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;

	(void) ddi_map(hp->ah_dip, &mr, hp->ah_offset,
	    hp->ah_len, &hp->ah_addr);

	impl_acc_hdl_free(*handlep);
	*handlep = (ddi_acc_handle_t)NULL;
}

void
pcie_set_rber_fatal(dev_info_t *dip, boolean_t val)
{
	pcie_bus_t *bus_p = PCIE_DIP2UPBUS(dip);
	bus_p->bus_pfd->pe_rber_fatal = val;
}

/*
 * Return parent Root Port's pe_rber_fatal value.
 */
boolean_t
pcie_get_rber_fatal(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2UPBUS(dip);
	pcie_bus_t *rp_bus_p = PCIE_DIP2UPBUS(bus_p->bus_rp_dip);
	return (rp_bus_p->bus_pfd->pe_rber_fatal);
}

int
pcie_ari_supported(dev_info_t *dip)
{
	uint32_t devcap2;
	uint16_t pciecap;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);
	uint8_t dev_type;

	PCIE_DBG("pcie_ari_supported: dip=%p\n", dip);

	if (bus_p == NULL)
		return (PCIE_ARI_FORW_NOT_SUPPORTED);

	dev_type = bus_p->bus_dev_type;

	if ((dev_type != PCIE_PCIECAP_DEV_TYPE_DOWN) &&
	    (dev_type != PCIE_PCIECAP_DEV_TYPE_ROOT))
		return (PCIE_ARI_FORW_NOT_SUPPORTED);

	if (pcie_disable_ari) {
		PCIE_DBG("pcie_ari_supported: dip=%p: ARI Disabled\n", dip);
		return (PCIE_ARI_FORW_NOT_SUPPORTED);
	}

	pciecap = PCIE_CAP_GET(16, bus_p, PCIE_PCIECAP);

	if ((pciecap & PCIE_PCIECAP_VER_MASK) < PCIE_PCIECAP_VER_2_0) {
		PCIE_DBG("pcie_ari_supported: dip=%p: Not 2.0\n", dip);
		return (PCIE_ARI_FORW_NOT_SUPPORTED);
	}

	devcap2 = PCIE_CAP_GET(32, bus_p, PCIE_DEVCAP2);

	PCIE_DBG("pcie_ari_supported: dip=%p: DevCap2=0x%x\n",
	    dip, devcap2);

	if (devcap2 & PCIE_DEVCAP2_ARI_FORWARD) {
		PCIE_DBG("pcie_ari_supported: "
		    "dip=%p: ARI Forwarding is supported\n", dip);
		return (PCIE_ARI_FORW_SUPPORTED);
	}
	return (PCIE_ARI_FORW_NOT_SUPPORTED);
}

int
pcie_ari_enable(dev_info_t *dip)
{
	uint16_t devctl2;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	PCIE_DBG("pcie_ari_enable: dip=%p\n", dip);

	if (pcie_ari_supported(dip) == PCIE_ARI_FORW_NOT_SUPPORTED)
		return (DDI_FAILURE);

	devctl2 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL2);
	devctl2 |= PCIE_DEVCTL2_ARI_FORWARD_EN;
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL2, devctl2);

	PCIE_DBG("pcie_ari_enable: dip=%p: writing 0x%x to DevCtl2\n",
	    dip, devctl2);

	return (DDI_SUCCESS);
}

int
pcie_ari_disable(dev_info_t *dip)
{
	uint16_t devctl2;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	PCIE_DBG("pcie_ari_disable: dip=%p\n", dip);

	if (pcie_ari_supported(dip) == PCIE_ARI_FORW_NOT_SUPPORTED)
		return (DDI_FAILURE);

	devctl2 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL2);
	devctl2 &= ~PCIE_DEVCTL2_ARI_FORWARD_EN;
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL2, devctl2);

	PCIE_DBG("pcie_ari_disable: dip=%p: writing 0x%x to DevCtl2\n",
	    dip, devctl2);

	return (DDI_SUCCESS);
}

int
pcie_ari_is_enabled(dev_info_t *dip)
{
	uint16_t devctl2;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	PCIE_DBG("pcie_ari_is_enabled: dip=%p\n", dip);

	if (pcie_ari_supported(dip) == PCIE_ARI_FORW_NOT_SUPPORTED)
		return (PCIE_ARI_FORW_DISABLED);

	devctl2 = PCIE_CAP_GET(32, bus_p, PCIE_DEVCTL2);

	PCIE_DBG("pcie_ari_is_enabled: dip=%p: DevCtl2=0x%x\n",
	    dip, devctl2);

	if (devctl2 & PCIE_DEVCTL2_ARI_FORWARD_EN) {
		PCIE_DBG("pcie_ari_is_enabled: "
		    "dip=%p: ARI Forwarding is enabled\n", dip);
		return (PCIE_ARI_FORW_ENABLED);
	}

	return (PCIE_ARI_FORW_DISABLED);
}

int
pcie_ari_device(dev_info_t *dip)
{
	ddi_acc_handle_t handle;
	uint16_t cap_ptr;

	PCIE_DBG("pcie_ari_device: dip=%p\n", dip);

	/*
	 * XXX - This function may be called before the bus_p structure
	 * has been populated.  This code can be changed to remove
	 * pci_config_setup()/pci_config_teardown() when the RFE
	 * to populate the bus_p structures early in boot is putback.
	 */

	/* First make sure it is a PCIe device */

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS)
		return (PCIE_NOT_ARI_DEVICE);

	if ((PCI_CAP_LOCATE(handle, PCI_CAP_ID_PCI_E, &cap_ptr))
	    != DDI_SUCCESS) {
		pci_config_teardown(&handle);
		return (PCIE_NOT_ARI_DEVICE);
	}

	/* Locate the ARI Capability */

	if ((PCI_CAP_LOCATE(handle, PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_ARI),
	    &cap_ptr)) == DDI_FAILURE) {
		pci_config_teardown(&handle);
		return (PCIE_NOT_ARI_DEVICE);
	}

	/* ARI Capability was found so it must be a ARI device */
	PCIE_DBG("pcie_ari_device: ARI Device dip=%p\n", dip);

	pci_config_teardown(&handle);
	return (PCIE_ARI_DEVICE);
}

int
pcie_ari_get_next_function(dev_info_t *dip, int *func)
{
	uint32_t val;
	uint16_t cap_ptr, next_function;
	ddi_acc_handle_t handle;

	/*
	 * XXX - This function may be called before the bus_p structure
	 * has been populated.  This code can be changed to remove
	 * pci_config_setup()/pci_config_teardown() when the RFE
	 * to populate the bus_p structures early in boot is putback.
	 */

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((PCI_CAP_LOCATE(handle,
	    PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_ARI), &cap_ptr)) == DDI_FAILURE) {
		pci_config_teardown(&handle);
		return (DDI_FAILURE);
	}

	val = PCI_CAP_GET32(handle, NULL, cap_ptr, PCIE_ARI_CAP);

	next_function = (val >> PCIE_ARI_CAP_NEXT_FUNC_SHIFT) &
	    PCIE_ARI_CAP_NEXT_FUNC_MASK;

	pci_config_teardown(&handle);

	*func = next_function;

	return (DDI_SUCCESS);
}

dev_info_t *
pcie_func_to_dip(dev_info_t *dip, pcie_req_id_t function)
{
	pcie_req_id_t child_bdf;
	dev_info_t *cdip;

	for (cdip = ddi_get_child(dip); cdip;
	    cdip = ddi_get_next_sibling(cdip)) {

		if (pcie_get_bdf_from_dip(cdip, &child_bdf) == DDI_FAILURE)
			return (NULL);

		if ((child_bdf & PCIE_REQ_ID_ARI_FUNC_MASK) == function)
			return (cdip);
	}
	return (NULL);
}

#ifdef	DEBUG

static void
pcie_print_bus(pcie_bus_t *bus_p)
{
	pcie_dbg("\tbus_dip = 0x%p\n", bus_p->bus_dip);
	pcie_dbg("\tbus_fm_flags = 0x%x\n", bus_p->bus_fm_flags);

	pcie_dbg("\tbus_bdf = 0x%x\n", bus_p->bus_bdf);
	pcie_dbg("\tbus_dev_ven_id = 0x%x\n", bus_p->bus_dev_ven_id);
	pcie_dbg("\tbus_rev_id = 0x%x\n", bus_p->bus_rev_id);
	pcie_dbg("\tbus_hdr_type = 0x%x\n", bus_p->bus_hdr_type);
	pcie_dbg("\tbus_dev_type = 0x%x\n", bus_p->bus_dev_type);
	pcie_dbg("\tbus_bdg_secbus = 0x%x\n", bus_p->bus_bdg_secbus);
	pcie_dbg("\tbus_pcie_off = 0x%x\n", bus_p->bus_pcie_off);
	pcie_dbg("\tbus_aer_off = 0x%x\n", bus_p->bus_aer_off);
	pcie_dbg("\tbus_pcix_off = 0x%x\n", bus_p->bus_pcix_off);
	pcie_dbg("\tbus_ecc_ver = 0x%x\n", bus_p->bus_ecc_ver);
}

/*
 * For debugging purposes set pcie_dbg_print != 0 to see printf messages
 * during interrupt.
 *
 * When a proper solution is in place this code will disappear.
 * Potential solutions are:
 * o circular buffers
 * o taskq to print at lower pil
 */
int pcie_dbg_print = 0;
void
pcie_dbg(char *fmt, ...)
{
	va_list ap;

	if (!pcie_debug_flags) {
		return;
	}
	va_start(ap, fmt);
	if (servicing_interrupt()) {
		if (pcie_dbg_print) {
			prom_vprintf(fmt, ap);
		}
	} else {
		prom_vprintf(fmt, ap);
	}
	va_end(ap);
}
#endif	/* DEBUG */

#if defined(__i386) || defined(__amd64)
static void
pcie_check_io_mem_range(ddi_acc_handle_t cfg_hdl, boolean_t *empty_io_range,
    boolean_t *empty_mem_range)
{
	uint8_t	class, subclass;
	uint_t	val;

	class = pci_config_get8(cfg_hdl, PCI_CONF_BASCLASS);
	subclass = pci_config_get8(cfg_hdl, PCI_CONF_SUBCLASS);

	if ((class == PCI_CLASS_BRIDGE) && (subclass == PCI_BRIDGE_PCI)) {
		val = (((uint_t)pci_config_get8(cfg_hdl, PCI_BCNF_IO_BASE_LOW) &
		    PCI_BCNF_IO_MASK) << 8);
		/*
		 * Assuming that a zero based io_range[0] implies an
		 * invalid I/O range.  Likewise for mem_range[0].
		 */
		if (val == 0)
			*empty_io_range = B_TRUE;
		val = (((uint_t)pci_config_get16(cfg_hdl, PCI_BCNF_MEM_BASE) &
		    PCI_BCNF_MEM_MASK) << 16);
		if (val == 0)
			*empty_mem_range = B_TRUE;
	}
}

#endif /* defined(__i386) || defined(__amd64) */
