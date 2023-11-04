/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer company
 */

/*
 * This file consolidates the basic devinfo properties that exist in the system
 * for PCI and PCI Express devices and attempts to ensure that there is only one
 * place to set these items. There are a bunch of different historical
 * considerations that are taken into account here.
 *
 * PCI Compatible Aliases
 * ----------------------
 *
 * The set of aliases that we put on devices is used in the 'compatible'
 * property to attach device drivers to nodes. These are ordered from more
 * specific aliases to less specific aliases. The original set of aliases that
 * was used was defined by Open Firmware for PCI and discussed in the PCI and
 * later the PCI Express bindings as part of IEEE 1275. Originally those
 * bindings consisted of aliases which we could describe as:
 *
 * pci<vendor id>,<device id>.<subsystem vendor>.<subsytem id>.<revision>
 * pci<vendor id>,<device id>.<subsystem vendor>.<subsytem id>
 * pci<subsystem vendor>,<subsytem id>
 * pci<vendor id>,<device id>.<revision>
 * pci<vendor id>,<device id>
 * pciclass,<class code><subclass><programming interface>
 * pciclass,<class code><subclass>
 *
 * When it came time to move to PCI Express, Sun had published a draft document
 * for how to adopt IEEE 1275 bindings to PCI Express. Most notably it dropped
 * the pci<subsystem vendor>.<subsytem id> entry and instead prefixed everything
 * with 'pciex' instead of 'pci'. The reason that this was dropped was because
 * of the fact that while the early days assumed that subsystem IDs were in a
 * shared namespace with device IDs, they ended up overlapping and therefore
 * have not proven to be unique. Because that ID syntax overlapped with
 * pci<vendor id>,<device id> this has led to problems where IDs are reused and
 * incorrect bindings occur. We already maintain a deny list where there are
 * known conflicts.
 *
 * To deal with the ambiguity here while trying to avoid the challenges of the
 * figuring out what IDs were meant to be subsystem IDs and which were primary
 * IDs (a non-obvious task given that some device drivers are almost exclusively
 * identified by standalone subsystem IDs -- see smrt(4D) and cpqary3(4D)), we
 * added two additional aliases for PCI (but not PCI Express) that allow drivers
 * to express what we call disambiguated IDs. These take the form:
 *
 * pci<subsystem vendor>,<subsystem id>,s
 * pci<vendor id>,<device id>,p
 *
 * Were that this was our only challenge. The next bit that we have to deal with
 * is another artifact of history. While Sun proposed the different PCIe
 * bindings in a draft, the original intent was just that the aliases would all
 * take the form of 'pciex' as above and that was it. However, the x86
 * implementation didn't actually roll with the plan. Instead, it placed the set
 * of PCI Express aliases and then followed it with the traditional PCI aliases.
 * As such, they have double the aliases. We still maintain this on x86, but do
 * not extend the double aliases to other platforms. Because these are specific
 * to the platform and not the instruction set architecture, whether this is
 * required or not is indicated by the PCI PRD compat flags interface
 * pci_prd_compat_flags().
 *
 * The last current wrinkle here is that of bridge IDs. Originally PCI bridges
 * didn't have any form of subsystem ID defined. In the PCI-PCI bridge
 * specification version 1.2, published in 2003, they eventually added an
 * optional capability to define a bridge's subsystem. This meant that for most
 * of PCI's existence this did not exist. In particular, until 2023 we did not
 * try to search for the capability and add it to a device's compatible
 * properties. Because of this lapse and having to deal with the above ID
 * disambiguation, we only add the disambiguated ,s subsystem ID for PCI. Both
 * PCI Express and PCI still have the fully qualified subsystem IDs added for
 * bridges.
 *
 * Our final set of aliases that we assign to all nodes is in the table below
 * called 'pci_alias_table'. This table has flags which control the behavior of
 * the ID generation. To summarize what a platform can control is:
 *
 *   o Whether or not both PCIe and PCI aliases are generated. This is
 *     controlled via PCI_PRD_COMPAT_PCI_NODE_NAME which also influences the
 *     node name below.
 *   o For PCI, whether or not we should generate the ambiguous subsystem ID
 *     alias. This is controlled by PCI_PRD_COMPAT_SUBSYS. We will always
 *     generate the disambiguated IDs for PCI to stick with IEEE 1275
 *     expectations across the system. PCI Express will not generate either of
 *     the standalone subsystem ID forms.
 *
 * Node Naming
 * -----------
 *
 * When we name devinfo names we generally do so in the form <type><subsystem
 * vendor id>,<subsystem id>. If there is no subsystem ID then we use
 * <type><vendor id>,<device id>. Type 1 headers do not have a subsystem ID.
 * They are instead found in an optional capability. Type 0 headers do have a
 * subsystem ID. If the subsystem vendor ID is zero, that indicates that the
 * subsystem ID is not present and we fall back to the vendor and device ID.
 *
 * x86 is again a land of exceptions. Because we never had subsystem IDs present
 * for bridges, they always use the vendor and device variant for compatibility
 * purposes. Similarly, x86 always sets the type to "pci" for compatibility.
 * Other platforms will set the type to "pciex" if it is a PCI Express device or
 * "pci" otherwise.
 *
 * Traditionally, node naming was originally driven by the PROM on SPARC which
 * used IEEE 1275 Open Firmware device class names instead of just the device
 * IDs that we have settled on. On our platforms there are two exceptions to
 * this. If we find an ISA compatible system and the PCI PRD indicates that the
 * platform supports ISA, then we will override that. In addition, a subset of
 * the display class codes have historically been used to name a device node
 * "display".
 *
 * Our order for naming device nodes is:
 *
 * 1. Check for display.
 * 2. Check for ISA.
 * 3. Attempt to use the subsystem.
 * 4. Fall back to the normal vendor and device.
 *
 * Platforms can influence this in the following ways:
 *
 *   o ISA is only considered if PCI_PRD_COMPAT_ISA is set.
 *   o Bridges will not use the subsystem IDs if PCI_PRD_COMPAT_SUBSYS is set.
 *   o The node name will always start with "pci" if
 *     PCI_PRD_COMPAT_PCI_NODE_NAME is set.
 *
 * Unit Address
 * ------------
 *
 * The unit address for a PCI device has historically been its device number.
 * For multi-function devices, everything past function zero is the device
 * number followed by the function number. ARI devices technically don't have a
 * device number. If we encounter such a device, we just set the device portion
 * of the unit address to 0.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/cmn_err.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_props.h>
#include <sys/sysmacros.h>
#include <sys/plat/pci_prd.h>
#include <pci_strings.h>

typedef struct {
	uint8_t ppc_class;
	uint8_t ppc_subclass;
	uint8_t ppc_pi;
} pci_prop_class_t;

static boolean_t
pci_prop_class_match(const pci_prop_data_t *prop, const pci_prop_class_t *class,
    const size_t nclass, boolean_t check_pi)
{
	for (size_t i = 0; i < nclass; i++) {
		if (prop->ppd_class == class[i].ppc_class &&
		    prop->ppd_subclass == class[i].ppc_subclass &&
		    (!check_pi || prop->ppd_pi == class[i].ppc_pi)) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * This is used to determine if a given set of data indicates that we have
 * encountered a VGA class code which should be given the "display" name. The
 * following tuples of class, subclass, programming interface are VGA
 * compatible:
 *
 * 0x00, 0x01, 0x00: The pre-class code VGA device
 * 0x03, 0x00, 0x00: A VGA Compatible controller
 * 0x03, 0x00, 0x01: A 8514 compatible controller
 */
static const pci_prop_class_t pci_prop_vga_classes[] = {
	{ PCI_CLASS_NONE, PCI_NONE_VGA, 0x00 },
	{ PCI_CLASS_DISPLAY, PCI_DISPLAY_VGA, PCI_DISPLAY_IF_VGA },
	{ PCI_CLASS_DISPLAY, PCI_DISPLAY_VGA, PCI_DISPLAY_IF_8514 }
};

static const pci_prop_class_t pci_prop_ioapic_classes[] = {
	{ PCI_CLASS_PERIPH, PCI_PERIPH_PIC, PCI_PERIPH_PIC_IF_IO_APIC },
	{ PCI_CLASS_PERIPH, PCI_PERIPH_PIC, PCI_PERIPH_PIC_IF_IOX_APIC },
};

static const pci_prop_class_t pci_prop_isa_classes[] = {
	{ PCI_CLASS_BRIDGE, PCI_BRIDGE_ISA, 0 }
};

static const pci_prop_class_t pci_prop_pcibridge_classes[] = {
	{ PCI_CLASS_BRIDGE, PCI_BRIDGE_PCI, 0 }
};

boolean_t
pci_prop_class_is_vga(const pci_prop_data_t *prop)
{
	return (pci_prop_class_match(prop, pci_prop_vga_classes,
	    ARRAY_SIZE(pci_prop_vga_classes), B_TRUE));
}

boolean_t
pci_prop_class_is_ioapic(const pci_prop_data_t *prop)
{
	return (pci_prop_class_match(prop, pci_prop_ioapic_classes,
	    ARRAY_SIZE(pci_prop_ioapic_classes), B_TRUE));
}

/*
 * Determine if a class indicates that it is ISA. Technically this should be
 * checking the programming interface as only PI 0x00 is defined; however, this
 * is the check that has historically been done and the PCI-SIG is unlikely to
 * define additional programming interfaces for an ISA bridge.
 */
boolean_t
pci_prop_class_is_isa(const pci_prop_data_t *prop)
{
	return (pci_prop_class_match(prop, pci_prop_isa_classes,
	    ARRAY_SIZE(pci_prop_isa_classes), B_FALSE));
}

/*
 * We don't check the programming class here because callers don't care if this
 * is subtractive or not.
 */
boolean_t
pci_prop_class_is_pcibridge(const pci_prop_data_t *prop)
{
	return (pci_prop_class_match(prop, pci_prop_pcibridge_classes,
	    ARRAY_SIZE(pci_prop_pcibridge_classes), B_FALSE));
}

static const char *
pci_prop_nodename_prefix(const pci_prop_data_t *prop,
    pci_prd_compat_flags_t flags)
{
	if ((flags & PCI_PRD_COMPAT_PCI_NODE_NAME) != 0) {
		return ("pci");
	}

	if ((prop->ppd_flags & PCI_PROP_F_PCIE) != 0) {
		return ("pciex");
	} else {
		return ("pci");
	}
}

static boolean_t
pci_prop_use_subsystem(const pci_prop_data_t *prop,
    pci_prd_compat_flags_t flags)
{
	if ((flags & PCI_PRD_COMPAT_SUBSYS) != 0 &&
	    prop->ppd_header == PCI_HEADER_PPB) {
		return (B_FALSE);
	}

	return (prop->ppd_subvid != 0);
}

/*
 * Name a device node per the theory statement.
 */
pci_prop_failure_t
pci_prop_name_node(dev_info_t *dip, const pci_prop_data_t *prop)
{
	char buf[64];
	pci_prd_compat_flags_t flags = pci_prd_compat_flags();

	if (pci_prop_class_is_vga(prop)) {
		(void) snprintf(buf, sizeof (buf), "display");
	} else if (pci_prop_class_is_isa(prop) &&
	    (flags & PCI_PRD_COMPAT_ISA) != 0) {
		(void) snprintf(buf, sizeof (buf), "isa");
	} else {
		const char *prefix = pci_prop_nodename_prefix(prop, flags);

		if (pci_prop_use_subsystem(prop, flags)) {
			(void) snprintf(buf, sizeof (buf), "%s%x,%x", prefix,
			    prop->ppd_subvid, prop->ppd_subsys);
		} else {
			(void) snprintf(buf, sizeof (buf), "%s%x,%x", prefix,
			    prop->ppd_vendid, prop->ppd_devid);
		}
	}

	if (ndi_devi_set_nodename(dip, buf, 0) != NDI_SUCCESS) {
		return (PCI_PROP_E_NDI);
	}
	return (PCI_PROP_OK);
}

static uint8_t
pci_prop_get8(ddi_acc_handle_t acc, const pci_prop_data_t *prop, uint16_t off)
{
	if (acc == NULL) {
		return ((*pci_getb_func)(prop->ppd_bus, prop->ppd_dev,
		    prop->ppd_func, off));
	} else {
		return (pci_config_get8(acc, off));
	}
}

static uint16_t
pci_prop_get16(ddi_acc_handle_t acc, const pci_prop_data_t *prop, uint16_t off)
{
	if (acc == NULL) {
		return ((*pci_getw_func)(prop->ppd_bus, prop->ppd_dev,
		    prop->ppd_func, off));
	} else {
		return (pci_config_get16(acc, off));
	}
}

static uint32_t
pci_prop_get32(ddi_acc_handle_t acc, const pci_prop_data_t *prop, uint16_t off)
{
	if (acc == NULL) {
		return ((*pci_getl_func)(prop->ppd_bus, prop->ppd_dev,
		    prop->ppd_func, off));
	} else {
		return (pci_config_get32(acc, off));
	}
}

static pci_prop_failure_t
pci_prop_data_fill_pcie(ddi_acc_handle_t acc, pci_prop_data_t *prop,
    uint8_t cap_base)
{
	uint16_t pciecap;
	uint32_t slotcap;
	uint8_t vers;

	pciecap = pci_prop_get16(acc, prop, cap_base + PCIE_PCIECAP);
	vers = pciecap & PCIE_PCIECAP_VER_MASK;
	switch (vers) {
	case PCIE_PCIECAP_VER_1_0:
	case PCIE_PCIECAP_VER_2_0:
		break;
	default:
		cmn_err(CE_WARN, "found device at b/d/f 0x%x/0x%x/0x%x with "
		    "PCIe capability with unsupported capability version: 0x%x",
		    prop->ppd_bus, prop->ppd_dev, prop->ppd_func, vers);
		return (PCI_PROP_E_BAD_PCIE_CAP);
	}

	prop->ppd_flags |= PCI_PROP_F_PCIE;
	prop->ppd_pcie_type = pciecap & PCIE_PCIECAP_DEV_TYPE_MASK;

	if ((pciecap & PCIE_PCIECAP_SLOT_IMPL) == 0) {
		return (PCI_PROP_OK);
	}

	slotcap = pci_prop_get32(acc, prop, cap_base + PCIE_SLOTCAP);
	prop->ppd_slotno = PCIE_SLOTCAP_PHY_SLOT_NUM(slotcap);
	prop->ppd_flags |= PCI_PROP_F_SLOT_VALID;
	return (PCI_PROP_OK);
}

/*
 * Obtain basic information about a device and store it for future processing
 * and for other code's general usage. This may be called early in boot before
 * we feel like we should use the normal access routines or later in boot where
 * the system opts to use normal DDI accesses. We accept either and make do with
 * the rest.
 *
 * We err on the side of trying to be lenient with devices that are potentially
 * a bit odd. Not all devices in the wild actually follow the spec.
 */
pci_prop_failure_t
pci_prop_data_fill(ddi_acc_handle_t acc, uint8_t bus, uint8_t dev, uint8_t func,
    pci_prop_data_t *prop)
{
	uint8_t htype, cap_off, max_cap = PCI_CAP_MAX_PTR;
	uint16_t status;

	bzero(prop, sizeof (pci_prop_data_t));
	prop->ppd_bus = bus;
	prop->ppd_dev = dev;
	prop->ppd_func = func;

	/*
	 * To fill this out, begin with getting things that are always going to
	 * be the same between different header types. We check the validity of
	 * the vendor ID as a proxy for hardware being present.
	 */
	prop->ppd_vendid = pci_prop_get16(acc, prop, PCI_CONF_VENID);
	if (prop->ppd_vendid == PCI_EINVAL16) {
		return (PCI_PROP_E_BAD_READ);
	}
	prop->ppd_devid = pci_prop_get16(acc, prop, PCI_CONF_DEVID);
	prop->ppd_rev = pci_prop_get8(acc, prop, PCI_CONF_REVID);
	prop->ppd_class = pci_prop_get8(acc, prop, PCI_CONF_BASCLASS);
	prop->ppd_subclass = pci_prop_get8(acc, prop, PCI_CONF_SUBCLASS);
	prop->ppd_pi = pci_prop_get8(acc, prop, PCI_CONF_PROGCLASS);

	htype = pci_prop_get8(acc, prop, PCI_CONF_HEADER);
	prop->ppd_header = htype & PCI_HEADER_TYPE_M;
	if ((htype & PCI_HEADER_MULTI) != 0) {
		prop->ppd_flags |= PCI_PROP_F_MULT_FUNC;
	}


	/*
	 * Next, we get fields from the header that vary between device types or
	 * are specific to a given device type. Bridges do not have a subsystem
	 * ID at this point, instead we will fetch it out when we walk the basic
	 * capabilities.
	 */
	switch (prop->ppd_header) {
	case PCI_HEADER_ZERO:
		prop->ppd_subvid = pci_prop_get16(acc, prop,
		    PCI_CONF_SUBVENID);
		prop->ppd_subsys =  pci_prop_get16(acc, prop,
		    PCI_CONF_SUBSYSID);
		prop->ppd_mingrt = pci_prop_get8(acc, prop, PCI_CONF_MIN_G);
		prop->ppd_maxlat = pci_prop_get8(acc, prop, PCI_CONF_MAX_L);
		break;
	case PCI_HEADER_CARDBUS:
		prop->ppd_subvid = pci_prop_get16(acc, prop,
		    PCI_CBUS_SUBVENID);
		prop->ppd_subsys =  pci_prop_get16(acc, prop,
		    PCI_CBUS_SUBSYSID);
		break;
	case PCI_HEADER_PPB:
		break;
	default:
		return (PCI_PROP_E_UNKNOWN_HEADER);
	}

	/*
	 * Capture registers which are used to derive various devinfo
	 * properties and are shared between all device types.
	 */
	prop->ppd_ipin = pci_prop_get8(acc, prop, PCI_CONF_IPIN);
	prop->ppd_status = pci_prop_get16(acc, prop, PCI_CONF_STAT);

	/*
	 * If there are no capabilities, there is nothing else for us to do.
	 */
	status = pci_prop_get16(acc, prop, PCI_CONF_STAT);
	if ((status & PCI_STAT_CAP) == 0)
		return (PCI_PROP_OK);

	cap_off = pci_prop_get8(acc, prop, PCI_CONF_CAP_PTR);
	for (; max_cap > 0 && cap_off >= PCI_CAP_PTR_OFF; max_cap--) {
		uint8_t cap_addr = cap_off & PCI_CAP_PTR_MASK;
		uint8_t cap_id = pci_prop_get8(acc, prop, cap_addr);
		pci_prop_failure_t ret;

		/*
		 * Look for an invalid read as a proxy for this being in illegal
		 * capability and that we're done. We don't treat this as fatal
		 * as some devices will place the caps at weird places.
		 */
		if (cap_id == PCI_EINVAL8) {
			return (PCI_PROP_OK);
		}

		switch (cap_id) {
		case PCI_CAP_ID_PCI_E:
			ret = pci_prop_data_fill_pcie(acc, prop, cap_addr);
			if (ret != PCI_PROP_OK) {
				return (ret);
			}
			break;
		case PCI_CAP_ID_P2P_SUBSYS:
			/*
			 * This is only legal in a type 1 header configuration
			 * space. If we encounter it elsewhere, warn about it,
			 * but don't fail.
			 */
			if (prop->ppd_header != PCI_HEADER_PPB) {
				cmn_err(CE_WARN, "found device at b/d/f "
				    "0x%x/0x%x/0x%x with PCI subsystem "
				    "capability, but wrong header type: 0x%x",
				    bus, dev, func, prop->ppd_header);
				break;
			}

			prop->ppd_subvid = pci_prop_get16(acc, prop, cap_addr +
			    PCI_SUBSYSCAP_SUBVID);
			prop->ppd_subsys = pci_prop_get16(acc, prop, cap_addr +
			    PCI_SUBSYSCAP_SUBSYS);
			break;
		default:
			break;
		}

		/*
		 * Again, we check for invalid capability offsets to try to flag
		 * the case of an invalid read. If we have a zero representing
		 * the end of the list, then we'll break out up above.
		 */
		cap_off = pci_prop_get8(acc, prop, cap_addr + PCI_CAP_NEXT_PTR);
		if (cap_off == PCI_EINVAL8) {
			return (PCI_PROP_OK);
		}
	}

	return (PCI_PROP_OK);
}

/*
 * The IEEE 1275 slot-names property has a unique construction. It starts off
 * with a uint32_t which is a bitmask of names for each device. Then there is a
 * number of strings ordered based on the bitfield. The NDI doesn't have a great
 * way to represent this combination of types so we are bound by history which
 * says to use an int array. Yes, this is gross.
 *
 * For PCIe this is at least somewhat straightforward. We only ever have one
 * device so our bitfield value is always 0x1. The name we use is also always
 * "pcie<slot>".
 */
static void
pci_prop_set_pciex_slot_name(dev_info_t *dip, uint16_t slotno)
{
	uint32_t slot[32];
	size_t len;

	bzero(slot, sizeof (slot));
	slot[0] = 1;

	/*
	 * We need to calculate the number of uint32_t's that we used. We round
	 * up the number of bytes used for the name, convert that to a number of
	 * uint32_t's and then add one for the bitfield.
	 */
	len = snprintf((char *)&slot[1], sizeof (slot) - sizeof (slot[0]),
	    "pcie%u", slotno) + 1;
	len = P2ROUNDUP(len, sizeof (uint32_t));
	len /= sizeof (uint32_t);
	len += 1;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "slot-names",
	    (int *)slot, len);
}

pci_prop_failure_t
pci_prop_set_common_props(dev_info_t *dip, const pci_prop_data_t *prop)
{
	int class;
	char unitaddr[16];
	pci_prd_compat_flags_t flags = pci_prd_compat_flags();

	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "vendor-id",
	    prop->ppd_vendid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "device-id",
	    prop->ppd_devid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "revision-id",
	    prop->ppd_rev);

	class = (prop->ppd_class << 16) | (prop->ppd_subclass << 8) |
	    prop->ppd_pi;
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "class-code", class);

	if (prop->ppd_subvid != 0) {
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "subsystem-vendor-id", prop->ppd_subvid);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "subsystem-id",
		    prop->ppd_subsys);
	}

	if (prop->ppd_func > 0) {
		(void) snprintf(unitaddr, sizeof (unitaddr), "%x,%x",
		    prop->ppd_dev, prop->ppd_func);
	} else {
		(void) snprintf(unitaddr, sizeof (unitaddr), "%x",
		    prop->ppd_dev);
	}
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, "unit-address",
	    unitaddr);

	/*
	 * Set properties specific to the device class (i.e. PCI or PCIe).
	 * While devsel-speed is meaningless for PCIe, this is still set
	 * anyways for it to match tradition.
	 */
	if ((prop->ppd_flags & PCI_PROP_F_PCIE) == 0) {
		if ((prop->ppd_status & PCI_STAT_FBBC) != 0) {
			(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
			    "fast-back-to-back");
		}

		if ((prop->ppd_status & PCI_STAT_66MHZ) != 0) {
			(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
			    "66mhz-capable");
		}

		if ((prop->ppd_status & PCI_STAT_UDF) != 0) {
			(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
			    "udf-supported");
		}

		if (prop->ppd_header == PCI_HEADER_ZERO) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "min-grant", prop->ppd_mingrt);

			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "max-latency", prop->ppd_maxlat);
		}
	} else {
		if ((prop->ppd_flags & PCI_PROP_F_SLOT_VALID) != 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "physical-slot#", prop->ppd_slotno);
			if (prop->ppd_pcie_type !=
			    PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
				pci_prop_set_pciex_slot_name(dip,
				    prop->ppd_slotno);
			}
		}
	}
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "devsel-speed",
	    (prop->ppd_status & PCI_STAT_DEVSELT) >> 9);

	/*
	 * The ipin indicates which INTx value a device should have. Zero
	 * indicates no INTx has been assigned.
	 */
	if (prop->ppd_ipin != 0) {
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "interrupts",
		    prop->ppd_ipin);
	}

	/*
	 * VGA class devices have required specific device_type and related
	 * properties to be set. The same is true of ISA. Parent bridges and the
	 * synthetic nexus nodes that represent root complexes ala npe, pci,
	 * pcieb, etc. set the device type to either "pci" or "pciex", but that
	 * is not done universally at this time. We should consider that for the
	 * future.
	 */
	if (pci_prop_class_is_vga(prop)) {
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "display");
	} else if (pci_prop_class_is_isa(prop) &&
	    (flags & PCI_PRD_COMPAT_ISA) != 0) {
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "isa");
	}

	/*
	 * Go through and add the model property. This utilizes the common PCI
	 * class codes. Traditionally a PCIe->PCI bridge was treated specially
	 * and given a unique label because of the fact it was crossing between
	 * the protocols (though the opposite wasn't true for PCI->PCIe
	 * bridges).
	 *
	 * The other traditional gotcha here is that any device whose class and
	 * subclass indicated it was an IDE controller got that name.
	 */
	if ((prop->ppd_flags & PCI_PROP_F_PCIE) != 0 &&
	    prop->ppd_pcie_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
		    (char *)"PCIe-PCI bridge");
	} else if (prop->ppd_class == PCI_CLASS_MASS &&
	    prop->ppd_subclass == PCI_MASS_IDE) {
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
		    (char *)"IDE controller");
	} else {
		const char *desc = NULL;

		for (int i = 0; i < class_pci_items; i++) {
			if (prop->ppd_class == class_pci[i].base_class &&
			    prop->ppd_subclass == class_pci[i].sub_class &&
			    prop->ppd_pi == class_pci[i].prog_class) {
				desc = class_pci[i].actual_desc;
				break;
			}
		}

		if (desc == NULL) {
			/*
			 * Yes, we're not dealing with PNP strictly any more,
			 * but this is the string we've traditionally used.
			 */
			desc = "Unknown class of pci/pnpbios device";
		}

		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
		    (char *)desc);
	}

	return (PCI_PROP_OK);
}


/*
 * This enumeration encodes the different possible forms of the alias
 * properties. In these definitions, the following groups of letters have
 * different means:
 *
 * "VD": Vendor ID,Device ID (1234,5678)
 * "SVSI": Subsystem Vendor ID, Subsystem ID
 * "R": Revision
 * "S": The string ,s to represent the disambiguated PCI subsystem alias
 * "P": The string ,p to represent the disambiguated PCI primary alias
 * "CSPI": Class, subclass, and Programming Interface
 * "CS": Class, subclass
 */
typedef enum {
	PCI_ALIAS_VD_SVSI_R,
	PCI_ALIAS_VD_SVSI,
	PCI_ALIAS_SVSI_S,
	PCI_ALIAS_SVSI,
	PCI_ALIAS_VD_R,
	PCI_ALIAS_VD_P,
	PCI_ALIAS_VD,
	PCI_ALIAS_CSPI,
	PCI_ALIAS_CS,
	PCI_ALIAS_MAX
} pci_alias_t;

/*
 * The upper bound on aliases is if everything is used once for PCIe and then
 * again for PCI. This is more than should be used.
 */
#define	PCI_MAX_ALIASES	(2 * PCI_ALIAS_MAX)

typedef enum {
	/*
	 * This flag indicates that a given alias should only be used for PCI
	 * devices.
	 */
	PCI_ALIAS_F_PCI_ONLY		= 1 << 0,
	/*
	 * This flag indicates that this value should not be used for any device
	 * with a type 1 header, aka PCI-PCI bridges.
	 */
	PCI_ALIAS_F_SKIP_BRIDGE		= 1 << 1,
	/*
	 * This flag indicates that we should create subsystem compatibility
	 * IDs. We only expect this to be done on x86 (and SPARC historically).
	 */
	PCI_ALIAS_F_COMPAT		= 1 << 2,
	/*
	 * This flag indicates that we need to check whether we've banned the
	 * subsystem ID due to duplication. This is still something we do even
	 * when we don't have PCI_ALIAS_F_COMPAT set for the disambiguated
	 * subsystem ID.
	 */
	PCI_ALIAS_F_CHECK_SUBSYS	= 1 << 3
} pci_alias_flags_t;

typedef struct {
	pci_alias_t pad_type;
	pci_alias_flags_t pad_flags;
} pci_alias_data_t;

static const pci_alias_data_t pci_alias_table[] = {
	{ PCI_ALIAS_VD_SVSI_R, 0 },
	{ PCI_ALIAS_VD_SVSI, 0 },
	{ PCI_ALIAS_SVSI_S, PCI_ALIAS_F_PCI_ONLY | PCI_ALIAS_F_CHECK_SUBSYS },
	{ PCI_ALIAS_SVSI, PCI_ALIAS_F_PCI_ONLY | PCI_ALIAS_F_SKIP_BRIDGE |
	    PCI_ALIAS_F_COMPAT | PCI_ALIAS_F_CHECK_SUBSYS },
	{ PCI_ALIAS_VD_R, 0 },
	{ PCI_ALIAS_VD_P, PCI_ALIAS_F_PCI_ONLY },
	{ PCI_ALIAS_VD, 0 },
	{ PCI_ALIAS_CSPI, 0 },
	{ PCI_ALIAS_CS, 0 },
};

/*
 * Our big theory statement talks about cases where we already know that PCI IDs
 * have had overlap with subsystems and them not being appropriate. The
 * following table describes how to match
 */
typedef enum {
	PCI_PROP_NSM_VID_CLASS,
	PCI_PROP_NSM_SUBSYS
} pci_prop_no_subsys_match_t;

typedef boolean_t (*pci_prop_no_subsys_class_f)(const pci_prop_data_t *);
typedef struct pci_prop_no_subsys {
	pci_prop_no_subsys_match_t	ppnsm_type;
	uint16_t			ppnsm_vid;
	uint16_t			ppnsm_did;
	uint16_t			ppnsm_subvid;
	uint16_t			ppnsm_subsys;
	pci_prop_no_subsys_class_f	ppnsm_class;
} pci_prop_no_subsys_t;

static const pci_prop_no_subsys_t pci_prop_no_subsys[] = {
	/*
	 * We've historically blocked nVidia subsystems because of subsystem
	 * reuse.
	 */
	{ .ppnsm_type = PCI_PROP_NSM_VID_CLASS, .ppnsm_vid = 0x10de,
	    .ppnsm_class = pci_prop_class_is_vga },
	/*
	 * 8086,166 is the Ivy Bridge built-in graphics controller on some
	 * models. Unfortunately 8086,2044 is the Skylake Server processor
	 * memory channel device. The Ivy Bridge device uses the Skylake
	 * ID as its sub-device ID. The GPU is not a memory controller DIMM
	 * channel.
	 */
	{ .ppnsm_type = PCI_PROP_NSM_SUBSYS, .ppnsm_vid = 0x8086,
	    .ppnsm_did = 0x166, .ppnsm_subvid = 0x8086, .ppnsm_subsys = 0x2044 }
};

static boolean_t
pci_prop_skip_subsys(const pci_prop_data_t *prop)
{
	for (size_t i = 0; i < ARRAY_SIZE(pci_prop_no_subsys); i++) {
		const pci_prop_no_subsys_t *p = &pci_prop_no_subsys[i];
		switch (p->ppnsm_type) {
		case PCI_PROP_NSM_VID_CLASS:
			if (prop->ppd_vendid == p->ppnsm_vid &&
			    p->ppnsm_class(prop)) {
				return (B_TRUE);
			}
			break;
		case PCI_PROP_NSM_SUBSYS:
			if (prop->ppd_vendid == p->ppnsm_vid &&
			    prop->ppd_devid == p->ppnsm_did &&
			    prop->ppd_subvid == p->ppnsm_subvid &&
			    prop->ppd_subsys == p->ppnsm_subsys) {
				return (B_TRUE);
			}
			break;
		}
	}
	return (B_FALSE);
}

static void
pci_prop_alias_pass(const pci_prop_data_t *prop, char **alias, uint_t *nalias,
    pci_prd_compat_flags_t compat, boolean_t force_pci)
{
	boolean_t is_pci = force_pci ||
	    (prop->ppd_flags & PCI_PROP_F_PCIE) == 0;
	const char *prefix = is_pci ? "pci" : "pciex";
	boolean_t subsys_valid = prop->ppd_subvid != 0;

	for (size_t i = 0; i < ARRAY_SIZE(pci_alias_table); i++) {
		const pci_alias_data_t *a = &pci_alias_table[i];

		if ((a->pad_flags & PCI_ALIAS_F_PCI_ONLY) != 0 && !is_pci) {
			continue;
		}

		if ((a->pad_flags & PCI_ALIAS_F_SKIP_BRIDGE) != 0 &&
		    prop->ppd_header == PCI_HEADER_PPB) {
			continue;
		}

		if ((a->pad_flags & PCI_ALIAS_F_COMPAT) != 0 &&
		    (compat & PCI_PRD_COMPAT_SUBSYS) == 0) {
			continue;
		}

		if ((a->pad_flags & PCI_ALIAS_F_CHECK_SUBSYS) != 0 &&
		    pci_prop_skip_subsys(prop)) {
			continue;
		}

		switch (a->pad_type) {
		case PCI_ALIAS_VD_SVSI_R:
			if (!subsys_valid)
				continue;
			alias[*nalias] = kmem_asprintf("%s%x,%x.%x.%x.%x",
			    prefix, prop->ppd_vendid, prop->ppd_devid,
			    prop->ppd_subvid, prop->ppd_subsys,
			    prop->ppd_rev);
			break;
		case PCI_ALIAS_VD_SVSI:
			if (!subsys_valid)
				continue;
			alias[*nalias] = kmem_asprintf("%s%x,%x.%x.%x", prefix,
			    prop->ppd_vendid, prop->ppd_devid,
			    prop->ppd_subvid, prop->ppd_subsys);
			break;
		case PCI_ALIAS_SVSI_S:
			if (!subsys_valid)
				continue;
			alias[*nalias] = kmem_asprintf("%s%x,%x,s", prefix,
			    prop->ppd_subvid, prop->ppd_subsys);
			break;
		case PCI_ALIAS_SVSI:
			if (!subsys_valid)
				continue;
			alias[*nalias] = kmem_asprintf("%s%x,%x", prefix,
			    prop->ppd_subvid, prop->ppd_subsys);
			break;
		case PCI_ALIAS_VD_R:
			alias[*nalias] = kmem_asprintf("%s%x,%x.%x", prefix,
			    prop->ppd_vendid, prop->ppd_devid, prop->ppd_rev);
			break;
		case PCI_ALIAS_VD_P:
			alias[*nalias] = kmem_asprintf("%s%x,%x,p", prefix,
			    prop->ppd_vendid, prop->ppd_devid);
			break;
		case PCI_ALIAS_VD:
			alias[*nalias] = kmem_asprintf("%s%x,%x", prefix,
			    prop->ppd_vendid, prop->ppd_devid);
			break;
		case PCI_ALIAS_CSPI:
			alias[*nalias] = kmem_asprintf("%sclass,%02x%02x%02x",
			    prefix, prop->ppd_class, prop->ppd_subclass,
			    prop->ppd_pi);
			break;
		case PCI_ALIAS_CS:
			alias[*nalias] = kmem_asprintf("%sclass,%02x%02x",
			    prefix, prop->ppd_class, prop->ppd_subclass);
			break;
		default:
			panic("encountered unknown alias type: 0x%x",
			    a->pad_type);
		}

		*nalias = *nalias + 1;
		ASSERT3U(*nalias, <=, PCI_MAX_ALIASES);
	}
}

/*
 * Go through the messy process of creating the compatible property. See the
 * theory statement for more info.
 */
pci_prop_failure_t
pci_prop_set_compatible(dev_info_t *dip, const pci_prop_data_t *prop)
{
	char *alias[PCI_MAX_ALIASES];
	uint_t nalias = 0;
	pci_prd_compat_flags_t compat = pci_prd_compat_flags();
	boolean_t two_sets = (compat & PCI_PRD_COMPAT_PCI_NODE_NAME) != 0;

	pci_prop_alias_pass(prop, alias, &nalias, compat, B_FALSE);
	if (two_sets && (prop->ppd_flags & PCI_PROP_F_PCIE) != 0) {
		pci_prop_alias_pass(prop, alias, &nalias, compat, B_TRUE);
	}

	(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, dip, "compatible",
	    alias, nalias);
	for (uint_t i = 0; i < nalias; i++) {
		strfree(alias[i]);
	}
	return (PCI_PROP_OK);
}
