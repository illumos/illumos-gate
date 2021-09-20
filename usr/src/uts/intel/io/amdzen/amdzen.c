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
 * Copyright 2019, Joyent, Inc.
 * Copyright 2021 Oxide Computer Company
 */

/*
 * Nexus Driver for AMD Zen family systems. The purpose of this driver is to
 * provide access to the following resources in a single, centralized fashion:
 *
 *  - The per-chip Data Fabric
 *  - The North Bridge
 *  - The System Management Network (SMN)
 *
 * This is a nexus driver as once we have attached to all the requisite
 * components, we will enumerate child devices which consume this functionality.
 *
 * ------------------------
 * Mapping Devices Together
 * ------------------------
 *
 * The operating system needs to expose things like temperature sensors and DRAM
 * configuration registers in terms that are meaningful to the system such as
 * logical CPUs, cores, etc. This driver attaches to the PCI IDs that represent
 * the northbridge and data fabric; however, there are multiple PCI devices (one
 * per die) that exist. This driver does manage to map all of these three things
 * together; however, it requires some acrobatics. Unfortunately, there's no
 * direct way to map a northbridge to its corresponding die. However, we can map
 * a CPU die to a data fabric PCI device and a data fabric PCI device to a
 * corresponding northbridge PCI device.
 *
 * In current Zen based products, there is a direct mapping between processor
 * nodes and a data fabric PCI device. All of the devices are on PCI Bus 0 and
 * start from Device 0x18. Device 0x18 maps to processor node 0, 0x19 to
 * processor node 1, etc. This means that to map a logical CPU to a data fabric
 * device, we take its processor node id, add it to 0x18 and find the PCI device
 * that is on bus 0, device 0x18. As each data fabric device is attached based
 * on its PCI ID, we add it to the global list, amd_nbdf_dfs that is in the
 * amd_f17nbdf_t structure.
 *
 * The northbridge PCI device has a defined device and function, but the PCI bus
 * that it's on can vary. Each die has its own series of PCI buses that are
 * assigned to it and the northbridge PCI device is on the first of die-specific
 * PCI bus for each die. This also means that the northbridge will not show up
 * on PCI bus 0, which is the PCI bus that all of the data fabric devices are
 * on. While conventionally the northbridge with the lowest PCI bus value
 * would correspond to processor node zero, hardware does not guarantee that at
 * all. Because we don't want to be at the mercy of firmware, we don't rely on
 * this ordering, even though we have yet to find a system that deviates from
 * this scheme.
 *
 * One of the registers in the data fabric device's function 0
 * (AMDZEN_DF_F0_CFG_ADDR_CTL) happens to have the first PCI bus that is
 * associated with the processor node. This means that we can map a data fabric
 * device to a northbridge by finding the northbridge whose PCI bus matches the
 * value in the corresponding data fabric's AMDZEN_DF_F0_CFG_ADDR_CTL.
 *
 * We can map a northbridge to a data fabric device and a data fabric device to
 * a die. Because these are generally 1:1 mappings, there is a transitive
 * relationship and therefore we know which northbridge is associated with which
 * processor die. This is summarized in the following image:
 *
 *  +-------+    +-----------------------------------+        +--------------+
 *  | Die 0 |--->| Data Fabric PCI BDF 0/18/0        |------->| Northbridge  |
 *  +-------+    | AMDZEN_DF_F0_CFG_ADDR_CTL: bus 10 |        | PCI  10/0/0  |
 *     ...       +-----------------------------------+        +--------------+
 *  +-------+     +------------------------------------+        +--------------+
 *  | Die n |---->| Data Fabric PCI BDF 0/18+n/0       |------->| Northbridge  |
 *  +-------+     | AMDZEN_DF_F0_CFG_ADDR_CTL: bus 133 |        | PCI 133/0/0  |
 *                +------------------------------------+        +--------------+
 *
 * Note, the PCI buses used by the northbridges here are arbitrary. They do not
 * reflect the actual values by hardware; however, the bus/device/function (BDF)
 * of the data fabric accurately models hardware. All of the BDF values are in
 * hex.
 *
 * Starting with the Rome generation of processors (Family 17h Model 30-3Fh),
 * AMD has multiple northbridges that exist on a given die. All of these
 * northbridges share the same data fabric and system management network port.
 * From our perspective this means that some of the northbridge devices will be
 * redundant and that we will no longer have a 1:1 mapping between the
 * northbridge and the data fabric devices. Every data fabric will have a
 * northbridge, but not every northbridge will have a data fabric device mapped.
 * Because we're always trying to map from a die to a northbridge and not the
 * reverse, the fact that there are extra northbridge devices hanging around
 * that we don't know about shouldn't be a problem.
 *
 * -------------------------------
 * Attach and Detach Complications
 * -------------------------------
 *
 * Because we need to map different PCI devices together, this means that we
 * have multiple dev_info_t structures that we need to manage. Each of these is
 * independently attached and detached. While this is easily managed for attach,
 * it is not for detach. Each of these devices is a 'stub'.
 *
 * Once a device has been detached it will only come back if we have an active
 * minor node that will be accessed. This means that if they are detached,
 * nothing would ever cause them to be reattached. The system also doesn't
 * provide us a way or any guarantees around making sure that we're attached to
 * all such devices before we detach. As a result, unfortunately, it's easier to
 * basically have detach always fail.
 *
 * ---------------
 * Exposed Devices
 * ---------------
 *
 * Rather than try and have all of the different functions that could be
 * provided by one driver, we instead have created a nexus driver that will
 * itself try and load children. Children are all pseudo-device drivers that
 * provide different pieces of functionality that use this.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>
#include <sys/sunndi.h>
#include <sys/x86_archext.h>
#include <sys/cpuvar.h>

#include "amdzen.h"

amdzen_t *amdzen_data;

/*
 * Array of northbridge IDs that we care about.
 */
static const uint16_t amdzen_nb_ids[] = {
	/* Family 17h Ryzen, Epyc Models 00h-0fh (Zen uarch) */
	0x1450,
	/* Family 17h Raven Ridge, Kestrel, Dali Models 10h-2fh (Zen uarch) */
	0x15d0,
	/* Family 17h/19h Rome, Milan, Matisse, Vermeer Zen 2/Zen 3 uarch */
	0x1480,
	/* Family 17h/19h Renoir, Cezanne Zen 2/3 uarch) */
	0x1630
};

typedef struct {
	char *acd_name;
	amdzen_child_t acd_addr;
} amdzen_child_data_t;

static const amdzen_child_data_t amdzen_children[] = {
	{ "smntemp", AMDZEN_C_SMNTEMP },
	{ "usmn", AMDZEN_C_USMN },
	{ "zen_udf", AMDZEN_C_ZEN_UDF }
};

static uint32_t
amdzen_stub_get32(amdzen_stub_t *stub, off_t reg)
{
	return (pci_config_get32(stub->azns_cfgspace, reg));
}

static uint64_t
amdzen_stub_get64(amdzen_stub_t *stub, off_t reg)
{
	return (pci_config_get64(stub->azns_cfgspace, reg));
}

static void
amdzen_stub_put32(amdzen_stub_t *stub, off_t reg, uint32_t val)
{
	pci_config_put32(stub->azns_cfgspace, reg, val);
}

/*
 * Perform a targeted 32-bit indirect read to a specific instance and function.
 */
static uint32_t
amdzen_df_read32(amdzen_t *azn, amdzen_df_t *df, uint8_t inst, uint8_t func,
    uint16_t reg)
{
	uint32_t val;

	VERIFY(MUTEX_HELD(&azn->azn_mutex));
	val = AMDZEN_DF_F4_FICAA_TARG_INST | AMDZEN_DF_F4_FICAA_SET_REG(reg) |
	    AMDZEN_DF_F4_FICAA_SET_FUNC(func) |
	    AMDZEN_DF_F4_FICAA_SET_INST(inst);
	amdzen_stub_put32(df->adf_funcs[4], AMDZEN_DF_F4_FICAA, val);
	return (amdzen_stub_get32(df->adf_funcs[4], AMDZEN_DF_F4_FICAD_LO));
}

/*
 * Perform a targeted 64-bit indirect read to a specific instance and function.
 */
static uint64_t
amdzen_df_read64(amdzen_t *azn, amdzen_df_t *df, uint8_t inst, uint8_t func,
    uint16_t reg)
{
	uint32_t val;

	VERIFY(MUTEX_HELD(&azn->azn_mutex));
	val = AMDZEN_DF_F4_FICAA_TARG_INST | AMDZEN_DF_F4_FICAA_SET_REG(reg) |
	    AMDZEN_DF_F4_FICAA_SET_FUNC(func) |
	    AMDZEN_DF_F4_FICAA_SET_INST(inst) | AMDZEN_DF_F4_FICAA_SET_64B;
	amdzen_stub_put32(df->adf_funcs[4], AMDZEN_DF_F4_FICAA, val);
	return (amdzen_stub_get64(df->adf_funcs[4], AMDZEN_DF_F4_FICAD_LO));
}

static uint32_t
amdzen_smn_read32(amdzen_t *azn, amdzen_df_t *df, uint32_t reg)
{
	VERIFY(MUTEX_HELD(&azn->azn_mutex));
	amdzen_stub_put32(df->adf_nb, AMDZEN_NB_SMN_ADDR, reg);
	return (amdzen_stub_get32(df->adf_nb, AMDZEN_NB_SMN_DATA));
}

static void
amdzen_smn_write32(amdzen_t *azn, amdzen_df_t *df, uint32_t reg, uint32_t val)
{
	VERIFY(MUTEX_HELD(&azn->azn_mutex));
	amdzen_stub_put32(df->adf_nb, AMDZEN_NB_SMN_ADDR, reg);
	amdzen_stub_put32(df->adf_nb, AMDZEN_NB_SMN_DATA, val);
}

static amdzen_df_t *
amdzen_df_find(amdzen_t *azn, uint_t dfno)
{
	uint_t i;

	ASSERT(MUTEX_HELD(&azn->azn_mutex));
	if (dfno >= azn->azn_ndfs) {
		return (NULL);
	}

	for (i = 0; i < azn->azn_ndfs; i++) {
		amdzen_df_t *df = &azn->azn_dfs[i];
		if ((df->adf_flags & AMDZEN_DF_F_VALID) == 0) {
			continue;
		}

		if (dfno == 0) {
			return (df);
		}
		dfno--;
	}

	return (NULL);
}

/*
 * Client functions that are used by nexus children.
 */
int
amdzen_c_smn_read32(uint_t dfno, uint32_t reg, uint32_t *valp)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;

	mutex_enter(&azn->azn_mutex);
	df = amdzen_df_find(azn, dfno);
	if (df == NULL) {
		mutex_exit(&azn->azn_mutex);
		return (ENOENT);
	}

	if ((df->adf_flags & AMDZEN_DF_F_FOUND_NB) == 0) {
		mutex_exit(&azn->azn_mutex);
		return (ENXIO);
	}

	*valp = amdzen_smn_read32(azn, df, reg);
	mutex_exit(&azn->azn_mutex);
	return (0);
}

int
amdzen_c_smn_write32(uint_t dfno, uint32_t reg, uint32_t val)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;

	mutex_enter(&azn->azn_mutex);
	df = amdzen_df_find(azn, dfno);
	if (df == NULL) {
		mutex_exit(&azn->azn_mutex);
		return (ENOENT);
	}

	if ((df->adf_flags & AMDZEN_DF_F_FOUND_NB) == 0) {
		mutex_exit(&azn->azn_mutex);
		return (ENXIO);
	}

	amdzen_smn_write32(azn, df, reg, val);
	mutex_exit(&azn->azn_mutex);
	return (0);
}


uint_t
amdzen_c_df_count(void)
{
	uint_t ret;
	amdzen_t *azn = amdzen_data;

	mutex_enter(&azn->azn_mutex);
	ret = azn->azn_ndfs;
	mutex_exit(&azn->azn_mutex);
	return (ret);
}

int
amdzen_c_df_read32(uint_t dfno, uint8_t inst, uint8_t func,
    uint16_t reg, uint32_t *valp)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;

	mutex_enter(&azn->azn_mutex);
	df = amdzen_df_find(azn, dfno);
	if (df == NULL) {
		mutex_exit(&azn->azn_mutex);
		return (ENOENT);
	}

	*valp = amdzen_df_read32(azn, df, inst, func, reg);
	mutex_exit(&azn->azn_mutex);

	return (0);
}

int
amdzen_c_df_read64(uint_t dfno, uint8_t inst, uint8_t func,
    uint16_t reg, uint64_t *valp)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;

	mutex_enter(&azn->azn_mutex);
	df = amdzen_df_find(azn, dfno);
	if (df == NULL) {
		mutex_exit(&azn->azn_mutex);
		return (ENOENT);
	}

	*valp = amdzen_df_read64(azn, df, inst, func, reg);
	mutex_exit(&azn->azn_mutex);

	return (0);
}

static boolean_t
amdzen_create_child(amdzen_t *azn, const amdzen_child_data_t *acd)
{
	int ret;
	dev_info_t *child;

	if (ndi_devi_alloc(azn->azn_dip, acd->acd_name,
	    (pnode_t)DEVI_SID_NODEID, &child) != NDI_SUCCESS) {
		dev_err(azn->azn_dip, CE_WARN, "!failed to allocate child "
		    "dip for %s", acd->acd_name);
		return (B_FALSE);
	}

	ddi_set_parent_data(child, (void *)acd);
	if ((ret = ndi_devi_online(child, 0)) != NDI_SUCCESS) {
		dev_err(azn->azn_dip, CE_WARN, "!failed to online child "
		    "dip %s: %d", acd->acd_name, ret);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
amdzen_map_dfs(amdzen_t *azn)
{
	amdzen_stub_t *stub;

	ASSERT(MUTEX_HELD(&azn->azn_mutex));

	for (stub = list_head(&azn->azn_df_stubs); stub != NULL;
	    stub = list_next(&azn->azn_df_stubs, stub)) {
		amdzen_df_t *df;
		uint_t dfno;

		dfno = stub->azns_dev - AMDZEN_DF_FIRST_DEVICE;
		if (dfno > AMDZEN_MAX_DFS) {
			dev_err(stub->azns_dip, CE_WARN, "encountered df "
			    "device with illegal DF PCI b/d/f: 0x%x/%x/%x",
			    stub->azns_bus, stub->azns_dev, stub->azns_func);
			goto err;
		}

		df = &azn->azn_dfs[dfno];

		if (stub->azns_func >= AMDZEN_MAX_DF_FUNCS) {
			dev_err(stub->azns_dip, CE_WARN, "encountered df "
			    "device with illegal DF PCI b/d/f: 0x%x/%x/%x",
			    stub->azns_bus, stub->azns_dev, stub->azns_func);
			goto err;
		}

		if (df->adf_funcs[stub->azns_func] != NULL) {
			dev_err(stub->azns_dip, CE_WARN, "encountered "
			    "duplicate df device with DF PCI b/d/f: 0x%x/%x/%x",
			    stub->azns_bus, stub->azns_dev, stub->azns_func);
			goto err;
		}
		df->adf_funcs[stub->azns_func] = stub;
	}

	return (B_TRUE);

err:
	azn->azn_flags |= AMDZEN_F_DEVICE_ERROR;
	return (B_FALSE);
}

static boolean_t
amdzen_check_dfs(amdzen_t *azn)
{
	uint_t i;
	boolean_t ret = B_TRUE;

	for (i = 0; i < AMDZEN_MAX_DFS; i++) {
		amdzen_df_t *df = &azn->azn_dfs[i];
		uint_t count = 0;

		/*
		 * We require all platforms to have DFs functions 0-6. Not all
		 * platforms have DF function 7.
		 */
		for (uint_t func = 0; func < AMDZEN_MAX_DF_FUNCS - 1; func++) {
			if (df->adf_funcs[func] != NULL) {
				count++;
			}
		}

		if (count == 0)
			continue;

		if (count != 7) {
			ret = B_FALSE;
			dev_err(azn->azn_dip, CE_WARN, "df %u devices "
			    "incomplete", i);
		} else {
			df->adf_flags |= AMDZEN_DF_F_VALID;
			azn->azn_ndfs++;
		}
	}

	return (ret);
}

static const uint8_t amdzen_df_rome_ids[0x2b] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
	44, 45, 46, 47, 48
};

/*
 * Check the first df entry to see if it belongs to Rome or Milan. If so, then
 * it uses the disjoint ID space.
 */
static boolean_t
amdzen_is_rome_style(uint_t id)
{
	return (id == 0x1490 || id == 0x1650);
}

/*
 * Initialize our knowledge about a given series of nodes on the data fabric.
 */
static void
amdzen_setup_df(amdzen_t *azn, amdzen_df_t *df)
{
	uint_t i;
	uint32_t val;

	val = amdzen_stub_get32(df->adf_funcs[0], AMDZEN_DF_F0_CFG_ADDR_CTL);
	df->adf_nb_busno = AMDZEN_DF_F0_CFG_ADDR_CTL_BUS_NUM(val);
	val = amdzen_stub_get32(df->adf_funcs[0], AMDZEN_DF_F0_FBICNT);
	df->adf_nents = AMDZEN_DF_F0_FBICNT_COUNT(val);
	if (df->adf_nents == 0)
		return;
	df->adf_ents = kmem_zalloc(sizeof (amdzen_df_ent_t) * df->adf_nents,
	    KM_SLEEP);

	for (i = 0; i < df->adf_nents; i++) {
		amdzen_df_ent_t *dfe = &df->adf_ents[i];
		uint8_t inst = i;

		/*
		 * Unfortunately, Rome uses a discontinuous instance ID pattern
		 * while everything else we can find uses a contiguous instance
		 * ID pattern.  This means that for Rome, we need to adjust the
		 * indexes that we iterate over, though the total number of
		 * entries is right.
		 */
		if (amdzen_is_rome_style(df->adf_funcs[0]->azns_did)) {
			if (inst > ARRAY_SIZE(amdzen_df_rome_ids)) {
				dev_err(azn->azn_dip, CE_WARN, "Rome family "
				    "processor reported more ids than the PPR, "
				    "resetting %u to instance zero", inst);
				inst = 0;
			} else {
				inst = amdzen_df_rome_ids[inst];
			}
		}

		dfe->adfe_drvid = inst;
		dfe->adfe_info0 = amdzen_df_read32(azn, df, inst, 0,
		    AMDZEN_DF_F0_FBIINFO0);
		dfe->adfe_info1 = amdzen_df_read32(azn, df, inst, 0,
		    AMDZEN_DF_F0_FBIINFO1);
		dfe->adfe_info2 = amdzen_df_read32(azn, df, inst, 0,
		    AMDZEN_DF_F0_FBIINFO2);
		dfe->adfe_info3 = amdzen_df_read32(azn, df, inst, 0,
		    AMDZEN_DF_F0_FBIINFO3);
		dfe->adfe_syscfg = amdzen_df_read32(azn, df, inst, 1,
		    AMDZEN_DF_F1_SYSCFG);
		dfe->adfe_mask0 = amdzen_df_read32(azn, df, inst, 1,
		    AMDZEN_DF_F1_FIDMASK0);
		dfe->adfe_mask1 = amdzen_df_read32(azn, df, inst, 1,
		    AMDZEN_DF_F1_FIDMASK1);

		dfe->adfe_type = AMDZEN_DF_F0_FBIINFO0_TYPE(dfe->adfe_info0);
		dfe->adfe_sdp_width =
		    AMDZEN_DF_F0_FBIINFO0_SDP_WIDTH(dfe->adfe_info0);
		if (AMDZEN_DF_F0_FBIINFO0_ENABLED(dfe->adfe_info0)) {
			dfe->adfe_flags |= AMDZEN_DFE_F_ENABLED;
		}
		dfe->adfe_fti_width =
		    AMDZEN_DF_F0_FBIINFO0_FTI_WIDTH(dfe->adfe_info0);
		dfe->adfe_sdp_count =
		    AMDZEN_DF_F0_FBIINFO0_SDP_PCOUNT(dfe->adfe_info0);
		dfe->adfe_fti_count =
		    AMDZEN_DF_F0_FBIINFO0_FTI_PCOUNT(dfe->adfe_info0);
		if (AMDZEN_DF_F0_FBIINFO0_HAS_MCA(dfe->adfe_info0)) {
			dfe->adfe_flags |= AMDZEN_DFE_F_MCA;
		}
		dfe->adfe_subtype =
		    AMDZEN_DF_F0_FBIINFO0_SUBTYPE(dfe->adfe_info0);

		dfe->adfe_inst_id =
		    AMDZEN_DF_F0_FBIINFO3_INSTID(dfe->adfe_info3);
		dfe->adfe_fabric_id =
		    AMDZEN_DF_F0_FBIINFO3_FABID(dfe->adfe_info3);
	}

	df->adf_syscfg = amdzen_stub_get32(df->adf_funcs[1],
	    AMDZEN_DF_F1_SYSCFG);
	df->adf_nodeid = AMDZEN_DF_F1_SYSCFG_NODEID(df->adf_syscfg);
	df->adf_mask0 = amdzen_stub_get32(df->adf_funcs[1],
	    AMDZEN_DF_F1_FIDMASK0);
	df->adf_mask1 = amdzen_stub_get32(df->adf_funcs[1],
	    AMDZEN_DF_F1_FIDMASK1);
}

static void
amdzen_find_nb(amdzen_t *azn, amdzen_df_t *df)
{
	amdzen_stub_t *stub;

	for (stub = list_head(&azn->azn_nb_stubs); stub != NULL;
	    stub = list_next(&azn->azn_nb_stubs, stub)) {
		if (stub->azns_bus == df->adf_nb_busno) {
			df->adf_flags |= AMDZEN_DF_F_FOUND_NB;
			df->adf_nb = stub;
			return;
		}
	}
}

static void
amdzen_nexus_init(void *arg)
{
	uint_t i;
	amdzen_t *azn = arg;

	/*
	 * First go through all of the stubs and assign the DF entries.
	 */
	mutex_enter(&azn->azn_mutex);
	if (!amdzen_map_dfs(azn) || !amdzen_check_dfs(azn)) {
		azn->azn_flags |= AMDZEN_F_MAP_ERROR;
		goto done;
	}

	for (i = 0; i < AMDZEN_MAX_DFS; i++) {
		amdzen_df_t *df = &azn->azn_dfs[i];

		if ((df->adf_flags & AMDZEN_DF_F_VALID) == 0)
			continue;
		amdzen_setup_df(azn, df);
		amdzen_find_nb(azn, df);
	}

	/*
	 * Not all children may be installed. As such, we do not treat the
	 * failure of a child as fatal to the driver.
	 */
	mutex_exit(&azn->azn_mutex);
	for (i = 0; i < ARRAY_SIZE(amdzen_children); i++) {
		(void) amdzen_create_child(azn, &amdzen_children[i]);
	}
	mutex_enter(&azn->azn_mutex);

done:
	azn->azn_flags &= ~AMDZEN_F_ATTACH_DISPATCHED;
	azn->azn_flags |= AMDZEN_F_ATTACH_COMPLETE;
	azn->azn_taskqid = TASKQID_INVALID;
	cv_broadcast(&azn->azn_cv);
	mutex_exit(&azn->azn_mutex);
}

static int
amdzen_stub_scan_cb(dev_info_t *dip, void *arg)
{
	amdzen_t *azn = arg;
	uint16_t vid, did;
	int *regs;
	uint_t nregs, i;
	boolean_t match = B_FALSE;

	if (dip == ddi_root_node()) {
		return (DDI_WALK_CONTINUE);
	}

	/*
	 * If a node in question is not a pci node, then we have no interest in
	 * it as all the stubs that we care about are related to pci devices.
	 */
	if (strncmp("pci", ddi_get_name(dip), 3) != 0) {
		return (DDI_WALK_PRUNECHILD);
	}

	/*
	 * If we can't get a device or vendor ID and prove that this is an AMD
	 * part, then we don't care about it.
	 */
	vid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", PCI_EINVAL16);
	did = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", PCI_EINVAL16);
	if (vid == PCI_EINVAL16 || did == PCI_EINVAL16) {
		return (DDI_WALK_CONTINUE);
	}

	if (vid != AMDZEN_PCI_VID_AMD && vid != AMDZEN_PCI_VID_HYGON) {
		return (DDI_WALK_CONTINUE);
	}

	for (i = 0; i < ARRAY_SIZE(amdzen_nb_ids); i++) {
		if (amdzen_nb_ids[i] == did) {
			match = B_TRUE;
		}
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &regs, &nregs) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_CONTINUE);
	}

	if (nregs == 0) {
		ddi_prop_free(regs);
		return (DDI_WALK_CONTINUE);
	}

	if (PCI_REG_BUS_G(regs[0]) == AMDZEN_DF_BUSNO &&
	    PCI_REG_DEV_G(regs[0]) >= AMDZEN_DF_FIRST_DEVICE) {
		match = B_TRUE;
	}

	ddi_prop_free(regs);
	if (match) {
		mutex_enter(&azn->azn_mutex);
		azn->azn_nscanned++;
		mutex_exit(&azn->azn_mutex);
	}

	return (DDI_WALK_CONTINUE);
}

static void
amdzen_stub_scan(void *arg)
{
	amdzen_t *azn = arg;

	mutex_enter(&azn->azn_mutex);
	azn->azn_nscanned = 0;
	mutex_exit(&azn->azn_mutex);

	ddi_walk_devs(ddi_root_node(), amdzen_stub_scan_cb, azn);

	mutex_enter(&azn->azn_mutex);
	azn->azn_flags &= ~AMDZEN_F_SCAN_DISPATCHED;
	azn->azn_flags |= AMDZEN_F_SCAN_COMPLETE;

	if (azn->azn_nscanned == 0) {
		azn->azn_flags |= AMDZEN_F_UNSUPPORTED;
		azn->azn_taskqid = TASKQID_INVALID;
		cv_broadcast(&azn->azn_cv);
	} else if (azn->azn_npresent == azn->azn_nscanned) {
		azn->azn_flags |= AMDZEN_F_ATTACH_DISPATCHED;
		azn->azn_taskqid = taskq_dispatch(system_taskq,
		    amdzen_nexus_init, azn, TQ_SLEEP);
	}
	mutex_exit(&azn->azn_mutex);
}

/*
 * Unfortunately we can't really let the stubs detach as we may need them to be
 * available for client operations. We may be able to improve this if we know
 * that the actual nexus is going away. However, as long as it's active, we need
 * all the stubs.
 */
int
amdzen_detach_stub(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

int
amdzen_attach_stub(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int *regs, reg;
	uint_t nregs, i;
	uint16_t vid, did;
	amdzen_stub_t *stub;
	amdzen_t *azn = amdzen_data;
	boolean_t valid = B_FALSE;
	boolean_t nb = B_FALSE;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/*
	 * Make sure that the stub that we've been asked to attach is a pci type
	 * device. If not, then there is no reason for us to proceed.
	 */
	if (strncmp("pci", ddi_get_name(dip), 3) != 0) {
		dev_err(dip, CE_WARN, "asked to attach a bad AMD Zen nexus "
		    "stub: %s", ddi_get_name(dip));
		return (DDI_FAILURE);
	}
	vid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", PCI_EINVAL16);
	did = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", PCI_EINVAL16);
	if (vid == PCI_EINVAL16 || did == PCI_EINVAL16) {
		dev_err(dip, CE_WARN, "failed to get PCI ID properties");
		return (DDI_FAILURE);
	}

	if (vid != AMDZEN_PCI_VID_AMD && vid != AMDZEN_PCI_VID_HYGON) {
		dev_err(dip, CE_WARN, "expected vendor ID (0x%x), found 0x%x",
		    cpuid_getvendor(CPU) == X86_VENDOR_HYGON ?
		    AMDZEN_PCI_VID_HYGON : AMDZEN_PCI_VID_AMD, vid);
		return (DDI_FAILURE);
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &regs, &nregs) != DDI_PROP_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to get 'reg' property");
		return (DDI_FAILURE);
	}

	if (nregs == 0) {
		ddi_prop_free(regs);
		dev_err(dip, CE_WARN, "missing 'reg' property values");
		return (DDI_FAILURE);
	}
	reg = *regs;
	ddi_prop_free(regs);

	for (i = 0; i < ARRAY_SIZE(amdzen_nb_ids); i++) {
		if (amdzen_nb_ids[i] == did) {
			valid = B_TRUE;
			nb = B_TRUE;
		}
	}

	if (!valid && PCI_REG_BUS_G(reg) == AMDZEN_DF_BUSNO &&
	    PCI_REG_DEV_G(reg) >= AMDZEN_DF_FIRST_DEVICE) {
		valid = B_TRUE;
		nb = B_FALSE;
	}

	if (!valid) {
		dev_err(dip, CE_WARN, "device %s didn't match the nexus list",
		    ddi_get_name(dip));
		return (DDI_FAILURE);
	}

	stub = kmem_alloc(sizeof (amdzen_stub_t), KM_SLEEP);
	if (pci_config_setup(dip, &stub->azns_cfgspace) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to set up config space");
		kmem_free(stub, sizeof (amdzen_stub_t));
		return (DDI_FAILURE);
	}

	stub->azns_dip = dip;
	stub->azns_vid = vid;
	stub->azns_did = did;
	stub->azns_bus = PCI_REG_BUS_G(reg);
	stub->azns_dev = PCI_REG_DEV_G(reg);
	stub->azns_func = PCI_REG_FUNC_G(reg);
	ddi_set_driver_private(dip, stub);

	mutex_enter(&azn->azn_mutex);
	azn->azn_npresent++;
	if (nb) {
		list_insert_tail(&azn->azn_nb_stubs, stub);
	} else {
		list_insert_tail(&azn->azn_df_stubs, stub);
	}

	if ((azn->azn_flags & AMDZEN_F_TASKQ_MASK) == AMDZEN_F_SCAN_COMPLETE &&
	    azn->azn_nscanned == azn->azn_npresent) {
		azn->azn_flags |= AMDZEN_F_ATTACH_DISPATCHED;
		azn->azn_taskqid = taskq_dispatch(system_taskq,
		    amdzen_nexus_init, azn, TQ_SLEEP);
	}
	mutex_exit(&azn->azn_mutex);

	return (DDI_SUCCESS);
}

static int
amdzen_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	char buf[32];
	dev_info_t *child;
	const amdzen_child_data_t *acd;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL) {
			return (DDI_FAILURE);
		}
		cmn_err(CE_CONT, "amdzen nexus: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		break;
	case DDI_CTLOPS_INITCHILD:
		child = arg;
		if (child == NULL) {
			dev_err(dip, CE_WARN, "!no child passed for "
			    "DDI_CTLOPS_INITCHILD");
		}

		acd = ddi_get_parent_data(child);
		if (acd == NULL) {
			dev_err(dip, CE_WARN, "!missing child parent data");
			return (DDI_FAILURE);
		}

		if (snprintf(buf, sizeof (buf), "%d", acd->acd_addr) >=
		    sizeof (buf)) {
			dev_err(dip, CE_WARN, "!failed to construct device "
			    "addr due to overflow");
			return (DDI_FAILURE);
		}

		ddi_set_name_addr(child, buf);
		break;
	case DDI_CTLOPS_UNINITCHILD:
		child = arg;
		if (child == NULL) {
			dev_err(dip, CE_WARN, "!no child passed for "
			    "DDI_CTLOPS_UNINITCHILD");
		}

		ddi_set_name_addr(child, NULL);
		break;
	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
	return (DDI_SUCCESS);
}

static int
amdzen_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	amdzen_t *azn = amdzen_data;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	mutex_enter(&azn->azn_mutex);
	if (azn->azn_dip != NULL) {
		dev_err(dip, CE_WARN, "driver is already attached!");
		mutex_exit(&azn->azn_mutex);
		return (DDI_FAILURE);
	}

	azn->azn_dip = dip;
	azn->azn_taskqid = taskq_dispatch(system_taskq, amdzen_stub_scan,
	    azn, TQ_SLEEP);
	azn->azn_flags |= AMDZEN_F_SCAN_DISPATCHED;
	mutex_exit(&azn->azn_mutex);

	return (DDI_SUCCESS);
}

static int
amdzen_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	amdzen_t *azn = amdzen_data;

	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	mutex_enter(&azn->azn_mutex);
	while (azn->azn_taskqid != TASKQID_INVALID) {
		cv_wait(&azn->azn_cv, &azn->azn_mutex);
	}

	/*
	 * If we've attached any stub drivers, e.g. this platform is important
	 * for us, then we fail detach.
	 */
	if (!list_is_empty(&azn->azn_df_stubs) ||
	    !list_is_empty(&azn->azn_nb_stubs)) {
		mutex_exit(&azn->azn_mutex);
		return (DDI_FAILURE);
	}

	azn->azn_dip = NULL;
	mutex_exit(&azn->azn_mutex);

	return (DDI_SUCCESS);
}

static void
amdzen_free(void)
{
	if (amdzen_data == NULL) {
		return;
	}

	VERIFY(list_is_empty(&amdzen_data->azn_df_stubs));
	list_destroy(&amdzen_data->azn_df_stubs);
	VERIFY(list_is_empty(&amdzen_data->azn_nb_stubs));
	list_destroy(&amdzen_data->azn_nb_stubs);
	cv_destroy(&amdzen_data->azn_cv);
	mutex_destroy(&amdzen_data->azn_mutex);
	kmem_free(amdzen_data, sizeof (amdzen_t));
	amdzen_data = NULL;
}

static void
amdzen_alloc(void)
{
	amdzen_data = kmem_zalloc(sizeof (amdzen_t), KM_SLEEP);
	mutex_init(&amdzen_data->azn_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&amdzen_data->azn_df_stubs, sizeof (amdzen_stub_t),
	    offsetof(amdzen_stub_t, azns_link));
	list_create(&amdzen_data->azn_nb_stubs, sizeof (amdzen_stub_t),
	    offsetof(amdzen_stub_t, azns_link));
	cv_init(&amdzen_data->azn_cv, NULL, CV_DRIVER, NULL);
}

struct bus_ops amdzen_bus_ops = {
	.busops_rev = BUSO_REV,
	.bus_map = nullbusmap,
	.bus_dma_map = ddi_no_dma_map,
	.bus_dma_allochdl = ddi_no_dma_allochdl,
	.bus_dma_freehdl = ddi_no_dma_freehdl,
	.bus_dma_bindhdl = ddi_no_dma_bindhdl,
	.bus_dma_unbindhdl = ddi_no_dma_unbindhdl,
	.bus_dma_flush = ddi_no_dma_flush,
	.bus_dma_win = ddi_no_dma_win,
	.bus_dma_ctl = ddi_no_dma_mctl,
	.bus_prop_op = ddi_bus_prop_op,
	.bus_ctl = amdzen_bus_ctl
};

static struct dev_ops amdzen_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nodev,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = amdzen_attach,
	.devo_detach = amdzen_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_bus_ops = &amdzen_bus_ops
};

static struct modldrv amdzen_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AMD Zen Nexus Driver",
	.drv_dev_ops = &amdzen_dev_ops
};

static struct modlinkage amdzen_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &amdzen_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	if (cpuid_getvendor(CPU) != X86_VENDOR_AMD &&
	    cpuid_getvendor(CPU) != X86_VENDOR_HYGON) {
		return (ENOTSUP);
	}

	if ((ret = mod_install(&amdzen_modlinkage)) == 0) {
		amdzen_alloc();
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&amdzen_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&amdzen_modlinkage)) == 0) {
		amdzen_free();
	}

	return (ret);
}
