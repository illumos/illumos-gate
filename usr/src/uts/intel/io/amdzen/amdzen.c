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
 * Copyright 2023 Oxide Computer Company
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
 * configuration registers in terms of things that are meaningful to the system
 * such as logical CPUs, cores, etc. This driver attaches to the PCI devices
 * that represent the northbridge, data fabrics, and dies. Note that there are
 * multiple northbridge and DF devices (one each per die) and this driver maps
 * all of these three things together. Unfortunately, this requires some
 * acrobatics as there is no direct way to map a northbridge to its
 * corresponding die. Instead, we map a CPU die to a data fabric PCI device and
 * a data fabric PCI device to a corresponding northbridge PCI device. This
 * transitive relationship allows us to map from between northbridge and die.
 *
 * As each data fabric device is attached, based on vendor and device portions
 * of the PCI ID, we add it to the DF stubs list in the global amdzen_t
 * structure, amdzen_data->azn_df_stubs. We must now map these to logical CPUs.
 *
 * In current Zen based products, there is a direct mapping between processor
 * nodes and a data fabric PCI device: all of the devices are on PCI Bus 0 and
 * start from Device 0x18, so device 0x18 maps to processor node 0, 0x19 to
 * processor node 1, etc. This means that to map a logical CPU to a data fabric
 * device, we take its processor node id, add it to 0x18 and find the PCI device
 * that is on bus 0 with that ID number. We already discovered the DF devices as
 * described above.
 *
 * The northbridge PCI device has a well-defined device and function, but the
 * bus that it is on varies. Each die has its own set of assigned PCI buses and
 * its northbridge device is on the first die-specific bus. This implies that
 * the northbridges do not show up on PCI bus 0, as that is the PCI bus that all
 * of the data fabric devices are on and is not assigned to any particular die.
 * Additionally, while the northbridge on the lowest-numbered PCI bus
 * intuitively corresponds to processor node zero, hardware does not guarantee
 * this. Because we don't want to be at the mercy of firmware, we don't rely on
 * this ordering assumption, though we have yet to find a system that deviates
 * from it, either.
 *
 * One of the registers in the data fabric device's function 0
 * (AMDZEN_DF_F0_CFG_ADDR_CTL) happens to identify the first PCI bus that is
 * associated with the processor node. This means that we can map a data fabric
 * device to a northbridge by finding the northbridge whose PCI bus ID matches
 * the value in the corresponding data fabric's AMDZEN_DF_F0_CFG_ADDR_CTL.
 *
 * Given all of the above, we can map a northbridge to a data fabric device and
 * a die to a data fabric device. Because these are 1:1 mappings, there is a
 * transitive relationship from northbridge to die. and therefore we know which
 * northbridge is associated with which processor die. This is summarized in the
 * following image:
 *
 *  +-------+     +------------------------------------+     +--------------+
 *  | Die 0 |---->| Data Fabric PCI BDF 0/18/0         |---->| Northbridge  |
 *  +-------+     | AMDZEN_DF_F0_CFG_ADDR_CTL: bus 10  |     | PCI  10/0/0  |
 *     ...        +------------------------------------+     +--------------+
 *  +-------+     +------------------------------------+     +--------------+
 *  | Die n |---->| Data Fabric PCI BDF 0/18+n/0       |---->| Northbridge  |
 *  +-------+     | AMDZEN_DF_F0_CFG_ADDR_CTL: bus 133 |     | PCI 133/0/0  |
 *                +------------------------------------+     +--------------+
 *
 * Note, the PCI buses used by the northbridges here are arbitrary examples that
 * do not necessarily reflect actual hardware values; however, the
 * bus/device/function (BDF) of the data fabric accurately models hardware. All
 * BDF values are in hex.
 *
 * Starting with the Rome generation of processors (Family 17h Model 30-3Fh),
 * AMD has multiple northbridges on a given die. All of these northbridges share
 * the same data fabric and system management network port. From our perspective
 * this means that some of the northbridge devices will be redundant and that we
 * no longer have a 1:1 mapping between the northbridge and the data fabric
 * devices. Every data fabric will have a northbridge, but not every northbridge
 * will have a data fabric device mapped. Because we're always trying to map
 * from a die to a northbridge and not the reverse, the fact that there are
 * extra northbridge devices hanging around that we don't know about shouldn't
 * be a problem.
 *
 * -------------------------------
 * Attach and Detach Complications
 * -------------------------------
 *
 * We need to map different PCI devices together. Each device is attached to a
 * amdzen_stub driver to facilitate integration with the rest of the kernel PCI
 * machinery and so we have to manage multiple dev_info_t structures, each of
 * which may be independently attached and detached.
 *
 * This is not particularly complex for attach: our _init routine allocates the
 * necessary mutex and list structures at module load time, and as each stub is
 * attached, it calls into this code to be added to the appropriate list. When
 * the nexus itself is attached, we walk the PCI device tree accumulating a
 * counter for all devices we expect to be attached. Once the scan is complete
 * and all such devices are accounted for (stub registration may be happening
 * asynchronously with respect to nexus attach), we initialize the nexus device
 * and the attach is complete.
 *
 * Most other device drivers support instances that can be brought back after
 * detach, provided they are associated with an active minor node in the
 * /devices file system. This driver is different. Once a stub device has been
 * attached, we do not permit detaching the nexus driver instance, as the kernel
 * does not give us interlocking guarantees between nexus and stub driver attach
 * and detach. It is simplest to just unconditionally fail detach once a stub
 * has attached.
 *
 * ---------------
 * Exposed Devices
 * ---------------
 *
 * Rather than try and have all of the different functions that could be
 * provided in one driver, we have a nexus driver that tries to load child
 * pseudo-device drivers that provide specific pieces of functionality.
 *
 * -------
 * Locking
 * -------
 *
 * The amdzen_data structure contains a single lock, azn_mutex.
 *
 * The various client functions here are intended for our nexus's direct
 * children, but have been designed in case someone else should depends on this
 * driver. Once a DF has been discovered, the set of entities inside of it
 * (adf_nents, adf_ents[]) is considered static, constant data, and iteration
 * over them does not require locking. However, the discovery of the amd_df_t
 * does. In addition, locking is required whenever performing register accesses
 * to the DF or SMN.
 *
 * To summarize, one must hold the lock in the following circumstances:
 *
 *  - Looking up DF structures
 *  - Reading or writing to DF registers
 *  - Reading or writing to SMN registers
 *
 * In general, it is preferred that the lock be held across an entire client
 * operation if possible. The only time this becomes an issue are when we have
 * callbacks into our callers (ala amdzen_c_df_iter()) as they may recursively
 * call into us.
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

#include <sys/amdzen/df.h>
#include "amdzen_client.h"
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
	/* Family 17h/19h Renoir, Cezanne, Van Gogh Zen 2/3 uarch */
	0x1630,
	/* Family 19h Genoa and Bergamo */
	0x14a4,
	/* Family 17h Mendocino, Family 19h Rembrandt */
	0x14b5,
	/* Family 19h Raphael */
	0x14d8,
	/* Family 19h Phoenix */
	0x14e8
};

typedef struct {
	char *acd_name;
	amdzen_child_t acd_addr;
} amdzen_child_data_t;

static const amdzen_child_data_t amdzen_children[] = {
	{ "smntemp", AMDZEN_C_SMNTEMP },
	{ "usmn", AMDZEN_C_USMN },
	{ "zen_udf", AMDZEN_C_ZEN_UDF },
	{ "zen_umc", AMDZEN_C_ZEN_UMC }
};

static uint8_t
amdzen_stub_get8(amdzen_stub_t *stub, off_t reg)
{
	return (pci_config_get8(stub->azns_cfgspace, reg));
}

static uint16_t
amdzen_stub_get16(amdzen_stub_t *stub, off_t reg)
{
	return (pci_config_get16(stub->azns_cfgspace, reg));
}

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
amdzen_stub_put8(amdzen_stub_t *stub, off_t reg, uint8_t val)
{
	pci_config_put8(stub->azns_cfgspace, reg, val);
}

static void
amdzen_stub_put16(amdzen_stub_t *stub, off_t reg, uint16_t val)
{
	pci_config_put16(stub->azns_cfgspace, reg, val);
}

static void
amdzen_stub_put32(amdzen_stub_t *stub, off_t reg, uint32_t val)
{
	pci_config_put32(stub->azns_cfgspace, reg, val);
}

static uint64_t
amdzen_df_read_regdef(amdzen_t *azn, amdzen_df_t *df, const df_reg_def_t def,
    uint8_t inst, boolean_t do_64)
{
	df_reg_def_t ficaa;
	df_reg_def_t ficad;
	uint32_t val = 0;
	df_rev_t df_rev = azn->azn_dfs[0].adf_rev;

	VERIFY(MUTEX_HELD(&azn->azn_mutex));
	ASSERT3U(def.drd_gens & df_rev, ==, df_rev);
	val = DF_FICAA_V2_SET_TARG_INST(val, 1);
	val = DF_FICAA_V2_SET_FUNC(val, def.drd_func);
	val = DF_FICAA_V2_SET_INST(val, inst);
	val = DF_FICAA_V2_SET_64B(val, do_64 ? 1 : 0);

	switch (df_rev) {
	case DF_REV_2:
	case DF_REV_3:
	case DF_REV_3P5:
		ficaa = DF_FICAA_V2;
		ficad = DF_FICAD_LO_V2;
		/*
		 * Both here and in the DFv4 case, the register ignores the
		 * lower 2 bits. That is we can only address and encode things
		 * in units of 4 bytes.
		 */
		val = DF_FICAA_V2_SET_REG(val, def.drd_reg >> 2);
		break;
	case DF_REV_4:
		ficaa = DF_FICAA_V4;
		ficad = DF_FICAD_LO_V4;
		val = DF_FICAA_V4_SET_REG(val, def.drd_reg >> 2);
		break;
	default:
		panic("encountered unexpected DF rev: %u", df_rev);
	}

	amdzen_stub_put32(df->adf_funcs[ficaa.drd_func], ficaa.drd_reg, val);
	if (do_64) {
		return (amdzen_stub_get64(df->adf_funcs[ficad.drd_func],
		    ficad.drd_reg));
	} else {
		return (amdzen_stub_get32(df->adf_funcs[ficad.drd_func],
		    ficad.drd_reg));
	}
}

/*
 * Perform a targeted 32-bit indirect read to a specific instance and function.
 */
static uint32_t
amdzen_df_read32(amdzen_t *azn, amdzen_df_t *df, uint8_t inst,
    const df_reg_def_t def)
{
	return (amdzen_df_read_regdef(azn, df, def, inst, B_FALSE));
}

/*
 * For a broadcast read, just go to the underlying PCI function and perform a
 * read. At this point in time, we don't believe we need to use the FICAA/FICAD
 * to access it (though it does have a broadcast mode).
 */
static uint32_t
amdzen_df_read32_bcast(amdzen_t *azn, amdzen_df_t *df, const df_reg_def_t def)
{
	VERIFY(MUTEX_HELD(&azn->azn_mutex));
	return (amdzen_stub_get32(df->adf_funcs[def.drd_func], def.drd_reg));
}

static uint32_t
amdzen_smn_read(amdzen_t *azn, amdzen_df_t *df, const smn_reg_t reg)
{
	const uint32_t base_addr = SMN_REG_ADDR_BASE(reg);
	const uint32_t addr_off = SMN_REG_ADDR_OFF(reg);

	VERIFY(SMN_REG_IS_NATURALLY_ALIGNED(reg));
	VERIFY(MUTEX_HELD(&azn->azn_mutex));
	amdzen_stub_put32(df->adf_nb, AMDZEN_NB_SMN_ADDR, base_addr);

	switch (SMN_REG_SIZE(reg)) {
	case 1:
		return ((uint32_t)amdzen_stub_get8(df->adf_nb,
		    AMDZEN_NB_SMN_DATA + addr_off));
	case 2:
		return ((uint32_t)amdzen_stub_get16(df->adf_nb,
		    AMDZEN_NB_SMN_DATA + addr_off));
	case 4:
		return (amdzen_stub_get32(df->adf_nb, AMDZEN_NB_SMN_DATA));
	default:
		panic("unreachable invalid SMN register size %u",
		    SMN_REG_SIZE(reg));
	}
}

static void
amdzen_smn_write(amdzen_t *azn, amdzen_df_t *df, const smn_reg_t reg,
    const uint32_t val)
{
	const uint32_t base_addr = SMN_REG_ADDR_BASE(reg);
	const uint32_t addr_off = SMN_REG_ADDR_OFF(reg);

	VERIFY(SMN_REG_IS_NATURALLY_ALIGNED(reg));
	VERIFY(SMN_REG_VALUE_FITS(reg, val));
	VERIFY(MUTEX_HELD(&azn->azn_mutex));
	amdzen_stub_put32(df->adf_nb, AMDZEN_NB_SMN_ADDR, base_addr);

	switch (SMN_REG_SIZE(reg)) {
	case 1:
		amdzen_stub_put8(df->adf_nb, AMDZEN_NB_SMN_DATA + addr_off,
		    (uint8_t)val);
		break;
	case 2:
		amdzen_stub_put16(df->adf_nb, AMDZEN_NB_SMN_DATA + addr_off,
		    (uint16_t)val);
		break;
	case 4:
		amdzen_stub_put32(df->adf_nb, AMDZEN_NB_SMN_DATA, val);
		break;
	default:
		panic("unreachable invalid SMN register size %u",
		    SMN_REG_SIZE(reg));
	}
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
amdzen_c_smn_read(uint_t dfno, const smn_reg_t reg, uint32_t *valp)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;

	if (!SMN_REG_SIZE_IS_VALID(reg))
		return (EINVAL);
	if (!SMN_REG_IS_NATURALLY_ALIGNED(reg))
		return (EINVAL);

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

	*valp = amdzen_smn_read(azn, df, reg);
	mutex_exit(&azn->azn_mutex);
	return (0);
}

int
amdzen_c_smn_write(uint_t dfno, const smn_reg_t reg, const uint32_t val)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;

	if (!SMN_REG_SIZE_IS_VALID(reg))
		return (EINVAL);
	if (!SMN_REG_IS_NATURALLY_ALIGNED(reg))
		return (EINVAL);
	if (!SMN_REG_VALUE_FITS(reg, val))
		return (EOVERFLOW);

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

	amdzen_smn_write(azn, df, reg, val);
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

df_rev_t
amdzen_c_df_rev(void)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;
	df_rev_t rev;

	/*
	 * Always use the first DF instance to determine what we're using. Our
	 * current assumption, which seems to generally be true, is that the
	 * given DF revisions are the same in a given system when the DFs are
	 * directly connected.
	 */
	mutex_enter(&azn->azn_mutex);
	df = amdzen_df_find(azn, 0);
	if (df == NULL) {
		rev = DF_REV_UNKNOWN;
	} else {
		rev = df->adf_rev;
	}
	mutex_exit(&azn->azn_mutex);

	return (rev);
}

int
amdzen_c_df_read32(uint_t dfno, uint8_t inst, const df_reg_def_t def,
    uint32_t *valp)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;

	mutex_enter(&azn->azn_mutex);
	df = amdzen_df_find(azn, dfno);
	if (df == NULL) {
		mutex_exit(&azn->azn_mutex);
		return (ENOENT);
	}

	*valp = amdzen_df_read_regdef(azn, df, def, inst, B_FALSE);
	mutex_exit(&azn->azn_mutex);

	return (0);
}

int
amdzen_c_df_read64(uint_t dfno, uint8_t inst, const df_reg_def_t def,
    uint64_t *valp)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;

	mutex_enter(&azn->azn_mutex);
	df = amdzen_df_find(azn, dfno);
	if (df == NULL) {
		mutex_exit(&azn->azn_mutex);
		return (ENOENT);
	}

	*valp = amdzen_df_read_regdef(azn, df, def, inst, B_TRUE);
	mutex_exit(&azn->azn_mutex);

	return (0);
}

int
amdzen_c_df_iter(uint_t dfno, zen_df_type_t type, amdzen_c_iter_f func,
    void *arg)
{
	amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;
	df_type_t df_type;
	uint8_t df_subtype;

	/*
	 * Unlike other calls here, we hold our lock only to find the DF here.
	 * The main reason for this is the nature of the callback function.
	 * Folks are iterating over instances so they can call back into us. If
	 * you look at the locking statement, the thing that is most volatile
	 * right here and what we need to protect is the DF itself and
	 * subsequent register accesses to it. The actual data about which
	 * entities exist is static and so once we have found a DF we should
	 * hopefully be in good shape as they only come, but don't go.
	 */
	mutex_enter(&azn->azn_mutex);
	df = amdzen_df_find(azn, dfno);
	if (df == NULL) {
		mutex_exit(&azn->azn_mutex);
		return (ENOENT);
	}
	mutex_exit(&azn->azn_mutex);

	switch (type) {
	case ZEN_DF_TYPE_CS_UMC:
		df_type = DF_TYPE_CS;
		/*
		 * In the original Zeppelin DFv2 die there was no subtype field
		 * used for the CS. The UMC is the only type and has a subtype
		 * of zero.
		 */
		if (df->adf_rev != DF_REV_2) {
			df_subtype = DF_CS_SUBTYPE_UMC;
		} else {
			df_subtype = 0;
		}
		break;
	case ZEN_DF_TYPE_CCM_CPU:
		/*
		 * While the wording of the PPR is a little weird, the CCM still
		 * has subtype 0 in DFv4 systems; however, what's said to be for
		 * the CPU appears to apply to the ACM.
		 */
		df_type = DF_TYPE_CCM;
		df_subtype = 0;
		break;
	default:
		return (EINVAL);
	}

	for (uint_t i = 0; i < df->adf_nents; i++) {
		amdzen_df_ent_t *ent = &df->adf_ents[i];

		/*
		 * Some DF components are not considered enabled and therefore
		 * will end up having bogus values in their ID fields. If we do
		 * not have an enable flag set, we must skip this node.
		 */
		if ((ent->adfe_flags & AMDZEN_DFE_F_ENABLED) == 0)
			continue;

		if (ent->adfe_type == df_type &&
		    ent->adfe_subtype == df_subtype) {
			int ret = func(dfno, ent->adfe_fabric_id,
			    ent->adfe_inst_id, arg);
			if (ret != 0) {
				return (ret);
			}
		}
	}

	return (0);
}

int
amdzen_c_df_fabric_decomp(df_fabric_decomp_t *decomp)
{
	const amdzen_df_t *df;
	amdzen_t *azn = amdzen_data;

	mutex_enter(&azn->azn_mutex);
	df = amdzen_df_find(azn, 0);
	if (df == NULL) {
		mutex_exit(&azn->azn_mutex);
		return (ENOENT);
	}

	*decomp = df->adf_decomp;
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
 * To be able to do most other things we want to do, we must first determine
 * what revision of the DF (data fabric) that we're using.
 *
 * Snapshot the df version. This was added explicitly in DFv4.0, around the Zen
 * 4 timeframe and allows us to tell apart different version of the DF register
 * set, most usefully when various subtypes were added.
 *
 * Older versions can theoretically be told apart based on usage of reserved
 * registers. We walk these in the following order, starting with the newest rev
 * and walking backwards to tell things apart:
 *
 *   o v3.5 -> Check function 1, register 0x150. This was reserved prior
 *             to this point. This is actually DF_FIDMASK0_V3P5. We are supposed
 *             to check bits [7:0].
 *
 *   o v3.0 -> Check function 1, register 0x208. The low byte (7:0) was
 *             changed to indicate a component mask. This is non-zero
 *             in the 3.0 generation. This is actually DF_FIDMASK_V2.
 *
 *   o v2.0 -> This is just the not that case. Presumably v1 wasn't part
 *             of the Zen generation.
 *
 * Because we don't know what version we are yet, we do not use the normal
 * versioned register accesses which would check what DF version we are and
 * would want to use the normal indirect register accesses (which also require
 * us to know the version). We instead do direct broadcast reads.
 */
static void
amdzen_determine_df_vers(amdzen_t *azn, amdzen_df_t *df)
{
	uint32_t val;
	df_reg_def_t rd = DF_FBICNT;

	val = amdzen_stub_get32(df->adf_funcs[rd.drd_func], rd.drd_reg);
	df->adf_major = DF_FBICNT_V4_GET_MAJOR(val);
	df->adf_minor = DF_FBICNT_V4_GET_MINOR(val);
	if (df->adf_major == 0 && df->adf_minor == 0) {
		rd = DF_FIDMASK0_V3P5;
		val = amdzen_stub_get32(df->adf_funcs[rd.drd_func], rd.drd_reg);
		if (bitx32(val, 7, 0) != 0) {
			df->adf_major = 3;
			df->adf_minor = 5;
			df->adf_rev = DF_REV_3P5;
		} else {
			rd = DF_FIDMASK_V2;
			val = amdzen_stub_get32(df->adf_funcs[rd.drd_func],
			    rd.drd_reg);
			if (bitx32(val, 7, 0) != 0) {
				df->adf_major = 3;
				df->adf_minor = 0;
				df->adf_rev = DF_REV_3;
			} else {
				df->adf_major = 2;
				df->adf_minor = 0;
				df->adf_rev = DF_REV_2;
			}
		}
	} else if (df->adf_major == 4 && df->adf_minor == 0) {
		df->adf_rev = DF_REV_4;
	} else {
		df->adf_rev = DF_REV_UNKNOWN;
	}
}

/*
 * All of the different versions of the DF have different ways of getting at and
 * answering the question of how do I break a fabric ID into a corresponding
 * socket, die, and component. Importantly the goal here is to obtain, cache,
 * and normalize:
 *
 *  o The DF System Configuration
 *  o The various Mask registers
 *  o The Node ID
 */
static void
amdzen_determine_fabric_decomp(amdzen_t *azn, amdzen_df_t *df)
{
	uint32_t mask;
	df_fabric_decomp_t *decomp = &df->adf_decomp;

	switch (df->adf_rev) {
	case DF_REV_2:
		df->adf_syscfg = amdzen_df_read32_bcast(azn, df, DF_SYSCFG_V2);
		switch (DF_SYSCFG_V2_GET_MY_TYPE(df->adf_syscfg)) {
		case DF_DIE_TYPE_CPU:
			mask = amdzen_df_read32_bcast(azn, df,
			    DF_DIEMASK_CPU_V2);
			break;
		case DF_DIE_TYPE_APU:
			mask = amdzen_df_read32_bcast(azn, df,
			    DF_DIEMASK_APU_V2);
			break;
		default:
			panic("DF thinks we're not on a CPU!");
		}
		df->adf_mask0 = mask;

		/*
		 * DFv2 is a bit different in how the fabric mask register is
		 * phrased. Logically a fabric ID is broken into something that
		 * uniquely identifies a "node" (a particular die on a socket)
		 * and something that identifies a "component", e.g. a memory
		 * controller.
		 *
		 * Starting with DFv3, these registers logically called out how
		 * to separate the fabric ID first into a node and a component.
		 * Then the node was then broken down into a socket and die. In
		 * DFv2, there is no separate mask and shift of a node. Instead
		 * the socket and die are absolute offsets into the fabric ID
		 * rather than relative offsets into the node ID. As such, when
		 * we encounter DFv2, we fake up a node mask and shift and make
		 * it look like DFv3+.
		 */
		decomp->dfd_node_mask = DF_DIEMASK_V2_GET_SOCK_MASK(mask) |
		    DF_DIEMASK_V2_GET_DIE_MASK(mask);
		decomp->dfd_node_shift = DF_DIEMASK_V2_GET_DIE_SHIFT(mask);
		decomp->dfd_comp_mask = DF_DIEMASK_V2_GET_COMP_MASK(mask);
		decomp->dfd_comp_shift = 0;

		decomp->dfd_sock_mask = DF_DIEMASK_V2_GET_SOCK_MASK(mask) >>
		    decomp->dfd_node_shift;
		decomp->dfd_die_mask = DF_DIEMASK_V2_GET_DIE_MASK(mask) >>
		    decomp->dfd_node_shift;
		decomp->dfd_sock_shift = DF_DIEMASK_V2_GET_SOCK_SHIFT(mask) -
		    decomp->dfd_node_shift;
		decomp->dfd_die_shift = DF_DIEMASK_V2_GET_DIE_SHIFT(mask) -
		    decomp->dfd_node_shift;
		ASSERT3U(decomp->dfd_die_shift, ==, 0);
		break;
	case DF_REV_3:
		df->adf_syscfg = amdzen_df_read32_bcast(azn, df, DF_SYSCFG_V3);
		df->adf_mask0 =  amdzen_df_read32_bcast(azn, df,
		    DF_FIDMASK0_V3);
		df->adf_mask1 =  amdzen_df_read32_bcast(azn, df,
		    DF_FIDMASK1_V3);

		decomp->dfd_sock_mask =
		    DF_FIDMASK1_V3_GET_SOCK_MASK(df->adf_mask1);
		decomp->dfd_sock_shift =
		    DF_FIDMASK1_V3_GET_SOCK_SHIFT(df->adf_mask1);
		decomp->dfd_die_mask =
		    DF_FIDMASK1_V3_GET_DIE_MASK(df->adf_mask1);
		decomp->dfd_die_shift = 0;
		decomp->dfd_node_mask =
		    DF_FIDMASK0_V3_GET_NODE_MASK(df->adf_mask0);
		decomp->dfd_node_shift =
		    DF_FIDMASK1_V3_GET_NODE_SHIFT(df->adf_mask1);
		decomp->dfd_comp_mask =
		    DF_FIDMASK0_V3_GET_COMP_MASK(df->adf_mask0);
		decomp->dfd_comp_shift = 0;
		break;
	case DF_REV_3P5:
		df->adf_syscfg = amdzen_df_read32_bcast(azn, df,
		    DF_SYSCFG_V3P5);
		df->adf_mask0 =  amdzen_df_read32_bcast(azn, df,
		    DF_FIDMASK0_V3P5);
		df->adf_mask1 =  amdzen_df_read32_bcast(azn, df,
		    DF_FIDMASK1_V3P5);
		df->adf_mask2 =  amdzen_df_read32_bcast(azn, df,
		    DF_FIDMASK2_V3P5);

		decomp->dfd_sock_mask =
		    DF_FIDMASK2_V3P5_GET_SOCK_MASK(df->adf_mask2);
		decomp->dfd_sock_shift =
		    DF_FIDMASK1_V3P5_GET_SOCK_SHIFT(df->adf_mask1);
		decomp->dfd_die_mask =
		    DF_FIDMASK2_V3P5_GET_DIE_MASK(df->adf_mask2);
		decomp->dfd_die_shift = 0;
		decomp->dfd_node_mask =
		    DF_FIDMASK0_V3P5_GET_NODE_MASK(df->adf_mask0);
		decomp->dfd_node_shift =
		    DF_FIDMASK1_V3P5_GET_NODE_SHIFT(df->adf_mask1);
		decomp->dfd_comp_mask =
		    DF_FIDMASK0_V3P5_GET_COMP_MASK(df->adf_mask0);
		decomp->dfd_comp_shift = 0;
		break;
	case DF_REV_4:
		df->adf_syscfg = amdzen_df_read32_bcast(azn, df, DF_SYSCFG_V4);
		df->adf_mask0 =  amdzen_df_read32_bcast(azn, df,
		    DF_FIDMASK0_V4);
		df->adf_mask1 =  amdzen_df_read32_bcast(azn, df,
		    DF_FIDMASK1_V4);
		df->adf_mask2 =  amdzen_df_read32_bcast(azn, df,
		    DF_FIDMASK2_V4);

		/*
		 * The DFv4 registers are at a different location in the DF;
		 * however, the actual layout of fields is the same as DFv3.5.
		 * This is why you see V3P5 below.
		 */
		decomp->dfd_sock_mask =
		    DF_FIDMASK2_V3P5_GET_SOCK_MASK(df->adf_mask2);
		decomp->dfd_sock_shift =
		    DF_FIDMASK1_V3P5_GET_SOCK_SHIFT(df->adf_mask1);
		decomp->dfd_die_mask =
		    DF_FIDMASK2_V3P5_GET_DIE_MASK(df->adf_mask2);
		decomp->dfd_die_shift = 0;
		decomp->dfd_node_mask =
		    DF_FIDMASK0_V3P5_GET_NODE_MASK(df->adf_mask0);
		decomp->dfd_node_shift =
		    DF_FIDMASK1_V3P5_GET_NODE_SHIFT(df->adf_mask1);
		decomp->dfd_comp_mask =
		    DF_FIDMASK0_V3P5_GET_COMP_MASK(df->adf_mask0);
		decomp->dfd_comp_shift = 0;
		break;
	default:
		panic("encountered suspicious, previously rejected DF "
		    "rev: 0x%x", df->adf_rev);
	}
}

/*
 * Initialize our knowledge about a given series of nodes on the data fabric.
 */
static void
amdzen_setup_df(amdzen_t *azn, amdzen_df_t *df)
{
	uint_t i;
	uint32_t val;

	amdzen_determine_df_vers(azn, df);

	switch (df->adf_rev) {
	case DF_REV_2:
	case DF_REV_3:
	case DF_REV_3P5:
		val = amdzen_df_read32_bcast(azn, df, DF_CFG_ADDR_CTL_V2);
		break;
	case DF_REV_4:
		val = amdzen_df_read32_bcast(azn, df, DF_CFG_ADDR_CTL_V4);
		break;
	default:
		dev_err(azn->azn_dip, CE_WARN, "encountered unsupported DF "
		    "revision: 0x%x", df->adf_rev);
		return;
	}
	df->adf_nb_busno = DF_CFG_ADDR_CTL_GET_BUS_NUM(val);
	val = amdzen_df_read32_bcast(azn, df, DF_FBICNT);
	df->adf_nents = DF_FBICNT_GET_COUNT(val);
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
		 * ID pattern. This means that for Rome, we need to adjust the
		 * indexes that we iterate over, though the total number of
		 * entries is right. This was carried over into Milan, but not
		 * Genoa.
		 */
		if (amdzen_is_rome_style(df->adf_funcs[0]->azns_did)) {
			if (inst >= ARRAY_SIZE(amdzen_df_rome_ids)) {
				dev_err(azn->azn_dip, CE_WARN, "Rome family "
				    "processor reported more ids than the PPR, "
				    "resetting %u to instance zero", inst);
				inst = 0;
			} else {
				inst = amdzen_df_rome_ids[inst];
			}
		}

		dfe->adfe_drvid = inst;
		dfe->adfe_info0 = amdzen_df_read32(azn, df, inst, DF_FBIINFO0);
		dfe->adfe_info1 = amdzen_df_read32(azn, df, inst, DF_FBIINFO1);
		dfe->adfe_info2 = amdzen_df_read32(azn, df, inst, DF_FBIINFO2);
		dfe->adfe_info3 = amdzen_df_read32(azn, df, inst, DF_FBIINFO3);

		dfe->adfe_type = DF_FBIINFO0_GET_TYPE(dfe->adfe_info0);
		dfe->adfe_subtype = DF_FBIINFO0_GET_SUBTYPE(dfe->adfe_info0);

		/*
		 * The enabled flag was not present in Zen 1. Simulate it by
		 * checking for a non-zero register instead.
		 */
		if (DF_FBIINFO0_V3_GET_ENABLED(dfe->adfe_info0) ||
		    (df->adf_rev == DF_REV_2 && dfe->adfe_info0 != 0)) {
			dfe->adfe_flags |= AMDZEN_DFE_F_ENABLED;
		}
		if (DF_FBIINFO0_GET_HAS_MCA(dfe->adfe_info0)) {
			dfe->adfe_flags |= AMDZEN_DFE_F_MCA;
		}
		dfe->adfe_inst_id = DF_FBIINFO3_GET_INSTID(dfe->adfe_info3);
		switch (df->adf_rev) {
		case DF_REV_2:
			dfe->adfe_fabric_id =
			    DF_FBIINFO3_V2_GET_BLOCKID(dfe->adfe_info3);
			break;
		case DF_REV_3:
			dfe->adfe_fabric_id =
			    DF_FBIINFO3_V3_GET_BLOCKID(dfe->adfe_info3);
			break;
		case DF_REV_3P5:
			dfe->adfe_fabric_id =
			    DF_FBIINFO3_V3P5_GET_BLOCKID(dfe->adfe_info3);
			break;
		case DF_REV_4:
			dfe->adfe_fabric_id =
			    DF_FBIINFO3_V4_GET_BLOCKID(dfe->adfe_info3);
			break;
		default:
			panic("encountered suspicious, previously rejected DF "
			    "rev: 0x%x", df->adf_rev);
		}
	}

	amdzen_determine_fabric_decomp(azn, df);
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
