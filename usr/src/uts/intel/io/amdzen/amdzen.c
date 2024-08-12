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
 * Copyright 2024 Oxide Computer Company
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
#include <sys/policy.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/bitmap.h>
#include <sys/stdbool.h>

#include <sys/amdzen/df.h>
#include <sys/amdzen/ccd.h>
#include "amdzen.h"
#include "amdzen_client.h"
#include "amdzen_topo.h"

amdzen_t *amdzen_data;

/*
 * Internal minor nodes for devices that the nexus provides itself.
 */
#define	AMDZEN_MINOR_TOPO	0

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
	/* Family 19h Raphael, Family 1Ah 40-4fh */
	0x14d8,
	/* Family 19h Phoenix */
	0x14e8,
	/* Family 1Ah Turin */
	0x153a,
	/* Family 1Ah 20-2fh */
	0x1507
};

typedef struct {
	char *acd_name;
	amdzen_child_t acd_addr;
	/*
	 * This indicates whether or not we should issue warnings to users when
	 * something happens specific to this instance. The main reason we don't
	 * want to is for optional devices that may not be installed as they are
	 * for development purposes (e.g. usmn, zen_udf); however, if there is
	 * an issue with the others we still want to know.
	 */
	bool acd_warn;
} amdzen_child_data_t;

static const amdzen_child_data_t amdzen_children[] = {
	{ "smntemp", AMDZEN_C_SMNTEMP, true },
	{ "usmn", AMDZEN_C_USMN, false },
	{ "zen_udf", AMDZEN_C_ZEN_UDF, false },
	{ "zen_umc", AMDZEN_C_ZEN_UMC, true }
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
	VERIFY(df_reg_valid(df_rev, def));

	VERIFY(MUTEX_HELD(&azn->azn_mutex));
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
		val = DF_FICAA_V2_SET_REG(val, def.drd_reg >>
		    DF_FICAA_REG_SHIFT);
		break;
	case DF_REV_4:
	case DF_REV_4D2:
		ficaa = DF_FICAA_V4;
		ficad = DF_FICAD_LO_V4;
		val = DF_FICAA_V4_SET_REG(val, def.drd_reg >>
		    DF_FICAA_REG_SHIFT);
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

/*
 * This is an unfortunate necessity due to the evolution of the CCM DF values.
 */
static inline boolean_t
amdzen_df_at_least(const amdzen_df_t *df, uint8_t major, uint8_t minor)
{
	return (df->adf_major > major || (df->adf_major == major &&
	    df->adf_minor >= minor));
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

static amdzen_df_ent_t *
amdzen_df_ent_find_by_instid(amdzen_df_t *df, uint8_t instid)
{
	for (uint_t i = 0; i < df->adf_nents; i++) {
		amdzen_df_ent_t *ent = &df->adf_ents[i];

		if ((ent->adfe_flags & AMDZEN_DFE_F_ENABLED) == 0) {
			continue;
		}

		if (ent->adfe_inst_id == instid) {
			return (ent);
		}
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

	if (df->adf_rev == DF_REV_UNKNOWN) {
		mutex_exit(&azn->azn_mutex);
		return (ENOTSUP);
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

	if (df->adf_rev == DF_REV_UNKNOWN) {
		mutex_exit(&azn->azn_mutex);
		return (ENOTSUP);
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
		df_type = DF_TYPE_CCM;

		if (df->adf_rev >= DF_REV_4 && amdzen_df_at_least(df, 4, 1)) {
			df_subtype = DF_CCM_SUBTYPE_CPU_V4P1;
		} else {
			df_subtype = DF_CCM_SUBTYPE_CPU_V2;
		}
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
		if (acd->acd_warn) {
			dev_err(azn->azn_dip, CE_WARN, "!failed to online "
			    "child dip %s: %d", acd->acd_name, ret);
		}
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
 * Deal with the differences between between how a CCM subtype is indicated
 * across CPU generations.
 */
static boolean_t
amdzen_dfe_is_ccm(const amdzen_df_t *df, const amdzen_df_ent_t *ent)
{
	if (ent->adfe_type != DF_TYPE_CCM) {
		return (B_FALSE);
	}

	if (df->adf_rev >= DF_REV_4 && amdzen_df_at_least(df, 4, 1)) {
		return (ent->adfe_subtype == DF_CCM_SUBTYPE_CPU_V4P1);
	} else {
		return (ent->adfe_subtype == DF_CCM_SUBTYPE_CPU_V2);
	}
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
	} else if (df->adf_major == 4 && df->adf_minor >= 2) {
		/*
		 * These are devices that have the newer memory layout that
		 * moves the DF::DramBaseAddress to 0x200. Please see the df.h
		 * theory statement for more information.
		 */
		df->adf_rev = DF_REV_4D2;
	} else if (df->adf_major == 4) {
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

		/*
		 * There is no register in the actual data fabric with the node
		 * ID in DFv2 that we have found. Instead we take the first
		 * entity's fabric ID and transform it into the node id.
		 */
		df->adf_nodeid = (df->adf_ents[0].adfe_fabric_id &
		    decomp->dfd_node_mask) >> decomp->dfd_node_shift;
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

		df->adf_nodeid = DF_SYSCFG_V3_GET_NODE_ID(df->adf_syscfg);
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

		df->adf_nodeid = DF_SYSCFG_V3P5_GET_NODE_ID(df->adf_syscfg);
		break;
	case DF_REV_4:
	case DF_REV_4D2:
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

		df->adf_nodeid = DF_SYSCFG_V4_GET_NODE_ID(df->adf_syscfg);
		break;
	default:
		panic("encountered suspicious, previously rejected DF "
		    "rev: 0x%x", df->adf_rev);
	}
}

/*
 * The purpose of this function is to map CCMs to the corresponding CCDs that
 * exist. This is not an obvious thing as there is no direct mapping in the data
 * fabric between these IDs.
 *
 * Prior to DFv4, a given CCM was only ever connected to at most one CCD.
 * Starting in DFv4 a given CCM may have one or two SDP (scalable data ports)
 * that connect to CCDs. These may be connected to the same CCD or a different
 * one. When both ports are enabled we must check whether or not the port is
 * considered to be in wide mode. When wide mode is enabled then the two ports
 * are connected to a single CCD. If wide mode is disabled then the two ports
 * are connected to separate CCDs.
 *
 * The physical number of a CCD, which is how we determine the SMN aperture to
 * use, is based on the CCM ID. In most sockets we have seen up to a maximum of
 * 8 CCMs. When a CCM is connected to more than one CCD we have determined based
 * on some hints from AMD's ACPI information that the numbering is assumed to be
 * that CCM's number plus the total number of CCMs.
 *
 * More concretely, the SP5 Genoa/Bergamo Zen 4 platform has 8 CCMs. When there
 * are more than 8 CCDs installed then CCM 0 maps to CCDs 0 and 8. CCM 1 to CCDs
 * 1 and 9, etc. CCMs 4-7 map 1:1 to CCDs 4-7. However, the placement of CCDs
 * within the package has changed across generations.
 *
 * Notably in Rome and Milan (Zen 2/3) it appears that each quadrant had an
 * increasing number of CCDs. So CCDs 0/1 were together, 2/3, 4/5, and 6/7. This
 * meant that in cases where only a subset of CCDs were populated it'd forcibly
 * disable the higher CCD in a group (but with DFv3 the CCM would still be
 * enabled). So a 4 CCD config would generally enable CCDs 0, 2, 4, and 6 say.
 * This was almost certainly done to balance the NUMA config.
 *
 * Instead, starting in Genoa (Zen 4) the CCMs are round-robined around the
 * quadrants so CCMs (CCDs) 0 (0/8) and 4 (4) are together, 1 (1/9) and 5 (5),
 * etc. This is also why we more often see disabled CCMs in Genoa, but not in
 * Rome/Milan.
 *
 * When we're operating in wide mode and therefore both SDPs are connected to a
 * single CCD, we've always found that the lower CCD index will be used by the
 * system and the higher one is not considered present. Therefore, when
 * operating in wide mode, we need to make sure that whenever we have a non-zero
 * value for SDPs being connected that we rewrite this to only appear as a
 * single CCD is present. It's conceivable (though hard to imagine) that we
 * could get a value of 0b10 indicating that only the upper SDP link is active
 * for some reason.
 */
static void
amdzen_setup_df_ccm(amdzen_t *azn, amdzen_df_t *df, amdzen_df_ent_t *dfe,
    uint32_t ccmno)
{
	amdzen_ccm_data_t *ccm = &dfe->adfe_data.aded_ccm;
	uint32_t ccd_en;
	boolean_t wide_en;

	if (df->adf_rev >= DF_REV_4) {
		uint32_t val = amdzen_df_read32(azn, df, dfe->adfe_inst_id,
		    DF_CCD_EN_V4);
		ccd_en = DF_CCD_EN_V4_GET_CCD_EN(val);

		if (df->adf_rev == DF_REV_4D2) {
			wide_en = DF_CCD_EN_V4D2_GET_WIDE_EN(val);
		} else {
			val = amdzen_df_read32(azn, df, dfe->adfe_inst_id,
			    DF_CCMCFG4_V4);
			wide_en = DF_CCMCFG4_V4_GET_WIDE_EN(val);
		}

		if (wide_en != 0 && ccd_en != 0) {
			ccd_en = 0x1;
		}
	} else {
		ccd_en = 0x1;
	}

	for (uint32_t i = 0; i < DF_MAX_CCDS_PER_CCM; i++) {
		ccm->acd_ccd_en[i] = (ccd_en & (1 << i)) != 0;
		if (ccm->acd_ccd_en[i] == 0)
			continue;
		ccm->acd_ccd_id[i] = ccmno + i * df->adf_nccm;
		ccm->acd_nccds++;
	}
}

/*
 * Initialize our knowledge about a given series of nodes on the data fabric.
 */
static void
amdzen_setup_df(amdzen_t *azn, amdzen_df_t *df)
{
	uint_t i;
	uint32_t val, ccmno;

	amdzen_determine_df_vers(azn, df);

	switch (df->adf_rev) {
	case DF_REV_2:
	case DF_REV_3:
	case DF_REV_3P5:
		val = amdzen_df_read32_bcast(azn, df, DF_CFG_ADDR_CTL_V2);
		break;
	case DF_REV_4:
	case DF_REV_4D2:
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
		if (df->adf_rev <= DF_REV_4) {
			dfe->adfe_info1 = amdzen_df_read32(azn, df, inst,
			    DF_FBIINFO1);
			dfe->adfe_info2 = amdzen_df_read32(azn, df, inst,
			    DF_FBIINFO2);
		}
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

		/*
		 * Starting with DFv4 there is no instance ID in the fabric info
		 * 3 register, so we instead grab it out of the driver ID which
		 * is what it should be anyways.
		 */
		if (df->adf_rev >= DF_REV_4) {
			dfe->adfe_inst_id = dfe->adfe_drvid;
		} else {
			dfe->adfe_inst_id =
			    DF_FBIINFO3_GET_INSTID(dfe->adfe_info3);
		}

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
		case DF_REV_4D2:
			dfe->adfe_fabric_id =
			    DF_FBIINFO3_V4_GET_BLOCKID(dfe->adfe_info3);
			break;
		default:
			panic("encountered suspicious, previously rejected DF "
			    "rev: 0x%x", df->adf_rev);
		}

		/*
		 * Record information about a subset of DF entities that we've
		 * found. Currently we're tracking this only for CCMs.
		 */
		if ((dfe->adfe_flags & AMDZEN_DFE_F_ENABLED) == 0)
			continue;

		if (amdzen_dfe_is_ccm(df, dfe)) {
			df->adf_nccm++;
		}
	}

	/*
	 * Now that we have filled in all of our info, attempt to fill in
	 * specific information about different types of instances.
	 */
	ccmno = 0;
	for (uint_t i = 0; i < df->adf_nents; i++) {
		amdzen_df_ent_t *dfe = &df->adf_ents[i];

		if ((dfe->adfe_flags & AMDZEN_DFE_F_ENABLED) == 0)
			continue;

		/*
		 * Perform type and sub-type specific initialization. Currently
		 * limited to CCMs.
		 */
		switch (dfe->adfe_type) {
		case DF_TYPE_CCM:
			amdzen_setup_df_ccm(azn, df, dfe, ccmno);
			ccmno++;
			break;
		default:
			break;
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

/*
 * We need to be careful using this function as different AMD generations have
 * acted in different ways when there is a missing CCD. We've found that in
 * hardware where the CCM is enabled but there is no CCD attached, it generally
 * is safe (i.e. DFv3 on Rome), but on DFv4 if we ask for a CCD that would
 * correspond to a disabled CCM then the firmware may inject a fatal error
 * (which is hopefully something missing in our RAS/MCA-X enablement).
 *
 * Put differently if this doesn't correspond to an Enabled CCM and you know the
 * number of valid CCDs on this, don't use it.
 */
static boolean_t
amdzen_ccd_present(amdzen_t *azn, amdzen_df_t *df, uint32_t ccdno)
{
	smn_reg_t die_reg = SMUPWR_CCD_DIE_ID(ccdno);
	uint32_t val = amdzen_smn_read(azn, df, die_reg);
	if (val == SMN_EINVAL32) {
		return (B_FALSE);
	}

	ASSERT3U(ccdno, ==, SMUPWR_CCD_DIE_ID_GET(val));
	return (B_TRUE);
}

static uint32_t
amdzen_ccd_thread_en(amdzen_t *azn, amdzen_df_t *df, uint32_t ccdno)
{
	smn_reg_t reg;

	if (uarchrev_uarch(azn->azn_uarchrev) >= X86_UARCH_AMD_ZEN5) {
		reg = L3SOC_THREAD_EN(ccdno);
	} else {
		reg = SMUPWR_THREAD_EN(ccdno);
	}

	return (amdzen_smn_read(azn, df, reg));
}

static uint32_t
amdzen_ccd_core_en(amdzen_t *azn, amdzen_df_t *df, uint32_t ccdno)
{
	smn_reg_t reg;

	if (uarchrev_uarch(azn->azn_uarchrev) >= X86_UARCH_AMD_ZEN5) {
		reg = L3SOC_CORE_EN(ccdno);
	} else {
		reg = SMUPWR_CORE_EN(ccdno);
	}

	return (amdzen_smn_read(azn, df, reg));
}

static void
amdzen_ccd_info(amdzen_t *azn, amdzen_df_t *df, uint32_t ccdno, uint32_t *nccxp,
    uint32_t *nlcorep, uint32_t *nthrp)
{
	uint32_t nccx, nlcore, smt;

	if (uarchrev_uarch(azn->azn_uarchrev) >= X86_UARCH_AMD_ZEN5) {
		smn_reg_t reg = L3SOC_THREAD_CFG(ccdno);
		uint32_t val = amdzen_smn_read(azn, df, reg);
		nccx = L3SOC_THREAD_CFG_GET_COMPLEX_COUNT(val) + 1;
		nlcore = L3SOC_THREAD_CFG_GET_CORE_COUNT(val) + 1;
		smt = L3SOC_THREAD_CFG_GET_SMT_MODE(val);
	} else {
		smn_reg_t reg = SMUPWR_THREAD_CFG(ccdno);
		uint32_t val = amdzen_smn_read(azn, df, reg);
		nccx = SMUPWR_THREAD_CFG_GET_COMPLEX_COUNT(val) + 1;
		nlcore = SMUPWR_THREAD_CFG_GET_CORE_COUNT(val) + 1;
		smt = SMUPWR_THREAD_CFG_GET_SMT_MODE(val);
	}

	if (nccxp != NULL) {
		*nccxp = nccx;
	}

	if (nlcorep != NULL) {
		*nlcorep = nlcore;
	}

	if (nthrp != NULL) {
		/* The L3::L3SOC and SMU::PWR values are the same here */
		if (smt == SMUPWR_THREAD_CFG_SMT_MODE_SMT) {
			*nthrp = 2;
		} else {
			*nthrp = 1;
		}
	}
}

static void
amdzen_initpkg_to_apic(amdzen_t *azn, const uint32_t pkg0, const uint32_t pkg7)
{
	uint32_t nsock, nccd, nccx, ncore, nthr, extccx;
	uint32_t nsock_bits, nccd_bits, nccx_bits, ncore_bits, nthr_bits;
	amdzen_apic_decomp_t *apic = &azn->azn_apic_decomp;

	/*
	 * These are all 0 based values, meaning that we need to add one to each
	 * of them. However, we skip this because to calculate the number of
	 * bits to cover an entity we would subtract one.
	 */
	nthr = SCFCTP_PMREG_INITPKG0_GET_SMTEN(pkg0);
	ncore = SCFCTP_PMREG_INITPKG7_GET_N_CORES(pkg7);
	nccx = SCFCTP_PMREG_INITPKG7_GET_N_CCXS(pkg7);
	nccd = SCFCTP_PMREG_INITPKG7_GET_N_DIES(pkg7);
	nsock = SCFCTP_PMREG_INITPKG7_GET_N_SOCKETS(pkg7);

	if (uarchrev_uarch(azn->azn_uarchrev) >= X86_UARCH_AMD_ZEN4) {
		extccx = SCFCTP_PMREG_INITPKG7_ZEN4_GET_16TAPIC(pkg7);
	} else {
		extccx = 0;
	}

	nthr_bits = highbit(nthr);
	ncore_bits = highbit(ncore);
	nccx_bits = highbit(nccx);
	nccd_bits = highbit(nccd);
	nsock_bits = highbit(nsock);

	apic->aad_thread_shift = 0;
	apic->aad_thread_mask = (1 << nthr_bits) - 1;

	apic->aad_core_shift = nthr_bits;
	if (ncore_bits > 0) {
		apic->aad_core_mask = (1 << ncore_bits) - 1;
		apic->aad_core_mask <<= apic->aad_core_shift;
	} else {
		apic->aad_core_mask = 0;
	}

	/*
	 * The APIC_16T_MODE bit indicates that the total shift to start the CCX
	 * should be at 4 bits if it's not. It doesn't mean that the CCX portion
	 * of the value should take up four bits. In the common Genoa case,
	 * nccx_bits will be zero.
	 */
	apic->aad_ccx_shift = apic->aad_core_shift + ncore_bits;
	if (extccx != 0 && apic->aad_ccx_shift < 4) {
		apic->aad_ccx_shift = 4;
	}
	if (nccx_bits > 0) {
		apic->aad_ccx_mask = (1 << nccx_bits) - 1;
		apic->aad_ccx_mask <<= apic->aad_ccx_shift;
	} else {
		apic->aad_ccx_mask = 0;
	}

	apic->aad_ccd_shift = apic->aad_ccx_shift + nccx_bits;
	if (nccd_bits > 0) {
		apic->aad_ccd_mask = (1 << nccd_bits) - 1;
		apic->aad_ccd_mask <<= apic->aad_ccd_shift;
	} else {
		apic->aad_ccd_mask = 0;
	}

	apic->aad_sock_shift = apic->aad_ccd_shift + nccd_bits;
	if (nsock_bits > 0) {
		apic->aad_sock_mask = (1 << nsock_bits) - 1;
		apic->aad_sock_mask <<= apic->aad_sock_shift;
	} else {
		apic->aad_sock_mask = 0;
	}

	/*
	 * Currently all supported Zen 2+ platforms only have a single die per
	 * socket as compared to Zen 1. So this is always kept at zero.
	 */
	apic->aad_die_mask = 0;
	apic->aad_die_shift = 0;
}

/*
 * We would like to determine what the logical APIC decomposition is on Zen 3
 * and newer family parts. While there is information added to CPUID in the form
 * of leaf 8X26, that isn't present in Zen 3, so instead we go to what we
 * believe is the underlying source of the CPUID data.
 *
 * Fundamentally there are a series of registers in SMN space that relate to the
 * SCFCTP. Coincidentally, there is one of these for each core and there are a
 * pair of related SMN registers. L3::SCFCTP::PMREG_INITPKG0 contains
 * information about a given's core logical and physical IDs. More interestingly
 * for this particular case, L3::SCFCTP::PMREG_INITPKG7, contains the overall
 * total number of logical entities. We've been promised that this has to be
 * the same across the fabric. That's all well and good, but this begs the
 * question of how do we actually get there. The above is a core-specific
 * register and requires that we understand information about which CCDs and
 * CCXs are actually present.
 *
 * So we are starting with a data fabric that has some CCM present. The CCM
 * entries in the data fabric may be tagged with our ENABLED flag.
 * Unfortunately, that can be true regardless of whether or not it's actually
 * present or not. As a result, we go to another chunk of SMN space registers,
 * SMU::PWR. These contain information about the CCDs, the physical cores that
 * are enabled, and related. So we will first walk the DF entities and see if we
 * can read its SMN::PWR::CCD_DIE_ID. If we get back a value of all 1s then
 * there is nothing present. Otherwise, we should get back something that
 * matches information in the data fabric.
 *
 * With that in hand, we can read the SMU::PWR::CORE_ENABLE register to
 * determine which physical cores are enabled in the CCD/CCX. That will finally
 * give us an index to get to our friend INITPKG7.
 */
static boolean_t
amdzen_determine_apic_decomp_initpkg(amdzen_t *azn)
{
	amdzen_df_t *df = &azn->azn_dfs[0];
	uint32_t ccdno = 0;

	for (uint_t i = 0; i < df->adf_nents; i++) {
		const amdzen_df_ent_t *ent = &df->adf_ents[i];
		if ((ent->adfe_flags & AMDZEN_DFE_F_ENABLED) == 0)
			continue;

		if (amdzen_dfe_is_ccm(df, ent)) {
			uint32_t val, nccx, pkg7, pkg0;
			smn_reg_t pkg7_reg, pkg0_reg;
			int core_bit;
			uint8_t pccxno, pcoreno;

			if (!amdzen_ccd_present(azn, df, ccdno)) {
				ccdno++;
				continue;
			}

			/*
			 * This die actually exists. Switch over to the core
			 * enable register to find one to ask about physically.
			 */
			amdzen_ccd_info(azn, df, ccdno, &nccx, NULL, NULL);
			val = amdzen_ccd_core_en(azn, df, ccdno);
			if (val == 0) {
				ccdno++;
				continue;
			}

			/*
			 * There exists an enabled physical core. Find the first
			 * index of it and map it to the corresponding CCD and
			 * CCX. ddi_ffs is the bit index, but we want the
			 * physical core number, hence the -1.
			 */
			core_bit = ddi_ffs(val);
			ASSERT3S(core_bit, !=, 0);
			pcoreno = core_bit - 1;

			/*
			 * Unfortunately SMU::PWR::THREAD_CONFIGURATION gives us
			 * the Number of logical cores that are present in the
			 * complex, not the total number of physical cores.
			 * Right now we do assume that the physical and logical
			 * ccx numbering is equivalent (we have no other way of
			 * knowing if it is or isn't right now) and that we'd
			 * always have CCX0 before CCX1. AMD seems to suggest we
			 * can assume this, though it is a worrisome assumption.
			 */
			pccxno = pcoreno / azn->azn_ncore_per_ccx;
			ASSERT3U(pccxno, <, nccx);
			pkg7_reg = SCFCTP_PMREG_INITPKG7(ccdno, pccxno,
			    pcoreno);
			pkg7 = amdzen_smn_read(azn, df, pkg7_reg);
			pkg0_reg = SCFCTP_PMREG_INITPKG0(ccdno, pccxno,
			    pcoreno);
			pkg0 = amdzen_smn_read(azn, df, pkg0_reg);
			amdzen_initpkg_to_apic(azn, pkg0, pkg7);
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * We have the fun job of trying to figure out what the correct form of the APIC
 * decomposition should be and how to break that into its logical components.
 * The way that we get at this is generation-specific unfortunately. Here's how
 * it works out:
 *
 * Zen 1-2	This era of CPUs are deceptively simple. The PPR for a given
 *		family defines exactly how the APIC ID is broken into logical
 *		components and it's fixed. That is, depending on whether or
 *		not SMT is enabled. Zen 1 and Zen 2 use different schemes for
 *		constructing this. The way that we're supposed to check if SMT
 *		is enabled is to use AMD leaf 8X1E and ask how many threads per
 *		core there are. We use the x86 feature set to determine that
 *		instead.
 *
 *		More specifically the Zen 1 scheme is 7 bits long. The bits have
 *		the following meanings.
 *
 *		[6]   Socket ID
 *		[5:4] Node ID
 *		[3]   Logical CCX ID
 *		With SMT		Without SMT
 *		[2:1] Logical Core ID	[2]   hardcoded to zero
 *		[0] Thread ID		[1:0] Logical Core ID
 *
 *		The following is the Zen 2 scheme assuming SMT. The Zen 2 scheme
 *		without SMT shifts everything to the right by one bit.
 *
 *		[7]   Socket ID
 *		[6:4] Logical CCD ID
 *		[3]   Logical CCX ID
 *		[2:1] Logical Core ID
 *		[0]   Thread ID
 *
 * Zen 3	Zen 3 CPUs moved past the fixed APIC ID format that Zen 1 and
 *		Zen 2 had, but also don't give us the nice way of discovering
 *		this via CPUID that Zen 4 did. The APIC ID id uses a given
 *		number of bits for each logical component that exists, but the
 *		exact number varies based on what's actually present. To get at
 *		this we use a piece of data that is embedded in the SCFCTP
 *		(Scalable Control Fabric, Clocks, Test, Power Gating). This can
 *		be used to determine how many logical entities of each kind the
 *		system thinks exist. While we could use the various CPUID
 *		topology items to try to speed this up, they don't tell us the
 *		die information that we need to do this.
 *
 * Zen 4+	Zen 4 introduced CPUID leaf 8000_0026h which gives us a means
 *		for determining how to extract the CCD, CCX, and related pieces
 *		out of the device. One thing we have to be aware of is that when
 *		the CCD and CCX shift are the same, that means that there is
 *		only a single CCX and therefore have to take that into account
 *		appropriately. This is the case generally on Zen 4 platforms,
 *		but not on Bergamo. Until we can confirm the actual CPUID leaf
 *		values that we receive in the cases of Bergamo and others, we
 *		opt instead to use the same SCFCTP scheme as Zen 3.
 */
static boolean_t
amdzen_determine_apic_decomp(amdzen_t *azn)
{
	amdzen_apic_decomp_t *apic = &azn->azn_apic_decomp;
	boolean_t smt = is_x86_feature(x86_featureset, X86FSET_HTT);

	switch (uarchrev_uarch(azn->azn_uarchrev)) {
	case X86_UARCH_AMD_ZEN1:
	case X86_UARCH_AMD_ZENPLUS:
		apic->aad_sock_mask = 0x40;
		apic->aad_sock_shift = 6;
		apic->aad_die_mask = 0x30;
		apic->aad_die_shift = 4;
		apic->aad_ccd_mask = 0;
		apic->aad_ccd_shift = 0;
		apic->aad_ccx_mask = 0x08;
		apic->aad_ccx_shift = 3;

		if (smt) {
			apic->aad_core_mask = 0x06;
			apic->aad_core_shift = 1;
			apic->aad_thread_mask = 0x1;
			apic->aad_thread_shift = 0;
		} else {
			apic->aad_core_mask = 0x03;
			apic->aad_core_shift = 0;
			apic->aad_thread_mask = 0;
			apic->aad_thread_shift = 0;
		}
		break;
	case X86_UARCH_AMD_ZEN2:
		if (smt) {
			apic->aad_sock_mask = 0x80;
			apic->aad_sock_shift = 7;
			apic->aad_die_mask = 0;
			apic->aad_die_shift = 0;
			apic->aad_ccd_mask = 0x70;
			apic->aad_ccd_shift = 4;
			apic->aad_ccx_mask = 0x08;
			apic->aad_ccx_shift = 3;
			apic->aad_core_mask = 0x06;
			apic->aad_core_shift = 1;
			apic->aad_thread_mask = 0x01;
			apic->aad_thread_shift = 0;
		} else {
			apic->aad_sock_mask = 0x40;
			apic->aad_sock_shift = 6;
			apic->aad_die_mask = 0;
			apic->aad_die_shift = 0;
			apic->aad_ccd_mask = 0x38;
			apic->aad_ccd_shift = 3;
			apic->aad_ccx_mask = 0x04;
			apic->aad_ccx_shift = 2;
			apic->aad_core_mask = 0x3;
			apic->aad_core_shift = 0;
			apic->aad_thread_mask = 0;
			apic->aad_thread_shift = 0;
		}
		break;
	case X86_UARCH_AMD_ZEN3:
	case X86_UARCH_AMD_ZEN4:
	case X86_UARCH_AMD_ZEN5:
		return (amdzen_determine_apic_decomp_initpkg(azn));
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Snapshot the number of cores that can exist in a CCX based on the Zen
 * microarchitecture revision. In Zen 1-4 this has been a constant number
 * regardless of the actual CPU Family. In Zen 5 this varies based upon whether
 * or not dense dies are being used.
 */
static void
amdzen_determine_ncore_per_ccx(amdzen_t *azn)
{
	switch (uarchrev_uarch(azn->azn_uarchrev)) {
	case X86_UARCH_AMD_ZEN1:
	case X86_UARCH_AMD_ZENPLUS:
	case X86_UARCH_AMD_ZEN2:
		azn->azn_ncore_per_ccx = 4;
		break;
	case X86_UARCH_AMD_ZEN3:
	case X86_UARCH_AMD_ZEN4:
		azn->azn_ncore_per_ccx = 8;
		break;
	case X86_UARCH_AMD_ZEN5:
		if (chiprev_family(azn->azn_chiprev) ==
		    X86_PF_AMD_DENSE_TURIN) {
			azn->azn_ncore_per_ccx = 16;
		} else {
			azn->azn_ncore_per_ccx = 8;
		}
		break;
	default:
		panic("asked about non-Zen or unknown uarch");
	}
}

/*
 * Attempt to determine a logical CCD number of a given CCD where we don't have
 * hardware support for L3::SCFCTP::PMREG_INITPKG* (e.g. pre-Zen 3 systems).
 * The CCD numbers that we have are the in the physical space. Likely because of
 * how the orientation of CCM numbers map to physical locations and the layout
 * of them within the package, we haven't found a good way using the core DFv3
 * registers to determine if a given CCD is actually present or not as generally
 * all the CCMs are left enabled. Instead we use SMU::PWR::DIE_ID as a proxy to
 * determine CCD presence.
 */
static uint32_t
amdzen_ccd_log_id_zen2(amdzen_t *azn, amdzen_df_t *df,
    const amdzen_df_ent_t *targ)
{
	uint32_t smnid = 0;
	uint32_t logid = 0;

	for (uint_t i = 0; i < df->adf_nents; i++) {
		const amdzen_df_ent_t *ent = &df->adf_ents[i];

		if ((ent->adfe_flags & AMDZEN_DFE_F_ENABLED) == 0) {
			continue;
		}

		if (ent->adfe_inst_id == targ->adfe_inst_id) {
			return (logid);
		}

		if (ent->adfe_type == targ->adfe_type &&
		    ent->adfe_subtype == targ->adfe_subtype) {
			boolean_t present = amdzen_ccd_present(azn, df, smnid);
			smnid++;
			if (present) {
				logid++;
			}
		}
	}

	panic("asked to match against invalid DF entity %p in df %p", targ, df);
}

static void
amdzen_ccd_fill_core_initpkg0(amdzen_t *azn, amdzen_df_t *df,
    amdzen_topo_ccd_t *ccd, amdzen_topo_ccx_t *ccx, amdzen_topo_core_t *core,
    boolean_t *ccd_set, boolean_t *ccx_set)
{
	smn_reg_t pkg0_reg;
	uint32_t pkg0;

	pkg0_reg = SCFCTP_PMREG_INITPKG0(ccd->atccd_phys_no, ccx->atccx_phys_no,
	    core->atcore_phys_no);
	pkg0 = amdzen_smn_read(azn, df, pkg0_reg);
	core->atcore_log_no = SCFCTP_PMREG_INITPKG0_GET_LOG_CORE(pkg0);

	if (!*ccx_set) {
		ccx->atccx_log_no = SCFCTP_PMREG_INITPKG0_GET_LOG_CCX(pkg0);
		*ccx_set = B_TRUE;
	}

	if (!*ccd_set) {
		ccd->atccd_log_no = SCFCTP_PMREG_INITPKG0_GET_LOG_DIE(pkg0);
		*ccd_set = B_TRUE;
	}
}

/*
 * Attempt to fill in the physical topology information for this given CCD.
 * There are a few steps to this that we undertake to perform this as follows:
 *
 * 1) First we determine whether the CCD is actually present or not by reading
 * SMU::PWR::DIE_ID. CCDs that are not installed will still have an enabled DF
 * entry it appears, but the request for the die ID will returns an invalid
 * read (all 1s). This die ID should match what we think of as the SMN number
 * below. If not, we're in trouble and the rest of this is in question.
 *
 * 2) We use the SMU::PWR registers to determine how many logical and physical
 * cores are present in this CCD and how they are split amongst the CCX. Here we
 * need to encode the CPU to CCX core size rankings. Through this process we
 * determine and fill out which threads and cores are enabled.
 *
 * 3) In Zen 3+ we then will read each core's INITPK0 values to ensure that we
 * have a proper physical to logical mapping, at which point we can fill in the
 * APIC IDs. For Zen 2, we will set the AMDZEN_TOPO_CCD_F_CORE_PHYS_UNKNOWN to
 * indicate that we just mapped the first logical processor to the first enabled
 * core.
 *
 * 4) Once we have the logical IDs determined we will construct the APIC ID that
 * we expect this to have.
 *
 * Steps (2) - (4) are intertwined and done together.
 */
static void
amdzen_ccd_fill_topo(amdzen_t *azn, amdzen_df_t *df, amdzen_df_ent_t *ent,
    amdzen_topo_ccd_t *ccd)
{
	uint32_t nccx, core_en, thread_en;
	uint32_t nlcore_per_ccx, nthreads_per_core;
	uint32_t sockid, dieid, compid;
	const uint32_t ccdno = ccd->atccd_phys_no;
	const x86_uarch_t uarch = uarchrev_uarch(azn->azn_uarchrev);
	boolean_t pkg0_ids, logccd_set = B_FALSE;

	ASSERT(MUTEX_HELD(&azn->azn_mutex));
	if (!amdzen_ccd_present(azn, df, ccdno)) {
		ccd->atccd_err = AMDZEN_TOPO_CCD_E_CCD_MISSING;
		return;
	}

	amdzen_ccd_info(azn, df, ccdno, &nccx, &nlcore_per_ccx,
	    &nthreads_per_core);
	ASSERT3U(nccx, <=, AMDZEN_TOPO_CCD_MAX_CCX);

	core_en = amdzen_ccd_core_en(azn, df, ccdno);
	thread_en = amdzen_ccd_thread_en(azn, df, ccdno);

	/*
	 * The BSP is never enabled in a conventional sense and therefore the
	 * bit is reserved and left as 0. As the BSP should be in the first CCD,
	 * we go through and OR back in the bit lest we think the thread isn't
	 * enabled.
	 */
	if (ccdno == 0) {
		thread_en |= 1;
	}

	ccd->atccd_phys_no = ccdno;
	if (uarch >= X86_UARCH_AMD_ZEN3) {
		pkg0_ids = B_TRUE;
	} else {
		ccd->atccd_flags |= AMDZEN_TOPO_CCD_F_CORE_PHYS_UNKNOWN;
		pkg0_ids = B_FALSE;

		/*
		 * Determine the CCD logical ID for Zen 2 now since this doesn't
		 * rely upon needing a valid physical core.
		 */
		ccd->atccd_log_no = amdzen_ccd_log_id_zen2(azn, df, ent);
		logccd_set = B_TRUE;
	}

	/*
	 * To construct the APIC ID we need to know the socket and die (not CCD)
	 * this is on. We deconstruct the CCD's fabric ID to determine that.
	 */
	zen_fabric_id_decompose(&df->adf_decomp, ent->adfe_fabric_id, &sockid,
	    &dieid, &compid);

	/*
	 * At this point we have all the information about the CCD, the number
	 * of CCX instances, and which physical cores and threads are enabled.
	 * Currently we assume that if we have one CCX enabled, then it is
	 * always CCX0. We cannot find evidence of a two CCX supporting part
	 * that doesn't always ship with both CCXs present and enabled.
	 */
	ccd->atccd_nlog_ccx = ccd->atccd_nphys_ccx = nccx;
	for (uint32_t ccxno = 0; ccxno < nccx; ccxno++) {
		amdzen_topo_ccx_t *ccx = &ccd->atccd_ccx[ccxno];
		const uint32_t core_mask = (1 << azn->azn_ncore_per_ccx) - 1;
		const uint32_t core_shift = ccxno * azn->azn_ncore_per_ccx;
		const uint32_t ccx_core_en = (core_en >> core_shift) &
		    core_mask;
		boolean_t logccx_set = B_FALSE;

		ccd->atccd_ccx_en[ccxno] = 1;
		ccx->atccx_phys_no = ccxno;
		ccx->atccx_nphys_cores = azn->azn_ncore_per_ccx;
		ccx->atccx_nlog_cores = nlcore_per_ccx;

		if (!pkg0_ids) {
			ccx->atccx_log_no = ccx->atccx_phys_no;
			logccx_set = B_TRUE;
		}

		for (uint32_t coreno = 0, logcorezen2 = 0;
		    coreno < azn->azn_ncore_per_ccx; coreno++) {
			amdzen_topo_core_t *core = &ccx->atccx_cores[coreno];

			if ((ccx_core_en & (1 << coreno)) == 0) {
				continue;
			}

			ccx->atccx_core_en[coreno] = 1;
			core->atcore_phys_no = coreno;

			/*
			 * Now that we have the physical core number present, we
			 * must determine the logical core number and fill out
			 * the logical CCX/CCD if it has not been set. We must
			 * do this before we attempt to look at which threads
			 * are enabled, because that operates based upon logical
			 * core number.
			 *
			 * For Zen 2 we do not have INITPKG0 at our disposal. We
			 * currently assume (and tag for userland with the
			 * AMDZEN_TOPO_CCD_F_CORE_PHYS_UNKNOWN flag) that we are
			 * mapping logical cores to physicals in the order of
			 * appearance.
			 */
			if (pkg0_ids) {
				amdzen_ccd_fill_core_initpkg0(azn, df, ccd, ccx,
				    core, &logccd_set, &logccx_set);
			} else {
				core->atcore_log_no = logcorezen2;
				logcorezen2++;
			}

			/*
			 * Determining which bits to use for the thread is a bit
			 * weird here. Thread IDs within a CCX are logical, but
			 * there are always physically spaced CCX sizes. See the
			 * comment at the definition for SMU::PWR::THREAD_ENABLE
			 * for more information.
			 */
			const uint32_t thread_shift = (ccx->atccx_nphys_cores *
			    ccx->atccx_log_no + core->atcore_log_no) *
			    nthreads_per_core;
			const uint32_t thread_mask = (nthreads_per_core << 1) -
			    1;
			const uint32_t core_thread_en = (thread_en >>
			    thread_shift) & thread_mask;
			core->atcore_nthreads = nthreads_per_core;
			core->atcore_thr_en[0] = core_thread_en & 0x01;
			core->atcore_thr_en[1] = core_thread_en & 0x02;
#ifdef	DEBUG
			if (nthreads_per_core == 1) {
				VERIFY0(core->atcore_thr_en[1]);
			}
#endif
			for (uint32_t thrno = 0; thrno < core->atcore_nthreads;
			    thrno++) {
				ASSERT3U(core->atcore_thr_en[thrno], !=, 0);

				zen_apic_id_compose(&azn->azn_apic_decomp,
				    sockid, dieid, ccd->atccd_log_no,
				    ccx->atccx_log_no, core->atcore_log_no,
				    thrno, &core->atcore_apicids[thrno]);

			}
		}

		ASSERT3U(logccx_set, ==, B_TRUE);
		ASSERT3U(logccd_set, ==, B_TRUE);
	}
}

static void
amdzen_nexus_init(void *arg)
{
	uint_t i;
	amdzen_t *azn = arg;

	/*
	 * Assign the requisite identifying information for this CPU.
	 */
	azn->azn_uarchrev = cpuid_getuarchrev(CPU);
	azn->azn_chiprev = cpuid_getchiprev(CPU);

	/*
	 * Go through all of the stubs and assign the DF entries.
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

	amdzen_determine_ncore_per_ccx(azn);

	if (amdzen_determine_apic_decomp(azn)) {
		azn->azn_flags |= AMDZEN_F_APIC_DECOMP_VALID;
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
amdzen_topo_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	minor_t m;
	amdzen_t *azn = amdzen_data;

	if (crgetzoneid(credp) != GLOBAL_ZONEID ||
	    secpolicy_sys_config(credp, B_FALSE) != 0) {
		return (EPERM);
	}

	if ((flag & (FEXCL | FNDELAY | FNONBLOCK)) != 0) {
		return (EINVAL);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	m = getminor(*devp);
	if (m != AMDZEN_MINOR_TOPO) {
		return (ENXIO);
	}

	mutex_enter(&azn->azn_mutex);
	if ((azn->azn_flags & AMDZEN_F_IOCTL_MASK) !=
	    AMDZEN_F_ATTACH_COMPLETE) {
		mutex_exit(&azn->azn_mutex);
		return (ENOTSUP);
	}
	mutex_exit(&azn->azn_mutex);

	return (0);
}

static int
amdzen_topo_ioctl_base(amdzen_t *azn, intptr_t arg, int mode)
{
	amdzen_topo_base_t base;

	bzero(&base, sizeof (base));
	mutex_enter(&azn->azn_mutex);
	base.atb_ndf = azn->azn_ndfs;

	if ((azn->azn_flags & AMDZEN_F_APIC_DECOMP_VALID) == 0) {
		mutex_exit(&azn->azn_mutex);
		return (ENOTSUP);
	}

	base.atb_apic_decomp = azn->azn_apic_decomp;
	for (uint_t i = 0; i < azn->azn_ndfs; i++) {
		const amdzen_df_t *df = &azn->azn_dfs[i];

		base.atb_maxdfent = MAX(base.atb_maxdfent, df->adf_nents);
		if (i == 0) {
			base.atb_rev = df->adf_rev;
			base.atb_df_decomp = df->adf_decomp;
		}
	}
	mutex_exit(&azn->azn_mutex);

	if (ddi_copyout(&base, (void *)(uintptr_t)arg, sizeof (base),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * Fill in the peers. We only have this information prior to DF 4D2.  The way we
 * do is this is to just fill in all the entries and then zero out the ones that
 * aren't valid.
 */
static void
amdzen_topo_ioctl_df_fill_peers(const amdzen_df_t *df,
    const amdzen_df_ent_t *ent, amdzen_topo_df_ent_t *topo_ent)
{
	topo_ent->atde_npeers = DF_FBIINFO0_GET_FTI_PCNT(ent->adfe_info0);

	if (df->adf_rev >= DF_REV_4D2) {
		bzero(topo_ent->atde_peers, sizeof (topo_ent->atde_npeers));
		return;
	}

	topo_ent->atde_peers[0] = DF_FBINFO1_GET_FTI0_NINSTID(ent->adfe_info1);
	topo_ent->atde_peers[1] = DF_FBINFO1_GET_FTI1_NINSTID(ent->adfe_info1);
	topo_ent->atde_peers[2] = DF_FBINFO1_GET_FTI2_NINSTID(ent->adfe_info1);
	topo_ent->atde_peers[3] = DF_FBINFO1_GET_FTI3_NINSTID(ent->adfe_info1);
	topo_ent->atde_peers[4] = DF_FBINFO2_GET_FTI4_NINSTID(ent->adfe_info2);
	topo_ent->atde_peers[5] = DF_FBINFO2_GET_FTI5_NINSTID(ent->adfe_info2);

	for (uint32_t i = topo_ent->atde_npeers; i < AMDZEN_TOPO_DF_MAX_PEERS;
	    i++) {
		topo_ent->atde_peers[i] = 0;
	}
}

static void
amdzen_topo_ioctl_df_fill_ccm(const amdzen_df_ent_t *ent,
    amdzen_topo_df_ent_t *topo_ent)
{
	const amdzen_ccm_data_t *ccm = &ent->adfe_data.aded_ccm;
	amdzen_topo_ccm_data_t *topo_ccm = &topo_ent->atde_data.atded_ccm;

	topo_ccm->atcd_nccds = ccm->acd_nccds;
	for (uint32_t i = 0; i < DF_MAX_CCDS_PER_CCM; i++) {
		topo_ccm->atcd_ccd_en[i] = ccm->acd_ccd_en[i];
		topo_ccm->atcd_ccd_ids[i] = ccm->acd_ccd_id[i];
	}
}

static int
amdzen_topo_ioctl_df(amdzen_t *azn, intptr_t arg, int mode)
{
	uint_t model;
	uint32_t max_ents, nwritten;
	const amdzen_df_t *df;
	amdzen_topo_df_t topo_df;
#ifdef	_MULTI_DATAMODEL
	amdzen_topo_df32_t topo_df32;
#endif

	model = ddi_model_convert_from(mode);
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)(uintptr_t)arg, &topo_df32,
		    sizeof (topo_df32), mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		bzero(&topo_df, sizeof (topo_df));
		topo_df.atd_dfno = topo_df32.atd_dfno;
		topo_df.atd_df_buf_nents = topo_df32.atd_df_buf_nents;
		topo_df.atd_df_ents = (void *)(uintptr_t)topo_df32.atd_df_ents;
		break;
#endif
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)(uintptr_t)arg, &topo_df,
		    sizeof (topo_df), mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	mutex_enter(&azn->azn_mutex);
	if (topo_df.atd_dfno >= azn->azn_ndfs) {
		mutex_exit(&azn->azn_mutex);
		return (EINVAL);
	}

	df = &azn->azn_dfs[topo_df.atd_dfno];
	topo_df.atd_nodeid = df->adf_nodeid;
	topo_df.atd_sockid = (df->adf_nodeid & df->adf_decomp.dfd_sock_mask) >>
	    df->adf_decomp.dfd_sock_shift;
	topo_df.atd_dieid = (df->adf_nodeid & df->adf_decomp.dfd_die_mask) >>
	    df->adf_decomp.dfd_die_shift;
	topo_df.atd_rev = df->adf_rev;
	topo_df.atd_major = df->adf_major;
	topo_df.atd_minor = df->adf_minor;
	topo_df.atd_df_act_nents = df->adf_nents;
	max_ents = MIN(topo_df.atd_df_buf_nents, df->adf_nents);

	if (topo_df.atd_df_ents == NULL) {
		topo_df.atd_df_buf_nvalid = 0;
		mutex_exit(&azn->azn_mutex);
		goto copyout;
	}

	nwritten = 0;
	for (uint32_t i = 0; i < max_ents; i++) {
		amdzen_topo_df_ent_t topo_ent;
		const amdzen_df_ent_t *ent = &df->adf_ents[i];

		/*
		 * We opt not to include disabled elements right now. They
		 * generally don't have a valid type and there isn't much useful
		 * information we can get from them. This can be changed if we
		 * find a use case for them for userland topo.
		 */
		if ((ent->adfe_flags & AMDZEN_DFE_F_ENABLED) == 0)
			continue;

		bzero(&topo_ent, sizeof (topo_ent));
		topo_ent.atde_type = ent->adfe_type;
		topo_ent.atde_subtype = ent->adfe_subtype;
		topo_ent.atde_fabric_id = ent->adfe_fabric_id;
		topo_ent.atde_inst_id = ent->adfe_inst_id;
		amdzen_topo_ioctl_df_fill_peers(df, ent, &topo_ent);

		if (amdzen_dfe_is_ccm(df, ent)) {
			amdzen_topo_ioctl_df_fill_ccm(ent, &topo_ent);
		}

		if (ddi_copyout(&topo_ent, &topo_df.atd_df_ents[nwritten],
		    sizeof (topo_ent), mode & FKIOCTL) != 0) {
			mutex_exit(&azn->azn_mutex);
			return (EFAULT);
		}
		nwritten++;
	}
	mutex_exit(&azn->azn_mutex);

	topo_df.atd_df_buf_nvalid = nwritten;
copyout:
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		topo_df32.atd_nodeid = topo_df.atd_nodeid;
		topo_df32.atd_sockid = topo_df.atd_sockid;
		topo_df32.atd_dieid = topo_df.atd_dieid;
		topo_df32.atd_rev = topo_df.atd_rev;
		topo_df32.atd_major = topo_df.atd_major;
		topo_df32.atd_minor = topo_df.atd_minor;
		topo_df32.atd_df_buf_nvalid = topo_df.atd_df_buf_nvalid;
		topo_df32.atd_df_act_nents = topo_df.atd_df_act_nents;

		if (ddi_copyout(&topo_df32, (void *)(uintptr_t)arg,
		    sizeof (topo_df32), mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
#endif
	case DDI_MODEL_NONE:
		if (ddi_copyout(&topo_df, (void *)(uintptr_t)arg,
		    sizeof (topo_df), mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		break;
	}


	return (0);
}

static int
amdzen_topo_ioctl_ccd(amdzen_t *azn, intptr_t arg, int mode)
{
	amdzen_topo_ccd_t ccd, *ccdp;
	amdzen_df_t *df;
	amdzen_df_ent_t *ent;
	amdzen_ccm_data_t *ccm;
	uint32_t ccdno;
	size_t copyin_size = offsetof(amdzen_topo_ccd_t, atccd_err);

	/*
	 * Only copy in the identifying information so that way we can ensure
	 * the rest of the structure we return to the user doesn't contain
	 * anything unexpected in it.
	 */
	bzero(&ccd, sizeof (ccd));
	if (ddi_copyin((void *)(uintptr_t)arg, &ccd, copyin_size,
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	mutex_enter(&azn->azn_mutex);
	if ((azn->azn_flags & AMDZEN_F_APIC_DECOMP_VALID) == 0) {
		ccd.atccd_err = AMDZEN_TOPO_CCD_E_NO_APIC_DECOMP;
		goto copyout;
	}

	df = amdzen_df_find(azn, ccd.atccd_dfno);
	if (df == NULL) {
		ccd.atccd_err = AMDZEN_TOPO_CCD_E_BAD_DFNO;
		goto copyout;
	}

	/*
	 * We don't have enough information to know how to construct this
	 * information in Zen 1 at this time, so refuse.
	 */
	if (df->adf_rev <= DF_REV_2) {
		ccd.atccd_err = AMDZEN_TOPO_CCD_E_SOC_UNSUPPORTED;
		goto copyout;
	}

	ent = amdzen_df_ent_find_by_instid(df, ccd.atccd_instid);
	if (ent == NULL) {
		ccd.atccd_err = AMDZEN_TOPO_CCD_E_BAD_INSTID;
		goto copyout;
	}

	if (!amdzen_dfe_is_ccm(df, ent)) {
		ccd.atccd_err = AMDZEN_TOPO_CCD_E_NOT_A_CCD;
		goto copyout;
	}

	ccm = &ent->adfe_data.aded_ccm;
	for (ccdno = 0; ccdno < DF_MAX_CCDS_PER_CCM; ccdno++) {
		if (ccm->acd_ccd_en[ccdno] != 0 &&
		    ccm->acd_ccd_id[ccdno] == ccd.atccd_phys_no) {
			break;
		}
	}

	if (ccdno == DF_MAX_CCDS_PER_CCM) {
		ccd.atccd_err = AMDZEN_TOPO_CCD_E_NOT_A_CCD;
		goto copyout;
	}

	if (ccm->acd_ccd_data[ccdno] == NULL) {
		/*
		 * We don't actually have this data. Go fill it out and save it
		 * for future use.
		 */
		ccdp = kmem_zalloc(sizeof (amdzen_topo_ccd_t), KM_NOSLEEP_LAZY);
		if (ccdp == NULL) {
			mutex_exit(&azn->azn_mutex);
			return (ENOMEM);
		}

		ccdp->atccd_dfno = ccd.atccd_dfno;
		ccdp->atccd_instid = ccd.atccd_instid;
		ccdp->atccd_phys_no = ccd.atccd_phys_no;
		amdzen_ccd_fill_topo(azn, df, ent, ccdp);
		ccm->acd_ccd_data[ccdno] = ccdp;
	}
	ASSERT3P(ccm->acd_ccd_data[ccdno], !=, NULL);
	bcopy(ccm->acd_ccd_data[ccdno], &ccd, sizeof (ccd));

copyout:
	mutex_exit(&azn->azn_mutex);
	if (ddi_copyout(&ccd, (void *)(uintptr_t)arg, sizeof (ccd),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
amdzen_topo_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	int ret;
	amdzen_t *azn = amdzen_data;

	if (getminor(dev) != AMDZEN_MINOR_TOPO) {
		return (ENXIO);
	}

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	switch (cmd) {
	case AMDZEN_TOPO_IOCTL_BASE:
		ret = amdzen_topo_ioctl_base(azn, arg, mode);
		break;
	case AMDZEN_TOPO_IOCTL_DF:
		ret = amdzen_topo_ioctl_df(azn, arg, mode);
		break;
	case AMDZEN_TOPO_IOCTL_CCD:
		ret = amdzen_topo_ioctl_ccd(azn, arg, mode);
		break;
	default:
		ret = ENOTTY;
		break;
	}

	return (ret);
}

static int
amdzen_topo_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	if (getminor(dev) != AMDZEN_MINOR_TOPO) {
		return (ENXIO);
	}

	return (0);
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

	if (ddi_create_minor_node(dip, "topo", S_IFCHR, AMDZEN_MINOR_TOPO,
	    DDI_PSEUDO, 0) != 0) {
		dev_err(dip, CE_WARN, "failed to create topo minor node!");
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

	ddi_remove_minor_node(azn->azn_dip, NULL);
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

static struct cb_ops amdzen_topo_cb_ops = {
	.cb_open = amdzen_topo_open,
	.cb_close = amdzen_topo_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = amdzen_topo_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

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
	.devo_bus_ops = &amdzen_bus_ops,
	.devo_cb_ops = &amdzen_topo_cb_ops
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
