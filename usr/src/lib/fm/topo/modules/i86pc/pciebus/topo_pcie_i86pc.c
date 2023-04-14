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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * This is the i86pc architecture specific part of the pciebus enumeration
 * module. It provides hooks which are called at module init and fini, and
 * after each topology node is created. It uses SMBIOS data to decorate
 * topology nodes with labels.
 *
 * At initialisation time, the SMBIOS structures are walked to collect:
 *  - Processor entries (Type 4) with their socket designations;
 *  - System slot entries (Type 9) with their reference designators and
 *    bus/device/function information;
 *  - On-board device extended entries (Type 41) with their reference
 *    designators and bus/device/function information.
 *
 * This information is then used when decorating topology nodes:
 *  - CPU nodes are labelled with the processor socket designation;
 *  - Downstream port nodes are labelled by matching the parent bridge's
 *    secondary bus number against SMBIOS slot and on-board device entries.
 *
 * The SMBIOS slot and on-board device entries include bus, device, and function
 * numbers but we only match on bus. This is sufficient because PCIe is a
 * point-to-point interface; the downstream side of a port is always on a
 * unique bus, so the bus number uniquely identifies the slot.
 */

#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/smbios.h>

#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/topo_method.h>

#include "topo_pcie_impl.h"

/*
 * An SMBIOS device entry, used for both upgradeable system slots (Type 9) and
 * on-board device extended entries (Type 41). The bus and device/function
 * numbers allow us to correlate SMBIOS entries with devices in the PCIe
 * topology.
 */
typedef struct smbios_dev_entry {
	const char	*sde_label;	/* reference designator */
	uint16_t	sde_sg;		/* segment group */
	uint8_t		sde_bus;	/* bus number */
	uint8_t		sde_df;		/* device/function number */
} smbios_dev_entry_t;

/*
 * An SMBIOS processor entry (Type 4). The label is the socket designation
 * from the structure's common information (location tag).
 */
typedef struct smbios_proc_entry {
	const char	*spe_label;	/* socket designation */
} smbios_proc_entry_t;

typedef struct mod_pcie_privdata {
	/* SMBIOS processor entries (Type 4) */
	smbios_proc_entry_t	*mpp_procs;
	uint_t			mpp_nprocs;
	uint_t			mpp_nprocs_alloc;

	/* SMBIOS slot entries (Type 9) */
	smbios_dev_entry_t	*mpp_slots;
	uint_t			mpp_nslots;
	uint_t			mpp_nslots_alloc;

	/* SMBIOS on-board device entries (Type 41) */
	smbios_dev_entry_t	*mpp_obdevs;
	uint_t			mpp_nobdevs;
	uint_t			mpp_nobdevs_alloc;
} mod_pcie_privdata_t;

static const char *
smbios_find_slot_by_bus(const mod_pcie_privdata_t *pd, uint8_t bus)
{
	for (uint_t i = 0; i < pd->mpp_nslots; i++) {
		if (pd->mpp_slots[i].sde_bus == bus)
			return (pd->mpp_slots[i].sde_label);
	}
	return (NULL);
}

static const char *
smbios_find_obdev_by_bus(const mod_pcie_privdata_t *pd, uint8_t bus)
{
	for (uint_t i = 0; i < pd->mpp_nobdevs; i++) {
		if (pd->mpp_obdevs[i].sde_bus == bus)
			return (pd->mpp_obdevs[i].sde_label);
	}
	return (NULL);
}

/*
 * Decorate a downstream port node with a label derived from SMBIOS.
 *
 * We only label downstream ports, which are ports whose parent in the
 * topology tree is a function node (not a link). The parent function
 * represents a root port or bridge whose bus-range property tells us
 * the secondary bus. This is the bus number where the slot's device
 * appears, and can be matched against SMBIOS slot (Type 9) and on-board
 * device (Type 41) entries.
 */
static tnode_t *
decorate_port(const mod_pcie_privdata_t *pd, topo_mod_t *mod,
    const pcie_node_t *node __unused, tnode_t *tn)
{
	tnode_t *ptn;
	const char *label;
	int *busrange, nval, err;
	uint_t secbus;
	const pcie_node_t *fn;

	ptn = topo_node_parent(tn);
	if (ptn == NULL || strcmp(topo_node_name(ptn), "link") == 0)
		return (tn);

	/*
	 * The parent function node has a pcie_node_t stored via
	 * topo_node_setspecific(). Retrieve it to access the devinfo node
	 * and its bus-range property.
	 */
	fn = topo_node_getspecific(ptn);
	if (fn == NULL || fn->pn_did == DI_NODE_NIL)
		return (tn);

	nval = di_prop_lookup_ints(DDI_DEV_T_ANY, fn->pn_did,
	    DI_BUSRANGE, &busrange);
	if (nval < 1)
		return (tn);

	secbus = (uint8_t)busrange[0];

	topo_mod_dprintf(mod,
	    "decorate port: parent %s%" PRIu64 " secondary bus 0x%02x",
	    topo_node_name(ptn), topo_node_instance(ptn), secbus);

	/*
	 * Prefer slot entries as they are more specific to expansion slots.
	 * Fall back to on-board device entries which cover integrated devices.
	 */
	label = smbios_find_slot_by_bus(pd, secbus);
	if (label == NULL)
		label = smbios_find_obdev_by_bus(pd, secbus);

	if (label != NULL) {
		topo_mod_dprintf(mod, "decorate port: label '%s'", label);
		(void) topo_node_label_set(tn, label, &err);
	}

	return (tn);
}

/*
 * The CPU's topology instance corresponds to the index into the SMBIOS
 * processor structure list (in the order they appear in the SMBIOS tables).
 * We assume that the SMBIOS table order matches the topology instance order;
 * there is no better way to correlate the two, and in practice firmware
 * enumerates processors in socket order.
 */
static tnode_t *
decorate_cpu(const mod_pcie_privdata_t *pd, topo_mod_t *mod,
    const pcie_node_t *node __unused, tnode_t *tn)
{
	topo_instance_t inst = topo_node_instance(tn);
	const char *label;
	int err;

	if (inst >= pd->mpp_nprocs)
		return (tn);

	label = pd->mpp_procs[inst].spe_label;
	if (label != NULL && label[0] != '\0') {
		topo_mod_dprintf(mod,
		    "decorate cpu%" PRIu64 ": label '%s'", inst, label);
		(void) topo_node_label_set(tn, label, &err);
	}

	return (tn);
}

/*
 * This is the main entry point for this arch-specific pciebus component. It is
 * called for every topology node that is created after the basic properties
 * are set.
 */
tnode_t *
mod_pcie_platform_topo_node_decorate(topo_mod_t *mod, const pcie_t *pcie,
    const pcie_node_t *node, tnode_t *tn)
{
	const mod_pcie_privdata_t *pd;
	const char *name;

	pd = pcie_get_platdata(pcie);
	if (pd == NULL) {
		topo_mod_dprintf(mod, "decorate: no privdata");
		return (tn);
	}

	name = topo_node_name(tn);

	topo_mod_dprintf(mod, "decorate: %s%" PRIu64,
	    name, topo_node_instance(tn));

	if (strcmp(name, CPU) == 0)
		return (decorate_cpu(pd, mod, node, tn));
	else if (strcmp(name, "port") == 0)
		return (decorate_port(pd, mod, node, tn));

	return (tn);
}

nvlist_t *
mod_pcie_platform_auth(topo_mod_t *mod, const pcie_t *pcie, tnode_t *parent)
{
	return (topo_mod_auth(mod, parent));
}

/*
 * Collect SMBIOS data for use during topology decoration.
 *
 * This is done in two passes over the SMBIOS structures:
 *  1. Count entries of each type;
 *  2. Allocate arrays and fill them in.
 */
typedef struct mod_pcie_smbios_collect {
	topo_mod_t		*sc_mod;
	smbios_hdl_t		*sc_shp;

	smbios_dev_entry_t	*sc_slots;
	uint_t			sc_nslots;

	smbios_dev_entry_t	*sc_obdevs;
	uint_t			sc_nobdevs;

	smbios_proc_entry_t	*sc_procs;
	uint_t			sc_nprocs;
} mod_pcie_smbios_collect_t;

static int
smbios_collect_count_cb(smbios_hdl_t *shp __unused,
    const smbios_struct_t *sp, void *arg)
{
	mod_pcie_smbios_collect_t *sc = arg;

	switch (sp->smbstr_type) {
	case SMB_TYPE_PROCESSOR:
		sc->sc_nprocs++;
		break;
	case SMB_TYPE_OBDEVEXT:
		sc->sc_nobdevs++;
		break;
	case SMB_TYPE_SLOT:
		sc->sc_nslots++;
		break;
	}

	return (0);
}

static int
smbios_collect_cb(smbios_hdl_t *shp,
    const smbios_struct_t *sp, void *arg)
{
	mod_pcie_smbios_collect_t *sc = arg;

	switch (sp->smbstr_type) {
	case SMB_TYPE_PROCESSOR: {
		smbios_proc_entry_t *entry;
		smbios_processor_t proc;
		smbios_info_t info;

		/*
		 * Always allocate an entry to maintain index alignment with
		 * topology CPU instance numbers, but only populate the label
		 * for sockets that are present.
		 */
		entry = &sc->sc_procs[sc->sc_nprocs++];

		if (smbios_info_processor(shp, sp->smbstr_id, &proc) != 0)
			break;

		if (!SMB_PRSTATUS_PRESENT(proc.smbp_status))
			break;

		if (smbios_info_common(shp, sp->smbstr_id, &info) != 0)
			break;

		/*
		 * The strings returned by the various smbios_info_*()
		 * functions point into the SMBIOS handle's data and are valid
		 * for its lifetime.
		 */
		entry->spe_label = info.smbi_location;

		topo_mod_dprintf(sc->sc_mod, "SMBIOS processor[%u]: '%s'",
		    sc->sc_nprocs - 1, info.smbi_location);
		break;
	}
	case SMB_TYPE_OBDEVEXT: {
		smbios_dev_entry_t *entry;
		smbios_obdev_ext_t ob;

		if (smbios_info_obdevs_ext(shp, sp->smbstr_id, &ob) != 0)
			break;

		entry = &sc->sc_obdevs[sc->sc_nobdevs++];
		entry->sde_label = ob.smboe_name;
		entry->sde_sg = ob.smboe_sg;
		entry->sde_bus = ob.smboe_bus;
		entry->sde_df = ob.smboe_df;

		topo_mod_dprintf(sc->sc_mod,
		    "SMBIOS obdev: '%s' seg %u bus 0x%02x df 0x%02x",
		    ob.smboe_name, ob.smboe_sg, ob.smboe_bus, ob.smboe_df);
		break;
	}
	case SMB_TYPE_SLOT: {
		smbios_dev_entry_t *entry;
		smbios_slot_t slot;

		if (smbios_info_slot(shp, sp->smbstr_id, &slot) != 0)
			break;

		/*
		 * Slots with bus number 0xff are not populated or do not
		 * have valid routing information; skip them.
		 */
		if (slot.smbl_bus == 0xff)
			break;

		entry = &sc->sc_slots[sc->sc_nslots++];
		entry->sde_label = slot.smbl_name;
		entry->sde_sg = slot.smbl_sg;
		entry->sde_bus = slot.smbl_bus;
		entry->sde_df = slot.smbl_df;

		topo_mod_dprintf(sc->sc_mod,
		    "SMBIOS slot: '%s' seg %u bus 0x%02x df 0x%02x",
		    slot.smbl_name, slot.smbl_sg, slot.smbl_bus, slot.smbl_df);
		break;
	}
	default:
		break;
	}

	return (0);
}

static bool
smbios_collect_init(topo_mod_t *mod, mod_pcie_privdata_t *pd)
{
	mod_pcie_smbios_collect_t sc = { 0 };
	smbios_hdl_t *shp;

	shp = topo_mod_smbios(mod);
	if (shp == NULL) {
		topo_mod_dprintf(mod, "SMBIOS not available");
		return (true);
	}

	sc.sc_mod = mod;
	sc.sc_shp = shp;

	/*
	 * Go through and count up the number of entries of each type.
	 * This callback never returns an error.
	 */
	VERIFY0(smbios_iter(shp, smbios_collect_count_cb, &sc));

	topo_mod_dprintf(mod,
	    "SMBIOS counts: processors: %u on-board devices: %u slots: %u",
	    sc.sc_nprocs, sc.sc_nobdevs, sc.sc_nslots);

	if (sc.sc_nprocs > 0) {
		pd->mpp_procs = topo_mod_zalloc(mod,
		    sc.sc_nprocs * sizeof (smbios_proc_entry_t));
		if (pd->mpp_procs == NULL)
			return (false);
		pd->mpp_nprocs_alloc = sc.sc_nprocs;
	}

	if (sc.sc_nobdevs > 0) {
		pd->mpp_obdevs = topo_mod_zalloc(mod,
		    sc.sc_nobdevs * sizeof (smbios_dev_entry_t));
		if (pd->mpp_obdevs == NULL)
			return (false);
		pd->mpp_nobdevs_alloc = sc.sc_nobdevs;
	}

	if (sc.sc_nslots > 0) {
		pd->mpp_slots = topo_mod_zalloc(mod,
		    sc.sc_nslots * sizeof (smbios_dev_entry_t));
		if (pd->mpp_slots == NULL)
			return (false);
		pd->mpp_nslots_alloc = sc.sc_nslots;
	}

	/* Now go through and populate the entries */
	sc.sc_procs = pd->mpp_procs;
	sc.sc_obdevs = pd->mpp_obdevs;
	sc.sc_slots = pd->mpp_slots;
	sc.sc_nprocs = sc.sc_nobdevs = sc.sc_nslots = 0;

	/* This callback never returns an error */
	VERIFY0(smbios_iter(shp, smbios_collect_cb, &sc));

	topo_mod_dprintf(mod,
	    "SMBIOS populated: processors: %u on-board devices: %u slots: %u",
	    sc.sc_nprocs, sc.sc_nobdevs, sc.sc_nslots);

	pd->mpp_nprocs = sc.sc_nprocs;
	pd->mpp_nobdevs = sc.sc_nobdevs;
	pd->mpp_nslots = sc.sc_nslots;

	return (true);
}

static void
privdata_free(topo_mod_t *mod, mod_pcie_privdata_t *pd)
{
	if (pd->mpp_procs != NULL) {
		topo_mod_free(mod, pd->mpp_procs,
		    pd->mpp_nprocs_alloc * sizeof (smbios_proc_entry_t));
	}

	if (pd->mpp_obdevs != NULL) {
		topo_mod_free(mod, pd->mpp_obdevs,
		    pd->mpp_nobdevs_alloc * sizeof (smbios_dev_entry_t));
	}

	if (pd->mpp_slots != NULL) {
		topo_mod_free(mod, pd->mpp_slots,
		    pd->mpp_nslots_alloc * sizeof (smbios_dev_entry_t));
	}

	topo_mod_free(mod, pd, sizeof (*pd));
}

bool
mod_pcie_platform_init(topo_mod_t *mod, pcie_t *pcie)
{
	mod_pcie_privdata_t *pd;

	topo_mod_dprintf(mod, "%s start", __func__);

	if ((pd = topo_mod_zalloc(mod, sizeof (*pd))) == NULL)
		return (false);

	if (!smbios_collect_init(mod, pd)) {
		topo_mod_dprintf(mod, "SMBIOS collection failed");
		privdata_free(mod, pd);
		return (false);
	}

	return (pcie_set_platdata(pcie, pd));
}

void
mod_pcie_platform_fini(topo_mod_t *mod, pcie_t *pcie)
{
	mod_pcie_privdata_t *pd;

	if ((pd = pcie_get_platdata(pcie)) == NULL)
		return;

	privdata_free(mod, pd);
	(void) pcie_set_platdata(pcie, NULL);
}
