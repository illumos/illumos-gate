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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <assert.h>
#include <fcntl.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>
#ifdef	__x86
#include <sys/mc.h>
#endif
#include <sys/fm/protocol.h>
#include <string.h>
#include <unistd.h>

typedef struct smb_enum_data {
	topo_mod_t	*sme_mod;
	tnode_t		*sme_pnode;
	tnode_t		*sme_slotnode;
	topo_instance_t	sme_slot_inst;
	topo_instance_t	sme_slot_maxinst;
	smbios_info_t	*sme_smb_info;
	char		*sme_slot_form;
} smb_enum_data_t;

/*
 * This function serves two purposes.  It filters out memory devices that
 * don't have a formfactor that represents a reasonably modern DIMM-like
 * device (and hence not a device we're interested in enumerating).  It also
 * converts the numeric SMBIOS type representation to a more generic TOPO dimm
 * type.
 *
 * Caller must free the returned string.
 */
static char *
distill_dimm_form(topo_mod_t *mod, smbios_memdevice_t *smb_md)
{
	switch (smb_md->smbmd_form) {
	case (SMB_MDFF_DIMM):
		return (topo_mod_strdup(mod, TOPO_DIMM_SLOT_FORM_DIMM));
	case (SMB_MDFF_SODIMM):
		return (topo_mod_strdup(mod, TOPO_DIMM_SLOT_FORM_SODIMM));
	case (SMB_MDFF_FBDIMM):
		return (topo_mod_strdup(mod, TOPO_DIMM_SLOT_FORM_FBDIMM));
	default:
		topo_mod_dprintf(mod, "skipping device with form factor 0x%x",
		    smb_md->smbmd_form);
		return (NULL);
	}
}

static char *
smbios2topotype(topo_mod_t *mod, uint8_t type)
{
	switch (type) {
	case (SMB_MDT_DDR):
		return (topo_mod_strdup(mod, TOPO_DIMM_TYPE_DDR));
	case (SMB_MDT_DDR2):
	case (SMB_MDT_DDR2FBDIMM):
		return (topo_mod_strdup(mod, TOPO_DIMM_TYPE_DDR2));
	case (SMB_MDT_DDR3):
		return (topo_mod_strdup(mod, TOPO_DIMM_TYPE_DDR3));
	case (SMB_MDT_DDR4):
		return (topo_mod_strdup(mod, TOPO_DIMM_TYPE_DDR4));
	case (SMB_MDT_LPDDR):
		return (topo_mod_strdup(mod, TOPO_DIMM_TYPE_LPDDR));
	case (SMB_MDT_LPDDR2):
		return (topo_mod_strdup(mod, TOPO_DIMM_TYPE_LPDDR2));
	case (SMB_MDT_LPDDR3):
		return (topo_mod_strdup(mod, TOPO_DIMM_TYPE_LPDDR3));
	case (SMB_MDT_LPDDR4):
		return (topo_mod_strdup(mod, TOPO_DIMM_TYPE_LPDDR4));
	default:
		return (topo_mod_strdup(mod, TOPO_DIMM_TYPE_UNKNOWN));
	}
}

static boolean_t
is_valid_string(const char *str)
{
	if (strcmp(str, SMB_DEFAULT1) != 0 && strcmp(str, SMB_DEFAULT2) != 0 &&
	    strlen(str) > 0)
		return (B_TRUE);

	return (B_FALSE);
}

static tnode_t *
smbios_make_slot(smb_enum_data_t *smed, smbios_memdevice_t *smb_md)
{
	nvlist_t *auth, *fmri;
	tnode_t *slotnode;
	topo_mod_t *mod = smed->sme_mod;
	topo_pgroup_info_t pgi;
	int err;

	if ((auth = topo_mod_auth(mod, smed->sme_pnode)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_auth() failed: %s",
		    topo_mod_errmsg(mod));
		/* errno set */
		return (NULL);
	}

	if ((fmri = topo_mod_hcfmri(mod, smed->sme_pnode, FM_HC_SCHEME_VERSION,
	    SLOT, smed->sme_slot_inst, NULL, auth, NULL, NULL, NULL)) ==
	    NULL) {
		nvlist_free(auth);
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		/* errno set */
		return (NULL);
	}
	nvlist_free(auth);
	if ((slotnode = topo_node_bind(mod, smed->sme_pnode, SLOT,
	    smed->sme_slot_inst, fmri)) == NULL) {
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		/* errno set */
		return (NULL);
	}
	nvlist_free(fmri);
	fmri = NULL;

	if (topo_node_label_set(slotnode, (char *)smb_md->smbmd_dloc, &err) !=
	    0) {
		topo_mod_dprintf(mod, "failed to set label on %s=%d: %s",
		    SLOT, smed->sme_slot_inst, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return (NULL);
	}
	if (topo_node_fru(smed->sme_pnode, &fmri, NULL, &err) != 0 ||
	    topo_node_fru_set(slotnode, fmri, NULL, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set FRU on %s=%d: %s", SLOT,
		    smed->sme_slot_inst, topo_strerror(err));
		nvlist_free(fmri);
		(void) topo_mod_seterrno(mod, err);
		return (NULL);
	}
	nvlist_free(fmri);

	pgi.tpi_name = TOPO_PGROUP_SLOT;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;
	if (topo_pgroup_create(slotnode, &pgi, &err) != 0 ||
	    topo_prop_set_uint32(slotnode, TOPO_PGROUP_SLOT,
	    TOPO_PROP_SLOT_TYPE, TOPO_PROP_IMMUTABLE, TOPO_SLOT_TYPE_DIMM,
	    &err)) {
		topo_mod_dprintf(mod, "failed to create slot properties: %s",
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return (NULL);
	}

	pgi.tpi_name = TOPO_PGROUP_DIMM_SLOT;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;
	if (topo_pgroup_create(slotnode, &pgi, &err) != 0 ||
	    topo_prop_set_string(slotnode, TOPO_PGROUP_DIMM_SLOT,
	    TOPO_PROP_DIMM_SLOT_FORM, TOPO_PROP_IMMUTABLE, smed->sme_slot_form,
	    &err)) {
		topo_mod_dprintf(mod, "failed to create slot properties: %s",
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return (NULL);
	}
	return (slotnode);
}

static tnode_t *
smbios_make_dimm(smb_enum_data_t *smed, smbios_memdevice_t *smb_md)
{
	nvlist_t *auth, *fmri;
	smbios_info_t *smb_info = smed->sme_smb_info;
	tnode_t *slotnode = smed->sme_slotnode;
	tnode_t *dimmnode, *ret = NULL;
	topo_mod_t *mod = smed->sme_mod;
	topo_pgroup_info_t pgi;
	const char *part = NULL, *rev = NULL, *serial = NULL;
	char *type, *manuf = NULL, *prod = NULL, *asset = NULL, *loc = NULL;
	int err, rc = 0;

	if ((auth = topo_mod_auth(mod, slotnode)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_auth() failed: %s",
		    topo_mod_errmsg(mod));
		/* errno set */
		return (NULL);
	}

	if (smed->sme_smb_info != NULL) {
		if (is_valid_string(smb_info->smbi_part) == B_TRUE)
			part = smb_info->smbi_part;
		if (is_valid_string(smb_info->smbi_version) == B_TRUE)
			rev = smb_info->smbi_version;
		if (is_valid_string(smb_info->smbi_serial) == B_TRUE)
			serial = smb_info->smbi_serial;
		if (is_valid_string(smb_info->smbi_manufacturer) == B_TRUE)
			manuf = topo_mod_clean_str(mod,
			    smb_info->smbi_manufacturer);
		if (is_valid_string(smb_info->smbi_product) == B_TRUE)
			prod = topo_mod_clean_str(mod, smb_info->smbi_product);
		if (is_valid_string(smb_info->smbi_asset) == B_TRUE)
			asset = topo_mod_clean_str(mod, smb_info->smbi_asset);
		if (is_valid_string(smb_info->smbi_location) == B_TRUE)
			loc = topo_mod_clean_str(mod, smb_info->smbi_location);
	}

	if ((fmri = topo_mod_hcfmri(mod, slotnode, FM_HC_SCHEME_VERSION,
	    DIMM, 0, NULL, auth, part, rev, serial)) == NULL) {
		nvlist_free(auth);
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		/* errno set */
		goto err;
	}
	nvlist_free(auth);

	if (topo_node_range_create(mod, slotnode, DIMM, 0, 0) < 0 ||
	    (dimmnode = topo_node_bind(mod, slotnode, DIMM, 0, fmri)) ==
	    NULL) {
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "failed to bind dimm node: %s",
		    topo_mod_errmsg(mod));
		/* errno set */
		goto err;
	}

	if (topo_node_fru_set(dimmnode, fmri, NULL, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set FRU on %s: %s",
		    DIMM, topo_strerror(err));
		nvlist_free(fmri);
		(void) topo_mod_seterrno(mod, err);
		goto err;
	}
	nvlist_free(fmri);

	if (topo_node_label_set(dimmnode, (char *)smb_md->smbmd_dloc, &err) !=
	    0) {
		topo_mod_dprintf(mod, "failed to set label on %s: %s",
		    DIMM, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto err;
	}

	pgi.tpi_name = TOPO_PGROUP_DIMM_PROPS;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;
	if (topo_pgroup_create(dimmnode, &pgi, &err) != 0) {
		(void) topo_mod_seterrno(mod, err);
		goto err;
	}

	rc += topo_prop_set_uint64(dimmnode, TOPO_PGROUP_DIMM_PROPS, "size",
	    TOPO_PROP_IMMUTABLE, smb_md->smbmd_size, &err);
	if (rc == 0 && (type = smbios2topotype(mod, smb_md->smbmd_type)) !=
	    NULL) {
		rc += topo_prop_set_string(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "type", TOPO_PROP_IMMUTABLE, type, &err);
		topo_mod_strfree(mod, type);
	}
	if (rc == 0 && smb_md->smbmd_set != 0 && smb_md->smbmd_set != 0xFF)
		rc += topo_prop_set_uint32(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "set", TOPO_PROP_IMMUTABLE, smb_md->smbmd_set, &err);
	if (rc == 0 && smb_md->smbmd_rank != 0)
		rc += topo_prop_set_uint32(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "rank", TOPO_PROP_IMMUTABLE, smb_md->smbmd_rank, &err);
	if (rc == 0 && smb_md->smbmd_clkspeed != 0)
		rc += topo_prop_set_uint32(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "configured-speed", TOPO_PROP_IMMUTABLE,
		    smb_md->smbmd_clkspeed, &err);
	if (rc == 0 && smb_md->smbmd_speed != 0)
		rc += topo_prop_set_uint32(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "maximum-speed", TOPO_PROP_IMMUTABLE, smb_md->smbmd_speed,
		    &err);
	if (rc == 0 && smb_md->smbmd_maxvolt != 0)
		rc += topo_prop_set_double(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "maximum-voltage", TOPO_PROP_IMMUTABLE,
		    (smb_md->smbmd_maxvolt / 1000), &err);
	if (rc == 0 && smb_md->smbmd_minvolt != 0)
		rc += topo_prop_set_double(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "minimum-voltage", TOPO_PROP_IMMUTABLE,
		    (smb_md->smbmd_minvolt / 1000), &err);
	if (rc == 0 && smb_md->smbmd_confvolt != 0)
		rc += topo_prop_set_double(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "configured-voltage", TOPO_PROP_IMMUTABLE,
		    (smb_md->smbmd_confvolt / 1000), &err);
	if (rc == 0 && manuf != NULL)
		rc += topo_prop_set_string(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "manufacturer", TOPO_PROP_IMMUTABLE, manuf, &err);
	if (rc == 0 && prod != NULL)
		rc += topo_prop_set_string(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "product", TOPO_PROP_IMMUTABLE, prod, &err);
	if (rc == 0 && asset != NULL)
		rc += topo_prop_set_string(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "asset-tag", TOPO_PROP_IMMUTABLE, asset, &err);
	if (rc == 0 && loc != NULL)
		rc += topo_prop_set_string(dimmnode, TOPO_PGROUP_DIMM_PROPS,
		    "location", TOPO_PROP_IMMUTABLE, loc, &err);

	if (rc != 0) {
		topo_mod_dprintf(mod, "error setting properties on %s node",
		    DIMM);
		(void) topo_mod_seterrno(mod, err);
		goto err;
	}
	ret = dimmnode;
err:
	topo_mod_strfree(mod, manuf);
	topo_mod_strfree(mod, prod);
	topo_mod_strfree(mod, asset);
	topo_mod_strfree(mod, loc);
	return (ret);
}

static int
smbios_enum_memory(smbios_hdl_t *shp, const smbios_struct_t *sp, void *arg)
{
	smbios_info_t smb_info;
	smbios_memdevice_t smb_md;
	smb_enum_data_t *smed = arg;
	topo_mod_t *mod = smed->sme_mod;
	tnode_t *slotnode;

	if (sp->smbstr_type != SMB_TYPE_MEMDEVICE)
		return (0);

	if (smbios_info_memdevice(shp, sp->smbstr_id, &smb_md) != 0) {
		topo_mod_dprintf(mod, "libsmbios error");
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	/*
	 * SMB_TYPE_MEMDEVICE records can also be used to represent memory
	 * that come in non-DIMM form factors. If we encounter something like
	 * that, then we skip over it.
	 */
	if ((smed->sme_slot_form = distill_dimm_form(mod, &smb_md)) == NULL)
		return (0);

	if ((slotnode = smbios_make_slot(smed, &smb_md)) == NULL) {
		topo_mod_dprintf(mod, "failed to create %s node", SLOT);
		topo_mod_strfree(mod, smed->sme_slot_form);
		/* errno set */
		return (-1);
	}
	topo_mod_strfree(mod, smed->sme_slot_form);
	smed->sme_slotnode = slotnode;

	/*
	 * A size of zero indicates that the DIMM slot is not populated, so
	 * we skip creating a child dimm node and return.
	 */
	if (smb_md.smbmd_size == 0) {
		smed->sme_slot_inst++;
		return (0);
	}

	if (smbios_info_common(shp, sp->smbstr_id, &smb_info) == 0)
		smed->sme_smb_info = &smb_info;

	if (smbios_make_dimm(smed, &smb_md) == NULL) {
		topo_mod_dprintf(mod, "failed to create %s node", DIMM);
		/* errno set */
		return (-1);
	}
	/*
	 * If we've exceeded our max inst then return non-zero to cause
	 * the walk to terminate.
	 */
	if (++smed->sme_slot_inst > smed->sme_slot_maxinst)
		return (1);

	return (0);
}

/*
 * A system with a functional memory controller driver will have one mc device
 * node per chip instance, starting at instance 0.  The driver provides an
 * ioctl interface for retrieving a snapshot of the system's memory topology.
 * If we're able to issue this ioctl on one of the mc device nodes then we'll
 * return B_TRUE, indicating that this system has a minimally functional memory
 * controller driver.
 */
static boolean_t
has_mc_driver()
{
#ifdef	__x86
	int mc_fd;
	mc_snapshot_info_t mcs;

	if ((mc_fd = open("/dev/mc/mc0", O_RDONLY)) < 0)
		return (B_FALSE);

	if (ioctl(mc_fd, MC_IOC_SNAPSHOT_INFO, &mcs) < 0) {
		(void) close(mc_fd);
		return (B_FALSE);
	}
	(void) close(mc_fd);
	return (B_TRUE);
#else
	return (B_TRUE);
#endif
}

/*ARGSUSED*/
static int
smbios_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *unused)
{
	smbios_hdl_t *smbh;
	smb_enum_data_t smed = { 0 };

	if ((smbh = topo_mod_smbios(mod)) == NULL) {
		topo_mod_dprintf(mod, "failed to get libsmbios handle");
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
	smed.sme_mod = mod;
	smed.sme_pnode = rnode;
	smed.sme_slot_inst = min;
	smed.sme_slot_maxinst = max;

	/*
	 * Currently we only support enumerating dimm-slot and dimm nodes, but
	 * this module could be expanded in the future to enumerate other
	 * hardware components from SMBIOS.
	 */
	if (strcmp(name, SLOT) == 0) {
		/*
		 * If the system has a functional memory controller driver then
		 * we'll assume that it has responsibility for enumerating the
		 * memory topology.
		 */
		if (has_mc_driver() == B_TRUE)
			return (0);
		if (smbios_iter(smbh, smbios_enum_memory, &smed) < 0)
			/* errno set */
			return (-1);
	} else {
		topo_mod_dprintf(mod, "smbios_enum() invoked for unsupported "
		    "node type: %s", name);
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
	return (0);
}

const topo_modops_t smbios_ops = { smbios_enum, NULL };

const topo_modinfo_t smbios_info =
	{ "smbios", FM_FMRI_SCHEME_HC, TOPO_VERSION, &smbios_ops };

/*ARGSUSED*/
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOSMBIOSDEBUG") != NULL)
		topo_mod_setdebug(mod);

	if (topo_mod_register(mod, &smbios_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "module registration failed: %s\n",
		    topo_mod_errmsg(mod));
		/* errno set */
		return (-1);
	}

	topo_mod_dprintf(mod, "SMBIOS enumerator initialized\n");
	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}
