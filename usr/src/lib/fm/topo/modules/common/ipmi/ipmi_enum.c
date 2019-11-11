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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2019 by Western Digital Corporation
 */

#include <assert.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define	TOPO_PGROUP_IPMI		"ipmi"
#define	TOPO_PROP_IPMI_ENTITY_REF	"entity_ref"
#define	TOPO_PROP_IPMI_ENTITY_PRESENT	"entity_present"
#define	FAC_PROV_IPMI			"fac_prov_ipmi"

typedef struct ipmi_enum_data {
	topo_mod_t		*ed_mod;
	tnode_t			*ed_pnode;
	const char		*ed_name;
	char			*ed_label;
	uint8_t			ed_entity;
	topo_instance_t		ed_instance;
	ipmi_sdr_fru_locator_t	*ed_frusdr;
} ipmi_enum_data_t;

static int ipmi_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int ipmi_unusable(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int ipmi_enum(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t, void *, void *);
static int ipmi_post_process(topo_mod_t *, tnode_t *);

extern int ipmi_fru_label(topo_mod_t *mod, tnode_t *node,
    topo_version_t vers, nvlist_t *in, nvlist_t **out);

extern int ipmi_fru_fmri(topo_mod_t *mod, tnode_t *node,
    topo_version_t vers, nvlist_t *in, nvlist_t **out);

static const topo_method_t ipmi_methods[] = {
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC,
	    TOPO_METH_PRESENT_VERSION0, TOPO_STABILITY_INTERNAL, ipmi_present },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL,
	    ipmi_unusable },
	{ "ipmi_fru_label", "Property method", 0,
	    TOPO_STABILITY_INTERNAL, ipmi_fru_label},
	{ "ipmi_fru_fmri", "Property method", 0,
	    TOPO_STABILITY_INTERNAL, ipmi_fru_fmri},
	{ TOPO_METH_SENSOR_FAILURE, TOPO_METH_SENSOR_FAILURE_DESC,
	    TOPO_METH_SENSOR_FAILURE_VERSION, TOPO_STABILITY_INTERNAL,
	    topo_method_sensor_failure },
	{ NULL }
};

const topo_modops_t ipmi_ops = { ipmi_enum, NULL };

const topo_modinfo_t ipmi_info =
	{ "ipmi", FM_FMRI_SCHEME_HC, TOPO_VERSION, &ipmi_ops };

/* Common code used by topo methods below to find an IPMI entity */
static int
ipmi_find_entity(topo_mod_t *mod, tnode_t *tn, ipmi_handle_t **ihpp,
    ipmi_entity_t **epp, char **namep, ipmi_sdr_t **sdrpp)
{
	ipmi_handle_t *ihp;
	ipmi_entity_t *ep;
	int err;
	char *name = NULL, **names;
	ipmi_sdr_t *sdrp = NULL;
	uint_t nelems, i;

	*ihpp = NULL;
	*epp = NULL;
	*namep = NULL;
	*sdrpp = NULL;

	if ((ihp = topo_mod_ipmi_hold(mod)) == NULL)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_UNKNOWN));

	ep = topo_node_getspecific(tn);
	if (ep != NULL) {
		*ihpp = ihp;
		*epp = ep;
		return (0);
	}

	if (topo_prop_get_string(tn, TOPO_PGROUP_IPMI,
	    TOPO_PROP_IPMI_ENTITY_PRESENT, &name, &err) == 0) {
		/*
		 * Some broken IPMI implementations don't export correct
		 * entities, so referring to an entity isn't sufficient.
		 * For these platforms, we allow the XML to specify a
		 * single SDR record that represents the current present
		 * state.
		 */
		sdrp = ipmi_sdr_lookup(ihp, name);
	} else {
		if (topo_prop_get_string_array(tn, TOPO_PGROUP_IPMI,
		    TOPO_PROP_IPMI_ENTITY_REF, &names, &nelems, &err) != 0) {
			/*
			 * Not all nodes have an entity_ref attribute.
			 * For these cases, return ENOTSUP so that we
			 * fall back to the default hc presence
			 * detection.
			 */
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, ETOPO_METHOD_NOTSUP));
		}

		for (i = 0; i < nelems; i++) {
			if ((ep = ipmi_entity_lookup_sdr(ihp, names[i]))
			    != NULL) {
				name = names[i];
				names[i] = NULL;
				break;
			}
		}

		for (i = 0; i < nelems; i++)
			topo_mod_strfree(mod, names[i]);
		topo_mod_free(mod, names, (nelems * sizeof (char *)));

		if (ep == NULL) {
			topo_mod_dprintf(mod,
			    "Failed to get present state of %s=%d\n",
			    topo_node_name(tn), topo_node_instance(tn));
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
		topo_node_setspecific(tn, ep);
	}

	*ihpp = ihp;
	*namep = name;
	*sdrpp = sdrp;
	return (0);
}

/*
 * Determine if the entity is present.
 */
/*ARGSUSED*/
static int
ipmi_present(topo_mod_t *mod, tnode_t *tn, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	ipmi_handle_t *ihp;
	ipmi_entity_t *ep;
	char *name;
	ipmi_sdr_t *sdrp;
	int err;
	boolean_t present = B_FALSE;
	nvlist_t *nvl;

	err = ipmi_find_entity(mod, tn, &ihp, &ep, &name, &sdrp);
	if (err != 0)
		return (err);

	if (ep != NULL) {
		if (ipmi_entity_present(ihp, ep, &present) != 0) {
			topo_mod_dprintf(mod,
			    "ipmi_entity_present() failed: %s",
			    ipmi_errmsg(ihp));
			topo_mod_strfree(mod, name);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}

		topo_mod_dprintf(mod,
		    "ipmi_entity_present(%d, %d) = %d\n", ep->ie_type,
		    ep->ie_instance, present);
	} else if (sdrp != NULL) {
		if (ipmi_entity_present_sdr(ihp, sdrp, &present) != 0) {
			topo_mod_dprintf(mod,
			    "Failed to get present state of %s (%s)\n",
			    name, ipmi_errmsg(ihp));
			topo_mod_strfree(mod, name);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}

		topo_mod_dprintf(mod, "ipmi_entity_present_sdr(%s) = %d\n",
		    name, present);
	}

	topo_mod_strfree(mod, name);
	topo_mod_ipmi_rele(mod);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_add_uint32(nvl, TOPO_METH_PRESENT_RET, present) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;

	return (0);
}

/*
 * Check whether an IPMI entity is a sensor that is unavailable
 */
static int
ipmi_check_sensor(ipmi_handle_t *ihp, ipmi_entity_t *ep, const char *name,
    ipmi_sdr_t *sdrp, void *data)
{
	ipmi_sdr_full_sensor_t *fsp;
	ipmi_sdr_compact_sensor_t *csp;
	uint8_t sensor_number;
	ipmi_sensor_reading_t *reading;

	switch (sdrp->is_type) {
	case IPMI_SDR_TYPE_FULL_SENSOR:
		fsp = (ipmi_sdr_full_sensor_t *)sdrp->is_record;
		sensor_number = fsp->is_fs_number;
		break;

	case IPMI_SDR_TYPE_COMPACT_SENSOR:
		csp = (ipmi_sdr_compact_sensor_t *)sdrp->is_record;
		sensor_number = csp->is_cs_number;
		break;

	default:
		return (0);
	}

	reading = ipmi_get_sensor_reading(ihp, sensor_number);
	if (reading != NULL && reading->isr_state_unavailable)
		return (1);

	return (0);
}

/*
 * Determine if the entity is unusable
 */
/*ARGSUSED*/
static int
ipmi_unusable(topo_mod_t *mod, tnode_t *tn, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	ipmi_handle_t *ihp;
	ipmi_entity_t *ep;
	char *name;
	ipmi_sdr_t *sdrp;
	int err;
	boolean_t unusable = B_FALSE;
	nvlist_t *nvl;

	err = ipmi_find_entity(mod, tn, &ihp, &ep, &name, &sdrp);
	if (err != 0)
		return (err);

	/*
	 * Check whether the IPMI presented us with an entity for a
	 * sensor that is unavailable.
	 */
	if (ep != NULL) {
		unusable = (ipmi_entity_iter_sdr(ihp, ep, ipmi_check_sensor,
		    NULL) != 0);
	} else if (sdrp != NULL) {
		unusable = (ipmi_check_sensor(ihp, NULL, NULL, sdrp,
		    NULL) != 0);
	}

	topo_mod_strfree(mod, name);
	topo_mod_ipmi_rele(mod);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_add_uint32(nvl, TOPO_METH_UNUSABLE_RET, unusable) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;

	return (0);
}

/*
 * This determines if the entity has a FRU locator record set, in which case we
 * treat this as a FRU, even if it's part of an association.
 */
/*ARGSUSED*/
static int
ipmi_check_sdr(ipmi_handle_t *ihp, ipmi_entity_t *ep, const char *name,
    ipmi_sdr_t *sdrp, void *data)
{
	ipmi_enum_data_t *edp = data;

	if (sdrp->is_type == IPMI_SDR_TYPE_FRU_LOCATOR)
		edp->ed_frusdr = (ipmi_sdr_fru_locator_t *)sdrp->is_record;

	return (0);
}

/*
 * Main entity enumerator.  If we find a matching entity type, then instantiate
 * a topo node.
 */
static int
ipmi_check_entity(ipmi_handle_t *ihp, ipmi_entity_t *ep, void *data)
{
	ipmi_enum_data_t *edp = data;
	ipmi_enum_data_t cdata;
	tnode_t *pnode = edp->ed_pnode;
	topo_mod_t *mod = edp->ed_mod;
	topo_mod_t *fmod = topo_mod_getspecific(mod);
	nvlist_t *auth, *fmri;
	tnode_t *tn;
	topo_pgroup_info_t pgi;
	char *frudata = NULL, *part = NULL, *rev = NULL, *serial = NULL;
	ipmi_fru_prod_info_t fruprod = {0};
	ipmi_fru_brd_info_t frubrd = {0};
	int err;
	const char *labelname;
	char label[64];
	size_t len;

	/*
	 * Some questionable IPMI implementations group psu and fan entities
	 * under things like motherboard or chassis entities.  So even if this
	 * entity type isn't typically associated with fans and psus, if it has
	 * children, then regardless of the type we need to decend down and
	 * iterate over them.
	 */
	if (ep->ie_type != edp->ed_entity) {
		if (ep->ie_children != 0 &&
		    ipmi_entity_iter_children(ihp, ep, ipmi_check_entity,
		    data) != 0)
			return (1);
		return (0);
	}

	/*
	 * The purpose of power and cooling domains is to group psus and fans
	 * together.  Unfortunately, some broken IPMI implementations declare
	 * domains that don't contain other elements.  Since the end goal is to
	 * only enumerate psus and fans, we'll just ignore such elements.
	 */
	if ((ep->ie_type == IPMI_ET_POWER_DOMAIN ||
	    ep->ie_type == IPMI_ET_COOLING_DOMAIN) &&
	    ep->ie_children == 0)
		return (0);

	if ((auth = topo_mod_auth(mod, pnode)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_auth() failed: %s",
		    topo_mod_errmsg(mod));
		return (1);
	}

	/*
	 * Determine if there's a FRU record associated with this entity.  If
	 * so, then read in the FRU identity info so that it can be included
	 * in the authority portion of the FMRI.
	 *
	 * topo_mod_hcfmri() will safely except NULL values for the part,
	 * rev and serial params, so we opt to simply drive on in the face of
	 * any strdup failures.
	 */
	edp->ed_frusdr = NULL;
	(void) ipmi_entity_iter_sdr(ihp, ep, ipmi_check_sdr, edp);
	if (edp->ed_frusdr != NULL &&
	    ipmi_fru_read(ihp, edp->ed_frusdr, &frudata) != -1) {
		if (ipmi_fru_parse_product(ihp, frudata, &fruprod) == 0) {
			part = strdup(fruprod.ifpi_part_number);
			rev = strdup(fruprod.ifpi_product_version);
			serial = strdup(fruprod.ifpi_product_serial);
		} else if (ipmi_fru_parse_board(ihp, frudata, &frubrd) == 0) {
			part = strdup(frubrd.ifbi_part_number);
			serial = strdup(frubrd.ifbi_product_serial);
		}
	}
	free(frudata);

	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
	    edp->ed_name, edp->ed_instance, NULL, auth, part, rev,
	    serial)) == NULL) {
		nvlist_free(auth);
		free(part);
		free(rev);
		free(serial);
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		return (1);
	}
	nvlist_free(auth);
	free(part);
	free(rev);
	free(serial);

	if ((tn = topo_node_bind(mod, pnode, edp->ed_name,
	    edp->ed_instance, fmri)) == NULL) {
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		return (1);
	}

	/*
	 * We inherit our label from our parent, appending our label in the
	 * process.  This results in defaults labels of the form "FM 1 FAN 0"
	 * by default when given a hierarchy.
	 */
	if (edp->ed_label != NULL)
		(void) snprintf(label, sizeof (label), "%s ", edp->ed_label);
	else
		label[0] = '\0';

	switch (edp->ed_entity) {
	case IPMI_ET_POWER_DOMAIN:
		labelname = "PM";
		break;

	case IPMI_ET_PSU:
		labelname = "PSU";
		break;

	case IPMI_ET_COOLING_DOMAIN:
		labelname = "FM";
		break;

	case IPMI_ET_FAN:
		labelname = "FAN";
		break;
	}

	len = strlen(label);
	(void) snprintf(label + len, sizeof (label) - len, "%s %d",
	    labelname, edp->ed_instance);

	nvlist_free(fmri);
	edp->ed_instance++;

	if (topo_node_label_set(tn, label, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set label: %s\n",
		    topo_strerror(err));
		return (1);
	}

	/*
	 * Store IPMI entity details as properties on the node
	 */
	pgi.tpi_name = TOPO_PGROUP_IPMI;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;
	if (topo_pgroup_create(tn, &pgi, &err) != 0) {
		if (err != ETOPO_PROP_DEFD) {
			topo_mod_dprintf(mod, "failed to create propgroup "
			    "%s: %s\n", TOPO_PGROUP_IPMI, topo_strerror(err));
			return (1);
		}
	}

	/*
	 * Add properties to contain the IPMI entity id and instance.  This
	 * will be used by the fac_prov_ipmi module to discover and enumerate
	 * facility nodes for any associated sensors.
	 */
	if (topo_prop_set_uint32(tn, TOPO_PGROUP_IPMI, TOPO_PROP_IPMI_ENTITY_ID,
	    TOPO_PROP_IMMUTABLE, ep->ie_type, &err) != 0 ||
	    topo_prop_set_uint32(tn, TOPO_PGROUP_IPMI,
	    TOPO_PROP_IPMI_ENTITY_INST, TOPO_PROP_IMMUTABLE, ep->ie_instance,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to add ipmi properties (%s)",
		    topo_strerror(err));
		return (1);
	}
	if (topo_method_register(mod, tn, ipmi_methods) != 0) {
		topo_mod_dprintf(mod, "topo_method_register() failed: %s",
		    topo_mod_errmsg(mod));
		return (1);
	}

	/*
	 * Invoke the tmo_enum callback from the fac_prov_ipmi module on this
	 * node.  This will have the effect of registering a method on this node
	 * for enumerating sensors.
	 */
	if (fmod == NULL && (fmod = topo_mod_load(mod, FAC_PROV_IPMI,
	    TOPO_VERSION)) == NULL) {
		topo_mod_dprintf(mod, "failed to load %s: %s",
		    FAC_PROV_IPMI, topo_mod_errmsg(mod));
		return (-1);
	}
	topo_mod_setspecific(mod, fmod);

	if (topo_mod_enumerate(fmod, tn, FAC_PROV_IPMI, FAC_PROV_IPMI, 0, 0,
	    NULL) != 0) {
		topo_mod_dprintf(mod, "facility provider enum failed (%s)",
		    topo_mod_errmsg(mod));
		return (1);
	}

	/*
	 * If we are a child of a non-chassis node, and there isn't an explicit
	 * FRU locator record, then propagate the parent's FRU.  Otherwise, set
	 * the FRU to be the same as the resource.
	 */
	if (strcmp(topo_node_name(pnode), CHASSIS) == 0 ||
	    edp->ed_frusdr != NULL) {
		if (topo_node_resource(tn, &fmri, &err) != 0) {
			topo_mod_dprintf(mod, "topo_node_resource() failed: %s",
			    topo_strerror(err));
			(void) topo_mod_seterrno(mod, err);
			return (1);
		}
	} else {
		if (topo_node_fru(pnode, &fmri, NULL, &err) != 0) {
			topo_mod_dprintf(mod, "topo_node_fru() failed: %s",
			    topo_strerror(err));
			(void) topo_mod_seterrno(mod, err);
			return (1);
		}
	}

	if (topo_node_fru_set(tn, fmri, 0, &err) != 0) {
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "topo_node_fru_set() failed: %s",
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return (1);
	}

	topo_node_setspecific(tn, ep);

	nvlist_free(fmri);

	/*
	 * Iterate over children, once for recursive domains and once for
	 * psu/fans.
	 */
	if (ep->ie_children != 0 &&
	    (ep->ie_type == IPMI_ET_POWER_DOMAIN ||
	    ep->ie_type == IPMI_ET_COOLING_DOMAIN)) {
		cdata.ed_mod = edp->ed_mod;
		cdata.ed_pnode = tn;
		cdata.ed_instance = 0;
		cdata.ed_name = edp->ed_name;
		cdata.ed_entity = edp->ed_entity;
		cdata.ed_label = label;

		if (ipmi_entity_iter_children(ihp, ep,
		    ipmi_check_entity, &cdata) != 0)
			return (1);

		switch (cdata.ed_entity) {
		case IPMI_ET_POWER_DOMAIN:
			cdata.ed_entity = IPMI_ET_PSU;
			cdata.ed_name = PSU;
			break;

		case IPMI_ET_COOLING_DOMAIN:
			cdata.ed_entity = IPMI_ET_FAN;
			cdata.ed_name = FAN;
			break;
		}

		if (ipmi_entity_iter_children(ihp, ep,
		    ipmi_check_entity, &cdata) != 0)
			return (1);
	}

	return (0);
}

static const char *
ipmi2toposrc(uint8_t ipmi_ip_src)
{
	char *cfgtype;

	switch (ipmi_ip_src) {
	case (IPMI_LAN_SRC_STATIC):
	case (IPMI_LAN_SRC_BIOS):
		cfgtype = TOPO_NETCFG_TYPE_STATIC;
		break;
	case (IPMI_LAN_SRC_DHCP):
		cfgtype = TOPO_NETCFG_TYPE_DHCP;
		break;
	default:
		cfgtype = TOPO_NETCFG_TYPE_UNKNOWN;
		break;
	}
	return (cfgtype);
}

/*
 * Channel related IPMI commands reserve 4 bits for the channel number.
 */
#define	IPMI_MAX_CHANNEL	0xf

static int
ipmi_enum_sp(topo_mod_t *mod, tnode_t *pnode)
{
	ipmi_handle_t *ihp;
	ipmi_channel_info_t *chinfo;
	ipmi_lan_config_t lancfg = { 0 };
	boolean_t found_lan = B_TRUE;
	char ipv4_addr[INET_ADDRSTRLEN], subnet[INET_ADDRSTRLEN];
	char gateway[INET_ADDRSTRLEN], macaddr[18];
	char ipv6_addr[INET6_ADDRSTRLEN];
	char **ipv6_routes;
	const char *sp_rev, *ipv4_cfgtype, *ipv6_cfgtype;
	nvlist_t *auth, *fmri;
	tnode_t *sp_node;
	topo_pgroup_info_t pgi;
	topo_ufm_slot_info_t slotinfo = { 0 };
	int err, ch, i, ret = -1;

	if ((ihp = topo_mod_ipmi_hold(mod)) == NULL)
		return (0);

	/*
	 * If we're able to successfully get the service processor version by
	 * issuing a GET_DEVICE_ID IPMI command over the KCS interface, then we
	 * can say with certainty that a service processor exists.  If not,
	 * then either the SP is unresponsive or one isn't present.  In either
	 * case, we bail.
	 */
	if ((sp_rev = ipmi_firmware_version(ihp)) == NULL) {
		topo_mod_dprintf(mod, "failed to query SP");
		topo_mod_ipmi_rele(mod);
		return (0);
	}

	if ((auth = topo_mod_auth(mod, pnode)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_auth() failed: %s",
		    topo_mod_errmsg(mod));
		/* errno set */
		goto out;
	}
	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
	    SP, 0, NULL, auth, NULL, sp_rev, NULL)) == NULL) {
		nvlist_free(auth);
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		/* errno set */
		goto out;
	}
	nvlist_free(auth);

	if ((sp_node = topo_node_bind(mod, pnode, SP, 0, fmri)) == NULL) {
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		/* errno set */
		goto out;
	}
	nvlist_free(fmri);
	fmri = NULL;

	if (topo_node_label_set(sp_node, "service-processor", &err) != 0) {
		topo_mod_dprintf(mod, "failed to set label on %s=%d: %s", SP,
		    0, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	if (topo_node_fru(pnode, &fmri, NULL, &err) != 0 ||
	    topo_node_fru_set(sp_node, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set FRU on %s=%d: %s", SP, 0,
		    topo_strerror(err));
		nvlist_free(fmri);
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}
	nvlist_free(fmri);

	/*
	 * Create UFM node to capture the SP LOM version
	 */
	slotinfo.usi_version = sp_rev;
	slotinfo.usi_active = B_TRUE;
	slotinfo.usi_mode = TOPO_UFM_SLOT_MODE_NONE;
	if (topo_node_range_create(mod, sp_node, UFM, 0, 0) != 0 ||
	    topo_mod_create_ufm(mod, sp_node,
	    "Baseboard Management Controller firmware", &slotinfo) == NULL) {
		topo_mod_dprintf(mod, "failed to create %s node", UFM);
		goto out;
	}

	/*
	 * Iterate through the channels to find the LAN channel.
	 */
	for (ch = 0; ch <= IPMI_MAX_CHANNEL; ch++) {
		if ((chinfo = ipmi_get_channel_info(ihp, ch)) != NULL &&
		    chinfo->ici_medium == IPMI_MEDIUM_8023LAN) {
			found_lan = B_TRUE;
			break;
		}
	}
	/*
	 * If we found a LAN channel, look up its configuration so that we can
	 * expose it via node properties.
	 */
	if (found_lan != B_TRUE ||
	    ipmi_lan_get_config(ihp, ch, &lancfg) != 0) {
		(void) fprintf(stderr, "failed to get LAN config\n");
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	pgi.tpi_name = TOPO_PGROUP_NETCFG;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;

	if (topo_pgroup_create(sp_node, &pgi, &err) != 0) {
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	/* Set MAC address property */
	(void) sprintf(macaddr, "%02x:%02x:%02x:%02x:%02x:%02x",
	    lancfg.ilc_macaddr[0], lancfg.ilc_macaddr[1],
	    lancfg.ilc_macaddr[2], lancfg.ilc_macaddr[3],
	    lancfg.ilc_macaddr[4], lancfg.ilc_macaddr[5]);
	macaddr[17] = '\0';

	if (topo_prop_set_string(sp_node, TOPO_PGROUP_NETCFG,
	    TOPO_PROP_NETCFG_MACADDR, TOPO_PROP_IMMUTABLE, macaddr,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to set properties on %s=%d: %s",
		    SP, 0, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	/* Set VLAN ID property, if VLAN is enabled */
	if (lancfg.ilc_vlan_enabled == B_TRUE &&
	    topo_prop_set_uint32(sp_node, TOPO_PGROUP_NETCFG,
	    TOPO_PROP_NETCFG_VLAN_ID, TOPO_PROP_IMMUTABLE, lancfg.ilc_vlan_id,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to set properties on %s=%d: %s",
		    SP, 0, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	/* Set IPv4 configuration properties if IPv4 is enabled */
	if (lancfg.ilc_ipv4_enabled == B_TRUE &&
	    (inet_ntop(AF_INET, &lancfg.ilc_ipaddr, ipv4_addr,
	    sizeof (ipv4_addr)) == NULL ||
	    inet_ntop(AF_INET, &lancfg.ilc_subnet, subnet,
	    sizeof (subnet)) == NULL ||
	    inet_ntop(AF_INET, &lancfg.ilc_gateway_addr, gateway,
	    sizeof (gateway)) == NULL)) {
		(void) fprintf(stderr, "failed to convert IP addresses: %s\n",
		    strerror(errno));
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}
	ipv4_cfgtype = ipmi2toposrc(lancfg.ilc_ipaddr_source);
	if (lancfg.ilc_ipv4_enabled == B_TRUE &&
	    (topo_prop_set_string(sp_node, TOPO_PGROUP_NETCFG,
	    TOPO_PROP_NETCFG_IPV4_ADDR, TOPO_PROP_IMMUTABLE, ipv4_addr,
	    &err) != 0 ||
	    topo_prop_set_string(sp_node, TOPO_PGROUP_NETCFG,
	    TOPO_PROP_NETCFG_IPV4_SUBNET, TOPO_PROP_IMMUTABLE, subnet,
	    &err) != 0 ||
	    topo_prop_set_string(sp_node, TOPO_PGROUP_NETCFG,
	    TOPO_PROP_NETCFG_IPV4_GATEWAY, TOPO_PROP_IMMUTABLE, gateway,
	    &err) != 0 ||
	    topo_prop_set_string(sp_node, TOPO_PGROUP_NETCFG,
	    TOPO_PROP_NETCFG_IPV4_TYPE, TOPO_PROP_IMMUTABLE, ipv4_cfgtype,
	    &err) != 0)) {
		topo_mod_dprintf(mod, "failed to set properties on %s=%d: %s",
		    SP, 0, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	/* Set IPv6 configuration properties if IPv6 is enabled */
	if (lancfg.ilc_ipv6_enabled == B_TRUE) {
		ipv6_cfgtype = ipmi2toposrc(lancfg.ilc_ipv6_source);

		if (inet_ntop(AF_INET6, &lancfg.ilc_ipv6_addr, ipv6_addr,
		    sizeof (ipv6_addr)) == NULL) {
			(void) fprintf(stderr, "failed to convert IPv6 "
			    "address: %s\n", strerror(errno));
			(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
			goto out;
		}

		/* allocate and populate ipv6-routes string array */
		if ((ipv6_routes = topo_mod_zalloc(mod,
		    lancfg.ilc_ipv6_nroutes * sizeof (char *))) == NULL) {
			/* errno set */
			goto out;
		}
		for (i = 0; i < lancfg.ilc_ipv6_nroutes; i++) {
			if ((ipv6_routes[i] = topo_mod_alloc(mod,
			    INET6_ADDRSTRLEN)) == NULL) {
				/* errno set */
				goto out;
			}
		}
		for (i = 0; i < lancfg.ilc_ipv6_nroutes; i++) {
			if (inet_ntop(AF_INET6, &lancfg.ilc_ipv6_routes[i],
			    ipv6_routes[i], sizeof (ipv6_routes[i])) == NULL) {
				(void) fprintf(stderr, "failed to convert "
				    "IPv6 addresses: %s\n", strerror(errno));
				(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
				goto out;
			}
		}
	}
	if (lancfg.ilc_ipv6_enabled == B_TRUE &&
	    (topo_prop_set_string(sp_node, TOPO_PGROUP_NETCFG,
	    TOPO_PROP_NETCFG_IPV6_ADDR, TOPO_PROP_IMMUTABLE, ipv6_addr,
	    &err) != 0 ||
	    topo_prop_set_string_array(sp_node, TOPO_PGROUP_NETCFG,
	    TOPO_PROP_NETCFG_IPV6_ROUTES, TOPO_PROP_IMMUTABLE,
	    (const char **)ipv6_routes, lancfg.ilc_ipv6_nroutes, &err) != 0 ||
	    topo_prop_set_string(sp_node, TOPO_PGROUP_NETCFG,
	    TOPO_PROP_NETCFG_IPV6_TYPE, TOPO_PROP_IMMUTABLE, ipv6_cfgtype,
	    &err) != 0)) {
		topo_mod_dprintf(mod, "failed to set properties on %s=%d: %s",
		    SP, 0, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}
	ret = 0;
out:
	if (lancfg.ilc_ipv6_nroutes > 0) {
		for (i = 0; i < lancfg.ilc_ipv6_nroutes; i++)
			topo_mod_free(mod, ipv6_routes[i], INET6_ADDRSTRLEN);
		topo_mod_free(mod, ipv6_routes,
		    lancfg.ilc_ipv6_nroutes * sizeof (char *));
	}
	topo_mod_ipmi_rele(mod);
	return (ret);
}

/*
 * libtopo enumeration point.  This simply iterates over entities looking for
 * the appropriate type.
 */
/*ARGSUSED*/
static int
ipmi_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *unused)
{
	ipmi_handle_t *ihp;
	ipmi_enum_data_t data;
	int ret;

	/*
	 * If the node being passed in ISN'T the chassis or motherboard node,
	 * then we're being asked to post-process a statically defined node.
	 */
	if (strcmp(topo_node_name(rnode), CHASSIS) != 0 &&
	    strcmp(topo_node_name(rnode), MOTHERBOARD) != 0) {
		if (ipmi_post_process(mod, rnode) != 0) {
			topo_mod_dprintf(mod, "post processing of node %s=%d "
			    "failed!", topo_node_name(rnode),
			    topo_node_instance(rnode));
			return (-1);
		}
		return (0);
	}

	/*
	 * For service processor enumeration we vector off into a special code
	 * path.
	 */
	if (strcmp(name, SP) == 0) {
		if (ipmi_enum_sp(mod, rnode) != 0) {
			topo_mod_dprintf(mod, "failed to enumerate the "
			    "service-processor");
			return (-1);
		}
		return (0);
	}

	if (strcmp(name, POWERMODULE) == 0) {
		data.ed_entity = IPMI_ET_POWER_DOMAIN;
	} else if (strcmp(name, PSU) == 0) {
		data.ed_entity = IPMI_ET_PSU;
	} else if (strcmp(name, FANMODULE) == 0) {
		data.ed_entity = IPMI_ET_COOLING_DOMAIN;
	} else if (strcmp(name, FAN) == 0) {
		data.ed_entity = IPMI_ET_FAN;
	} else {
		topo_mod_dprintf(mod, "unknown enumeration type '%s'",
		    name);
		return (-1);
	}

	if ((ihp = topo_mod_ipmi_hold(mod)) == NULL)
		return (0);

	data.ed_mod = mod;
	data.ed_pnode = rnode;
	data.ed_name = name;
	data.ed_instance = 0;
	data.ed_label = NULL;

	if ((ret = ipmi_entity_iter(ihp, ipmi_check_entity, &data)) != 0) {
		/*
		 * We don't return failure if IPMI enumeration fails.  This may
		 * be due to the SP being unavailable or an otherwise transient
		 * event.
		 */
		if (ret < 0) {
			topo_mod_dprintf(mod,
			    "failed to enumerate entities: %s",
			    ipmi_errmsg(ihp));
		} else {
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
	}

	topo_mod_ipmi_rele(mod);
	return (0);
}

static int
ipmi_post_process(topo_mod_t *mod, tnode_t *tn)
{
	if (topo_method_register(mod, tn, ipmi_methods) != 0) {
		topo_mod_dprintf(mod, "ipmi_post_process() failed: %s",
		    topo_mod_errmsg(mod));
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOIPMIDEBUG") != NULL)
		topo_mod_setdebug(mod);

	if (topo_mod_register(mod, &ipmi_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "module registration failed: %s\n",
		    topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}

	topo_mod_dprintf(mod, "IPMI enumerator initialized\n");
	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	/*
	 * This is the logical, and probably only safe spot where we could
	 * unload fac_prov_ipmi.  But unfortunately, calling topo_mod_unload()
	 * in the context of a module's _topo_fini entry point would result
	 * in recursively grabbing the modhash lock and we'd deadlock.
	 *
	 * Unfortunately, libtopo doesn't currently have a mechanism for
	 * expressing and handling intermodule dependencies, so we're left
	 * with this situation where once a module loads another module,
	 * it's going to be with us until we teardown the process.
	 */
	topo_mod_unregister(mod);
}
