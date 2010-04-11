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
 */

#include <alloca.h>
#include <dirent.h>
#include <devid.h>
#include <fm/libdiskstatus.h>
#include <inttypes.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <sys/dkio.h>
#include <sys/fm/protocol.h>
#include <sys/libdevid.h>
#include <sys/scsi/scsi_types.h>
#include <sys/byteorder.h>

#include "disk.h"
#include "ses.h"

#define	SES_VERSION	1

#define	SES_STARTING_SUBCHASSIS 256	/* valid subchassis IDs are uint8_t */
#define	NO_SUBCHASSIS	((uint64_t)-1)

static int ses_snap_freq = 250;		/* in milliseconds */

#define	SES_STATUS_UNAVAIL(s)	\
	((s) == SES_ESC_UNSUPPORTED || (s) >= SES_ESC_NOT_INSTALLED)

/*
 * Because multiple SES targets can be part of a single chassis, we construct
 * our own hierarchy that takes this into account.  These SES targets may refer
 * to the same devices (multiple paths) or to different devices (managing
 * different portions of the space).  We arrange things into a
 * ses_enum_enclosure_t, which contains a set of ses targets, and a list of all
 * nodes found so far.
 */
typedef struct ses_alt_node {
	topo_list_t		san_link;
	ses_node_t		*san_node;
} ses_alt_node_t;

typedef struct ses_enum_node {
	topo_list_t		sen_link;
	ses_node_t		*sen_node;
	topo_list_t		sen_alt_nodes;
	uint64_t		sen_type;
	uint64_t		sen_instance;
	ses_enum_target_t	*sen_target;
} ses_enum_node_t;

typedef struct ses_enum_chassis {
	topo_list_t		sec_link;
	topo_list_t		sec_subchassis;
	topo_list_t		sec_nodes;
	topo_list_t		sec_targets;
	const char		*sec_csn;
	ses_node_t		*sec_enclosure;
	ses_enum_target_t	*sec_target;
	topo_instance_t		sec_instance;
	topo_instance_t		sec_scinstance;
	topo_instance_t		sec_maxinstance;
	boolean_t		sec_hasdev;
	boolean_t		sec_internal;
} ses_enum_chassis_t;

typedef struct ses_enum_data {
	topo_list_t		sed_devs;
	topo_list_t		sed_chassis;
	ses_enum_chassis_t	*sed_current;
	ses_enum_target_t	*sed_target;
	int			sed_errno;
	char			*sed_name;
	topo_mod_t		*sed_mod;
	topo_instance_t		sed_instance;
} ses_enum_data_t;

typedef struct sas_connector_phy_data {
	uint64_t    index;
	uint64_t    phy_mask;
} sas_connector_phy_data_t;

typedef struct sas_connector_type {
	uint64_t    type;
	char	    *name;
} sas_connector_type_t;

static const sas_connector_type_t sas_connector_type_list[] = {
	{   0x0, "Information unknown"  },
	{   0x1, "External SAS 4x receptacle (see SAS-2 and SFF-8470)"	},
	{   0x2, "Exteranl Mini SAS 4x receptacle (see SAS-2 and SFF-8088)" },
	{   0xF, "Vendor-specific external connector"	},
	{   0x10, "Internal wide SAS 4i plug (see SAS-2 and SFF-8484)"	},
	{   0x11,
	"Internal wide Mini SAS 4i receptacle (see SAS-2 and SFF-8087)"	},
	{   0x20, "Internal SAS Drive receptacle (see SAS-2 and SFF-8482)"  },
	{   0x21, "Internal SATA host plug (see SAS-2 and SATA-2)"  },
	{   0x22, "Internal SAS Drive plug (see SAS-2 and SFF-8482)"	},
	{   0x23, "Internal SATA device plug (see SAS-2 and SATA-2)"	},
	{   0x2F, "Internal SAS virtual connector"  },
	{   0x3F, "Vendor-specific internal connector"	},
	{   0x70, "Other Vendor-specific connector"	},
	{   0x71, "Other Vendor-specific connector"	},
	{   0x72, "Other Vendor-specific connector"	},
	{   0x73, "Other Vendor-specific connector"	},
	{   0x74, "Other Vendor-specific connector"	},
	{   0x75, "Other Vendor-specific connector"	},
	{   0x76, "Other Vendor-specific connector"	},
	{   0x77, "Other Vendor-specific connector"	},
	{   0x78, "Other Vendor-specific connector"	},
	{   0x79, "Other Vendor-specific connector"	},
	{   0x7A, "Other Vendor-specific connector"	},
	{   0x7B, "Other Vendor-specific connector"	},
	{   0x7C, "Other Vendor-specific connector"	},
	{   0x7D, "Other Vendor-specific connector"	},
	{   0x7E, "Other Vendor-specific connector"	},
	{   0x7F, "Other Vendor-specific connector"	},
	{   0x80, "Not Defined"	}
};

#define	SAS_CONNECTOR_TYPE_CODE_NOT_DEFINED  0x80
#define	SAS_CONNECTOR_TYPE_NOT_DEFINED \
	"Connector type not definedi by SES-2 standard"
#define	SAS_CONNECTOR_TYPE_RESERVED \
	"Connector type reserved by SES-2 standard"

typedef enum {
	SES_NEW_CHASSIS		= 0x1,
	SES_NEW_SUBCHASSIS	= 0x2,
	SES_DUP_CHASSIS		= 0x4,
	SES_DUP_SUBCHASSIS	= 0x8
} ses_chassis_type_e;

static const topo_pgroup_info_t io_pgroup = {
	TOPO_PGROUP_IO,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t storage_pgroup = {
	TOPO_PGROUP_STORAGE,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static int ses_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int ses_contains(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

static const topo_method_t ses_component_methods[] = {
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC,
	    TOPO_METH_PRESENT_VERSION0, TOPO_STABILITY_INTERNAL, ses_present },
	{ TOPO_METH_FAC_ENUM, TOPO_METH_FAC_ENUM_DESC, 0,
	    TOPO_STABILITY_INTERNAL, ses_node_enum_facility },
	{ TOPO_METH_SENSOR_FAILURE, TOPO_METH_SENSOR_FAILURE_DESC,
	    TOPO_METH_SENSOR_FAILURE_VERSION, TOPO_STABILITY_INTERNAL,
	    topo_method_sensor_failure },
	{ NULL }
};

static const topo_method_t ses_bay_methods[] = {
	{ TOPO_METH_FAC_ENUM, TOPO_METH_FAC_ENUM_DESC, 0,
	    TOPO_STABILITY_INTERNAL, ses_node_enum_facility },
	{ NULL }
};

static const topo_method_t ses_enclosure_methods[] = {
	{ TOPO_METH_CONTAINS, TOPO_METH_CONTAINS_DESC,
	    TOPO_METH_CONTAINS_VERSION, TOPO_STABILITY_INTERNAL, ses_contains },
	{ TOPO_METH_FAC_ENUM, TOPO_METH_FAC_ENUM_DESC, 0,
	    TOPO_STABILITY_INTERNAL, ses_enc_enum_facility },
	{ NULL }
};

static void
ses_target_free(topo_mod_t *mod, ses_enum_target_t *stp)
{
	if (--stp->set_refcount == 0) {
		ses_snap_rele(stp->set_snap);
		ses_close(stp->set_target);
		topo_mod_strfree(mod, stp->set_devpath);
		topo_mod_free(mod, stp, sizeof (ses_enum_target_t));
	}
}

static void
ses_data_free(ses_enum_data_t *sdp, ses_enum_chassis_t *pcp)
{
	topo_mod_t *mod = sdp->sed_mod;
	ses_enum_chassis_t *cp;
	ses_enum_node_t *np;
	ses_enum_target_t *tp;
	ses_alt_node_t *ap;
	topo_list_t *cpl;


	if (pcp != NULL)
		cpl = &pcp->sec_subchassis;
	else
		cpl = &sdp->sed_chassis;

	while ((cp = topo_list_next(cpl)) != NULL) {
		topo_list_delete(cpl, cp);

		while ((np = topo_list_next(&cp->sec_nodes)) != NULL) {
			while ((ap = topo_list_next(&np->sen_alt_nodes)) !=
			    NULL) {
				topo_list_delete(&np->sen_alt_nodes, ap);
				topo_mod_free(mod, ap, sizeof (ses_alt_node_t));
			}
			topo_list_delete(&cp->sec_nodes, np);
			topo_mod_free(mod, np, sizeof (ses_enum_node_t));
		}

		while ((tp = topo_list_next(&cp->sec_targets)) != NULL) {
			topo_list_delete(&cp->sec_targets, tp);
			ses_target_free(mod, tp);
		}

		topo_mod_free(mod, cp, sizeof (ses_enum_chassis_t));
	}

	if (pcp == NULL) {
		dev_list_free(mod, &sdp->sed_devs);
		topo_mod_free(mod, sdp, sizeof (ses_enum_data_t));
	}
}

/*
 * For enclosure nodes, we have a special contains method.  By default, the hc
 * walker will compare the node name and instance number to determine if an
 * FMRI matches.  For enclosures where the enumeration order is impossible to
 * predict, we instead use the chassis-id as a unique identifier, and ignore
 * the instance number.
 */
static int
fmri_contains(topo_mod_t *mod, nvlist_t *nv1, nvlist_t *nv2)
{
	uint8_t v1, v2;
	nvlist_t **hcp1, **hcp2;
	int err, i;
	uint_t nhcp1, nhcp2;
	nvlist_t *a1, *a2;
	char *c1, *c2;
	int mindepth;

	if (nvlist_lookup_uint8(nv1, FM_VERSION, &v1) != 0 ||
	    nvlist_lookup_uint8(nv2, FM_VERSION, &v2) != 0 ||
	    v1 > FM_HC_SCHEME_VERSION || v2 > FM_HC_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_FMRI_VERSION));

	err = nvlist_lookup_nvlist_array(nv1, FM_FMRI_HC_LIST, &hcp1, &nhcp1);
	err |= nvlist_lookup_nvlist_array(nv2, FM_FMRI_HC_LIST, &hcp2, &nhcp2);
	if (err != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	/*
	 * If the chassis-id doesn't match, then these FMRIs are not
	 * equivalent.  If one of the FMRIs doesn't have a chassis ID, then we
	 * have no choice but to fall back to the instance ID.
	 */
	if (nvlist_lookup_nvlist(nv1, FM_FMRI_AUTHORITY, &a1) == 0 &&
	    nvlist_lookup_nvlist(nv2, FM_FMRI_AUTHORITY, &a2) == 0 &&
	    nvlist_lookup_string(a1, FM_FMRI_AUTH_CHASSIS, &c1) == 0 &&
	    nvlist_lookup_string(a2, FM_FMRI_AUTH_CHASSIS, &c2) == 0) {
		if (strcmp(c1, c2) != 0)
			return (0);

		mindepth = 1;
	} else {
		mindepth = 0;
	}

	if (nhcp2 < nhcp1)
		return (0);

	for (i = 0; i < nhcp1; i++) {
		char *nm1 = NULL;
		char *nm2 = NULL;
		char *id1 = NULL;
		char *id2 = NULL;

		(void) nvlist_lookup_string(hcp1[i], FM_FMRI_HC_NAME, &nm1);
		(void) nvlist_lookup_string(hcp2[i], FM_FMRI_HC_NAME, &nm2);
		(void) nvlist_lookup_string(hcp1[i], FM_FMRI_HC_ID, &id1);
		(void) nvlist_lookup_string(hcp2[i], FM_FMRI_HC_ID, &id2);
		if (nm1 == NULL || nm2 == NULL || id1 == NULL || id2 == NULL)
			return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

		if (strcmp(nm1, nm2) == 0 &&
		    (i < mindepth || strcmp(id1, id2) == 0))
			continue;

		return (0);
	}

	return (1);
}

/*ARGSUSED*/
static int
ses_contains(topo_mod_t *mod, tnode_t *tn, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int ret;
	nvlist_t *nv1, *nv2;

	if (version > TOPO_METH_CONTAINS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_FMRI, &nv1) != 0 ||
	    nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_SUBFMRI, &nv2) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	ret = fmri_contains(mod, nv1, nv2);
	if (ret < 0)
		return (-1);

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) == 0) {
		if (nvlist_add_uint32(*out, TOPO_METH_CONTAINS_RET,
		    ret) == 0)
			return (0);
		else
			nvlist_free(*out);
	}

	return (-1);

}

/*
 * Return a current instance of the node.  This is somewhat complicated because
 * we need to take a new snapshot in order to get the new data, but we don't
 * want to be constantly taking SES snapshots if the consumer is going to do a
 * series of queries.  So we adopt the strategy of assuming that the SES state
 * is not going to be rapidly changing, and limit our snapshot frequency to
 * some defined bounds.
 */
ses_node_t *
ses_node_lock(topo_mod_t *mod, tnode_t *tn)
{
	ses_enum_target_t *tp = topo_node_getspecific(tn);
	hrtime_t now;
	ses_snap_t *snap;
	int err;
	uint64_t nodeid;
	ses_node_t *np;

	if (tp == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP);
		return (NULL);
	}

	(void) pthread_mutex_lock(&tp->set_lock);

	/*
	 * Determine if we need to take a new snapshot.
	 */
	now = gethrtime();

	if (now - tp->set_snaptime > (ses_snap_freq * 1000 * 1000) &&
	    (snap = ses_snap_new(tp->set_target)) != NULL) {
		if (ses_snap_generation(snap) !=
		    ses_snap_generation(tp->set_snap)) {
			/*
			 * If we find ourselves in this situation, we're in
			 * trouble.  The generation count has changed, which
			 * indicates that our current topology is out of date.
			 * But we need to consult the new topology in order to
			 * determine presence at this moment in time.  We can't
			 * go back and change the topo snapshot in situ, so
			 * we'll just have to fail the call in this unlikely
			 * scenario.
			 */
			ses_snap_rele(snap);
			(void) topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP);
			(void) pthread_mutex_unlock(&tp->set_lock);
			return (NULL);
		} else {
			ses_snap_rele(tp->set_snap);
			tp->set_snap = snap;
		}
		tp->set_snaptime = gethrtime();
	}

	snap = tp->set_snap;

	verify(topo_prop_get_uint64(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_NODE_ID, &nodeid, &err) == 0);
	verify((np = ses_node_lookup(snap, nodeid)) != NULL);

	return (np);
}

/*ARGSUSED*/
void
ses_node_unlock(topo_mod_t *mod, tnode_t *tn)
{
	ses_enum_target_t *tp = topo_node_getspecific(tn);

	verify(tp != NULL);

	(void) pthread_mutex_unlock(&tp->set_lock);
}

/*
 * Determine if the element is present.
 */
/*ARGSUSED*/
static int
ses_present(topo_mod_t *mod, tnode_t *tn, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	boolean_t present;
	ses_node_t *np;
	nvlist_t *props, *nvl;
	uint64_t status;

	if ((np = ses_node_lock(mod, tn)) == NULL)
		return (-1);

	verify((props = ses_node_props(np)) != NULL);
	verify(nvlist_lookup_uint64(props,
	    SES_PROP_STATUS_CODE, &status) == 0);

	ses_node_unlock(mod, tn);

	present = (status != SES_ESC_NOT_INSTALLED);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_add_uint32(nvl, TOPO_METH_PRESENT_RET,
	    present) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;

	return (0);
}

/*
 * Sets standard properties for a ses node (enclosure, bay, controller
 * or expander).
 * This includes setting the FRU, as well as setting the
 * authority information.  When  the fru topo node(frutn) is not NULL
 * its resouce should be used as FRU.
 */
static int
ses_set_standard_props(topo_mod_t *mod, tnode_t *frutn, tnode_t *tn,
    nvlist_t *auth, uint64_t nodeid, const char *path)
{
	int err;
	char *product, *chassis;
	nvlist_t *fmri;
	topo_pgroup_info_t pgi;

	/*
	 * Set the authority explicitly if specified.
	 */
	if (auth) {
		verify(nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT,
		    &product) == 0);
		verify(nvlist_lookup_string(auth, FM_FMRI_AUTH_CHASSIS,
		    &chassis) == 0);
		if (topo_prop_set_string(tn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, TOPO_PROP_IMMUTABLE, product,
		    &err) != 0 ||
		    topo_prop_set_string(tn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, TOPO_PROP_IMMUTABLE, chassis,
		    &err) != 0 ||
		    topo_prop_set_string(tn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, TOPO_PROP_IMMUTABLE, "",
		    &err) != 0) {
			topo_mod_dprintf(mod, "failed to add authority "
			    "properties: %s\n", topo_strerror(err));
			return (topo_mod_seterrno(mod, err));
		}
	}

	/*
	 * Copy the resource and set that as the FRU.
	 */
	if (frutn != NULL) {
		if (topo_node_resource(frutn, &fmri, &err) != 0) {
			topo_mod_dprintf(mod,
			    "topo_node_resource() failed : %s\n",
			    topo_strerror(err));
			return (topo_mod_seterrno(mod, err));
		}
	} else {
		if (topo_node_resource(tn, &fmri, &err) != 0) {
			topo_mod_dprintf(mod,
			    "topo_node_resource() failed : %s\n",
			    topo_strerror(err));
			return (topo_mod_seterrno(mod, err));
		}
	}

	if (topo_node_fru_set(tn, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_fru_set() failed : %s\n",
		    topo_strerror(err));
		nvlist_free(fmri);
		return (topo_mod_seterrno(mod, err));
	}

	nvlist_free(fmri);

	/*
	 * Set the SES-specific properties so that consumers can query
	 * additional information about the particular SES element.
	 */
	pgi.tpi_name = TOPO_PGROUP_SES;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;
	if (topo_pgroup_create(tn, &pgi, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create propgroup "
		    "%s: %s\n", TOPO_PGROUP_SES, topo_strerror(err));
		return (-1);
	}

	if (topo_prop_set_uint64(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_NODE_ID, TOPO_PROP_IMMUTABLE,
	    nodeid, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to create property %s: %s\n",
		    TOPO_PROP_NODE_ID, topo_strerror(err));
		return (-1);
	}

	if (topo_prop_set_string(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_TARGET_PATH, TOPO_PROP_IMMUTABLE,
	    path, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to create property %s: %s\n",
		    TOPO_PROP_TARGET_PATH, topo_strerror(err));
		return (-1);
	}

	return (0);
}

/*
 * Callback to add a disk to a given bay.  We first check the status-code to
 * determine if a disk is present, ignoring those that aren't in an appropriate
 * state.  We then scan the parent bay node's SAS address array to determine
 * possible attached SAS addresses.  We create a disk node if the disk is not
 * SAS or the SES target does not support the necessary pages for this; if we
 * find the SAS address, we create a disk node and also correlate it with
 * the corresponding Solaris device node to fill in the rest of the data.
 */
static int
ses_create_disk(ses_enum_data_t *sdp, tnode_t *pnode, nvlist_t *props)
{
	topo_mod_t *mod = sdp->sed_mod;
	uint64_t status;
	nvlist_t **sas;
	uint_t s, nsas;
	char **paths;
	int err, ret;
	tnode_t *child = NULL;

	/*
	 * Skip devices that are not in a present (and possibly damaged) state.
	 */
	if (nvlist_lookup_uint64(props, SES_PROP_STATUS_CODE, &status) != 0)
		return (0);

	if (status != SES_ESC_UNSUPPORTED &&
	    status != SES_ESC_OK &&
	    status != SES_ESC_CRITICAL &&
	    status != SES_ESC_NONCRITICAL &&
	    status != SES_ESC_UNRECOVERABLE &&
	    status != SES_ESC_NO_ACCESS)
		return (0);

	topo_mod_dprintf(mod, "found attached disk");

	/*
	 * Create the disk range.
	 */
	if (topo_node_range_create(mod, pnode, DISK, 0, 0) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_create_range() failed: %s",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	/*
	 * Look through all SAS addresses and attempt to correlate them to a
	 * known Solaris device.  If we don't find a matching node, then we
	 * don't enumerate the disk node.
	 */
	if (nvlist_lookup_nvlist_array(props, SES_SAS_PROP_PHYS,
	    &sas, &nsas) != 0)
		return (0);

	if (topo_prop_get_string_array(pnode, TOPO_PGROUP_SES,
	    TOPO_PROP_SAS_ADDR, &paths, &nsas, &err) != 0)
		return (0);

	err = 0;

	for (s = 0; s < nsas; s++) {
		ret = disk_declare_addr(mod, pnode, &sdp->sed_devs, paths[s],
		    &child);
		if (ret == 0) {
			break;
		} else if (ret < 0) {
			err = -1;
			break;
		}
	}

	if (s == nsas)
		disk_declare_non_enumerated(mod, pnode, &child);

	/* copy sas_addresses (target-ports) from parent (with 'w'added) */
	if (child != NULL) {
		int i;
		char **tports;
		uint64_t wwn;

		tports = topo_mod_zalloc(mod, sizeof (char *) * nsas);
		if (tports != NULL) {
			for (i = 0; i < nsas; i++) {
				if (scsi_wwnstr_to_wwn(paths[i], &wwn) !=
				    DDI_SUCCESS)
					break;
				tports[i] = scsi_wwn_to_wwnstr(wwn, 1, NULL);
				if (tports[i] == NULL)
					break;
			}
			/* if they all worked then create the property */
			if (i == nsas)
				(void) topo_prop_set_string_array(child,
				    TOPO_PGROUP_STORAGE,
				    TOPO_STORAGE_TARGET_PORT_L0IDS,
				    TOPO_PROP_IMMUTABLE, (const char **)tports,
				    nsas, &err);

			for (i = 0; i < nsas; i++)
				if (tports[i] != NULL)
					scsi_free_wwnstr(tports[i]);
			topo_mod_free(mod, tports, sizeof (char *) * nsas);
		}
	}

	for (s = 0; s < nsas; s++)
		topo_mod_free(mod, paths[s], strlen(paths[s]) + 1);
	topo_mod_free(mod, paths, nsas * sizeof (char *));

	return (err);
}

static int
ses_add_bay_props(topo_mod_t *mod, tnode_t *tn, ses_enum_node_t *snp)
{
	ses_alt_node_t *ap;
	ses_node_t *np;
	nvlist_t *props;

	nvlist_t **phys;
	uint_t i, j, n_phys, all_phys = 0;
	char **paths;
	uint64_t addr;
	size_t len;
	int terr, err = -1;

	for (ap = topo_list_next(&snp->sen_alt_nodes); ap != NULL;
	    ap = topo_list_next(ap)) {
		np = ap->san_node;
		props = ses_node_props(np);

		if (nvlist_lookup_nvlist_array(props, SES_SAS_PROP_PHYS,
		    &phys, &n_phys) != 0)
			continue;

		all_phys += n_phys;
	}

	if (all_phys == 0)
		return (0);

	if ((paths = topo_mod_zalloc(mod, all_phys * sizeof (char *))) == NULL)
		return (-1);

	for (i = 0, ap = topo_list_next(&snp->sen_alt_nodes); ap != NULL;
	    ap = topo_list_next(ap)) {
		np = ap->san_node;
		props = ses_node_props(np);

		if (nvlist_lookup_nvlist_array(props, SES_SAS_PROP_PHYS,
		    &phys, &n_phys) != 0)
			continue;

		for (j = 0; j < n_phys; j++) {
			if (nvlist_lookup_uint64(phys[j], SES_SAS_PROP_ADDR,
			    &addr) != 0)
				continue;

			len = snprintf(NULL, 0, "%016llx", addr) + 1;
			if ((paths[i] = topo_mod_alloc(mod, len)) == NULL)
				goto error;

			(void) snprintf(paths[i], len, "%016llx", addr);

			++i;
		}
	}

	err = topo_prop_set_string_array(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_SAS_ADDR, TOPO_PROP_IMMUTABLE,
	    (const char **)paths, i, &terr);
	if (err != 0)
		err = topo_mod_seterrno(mod, terr);

error:
	for (i = 0; i < all_phys && paths[i] != NULL; i++)
		topo_mod_free(mod, paths[i], strlen(paths[i]) + 1);
	topo_mod_free(mod, paths, all_phys * sizeof (char *));

	return (err);
}

/*
 * Callback to create a basic node (bay, psu, fan, or controller and expander).
 */
static int
ses_create_generic(ses_enum_data_t *sdp, ses_enum_node_t *snp,
    tnode_t *pnode, const char *nodename, const char *labelname, tnode_t **node)
{
	ses_node_t *np = snp->sen_node;
	ses_node_t *parent;
	uint64_t instance = snp->sen_instance;
	topo_mod_t *mod = sdp->sed_mod;
	nvlist_t *props, *aprops;
	nvlist_t *auth = NULL, *fmri = NULL;
	tnode_t *tn = NULL, *frutn = NULL;
	char label[128];
	int err;
	char *part = NULL, *serial = NULL, *revision = NULL;
	char *desc;
	boolean_t report;

	props = ses_node_props(np);

	(void) nvlist_lookup_string(props, LIBSES_PROP_PART, &part);
	(void) nvlist_lookup_string(props, LIBSES_PROP_SERIAL, &serial);

	topo_mod_dprintf(mod, "adding %s %llu", nodename, instance);

	/*
	 * Create the node.  The interesting information is all copied from the
	 * parent enclosure node, so there is not much to do.
	 */
	if ((auth = topo_mod_auth(mod, pnode)) == NULL)
		goto error;

	/*
	 * We want to report revision information for the controller nodes, but
	 * we do not get per-element revision information.  However, we do have
	 * revision information for the entire enclosure, and we can use the
	 * 'reported-via' property to know that this controller corresponds to
	 * the given revision information.  This means we cannot get revision
	 * information for targets we are not explicitly connected to, but
	 * there is little we can do about the situation.
	 */
	if (strcmp(nodename, CONTROLLER) == 0 &&
	    nvlist_lookup_boolean_value(props, SES_PROP_REPORT, &report) == 0 &&
	    report) {
		for (parent = ses_node_parent(np); parent != NULL;
		    parent = ses_node_parent(parent)) {
			if (ses_node_type(parent) == SES_NODE_ENCLOSURE) {
				(void) nvlist_lookup_string(
				    ses_node_props(parent),
				    SES_EN_PROP_REV, &revision);
				break;
			}
		}
	}

	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
	    nodename, (topo_instance_t)instance, NULL, auth, part, revision,
	    serial)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((tn = topo_node_bind(mod, pnode, nodename,
	    instance, fmri)) == NULL) {
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	/*
	 * For the node label, we look for the following in order:
	 *
	 * 	<ses-description>
	 * 	<ses-class-description> <instance>
	 * 	<default-type-label> <instance>
	 */
	if (nvlist_lookup_string(props, SES_PROP_DESCRIPTION, &desc) != 0 ||
	    desc[0] == '\0') {
		parent = ses_node_parent(np);
		aprops = ses_node_props(parent);
		if (nvlist_lookup_string(aprops, SES_PROP_CLASS_DESCRIPTION,
		    &desc) != 0 || desc[0] == '\0')
			desc = (char *)labelname;
		(void) snprintf(label, sizeof (label), "%s %llu", desc,
		    instance);
		desc = label;
	}

	if (topo_node_label_set(tn, desc, &err) != 0)
		goto error;

	/*
	 * For an expander node, set the FRU to its parent(controller).
	 * For a connector node, set the FRU to its grand parent(controller).
	 */
	if (strcmp(nodename, SASEXPANDER) == 0) {
		frutn = pnode;
	} else if (strcmp(nodename, RECEPTACLE) == 0) {
		frutn = topo_node_parent(pnode);
	}

	if (ses_set_standard_props(mod, frutn, tn, NULL, ses_node_id(np),
	    snp->sen_target->set_devpath) != 0)
		goto error;

	if (strcmp(nodename, BAY) == 0) {
		if (ses_add_bay_props(mod, tn, snp) != 0)
			goto error;

		if (ses_create_disk(sdp, tn, props) != 0)
			goto error;

		if (topo_method_register(mod, tn, ses_bay_methods) != 0) {
			topo_mod_dprintf(mod,
			    "topo_method_register() failed: %s",
			    topo_mod_errmsg(mod));
			goto error;
		}
	} else if ((strcmp(nodename, FAN) == 0) ||
	    (strcmp(nodename, PSU) == 0) ||
	    (strcmp(nodename, CONTROLLER) == 0)) {
		/*
		 * Only fan, psu, and controller nodes have a 'present' method.
		 * Bay nodes are always present, and disk nodes are present by
		 * virtue of being enumerated and SAS expander nodes and
		 * SAS connector nodes are also always present once
		 * the parent controller is found.
		 */
		if (topo_method_register(mod, tn, ses_component_methods) != 0) {
			topo_mod_dprintf(mod,
			    "topo_method_register() failed: %s",
			    topo_mod_errmsg(mod));
			goto error;
		}

	}

	snp->sen_target->set_refcount++;
	topo_node_setspecific(tn, snp->sen_target);

	nvlist_free(auth);
	nvlist_free(fmri);
	if (node != NULL) *node = tn;
	return (0);

error:
	nvlist_free(auth);
	nvlist_free(fmri);
	return (-1);
}

/*
 * Create SAS expander specific props.
 */
/*ARGSUSED*/
static int
ses_set_expander_props(ses_enum_data_t *sdp, ses_enum_node_t *snp,
    tnode_t *ptnode, tnode_t *tnode, int *phycount, int64_t *connlist)
{
	ses_node_t *np = snp->sen_node;
	topo_mod_t *mod = sdp->sed_mod;
	nvlist_t *auth = NULL, *fmri = NULL;
	nvlist_t *props, **phylist;
	int err, i;
	uint_t pcount;
	uint64_t sasaddr, connidx;
	char sasaddr_str[17];
	boolean_t found = B_FALSE;
	dev_di_node_t *dnode;

	props = ses_node_props(np);

	/*
	 * the uninstalled expander is not enumerated by checking
	 * the element status code.  No present present' method provided.
	 */
	/*
	 * Get the Expander SAS address.  It should exist.
	 */
	if (nvlist_lookup_uint64(props, SES_EXP_PROP_SAS_ADDR,
	    &sasaddr) != 0) {
		topo_mod_dprintf(mod,
		    "Failed to get prop %s.", SES_EXP_PROP_SAS_ADDR);
		goto error;
	}

	(void) sprintf(sasaddr_str, "%llx", sasaddr);

	/* search matching dev_di_node. */
	for (dnode = topo_list_next(&sdp->sed_devs); dnode != NULL;
	    dnode = topo_list_next(dnode)) {
		if (strstr(dnode->ddn_dpath, sasaddr_str) != NULL) {
			found = B_TRUE;
			break;
		}
	}

	if (!found) {
		topo_mod_dprintf(mod,
		    "ses_set_expander_props: Failed to find matching "
		    "devinfo node for Exapnder SAS address %s",
		    SES_EXP_PROP_SAS_ADDR);
		/* continue on to get storage group props. */
	} else {
		/* create/set the devfs-path and devid in the io group */
		if (topo_pgroup_create(tnode, &io_pgroup, &err) != 0) {
			topo_mod_dprintf(mod, "ses_set_expander_props: "
			    "create io error %s\n", topo_strerror(err));
			goto error;
		} else {
			if (topo_prop_set_string(tnode, TOPO_PGROUP_IO,
			    TOPO_IO_DEV_PATH, TOPO_PROP_IMMUTABLE,
			    dnode->ddn_dpath, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set dev error %s\n", topo_strerror(err));
			}
			if (topo_prop_set_string(tnode, TOPO_PGROUP_IO,
			    TOPO_IO_DEVID, TOPO_PROP_IMMUTABLE,
			    dnode->ddn_devid, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set devid error %s\n", topo_strerror(err));
			}
			if (dnode->ddn_ppath_count != 0 &&
			    topo_prop_set_string_array(tnode, TOPO_PGROUP_IO,
			    TOPO_IO_PHYS_PATH, TOPO_PROP_IMMUTABLE,
			    (const char **)dnode->ddn_ppath,
			    dnode->ddn_ppath_count, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set phys-path error %s\n",
				    topo_strerror(err));
			}
		}
	}

	/* create the storage group */
	if (topo_pgroup_create(tnode, &storage_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "ses_set_expander_props: "
		    "create storage error %s\n", topo_strerror(err));
		goto error;
	} else {
		/* set the SAS address prop of the expander. */
		if (topo_prop_set_string(tnode, TOPO_PGROUP_STORAGE,
		    TOPO_PROP_SAS_ADDR, TOPO_PROP_IMMUTABLE, sasaddr_str,
		    &err) != 0) {
			topo_mod_dprintf(mod, "ses_set_expander_props: "
			    "set %S error %s\n", TOPO_PROP_SAS_ADDR,
			    topo_strerror(err));
		}

		/* Get the phy information for the expander */
		if (nvlist_lookup_nvlist_array(props, SES_SAS_PROP_PHYS,
		    &phylist, &pcount) != 0) {
			topo_mod_dprintf(mod,
			    "Failed to get prop %s.", SES_SAS_PROP_PHYS);
		} else {
			/*
			 * For each phy, get the connector element index and
			 * stores into connector element index array.
			 */
			*phycount = pcount;
			for (i = 0; i < pcount; i++) {
				if (nvlist_lookup_uint64(phylist[i],
				    SES_PROP_CE_IDX, &connidx) == 0) {
					if (connidx != 0xff) {
						connlist[i] = connidx;
					} else {
						connlist[i] = -1;
					}
				} else {
					/* Fail to get the index. set to -1. */
					connlist[i] = -1;
				}
			}

			/* set the phy count prop of the expander. */
			if (topo_prop_set_uint64(tnode, TOPO_PGROUP_STORAGE,
			    TOPO_PROP_PHY_COUNT, TOPO_PROP_IMMUTABLE, pcount,
			    &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set %S error %s\n", TOPO_PROP_PHY_COUNT,
				    topo_strerror(err));
			}

			/*
			 * set the connector element index of
			 * the expander phys.
			 */
		}

		/* populate other misc storage group properties */
		if (found) {
			if (dnode->ddn_mfg && (topo_prop_set_string(tnode,
			    TOPO_PGROUP_STORAGE, TOPO_STORAGE_MANUFACTURER,
			    TOPO_PROP_IMMUTABLE, dnode->ddn_mfg, &err) != 0)) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set mfg error %s\n", topo_strerror(err));
			}

			if (dnode->ddn_model && (topo_prop_set_string(tnode,
			    TOPO_PGROUP_STORAGE, TOPO_STORAGE_MODEL,
			    TOPO_PROP_IMMUTABLE,
			    dnode->ddn_model, &err) != 0)) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set model error %s\n", topo_strerror(err));
			}

			if (dnode->ddn_serial && (topo_prop_set_string(tnode,
			    TOPO_PGROUP_STORAGE, TOPO_STORAGE_SERIAL_NUM,
			    TOPO_PROP_IMMUTABLE,
			    dnode->ddn_serial, &err) != 0)) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set serial error %s\n",
				    topo_strerror(err));
			}

			if (dnode->ddn_firm && (topo_prop_set_string(tnode,
			    TOPO_PGROUP_STORAGE,
			    TOPO_STORAGE_FIRMWARE_REV, TOPO_PROP_IMMUTABLE,
			    dnode->ddn_firm, &err) != 0)) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set firm error %s\n", topo_strerror(err));
			}
		}
	}

	return (0);

error:
	nvlist_free(auth);
	nvlist_free(fmri);
	return (-1);
}

/*
 * Create SAS expander specific props.
 */
/*ARGSUSED*/
static int
ses_set_connector_props(ses_enum_data_t *sdp, ses_enum_node_t *snp,
    tnode_t *tnode, int64_t phy_mask)
{
	ses_node_t *np = snp->sen_node;
	topo_mod_t *mod = sdp->sed_mod;
	nvlist_t *props;
	int err, i;
	uint64_t conntype;
	char phymask_str[17], *conntype_str;
	boolean_t   found;

	props = ses_node_props(np);

	/*
	 * convert phy mask to string.
	 */
	(void) snprintf(phymask_str, 17, "%llx", phy_mask);

	/* create the storage group */
	if (topo_pgroup_create(tnode, &storage_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "ses_set_expander_props: "
		    "create storage error %s\n", topo_strerror(err));
		return (-1);
	} else {
		/* set the SAS address prop of the expander. */
		if (topo_prop_set_string(tnode, TOPO_PGROUP_STORAGE,
		    TOPO_STORAGE_SAS_PHY_MASK, TOPO_PROP_IMMUTABLE,
		    phymask_str, &err) != 0) {
			topo_mod_dprintf(mod, "ses_set_expander_props: "
			    "set %S error %s\n", TOPO_STORAGE_SAS_PHY_MASK,
			    topo_strerror(err));
		}

		/* Get the connector type information for the expander */
		if (nvlist_lookup_uint64(props,
		    SES_SC_PROP_CONNECTOR_TYPE, &conntype) != 0) {
			topo_mod_dprintf(mod, "Failed to get prop %s.",
			    TOPO_STORAGE_SAS_PHY_MASK);
		} else {
			found = B_FALSE;
			for (i = 0; ; i++) {
				if (sas_connector_type_list[i].type ==
				    SAS_CONNECTOR_TYPE_CODE_NOT_DEFINED) {
					break;
				}
				if (sas_connector_type_list[i].type ==
				    conntype) {
					conntype_str =
					    sas_connector_type_list[i].name;
					found = B_TRUE;
					break;
				}
			}

			if (!found) {
				if (conntype <
				    SAS_CONNECTOR_TYPE_CODE_NOT_DEFINED) {
					conntype_str =
					    SAS_CONNECTOR_TYPE_RESERVED;
				} else {
					conntype_str =
					    SAS_CONNECTOR_TYPE_NOT_DEFINED;
				}
			}

			/* set the phy count prop of the expander. */
			if (topo_prop_set_string(tnode, TOPO_PGROUP_STORAGE,
			    TOPO_STORAGE_SAS_CONNECTOR_TYPE,
			    TOPO_PROP_IMMUTABLE, conntype_str, &err) != 0) {
				topo_mod_dprintf(mod, "ses_set_expander_props: "
				    "set %S error %s\n", TOPO_PROP_PHY_COUNT,
				    topo_strerror(err));
			}
		}
	}

	return (0);
}

/*
 * Instantiate SAS expander nodes for a given ESC Electronics node(controller)
 * nodes.
 */
/*ARGSUSED*/
static int
ses_create_esc_sasspecific(ses_enum_data_t *sdp, ses_enum_node_t *snp,
    tnode_t *pnode, ses_enum_chassis_t *cp,
    boolean_t dorange)
{
	topo_mod_t *mod = sdp->sed_mod;
	tnode_t	*exptn, *contn;
	boolean_t found;
	sas_connector_phy_data_t connectors[64] = {NULL};
	uint64_t max;
	ses_enum_node_t *ctlsnp, *xsnp, *consnp;
	ses_node_t *np = snp->sen_node;
	nvlist_t *props, *psprops;
	uint64_t index, psindex, conindex, psstatus, i, j, count;
	int64_t cidxlist[256] = {NULL};
	int phycount;

	props = ses_node_props(np);

	if (nvlist_lookup_uint64(props, SES_PROP_ELEMENT_ONLY_INDEX,
	    &index) != 0)
		return (-1);

	/*
	 * For SES constroller node, check to see if there are
	 * associated SAS expanders.
	 */
	found = B_FALSE;
	max = 0;
	for (ctlsnp = topo_list_next(&cp->sec_nodes); ctlsnp != NULL;
	    ctlsnp = topo_list_next(ctlsnp)) {
		if (ctlsnp->sen_type == SES_ET_SAS_EXPANDER) {
			found = B_TRUE;
			if (ctlsnp->sen_instance > max)
				max = ctlsnp->sen_instance;
		}
	}

	/*
	 * No SAS expander found notthing to process.
	 */
	if (!found)
		return (0);

	topo_mod_dprintf(mod, "%s Controller %d: creating "
	    "%llu %s nodes", cp->sec_csn, index, max + 1, SASEXPANDER);

	/*
	 * The max number represent the number of elements
	 * deducted from the highest SES_PROP_ELEMENT_CLASS_INDEX
	 * of SET_ET_SAS_EXPANDER type element.
	 *
	 * There may be multiple ESC Electronics element(controllers)
	 * within JBOD(typicall two for redundancy) and SAS expander
	 * elements are associated with only one of them.  We are
	 * still creating the range based max number here.
	 * That will cover the case that all expanders are associated
	 * with one SES controller.
	 */
	if (dorange && topo_node_range_create(mod, pnode,
	    SASEXPANDER, 0, max) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_create_range() failed: %s",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	/*
	 * Search exapnders with the parent index matching with
	 * ESC Electronics element index.
	 * Note the index used here is a global index across
	 * SES elements.
	 */
	for (xsnp = topo_list_next(&cp->sec_nodes); xsnp != NULL;
	    xsnp = topo_list_next(xsnp)) {
		if (xsnp->sen_type == SES_ET_SAS_EXPANDER) {
			/*
			 * get the parent ESC controller.
			 */
			psprops = ses_node_props(xsnp->sen_node);
			if (nvlist_lookup_uint64(psprops,
			    SES_PROP_STATUS_CODE, &psstatus) == 0) {
				if (psstatus == SES_ESC_NOT_INSTALLED) {
					/*
					 * Not installed.
					 * Don't create a ndoe.
					 */
					continue;
				}
			} else {
				/*
				 * The element should have status code.
				 * If not there is no way to find
				 * out if the expander element exist or
				 * not.
				 */
				continue;
			}

			/* Get the physical parent index to compare. */
			if (nvlist_lookup_uint64(psprops,
			    LIBSES_PROP_PHYS_PARENT, &psindex) == 0) {
				if (index == psindex) {
		/* indentation moved forward */
		/*
		 * Handle basic node information of SAS expander
		 * element - binding to parent node and
		 * allocating FMRI...
		 */
		if (ses_create_generic(sdp, xsnp, pnode, SASEXPANDER,
		    "SAS-EXPANDER", &exptn) != 0)
			continue;
		/*
		 * Now handle SAS expander unique portion of node creation.
		 * The max nubmer of the phy count is 256 since SES-2
		 * defines as 1 byte field.  The cidxlist has the same
		 * number of elements.
		 *
		 * We use size 64 array to store the connectors.
		 * Typically a connectors associated with 4 phys so that
		 * matches with the max number of connecters associated
		 * with an expander.
		 * The phy count goes up to 38 for Sun supported
		 * JBOD.
		 */
		memset(cidxlist, 0, sizeof (int64_t) * 64);
		if (ses_set_expander_props(sdp, xsnp, pnode, exptn, &phycount,
		    cidxlist) != 0) {
			/*
			 * error on getting specific prop failed.
			 * continue on.  Note that the node is
			 * left bound.
			 */
			continue;
		}

		/*
		 * count represetns the number of connectors discovered so far.
		 */
		count = 0;
		memset(connectors, 0, sizeof (sas_connector_phy_data_t) * 64);
		for (i = 0; i < phycount; i++) {
			if (cidxlist[i] != -1) {
				/* connector index is valid. */
				for (j = 0; j < count; j++) {
					if (connectors[j].index ==
					    cidxlist[i]) {
						/*
						 * Just update phy mask.
						 * The postion for connector
						 * index lists(cidxlist index)
						 * is set.
						 */
						connectors[j].phy_mask =
						    connectors[j].phy_mask |
						    (1ULL << i);
						break;
					}
				}
				/*
				 * If j and count matche a  new connector
				 * index is found.
				 */
				if (j == count) {
					/* add a new index and phy mask. */
					connectors[count].index = cidxlist[i];
					connectors[count].phy_mask =
					    connectors[count].phy_mask |
					    (1ULL << i);
					count++;
				}
			}
		}

		/*
		 * create range for the connector nodes.
		 * The class index of the ses connector element
		 * is set as the instance nubmer for the node.
		 * Even though one expander may not have all connectors
		 * are associated with we are creating the range with
		 * max possible instance number.
		 */
		found = B_FALSE;
		max = 0;
		for (consnp = topo_list_next(&cp->sec_nodes);
		    consnp != NULL; consnp = topo_list_next(consnp)) {
			if (consnp->sen_type == SES_ET_SAS_CONNECTOR) {
				psprops = ses_node_props(consnp->sen_node);
				found = B_TRUE;
				if (consnp->sen_instance > max)
					max = consnp->sen_instance;
			}
		}

		/*
		 * No SAS connector found nothing to process.
		 */
		if (!found)
			return (0);

		if (dorange && topo_node_range_create(mod, exptn,
		    RECEPTACLE, 0, max) != 0) {
			topo_mod_dprintf(mod,
			    "topo_node_create_range() failed: %s",
			    topo_mod_errmsg(mod));
			return (-1);
		}

		/* search matching connector element using the index. */
		for (i = 0; i < count; i++) {
			found = B_FALSE;
			for (consnp = topo_list_next(&cp->sec_nodes);
			    consnp != NULL; consnp = topo_list_next(consnp)) {
				if (consnp->sen_type == SES_ET_SAS_CONNECTOR) {
					psprops = ses_node_props(
					    consnp->sen_node);
					/*
					 * Get the physical parent index to
					 * compare.
					 * The connector elements are children
					 * of ESC Electronics element even
					 * though we enumerate them under
					 * an expander in libtopo.
					 */
					if (nvlist_lookup_uint64(psprops,
					    SES_PROP_ELEMENT_ONLY_INDEX,
					    &conindex) == 0) {
						if (conindex ==
						    connectors[i].index) {
							found = B_TRUE;
							break;
						}
					}
				}
			}

			/* now create a libtopo node. */
			if (found) {
				/* Create generic props. */
				if (ses_create_generic(sdp, consnp, exptn,
				    RECEPTACLE, "RECEPTACLE", &contn) !=
				    0) {
					continue;
				}
				/* Create connector specific props. */
				if (ses_set_connector_props(sdp, consnp,
				    contn, connectors[i].phy_mask) != 0) {
					continue;
				}
			}
		}
		/* end indentation change */
				}
			}
		}
	}

	return (0);
}

/*
 * Instantiate any protocol specific portion of a node.
 */
/*ARGSUSED*/
static int
ses_create_protocol_specific(ses_enum_data_t *sdp, ses_enum_node_t *snp,
    tnode_t *pnode, uint64_t type, ses_enum_chassis_t *cp,
    boolean_t dorange)
{

	if (type == SES_ET_ESC_ELECTRONICS) {
		/* create SAS specific children(expanders and connectors. */
		return (ses_create_esc_sasspecific(sdp, snp, pnode, cp,
		    dorange));
	}

	return (0);
}

/*
 * Instantiate any children of a given type.
 */
static int
ses_create_children(ses_enum_data_t *sdp, tnode_t *pnode, uint64_t type,
    const char *nodename, const char *defaultlabel, ses_enum_chassis_t *cp,
    boolean_t dorange)
{
	topo_mod_t *mod = sdp->sed_mod;
	boolean_t found;
	uint64_t max;
	ses_enum_node_t *snp;
	tnode_t	*tn;

	/*
	 * First go through and count how many matching nodes we have.
	 */
	max = 0;
	found = B_FALSE;
	for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
	    snp = topo_list_next(snp)) {
		if (snp->sen_type == type) {
			found = B_TRUE;
			if (snp->sen_instance > max)
				max = snp->sen_instance;
		}
	}

	/*
	 * No enclosure should export both DEVICE and ARRAY_DEVICE elements.
	 * Since we map both of these to 'disk', if an enclosure does this, we
	 * just ignore the array elements.
	 */
	if (!found ||
	    (type == SES_ET_ARRAY_DEVICE && cp->sec_hasdev))
		return (0);

	topo_mod_dprintf(mod, "%s: creating %llu %s nodes",
	    cp->sec_csn, max + 1, nodename);

	if (dorange && topo_node_range_create(mod, pnode,
	    nodename, 0, max) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_create_range() failed: %s",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
	    snp = topo_list_next(snp)) {
		if (snp->sen_type == type) {
			if (ses_create_generic(sdp, snp, pnode,
			    nodename, defaultlabel, &tn) != 0)
				return (-1);
			/*
			 * For some SES element there may be protocol specific
			 * information to process.   Here we are processing
			 * the association between enclosure controller and
			 * SAS expanders.
			 */
			if (type == SES_ET_ESC_ELECTRONICS) {
				/* create SAS expander node */
				if (ses_create_protocol_specific(sdp, snp,
				    tn, type, cp, dorange) != 0) {
					return (-1);
				}
			}

		}
	}

	return (0);
}

/*
 * Instantiate a new subchassis instance in the topology.
 */
static int
ses_create_subchassis(ses_enum_data_t *sdp, tnode_t *pnode,
    ses_enum_chassis_t *scp)
{
	topo_mod_t *mod = sdp->sed_mod;
	tnode_t *tn;
	nvlist_t *props;
	nvlist_t *auth = NULL, *fmri = NULL;
	uint64_t instance = scp->sec_instance;
	char *desc;
	char label[128];
	char **paths;
	int i, err;
	ses_enum_target_t *stp;
	int ret = -1;

	/*
	 * Copy authority information from parent enclosure node
	 */
	if ((auth = topo_mod_auth(mod, pnode)) == NULL)
		goto error;

	/*
	 * Record the subchassis serial number in the FMRI.
	 * For now, we assume that logical id is the subchassis serial number.
	 * If this assumption changes in future, then the following
	 * piece of code will need to be updated via an RFE.
	 */
	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
	    SUBCHASSIS, (topo_instance_t)instance, NULL, auth, NULL, NULL,
	    NULL)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((tn = topo_node_bind(mod, pnode, SUBCHASSIS,
	    instance, fmri)) == NULL) {
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	props = ses_node_props(scp->sec_enclosure);

	/*
	 * Look for the subchassis label in the following order:
	 *	<ses-description>
	 *	<ses-class-description> <instance>
	 *	<default-type-label> <instance>
	 *
	 * For subchassis, the default label is "SUBCHASSIS"
	 */
	if (nvlist_lookup_string(props, SES_PROP_DESCRIPTION, &desc) != 0 ||
	    desc[0] == '\0') {
		if (nvlist_lookup_string(props, SES_PROP_CLASS_DESCRIPTION,
		    &desc) == 0 && desc[0] != '\0')
			(void) snprintf(label, sizeof (label), "%s %llu", desc,
			    instance);
		else
			(void) snprintf(label, sizeof (label),
			    "SUBCHASSIS %llu", instance);
		desc = label;
	}

	if (topo_node_label_set(tn, desc, &err) != 0)
		goto error;

	if (ses_set_standard_props(mod, NULL, tn, NULL,
	    ses_node_id(scp->sec_enclosure), scp->sec_target->set_devpath) != 0)
		goto error;

	/*
	 * Set the 'chassis-type' property for this subchassis.  This is either
	 * 'ses-class-description' or 'subchassis'.
	 */
	if (nvlist_lookup_string(props, SES_PROP_CLASS_DESCRIPTION, &desc) != 0)
		desc = "subchassis";

	if (topo_prop_set_string(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_CHASSIS_TYPE, TOPO_PROP_IMMUTABLE, desc, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s\n",
		    TOPO_PROP_CHASSIS_TYPE, topo_strerror(err));
		goto error;
	}

	/*
	 * For enclosures, we want to include all possible targets (for upgrade
	 * purposes).
	 */
	for (i = 0, stp = topo_list_next(&scp->sec_targets); stp != NULL;
	    stp = topo_list_next(stp), i++)
		;

	verify(i != 0);
	paths = alloca(i * sizeof (char *));

	for (i = 0, stp = topo_list_next(&scp->sec_targets); stp != NULL;
	    stp = topo_list_next(stp), i++)
		paths[i] = stp->set_devpath;

	if (topo_prop_set_string_array(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_PATHS, TOPO_PROP_IMMUTABLE, (const char **)paths,
	    i, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create property %s: %s\n",
		    TOPO_PROP_PATHS, topo_strerror(err));
		goto error;
	}

	if (topo_method_register(mod, tn, ses_enclosure_methods) != 0) {
		topo_mod_dprintf(mod, "topo_method_register() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	/*
	 * Create the nodes for controllers and bays.
	 */
	if (ses_create_children(sdp, tn, SES_ET_ESC_ELECTRONICS,
	    CONTROLLER, "CONTROLLER", scp, B_TRUE) != 0 ||
	    ses_create_children(sdp, tn, SES_ET_DEVICE,
	    BAY, "BAY", scp, B_TRUE) != 0 ||
	    ses_create_children(sdp, tn, SES_ET_ARRAY_DEVICE,
	    BAY, "BAY", scp, B_TRUE) != 0)
		goto error;

	ret = 0;

error:
	nvlist_free(auth);
	nvlist_free(fmri);
	return (ret);
}

/*
 * Instantiate a new chassis instance in the topology.
 */
static int
ses_create_chassis(ses_enum_data_t *sdp, tnode_t *pnode, ses_enum_chassis_t *cp)
{
	topo_mod_t *mod = sdp->sed_mod;
	nvlist_t *props;
	char *raw_manufacturer, *raw_model, *raw_revision;
	char *manufacturer = NULL, *model = NULL, *product = NULL;
	char *revision = NULL;
	char *serial;
	char **paths;
	size_t prodlen;
	tnode_t *tn;
	nvlist_t *fmri = NULL, *auth = NULL;
	int ret = -1;
	ses_enum_node_t *snp;
	ses_enum_target_t *stp;
	ses_enum_chassis_t *scp;
	int i, err;
	uint64_t sc_count = 0;

	/*
	 * Ignore any internal enclosures.
	 */
	if (cp->sec_internal)
		return (0);

	/*
	 * Check to see if there are any devices presennt in the chassis.  If
	 * not, ignore the chassis alltogether.  This is most useful for
	 * ignoring internal HBAs that present a SES target but don't actually
	 * manage any of the devices.
	 */
	for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
	    snp = topo_list_next(snp)) {
		if (snp->sen_type == SES_ET_DEVICE ||
		    snp->sen_type == SES_ET_ARRAY_DEVICE)
			break;
	}

	if (snp == NULL)
		return (0);

	props = ses_node_props(cp->sec_enclosure);

	/*
	 * We use the following property mappings:
	 *
	 * 	manufacturer		vendor-id
	 * 	model			product-id
	 * 	serial-number		libses-chassis-serial
	 */
	verify(nvlist_lookup_string(props, SES_EN_PROP_VID,
	    &raw_manufacturer) == 0);
	verify(nvlist_lookup_string(props, SES_EN_PROP_PID, &raw_model) == 0);
	verify(nvlist_lookup_string(props, SES_EN_PROP_REV,
	    &raw_revision) == 0);
	verify(nvlist_lookup_string(props, LIBSES_EN_PROP_CSN, &serial) == 0);

	/*
	 * To construct the authority information, we 'clean' each string by
	 * removing any offensive characters and trimmming whitespace.  For the
	 * 'product-id', we use a concatenation of 'manufacturer-model'.  We
	 * also take the numerical serial number and convert it to a string.
	 */
	if ((manufacturer = disk_auth_clean(mod, raw_manufacturer)) == NULL ||
	    (model = disk_auth_clean(mod, raw_model)) == NULL ||
	    (revision = disk_auth_clean(mod, raw_revision)) == NULL) {
		goto error;
	}

	prodlen = strlen(manufacturer) + strlen(model) + 2;
	if ((product = topo_mod_alloc(mod, prodlen)) == NULL)
		goto error;

	(void) snprintf(product, prodlen, "%s-%s", manufacturer, model);

	/*
	 * Construct the topo node and bind it to our parent.
	 */
	if (topo_mod_nvalloc(mod, &auth, NV_UNIQUE_NAME) != 0)
		goto error;

	if (nvlist_add_string(auth, FM_FMRI_AUTH_PRODUCT, product) != 0 ||
	    nvlist_add_string(auth, FM_FMRI_AUTH_CHASSIS, serial) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		goto error;
	}

	/*
	 * We pass NULL for the parent FMRI because there is no resource
	 * associated with it.  For the toplevel enclosure, we leave the
	 * serial/part/revision portions empty, which are reserved for
	 * individual components within the chassis.
	 */
	if ((fmri = topo_mod_hcfmri(mod, NULL, FM_HC_SCHEME_VERSION,
	    SES_ENCLOSURE, cp->sec_instance, NULL, auth,
	    model, revision, serial)) == NULL) {
		topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if ((tn = topo_node_bind(mod, pnode, SES_ENCLOSURE,
	    cp->sec_instance, fmri)) == NULL) {
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if (topo_method_register(mod, tn, ses_enclosure_methods) != 0) {
		topo_mod_dprintf(mod,
		    "topo_method_register() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	if (ses_set_standard_props(mod, NULL, tn, auth,
	    ses_node_id(cp->sec_enclosure), cp->sec_target->set_devpath) != 0)
		goto error;

	/*
	 * For enclosures, we want to include all possible targets (for upgrade
	 * purposes).
	 */
	for (i = 0, stp = topo_list_next(&cp->sec_targets); stp != NULL;
	    stp = topo_list_next(stp), i++)
		;

	verify(i != 0);
	paths = alloca(i * sizeof (char *));

	for (i = 0, stp = topo_list_next(&cp->sec_targets); stp != NULL;
	    stp = topo_list_next(stp), i++)
		paths[i] = stp->set_devpath;


	if (topo_prop_set_string_array(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_PATHS, TOPO_PROP_IMMUTABLE, (const char **)paths,
	    i, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to create property %s: %s\n",
		    TOPO_PROP_PATHS, topo_strerror(err));
		goto error;
	}

	/*
	 * Create the nodes for power supplies, fans, controllers and devices.
	 * Note that SAS exopander nodes and connector nodes are handled
	 * through protocol specific processing of controllers.
	 */
	if (ses_create_children(sdp, tn, SES_ET_POWER_SUPPLY,
	    PSU, "PSU", cp, B_TRUE) != 0 ||
	    ses_create_children(sdp, tn, SES_ET_COOLING,
	    FAN, "FAN", cp, B_TRUE) != 0 ||
	    ses_create_children(sdp, tn, SES_ET_ESC_ELECTRONICS,
	    CONTROLLER, "CONTROLLER", cp, B_TRUE) != 0 ||
	    ses_create_children(sdp, tn, SES_ET_DEVICE,
	    BAY, "BAY", cp, B_TRUE) != 0 ||
	    ses_create_children(sdp, tn, SES_ET_ARRAY_DEVICE,
	    BAY, "BAY", cp, B_TRUE) != 0)
		goto error;

	if (cp->sec_maxinstance >= 0 &&
	    (topo_node_range_create(mod, tn, SUBCHASSIS, 0,
	    cp->sec_maxinstance) != 0)) {
		topo_mod_dprintf(mod, "topo_node_create_range() failed: %s",
		    topo_mod_errmsg(mod));
		goto error;
	}

	for (scp = topo_list_next(&cp->sec_subchassis); scp != NULL;
	    scp = topo_list_next(scp)) {

		if (ses_create_subchassis(sdp, tn, scp) != 0)
			goto error;

		topo_mod_dprintf(mod, "created Subchassis node with "
		    "instance %u\nand target (%s) under Chassis with CSN %s",
		    scp->sec_instance, scp->sec_target->set_devpath,
		    cp->sec_csn);

		sc_count++;
	}

	topo_mod_dprintf(mod, "%s: created %llu %s nodes",
	    cp->sec_csn, sc_count, SUBCHASSIS);

	cp->sec_target->set_refcount++;
	topo_node_setspecific(tn, cp->sec_target);

	ret = 0;
error:
	topo_mod_strfree(mod, manufacturer);
	topo_mod_strfree(mod, model);
	topo_mod_strfree(mod, revision);
	topo_mod_strfree(mod, product);

	nvlist_free(fmri);
	nvlist_free(auth);
	return (ret);
}

/*
 * Create a bay node explicitly enumerated via XML.
 */
static int
ses_create_bays(ses_enum_data_t *sdp, tnode_t *pnode)
{
	topo_mod_t *mod = sdp->sed_mod;
	ses_enum_chassis_t *cp;

	/*
	 * Iterate over chassis looking for an internal enclosure.  This
	 * property is set via a vendor-specific plugin, and there should only
	 * ever be a single internal chassis in a system.
	 */
	for (cp = topo_list_next(&sdp->sed_chassis); cp != NULL;
	    cp = topo_list_next(cp)) {
		if (cp->sec_internal)
			break;
	}

	if (cp == NULL) {
		topo_mod_dprintf(mod, "failed to find internal chassis\n");
		return (-1);
	}

	if (ses_create_children(sdp, pnode, SES_ET_DEVICE,
	    BAY, "BAY", cp, B_FALSE) != 0 ||
	    ses_create_children(sdp, pnode, SES_ET_ARRAY_DEVICE,
	    BAY, "BAY", cp, B_FALSE) != 0)
		return (-1);

	return (0);
}

/*
 * Initialize chassis or subchassis.
 */
static int
ses_init_chassis(topo_mod_t *mod, ses_enum_data_t *sdp, ses_enum_chassis_t *pcp,
    ses_enum_chassis_t *cp, ses_node_t *np, nvlist_t *props,
    uint64_t subchassis, ses_chassis_type_e flags)
{
	boolean_t internal, ident;

	assert((flags & (SES_NEW_CHASSIS | SES_NEW_SUBCHASSIS |
	    SES_DUP_CHASSIS | SES_DUP_SUBCHASSIS)) != 0);

	assert(cp != NULL);
	assert(np != NULL);
	assert(props != NULL);

	if (flags & (SES_NEW_SUBCHASSIS | SES_DUP_SUBCHASSIS))
		assert(pcp != NULL);

	topo_mod_dprintf(mod, "ses_init_chassis: %s: index %llu, flags (%d)",
	    sdp->sed_name, subchassis, flags);

	if (flags & (SES_NEW_CHASSIS | SES_NEW_SUBCHASSIS)) {

		topo_mod_dprintf(mod, "new chassis/subchassis");
		if (nvlist_lookup_boolean_value(props,
		    LIBSES_EN_PROP_INTERNAL, &internal) == 0)
			cp->sec_internal = internal;

		cp->sec_enclosure = np;
		cp->sec_target = sdp->sed_target;

		if (flags & SES_NEW_CHASSIS) {
			if (!cp->sec_internal)
				cp->sec_instance = sdp->sed_instance++;
			topo_list_append(&sdp->sed_chassis, cp);
		} else {
			if (subchassis != NO_SUBCHASSIS)
				cp->sec_instance = subchassis;
			else
				cp->sec_instance = pcp->sec_scinstance++;

			if (cp->sec_instance > pcp->sec_maxinstance)
				pcp->sec_maxinstance = cp->sec_instance;

			topo_list_append(&pcp->sec_subchassis, cp);
		}

	} else {
		topo_mod_dprintf(mod, "dup chassis/subchassis");
		if (nvlist_lookup_boolean_value(props,
		    SES_PROP_IDENT, &ident) == 0) {
			topo_mod_dprintf(mod,  "overriding enclosure node");

			cp->sec_enclosure = np;
			cp->sec_target = sdp->sed_target;
		}
	}

	topo_list_append(&cp->sec_targets, sdp->sed_target);
	sdp->sed_current = cp;

	return (0);
}

/*
 * Gather nodes from the current SES target into our chassis list, merging the
 * results if necessary.
 */
static ses_walk_action_t
ses_enum_gather(ses_node_t *np, void *data)
{
	nvlist_t *props = ses_node_props(np);
	ses_enum_data_t *sdp = data;
	topo_mod_t *mod = sdp->sed_mod;
	ses_enum_chassis_t *cp, *scp;
	ses_enum_node_t *snp;
	ses_alt_node_t *sap;
	char *csn;
	uint64_t instance, type;
	uint64_t prevstatus, status;
	boolean_t report;
	uint64_t subchassis = NO_SUBCHASSIS;

	if (ses_node_type(np) == SES_NODE_ENCLOSURE) {
		/*
		 * If we have already identified the chassis for this target,
		 * then this is a secondary enclosure and we should ignore it,
		 * along with the rest of the tree (since this is depth-first).
		 */
		if (sdp->sed_current != NULL)
			return (SES_WALK_ACTION_TERMINATE);

		/*
		 * Go through the list of chassis we have seen so far and see
		 * if this serial number matches one of the known values.
		 * If so, check whether this enclosure is a subchassis.
		 */
		if (nvlist_lookup_string(props, LIBSES_EN_PROP_CSN,
		    &csn) != 0)
			return (SES_WALK_ACTION_TERMINATE);

		(void) nvlist_lookup_uint64(props, LIBSES_EN_PROP_SUBCHASSIS_ID,
		    &subchassis);

		topo_mod_dprintf(mod, "ses_enum_gather: Enclosure Node (%s) "
		    "CSN (%s), subchassis (%llu)", sdp->sed_name, csn,
		    subchassis);

		/*
		 * We need to determine whether this enclosure node
		 * represents a chassis or a subchassis. Since we may
		 * receive the enclosure nodes in a non-deterministic
		 * manner, we need to account for all possible combinations:
		 *	1. Chassis for the current CSN has not yet been
		 *	   allocated
		 *		1.1 This is a new chassis:
		 *			allocate and instantiate the chassis
		 *		1.2 This is a new subchassis:
		 *			allocate a placeholder chassis
		 *			allocate and instantiate the subchassis
		 *			link the subchassis to the chassis
		 *	2. Chassis for the current CSN has been allocated
		 *		2.1 This is a duplicate chassis enclosure
		 *			check whether to override old chassis
		 *			append to chassis' target list
		 *		2.2 Only placeholder chassis exists
		 *			fill in the chassis fields
		 *		2.3 This is a new subchassis
		 *			allocate and instantiate the subchassis
		 *			link the subchassis to the chassis
		 *		2.4 This is a duplicate subchassis enclosure
		 *			 check whether to override old chassis
		 *			 append to chassis' target list
		 */

		for (cp = topo_list_next(&sdp->sed_chassis); cp != NULL;
		    cp = topo_list_next(cp))
			if (strcmp(cp->sec_csn, csn) == 0)
				break;

		if (cp == NULL) {
			/* 1. Haven't seen a chassis with this CSN before */

			if ((cp = topo_mod_zalloc(mod,
			    sizeof (ses_enum_chassis_t))) == NULL)
				goto error;

			cp->sec_scinstance = SES_STARTING_SUBCHASSIS;
			cp->sec_maxinstance = -1;
			cp->sec_csn = csn;

			if (subchassis == NO_SUBCHASSIS) {
				/* 1.1 This is a new chassis */

				topo_mod_dprintf(mod, "%s: Initialize new "
				    "chassis with CSN %s", sdp->sed_name, csn);

				if (ses_init_chassis(mod, sdp, NULL, cp,
				    np, props, NO_SUBCHASSIS,
				    SES_NEW_CHASSIS) < 0)
					goto error;
			} else {
				/* 1.2 This is a new subchassis */

				topo_mod_dprintf(mod, "%s: Initialize new "
				    "subchassis with CSN %s and index %llu",
				    sdp->sed_name, csn, subchassis);

				if ((scp = topo_mod_zalloc(mod,
				    sizeof (ses_enum_chassis_t))) == NULL)
					goto error;

				scp->sec_csn = csn;

				if (ses_init_chassis(mod, sdp, cp, scp, np,
				    props, subchassis, SES_NEW_SUBCHASSIS) < 0)
					goto error;
			}
		} else {
			/*
			 * We have a chassis or subchassis with this CSN.  If
			 * it's a chassis, we must check to see whether it is
			 * a placeholder previously created because we found a
			 * subchassis with this CSN.  We will know that because
			 * the sec_target value will not be set; it is set only
			 * in ses_init_chassis().  In that case, initialise it
			 * as a new chassis; otherwise, it's a duplicate and we
			 * need to append only.
			 */
			if (subchassis == NO_SUBCHASSIS) {
				if (cp->sec_target != NULL) {
					/* 2.1 This is a duplicate chassis */

					topo_mod_dprintf(mod, "%s: Append "
					    "duplicate chassis with CSN (%s)",
					    sdp->sed_name, csn);

					if (ses_init_chassis(mod, sdp, NULL, cp,
					    np, props, NO_SUBCHASSIS,
					    SES_DUP_CHASSIS) < 0)
						goto error;
				} else {
					/* Placeholder chassis - init it up */
					topo_mod_dprintf(mod, "%s: Initialize"
					    "placeholder chassis with CSN %s",
					    sdp->sed_name, csn);

					if (ses_init_chassis(mod, sdp, NULL,
					    cp, np, props, NO_SUBCHASSIS,
					    SES_NEW_CHASSIS) < 0)
						goto error;

				}
			} else {
				/* This is a subchassis */

				for (scp = topo_list_next(&cp->sec_subchassis);
				    scp != NULL; scp = topo_list_next(scp))
					if (scp->sec_instance == subchassis)
						break;

				if (scp == NULL) {
					/* 2.3 This is a new subchassis */

					topo_mod_dprintf(mod, "%s: Initialize "
					    "new subchassis with CSN (%s) "
					    "and LID (%s)",
					    sdp->sed_name, csn);

					if ((scp = topo_mod_zalloc(mod,
					    sizeof (ses_enum_chassis_t)))
					    == NULL)
						goto error;

					scp->sec_csn = csn;

					if (ses_init_chassis(mod, sdp, cp, scp,
					    np, props, subchassis,
					    SES_NEW_SUBCHASSIS) < 0)
						goto error;
				} else {
					/* 2.4 This is a duplicate subchassis */

					topo_mod_dprintf(mod, "%s: Append "
					    "duplicate subchassis with "
					    "CSN (%s)", sdp->sed_name, csn);

					if (ses_init_chassis(mod, sdp, cp, scp,
					    np, props, subchassis,
					    SES_DUP_SUBCHASSIS) < 0)
						goto error;
				}
			}
		}
	} else if (ses_node_type(np) == SES_NODE_ELEMENT) {
		/*
		 * If we haven't yet seen an enclosure node and identified the
		 * current chassis, something is very wrong; bail out.
		 */
		if (sdp->sed_current == NULL)
			return (SES_WALK_ACTION_TERMINATE);

		/*
		 * If this isn't one of the element types we care about, then
		 * ignore it.
		 */
		verify(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE,
		    &type) == 0);
		if (type != SES_ET_DEVICE &&
		    type != SES_ET_ARRAY_DEVICE &&
		    type != SES_ET_COOLING &&
		    type != SES_ET_POWER_SUPPLY &&
		    type != SES_ET_ESC_ELECTRONICS &&
		    type != SES_ET_SAS_EXPANDER &&
		    type != SES_ET_SAS_CONNECTOR)
			return (SES_WALK_ACTION_CONTINUE);

		/*
		 * Get the current instance number and see if we already know
		 * about this element.  If so, it means we have multiple paths
		 * to the same elements, and we should ignore the current path.
		 */
		verify(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_CLASS_INDEX,
		    &instance) == 0);
		if (type == SES_ET_DEVICE || type == SES_ET_ARRAY_DEVICE)
			(void) nvlist_lookup_uint64(props, SES_PROP_BAY_NUMBER,
			    &instance);

		cp = sdp->sed_current;

		for (snp = topo_list_next(&cp->sec_nodes); snp != NULL;
		    snp = topo_list_next(snp)) {
			if (snp->sen_type == type &&
			    snp->sen_instance == instance)
				break;
		}

		/*
		 * We prefer the new element under the following circumstances:
		 *
		 * - The currently known element's status is unknown or not
		 *   available, but the new element has a known status.  This
		 *   occurs if a given element is only available through a
		 *   particular target.
		 *
		 * - This is an ESC_ELECTRONICS element, and the 'reported-via'
		 *   property is set.  This allows us to get reliable firmware
		 *   revision information from the enclosure node.
		 */
		if (snp != NULL) {
			if (nvlist_lookup_uint64(
			    ses_node_props(snp->sen_node),
			    SES_PROP_STATUS_CODE, &prevstatus) != 0)
				prevstatus = SES_ESC_UNSUPPORTED;
			if (nvlist_lookup_uint64(
			    props, SES_PROP_STATUS_CODE, &status) != 0)
				status = SES_ESC_UNSUPPORTED;
			if (nvlist_lookup_boolean_value(
			    props, SES_PROP_REPORT, &report) != 0)
				report = B_FALSE;

			if ((SES_STATUS_UNAVAIL(prevstatus) &&
			    !SES_STATUS_UNAVAIL(status)) ||
			    (type == SES_ET_ESC_ELECTRONICS &&
			    report)) {
				snp->sen_node = np;
				snp->sen_target = sdp->sed_target;
			}

			if ((sap = topo_mod_zalloc(mod,
			    sizeof (ses_alt_node_t))) == NULL)
				goto error;

			sap->san_node = np;
			topo_list_append(&snp->sen_alt_nodes, sap);

			return (SES_WALK_ACTION_CONTINUE);
		}

		if ((snp = topo_mod_zalloc(mod,
		    sizeof (ses_enum_node_t))) == NULL)
			goto error;

		if ((sap = topo_mod_zalloc(mod,
		    sizeof (ses_alt_node_t))) == NULL) {
			topo_mod_free(mod, snp, sizeof (ses_enum_node_t));
			goto error;
		}

		topo_mod_dprintf(mod, "%s: adding node (%llu, %llu)",
		    sdp->sed_name, type, instance);
		snp->sen_node = np;
		snp->sen_type = type;
		snp->sen_instance = instance;
		snp->sen_target = sdp->sed_target;
		sap->san_node = np;
		topo_list_append(&snp->sen_alt_nodes, sap);
		topo_list_append(&cp->sec_nodes, snp);

		if (type == SES_ET_DEVICE)
			cp->sec_hasdev = B_TRUE;
	}

	return (SES_WALK_ACTION_CONTINUE);

error:
	sdp->sed_errno = -1;
	return (SES_WALK_ACTION_TERMINATE);
}

static int
ses_process_dir(const char *dirpath, ses_enum_data_t *sdp)
{
	topo_mod_t *mod = sdp->sed_mod;
	DIR *dir;
	struct dirent *dp;
	char path[PATH_MAX];
	ses_enum_target_t *stp;
	int err = -1;

	/*
	 * Open the SES target directory and iterate over any available
	 * targets.
	 */
	if ((dir = opendir(dirpath)) == NULL) {
		/*
		 * If the SES target directory does not exist, then return as if
		 * there are no active targets.
		 */
		topo_mod_dprintf(mod, "failed to open ses "
		    "directory '%s'", dirpath);
		return (0);
	}

	while ((dp = readdir(dir)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		/*
		 * Create a new target instance and take a snapshot.
		 */
		if ((stp = topo_mod_zalloc(mod,
		    sizeof (ses_enum_target_t))) == NULL)
			goto error;

		(void) pthread_mutex_init(&stp->set_lock, NULL);

		(void) snprintf(path, sizeof (path), "%s/%s", dirpath,
		    dp->d_name);

		/*
		 * We keep track of the SES device path and export it on a
		 * per-node basis to allow higher level software to get to the
		 * corresponding SES state.
		 */
		if ((stp->set_devpath = topo_mod_strdup(mod, path)) == NULL) {
			topo_mod_free(mod, stp, sizeof (ses_enum_target_t));
			goto error;
		}

		if ((stp->set_target =
		    ses_open(LIBSES_VERSION, path)) == NULL) {
			topo_mod_dprintf(mod, "failed to open ses target "
			    "'%s': %s", dp->d_name, ses_errmsg());
			topo_mod_strfree(mod, stp->set_devpath);
			topo_mod_free(mod, stp, sizeof (ses_enum_target_t));
			continue;
		}

		stp->set_refcount = 1;
		sdp->sed_target = stp;
		stp->set_snap = ses_snap_hold(stp->set_target);
		stp->set_snaptime = gethrtime();

		/*
		 * Enumerate over all SES elements and merge them into the
		 * correct ses_enum_chassis_t.
		 */
		sdp->sed_current = NULL;
		sdp->sed_errno = 0;
		sdp->sed_name = dp->d_name;
		(void) ses_walk(stp->set_snap, ses_enum_gather, sdp);

		if (sdp->sed_errno != 0)
			goto error;
	}

	err = 0;
error:
	closedir(dir);
	return (err);
}

static void
ses_release(topo_mod_t *mod, tnode_t *tn)
{
	ses_enum_target_t *stp;

	if ((stp = topo_node_getspecific(tn)) != NULL)
		ses_target_free(mod, stp);
}

/*ARGSUSED*/
static int
ses_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	ses_enum_chassis_t *cp;
	ses_enum_data_t *data;

	/*
	 * Check to make sure we're being invoked sensibly, and that we're not
	 * being invoked as part of a post-processing step.
	 */
	if (strcmp(name, SES_ENCLOSURE) != 0 && strcmp(name, BAY) != 0)
		return (0);

	/*
	 * If this is the first time we've called our enumeration method, then
	 * gather information about any available enclosures.
	 */
	if ((data = topo_mod_getspecific(mod)) == NULL) {
		if ((data = topo_mod_zalloc(mod, sizeof (ses_enum_data_t))) ==
		    NULL)
			return (-1);

		data->sed_mod = mod;
		topo_mod_setspecific(mod, data);

		if (dev_list_gather(mod, &data->sed_devs) != 0)
			goto error;

		/*
		 * We search both the ses(7D) and sgen(7D) locations, so we are
		 * independent of any particular driver class bindings.
		 */
		if (ses_process_dir("/dev/es", data) != 0 ||
		    ses_process_dir("/dev/scsi/ses", data) != 0)
			goto error;
	}

	if (strcmp(name, SES_ENCLOSURE) == 0) {
		/*
		 * This is a request to enumerate external enclosures.  Go
		 * through all the targets and create chassis nodes where
		 * necessary.
		 */
		for (cp = topo_list_next(&data->sed_chassis); cp != NULL;
		    cp = topo_list_next(cp)) {
			if (ses_create_chassis(data, rnode, cp) != 0)
				goto error;
		}
	} else {
		/*
		 * This is a request to enumerate a specific bay underneath the
		 * root chassis (for internal disks).
		 */
		if (ses_create_bays(data, rnode) != 0)
			goto error;
	}

	/*
	 * This is a bit of a kludge.  In order to allow internal disks to be
	 * enumerated and share snapshot-specific information with the external
	 * enclosure enumeration, we rely on the fact that we will be invoked
	 * for the 'ses-enclosure' node last.
	 */
	if (strcmp(name, SES_ENCLOSURE) == 0) {
		for (cp = topo_list_next(&data->sed_chassis); cp != NULL;
		    cp = topo_list_next(cp))
			ses_data_free(data, cp);
		ses_data_free(data, NULL);
		topo_mod_setspecific(mod, NULL);
	}
	return (0);

error:
	for (cp = topo_list_next(&data->sed_chassis); cp != NULL;
	    cp = topo_list_next(cp))
		ses_data_free(data, cp);
	ses_data_free(data, NULL);
	topo_mod_setspecific(mod, NULL);
	return (-1);
}

static const topo_modops_t ses_ops =
	{ ses_enum, ses_release };

static topo_modinfo_t ses_info =
	{ SES_ENCLOSURE, FM_FMRI_SCHEME_HC, SES_VERSION, &ses_ops };

/*ARGSUSED*/
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOSESDEBUG") != NULL)
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "initializing %s enumerator\n",
	    SES_ENCLOSURE);

	return (topo_mod_register(mod, &ses_info, TOPO_VERSION));
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}
