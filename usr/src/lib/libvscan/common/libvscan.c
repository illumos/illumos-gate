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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <math.h>
#include <limits.h>
#include <libscf.h>
#include <errno.h>
#include <fcntl.h>
#include <door.h>
#include <pwd.h>
#include <auth_attr.h>
#include <secdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libintl.h>
#include <libvscan.h>

#define	VS_DOOR_CALL_RETRIES	3

#define	VS_INSTANCE_FMRI	"svc:/system/filesystem/vscan:icap"

/* SMF property group and property names */
#define	VS_PGNAME_GENERAL		"vs_general"
#define	VS_PGNAME_ENGINE_PREFIX		"vs_engine_"
#define	VS_PGNAME_ENGINE_LEN		VS_SE_NAME_LEN + 16

#define	VS_PNAME_MAXSIZE		"maxsize"
#define	VS_PNAME_MAXSIZE_ACTION		"maxsize_action"
#define	VS_PNAME_TYPES			"types"
#define	VS_PNAME_VLOG			"viruslog"

#define	VS_PNAME_SE_ENABLE		"enable"
#define	VS_PNAME_SE_HOST		"host"
#define	VS_PNAME_SE_PORT		"port"
#define	VS_PNAME_SE_MAXCONN		"max_connect"
#define	VS_PNAME_VAUTH			"value_authorization"


/* types string processing */
#define	VS_TYPES_SEP		','
#define	VS_TYPES_ESCAPE		'\\'
#define	VS_TYPES_RULES		"+-"


/*
 * The SCF context enapsulating the SCF objects used in the
 * repository load and store routines vs_scf_values_get()
 * and vs_scf_values_set().
 *
 * The context is always opened before a get or set, then
 * closed when finished (or on error); the open does an
 * initial setup, while inside the get and set functions,
 * additional objects within the context may be selectively
 * initialized for use, depending on the actions needed and
 * the properties being operated on.
 */
typedef struct vs_scfctx {
	scf_handle_t *vscf_handle;
	scf_instance_t *vscf_inst;
	scf_propertygroup_t *vscf_pgroup;
	scf_transaction_t *vscf_tx;
	scf_iter_t *vscf_iter;
	scf_property_t *vscf_prop[VS_NUM_PROPIDS];
	scf_transaction_entry_t *vscf_ent[VS_NUM_PROPIDS];
	scf_value_t *vscf_val[VS_NUM_PROPIDS];
} vs_scfctx_t;

/*
 * The vscan property definition. Maps the property id with the name
 * and type used to store the property in the repository.
 * A table of these definitions is defined with a single entry per
 * property.
 */
typedef struct {
	const char *vpd_name;
	uint64_t vpd_id;
	scf_type_t vpd_type;
} vs_propdef_t;

typedef enum {
	VS_PTYPE_GEN,
	VS_PTYPE_SE
} vs_prop_type_t;

typedef struct vs_prop_hd {
	vs_prop_type_t vp_type;
	uint64_t vp_ids;
	uint64_t vp_all;
	union {
		vs_props_t vp_gen;
		vs_props_se_t vp_se;
	} vp_props;
} vs_prop_hd_t;

#define	vp_gen	vp_props.vp_gen
#define	vp_se	vp_props.vp_se

/*
 * Default values - these are used to return valid data
 * to the caller in cases where invalid or unexpected values
 * are found in the repository.
 *
 * Note: These values must be kept in sync with those defined
 * in the service manifest.
 */
static const boolean_t vs_dflt_allow = B_TRUE;
static const boolean_t vs_dflt_enable = B_TRUE;
static const char *vs_dflt_maxsize = "1GB";
static const char *vs_dflt_host = "";
static const uint16_t vs_dflt_port = 1344;
static const uint16_t vs_dflt_maxconn = 32L;
static const  char *vs_dflt_types = "+*";
static const char *vs_dflt_vlog = "";

/* Property definition table */
static const vs_propdef_t vs_propdefs[] = {
	/* general properties */
	{ VS_PNAME_MAXSIZE, VS_PROPID_MAXSIZE, SCF_TYPE_ASTRING },
	{ VS_PNAME_MAXSIZE_ACTION, VS_PROPID_MAXSIZE_ACTION, SCF_TYPE_BOOLEAN },
	{ VS_PNAME_TYPES, VS_PROPID_TYPES, SCF_TYPE_ASTRING },
	{ VS_PNAME_VLOG, VS_PROPID_VLOG, SCF_TYPE_ASTRING },
	/* scan engine properties */
	{ VS_PNAME_SE_ENABLE, VS_PROPID_SE_ENABLE, SCF_TYPE_BOOLEAN },
	{ VS_PNAME_SE_HOST, VS_PROPID_SE_HOST, SCF_TYPE_HOST },
	{ VS_PNAME_SE_PORT, VS_PROPID_SE_PORT, SCF_TYPE_INTEGER },
	{ VS_PNAME_SE_MAXCONN, VS_PROPID_SE_MAXCONN, SCF_TYPE_INTEGER },
	{ VS_PNAME_VAUTH, VS_PROPID_VALUE_AUTH, SCF_TYPE_ASTRING }
};

static const int vs_npropdefs = sizeof (vs_propdefs)/sizeof (vs_propdef_t);

/* Local functions */
static const vs_propdef_t *vs_get_propdef(uint64_t);
static void vs_default_value(vs_prop_hd_t *, const uint64_t);

static int vs_scf_values_get(const char *, vs_prop_hd_t *);
static int vs_scf_get(const vs_propdef_t *, vs_prop_hd_t *, vs_scfctx_t *, int);

static int vs_scf_values_set(const char *, vs_prop_hd_t *);
static int vs_scf_set(const vs_propdef_t *, vs_prop_hd_t *, vs_scfctx_t *, int);
static int vs_scf_pg_create(const char *, vs_prop_hd_t *);
static int vs_scf_pg_delete(const char *);

static int vs_scf_ctx_open(vs_scfctx_t *);
static void vs_scf_ctx_close(vs_scfctx_t *);

static int vs_validate(const vs_prop_hd_t *, uint64_t);
static int vs_is_valid_types(const char *);
static int vs_is_valid_host(const char *);
static int vs_checkauth(char *);
static int vs_door_call(int, door_arg_t *);

static int vs_props_get_engines(char *[], int *);
static void vs_engid_to_pgname(const char *, char [VS_PGNAME_ENGINE_LEN]);
static int vs_scf_pg_count(void);
static int vs_strtoshift(const char *);


/*
 * vs_props_get_all
 *
 * Retrieves the general service properties and all properties
 * for all scan engines from the repository.
 *
 * If invalid property values are found, the values are corrected to
 * the default value.
 *
 * Return codes:
 *	VS_ERR_VS_ERR_NONE
 *	VS_ERR_SCF
 *	VS_ERR_SYS
 */
int
vs_props_get_all(vs_props_all_t *va)
{
	int i, rc, n;
	char *engids[VS_SE_MAX];

	(void) memset(va, 0, sizeof (vs_props_all_t));
	if ((rc = vs_props_get(&va->va_props, VS_PROPID_GEN_ALL))
	    != VS_ERR_NONE)
		return (rc);

	n = VS_SE_MAX;
	if ((rc = vs_props_get_engines(engids, &n)) != VS_ERR_NONE)
		return (rc);

	for (i = 0; i < n; i++) {
		if ((rc = vs_props_se_get(engids[i],
		    &va->va_se[i], VS_PROPID_SE_ALL)) != VS_ERR_NONE)
			break;
	}

	/* free engids allocated in vs_props_get_engines */
	for (i = 0; i < VS_SE_MAX; i++)	{
		if (engids[i] != NULL)
			free(engids[i]);
	}

	return (rc);
}


/*
 * vs_props_get
 *
 * Retrieves values for the specified general service properties from
 * the repository.
 *
 * If invalid property values are found, the values are corrected to
 * the default value.
 *
 * Return codes:
 *	VS_ERR_VS_ERR_NONE
 *	VS_ERR_INVALID_PROPERTY
 *	VS_ERR_SCF
 *	VS_ERR_SYS
 */
int
vs_props_get(vs_props_t *vp, uint64_t propids)
{
	int  rc;
	vs_prop_hd_t prop_hd;

	if ((propids & VS_PROPID_GEN_ALL) != propids)
		return (VS_ERR_INVALID_PROPERTY);

	(void) memset(&prop_hd, 0, sizeof (vs_prop_hd_t));
	prop_hd.vp_type = VS_PTYPE_GEN;
	prop_hd.vp_ids = propids;
	prop_hd.vp_all = VS_PROPID_GEN_ALL;

	rc = vs_scf_values_get(VS_PGNAME_GENERAL, &prop_hd);

	*vp = prop_hd.vp_gen;
	return (rc);
}


/*
 * vs_props_set
 *
 * Changes values for the specified general service properties
 * in the repository.
 *
 * Return codes:
 *	VS_ERR_VS_ERR_NONE
 *	VS_ERR_INVALID_PROPERTY
 *	VS_ERR_INVALID_VALUE
 *	VS_ERR_SCF
 *	VS_ERR_SYS
 */
int
vs_props_set(const vs_props_t *vp, uint64_t propids)
{
	vs_prop_hd_t prop_hd;

	if ((propids & VS_PROPID_GEN_ALL) != propids)
		return (VS_ERR_INVALID_PROPERTY);

	(void) memset(&prop_hd, 0, sizeof (vs_prop_hd_t));
	prop_hd.vp_type = VS_PTYPE_GEN;
	prop_hd.vp_ids = propids;
	prop_hd.vp_all = VS_PROPID_GEN_ALL;
	prop_hd.vp_gen = *vp;
	return (vs_scf_values_set(VS_PGNAME_GENERAL, &prop_hd));
}


/*
 * vs_props_se_get
 *
 * Retrieves values for the specified scan engine properties from the
 * repository.
 *
 * If the enable property is set (true), the host property is
 * checked for validity. If it is not valid, the requested values
 * are returned with the enable propery set to off (false)
 *
 * Return codes:
 *	VS_ERR_VS_ERR_NONE
 *	VS_ERR_INVALID_PROPERTY
 *	VS_ERR_SCF
 *	VS_ERR_SYS
 */
int
vs_props_se_get(char *engid, vs_props_se_t *sep, uint64_t propids)
{
	int rc;
	char pgname[VS_PGNAME_ENGINE_LEN];
	vs_prop_hd_t prop_hd;

	/* VS_PGNAME_GENERAL is a reserved for GENERAL property group */
	if (strcmp(engid, VS_PGNAME_GENERAL) == 0)
		return (VS_ERR_INVALID_SE);

	if ((propids & VS_PROPID_SE_ALL) != propids)
		return (VS_ERR_INVALID_PROPERTY);

	(void) memset(&prop_hd, 0, sizeof (vs_prop_hd_t));
	prop_hd.vp_type = VS_PTYPE_SE;
	prop_hd.vp_ids = propids;
	prop_hd.vp_all = VS_PROPID_SE_ALL;
	(void) strlcpy(prop_hd.vp_se.vep_engid, engid, VS_SE_NAME_LEN);

	/* If getting enable, get the host property too */
	if ((propids & VS_PROPID_SE_ENABLE))
		prop_hd.vp_ids |= VS_PROPID_SE_HOST;

	/* Load values from the repository */
	vs_engid_to_pgname(engid, pgname);
	rc = vs_scf_values_get(pgname, &prop_hd);
	if (rc != VS_ERR_NONE)
		return (rc);

	/*
	 *  If the host is invalid and the enable property is on,
	 *  return enable property as off
	 */
	if ((prop_hd.vp_ids & VS_PROPID_SE_HOST) &&
	    (vs_validate(&prop_hd, VS_PROPID_SE_HOST) != VS_ERR_NONE)) {
		prop_hd.vp_se.vep_enable = B_FALSE;
	}

	*sep = prop_hd.vp_se;
	return (rc);
}



/*
 * vs_props_se_set
 *
 * Changes the values for the specified scan engine properties in the
 * repository.
 *
 * If the enable property is being changed to true in this operation,
 * a host property must also be specified, or already exist in the
 * repository.
 *
 * Return codes:
 *	VS_ERR_NONE
 *	VS_ERR_INVALID_PROPERTY
 *	VS_ERR_INVALID_VALUE
 *	VS_ERR_SCF
 *	VS_ERR_SYS
 */
int
vs_props_se_set(char *engid, const vs_props_se_t *sep, uint64_t propids)
{
	int rc;
	char pgname[VS_PGNAME_ENGINE_LEN];
	vs_prop_hd_t prop_hd;

	/* VS_PGNAME_GENERAL is a reserved for GENERAL property group */
	if (strcmp(engid, VS_PGNAME_GENERAL) == 0)
		return (VS_ERR_INVALID_SE);

	if ((propids & VS_PROPID_SE_ALL) != propids)
		return (VS_ERR_INVALID_PROPERTY);

	(void) memset(&prop_hd, 0, sizeof (vs_prop_hd_t));
	prop_hd.vp_type = VS_PTYPE_SE;
	prop_hd.vp_all = VS_PROPID_SE_ALL;

	vs_engid_to_pgname(engid, pgname);

	/*
	 * if enabling a scan engine, ensure that a valid host
	 * is also being set, or already exists in the repository
	 */
	if ((propids & VS_PROPID_SE_ENABLE) && (sep->vep_enable == B_TRUE) &&
	    !(propids & VS_PROPID_SE_HOST)) {

		prop_hd.vp_ids = VS_PROPID_SE_HOST;
		if ((rc = vs_scf_values_get(pgname, &prop_hd)) != VS_ERR_NONE)
			return (rc);

		if (vs_validate(&prop_hd, VS_PROPID_SE_HOST) != VS_ERR_NONE)
			return (VS_ERR_INVALID_HOST);
	}

	prop_hd.vp_ids = propids;
	prop_hd.vp_se = *sep;

	return (vs_scf_values_set(pgname, &prop_hd));
}


/*
 * vs_props_se_create
 */
int
vs_props_se_create(char *engid, const vs_props_se_t *sep, uint64_t propids)
{
	int n;
	char pgname[VS_PGNAME_ENGINE_LEN];
	vs_prop_hd_t prop_hd;

	if ((propids & VS_PROPID_SE_ALL) != propids)
		return (VS_ERR_INVALID_PROPERTY);

	/* VS_PGNAME_GENERAL is a reserved for GENERAL property group */
	if (strcmp(engid, VS_PGNAME_GENERAL) == 0)
		return (VS_ERR_INVALID_SE);

	if ((n = vs_scf_pg_count()) == -1)
		return (VS_ERR_SCF);

	if (n == VS_SE_MAX)
		return (VS_ERR_MAX_SE);

	vs_engid_to_pgname(engid, pgname);

	(void) memset(&prop_hd, 0, sizeof (vs_prop_hd_t));
	prop_hd.vp_type = VS_PTYPE_SE;
	prop_hd.vp_all = VS_PROPID_SE_ALL;
	prop_hd.vp_ids = propids | VS_PROPID_VALUE_AUTH;
	prop_hd.vp_se = *sep;

	/* if hostname not specified, default it to engid */
	if ((propids & VS_PROPID_SE_HOST) == 0) {
		(void) strlcpy(prop_hd.vp_se.vep_host, engid, MAXHOSTNAMELEN);
		prop_hd.vp_ids |= VS_PROPID_SE_HOST;
	}

	return (vs_scf_pg_create(pgname, &prop_hd));
}


/*
 * vs_props_se_delete
 */
int
vs_props_se_delete(const char *engid)
{
	char pgname[VS_PGNAME_ENGINE_LEN];

	/* VS_PGNAME_GENERAL is a reserved for GENERAL property group */
	if (strcmp(engid, VS_PGNAME_GENERAL) == 0)
		return (VS_ERR_INVALID_SE);

	vs_engid_to_pgname(engid, pgname);

	return (vs_scf_pg_delete(pgname));
}


/*
 * vs_strerror
 */
const char *
vs_strerror(int error)
{
	switch (error) {
	case VS_ERR_NONE:
		return (gettext("no error"));
	case VS_ERR_INVALID_PROPERTY:
		return (gettext("invalid property id"));
	case VS_ERR_INVALID_VALUE:
		return (gettext("invalid property value"));
	case VS_ERR_INVALID_HOST:
		return (gettext("invalid host"));
	case VS_ERR_INVALID_SE:
		return (gettext("invalid scan engine"));
	case VS_ERR_MAX_SE:
		return (gettext("max scan engines exceeded"));
	case VS_ERR_AUTH:
		return (gettext("insufficient privileges for action"));
	case VS_ERR_DAEMON_COMM:
		return (gettext("unable to contact vscand"));
	case VS_ERR_SCF:
		return (scf_strerror(scf_error()));
	case VS_ERR_SYS:
		return (strerror(errno));
	default:
		return (gettext("unknown error"));
	}
}


/*
 * vs_get_propdef
 *
 * Finds and returns a property definition by property id.
 */
static const vs_propdef_t *
vs_get_propdef(uint64_t propid)
{
	int i;

	for (i = 0; i < vs_npropdefs; i++) {
		if (propid == vs_propdefs[i].vpd_id)
			return (&vs_propdefs[i]);
	}

	return (NULL);
}


/*
 * vs_default_value
 *
 * Sets a property value that contains invalid data to its default value.
 *
 * Note that this function does not alter any values in the repository
 * This is only to enable the caller to get valid data.
 */
static void
vs_default_value(vs_prop_hd_t *prop_hd, const uint64_t propid)
{
	vs_props_t *vp = &prop_hd->vp_gen;
	vs_props_se_t *vep = &prop_hd->vp_se;

	switch (propid) {
	case VS_PROPID_MAXSIZE:
		(void) strlcpy(vp->vp_maxsize, vs_dflt_maxsize,
		    sizeof (vp->vp_maxsize));
		break;
	case VS_PROPID_MAXSIZE_ACTION:
		vp->vp_maxsize_action = vs_dflt_allow;
		break;
	case VS_PROPID_TYPES:
		(void) strlcpy(vp->vp_types, vs_dflt_types,
		    sizeof (vp->vp_types));
		break;
	case VS_PROPID_VLOG:
		(void) strlcpy(vp->vp_vlog, vs_dflt_vlog,
		    sizeof (vp->vp_vlog));
		break;
	case VS_PROPID_SE_ENABLE:
		vep->vep_enable = vs_dflt_enable;
		break;
	case VS_PROPID_SE_HOST:
		(void) strlcpy(vep->vep_host, vs_dflt_host,
		    sizeof (vep->vep_host));
		break;
	case VS_PROPID_SE_PORT:
		vep->vep_port = vs_dflt_port;
		break;
	case VS_PROPID_SE_MAXCONN:
		vep->vep_maxconn = vs_dflt_maxconn;
		break;
	default:
		break;
	}
}


/*
 * vs_scf_values_get
 *
 * Gets property values for one or more properties from the repository.
 * This is the single entry point for loading SMF values.
 *
 * While a transaction is not used for loading property values,
 * the operation is parameterized by a property group. All properties
 * retrieved in this function, then, must belong to the same property
 * group.
 */
int
vs_scf_values_get(const char *pgname, vs_prop_hd_t *prop_hd)
{
	vs_scfctx_t vsc;
	int rc, np;
	const vs_propdef_t *vpd;
	uint64_t propid;

	if ((vs_scf_ctx_open(&vsc)) != 0) {
		vs_scf_ctx_close(&vsc);
		return (VS_ERR_SCF);
	}

	if (scf_instance_get_pg(vsc.vscf_inst, pgname, vsc.vscf_pgroup) == -1) {
		vs_scf_ctx_close(&vsc);
		if (strcmp(pgname, "VS_PGNAME_GENERAL") != 0) {
			rc = scf_error();
			if ((rc == SCF_ERROR_NOT_FOUND) ||
			    (rc == SCF_ERROR_INVALID_ARGUMENT))
				return (VS_ERR_INVALID_SE);
		}
		return (VS_ERR_SCF);
	}

	rc = VS_ERR_NONE;
	np = 0;
	for (propid = 1LL; propid <= VS_PROPID_MAX; propid <<= 1) {
		if ((prop_hd->vp_ids & propid) == 0)
			continue;

		if ((vpd = vs_get_propdef(propid)) == NULL) {
			rc = VS_ERR_INVALID_PROPERTY;
			break;
		}

		vsc.vscf_prop[np] = scf_property_create(vsc.vscf_handle);
		vsc.vscf_val[np] = scf_value_create(vsc.vscf_handle);

		if (vsc.vscf_prop[np] == NULL || vsc.vscf_val[np] == NULL) {
			rc = VS_ERR_SCF;
			break;
		}

		if (scf_pg_get_property(vsc.vscf_pgroup, vpd->vpd_name,
		    vsc.vscf_prop[np]) == -1) {
			if (scf_error() == SCF_ERROR_NOT_FOUND) {
				vs_default_value(prop_hd, vpd->vpd_id);
				continue;
			}
			rc = VS_ERR_SCF;
			break;
		}

		if ((rc = vs_scf_get(vpd, prop_hd, &vsc, np)) != VS_ERR_NONE)
			break;

		++np;
	}


	vs_scf_ctx_close(&vsc);

	return (rc);
}


/*
 * vs_scf_get
 *
 * Loads a single values from the repository into the appropriate vscan
 * property structure member.
 */
static int
vs_scf_get(const vs_propdef_t *vpd, vs_prop_hd_t *prop_hd,
	vs_scfctx_t *vsc, int idx)
{
	int rc;
	int64_t port;
	uint8_t valbool;
	vs_props_t *vp = &prop_hd->vp_gen;
	vs_props_se_t *vep = &prop_hd->vp_se;

	if ((rc = scf_property_get_value(vsc->vscf_prop[idx],
	    vsc->vscf_val[idx])) == -1) {
		if (rc == SCF_ERROR_CONSTRAINT_VIOLATED ||
		    rc == SCF_ERROR_NOT_FOUND) {
			vs_default_value(prop_hd, vpd->vpd_id);
			return (VS_ERR_NONE);
		}
		return (VS_ERR_SCF);
	}

	rc = VS_ERR_NONE;
	switch (vpd->vpd_id) {
	case VS_PROPID_MAXSIZE:
		if ((scf_value_get_astring(vsc->vscf_val[idx],
		    vp->vp_maxsize, sizeof (vp->vp_maxsize))) == -1) {
			return (VS_ERR_SCF);
		}
		break;
	case VS_PROPID_MAXSIZE_ACTION:
		if ((scf_value_get_boolean(vsc->vscf_val[idx],
		    &valbool)) == -1) {
			return (VS_ERR_SCF);
		}
		vp->vp_maxsize_action = (valbool == 0) ? B_FALSE : B_TRUE;
		break;
	case VS_PROPID_TYPES:
		if ((scf_value_get_astring(vsc->vscf_val[idx],
		    vp->vp_types, sizeof (vp->vp_types))) == -1) {
			return (VS_ERR_SCF);
		}
		break;
	case VS_PROPID_VLOG:
		if ((scf_value_get_astring(vsc->vscf_val[idx],
		    vp->vp_vlog, sizeof (vp->vp_vlog))) == -1) {
			return (VS_ERR_SCF);
		}
		break;
	case VS_PROPID_SE_ENABLE:
		if ((scf_value_get_boolean(vsc->vscf_val[idx],
		    &valbool)) == -1) {
			return (VS_ERR_SCF);
		}
		vep->vep_enable = (valbool == 0) ? B_FALSE : B_TRUE;
		break;
	case VS_PROPID_SE_HOST:
		(void) scf_value_get_as_string_typed(vsc->vscf_val[idx],
		    vpd->vpd_type, vep->vep_host, sizeof (vep->vep_host));
		break;
	case VS_PROPID_SE_PORT:
		if ((scf_value_get_integer(vsc->vscf_val[idx], &port)) == -1)
			return (VS_ERR_SCF);
		if (port <= 0 || port >= UINT16_MAX)
			rc = VS_ERR_INVALID_VALUE;
		else
			vep->vep_port = (uint16_t)port;
		break;
	case VS_PROPID_SE_MAXCONN:
		if ((scf_value_get_integer(vsc->vscf_val[idx],
		    (int64_t *)&vep->vep_maxconn)) == -1) {
			return (VS_ERR_SCF);
		}
		break;
	default:
		break;
	}

	if ((rc != VS_ERR_NONE) ||
	    (vs_validate(prop_hd, vpd->vpd_id) != VS_ERR_NONE)) {
		vs_default_value(prop_hd, vpd->vpd_id);
	}

	return (VS_ERR_NONE);
}


/*
 * vs_scf_pg_create
 */
static int
vs_scf_pg_create(const char *pgname, vs_prop_hd_t *prop_hd)
{
	int rc;
	uint64_t propid;
	vs_scfctx_t vsc;

	/* ensure that caller has authorization to refresh service */
	if ((rc = vs_checkauth(VS_ACTION_AUTH)) != VS_ERR_NONE)
		return (rc);

	if (vs_scf_ctx_open(&vsc) != 0) {
		vs_scf_ctx_close(&vsc);
		return (VS_ERR_SCF);
	}

	if (scf_instance_add_pg(vsc.vscf_inst, pgname,
	    SCF_GROUP_APPLICATION, 0, vsc.vscf_pgroup) == -1) {
		vs_scf_ctx_close(&vsc);
		if (scf_error() == SCF_ERROR_INVALID_ARGUMENT)
			return (VS_ERR_INVALID_SE);
		return (VS_ERR_SCF);
	}
	vs_scf_ctx_close(&vsc);

	/* set default values for those not specified */
	for (propid = 1LL; propid <= VS_PROPID_MAX; propid <<= 1) {
		if ((propid & prop_hd->vp_all) && !(propid & prop_hd->vp_ids))
			vs_default_value(prop_hd, propid);
	}

	prop_hd->vp_ids = prop_hd->vp_all;
	prop_hd->vp_ids |= VS_PROPID_VALUE_AUTH;

	rc = vs_scf_values_set(pgname, prop_hd);
	if (rc != VS_ERR_NONE)
		(void) vs_scf_pg_delete(pgname);

	return (rc);
}


/*
 * vs_scf_pg_delete
 */
static int
vs_scf_pg_delete(const char *pgname)
{
	int rc;
	vs_scfctx_t vsc;

	/* ensure that caller has authorization to refresh service */
	if ((rc = vs_checkauth(VS_ACTION_AUTH)) != VS_ERR_NONE)
		return (rc);

	if (vs_scf_ctx_open(&vsc) != 0) {
		vs_scf_ctx_close(&vsc);
		return (VS_ERR_SCF);
	}

	if (scf_instance_get_pg(vsc.vscf_inst, pgname, vsc.vscf_pgroup) == -1) {
		vs_scf_ctx_close(&vsc);
		rc = scf_error();
		if ((rc == SCF_ERROR_NOT_FOUND) ||
		    (rc == SCF_ERROR_INVALID_ARGUMENT))
			return (VS_ERR_INVALID_SE);
		else
			return (VS_ERR_SCF);
	}

	if (scf_pg_delete(vsc.vscf_pgroup) == -1) {
		vs_scf_ctx_close(&vsc);
		rc = scf_error();
		if ((rc == SCF_ERROR_NOT_FOUND) ||
		    (rc == SCF_ERROR_INVALID_ARGUMENT))
			return (VS_ERR_INVALID_SE);

		return (VS_ERR_SCF);
	}

	vs_scf_ctx_close(&vsc);

	/* Notify the daemon that things have changed */
	if ((smf_refresh_instance(VS_INSTANCE_FMRI)) == -1) {
		return (VS_ERR_SCF);
	}

	return (VS_ERR_NONE);
}


/*
 * vs_scf_values_set
 *
 * Sets property values in the repository.  This is the single
 * entry point for storing SMF values.
 *
 * Like loading values, this is an operation based on a single property
 * group, so all property values changed in this function must belong
 * to the same property group. Additionally, this operation is done in
 * the context of a repository transaction; on any fatal error, the
 * SCF context will be closed, destroying all SCF objects and aborting
 * the transaction.
 */
static int
vs_scf_values_set(const char *pgname, vs_prop_hd_t *prop_hd)
{
	int rc, np;
	const vs_propdef_t *vpd;
	uint64_t propid;
	vs_scfctx_t vsc;

	/* ensure that caller has authorization to refresh service */
	if ((rc = vs_checkauth(VS_ACTION_AUTH)) != VS_ERR_NONE)
		return (rc);

	if (vs_scf_ctx_open(&vsc) != 0) {
		vs_scf_ctx_close(&vsc);
		return (VS_ERR_SCF);
	}

	if (scf_instance_get_pg(vsc.vscf_inst, pgname, vsc.vscf_pgroup) == -1) {
		vs_scf_ctx_close(&vsc);
		rc = scf_error();
		if (strcmp(pgname, "VS_PGNAME_GENERAL") != 0) {
			if ((rc == SCF_ERROR_NOT_FOUND) ||
			    (rc == SCF_ERROR_INVALID_ARGUMENT))
				return (VS_ERR_INVALID_SE);
		}
		return (VS_ERR_SCF);
	}

	if (((vsc.vscf_tx = scf_transaction_create(vsc.vscf_handle)) == NULL) ||
	    (scf_transaction_start(vsc.vscf_tx, vsc.vscf_pgroup) == -1)) {
		vs_scf_ctx_close(&vsc);
		return (VS_ERR_SCF);
	}

	/* Process the value change for each specified property */
	rc = 0;
	np = 0;
	for (propid = 1LL; propid <= VS_PROPID_MAX; propid <<= 1) {
		if ((prop_hd->vp_ids & propid) == 0)
			continue;

		if ((vpd = vs_get_propdef(propid)) == NULL) {
			rc = VS_ERR_INVALID_PROPERTY;
			break;
		}

		vsc.vscf_val[np] = scf_value_create(vsc.vscf_handle);
		vsc.vscf_ent[np] = scf_entry_create(vsc.vscf_handle);

		if (vsc.vscf_val[np] == NULL || vsc.vscf_ent[np] == NULL) {
			rc = VS_ERR_SCF;
			break;
		}

		if ((rc = scf_transaction_property_change(vsc.vscf_tx,
		    vsc.vscf_ent[np], vpd->vpd_name, vpd->vpd_type)) == -1) {
			rc = scf_transaction_property_new(vsc.vscf_tx,
			    vsc.vscf_ent[np], vpd->vpd_name, vpd->vpd_type);
		}
		if (rc == -1) {
			rc = VS_ERR_SCF;
			break;
		}

		if ((rc = vs_scf_set(vpd, prop_hd, &vsc, np)) != VS_ERR_NONE)
			break;

		++np;
	}

	if (rc != VS_ERR_NONE) {
		vs_scf_ctx_close(&vsc);
		return (rc);
	}

	/* Commit the transaction */
	if (scf_transaction_commit(vsc.vscf_tx) == -1) {
		vs_scf_ctx_close(&vsc);
		return (VS_ERR_SCF);
	}
	vs_scf_ctx_close(&vsc);

	/* Notify the daemon that things have changed */
	if ((smf_refresh_instance(VS_INSTANCE_FMRI)) == -1)
		return (VS_ERR_SCF);

	return (VS_ERR_NONE);
}


/*
 * vs_scf_set
 *
 * Stores a single value from the appropriate vscan property structure
 * member into the repository.
 *
 * Values are set in the SCF value object, then the value object
 * is added to the SCF property object.
 */
static int
vs_scf_set(const vs_propdef_t *vpd, vs_prop_hd_t *prop_hd,
    vs_scfctx_t *vsc, int idx)
{
	int rc;
	vs_props_t *vp = &prop_hd->vp_gen;
	vs_props_se_t *vep = &prop_hd->vp_se;

	if ((rc = vs_validate(prop_hd, vpd->vpd_id)) != VS_ERR_NONE)
		return (rc);

	rc = VS_ERR_NONE;
	switch (vpd->vpd_id) {
	case VS_PROPID_MAXSIZE:
		if ((scf_value_set_astring(vsc->vscf_val[idx],
		    vp->vp_maxsize)) == -1) {
			rc = VS_ERR_SCF;
		}
		break;
	case VS_PROPID_MAXSIZE_ACTION:
		scf_value_set_boolean(vsc->vscf_val[idx],
		    (uint8_t)vp->vp_maxsize_action);
		break;
	case VS_PROPID_TYPES:
		if ((scf_value_set_astring(vsc->vscf_val[idx],
		    vp->vp_types)) == -1) {
			return (VS_ERR_SCF);
		}
		break;
	case VS_PROPID_SE_ENABLE:
		scf_value_set_boolean(vsc->vscf_val[idx],
		    (uint8_t)vep->vep_enable);
		break;
	case VS_PROPID_SE_HOST:
		if ((scf_value_set_from_string(vsc->vscf_val[idx],
		    vpd->vpd_type, vep->vep_host)) == -1) {
			rc = VS_ERR_SCF;
		}
		break;
	case VS_PROPID_SE_PORT:
		scf_value_set_integer(vsc->vscf_val[idx], vep->vep_port);
		break;
	case VS_PROPID_SE_MAXCONN:
		scf_value_set_integer(vsc->vscf_val[idx],
		    vep->vep_maxconn);
		break;
	case VS_PROPID_VALUE_AUTH:
		if ((scf_value_set_astring(vsc->vscf_val[idx],
		    VS_VALUE_AUTH)) == -1) {
			return (VS_ERR_SCF);
		}
		break;
	default:
		break;
	}

	if ((scf_entry_add_value(vsc->vscf_ent[idx],
	    vsc->vscf_val[idx])) == -1) {
		return (VS_ERR_SCF);
	}

	return (rc);
}


/*
 * vs_scf_ctx_open
 *
 * Opens an SCF context; creates the minumum SCF objects
 * for use in loading/storing from the SMF repository (meaning
 * vscf_property group data).
 *
 * Other SCF objects in the context may be initialized elsewher
 * subsequent to open, but all initialized structures are destroyed
 * in vs_scf_ctx_close().
 */
static int
vs_scf_ctx_open(vs_scfctx_t *vsc)
{
	(void) memset(vsc, 0, sizeof (vs_scfctx_t));

	if ((vsc->vscf_handle = scf_handle_create(SCF_VERSION)) == NULL)
		return (VS_ERR_SCF);

	if (scf_handle_bind(vsc->vscf_handle) == -1)
		return (VS_ERR_SCF);

	if ((vsc->vscf_inst = scf_instance_create(vsc->vscf_handle)) == NULL)
		return (VS_ERR_SCF);

	if (scf_handle_decode_fmri(vsc->vscf_handle, VS_INSTANCE_FMRI,
	    NULL, NULL, vsc->vscf_inst, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) == -1) {
		return (VS_ERR_SCF);
	}

	if ((vsc->vscf_pgroup = scf_pg_create(vsc->vscf_handle)) == NULL)
		return (VS_ERR_SCF);

	return (VS_ERR_NONE);
}


/*
 * vs_scf_ctx_close
 *
 * Closes an SCF context; destroys all initialized SCF objects.
 */
static void
vs_scf_ctx_close(vs_scfctx_t *vsc)
{
	int i;

	for (i = 0; i < VS_NUM_PROPIDS; i++) {
		if (vsc->vscf_val[i])
			scf_value_destroy(vsc->vscf_val[i]);
		if (vsc->vscf_ent[i])
			scf_entry_destroy(vsc->vscf_ent[i]);
		if (vsc->vscf_prop[i])
			scf_property_destroy(vsc->vscf_prop[i]);
	}

	if (vsc->vscf_iter)
		scf_iter_destroy(vsc->vscf_iter);
	if (vsc->vscf_tx)
		scf_transaction_destroy(vsc->vscf_tx);
	if (vsc->vscf_pgroup)
		scf_pg_destroy(vsc->vscf_pgroup);
	if (vsc->vscf_inst)
		scf_instance_destroy(vsc->vscf_inst);
	if (vsc->vscf_handle)
		scf_handle_destroy(vsc->vscf_handle);
}


/*
 * vs_validate
 *
 * Validate property identified in propid.
 *
 * Returns: VS_ERR_NONE
 *          VS_ERR_INVALID_VALUE
 *          VS_ERR_INVALID_PROPERTY
 */
static int
vs_validate(const vs_prop_hd_t *prop_hd, uint64_t propid)
{
	uint64_t num;
	const vs_props_t *vp = &prop_hd->vp_gen;
	const vs_props_se_t *vep = &prop_hd->vp_se;

	switch (propid) {
	case VS_PROPID_MAXSIZE:
		if ((vs_strtonum(vp->vp_maxsize, &num) != 0) || (num == 0))
			return (VS_ERR_INVALID_VALUE);
		break;
	case VS_PROPID_MAXSIZE_ACTION:
		break;
	case VS_PROPID_TYPES:
		if (!vs_is_valid_types(vp->vp_types))
			return (VS_ERR_INVALID_VALUE);
		break;
	case VS_PROPID_SE_ENABLE:
		break;
	case VS_PROPID_SE_PORT:
		if (vep->vep_port == 0)
			return (VS_ERR_INVALID_VALUE);
		break;
	case VS_PROPID_SE_HOST:
		if (!vs_is_valid_host(vep->vep_host))
			return (VS_ERR_INVALID_VALUE);
		break;
	case VS_PROPID_SE_MAXCONN:
		if (vep->vep_maxconn < VS_VAL_SE_MAXCONN_MIN ||
		    vep->vep_maxconn > VS_VAL_SE_MAXCONN_MAX)
			return (VS_ERR_INVALID_VALUE);
		break;
	case VS_PROPID_VALUE_AUTH:
	case VS_PROPID_VLOG:
		break;
	default:
		return (VS_ERR_INVALID_PROPERTY);
	}

	return (VS_ERR_NONE);
}


/*
 * vs_props_validate
 *
 * Validate  properties identified in propids.
 *
 * Returns: VS_ERR_NONE
 *          VS_ERR_INVALID_VALUE
 *          VS_ERR_INVALID_PROPERTY
 */
int
vs_props_validate(const vs_props_t *props, uint64_t propids)
{
	uint64_t propid;
	vs_prop_hd_t prop_hd;

	if ((propids & VS_PROPID_GEN_ALL) != propids)
		return (VS_ERR_INVALID_PROPERTY);

	(void) memset(&prop_hd, 0, sizeof (vs_prop_hd_t));
	prop_hd.vp_gen = *props;
	prop_hd.vp_type = VS_PTYPE_GEN;
	prop_hd.vp_ids = propids;
	prop_hd.vp_all = VS_PROPID_GEN_ALL;

	for (propid = 1LL; propid <= VS_PROPID_MAX; propid <<= 1) {
		if ((propids & propid) == 0)
			continue;

		if (vs_validate(&prop_hd, propid) != VS_ERR_NONE)
			return (VS_ERR_INVALID_VALUE);
	}

	return (VS_ERR_NONE);
}


/*
 * vs_props_se_validate
 *
 * Validate properties identified in propids.
 *
 * Returns: VS_ERR_NONE
 *          VS_ERR_INVALID_VALUE
 *          VS_ERR_INVALID_PROPERTY
 */
int
vs_props_se_validate(const vs_props_se_t *se_props, uint64_t propids)
{
	uint64_t propid;
	vs_prop_hd_t prop_hd;

	if ((propids & VS_PROPID_SE_ALL) != propids)
		return (VS_ERR_INVALID_PROPERTY);

	(void) memset(&prop_hd, 0, sizeof (vs_prop_hd_t));
	prop_hd.vp_se = *se_props;
	prop_hd.vp_type = VS_PTYPE_SE;
	prop_hd.vp_ids = propids;
	prop_hd.vp_all = VS_PROPID_SE_ALL;

	for (propid = 1LL; propid <= VS_PROPID_MAX; propid <<= 1) {
		if ((propids & propid) == 0)
			continue;

		if (vs_validate(&prop_hd, propid) != VS_ERR_NONE)
			return (VS_ERR_INVALID_VALUE);
	}

	return (VS_ERR_NONE);
}


/*
 * vs_is_valid_types
 *
 * Checks that types property is a valid format:
 * - doesn't exceed VS_VAL_TYPES_MAX
 * - doesn't contain VS_VAL_TYPES_INVALID_CHARS
 * - is correctly formatted - passes the parsing tests
 *
 * Returns 1 on success, 0 on failure
 */
static int
vs_is_valid_types(const char *types)
{
	char buf[VS_VAL_TYPES_LEN];
	uint32_t len = VS_VAL_TYPES_LEN;

	if (strlen(types) > VS_VAL_TYPES_LEN)
		return (0);

	if (strpbrk(types, VS_VAL_TYPES_INVALID_CHARS) != NULL)
		return (0);

	if (vs_parse_types(types, buf, &len) != 0)
		return (0);

	return (1);
}


/*
 * vs_is_valid_host
 *
 * Returns 1 on success, 0 on failure
 */
static int
vs_is_valid_host(const char *host)
{
	long naddr;
	const char *p;

	if (!host || *host == '\0')
		return (0);

	if ('0' <= host[0] && host[0] <= '9') {
		/* ip address */
		if ((inet_pton(AF_INET, host, &naddr)) == 0)
			return (0);
		if ((naddr & IN_CLASSA_NET) == 0)
			return (0);
		if ((naddr & IN_CLASSC_HOST) == 0)
			return (0);
	} else {
		/* hostname */
		p = host;
		while (*p != '\0') {
			if (!isascii(*p))
				return (0);

			if (isalnum(*p) ||
			    (*p == '.') || (*p == '-') || (*p == '_')) {
				++p;
			} else {
				return (0);
			}
		}
	}

	return (1);
}


/*
 * vs_parse_types
 *
 * Replace comma separators with '\0'.
 *
 * Types contains comma separated rules each beginning with +|-
 *   - embedded commas are escaped by backslash
 *   - backslash is escaped by backslash
 *   - a single backslash not followed by comma is illegal
 *
 * On entry to the function len must contain the length of
 * the buffer. On sucecssful exit len will contain the length
 * of the parsed data within the buffer.
 *
 * Returns 0 on success, -1 on failure
 */
int
vs_parse_types(const char *types, char *buf, uint32_t *len)
{
	char *p = (char *)types;
	char *b = buf;

	if (strlen(types) > *len)
		return (-1);

	if (strchr(VS_TYPES_RULES, *p) == NULL)
		return (-1);

	(void) memset(buf, 0, *len);

	while (*p) {
		switch (*p) {
		case VS_TYPES_SEP:
			if (*(p + 1) &&
			    (strchr(VS_TYPES_RULES, *(p + 1))) == NULL)
				return (-1);
			*b = '\0';
			break;
		case VS_TYPES_ESCAPE:
			++p;
			if (*p == VS_TYPES_ESCAPE || *p == VS_TYPES_SEP)
				*b = *p;
			else
				return (-1);
			break;
		default:
			*b = *p;
		}
		++p;
		++b;
	}

	*len = (b - buf) + 1;

	return (0);
}


/*
 * vs_statistics
 */
int
vs_statistics(vs_stats_t *stats)
{
	int door_fd, rc = VS_ERR_NONE;
	vs_stats_req_t *req;
	vs_stats_rsp_t *rsp;
	door_arg_t arg;

	if ((req = calloc(1, sizeof (vs_stats_req_t))) == NULL)
		return (VS_ERR_SYS);

	if ((rsp = calloc(1, sizeof (vs_stats_rsp_t))) == NULL) {
		free(req);
		return (VS_ERR_SYS);
	}

	if ((door_fd = open(VS_STATS_DOOR_NAME, O_RDONLY)) < 0) {
		free(req);
		free(rsp);
		return (VS_ERR_DAEMON_COMM);
	}

	req->vsr_magic = VS_STATS_DOOR_MAGIC;
	req->vsr_id = VS_STATS_GET;

	arg.data_ptr = (char *)req;
	arg.data_size = sizeof (vs_stats_req_t);
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = (char *)rsp;
	arg.rsize = sizeof (vs_stats_rsp_t);

	rc = vs_door_call(door_fd, &arg);

	if ((rc == VS_ERR_NONE) && (rsp->vsr_magic == VS_STATS_DOOR_MAGIC))
		*stats = rsp->vsr_stats;
	else
		rc = VS_ERR_DAEMON_COMM;

	(void) close(door_fd);

	free(req);
	free(rsp);
	return (rc);
}


/*
 * vs_statistics_reset
 */
int
vs_statistics_reset()
{
	int door_fd, rc;
	vs_stats_req_t *req;
	door_arg_t arg;

	/* ensure that caller has authorization to reset stats */
	if ((rc = vs_checkauth(VS_VALUE_AUTH)) != VS_ERR_NONE)
		return (rc);

	if ((req = calloc(1, sizeof (vs_stats_req_t))) == NULL)
		return (VS_ERR_SYS);

	if ((door_fd = open(VS_STATS_DOOR_NAME, O_RDONLY)) < 0) {
		free(req);
		return (VS_ERR_DAEMON_COMM);
	}

	req->vsr_magic = VS_STATS_DOOR_MAGIC;
	req->vsr_id = VS_STATS_RESET;

	arg.data_ptr = (char *)req;
	arg.data_size = sizeof (vs_stats_req_t);
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = NULL;
	arg.rsize = 0;

	rc = vs_door_call(door_fd, &arg);

	(void) close(door_fd);
	free(req);
	return (rc);
}

/*
 * Door call with retries.
 *
 * Returns VS_ERR_NONE on success, otherwise VS_ERR_DAEMON_COMM.
 */
static int
vs_door_call(int fd, door_arg_t *arg)
{
	int rc = -1;
	int i;

	for (i = 0; i < VS_DOOR_CALL_RETRIES; ++i) {
		errno = 0;

		if ((rc = door_call(fd, arg)) == 0)
			break;

		if (errno != EAGAIN && errno != EINTR)
			break;
	}

	return ((rc == 0) ? VS_ERR_NONE : VS_ERR_DAEMON_COMM);
}

/*
 * vs_checkauth
 */
static int
vs_checkauth(char *auth)
{
	struct passwd *pw;
	uid_t uid;

	uid = getuid();

	if ((pw = getpwuid(uid)) == NULL)
		return (VS_ERR_SYS);

	if (chkauthattr(auth, pw->pw_name) != 1) {
		return (VS_ERR_AUTH);
	}

	return (VS_ERR_NONE);
}


/*
 * vs_props_get_engines
 *
 * On input, count specifies the maximum number of engine ids to
 * return. engids must be an array with count entries.
 * On return, count specifies the number of engine ids being
 * returned in engids.
 *
 * Caller is responsible for free'ing the engids allocated herein.
 */
static int
vs_props_get_engines(char *engids[], int *count)
{
	int i, prefix_len;
	char pgname[VS_PGNAME_ENGINE_LEN];
	vs_scfctx_t vsc;


	if (((vs_scf_ctx_open(&vsc)) != 0) ||
	    ((vsc.vscf_iter = scf_iter_create(vsc.vscf_handle)) == NULL) ||
	    (scf_iter_instance_pgs_typed(vsc.vscf_iter, vsc.vscf_inst,
	    SCF_GROUP_APPLICATION) != 0)) {
		vs_scf_ctx_close(&vsc);
		return (VS_ERR_SCF);
	}

	for (i = 0; i < *count; i++)
		engids[i] = NULL;

	i = 0;
	prefix_len = sizeof (VS_PGNAME_ENGINE_PREFIX) - 1;

	while ((i < VS_SE_MAX) &&
	    (scf_iter_next_pg(vsc.vscf_iter, vsc.vscf_pgroup) == 1)) {
		if (scf_pg_get_name(vsc.vscf_pgroup, pgname,
		    VS_PGNAME_ENGINE_LEN) < 0) {
			vs_scf_ctx_close(&vsc);
			return (VS_ERR_SCF);
		}

		if (strncmp(pgname, VS_PGNAME_ENGINE_PREFIX, prefix_len) == 0) {
			if ((engids[i] = strdup(pgname + prefix_len)) != NULL) {
				if (++i == *count)
					break;
			}
		}
	}
	vs_scf_ctx_close(&vsc);

	*count = i;
	return (VS_ERR_NONE);
}


/*
 * vs_scf_pg_count
 */
static int
vs_scf_pg_count(void)
{
	int count = 0;
	vs_scfctx_t vsc;

	if ((vs_scf_ctx_open(&vsc) != 0) ||
	    ((vsc.vscf_iter = scf_iter_create(vsc.vscf_handle)) == NULL) ||
	    (scf_iter_instance_pgs_typed(vsc.vscf_iter, vsc.vscf_inst,
	    SCF_GROUP_APPLICATION) != 0)) {
		vs_scf_ctx_close(&vsc);
		return (-1);
	}

	while (scf_iter_next_pg(vsc.vscf_iter, vsc.vscf_pgroup) == 1)
		++count;

	vs_scf_ctx_close(&vsc);

	return (count);
}


/*
 * vs_engid_to_pgname
 *
 * To convert an engine id (engid) to a property group name (pgname),
 * the engine id is prefixed with VS_PGNAME_ENGINE_PREFIX.
 */
static void
vs_engid_to_pgname(const char *engid, char pgname[VS_PGNAME_ENGINE_LEN])
{
	(void) snprintf(pgname, VS_PGNAME_ENGINE_LEN, "%s%s",
	    VS_PGNAME_ENGINE_PREFIX, engid);
}


/*
 *  vs_strtonum
 *
 *  Converts a size string in the format into an integer.
 *
 *  A size string is a numeric value followed by an optional unit
 *  specifier which is used as a multiplier to calculate a raw
 *  number.
 *  The size string format is:  N[.N][KMGTP][B]
 *
 *  The numeric value can contain a decimal portion. Unit specifiers
 *  are either a one-character or two-character string; i.e. "K" or
 *  "KB" for kilobytes. Unit specifiers must follow the numeric portion
 *  immediately, and are not case-sensitive.
 *
 *  If either "B" is specified, or there is no unit specifier portion
 *  in the string, the numeric value is calculated with no multiplier
 *  (assumes a basic unit of "bytes").
 *
 *  Returns:
 *	-1:	Failure; errno set to specify the error.
 *	 0:	Success.
 */
int
vs_strtonum(const char *value, uint64_t *num)
{
	char *end;
	int shift;
	double fval;

	*num = 0;

	/* Check to see if this looks like a number.  */
	if ((value[0] < '0' || value[0] > '9') && value[0] != '.') {
		errno = EINVAL;
		return (-1);
	}

	/* Rely on stroll() to process the numeric portion.  */
	errno = 0;
	*num = strtoll(value, &end, 10);

	/*
	 * Check for ERANGE, which indicates that the value is too large to
	 * fit in a 64-bit value.
	 */
	if (errno != 0)
		return (-1);

	/*
	 * If we have a decimal value, then do the computation with floating
	 * point arithmetic.  Otherwise, use standard arithmetic.
	 */
	if (*end == '.') {
		fval = strtod(value, &end);

		if ((shift = vs_strtoshift(end)) == -1)
			return (-1); /* errno set */

		fval *= pow(2, shift);
		if (fval > UINT64_MAX) {
			errno = ERANGE;
			return (-1);
		}

		*num = (uint64_t)fval;
	} else {
		if ((shift = vs_strtoshift(end)) == -1)
			return (-1); /* errno set */

		/* Check for overflow */
		if (shift >= 64 || (*num << shift) >> shift != *num) {
			errno = ERANGE;
			return (-1);
		}

		*num <<= shift;
	}

	return (0);
}


/*
 *  vs_strtoshift
 *
 *  Converts a unit specifier string into a number of bits that
 *  a numeric value must be shifted.
 *
 *  Returns:
 *	-1:	Failure; errno set to specify the error.
 *	>-1:	Success; the shift count.
 *
 */
static int
vs_strtoshift(const char *buf)
{
	const char *ends = "BKMGTPEZ";
	int i;

	if (buf[0] == '\0')
		return (0);
	for (i = 0; i < strlen(ends); i++) {
		if (toupper(buf[0]) == ends[i])
			break;
	}
	if (i == strlen(ends)) {
		errno = EINVAL;
		return (-1);
	}

	/* Allow trailing 'b' characters except in the case of 'BB'. */
	if (buf[1] == '\0' || (toupper(buf[1]) == 'B' && buf[2] == '\0' &&
	    toupper(buf[0]) != 'B')) {
		return (10 * i);
	}

	errno = EINVAL;
	return (-1);
}
