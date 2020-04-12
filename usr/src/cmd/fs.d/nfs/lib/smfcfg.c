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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2023 Oxide Computer Company
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <nfs/nfs.h>
#include <rpcsvc/daemon_utils.h>
#include <sys/sysmacros.h>
#include "smfcfg.h"

/*
 * NFS version strings translation table to numeric form.
 */
static struct str_val {
	const char *str;
	uint32_t val;
} nfs_versions[] = {
	{ "2",		NFS_VERS_2 },
	{ "3",		NFS_VERS_3 },
	{ "4",		NFS_VERS_4 },
	{ "4.0",	NFS_VERS_4 },
	{ "4.1",	NFS_VERS_4_1 },
	{ "4.2",	NFS_VERS_4_2 }
};

/*
 * Translate NFS version string to numeric form.
 * Returns NFS_VERS_... value or zero for invalid version string.
 */
uint32_t
nfs_convert_version_str(const char *version)
{
	uint32_t v = 0;

	for (size_t i = 0; i < ARRAY_SIZE(nfs_versions); i++) {
		if (strcmp(version, nfs_versions[i].str) == 0) {
			v = nfs_versions[i].val;
			break;
		}
	}

	return (v);
}

fs_smfhandle_t *
fs_smf_init(const char *fmri, const char *instance)
{
	fs_smfhandle_t *handle = NULL;
	char *svcname, srv[MAXPATHLEN];

	/*
	 * svc name is of the form svc://network/fs/server:instance1
	 * FMRI portion is /network/fs/server
	 */
	(void) snprintf(srv, MAXPATHLEN, "%s", fmri + strlen("svc:/"));
	svcname = strrchr(srv, ':');
	if (svcname != NULL)
		*svcname = '\0';
	svcname = srv;

	handle = calloc(1, sizeof (fs_smfhandle_t));
	if (handle != NULL) {
		handle->fs_handle = scf_handle_create(SCF_VERSION);
		if (handle->fs_handle == NULL)
			goto out;
		if (scf_handle_bind(handle->fs_handle) != 0)
			goto out;
		handle->fs_service =
		    scf_service_create(handle->fs_handle);
		handle->fs_scope =
		    scf_scope_create(handle->fs_handle);
		if (scf_handle_get_local_scope(handle->fs_handle,
		    handle->fs_scope) != 0)
			goto out;
		if (scf_scope_get_service(handle->fs_scope,
		    svcname, handle->fs_service)  != SCF_SUCCESS) {
			goto out;
		}
		handle->fs_pg =
		    scf_pg_create(handle->fs_handle);
		handle->fs_instance =
		    scf_instance_create(handle->fs_handle);
		handle->fs_property =
		    scf_property_create(handle->fs_handle);
		handle->fs_value =
		    scf_value_create(handle->fs_handle);
	} else {
		fprintf(stderr,
		    gettext("Cannot access SMF repository: %s\n"), fmri);
	}
	return (handle);

out:
	fs_smf_fini(handle);
	if (scf_error() != SCF_ERROR_NOT_FOUND) {
		fprintf(stderr,
		    gettext("SMF Initialization problem(%s): %s\n"),
		    fmri, scf_strerror(scf_error()));
	}
	return (NULL);
}

void
fs_smf_fini(fs_smfhandle_t *handle)
{
	if (handle != NULL) {
		scf_scope_destroy(handle->fs_scope);
		scf_instance_destroy(handle->fs_instance);
		scf_service_destroy(handle->fs_service);
		scf_pg_destroy(handle->fs_pg);
		scf_property_destroy(handle->fs_property);
		scf_value_destroy(handle->fs_value);
		if (handle->fs_handle != NULL) {
			(void) scf_handle_unbind(handle->fs_handle);
			scf_handle_destroy(handle->fs_handle);
		}
		free(handle);
	}
}

int
fs_smf_set_prop(smf_fstype_t fstype, char *prop_name, char *valbuf,
    char *instance, scf_type_t sctype, char *fmri)
{
	fs_smfhandle_t *phandle = NULL;
	scf_handle_t *handle;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_transaction_t *tran = NULL;
	scf_transaction_entry_t *entry = NULL;
	scf_instance_t *inst;
	scf_value_t *val;
	int valint;
	int ret = 0;
	char *p = NULL;
	char *svcname, srv[MAXPATHLEN];
	const char *pgname;

	/*
	 * The SVC names we are using currently are already
	 * appended by default. Fix this for instances project.
	 */
	(void) snprintf(srv, MAXPATHLEN, "%s", fmri);
	p = strstr(fmri, ":default");
	if (p == NULL) {
		(void) strcat(srv, ":");
		if (instance == NULL)
			instance = "default";
		if (strlen(srv) + strlen(instance) > MAXPATHLEN)
			goto out;
		(void) strncat(srv, instance, strlen(instance));
	}
	svcname = srv;
	phandle = fs_smf_init(fmri, instance);
	if (phandle == NULL) {
		return (SMF_SYSTEM_ERR);
	}
	handle = phandle->fs_handle;
	pg = phandle->fs_pg;
	prop = phandle->fs_property;
	inst = phandle->fs_instance;
	val = phandle->fs_value;
	tran = scf_transaction_create(handle);
	entry = scf_entry_create(handle);

	if (handle == NULL || pg == NULL || prop == NULL ||
	    val == NULL|| tran == NULL || entry == NULL || inst == NULL) {
		ret = SMF_SYSTEM_ERR;
		goto out;
	}

	if (scf_handle_decode_fmri(handle, svcname, phandle->fs_scope,
	    phandle->fs_service, inst, NULL, NULL, 0) != 0) {
		ret = scf_error();
		goto out;
	}
	if (fstype == AUTOFS_SMF)
		pgname = AUTOFS_PROPS_PGNAME;
	else
		pgname = NFS_PROPS_PGNAME;

	if (scf_instance_get_pg(inst, pgname,
	    pg) != -1) {
		uint8_t	vint;
		if (scf_transaction_start(tran, pg) == -1) {
			ret = scf_error();
			goto out;
		}
		switch (sctype) {
		case SCF_TYPE_INTEGER:
			errno = 0;
			valint = strtoul(valbuf, NULL, 0);
			if (errno != 0) {
				ret = SMF_SYSTEM_ERR;
				goto out;
			}
			if (scf_transaction_property_change(tran,
			    entry, prop_name, SCF_TYPE_INTEGER) == 0) {
				scf_value_set_integer(val, valint);
				if (scf_entry_add_value(entry, val) < 0) {
					ret = scf_error();
					goto out;
				}
			}
			break;
		case SCF_TYPE_ASTRING:
			if (scf_transaction_property_change(tran, entry,
			    prop_name, SCF_TYPE_ASTRING) == 0) {
				if (scf_value_set_astring(val,
				    valbuf) == 0) {
					if (scf_entry_add_value(entry,
					    val) != 0) {
						ret = scf_error();
						goto out;
					}
				} else
					ret = SMF_SYSTEM_ERR;
			} else
				ret = SMF_SYSTEM_ERR;
			break;
		case SCF_TYPE_BOOLEAN:
			if (strcmp(valbuf, "1") == 0) {
				vint = 1;
			} else if (strcmp(valbuf, "0") == 0) {
				vint = 0;
			} else  {
				ret = SMF_SYSTEM_ERR;
				break;
			}
			if (scf_transaction_property_change(tran, entry,
			    prop_name, SCF_TYPE_BOOLEAN) == 0) {
				scf_value_set_boolean(val, (uint8_t)vint);
				if (scf_entry_add_value(entry, val) != 0) {
					ret = scf_error();
					goto out;
				}
			} else {
				ret = SMF_SYSTEM_ERR;
			}
			break;
		default:
			break;
		}
		if (ret != SMF_SYSTEM_ERR)
			(void) scf_transaction_commit(tran);
	}
out:
	if (tran != NULL)
		scf_transaction_destroy(tran);
	if (entry != NULL)
		scf_entry_destroy(entry);
	fs_smf_fini(phandle);
	return (ret);
}

int
fs_smf_get_prop(smf_fstype_t fstype, char *prop_name, char *cbuf,
    char *instance, scf_type_t sctype, char *fmri, int *bufsz)
{
	fs_smfhandle_t *phandle = NULL;
	scf_handle_t *handle;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	scf_instance_t *inst;
	int ret = 0, len = 0, length;
	int64_t valint = 0;
	char srv[MAXPATHLEN], *p, *svcname;
	const char *pgname;
	uint8_t bval;

	/*
	 * The SVC names we are using currently are already
	 * appended by default. Fix this for instances project.
	 */
	(void) snprintf(srv, MAXPATHLEN, "%s", fmri);
	p = strstr(fmri, ":default");
	if (p == NULL) {
		(void) strcat(srv, ":");
		if (instance == NULL)
			instance = "default";
		if (strlen(srv) + strlen(instance) > MAXPATHLEN)
			goto out;
		(void) strncat(srv, instance, strlen(instance));
	}
	svcname = srv;
	phandle = fs_smf_init(fmri, instance);
	if (phandle == NULL)
		return (SMF_SYSTEM_ERR);
	handle = phandle->fs_handle;
	pg = phandle->fs_pg;
	inst = phandle->fs_instance;
	prop = phandle->fs_property;
	val = phandle->fs_value;

	if (handle == NULL || pg == NULL || prop == NULL || val == NULL ||
	    inst == NULL)  {
		return (SMF_SYSTEM_ERR);
	}


	if (scf_handle_decode_fmri(handle, svcname, phandle->fs_scope,
	    phandle->fs_service, inst, NULL, NULL, 0) != 0) {
		ret = scf_error();
		goto out;
	}

	if (fstype == AUTOFS_SMF)
		pgname = AUTOFS_PROPS_PGNAME;
	else
		pgname = NFS_PROPS_PGNAME;

	if (scf_instance_get_pg(inst, pgname, pg) != -1) {
		if (scf_pg_get_property(pg, prop_name,
		    prop) != SCF_SUCCESS) {
			ret = scf_error();
			goto out;
		}
		if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
			ret = scf_error();
			goto out;
		}
		switch (sctype) {
		case SCF_TYPE_ASTRING:
			len = scf_value_get_astring(val, cbuf, *bufsz);
			if (len < 0 || len > *bufsz) {
				ret = scf_error();
				goto out;
			}
			ret = 0;
			*bufsz = len;
			break;
		case SCF_TYPE_INTEGER:
			if (scf_value_get_integer(val, &valint) != 0) {
				ret = scf_error();
				goto out;
			}
			length =  snprintf(cbuf, *bufsz, "%lld", valint);
			if (length < 0 || length > *bufsz) {
				ret = SA_BAD_VALUE;
				goto out;
			}
			ret = 0;
			break;
		case SCF_TYPE_BOOLEAN:
			if (scf_value_get_boolean(val, &bval) != 0) {
				ret = scf_error();
				goto out;
			}
			if (bval == 1) {
				length = snprintf(cbuf, *bufsz, "%s", "true");
			} else {
				length = snprintf(cbuf, *bufsz, "%s", "false");
			}
			if (length < 0 || length > *bufsz) {
				ret = SA_BAD_VALUE;
				goto out;
			}
			break;
		default:
			break;
		}
	} else {
		ret = scf_error();
	}
	if ((ret != 0) && scf_error() != SCF_ERROR_NONE)
		fprintf(stdout, gettext("%s\n"), scf_strerror(ret));
out:
	fs_smf_fini(phandle);
	return (ret);
}


int
nfs_smf_get_prop(char *prop_name, char *propbuf, char *instance,
    scf_type_t sctype, char *svc_name, int *bufsz)
{
	return (fs_smf_get_prop(NFS_SMF, prop_name, propbuf,
	    instance, sctype, svc_name, bufsz));
}

/* Get an integer (base 10) property */
int
nfs_smf_get_iprop(char *prop_name, int *rvp, char *instance,
    scf_type_t sctype, char *svc_name)
{
	char propbuf[32];
	int bufsz, rc, val;

	bufsz = sizeof (propbuf);
	rc = fs_smf_get_prop(NFS_SMF, prop_name, propbuf,
	    instance, sctype, svc_name, &bufsz);
	if (rc != SA_OK)
		return (rc);
	errno = 0;
	val = strtol(propbuf, NULL, 10);
	if (errno != 0)
		return (SA_BAD_VALUE);
	*rvp = val;
	return (SA_OK);
}

int
nfs_smf_set_prop(char *prop_name, char *value, char *instance,
    scf_type_t type, char *svc_name)
{
	return (fs_smf_set_prop(NFS_SMF, prop_name, value, instance,
	    type, svc_name));
}

int
autofs_smf_set_prop(char *prop_name, char *value, char *instance,
    scf_type_t type, char *svc_name)
{
	return (fs_smf_set_prop(AUTOFS_SMF, prop_name, value, instance,
	    type, svc_name));
}

int
autofs_smf_get_prop(char *prop_name, char *propbuf, char *instance,
    scf_type_t sctype, char *svc_name, int *bufsz)
{
	return (fs_smf_get_prop(AUTOFS_SMF, prop_name, propbuf,
	    instance, sctype, svc_name, bufsz));
}

boolean_t
string_to_boolean(const char *str)
{
	if (strcasecmp(str, "true") == 0 || atoi(str) == 1 ||
	    strcasecmp(str, "on") == 0 || strcasecmp(str, "yes") == 0) {
		return (B_TRUE);
	} else
		return (B_FALSE);
}

/*
 * upgrade server_versmin and server_versmax from int to string.
 * This is needed to allow to specify version as major.minor.
 */
static void
nfs_upgrade_server_vers(const char *fmri)
{
	fs_smfhandle_t *phandle;
	scf_handle_t *handle;
	scf_propertygroup_t *pg;
	scf_instance_t *inst;
	scf_value_t *vmin = NULL, *vmax = NULL;
	scf_transaction_t *tran = NULL;
	scf_transaction_entry_t *emin = NULL, *emax = NULL;
	char versmax[32];
	char versmin[32];
	int bufsz;

	/*
	 * Read old integer values, stop in case of error - apparently
	 * the upgrade is already done.
	 */
	bufsz = sizeof (versmax);
	if (nfs_smf_get_prop("server_versmax", versmax, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, (char *)fmri, &bufsz) != SA_OK) {
		return;
	}
	bufsz = sizeof (versmin);
	if (nfs_smf_get_prop("server_versmin", versmin, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, (char *)fmri, &bufsz) != SA_OK) {
		return;
	}

	/* Write back as SCF_TYPE_ASTRING */
	phandle = fs_smf_init(fmri, NULL);
	if (phandle == NULL)
		return;

	handle = phandle->fs_handle;
	if (handle == NULL)
		goto done;
	pg = phandle->fs_pg;
	inst = phandle->fs_instance;
	tran = scf_transaction_create(handle);
	vmin = scf_value_create(handle);
	vmax = scf_value_create(handle);
	emin = scf_entry_create(handle);
	emax = scf_entry_create(handle);

	if (pg == NULL || inst == NULL || tran == NULL ||
	    emin == NULL || emax == NULL || vmin == NULL || vmax == NULL) {
		goto done;
	}

	if (scf_handle_decode_fmri(handle, (char *)fmri,
	    phandle->fs_scope, phandle->fs_service, inst, NULL, NULL, 0) != 0) {
		goto done;
	}

	if (scf_instance_get_pg(inst, NFS_PROPS_PGNAME, pg) == -1)
		goto done;

	if (scf_pg_update(pg) == -1)
		goto done;

	if (scf_transaction_start(tran, pg) == -1)
		goto done;

	if (scf_transaction_property_change_type(tran, emax,
	    "server_versmax", SCF_TYPE_ASTRING) != 0) {
		goto done;
	}
	if (scf_value_set_astring(vmax, versmax) == 0) {
		if (scf_entry_add_value(emax, vmax) != 0)
			goto done;
	} else {
		goto done;
	}

	if (scf_transaction_property_change_type(tran, emin,
	    "server_versmin", SCF_TYPE_ASTRING) != 0) {
		goto done;
	}
	if (scf_value_set_astring(vmin, versmin) == 0) {
		if (scf_entry_add_value(emin, vmin) != 0)
			goto done;
	} else {
		goto done;
	}

	(void) scf_transaction_commit(tran);
done:
	if (tran != NULL)
		scf_transaction_destroy(tran);
	if (emin != NULL)
		scf_entry_destroy(emin);
	if (emax != NULL)
		scf_entry_destroy(emax);
	if (vmin != NULL)
		scf_value_destroy(vmin);
	if (vmax != NULL)
		scf_value_destroy(vmax);
	fs_smf_fini(phandle);
}

void
nfs_config_upgrade(const char *svc_name)
{
	if (strcmp(svc_name, NFSD) == 0) {
		nfs_upgrade_server_vers(svc_name);
	}
}
