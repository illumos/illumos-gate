/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NDMP configuration management
 */
#include <stdio.h>
#include <stdlib.h>
#include <synch.h>
#include <libintl.h>
#include <strings.h>
#include <libndmp.h>

/* NDMP properties configuration */
#define	NDMP_GROUP_FMRI_PREFIX	"system/ndmpd"
#define	NDMP_INST		"svc:/system/ndmpd:default"
#define	NDMP_PROP_LEN		600
static char *ndmp_pg[] = {
	"ndmpd",
	"read"
};
#define	NPG	(sizeof (ndmp_pg) / sizeof (ndmp_pg[0]))

/* Handle Init states */
#define	NDMP_SCH_STATE_UNINIT		0
#define	NDMP_SCH_STATE_INITIALIZING	1
#define	NDMP_SCH_STATE_INIT		2

/* NDMP scf handle structure */
typedef struct ndmp_scfhandle {
	scf_handle_t *scf_handle;
	int scf_state;
	scf_service_t *scf_service;
	scf_scope_t *scf_scope;
	scf_transaction_t *scf_trans;
	scf_propertygroup_t *scf_pg;
} ndmp_scfhandle_t;

static int ndmp_config_saveenv(ndmp_scfhandle_t *);
static ndmp_scfhandle_t *ndmp_smf_scf_init(char *);
static void ndmp_smf_scf_fini(ndmp_scfhandle_t *);
static int ndmp_smf_start_transaction(ndmp_scfhandle_t *);
static int ndmp_smf_end_transaction(ndmp_scfhandle_t *);
static int ndmp_smf_set_property(ndmp_scfhandle_t *, char *, char *);
static int ndmp_smf_get_property(ndmp_scfhandle_t *, char *, char *, size_t);
static int ndmp_smf_create_service_pgroup(ndmp_scfhandle_t *, char *);
static int ndmp_smf_delete_property(ndmp_scfhandle_t *, char *);
static int ndmp_smf_get_pg_name(ndmp_scfhandle_t *, char *, char **);

/*
 * This routine send a refresh signal to ndmpd service which cause ndmpd
 * property table to be refeshed with current ndmpd properties value from SMF.
 */
int
ndmp_service_refresh(void)
{
	if ((smf_get_state(NDMP_INST)) != NULL)
		return (smf_refresh_instance(NDMP_INST));

	ndmp_errno = ENDMP_SMF_INTERNAL;
	return (-1);
}

/*
 * Returns value of the specified variable/property. The return value is a
 * string pointer to the locally allocated memory if the config param is
 * defined otherwise it would be NULL.
 */
int
ndmp_get_prop(char *prop, char **value)
{
	ndmp_scfhandle_t *handle = NULL;
	char *lval = (char *)malloc(NDMP_PROP_LEN);
	char *pgname;

	if (!lval) {
		ndmp_errno = ENDMP_MEM_ALLOC;
		return (-1);
	}
	if ((handle = ndmp_smf_scf_init(NDMP_GROUP_FMRI_PREFIX)) == NULL) {
		free(lval);
		return (-1);
	}
	if (ndmp_smf_get_pg_name(handle, prop, &pgname)) {
		free(lval);
		ndmp_errno = ENDMP_SMF_PROP_GRP;
		return (-1);
	}
	if (ndmp_smf_create_service_pgroup(handle, pgname)) {
		ndmp_smf_scf_fini(handle);
		free(lval);
		return (-1);
	}
	if (ndmp_smf_get_property(handle, prop, lval, NDMP_PROP_LEN) != 0) {
		ndmp_smf_scf_fini(handle);
		free(lval);
		ndmp_errno = ENDMP_SMF_PROP;
		return (-1);
	}
	*value = lval;
	ndmp_smf_scf_fini(handle);
	return (0);
}

int
ndmp_set_prop(char *env, char *env_val)
{
	ndmp_scfhandle_t *handle = NULL;
	char *pgname;

	if ((handle = ndmp_smf_scf_init(NDMP_GROUP_FMRI_PREFIX)) == NULL)
		return (-1);

	if (ndmp_smf_get_pg_name(handle, env, &pgname)) {
		ndmp_errno = ENDMP_SMF_PROP_GRP;
		return (-1);
	}

	if (ndmp_smf_create_service_pgroup(handle, pgname))
		return (-1);

	if (ndmp_smf_start_transaction(handle))
		return (-1);

	if (env_val) {
		if (ndmp_smf_set_property(handle, env, env_val)) {
			return (-1);
		}
	} else {
		if (ndmp_smf_delete_property(handle, env))
			return (-1);
	}

	if (ndmp_config_saveenv(handle) != 0)
		return (-1);

	return (0);
}

static int
ndmp_smf_get_pg_name(ndmp_scfhandle_t *h, char *pname, char **pgname)
{
	scf_value_t *value;
	scf_property_t *prop;
	int i;

	for (i = 0; i < NPG; i++) {
		if (scf_service_get_pg(h->scf_service, ndmp_pg[i],
		    h->scf_pg) != 0)
			return (-1);

		if ((value = scf_value_create(h->scf_handle)) == NULL)
			return (-1);

		if ((prop = scf_property_create(h->scf_handle)) == NULL) {
			scf_value_destroy(value);
			return (-1);
		}
		/*
		 * This will fail if property does not exist in the property
		 * group. Check the next property group in case of failure.
		 */
		if ((scf_pg_get_property(h->scf_pg, pname, prop)) != 0) {
			scf_value_destroy(value);
			scf_property_destroy(prop);
			continue;
		}

		*pgname = ndmp_pg[i];
		scf_value_destroy(value);
		scf_property_destroy(prop);
		return (0);
	}
	return (-1);
}

/*
 * Basically commit the transaction.
 */
static int
ndmp_config_saveenv(ndmp_scfhandle_t *handle)
{
	int ret = 0;

	ret = ndmp_smf_end_transaction(handle);

	ndmp_smf_scf_fini(handle);
	return (ret);
}

/*
 * Must be called when done. Called with the handle allocated in
 * ndmp_smf_scf_init(), it cleans up the state and frees any SCF resources
 * still in use.
 */
static void
ndmp_smf_scf_fini(ndmp_scfhandle_t *handle)
{
	if (handle != NULL) {
		scf_scope_destroy(handle->scf_scope);
		scf_service_destroy(handle->scf_service);
		scf_pg_destroy(handle->scf_pg);
		handle->scf_state = NDMP_SCH_STATE_UNINIT;
		(void) scf_handle_unbind(handle->scf_handle);
		scf_handle_destroy(handle->scf_handle);
		free(handle);
	}
}

/*
 * Must be called before using any of the SCF functions. Returns
 * ndmp_scfhandle_t pointer if success.
 */
static ndmp_scfhandle_t *
ndmp_smf_scf_init(char *svc_name)
{
	ndmp_scfhandle_t *handle;

	handle = (ndmp_scfhandle_t *)calloc(1, sizeof (ndmp_scfhandle_t));
	if (handle != NULL) {
		handle->scf_state = NDMP_SCH_STATE_INITIALIZING;
		if (((handle->scf_handle =
		    scf_handle_create(SCF_VERSION)) != NULL) &&
		    (scf_handle_bind(handle->scf_handle) == 0)) {
			if ((handle->scf_scope =
			    scf_scope_create(handle->scf_handle)) == NULL)
				goto err;

			if (scf_handle_get_local_scope(handle->scf_handle,
			    handle->scf_scope) != 0)
				goto err;

			if ((handle->scf_service =
			    scf_service_create(handle->scf_handle)) == NULL)
				goto err;

			if (scf_scope_get_service(handle->scf_scope, svc_name,
			    handle->scf_service) != SCF_SUCCESS)
				goto err;

			if ((handle->scf_pg =
			    scf_pg_create(handle->scf_handle)) == NULL)
				goto err;

			handle->scf_state = NDMP_SCH_STATE_INIT;
		} else {
			goto err;
		}
	} else {
		ndmp_errno = ENDMP_MEM_ALLOC;
		handle = NULL;
	}
	return (handle);

	/* Error handling/unwinding */
err:
	(void) ndmp_smf_scf_fini(handle);
	ndmp_errno = ENDMP_SMF_INTERNAL;
	return (NULL);
}

/*
 * Create a new property group at service level.
 */
static int
ndmp_smf_create_service_pgroup(ndmp_scfhandle_t *handle, char *pgroup)
{
	int err;

	/*
	 * Only create a handle if it doesn't exist. It is ok to exist since
	 * the pg handle will be set as a side effect.
	 */
	if (handle->scf_pg == NULL) {
		if ((handle->scf_pg =
		    scf_pg_create(handle->scf_handle)) == NULL)
			ndmp_errno = ENDMP_SMF_INTERNAL;
			return (-1);
	}

	/*
	 * If the pgroup exists, we are done. If it doesn't, then we need to
	 * actually add one to the service instance.
	 */
	if (scf_service_get_pg(handle->scf_service,
	    pgroup, handle->scf_pg) != 0) {
		/* Doesn't exist so create one */
		if (scf_service_add_pg(handle->scf_service, pgroup,
		    SCF_GROUP_FRAMEWORK, 0, handle->scf_pg) != 0) {
			err = scf_error();
			switch (err) {
			case SCF_ERROR_PERMISSION_DENIED:
				ndmp_errno = ENDMP_SMF_PERM;
				return (-1);
			default:
				ndmp_errno = ENDMP_SMF_INTERNAL;
				return (-1);
			}
		}
	}
	return (0);
}

/*
 * Start transaction on current pg in handle. The pg could be service or
 * instance level. Must be called after pg handle is obtained from create or
 * get.
 */
static int
ndmp_smf_start_transaction(ndmp_scfhandle_t *handle)
{
	/*
	 * Lookup the property group and create it if it doesn't already
	 * exist.
	 */
	if (handle->scf_state == NDMP_SCH_STATE_INIT) {
		if ((handle->scf_trans =
		    scf_transaction_create(handle->scf_handle)) != NULL) {
			if (scf_transaction_start(handle->scf_trans,
			    handle->scf_pg) != 0) {
				scf_transaction_destroy(handle->scf_trans);
				handle->scf_trans = NULL;
				ndmp_errno = ENDMP_SMF_INTERNAL;
				return (-1);
			}
		} else {
			ndmp_errno = ENDMP_SMF_INTERNAL;
			return (-1);
		}
	}
	if (scf_error() == SCF_ERROR_PERMISSION_DENIED) {
		ndmp_errno = ENDMP_SMF_PERM;
		return (-1);
	}

	return (0);
}

/*
 * Commit the changes that were added to the transaction in the handle. Do all
 * necessary cleanup.
 */
static int
ndmp_smf_end_transaction(ndmp_scfhandle_t *handle)
{
	if (scf_transaction_commit(handle->scf_trans) < 0) {
		ndmp_errno = ENDMP_SMF_INTERNAL;
		return (-1);
	}

	scf_transaction_destroy_children(handle->scf_trans);
	scf_transaction_destroy(handle->scf_trans);
	handle->scf_trans = NULL;

	return (0);
}

/*
 * Deletes property in current pg
 */
static int
ndmp_smf_delete_property(ndmp_scfhandle_t *handle, char *propname)
{
	scf_transaction_entry_t *entry = NULL;

	/*
	 * Properties must be set in transactions and don't take effect until
	 * the transaction has been ended/committed.
	 */
	if ((entry = scf_entry_create(handle->scf_handle)) != NULL) {
		if (scf_transaction_property_delete(handle->scf_trans, entry,
		    propname) != 0) {
			scf_entry_destroy(entry);
			ndmp_errno = ENDMP_SMF_INTERNAL;
			return (-1);
		}
	} else {
		ndmp_errno = ENDMP_SMF_INTERNAL;
		return (-1);
	}
	if ((scf_error()) == SCF_ERROR_PERMISSION_DENIED) {
		ndmp_errno = ENDMP_SMF_PERM;
		scf_entry_destroy(entry);
		return (-1);
	}

	return (0);
}

/*
 * Sets property in current pg
 */
static int
ndmp_smf_set_property(ndmp_scfhandle_t *handle,
    char *propname, char *valstr)
{
	int ret = 0;
	scf_value_t *value = NULL;
	scf_transaction_entry_t *entry = NULL;
	scf_property_t *prop;
	scf_type_t type;
	int64_t valint;
	uint8_t valbool;

	/*
	 * Properties must be set in transactions and don't take effect until
	 * the transaction has been ended/committed.
	 */
	if (((value = scf_value_create(handle->scf_handle)) != NULL) &&
	    (entry = scf_entry_create(handle->scf_handle)) != NULL) {
		if (((prop =
		    scf_property_create(handle->scf_handle)) != NULL) &&
		    ((scf_pg_get_property(handle->scf_pg, propname,
		    prop)) == 0)) {
			if (scf_property_get_value(prop, value) == 0) {
				type = scf_value_type(value);
				if ((scf_transaction_property_change(
				    handle->scf_trans, entry, propname,
				    type) == 0) ||
				    (scf_transaction_property_new(
				    handle->scf_trans, entry, propname,
				    type) == 0)) {
					switch (type) {
					case SCF_TYPE_ASTRING:
						if ((scf_value_set_astring(
						    value,
						    valstr)) != SCF_SUCCESS)
							ret = -1;
						break;
					case SCF_TYPE_INTEGER:
						valint = strtoll(valstr, 0, 0);
						scf_value_set_integer(value,
						    valint);
						break;
					case SCF_TYPE_BOOLEAN:
						if (strncmp(valstr, "yes", 3))
							valbool = 0;
						else
							valbool = 1;
						scf_value_set_boolean(value,
						    valbool);
						break;
					default:
						ret = -1;
					}
					if (scf_entry_add_value(entry,
					    value) != 0) {
						ret = -1;
						scf_value_destroy(value);
					}
					/* The value is in the transaction */
					value = NULL;
				}
				/* The entry is in the transaction */
				entry = NULL;
			} else {
				ret = -1;
			}
		} else {
			ret = -1;
		}
	} else {
		ret = -1;
	}
	if (ret == -1) {
		if ((scf_error() == SCF_ERROR_PERMISSION_DENIED))
			ndmp_errno = ENDMP_SMF_PERM;
		else
			ndmp_errno = ENDMP_SMF_INTERNAL;
	}
	scf_value_destroy(value);
	scf_entry_destroy(entry);
	return (ret);
}

/*
 * Gets a property value.upto sz size. Caller is responsible to have enough
 * memory allocated.
 */
static int
ndmp_smf_get_property(ndmp_scfhandle_t *handle, char *propname,
    char *valstr, size_t sz)
{
	int ret = 0;
	scf_value_t *value;
	scf_property_t *prop;
	scf_type_t type;
	int64_t valint;
	uint8_t valbool;
	char valstrbuf[NDMP_PROP_LEN];

	if (((value = scf_value_create(handle->scf_handle)) != NULL) &&
	    ((prop = scf_property_create(handle->scf_handle)) != NULL) &&
	    (scf_pg_get_property(handle->scf_pg, propname, prop) == 0)) {
		if (scf_property_get_value(prop, value) == 0) {
			type = scf_value_type(value);
			switch (type) {
			case SCF_TYPE_ASTRING:
				if (scf_value_get_astring(value, valstr,
				    sz) < 0) {
					ret = -1;
				}
				break;
			case SCF_TYPE_INTEGER:
				if (scf_value_get_integer(value,
				    &valint) != 0) {
					ret = -1;
					break;
				}
				valstrbuf[NDMP_PROP_LEN - 1] = '\0';
				(void) strncpy(valstr, lltostr(valint,
				    &valstrbuf[NDMP_PROP_LEN - 1]),
				    NDMP_PROP_LEN);
				break;
			case SCF_TYPE_BOOLEAN:
				if (scf_value_get_boolean(value,
				    &valbool) != 0) {
					ret = -1;
					break;
				}
				if (valbool == 1)
					(void) strncpy(valstr, "yes", 4);
				else
					(void) strncpy(valstr, "no", 3);
				break;
			default:
				ret = -1;
			}
		} else {
			ret = -1;
		}
	} else {
		ret = -1;
	}
	scf_value_destroy(value);
	scf_property_destroy(prop);
	return (ret);
}
