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
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/* helper functions for using libscf with CIFS */

#include <libscf.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <libintl.h>
#include <assert.h>
#include <strings.h>

#include <uuid/uuid.h>
#include <sys/param.h>

#include <smbsrv/libsmb.h>

/*
 * smb_smf_scf_log_error(msg)
 * Logs error messages from scf API's
 */
static void
smb_smf_scf_log_error(char *msg)
{
	if (msg == NULL)
		msg = "SMBD SMF problem";

	syslog(LOG_ERR, " %s: %s", msg, scf_strerror(scf_error()));
}

/*
 * smb_smf_create_service_pgroup(handle, pgroup)
 *
 * create a new property group at service level.
 */
int
smb_smf_create_service_pgroup(smb_scfhandle_t *handle, char *pgroup)
{
	int ret = SMBD_SMF_OK;
	int err;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	/*
	 * only create a handle if it doesn't exist. It is ok to exist
	 * since the pg handle will be set as a side effect.
	 */
	if (handle->scf_pg == NULL)
		if ((handle->scf_pg =
		    scf_pg_create(handle->scf_handle)) == NULL)
			return (SMBD_SMF_SYSTEM_ERR);

	/*
	 * if the pgroup exists, we are done. If it doesn't, then we
	 * need to actually add one to the service instance.
	 */
	if (scf_service_get_pg(handle->scf_service,
	    pgroup, handle->scf_pg) != 0) {
		/* doesn't exist so create one */
		if (scf_service_add_pg(handle->scf_service, pgroup,
		    SCF_GROUP_APPLICATION, 0, handle->scf_pg) != 0) {
			err = scf_error();
			if (err != SCF_ERROR_NONE)
				smb_smf_scf_log_error(NULL);
			switch (err) {
			case SCF_ERROR_PERMISSION_DENIED:
				ret = SMBD_SMF_NO_PERMISSION;
				break;
			default:
				ret = SMBD_SMF_SYSTEM_ERR;
				break;
			}
		}
	}
	return (ret);
}

/*
 * Start transaction on current pg in handle.
 * The pg could be service or instance level.
 * Must be called after pg handle is obtained
 * from create or get.
 */
int
smb_smf_start_transaction(smb_scfhandle_t *handle)
{
	int ret = SMBD_SMF_OK;

	if (!handle || (!handle->scf_pg))
		return (SMBD_SMF_SYSTEM_ERR);

	/*
	 * lookup the property group and create it if it doesn't already
	 * exist.
	 */
	if (handle->scf_state == SCH_STATE_INIT) {
		if (ret == SMBD_SMF_OK) {
			handle->scf_trans =
			    scf_transaction_create(handle->scf_handle);
			if (handle->scf_trans != NULL) {
				if (scf_transaction_start(handle->scf_trans,
				    handle->scf_pg) != 0) {
					ret = SMBD_SMF_SYSTEM_ERR;
					scf_transaction_destroy(
					    handle->scf_trans);
					handle->scf_trans = NULL;
				}
			} else {
				ret = SMBD_SMF_SYSTEM_ERR;
			}
		}
	}
	if (ret == SMBD_SMF_SYSTEM_ERR &&
	    scf_error() == SCF_ERROR_PERMISSION_DENIED)
		ret = SMBD_SMF_NO_PERMISSION;

	return (ret);
}

/*
 * smb_smf_end_transaction(handle)
 *
 * Commit the changes that were added to the transaction in the
 * handle. Do all necessary cleanup.
 */
int
smb_smf_end_transaction(smb_scfhandle_t *handle)
{
	int ret = SMBD_SMF_OK;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	if (handle->scf_trans == NULL) {
		ret = SMBD_SMF_SYSTEM_ERR;
	} else {
		if (scf_transaction_commit(handle->scf_trans) < 0) {
			ret = SMBD_SMF_SYSTEM_ERR;
			smb_smf_scf_log_error("Failed to commit "
			    "transaction: %s");
		}
		scf_transaction_destroy_children(handle->scf_trans);
		scf_transaction_destroy(handle->scf_trans);
		handle->scf_trans = NULL;
	}
	return (ret);
}

/*
 * Sets string property in current pg
 */
int
smb_smf_set_string_property(smb_scfhandle_t *handle,
    char *propname, char *valstr)
{
	int ret = SMBD_SMF_OK;
	scf_value_t *value = NULL;
	scf_transaction_entry_t *entry = NULL;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	/*
	 * properties must be set in transactions and don't take
	 * effect until the transaction has been ended/committed.
	 */
	value = scf_value_create(handle->scf_handle);
	entry = scf_entry_create(handle->scf_handle);
	if (value != NULL && entry != NULL) {
		if (scf_transaction_property_change(handle->scf_trans, entry,
		    propname, SCF_TYPE_ASTRING) == 0 ||
		    scf_transaction_property_new(handle->scf_trans, entry,
		    propname, SCF_TYPE_ASTRING) == 0) {
			if (scf_value_set_astring(value, valstr) == 0) {
				if (scf_entry_add_value(entry, value) != 0) {
					ret = SMBD_SMF_SYSTEM_ERR;
					scf_value_destroy(value);
				}
				/* the value is in the transaction */
				value = NULL;
			} else {
				/* value couldn't be constructed */
				ret = SMBD_SMF_SYSTEM_ERR;
			}
			/* the entry is in the transaction */
			entry = NULL;
		} else {
			ret = SMBD_SMF_SYSTEM_ERR;
		}
	} else {
		ret = SMBD_SMF_SYSTEM_ERR;
	}
	if (ret == SMBD_SMF_SYSTEM_ERR) {
		switch (scf_error()) {
		case SCF_ERROR_PERMISSION_DENIED:
			ret = SMBD_SMF_NO_PERMISSION;
			break;
		}
	}

	/*
	 * cleanup if there were any errors that didn't leave these
	 * values where they would be cleaned up later.
	 */
	if (value != NULL)
		scf_value_destroy(value);
	if (entry != NULL)
		scf_entry_destroy(entry);
	return (ret);
}

/*
 * Gets string property value.upto sz size.
 * Caller is responsible to have enough memory allocated.
 */
int
smb_smf_get_string_property(smb_scfhandle_t *handle, char *propname,
    char *valstr, size_t sz)
{
	int ret = SMBD_SMF_OK;
	scf_value_t *value;
	scf_property_t *prop;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	value = scf_value_create(handle->scf_handle);
	prop = scf_property_create(handle->scf_handle);
	if (value && prop &&
	    (scf_pg_get_property(handle->scf_pg, propname, prop) == 0)) {
		if (scf_property_get_value(prop, value) == 0) {
			if (scf_value_get_astring(value, valstr, sz) < 0) {
				ret = SMBD_SMF_SYSTEM_ERR;
			}
		} else {
			ret = SMBD_SMF_SYSTEM_ERR;
		}
	} else {
		ret = SMBD_SMF_SYSTEM_ERR;
	}
	if (value != NULL)
		scf_value_destroy(value);
	if (prop != NULL)
		scf_property_destroy(prop);
	return (ret);
}

/*
 * Set integer value of property.
 * The value is returned as int64_t value
 * Caller ensures appropriate translation.
 */
int
smb_smf_set_integer_property(smb_scfhandle_t *handle, char *propname,
    int64_t valint)
{
	int ret = SMBD_SMF_OK;
	scf_value_t *value = NULL;
	scf_transaction_entry_t *entry = NULL;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	/*
	 * properties must be set in transactions and don't take
	 * effect until the transaction has been ended/committed.
	 */
	value = scf_value_create(handle->scf_handle);
	entry = scf_entry_create(handle->scf_handle);
	if (value != NULL && entry != NULL) {
		if (scf_transaction_property_change(handle->scf_trans, entry,
		    propname, SCF_TYPE_INTEGER) == 0 ||
		    scf_transaction_property_new(handle->scf_trans, entry,
		    propname, SCF_TYPE_INTEGER) == 0) {
			scf_value_set_integer(value, valint);
			if (scf_entry_add_value(entry, value) != 0) {
				ret = SMBD_SMF_SYSTEM_ERR;
				scf_value_destroy(value);
			}
			/* the value is in the transaction */
			value = NULL;
		}
		/* the entry is in the transaction */
		entry = NULL;
	} else {
		ret = SMBD_SMF_SYSTEM_ERR;
	}
	if (ret == SMBD_SMF_SYSTEM_ERR) {
		switch (scf_error()) {
		case SCF_ERROR_PERMISSION_DENIED:
			ret = SMBD_SMF_NO_PERMISSION;
			break;
		}
	}
	/*
	 * cleanup if there were any errors that didn't leave these
	 * values where they would be cleaned up later.
	 */
	if (value != NULL)
		scf_value_destroy(value);
	if (entry != NULL)
		scf_entry_destroy(entry);
	return (ret);
}

/*
 * Gets integer property value.
 * Caller is responsible to have enough memory allocated.
 */
int
smb_smf_get_integer_property(smb_scfhandle_t *handle, char *propname,
    int64_t *valint)
{
	int ret = SMBD_SMF_OK;
	scf_value_t *value = NULL;
	scf_property_t *prop = NULL;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	value = scf_value_create(handle->scf_handle);
	prop = scf_property_create(handle->scf_handle);
	if ((prop) && (value) &&
	    (scf_pg_get_property(handle->scf_pg, propname, prop) == 0)) {
		if (scf_property_get_value(prop, value) == 0) {
			if (scf_value_get_integer(value,
			    valint) != 0) {
				ret = SMBD_SMF_SYSTEM_ERR;
			}
		} else {
			ret = SMBD_SMF_SYSTEM_ERR;
		}
	} else {
		ret = SMBD_SMF_SYSTEM_ERR;
	}
	if (value != NULL)
		scf_value_destroy(value);
	if (prop != NULL)
		scf_property_destroy(prop);
	return (ret);
}

/*
 * Set boolean value of property.
 * The value is returned as int64_t value
 * Caller ensures appropriate translation.
 */
int
smb_smf_set_boolean_property(smb_scfhandle_t *handle, char *propname,
    uint8_t valbool)
{
	int ret = SMBD_SMF_OK;
	scf_value_t *value = NULL;
	scf_transaction_entry_t *entry = NULL;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	/*
	 * properties must be set in transactions and don't take
	 * effect until the transaction has been ended/committed.
	 */
	value = scf_value_create(handle->scf_handle);
	entry = scf_entry_create(handle->scf_handle);
	if (value != NULL && entry != NULL) {
		if (scf_transaction_property_change(handle->scf_trans, entry,
		    propname, SCF_TYPE_BOOLEAN) == 0 ||
		    scf_transaction_property_new(handle->scf_trans, entry,
		    propname, SCF_TYPE_BOOLEAN) == 0) {
			scf_value_set_boolean(value, valbool);
			if (scf_entry_add_value(entry, value) != 0) {
				ret = SMBD_SMF_SYSTEM_ERR;
				scf_value_destroy(value);
			}
			/* the value is in the transaction */
			value = NULL;
		}
		/* the entry is in the transaction */
		entry = NULL;
	} else {
		ret = SMBD_SMF_SYSTEM_ERR;
	}
	if (ret == SMBD_SMF_SYSTEM_ERR) {
		switch (scf_error()) {
		case SCF_ERROR_PERMISSION_DENIED:
			ret = SMBD_SMF_NO_PERMISSION;
			break;
		}
	}
	/*
	 * cleanup if there were any errors that didn't leave these
	 * values where they would be cleaned up later.
	 */
	if (value != NULL)
		scf_value_destroy(value);
	if (entry != NULL)
		scf_entry_destroy(entry);
	return (ret);
}

/*
 * Gets boolean property value.
 * Caller is responsible to have enough memory allocated.
 */
int
smb_smf_get_boolean_property(smb_scfhandle_t *handle, char *propname,
    uint8_t *valbool)
{
	int ret = SMBD_SMF_OK;
	scf_value_t *value = NULL;
	scf_property_t *prop = NULL;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	value = scf_value_create(handle->scf_handle);
	prop = scf_property_create(handle->scf_handle);
	if ((prop) && (value) &&
	    (scf_pg_get_property(handle->scf_pg, propname, prop) == 0)) {
		if (scf_property_get_value(prop, value) == 0) {
			if (scf_value_get_boolean(value,
			    valbool) != 0) {
				ret = SMBD_SMF_SYSTEM_ERR;
			}
		} else {
			ret = SMBD_SMF_SYSTEM_ERR;
		}
	} else {
		ret = SMBD_SMF_SYSTEM_ERR;
	}
	if (value != NULL)
		scf_value_destroy(value);
	if (prop != NULL)
		scf_property_destroy(prop);
	return (ret);
}

/*
 * Sets a blob property value.
 */
int
smb_smf_set_opaque_property(smb_scfhandle_t *handle, char *propname,
    void *voidval, size_t sz)
{
	int ret = SMBD_SMF_OK;
	scf_value_t *value;
	scf_transaction_entry_t *entry;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	/*
	 * properties must be set in transactions and don't take
	 * effect until the transaction has been ended/committed.
	 */
	value = scf_value_create(handle->scf_handle);
	entry = scf_entry_create(handle->scf_handle);
	if (value != NULL && entry != NULL) {
		if (scf_transaction_property_change(handle->scf_trans, entry,
		    propname, SCF_TYPE_OPAQUE) == 0 ||
		    scf_transaction_property_new(handle->scf_trans, entry,
		    propname, SCF_TYPE_OPAQUE) == 0) {
			if (scf_value_set_opaque(value, voidval, sz) == 0) {
				if (scf_entry_add_value(entry, value) != 0) {
					ret = SMBD_SMF_SYSTEM_ERR;
					scf_value_destroy(value);
				}
				/* the value is in the transaction */
				value = NULL;
			} else {
				/* value couldn't be constructed */
				ret = SMBD_SMF_SYSTEM_ERR;
			}
			/* the entry is in the transaction */
			entry = NULL;
		} else {
			ret = SMBD_SMF_SYSTEM_ERR;
		}
	} else {
		ret = SMBD_SMF_SYSTEM_ERR;
	}
	if (ret == SMBD_SMF_SYSTEM_ERR) {
		switch (scf_error()) {
		case SCF_ERROR_PERMISSION_DENIED:
			ret = SMBD_SMF_NO_PERMISSION;
			break;
		}
	}
	/*
	 * cleanup if there were any errors that didn't leave these
	 * values where they would be cleaned up later.
	 */
	if (value != NULL)
		scf_value_destroy(value);
	if (entry != NULL)
		scf_entry_destroy(entry);
	return (ret);
}

/*
 * Gets a blob property value.
 * Caller is responsible to have enough memory allocated.
 */
int
smb_smf_get_opaque_property(smb_scfhandle_t *handle, char *propname,
    void *v, size_t sz)
{
	int ret = SMBD_SMF_OK;
	scf_value_t *value = NULL;
	scf_property_t *prop = NULL;

	if (handle == NULL)
		return (SMBD_SMF_SYSTEM_ERR);

	value = scf_value_create(handle->scf_handle);
	prop = scf_property_create(handle->scf_handle);
	if ((prop) && (value) &&
	    (scf_pg_get_property(handle->scf_pg, propname, prop) == 0)) {
		if (scf_property_get_value(prop, value) == 0) {
			if (scf_value_get_opaque(value, (char *)v, sz) != sz) {
				ret = SMBD_SMF_SYSTEM_ERR;
			}
		} else {
			ret = SMBD_SMF_SYSTEM_ERR;
		}
	} else {
		ret = SMBD_SMF_SYSTEM_ERR;
	}
	if (value != NULL)
		scf_value_destroy(value);
	if (prop != NULL)
		scf_property_destroy(prop);
	return (ret);
}

/*
 * Put the smb service into maintenance mode.
 */
int
smb_smf_maintenance_mode(void)
{
	return (smf_maintain_instance(SMBD_DEFAULT_INSTANCE_FMRI, 0));
}

/*
 * Restart the smb service.
 */
int
smb_smf_restart_service(void)
{
	return (smf_restart_instance(SMBD_DEFAULT_INSTANCE_FMRI));
}

/*
 * smb_smf_scf_init()
 *
 * must be called before using any of the SCF functions.
 * Returns smb_scfhandle_t pointer if success.
 */
smb_scfhandle_t *
smb_smf_scf_init(char *svc_name)
{
	smb_scfhandle_t *handle;

	handle = malloc(sizeof (smb_scfhandle_t));
	if (handle != NULL) {
		bzero((char *)handle, sizeof (smb_scfhandle_t));
		handle->scf_state = SCH_STATE_INITIALIZING;
		handle->scf_handle = scf_handle_create(SCF_VERSION);
		if (handle->scf_handle != NULL) {
			if (scf_handle_bind(handle->scf_handle) == 0) {
				handle->scf_scope =
				    scf_scope_create(handle->scf_handle);

				if (handle->scf_scope == NULL)
					goto err;

				if (scf_handle_get_local_scope(
				    handle->scf_handle, handle->scf_scope) != 0)
					goto err;

				handle->scf_service =
				    scf_service_create(handle->scf_handle);

				if (handle->scf_service == NULL)
					goto err;

				if (scf_scope_get_service(handle->scf_scope,
				    svc_name, handle->scf_service)
				    != SCF_SUCCESS) {
					goto err;
				}
				handle->scf_pg =
				    scf_pg_create(handle->scf_handle);

				if (handle->scf_pg == NULL)
					goto err;

				handle->scf_state = SCH_STATE_INIT;
			} else {
				goto err;
			}
		} else {
			free(handle);
			handle = NULL;
			smb_smf_scf_log_error("Could not access SMF "
			    "repository: %s\n");
		}
	}
	return (handle);

	/* error handling/unwinding */
err:
	(void) smb_smf_scf_fini(handle);
	(void) smb_smf_scf_log_error("SMF initialization problem: %s\n");
	return (NULL);
}

/*
 * smb_smf_scf_fini(handle)
 *
 * must be called when done. Called with the handle allocated in
 * smb_smf_scf_init(), it cleans up the state and frees any SCF resources
 * still in use.
 */
void
smb_smf_scf_fini(smb_scfhandle_t *handle)
{
	if (handle != NULL) {
		int unbind = 0;
		scf_iter_destroy(handle->scf_pg_iter);
		handle->scf_pg_iter = NULL;

		scf_iter_destroy(handle->scf_inst_iter);
		handle->scf_inst_iter = NULL;

		unbind = 1;
		scf_scope_destroy(handle->scf_scope);
		handle->scf_scope = NULL;

		scf_instance_destroy(handle->scf_instance);
		handle->scf_instance = NULL;

		scf_service_destroy(handle->scf_service);
		handle->scf_service = NULL;

		scf_pg_destroy(handle->scf_pg);
		handle->scf_pg = NULL;

		handle->scf_state = SCH_STATE_UNINIT;
		if (unbind)
			(void) scf_handle_unbind(handle->scf_handle);
		scf_handle_destroy(handle->scf_handle);
		handle->scf_handle = NULL;

		free(handle);
	}
}
