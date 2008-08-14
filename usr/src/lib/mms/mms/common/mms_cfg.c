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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <syslog.h>
#include <malloc.h>
#include <errno.h>
#include <sys/param.h>
#include <pthread.h>
#include "mms_cfg.h"

static struct {
	char		*mms_cfg_fmri;
	scf_type_t	mms_cfg_type;
} mms_cfg_list [] = {
	MMS_CFG_CONFIG_TYPE,	SCF_TYPE_ASTRING,
	MMS_CFG_MGR_HOST,	SCF_TYPE_USTRING,
	MMS_CFG_MGR_PORT,	SCF_TYPE_INTEGER,
	MMS_CFG_SSL_ENABLED,	SCF_TYPE_BOOLEAN,
	MMS_CFG_SSL_CERT_FILE,	SCF_TYPE_ASTRING,
	MMS_CFG_SSL_PASS_FILE,	SCF_TYPE_ASTRING,
	MMS_CFG_SSL_DH_FILE,	SCF_TYPE_ASTRING,
	MMS_CFG_SSL_CRL_FILE,	SCF_TYPE_ASTRING,
	MMS_CFG_SSL_PEER_FILE,	SCF_TYPE_ASTRING,
	MMS_CFG_SSL_CIPHER,	SCF_TYPE_ASTRING,
	MMS_CFG_SSL_VERIFY,	SCF_TYPE_BOOLEAN,
	MMS_CFG_DB_DATA,	SCF_TYPE_ASTRING,
	MMS_CFG_DB_LOG,		SCF_TYPE_ASTRING,
	MMS_CFG_MM_DB_HOST,	SCF_TYPE_ASTRING,
	MMS_CFG_MM_DB_PORT,	SCF_TYPE_INTEGER,
	MMS_CFG_MM_DB_USER,	SCF_TYPE_ASTRING,
	MMS_CFG_MM_DB_NAME,	SCF_TYPE_ASTRING,
	MMS_CFG_MM_TRACE,	SCF_TYPE_ASTRING,
	MMS_CFG_SSI_PATH,	SCF_TYPE_ASTRING,
	MMS_CFG_LIBAPI_PATH,	SCF_TYPE_ASTRING,
	MMS_CFG_DB_RETRY,	SCF_TYPE_INTEGER,
	MMS_CFG_DB_TIMEOUT,	SCF_TYPE_INTEGER,
	NULL,			NULL,
};

static pthread_mutex_t		mms_cfg_mutex = PTHREAD_MUTEX_INITIALIZER;
static scf_handle_t		*mms_cfg_handle = NULL;
static scf_scope_t		*mms_cfg_scope = NULL;
static scf_service_t		*mms_cfg_svc = NULL;
static scf_instance_t		*mms_cfg_inst = NULL;
static scf_propertygroup_t	*mms_cfg_pg = NULL;
static scf_property_t		*mms_cfg_prop = NULL;

static int mms_cfg_bind(void);
static int mms_cfg_open(const char *fmri);
static void mms_cfg_close(void);
static int mms_cfg_set_prop(const char *name, const char *value,
    scf_type_t type);
static int mms_cfg_delete_prop(const char *name);
static int mms_cfg_tx_error(scf_transaction_t *tx,
    scf_transaction_entry_t *e1, scf_value_t *v1);
static void mms_cfg_tx_fini(scf_transaction_t *tx,
    scf_transaction_entry_t *e1, scf_value_t *v1);

scf_type_t
mms_cfg_get_type(const char *fmri)
{
	int	i;

	for (i = 0; mms_cfg_list[i].mms_cfg_fmri != NULL; i++) {
		if (strcmp(mms_cfg_list[i].mms_cfg_fmri, fmri) == 0) {
			/* built-in property */
			return (mms_cfg_list[i].mms_cfg_type);
		}
	}
	/* not built-in property */
	return (SCF_TYPE_INVALID);
}

static int
mms_cfg_bind(void)
{
	int	rc = 0;

	if (!(mms_cfg_handle = scf_handle_create(SCF_VERSION)) ||
	    !(mms_cfg_scope = scf_scope_create(mms_cfg_handle)) ||
	    !(mms_cfg_svc = scf_service_create(mms_cfg_handle)) ||
	    !(mms_cfg_inst = scf_instance_create(mms_cfg_handle)) ||
	    !(mms_cfg_pg = scf_pg_create(mms_cfg_handle)) ||
	    !(mms_cfg_prop = scf_property_create(mms_cfg_handle)) ||
	    scf_handle_bind(mms_cfg_handle) == -1) {
		rc = scf_error();
		mms_cfg_close();
	}
	return (rc);
}

static int
mms_cfg_open(const char *fmri)
{
	int	rc;

	if (rc = mms_cfg_bind()) {
		return (rc);
	}
	if (scf_handle_decode_fmri(mms_cfg_handle, fmri,
	    mms_cfg_scope, mms_cfg_svc, mms_cfg_inst, mms_cfg_pg,
	    mms_cfg_prop, 0) == -1) {
		rc = scf_error();
		mms_cfg_close();
	}
	return (rc);
}

static void
mms_cfg_close(void)
{
	if (mms_cfg_handle)
		scf_handle_destroy(mms_cfg_handle);
	if (mms_cfg_scope)
		scf_scope_destroy(mms_cfg_scope);
	if (mms_cfg_svc)
		scf_service_destroy(mms_cfg_svc);
	if (mms_cfg_inst)
		scf_instance_destroy(mms_cfg_inst);
	if (mms_cfg_pg)
		scf_pg_destroy(mms_cfg_pg);
	if (mms_cfg_prop)
		scf_property_destroy(mms_cfg_prop);

	mms_cfg_handle = NULL;
	mms_cfg_scope = NULL;
	mms_cfg_svc = NULL;
	mms_cfg_inst = NULL;
	mms_cfg_pg = NULL;
	mms_cfg_prop = NULL;
}

char *
mms_cfg_alloc_getvar(const char *fmri, int *err)
{
	char	*value = malloc(MMS_CFG_MAX_VALUE);
	char	*str = NULL;
	int	rc;

	if (rc = mms_cfg_getvar(fmri, value)) {
		if (err)
			*err = rc;
		free(value);
		return (NULL);
	}
	if (strlen(value) > 0) {
		if ((str = strdup(value)) == NULL) {
			rc = SCF_ERROR_NO_MEMORY;
		}
	}
	if (err)
		*err = rc;
	free(value);
	return (str);
}

int
mms_cfg_getvar(const char *fmri, char *value)
{
	int		rc;
	scf_value_t	*svalue;

	(void) pthread_mutex_lock(&mms_cfg_mutex);
	if (rc = mms_cfg_open(fmri)) {
		(void) pthread_mutex_unlock(&mms_cfg_mutex);
		return (rc);
	}

	if (!(svalue = scf_value_create(mms_cfg_handle)) ||
	    scf_property_get_value(mms_cfg_prop, svalue) == -1 ||
	    scf_value_get_as_string(svalue, value, MMS_CFG_MAX_VALUE) == -1) {
		rc = scf_error();
	}

	if (svalue)
		scf_value_destroy(svalue);

	mms_cfg_close();
	(void) pthread_mutex_unlock(&mms_cfg_mutex);
	return (rc);
}

static int
mms_cfg_set_prop(const char *name, const char *value, scf_type_t type)
{
	scf_transaction_t	*tx;
	scf_transaction_entry_t *e1;
	scf_value_t		*v1;

	tx = scf_transaction_create(mms_cfg_handle);
	e1 = scf_entry_create(mms_cfg_handle);
	v1 = scf_value_create(mms_cfg_handle);

	if (scf_pg_update(mms_cfg_pg) == -1) {
		return (mms_cfg_tx_error(tx, e1, v1));
	}
	if (scf_transaction_start(tx, mms_cfg_pg) == -1) {
		return (mms_cfg_tx_error(tx, e1, v1));
	}
	if (scf_transaction_property_new(tx, e1, name, type) == -1) {
		if (scf_error() != SCF_ERROR_EXISTS) {
			return (mms_cfg_tx_error(tx, e1, v1));
		}
		if (scf_transaction_property_change(tx, e1, name, type) == -1) {
			return (mms_cfg_tx_error(tx, e1, v1));
		}
	}
	if (scf_value_set_from_string(v1, type, value) == -1) {
		return (mms_cfg_tx_error(tx, e1, v1));
	}
	if (scf_entry_add_value(e1, v1) == -1) {
		return (mms_cfg_tx_error(tx, e1, v1));
	}
	if (scf_transaction_commit(tx) == -1) {
		return (mms_cfg_tx_error(tx, e1, v1));
	}
	mms_cfg_tx_fini(tx, e1, v1);
	return (0);
}

static void
mms_cfg_get_pg_name(const char *fmri, char *name)
{
	char	*buf = malloc(MMS_CFG_MAX_NAME);
	char	*end;
	char	*begin;

	(void) strlcpy(buf, fmri, MMS_CFG_MAX_NAME);
	if (end = strrchr(buf, '/')) {
		*end = 0;
		if (begin = strrchr(buf, '/')) {
			(void) strlcpy(name, begin + 1, MMS_CFG_MAX_NAME);
			free(buf);
			return;
		}
	}
	(void) strlcpy(name, fmri, MMS_CFG_MAX_NAME);
	free(buf);
}

static void
mms_cfg_get_prop_name(const char *fmri, char *name)
{
	char	*begin;

	if (begin = strrchr(fmri, '/')) {
		(void) strlcpy(name, begin + 1, MMS_CFG_MAX_NAME);
		return;
	}
	(void) strlcpy(name, fmri, MMS_CFG_MAX_NAME);
}

static char *
mms_cfg_get_inst(const char *fmri)
{
	if (strncmp(fmri, MMS_CFG_MM_INST, strlen(MMS_CFG_MM_INST)) == 0) {
		return (MMS_CFG_MM_INST);
	}

	if (strncmp(fmri, MMS_CFG_DB_INST, strlen(MMS_CFG_DB_INST)) == 0) {
		return (MMS_CFG_DB_INST);
	}

	if (strncmp(fmri, MMS_CFG_WCR_INST, strlen(MMS_CFG_WCR_INST)) == 0) {
		return (MMS_CFG_WCR_INST);
	}

	return ((char *)fmri);
}

static int
mms_cfg_newvar(const char *fmri, const char *value, scf_type_t type)
{
	int		rc;
	char		*pg_name = malloc(MMS_CFG_MAX_NAME);
	char		*prop_name = malloc(MMS_CFG_MAX_NAME);

	if (rc = mms_cfg_bind()) {
		free(pg_name);
		free(prop_name);
		return (rc);
	}

	mms_cfg_get_pg_name(fmri, pg_name);
	mms_cfg_get_prop_name(fmri, prop_name);

	if (fmri[strlen(MMS_CFG_SVC)] == '/') {
		/* service property group */
		if (scf_handle_get_scope(mms_cfg_handle, SCF_SCOPE_LOCAL,
		    mms_cfg_scope) == -1) {
			free(pg_name);
			free(prop_name);
			return (scf_error());
		}
		if (scf_scope_get_service(mms_cfg_scope, MMS_CFG_MMS_SVC,
		    mms_cfg_svc) == -1) {
			free(pg_name);
			free(prop_name);
			return (scf_error());
		}
		if (scf_service_get_pg(mms_cfg_svc, pg_name,
		    mms_cfg_pg) == -1) {
			if ((rc = scf_error()) != SCF_ERROR_NOT_FOUND) {
				free(pg_name);
				free(prop_name);
				return (rc);
			}
			if (scf_service_add_pg(mms_cfg_svc, pg_name,
			    SCF_GROUP_APPLICATION, 0, mms_cfg_pg) == -1) {
				free(pg_name);
				free(prop_name);
				return (scf_error());
			}
		}
	} else {
		/* service instance property group */
		if (scf_handle_decode_fmri(mms_cfg_handle,
		    mms_cfg_get_inst(fmri), mms_cfg_scope, mms_cfg_svc,
		    mms_cfg_inst, mms_cfg_pg, NULL, 0) == -1) {
			free(pg_name);
			free(prop_name);
			return (scf_error());
		}
		if (scf_instance_get_pg(mms_cfg_inst, pg_name,
		    mms_cfg_pg) == -1) {
			if ((rc = scf_error()) != SCF_ERROR_NOT_FOUND) {
				free(pg_name);
				free(prop_name);
				return (rc);
			}
			if (scf_instance_add_pg(mms_cfg_inst, pg_name,
			    SCF_GROUP_APPLICATION, 0, mms_cfg_pg) == -1) {
				free(pg_name);
				free(prop_name);
				return (scf_error());
			}
		}
	}
	rc = mms_cfg_set_prop(prop_name, value, type);
	free(pg_name);
	free(prop_name);
	return (rc);
}

int
mms_cfg_setvar(const char *fmri, const char *value)
{
	int		rc;
	scf_type_t	type;

	if ((type = mms_cfg_get_type(fmri)) == SCF_TYPE_INVALID) {
		/* not built-in, try explicit setvar type func */
		return (SCF_TYPE_INVALID);
	}
	rc = mms_cfg_setvar_type(fmri, value, type);
	return (rc);
}

int
mms_cfg_setvar_type(const char *fmri, const char *value, scf_type_t type)
{
	int	rc;
	char	*name = malloc(MMS_CFG_MAX_NAME);

	(void) pthread_mutex_lock(&mms_cfg_mutex);
	if (rc = mms_cfg_open(fmri)) {
		if (rc != SCF_ERROR_NOT_FOUND) {
			(void) pthread_mutex_unlock(&mms_cfg_mutex);
			free(name);
			return (rc);
		}
		rc = mms_cfg_newvar(fmri, value, type);
	} else {
		if (scf_property_get_name(mms_cfg_prop, name,
		    MMS_CFG_MAX_NAME) == -1) {
			rc = scf_error();
		} else {
			rc = mms_cfg_set_prop(name, value, type);
		}
	}
	mms_cfg_close();
	(void) pthread_mutex_unlock(&mms_cfg_mutex);
	free(name);
	return (rc);
}

static int
mms_cfg_delete_prop(const char *name)
{
	scf_transaction_t *tx;
	scf_transaction_entry_t *e1;

	tx = scf_transaction_create(mms_cfg_handle);
	e1 = scf_entry_create(mms_cfg_handle);

	if (scf_pg_update(mms_cfg_pg) == -1) {
		return (mms_cfg_tx_error(tx, e1, NULL));
	}
	if (scf_transaction_start(tx, mms_cfg_pg) == -1) {
		return (mms_cfg_tx_error(tx, e1, NULL));
	}
	if (scf_transaction_property_delete(tx, e1, name) == -1) {
		return (mms_cfg_tx_error(tx, e1, NULL));
	}
	if (scf_transaction_commit(tx) == -1) {
		return (mms_cfg_tx_error(tx, e1, NULL));
	}
	mms_cfg_tx_fini(tx, e1, NULL);
	return (0);
}

int
mms_cfg_unsetvar(const char *fmri)
{
	int	rc;
	char	*name = malloc(MMS_CFG_MAX_NAME);

	(void) pthread_mutex_lock(&mms_cfg_mutex);
	if (rc = mms_cfg_open(fmri)) {
		(void) pthread_mutex_unlock(&mms_cfg_mutex);
		free(name);
		return (rc);
	}
	if (scf_property_get_name(mms_cfg_prop, name, MMS_CFG_MAX_NAME) == -1) {
		rc = scf_error();
	} else {
		rc = mms_cfg_delete_prop(name);
	}
	mms_cfg_close();
	(void) pthread_mutex_unlock(&mms_cfg_mutex);
	free(name);
	return (rc);
}

static int
mms_cfg_tx_error(scf_transaction_t *tx, scf_transaction_entry_t *e1,
    scf_value_t *v1)
{
	mms_cfg_tx_fini(tx, e1, v1);
	return (scf_error());
}

static void
mms_cfg_tx_fini(scf_transaction_t *tx, scf_transaction_entry_t *e1,
    scf_value_t *v1)
{
	scf_transaction_reset(tx);
	scf_transaction_destroy(tx);
	if (e1)
		scf_entry_destroy(e1);
	if (v1)
		scf_value_destroy(v1);
}
