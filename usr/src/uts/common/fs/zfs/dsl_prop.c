/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/spa.h>
#include <sys/zio_checksum.h> /* for the default checksum value */
#include <sys/zap.h>
#include <sys/fs/zfs.h>

#include "zfs_prop.h"

static int
dodefault(const char *propname, int intsz, int numint, void *buf)
{
	zfs_prop_t prop;

	if ((prop = zfs_name_to_prop(propname)) == ZFS_PROP_INVAL ||
	    zfs_prop_readonly(prop))
		return (ENOENT);

	if (zfs_prop_get_type(prop) == prop_type_string) {
		if (intsz != 1)
			return (EOVERFLOW);
		zfs_prop_default_string(prop, buf, numint);
	} else {
		if (intsz != 8 || numint < 1)
			return (EOVERFLOW);

		*(uint64_t *)buf = zfs_prop_default_numeric(prop);
	}

	return (0);
}

static int
dsl_prop_get_impl(dsl_pool_t *dp, uint64_t ddobj, const char *propname,
    int intsz, int numint, void *buf, char *setpoint)
{
	int err = 0;
	objset_t *mos = dp->dp_meta_objset;

	if (setpoint)
		setpoint[0] = '\0';

	ASSERT(RW_LOCK_HELD(&dp->dp_config_rwlock));

	while (ddobj != 0) {
		dsl_dir_t *dd = dsl_dir_open_obj(dp, ddobj, NULL, FTAG);
		err = zap_lookup(mos, dd->dd_phys->dd_props_zapobj,
		    propname, intsz, numint, buf);
		if (err != ENOENT) {
			if (setpoint)
				dsl_dir_name(dd, setpoint);
			dsl_dir_close(dd, FTAG);
			break;
		}
		ASSERT3U(err, ==, ENOENT);
		ddobj = dd->dd_phys->dd_parent_obj;
		dsl_dir_close(dd, FTAG);
	}
	if (err == ENOENT)
		err = dodefault(propname, intsz, numint, buf);

	return (err);
}

/*
 * Register interest in the named property.  We'll call the callback
 * once to notify it of the current property value, and again each time
 * the property changes, until this callback is unregistered.
 *
 * Return 0 on success, errno if the prop is not an integer value.
 */
int
dsl_prop_register(dsl_dataset_t *ds, const char *propname,
    dsl_prop_changed_cb_t *callback, void *cbarg)
{
	dsl_dir_t *dd;
	uint64_t value;
	dsl_prop_cb_record_t *cbr;
	int err;

	dd = ds->ds_dir;

	rw_enter(&dd->dd_pool->dp_config_rwlock, RW_READER);

	err = dsl_prop_get_impl(dd->dd_pool, dd->dd_object, propname,
	    8, 1, &value, NULL);
	if (err == ENOENT) {
		err = 0;
		value = DSL_PROP_VALUE_UNDEFINED;
	}
	if (err != 0) {
		rw_exit(&dd->dd_pool->dp_config_rwlock);
		return (err);
	}

	cbr = kmem_alloc(sizeof (dsl_prop_cb_record_t), KM_SLEEP);
	cbr->cbr_propname = kmem_alloc(strlen(propname)+1, KM_SLEEP);
	(void) strcpy((char *)cbr->cbr_propname, propname);
	cbr->cbr_func = callback;
	cbr->cbr_arg = cbarg;
	mutex_enter(&dd->dd_lock);
	list_insert_head(&dd->dd_prop_cbs, cbr);
	mutex_exit(&dd->dd_lock);

	cbr->cbr_func(cbr->cbr_arg, value);

	(void) dsl_dir_open_obj(dd->dd_pool, dd->dd_object, NULL, cbr);
	rw_exit(&dd->dd_pool->dp_config_rwlock);
	/* Leave dataset open until this callback is unregistered */
	return (0);
}

int
dsl_prop_get_ds(dsl_dir_t *dd, const char *propname,
    int intsz, int numints, void *buf, char *setpoint)
{
	int err;

	rw_enter(&dd->dd_pool->dp_config_rwlock, RW_READER);
	err = dsl_prop_get_impl(dd->dd_pool, dd->dd_object,
	    propname, intsz, numints, buf, setpoint);
	rw_exit(&dd->dd_pool->dp_config_rwlock);

	return (err);
}

int
dsl_prop_get(const char *ddname, const char *propname,
    int intsz, int numints, void *buf, char *setpoint)
{
	dsl_dir_t *dd;
	const char *tail;
	int err;

	dd = dsl_dir_open(ddname, FTAG, &tail);
	if (dd == NULL)
		return (ENOENT);
	if (tail && tail[0] != '@') {
		dsl_dir_close(dd, FTAG);
		return (ENOENT);
	}

	err = dsl_prop_get_ds(dd, propname, intsz, numints, buf, setpoint);

	dsl_dir_close(dd, FTAG);
	return (err);
}

/*
 * Return 0 on success, ENOENT if ddname is invalid, EOVERFLOW if
 * valuelen not big enough.
 */
int
dsl_prop_get_string(const char *ddname, const char *propname,
    char *value, int valuelen, char *setpoint)
{
	return (dsl_prop_get(ddname, propname, 1, valuelen, value, setpoint));
}

/*
 * Get the current property value.  It may have changed by the time this
 * function returns, so it is NOT safe to follow up with
 * dsl_prop_register() and assume that the value has not changed in
 * between.
 *
 * Return 0 on success, ENOENT if ddname is invalid.
 */
int
dsl_prop_get_integer(const char *ddname, const char *propname,
    uint64_t *valuep, char *setpoint)
{
	return (dsl_prop_get(ddname, propname, 8, 1, valuep, setpoint));
}

int
dsl_prop_get_ds_integer(dsl_dir_t *dd, const char *propname,
    uint64_t *valuep, char *setpoint)
{
	return (dsl_prop_get_ds(dd, propname, 8, 1, valuep, setpoint));
}

/*
 * Unregister this callback.  Return 0 on success, ENOENT if ddname is
 * invalid, ENOMSG if no matching callback registered.
 */
int
dsl_prop_unregister(dsl_dataset_t *ds, const char *propname,
    dsl_prop_changed_cb_t *callback, void *cbarg)
{
	dsl_dir_t *dd;
	dsl_prop_cb_record_t *cbr;

	dd = ds->ds_dir;

	mutex_enter(&dd->dd_lock);
	for (cbr = list_head(&dd->dd_prop_cbs);
	    cbr; cbr = list_next(&dd->dd_prop_cbs, cbr)) {
		if (strcmp(cbr->cbr_propname, propname) == 0 &&
		    cbr->cbr_func == callback &&
		    cbr->cbr_arg == cbarg)
			break;
	}

	if (cbr == NULL) {
		mutex_exit(&dd->dd_lock);
		return (ENOMSG);
	}

	list_remove(&dd->dd_prop_cbs, cbr);
	mutex_exit(&dd->dd_lock);
	kmem_free((void*)cbr->cbr_propname, strlen(cbr->cbr_propname)+1);
	kmem_free(cbr, sizeof (dsl_prop_cb_record_t));

	/* Clean up from dsl_prop_register */
	dsl_dir_close(dd, cbr);
	return (0);
}

static void
dsl_prop_changed_notify(dsl_pool_t *dp, uint64_t ddobj,
    const char *propname, uint64_t value, int first)
{
	dsl_dir_t *dd;
	dsl_prop_cb_record_t *cbr;
	objset_t *mos = dp->dp_meta_objset;
	int err;

	ASSERT(RW_WRITE_HELD(&dp->dp_config_rwlock));
	dd = dsl_dir_open_obj(dp, ddobj, NULL, FTAG);

	if (!first) {
		/*
		 * If the prop is set here, then this change is not
		 * being inherited here or below; stop the recursion.
		 */
		err = zap_lookup(mos, dd->dd_phys->dd_props_zapobj, propname,
		    8, 1, &value);
		if (err == 0) {
			dsl_dir_close(dd, FTAG);
			return;
		}
		ASSERT3U(err, ==, ENOENT);
	}

	mutex_enter(&dd->dd_lock);
	for (cbr = list_head(&dd->dd_prop_cbs);
	    cbr; cbr = list_next(&dd->dd_prop_cbs, cbr)) {
		if (strcmp(cbr->cbr_propname, propname) == 0) {
			cbr->cbr_func(cbr->cbr_arg, value);
		}
	}
	mutex_exit(&dd->dd_lock);

	if (dd->dd_phys->dd_child_dir_zapobj) {
		zap_cursor_t zc;
		zap_attribute_t za;

		for (zap_cursor_init(&zc, mos,
		    dd->dd_phys->dd_child_dir_zapobj);
		    zap_cursor_retrieve(&zc, &za) == 0;
		    zap_cursor_advance(&zc)) {
			/* XXX recursion could blow stack; esp. za! */
			dsl_prop_changed_notify(dp, za.za_first_integer,
			    propname, value, FALSE);
		}
	}
	dsl_dir_close(dd, FTAG);
}

struct prop_set_arg {
	const char *name;
	int intsz;
	int numints;
	const void *buf;
};

static int
dsl_prop_set_sync(dsl_dir_t *dd, void *arg, dmu_tx_t *tx)
{
	struct prop_set_arg *psa = arg;
	objset_t *mos = dd->dd_pool->dp_meta_objset;
	uint64_t zapobj = dd->dd_phys->dd_props_zapobj;
	uint64_t intval;
	int err, isint;

	rw_enter(&dd->dd_pool->dp_config_rwlock, RW_WRITER);

	isint = (dodefault(psa->name, 8, 1, &intval) == 0);

	if (psa->numints == 0) {
		err = zap_remove(mos, zapobj, psa->name, tx);
		if (err == ENOENT) /* that's fine. */
			err = 0;
		if (err == 0 && isint) {
			err = dsl_prop_get_impl(dd->dd_pool,
			    dd->dd_phys->dd_parent_obj, psa->name,
			    8, 1, &intval, NULL);
		}
	} else {
		err = zap_update(mos, zapobj, psa->name,
		    psa->intsz, psa->numints, psa->buf, tx);
		if (isint)
			intval = *(uint64_t *)psa->buf;
	}

	if (err == 0 && isint) {
		dsl_prop_changed_notify(dd->dd_pool,
		    dd->dd_object, psa->name, intval, TRUE);
	}
	rw_exit(&dd->dd_pool->dp_config_rwlock);

	return (err);
}

int
dsl_prop_set(const char *ddname, const char *propname,
    int intsz, int numints, const void *buf)
{
	dsl_dir_t *dd;
	int err;
	struct prop_set_arg psa;

	dd = dsl_dir_open(ddname, FTAG, NULL);
	if (dd == NULL)
		return (ENOENT);

	psa.name = propname;
	psa.intsz = intsz;
	psa.numints = numints;
	psa.buf = buf;
	err = dsl_dir_sync_task(dd, dsl_prop_set_sync, &psa, 0);

	dsl_dir_close(dd, FTAG);

	return (err);
}
