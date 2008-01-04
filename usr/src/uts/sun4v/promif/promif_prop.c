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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/promif_impl.h>
#include <sys/ds.h>
#include <sys/modctl.h>
#include <sys/ksynch.h>
#include <sys/varconfig.h>

#ifndef _KMDB

#define	PROMIF_DS_TIMEOUT_SEC 15

static kmutex_t promif_prop_lock;
static kcondvar_t promif_prop_cv;
static var_config_msg_t promif_ds_resp;
static var_config_resp_t *cfg_rsp = &promif_ds_resp.var_config_resp;
static int (*ds_send)();
static int (*ds_init)();

/*
 * Domains Services interaction
 */
static ds_svc_hdl_t	ds_primary_handle;
static ds_svc_hdl_t	ds_backup_handle;

static ds_ver_t		vc_version[] = { { 1, 0 } };

#define	VC_NVERS	(sizeof (vc_version) / sizeof (vc_version[0]))

static ds_capability_t vc_primary_cap = {
	"var-config",		/* svc_id */
	vc_version,		/* vers */
	VC_NVERS		/* nvers */
};

static ds_capability_t vc_backup_cap = {
	"var-config-backup",	/* svc_id */
	vc_version,		/* vers */
	VC_NVERS		/* nvers */
};

static void vc_reg_handler(ds_cb_arg_t, ds_ver_t *, ds_svc_hdl_t);
static void vc_unreg_handler(ds_cb_arg_t);
static void vc_data_handler(ds_cb_arg_t, void *, size_t);

static ds_clnt_ops_t vc_primary_ops = {
	vc_reg_handler,		/* ds_primary_reg_cb */
	vc_unreg_handler,	/* ds_primary_unreg_cb */
	vc_data_handler,	/* ds_data_cb */
	&ds_primary_handle	/* cb_arg */
};

static ds_clnt_ops_t vc_backup_ops = {
	vc_reg_handler,		/* ds_backup_reg_cb */
	vc_unreg_handler,	/* ds_backup_unreg_cb */
	vc_data_handler,	/* ds_data_cb */
	&ds_backup_handle	/* cb_arg */
};

static void
vc_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
{
	_NOTE(ARGUNUSED(ver))

	if ((ds_svc_hdl_t *)arg == &ds_primary_handle)
		ds_primary_handle = hdl;
	else if ((ds_svc_hdl_t *)arg == &ds_backup_handle)
		ds_backup_handle = hdl;
}

static void
vc_unreg_handler(ds_cb_arg_t arg)
{
	if ((ds_svc_hdl_t *)arg == &ds_primary_handle)
		ds_primary_handle = DS_INVALID_HDL;
	else if ((ds_svc_hdl_t *)arg == &ds_backup_handle)
		ds_backup_handle = DS_INVALID_HDL;
}

static void
vc_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	_NOTE(ARGUNUSED(arg))

	bcopy(buf, &promif_ds_resp, buflen);
	mutex_enter(&promif_prop_lock);
	cv_signal(&promif_prop_cv);
	mutex_exit(&promif_prop_lock);
}

/*
 * Initialize the linkage with DS (Domain Services).  We assume that
 * the DS module has already been loaded by the platmod.
 *
 * The call to the DS init functions will eventually result in the
 * invocation of our registration callback handlers, at which time DS
 * is able to accept requests.
 */
static void
promif_ds_init(void)
{
	static char *me = "promif_ds_init";
	int rv;

	if ((ds_init =
	    (int (*)())modgetsymvalue("ds_cap_init", 0)) == 0) {
		cmn_err(CE_WARN, "%s: can't find ds_cap_init", me);
		return;
	}

	if ((ds_send =
	    (int (*)())modgetsymvalue("ds_cap_send", 0)) == 0) {
		cmn_err(CE_WARN, "%s: can't find ds_cap_send", me);
		return;
	}

	if ((rv = (*ds_init)(&vc_primary_cap, &vc_primary_ops)) != 0) {
		cmn_err(CE_NOTE,
		    "%s: ds_cap_init failed (primary): %d", me, rv);
	}


	if ((rv = (*ds_init)(&vc_backup_cap, &vc_backup_ops)) != 0) {
		cmn_err(CE_NOTE,
		    "%s: ds_cap_init failed (backup): %d", me, rv);
	}
}

/*
 * Prepare for ldom variable requests.
 */
void
promif_prop_init(void)
{
	mutex_init(&promif_prop_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&promif_prop_cv, NULL, CV_DEFAULT, NULL);

	promif_ds_init();
}


/*
 * Replace the current value of a property string given its name and
 * new value.
 */
int
promif_ldom_setprop(char *name, void *value, int valuelen)
{
	var_config_msg_t *req;
	var_config_set_req_t *setp;
	var_config_cmd_t cmd;
	ds_svc_hdl_t ds_handle;
	int rv;
	int namelen = strlen(name);
	int paylen = namelen + 1 + valuelen; /* valuelen includes the null */
	static char *me = "promif_ldom_setprop";

	if (ds_primary_handle != DS_INVALID_HDL)
		ds_handle = ds_primary_handle;
	else if (ds_backup_handle != DS_INVALID_HDL)
		ds_handle = ds_backup_handle;
	else
		return (-1);

	/*
	 * Since we are emulating OBP, we must comply with the promif
	 * infrastructure and execute only on the originating cpu.
	 */
	thread_affinity_set(curthread, CPU->cpu_id);

	req = kmem_zalloc(sizeof (var_config_hdr_t) + paylen, KM_SLEEP);
	req->var_config_cmd = VAR_CONFIG_SET_REQ;
	setp = &req->var_config_set;
	(void) strcpy(setp->name_and_value, name);
	(void) strncpy(&setp->name_and_value[namelen + 1], value, valuelen);

	if ((rv = (*ds_send)(ds_handle, req,
	    sizeof (var_config_hdr_t) + paylen)) != 0) {
		cmn_err(CE_WARN, "%s: ds_cap_send failed: %d", me, rv);
		kmem_free(req, sizeof (var_config_hdr_t) + paylen);
		thread_affinity_clear(curthread);
		return (-1);
	}

	kmem_free(req, sizeof (var_config_hdr_t) + paylen);

	mutex_enter(&promif_prop_lock);
	if (cv_timedwait(&promif_prop_cv,
	    &promif_prop_lock, lbolt + PROMIF_DS_TIMEOUT_SEC * hz) == -1) {
		cmn_err(CE_WARN, "%s: ds response timeout", me);
		rv = -1;
		goto out;
	}

	cmd = promif_ds_resp.vc_hdr.cmd;
	if (cmd != VAR_CONFIG_SET_RESP) {
		cmn_err(CE_WARN, "%s: bad response type: %d", me, cmd);
		rv = -1;
		goto out;
	}
	rv = (cfg_rsp->result == VAR_CONFIG_SUCCESS) ? valuelen : -1;

out:
	mutex_exit(&promif_prop_lock);
	thread_affinity_clear(curthread);
	return (rv);
}

int
promif_setprop(void *p)
{
	cell_t	*ci = (cell_t *)p;
	pnode_t node;
	caddr_t	name;
	caddr_t	value;
	int	len;

	ASSERT(ci[1] == 4);

	node  = p1275_cell2dnode(ci[3]);
	ASSERT(node == prom_optionsnode());
	name  = p1275_cell2ptr(ci[4]);
	value = p1275_cell2ptr(ci[5]);
	len = p1275_cell2int(ci[6]);

	if (promif_stree_getproplen(node, name) != -1)
		len = promif_ldom_setprop(name, value, len);

	if (len >= 0)
		len = promif_stree_setprop(node, name, (void *)value, len);


	ci[7] = p1275_int2cell(len);

	return ((len == -1) ? len : 0);
}

#endif

int
promif_getprop(void *p)
{
	cell_t	*ci = (cell_t *)p;
	pnode_t	node;
	caddr_t	name;
	caddr_t	value;
	int	len;

	ASSERT(ci[1] == 4);

	node  = p1275_cell2dnode(ci[3]);
	name  = p1275_cell2ptr(ci[4]);
	value = p1275_cell2ptr(ci[5]);

	len = promif_stree_getprop(node, name, value);

	ci[7] = p1275_int2cell(len);

	return ((len == -1) ? len : 0);
}

int
promif_getproplen(void *p)
{
	cell_t	*ci = (cell_t *)p;
	pnode_t	node;
	caddr_t	name;
	int	len;

	ASSERT(ci[1] == 2);

	node = p1275_cell2dnode(ci[3]);
	name = p1275_cell2ptr(ci[4]);

	len = promif_stree_getproplen(node, name);

	ci[5] = p1275_int2cell(len);

	return (0);
}

int
promif_nextprop(void *p)
{
	cell_t	*ci = (cell_t *)p;
	pnode_t	node;
	caddr_t	prev;
	caddr_t	next;

	ASSERT(ci[1] == 3);

	node = p1275_cell2dnode(ci[3]);
	prev = p1275_cell2ptr(ci[4]);
	next = p1275_cell2ptr(ci[5]);

	(void) promif_stree_nextprop(node, prev, next);

	return (0);
}
