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

/*
 * sun4v Platform Services Module
 */

#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/machsystm.h>
#include <sys/note.h>
#include <sys/uadmin.h>
#include <sys/ds.h>
#include <sys/platsvc.h>

/*
 * Debugging routines
 */
#ifdef DEBUG
uint_t ps_debug = 0x0;
#define	DBG	if (ps_debug) printf
#else /* DEBUG */
#define	DBG	_NOTE(CONSTCOND) if (0) printf
#endif /* DEBUG */

/*
 * Time resolution conversions.
 */
#define	MS2NANO(x)	((x) * MICROSEC)
#define	MS2SEC(x)	((x) / MILLISEC)
#define	MS2MIN(x)	(MS2SEC(x) / 60)

/*
 * Domains Services interaction
 */
static ds_svc_hdl_t	ds_md_handle;
static ds_svc_hdl_t	ds_shutdown_handle;
static ds_svc_hdl_t	ds_panic_handle;

static ds_ver_t		ps_vers[] = {{ 1, 0 }};
#define	PS_NVERS	(sizeof (ps_vers) / sizeof (ps_vers[0]))

static ds_capability_t ps_md_cap = {
	"md-update",		/* svc_id */
	ps_vers,		/* vers */
	PS_NVERS		/* nvers */
};

static ds_capability_t ps_shutdown_cap = {
	"domain-shutdown",	/* svc_id */
	ps_vers,		/* vers */
	PS_NVERS		/* nvers */
};

static ds_capability_t ps_panic_cap = {
	"domain-panic",		/* svc_id */
	ps_vers,		/* vers */
	PS_NVERS		/* nvers */
};

static void ps_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl);
static void ps_unreg_handler(ds_cb_arg_t arg);

static void ps_md_data_handler(ds_cb_arg_t arg, void * buf, size_t buflen);
static void ps_shutdown_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);
static void ps_panic_data_handler(ds_cb_arg_t arg, void * buf, size_t buflen);

static ds_clnt_ops_t ps_md_ops = {
	ps_reg_handler,			/* ds_reg_cb */
	ps_unreg_handler,		/* ds_unreg_cb */
	ps_md_data_handler,		/* ds_data_cb */
	&ds_md_handle			/* cb_arg */
};

static ds_clnt_ops_t ps_shutdown_ops = {
	ps_reg_handler,			/* ds_reg_cb */
	ps_unreg_handler,		/* ds_unreg_cb */
	ps_shutdown_data_handler,	/* ds_data_cb */
	&ds_shutdown_handle		/* cb_arg */
};

static ds_clnt_ops_t ps_panic_ops = {
	ps_reg_handler,			/* ds_reg_cb */
	ps_unreg_handler,		/* ds_unreg_cb */
	ps_panic_data_handler,		/* ds_data_cb */
	&ds_panic_handle		/* cb_arg */
};

static int ps_init(void);
static void ps_fini(void);

/*
 * Power down timeout value of 5 minutes.
 */
#define	PLATSVC_POWERDOWN_DELAY		1200

static struct modlmisc modlmisc = {
	&mod_miscops,
	"sun4v Platform Services"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

int
_init(void)
{
	int	rv;

	if ((rv = ps_init()) != 0)
		return (rv);

	if ((rv = mod_install(&modlinkage)) != 0)
		ps_fini();

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int platsvc_allow_unload;

int
_fini(void)
{
	int	status;

	if (platsvc_allow_unload == 0)
		return (EBUSY);

	if ((status = mod_remove(&modlinkage)) == 0)
		ps_fini();

	return (status);
}

static int
ps_init(void)
{
	int	rv;
	extern int mdeg_init(void);

	/* register with domain services framework */
	rv = ds_cap_init(&ps_md_cap, &ps_md_ops);
	if (rv != 0) {
		cmn_err(CE_WARN, "ds_cap_init md-update failed: %d", rv);
		return (rv);
	}

	rv = ds_cap_init(&ps_shutdown_cap, &ps_shutdown_ops);
	if (rv != 0) {
		cmn_err(CE_WARN, "ds_cap_init domain-shutdown failed: %d", rv);
		(void) ds_cap_fini(&ps_md_cap);
		return (rv);
	}

	rv = ds_cap_init(&ps_panic_cap, &ps_panic_ops);
	if (rv != 0) {
		cmn_err(CE_WARN, "ds_cap_init domain-panic failed: %d", rv);
		(void) ds_cap_fini(&ps_md_cap);
		(void) ds_cap_fini(&ps_shutdown_cap);
		return (rv);
	}

	rv = mdeg_init();

	return (rv);
}

static void
ps_fini(void)
{
	extern void mdeg_fini(void);

	/*
	 * Stop incoming requests from Zeus
	 */
	(void) ds_cap_fini(&ps_md_cap);
	(void) ds_cap_fini(&ps_shutdown_cap);
	(void) ds_cap_fini(&ps_panic_cap);

	mdeg_fini();
}

static void
ps_md_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	extern int mach_descrip_update(void);
	extern void mdeg_notify_clients(void);
	extern void recalc_xc_timeouts(void);

	ds_svc_hdl_t		 ds_handle = ds_md_handle;
	platsvc_md_update_req_t	 *msg = buf;
	platsvc_md_update_resp_t resp_msg;
	uint_t			 rv;

	if (arg == NULL)
		return;

	if (ds_handle == DS_INVALID_HDL) {
		DBG("ps_md_data_handler: DS handle no longer valid\n");
		return;
	}

	if (msg == NULL || buflen != sizeof (platsvc_md_update_req_t)) {
		resp_msg.req_num = 0;
		resp_msg.result = MD_UPDATE_INVALID_MSG;
		if ((rv = ds_cap_send(ds_handle, &resp_msg,
		    sizeof (resp_msg))) != 0) {
			cmn_err(CE_NOTE, "md ds_cap_send failed (%d)", rv);
		}
		return;
	}

	DBG("MD Reload...\n");
	if (mach_descrip_update()) {
		cmn_err(CE_WARN, "MD reload failed\n");
		return;
	}

	recalc_xc_timeouts();

	/*
	 * notify registered clients that MD has
	 * been updated
	 */
	mdeg_notify_clients();

	resp_msg.req_num = msg->req_num;
	resp_msg.result = MD_UPDATE_SUCCESS;
	if ((rv = ds_cap_send(ds_handle, &resp_msg, sizeof (resp_msg))) != 0) {
		cmn_err(CE_NOTE, "md ds_cap_send resp failed (%d)", rv);
	}
}

static void
ps_shutdown_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	ds_svc_hdl_t		ds_handle = ds_shutdown_handle;
	platsvc_shutdown_req_t	*msg = buf;
	platsvc_shutdown_resp_t	resp_msg;
	uint_t			rv;
	hrtime_t		start;

	if (arg == NULL)
		return;

	if (ds_handle == DS_INVALID_HDL) {
		DBG("ps_shutdown_data_handler: DS handle no longer valid\n");
		return;
	}

	if (msg == NULL || buflen != sizeof (platsvc_shutdown_req_t)) {
		resp_msg.req_num = 0;
		resp_msg.result = DOMAIN_SHUTDOWN_INVALID_MSG;
		resp_msg.reason[0] = '\0';
		if ((rv = ds_cap_send(ds_handle, &resp_msg,
		    sizeof (resp_msg))) != 0) {
			cmn_err(CE_NOTE, "shutdown ds_cap_send failed (%d)",
			    rv);
		}
		return;
	}

	resp_msg.req_num = msg->req_num;
	resp_msg.result = DOMAIN_SHUTDOWN_SUCCESS;
	resp_msg.reason[0] = '\0';

	if ((rv = ds_cap_send(ds_handle, &resp_msg, sizeof (resp_msg))) != 0) {
		cmn_err(CE_NOTE, "shutdown ds_cap_send resp failed (%d)", rv);
	}

	/*
	 * Honor the ldoms manager's shutdown delay requirement.
	 */
	cmn_err(CE_NOTE, "shutdown requested by ldom manager, "
	    "system shutdown in %d minutes", MS2MIN(msg->delay));

	start = gethrtime();
	while (gethrtime() - start < MS2NANO(msg->delay))
		;

	(void) kadmin(A_SHUTDOWN, AD_POWEROFF, NULL, kcred);
}


static void
ps_panic_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	ds_svc_hdl_t		ds_handle = ds_panic_handle;
	platsvc_panic_req_t	*msg = buf;
	platsvc_panic_resp_t	resp_msg;
	uint_t			rv;

	if (arg == NULL)
		return;

	if (ds_handle == DS_INVALID_HDL) {
		DBG("ps_panic_data_handler: DS handle no longer valid\n");
		return;
	}

	if (msg == NULL || buflen != sizeof (platsvc_panic_req_t)) {
		resp_msg.req_num = 0;
		resp_msg.result = DOMAIN_PANIC_INVALID_MSG;
		resp_msg.reason[0] = '\0';
		if ((rv = ds_cap_send(ds_handle, &resp_msg,
		    sizeof (resp_msg))) != 0) {
			cmn_err(CE_NOTE, "panic ds_cap_send resp failed (%d)",
			    rv);
		}
		return;
	}

	resp_msg.req_num = msg->req_num;
	resp_msg.result = DOMAIN_PANIC_SUCCESS;
	resp_msg.reason[0] = '\0';
	if ((rv = ds_cap_send(ds_handle, &resp_msg, sizeof (resp_msg))) != 0) {
		cmn_err(CE_NOTE, "panic ds_cap_send resp failed (%d)", rv);
	}

	cmn_err(CE_PANIC, "Panic forced by ldom manager");
	_NOTE(NOTREACHED)
}

static void
ps_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
{
	DBG("ps_reg_handler: arg=0x%p, ver=%d.%d, hdl=0x%lx\n",
	    arg, ver->major, ver->minor, hdl);

	if ((ds_svc_hdl_t *)arg == &ds_md_handle)
		ds_md_handle = hdl;
	if ((ds_svc_hdl_t *)arg == &ds_shutdown_handle)
		ds_shutdown_handle = hdl;
	if ((ds_svc_hdl_t *)arg == &ds_panic_handle)
		ds_panic_handle = hdl;
}

static void
ps_unreg_handler(ds_cb_arg_t arg)
{
	DBG("ps_unreg_handler: arg=0x%p\n", arg);

	if ((ds_svc_hdl_t *)arg == &ds_md_handle)
		ds_md_handle = DS_INVALID_HDL;
	if ((ds_svc_hdl_t *)arg == &ds_shutdown_handle)
		ds_shutdown_handle = DS_INVALID_HDL;
	if ((ds_svc_hdl_t *)arg == &ds_panic_handle)
		ds_panic_handle = DS_INVALID_HDL;
}
