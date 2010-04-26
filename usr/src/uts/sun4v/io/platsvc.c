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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/ddi.h>
#include <sys/suspend.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/drctl.h>

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
#define	SEC2HZ(x)	(drv_usectohz((x) * MICROSEC))

/*
 * Domains Services interaction
 */
static ds_svc_hdl_t	ds_md_handle;
static ds_svc_hdl_t	ds_shutdown_handle;
static ds_svc_hdl_t	ds_panic_handle;
static ds_svc_hdl_t	ds_suspend_handle;

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

static ds_capability_t ps_suspend_cap = {
	"domain-suspend",	/* svc_id */
	ps_vers,		/* vers */
	PS_NVERS		/* nvers */
};

static void ps_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl);
static void ps_unreg_handler(ds_cb_arg_t arg);

static void ps_md_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);
static void ps_shutdown_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);
static void ps_panic_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);
static void ps_suspend_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);

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

static ds_clnt_ops_t ps_suspend_ops = {
	ps_reg_handler,			/* ds_reg_cb */
	ps_unreg_handler,		/* ds_unreg_cb */
	ps_suspend_data_handler,	/* ds_data_cb */
	&ds_suspend_handle		/* cb_arg */
};

static int ps_init(void);
static void ps_fini(void);

/*
 * Power down timeout value of 5 minutes.
 */
#define	PLATSVC_POWERDOWN_DELAY		1200

/*
 * Set to true if OS suspend is supported. If OS suspend is not
 * supported, the suspend service will not be started.
 */
static boolean_t ps_suspend_enabled = B_FALSE;

/*
 * Suspend service request handling
 */
typedef struct ps_suspend_data {
	void		*buf;
	size_t		buflen;
} ps_suspend_data_t;

static kmutex_t ps_suspend_mutex;
static kcondvar_t ps_suspend_cv;

static ps_suspend_data_t *ps_suspend_data = NULL;
static boolean_t ps_suspend_thread_exit = B_FALSE;
static kthread_t *ps_suspend_thread = NULL;

static void ps_suspend_sequence(ps_suspend_data_t *data);
static void ps_suspend_thread_func(void);

/*
 * The DELAY timeout is the time (in seconds) to wait for the
 * suspend service to be re-registered after a suspend/resume
 * operation. The INTVAL time is the time (in seconds) to wait
 * between retry attempts when sending the post-suspend message
 * after a suspend/resume operation.
 */
#define	PLATSVC_SUSPEND_REREG_DELAY	60
#define	PLATSVC_SUSPEND_RETRY_INTVAL	1
static int ps_suspend_rereg_delay = PLATSVC_SUSPEND_REREG_DELAY;
static int ps_suspend_retry_intval = PLATSVC_SUSPEND_RETRY_INTVAL;


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
	extern void mdeg_fini(void);

	/* register with domain services framework */
	rv = ds_cap_init(&ps_md_cap, &ps_md_ops);
	if (rv != 0) {
		cmn_err(CE_WARN, "ds_cap_init md-update failed: %d", rv);
		return (rv);
	}

	rv = mdeg_init();
	if (rv != 0) {
		(void) ds_cap_fini(&ps_md_cap);
		return (rv);
	}

	rv = ds_cap_init(&ps_shutdown_cap, &ps_shutdown_ops);
	if (rv != 0) {
		cmn_err(CE_WARN, "ds_cap_init domain-shutdown failed: %d", rv);
		mdeg_fini();
		(void) ds_cap_fini(&ps_md_cap);
		return (rv);
	}

	rv = ds_cap_init(&ps_panic_cap, &ps_panic_ops);
	if (rv != 0) {
		cmn_err(CE_WARN, "ds_cap_init domain-panic failed: %d", rv);
		(void) ds_cap_fini(&ps_md_cap);
		mdeg_fini();
		(void) ds_cap_fini(&ps_shutdown_cap);
		return (rv);
	}

	ps_suspend_enabled = suspend_supported();

	if (ps_suspend_enabled) {
		mutex_init(&ps_suspend_mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&ps_suspend_cv, NULL, CV_DEFAULT, NULL);
		ps_suspend_thread_exit = B_FALSE;

		rv = ds_cap_init(&ps_suspend_cap, &ps_suspend_ops);
		if (rv != 0) {
			cmn_err(CE_WARN, "ds_cap_init domain-suspend failed: "
			    "%d", rv);
			(void) ds_cap_fini(&ps_md_cap);
			mdeg_fini();
			(void) ds_cap_fini(&ps_shutdown_cap);
			(void) ds_cap_fini(&ps_panic_cap);
			mutex_destroy(&ps_suspend_mutex);
			cv_destroy(&ps_suspend_cv);
			return (rv);
		}

		ps_suspend_thread = thread_create(NULL, 2 * DEFAULTSTKSZ,
		    ps_suspend_thread_func, NULL, 0, &p0, TS_RUN, minclsyspri);
	}

	return (0);
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

	if (ps_suspend_enabled) {
		(void) ds_cap_fini(&ps_suspend_cap);
		if (ps_suspend_thread != NULL) {
			mutex_enter(&ps_suspend_mutex);
			ps_suspend_thread_exit = B_TRUE;
			cv_signal(&ps_suspend_cv);
			mutex_exit(&ps_suspend_mutex);

			thread_join(ps_suspend_thread->t_did);
			ps_suspend_thread = NULL;

			mutex_destroy(&ps_suspend_mutex);
			cv_destroy(&ps_suspend_cv);
		}
	}

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

/*
 * Send a suspend response message. If a timeout is specified, wait
 * intval seconds between attempts to send the message. The timeout
 * and intval arguments are in seconds.
 */
static void
ps_suspend_send_response(ds_svc_hdl_t *ds_handle, uint64_t req_num,
    uint32_t result, uint32_t rec_result, char *reason, int timeout,
    int intval)
{
	platsvc_suspend_resp_t	*resp;
	size_t			reason_length;
	int			tries = 0;
	int			rv = -1;
	time_t			deadline;

	if (reason == NULL) {
		reason_length = 0;
	} else {
		/* Get number of non-NULL bytes */
		reason_length = strnlen(reason, SUSPEND_MAX_REASON_SIZE - 1);
		ASSERT(reason[reason_length] == '\0');
		/* Account for NULL terminator */
		reason_length++;
	}

	resp = (platsvc_suspend_resp_t *)
	    kmem_zalloc(sizeof (platsvc_suspend_resp_t) + reason_length,
	    KM_SLEEP);

	resp->req_num = req_num;
	resp->result = result;
	resp->rec_result = rec_result;
	if (reason_length > 0) {
		bcopy(reason, &resp->reason, reason_length - 1);
		/* Ensure NULL terminator is present */
		resp->reason[reason_length] = '\0';
	}

	if (timeout == 0) {
		tries++;
		rv = ds_cap_send(*ds_handle, resp,
		    sizeof (platsvc_suspend_resp_t) + reason_length);
	} else {
		deadline = gethrestime_sec() + timeout;
		do {
			ds_svc_hdl_t hdl;
			/*
			 * Copy the handle so we can ensure we never pass
			 * an invalid handle to ds_cap_send. We don't want
			 * to trigger warning messages just because the
			 * service was temporarily unregistered.
			 */
			if ((hdl = *ds_handle) == DS_INVALID_HDL) {
				delay(SEC2HZ(intval));
			} else if ((rv = ds_cap_send(hdl, resp,
			    sizeof (platsvc_suspend_resp_t) +
			    reason_length)) != 0) {
				tries++;
				delay(SEC2HZ(intval));
			}
		} while ((rv != 0) && (gethrestime_sec() < deadline));
	}

	if (rv != 0) {
		cmn_err(CE_NOTE, "suspend ds_cap_send resp failed (%d) "
		    "sending message: %d, attempts: %d", rv, resp->result,
		    tries);
	}

	kmem_free(resp, sizeof (platsvc_suspend_resp_t) + reason_length);
}

/*
 * Handle data coming in for the suspend service. The suspend is
 * sequenced by the ps_suspend_thread, but perform some checks here
 * to make sure that the request is a valid request message and that
 * a suspend operation is not already in progress.
 */
/*ARGSUSED*/
static void
ps_suspend_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	platsvc_suspend_req_t	*msg = buf;

	if (arg == NULL)
		return;

	if (ds_suspend_handle == DS_INVALID_HDL) {
		DBG("ps_suspend_data_handler: DS handle no longer valid\n");
		return;
	}

	/* Handle invalid requests */
	if (msg == NULL || buflen != sizeof (platsvc_suspend_req_t) ||
	    msg->type != DOMAIN_SUSPEND_SUSPEND) {
		ps_suspend_send_response(&ds_suspend_handle, msg->req_num,
		    DOMAIN_SUSPEND_INVALID_MSG, DOMAIN_SUSPEND_REC_SUCCESS,
		    NULL, 0, 0);
		return;
	}

	/*
	 * If ps_suspend_thread_exit is set, ds_cap_fini has been
	 * called and we shouldn't be receving data. Handle this unexpected
	 * case by returning without sending a response.
	 */
	if (ps_suspend_thread_exit) {
		DBG("ps_suspend_data_handler: ps_suspend_thread is exiting\n");
		return;
	}

	mutex_enter(&ps_suspend_mutex);

	/* If a suspend operation is in progress, abort now */
	if (ps_suspend_data != NULL) {
		mutex_exit(&ps_suspend_mutex);
		ps_suspend_send_response(&ds_suspend_handle, msg->req_num,
		    DOMAIN_SUSPEND_INPROGRESS, DOMAIN_SUSPEND_REC_SUCCESS,
		    NULL, 0, 0);
		return;
	}

	ps_suspend_data = kmem_alloc(sizeof (ps_suspend_data_t), KM_SLEEP);
	ps_suspend_data->buf = kmem_alloc(buflen, KM_SLEEP);
	ps_suspend_data->buflen = buflen;
	bcopy(buf, ps_suspend_data->buf, buflen);

	cv_signal(&ps_suspend_cv);
	mutex_exit(&ps_suspend_mutex);
}

/*
 * Schedule the suspend operation by calling the pre-suspend, suspend,
 * and post-suspend functions. When sending back response messages, we
 * only use a timeout for the post-suspend response because after
 * a resume, domain services will be re-registered and we may not
 * be able to send the response immediately.
 */
static void
ps_suspend_sequence(ps_suspend_data_t *data)
{
	platsvc_suspend_req_t	*msg;
	uint32_t		rec_result;
	char			*error_reason;
	boolean_t		recovered = B_TRUE;
	uint_t			rv = 0;
	int			dr_block;

	ASSERT(data != NULL);

	msg = data->buf;
	error_reason = (char *)kmem_zalloc(SUSPEND_MAX_REASON_SIZE, KM_SLEEP);

	/*
	 * Abort the suspend if a DR operation is in progress. Otherwise,
	 * continue whilst blocking any new DR operations.
	 */
	if ((dr_block = drctl_tryblock()) == 0) {
		/* Pre-suspend */
		rv = suspend_pre(error_reason, SUSPEND_MAX_REASON_SIZE,
		    &recovered);
	} else {
		/* A DR operation is in progress */
		(void) strncpy(error_reason, DOMAIN_SUSPEND_DR_ERROR_STR,
		    SUSPEND_MAX_REASON_SIZE);
	}

	if (dr_block != 0 || rv != 0) {
		rec_result = (recovered ? DOMAIN_SUSPEND_REC_SUCCESS :
		    DOMAIN_SUSPEND_REC_FAILURE);

		ps_suspend_send_response(&ds_suspend_handle, msg->req_num,
		    DOMAIN_SUSPEND_PRE_FAILURE, rec_result, error_reason, 0, 0);

		if (dr_block == 0)
			drctl_unblock();
		kmem_free(error_reason, SUSPEND_MAX_REASON_SIZE);
		return;
	}

	ps_suspend_send_response(&ds_suspend_handle, msg->req_num,
	    DOMAIN_SUSPEND_PRE_SUCCESS, 0, NULL, 0, 0);

	/* Suspend */
	rv = suspend_start(error_reason, SUSPEND_MAX_REASON_SIZE);
	if (rv != 0) {
		rec_result = (suspend_post(NULL, 0) == 0 ?
		    DOMAIN_SUSPEND_REC_SUCCESS : DOMAIN_SUSPEND_REC_FAILURE);

		ps_suspend_send_response(&ds_suspend_handle, msg->req_num,
		    DOMAIN_SUSPEND_SUSPEND_FAILURE, rec_result, error_reason,
		    0, 0);

		drctl_unblock();
		kmem_free(error_reason, SUSPEND_MAX_REASON_SIZE);
		return;
	}

	/* Post-suspend */
	rv = suspend_post(error_reason, SUSPEND_MAX_REASON_SIZE);
	if (rv != 0) {
		ps_suspend_send_response(&ds_suspend_handle, msg->req_num,
		    DOMAIN_SUSPEND_POST_FAILURE, 0, error_reason,
		    ps_suspend_rereg_delay, ps_suspend_retry_intval);
	} else {
		ps_suspend_send_response(&ds_suspend_handle, msg->req_num,
		    DOMAIN_SUSPEND_POST_SUCCESS, 0, error_reason,
		    ps_suspend_rereg_delay, ps_suspend_retry_intval);
	}

	drctl_unblock();
	kmem_free(error_reason, SUSPEND_MAX_REASON_SIZE);
}

/*
 * Wait for a suspend request or for ps_suspend_thread_exit to be set.
 */
static void
ps_suspend_thread_func(void)
{
	mutex_enter(&ps_suspend_mutex);

	while (ps_suspend_thread_exit == B_FALSE) {

		if (ps_suspend_data == NULL) {
			cv_wait(&ps_suspend_cv, &ps_suspend_mutex);
			continue;
		}

		mutex_exit(&ps_suspend_mutex);
		ps_suspend_sequence(ps_suspend_data);
		mutex_enter(&ps_suspend_mutex);

		kmem_free(ps_suspend_data->buf, ps_suspend_data->buflen);
		kmem_free(ps_suspend_data, sizeof (ps_suspend_data_t));
		ps_suspend_data = NULL;
	}

	mutex_exit(&ps_suspend_mutex);

	thread_exit();
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
	if ((ds_svc_hdl_t *)arg == &ds_suspend_handle)
		ds_suspend_handle = hdl;
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
	if ((ds_svc_hdl_t *)arg == &ds_suspend_handle)
		ds_suspend_handle = DS_INVALID_HDL;
}
