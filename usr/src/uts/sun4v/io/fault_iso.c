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
 * sun4v Fault Isolation Services Module
 */

#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/machsystm.h>
#include <sys/processor.h>
#include <sys/mem.h>
#include <vm/page.h>
#include <sys/note.h>
#include <sys/ds.h>
#include <sys/fault_iso.h>

/*
 * Debugging routines
 */
#ifdef DEBUG
uint_t fi_debug = 0x0;
#define	FI_DBG	if (fi_debug) cmn_err
#else /* DEBUG */
#define	FI_DBG	_NOTE(CONSTCOND) if (0) cmn_err
#endif /* DEBUG */

/*
 * Domains Services interaction
 */
static ds_svc_hdl_t	cpu_handle;
static ds_svc_hdl_t	mem_handle;

static ds_ver_t		fi_vers[] = { { 1, 0 } };
#define	FI_NVERS	(sizeof (fi_vers) / sizeof (fi_vers[0]))

static ds_capability_t cpu_cap = {
	"fma-cpu-service",	/* svc_id */
	fi_vers,		/* vers */
	FI_NVERS		/* nvers */
};

static ds_capability_t mem_cap = {
	"fma-mem-service",	/* svc_id */
	fi_vers,		/* vers */
	FI_NVERS		/* nvers */
};

static void fi_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl);
static void fi_unreg_handler(ds_cb_arg_t arg);

static void cpu_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);
static void mem_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);

static ds_clnt_ops_t cpu_ops = {
	fi_reg_handler,		/* ds_reg_cb */
	fi_unreg_handler,	/* ds_unreg_cb */
	cpu_data_handler,	/* ds_data_cb */
	&cpu_handle		/* cb_arg */
};

static ds_clnt_ops_t mem_ops = {
	fi_reg_handler,		/* ds_reg_cb */
	fi_unreg_handler,	/* ds_unreg_cb */
	mem_data_handler,	/* ds_data_cb */
	&mem_handle		/* cb_arg */
};

static int fi_init(void);
static void fi_fini(void);

static struct modlmisc modlmisc = {
	&mod_miscops,
	"sun4v Fault Isolation Services"
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

	if ((rv = fi_init()) != 0)
		return (rv);

	if ((rv = mod_install(&modlinkage)) != 0)
		fi_fini();

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int fi_allow_unload;

int
_fini(void)
{
	int	status;

	if (fi_allow_unload == 0)
		return (EBUSY);

	if ((status = mod_remove(&modlinkage)) == 0)
		fi_fini();

	return (status);
}

static int
fi_init(void)
{
	int	rv;

	/* register CPU service with domain services framework */
	rv = ds_cap_init(&cpu_cap, &cpu_ops);
	if (rv != 0) {
		FI_DBG(CE_CONT, "ds_cap_init failed: %d", rv);
		return (rv);
	}

	/* register MEM servicewith domain services framework */
	rv = ds_cap_init(&mem_cap, &mem_ops);
	if (rv != 0) {
		FI_DBG(CE_CONT, "ds_cap_init failed: %d", rv);
		(void) ds_cap_fini(&cpu_cap);
		return (rv);
	}

	return (rv);
}

static void
fi_fini(void)
{
	/*
	 * Stop incoming requests from Zeus
	 */
	(void) ds_cap_fini(&cpu_cap);
	(void) ds_cap_fini(&mem_cap);
}

static void
cpu_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	_NOTE(ARGUNUSED(arg))

	fma_cpu_service_req_t	*msg = buf;
	fma_cpu_resp_t		resp_msg;
	int			rv = 0;
	int			cpu_status;
	int			resp_back = 0;

	/*
	 * If the buffer is the wrong size for CPU calls or is NULL then
	 * do not return any message. The call from the ldom mgr. will time out
	 * and the response will be NULL.
	 */
	if (msg == NULL || buflen != sizeof (fma_cpu_service_req_t)) {
		return;
	}

	FI_DBG(CE_CONT, "req_num = %ld, msg_type = %d, cpu_id = %d\n",
	    msg->req_num, msg->msg_type, msg->cpu_id);

	resp_msg.req_num = msg->req_num;

	switch (msg->msg_type) {
	case FMA_CPU_REQ_STATUS:
		rv = p_online_internal(msg->cpu_id, P_STATUS,
		    &cpu_status);
		if (rv == EINVAL) {
			FI_DBG(CE_CONT, "Failed p_online call failed."
			    "Invalid CPU\n");
			resp_msg.result = FMA_CPU_RESP_FAILURE;
			resp_msg.status = FMA_CPU_STAT_ILLEGAL;
			resp_back = 1;
		}
		break;
	case FMA_CPU_REQ_OFFLINE:
		rv = p_online_internal(msg->cpu_id, P_FAULTED,
		    &cpu_status);
		if (rv == EINVAL) {
			FI_DBG(CE_CONT, "Failed p_online call failed."
			    "Invalid CPU\n");
			resp_msg.result = FMA_CPU_RESP_FAILURE;
			resp_msg.status = FMA_CPU_STAT_ILLEGAL;
			resp_back = 1;
		} else if (rv == EBUSY) {
			FI_DBG(CE_CONT, "Failed p_online call failed."
			    "Tried to offline while busy\n");
			resp_msg.result = FMA_CPU_RESP_FAILURE;
			resp_msg.status = FMA_CPU_STAT_ONLINE;
			resp_back = 1;
		}
		break;
	case FMA_CPU_REQ_ONLINE:
		rv = p_online_internal(msg->cpu_id, P_ONLINE,
		    &cpu_status);
		if (rv == EINVAL) {
			FI_DBG(CE_CONT, "Failed p_online call failed."
			    "Invalid CPU\n");
			resp_msg.result = FMA_CPU_RESP_FAILURE;
			resp_msg.status = FMA_CPU_STAT_ILLEGAL;
			resp_back = 1;
		} else if (rv == ENOTSUP) {
			FI_DBG(CE_CONT, "Failed p_online call failed."
			    "Online not supported for single CPU\n");
			resp_msg.result = FMA_CPU_RESP_FAILURE;
			resp_msg.status = FMA_CPU_STAT_OFFLINE;
			resp_back = 1;
		}
		break;
	default:
		/*
		 * If the msg_type was of unknown type simply return and
		 * have the ldom mgr. time out with a NULL response.
		 */
		return;
	}

	if (rv != 0) {
		if (resp_back) {
			if ((rv = ds_cap_send(cpu_handle, &resp_msg,
			    sizeof (resp_msg))) != 0) {
				FI_DBG(CE_CONT, "ds_cap_send failed (%d)\n",
				    rv);
			}
			return;
		}
		ASSERT((rv == EINVAL) || ((rv == EBUSY) &&
		    (msg->msg_type == FMA_CPU_REQ_OFFLINE)) ||
		    ((rv == ENOTSUP) && (msg->msg_type == FMA_CPU_REQ_ONLINE)));

		cmn_err(CE_WARN, "p_online_internal error not handled "
		    "rv = %d\n", rv);
	}

	resp_msg.req_num = msg->req_num;
	resp_msg.result = FMA_CPU_RESP_OK;

	switch (cpu_status) {
	case P_OFFLINE:
	case P_FAULTED:
	case P_POWEROFF:
	case P_SPARE:
		resp_msg.status = FMA_CPU_STAT_OFFLINE;
		break;
	case P_ONLINE:
	case P_NOINTR:
		resp_msg.status = FMA_CPU_STAT_ONLINE;
		break;
	default:
		resp_msg.status = FMA_CPU_STAT_ILLEGAL;
	}

	if ((rv = ds_cap_send(cpu_handle, &resp_msg,
	    sizeof (resp_msg))) != 0) {
		FI_DBG(CE_CONT, "ds_cap_send failed (%d)\n", rv);
	}
}

static void
mem_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	_NOTE(ARGUNUSED(arg))

	fma_mem_service_req_t	*msg = buf;
	fma_mem_resp_t		resp_msg;
	int			rv = 0;

	/*
	 * If the buffer is the wrong size for Mem calls or is NULL then
	 * do not return any message. The call from the ldom mgr. will time out
	 * and the response will be NULL.
	 */
	if (msg == NULL || buflen != sizeof (fma_mem_service_req_t)) {
		return;
	}

	FI_DBG(CE_CONT, "req_num = %ld, msg_type = %d, memory addr = 0x%lx"
	"memory length = 0x%lx\n", msg->req_num, msg->msg_type,
	    msg->real_addr, msg->length);

	resp_msg.req_num = msg->req_num;
	resp_msg.res_addr = msg->real_addr;
	resp_msg.res_length = msg->length;

	/*
	 * Information about return values for page calls can be referenced
	 * in usr/src/uts/common/vm/page_retire.c
	 */
	switch (msg->msg_type) {
	case FMA_MEM_REQ_STATUS:
		rv = page_retire_check(msg->real_addr, NULL);
		switch (rv) {
		/* Page is retired */
		case 0:
			resp_msg.result = FMA_MEM_RESP_OK;
			resp_msg.status = FMA_MEM_STAT_RETIRED;
			break;
		/* Page is pending. Send back failure and not retired */
		case EAGAIN:
			resp_msg.result = FMA_MEM_RESP_FAILURE;
			resp_msg.status = FMA_MEM_STAT_NOTRETIRED;
			break;
		/* Page is not retired. */
		case EIO:
			resp_msg.result = FMA_MEM_RESP_OK;
			resp_msg.status = FMA_MEM_STAT_NOTRETIRED;
			break;
		/* PA is not valid */
		case EINVAL:
			resp_msg.result = FMA_MEM_RESP_FAILURE;
			resp_msg.status = FMA_MEM_STAT_ILLEGAL;
			break;
		default:
			ASSERT((rv == 0) || (rv == EAGAIN) || (rv == EIO) ||
			    (rv ==  EINVAL));
			cmn_err(CE_WARN, "fault_iso: return value from "
			    "page_retire_check invalid: %d\n", rv);
		}
		break;
	case FMA_MEM_REQ_RETIRE:
		rv = page_retire(msg->real_addr, PR_FMA);
		switch (rv) {
		/* Page retired successfully */
		case 0:
			resp_msg.result = FMA_MEM_RESP_OK;
			resp_msg.status = FMA_MEM_STAT_RETIRED;
			break;
		/* Tried to retire and now Pending retirement */
		case EAGAIN:
			resp_msg.result = FMA_MEM_RESP_FAILURE;
			resp_msg.status = FMA_MEM_STAT_NOTRETIRED;
			break;
		/* Did not try to retire. Page already retired */
		case EIO:
			resp_msg.result = FMA_MEM_RESP_FAILURE;
			resp_msg.status = FMA_MEM_STAT_RETIRED;
			break;
		/* PA is not valid */
		case EINVAL:
			resp_msg.result = FMA_MEM_RESP_FAILURE;
			resp_msg.status = FMA_MEM_STAT_ILLEGAL;
			break;
		default:
			ASSERT((rv == 0) || (rv == EAGAIN) || (rv == EIO) ||
			    (rv ==  EINVAL));
			cmn_err(CE_WARN, "fault_iso: return value from "
			    "page_retire invalid: %d\n", rv);
		}
		break;
	case FMA_MEM_REQ_RESURRECT:
		rv = page_unretire(msg->real_addr);
		switch (rv) {
		/* Page succesfullly unretired */
		case 0:
			resp_msg.result = FMA_MEM_RESP_OK;
			resp_msg.status = FMA_MEM_STAT_NOTRETIRED;
			break;
		/* Page could not be locked. Still retired */
		case EAGAIN:
			resp_msg.result = FMA_MEM_RESP_FAILURE;
			resp_msg.status = FMA_MEM_STAT_RETIRED;
			break;
		/* Page was not retired already */
		case EIO:
			resp_msg.result = FMA_MEM_RESP_FAILURE;
			resp_msg.status = FMA_MEM_STAT_NOTRETIRED;
			break;
		/* PA is not valid */
		case EINVAL:
			resp_msg.result = FMA_MEM_RESP_FAILURE;
			resp_msg.status = FMA_MEM_STAT_ILLEGAL;
			break;
		default:
			ASSERT((rv == 0) || (rv == EAGAIN) || (rv == EIO) ||
			    (rv ==  EINVAL));
			cmn_err(CE_WARN, "fault_iso: return value from "
			    "page_unretire invalid: %d\n", rv);
		}
		break;
	default:
		/*
		 * If the msg_type was of unknown type simply return and
		 * have the ldom mgr. time out with a NULL response.
		 */
		return;
	}

	if ((rv = ds_cap_send(mem_handle, &resp_msg, sizeof (resp_msg))) != 0) {
		FI_DBG(CE_CONT, "ds_cap_send failed (%d)\n", rv);
	}
}

static void
fi_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
{
	FI_DBG(CE_CONT, "fi_reg_handler: arg=0x%p, ver=%d.%d, hdl=0x%lx\n",
	    arg, ver->major, ver->minor, hdl);

	if ((ds_svc_hdl_t *)arg == &cpu_handle)
		cpu_handle = hdl;
	if ((ds_svc_hdl_t *)arg == &mem_handle)
		mem_handle = hdl;
}

static void
fi_unreg_handler(ds_cb_arg_t arg)
{
	FI_DBG(CE_CONT, "fi_unreg_handler: arg=0x%p\n", arg);

	if ((ds_svc_hdl_t *)arg == &cpu_handle)
		cpu_handle = DS_INVALID_HDL;
	if ((ds_svc_hdl_t *)arg == &mem_handle)
		mem_handle = DS_INVALID_HDL;
}
