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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/systeminfo.h>
#include <pthread.h>
#include <syslog.h>
#include <picl.h>
#include <picltree.h>
#include <picldefs.h>
#include <string.h>
#include <libnvpair.h>
#include <libintl.h>
#include <librcm.h>
#include <stropts.h>
#include <smclib.h>
#include <sys/sysevent/dr.h>
#include "piclenvmond.h"
#include "picldr.h"

/* local defines */
#define	RESET_CPU "/usr/sbin/shutdown -y -g 0 -i6"
#define	SHUTDOWN_CPU "/usr/sbin/shutdown -y -g 0 -i0"
#define	RCM_ABSTRACT_RESOURCE	"SUNW_snowbird/board0/CPU1"
#define	CPU_SENSOR_GEO_ADDR	0xe
#define	IS_HEALTHY		0x01
#define	PICL_NODE_SYSMGMT	"sysmgmt"
#define	SYSMGMT_PATH 		PLATFORM_PATH"/pci/pci/isa/sysmgmt"
#define	BUF_SIZE		7

/* external functions */
extern picl_errno_t env_create_property(int, int, size_t, char *,
	int (*readfn)(ptree_rarg_t *, void *),
	int (*writefn)(ptree_warg_t *, const void *),
	picl_nodehdl_t, picl_prophdl_t *, void *);
extern picl_errno_t post_dr_req_event(picl_nodehdl_t, char *, uint8_t);
extern picl_errno_t post_dr_ap_state_change_event(picl_nodehdl_t, char *,
	uint8_t);
extern boolean_t env_admin_lock_enabled(picl_nodehdl_t);
extern picl_errno_t env_create_temp_sensor_node(picl_nodehdl_t, uint8_t);
extern void env_handle_sensor_event(void *);
extern int env_open_smc();

/* external variables */
extern int env_debug;
extern uint8_t cpu_geo_addr;
extern picl_nodehdl_t rooth, platformh, sysmgmth, sensorh;
extern picl_nodehdl_t chassis_nodehdl, cpu_nodehdl, cpu_lnodehdl;

/* locals */
static pthread_mutex_t env_dmc_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t env_dmc_cond = PTHREAD_COND_INITIALIZER;
static boolean_t env_reset_cpu = B_FALSE;
static boolean_t env_shutdown_system = B_FALSE;
static env_state_event_t env_chassis_state = FRU_STATE_UNKNOWN;
static char *rcm_abstr_cp2300_name = RCM_ABSTRACT_RESOURCE;
static boolean_t env_got_dmc_msg = B_FALSE;
static long env_dmc_wait_time = 15;
static pthread_t dmc_thr_tid;

/*
 * issue halt or reboot based on the reset_cpu flag
 */
/*ARGSUSED*/
static void
shutdown_cpu(boolean_t force)
{
	if (env_shutdown_system) {
		if (env_reset_cpu) {
			(void) pclose(popen(RESET_CPU, "w"));
		} else {
			(void) pclose(popen(SHUTDOWN_CPU, "w"));
		}
	}
}

/*
 * inform RCM framework that the remove op is successful
 */
static void
confirm_rcm(char *abstr_name, rcm_handle_t *rhandle)
{
	rcm_notify_remove(rhandle, abstr_name, 0, NULL);
}

/*
 * inform RCM framework that the remove op is failed
 */
static void
fail_rcm(char *abstr_name, rcm_handle_t *rhandle)
{
	(void) rcm_notify_online(rhandle, abstr_name, 0, NULL);
}

/*
 * check RCM framework if it is ok to offline a device
 */
static int
check_rcm(char *rcm_abstr_cp2300_name, uint_t flags)
{
	rcm_info_t *rinfo;
	rcm_handle_t *rhandle;
	int rv;

	if (rcm_alloc_handle(NULL, 0, NULL, &rhandle) != RCM_SUCCESS) {
		return (RCM_FAILURE);
	}

	rv = rcm_request_offline(rhandle, rcm_abstr_cp2300_name,
		flags, &rinfo);

	if (rv == RCM_FAILURE) {
		rcm_free_info(rinfo);
		fail_rcm(rcm_abstr_cp2300_name, rhandle);
		rcm_free_handle(rhandle);
		return (RCM_FAILURE);
	}
	if (rv == RCM_CONFLICT) {
		rcm_free_info(rinfo);
		rcm_free_handle(rhandle);
		return (RCM_CONFLICT);
	}

	confirm_rcm(rcm_abstr_cp2300_name, rhandle);
	rcm_free_info(rinfo);
	rcm_free_handle(rhandle);
	return (RCM_SUCCESS);
}

/*
 * utility routine to send response to an IPMI message
 */
static int
send_response2remote_device(uint8_t ipmb_addr, uint8_t cmd, uint8_t reqseq_lun,
	uint8_t cc)
{
	int rc = SMC_SUCCESS;
	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;
	uint8_t data = cc; /* completion code */

	/* make a call to ctsmc lib */
	(void) smc_init_ipmi_msg(&req_pkt, cmd, DEFAULT_FD, 1, &data,
		(reqseq_lun >> 2), ipmb_addr, SMC_NETFN_APP_RSP,
		(reqseq_lun & 0x03));
	rc = smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT);

	if (rc != SMC_SUCCESS)
		syslog(LOG_ERR, gettext("SUNW_envmond:Error in sending response"
			" to %x, error = %d"), ipmb_addr, rc);
	return (rc);
}

/*
 * do all the checks like adminlock check, rcm check and initiate
 * shutdown
 */
/*ARGSUSED*/
static int
initiate_shutdown(boolean_t force)
{
	int rv;
	uint_t	rcmflags = 0;
	struct timespec rqtp, rmtp;

	if (!env_shutdown_system) {
		return (-1);
	}

	/* check the adminlock prop */
	if ((!force) && (env_admin_lock_enabled(cpu_nodehdl))) {
		syslog(LOG_ERR, gettext("SUNW_envmond: "
			"CPU in use! Cannot shutdown"));
		return (-1);
	}

	if (force) {
		rcmflags = RCM_FORCE;
	}

	/* check with rcm framework */
	rv = check_rcm(rcm_abstr_cp2300_name, rcmflags);

	if ((rv == RCM_FAILURE) || (rv == RCM_CONFLICT)) {
		syslog(LOG_ERR, gettext("SUNW_envmond: RCM error %d, Cannot"
			" shutdown"), rv);
		return (-1);
	}

	/*
	 * force events on chassis node
	 */
	if (force) {
		if (post_dr_req_event(chassis_nodehdl, DR_REQ_OUTGOING_RES,
			NO_WAIT) == PICL_SUCCESS) {
			/* wait a little for clean up of frutree */
			rqtp.tv_sec = 5;
			rqtp.tv_nsec = 0;
			(void) nanosleep(&rqtp, &rmtp);
		}
		/*
		 * If force option is set, do it right here for now
		 * since there is no way to pass this info via events
		 * to frutree framework.
		 */
		shutdown_cpu(force);
		return (0);
	}

	if (post_dr_req_event(chassis_nodehdl, DR_REQ_OUTGOING_RES, NO_WAIT)
		!= PICL_SUCCESS) {
		syslog(LOG_ERR, gettext("SUNW_envmond:cannot shutdown "
			"the host CPU."));
		return (-1);
	}
	return (0);
}

/*
 * get the HEALTHY# line state
 * Return -1 for Error
 *         0 for HEALTHY# down
 *         1 for HEALTHY# up
 */
static int
env_get_healthy_status()
{
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;
	uint8_t		size = 0;

	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_GET_EXECUTION_STATE,
		DEFAULT_SEQN, size);

	/* make a call to smc library to send cmd */
	if (smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}
	return (rsp_pkt.data[0] & IS_HEALTHY);
}

/*
 * initialization
 */
picl_errno_t
env_platmod_init()
{
	picl_errno_t rc =  PICL_SUCCESS;

	if (rooth == 0) {
		if (ptree_get_root(&rooth) != PICL_SUCCESS) {
			return (rc);
		}
	}

	if (chassis_nodehdl == 0) {
		if ((rc = ptree_get_node_by_path(PICL_FRUTREE_CHASSIS,
			&chassis_nodehdl)) != PICL_SUCCESS) {
			return (rc);
		}
	}
	if (post_dr_req_event(chassis_nodehdl, DR_REQ_INCOMING_RES,
		NO_WAIT) != PICL_SUCCESS) {
		syslog(LOG_ERR, gettext("SUNW_envmond: Error in "
			"Posting configure event for Chassis node"));
		rc = PICL_FAILURE;
	}
	return (rc);
}

/*
 * release all the resources
 */
void
env_platmod_fini()
{
	cpu_geo_addr = 0;
	rooth = platformh = sysmgmth = 0;
	chassis_nodehdl = cpu_nodehdl = cpu_lnodehdl = 0;
	env_chassis_state = FRU_STATE_UNKNOWN;
	(void) ptree_delete_node(sensorh);
	(void) ptree_destroy_node(sensorh);
}

/*
 * handle chassis state change
 */
static void
env_handle_chassis_state_event(char *state)
{
	if (strcmp(state, PICLEVENTARGVAL_CONFIGURING) == 0) {
		env_chassis_state = FRU_STATE_CONFIGURING;
		return;
	}

	if (strcmp(state, PICLEVENTARGVAL_UNCONFIGURED) == 0) {
		if (env_chassis_state == FRU_STATE_CONFIGURING ||
			env_chassis_state == FRU_STATE_UNKNOWN) {
			/* picl intialization is failed, dont issue shutdown */
			env_chassis_state = FRU_STATE_UNCONFIGURED;
			return;
		}
		env_chassis_state = FRU_STATE_UNCONFIGURED;
		if (env_reset_cpu) {
			(void) pclose(popen(RESET_CPU, "w"));
		} else {
			(void) pclose(popen(SHUTDOWN_CPU, "w"));
		}
		return;
	}

	if (strcmp(state, PICLEVENTARGVAL_CONFIGURED) == 0) {
		env_chassis_state = FRU_STATE_CONFIGURED;
	}
}

/*
 *  event handler for watchdog state change event
 */
static picl_errno_t
env_handle_watchdog_expiry(picl_nodehdl_t wd_nodehdl)
{
	picl_errno_t rc = PICL_SUCCESS;
	char class[PICL_CLASSNAMELEN_MAX];
	char value[PICL_PROPNAMELEN_MAX];
	char cond[BUF_SIZE];

	if ((rc = ptree_get_propval_by_name(wd_nodehdl,
		PICL_PROP_CLASSNAME, class,
		PICL_CLASSNAMELEN_MAX)) != PICL_SUCCESS) {
		return (rc);
	}

	/* if the event is not of watchdog-timer, return */
	if (strcmp(class, PICL_CLASS_WATCHDOG_TIMER) != 0) {
		return (PICL_INVALIDARG);
	}

	if ((rc = ptree_get_propval_by_name(wd_nodehdl,
		PICL_PROP_WATCHDOG_ACTION, value, sizeof (value))) !=
		PICL_SUCCESS) {
		return (rc);
	}

	/* if action is none, dont do anything */
	if (strcmp(value, PICL_PROPVAL_WD_ACTION_ALARM) != 0) {
		return (PICL_SUCCESS);
	}

	(void) strncpy(cond, PICLEVENTARGVAL_FAILED, sizeof (cond));
	/* update CPU condition to failed */
	if ((rc = ptree_update_propval_by_name(cpu_nodehdl,
		PICL_PROP_CONDITION, cond, sizeof (cond))) != PICL_SUCCESS) {
		return (rc);
	}

	/* post dr ap state change event */
	rc = post_dr_ap_state_change_event(cpu_nodehdl,
		DR_RESERVED_ATTR, NO_COND_TIMEDWAIT);
	return (rc);
}

/*
 * rotine that handles all the picl state and condition change events
 */
void
env_platmod_handle_event(const char *ename, const void *earg, size_t size)
{
	picl_errno_t		rc;
	picl_nodehdl_t		nodeh = 0;
	picl_prophdl_t		proph;
	nvlist_t		*nvlp;
	char			*value;
	boolean_t		state_event;
	env_state_event_t	event;
	char			result[PICL_PROPNAMELEN_MAX];
	uint64_t		status_time, cond_time;
	char 			cond[BUF_SIZE];

	if (!ename) {
		return;
	}
	if (strcmp(ename, PICLEVENT_STATE_CHANGE) == 0) {
		state_event = B_TRUE;
	} else if (strcmp(ename, PICLEVENT_CONDITION_CHANGE) == 0) {
		state_event = B_FALSE;
	} else {
		syslog(LOG_ERR, gettext("SUNW_envmond: unknown event:%s\n"),
			ename);
		return;
	}

	/* unpack the nvlist and get the information */
	if (nvlist_unpack((char *)earg, size, &nvlp, NULL)) {
		return;
	}
	if (nvlist_lookup_uint64(nvlp, PICLEVENTARG_NODEHANDLE, &nodeh) == -1) {
		nvlist_free(nvlp);
		return;
	}
	if (nvlist_lookup_string(nvlp, (state_event) ?
		PICLEVENTARG_STATE :
		PICLEVENTARG_CONDITION, &value) != 0) {
		nvlist_free(nvlp);
		return;
	}

	if (env_debug & PICLEVENTS) {
		if (ptree_get_propval_by_name(nodeh, PICL_PROP_NAME,
			result, sizeof (result)) != PICL_SUCCESS) {
			syslog(LOG_ERR, " SUNW_envmond: error in getting"
				" node name");
			nvlist_free(nvlp);
			return;
		}
		syslog(LOG_INFO, "SUNW_envmond: %s (%s) on %s",
			ename, value, result);
	}

	if (chassis_nodehdl == 0 && state_event) {
		if (ptree_get_propval_by_name(nodeh, PICL_PROP_NAME,
			result, sizeof (result)) != PICL_SUCCESS) {
			nvlist_free(nvlp);
			return;
		}
		if (strcmp(result, PICL_NODE_CHASSIS) == 0) {
			chassis_nodehdl = nodeh;
		}
	}

	if (nodeh == chassis_nodehdl && state_event) {
		env_handle_chassis_state_event(value);
		nvlist_free(nvlp);
		return;
	}

	if (strcmp(PICLEVENTARGVAL_DISCONNECTED, value) == 0) {
		event = LOC_STATE_DISCONNECTED;
	} else if (strcmp(PICLEVENTARGVAL_CONNECTED, value) == 0) {
		event = LOC_STATE_CONNECTED;
	} else if (strcmp(PICLEVENTARGVAL_EMPTY, value) == 0) {
		event = LOC_STATE_EMPTY;
	} else if (strcmp(PICLEVENTARGVAL_CONFIGURED, value) == 0) {
		event = FRU_STATE_CONFIGURED;
	} else if (strcmp(PICLEVENTARGVAL_UNCONFIGURED, value) == 0) {
		event = FRU_STATE_UNCONFIGURED;
	} else if (strcmp(PICL_PROPVAL_WD_STATE_EXPIRED, value) == 0) {
		/* watchdog expiry event */
		if ((rc = env_handle_watchdog_expiry(nodeh)) != PICL_SUCCESS) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Error in handling"
				"watchdog expiry event"));
		}
		nvlist_free(nvlp);
		return;
	} else {
		nvlist_free(nvlp);
		return;
	}

	switch (event) {
	case LOC_STATE_EMPTY:
		break;

	case LOC_STATE_DISCONNECTED:
		if (nodeh == cpu_lnodehdl) {
			(void) initiate_shutdown(B_FALSE);
		}
		break;
	case LOC_STATE_CONNECTED:
		if (nodeh != cpu_lnodehdl) {
			break;
		}
		if (ptree_get_propval_by_name(cpu_lnodehdl,
			PICL_PROP_CHILD, &cpu_nodehdl,
			sizeof (picl_nodehdl_t)) != PICL_SUCCESS) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Cannot "
				"initialize CPU node handle %llx"), nodeh);
			cpu_nodehdl = 0;
		}
		break;
	case FRU_STATE_CONFIGURED:
		if (nodeh != cpu_nodehdl) {
			break;
		}
		if (ptree_get_prop_by_name(cpu_nodehdl,
			PICL_PROP_STATUS_TIME, &proph) != PICL_SUCCESS) {
				status_time = (uint64_t)time(NULL);
				(void) env_create_property(PICL_PTYPE_TIMESTAMP,
					PICL_READ, sizeof (status_time),
					PICL_PROP_STATUS_TIME, NULLREAD,
					NULLWRITE, cpu_nodehdl, &proph,
					&status_time);
		}
		if (ptree_get_prop_by_name(cpu_nodehdl,
			PICL_PROP_CONDITION_TIME, &proph) != PICL_SUCCESS) {
				cond_time = (uint64_t)time(NULL);
				(void) env_create_property(PICL_PTYPE_TIMESTAMP,
					PICL_READ, sizeof (cond_time),
					PICL_PROP_CONDITION_TIME, NULLREAD,
					NULLWRITE, cpu_nodehdl, &proph,
					&cond_time);
			}
		env_shutdown_system = B_FALSE;
		/* if HEALTHY# is UP update the condition to "ok" */
		switch (env_get_healthy_status()) {
		case 0:
		/* update CPU condition to failed */
		(void) strncpy(cond, PICLEVENTARGVAL_FAILED, sizeof (cond));
		break;
		case 1:
		/* update CPU condition to ok */
		(void) strncpy(cond, PICLEVENTARGVAL_OK, sizeof (cond));
		break;
		case -1:	/*FALLTHRU*/
		default:
		/* update the condition to unknown */
		(void) strncpy(cond, PICLEVENTARGVAL_UNKNOWN, sizeof (cond));
			syslog(LOG_ERR, gettext("SUNW_envmond:Error in "
				"reading HEALTHY# status"));
		}

		if ((rc = ptree_update_propval_by_name(cpu_nodehdl,
			PICL_PROP_CONDITION, cond, sizeof (cond))) !=
			PICL_SUCCESS) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Error in "
				"updating CPU condition, error = %d"), rc);
		}
		break;
	case FRU_STATE_UNCONFIGURED:
		if (env_reset_cpu && nodeh == cpu_nodehdl) {
			(void) initiate_shutdown(B_FALSE);
		}
		break;
	default:
	break;
	} /* end of switch */
	nvlist_free(nvlp);
}

/*
 * This thread waits for dmc message to come, as it has to send
 * response ACK back to DMC. Otherwise DMC may think that message
 * is lost and issues poweroff on a node. So there is a chance for
 * CPU to be powered off in the middle of shutdown process. If the
 * DMC message didnt come, then process the local shutdown request.
 */
/*ARGSUSED*/
static void *
env_wait_for_dmc_msg(void *args)
{
	struct timeval  ct;
	struct timespec to;

	(void) pthread_mutex_lock(&env_dmc_mutex);
	if (env_got_dmc_msg == B_TRUE) {
		(void) pthread_mutex_unlock(&env_dmc_mutex);
		return (NULL);
	}

	/*
	 * wait for specified time to check if dmc sends the
	 * shutdown request
	 */
	(void) gettimeofday(&ct, NULL);
	to.tv_sec = ct.tv_sec + env_dmc_wait_time;
	to.tv_nsec = 0;
	(void) pthread_cond_timedwait(&env_dmc_cond,
		&env_dmc_mutex, &to);
	if (env_got_dmc_msg == B_TRUE) {
		(void) pthread_mutex_unlock(&env_dmc_mutex);
		return (NULL);
	}
	(void) pthread_mutex_unlock(&env_dmc_mutex);

	env_shutdown_system = B_TRUE;
	env_reset_cpu = B_FALSE;
	(void) initiate_shutdown(B_FALSE);
	return (NULL);
}

/*
 * Handle the Latch open event(shutdown the node)
 */
picl_errno_t
env_platmod_handle_latch_open()
{
	/*
	 * create a thread to process local event after waiting for DMC CPU
	 * node state offline message
	 */
	if (pthread_create(&dmc_thr_tid, NULL, &env_wait_for_dmc_msg,
		NULL) != 0) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Error in creating "
			"dmc thread"));
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

/*
 * For Sanibel, hotswap initialization is not reqd.
 */
picl_errno_t
env_platmod_setup_hotswap()
{
	return (PICL_SUCCESS);
}

/*
 * For sanibel this supoort is not required
 */
picl_errno_t
env_platmod_sp_monitor()
{
	return (PICL_SUCCESS);
}

/*
 * For sanibel this supoort is not required
 */
picl_errno_t
env_platmod_create_hotswap_prop()
{
	return (PICL_SUCCESS);
}

/*
 * For sanibel this supoort is not required
 */
/*ARGSUSED*/
void
process_platmod_sp_heartbeat(uint8_t data)
{
}

/*
 * For sanibel this supoort is not required
 */
/*ARGSUSED*/
int
process_platmod_async_msg_notif(void *resdatap)
{
	return (0);
}

/*
 * For sanibel this supoort is not required
 */
/*ARGSUSED*/
int
process_platmod_change_cpci_state(void *res_datap)
{
	return (0);
}

/*
 * handle request from service processor for shutdown/online
 */
int
process_platmod_change_cpu_node_state(void *res_datap)
{
	int rc = SMC_SUCCESS;
	uint8_t state = BYTE_7(res_datap);
	boolean_t force_flag = B_FALSE;

	switch (state & 1) {
	case CPU_NODE_STATE_OFFLINE:
		(void) pthread_mutex_lock(&env_dmc_mutex);
		env_got_dmc_msg = B_TRUE;
		(void) pthread_cond_signal(&env_dmc_cond);
		(void) pthread_mutex_unlock(&env_dmc_mutex);
		env_shutdown_system = B_TRUE;
		if ((state >> 2) & 1)
			env_reset_cpu = B_TRUE;
		if (state >> 1 & 1) {	/* force flag set? */
			force_flag = B_TRUE;
		} else {
			force_flag = B_FALSE;
		}

		if (initiate_shutdown(force_flag) == 0) {
			if ((rc = send_response2remote_device(SMC_BMC_ADDR,
				EVENT_MSG_CHANGE_CPU_NODE_STATE,
				BYTE_5(res_datap), 0x0)) != SMC_SUCCESS) {
				return (rc);
			}
		} else {
			if ((rc = send_response2remote_device(SMC_BMC_ADDR,
				EVENT_MSG_CHANGE_CPU_NODE_STATE,
				BYTE_5(res_datap), 0xFF)) != SMC_SUCCESS) {
				return (rc);
			}
			env_shutdown_system = B_FALSE;
			if ((state >> 2) & 1)
				env_reset_cpu = B_FALSE;
		}
		break;
	case CPU_NODE_STATE_ONLINE:
		if ((rc =  send_response2remote_device(SMC_BMC_ADDR,
			EVENT_MSG_CHANGE_CPU_NODE_STATE,
			BYTE_5(res_datap), 0x0)) != SMC_SUCCESS) {
			return (rc);
		}
		break;
	default:
		break;
	}
	return (0);
}

/*
 * Handle change in state of service processor
 */
int
process_platmod_sp_state_change_notif(void *res_datap)
{
	int rc = SMC_SUCCESS;
	uint8_t state = BYTE_7(res_datap);
	uint8_t rq_addr = BYTE_4(res_datap);

	if (rq_addr != SMC_BMC_ADDR) {
		return (PICL_FAILURE);
	}

	switch (state) {
	case CPU_NODE_STATE_ONLINE:
		/* Send ACK to service processor */
		if ((rc = send_response2remote_device(SMC_BMC_ADDR,
			EVENT_MSG_AC_STATE_CHANGE,
			BYTE_5(res_datap), 0x0)) != SMC_SUCCESS) {
			return (rc);
		}
		break;

	case CPU_NODE_STATE_OFFLINE:
		/* Send ACK to service processor */
		if ((rc = send_response2remote_device(SMC_BMC_ADDR,
			EVENT_MSG_AC_STATE_CHANGE,
			BYTE_5(res_datap), 0x0)) != SMC_SUCCESS) {
			return (rc);
		}
		break;

	default:
		if ((rc = send_response2remote_device(SMC_BMC_ADDR,
			EVENT_MSG_AC_STATE_CHANGE,
			BYTE_5(res_datap), 0xFF)) != SMC_SUCCESS) {
			return (rc);
		}
		break;
	}
	return (0);
}

/*
 * For sanibel this supoort is not required
 */
/*ARGSUSED*/
picl_errno_t
env_platmod_handle_bus_if_change(uint8_t data)
{
	return (PICL_SUCCESS);
}

/*
 * create the temperature sensor nodes
 */
picl_errno_t
env_platmod_create_sensors()
{
	picl_errno_t rc = PICL_SUCCESS;

	if (rooth == 0) {
		if ((rc = ptree_get_root(&rooth)) != PICL_SUCCESS) {
			return (rc);
		}
	}

	if (platformh == 0) {
		if ((rc = ptree_get_node_by_path(PLATFORM_PATH,
			&platformh)) != PICL_SUCCESS) {
			return (rc);
		}
	}

	if (sysmgmth == 0) {
		if ((rc = ptree_get_node_by_path(SYSMGMT_PATH,
			&sysmgmth)) != PICL_SUCCESS) {
			return (rc);
		}
	}

	rc = env_create_temp_sensor_node(sysmgmth, CPU_SENSOR_GEO_ADDR);
	return (rc);
}

/*
 * handler for sensor event
 */
void
env_platmod_handle_sensor_event(void *res_datap)
{
	if (BYTE_4(res_datap) != CPU_SENSOR_GEO_ADDR) {
		return;
	}
	env_handle_sensor_event(res_datap);
}
