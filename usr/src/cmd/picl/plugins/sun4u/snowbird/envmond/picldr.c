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
#include <stdlib.h>
#include <limits.h>
#include <sys/systeminfo.h>
#include <pthread.h>
#include <syslog.h>
#include <picl.h>
#include <picltree.h>
#include <picldefs.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <assert.h>
#include <libnvpair.h>
#include <libintl.h>
#include <poll.h>
#include <smclib.h>
#include "piclenvmond.h"
#include "picldr.h"

/* external functions */
extern picl_errno_t env_platmod_init();
extern void env_platmod_handle_event(const char *, const void *, size_t);
extern picl_errno_t env_platmod_create_sensors();
extern picl_errno_t env_platmod_setup_hotswap();
extern picl_errno_t env_platmod_sp_monitor();
extern picl_errno_t env_platmod_handle_bus_if_change(uint8_t);
extern picl_errno_t env_platmod_handle_latch_open();
extern void env_platmod_handle_sensor_event(void *);
extern int process_platmod_sp_state_change_notif(void *);
extern int process_platmod_change_cpu_node_state(void *);
extern int process_platmod_change_cpci_state(void *);
extern int process_platmod_async_msg_notif(void *);
extern void process_platmod_sp_heartbeat(uint8_t);
extern picl_errno_t env_platmod_create_hotswap_prop();
extern picl_errno_t env_create_property(int ptype, int pmode,
	size_t psize, char *pname, int (*readfn)(ptree_rarg_t *, void *),
	int (*writefn)(ptree_warg_t *, const void *),
	picl_nodehdl_t nodeh, picl_prophdl_t *propp, void *vbuf);
extern char *strtok_r(char *s1, const char *s2, char **lasts);

/* external variables */
extern int env_debug;

static char sys_name[SYS_NMLN];
static char chassisconf_name[SYS_NMLN];
static boolean_t parse_config_file = B_FALSE;
static int8_t alarm_check_interval = -1;
static picl_nodehdl_t frutreeh = 0;
static pthread_t polling_threadID;
static boolean_t create_polling_thr = B_TRUE;

/* globals */
uint8_t cpu_geo_addr = 0;
picl_nodehdl_t rooth = 0, chassis_nodehdl = 0, cpu_nodehdl = 0;
picl_nodehdl_t platformh = 0, sysmgmth = 0, cpu_lnodehdl = 0;

/*
 * envmond policy structure
 */
typedef struct _policy {
	uint8_t		interval;
	char		*pname;
	char		*argp;
	struct _policy	*nextp;
} env_policy_t;

/*
 * read_policy_configuration - extract info. from the envmond.conf
 */
static int
env_read_policy_configuration(char *conffile, env_policy_t **policypp)
{
	FILE		*fp;
	char		buf[RECORD_MAXSIZE];
	char		*token, *lasts;
	env_policy_t	*policyp;

	if ((fp = fopen(conffile, "r")) == NULL) {
		return (-1);
	}
	while (fgets(buf, sizeof (buf), fp) != NULL) {
		if (buf[0] && (buf[0] == '#' || buf[0] == '\n')) {
			continue;
		}
		token = (char *)strtok_r(buf, RECORD_WHITESPACE, &lasts);
		if (token == NULL) {
			continue;
		}
		policyp = (env_policy_t *)malloc(sizeof (env_policy_t));
		if (policyp == NULL) {
			goto errors;
		}
		policyp->interval = (uint8_t)strtoul(token, NULL, 0);
		token = (char *)strtok_r(lasts, RECORD_WHITESPACE, &lasts);
		if (token == NULL) {
			free(policyp);
		} else {
			policyp->pname = strdup(token);
			if (NULL == policyp->pname) {
				goto errors;
			}
		}
		if (lasts) {
			policyp->argp = strdup(lasts);
			if (policyp->argp == NULL) {
				goto errors;
			}
		} else {
			policyp->argp = NULL;
		}
		policyp->nextp = *policypp;
		*policypp = policyp;
	}
	(void) fclose(fp);
	return (0);

errors:
	(void) fclose(fp);
	while (*policypp) {
		policyp = *policypp;
		*policypp = (*policypp)->nextp;
		free(policyp->pname);
		free(policyp->argp);
		free(policyp);
	}
	return (-1);
}

/*
 * supports environmental policies
 */
static void
env_parse_config_file()
{
	char		conffile[MAXPATHLEN];
	env_policy_t	*policyp, *tmp;
	struct stat	st;

	if (parse_config_file == B_FALSE) {
		return;
	}
	(void) snprintf(conffile, sizeof (conffile), ENV_CONFIG_FILE,
		sys_name);
	bzero(&st, sizeof (st));
	if (stat(conffile, &st) == -1) {
		return;
	}

	policyp = NULL;
	if (env_read_policy_configuration(conffile, &policyp) == -1) {
		return;
	}
	assert(policyp);

	while (policyp) {
		tmp = policyp;
		policyp = policyp->nextp;
		if (strcmp(tmp->pname, SERVICE_PROCESSOR) == 0) {
			alarm_check_interval = tmp->interval;
			if (env_debug & DEBUG)
				syslog(LOG_INFO, "Alarm Heartbeat frequency: "
					"%d seconds", alarm_check_interval);
		}
		free(tmp->pname);
		free(tmp->argp);
		free(tmp);
	}
}

/*
 * detects the presence of RTM for CPU board
 */
static boolean_t
is_rtm_present()
{
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;
	uint8_t		size = 0;

	req_pkt.data[0] = ENV_RTM_BUS_ID;
	req_pkt.data[1] = ENV_RTM_SLAVE_ADDR;
	req_pkt.data[2] = ENV_RTM_READ_SIZE;
	size = ENV_RTM_PKT_LEN;

	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_MASTER_RW_CMD,
		DEFAULT_SEQN, size);

	/* make a call to smc library to send cmd */
	if (smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * this routine does the following:
 * 1. initializes the CPU geo-addr
 * 2. gets the system name
 * 3. create the chassis type property
 * 4. creates the conf_file property
 */
static picl_errno_t
env_set_cpu_info()
{
	int rc = 0;
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;
	uint8_t		size = 0;
	char 		conf_name[PICL_PROPNAMELEN_MAX];

	/* get the geo_addr */
	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_GET_GEOGRAPHICAL_ADDRESS,
		DEFAULT_SEQN, size);

	/* make a call to smc library to send cmd */
	if (smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (PICL_FAILURE);
	}
	cpu_geo_addr = rsp_pkt.data[0];

	/* get the system name */
	if (sysinfo(SI_PLATFORM, sys_name, sizeof (sys_name)) == -1) {
		return (PICL_FAILURE);
	}
	(void) strncpy(chassisconf_name, sys_name,
		sizeof (chassisconf_name));

	/* initialize the node handles */
	if ((rc = ptree_get_root(&rooth)) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = ptree_get_node_by_path(FRUTREE_PATH, &frutreeh)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = ptree_get_node_by_path(PICL_FRUTREE_CHASSIS,
		&chassis_nodehdl)) != PICL_SUCCESS) {
		return (rc);
	}

	/* create the chassis type property */
	if ((rc = env_create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ, PICL_PROPNAMELEN_MAX, PICL_PROP_CHASSIS_TYPE,
		NULLREAD, NULLWRITE, chassis_nodehdl, (picl_prophdl_t *)NULL,
		chassisconf_name)) != PICL_SUCCESS) {
		return (rc);
	}

	/*
	 * create dummy prop to inform frutree plugin abt conf file
	 * (rtm based or w/o rtm)
	 * frutree plugin removes this prop after reading the value
	 */
	if (is_rtm_present() == B_TRUE) {
		(void) snprintf(conf_name, sizeof (conf_name),
			"%s.RTM.conf", chassisconf_name);
	} else {
		(void) snprintf(conf_name, sizeof (conf_name),
			"%s.conf", chassisconf_name);
	}

	if ((rc = env_create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ, PICL_PROPNAMELEN_MAX, PICL_PROP_CONF_FILE, NULLREAD,
		NULLWRITE, chassis_nodehdl, (picl_prophdl_t *)NULL,
		conf_name)) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*
 * initialization
 */
picl_errno_t
env_init()
{
	picl_errno_t rc = PICL_SUCCESS;

	if ((rc = env_set_cpu_info()) != PICL_SUCCESS) {
		return (rc);
	}

	/* parse the configuration file */
	env_parse_config_file();

	/*
	 * do any platform specific intialization if required
	 * IMPORTANT: must post dr_incoming resource event on
	 * chassis after doing all the reqd checks
	 */
	rc = env_platmod_init();
	return (rc);
}

/*
 * sets smc global enables
 */
static int
env_set_smc_global_enables(boolean_t ipmi_enable)
{
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;
	uint8_t		size = 0;

	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_GET_GLOBAL_ENABLES,
		DEFAULT_SEQN, size);

	/* make a call to smc library to send cmd */
	if (smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}

	req_pkt.data[0] = rsp_pkt.data[0];
	req_pkt.data[1] = rsp_pkt.data[1];
	if (ipmi_enable) {
		req_pkt.data[1] |= ENV_IPMI_ENABLE_MASK;
		req_pkt.data[1] &= ENV_SENSOR_ENABLE_MASK;
	} else {
		req_pkt.data[1] &= ENV_IPMI_DISABLE_MASK;
		req_pkt.data[1] |= ENV_SENSOR_DISABLE_MASK;
	}
	size = ENV_SET_GLOBAL_PKT_LEN;
	(void) smc_init_smc_msg(&req_pkt, SMC_SET_GLOBAL_ENABLES,
		DEFAULT_SEQN, size);

	/* make a call to smc library to send cmd */
	if (smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}
	return (0);
}

/*
 * wrapper smc drv open
 */
int
env_open_smc(void)
{
	int	fd;
	if ((fd = open(SMC_NODE, O_RDWR)) < 0) {
		return (-1);
	}
	return (fd);
}

static picl_smc_event_t
env_handle_smc_local_event(void *res_datap)
{
	picl_errno_t rc = PICL_SUCCESS;
	uint8_t event = SMC_LOCAL_EVENT;
	uint8_t event_data = BYTE_0(res_datap);

	if (env_debug & EVENTS)
		syslog(LOG_INFO, "Local Event Received, data %x\n", event_data);

	switch (event_data) {
		case SMC_LOCAL_EVENT_BRIDGE_IN_RESET :	/*FALLTHRU*/
		case SMC_LOCAL_EVENT_BRIDGE_OUT_OF_RESET :
			if ((rc = env_platmod_handle_bus_if_change(
				event_data)) != PICL_SUCCESS) {
				syslog(LOG_ERR, gettext("SUNW_envmond:Error"
					" in handling bus interface change "
					"event, error = %d"), rc);
			}
			break;
		case SMC_LOCAL_EVENT_LATCH_OPENED:
			syslog(LOG_INFO, gettext("LATCH OPEN DETECTED"));
			if ((rc = env_platmod_handle_latch_open()) !=
				PICL_SUCCESS) {
				syslog(LOG_ERR, gettext("SUNW_envmond:Error"
					" in handling latch open event, "
					"error = %d"), rc);
			}
			break;
		default:
			break;
	}
	return (event);
}

static void
env_handle_async_msg_event(void *res_datap)
{
	int rc = SMC_SUCCESS;
	uint8_t event = BYTE_6(res_datap);

	if (env_debug & EVENTS)
		syslog(LOG_INFO, "Asynchronous Event %x Received, data %x\n",
			event, BYTE_7(res_datap));
	switch (event) {
	/*
	 * This message comes to CPU when the service processor is going offline
	 * or online.
	 */
	case EVENT_MSG_AC_STATE_CHANGE:
		if ((rc = process_platmod_sp_state_change_notif(res_datap)) !=
			SMC_SUCCESS) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Error in handling"
				"service processor change of state event, "
				"error = %d"), rc);
		}
		break;
	/*
	 * This message comes to CPU when service processor
	 * requests the CPU to go online or offline (shutdown).
	 */
	case EVENT_MSG_CHANGE_CPU_NODE_STATE:
		if ((rc = process_platmod_change_cpu_node_state(res_datap)) !=
			SMC_SUCCESS) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Error in handling"
				"cpu change of state event, error = %d"), rc);
		}
		break;
	/*
	 * This message comes to CPU(Satellite) when the
	 * other node (Host) is going online or offline.
	 */
	case EVENT_MSG_CHANGE_CPCI_STATE:
		if ((rc = process_platmod_change_cpci_state(res_datap)) !=
			SMC_SUCCESS) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Error in handling"
				"cpci change state event, error = %d"), rc);
		}
		break;
	/*
	 * This message comes from service processor to inform
	 * change in states for other nodes
	 */
	case EVENT_MSG_ASYNC_EVENT_NOTIFICATION:
		if ((rc = process_platmod_async_msg_notif(res_datap)) !=
			SMC_SUCCESS) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Error in handling"
				"async event notification, error = %d"), rc);
		}
		break;
	case MSG_GET_CPU_NODE_STATE:
		/* respond to the service processor heartbeat */
		process_platmod_sp_heartbeat(BYTE_5(res_datap));
		break;
	default:
		event = NO_EVENT;
		break;
	}
}

/*ARGSUSED*/
static picl_smc_event_t
env_process_smc_event(int fd, void **datapp)
{
	sc_rspmsg_t		rsp_msg;
	picl_smc_event_t	event;
	void			*res_datap = NULL;

	if (read(fd, (char *)&rsp_msg, SC_MSG_MAX_SIZE) < 0) {
		return (NO_EVENT);
	}

	if (SC_MSG_CC(&rsp_msg) != 0) {
		return (NO_EVENT);
	}

	res_datap = SC_MSG_DATA(&rsp_msg);
	if (env_debug & EVENTS)
		syslog(LOG_INFO, "Async Msg Cmd,data0,2 = %x,%x,%x\n",
			SC_MSG_CMD(&rsp_msg), BYTE_0(res_datap),
			BYTE_2(res_datap));

	if (SC_MSG_CMD(&rsp_msg) == SMC_SMC_LOCAL_EVENT_NOTIF) {
		event = env_handle_smc_local_event(res_datap);
	} else {	/* it must be an IPMI event */
		switch (BYTE_2(res_datap)) {
		case 0x3:
		case 0x4:
			if (env_debug & DEBUG)
				syslog(LOG_INFO, gettext("SUNW_envmond: "
					" Sensor Event Received\n"));
			/* sensor event */
			switch (BYTE_3(res_datap)) {
			case TEMPERATURE_SENSOR_TYPE:
				event = TEMPERATURE_SENSOR_EVENT;
				env_platmod_handle_sensor_event(res_datap);
				break;
			default:
				syslog(LOG_ERR, gettext("SUNW_envmond:Unknown "
				"sensor Event:%d\n"), BYTE_3(res_datap));
				event = NO_EVENT;
				break;
			}
		default:
			env_handle_async_msg_event(res_datap);
			break;
		}
	}
	return (event);
}

/*
 * polls SMC driver for SMC events
 */
/*ARGSUSED*/
static void *
env_polling_thread(void *args)
{
	int			poll_rc;
	struct pollfd		poll_fds[1];
	void			*datap;
	int			smcfd;
	struct strioctl		strio;
	sc_cmdspec_t		set;

	smcfd = env_open_smc();
	if (smcfd == -1) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Error in polling, "
			"Open of SMC drv failed"));
		create_polling_thr = B_TRUE;
		return (NULL);
	}

	set.args[0]	= SMC_SENSOR_EVENT_ENABLE_SET;
	set.attribute	= SC_ATTR_SHARED;
	strio.ic_cmd	= SCIOC_MSG_SPEC;
	strio.ic_timout	= 0;
	strio.ic_len	= ENV_SENSOR_EV_ENABLE_PKT_LEN;
	strio.ic_dp	= (char *)&set;
	if (ioctl(smcfd, I_STR, &strio) < 0) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Request for "
			"Sensor events failed"));
		(void) close(smcfd);
		create_polling_thr = B_TRUE;
		return (NULL);
	}

	/* request for async messages */
	poll_fds[0].fd		= smcfd;
	poll_fds[0].events	= POLLIN|POLLPRI;
	poll_fds[0].revents	= 0;

	set.attribute	= SC_ATTR_SHARED;
	set.args[0]	= SMC_IPMI_RESPONSE_NOTIF;
	set.args[1]	= SMC_SMC_LOCAL_EVENT_NOTIF;
	strio.ic_cmd	= SCIOC_MSG_SPEC;
	strio.ic_timout	= 0;
	strio.ic_len	= ENV_IPMI_SMC_ENABLE_PKT_LEN;
	strio.ic_dp	= (char *)&set;
	if (ioctl(smcfd, I_STR, &strio) == -1) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Request for"
			"Async messages failed"));
		(void) close(smcfd);
		create_polling_thr = B_TRUE;
		return (NULL);
	}

	/* Now wait for SMC events to come */
	for (;;) {
		poll_rc = poll(poll_fds, 1, -1); /* poll forever */
		if (poll_rc < 0) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Event "
				"processing halted"));
			break;
		}
		if (env_process_smc_event(smcfd, &datap) == NO_EVENT) {
			syslog(LOG_ERR, gettext("SUNW_envmond:"
				"wrong event data posted from SMC"));
		}
	}
	(void) close(smcfd);
	create_polling_thr = B_TRUE;
	return (NULL);
}

/*
 * (to be)Called during chassis configuration. It does the following tasks.
 * Set global enables on SMC
 * Register for local(SMC) events and remote(IPMI) messages (State Change msgs)
 * creates sensor nodes
 * Initialize hotswap
 * Initiallize the interaction with service processor
 */
static picl_errno_t
env_start_services(void)
{
	int rc;
	if (env_debug & DEBUG) {
		syslog(LOG_INFO, "env_start_services begin");
	}

	/* set the SMC global enables */
	if (env_set_smc_global_enables(B_TRUE) == -1) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Setting SMC "
			"Globals failed"));
		return (PICL_FAILURE);
	}

	/* start a worker thread to poll for SMC events */
	if (create_polling_thr) {
		rc = pthread_create(&polling_threadID, NULL,
			&env_polling_thread, NULL);
		if (rc != 0) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Error in "
				"creating polling thread"));
			return (PICL_FAILURE);
		}
		create_polling_thr = B_FALSE;
	}

	/* create the sensor nodes */
	if ((rc = env_platmod_create_sensors()) != PICL_SUCCESS) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Error in creating sensor"
			" nodes, error = %d"), rc);
	}

	/* intialize the hotswap framework */
	if ((rc = env_platmod_setup_hotswap()) != PICL_SUCCESS) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Error in hotswap "
			"initialization, error = %d"), rc);
	}

	if ((rc = env_platmod_create_hotswap_prop()) != PICL_SUCCESS) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Error in creating "
			"hotswap prop, error = %d"), rc);
	}

	/* intialize interaction with service processor */
	if ((rc = env_platmod_sp_monitor()) != PICL_SUCCESS) {
		syslog(LOG_ERR, gettext("SUNW_envmond:Failed to interact with"
			" service processor, error = %d"), rc);
	}
	return (PICL_SUCCESS);
}

static picl_errno_t
env_handle_chassis_configuring_event(char *state)
{
	picl_errno_t rc = PICL_SUCCESS;
	picl_prophdl_t proph;
	picl_nodehdl_t rtm_lnodehdl = 0;
	char *cpu_name = PICL_NODE_CPU;
	char *rtm_name = PICL_NODE_RTM;
	uint64_t status_time;

	if (strcmp(state, PICLEVENTARGVAL_CONFIGURING) != 0) {
		return (PICL_SUCCESS);
	}

	/* initialize cpu loc node handle */
	if (cpu_lnodehdl == 0) {
		if ((rc = ptree_find_node(chassis_nodehdl,
			PICL_PROP_NAME,	PICL_PTYPE_CHARSTRING,
			cpu_name, (strlen(cpu_name) + 1),
			&cpu_lnodehdl)) != PICL_SUCCESS) {
			syslog(LOG_ERR, gettext("SUNW_envmond: failed "
			" to get CPU nodehdl, error = %d"), rc);
			return (rc);
		}
	}

	/* create geo-addr prop under CPU location */
	if (ptree_get_prop_by_name(cpu_lnodehdl, PICL_PROP_GEO_ADDR,
		&proph) == PICL_PROPNOTFOUND) {
		if ((rc = env_create_property(PICL_PTYPE_UNSIGNED_INT,
			PICL_READ, sizeof (cpu_geo_addr),
			PICL_PROP_GEO_ADDR, NULLREAD, NULLWRITE,
			cpu_lnodehdl, &proph,
			(void *)&cpu_geo_addr)) != PICL_SUCCESS) {
			return (rc);
		}
	}
	if (ptree_get_prop_by_name(cpu_lnodehdl,
		PICL_PROP_STATUS_TIME, &proph) != PICL_SUCCESS) {
			status_time = (uint64_t)time(NULL);
			(void) env_create_property(PICL_PTYPE_TIMESTAMP,
				PICL_READ, sizeof (status_time),
				PICL_PROP_STATUS_TIME, NULLREAD, NULLWRITE,
				cpu_lnodehdl, &proph, &status_time);
	}

	/* create geo address property for RTM node (if present) */
	(void) ptree_find_node(chassis_nodehdl,
		PICL_PROP_NAME,	PICL_PTYPE_CHARSTRING, rtm_name,
		(strlen(rtm_name) + 1), &rtm_lnodehdl);

	if (rtm_lnodehdl == 0) {	/* RTM not present */
		return (PICL_SUCCESS);
	}

	if (ptree_get_prop_by_name(rtm_lnodehdl, PICL_PROP_GEO_ADDR,
		&proph) == PICL_PROPNOTFOUND) {
		if ((rc = env_create_property(PICL_PTYPE_UNSIGNED_INT,
			PICL_READ, sizeof (cpu_geo_addr), PICL_PROP_GEO_ADDR,
			NULLREAD, NULLWRITE, rtm_lnodehdl, &proph,
			&cpu_geo_addr)) != PICL_SUCCESS) {
			syslog(LOG_ERR, gettext("SUNW_envmond:Failed "
				"to create CPU geo-addr, error = %d"), rc);
			return (rc);
		}
	}
	if (ptree_get_prop_by_name(rtm_lnodehdl,
		PICL_PROP_STATUS_TIME, &proph) != PICL_SUCCESS) {
		status_time = (uint64_t)time(NULL);
		(void) env_create_property(PICL_PTYPE_TIMESTAMP,
			PICL_READ, sizeof (status_time), PICL_PROP_STATUS_TIME,
			NULLREAD, NULLWRITE, rtm_lnodehdl, &proph,
			&status_time);
	}

	/* start all the environment monitoring services */
	if ((rc = env_start_services()) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*
 * routine to handle all the picl state and condition change events
 */
void
env_handle_event(const char *ename, const void *earg, size_t size)
{
	picl_nodehdl_t		nodeh = 0;
	nvlist_t		*nvlp;
	char			*value;
	boolean_t		state_event;
	char			result[PICL_PROPNAMELEN_MAX];

	if (!ename) {
		return;
	}
	if (strcmp(ename, PICLEVENT_STATE_CHANGE) == 0) {
		state_event = B_TRUE;
	} else if (strcmp(ename, PICLEVENT_CONDITION_CHANGE) == 0) {
		state_event = B_FALSE;
	} else {
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
				" %s", PICL_PROP_NAME);
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
		(void) env_handle_chassis_configuring_event(value);
	}
	/* do any platform specific handling that is reqd */
	env_platmod_handle_event(ename, earg, size);
	nvlist_free(nvlp);
}
