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

/*
 * This module is used to monitor and control watchdog timer for
 * UltraSPARC-IIi CPU in Snowbird
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <alloca.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libintl.h>
#include <syslog.h>
#include <locale.h>
#include <picl.h>
#include <picltree.h>
#include <libnvpair.h>
#include <poll.h>
#include <errno.h>
#include <syslog.h>
#include <sys/priocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/tspriocntl.h>
#include <sys/fsspriocntl.h>
#include <stropts.h>
#include <synch.h>
#include <signal.h>
#include <thread.h>
#include <picldefs.h>
#include <smclib.h>
#include "piclwatchdog.h"

#pragma	init(wd_picl_register)	/* init section */

/* debug variables */
static  int wd_debug = 0;
static hrtime_t start1, end1;
static int count = 0;
typedef struct { /* used to keep track of time taken for last 5 pats */
	int res_seq;
	int req_seq;
	int64_t time;
} wd_time_t;

#define	NUMBER_OF_READINGS	5
static wd_time_t time1[NUMBER_OF_READINGS];

/* global declarations */
static int	wd_fd = -1;	/* fd used to send watchdog commands */
static int 	polling_fd = -1; /* polling thread that snoops for events */
static int 	wd_enable = 1;
static int 	state_configured = 0;	/* chassis state */
static int	props_created = 0;
static int 	wd_pat_thr_priority = -1;
static pid_t 	pid = -1;	/* PID that owns watchdog services */
static cond_t	patting_cv;
static mutex_t	data_lock;
static mutex_t	patting_lock;
static int32_t	pat_time = 0;
static thread_t	polling_thr_tid;
static thread_t patting_thr_tid;
static wd_data_t wd_data;
static char wd_conf[MAXPATHLEN];

#define	NULLREAD	(int (*)(ptree_rarg_t *, void *))0
#define	NULLWRITE	(int (*)(ptree_warg_t *, const void *))0

/* ptree interface */
static void wd_picl_register(void);
static void wd_picl_init(void);
static void wd_picl_fini(void);
static void wd_state_change_evhandler(const char *,
	const void *, size_t, void *);

/* local functions */
static int wd_write_timeout(ptree_warg_t *, const void *);
static int wd_write_action(ptree_warg_t *, const void *);
static int wd_read_action(ptree_rarg_t *, void *);
static int wd_read_timeout(ptree_rarg_t *, void *);
extern char *strtok_r(char *s1, const char *s2, char **lasts);
extern int wd_get_chassis_type();

static picld_plugin_reg_t wd_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_picl_watchdog",
	wd_picl_init,
	wd_picl_fini,
};

/*
 * This function parses wd.conf file to set the tunables
 * tunables at present: patting thread priority, pat time, wd_enable
 */
static void
wd_parse_config_file(char *wd_conf)
{
	FILE	*fp;
	char	buf[WD_CONF_MAXSIZE];
	char	*token, *last, *value;

	if ((fp = fopen(wd_conf, "r")) == NULL) {
		return;
	}

	while (fgets(buf, sizeof (buf), fp) != NULL) {
		if (buf[0] == '\0' || buf[0] == '#') {
			continue;
		}
		token = last = value = NULL;
		value = (char *)strtok_r((char *)buf, WD_DELIMETER, &last);
		if (last) {
			token = (char *)strtok_r(last, WD_DELIMETER, &last);
		} else {
			continue;
		}

		if (value == NULL || token == NULL) {
			continue;
		}
		if (strcmp(token, WD_PAT_THREAD_PRIORITY) == 0) {
			wd_pat_thr_priority = strtol(value,
				(char **)NULL, 10);
		} else if (strcmp(token, WD_PATTING_TIME) == 0) {
			errno = 0;
			pat_time = strtol(value, (char **)NULL, 10);
			if (errno != 0) {
				pat_time = 0;
			}
		} else if (strcmp(token, WD_ENABLE) == 0) {
			if (strcmp(value, "false") == 0) {
				wd_enable = 0;
			}
		} else {	/* unknown token */
			continue;
		}
	}
	(void) fclose(fp);
}

/*
 * read the SMC watchdog registers
 */
static int
wd_get_reg_dump(uint8_t buffer[])
{
	int rc = 0, i;
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;

	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_GET_WATCHDOG_TIMER,
		DEFAULT_SEQN, 0);

	/* make a call to smc library to send cmd */
	if ((rc = smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		WD_POLL_TIMEOUT)) != SMC_SUCCESS) {
		WD_DEBUG1(WD_PICL_GET_ERR, rc);
		return (PICL_FAILURE);
	}

	/* read 8 bytes */
	bzero(buffer, WD_REGISTER_LEN);
	for (i = 0; i < WD_REGISTER_LEN; i++) {
		buffer[i] = rsp_pkt.data[i];
	}
	return (PICL_SUCCESS);
}

/*
 * get the HEALTHY# line state
 * Return -1 for Error
 *         0 for HEALTHY# down
 *         1 for HEALTHY# up
 */
static int
wd_get_healthy_status()
{
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;

	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_GET_EXECUTION_STATE,
		DEFAULT_SEQN, 0);

	/* make a call to smc library to send cmd */
	if (smc_send_msg(DEFAULT_FD, &req_pkt, &rsp_pkt,
		WD_POLL_TIMEOUT) != SMC_SUCCESS) {
		return (-1);
	}

	return ((rsp_pkt.data[0] & IS_HEALTHY) ? WD_HEALTHY_UP :
		WD_HEALTHY_DOWN);
}

/*ARGSUSED*/
static void
event_completion_handler(char *ename, void *earg, size_t size)
{
	free(ename);
	free(earg);
}

/*
 * posts picl-state-change event if there is change in watchdog-timer state
 */
static picl_errno_t
post_wd_state_event(picl_nodehdl_t nodeh, char *state)
{
	nvlist_t	*nvl;
	size_t		nvl_size;
	char		*pack_buf = NULL;
	picl_errno_t	rc;
	char *ename = PICLEVENT_STATE_CHANGE, *evname = NULL;

	if (state == NULL) {
		return (PICL_FAILURE);
	}

	if ((evname = strdup(ename)) == NULL) {
		return (PICL_NOSPACE);
	}

	if ((rc = nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, NULL)) != 0) {
		free(evname);
		syslog(LOG_ERR, WD_NVLIST_ERR, rc);
		return (PICL_FAILURE);
	}

	if ((rc = nvlist_add_uint64(nvl, PICLEVENTARG_NODEHANDLE,
		nodeh)) != 0) {
		nvlist_free(nvl);
		free(evname);
		syslog(LOG_ERR, WD_NVLIST_ERR, rc);
		return (PICL_FAILURE);
	}

	if ((rc = nvlist_add_string(nvl, PICLEVENTARG_STATE,
		state)) != 0) {
		nvlist_free(nvl);
		free(evname);
		syslog(LOG_ERR, WD_NVLIST_ERR, rc);
		return (PICL_FAILURE);
	}

	if ((rc = nvlist_pack(nvl, &pack_buf, &nvl_size, NV_ENCODE_NATIVE,
		NULL)) != 0) {
		nvlist_free(nvl);
		free(evname);
		syslog(LOG_ERR, WD_NVLIST_ERR, rc);
		return (PICL_FAILURE);
	}

	if ((rc = ptree_post_event(evname, pack_buf, nvl_size,
		event_completion_handler)) != PICL_SUCCESS) {
		free(pack_buf);
		free(evname);
		nvlist_free(nvl);
		return (rc);
	}
	nvlist_free(nvl);
	return (PICL_SUCCESS);
}

/*
 * Updates the State value in picl tree and posts a state-change event
 */
static void
wd_picl_update_state(int level, uint8_t stat)
{
	picl_errno_t rc;
	char 	state[PICL_PROPNAMELEN_MAX];

	switch (stat) {
	case WD_ARMED:
		(void) strncpy(state, PICL_PROPVAL_WD_STATE_ARMED,
			sizeof (state));
		break;
	case WD_DISARMED:
		(void) strncpy(state, PICL_PROPVAL_WD_STATE_DISARMED,
			sizeof (state));
		break;
	case WD_EXPIRED:
		(void) strncpy(state, PICL_PROPVAL_WD_STATE_EXPIRED,
			sizeof (state));
		break;
	default:
		return;
	}

	(void) mutex_lock(&data_lock);
	switch (level) {
	case WD1:
		wd_data.wd1_run_state = stat;
		break;
	case WD2:
		wd_data.wd2_run_state = stat;
		break;
	case WD1_2:
		wd_data.wd1_run_state = stat;
		wd_data.wd2_run_state = stat;
		break;
	default:
		return;
	}
	(void) mutex_unlock(&data_lock);

	if (!state_configured) {
		return;
	}

	switch (level) {
	case WD1:
		if ((rc = post_wd_state_event(wd_data.wd1_nodehdl,
			state)) != PICL_SUCCESS) {
			syslog(LOG_ERR, WD_PICL_POST_EVENT_ERR, rc);
		}
		break;
	case WD2:
		if ((rc = post_wd_state_event(wd_data.wd2_nodehdl,
			state)) != PICL_SUCCESS) {
			syslog(LOG_ERR, WD_PICL_POST_EVENT_ERR, rc);
		}
		break;

	case WD1_2:
		if ((rc = post_wd_state_event(wd_data.wd1_nodehdl,
			state)) != PICL_SUCCESS) {
			syslog(LOG_ERR, WD_PICL_POST_EVENT_ERR, rc);
		}
		if ((rc = post_wd_state_event(wd_data.wd2_nodehdl,
			state)) != PICL_SUCCESS) {
			syslog(LOG_ERR, WD_PICL_POST_EVENT_ERR, rc);
		}
		break;
	}
}

/*
 * Sends a command to SMC to reset the watchdog-timers
 */
static int
wd_pat()
{
	int rc = 0;
	static uint8_t	seq = 1;
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;

	if (seq < WD_MAX_SEQN) {
		req_pkt.hdr.msg_id = seq++;
	} else {
		seq = 1;
		req_pkt.hdr.msg_id = seq;
	}

	if (wd_debug & WD_TIME_DEBUG) {
		start1 = gethrtime();
	}

	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_RESET_WATCHDOG_TIMER,
		DEFAULT_SEQN, 0);

	/* make a call to smc library to send cmd */
	if ((rc = smc_send_msg(wd_fd, &req_pkt, &rsp_pkt,
		WD_POLL_TIMEOUT)) != SMC_SUCCESS) {
		syslog(LOG_CRIT, WD_PICL_PAT_ERR, rc);
		return (PICL_FAILURE);
	}

	if (wd_debug & WD_TIME_DEBUG) {
		end1 = gethrtime();
		time1[count].res_seq = SC_MSG_ID(&rsp_pkt);
		time1[count].req_seq = SC_MSG_ID(&req_pkt);
		time1[count].time = (end1 - start1);

		if (count < (NUMBER_OF_READINGS - 1)) {
			count++;
		} else {
			count = 0;
		}
	}
	return (PICL_SUCCESS);
}

/* used to set the new values for watchdog and start the watchdog */
static int
wd_start(uchar_t action_1, uchar_t action_2,
	uchar_t timeout_2, uchar_t *timeout_1, uint8_t patting_option)
{
	int rc = 0;
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;

	if (timeout_1 == NULL) {
		return (PICL_FAILURE);
	}

	req_pkt.data[0] = WD_USEFLAG_OS;
	req_pkt.data[1] = action_1 | action_2;	/* actions */
	req_pkt.data[2] = timeout_2;		/* wd timeout 2 */
	req_pkt.data[3] = WD_XPR_FLG_CLR_OS;	/* expiration flags */
	req_pkt.data[4] = timeout_1[1];		/* LSB for wd timeout 1 */
	req_pkt.data[5] = timeout_1[0];		/* MSB for wd timeout 1 */

	if (patting_option == ENABLE_AUTO_PAT) {
		req_pkt.data[0] |= WD_ENABLE_AUTO_PAT;
	}

	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_SET_WATCHDOG_TIMER,
		DEFAULT_SEQN, WD_SET_CMD_DATA_LEN);

	/* make a call to smc library to send cmd */
	if ((rc = smc_send_msg(wd_fd, &req_pkt, &rsp_pkt,
		WD_POLL_TIMEOUT)) != SMC_SUCCESS) {
		WD_DEBUG1(WD_PICL_START_ERR, rc);
		return (PICL_FAILURE);
	}

	/* reset the watchdog timer */
	(void) smc_init_smc_msg(&req_pkt, SMC_RESET_WATCHDOG_TIMER,
		DEFAULT_SEQN, 0);
	if ((rc = smc_send_msg(wd_fd, &req_pkt, &rsp_pkt,
		WD_POLL_TIMEOUT)) != SMC_SUCCESS) {
		WD_DEBUG1(WD_PICL_START_ERR, rc);
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

/*
 * Validates timeout and action fields and arms the watchdog-timers
 */
static int
wd_arm(uint8_t patting_option)
{
	int rc;
	uint16_t	wd_time1;
	uint8_t		wd_time2, wd1_action, wd2_action;
	uint8_t		timeout1[2];

	if (wd_data.wd1_timeout >= 0) {
		wd_time1 = wd_data.wd1_timeout/WD_L1_RESOLUTION;
	} else {
		wd_time1 = 0;
	}

	if (wd_data.wd2_timeout >= 0) {
		wd_time2 = wd_data.wd2_timeout/WD_L2_RESOLUTION;
	} else {
		wd_time2 = 0;
	}

	timeout1[0] = wd_time1 >> 8;	/* MSB */
	timeout1[1] = wd_time1 & 0x00ff;	/* LSB */

	/* check the HELATHY# status if action is alarm */
	if (wd_data.wd1_action == WD_ACTION_HEALTHY_DOWN_HOST ||
		wd_data.wd1_action == WD_ACTION_HEALTHY_DOWN_SAT) {
		rc = wd_get_healthy_status();
		if (rc == WD_HEALTHY_DOWN) {
			WD_DEBUG0(WD_HEALTHY_ERR);
			return (PICL_FAILURE);
		} else if (rc == -1) {
			syslog(LOG_ERR, WD_GET_HEALTH_ERR);
			return (PICL_FAILURE);
		}
	}

	if (wd_data.wd1_timeout == -1) {
		wd1_action = WD_ACTION_NONE2;
	} else {
		wd1_action = wd_data.wd1_action;
	}

	if (wd_data.wd2_timeout == -1) {
		wd2_action = WD_ACTION_NONE2;
	} else {
		wd2_action = wd_data.wd2_action;
	}

	rc = wd_start(wd1_action, wd2_action,
		wd_time2, timeout1, patting_option);
	return (rc);
}

/*
 * This is thread is a RealTime class thread. This thread pats the
 * watchdog-timers in regular intervals before the expiry.
 */
/*ARGSUSED*/
static void *
wd_patting_thread(void *args)
{
	time_t sec;
	pcinfo_t pci;
	long nano_sec;
	timestruc_t to;
	long sleep_time;
	struct timeval tp;
	int err, state;

	for (;;) {
		(void) mutex_lock(&patting_lock);
		while (wd_data.wd_pat_state == WD_NORESET) {
			(void) cond_wait(&patting_cv, &patting_lock);
		}
		(void) mutex_unlock(&patting_lock);

		/* reset pat-time to zero */
		pat_time = 0;		/* tunable */
		wd_parse_config_file(wd_conf);

		if (wd_pat_thr_priority < 0 || wd_pat_thr_priority > 59) {
			wd_pat_thr_priority = WD_DEFAULT_THREAD_PRIORITY;
		}

		/* change the priority of thread to realtime class */
		(void) strncpy(pci.pc_clname, "RT", sizeof (pci.pc_clname));
		if (priocntl(P_LWPID, P_MYID, PC_GETCID, (caddr_t)&pci) != -1) {
			pcparms_t pcp;
			rtparms_t *rtp = (rtparms_t *)pcp.pc_clparms;
			rtp->rt_pri = wd_pat_thr_priority;
			rtp->rt_tqsecs = 0;
			rtp->rt_tqnsecs = RT_TQDEF;
			pcp.pc_cid = pci.pc_cid;
			if (priocntl(P_LWPID, P_MYID, PC_SETPARMS,
				(caddr_t)&pcp) != 0) {
				syslog(LOG_ERR, WD_PICL_RT_THRD_FAIL);
			}
		} else {
			syslog(LOG_ERR, WD_PICL_RT_THRD_NO_PERM_ERR);
		}

		switch (wd_data.wd1_timeout) {
		case 0:
			if (wd_arm(DISABLE_AUTO_PAT) == PICL_SUCCESS) {
				wd_picl_update_state(WD1, WD_ARMED);
				if (wd_data.wd2_timeout >= 0) {
					wd_picl_update_state(WD2, WD_ARMED);
				}
			} else {
				syslog(LOG_ERR, WD_PICL_START_ERR,
					PICL_FAILURE);
			}
			/* no need to pat */
			(void) mutex_lock(&patting_lock);
			wd_data.wd_pat_state = WD_NORESET;
			(void) mutex_unlock(&patting_lock);
			continue;
		case -1:
			if (wd_data.wd2_timeout < 0) {
				(void) mutex_lock(&patting_lock);
				wd_data.wd_pat_state = WD_NORESET;
				(void) mutex_unlock(&patting_lock);
				continue;
			}
			if (wd_arm(DISABLE_AUTO_PAT) == PICL_SUCCESS) {
				wd_picl_update_state(WD2, WD_ARMED);
			} else {
				syslog(LOG_ERR, WD_PICL_START_ERR,
					PICL_FAILURE);
			}
			/* no need to pat */
			(void) mutex_lock(&patting_lock);
			wd_data.wd_pat_state = WD_NORESET;
			(void) mutex_unlock(&patting_lock);
			continue;
		default:
			break;
		}

		if (pat_time == 0) {
			if (wd_data.wd1_timeout > WD_PAT_TIME) {
				pat_time = WD_PAT_TIME;
			} else {
				pat_time = wd_data.wd1_timeout - 80;
			}
		}
		if (pat_time <= 0) {
			WD_DEBUG0(WD_PICL_PAT_TIME_ERR);
			(void) mutex_lock(&patting_lock);
				wd_data.wd_pat_state = WD_NORESET;
			(void) mutex_unlock(&patting_lock);
			continue;
		}
		sleep_time = wd_data.wd1_timeout - pat_time;

		if (wd_data.wd1_timeout <= 0 || sleep_time <= 0) {
			WD_DEBUG0(WD_PICL_ARM_PAT_ERR);
			(void) mutex_lock(&patting_lock);
				wd_data.wd_pat_state = WD_NORESET;
			(void) mutex_unlock(&patting_lock);
			continue;
		} else {
			wd_picl_update_state(WD1, WD_ARMED);
		}

		if (wd_data.wd2_timeout >= 0) {
			wd_picl_update_state(WD2, WD_ARMED);
		}

		sec = sleep_time/1000;
		nano_sec = (sleep_time - (sec * 1000)) * 1000000;

		if (wd_arm(ENABLE_AUTO_PAT) != PICL_SUCCESS) {
			wd_picl_update_state(WD1_2, WD_DISARMED);
			(void) mutex_lock(&patting_lock);
				wd_data.wd_pat_state = WD_NORESET;
			(void) mutex_unlock(&patting_lock);
			syslog(LOG_ERR, WD_PICL_START_ERR, PICL_FAILURE);
			continue;
		}

		do	/* pat the watchdog until expiry or user disarm */
		{
			(void) mutex_lock(&patting_lock);
			state = wd_data.wd_pat_state;
			if (state == WD_NORESET) {
				(void) mutex_unlock(&patting_lock);
				break;
			}
			(void) gettimeofday(&tp, NULL);
			to.tv_sec = tp.tv_sec + sec;
			if ((nano_sec + (tp.tv_usec * 1000)) >= 1000000000) {
				to.tv_sec +=  1;
				to.tv_nsec = (nano_sec +
					(tp.tv_usec * 1000)) - 1000000000;
			} else {
				to.tv_nsec = nano_sec + (tp.tv_usec * 1000);
			}

			err = cond_timedwait(&patting_cv, &patting_lock, &to);
			(void) mutex_unlock(&patting_lock);

			if (err == ETIME) { /* woke up from sleep */
				(void) wd_pat();
			}
		} while (state == WD_RESET);
	}
	/*NOTREACHED*/
	return (NULL);
}

/*
 * returns 0 if owner is not alive
 * returns 1 if owner is alive
 * returns -1 if there is no active owner
 */
static int
is_owner_alive()
{
	char strpid[50];
	struct stat buf;

	if (pid == -1) {
		return (-1);
	}

	/* check if the file exists or not */
	(void) snprintf(strpid, sizeof (pid), "/proc/%ld/status", pid);
	errno = 0;
	if (stat(strpid, &buf) == 0) {
		return (1);
	}
	if (errno == ENOENT) {
		return (0);
	} else {
		syslog(LOG_ERR, WD_GET_OWN_FAILED, errno);
	}
	return (-1);
}

/*
 * Sends a cmd to SMC to stop watchdog timers
 */
static int
wd_stop()
{
	int rc = 0;
	sc_reqmsg_t	req_pkt;
	sc_rspmsg_t	rsp_pkt;
	uint8_t	buffer[8];

	if (wd_get_reg_dump(buffer) != 0) {
		return (PICL_FAILURE);
	}
	/* clear the expiration flags */
	buffer[3] = 0xff;	/* expiration flags */

	(void) memcpy(SC_MSG_DATA(&req_pkt), buffer,
		WD_SET_CMD_DATA_LEN);

	/* initialize the request packet */
	(void) smc_init_smc_msg(&req_pkt, SMC_SET_WATCHDOG_TIMER,
		DEFAULT_SEQN, WD_SET_CMD_DATA_LEN);

	/* make a call to smc library to send cmd */
	if ((rc = smc_send_msg(wd_fd, &req_pkt, &rsp_pkt,
		WD_POLL_TIMEOUT)) != SMC_SUCCESS) {
		syslog(LOG_ERR, WD_PICL_STOP_ERR, rc);
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

/*
 * Function used by volatile callback function for wd-op property
 * under controller. This is used to arm, disarm the watchdog-timers
 * in response to user actions
 */
static int
wd_worker_function(uint8_t flag, pid_t proc_id)
{
	int rc = PICL_SUCCESS;
	int wd1_state, wd2_state;

	(void) mutex_lock(&data_lock);
	wd1_state = wd_data.wd1_run_state;
	wd2_state = wd_data.wd2_run_state;
	(void) mutex_unlock(&data_lock);

	switch (flag) {

	case USER_ARMED_WD:

	/* watchdog can only be armed if all the timers are disarmed */
	if (wd1_state != WD_DISARMED) {
		WD_DEBUG0(WD_PICL_WD1_RUNNING_ERR);
		rc = PICL_FAILURE;
		break;
	}
	if (wd2_state != WD_DISARMED) {
		WD_DEBUG0(WD_PICL_WD2_RUNNING_ERR);
		rc = PICL_FAILURE;
		break;
	}

	/* check the HELATHY# status if action is alarm */
	if (wd_data.wd1_timeout >= 0) {
		if (wd_data.wd1_action == WD_ACTION_HEALTHY_DOWN_HOST ||
			wd_data.wd1_action == WD_ACTION_HEALTHY_DOWN_SAT) {
			rc = wd_get_healthy_status();
			if (rc == WD_HEALTHY_DOWN) {
				WD_DEBUG0(WD_HEALTHY_ERR);
				return (PICL_FAILURE);
			} else if (rc == -1) {
				syslog(LOG_ERR, WD_GET_HEALTH_ERR);
				return (PICL_FAILURE);
			} else {
				rc = PICL_SUCCESS;
			}
		}
	}

	/* signal the patting thread */
	(void) mutex_lock(&patting_lock);
	wd_data.wd_pat_state = WD_RESET;
	(void) cond_signal(&patting_cv);
	(void) mutex_unlock(&patting_lock);
	break;

	case USER_DISARMED_WD:

	/*
	 * if the caller doesnot own watchdog services,
	 * check to see if the owner is still alive using procfs
	 */
	if (proc_id !=  pid) {
		switch (is_owner_alive()) {
		case -1:
			if ((wd1_state != WD_DISARMED) ||
			(wd2_state != WD_DISARMED)) {
				break;
			}
			/* watchdog is already disarmed */
			WD_DEBUG0(WD_PICL_NO_WD_ERR);
			return (PICL_FAILURE);
		case 1:
			/* owner is still alive, deny the operation */
			WD_DEBUG0(WD_PICL_PERM_DENIED);
			return (PICL_PERMDENIED);
		default:
			break;
		}
	}

	/* watchdog is running */
	if ((rc = wd_stop()) == PICL_SUCCESS) {
		wd_picl_update_state(WD1_2, WD_DISARMED);
		(void) mutex_lock(&patting_lock);
		wd_data.wd_pat_state = WD_NORESET;
		(void) cond_signal(&patting_cv);
		(void) mutex_unlock(&patting_lock);
	}
	break;

	case USER_ARMED_PAT_WD: /* for debug purposes only */

	/*
	 * first arm-pat operation is used for arming the watchdog
	 * subsequent arm-pat operations will be used for patting
	 * the watchdog
	 */
	/* WD is stopped */
	if (wd1_state == WD_DISARMED && wd2_state == WD_DISARMED) {
		if ((rc = wd_arm(DISABLE_AUTO_PAT)) == PICL_SUCCESS) {
			if (wd_data.wd1_timeout >= 0) {
				wd_picl_update_state(WD1, WD_ARMED);
			}

			if (wd_data.wd2_timeout >= 0) {
				wd_picl_update_state(WD2, WD_ARMED);
			}
		} else {
			return (rc);
		}
	} else {	/* WD is running */
		if (wd1_state != WD_ARMED) {
			WD_DEBUG0(WD_PICL_NO_WD_ERR);
			return (PICL_INVALIDARG);
		}

		/* check if OS is patting the watchdog or not */
		(void) mutex_lock(&patting_lock);
		if (wd_data.wd_pat_state == WD_RESET) {
			WD_DEBUG0(WD_PICL_TRY_PAT_ERR);
			(void) mutex_unlock(&patting_lock);
			return (PICL_INVALIDARG);
		}

		/* check if the process owns the WD services */
		if (proc_id != pid) {
			WD_DEBUG0(WD_PICL_PERM_DENIED);
			return (PICL_PERMDENIED);
		}
		rc = wd_pat();
	}
	break;

	default:
	rc = PICL_INVALIDARG;
	break;

	} /* switch */

	return (rc);
}

/*ARGSUSED*/
static int
wd_write_op(ptree_warg_t *parg, const void *buf)
{
	int rc = PICL_INVALIDARG;
	uint8_t	flag;

	/* only after state is configured */
	if (!state_configured) {
		if (parg->cred.dc_pid != getpid()) {
			WD_DEBUG0(WD_PICL_STATE_INVALID);
			return (PICL_PERMDENIED);
		}
	}

	/* only super user can write this property */
	if (parg->cred.dc_euid != SUPER_USER) {
		WD_DEBUG0(WD_NO_ROOT_PERM);
		return (PICL_PERMDENIED);
	}

	if (strcmp((char *)buf, PICL_PROPVAL_WD_OP_ARM) == 0) {
		flag = USER_ARMED_WD;
		rc = PICL_SUCCESS;
	}

	if (strcmp((char *)buf, PICL_PROPVAL_WD_OP_DISARM) == 0) {
		flag = USER_DISARMED_WD;
		rc = PICL_SUCCESS;
	}

	/* for debug purpose only */
	if (strcmp((char *)buf, WD_ARM_PAT) == 0) {
		flag = USER_ARMED_PAT_WD;
		rc = PICL_SUCCESS;
	}

	if (rc == PICL_SUCCESS) {
		rc = wd_worker_function(flag, parg->cred.dc_pid);
	} else {
		rc = PICL_INVALIDARG;
	}

	if (rc == PICL_SUCCESS) {

		switch (flag) {
		case USER_ARMED_PAT_WD:
		case USER_ARMED_WD:

			/* get the process id of client */
			if (parg->cred.dc_pid != getpid()) {
				pid = parg->cred.dc_pid;
			} else {
				pid = -1;
			}
			break;
		case USER_DISARMED_WD:
			/* reset the pid */
			pid = -1;
		default:
			break;
		}
	}
	return (rc);
}

/* volatile call back function to read the watchdog L1 status */
/*ARGSUSED*/
static int
wd1_read_status(ptree_rarg_t *parg, void *buf)
{
	int rc = PICL_SUCCESS;

	(void) mutex_lock(&data_lock);

	switch (wd_data.wd1_run_state) {

	case WD_EXPIRED:
		(void) strncpy((char *)buf, PICL_PROPVAL_WD_STATE_EXPIRED,
			PICL_PROPNAMELEN_MAX);
		break;

	case WD_DISARMED:
		(void) strncpy((char *)buf, PICL_PROPVAL_WD_STATE_DISARMED,
			PICL_PROPNAMELEN_MAX);
		break;

	case WD_ARMED:
		(void) strncpy((char *)buf, PICL_PROPVAL_WD_STATE_ARMED,
			PICL_PROPNAMELEN_MAX);
		break;

	default:
		rc = PICL_FAILURE;
	}
	(void) mutex_unlock(&data_lock);
	return (rc);
}

/*
 * this function is used to read the state of L2 timer
 */
static int
wd_get_wd2_status(int *present_status)
{
	int rc;
	uchar_t	buffer[WD_REGISTER_LEN];

	bzero(buffer, WD_REGISTER_LEN);
	(void) mutex_lock(&data_lock);
	*present_status = wd_data.wd2_run_state;
	if (wd_data.wd2_run_state != WD_ARMED) {
		/* we already have the latest state */
		(void) mutex_unlock(&data_lock);
		return (PICL_SUCCESS);
	}
	(void) mutex_unlock(&data_lock);

	/* read watchdog registers */
	if ((rc = wd_get_reg_dump(buffer)) != 0) {
		return (rc);
	}

	if (buffer[0] & WD_WD_RUNNING) {
		*present_status = WD_ARMED;
		return (PICL_SUCCESS);
	}

	if (buffer[3] != 0) {
		(void) mutex_lock(&data_lock);
		*present_status = wd_data.wd2_run_state = WD_EXPIRED;
		(void) mutex_unlock(&data_lock);
	}
	return (PICL_SUCCESS);
}

/* volatile call back function to read the watchdog L2 status */
/*ARGSUSED*/
static int
wd2_read_status(ptree_rarg_t *parg, void *buf)
{
	int present_status, rc;

	if ((rc = wd_get_wd2_status(&present_status)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	/* copy the present state in user buffer */
	switch (present_status) {
	case WD_ARMED:
		(void) strncpy((char *)buf, PICL_PROPVAL_WD_STATE_ARMED,
			PICL_PROPNAMELEN_MAX);
		break;
	case WD_EXPIRED:
		(void) strncpy((char *)buf, PICL_PROPVAL_WD_STATE_EXPIRED,
			PICL_PROPNAMELEN_MAX);
		break;
	case WD_DISARMED:
		(void) strncpy((char *)buf, PICL_PROPVAL_WD_STATE_DISARMED,
			PICL_PROPNAMELEN_MAX);
		break;
	}
	return (PICL_SUCCESS);
}

/* this thread listens for watchdog expiry events */
/*ARGSUSED*/
static void *
wd_polling(void *args)
{
	uint8_t	stat;
	int poll_retval;
	struct pollfd fds;
	sc_rspmsg_t rsp_pkt;
	int i;

	fds.fd = polling_fd;
	fds.events = POLLIN | POLLPRI;
	fds.revents = 0;

	for (;;) {
		poll_retval = poll(&fds, 1, -1);
		if (props_created == 0)
			continue;
		switch (poll_retval) {
		case 0:
		break;

		case -1:
			syslog(LOG_ERR, WD_PICL_POLL_ERR);
		break;

		default:
		/* something happened */
		if ((read(polling_fd, &rsp_pkt,
			sizeof (sc_rspmsg_t))) < 0) {
			syslog(LOG_ERR, WD_PICL_SMC_READ_ERR);
			break;
		}

		if (rsp_pkt.hdr.cmd == SMC_EXPIRED_WATCHDOG_NOTIF) {

			(void) mutex_lock(&data_lock);
			stat = wd_data.wd1_run_state;
			(void) mutex_unlock(&data_lock);

			if (stat != WD_ARMED) {
				continue;
			}

			wd_picl_update_state(WD1, WD_EXPIRED);

			(void) mutex_lock(&patting_lock);
			wd_data.wd_pat_state = WD_NORESET;
			(void) cond_signal(&patting_cv);

			(void) mutex_unlock(&patting_lock);
			syslog(LOG_WARNING, WD_WD1_EXPIRED);
			if (wd_debug & WD_TIME_DEBUG) {
				syslog(LOG_ERR, " latest count : %d", count);
				for (i = 0; i < NUMBER_OF_READINGS; i++) {
					syslog(LOG_ERR, "i = %d, req_seq = %d,"
					"res_seq = %d, time = %lld nsec",
						i, time1[i].req_seq,
						time1[i].res_seq,
						time1[i].time);
				}
			}
			if (wd_data.reboot_action) {
				wd_data.reboot_action = 0;
				(void) system(SHUTDOWN_CMD);
			}
		}
		break;

		} /* switch */
	}
	/*NOTREACHED*/
	return (NULL);
}

/*
 * This function reads the hardware state and gets the status of
 * watchdog-timers
 */
static int
wd_get_status(wd_state_t *state)
{
	picl_errno_t	rc;
	uchar_t		buffer[WD_REGISTER_LEN];

	bzero(buffer, WD_REGISTER_LEN);
	/* read watchdog registers */
	if ((rc = wd_get_reg_dump(buffer)) != 0) {
		return (rc);
	}

	/* get action */
	state->action1 = buffer[1] & 0xF0; /* most significant 4 bits */
	if (state->action1 == 0x0) {
		state->action1 = WD_ACTION_NONE1;
	}
	state->action2 = buffer[1] & 0x0F; /* least significant 4 bits */
	if (state->action2 == 0x0) {
		state->action2 = WD_ACTION_NONE2;
	}

	state->timeout2 = buffer[2];
	state->timeout1[0] = buffer[5];	/* MSB */
	state->timeout1[1] = buffer[4];	/* LSB */

	state->present_t1[0] = buffer[7]; /* MSB */
	state->present_t1[1] = buffer[6]; /* LSB */

	if (buffer[0] & WD_WD_RUNNING) {
		state->present_state = WD_ARMED;
		return (PICL_SUCCESS);
	}

	if (buffer[3] != 0) {
		state->present_state = WD_EXPIRED;
		return (PICL_SUCCESS);
	} else {
		state->present_state = WD_DISARMED;
		return (PICL_SUCCESS);
	}
}

/* read the smc hardware and intialize the internal state */
static void
wd_set_init_state()
{
	wd_state_t state;
	uint16_t tmp1, tmp2, wd_time1;

	if (wd_get_status(&state) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_PICL_GET_STAT_ERR);
		/* defualt state is expired ??? */
		state.present_state = WD_EXPIRED;
	}

	switch (state.present_state) {
	case WD_EXPIRED:
	case WD_DISARMED:
		if (state.present_state == WD_EXPIRED)
			wd_picl_update_state(WD1_2, WD_EXPIRED);
		else
			wd_picl_update_state(WD1_2, WD_DISARMED);
		wd_data.wd_pat_state = WD_NORESET;
		wd_data.wd1_action = state.action1;
		wd_data.wd2_action = state.action2;
		tmp1 = state.timeout1[0] << 8;
		tmp2 = state.timeout1[1];
		wd_time1 = tmp1 | tmp2;
		wd_data.wd1_timeout = wd_time1 * WD_L1_RESOLUTION;
		wd_data.wd2_timeout = state.timeout2 * WD_L2_RESOLUTION;
		break;
	case WD_ARMED:
		/*
		 * get the present values and restart the
		 * watchdog from os level and continue to pat
		 */
		wd_picl_update_state(WD1_2, WD_ARMED);
		wd_data.wd_pat_state = WD_RESET;
		wd_data.wd1_action = (state.action1 << 4);
		wd_data.wd2_action = state.action2;

		tmp1 = state.timeout1[0] << 8;
		tmp2 = state.timeout1[1];
		wd_time1 = tmp1 | tmp2;
		wd_data.wd1_timeout = wd_time1 * WD_L1_RESOLUTION;
		wd_data.wd2_timeout = state.timeout2 * WD_L2_RESOLUTION;
		(void) wd_stop();
	}
}

/*
 * wrapper for ptree interface to create property
 */
static int
wd_create_property(
	int		ptype,		/* PICL property type */
	int		pmode,		/* PICL access mode */
	size_t		psize,		/* size of PICL property */
	char		*pname,		/* property name */
	int		(*readfn)(ptree_rarg_t *, void *),
	int		(*writefn)(ptree_warg_t *, const void *),
	picl_nodehdl_t	nodeh,		/* node for property */
	picl_prophdl_t	*propp,		/* pointer to prop_handle */
	void		*vbuf)		/* initial value */
{
	picl_errno_t		rc;
	ptree_propinfo_t	propinfo;

	rc = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		ptype, pmode, psize, pname, readfn, writefn);
	if (rc != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_PICL_PROP_INIT_ERR, rc);
		return (rc);
	}

	rc = ptree_create_and_add_prop(nodeh, &propinfo, vbuf, propp);
	if (rc != PICL_SUCCESS) {
		return (rc);
	}

	return (PICL_SUCCESS);
}

/* Create and add Watchdog properties */
static void
wd_create_add_props()
{
	int rc;
	picl_nodehdl_t	rooth, sysmgmt_h, platformh;
	int32_t	timeout1 = 0;
	int32_t	timeout2 = 0;
	char		buf[PICL_WD_PROPVAL_MAX];

	/* get picl root node handle */
	if ((rc = ptree_get_root(&rooth)) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 1, rc);
		return;
	}

	/* get picl platform node handle */
	if ((rc = ptree_get_node_by_path(PLATFORM_PATH,
		&platformh)) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 2, rc);
		return;
	}

	/* get the picl sysmgmt node handle */
	if ((rc = ptree_find_node(platformh, PICL_PROP_NAME,
		PICL_PTYPE_CHARSTRING,
		PICL_NODE_SYSMGMT, strlen(PICL_NODE_SYSMGMT),
		&sysmgmt_h)) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 3, rc);
		return;
	}

	/* start creating the watchdog nodes and properties */
	if ((rc = ptree_create_and_add_node(sysmgmt_h, PICL_NODE_WD_CONTROLLER,
		PICL_CLASS_WATCHDOG_CONTROLLER,
		&(wd_data.wd_ctrl_nodehdl))) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 4, rc);
		return;
	}

	/* Add wd-op property to watchdog controller node */
	(void) strncpy(buf, "", sizeof (buf));
	if ((rc = wd_create_property(PICL_PTYPE_CHARSTRING,
		PICL_WRITE + PICL_VOLATILE,
		PICL_PROPNAMELEN_MAX, PICL_PROP_WATCHDOG_OPERATION,
		NULL, wd_write_op,
		wd_data.wd_ctrl_nodehdl,
		&(wd_data.wd_ops_hdl),
		(void *)buf)) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 5, rc);
		return;
	}

	/* create L1 node and add to controller */
	if ((rc = ptree_create_and_add_node(wd_data.wd_ctrl_nodehdl,
		PICL_NODE_WD_L1, PICL_CLASS_WATCHDOG_TIMER,
		&(wd_data.wd1_nodehdl))) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 6, rc);
		return;
	}

	/* create L2 node and add to controller */
	if ((rc = ptree_create_and_add_node(wd_data.wd_ctrl_nodehdl,
		PICL_NODE_WD_L2, PICL_CLASS_WATCHDOG_TIMER,
		&(wd_data.wd2_nodehdl))) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 7, rc);
		return;
	}

	/* create watchdog properties */
	/* create state property here */
	(void) strncpy(buf, PICL_PROPVAL_WD_STATE_DISARMED,
		sizeof (buf));
	if ((rc = wd_create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ + PICL_VOLATILE, PICL_PROPNAMELEN_MAX,
		PICL_PROP_STATE, wd1_read_status, NULLWRITE,
		wd_data.wd1_nodehdl,
		&(wd_data.wd1_state_hdl), (void *)buf)) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 8, rc);
		return;
	}

	if ((rc = wd_create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ + PICL_VOLATILE, PICL_PROPNAMELEN_MAX,
		PICL_PROP_STATE, wd2_read_status, NULLWRITE,
		wd_data.wd2_nodehdl,
		&(wd_data.wd2_state_hdl), (void *)buf)) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 9, rc);
		return;
	}

	/* create timeout property here */
	if ((rc = wd_create_property(PICL_PTYPE_UNSIGNED_INT,
		PICL_READ + PICL_WRITE + PICL_VOLATILE,
		sizeof (timeout1), PICL_PROP_WATCHDOG_TIMEOUT,
		wd_read_timeout, wd_write_timeout, wd_data.wd1_nodehdl,
		&(wd_data.wd1_timeout_hdl), (void *)&(timeout1))) !=
		PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 10, rc);
		return;
	}

	if ((rc = wd_create_property(PICL_PTYPE_UNSIGNED_INT,
		PICL_READ + PICL_WRITE + PICL_VOLATILE,
		sizeof (wd_data.wd2_timeout), PICL_PROP_WATCHDOG_TIMEOUT,
		wd_read_timeout, wd_write_timeout, wd_data.wd2_nodehdl,
		&(wd_data.wd2_timeout_hdl), (void *)&(timeout2))) !=
		PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 11, rc);
		return;
	}

	/* create wd_action property here */
	(void) strncpy(buf, PICL_PROPVAL_WD_ACTION_NONE,
		sizeof (buf));
	if ((rc = wd_create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ + PICL_WRITE + PICL_VOLATILE,
		PICL_PROPNAMELEN_MAX, PICL_PROP_WATCHDOG_ACTION,
		wd_read_action, wd_write_action,
		wd_data.wd1_nodehdl, &(wd_data.wd1_action_hdl),
		(void *)buf)) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 12, rc);
		return;
	}

	if ((rc = wd_create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ + PICL_WRITE + PICL_VOLATILE,
		PICL_PROPNAMELEN_MAX, PICL_PROP_WATCHDOG_ACTION,
		wd_read_action, wd_write_action,
		wd_data.wd2_nodehdl, &(wd_data.wd2_action_hdl),
		(void *)buf)) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_NODE_INIT_ERR, 13, rc);
		return;
	}
}

static int
wd_ioctl(int fd, int cmd, int len, char *buf)
{
	int rtnval;
	struct strioctl sioc;
	sioc.ic_cmd = cmd;
	sioc.ic_timout = 60;
	sioc.ic_len = len;
	sioc.ic_dp = buf;
	rtnval = ioctl(fd, I_STR, &sioc);
	return (rtnval);
}

static int
wd_open(int attr)
{
	int cc;
	sc_cmdspec_t wd_cmdspec;

	if ((wd_fd = open(SMC_NODE, attr)) < 0) {
		return (-1);
	}

	/* get exclusive access for set and reset commands of watchdog */
	wd_cmdspec.args[0] = SMC_SET_WATCHDOG_TIMER;
	wd_cmdspec.args[1] = SMC_RESET_WATCHDOG_TIMER;
	wd_cmdspec.attribute = SC_ATTR_EXCLUSIVE;

	cc = wd_ioctl(wd_fd, SCIOC_MSG_SPEC, 3,
		(char *)&wd_cmdspec);
	if (cc < 0) {
		syslog(LOG_ERR, WD_PICL_EXCLUSIVE_ACCESS_ERR);
		return (-1);
	}
	return (wd_fd);
}

static int
wd_open_pollfd(int attr)
{
	int cc;
	sc_cmdspec_t wd_cmdspec;

	if ((polling_fd = open(SMC_NODE, attr)) < 0) {
		return (-1);
	}

	/* request for watchdog expiry notification	*/
	wd_cmdspec.args[0] = SMC_EXPIRED_WATCHDOG_NOTIF;
	wd_cmdspec.attribute = SC_ATTR_EXCLUSIVE;

	cc = wd_ioctl(polling_fd, SCIOC_MSG_SPEC, 2,
		(char *)&wd_cmdspec);
	if (cc < 0) {
		syslog(LOG_ERR, WD_PICL_SET_ATTR_FAILED);
		return (-1);
	}
	return (polling_fd);
}

/* read the ENVIRONMENT variables and initialize tunables */
static void
wd_get_env()
{
	char *val;
	int intval = 0;

	/* read frutree debug flag value */
	if (val = getenv(WATCHDOG_DEBUG)) {
		errno = 0;
		intval = strtol(val, (char **)NULL, 0);
		if (errno == 0) {
			wd_debug = intval;
		}
	}
}

/*
 * PTREE Entry Points
 */

/* picl-state-change event handler */
/*ARGSUSED*/
static void
wd_state_change_evhandler(const char *ename, const void *earg,
			size_t size, void *cookie)
{
	char 		*value;
	picl_errno_t	rc;
	nvlist_t	*nvlp;
	picl_nodehdl_t  fruhdl;
	static 		int spawn_threads = 1;
	char 		name[PICL_PROPNAMELEN_MAX];

	if (strcmp(ename, PICLEVENT_STATE_CHANGE)) {
		return;
	}

	/* neglect all events if wd props are already created */
	if (props_created && state_configured) {
		return;
	}

	if (nvlist_unpack((char *)earg, size, &nvlp, NULL)) {
		return;
	}
	if ((nvlist_lookup_uint64(nvlp, PICLEVENTARG_NODEHANDLE,
		&fruhdl)) == -1) {
		nvlist_free(nvlp);
		return;
	}
	if (nvlist_lookup_string(nvlp, PICLEVENTARG_STATE, &value)) {
		nvlist_free(nvlp);
		return;
	}

	rc = ptree_get_propval_by_name(fruhdl, PICL_PROP_NAME,
		(void *)name, sizeof (name));
	if (rc != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	/* care for only events on chassis node */
	if (strcmp(name, PICL_NODE_CHASSIS) != 0) {
		nvlist_free(nvlp);
		return;
	}

	if (strcmp(value, PICLEVENTARGVAL_CONFIGURED) == 0) {
		state_configured = 1;
		nvlist_free(nvlp);
		return;
	}

	if (strcmp(value, PICLEVENTARGVAL_CONFIGURING) != 0) {
		nvlist_free(nvlp);
		return;
	}

	if (wd_fd < 0) {
		if ((wd_fd = wd_open(O_RDWR))  < 0) {
			syslog(LOG_CRIT, WD_PICL_SMC_OPEN_ERR);
			nvlist_free(nvlp);
			return;
		}
	}

	if (polling_fd < 0) {
		if ((polling_fd = wd_open_pollfd(O_RDWR))  < 0) {
			syslog(LOG_CRIT, WD_PICL_SMC_OPEN_ERR);
			nvlist_free(nvlp);
			return;
		}
	}

	switch (wd_get_chassis_type()) {
		case WD_HOST: /* is host */
			wd_data.is_host = B_TRUE;
			break;
		case WD_STANDALONE: /* is satellite */
			wd_data.is_host = B_FALSE;
			break;
		default:
			nvlist_free(nvlp);
			return;
	}

	(void) wd_create_add_props(); /* create and add properties */
	props_created = 1;

	/* read the hardware and initialize values */
	(void) wd_set_init_state();

	/* initialize wd-conf value */
	(void) snprintf(wd_conf, sizeof (wd_conf), "%s/%s",
		PICL_CONFIG_DIR, WD_CONF_FILE);

	if (spawn_threads == 0) {
		/* threads are already created */
		nvlist_free(nvlp);
		return;
	}

	/* start monitoring for the events */
	if (thr_create(NULL,  NULL,  wd_polling,
		NULL,  THR_BOUND, &polling_thr_tid) != 0) {
		syslog(LOG_ERR, WD_PICL_THREAD_CREATE_FAILED,
			"polling");
		nvlist_free(nvlp);
		return;
	}

	/* thread used to pat watchdog */
	if (thr_create(NULL,  NULL,  wd_patting_thread,
		NULL,  THR_BOUND, &patting_thr_tid) != 0) {
		syslog(LOG_ERR, WD_PICL_THREAD_CREATE_FAILED,
			"patting");
		nvlist_free(nvlp);
		return;
	}
	spawn_threads = 0;
	nvlist_free(nvlp);
}

static void
wd_picl_register(void)
{
	int rc = 0;
	if ((rc = picld_plugin_register(&wd_reg_info)) != PICL_SUCCESS) {
		syslog(LOG_ERR, WD_PICL_REG_ERR, rc);
	}
}

/* entry point (initialization) */
static void
wd_picl_init(void)
{
	/* initialize the wd_conf path and name */
	(void) snprintf(wd_conf, sizeof (wd_conf), "%s/%s",
		PICL_CONFIG_DIR, WD_CONF_FILE);

	/* parse configuration file and set tunables */
	wd_parse_config_file(wd_conf);

	/* if watchdog-enable is set to false dont intialize wd subsystem */
	if (wd_enable == 0) {
		return;
	}

	/* read watchdog related environment variables */
	wd_get_env();

	/* event handler for state change notifications from frutree */
	(void) ptree_register_handler(PICLEVENT_STATE_CHANGE,
		wd_state_change_evhandler, NULL);
}

static void
wd_picl_fini(void)
{
	(void) ptree_unregister_handler(PICLEVENT_STATE_CHANGE,
		wd_state_change_evhandler, NULL);

	state_configured = 0;	/* chassis state */
	props_created = 0;
	(void) ptree_delete_node(wd_data.wd_ctrl_nodehdl);
	(void) ptree_destroy_node(wd_data.wd_ctrl_nodehdl);
}

/*
 * volatile function to read the timeout
 */
static int
wd_read_timeout(ptree_rarg_t *parg, void *buf)
{
	/* update the buffer provided by user */
	(void) mutex_lock(&data_lock);
	if (parg->proph == wd_data.wd1_timeout_hdl) {
		*(int32_t *)buf = wd_data.wd1_timeout;
	} else if (parg->proph == wd_data.wd2_timeout_hdl) {
		*(int32_t *)buf = wd_data.wd2_timeout;
	}
	(void) mutex_unlock(&data_lock);
	return (PICL_SUCCESS);
}

/*
 * volatile function to read the action
 */
static int
wd_read_action(ptree_rarg_t *parg, void *buf)
{
	(void) mutex_lock(&data_lock);
	if (parg->proph == wd_data.wd1_action_hdl) {
		switch (wd_data.wd1_action) {
		case WD_ACTION_HEALTHY_DOWN_HOST:
		case WD_ACTION_HEALTHY_DOWN_SAT:
		(void) strcpy((char *)buf,
			PICL_PROPVAL_WD_ACTION_ALARM);
		break;
		case WD_ACTION_NONE1:
		case WD_ACTION_NONE2:
		if (wd_data.reboot_action == 1) {
			(void) strcpy((char *)buf,
				PICL_PROPVAL_WD_ACTION_REBOOT);
		} else {
			(void) strcpy((char *)buf,
				PICL_PROPVAL_WD_ACTION_NONE);
		}
		break;
		}
	} else if (parg->proph == wd_data.wd2_action_hdl) {
		switch (wd_data.wd2_action) {
		case WD_ACTION_HARD_RESET:
		(void) strcpy((char *)buf,
			PICL_PROPVAL_WD_ACTION_RESET);
		break;
		case WD_ACTION_NONE2:
		(void) strcpy((char *)buf, PICL_PROPVAL_WD_ACTION_NONE);
		break;
		}
	}
	(void) mutex_unlock(&data_lock);
	return (PICL_SUCCESS);
}

/*
 * volatile function to write the action
 * this function validates the user value before programming the
 * action property. Properties can be modified only when watchdog
 * is in disarmed state.
 */
static int
wd_write_action(ptree_warg_t *parg, const void *buf)
{
	int flag = 0x0;
	picl_errno_t rc = PICL_SUCCESS;
	char wd_action[PICL_WD_PROPVAL_MAX];

	/* only super user can write this property */
	if (parg->cred.dc_euid != SUPER_USER) {
		return (PICL_PERMDENIED);
	}

	if (parg->proph == wd_data.wd1_action_hdl) {
		flag = WD1;
	} else if (parg->proph == wd_data.wd2_action_hdl) {
		flag = WD2;
	}

	/* dont allow any write operations when watchdog is armed */
	(void) mutex_lock(&data_lock);
	if (wd_data.wd1_run_state != WD_DISARMED ||
		wd_data.wd2_run_state != WD_DISARMED) {
		(void) mutex_unlock(&data_lock);
		return (PICL_PERMDENIED);
	}

	/* validate the values and store in internal cache */
	(void) strcpy(wd_action, (char *)buf);
	switch (flag) {
	case WD1:
	if (strcmp(wd_action, PICL_PROPVAL_WD_ACTION_ALARM) == 0) {
		if (wd_data.is_host)
			wd_data.wd1_action = WD_ACTION_HEALTHY_DOWN_HOST;
		else
			wd_data.wd1_action = WD_ACTION_HEALTHY_DOWN_SAT;
		wd_data.reboot_action = 0;
	} else if (strcmp(wd_action, PICL_PROPVAL_WD_ACTION_NONE) == 0) {
		wd_data.wd1_action = WD_ACTION_NONE1;
		wd_data.reboot_action = 0;
	} else if (strcmp(wd_action, PICL_PROPVAL_WD_ACTION_REBOOT) == 0) {
		wd_data.wd1_action = WD_ACTION_NONE1;
		wd_data.reboot_action = 1;
	} else {
		rc = PICL_INVALIDARG;
	}
	break;

	case WD2:
	if (strcmp(wd_action, PICL_PROPVAL_WD_ACTION_RESET) == 0) {
		wd_data.wd2_action = WD_ACTION_HARD_RESET;
	} else if (strcmp(wd_action, PICL_PROPVAL_WD_ACTION_NONE) == 0) {
		wd_data.wd2_action = WD_ACTION_NONE2;
	} else {
		rc = PICL_INVALIDARG;
	}
	break;
	}
	(void) mutex_unlock(&data_lock);
	return (rc);
}

/*
 * volatile function to write the timeout
 * this function validates the user value before programming the
 * timeout property. Properties can be modified only when watchdog
 * is in disarmed state.
 */
static int
wd_write_timeout(ptree_warg_t *parg, const void *buf)
{
	int32_t timeout;
	int flag = 0x0;

	/* only super user can write this property */
	if (parg->cred.dc_euid != SUPER_USER) {
		return (PICL_PERMDENIED);
	}

	/* dont allow any write operations when watchdog is armed */
	(void) mutex_lock(&data_lock);
	if (wd_data.wd1_run_state != WD_DISARMED ||
		wd_data.wd2_run_state != WD_DISARMED) {
		(void) mutex_unlock(&data_lock);
		return (PICL_PERMDENIED);
	}
	(void) mutex_unlock(&data_lock);

	if (parg->proph == wd_data.wd1_timeout_hdl) {
		flag = WD1;
	} else if (parg->proph == wd_data.wd2_timeout_hdl) {
		flag = WD2;
	}

	/* validate the timeout values */
	timeout = *(int32_t *)buf;
	if (timeout < -1) {
		return (PICL_INVALIDARG);
	}

	if (timeout > 0) {
		switch (flag) {
		case WD1:
		if ((timeout % WD_L1_RESOLUTION) != 0) {
			return (PICL_INVALIDARG);
		}
		if ((timeout/WD_L1_RESOLUTION) > WD_MAX_L1) {
			return (PICL_INVALIDARG);
		}
		break;
		case WD2:
		if ((timeout % WD_L2_RESOLUTION) != 0) {
			return (PICL_INVALIDARG);
		}
		if ((timeout/WD_L2_RESOLUTION) > WD_MAX_L2) {
							/* 255 sec */
			return (PICL_INVALIDARG);
		}
		}
	}

	/* update the internal cache */
	(void) mutex_lock(&data_lock);
	switch (flag) {
	case WD1:
		wd_data.wd1_timeout = timeout;
		break;
	case WD2:
		wd_data.wd2_timeout = timeout;
		break;
	}
	(void) mutex_unlock(&data_lock);
	return (PICL_SUCCESS);
}
