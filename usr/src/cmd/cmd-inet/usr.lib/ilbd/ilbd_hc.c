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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/list.h>
#include <sys/stropts.h>
#include <sys/siginfo.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <stddef.h>
#include <unistd.h>
#include <libilb.h>
#include <port.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <spawn.h>
#include <fcntl.h>
#include <limits.h>
#include "libilb_impl.h"
#include "ilbd.h"

/* Global list of HC objects */
list_t ilbd_hc_list;

/* Timer queue for all hc related timers. */
static iu_tq_t *ilbd_hc_timer_q;

/* Indicate whether the timer needs to be updated */
static boolean_t hc_timer_restarted;

static void ilbd_hc_probe_timer(iu_tq_t *, void *);
static ilb_status_t ilbd_hc_restart_timer(ilbd_hc_t *, ilbd_hc_srv_t *);
static boolean_t ilbd_run_probe(ilbd_hc_srv_t *);

#define	MAX(a, b)	((a) > (b) ? (a) : (b))

/*
 * Number of arguments passed to a probe.  argc[0] is the path name of
 * the probe.
 */
#define	HC_PROBE_ARGC	8

/*
 * Max number of characters to be read from the output of a probe.  It
 * is long enough to read in a 64 bit integer.
 */
#define	HC_MAX_PROBE_OUTPUT	24

void
i_ilbd_setup_hc_list(void)
{
	list_create(&ilbd_hc_list, sizeof (ilbd_hc_t),
	    offsetof(ilbd_hc_t, ihc_link));
}

/*
 * Given a hc object name, return a pointer to hc object if found.
 */
ilbd_hc_t *
ilbd_get_hc(const char *name)
{
	ilbd_hc_t *hc;

	for (hc = list_head(&ilbd_hc_list); hc != NULL;
	    hc = list_next(&ilbd_hc_list, hc)) {
		if (strcasecmp(hc->ihc_name, name) == 0)
			return (hc);
	}
	return (NULL);
}

/*
 * Generates an audit record for create-healthcheck,
 * delete-healtcheck subcommands.
 */
static void
ilbd_audit_hc_event(const char *audit_hcname,
    const ilb_hc_info_t *audit_hcinfo, ilbd_cmd_t cmd,
    ilb_status_t rc, ucred_t *ucredp)
{
	adt_session_data_t	*ah;
	adt_event_data_t	*event;
	au_event_t	flag;
	int	audit_error;

	if ((ucredp == NULL) && (cmd == ILBD_CREATE_HC))  {
		/*
		 * we came here from the path where ilbd incorporates
		 * the configuration that is listed in SCF:
		 * i_ilbd_read_config->ilbd_walk_hc_pgs->
		 *   ->ilbd_scf_instance_walk_pg->ilbd_create_hc
		 * We skip auditing in that case
		 */
		logdebug("ilbd_audit_hc_event: skipping auditing");
		return;
	}

	if (adt_start_session(&ah, NULL, 0) != 0) {
		logerr("ilbd_audit_hc_event: adt_start_session failed");
		exit(EXIT_FAILURE);
	}
	if (adt_set_from_ucred(ah, ucredp, ADT_NEW) != 0) {
		(void) adt_end_session(ah);
		logerr("ilbd_audit_rule_event: adt_set_from_ucred failed");
		exit(EXIT_FAILURE);
	}
	if (cmd == ILBD_CREATE_HC)
		flag = ADT_ilb_create_healthcheck;
	else if (cmd == ILBD_DESTROY_HC)
		flag = ADT_ilb_delete_healthcheck;

	if ((event = adt_alloc_event(ah, flag)) == NULL) {
		logerr("ilbd_audit_hc_event: adt_alloc_event failed");
		exit(EXIT_FAILURE);
	}
	(void) memset((char *)event, 0, sizeof (adt_event_data_t));

	switch (cmd) {
	case ILBD_CREATE_HC:
		event->adt_ilb_create_healthcheck.auth_used =
		    NET_ILB_CONFIG_AUTH;
		event->adt_ilb_create_healthcheck.hc_test =
		    (char *)audit_hcinfo->hci_test;
		event->adt_ilb_create_healthcheck.hc_name =
		    (char *)audit_hcinfo->hci_name;

		/*
		 * If the value 0 is stored, the default values are
		 * set in the kernel. User land does not know about them
		 * So if the user does not specify them, audit record
		 * will show them as 0
		 */
		event->adt_ilb_create_healthcheck.hc_timeout =
		    audit_hcinfo->hci_timeout;
		event->adt_ilb_create_healthcheck.hc_count =
		    audit_hcinfo->hci_count;
		event->adt_ilb_create_healthcheck.hc_interval =
		    audit_hcinfo->hci_interval;
		break;
	case ILBD_DESTROY_HC:
		event->adt_ilb_delete_healthcheck.auth_used =
		    NET_ILB_CONFIG_AUTH;
		event->adt_ilb_delete_healthcheck.hc_name =
		    (char *)audit_hcname;
		break;
	}

	/* Fill in success/failure */
	if (rc == ILB_STATUS_OK) {
		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
			logerr("ilbd_audit_hc_event: adt_put_event failed");
			exit(EXIT_FAILURE);
		}
	} else {
		audit_error = ilberror2auditerror(rc);
		if (adt_put_event(event, ADT_FAILURE, audit_error) != 0) {
			logerr("ilbd_audit_hc_event: adt_put_event failed");
			exit(EXIT_FAILURE);
		}
	}
	adt_free_event(event);
	(void) adt_end_session(ah);
}

/*
 * Given the ilb_hc_info_t passed in (from the libilb), create a hc object
 * in ilbd.  The parameter ev_port is not used, refer to comments of
 * ilbd_create_sg() in ilbd_sg.c
 */
/* ARGSUSED */
ilb_status_t
ilbd_create_hc(const ilb_hc_info_t *hc_info, int ev_port,
    const struct passwd *ps, ucred_t *ucredp)
{
	ilbd_hc_t *hc;
	ilb_status_t ret = ILB_STATUS_OK;

	/*
	 * ps == NULL is from the daemon when it starts and load configuration
	 * ps != NULL is from client.
	 */
	if (ps != NULL) {
		ret = ilbd_check_client_config_auth(ps);
		if (ret != ILB_STATUS_OK) {
			ilbd_audit_hc_event(NULL, hc_info, ILBD_CREATE_HC,
			    ret, ucredp);
			return (ret);
		}
	}

	if (hc_info->hci_name[0] == '\0') {
		logdebug("ilbd_create_hc: missing healthcheck info");
		ilbd_audit_hc_event(NULL, hc_info, ILBD_CREATE_HC,
		    ILB_STATUS_ENOHCINFO, ucredp);
		return (ILB_STATUS_ENOHCINFO);
	}

	hc = ilbd_get_hc(hc_info->hci_name);
	if (hc != NULL) {
		logdebug("ilbd_create_hc: healthcheck name %s already"
		    " exists", hc_info->hci_name);
		ilbd_audit_hc_event(NULL, hc_info, ILBD_CREATE_HC,
		    ILB_STATUS_EEXIST, ucredp);
		return (ILB_STATUS_EEXIST);
	}

	/*
	 * Sanity check on user supplied probe.  The given path name
	 * must be a full path name (starts with '/') and is
	 * executable.
	 */
	if (strcasecmp(hc_info->hci_test, ILB_HC_STR_TCP) != 0 &&
	    strcasecmp(hc_info->hci_test, ILB_HC_STR_UDP) != 0 &&
	    strcasecmp(hc_info->hci_test, ILB_HC_STR_PING) != 0 &&
	    (hc_info->hci_test[0] != '/' ||
	    access(hc_info->hci_test, X_OK) == -1)) {
		if (errno == ENOENT) {
			logdebug("ilbd_create_hc: user script %s doesn't "
			    "exist", hc_info->hci_test);
			ilbd_audit_hc_event(NULL, hc_info, ILBD_CREATE_HC,
			    ILB_STATUS_ENOENT, ucredp);
			return (ILB_STATUS_ENOENT);
		} else {
			logdebug("ilbd_create_hc: user script %s is "
			    "invalid", hc_info->hci_test);
			ilbd_audit_hc_event(NULL, hc_info, ILBD_CREATE_HC,
			    ILB_STATUS_EINVAL, ucredp);
			return (ILB_STATUS_EINVAL);
		}
	}

	/* Create and add the hc object */
	hc = calloc(1, sizeof (ilbd_hc_t));
	if (hc == NULL) {
		ilbd_audit_hc_event(NULL, hc_info, ILBD_CREATE_HC,
		    ILB_STATUS_ENOMEM, ucredp);
		return (ILB_STATUS_ENOMEM);
	}
	(void) memcpy(&hc->ihc_info, hc_info, sizeof (ilb_hc_info_t));
	if (strcasecmp(hc->ihc_test, ILB_HC_STR_TCP) == 0)
		hc->ihc_test_type = ILBD_HC_TCP;
	else if (strcasecmp(hc->ihc_test, ILB_HC_STR_UDP) == 0)
		hc->ihc_test_type = ILBD_HC_UDP;
	else if (strcasecmp(hc->ihc_test, ILB_HC_STR_PING) == 0)
		hc->ihc_test_type = ILBD_HC_PING;
	else
		hc->ihc_test_type = ILBD_HC_USER;
	list_create(&hc->ihc_rules, sizeof (ilbd_hc_rule_t),
	    offsetof(ilbd_hc_rule_t, hcr_link));

	/* Update SCF */
	if (ps != NULL) {
		if ((ret = ilbd_create_pg(ILBD_SCF_HC, (void *)hc)) !=
		    ILB_STATUS_OK) {
			ilbd_audit_hc_event(NULL, hc_info, ILBD_CREATE_HC,
			    ret, ucredp);
			list_destroy(&hc->ihc_rules);
			free(hc);
			return (ret);
		}
	}

	/* Everything is fine, now add it to the global list. */
	list_insert_tail(&ilbd_hc_list, hc);
	ilbd_audit_hc_event(NULL, hc_info, ILBD_CREATE_HC, ret, ucredp);
	return (ret);
}

/*
 * Given a name of a hc object, destroy it.
 */
ilb_status_t
ilbd_destroy_hc(const char *hc_name, const struct passwd *ps,
    ucred_t *ucredp)
{
	ilb_status_t ret;
	ilbd_hc_t *hc;

	/*
	 * No need to check ps == NULL, daemon won't call any destroy func
	 * at start up.
	 */
	ret = ilbd_check_client_config_auth(ps);
	if (ret != ILB_STATUS_OK) {
		ilbd_audit_hc_event(hc_name, NULL, ILBD_DESTROY_HC,
		    ret, ucredp);
		return (ret);
	}

	hc = ilbd_get_hc(hc_name);
	if (hc == NULL) {
		logdebug("ilbd_destroy_hc: healthcheck %s does not exist",
		    hc_name);
		ilbd_audit_hc_event(hc_name, NULL, ILBD_DESTROY_HC,
		    ILB_STATUS_ENOENT, ucredp);
		return (ILB_STATUS_ENOENT);
	}

	/* If hc is in use, cannot delete it */
	if (hc->ihc_rule_cnt > 0) {
		logdebug("ilbd_destroy_hc: healthcheck %s is associated"
		    " with a rule - cannot remove", hc_name);
		ilbd_audit_hc_event(hc_name, NULL, ILBD_DESTROY_HC,
		    ILB_STATUS_INUSE, ucredp);
		return (ILB_STATUS_INUSE);
	}

	if ((ret = ilbd_destroy_pg(ILBD_SCF_HC, hc_name)) !=
	    ILB_STATUS_OK) {
		logdebug("ilbd_destroy_hc: cannot destroy healthcheck %s "
		    "property group", hc_name);
		ilbd_audit_hc_event(hc_name, NULL, ILBD_DESTROY_HC,
		    ret, ucredp);
		return (ret);
	}

	list_remove(&ilbd_hc_list, hc);
	list_destroy(&hc->ihc_rules);
	free(hc);
	ilbd_audit_hc_event(hc_name, NULL, ILBD_DESTROY_HC, ret, ucredp);
	return (ret);
}

/*
 * Given a hc object name, return its information.  Used by libilb to
 * get hc info.
 */
ilb_status_t
ilbd_get_hc_info(const char *hc_name, uint32_t *rbuf, size_t *rbufsz)
{
	ilbd_hc_t	*hc;
	ilb_hc_info_t	*hc_info;
	ilb_comm_t	*ic = (ilb_comm_t *)rbuf;

	hc = ilbd_get_hc(hc_name);
	if (hc == NULL) {
		logdebug("%s: healthcheck %s does not exist", __func__,
		    hc_name);
		return (ILB_STATUS_ENOENT);
	}
	ilbd_reply_ok(rbuf, rbufsz);
	hc_info = (ilb_hc_info_t *)&ic->ic_data;

	(void) strlcpy(hc_info->hci_name, hc->ihc_name, sizeof (hc->ihc_name));
	(void) strlcpy(hc_info->hci_test, hc->ihc_test, sizeof (hc->ihc_test));
	hc_info->hci_timeout = hc->ihc_timeout;
	hc_info->hci_count = hc->ihc_count;
	hc_info->hci_interval = hc->ihc_interval;
	hc_info->hci_def_ping = hc->ihc_def_ping;

	*rbufsz += sizeof (ilb_hc_info_t);

	return (ILB_STATUS_OK);
}

static void
ilbd_hc_copy_srvs(uint32_t *rbuf, size_t *rbufsz, ilbd_hc_rule_t *hc_rule,
    const char *rulename)
{
	ilbd_hc_srv_t		*tmp_srv;
	ilb_hc_srv_t		*dst_srv;
	ilb_hc_rule_srv_t	*srvs;
	size_t			tmp_rbufsz;
	int			i;

	tmp_rbufsz = *rbufsz;
	/* Set up the reply buffer.  rbufsz will be set to the new size. */
	ilbd_reply_ok(rbuf, rbufsz);

	/* Calculate how much space is left for holding server info. */
	*rbufsz += sizeof (ilb_hc_rule_srv_t);
	tmp_rbufsz -= *rbufsz;

	srvs = (ilb_hc_rule_srv_t *)&((ilb_comm_t *)rbuf)->ic_data;

	tmp_srv = list_head(&hc_rule->hcr_servers);
	for (i = 0; tmp_srv != NULL && tmp_rbufsz >= sizeof (*dst_srv); i++) {
		dst_srv = &srvs->rs_srvs[i];

		(void) strlcpy(dst_srv->hcs_rule_name, rulename, ILB_NAMESZ);
		(void) strlcpy(dst_srv->hcs_ID, tmp_srv->shc_sg_srv->sgs_srvID,
		    ILB_NAMESZ);
		(void) strlcpy(dst_srv->hcs_hc_name,
		    tmp_srv->shc_hc->ihc_name, ILB_NAMESZ);
		dst_srv->hcs_IP = tmp_srv->shc_sg_srv->sgs_addr;
		dst_srv->hcs_fail_cnt = tmp_srv->shc_fail_cnt;
		dst_srv->hcs_status = tmp_srv->shc_status;
		dst_srv->hcs_rtt = tmp_srv->shc_rtt;
		dst_srv->hcs_lasttime = tmp_srv->shc_lasttime;
		dst_srv->hcs_nexttime = tmp_srv->shc_nexttime;

		tmp_srv = list_next(&hc_rule->hcr_servers, tmp_srv);
		tmp_rbufsz -= sizeof (*dst_srv);
	}
	srvs->rs_num_srvs = i;
	*rbufsz += i * sizeof (*dst_srv);
}

/*
 * Given a rule name, return the hc status of its servers.
 */
ilb_status_t
ilbd_get_hc_srvs(const char *rulename, uint32_t *rbuf, size_t *rbufsz)
{
	ilbd_hc_t	*hc;
	ilbd_hc_rule_t	*hc_rule;

	for (hc = list_head(&ilbd_hc_list); hc != NULL;
	    hc = list_next(&ilbd_hc_list, hc)) {
		for (hc_rule = list_head(&hc->ihc_rules); hc_rule != NULL;
		    hc_rule = list_next(&hc->ihc_rules, hc_rule)) {
			if (strcasecmp(hc_rule->hcr_rule->irl_name,
			    rulename) != 0) {
				continue;
			}
			ilbd_hc_copy_srvs(rbuf, rbufsz, hc_rule, rulename);
			return (ILB_STATUS_OK);
		}
	}
	return (ILB_STATUS_RULE_NO_HC);
}

/*
 * Initialize the hc timer and associate the notification of timeout to
 * the given event port.
 */
void
ilbd_hc_timer_init(int ev_port, ilbd_timer_event_obj_t *ev_obj)
{
	struct sigevent sigev;
	port_notify_t notify;

	if ((ilbd_hc_timer_q = iu_tq_create()) == NULL) {
		logerr("%s: cannot create hc timer queue", __func__);
		exit(EXIT_FAILURE);
	}
	hc_timer_restarted = B_FALSE;

	ev_obj->ev = ILBD_EVENT_TIMER;
	ev_obj->timerid = -1;

	notify.portnfy_port = ev_port;
	notify.portnfy_user = ev_obj;
	sigev.sigev_notify = SIGEV_PORT;
	sigev.sigev_value.sival_ptr = &notify;
	if (timer_create(CLOCK_REALTIME, &sigev, &ev_obj->timerid) == -1) {
		logerr("%s: cannot create timer", __func__);
		exit(EXIT_FAILURE);
	}
}

/*
 * HC timeout handler.
 */
void
ilbd_hc_timeout(void)
{
	(void) iu_expire_timers(ilbd_hc_timer_q);
	hc_timer_restarted = B_TRUE;
}

/*
 * Set up the timer to fire at the earliest timeout.
 */
void
ilbd_hc_timer_update(ilbd_timer_event_obj_t *ev_obj)
{
	itimerspec_t itimeout;
	int timeout;

	/*
	 * There is no change on the timer list, so no need to set up the
	 * timer again.
	 */
	if (!hc_timer_restarted)
		return;

restart:
	if ((timeout = iu_earliest_timer(ilbd_hc_timer_q)) == INFTIM) {
		hc_timer_restarted = B_FALSE;
		return;
	} else if (timeout == 0) {
		/*
		 * Handle the timeout immediately.  After that (clearing all
		 * the expired timers), check to  see if there are still
		 * timers running.  If yes, start them.
		 */
		(void) iu_expire_timers(ilbd_hc_timer_q);
		goto restart;
	}

	itimeout.it_value.tv_sec = timeout / MILLISEC + 1;
	itimeout.it_value.tv_nsec = 0;
	itimeout.it_interval.tv_sec = 0;
	itimeout.it_interval.tv_nsec = 0;

	/*
	 * Failure to set a timeout is "OK" since hopefully there will be
	 * other events and timer_settime() will be called again.  So
	 * we will only miss some timeouts.  But in the worst case, no event
	 * will happen and ilbd will get stuck...
	 */
	if (timer_settime(ev_obj->timerid, 0, &itimeout, NULL) == -1)
		logerr("%s: cannot set timer", __func__);
	hc_timer_restarted = B_FALSE;
}

/*
 * Kill the probe process of a server.
 */
static void
ilbd_hc_kill_probe(ilbd_hc_srv_t *srv)
{
	/*
	 * First dissociate the fd from the event port.  It should not
	 * fail.
	 */
	if (port_dissociate(srv->shc_ev_port, PORT_SOURCE_FD,
	    srv->shc_child_fd) != 0) {
		logdebug("%s: port_dissociate: %s", __func__, strerror(errno));
	}
	(void) close(srv->shc_child_fd);
	free(srv->shc_ev);
	srv->shc_ev = NULL;

	/* Then kill the probe process. */
	if (kill(srv->shc_child_pid, SIGKILL) != 0) {
		logerr("%s: rule %s server %s: %s", __func__,
		    srv->shc_hc_rule->hcr_rule->irl_name,
		    srv->shc_sg_srv->sgs_srvID, strerror(errno));
	}
	/* Should not fail... */
	if (waitpid(srv->shc_child_pid, NULL, 0) != srv->shc_child_pid) {
		logdebug("%s: waitpid: rule %s server %s", __func__,
		    srv->shc_hc_rule->hcr_rule->irl_name,
		    srv->shc_sg_srv->sgs_srvID);
	}
	srv->shc_child_pid = 0;
}

/*
 * Disable the server, either because the server is dead or because a timer
 * cannot be started for this server.  Note that this only affects the
 * transient configuration, meaning only in memory.  The persistent
 * configuration is not affected.
 */
static void
ilbd_mark_server_disabled(ilbd_hc_srv_t *srv)
{
	srv->shc_status = ILB_HCS_DISABLED;

	/* Disable the server in kernel. */
	if (ilbd_k_Xable_server(&srv->shc_sg_srv->sgs_addr,
	    srv->shc_hc_rule->hcr_rule->irl_name,
	    stat_declare_srv_dead) != ILB_STATUS_OK) {
		logerr("%s: cannot disable server in kernel: rule %s "
		    "server %s", __func__,
		    srv->shc_hc_rule->hcr_rule->irl_name,
		    srv->shc_sg_srv->sgs_srvID);
	}
}

/*
 * A probe fails, set the state of the server.
 */
static void
ilbd_set_fail_state(ilbd_hc_srv_t *srv)
{
	if (++srv->shc_fail_cnt < srv->shc_hc->ihc_count) {
		/* Probe again */
		ilbd_hc_probe_timer(ilbd_hc_timer_q, srv);
		return;
	}

	logdebug("%s: rule %s server %s fails %u", __func__,
	    srv->shc_hc_rule->hcr_rule->irl_name, srv->shc_sg_srv->sgs_srvID,
	    srv->shc_fail_cnt);

	/*
	 * If this is a ping test, mark the server as
	 * unreachable instead of dead.
	 */
	if (srv->shc_hc->ihc_test_type == ILBD_HC_PING ||
	    srv->shc_state == ilbd_hc_def_pinging) {
		srv->shc_status = ILB_HCS_UNREACH;
	} else {
		srv->shc_status = ILB_HCS_DEAD;
	}

	/* Disable the server in kernel. */
	if (ilbd_k_Xable_server(&srv->shc_sg_srv->sgs_addr,
	    srv->shc_hc_rule->hcr_rule->irl_name, stat_declare_srv_dead) !=
	    ILB_STATUS_OK) {
		logerr("%s: cannot disable server in kernel: rule %s "
		    "server %s", __func__,
		    srv->shc_hc_rule->hcr_rule->irl_name,
		    srv->shc_sg_srv->sgs_srvID);
	}

	/* Still keep probing in case the server is alive again. */
	if (ilbd_hc_restart_timer(srv->shc_hc, srv) != ILB_STATUS_OK) {
		/* Only thing to do is to disable the server... */
		logerr("%s: cannot restart timer: rule %s server %s", __func__,
		    srv->shc_hc_rule->hcr_rule->irl_name,
		    srv->shc_sg_srv->sgs_srvID);
		srv->shc_status = ILB_HCS_DISABLED;
	}
}

/*
 * A probe process has not returned for the ihc_timeout period, we should
 * kill it.  This function is the handler of this.
 */
/* ARGSUSED */
static void
ilbd_hc_kill_timer(iu_tq_t *tq, void *arg)
{
	ilbd_hc_srv_t *srv = (ilbd_hc_srv_t *)arg;

	ilbd_hc_kill_probe(srv);
	ilbd_set_fail_state(srv);
}

/*
 * Probe timeout handler.  Send out the appropriate probe.
 */
/* ARGSUSED */
static void
ilbd_hc_probe_timer(iu_tq_t *tq, void *arg)
{
	ilbd_hc_srv_t *srv = (ilbd_hc_srv_t *)arg;

	/*
	 * If starting the probe fails, just pretend that the timeout has
	 * extended.
	 */
	if (!ilbd_run_probe(srv)) {
		/*
		 * If we cannot restart the timer, the only thing we can do
		 * is to disable this server.  Hopefully the sys admin will
		 * notice this and enable this server again later.
		 */
		if (ilbd_hc_restart_timer(srv->shc_hc, srv) != ILB_STATUS_OK) {
			logerr("%s: cannot restart timer: rule %s server %s, "
			    "disabling it", __func__,
			    srv->shc_hc_rule->hcr_rule->irl_name,
			    srv->shc_sg_srv->sgs_srvID);
			ilbd_mark_server_disabled(srv);
		}
		return;
	}

	/*
	 * Similar to above, if kill timer cannot be started, disable the
	 * server.
	 */
	if ((srv->shc_tid = iu_schedule_timer(ilbd_hc_timer_q,
	    srv->shc_hc->ihc_timeout, ilbd_hc_kill_timer, srv)) == -1) {
		logerr("%s: cannot start kill timer: rule %s server %s, "
		    "disabling it", __func__,
		    srv->shc_hc_rule->hcr_rule->irl_name,
		    srv->shc_sg_srv->sgs_srvID);
		ilbd_mark_server_disabled(srv);
	}
	hc_timer_restarted = B_TRUE;
}

/* Restart the periodic timer for a given server. */
static ilb_status_t
ilbd_hc_restart_timer(ilbd_hc_t *hc, ilbd_hc_srv_t *srv)
{
	int timeout;

	/* Don't allow the timeout interval to be less than 1s */
	timeout = MAX((hc->ihc_interval >> 1) + (gethrtime() %
	    (hc->ihc_interval + 1)), 1);

	/*
	 * If the probe is actually a ping probe, there is no need to
	 * do default pinging.  Just skip the step.
	 */
	if (hc->ihc_def_ping && hc->ihc_test_type != ILBD_HC_PING)
		srv->shc_state = ilbd_hc_def_pinging;
	else
		srv->shc_state = ilbd_hc_probing;
	srv->shc_tid = iu_schedule_timer(ilbd_hc_timer_q, timeout,
	    ilbd_hc_probe_timer, srv);

	if (srv->shc_tid == -1)
		return (ILB_STATUS_TIMER);
	srv->shc_lasttime = time(NULL);
	srv->shc_nexttime = time(NULL) + timeout;

	hc_timer_restarted = B_TRUE;
	return (ILB_STATUS_OK);
}

/* Helper routine to associate a server with its hc object. */
static ilb_status_t
ilbd_hc_srv_add(ilbd_hc_t *hc, ilbd_hc_rule_t *hc_rule,
    const ilb_sg_srv_t *srv, int ev_port)
{
	ilbd_hc_srv_t *new_srv;
	ilb_status_t ret;

	if ((new_srv = calloc(1, sizeof (ilbd_hc_srv_t))) == NULL)
		return (ILB_STATUS_ENOMEM);
	new_srv->shc_hc = hc;
	new_srv->shc_hc_rule = hc_rule;
	new_srv->shc_sg_srv = srv;
	new_srv->shc_ev_port = ev_port;
	new_srv->shc_tid = -1;
	new_srv->shc_nexttime = time(NULL);
	new_srv->shc_lasttime = new_srv->shc_nexttime;

	if ((hc_rule->hcr_rule->irl_flags & ILB_FLAGS_RULE_ENABLED) &&
	    ILB_IS_SRV_ENABLED(srv->sgs_flags)) {
		new_srv->shc_status = ILB_HCS_UNINIT;
		ret = ilbd_hc_restart_timer(hc, new_srv);
		if (ret != ILB_STATUS_OK) {
			free(new_srv);
			return (ret);
		}
	} else {
		new_srv->shc_status = ILB_HCS_DISABLED;
	}

	list_insert_tail(&hc_rule->hcr_servers, new_srv);
	return (ILB_STATUS_OK);
}

/* Handy macro to cancel a server's timer. */
#define	HC_CANCEL_TIMER(srv)						\
{									\
	void *arg;							\
	int ret;							\
	if ((srv)->shc_tid != -1) {					\
		ret = iu_cancel_timer(ilbd_hc_timer_q, (srv)->shc_tid, &arg); \
		(srv)->shc_tid = -1;					\
		assert(ret == 1);					\
		assert(arg == (srv));					\
	}								\
	hc_timer_restarted = B_TRUE;					\
}

/* Helper routine to dissociate a server from its hc object. */
static ilb_status_t
ilbd_hc_srv_rem(ilbd_hc_rule_t *hc_rule, const ilb_sg_srv_t *srv)
{
	ilbd_hc_srv_t *tmp_srv;

	for (tmp_srv = list_head(&hc_rule->hcr_servers); tmp_srv != NULL;
	    tmp_srv = list_next(&hc_rule->hcr_servers, tmp_srv)) {
		if (tmp_srv->shc_sg_srv == srv) {
			list_remove(&hc_rule->hcr_servers, tmp_srv);
			HC_CANCEL_TIMER(tmp_srv);
			if (tmp_srv->shc_child_pid != 0)
				ilbd_hc_kill_probe(tmp_srv);
			free(tmp_srv);
			return (ILB_STATUS_OK);
		}
	}
	return (ILB_STATUS_ENOENT);
}

/* Helper routine to dissociate all servers of a rule from its hc object. */
static void
ilbd_hc_srv_rem_all(ilbd_hc_rule_t *hc_rule)
{
	ilbd_hc_srv_t *srv;

	while ((srv = list_remove_head(&hc_rule->hcr_servers)) != NULL) {
		HC_CANCEL_TIMER(srv);
		if (srv->shc_child_pid != 0)
			ilbd_hc_kill_probe(srv);
		free(srv);
	}
}

/* Associate a rule with its hc object. */
ilb_status_t
ilbd_hc_associate_rule(const ilbd_rule_t *rule, int ev_port)
{
	ilbd_hc_t	*hc;
	ilbd_hc_rule_t	*hc_rule;
	ilb_status_t	ret;
	ilbd_sg_t	*sg;
	ilbd_srv_t	*ilbd_srv;

	/* The rule is assumed to be initialized appropriately. */
	if ((hc = ilbd_get_hc(rule->irl_hcname)) == NULL) {
		logdebug("ilbd_hc_associate_rule: healthcheck %s does not "
		    "exist", rule->irl_hcname);
		return (ILB_STATUS_ENOHCINFO);
	}
	if ((hc->ihc_test_type == ILBD_HC_TCP &&
	    rule->irl_proto != IPPROTO_TCP) ||
	    (hc->ihc_test_type == ILBD_HC_UDP &&
	    rule->irl_proto != IPPROTO_UDP)) {
		return (ILB_STATUS_RULE_HC_MISMATCH);
	}
	if ((hc_rule = calloc(1, sizeof (ilbd_hc_rule_t))) == NULL) {
		logdebug("ilbd_hc_associate_rule: out of memory");
		return (ILB_STATUS_ENOMEM);
	}

	hc_rule->hcr_rule = rule;
	list_create(&hc_rule->hcr_servers, sizeof (ilbd_hc_srv_t),
	    offsetof(ilbd_hc_srv_t, shc_srv_link));

	/* Add all the servers. */
	sg = rule->irl_sg;
	for (ilbd_srv = list_head(&sg->isg_srvlist); ilbd_srv != NULL;
	    ilbd_srv = list_next(&sg->isg_srvlist, ilbd_srv)) {
		if ((ret = ilbd_hc_srv_add(hc, hc_rule, &ilbd_srv->isv_srv,
		    ev_port)) != ILB_STATUS_OK) {
			/* Remove all previously added servers */
			ilbd_hc_srv_rem_all(hc_rule);
			list_destroy(&hc_rule->hcr_servers);
			free(hc_rule);
			return (ret);
		}
	}
	list_insert_tail(&hc->ihc_rules, hc_rule);
	hc->ihc_rule_cnt++;

	return (ILB_STATUS_OK);
}

/* Dissociate a rule from its hc object. */
ilb_status_t
ilbd_hc_dissociate_rule(const ilbd_rule_t *rule)
{
	ilbd_hc_t	*hc;
	ilbd_hc_rule_t	*hc_rule;

	/* The rule is assumed to be initialized appropriately. */
	if ((hc = ilbd_get_hc(rule->irl_hcname)) == NULL) {
		logdebug("ilbd_hc_dissociate_rule: healthcheck %s does not "
		    "exist", rule->irl_hcname);
		return (ILB_STATUS_ENOENT);
	}
	for (hc_rule = list_head(&hc->ihc_rules); hc_rule != NULL;
	    hc_rule = list_next(&hc->ihc_rules, hc_rule)) {
		if (hc_rule->hcr_rule == rule)
			break;
	}
	if (hc_rule == NULL) {
		logdebug("ilbd_hc_dissociate_rule: rule %s is not associated "
		    "with healtcheck %s", rule->irl_hcname, hc->ihc_name);
		return (ILB_STATUS_ENOENT);
	}
	ilbd_hc_srv_rem_all(hc_rule);
	list_remove(&hc->ihc_rules, hc_rule);
	hc->ihc_rule_cnt--;
	list_destroy(&hc_rule->hcr_servers);
	free(hc_rule);
	return (ILB_STATUS_OK);
}

/*
 * Given a hc object name and a rule, check to see if the rule is associated
 * with the hc object.  If it is, the hc object is returned in **hc and the
 * ilbd_hc_rule_t is returned in **hc_rule.
 */
static boolean_t
ilbd_hc_check_rule(const char *hc_name, const ilbd_rule_t *rule,
    ilbd_hc_t **hc, ilbd_hc_rule_t **hc_rule)
{
	ilbd_hc_t	*tmp_hc;
	ilbd_hc_rule_t	*tmp_hc_rule;

	if ((tmp_hc = ilbd_get_hc(hc_name)) == NULL)
		return (B_FALSE);
	for (tmp_hc_rule = list_head(&tmp_hc->ihc_rules); tmp_hc_rule != NULL;
	    tmp_hc_rule = list_next(&tmp_hc->ihc_rules, tmp_hc_rule)) {
		if (tmp_hc_rule->hcr_rule == rule) {
			*hc = tmp_hc;
			*hc_rule = tmp_hc_rule;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/* Associate a server with its hc object. */
ilb_status_t
ilbd_hc_add_server(const ilbd_rule_t *rule, const ilb_sg_srv_t *srv,
    int ev_port)
{
	ilbd_hc_t	*hc;
	ilbd_hc_rule_t	*hc_rule;

	if (!ilbd_hc_check_rule(rule->irl_hcname, rule, &hc, &hc_rule))
		return (ILB_STATUS_ENOENT);
	return (ilbd_hc_srv_add(hc, hc_rule, srv, ev_port));
}

/* Dissociate a server from its hc object. */
ilb_status_t
ilbd_hc_del_server(const ilbd_rule_t *rule, const ilb_sg_srv_t *srv)
{
	ilbd_hc_t	*hc;
	ilbd_hc_rule_t	*hc_rule;

	if (!ilbd_hc_check_rule(rule->irl_hcname, rule, &hc, &hc_rule))
		return (ILB_STATUS_ENOENT);
	return (ilbd_hc_srv_rem(hc_rule, srv));
}

/* Helper routine to enable/disable a server's hc probe. */
static ilb_status_t
ilbd_hc_toggle_server(const ilbd_rule_t *rule, const ilb_sg_srv_t *srv,
    boolean_t enable)
{
	ilbd_hc_t	*hc;
	ilbd_hc_rule_t	*hc_rule;
	ilbd_hc_srv_t	*tmp_srv;
	ilb_status_t	ret;

	if (!ilbd_hc_check_rule(rule->irl_hcname, rule, &hc, &hc_rule))
		return (ILB_STATUS_ENOENT);
	for (tmp_srv = list_head(&hc_rule->hcr_servers); tmp_srv != NULL;
	    tmp_srv = list_next(&hc_rule->hcr_servers, tmp_srv)) {
		if (tmp_srv->shc_sg_srv != srv) {
			continue;
		}
		if (enable) {
			if (tmp_srv->shc_status == ILB_HCS_DISABLED) {
				ret = ilbd_hc_restart_timer(hc, tmp_srv);
				if (ret != ILB_STATUS_OK) {
					logerr("%s: cannot start timers for "
					    "rule %s server %s", __func__,
					    rule->irl_name,
					    tmp_srv->shc_sg_srv->sgs_srvID);
					return (ret);
				}
				/* Start from fresh... */
				tmp_srv->shc_status = ILB_HCS_UNINIT;
				tmp_srv->shc_rtt = 0;
				tmp_srv->shc_fail_cnt = 0;
			}
		} else {
			if (tmp_srv->shc_status != ILB_HCS_DISABLED) {
				tmp_srv->shc_status = ILB_HCS_DISABLED;
				HC_CANCEL_TIMER(tmp_srv);
				if (tmp_srv->shc_child_pid != 0)
					ilbd_hc_kill_probe(tmp_srv);
			}
		}
		return (ILB_STATUS_OK);
	}
	return (ILB_STATUS_ENOENT);
}

ilb_status_t
ilbd_hc_enable_server(const ilbd_rule_t *rule, const ilb_sg_srv_t *srv)
{
	return (ilbd_hc_toggle_server(rule, srv, B_TRUE));
}

ilb_status_t
ilbd_hc_disable_server(const ilbd_rule_t *rule, const ilb_sg_srv_t *srv)
{
	return (ilbd_hc_toggle_server(rule, srv, B_FALSE));
}

/*
 * Helper routine to enable/disable a rule's hc probe (including all its
 * servers).
 */
static ilb_status_t
ilbd_hc_toggle_rule(const ilbd_rule_t *rule, boolean_t enable)
{
	ilbd_hc_t	*hc;
	ilbd_hc_rule_t	*hc_rule;
	ilbd_hc_srv_t	*tmp_srv;
	int		ret;

	if (!ilbd_hc_check_rule(rule->irl_hcname, rule, &hc, &hc_rule))
		return (ILB_STATUS_ENOENT);

	for (tmp_srv = list_head(&hc_rule->hcr_servers); tmp_srv != NULL;
	    tmp_srv = list_next(&hc_rule->hcr_servers, tmp_srv)) {
		if (enable) {
			/*
			 * If the server is disabled in the rule, do not
			 * restart its timer.
			 */
			if (tmp_srv->shc_status == ILB_HCS_DISABLED &&
			    ILB_IS_SRV_ENABLED(
			    tmp_srv->shc_sg_srv->sgs_flags)) {
				ret = ilbd_hc_restart_timer(hc, tmp_srv);
				if (ret != ILB_STATUS_OK) {
					logerr("%s: cannot start timers for "
					    "rule %s server %s", __func__,
					    rule->irl_name,
					    tmp_srv->shc_sg_srv->sgs_srvID);
					goto rollback;
				} else {
					/* Start from fresh... */
					tmp_srv->shc_status = ILB_HCS_UNINIT;
					tmp_srv->shc_rtt = 0;
					tmp_srv->shc_fail_cnt = 0;
				}
			}
		} else {
			if (tmp_srv->shc_status != ILB_HCS_DISABLED) {
				HC_CANCEL_TIMER(tmp_srv);
				tmp_srv->shc_status = ILB_HCS_DISABLED;
				if (tmp_srv->shc_child_pid != 0)
					ilbd_hc_kill_probe(tmp_srv);
			}
		}
	}
	return (ILB_STATUS_OK);
rollback:
	enable = !enable;
	for (tmp_srv = list_prev(&hc_rule->hcr_servers, tmp_srv);
	    tmp_srv != NULL;
	    tmp_srv = list_prev(&hc_rule->hcr_servers, tmp_srv)) {
		if (enable) {
			if (tmp_srv->shc_status == ILB_HCS_DISABLED &&
			    ILB_IS_SRV_ENABLED(
			    tmp_srv->shc_sg_srv->sgs_flags)) {
				(void) ilbd_hc_restart_timer(hc, tmp_srv);
				tmp_srv->shc_status = ILB_HCS_UNINIT;
				tmp_srv->shc_rtt = 0;
				tmp_srv->shc_fail_cnt = 0;
			}
		} else {
			if (tmp_srv->shc_status != ILB_HCS_DISABLED) {
				HC_CANCEL_TIMER(tmp_srv);
				tmp_srv->shc_status = ILB_HCS_DISABLED;
				if (tmp_srv->shc_child_pid != 0)
					ilbd_hc_kill_probe(tmp_srv);
			}
		}
	}
	return (ret);
}

ilb_status_t
ilbd_hc_enable_rule(const ilbd_rule_t *rule)
{
	return (ilbd_hc_toggle_rule(rule, B_TRUE));
}

ilb_status_t
ilbd_hc_disable_rule(const ilbd_rule_t *rule)
{
	return (ilbd_hc_toggle_rule(rule, B_FALSE));
}

static const char *
topo_2_str(ilb_topo_t topo)
{
	switch (topo) {
	case ILB_TOPO_DSR:
		return ("DSR");
	case ILB_TOPO_NAT:
		return ("NAT");
	case ILB_TOPO_HALF_NAT:
		return ("HALF_NAT");
	default:
		/* Should not happen. */
		logerr("%s: unknown topology", __func__);
		break;
	}
	return ("");
}

/*
 * Create the argument list to be passed to a hc probe command.
 * The passed in argv is assumed to have HC_PROBE_ARGC elements.
 */
static boolean_t
create_argv(ilbd_hc_srv_t *srv, char *argv[])
{
	char buf[INET6_ADDRSTRLEN];
	ilbd_rule_t const *rule;
	ilb_sg_srv_t const *sg_srv;
	struct in_addr v4_addr;
	in_port_t port;
	int i;

	rule = srv->shc_hc_rule->hcr_rule;
	sg_srv = srv->shc_sg_srv;

	if (srv->shc_state == ilbd_hc_def_pinging) {
		if ((argv[0] = strdup(ILB_PROBE_PING)) == NULL)
			return (B_FALSE);
	} else {
		switch (srv->shc_hc->ihc_test_type) {
		case ILBD_HC_USER:
			if ((argv[0] = strdup(srv->shc_hc->ihc_test)) == NULL)
				return (B_FALSE);
			break;
		case ILBD_HC_TCP:
		case ILBD_HC_UDP:
			if ((argv[0] = strdup(ILB_PROBE_PROTO)) ==
			    NULL) {
				return (B_FALSE);
			}
			break;
		case ILBD_HC_PING:
			if ((argv[0] = strdup(ILB_PROBE_PING)) == NULL) {
				return (B_FALSE);
			}
			break;
		}
	}

	/*
	 * argv[1] is the VIP.
	 *
	 * Right now, the VIP and the backend server addresses should be
	 * in the same IP address family.  Here we don't do that in case
	 * this assumption is changed in future.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&rule->irl_vip)) {
		IN6_V4MAPPED_TO_INADDR(&rule->irl_vip, &v4_addr);
		if (inet_ntop(AF_INET, &v4_addr, buf, sizeof (buf)) == NULL)
			goto cleanup;
	} else {
		if (inet_ntop(AF_INET6, &rule->irl_vip, buf,
		    sizeof (buf)) == NULL) {
			goto cleanup;
		}
	}
	if ((argv[1] = strdup(buf)) == NULL)
		goto cleanup;

	/*
	 * argv[2] is the backend server address.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&sg_srv->sgs_addr)) {
		IN6_V4MAPPED_TO_INADDR(&sg_srv->sgs_addr, &v4_addr);
		if (inet_ntop(AF_INET, &v4_addr, buf, sizeof (buf)) == NULL)
			goto cleanup;
	} else {
		if (inet_ntop(AF_INET6, &sg_srv->sgs_addr, buf,
		    sizeof (buf)) == NULL) {
			goto cleanup;
		}
	}
	if ((argv[2] = strdup(buf)) == NULL)
		goto cleanup;

	/*
	 * argv[3] is the transport protocol used in the rule.
	 */
	switch (rule->irl_proto) {
	case IPPROTO_TCP:
		argv[3] = strdup("TCP");
		break;
	case IPPROTO_UDP:
		argv[3] = strdup("UDP");
		break;
	default:
		logerr("%s: unknown protocol", __func__);
		goto cleanup;
	}
	if (argv[3] == NULL)
		goto cleanup;

	/*
	 * argv[4] is the load balance mode, DSR, NAT, HALF-NAT.
	 */
	if ((argv[4] = strdup(topo_2_str(rule->irl_topo))) == NULL)
		goto cleanup;

	/*
	 * argv[5] is the port range.  Right now, there should only be 1 port.
	 */
	switch (rule->irl_hcpflag) {
	case ILB_HCI_PROBE_FIX:
		port = ntohs(rule->irl_hcport);
		break;
	case ILB_HCI_PROBE_ANY: {
		in_port_t min, max;

		if (ntohs(sg_srv->sgs_minport) == 0) {
			min = ntohs(rule->irl_minport);
			max = ntohs(rule->irl_maxport);
		} else {
			min = ntohs(sg_srv->sgs_minport);
			max = ntohs(sg_srv->sgs_maxport);
		}
		if (max > min)
			port = min + gethrtime() % (max - min + 1);
		else
			port = min;
		break;
	}
	default:
		logerr("%s: unknown HC flag", __func__);
		goto cleanup;
	}
	(void) sprintf(buf, "%d", port);
	if ((argv[5] = strdup(buf)) == NULL)
		goto cleanup;

	/*
	 * argv[6] is the probe timeout.
	 */
	(void) sprintf(buf, "%d", srv->shc_hc->ihc_timeout);
	if ((argv[6] = strdup(buf)) == NULL)
		goto cleanup;

	argv[7] = NULL;
	return (B_TRUE);

cleanup:
	for (i = 0; i < HC_PROBE_ARGC; i++) {
		if (argv[i] != NULL)
			free(argv[i]);
	}
	return (B_FALSE);
}

static void
destroy_argv(char *argv[])
{
	int i;

	for (i = 0; argv[i] != NULL; i++)
		free(argv[i]);
}

/* Spawn a process to run the hc probe on the given server. */
static boolean_t
ilbd_run_probe(ilbd_hc_srv_t *srv)
{
	posix_spawn_file_actions_t	fd_actions;
	posix_spawnattr_t		attr;
	sigset_t			child_sigset;
	int				fds[2];
	int				fdflags;
	pid_t				pid;
	char				*child_argv[HC_PROBE_ARGC];
	ilbd_hc_probe_event_t		*probe_ev;
	char				*probe_name;

	bzero(child_argv, HC_PROBE_ARGC * sizeof (char *));
	if ((probe_ev = calloc(1, sizeof (*probe_ev))) == NULL) {
		logdebug("ilbd_run_probe: calloc");
		return (B_FALSE);
	}

	/* Set up a pipe to get output from probe command. */
	if (pipe(fds) < 0) {
		logdebug("ilbd_run_probe: cannot create pipe");
		free(probe_ev);
		return (B_FALSE);
	}
	/* Set our side of the pipe to be non-blocking */
	if ((fdflags = fcntl(fds[0], F_GETFL, 0)) == -1) {
		logdebug("ilbd_run_probe: fcntl(F_GETFL)");
		goto cleanup;
	}
	if (fcntl(fds[0], F_SETFL, fdflags | O_NONBLOCK) == -1) {
		logdebug("ilbd_run_probe: fcntl(F_SETFL)");
		goto cleanup;
	}

	if (posix_spawn_file_actions_init(&fd_actions) != 0) {
		logdebug("ilbd_run_probe: posix_spawn_file_actions_init");
		goto cleanup;
	}
	if (posix_spawnattr_init(&attr) != 0) {
		logdebug("ilbd_run_probe: posix_spawnattr_init");
		goto cleanup;
	}
	if (posix_spawn_file_actions_addclose(&fd_actions, fds[0]) != 0) {
		logdebug("ilbd_run_probe: posix_spawn_file_actions_addclose");
		goto cleanup;
	}
	if (posix_spawn_file_actions_adddup2(&fd_actions, fds[1],
	    STDOUT_FILENO) != 0) {
		logdebug("ilbd_run_probe: posix_spawn_file_actions_dup2");
		goto cleanup;
	}
	if (posix_spawn_file_actions_addclose(&fd_actions, fds[1]) != 0) {
		logdebug("ilbd_run_probe: posix_spawn_file_actions_addclose");
		goto cleanup;
	}

	/* Reset all signal handling of the child to default. */
	(void) sigfillset(&child_sigset);
	if (posix_spawnattr_setsigdefault(&attr, &child_sigset) != 0) {
		logdebug("ilbd_run_probe: posix_spawnattr_setsigdefault");
		goto cleanup;
	}
	/* Don't want SIGCHLD. */
	if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_NOSIGCHLD_NP|
	    POSIX_SPAWN_SETSIGDEF) != 0) {
		logdebug("ilbd_run_probe: posix_spawnattr_setflags");
		goto cleanup;
	}

	if (!create_argv(srv, child_argv)) {
		logdebug("ilbd_run_probe: create_argv");
		goto cleanup;
	}

	/*
	 * If we are doing default pinging or not using a user supplied
	 * probe, we should execute our standard supplied probe.  The
	 * supplied probe command handles all types of probes.  And the
	 * type used depends on argv[0], as filled in by create_argv().
	 */
	if (srv->shc_state == ilbd_hc_def_pinging ||
	    srv->shc_hc->ihc_test_type != ILBD_HC_USER) {
		probe_name = ILB_PROBE_PROTO;
	} else {
		probe_name = srv->shc_hc->ihc_test;
	}
	if (posix_spawn(&pid, probe_name, &fd_actions, &attr, child_argv,
	    NULL) != 0) {
		logerr("%s: posix_spawn: %s for server %s: %s", __func__,
		    srv->shc_hc->ihc_test, srv->shc_sg_srv->sgs_srvID,
		    strerror(errno));
		goto cleanup;
	}

	(void) close(fds[1]);
	destroy_argv(child_argv);
	srv->shc_child_pid = pid;
	srv->shc_child_fd = fds[0];
	srv->shc_ev = probe_ev;

	probe_ev->ihp_ev = ILBD_EVENT_PROBE;
	probe_ev->ihp_srv = srv;
	probe_ev->ihp_pid = pid;
	if (port_associate(srv->shc_ev_port, PORT_SOURCE_FD, fds[0],
	    POLLRDNORM, probe_ev) != 0) {
		/*
		 * Need to kill the child.  It will free the srv->shc_ev,
		 * which is probe_ev.  So set probe_ev to NULL.
		 */
		ilbd_hc_kill_probe(srv);
		probe_ev = NULL;
		goto cleanup;
	}

	return (B_TRUE);

cleanup:
	(void) close(fds[0]);
	(void) close(fds[1]);
	destroy_argv(child_argv);
	if (probe_ev != NULL)
		free(probe_ev);
	return (B_FALSE);
}

/*
 * Called by ild_hc_probe_return() to re-associate the fd to a child to
 * the event port.
 */
static void
reassociate_port(int ev_port, int fd, ilbd_hc_probe_event_t *ev)
{
	if (port_associate(ev_port, PORT_SOURCE_FD, fd,
	    POLLRDNORM, ev) != 0) {
		/*
		 * If we cannot reassociate with the port, the only
		 * thing we can do now is to kill the child and
		 * do a blocking wait here...
		 */
		logdebug("%s: port_associate: %s", __func__, strerror(errno));
		if (kill(ev->ihp_pid, SIGKILL) != 0)
			logerr("%s: kill: %s", __func__, strerror(errno));
		if (waitpid(ev->ihp_pid, NULL, 0) != ev->ihp_pid)
			logdebug("%s: waitpid: %s", __func__, strerror(errno));
		free(ev);
	}
}

/*
 * To handle a child probe process hanging up.
 */
static void
ilbd_hc_child_hup(int ev_port, int fd, ilbd_hc_probe_event_t *ev)
{
	ilbd_hc_srv_t *srv;
	pid_t ret_pid;
	int ret;

	srv = ev->ihp_srv;

	if (!ev->ihp_done) {
		/* ilbd does not care about this process anymore ... */
		ev->ihp_done = B_TRUE;
		srv->shc_ev = NULL;
		srv->shc_child_pid = 0;
		HC_CANCEL_TIMER(srv);
		ilbd_set_fail_state(srv);
	}
	ret_pid = waitpid(ev->ihp_pid, &ret, WNOHANG);
	switch (ret_pid) {
	case -1:
		logperror("ilbd_hc_child_hup: waitpid");
		/* FALLTHROUGH */
	case 0:
		/* The child has not completed the exit. Wait again. */
		reassociate_port(ev_port, fd, ev);
		break;
	default:
		/* Right now, we just ignore the exit status. */
		if (WIFEXITED(ret))
			ret = WEXITSTATUS(ret);
		(void) close(fd);
		free(ev);
	}
}

/*
 * To read the output of a child probe process.
 */
static void
ilbd_hc_child_data(int fd, ilbd_hc_probe_event_t *ev)
{
	ilbd_hc_srv_t *srv;
	char buf[HC_MAX_PROBE_OUTPUT];
	int ret;
	int64_t rtt;

	srv = ev->ihp_srv;

	bzero(buf, HC_MAX_PROBE_OUTPUT);
	ret = read(fd, buf, HC_MAX_PROBE_OUTPUT - 1);
	/* Should not happen since event port should have caught this. */
	assert(ret > 0);

	/*
	 * We expect the probe command to print out the RTT only.  But
	 * the command may misbehave and print out more than what we intend to
	 * read in.  So need to do this check below to "flush" out all the
	 * output from the command.
	 */
	if (!ev->ihp_done) {
		ev->ihp_done = B_TRUE;
		/* We don't need to know about this event anymore. */
		srv->shc_ev = NULL;
		srv->shc_child_pid = 0;
		HC_CANCEL_TIMER(srv);
	} else {
		return;
	}

	rtt = strtoll(buf, NULL, 10);

	/*
	 * -1 means the server is dead or the probe somehow fails.  Treat
	 * them both as server is dead.
	 */
	if (rtt == -1) {
		ilbd_set_fail_state(srv);
		return;
	} else if (rtt > 0) {
		/* If the returned RTT value is not valid, just ignore it. */
		if (rtt > 0 && rtt <= UINT_MAX) {
			/* Set rtt to be the simple smoothed average. */
			if (srv->shc_rtt == 0) {
				srv->shc_rtt = rtt;
			} else {
				srv->shc_rtt = 3 * ((srv)->shc_rtt >> 2) +
				    (rtt >> 2);
			}
		}

	}

	switch (srv->shc_state) {
	case ilbd_hc_def_pinging:
		srv->shc_state = ilbd_hc_probing;

		/* Ping is OK, now start the probe. */
		ilbd_hc_probe_timer(ilbd_hc_timer_q, srv);
		break;
	case ilbd_hc_probing:
		srv->shc_fail_cnt = 0;

		/* Server is dead before, re-enable it. */
		if (srv->shc_status == ILB_HCS_UNREACH ||
		    srv->shc_status == ILB_HCS_DEAD) {
			/*
			 * If enabling the server in kernel fails now,
			 * hopefully when the timer fires again later, the
			 * enabling can be done.
			 */
			if (ilbd_k_Xable_server(&srv->shc_sg_srv->sgs_addr,
			    srv->shc_hc_rule->hcr_rule->irl_name,
			    stat_declare_srv_alive) != ILB_STATUS_OK) {
				logerr("%s: cannot enable server in kernel: "
				    " rule %s server %s", __func__,
				    srv->shc_hc_rule->hcr_rule->irl_name,
				    srv->shc_sg_srv->sgs_srvID);
			} else {
				srv->shc_status = ILB_HCS_ALIVE;
			}
		} else {
			srv->shc_status = ILB_HCS_ALIVE;
		}
		if (ilbd_hc_restart_timer(srv->shc_hc, srv) != ILB_STATUS_OK) {
			logerr("%s: cannot restart timer: rule %s server %s",
			    __func__, srv->shc_hc_rule->hcr_rule->irl_name,
			    srv->shc_sg_srv->sgs_srvID);
			ilbd_mark_server_disabled(srv);
		}
		break;
	default:
		logdebug("%s: unknown state", __func__);
		break;
	}
}

/*
 * Handle the return event of a child probe fd.
 */
void
ilbd_hc_probe_return(int ev_port, int fd, int port_events,
    ilbd_hc_probe_event_t *ev)
{
	/*
	 * Note that there can be more than one events delivered to us at
	 * the same time.  So we need to check them individually.
	 */
	if (port_events & POLLRDNORM)
		ilbd_hc_child_data(fd, ev);

	if (port_events & (POLLHUP|POLLERR)) {
		ilbd_hc_child_hup(ev_port, fd, ev);
		return;
	}

	/*
	 * Re-associate the fd with the port so that when the child
	 * exits, we can reap the status.
	 */
	reassociate_port(ev_port, fd, ev);
}
