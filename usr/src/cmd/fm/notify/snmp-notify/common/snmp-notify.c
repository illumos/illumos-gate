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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/fm/protocol.h>
#include <fm/fmd_snmp.h>
#include <fm/fmd_msg.h>
#include <fm/libfmevent.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <errno.h>
#include <locale.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <alloca.h>
#include <priv_utils.h>
#include <zone.h>
#include "libfmnotify.h"

/*
 * Debug messages can be enabled by setting the debug property to true
 *
 * # svccfg -s svc:/system/fm/snmp-notify setprop config/debug=true
 */
#define	SVCNAME		"system/fm/snmp-notify"

typedef struct ireport_trap {
	char *host;
	char *msgid;
	char *desc;
	long long tstamp;
	char *fmri;
	uint32_t from_state;
	uint32_t to_state;
	char *reason;
	boolean_t is_stn_event;
} ireport_trap_t;

static nd_hdl_t *nhdl;
static const char optstr[] = "dfR:";
static const char SNMP_SUPPCONF[] = "fmd-trapgen";
static char hostname[MAXHOSTNAMELEN + 1];

static int
usage(const char *pname)
{
	(void) fprintf(stderr, "Usage: %s [-df] [-R <altroot>]\n", pname);

	(void) fprintf(stderr,
	    "\t-d  enable debug mode\n"
	    "\t-f  stay in foreground\n"
	    "\t-R  specify alternate root\n");

	return (1);
}

/*
 * If someone does an "svcadm refresh" on us, then this function gets called,
 * which rereads our service configuration.
 */
static void
get_svc_config()
{
	int s = 0;
	uint8_t val;

	s = nd_get_boolean_prop(nhdl, SVCNAME, "config", "debug", &val);
	nhdl->nh_debug = val;

	s += nd_get_astring_prop(nhdl, SVCNAME, "config", "rootdir",
	    &(nhdl->nh_rootdir));

	if (s != 0)
		nd_error(nhdl, "Failed to read retrieve service "
		    "properties");
}

static void
nd_sighandler(int sig)
{
	if (sig == SIGHUP)
		get_svc_config();
	else
		nd_cleanup(nhdl);
}

static int
get_snmp_prefs(nd_hdl_t *nhdl, nvlist_t **pref_nvl, uint_t npref)
{
	boolean_t *a1, *a2;
	uint_t n;
	int r;

	/*
	 * For SMF state transition events, pref_nvl contain two sets of
	 * preferences, which will have to be merged.
	 *
	 * The "snmp" nvlist currently only supports a single boolean member,
	 * "active" which will be set to true, if it is true in either set
	 */
	if (npref == 2) {
		r = nvlist_lookup_boolean_array(pref_nvl[0], "active", &a1, &n);
		r += nvlist_lookup_boolean_array(pref_nvl[1], "active", &a2,
		    &n);
		if (r != 0) {
			nd_debug(nhdl, "Malformed snmp notification "
			    "preferences");
			nd_dump_nvlist(nhdl, pref_nvl[0]);
			nd_dump_nvlist(nhdl, pref_nvl[1]);
			return (-1);
		} else if (!a1[0] && !a2[0]) {
			nd_debug(nhdl, "SNMP notification is disabled");
			return (-1);
		}
	} else {
		if (nvlist_lookup_boolean_array(pref_nvl[0], "active",
		    &a1, &n)) {
			nd_debug(nhdl, "Malformed snmp notification "
			    "preferences");
			nd_dump_nvlist(nhdl, pref_nvl[0]);
			return (-1);
		} else if (!a1[0]) {
			nd_debug(nhdl, "SNMP notification is disabled");
			return (-1);
		}
	}
	return (0);
}

static void
send_ireport_trap(ireport_trap_t *t)
{
	static const oid sunIreportTrap_oid[] =
	    { SUNIREPORTTRAP_OID };
	const size_t sunIreportTrap_len =
	    OID_LENGTH(sunIreportTrap_oid);

	static const oid sunIreportHostname_oid[] =
	    { SUNIREPORTHOSTNAME_OID };
	static const oid sunIreportMsgid_oid[] =
	    { SUNIREPORTMSGID_OID };
	static const oid sunIreportDescription_oid[] =
	    { SUNIREPORTDESCRIPTION_OID };
	static const oid sunIreportTime_oid[] =
	    { SUNIREPORTTIME_OID };

	static const oid sunIreportSmfFmri_oid[] =
	    { SUNIREPORTSMFFMRI_OID };
	static const oid sunIreportSmfFromState_oid[] =
	    { SUNIREPORTSMFFROMSTATE_OID };
	static const oid sunIreportSmfToState_oid[] =
	    { SUNIREPORTSMFTOSTATE_OID };
	static const oid sunIreportSmfTransitionReason_oid[] =
	    { SUNIREPORTTRANSITIONREASON_OID };
	const size_t
	    sunIreport_base_len = OID_LENGTH(sunIreportHostname_oid);

	size_t var_len = sunIreport_base_len + 1;
	oid var_name[MAX_OID_LEN];

	netsnmp_variable_list *notification_vars = NULL;

	size_t dt_len;
	uchar_t dt[11], *tdt;
	time_t ts = t->tstamp;

	tdt = date_n_time(&ts, &dt_len);
	/*
	 * We know date_n_time is broken, it returns a buffer from
	 * its stack. So we copy before we step over it!
	 */
	for (int i = 0; i < dt_len; ++i)
		dt[i] = tdt[i];

	if (var_len > MAX_OID_LEN) {
		nd_error(nhdl, "var_len %d > MAX_OID_LEN %d\n", var_len,
		    MAX_OID_LEN);
		return;
	}

	(void) memcpy(var_name, sunIreportHostname_oid, sunIreport_base_len *
	    sizeof (oid));
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    sunIreport_base_len + 1, ASN_OCTET_STR, (uchar_t *)t->host,
	    strlen(t->host));

	(void) memcpy(var_name, sunIreportMsgid_oid,
	    sunIreport_base_len * sizeof (oid));
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    sunIreport_base_len + 1, ASN_OCTET_STR, (uchar_t *)t->msgid,
	    strlen(t->msgid));

	(void) memcpy(var_name, sunIreportDescription_oid,
	    sunIreport_base_len * sizeof (oid));
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    sunIreport_base_len + 1, ASN_OCTET_STR, (uchar_t *)t->desc,
	    strlen(t->desc));

	(void) memcpy(var_name, sunIreportTime_oid, sunIreport_base_len *
	    sizeof (oid));
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    sunIreport_base_len + 1, ASN_OCTET_STR, dt, dt_len);

	if (t->is_stn_event) {
		(void) memcpy(var_name, sunIreportSmfFmri_oid,
		    sunIreport_base_len * sizeof (oid));
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    sunIreport_base_len + 1, ASN_OCTET_STR, (uchar_t *)t->fmri,
		    strlen(t->fmri));

		(void) memcpy(var_name, sunIreportSmfFromState_oid,
		    sunIreport_base_len * sizeof (oid));
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    sunIreport_base_len + 1, ASN_INTEGER,
		    (uchar_t *)&t->from_state, sizeof (uint32_t));

		(void) memcpy(var_name, sunIreportSmfToState_oid,
		    sunIreport_base_len * sizeof (oid));
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    sunIreport_base_len + 1, ASN_INTEGER,
		    (uchar_t *)&t->to_state, sizeof (uint32_t));

		(void) memcpy(var_name, sunIreportSmfTransitionReason_oid,
		    sunIreport_base_len * sizeof (oid));
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    sunIreport_base_len + 1, ASN_OCTET_STR,
		    (uchar_t *)t->reason, strlen(t->reason));
	}

	/*
	 * This function is capable of sending both v1 and v2/v3 traps.
	 * Which is sent to a specific destination is determined by the
	 * configuration file(s).
	 */
	send_enterprise_trap_vars(SNMP_TRAP_ENTERPRISESPECIFIC,
	    sunIreportTrap_oid[sunIreportTrap_len - 1],
	    (oid *)sunIreportTrap_oid, sunIreportTrap_len - 2,
	    notification_vars);
	nd_debug(nhdl, "Sent SNMP trap for %s", t->msgid);

	snmp_free_varbind(notification_vars);

}

/*ARGSUSED*/
static void
send_fm_trap(const char *uuid, const char *code, const char *url)
{
	static const oid sunFmProblemTrap_oid[] = { SUNFMPROBLEMTRAP_OID };
	const size_t sunFmProblemTrap_len = OID_LENGTH(sunFmProblemTrap_oid);

	static const oid sunFmProblemUUID_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_UUID };
	static const oid sunFmProblemCode_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_CODE };
	static const oid sunFmProblemURL_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_URL };

	const size_t sunFmProblem_base_len = OID_LENGTH(sunFmProblemUUID_oid);

	size_t uuid_len = strlen(uuid);
	size_t var_len = sunFmProblem_base_len + 1 + uuid_len;
	oid var_name[MAX_OID_LEN];

	netsnmp_variable_list *notification_vars = NULL;

	/*
	 * The format of our trap varbinds' oids is as follows:
	 *
	 * +-----------------------+---+--------+----------+------+
	 * | SUNFMPROBLEMTABLE_OID | 1 | column | uuid_len | uuid |
	 * +-----------------------+---+--------+----------+------+
	 *					 \---- index ----/
	 *
	 * A common mistake here is to send the trap with varbinds that
	 * do not contain the index.  All the indices are the same, and
	 * all the oids are the same length, so the only thing we need to
	 * do for each varbind is set the table and column parts of the
	 * variable name.
	 */

	if (var_len > MAX_OID_LEN)
		return;

	var_name[sunFmProblem_base_len] = (oid)uuid_len;
	for (int i = 0; i < uuid_len; i++)
		var_name[i + sunFmProblem_base_len + 1] = (oid)uuid[i];

	/*
	 * Ordinarily, we would need to add the OID of the trap itself
	 * to the head of the variable list; this is required by SNMP v2.
	 * However, send_enterprise_trap_vars does this for us as a part
	 * of converting between v1 and v2 traps, so we skip directly to
	 * the objects we're sending.
	 */

	(void) memcpy(var_name, sunFmProblemUUID_oid,
	    sunFmProblem_base_len * sizeof (oid));
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)uuid, strlen(uuid));
	(void) memcpy(var_name, sunFmProblemCode_oid,
	    sunFmProblem_base_len * sizeof (oid));
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)code, strlen(code));
	(void) memcpy(var_name, sunFmProblemURL_oid,
	    sunFmProblem_base_len * sizeof (oid));
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)url, strlen(url));

	/*
	 * This function is capable of sending both v1 and v2/v3 traps.
	 * Which is sent to a specific destination is determined by the
	 * configuration file(s).
	 */
	send_enterprise_trap_vars(SNMP_TRAP_ENTERPRISESPECIFIC,
	    sunFmProblemTrap_oid[sunFmProblemTrap_len - 1],
	    (oid *)sunFmProblemTrap_oid, sunFmProblemTrap_len - 2,
	    notification_vars);
	nd_debug(nhdl, "Sent SNMP trap for %s", code);

	snmp_free_varbind(notification_vars);
}

/*
 * The SUN-IREPORT-MIB declares the following enum to represent SMF service
 * states.
 *
 * offline(0), online(1), degraded(2), disabled(3), maintenance(4),
 * uninitialized(5)
 *
 * This function converts a string representation of an SMF service state
 * to it's corresponding enum val.
 */
static int
state_to_val(char *statestr, uint32_t *stateval)
{
	if (strcmp(statestr, "offline") == 0)
		*stateval = 0;
	else if (strcmp(statestr, "online") == 0)
		*stateval = 1;
	else if (strcmp(statestr, "degraded") == 0)
		*stateval = 2;
	else if (strcmp(statestr, "disabled") == 0)
		*stateval = 3;
	else if (strcmp(statestr, "maintenance") == 0)
		*stateval = 4;
	else if (strcmp(statestr, "uninitialized") == 0)
		*stateval = 5;
	else
		return (-1);
	return (0);
}

/*ARGSUSED*/
static void
ireport_cb(fmev_t ev, const char *class, nvlist_t *nvl, void *arg)
{
	nvlist_t **pref_nvl = NULL;
	nd_ev_info_t *ev_info = NULL;
	ireport_trap_t swtrap;
	uint_t npref;
	int ret;

	nd_debug(nhdl, "Received event of class %s", class);

	ret = nd_get_notify_prefs(nhdl, "snmp", ev, &pref_nvl, &npref);
	if (ret == SCF_ERROR_NOT_FOUND) {
		/*
		 * No snmp notification preferences specified for this type of
		 * event, so we're done
		 */
		return;
	} else if (ret != 0) {
		nd_error(nhdl, "Failed to retrieve notification preferences "
		    "for this event");
		return;
	}

	if (get_snmp_prefs(nhdl, pref_nvl, npref) != 0)
		goto irpt_done;

	if (nd_get_event_info(nhdl, class, ev, &ev_info) != 0)
		goto irpt_done;

	swtrap.host = hostname;
	swtrap.msgid = ev_info->ei_diagcode;
	swtrap.desc = ev_info->ei_descr;
	swtrap.tstamp = (time_t)fmev_time_sec(ev);

	if (strncmp(class, "ireport.os.smf", 14) == 0) {
		swtrap.fmri = ev_info->ei_fmri;
		if (state_to_val(ev_info->ei_from_state, &swtrap.from_state)
		    < 0 ||
		    state_to_val(ev_info->ei_to_state, &swtrap.to_state) < 0) {
			nd_error(nhdl, "Malformed event - invalid svc state");
			nd_dump_nvlist(nhdl, ev_info->ei_payload);
			goto irpt_done;
		}
		swtrap.reason = ev_info->ei_reason;
		swtrap.is_stn_event = B_TRUE;
	}
	send_ireport_trap(&swtrap);
irpt_done:
	if (ev_info)
		nd_free_event_info(ev_info);
	nd_free_nvlarray(pref_nvl, npref);
}

/*ARGSUSED*/
static void
list_cb(fmev_t ev, const char *class, nvlist_t *nvl, void *arg)
{
	char *uuid;
	uint8_t version;
	nd_ev_info_t *ev_info = NULL;
	nvlist_t **pref_nvl = NULL;
	uint_t npref;
	int ret;
	boolean_t domsg;

	nd_debug(nhdl, "Received event of class %s", class);

	ret = nd_get_notify_prefs(nhdl, "snmp", ev, &pref_nvl, &npref);
	if (ret == SCF_ERROR_NOT_FOUND) {
		/*
		 * No snmp notification preferences specified for this type of
		 * event, so we're done
		 */
		return;
	} else if (ret != 0) {
		nd_error(nhdl, "Failed to retrieve notification preferences "
		    "for this event");
		return;
	}

	if (get_snmp_prefs(nhdl, pref_nvl, npref) != 0)
		goto listcb_done;

	if (nd_get_event_info(nhdl, class, ev, &ev_info) != 0)
		goto listcb_done;

	/*
	 * If the message payload member is set to 0, then it's an event we
	 * typically suppress messaging on, so we won't send a trap for it.
	 */
	if (nvlist_lookup_boolean_value(ev_info->ei_payload, FM_SUSPECT_MESSAGE,
	    &domsg) == 0 && !domsg) {
		nd_debug(nhdl, "Messaging suppressed for this event");
		goto listcb_done;
	}

	if (nvlist_lookup_uint8(ev_info->ei_payload, FM_VERSION, &version)
	    != 0 || version > FM_SUSPECT_VERSION) {
		nd_error(nhdl, "invalid event version: %u", version);
		goto listcb_done;
	}

	(void) nvlist_lookup_string(ev_info->ei_payload, FM_SUSPECT_UUID,
	    &uuid);

	if (strcmp(ev_info->ei_url, ND_UNKNOWN) != 0)
		send_fm_trap(uuid, ev_info->ei_diagcode, ev_info->ei_url);
	else
		nd_error(nhdl, "failed to format url for %s", uuid);
listcb_done:
	nd_free_nvlarray(pref_nvl, npref);
	if (ev_info)
		nd_free_event_info(ev_info);
}

static int
init_sma(void)
{
	int err;

	/*
	 * The only place we could possibly log is syslog, but the
	 * full agent doesn't normally log there.  It would be confusing
	 * if this agent did so; therefore we disable logging entirely.
	 */
	snmp_disable_log();

	/*
	 * Net-SNMP has a provision for reading an arbitrary number of
	 * configuration files.  A configuration file is read if it has
	 * had any handlers registered for it, or if it's the value in
	 * of NETSNMP_DS_LIB_APPTYPE.  Our objective here is to read
	 * both snmpd.conf and fmd-trapgen.conf.
	 */
	if ((err = netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
	    NETSNMP_DS_AGENT_ROLE, 0 /* MASTER_AGENT */)) != SNMPERR_SUCCESS)
		return (err);

	init_agent_read_config("snmpd");
	if ((err = netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
	    NETSNMP_DS_LIB_APPTYPE, SNMP_SUPPCONF)) != SNMPERR_SUCCESS)
		return (err);
	if (register_app_config_handler("trapsink", snmpd_parse_config_trapsink,
	    snmpd_free_trapsinks, "host [community] [port]") == NULL)
		return (SNMPERR_MALLOC);
	if (register_app_config_handler("trap2sink",
	    snmpd_parse_config_trap2sink, NULL, "host [community] [port]") ==
	    NULL)
		return (SNMPERR_MALLOC);
	if (register_app_config_handler("trapsess", snmpd_parse_config_trapsess,
	    NULL, "[snmpcmdargs] host") == NULL)
		return (SNMPERR_MALLOC);

	init_traps();
	init_snmp(SNMP_SUPPCONF);

	return (SNMPERR_SUCCESS);
}

int
main(int argc, char *argv[])
{
	struct rlimit rlim;
	struct sigaction act;
	sigset_t set;
	char c;
	boolean_t run_fg = B_FALSE;

	if ((nhdl = malloc(sizeof (nd_hdl_t))) == NULL) {
		(void) fprintf(stderr, "Failed to allocate space for notifyd "
		    "handle (%s)", strerror(errno));
		return (1);
	}
	bzero(nhdl, sizeof (nd_hdl_t));
	nhdl->nh_keep_running = B_TRUE;
	nhdl->nh_log_fd = stderr;
	nhdl->nh_pname = argv[0];

	get_svc_config();

	/*
	 * In the case where we get started outside of SMF, args passed on the
	 * command line override SMF property setting
	 */
	while (optind < argc) {
		while ((c = getopt(argc, argv, optstr)) != -1) {
			switch (c) {
			case 'd':
				nhdl->nh_debug = B_TRUE;
				break;
			case 'f':
				run_fg = B_TRUE;
				break;
			case 'R':
				nhdl->nh_rootdir = strdup(optarg);
				break;
			default:
				free(nhdl);
				return (usage(argv[0]));
			}
		}
	}

	/*
	 * Set up a signal handler for SIGTERM (and SIGINT if we'll
	 * be running in the foreground) to ensure sure we get a chance to exit
	 * in an orderly fashion.  We also catch SIGHUP, which will be sent to
	 * us by SMF if the service is refreshed.
	 */
	(void) sigfillset(&set);
	(void) sigfillset(&act.sa_mask);
	act.sa_handler = nd_sighandler;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigdelset(&set, SIGTERM);
	(void) sigaction(SIGHUP, &act, NULL);
	(void) sigdelset(&set, SIGHUP);

	if (run_fg) {
		(void) sigaction(SIGINT, &act, NULL);
		(void) sigdelset(&set, SIGINT);
	} else
		nd_daemonize(nhdl);

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	(void) setrlimit(RLIMIT_CORE, &rlim);

	/*
	 * We need to be root initialize our libfmevent handle (because that
	 * involves reading/writing to /dev/sysevent), so we do this before
	 * calling __init_daemon_priv.
	 */
	nhdl->nh_evhdl = fmev_shdl_init(LIBFMEVENT_VERSION_2, NULL, NULL, NULL);
	if (nhdl->nh_evhdl == NULL) {
		(void) sleep(5);
		nd_abort(nhdl, "failed to initialize libfmevent: %s",
		    fmev_strerror(fmev_errno));
	}

	/*
	 * If we're in the global zone, reset all of our privilege sets to
	 * the minimum set of required privileges.   We also change our
	 * uid/gid to noaccess/noaccess
	 *
	 * __init_daemon_priv will also set the process core path for us
	 *
	 */
	if (getzoneid() == GLOBAL_ZONEID)
		if (__init_daemon_priv(
		    PU_RESETGROUPS | PU_LIMITPRIVS | PU_INHERITPRIVS,
		    60002, 60002, PRIV_FILE_DAC_READ, NULL) != 0)
			nd_abort(nhdl, "additional privileges required to run");

	nhdl->nh_msghdl = fmd_msg_init(nhdl->nh_rootdir, FMD_MSG_VERSION);
	if (nhdl->nh_msghdl == NULL)
		nd_abort(nhdl, "failed to initialize libfmd_msg");

	if (init_sma() != SNMPERR_SUCCESS)
		nd_abort(nhdl, "SNMP initialization failed");

	(void) gethostname(hostname, MAXHOSTNAMELEN + 1);
	/*
	 * Set up our event subscriptions.  We subscribe to everything and then
	 * consult libscf when we receive an event to determine what (if any)
	 * notification to send.
	 */
	nd_debug(nhdl, "Subscribing to ireport.os.smf.* events");
	if (fmev_shdl_subscribe(nhdl->nh_evhdl, "ireport.os.smf.*",
	    ireport_cb, NULL) != FMEV_SUCCESS) {
		nd_abort(nhdl, "fmev_shdl_subscribe failed: %s",
		    fmev_strerror(fmev_errno));
	}

	nd_debug(nhdl, "Subscribing to list.* events");
	if (fmev_shdl_subscribe(nhdl->nh_evhdl, "list.*", list_cb,
	    NULL) != FMEV_SUCCESS) {
		nd_abort(nhdl, "fmev_shdl_subscribe failed: %s",
		    fmev_strerror(fmev_errno));
	}

	/*
	 * We run until someone kills us
	 */
	while (nhdl->nh_keep_running)
		(void) sigsuspend(&set);

	/*
	 * snmp_shutdown, which we would normally use here, calls free_slots,
	 * a callback that is supposed to tear down the pkcs11 state; however,
	 * it abuses C_Finalize, causing fmd to drop core on shutdown.  Avoid
	 * this by shutting down the library piecemeal.
	 */
	snmp_store(SNMP_SUPPCONF);
	snmp_alarm_unregister_all();
	(void) snmp_close_sessions();
	shutdown_mib();
	unregister_all_config_handlers();
	netsnmp_ds_shutdown();

	free(nhdl->nh_rootdir);
	free(nhdl);

	return (0);
}
