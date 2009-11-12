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
 */

#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>
#include <fm/fmd_snmp.h>
#include <fm/fmd_msg.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <locale.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <alloca.h>

static struct stats {
	fmd_stat_t bad_vers;
	fmd_stat_t bad_code;
	fmd_stat_t bad_uuid;
	fmd_stat_t no_trap;
} snmp_stats = {
	{ "bad_vers", FMD_TYPE_UINT64, "event version is missing or invalid" },
	{ "bad_code", FMD_TYPE_UINT64, "failed to compute url for code" },
	{ "bad_uuid", FMD_TYPE_UINT64, "event uuid is too long to send" },
	{ "no_trap", FMD_TYPE_UINT64, "trap generation suppressed" }
};

static fmd_msg_hdl_t *snmp_msghdl;	/* handle for libfmd_msg */
static int snmp_trapall;		/* set to trap on all faults */

static const char SNMP_SUPPCONF[] = "fmd-trapgen";

/*ARGSUSED*/
static void
send_trap(fmd_hdl_t *hdl, const char *uuid, const char *code, const char *url)
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
	int i;

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

	if (var_len > MAX_OID_LEN) {
		snmp_stats.bad_uuid.fmds_value.ui64++;
		return;
	}

	var_name[sunFmProblem_base_len] = (oid)uuid_len;
	for (i = 0; i < uuid_len; i++)
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

	snmp_free_varbind(notification_vars);
}

/*ARGSUSED*/
static void
snmp_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	char *uuid, *code, *url;
	boolean_t domsg;
	uint8_t version;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_SUSPECT_VERSION) {
		fmd_hdl_debug(hdl, "invalid event version: %u\n", version);
		snmp_stats.bad_vers.fmds_value.ui64++;
		return;
	}

	if (!snmp_trapall && nvlist_lookup_boolean_value(nvl,
	    FM_SUSPECT_MESSAGE, &domsg) == 0 && !domsg) {
		fmd_hdl_debug(hdl, "%s requested no trap\n", class);
		snmp_stats.no_trap.fmds_value.ui64++;
		return;
	}

	(void) nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid);
	(void) nvlist_lookup_string(nvl, FM_SUSPECT_DIAG_CODE, &code);

	url = fmd_msg_getitem_nv(snmp_msghdl, NULL, nvl, FMD_MSG_ITEM_URL);

	if (url != NULL) {
		send_trap(hdl, uuid, code, url);
		free(url);
	} else {
		fmd_hdl_debug(hdl, "failed to format url for %s", uuid);
		snmp_stats.bad_code.fmds_value.ui64++;
	}
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

static const fmd_prop_t fmd_props[] = {
	{ "url", FMD_TYPE_STRING, "http://sun.com/msg/" },
	{ "trap_all", FMD_TYPE_BOOL, "false" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_ops = {
	snmp_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
};

static const fmd_hdl_info_t fmd_info = {
	"SNMP Trap Generation Agent", "1.0", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	char *rootdir, *urlbase;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* invalid data in configuration file */

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (snmp_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&snmp_stats);

	if (init_sma() != SNMPERR_SUCCESS)
		fmd_hdl_abort(hdl, "snmp-trapgen agent initialization failed");

	rootdir = fmd_prop_get_string(hdl, "fmd.rootdir");
	snmp_msghdl = fmd_msg_init(rootdir, FMD_MSG_VERSION);
	fmd_prop_free_string(hdl, rootdir);

	if (snmp_msghdl == NULL)
		fmd_hdl_abort(hdl, "failed to initialize libfmd_msg");

	urlbase = fmd_prop_get_string(hdl, "url");
	(void) fmd_msg_url_set(snmp_msghdl, urlbase);
	fmd_prop_free_string(hdl, urlbase);

	snmp_trapall = fmd_prop_get_int32(hdl, "trap_all");
	fmd_hdl_subscribe(hdl, FM_LIST_SUSPECT_CLASS);
	fmd_hdl_subscribe(hdl, FM_LIST_REPAIRED_CLASS);
	fmd_hdl_subscribe(hdl, FM_LIST_RESOLVED_CLASS);
}

/*ARGSUSED*/
void
_fmd_fini(fmd_hdl_t *hdl)
{
	fmd_msg_fini(snmp_msghdl);

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
}
