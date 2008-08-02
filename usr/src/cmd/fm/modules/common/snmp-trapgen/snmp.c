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

/*
 * SNMP_DOMAIN defines the dgettext() parameters the agent
 * can use to retrieve the localized format string for diagnosis messages.
 * The format string retrieved from SNMP_DOMAIN is the default format
 * string, but when processing each suspect list, dgettext() is also called
 * for the domain that matches the diagcode dictname.
 *
 * Similarly, SNMP_URL is also checked to see if snmp_url
 * should be overridden for each suspect list.
 *
 * The net effect of all this is that for a given diagcode DICT-1234-56:
 *
 *	- If DICT.mo defines snmp-url, it is used when filling
 *	  in the sunFmProblemURL variable.
 *
 *	- Otherwise, if snmp-trapgen.conf defines a "url" property, that
 *	  value is used.
 *
 *	- Otherwise, the default "http://sun.com/msg/" is used (via the
 *	  fmd_props[] table defined in this file).
 */
static const char SNMP_DOMAIN[] = "FMD";
static const char SNMP_URL[] = SNMP_URL_MSG;

static struct stats {
	fmd_stat_t bad_vers;
	fmd_stat_t bad_code;
	fmd_stat_t bad_uuid;
	fmd_stat_t no_trap;
} snmp_stats = {
	{ "bad_vers", FMD_TYPE_UINT64, "event version is missing or invalid" },
	{ "bad_code", FMD_TYPE_UINT64, "event code has no dictionary name" },
	{ "bad_uuid", FMD_TYPE_UINT64, "event uuid is too long to send" },
	{ "no_trap", FMD_TYPE_UINT64, "trap generation suppressed" }
};

static char *snmp_locdir;	/* l10n messages directory (if alternate) */
static char *snmp_url;		/* current value of "url" property */
static int snmp_trapall;	/* set to trap on all faults */

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
	char *uuid, *code, *dict, *url, *urlcode, *locdir, *p;
	boolean_t domsg;

	uint8_t version;
	char *olang = NULL;
	int locale_c = 0;
	size_t len;

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

	/*
	 * Extract the uuid and diagcode dictionary from the event code.  The
	 * dictionary name is the text preceding the first "-" in the code.
	 */
	(void) nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid);
	(void) nvlist_lookup_string(nvl, FM_SUSPECT_DIAG_CODE, &code);

	if ((p = strchr(code, '-')) == NULL || p == code) {
		fmd_hdl_debug(hdl, "invalid diagnosis code: %s\n", code);
		snmp_stats.bad_code.fmds_value.ui64++;
		return;
	}

	dict = alloca((size_t)(p - code) + 1);
	(void) strncpy(dict, code, (size_t)(p - code));
	dict[(size_t)(p - code)] = '\0';

	fmd_msg_lock();

	if (snmp_locdir != NULL)
		locdir = bindtextdomain(dict, snmp_locdir);

	if ((url = dgettext(dict, SNMP_URL)) == SNMP_URL) {
		/*
		 * We didn't find a translation in the dictionary for the
		 * current language.  Fall back to C and try again.
		 */
		olang = setlocale(LC_MESSAGES, NULL);
		if (olang) {
			p = alloca(strlen(olang) + 1);
			olang = strcpy(p, olang);
		}
		locale_c = 1;
		(void) setlocale(LC_MESSAGES, "C");
		if ((url = dgettext(dict, SNMP_URL)) == SNMP_URL)
			url = snmp_url;
	}

	/*
	 * If the URL ends with a slash, that indicates the code should be
	 * appended to it.  After formatting the URL, reformat the DESC
	 * text using the URL as an snprintf argument.
	 */
	len = strlen(url);
	if (url[len - 1] == '/') {
		urlcode = alloca(len + strlen(code) + 1);
		(void) snprintf(urlcode, INT_MAX, "%s%s", url, code);
	} else {
		urlcode = url;
	}

	/*
	 * We have what we need; now send the trap.
	 */
	send_trap(hdl, uuid, code, urlcode);

	/*
	 * Switch back to our original language if we had to fall back to C.
	 */
	if (olang != NULL)
		(void) setlocale(LC_MESSAGES, olang);

	if (snmp_locdir != NULL)
		(void) bindtextdomain(dict, locdir);

	fmd_msg_unlock();

	if (locale_c) {
		fmd_hdl_debug(hdl,
		    url == snmp_url ?
		    "dgettext(%s, %s) in %s and C failed\n" :
		    "dgettext(%s, %s) in %s failed; C used\n",
		    dict, SNMP_URL, olang ? olang : "<null>");
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
	char *rootdir, *locdir, *locale, *p;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* invalid data in configuration file */

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (snmp_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&snmp_stats);

	if (init_sma() != SNMPERR_SUCCESS)
		fmd_hdl_abort(hdl, "snmp-trapgen agent initialization failed");

	/*
	 * All FMA event dictionaries use msgfmt(1) message objects to produce
	 * messages, even for the C locale.  We therefore want to use dgettext
	 * for all message lookups, but its defined behavior in the C locale is
	 * to return the input string.  Since our input strings are event codes
	 * and not format strings, this doesn't help us.  We resolve this nit
	 * by setting NLSPATH to a non-existent file: the presence of NLSPATH
	 * is defined to force dgettext(3C) to do a full lookup even for C.
	 */
	if (getenv("NLSPATH") == NULL && putenv(fmd_hdl_strdup(hdl,
	    "NLSPATH=/usr/lib/fm/fmd/fmd.cat", FMD_SLEEP)) != 0)
		fmd_hdl_abort(hdl, "snmp-trapgen failed to set NLSPATH");

	fmd_msg_lock();
	(void) setlocale(LC_MESSAGES, "");
	locale = setlocale(LC_MESSAGES, NULL);
	if (locale) {
		p = alloca(strlen(locale) + 1);
		locale = strcpy(p, locale);
	} else {
		locale = "<null>";
	}
	fmd_msg_unlock();
	fmd_hdl_debug(hdl, "locale=%s\n", locale);

	/*
	 * Cache any properties we use every time we receive an event and
	 * subscribe to list.suspect events regardless of the .conf file.
	 */
	snmp_url = fmd_prop_get_string(hdl, "url");
	snmp_trapall = fmd_prop_get_int32(hdl, "trap_all");

	/*
	 * If fmd's rootdir property is set to a non-default root, then we are
	 * going to need to rebind the text domains we use for dgettext() as
	 * we go.  Look up the default l10n messages directory and make
	 * snmp_locdir be this path with fmd.rootdir prepended to it.
	 */
	rootdir = fmd_prop_get_string(hdl, "fmd.rootdir");

	if (*rootdir != '\0' && strcmp(rootdir, "/") != 0) {
		fmd_msg_lock();
		locdir = bindtextdomain(SNMP_DOMAIN, NULL);
		fmd_msg_unlock();
		if (locdir != NULL) {
			size_t len = strlen(rootdir) + strlen(locdir) + 1;
			snmp_locdir = fmd_hdl_alloc(hdl, len, FMD_SLEEP);
			(void) snprintf(snmp_locdir, len, "%s%s", rootdir,
			    locdir);
			fmd_hdl_debug(hdl,
			    "binding textdomain to %s for snmp\n",
			    snmp_locdir);
		}
	}

	fmd_prop_free_string(hdl, rootdir);
	fmd_hdl_subscribe(hdl, FM_LIST_SUSPECT_CLASS);
	fmd_hdl_subscribe(hdl, FM_LIST_REPAIRED_CLASS);
	fmd_hdl_subscribe(hdl, FM_LIST_RESOLVED_CLASS);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	fmd_hdl_strfree(hdl, snmp_locdir);
	fmd_prop_free_string(hdl, snmp_url);

	/*
	 * snmp_shutdown, which we would normally use here, calls free_slots,
	 * a callback that is supposed to tear down the pkcs11 state; however,
	 * it abuses C_Finalize, causing fmd to drop core on shutdown.  Avoid
	 * this by shutting down the library piecemeal.
	 */
	snmp_store(SNMP_SUPPCONF);
	snmp_alarm_unregister_all();
	snmp_close_sessions();
	shutdown_mib();
	unregister_all_config_handlers();
	netsnmp_ds_shutdown();
}
