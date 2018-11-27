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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/fm/util.h>

#include <smbios.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <door.h>

#include <fmd_conf.h>
#include <fmd_dispq.h>
#include <fmd_timerq.h>
#include <fmd_subr.h>
#include <fmd_error.h>
#include <fmd_module.h>
#include <fmd_thread.h>
#include <fmd_alloc.h>
#include <fmd_string.h>
#include <fmd_builtin.h>
#include <fmd_ustat.h>
#include <fmd_protocol.h>
#include <fmd_scheme.h>
#include <fmd_asru.h>
#include <fmd_case.h>
#include <fmd_log.h>
#include <fmd_idspace.h>
#include <fmd_rpc.h>
#include <fmd_dr.h>
#include <fmd_topo.h>
#include <fmd_xprt.h>
#include <fmd_ctl.h>
#include <sys/openpromio.h>
#include <libdevinfo.h>

#include <fmd.h>

extern const nv_alloc_ops_t fmd_nv_alloc_ops;	/* see fmd_nv.c */

const char _fmd_version[] = "1.2";		/* daemon version string */
static char _fmd_plat[MAXNAMELEN];		/* native platform string */
static char _fmd_isa[MAXNAMELEN];		/* native instruction set */
static struct utsname _fmd_uts;			/* native uname(2) info */
static char _fmd_psn[MAXNAMELEN];		/* product serial number */
static char _fmd_csn[MAXNAMELEN];		/* chassis serial number */
static char _fmd_prod[MAXNAMELEN];		/* product name string */

/*
 * Note: the configuration file path is ordered from most common to most host-
 * specific because new conf files are merged/override previous ones.  The
 * module paths are in the opposite order, from most specific to most common,
 * because once a module is loaded fmd will not try to load over the same name.
 */

static const char _fmd_conf_path[] =
	"%r/usr/lib/fm/fmd:"
	"%r/usr/platform/%m/lib/fm/fmd:"
	"%r/usr/platform/%i/lib/fm/fmd:"
	"%r/etc/fm/fmd";

static const char _fmd_agent_path[] =
	"%r/usr/platform/%i/lib/fm/fmd/agents:"
	"%r/usr/platform/%m/lib/fm/fmd/agents:"
	"%r/usr/lib/fm/fmd/agents";

static const char _fmd_plugin_path[] =
	"%r/usr/platform/%i/lib/fm/fmd/plugins:"
	"%r/usr/platform/%m/lib/fm/fmd/plugins:"
	"%r/usr/lib/fm/fmd/plugins";

static const char _fmd_scheme_path[] =
	"usr/lib/fm/fmd/schemes";

static const fmd_conf_mode_t _fmd_cerror_modes[] = {
	{ "unload", "unload offending client module", FMD_CERROR_UNLOAD },
	{ "stop", "stop daemon for debugger attach", FMD_CERROR_STOP },
	{ "abort", "abort daemon and force core dump", FMD_CERROR_ABORT },
	{ NULL, NULL, 0 }
};

static const fmd_conf_mode_t _fmd_dbout_modes[] = {
	{ "stderr", "send debug messages to stderr", FMD_DBOUT_STDERR },
	{ "syslog", "send debug messages to syslog", FMD_DBOUT_SYSLOG },
	{ NULL, NULL, 0 }
};

static const fmd_conf_mode_t _fmd_debug_modes[] = {
	{ "help", "display debugging modes and exit", FMD_DBG_HELP },
	{ "mod", "debug module load/unload/locking", FMD_DBG_MOD },
	{ "disp", "debug dispatch queue processing", FMD_DBG_DISP },
	{ "xprt", "debug transport-specific routines", FMD_DBG_XPRT },
	{ "evt", "debug event subsystem routines", FMD_DBG_EVT },
	{ "log", "debug log subsystem routines", FMD_DBG_LOG },
	{ "tmr", "debug timer subsystem routines", FMD_DBG_TMR },
	{ "fmri", "debug fmri subsystem routines", FMD_DBG_FMRI },
	{ "asru", "debug asru subsystem routines", FMD_DBG_ASRU },
	{ "case", "debug case subsystem routines", FMD_DBG_CASE },
	{ "ckpt", "debug checkpoint routines", FMD_DBG_CKPT },
	{ "rpc", "debug rpc service routines", FMD_DBG_RPC },
	{ "trace", "display matching trace calls", FMD_DBG_TRACE },
	{ "all", "enable all available debug modes", FMD_DBG_ALL },
	{ NULL, NULL, 0 }
};

static int
fmd_cerror_set(fmd_conf_param_t *pp, const char *value)
{
	return (fmd_conf_mode_set(_fmd_cerror_modes, pp, value));
}

static int
fmd_dbout_set(fmd_conf_param_t *pp, const char *value)
{
	return (fmd_conf_mode_set(_fmd_dbout_modes, pp, value));
}

static int
fmd_debug_set(fmd_conf_param_t *pp, const char *value)
{
	int err = fmd_conf_mode_set(_fmd_debug_modes, pp, value);

	if (err == 0)
		fmd.d_fmd_debug = pp->cp_value.cpv_num;

	return (err);
}

static int
fmd_trmode_set(fmd_conf_param_t *pp, const char *value)
{
	fmd_tracebuf_f *func;

	if (strcasecmp(value, "none") == 0)
		func = fmd_trace_none;
	else if (strcasecmp(value, "lite") == 0)
		func = fmd_trace_lite;
	else if (strcasecmp(value, "full") == 0)
		func = fmd_trace_full;
	else
		return (fmd_set_errno(EFMD_CONF_INVAL));

	fmd.d_thr_trace = func;
	pp->cp_value.cpv_ptr = func;
	return (0);
}

static void
fmd_trmode_get(const fmd_conf_param_t *pp, void *ptr)
{
	*((void **)ptr) = pp->cp_value.cpv_ptr;
}

static int
fmd_clkmode_set(fmd_conf_param_t *pp, const char *value)
{
	const fmd_timeops_t *ops;

	if (strcasecmp(value, "native") == 0)
		ops = &fmd_timeops_native;
	else if (strcasecmp(value, "simulated") == 0)
		ops = &fmd_timeops_simulated;
	else
		return (fmd_set_errno(EFMD_CONF_INVAL));

	fmd.d_clockops = ops;
	pp->cp_value.cpv_ptr = (void *)ops;
	return (0);
}

static void
fmd_clkmode_get(const fmd_conf_param_t *pp, void *ptr)
{
	*((void **)ptr) = pp->cp_value.cpv_ptr;
}

static const fmd_conf_ops_t fmd_cerror_ops = {
	fmd_cerror_set, fmd_conf_mode_get, fmd_conf_notsup, fmd_conf_nop
};

static const fmd_conf_ops_t fmd_dbout_ops = {
	fmd_dbout_set, fmd_conf_mode_get, fmd_conf_notsup, fmd_conf_nop
};

static const fmd_conf_ops_t fmd_debug_ops = {
	fmd_debug_set, fmd_conf_mode_get, fmd_conf_notsup, fmd_conf_nop
};

static const fmd_conf_ops_t fmd_trmode_ops = {
	fmd_trmode_set, fmd_trmode_get, fmd_conf_notsup, fmd_conf_nop
};

static const fmd_conf_ops_t fmd_clkmode_ops = {
	fmd_clkmode_set, fmd_clkmode_get, fmd_conf_notsup, fmd_conf_nop
};

static const fmd_conf_formal_t _fmd_conf[] = {
{ "agent.path", &fmd_conf_path, _fmd_agent_path }, /* path for agents */
{ "alloc_msecs", &fmd_conf_uint32, "10" },	/* msecs before alloc retry */
{ "alloc_tries", &fmd_conf_uint32, "3" },	/* max # of alloc retries */
{ "product_sn", &fmd_conf_string, _fmd_psn },	/* product serial number */
{ "chassis", &fmd_conf_string, _fmd_csn },	/* chassis serial number */
{ "ckpt.dir", &fmd_conf_string, "var/fm/fmd/ckpt" }, /* ckpt directory path */
{ "ckpt.dirmode", &fmd_conf_int32, "0755" },	/* ckpt directory perm mode */
{ "ckpt.mode", &fmd_conf_int32, "0644" },	/* ckpt file perm mode */
{ "ckpt.restore", &fmd_conf_bool, "true" },	/* restore checkpoints? */
{ "ckpt.save", &fmd_conf_bool, "true" },	/* save checkpoints? */
{ "ckpt.zero", &fmd_conf_bool, "false" },	/* zero checkpoints on start? */
{ "client.buflim", &fmd_conf_size, "10m" },	/* client buffer space limit */
{ "client.dbout", &fmd_dbout_ops, NULL },	/* client debug output sinks */
{ "client.debug", &fmd_conf_bool, NULL },	/* client debug enable */
{ "client.doorthrlim", &fmd_conf_uint32, "20" }, /* client door thread limit */
{ "client.error", &fmd_cerror_ops, "unload" },	/* client error policy */
{ "client.memlim", &fmd_conf_size, "10m" },	/* client allocation limit */
{ "client.evqlim", &fmd_conf_uint32, "256" },	/* client event queue limit */
{ "client.thrlim", &fmd_conf_uint32, "20" },	/* client aux thread limit */
{ "client.thrsig", &fmd_conf_signal, "SIGUSR1" }, /* fmd_thr_signal() value */
{ "client.tmrlim", &fmd_conf_uint32, "1024" },	/* client pending timer limit */
{ "client.xprtlim", &fmd_conf_uint32, "256" },	/* client transport limit */
{ "client.xprtlog", &fmd_conf_bool, NULL },	/* client transport logging? */
{ "client.xprtqlim", &fmd_conf_uint32, "1024" }, /* client transport queue li */
{ "clock", &fmd_clkmode_ops, "native" },	/* clock operation mode */
{ "conf_path", &fmd_conf_path, _fmd_conf_path }, /* root config file path */
{ "conf_file", &fmd_conf_string, "fmd.conf" },	/* root config file name */
{ "core", &fmd_conf_bool, "false" },		/* force core dump on quit */
{ "dbout", &fmd_dbout_ops, NULL },		/* daemon debug output sinks */
{ "debug", &fmd_debug_ops, NULL },		/* daemon debugging flags */
{ "dictdir", &fmd_conf_string, "usr/lib/fm/dict" }, /* default diagcode dir */
{ "domain", &fmd_conf_string, NULL },		/* domain id for de auth */
{ "fakenotpresent", &fmd_conf_uint32, "0" },	/* simulate rsrc not present */
{ "fg", &fmd_conf_bool, "false" },		/* run daemon in foreground */
{ "gc_interval", &fmd_conf_time, "1d" },	/* garbage collection intvl */
{ "ids.avg", &fmd_conf_uint32, "4" },		/* desired idspace chain len */
{ "ids.max", &fmd_conf_uint32, "1024" },	/* maximum idspace buckets */
{ "isaname", &fmd_conf_string, _fmd_isa },	/* instruction set (uname -p) */
{ "log.creator", &fmd_conf_string, "fmd" },	/* exacct log creator string */
{ "log.error", &fmd_conf_string, "var/fm/fmd/errlog" }, /* error log path */
{ "log.fault", &fmd_conf_string, "var/fm/fmd/fltlog" }, /* fault log path */
{ "log.info", &fmd_conf_string, "var/fm/fmd/infolog" }, /* info log path */
{ "log.info_hival", &fmd_conf_string, "var/fm/fmd/infolog_hival" }, /* hi pri */
{ "log.minfree", &fmd_conf_size, "2m" },	/* min log fsys free space */
{ "log.rsrc", &fmd_conf_string, "var/fm/fmd/rsrc" }, /* asru log dir path */
{ "log.tryrotate", &fmd_conf_uint32, "10" },	/* max log rotation attempts */
{ "log.waitrotate", &fmd_conf_time, "200ms" },	/* log rotation retry delay */
{ "log.xprt", &fmd_conf_string, "var/fm/fmd/xprt" }, /* transport log dir */
{ "machine", &fmd_conf_string, _fmd_uts.machine }, /* machine name (uname -m) */
{ "nodiagcode", &fmd_conf_string, "-" },	/* diagcode to use if error */
{ "repaircode", &fmd_conf_string, "-" },	/* diagcode for list.repaired */
{ "resolvecode", &fmd_conf_string, "-" },	/* diagcode for list.resolved */
{ "updatecode", &fmd_conf_string, "-" },	/* diagcode for list.updated */
{ "osrelease", &fmd_conf_string, _fmd_uts.release }, /* release (uname -r) */
{ "osversion", &fmd_conf_string, _fmd_uts.version }, /* version (uname -v) */
{ "platform", &fmd_conf_string, _fmd_plat },	/* platform string (uname -i) */
{ "plugin.close", &fmd_conf_bool, "true" },	/* dlclose plugins on fini */
{ "plugin.path", &fmd_conf_path, _fmd_plugin_path }, /* path for plugin mods */
{ "product", &fmd_conf_string, _fmd_prod },	/* product name string */
{ "rootdir", &fmd_conf_string, "" },		/* root directory for paths */
{ "rpc.adm.path", &fmd_conf_string, NULL },	/* FMD_ADM rendezvous file */
{ "rpc.adm.prog", &fmd_conf_uint32, "100169" },	/* FMD_ADM rpc program num */
{ "rpc.api.path", &fmd_conf_string, NULL },	/* FMD_API rendezvous file */
{ "rpc.api.prog", &fmd_conf_uint32, "100170" },	/* FMD_API rpc program num */
{ "rpc.rcvsize", &fmd_conf_size, "128k" },	/* rpc receive buffer size */
{ "rpc.sndsize", &fmd_conf_size, "128k" },	/* rpc send buffer size */
{ "rsrc.pollperiod", &fmd_conf_time, "1h" },	/* aged rsrcs poller period */
{ "rsrc.age", &fmd_conf_time, "30d" },		/* max age of old rsrc log */
{ "rsrc.zero", &fmd_conf_bool, "false" },	/* zero rsrc cache on start? */
{ "schemedir", &fmd_conf_string, _fmd_scheme_path }, /* path for scheme mods */
{ "self.name", &fmd_conf_string, "fmd-self-diagnosis" }, /* self-diag module */
{ "self.dict", &fmd_conf_list, "FMD.dict" },	/* self-diag dictionary list */
{ "server", &fmd_conf_string, _fmd_uts.nodename }, /* server id for de auth */
{ "strbuckets", &fmd_conf_uint32, "211" },	/* size of string hashes */
#ifdef DEBUG
{ "trace.mode", &fmd_trmode_ops, "full" },	/* trace mode: none/lite/full */
#else
{ "trace.mode", &fmd_trmode_ops, "lite" },	/* trace mode: none/lite/full */
#endif
{ "trace.recs", &fmd_conf_uint32, "128" },	/* trace records per thread */
{ "trace.frames", &fmd_conf_uint32, "16" },	/* max trace rec stack frames */
{ "uuidlen", &fmd_conf_uint32, "36" },		/* UUID ASCII string length */
{ "xprt.ttl", &fmd_conf_uint8, "1" },		/* default event time-to-live */
};

/*
 * Statistics maintained by fmd itself on behalf of various global subsystems.
 * NOTE: FMD_TYPE_STRING statistics should not be used here.  If they are
 * required in the future, the FMD_ADM_MODGSTAT service routine must change.
 */
static fmd_statistics_t _fmd_stats = {
{ "errlog.replayed", FMD_TYPE_UINT64, "total events replayed from errlog" },
{ "errlog.partials", FMD_TYPE_UINT64, "events partially committed in errlog" },
{ "errlog.enospc", FMD_TYPE_UINT64, "events not appended to errlog (ENOSPC)" },
{ "fltlog.enospc", FMD_TYPE_UINT64, "events not appended to fltlog (ENOSPC)" },
{ "log.enospc", FMD_TYPE_UINT64, "events not appended to other logs (ENOSPC)" },
{ "dr.gen", FMD_TYPE_UINT64, "dynamic reconfiguration generation" },
{ "topo.gen", FMD_TYPE_UINT64, "topology snapshot generation" },
{ "topo.drgen", FMD_TYPE_UINT64, "current topology DR generation number" },
};

/*
 * SMBIOS serial numbers can contain characters (particularly ':' and ' ')
 * that are invalid for the authority and can break FMRI parsing.  We translate
 * any invalid characters to a safe '-', as well as trimming any leading or
 * trailing whitespace.  Similarly, '/' can be found in some product names
 * so we translate that to '-'.
 */
void
fmd_cleanup_auth_str(char *buf, const char *begin)
{
	const char *end, *cp;
	char c;
	int i;

	end = begin + strlen(begin);

	while (begin < end && isspace(*begin))
		begin++;
	while (begin < end && isspace(*(end - 1)))
		end--;

	if (begin >= end)
		return;

	cp = begin;
	for (i = 0; i < MAXNAMELEN - 1; i++) {
		if (cp >= end)
			break;
		c = *cp;
		if (c == ':' || c == '=' || c == '/' || isspace(c) ||
		    !isprint(c))
			buf[i] = '-';
		else
			buf[i] = c;
		cp++;
	}
	buf[i] = 0;
}

void
fmd_create(fmd_t *dp, const char *arg0, const char *root, const char *conf)
{
	fmd_conf_path_t *pap;
	char file[PATH_MAX];
	const char *name, *psn, *csn;
	fmd_stat_t *sp;
	int i;

	smbios_hdl_t *shp;
	smbios_system_t s1;
	smbios_info_t s2;
	id_t id;

	di_prom_handle_t promh = DI_PROM_HANDLE_NIL;
	di_node_t rooth = DI_NODE_NIL;
	char *bufp;

	(void) sysinfo(SI_PLATFORM, _fmd_plat, sizeof (_fmd_plat));
	(void) sysinfo(SI_ARCHITECTURE, _fmd_isa, sizeof (_fmd_isa));
	(void) uname(&_fmd_uts);

	if ((shp = smbios_open(NULL, SMB_VERSION, 0, NULL)) != NULL) {
		if ((id = smbios_info_system(shp, &s1)) != SMB_ERR &&
		    smbios_info_common(shp, id, &s2) != SMB_ERR)
			fmd_cleanup_auth_str(_fmd_prod, s2.smbi_product);

		if ((psn = smbios_psn(shp)) != NULL)
			fmd_cleanup_auth_str(_fmd_psn, psn);

		if ((csn = smbios_csn(shp)) != NULL)
			fmd_cleanup_auth_str(_fmd_csn, csn);

		smbios_close(shp);
	} else if ((rooth = di_init("/", DINFOPROP)) != DI_NODE_NIL &&
	    (promh = di_prom_init()) != DI_PROM_HANDLE_NIL) {
		if (di_prom_prop_lookup_bytes(promh, rooth, "chassis-sn",
		    (unsigned char **)&bufp) != -1) {
			fmd_cleanup_auth_str(_fmd_csn, bufp);
		}
	}

	if (promh != DI_PROM_HANDLE_NIL)
		di_prom_fini(promh);
	if (rooth != DI_NODE_NIL)
		di_fini(rooth);

	bzero(dp, sizeof (fmd_t));

	dp->d_version = _fmd_version;
	dp->d_pname = fmd_strbasename(arg0);
	dp->d_pid = getpid();

	if (pthread_key_create(&dp->d_key, NULL) != 0)
		fmd_error(EFMD_EXIT, "failed to create pthread key");

	(void) pthread_mutex_init(&dp->d_xprt_lock, NULL);
	(void) pthread_mutex_init(&dp->d_err_lock, NULL);
	(void) pthread_mutex_init(&dp->d_thr_lock, NULL);
	(void) pthread_mutex_init(&dp->d_mod_lock, NULL);
	(void) pthread_mutex_init(&dp->d_stats_lock, NULL);
	(void) pthread_mutex_init(&dp->d_topo_lock, NULL);
	(void) pthread_rwlock_init(&dp->d_log_lock, NULL);
	(void) pthread_rwlock_init(&dp->d_hvilog_lock, NULL);
	(void) pthread_rwlock_init(&dp->d_ilog_lock, NULL);
	(void) pthread_mutex_init(&dp->d_fmd_lock, NULL);
	(void) pthread_cond_init(&dp->d_fmd_cv, NULL);

	/*
	 * A small number of properties must be set manually before we open
	 * the root configuration file.  These include any settings for our
	 * memory allocator and path expansion token values, because these
	 * values are needed by the routines in fmd_conf.c itself.  After
	 * the root configuration file is processed, we reset these properties
	 * based upon the latest values from the configuration file.
	 */
	dp->d_alloc_msecs = 10;
	dp->d_alloc_tries = 3;
	dp->d_str_buckets = 211;

	dp->d_rootdir = root ? root : "";
	dp->d_platform = _fmd_plat;
	dp->d_machine = _fmd_uts.machine;
	dp->d_isaname = _fmd_isa;

	dp->d_conf = fmd_conf_open(conf, sizeof (_fmd_conf) /
	    sizeof (_fmd_conf[0]), _fmd_conf, FMD_CONF_DEFER);

	if (dp->d_conf == NULL) {
		fmd_error(EFMD_EXIT,
		    "failed to load required configuration properties\n");
	}

	(void) fmd_conf_getprop(dp->d_conf, "alloc.msecs", &dp->d_alloc_msecs);
	(void) fmd_conf_getprop(dp->d_conf, "alloc.tries", &dp->d_alloc_tries);
	(void) fmd_conf_getprop(dp->d_conf, "strbuckets", &dp->d_str_buckets);

	(void) fmd_conf_getprop(dp->d_conf, "platform", &dp->d_platform);
	(void) fmd_conf_getprop(dp->d_conf, "machine", &dp->d_machine);
	(void) fmd_conf_getprop(dp->d_conf, "isaname", &dp->d_isaname);

	/*
	 * Manually specified rootdirs override config files, so only update
	 * d_rootdir based on the config files we parsed if no 'root' was set.
	 */
	if (root == NULL)
		(void) fmd_conf_getprop(dp->d_conf, "rootdir", &dp->d_rootdir);
	else
		(void) fmd_conf_setprop(dp->d_conf, "rootdir", dp->d_rootdir);

	/*
	 * Once the base conf file properties are loaded, lookup the values
	 * of $conf_path and $conf_file and merge in any other conf files.
	 */
	(void) fmd_conf_getprop(dp->d_conf, "conf_path", &pap);
	(void) fmd_conf_getprop(dp->d_conf, "conf_file", &name);

	for (i = 0; i < pap->cpa_argc; i++) {
		(void) snprintf(file, sizeof (file),
		    "%s/%s", pap->cpa_argv[i], name);
		if (access(file, F_OK) == 0)
			fmd_conf_merge(dp->d_conf, file);
	}

	/*
	 * Update the value of fmd.d_fg based on "fg".  We cache this property
	 * because it must be accessed deep within fmd at fmd_verror() time.
	 * Update any other properties that must be cached for performance.
	 */
	(void) fmd_conf_getprop(fmd.d_conf, "fg", &fmd.d_fg);
	(void) fmd_conf_getprop(fmd.d_conf, "xprt.ttl", &fmd.d_xprt_ttl);

	/*
	 * Initialize our custom libnvpair allocator and create an nvlist for
	 * authority elements corresponding to this instance of the daemon.
	 */
	(void) nv_alloc_init(&dp->d_nva, &fmd_nv_alloc_ops);
	dp->d_auth = fmd_protocol_authority();

	/*
	 * The fmd_module_t for the root module must be created manually.  Most
	 * of it remains unused and zero, except for the few things we fill in.
	 */
	dp->d_rmod = fmd_zalloc(sizeof (fmd_module_t), FMD_SLEEP);
	dp->d_rmod->mod_name = fmd_strdup(dp->d_pname, FMD_SLEEP);
	dp->d_rmod->mod_fmri = fmd_protocol_fmri_module(dp->d_rmod);

	fmd_list_append(&dp->d_mod_list, dp->d_rmod);
	fmd_module_hold(dp->d_rmod);

	(void) pthread_mutex_init(&dp->d_rmod->mod_lock, NULL);
	(void) pthread_cond_init(&dp->d_rmod->mod_cv, NULL);
	(void) pthread_mutex_init(&dp->d_rmod->mod_stats_lock, NULL);

	dp->d_rmod->mod_thread = fmd_thread_xcreate(dp->d_rmod, pthread_self());
	dp->d_rmod->mod_stats = fmd_zalloc(sizeof (fmd_modstat_t), FMD_SLEEP);
	dp->d_rmod->mod_ustat = fmd_ustat_create();

	if (pthread_setspecific(dp->d_key, dp->d_rmod->mod_thread) != 0)
		fmd_error(EFMD_EXIT, "failed to attach main thread key");

	if ((dp->d_stats = (fmd_statistics_t *)fmd_ustat_insert(
	    dp->d_rmod->mod_ustat, FMD_USTAT_NOALLOC, sizeof (_fmd_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&_fmd_stats, NULL)) == NULL)
		fmd_error(EFMD_EXIT, "failed to initialize statistics");

	(void) pthread_mutex_lock(&dp->d_rmod->mod_lock);
	dp->d_rmod->mod_flags |= FMD_MOD_INIT;
	(void) pthread_mutex_unlock(&dp->d_rmod->mod_lock);

	/*
	 * In addition to inserting the _fmd_stats collection of program-wide
	 * statistics, we also insert a statistic named after each of our
	 * errors and update these counts in fmd_verror() (see fmd_subr.c).
	 */
	dp->d_errstats = sp = fmd_zalloc(sizeof (fmd_stat_t) *
	    (EFMD_END - EFMD_UNKNOWN), FMD_SLEEP);

	for (i = 0; i < EFMD_END - EFMD_UNKNOWN; i++, sp++) {
		(void) snprintf(sp->fmds_name, sizeof (sp->fmds_name), "err.%s",
		    strrchr(fmd_errclass(EFMD_UNKNOWN + i), '.') + 1);
		sp->fmds_type = FMD_TYPE_UINT64;
	}

	(void) fmd_ustat_insert(dp->d_rmod->mod_ustat, FMD_USTAT_NOALLOC,
	    EFMD_END - EFMD_UNKNOWN, dp->d_errstats, NULL);
}

void
fmd_destroy(fmd_t *dp)
{
	fmd_module_t *mp;
	fmd_case_t *cp;
	int core;

	(void) fmd_conf_getprop(fmd.d_conf, "core", &core);

	fmd_rpc_fini();

	if (dp->d_xprt_ids != NULL)
		fmd_xprt_suspend_all();

	/*
	 * Unload the self-diagnosis module first.  This ensures that it does
	 * not get confused as we start unloading other modules, etc.  We must
	 * hold the dispq lock as a writer while doing so since it uses d_self.
	 */
	if (dp->d_self != NULL) {
		fmd_module_t *self;

		(void) pthread_rwlock_wrlock(&dp->d_disp->dq_lock);
		self = dp->d_self;
		dp->d_self = NULL;
		(void) pthread_rwlock_unlock(&dp->d_disp->dq_lock);

		fmd_module_unload(self);
		fmd_module_rele(self);
	}

	/*
	 * Unload modules in reverse order *except* for the root module, which
	 * is first in the list.  This allows it to keep its thread and trace.
	 */
	for (mp = fmd_list_prev(&dp->d_mod_list); mp != dp->d_rmod; ) {
		fmd_module_unload(mp);
		mp = fmd_list_prev(mp);
	}

	if (dp->d_mod_hash != NULL) {
		fmd_modhash_destroy(dp->d_mod_hash);
		dp->d_mod_hash = NULL;
	}

	/*
	 * Close both log files now that modules are no longer active.  We must
	 * set these pointers to NULL in case any subsequent errors occur.
	 */
	if (dp->d_errlog != NULL) {
		fmd_log_rele(dp->d_errlog);
		dp->d_errlog = NULL;
	}

	if (dp->d_fltlog != NULL) {
		fmd_log_rele(dp->d_fltlog);
		dp->d_fltlog = NULL;
	}

	/*
	 * Now destroy the resource cache: each ASRU contains a case reference,
	 * which may in turn contain a pointer to a referenced owning module.
	 */
	if (dp->d_asrus != NULL) {
		fmd_asru_hash_destroy(dp->d_asrus);
		dp->d_asrus = NULL;
	}

	/*
	 * Now that all data structures that refer to modules are torn down,
	 * no modules should be remaining on the module list except for d_rmod.
	 * If we trip one of these assertions, we're missing a rele somewhere.
	 */
	ASSERT(fmd_list_prev(&dp->d_mod_list) == dp->d_rmod);
	ASSERT(fmd_list_next(&dp->d_mod_list) == dp->d_rmod);

	/*
	 * Now destroy the root module.  We clear its thread key first so any
	 * calls to fmd_trace() inside of the module code will be ignored.
	 */
	(void) pthread_setspecific(dp->d_key, NULL);
	fmd_module_lock(dp->d_rmod);

	while ((cp = fmd_list_next(&dp->d_rmod->mod_cases)) != NULL)
		fmd_case_discard(cp, B_FALSE);

	fmd_module_unlock(dp->d_rmod);
	fmd_free(dp->d_rmod->mod_stats, sizeof (fmd_modstat_t));
	dp->d_rmod->mod_stats = NULL;

	(void) pthread_mutex_lock(&dp->d_rmod->mod_lock);
	dp->d_rmod->mod_flags |= FMD_MOD_FINI;
	(void) pthread_mutex_unlock(&dp->d_rmod->mod_lock);

	fmd_module_rele(dp->d_rmod);
	ASSERT(fmd_list_next(&dp->d_mod_list) == NULL);

	/*
	 * Now destroy the remaining global data structures.  If 'core' was
	 * set to true, force a core dump so we can check for memory leaks.
	 */
	if (dp->d_cases != NULL)
		fmd_case_hash_destroy(dp->d_cases);
	if (dp->d_disp != NULL)
		fmd_dispq_destroy(dp->d_disp);
	if (dp->d_timers != NULL)
		fmd_timerq_destroy(dp->d_timers);
	if (dp->d_schemes != NULL)
		fmd_scheme_hash_destroy(dp->d_schemes);
	if (dp->d_xprt_ids != NULL)
		fmd_idspace_destroy(dp->d_xprt_ids);

	if (dp->d_errstats != NULL) {
		fmd_free(dp->d_errstats,
		    sizeof (fmd_stat_t) * (EFMD_END - EFMD_UNKNOWN));
	}

	if (dp->d_conf != NULL)
		fmd_conf_close(dp->d_conf);

	fmd_topo_fini();

	nvlist_free(dp->d_auth);
	(void) nv_alloc_fini(&dp->d_nva);
	dp->d_clockops->fto_fini(dp->d_clockptr);

	(void) pthread_key_delete(dp->d_key);
	bzero(dp, sizeof (fmd_t));

	if (core)
		fmd_panic("forcing core dump at user request\n");
}

/*ARGSUSED*/
static void
fmd_gc(fmd_t *dp, id_t id, hrtime_t hrt)
{
	hrtime_t delta;

	if (id != 0) {
		TRACE((FMD_DBG_MOD, "garbage collect start"));
		fmd_modhash_apply(dp->d_mod_hash, fmd_module_gc);
		TRACE((FMD_DBG_MOD, "garbage collect end"));

		(void) pthread_rwlock_rdlock(&dp->d_log_lock);
		fmd_log_update(dp->d_errlog);
		(void) pthread_rwlock_unlock(&dp->d_log_lock);

		(void) pthread_rwlock_rdlock(&dp->d_hvilog_lock);
		fmd_log_update(dp->d_hvilog);
		(void) pthread_rwlock_unlock(&dp->d_hvilog_lock);

		(void) pthread_rwlock_rdlock(&dp->d_ilog_lock);
		fmd_log_update(dp->d_ilog);
		(void) pthread_rwlock_unlock(&dp->d_ilog_lock);
	}

	(void) fmd_conf_getprop(dp->d_conf, "gc_interval", &delta);
	(void) fmd_timerq_install(dp->d_timers, dp->d_rmod->mod_timerids,
	    (fmd_timer_f *)fmd_gc, dp, NULL, delta);
}

/*ARGSUSED*/
static void
fmd_clear_aged_rsrcs(fmd_t *dp, id_t id, hrtime_t hrt)
{
	hrtime_t period;

	fmd_asru_clear_aged_rsrcs();
	(void) fmd_conf_getprop(dp->d_conf, "rsrc.pollperiod", &period);
	(void) fmd_timerq_install(dp->d_timers, dp->d_rmod->mod_timerids,
	    (fmd_timer_f *)fmd_clear_aged_rsrcs, dp, NULL, period);
}

/*
 * Events are committed to the errlog after cases are checkpointed.  If fmd
 * crashes before an event is ever associated with a module, this function will
 * be called to replay it to all subscribers.  If fmd crashes in between the
 * subscriber checkpointing and committing the event in the error log, the
 * module will have seen the event and we don't want to replay it.  So we look
 * for the event in all modules and transition it to the proper state.  If
 * it is found, we commit it to the error log and do not replay it.  The in-
 * memory case search used by fmd_module_contains() et al isn't particularly
 * efficient, but it is faster than doing read i/o's on every case event to
 * check their status or write i/o's on every event to replay to update states.
 * We can improve the efficiency of this lookup algorithm later if necessary.
 */
/*ARGSUSED*/
static void
fmd_err_replay(fmd_log_t *lp, fmd_event_t *ep, fmd_t *dp)
{
	fmd_module_t *mp;
	fmd_stat_t *sp;

	(void) pthread_mutex_lock(&dp->d_mod_lock);

	for (mp = fmd_list_next(&dp->d_mod_list);
	    mp != NULL; mp = fmd_list_next(mp)) {
		if (fmd_module_contains(mp, ep)) {
			fmd_module_hold(mp);
			break;
		}
	}

	(void) pthread_mutex_unlock(&dp->d_mod_lock);

	if (mp != NULL) {
		fmd_event_commit(ep);
		fmd_module_rele(mp);
		sp = &dp->d_stats->ds_log_partials;
	} else {
		fmd_dispq_dispatch(dp->d_disp, ep, FMD_EVENT_DATA(ep));
		sp = &dp->d_stats->ds_log_replayed;
	}

	(void) pthread_mutex_lock(&dp->d_stats_lock);
	sp->fmds_value.ui64++;
	(void) pthread_mutex_unlock(&dp->d_stats_lock);
}

void
fmd_door_server(void *dip)
{
	fmd_dprintf(FMD_DBG_XPRT, "door server starting for %p\n", dip);
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	(void) door_return(NULL, 0, NULL, 0);
}

/*
 * Custom door server create callback.  Any fmd services that use doors will
 * require those threads to have their fmd-specific TSD initialized, etc.
 * Modules should use door_xcreate and derivatives such as
 * sysevent_evc_xsubscribe in order to use private doors that
 * avoid this global door server function (see fmd_api_module comments).
 */
static void
fmd_door(door_info_t *dip)
{
	if (fmd_thread_create(fmd.d_rmod, fmd_door_server, dip) == NULL)
		fmd_panic("failed to create server for door %p", (void *)dip);
}

/*
 * This signal handler is installed for the client.thrsig signal to be used to
 * force an auxiliary thread to wake up from a system call and return EINTR in
 * response to a module's use of fmd_thr_signal().  We also trace the event.
 */
static void
fmd_signal(int sig)
{
	TRACE((FMD_DBG_MOD, "module thread received sig #%d", sig));
}

void
fmd_run(fmd_t *dp, int pfd)
{
	char *nodc_key[] = { FMD_FLT_NODC, NULL };
	char *repair_key[] = { FM_LIST_REPAIRED_CLASS, NULL };
	char *resolve_key[] = { FM_LIST_RESOLVED_CLASS, NULL };
	char *update_key[] = { FM_LIST_UPDATED_CLASS, NULL };
	char code_str[128];
	struct sigaction act;

	int status = FMD_EXIT_SUCCESS;
	const char *name;
	fmd_conf_path_t *pap;
	fmd_event_t *e;
	int dbout;

	/*
	 * Cache all the current debug property settings in d_fmd_debug,
	 * d_fmd_dbout, d_hdl_debug, and d_hdl_dbout.  If a given debug mask
	 * is non-zero and the corresponding dbout mask is zero, set dbout
	 * to a sensible default value based on whether we have daemonized.
	 */
	(void) fmd_conf_getprop(dp->d_conf, "dbout", &dbout);

	if (dp->d_fmd_debug != 0 && dbout == 0)
		dp->d_fmd_dbout = dp->d_fg? FMD_DBOUT_STDERR : FMD_DBOUT_SYSLOG;
	else
		dp->d_fmd_dbout = dbout;

	(void) fmd_conf_getprop(dp->d_conf, "client.debug", &dp->d_hdl_debug);
	(void) fmd_conf_getprop(dp->d_conf, "client.dbout", &dbout);

	if (dp->d_hdl_debug != 0 && dbout == 0)
		dp->d_hdl_dbout = dp->d_fg? FMD_DBOUT_STDERR : FMD_DBOUT_SYSLOG;
	else
		dp->d_hdl_dbout = dbout;

	/*
	 * Initialize remaining major program data structures such as the
	 * clock, dispatch queues, log files, module hash collections, etc.
	 * This work is done here rather than in fmd_create() to permit the -o
	 * command-line option to modify properties after fmd_create() is done.
	 */
	name = dp->d_rootdir != NULL &&
	    *dp->d_rootdir != '\0' ? dp->d_rootdir : NULL;

	/*
	 * The clock must be initialized before fmd_topo_init() because
	 * fmd_topo_update() calls fmd_time_gethrtime().
	 */
	dp->d_clockptr = dp->d_clockops->fto_init();

	fmd_topo_init();

	dp->d_xprt_ids = fmd_idspace_create("xprt_ids", 1, INT_MAX);
	fmd_xprt_suspend_all();

	(void) door_server_create(fmd_door);

	dp->d_rmod->mod_timerids = fmd_idspace_create(dp->d_pname, 1, 16);
	dp->d_timers = fmd_timerq_create();
	dp->d_disp = fmd_dispq_create();
	dp->d_cases = fmd_case_hash_create();

	/*
	 * The root module's mod_queue is created with limit zero, making it
	 * act like /dev/null; anything inserted here is simply ignored.
	 */
	dp->d_rmod->mod_queue = fmd_eventq_create(dp->d_rmod,
	    &dp->d_rmod->mod_stats->ms_evqstat, &dp->d_rmod->mod_stats_lock, 0);

	/*
	 * Once our subsystems that use signals have been set up, install the
	 * signal handler for the fmd_thr_signal() API.  Verify that the signal
	 * being used for this purpose doesn't conflict with something else.
	 */
	(void) fmd_conf_getprop(dp->d_conf, "client.thrsig", &dp->d_thr_sig);

	if (sigaction(dp->d_thr_sig, NULL, &act) != 0) {
		fmd_error(EFMD_EXIT, "invalid signal selected for "
		    "client.thrsig property: %d\n", dp->d_thr_sig);
	}

	if (act.sa_handler != SIG_IGN && act.sa_handler != SIG_DFL) {
		fmd_error(EFMD_EXIT, "signal selected for client.thrsig "
		    "property is already in use: %d\n", dp->d_thr_sig);
	}

	act.sa_handler = fmd_signal;
	act.sa_flags = 0;

	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(dp->d_thr_sig, &act, NULL);

	(void) fmd_conf_getprop(dp->d_conf, "schemedir", &name);
	dp->d_schemes = fmd_scheme_hash_create(dp->d_rootdir, name);

	(void) fmd_conf_getprop(dp->d_conf, "log.rsrc", &name);
	dp->d_asrus = fmd_asru_hash_create(dp->d_rootdir, name);

	(void) fmd_conf_getprop(dp->d_conf, "log.error", &name);
	dp->d_errlog = fmd_log_open(dp->d_rootdir, name, FMD_LOG_ERROR);

	(void) fmd_conf_getprop(dp->d_conf, "log.fault", &name);
	dp->d_fltlog = fmd_log_open(dp->d_rootdir, name, FMD_LOG_FAULT);

	(void) fmd_conf_getprop(dp->d_conf, "log.info_hival", &name);
	dp->d_hvilog = fmd_log_open(dp->d_rootdir, name, FMD_LOG_INFO);

	(void) fmd_conf_getprop(dp->d_conf, "log.info", &name);
	dp->d_ilog = fmd_log_open(dp->d_rootdir, name, FMD_LOG_INFO);

	if (dp->d_asrus == NULL || dp->d_errlog == NULL || dp->d_fltlog == NULL)
		fmd_error(EFMD_EXIT, "failed to initialize log files\n");

	/*
	 * Before loading modules, create an empty control event which will act
	 * as a global barrier for module event processing.  Each module we
	 * load successfully will insert it at their head of their event queue,
	 * and then pause inside of fmd_ctl_rele() after dequeuing the event.
	 * This module barrier is required for two reasons:
	 *
	 * (a) During module loading, the restoration of case checkpoints may
	 *    result in a list.* event being recreated for which the intended
	 *    subscriber has not yet loaded depending on the load order. Such
	 *    events could then result in spurious "no subscriber" errors.
	 *
	 * (b) During errlog replay, a sequence of errors from a long time ago
	 *    may be replayed, and the module may attempt to install relative
	 *    timers associated with one or more of these events.  If errlog
	 *    replay were "racing" with active module threads, an event E1
	 *    that resulted in a relative timer T at time E1 + N nsec could
	 *    fire prior to an event E2 being enqueued, even if the relative
	 *    time ordering was E1 < E2 < E1 + N, causing mis-diagnosis.
	 */
	dp->d_mod_event = e = fmd_event_create(FMD_EVT_CTL,
	    FMD_HRT_NOW, NULL, fmd_ctl_init(NULL));

	fmd_event_hold(e);

	/*
	 * Once all data structures are initialized, we load all of our modules
	 * in order according to class in order to load up any subscriptions.
	 * Once built-in modules are loaded, we detach from our waiting parent.
	 */
	dp->d_mod_hash = fmd_modhash_create();

	if (fmd_builtin_loadall(dp->d_mod_hash) != 0 && !dp->d_fg)
		fmd_error(EFMD_EXIT, "failed to initialize fault manager\n");

	(void) fmd_conf_getprop(dp->d_conf, "self.name", &name);
	dp->d_self = fmd_modhash_lookup(dp->d_mod_hash, name);

	if (dp->d_self != NULL) {
		if (fmd_module_dc_key2code(dp->d_self, nodc_key, code_str,
		    sizeof (code_str)) == 0)
			(void) fmd_conf_setprop(dp->d_conf, "nodiagcode",
			    code_str);
		if (fmd_module_dc_key2code(dp->d_self, repair_key, code_str,
		    sizeof (code_str)) == 0)
			(void) fmd_conf_setprop(dp->d_conf, "repaircode",
			    code_str);
		if (fmd_module_dc_key2code(dp->d_self, resolve_key, code_str,
		    sizeof (code_str)) == 0)
			(void) fmd_conf_setprop(dp->d_conf, "resolvecode",
			    code_str);
		if (fmd_module_dc_key2code(dp->d_self, update_key, code_str,
		    sizeof (code_str)) == 0)
			(void) fmd_conf_setprop(dp->d_conf, "updatecode",
			    code_str);
	}

	fmd_rpc_init();
	dp->d_running = 1; /* we are now officially an active fmd */

	/*
	 * Now that we're running, if a pipe fd was specified, write an exit
	 * status to it to indicate that our parent process can safely detach.
	 * Then proceed to loading the remaining non-built-in modules.
	 */
	if (pfd >= 0)
		(void) write(pfd, &status, sizeof (status));

	/*
	 * Before loading all modules, repopulate the ASRU cache from its
	 * persistent repository on disk.  Then during module loading, the
	 * restoration of checkpoint files will reparent any active cases.
	 */
	fmd_asru_hash_refresh(dp->d_asrus);

	(void) fmd_conf_getprop(dp->d_conf, "plugin.path", &pap);
	fmd_modhash_loadall(dp->d_mod_hash, pap, &fmd_rtld_ops, ".so");

	(void) fmd_conf_getprop(dp->d_conf, "agent.path", &pap);
	fmd_modhash_loadall(dp->d_mod_hash, pap, &fmd_proc_ops, NULL);

	dp->d_loaded = 1; /* modules are now loaded */

	/*
	 * With all modules loaded, replay fault events from the ASRU cache for
	 * any ASRUs that must be retired, replay error events from the errlog
	 * that did not finish processing the last time ran, and then release
	 * the global module barrier by executing a final rele on d_mod_event.
	 */
	fmd_asru_hash_replay(dp->d_asrus);

	(void) pthread_rwlock_rdlock(&dp->d_log_lock);
	fmd_log_replay(dp->d_errlog, (fmd_log_f *)fmd_err_replay, dp);
	fmd_log_update(dp->d_errlog);
	(void) pthread_rwlock_unlock(&dp->d_log_lock);

	dp->d_mod_event = NULL;
	fmd_event_rele(e);

	/*
	 * Now replay list.updated and list.repaired events
	 */
	fmd_case_repair_replay();

	/*
	 * Finally, awaken any threads associated with receiving events from
	 * open transports and tell them to proceed with fmd_xprt_recv().
	 */
	fmd_xprt_resume_all();
	fmd_gc(dp, 0, 0);
	fmd_clear_aged_rsrcs(dp, 0, 0);

	(void) pthread_mutex_lock(&dp->d_fmd_lock);
	dp->d_booted = 1;
	(void) pthread_cond_broadcast(&dp->d_fmd_cv);
	(void) pthread_mutex_unlock(&dp->d_fmd_lock);
}

void
fmd_help(fmd_t *dp)
{
	const fmd_conf_mode_t *cmp;

	(void) printf("Usage: %s -o debug=mode[,mode]\n", dp->d_pname);

	for (cmp = _fmd_debug_modes; cmp->cm_name != NULL; cmp++)
		(void) printf("\t%s\t%s\n", cmp->cm_name, cmp->cm_desc);
}
