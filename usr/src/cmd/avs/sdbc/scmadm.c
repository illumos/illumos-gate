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
 * Utility for cache configuration
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <time.h>
#include <sys/nsctl/sd_bcache.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stropts.h>
#include <ctype.h>
#include <libgen.h>

#include <sys/nsctl/sdbc_ioctl.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>
#include <nsctl.h>

#include <sys/nsctl/cfg.h>
#define	STATS_PATH	"/usr/bin/sd_stats"

#define	_SD_FNAME	/* bring in function names from sd_trace.h */
#include <sys/nsctl/sd_trace.h>
#include <sys/syslog.h>

/*
 * Since we no longer support nvram cards, the hints wrthru and nowrthru no
 * longer serve any purpose, and the system will always be in wrthru mode.
 * WRTHRU_HINTS, if defined still allows the setting and reporting of write
 * hints.  This is defined by default on DEBUG builds.
 */
#ifdef DEBUG
#define	WRTHRU_HINTS
#endif

static int sdbc_max_devices = 0;

static char alert_file[200]  = "/dev/console";

/* Variables used to set up paramater block passed to kernel */
static _sd_cache_param_t	user_level_conf;
static int			myid;

static int		nodes_configured = 0;
static int		minidsp = 0; /* Is it a sp10 */
static int		forced_wrthru = -1; /* 0 clear, 1 set,-1 as is */
static int		no_forced_wrthru = -1;
static short		node_defined[MAX_SD_NODES];
static short		nodes_conf[MAX_SD_NODES];

#define	USAGELEN	1024
char stats_usage[USAGELEN+128];
char scmadmUsage[USAGELEN];

static caddr_t progname;


/*
 * Functions exported for fwcadm.
 */
void enable_sdbc(void);
void disable_sdbc(void);
void sdbc_set_maxdev();

static void buildusage(char *);

void print_all_options(void);
void get_cd_all(void);
int toggle_flush(void);
static void sd_gather_alert_dumps();
static int get_cd(char *);
static int get_hint(char *, int *, int *);
static void check_and_set_mirrors(int, int);
static void print_hint(const uint_t, const int);
static char *get_device_name(char *arg);
static void get_version();

extern struct tm *localtime_r(const time_t *, struct tm *);

#define	PRINT_CACHE_SZ_ERR(sz) {\
	(void) fprintf(stderr, gettext("\n%s: desired cache size (%d) "\
	    "set to system max (%d)\n"), \
	    progname, (sz), MAX_CACHE_SIZE); \
	spcs_log("sdbc", NULL, \
		gettext("desired cache size (%d) "\
		    "set to system max (%d)\n"), \
		(sz), MAX_CACHE_SIZE); \
}

void
sdbc_report_error(spcs_s_info_t *ustatus)
{
	if (*ustatus != NULL) {
		spcs_s_report(*ustatus, stderr);
		spcs_s_ufree(ustatus);
	} else
		(void) fprintf(stderr, "%s\n", strerror(errno));
}


/*
 * Return the per-cd hints for a cd.
 *
 * Since the global (no)wrthru and NSC_NOCACHE hints take precedence
 * over the per-cd hints, get them as well and OR the whole lot
 * together.
 */
static int
get_cd_hint(const int cd)
{
	spcs_s_info_t ustats;
	int nodehint, cdhint;

	nodehint = SDBC_IOCTL(SDBC_GET_NODE_HINT, 0, 0, 0, 0, 0, &ustats);
	if (nodehint == SPCS_S_ERROR) {
		(void) fprintf(stderr,
		    gettext("%s: get system options failed\n"), progname);
		sdbc_report_error(&ustats);
		exit(1);
	}

	cdhint = SDBC_IOCTL(SDBC_GET_CD_HINT, cd, 0, 0, 0, 0, &ustats);
	if (cdhint == SPCS_S_ERROR) {
		(void) fprintf(stderr,
		    gettext("%s: get cd(%d) hint failed\n"), progname, cd);
		sdbc_report_error(&ustats);
		exit(1);
	}

#ifdef WRTHRU_HINTS
	nodehint &= (NSC_FORCED_WRTHRU | NSC_NO_FORCED_WRTHRU | NSC_NOCACHE);
#else
	nodehint &= (NSC_NOCACHE);
#endif
	if (nodehint) {
		/* set the top bit to mark it as a system override */
		nodehint |= 0x80000000;
	}

	return (cdhint | nodehint);
}



/*
 * Check for a config.
 *
 * If no suitable config can be found, install the default config.
 *
 * Calling state:
 *	libcfg locked (mode describes type of lock)
 */
static void
convert_config(CFGFILE *cfg, CFGLOCK mode)
{
	char buf[CFG_MAX_BUF];
	char *default_cfg = "128 64";

retry:
	if (cfg_get_cstring(cfg, "scm.set1", buf, sizeof (buf)) >= 0) {
		/* config exists, return */
		return;
	}

	cfg_rewind(cfg, CFG_SEC_CONF);

#ifdef DEBUG
	(void) printf(gettext("%s: installing default config entry '%s'\n"),
		progname, default_cfg);
#endif
	if (mode != CFG_WRLOCK) {
		cfg_unlock(cfg);
		if (!cfg_lock(cfg, CFG_WRLOCK)) {
			(void) fprintf(stderr,
			    gettext("%s: unable to lock configuration: %s\n"),
			    progname, cfg_error(NULL));
			exit(1);
		}
		mode = CFG_WRLOCK;
#ifdef DEBUG
		(void) printf(gettext("%s: upgraded lock, retrying\n"),
		    progname);
#endif
		goto retry;
	}

	if (cfg_put_cstring(cfg, "scm", default_cfg, strlen(default_cfg)) < 0) {
		(void) fprintf(stderr,
		    gettext("%s: unable to write configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	if (!cfg_commit(cfg)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to write to configuration: %s\n"),
		    progname, cfg_error(NULL));
	}

	if (mode != CFG_WRLOCK) {
		if (!cfg_lock(cfg, mode)) {
			(void) fprintf(stderr,
			    gettext("%s: unable to relock configuration: %s\n"),
			    progname, cfg_error(NULL));
			exit(1);
		}
	}

	cfg_rewind(cfg, CFG_SEC_CONF);
}


static int
iscluster(void)
{
	int rc;

	rc = cfg_iscluster();
	if (rc == 0) {
		return (FALSE);
	} else if (rc > 0) {
		return (TRUE);
	} else {
		(void) fprintf(stderr, "%s\n",
		    (gettext("%s: unable to ascertain environment"), progname));
		exit(1);
	}

	/* NOTREACHED */
}


static void
restore_hints()
{
	CFGFILE *cfg;
	char key[CFG_MAX_KEY], buf[CFG_MAX_BUF];
	int setnumber;
	spcs_s_info_t ustatus;
	int cd;

	if ((cfg = cfg_open(NULL)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: unable to access configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}
	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to lock configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	for (setnumber = 1; /*CONSTCOND*/ TRUE; setnumber++) {
		(void) snprintf(key, sizeof (key), "cache_hint.set%d.device",
		    setnumber);
		if (cfg_get_cstring(cfg,  key,  buf, sizeof (buf)) < 0) {
			/* error or not found */
			break;
		}

		if (strcmp(buf, "system") == 0) {
			cd = -1;
		} else {
			cd = get_cd(buf);
			if (cd < 0)
				continue;
		}

		(void) snprintf(key, sizeof (key), "cache_hint.set%d.wrthru",
		    setnumber);
		if (cfg_get_cstring(cfg,  key,  buf, sizeof (buf)) < 0)
			continue;

		if (atoi(buf) == 1) {
			if (cd == -1) {
				/* Node hint */
				if (SDBC_IOCTL(SDBC_SET_NODE_HINT, NSC_WRTHRU,
				    1, 0, 0, 0, &ustatus) == SPCS_S_ERROR) {
					(void) fprintf(stderr,
					    gettext("%s: set system "
					    "option failed\n"),
					    progname);
					sdbc_report_error(&ustatus);
					exit(1);
				}
			} else if (SDBC_IOCTL(SDBC_SET_CD_HINT, cd,
			    NSC_WRTHRU, 1, 0, 0, &ustatus) == SPCS_S_ERROR) {
				(void) fprintf(stderr,
				    gettext("%s: set option failed\n"),
				    progname);
				sdbc_report_error(&ustatus);
				exit(1);
			}
		}

		(void) snprintf(key, sizeof (key), "cache_hint.set%d.nordcache",
		    setnumber);
		if (cfg_get_cstring(cfg,  key,  buf, sizeof (buf)) < 0)
			continue;

		if (atoi(buf) == 1) {
			if (cd == -1) {
				/* Node hint */
				if (SDBC_IOCTL(SDBC_SET_NODE_HINT, NSC_NOCACHE,
				    1, 0, 0, 0, &ustatus) == SPCS_S_ERROR) {
					(void) fprintf(stderr,
					    gettext("%s: set system "
					    "option failed\n"),
					    progname);
					sdbc_report_error(&ustatus);
					exit(1);
				}
			} else if (SDBC_IOCTL(SDBC_SET_CD_HINT, cd, NSC_NOCACHE,
			    1, 0, 0, &ustatus) == SPCS_S_ERROR) {
				(void) fprintf(stderr,
				    gettext("%s: set option failed\n"),
				    progname);
				sdbc_report_error(&ustatus);
				exit(1);
			}
		}
	}

	cfg_close(cfg);
}

void
sdbc_set_maxdev()
{
	spcs_s_info_t ustats;

	if (SDBC_IOCTL(SDBC_MAXFILES, &sdbc_max_devices,
	    0, 0, 0, 0, &ustats) == SPCS_S_ERROR) {
		(void) fprintf(stderr, gettext("%s: get maxfiles failed\n"),
		    progname);
		sdbc_report_error(&ustats);
		exit(1);
	}
}

static void
bitmapfs_print(void)
{
	CFGFILE *cfg;
	char key[CFG_MAX_KEY], buf[CFG_MAX_BUF];
	int setnumber;

	cfg = cfg_open(NULL);
	if (cfg == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: unable to access configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to lock configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	for (setnumber = 1; /*CSTYLED*/; setnumber++) {
		(void) snprintf(key, sizeof (key),
		    "bitmaps.set%d.bitmap", setnumber);
		buf[0] = 0;

		if (cfg_get_cstring(cfg, key, buf, sizeof (buf)) < 0) {
			if (errno == ESRCH) {
				/* end of list */
				break;
			}

			(void) fprintf(stderr,
			    gettext("%s: error reading configuration: %s\n"),
			    progname, cfg_error(NULL));
			exit(1);
		}

		(void) printf("%s\n", buf);
	}

	cfg_close(cfg);
}


static void
bitmapfs_delete(char *bitmapfs)
{
	CFGFILE *cfg;
	char key[CFG_MAX_KEY], buf[CFG_MAX_BUF];
	int setnumber;
	int commit = 0;

	cfg = cfg_open(NULL);
	if (cfg == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: unable to access configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to lock configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	for (setnumber = 1; /*CSTYLED*/; setnumber++) {
		(void) snprintf(key, sizeof (key),
		    "bitmaps.set%d.bitmap", setnumber);
		buf[0] = 0;

		if (cfg_get_cstring(cfg, key, buf, sizeof (buf)) < 0) {
			if (errno == ESRCH) {
				/* end of list */
				(void) fprintf(stderr,
				    gettext("%s: %s not found "
				    "in configuration\n"),
				    progname, bitmapfs);
				break;
			}

			(void) fprintf(stderr,
			    gettext("%s: error reading configuration: %s\n"),
			    progname, cfg_error(NULL));
			exit(1);
		}

		if (strcmp(bitmapfs, buf) == 0) {
			(void) snprintf(key, sizeof (key),
			    "bitmaps.set%d", setnumber);

			if (cfg_put_cstring(cfg, key, (char *)NULL, 0) < 0) {
				(void) fprintf(stderr,
				    gettext("%s: unable to delete %s "
				    "from configuration: %s\n"),
				    progname, bitmapfs, cfg_error(NULL));
			} else
				commit++;

			break;
		}
	}

	if (commit) {
		if (!cfg_commit(cfg)) {
			(void) fprintf(stderr,
			    gettext("%s: unable to write "
			    "to configuration: %s\n"),
			    progname, cfg_error(NULL));
		}
		commit = 0;
	}

	cfg_close(cfg);
}


/*
 * User visible configuration.
 */

static const struct {
	const char *tag;	/* libcfg tag */
	const char *name;	/* user presented name */
	const char *help;	/* explanation string */
} sdbc_cfg_options[] = {
	{ "thread", "nthreads", "number of threads" },
	{ "size", "cache_size", "total cache size" },
#ifdef DEBUG
	{ "write_cache", "write_cache_size", "write cache size" },
	{ "fill_pattern", "fill_pattern", "debug fill pattern" },
	{ "reserved1", "reserved1", "unavailable, do not use" },
	{ "iobuf", "niobuf", "number of io buffers" },
	{ "tdemons", "ntdeamons", "number of sd_test daemons" },
	{ "forced_wrthru", "forced_wrthru", "override wrthru detection" },
	{ "no_forced_wrthru", "no_forced_wrthru", "override wrthru"},
#endif
	{ NULL }
};


static int
configure_sdbc(int argc, char *argv[], int optind)
{
	CFGFILE *cfg;
	char key[CFG_MAX_KEY], buf[CFG_MAX_BUF];
	char *cp, option[CFG_MAX_BUF], value[CFG_MAX_BUF];
	const int opt_width = 20;
	int error, found, commit;
	int i;

	error = commit = 0;

	cfg = cfg_open(NULL);
	if (cfg == NULL) {
		(void) fprintf(stderr, "%s: unable to open configuration: %s",
		    progname, cfg_error(NULL));
		return (1);
	}

	if (argc == optind) {
		/* display current user visible config */

		if (!cfg_lock(cfg, CFG_RDLOCK)) {
			(void) fprintf(stderr,
			    gettext("%s: unable to lock configuration: %s\n"),
			    progname, cfg_error(NULL));
			error = 1;
			goto out;
		}

		convert_config(cfg, CFG_RDLOCK);

		for (i = 0; sdbc_cfg_options[i].tag != NULL; i++) {
			(void) snprintf(key, sizeof (key),
			    "scm.set1.%s", sdbc_cfg_options[i].tag);
			if (cfg_get_cstring(cfg, key, buf, sizeof (buf)) < 0) {
				if (errno == ESRCH) {
					/* not found */
					strcpy(buf, "");
				} else {
					(void) fprintf(stderr,
					    gettext("%s: error reading "
					    "configuration: %s\n"),
					    progname, cfg_error(NULL));
					error = 1;
					goto out;
				}
			}

			(void) printf("%-*s: %-*s /* %s */\n",
			    opt_width, sdbc_cfg_options[i].name,
			    opt_width, buf, sdbc_cfg_options[i].help);
		}
	} else {
		if (!cfg_lock(cfg, CFG_WRLOCK)) {
			(void) fprintf(stderr,
			    gettext("%s: unable to lock configuration: %s\n"),
			    progname, cfg_error(NULL));
			error = 1;
			goto out;
		}

		convert_config(cfg, CFG_WRLOCK);

		for (/*CSTYLED*/; optind < argc; optind++) {
			strncpy(option, argv[optind], sizeof (option));
			option[sizeof (option) - 1] = '\0';	/* terminate */

			cp = strchr(option, '=');
			if (cp != NULL) {
				*cp = '\0';	/* terminate option */
				cp++;
				strncpy(value, cp, sizeof (value));
				value[sizeof (value) - 1] = '\0';

				if (*value == '\0')
					strncpy(value, "-", sizeof (value));
			}

			found = 0;
			for (i = 0; sdbc_cfg_options[i].tag != NULL; i++) {
				if (strcmp(option,
				    sdbc_cfg_options[i].name) == 0) {
					found = 1;
					break;
				}
			}

			if (!found) {
				(void) fprintf(stderr,
				    gettext("%s: unknown configuration "
				    "parameter: %s\n"), progname, option);
				continue;
			}

			(void) snprintf(key, sizeof (key),
			    "scm.set1.%s", sdbc_cfg_options[i].tag);
			if (cfg_get_cstring(cfg, key, buf, sizeof (buf)) < 0) {
				(void) fprintf(stderr,
				    gettext("%s: error reading "
				    "configuration: %s\n"),
				    progname, cfg_error(NULL));
				error = 1;
				goto out;
			}

			if (*buf == '\0')
				strncpy(buf, "<default>", sizeof (buf));

			if (cp != NULL) {
				char *tmp;
				long val;
				/* set to new value */

				if (strcmp(value, "-")) { /* default ? */

					val = strtol(value, &tmp, 0);
					if (strcmp(value, tmp) == 0) {
						(void) fprintf(stderr,
						    gettext(
							"%s: bad value (%s) "
							"for option %s\n"),
						    progname, value, option);
						error = 1;
						goto out;
					}

					/* make sure cache size is valid */
					if (strcmp(key, "scm.set1.size") == 0) {
						if (val > MAX_CACHE_SIZE) {
							PRINT_CACHE_SZ_ERR(val);

							/*
							 * Overwrite the
							 * cache size with
							 * the maximum cache
							 * size.
							 */
							(void) snprintf(value,
							    sizeof (value),
							    "%ld",
							    (long)
							    MAX_CACHE_SIZE);
						}
					}
				}

				if (cfg_put_cstring(cfg, key, value,
				    strlen(value)) < 0) {
					(void) fprintf(stderr,
					    gettext("\n%s: error writing "
					    "configuration: %s\n"),
					    progname, cfg_error(NULL));
					error = 1;
					goto out;
				}

				(void) snprintf(buf, sizeof (buf),
				    "%s = %s", buf,
				    (strcmp(value, "-") == 0) ?
				    "<default>" : value);

				commit = 1;
			}

			(void) printf("%-*s: %-*s /* %s */\n",
			    opt_width, sdbc_cfg_options[i].name,
			    opt_width, buf, sdbc_cfg_options[i].help);
		} /* end command line args */
	}

out:
	if (commit) {
		if (!cfg_commit(cfg)) {
			(void) fprintf(stderr,
			    gettext("%s: unable to write "
			    "to configuration: %s\n"),
			    progname, cfg_error(NULL));
		}
		commit = 0;

		(void) printf("\n%s\n",
		    gettext("Changed configuration parameters "
		    "will take effect when the cache is restarted"));
	}

	cfg_close(cfg);
	return (error);
}


static char *
cd_to_device(int cd)
{
	static _sd_stats_t *cs_cur = NULL;
	spcs_s_info_t ustatus;

	if (cs_cur == NULL) {
		cs_cur = malloc(sizeof (_sd_stats_t) +
		    (sdbc_max_devices - 1) * sizeof (_sd_shared_t));

		if (cs_cur == NULL) {
			(void) fprintf(stderr, gettext("%s malloc: %s\n"),
			    progname, strerror(errno));
			exit(1);
		}
	}

	if (SDBC_IOCTL(SDBC_STATS, cs_cur, 0, 0, 0, 0,
	    &ustatus) == SPCS_S_ERROR) {
		(void) fprintf(stderr,
		    gettext("%s: stats ioctl failed\n"), progname);
		sdbc_report_error(&ustatus);
		exit(1);
	}
	if (cs_cur->st_cachesize == 0 || cd >= cs_cur->st_count)
		return ("");

	return (cs_cur->st_shared[cd].sh_filename);
}

/*
 * takes either either a string containing the cd or the device name, and
 * returns the device name.
 */
static char *
get_device_name(char *arg)
{
	long cd = 0;
	char *device;

	/* if the arg has a leading '/', assume it's a valid device name */
	if (!arg || *arg == '/') {
		return (arg);
	}

	/* treat the "all" keyword as a valid device name */
	if (strcmp(arg, "all") == 0) {
		return (arg);
	}

	/*
	 * Next, assume it's a cd, and try to convert it to an integer, and
	 * subsequently convert that cd to its corresponding device name.
	 *
	 * Since strtol returns 0 on failure, we need to make a special case
	 * for a cd of "0", which is valid.
	 */
	if (((cd = strtol(arg, (char **)NULL, 10)) > 0) ||
	    strcmp(arg, "0") == 0) {
		device = cd_to_device((int)cd);

		/* cd_to_device returns NULL or "" on failure--check both */
		if (device && (strcmp(device, ""))) {
			/* it seems to be a valid device name */
			return (device);
		}
	}

	return (NULL);
}

static void
remove_hint(char *device)
{
	CFGFILE *cfg;
	char key[CFG_MAX_KEY], buf[CFG_MAX_BUF];
	int setnumber;
	int rc;

	if ((cfg = cfg_open(NULL)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: unable to access configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}
	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to lock configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	for (setnumber = 1; /*CONSTCOND*/ TRUE; setnumber++) {
		(void) snprintf(key, sizeof (key), "cache_hint.set%d.device",
		    setnumber);
		if (cfg_get_cstring(cfg,  key,  buf, sizeof (buf)) < 0) {
			/* error or not found */
			break;
		}

		if (strcmp(device, buf) != 0)
			continue;

		/* remove config file entry */
		(void) snprintf(key, sizeof (key),
		    "cache_hint.set%d", setnumber);
		rc = cfg_put_cstring(cfg, key, NULL, 0);
		if (rc < 0)
			(void) fprintf(stderr,
			    gettext("%s: unable to update configuration "
			    "storage: %s"),
			    progname, cfg_error(NULL));
		else if (!cfg_commit(cfg))
			(void) fprintf(stderr,
			    gettext("%s: unable to update configuration "
			    "storage: %s"),
			    progname, cfg_error(NULL));
		else
			(void) fprintf(stderr,
			    gettext("%s: persistent hint for %s"
			    " removed from configuration\n"),
			    progname, device);
		break;
	}
	cfg_close(cfg);
}


static void
save_hint(int cd, int hint, int flag)
{
	char device[NSC_MAXPATH];
	CFGFILE *cfg;
	char key[CFG_MAX_KEY], buf[CFG_MAX_BUF];
	int setnumber;
	int found;
	int rc;

	if (hint != NSC_WRTHRU && hint != NSC_NOCACHE)
		return;

	if (flag != 0 && flag != 1)
		return;

	if ((cfg = cfg_open(NULL)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: unable to access configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}
	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to lock configuration: %s\n"),
		    progname, cfg_error(NULL));
		exit(1);
	}

	if (cd == -1)
		strcpy(device, "system");
	else
		strncpy(device, cd_to_device(cd), NSC_MAXPATH);

	found = 0;
	for (setnumber = 1; /*CONSTCOND*/ TRUE; setnumber++) {
		(void) snprintf(key, sizeof (key), "cache_hint.set%d.device",
		    setnumber);
		if (cfg_get_cstring(cfg,  key,  buf, sizeof (buf)) < 0) {
			/* error or not found */
			break;
		}

		if (strcmp(device, buf) == 0) {
			found = 1;
			break;
		}
	}

	if (found) {
		if (hint == NSC_WRTHRU)
			(void) snprintf(key, sizeof (key),
			    "cache_hint.set%d.wrthru", setnumber);
		else /* NSC_NOCACHE */
			(void) snprintf(key, sizeof (key),
			    "cache_hint.set%d.nordcache", setnumber);
		if (flag == 0)
			rc = cfg_put_cstring(cfg, key, "0", 1);
		else
			rc = cfg_put_cstring(cfg, key, "1", 1);
	} else {
		strncpy(buf, device, CFG_MAX_BUF);
		if (flag == 0)
			strncat(buf, " 0 0", CFG_MAX_BUF);
		else if (hint == NSC_WRTHRU)
			strncat(buf, " 1 0", CFG_MAX_BUF);
		else /* NSC_NOCACHE */
			strncat(buf, " 0 1", CFG_MAX_BUF);
		rc = cfg_put_cstring(cfg, "cache_hint", buf, sizeof (buf));
	}

	if (rc < 0)
		(void) fprintf(stderr,
		    gettext("%s: unable to update configuration storage: %s"),
		    progname, cfg_error(NULL));
	else if (!cfg_commit(cfg))
		(void) fprintf(stderr,
		    gettext("%s: unable to update configuration storage: %s"),
		    progname, cfg_error(NULL));
	cfg_close(cfg);
}

#ifdef lint
int
scmadm_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	int o = 0;
	int c;
	int errflg = 0;
	int hflag = 0;
	int qflag = 1;
	extern int optind;
	extern char *optarg;
	int cd;
	int hint;
	int flag;
	int optflag = 0;
	spcs_s_info_t ustats;
	int Dopt, Lopt;
	int Oopt = 0;
	char *bitmapfs = NULL;
	const char *exclusive = gettext(
	    "-d, -e, -m, -o, -C, -D, -L, and -v "
	    "are mutually exclusive\n");

	(void) setlocale(LC_ALL, "");
	(void) textdomain("scm");

	progname = strdup(basename(argv[0]));

	sdbc_set_maxdev();

	buildusage(progname);

	Dopt = Lopt = 0;

	while ((c = getopt(argc, argv,
#ifdef DEBUG
	    "gi:t:S"
#endif
	    "CD:LOa:devqhm:o:")) != EOF) {

		switch (c) {

		case 'D':
			if (optflag) {
				(void) fprintf(stderr, exclusive);
				goto usage;
			}

			Dopt++;
			optflag++;
			bitmapfs = optarg;
			break;

		case 'L':
			if (optflag) {
				(void) fprintf(stderr, exclusive);
				goto usage;
			}

			Lopt++;
			optflag++;
			break;

#ifdef DEBUG
		case 'S':
			if (optflag) {
				(void) fprintf(stderr, exclusive);
				goto usage;
			}

			if (putenv(stats_usage) != 0) {
				(void) fprintf(stderr,
				    gettext("%s: unable to putenv()\n"),
				    progname);
				exit(1);
			}

			argv[1] = "scmadm";
			if (execv(STATS_PATH, &argv[1]) == -1) {
				(void) fprintf(stderr,
				    gettext("%s: failed to execute " STATS_PATH
					"\n"), progname);
				(void) fprintf(stderr,
				    gettext("Please be sure to copy sd_stats"
					" from src/cmd/ns/sdbc in a development"
					" workspace\n"));
			}
			exit(0);
			break;
#endif
		case 'a':
			strcpy(alert_file, optarg);
			break;
		case 'q':
			qflag++;
			break;
		case 'O': /* restore hints */
			Oopt++;
			break;
		case 'C': /* configure */
		case 'e': /* enable */
		case 'd': /* disable */
		case 'v': /* get version */
		case 'o': /* get/set options */
		case 'm': /* get cd map */
#ifdef DEBUG
		case 't': /* trace */
		case 'i': /* inject_ioerr */
		case 'c': /* clear_ioerr */
		case 'g': /* toggle_flush */
#endif
			if (optflag) {
				(void) fprintf(stderr,
#ifdef DEBUG
				    "%s%s", gettext("-t, -i, -c, -g, "),
#endif
				    exclusive);

				errflg++;
			}
			optflag++;
			o = c;
			break;
		case 'h':
			hflag = 1;
			break;
		case '?':
		default:
			errflg++;
			break;
		}
		if (errflg || hflag)
			goto usage;
	}

	if (Oopt) {
		/* Set hints saved in persistent configuration */
		restore_hints();
		exit(0);
	}
	if (Dopt || Lopt) {
		/* bitmapfs control */

		if (iscluster()) {
			(void) fprintf(stderr,
			    gettext("%s: bitmap filesystems are not "
			    "allowed in a cluster\n"), progname);
			goto usage;
		}

		if ((Dopt + Lopt) > 1) {
			(void) fprintf(stderr, gettext("-D and -L are"
			    "mutually exclusive\n"));
			goto usage;
		}

		if (Lopt)
			bitmapfs_print();
		else /* if (Dopt) */
			bitmapfs_delete(bitmapfs);

		exit(0);
	}

	if (!o) {
		if (argc > 1)
			goto usage;
		(void) printf(gettext("%s: Printing all cd's and options:\n"),
		    progname);
		print_all_options();
	}

	/* Configure */
	if (o == 'C') {
		exit(configure_sdbc(argc, argv, optind));
	}
	/* enable */
	if (o == 'e') {
		enable_sdbc();
		if (qflag == 0)
			sd_gather_alert_dumps();
		exit(0);
	}
	/* disable */
	if (o == 'd') {
		disable_sdbc();
		exit(0);
	}
	/* get version */
	if (o == 'v') {
		get_version();
		exit(0);
	}
	/* node_hint or cd_hint */
	if (o == 'o') {
		if (!(strcoll(optarg, "system"))) {  /* node_hint */
			if ((optind - 1) == (argc - 1)) {  /* get */
				if ((hint = SDBC_IOCTL(SDBC_GET_NODE_HINT, 0, 0,
				    0, 0, 0, &ustats)) == SPCS_S_ERROR) {
					(void) fprintf(stderr,
					    gettext("%s: get system "
					    "options failed\n"),
					    progname);
					sdbc_report_error(&ustats);
					exit(1);
				}
#ifdef WRTHRU_HINTS
				(void) printf(gettext("System Status: "));
				print_hint(hint, 1);
#endif
				(void) printf(gettext("System Options: "));
				print_hint(hint, 0);
				exit(0);
			} else {  /* set, clear */
				if (get_hint(argv[optind], &hint, &flag) == -1)
					goto usage;
				if (hint == -1) {
					/* remove hint from config */
					remove_hint("system");
					exit(0);
				}

				if (SDBC_IOCTL(SDBC_SET_NODE_HINT, hint, flag,
				    0, 0, 0, &ustats) == SPCS_S_ERROR) {
					(void) fprintf(stderr,
					    gettext("%s: set system "
					    "option failed\n"),
					    progname);
					sdbc_report_error(&ustats);
					exit(1);
				}
				save_hint(-1, hint, flag);
				(void) printf(gettext("%s: System option %s"
				    " now set.\n"), progname, argv[optind]);
				exit(0);
			}
		} else {  /* cd_hint */
			cd = get_cd(optarg);
			if ((optind - 1) == (argc - 1)) {  /* get */
				if (cd < 0) {
					(void) fprintf(stderr,
					    gettext("%s: device %s not "
					    "found\n"),
					    progname, optarg);
					exit(1);
				}
				hint = get_cd_hint(cd);
				(void) printf(gettext("%s: cd(%d) Current "
				    "options are: "), progname, cd);
				print_hint(hint, 0);
				exit(0);
			} else { /* set, clear */
				if (get_hint(argv[optind], &hint, &flag) == -1)
					goto usage;
				if (hint == -1) {
					/* remove hint from config */
					if (cd < 0)
						remove_hint(optarg);
					else
						remove_hint(cd_to_device(cd));
					exit(0);
				}
				if (cd < 0) {
					(void) fprintf(stderr,
					    gettext("%s: device %s not "
					    "found\n"),
					    progname, optarg);
					exit(1);
				}

				if (SDBC_IOCTL(SDBC_SET_CD_HINT, cd, hint,
				    flag, 0, 0, &ustats) == SPCS_S_ERROR) {
					(void) fprintf(stderr,
					    gettext("%s: set option "
					    "failed\n"), progname);
					sdbc_report_error(&ustats);
					exit(1);
				}
				save_hint(cd, hint, flag);
				(void) printf(gettext("%s: cd %d option %s now"
				    " set.\n"), progname, cd, argv[optind]);
				exit(0);
			}
		}
	}

	if (o == 'm') {   /* "get_cd" = map */
		char *dev_name;

		if (!(strcoll(optarg, "all"))) /* all */
			(void) get_cd_all();
		else {
			cd = get_cd(optarg);
			if (cd < 0) {
				(void) fprintf(stderr,
				    gettext("%s: device or cd %s not found\n"),
				    progname, optarg);
				exit(1);
			}

			if ((dev_name = get_device_name(optarg)) == NULL) {
				(void) fprintf(stderr, gettext(
				    "%s: device for cd %d not found\n"),
				    progname, cd);
				exit(1);
			}

			(void) printf(gettext("%s: diskname %s; cd %d\n"),
			    progname, dev_name, cd);
			exit(0);
		}
	}

#ifdef DEBUG
	if (o == 't') { /* "trace" */
		int flag, value;
		_sdtr_table_t tt;
		if ((optind+1) != (argc-1))
			goto usage;
		cd = get_cd(argv[optind]);
		if (cd < 0) {
			(void) fprintf(stderr,
			    gettext("%s: device or cd %s not found\n"),
			    progname, argv[optind]);
			exit(1);
		}

		value = strtol(argv[optind+1], 0, 0);
		if (!(strcoll(optarg, gettext("size")))) {
			flag = SD_SET_SIZE;
			tt.tt_max = value;
		} else if (!(strcoll(optarg, gettext("mask")))) {
			flag = SD_SET_MASK;
			tt.tt_mask = value;
		} else if (!(strcoll(optarg, gettext("lbolt")))) {
			flag = SD_SET_LBOLT;
			tt.tt_lbolt = value;
		} else if (!(strcoll(optarg, gettext("good")))) {
			flag = SD_SET_GOOD;
			tt.tt_good = value;
		} else	goto usage;

		if (SDBC_IOCTL(SDBC_ADUMP, (long)cd, &tt, NULL, 0L,
		    (long)flag, &ustats) == SPCS_S_ERROR) {
			(void) fprintf(stderr,
			    gettext("%s: trace %s failed\n"),
			    progname, optarg);
			sdbc_report_error(&ustats);
			exit(1);
		}
		(void) printf(gettext("%s: trace %s processed\n"),
		    progname, optarg);
		if (cd != -1)
			(void) printf(gettext(" cd %d; size %d; mask 0x%04x; "
			    "lbolt %d; good %d;\n"),
			    cd, tt.tt_max, tt.tt_mask,
			    tt.tt_lbolt, tt.tt_good);
		exit(0);
	}

	if (o == 'i') { /* "inject_ioerr" */
		int ioj_err = EIO;
		int cd;
		int ioj_cnt = 0;

		/* a cd of "-1" represents all devices */
		if (strcmp(optarg, "-1") == 0) {
			cd = -1;
		} else if ((cd = get_cd(optarg)) < 0) {
			(void) fprintf(stderr,
			    gettext("%s: device or cd %s not found\n"),
			    progname, optarg);
			exit(1);
		}
		if (argc == 4)
			ioj_err = strtol(argv[optind], 0, 0);
		if (argc == 5)
			ioj_cnt = strtol(argv[optind+1], 0, 0);

		if (SDBC_IOCTL(SDBC_INJ_IOERR, cd, ioj_err, ioj_cnt, 0, 0,
		    &ustats) == SPCS_S_ERROR)  {
			(void) fprintf(stderr,
			    gettext("%s: i/o error injection for cd %s "
			    "failed\n"), progname, optarg);
			sdbc_report_error(&ustats);
			exit(1);
		}
		(void) printf(gettext("%s: i/o error injection cd %d errno %d "
		    "processed\n"), progname, cd, ioj_err);
		exit(0);
	}

	if (o == 'c') { /* "clear_ioerr" */
		int cd;

		/* a cd of "-1" represents all devices */
		if (strcmp(optarg, "-1") == 0) {
			cd = -1;
		} else if ((cd = get_cd(optarg)) < 0) {
			(void) fprintf(stderr,
			    gettext("%s: device or cd %s not found\n"),
			    progname, optarg);
			exit(1);
		}

		if (SDBC_IOCTL(SDBC_CLR_IOERR, cd, 0, 0, 0, 0, &ustats)
		    == SPCS_S_ERROR) {
			(void) fprintf(stderr,
			    gettext("%s: i/o error clear %s failed\n"),
			    progname, optarg);
			sdbc_report_error(&ustats);
			exit(1);
		}
		(void) printf(gettext("%s: i/o error clear for cd %d "
		    "processed\n"), progname, cd);
		exit(0);
	}

	if (o == 'g') { /* "toggle_flush" */
		flag = toggle_flush();
		(void) printf(gettext("%s: sdbc cache flush now %s\n"),
		    progname, flag ? "on" : "off");
		exit(0);
	}
#endif /* DEBUG */

	return (0);
usage:
	(void) fprintf(stderr, "%s\n", scmadmUsage);
	if (hflag) {
		return (0);
	}
	return (1);
}


#define	addusage(f__)	\
	strncat(scmadmUsage, f__, sizeof (scmadmUsage));

#define	addusage1(f__, a__)	\
	(void) snprintf(fmt, sizeof (fmt), "%s%s", scmadmUsage, f__);	\
	(void) snprintf(scmadmUsage, sizeof (scmadmUsage), fmt, a__);

#define	addusage2(f__, a__, b__)	\
	(void) snprintf(fmt, sizeof (fmt), "%s%s", scmadmUsage, f__);	\
	(void) snprintf(scmadmUsage, sizeof (scmadmUsage), fmt, a__, b__);

static void
buildusage(char *p)
{
	char fmt[USAGELEN];
#ifdef WRTHRU_HINTS
	char *hints_str = "[nordcache|rdcache|wrthru|nowrthru|forget]\n";
#else
	char *hints_str = "[nordcache|rdcache|forget]\n";
#endif

	bzero(scmadmUsage, sizeof (scmadmUsage));
	bzero(fmt, sizeof (fmt));

	addusage(gettext("Usage :\n"));
	addusage1(gettext("\t%s\n"), p);
	addusage1(gettext("\t%s -h\n"), p);
	addusage1(gettext("\t%s -e\n"), p);
	addusage1(gettext("\t%s -d\n"), p);
	addusage1(gettext("\t%s -v\n"), p);
	addusage1(gettext("\t%s {-L | -D bitmapfs}\n"), p);
	addusage1(gettext("\t%s -C [parameter[=[value]] ...]\n"), p);
	addusage2(gettext("\t%s -o system %s"), p, hints_str);
	addusage2(gettext("\t%s -o <cd> %s"), p, hints_str);
	addusage2(gettext("\t%s -o <diskname> %s"), p, hints_str);
	addusage1(gettext("\t%s -m {<cd>|<diskname>|all}\n"), p);
#ifdef DEBUG
	addusage1(gettext(
	    "\t%s -S [-Mz] [-d delay_time] [-l logfile] [-r range]\n"), p);
	addusage1(gettext(
	    "\t%s -t {size|mask|lbolt|good} <cd|diskname> <value>\n"), p);
	addusage1(gettext("\t%s -g\n"), p);
	addusage1(gettext(
	    "\t%s -i {cd|diskname|-1 for all} [errno [countdown]]\n"), p);
	addusage1(gettext("\t%s -c {cd|diskname|-1 for all}\n"), p);
	addusage(gettext("\nt = trace\tg = toggle_flush\ti = inject ioerr\n"
	    "c = clear ioerr\tS = stats\n"));
#endif /* DEBUG */
	addusage(gettext(
	    "e = enable\td = disable\tv=version\to = get/ set options\n"));
	addusage(gettext(
	    "m = get cd map\n"));
	addusage1(gettext(
	    "note: cd is a cache descriptor integer in the range [0-%d]\n"),
	    sdbc_max_devices - 1);
	addusage(gettext(
	    "      bitmapfs is a block device or filesystem mount point\n"));

#ifdef DEBUG
	(void) snprintf(stats_usage, sizeof (stats_usage),
	    "SD_STATS_USAGE=%s", scmadmUsage);
#endif
}

static int
get_hint(char *str,  int *hint, int *flag)
{
#ifdef WRTHRU_HINTS
	if (!(strcoll(str, gettext("wrthru")))) {
		*hint = NSC_WRTHRU;
		*flag = 1;
		return (0);
	} else if (!(strcoll(str, gettext("nowrthru")))) {
		*hint =  NSC_WRTHRU;
		*flag = 0;
		return (0);
	} else
#endif
	if (!(strcoll(str, gettext("nordcache")))) {
		*hint = NSC_NOCACHE;
		*flag = 1;
		return (0);
	} else if (!(strcoll(str, gettext("rdcache")))) {
		*hint = NSC_NOCACHE;
		*flag = 0;
		return (0);
	} else if (!(strcoll(str, gettext("forget")))) {
		*hint = -1;
		*flag = 0;
		return (0);
	}
	return (-1);
}

/*ARGSUSED*/
void
print_hint(const uint_t type, const int status)
{
#ifdef WRTHRU_HINTS
	if (status) {
		if (type & NSC_FORCED_WRTHRU) {
			(void) printf(gettext("Fast Writes Overridden\n"));
		} else {
			/* if (type & NSC_NO_FORCED_WRTHRU) */
			(void) printf(gettext("default\n"));
		}
	} else {
		(void) printf("%swrthru, %srdcache",
		    (type & (NSC_FORCED_WRTHRU|NSC_WRTHRU)) ? "" : "no",
		    (type & NSC_NOCACHE) ? "no" : "");
#else
	{
		(void) printf("%srdcache", (type & NSC_NOCACHE) ? "no" : "");
#endif

		if (type & 0x80000000)
			(void) printf(" (overridden by system)");

		(void) printf("\n");
	}
}

/*
 * Read the configuration via libcfg
 */

int
get_cache_config()
{
	int i;
	int sysid;
	CFGFILE *cfg;
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];


	if ((cfg = cfg_open(NULL)) == NULL) {
		(void) fprintf(stderr,
		    gettext("Cannot open configuration file\n"));
		exit(1);
	}

	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		(void) fprintf(stderr,
		    gettext("Cannot lock configuration file\n"));
		exit(1);
	}

	convert_config(cfg, CFG_RDLOCK);
	(void) memset((char *)&user_level_conf, 0, sizeof (_sd_cache_param_t));

	/* Get the system ID */
	if (nsc_getsystemid(&sysid) < 0) {
		(void) fprintf(stderr,
		    gettext("%s Unable to obtain subsystem ID: %s\n"),
		    progname, strerror(errno));
		exit(1);
	}
	myid = sysid;

	user_level_conf.blk_size = 8192;	/* DEFAULT */
	user_level_conf.procs = 16;	/* DEFAULT */
	user_level_conf.reserved1 = RESERVED1_DEFAULTS;

	bzero(buf, CFG_MAX_BUF);
	(void) snprintf(key, sizeof (key), "scm.set1.thread");
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) > 0) {
		user_level_conf.threads = atoi(buf);
	} else
		user_level_conf.threads = 128;	/* DEFAULT */

	(void) snprintf(key, sizeof (key), "scm.set1.tdemons");
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) > 0) {
		user_level_conf.test_demons = atoi(buf);
	}

	(void) snprintf(key, sizeof (key), "scm.set1.write_cache");
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) > 0) {
		user_level_conf.write_cache = atoi(buf);
	}

	(void) snprintf(key, sizeof (key), "scm.set1.size");
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) > 0) {
		/*
		 * We need to run strtol for backwards compatibility in 3.2.
		 * A workaround for this bug was put in 3.2 which allowed
		 * customers to set the cache size up to 1024 if it was
		 * specified in hexadecimal. Decimal still had the limit
		 * of 128.  This change treats them both identically.
		 */
		user_level_conf.cache_mem[0] = (int)strtol(buf, NULL, 0);
		if (user_level_conf.cache_mem[0] > MAX_CACHE_SIZE) {
			(void) fprintf(stderr, gettext(
			    "The cache size of %ld is larger than "
			    "the system maximum of %ld.\nUse \"scmadm -C "
			    "cache_size=<size>\" to set the size to a proper "
			    "value.\n"),
			    user_level_conf.cache_mem[0], MAX_CACHE_SIZE);
			user_level_conf.cache_mem[0] = MAX_CACHE_SIZE;
		}
	}

	(void) snprintf(key, sizeof (key), "scm.set1.iobuf");
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) > 0) {
		user_level_conf.iobuf = atoi(buf);
	}

	(void) snprintf(key, sizeof (key), "scm.set1.fill_pattern");
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) > 0) {
		user_level_conf.fill_pattern = atoi(buf);
		user_level_conf.gen_pattern = 1;
	}

	(void) snprintf(key, sizeof (key), "scm.set1.no_forced_wrthru");
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) > 0) {
		no_forced_wrthru = atoi(buf);
	}

	(void) snprintf(key, sizeof (key), "scm.set1.forced_wrthru");
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) > 0) {
		forced_wrthru = atoi(buf);
	}

	(void) snprintf(key, sizeof (key), "scm.set1.reserved1");
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) > 0) {
		user_level_conf.reserved1 = atoi(buf);
	}

	cfg_close(cfg);

	/*
	 * use the default minidsp configuration if no
	 * node/mirror/remote-mirror/cluster line is in the sd.cf file
	 */
	if (nodes_configured == 0)
		check_and_set_mirrors(myid, _SD_NO_HOST);


	/* Check if our sysid was defined */
	if (!node_defined[myid]) {
		(void) fprintf(stderr,
		    gettext("This node(%d) is not defined in config.\n"), myid);
		exit(1);
	}

	/*
	 * Save off number of nodes so we can calculate the point-to-point
	 * segements.  Code in kernel currently supports MAX_SD_NODES
	 */
	if ((user_level_conf.num_nodes = nodes_configured) >
	    MAX_SD_NODES) {
		(void) fprintf(stderr,
		    gettext("Cache can support only %d nodes(%d).\n"),
		    MAX_SD_NODES, nodes_configured);
		exit(1);
	}

	if ((nodes_configured % 2) && !minidsp) {
		if (nodes_configured == 1)
			(void) fprintf(stderr,
			    gettext("Only one node configured, "
			    "mirror node must be %d\n"), _SD_NO_HOST);
		else
			(void) fprintf(stderr,
			    gettext("Cannot configure odd number of nodes.\n"));
		exit(1);
	}


	/* Pass List of Nodes Configured to Cache */
	for (i = 0; i < nodes_configured; i++)
		user_level_conf.nodes_conf[i] = nodes_conf[i];

	/* Place magic number in user_level_conf.  Kernel will test for it */
	user_level_conf.magic = _SD_MAGIC;
	(void) sleep(1);
	return (0);
}

_sdtr_t hdr;

/* function name string */
char *
_sd_fname(int f)
{
	int fn = f & ST_FUNC;
	static char c[8];
	char *s;

	if (f & ST_BCACHE)
		s = _bcache_fname[fn];
	else if (f & ST_BSUB)
		s = _bsub_fname[fn];
	else if (f & ST_IO)
		s = _io_fname[fn];
	else if (f & ST_STATS)
		s = _stats_fname[fn];
	else if (f & ST_CCIO)
		s = _ccio_fname[fn];
	else if (f & ST_FT)
		s = _ft_fname[fn];
	else if (f & ST_INFO)
		s = _info_fname[fn];
	if (!s)
		(void) sprintf(s = c, "0x%04x", f & 0xffff);
	return (s);
}

int alerts = 0;

/*
 * Background daemon to wait for alert (on any device)
 * Writes the traces to "sd_alert.CD.NUM",
 * and writes an information message to the alert_file.
 */

void
sd_gather_alert_dumps()
{
	_sdtr_table_t tt;
	_sdtr_t *buf;
	int cd, count, size, flag;
	char filename[64];
	int fd;
	time_t tloc;
	struct tm tm_storage;
	struct tm *tm_ptr;
	char timebuf[80];
	spcs_s_info_t ustats;

	/* fork and detach daemon */
	if (fork())
		exit(0);
	(void) close(0);
	fd = open(alert_file, O_WRONLY|O_APPEND|O_CREAT, 0644);
	if (fd == -1)
		fd = open("/dev/console", O_WRONLY);
	if (fd != -1) {
		(void) dup2(fd, 1);
		(void) dup2(fd, 2);
		(void) close(fd);
	}
	(void) setsid();

	size = 10000;
	if (size < user_level_conf.trace_size)
		size = user_level_conf.trace_size;

	buf = (_sdtr_t *)malloc(size * sizeof (_sdtr_t));
	if (!buf) {
		(void) fprintf(stderr, gettext("%s malloc: %s\n"),
		    progname, strerror(errno));
		exit(1);
	}
	tloc = time(NULL);
	tm_ptr = (struct tm *)localtime_r(&tloc, &tm_storage);

loop:
	cd = SDT_ANY_CD;		/* any device */
	flag = SD_ALERT_WAIT;	/* block for alert */
	if ((count = SDBC_IOCTL(SDBC_ADUMP, cd, &tt, buf, size,
		flag, &ustats)) == SPCS_S_ERROR) {
		(void) fprintf(stderr, gettext("%s: sd_adump\n"), progname);
		sdbc_report_error(&ustats);
		if (errno == EIDRM) {
			(void) strftime(timebuf, 80, "%x %X", tm_ptr);
			(void) fprintf(stderr,
			    gettext("%s: cache deconfigured at %s\n"),
			    progname, timebuf);
			exit(0);
		}
		if (errno == ENOSYS)
			exit(0);
		exit(errno);
	}
	if (count == 0)
		goto loop;
	cd = tt.tt_cd;
	(void) sprintf(filename, "%s.%d.%d", "sd_alert", cd, alerts++);
	if ((fd = open(filename, O_CREAT | O_RDWR, 0444)) == -1) {
		(void) fprintf(stderr, gettext("%s: open: %s\n"),
		    progname, strerror(errno));
		exit(errno);
	}
	/*
	 * write header to identify device, write entries
	 */
	hdr.t_func = SDF_CD;
	hdr.t_len = count;
	hdr.t_ret = tt.tt_cd;
	if (write(fd, &hdr, sizeof (_sdtr_t)) == -1) {
		(void) fprintf(stderr, gettext("%s: write: %s\n"),
		    progname, strerror(errno));
		exit(errno);
	}

	if (write(fd, buf, sizeof (_sdtr_t)*count) == -1) {
		(void) fprintf(stderr, gettext("%s: write: %s\n"),
		    progname, strerror(errno));
		exit(errno);
	}
	(void) close(fd);

	(void) strftime(timebuf, 80, "%x %X", tm_ptr);
	(void) printf("sd alert trace dump %s at %s\n", filename, timebuf);
	goto loop;
}



/*
 * print list of configured cd's, diskname, options and global options
 */
void
print_all_options()
{
	static _sd_stats_t *cs_cur;
	spcs_s_info_t ustats;
	int cd;
	int hint;
	char *s1 = "device name";
	char *s2 = "option";
	char fn[19];
	int len;

	/* No corresponding free because this function exits */
	cs_cur = malloc(sizeof (_sd_stats_t) +
	    (sdbc_max_devices - 1) * sizeof (_sd_shared_t));
	if (cs_cur == NULL) {
		(void) fprintf(stderr, gettext("%s malloc: %s\n"),
		    progname, strerror(errno));
		exit(1);
	}

	/* node hints */
	if ((hint = SDBC_IOCTL(SDBC_GET_NODE_HINT, 0, 0, 0, 0, 0,
	    &ustats)) == SPCS_S_ERROR) {
		(void) fprintf(stderr,
		    gettext("%s: get system option failed\n"),
		    progname);
		sdbc_report_error(&ustats);
		exit(1);
	}
#ifdef WRTHRU_HINTS
	(void) printf(gettext("System Status: "));
	print_hint(hint, 1);
#endif
	(void) printf(gettext("System Options: "));
	print_hint(hint, 0);

	/* get cds */
	if (SDBC_IOCTL(SDBC_STATS, cs_cur, 0, 0, 0, 0, &ustats)
	    == SPCS_S_ERROR) {
		(void) fprintf(stderr,
		    gettext("%s: get_cd failed in print_all options\n"),
		    progname);
		sdbc_report_error(&ustats);
		exit(1);
	}
	if (cs_cur->st_cachesize == 0)
		(void) printf(gettext("Cache is disabled\n"));
	else if (cs_cur->st_count == 0)
		(void) printf(gettext("No devices are configured\n"));
	else {
		(void) printf(
		    gettext("\nConfigured cd's, disknames and options: \n"));
		(void) printf(gettext("cd\t%-28s\t%-20s\n"), s1, s2);
		for (cd = 0; cd < cs_cur->st_count; cd++) {
			if (cs_cur->st_shared[cd].sh_alloc) {
				hint = get_cd_hint(cd);
				if ((len =
				    strlen(cs_cur->st_shared[cd].sh_filename))
				    > 23) {
					strcpy(fn, "...");
					strcat(fn,
					    cs_cur->st_shared[cd].sh_filename +
					    len - 20);
				} else {
					strcpy(fn,
					    cs_cur->st_shared[cd].sh_filename);
				}

				(void) printf(gettext("%d\t%-28.*s\t"), cd,
				    NSC_MAXPATH, fn);

				print_hint(hint, 0);
			}
		}
	}
	exit(0);
}


/*
 * cache device -- lookup names and cache descriptors of all configured devices
 */
void
get_cd_all()
{
	static _sd_stats_t *cs_cur;
	spcs_s_info_t ustats;
	int cd;
	char fn[19];
	int len;

	/* No corresponding free because this function exits */
	cs_cur = malloc(sizeof (_sd_stats_t) +
	    (sdbc_max_devices - 1) * sizeof (_sd_shared_t));
	if (cs_cur == NULL) {
		(void) fprintf(stderr, gettext("%s malloc: %s\n"),
		    progname, strerror(errno));
		exit(1);
	}

	if (SDBC_IOCTL(SDBC_STATS, cs_cur, 0, 0, 0, 0, &ustats)
	    == SPCS_S_ERROR) {
		(void) fprintf(stderr, gettext("%s: get_cd_all"),
		    progname);
		sdbc_report_error(&ustats);
		exit(1);
	}
	if (cs_cur->st_cachesize == 0)
		(void) printf(gettext("Cache is disabled\n"));
	else if (cs_cur->st_count == 0)
		(void) printf(gettext("No devices are configured\n"));
	else {
		(void) printf(gettext("\tcd\tdevice name\n"));
		for (cd = 0; cd < cs_cur->st_count; cd++) {
			if (cs_cur->st_shared[cd].sh_alloc) {
				if ((len = strlen(
				    cs_cur->st_shared[cd].sh_filename)) > 15) {
					strcpy(fn, "...");
					strcat(fn,
					    cs_cur->st_shared[cd].sh_filename +
					    len - 12);
				} else {
					strcpy(fn,
					    cs_cur->st_shared[cd].sh_filename);
				}
				(void) printf(gettext("\t%d\t%s\n"),
				    cd, fn);
			}
		}
	}
	exit(0);
}

/*
 * cache device -- specified by number or lookup name
 */
static int
get_cd(char *s)
{
	static _sd_stats_t *cs_cur = NULL;
	spcs_s_info_t ustats;
	int cd, arg_cd = -1;

	if (cs_cur == NULL) {
		/*
		 * No corresponding free because the memory is reused
		 * every time the function is called.
		 */
		cs_cur = malloc(sizeof (_sd_stats_t) +
		    (sdbc_max_devices - 1) * sizeof (_sd_shared_t));
		if (cs_cur == NULL) {
			(void) fprintf(stderr, gettext("%s malloc: %s\n"),
			    progname, strerror(errno));
			exit(1);
		}
	}

	if (SDBC_IOCTL(SDBC_STATS, cs_cur, 0, 0, 0, 0, &ustats)
	    == SPCS_S_ERROR) {
		(void) fprintf(stderr, gettext("%s: get_cd\n"), progname);
		sdbc_report_error(&ustats);
		exit(1);
	}
	if (cs_cur->st_cachesize == 0) {
		(void) printf(gettext("Cache is disabled\n"));
		exit(0);
	}

	if (*s != '/') {
		/*
		 * Since strtol returns 0 on failure, we need to make a
		 * special case for a cd of "0", which is valid.
		 *
		 * This case also deals with the difference between
		 * scmadm -o system and scmadm -o 0
		 */
		if (((int)strtol(s, (char **)NULL, 10) == 0) &&
		    strcmp(s, "0"))
			return (-1);

		/*
		 * Only return failure at this point, in order to allow
		 * checking arg_cd against st_count later on.
		 */
		if ((arg_cd = strtol(s, 0, 0)) < 0) {
			return (arg_cd);
		}
	}

	/* make sure the cd passed as an argument is alloc'd and < st_count */
	if (arg_cd >= 0) {
		return (((arg_cd < cs_cur->st_count) &&
		    (cs_cur->st_shared[arg_cd].sh_alloc)) ? arg_cd : -1);
	}

	for (cd = 0; cd < cs_cur->st_count; cd++) {
		if (cs_cur->st_shared[cd].sh_alloc &&
		    strcmp(s, cs_cur->st_shared[cd].sh_filename) == 0)
			return (cd);
	}
	return (-1);
}

void
check_and_set_mirrors(int node, int mirror)
{

	if (minidsp) {
		(void) fprintf(stderr,
		    gettext("%s: minidsp defined. "
		    "Cannot define other nodes.\n"),
		    progname);
		exit(1);
	}

	if (mirror == _SD_NO_HOST) {
		minidsp++;
	} else if ((!(node % 2) && !(node == mirror - 1)) ||
	    (((node % 2) && !(node == mirror + 1)))) {
		(void) fprintf(stderr,
		    gettext("%s: Node and Mirror identification values "
		    "must be consecutive\n"
		    "starting at an even number (Node = %d Mirror = %d)\n"),
		    progname, node, mirror);
		exit(1);
	}

	node_defined[node]++;

	nodes_conf[nodes_configured] = node;
	nodes_configured++;

	if (node == myid) {
		user_level_conf.mirror_host  = mirror;
	}
}

char *mem_string =
	"%-8s Structures use approx. %8d bytes (%5d pages) of memory\n";

void
enable_sdbc()
{
	spcs_s_info_t ustats;

	if (get_cache_config()) {
		(void) fprintf(stderr,
		    gettext("%s: unable to read configuration file\n"),
		    progname);
		exit(1);
	}

	if (SDBC_IOCTL(SDBC_ENABLE, &user_level_conf, 0, 0, 0, 0,
	    &ustats) == SPCS_S_ERROR) {
		(void) fprintf(stderr, gettext("%s: cache enable failed\n"),
		    progname);
		spcs_log("scm", &ustats, gettext("%s cache enable failed"),
		    progname);
		sdbc_report_error(&ustats);
		exit(1);
	}
	spcs_log("scm", NULL, gettext("%s cache enable succeeded"),
	    progname);
#ifdef DEBUG
	(void) printf(gettext("%s: cache has been configured\n"), progname);
#endif
#ifdef WRTHRU_HINTS
	if (iscluster()) {
		/* Must writethru on a cluster, even if nvram configured */
		forced_wrthru = 1;
	}

	if (minidsp && forced_wrthru != -1) {
		/* Have minidsp with forced_wrthru hint. Set / Clear hint */
		if (SDBC_IOCTL(SDBC_SET_NODE_HINT, NSC_FORCED_WRTHRU,
		    forced_wrthru, 0, 0, 0, &ustats) == SPCS_S_ERROR) {
			(void) fprintf(stderr,
			    gettext("%s: set/clear forced_wrthru failed\n"),
			    progname);
			sdbc_report_error(&ustats);
		} else if (forced_wrthru) {
			(void) printf(gettext("%s: Node option forced_wrthru "
			    "now set.\n"), progname);
		} else {
			(void) printf(gettext("%s: Node option forced_wrthru "
			    "now cleared.\n"), progname);
		}
	}
	if (no_forced_wrthru != -1) {
		if (SDBC_IOCTL(SDBC_SET_NODE_HINT, NSC_NO_FORCED_WRTHRU,
		    no_forced_wrthru, 0, 0, 0, &ustats) == SPCS_S_ERROR) {
			(void) fprintf(stderr,
			    gettext("%s: set/clear no_forced_wrthru "
			    "failed\n"), progname);
			sdbc_report_error(&ustats);
		} else if (no_forced_wrthru) {
			(void) printf(gettext("%s: Node option no_forced_wrthru"
			    " now set.\n"), progname);
		} else {
			(void) printf(gettext("%s: Node option no_forced_wrthru"
			    " now cleared.\n"), progname);
		}
	}
#endif

	/* do scmadm -O to cater for manual cache disable then enable */
	restore_hints();
}

void
disable_sdbc()
{
	spcs_s_info_t ustats;

	if (SDBC_IOCTL(SDBC_DISABLE, 0, 0, 0, 0, 0, &ustats) != SPCS_S_OK) {
		/*
		 * If it wasn't already enabled, don't appear to fail
		 * or users of this program might think the cache is
		 * configured, when it actually isn't.
		 */
		if (errno != SDBC_EDISABLE) {
			spcs_log("scm", &ustats,
			    gettext("%s cache disable failed"), progname);
			sdbc_report_error(&ustats);
			exit(1);
		}
	}
#ifdef DEBUG
	(void) printf(gettext("%s: cache has been deconfigured\n"), progname);
#endif
	spcs_log("scm", NULL, gettext("%s cache disable succeeded"),
	    progname);
}

static void
get_version()
{
	cache_version_t version;
	spcs_s_info_t ustats;

	if (SDBC_IOCTL(SDBC_VERSION, &version, 0, 0, 0, 0, &ustats) ==
	    SPCS_S_ERROR) {
		(void) fprintf(stderr,
		    gettext("%s: get cache version failed\n"), progname);
		sdbc_report_error(&ustats);
		exit(1);
	}
#ifdef DEBUG
	(void) printf(gettext("Cache version %d.%d.%d.%d\n"),
	    version.major, version.minor, version.micro, version.baseline);
#else
	if (version.micro) {
		(void) printf(gettext("Cache version %d.%d.%d\n"),
		    version.major, version.minor, version.micro);
	} else {
		(void) printf(gettext("Cache version %d.%d\n"),
		    version.major, version.minor);
	}
#endif
}

#ifdef DEBUG
int
toggle_flush(void)
{
	int rc;
	spcs_s_info_t ustats;

	if ((rc = SDBC_IOCTL(SDBC_TOGGLE_FLUSH, 0, 0, 0,
	    0, 0, &ustats)) == SPCS_S_ERROR) {
		(void) fprintf(stderr,
		    gettext("%s: toggle sdbc cache flush failed\n"),
		    progname);
		sdbc_report_error(&ustats);
		exit(1);
	}
	return (rc);
}
#endif
