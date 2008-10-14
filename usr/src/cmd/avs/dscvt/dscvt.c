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

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <locale.h>
#include <unistd.h>
#include <search.h>
#include <libgen.h>
#include <nsctl.h>
#include <dlfcn.h>
#include <langinfo.h>
#include <libintl.h>
#include <netdb.h>
#include <ctype.h>

#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/rdc_prot.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsctl/sv.h>
#include <sys/nsctl/sv_impl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <rpc/rpc_com.h>
#include <rpc/rpc.h>

#include <sys/nsctl/cfg.h>
#include <sys/nsctl/nsc_hash.h>

#define	RDC_LIB "/usr/lib/librdc.so.1"

/*
 * Structure to keep track of how many times a volume is used.
 */
typedef struct vol_s {
	int count;
} vol_t;
int rflg;

static void error(char *, char *, ...);
static void process_dsw(CFGFILE *, hash_node_t **);
static void process_rdc(CFGFILE *, hash_node_t **);
static void process_sv(CFGFILE *, hash_node_t **);
static void register_vol(CFGFILE *, hash_node_t **, char *, char *, char *,
    hash_node_t **);

static int do_cluster;
static int (*self_check)(char *);

int
main(int argc, char *argv[])
{
	CFGFILE *cfg;
	hash_node_t **svhash;
	extern char *optarg;
	int rc;
	void *librdc;
	char altroot[NSC_MAXPATH]; /* jumpstart */
	char altlib[NSC_MAXPATH]; /* jumpstart */
	char *cfgloc;
	char c;

	while ((c = getopt(argc, argv, "r:")) != EOF) {
		switch (c) {
			case 'r':
				rflg++;
				strcpy(altroot, optarg);
				break;
			default:
				error(NULL, "Usage: dscvt [-r root_dir]\n");
				/*NOTREACHED*/
		};
	}
	cfgloc = cfg_location(NULL, CFG_LOC_GET_CLUSTER, rflg ? altroot : NULL);

	cfg = cfg_open(cfgloc);
	if (!cfg) {
		error("cfg_open", gettext("unable to open dscfg"));
		/*NOTREACHED*/
	}
	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		error("cfg_lock",
		    gettext("unable to obtain write lock for dscfg"));
		/*NOTREACHED*/
	}
	if (cfg_update_parser_config(cfg, "dsvol.path.cnode.users\n",
	    CFG_PARSE_CONF) < 0) {
		if (errno != EEXIST) {
			error("cfg_update_parser_config",
			    gettext("unable to update parser config"));
			/*NOTREACHED*/
		}
	}
	if (cfg_commit(cfg) < 0) {
		error("cfg_commit",
		    gettext("unable to commit, parser info may be wrong"));
	}
	cfg_close(cfg);
	/*
	 * re-open with new parser entry
	 */

	cfg = NULL;
	cfg = cfg_open(cfgloc);
	if (!cfg) {
		error("cfg_open", gettext("unable to open dscfg"));
		/*NOTREACHED*/
	}
	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		error("cfg_lock",
		    gettext("unable to obtain write lock for dscfg"));
		/*NOTREACHED*/
	}

	cfg_resource(cfg, NULL);

	svhash = nsc_create_hash();
	if (!svhash) {
		error("nsc_create_hash",
		    gettext("unable to create hash for sv"));
		/*NOTREACHED*/
	}

	/* preload volumes from 'dsvol' section, if any */
	rc = cfg_load_dsvols(cfg);
	if (rc < 0) {
		error("cfg_load_dsvols", gettext("cannot read config file"));
		/*NOTREACHED*/
	}

	/* handle cluster tags */
	do_cluster = cfg_issuncluster();
	if (do_cluster < 0) {
		error("cfg_issuncluster",
		    gettext("unable to ascertain environment"));
		/*NOTREACHED*/
	}

	/* find out if RDC is installed */
	if (!rflg)
		librdc = dlopen(RDC_LIB, RTLD_LAZY | RTLD_GLOBAL);
	else {
		if ((strlen(altroot) + strlen(RDC_LIB)) >= NSC_MAXPATH) {
			(void) fprintf(stderr,
			    "sndr library name too long, skipping\n");
			librdc = NULL;
		} else {
			strcpy(altlib, altroot);
			strcat(altlib, RDC_LIB);
			librdc = dlopen(altlib, RTLD_LAZY | RTLD_GLOBAL);
		}
	}


	/* now handle all the sections of the config file */
	process_dsw(cfg, svhash);
	if (librdc) {
		self_check = (int (*)(char *)) dlsym(librdc, "self_check");
		process_rdc(cfg, svhash);
		(void) dlclose(librdc);
	}
	process_sv(cfg, svhash);

	/* write changes and exit */
	(void) cfg_commit(cfg);
	cfg_close(cfg);

	nsc_remove_all(svhash, free);

	return (0);
}

static void
error(char *func, char *str, ...)
{
	va_list ap;

	va_start(ap, str);

	(void) fprintf(stderr, "dscvt: ");
	(void) vfprintf(stderr, str, ap);

	va_end(ap);

	if (errno && func) {
		perror(func);
	}

	exit(1);
}

/*
 * Determines which volumes are being used by II and adds them to
 * the 'dsvol' section of the config file.
 */
static void
process_dsw(CFGFILE *cfg, hash_node_t **svhash)
{
	hash_node_t **iihash;
	int set;
	char key[ CFG_MAX_KEY ];
	char buf[ CFG_MAX_BUF ];
	char *master, *shadow, *p;
	char *ctag = "-";

	iihash = nsc_create_hash();
	if (!iihash) {
		error("nsc_create_hash",
		    gettext("unable to create hashtable for Point-in-Time "
			    "Copy"));
		/*NOTREACHED*/
	}
	cfg_rewind(cfg, CFG_SEC_CONF);
	for (set = 1; /*CSTYLED*/; set++) {
		(void) snprintf(key, CFG_MAX_KEY, "ii.set%d", set);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF)) {
			break;
		}
		p = buf;
		while (*p && isspace(*p)) {
			++p;
		}
		master = strtok(p, " ");
		shadow = strtok(NULL, " ");
		if (do_cluster) {
			/* skip some fields */
			(void) strtok(NULL, " ");	/* bitmap */
			(void) strtok(NULL, " ");	/* mode */
			(void) strtok(NULL, " ");	/* overflow */
			ctag = strtok(NULL, " ");
		}

		if (!master) {
			break;
		}
		register_vol(cfg, iihash, master, "ii", ctag, svhash);

		if (!shadow) {
			break;
		}
		register_vol(cfg, iihash, shadow, "ii", ctag, svhash);

	}
	nsc_remove_all(iihash, free);
}

/*
 * Determines which volumes are being used by SNDR and adds them to
 * the 'dsvol' section of the config file.
 */
static void
process_rdc(CFGFILE *cfg, hash_node_t **svhash)
{
	hash_node_t **rdchash;
	int set;
	char key[ CFG_MAX_KEY ];
	char buf[ CFG_MAX_BUF ];
	char *host, *vol, *bmp, *p;
	char *ctag = "-";

	rdchash = nsc_create_hash();
	if (!rdchash) {
		error("nsc_create_hash",
		    gettext("unable to create hashtable for Remote Mirror"));
		/*NOTREACHED*/
	}
	cfg_rewind(cfg, CFG_SEC_CONF);
	for (set = 1; /*CSTYLED*/; set++) {
		(void) snprintf(key, CFG_MAX_KEY, "sndr.set%d", set);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF)) {
			break;
		}
		p = buf;
		while (*p && isspace(*p)) {
			++p;
		}
		host = strtok(p, " ");
		vol = strtok(NULL, " ");
		bmp = strtok(NULL, " ");
		if (!self_check(host)) {
			host = strtok(NULL, " ");
			vol = strtok(NULL, " ");
			bmp = strtok(NULL, " ");
			if (do_cluster) {
				/* skip some fields */
				(void) strtok(NULL, " ");	/* type */
				(void) strtok(NULL, " ");	/* mode */
				(void) strtok(NULL, " ");	/* group */
			}
		} else if (do_cluster) {
			/* skip some fields */
			(void) strtok(NULL, " ");	/* shost */
			(void) strtok(NULL, " ");	/* secondary */
			(void) strtok(NULL, " ");	/* sbitmap */
			(void) strtok(NULL, " ");	/* type */
			(void) strtok(NULL, " ");	/* mode */
			(void) strtok(NULL, " ");	/* group */
		}

		if (do_cluster) {
			ctag = strtok(NULL, " ");
		}
		if (self_check(host)) {
			register_vol(cfg, rdchash, vol, "sndr", ctag, svhash);
			register_vol(cfg, rdchash, bmp, "sndr", ctag, svhash);
		}
	}
	nsc_remove_all(rdchash, free);
}

/*
 * This must be executed last.  Any volumes that are configured in sv
 * which are not already claimed by II or SNDR must be put under SV
 * control.
 */
static void
process_sv(CFGFILE *cfg, hash_node_t **svhash)
{
	int set;
	char key[ CFG_MAX_KEY ];
	char buf[ CFG_MAX_BUF ];
	char *path, *p;
	char *ctag = "-";

	cfg_rewind(cfg, CFG_SEC_CONF);
	for (set = 1; /*CSTYLED*/; set++) {
		(void) snprintf(key, CFG_MAX_KEY, "sv.set%d", set);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF)) {
			break;
		}
		p = buf;
		while (*p && isspace(*p)) {
			++p;
		}
		path = strtok(p, " ");
		if (do_cluster) {
			(void) strtok(NULL, " ");	/* skip 'mode' field */
			ctag = strtok(NULL, " ");
		}
		register_vol(cfg, svhash, path, "sv", ctag, NULL);
	}
}

static void
register_vol(CFGFILE *cfg, hash_node_t **hash, char *path, char *user,
    char *ctag, hash_node_t **svhash)
{
	vol_t *volp, *svolp;
	int rc;

	volp = (vol_t *)nsc_lookup(hash, path);
	if (!volp) {
		volp = (vol_t *)malloc(sizeof (vol_t));
		volp->count = 0;
		(void) printf("%s: adding %s as volume\n", user, path);
		if (nsc_insert_node(hash, volp, path) < 0) {
			error("nsc_insert_node", gettext(
			    "Error manipulating data: vol %s, user %s\n"),
			    path, user);
			/*NOTREACHED*/
		}
		rc = cfg_add_user(cfg, path, ctag, user);
		if (CFG_USER_ERR == rc) {
			error("cfg_add_user", gettext("Error adding volume %s"
			    " for user %s\n"), path, user);
			perror("cfg_add_user");
			/*NOTREACHED*/
		}
	} else {
		++volp->count;
		(void) printf("%s: incrementing usage of %s to %d\n", user,
		    path, volp->count);
	}

	if (svhash) {
		svolp = (vol_t *)nsc_lookup(svhash, path);
		if (!svolp) {
			svolp = (vol_t *)malloc(sizeof (vol_t));
			svolp->count = volp->count;
			if (nsc_insert_node(svhash, svolp, path) < 0) {
				error("nsc_insert_node", gettext("Unable to"
				    " insert node into svhash for %s (%s)"),
				    path, user);
				/*NOTREACHED*/
			}
		} else {
			++svolp->count;
		}
		/* remove it from 'sv' in case it was previously put there */
		(void) cfg_rem_user(cfg, path, ctag, "-sv");
	}
}
