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

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/vtoc.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <netdb.h>
#include <ctype.h>
#include <assert.h>

#include <sys/nsctl/cfg_impl.h>
#include <sys/nsctl/cfg.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#ifdef DEBUG
#include <sys/nsctl/dsw.h>
#endif

#define	DEFAULT_PARSER_LOC "/etc/dscfg_format"

int Cflg;
int Dflg;
int Lflg;
int aflg;
int iflg;
int lflg;
int nflg;
int pflg;
int rflg;
int sflg;
int uflg;

int verbose;
int noflags;
int errflg;
int mustcommit;
char *locname;		/* config location  from cfg_location */
char *cmdname;

#define	MAX_FILENAME	80

char output_file[MAX_FILENAME];	/* specified output file */
char altroot[MAX_FILENAME];	/* specifed root location */
char config_file[MAX_FILENAME];	/* specified configuration file */
char input_file[MAX_FILENAME];	/* specified input file */
char logical_host[MAX_FILENAME]; /* specified  cluster node */
char device_group[MAX_FILENAME]; /* specified device group name */

#define	IS_NOT_CLUSTER	1
#define	IS_CLUSTER	2

void cfg_invalidate_hsizes(int, const char *);
static int check_cluster();

void
usage(char *errmsg)
{
	if (errmsg)
		(void) fprintf(stderr, "%s: %s\n", cmdname, errmsg);
	(void) fprintf(stderr,
	    gettext("dscfg \t\t\t\tDisplay location of "
		"local configuration database\n"));
	(void) fprintf(stderr, gettext("dscfg -l -s path\t\t"
		"List contents of configuration database\n"));
	(void) fprintf(stderr, gettext(
		"\t\t\t\tlocated at path specified\n"));
	(void) fprintf(stderr, gettext("dscfg -i\t\t\t"
		"Initialize configuration database\n"));
	(void) fprintf(stderr,
	    gettext("dscfg -i -p "
#ifdef DEBUG
"[-n] "
#endif
	    "/etc/dscfg_format\tFormat configuration database\n"));
	(void) fprintf(stderr,
	    gettext("dscfg -a file\t\t\tRestore configuration "
	    "database from file\n"));
	(void) fprintf(stderr, gettext("\t\t\t\tspecified\n"));
	(void) fprintf(stderr,
		gettext("dscfg -l\t\t\tList contents of configuration database"
		"\n"));
	(void) fprintf(stderr,
		gettext("dscfg -L\t\t\tDisplay configuration database's\n"));
	(void) fprintf(stderr, gettext("\t\t\t\tlock status\n"));
	(void) fprintf(stderr, gettext("dscfg -h\t\t\tUsage message\n"));
	if (check_cluster() != IS_NOT_CLUSTER) {
	(void) fprintf(stderr, gettext("\nSun Cluster Usage\n"));
	(void) fprintf(stderr, gettext("******************\n"));
	(void) fprintf(stderr,
		gettext("dscfg -s path\t\t\tSet cluster "
		"configuration database at DID\n"));
	(void) fprintf(stderr, gettext("\t\t\t\tpath specified\n"));
	(void) fprintf(stderr, gettext("dscfg -D device_group\t\t"
		"Check status of cluster device group\n"));
	(void) fprintf(stderr, gettext("dscfg -C -\t\t\t"
		"Display location of cluster configuration\n"));
	(void) fprintf(stderr, gettext("\t\t\t\tdatabase\n"));
	(void) fprintf(stderr, gettext("dscfg -l -s DID_device\t\tList "
		"the contents of cluster configuration\n"));
	(void) fprintf(stderr, gettext("\t\t\t\tdatabase\n"));
	(void) fprintf(stderr, gettext("dscfg -C - -i\t\t\tInitialize "
		"cluster configuration database\n"));
	(void) fprintf(stderr, gettext("dscfg -C - -i -p "
		"/etc/dscfg_format Format cluster configuration database\n"));
	(void) fprintf(stderr, gettext("dscfg -C - -a file\t\t"
		"Restore cluster configuration database from\n"));
	(void) fprintf(stderr, gettext("\t\t\t\tfile specified\n"));
	(void) fprintf(stderr, gettext("dscfg -C - -l\t\t\t"
		"List contents of local configuration database\n"));
	(void) fprintf(stderr, gettext("dscfg -C device_group -l\t"
		"List configuration database by device group\n"));
	(void) fprintf(stderr, gettext("dscfg -C \"-\" -l\t\t\t"
		"List configuration database excluding\n"));
	(void) fprintf(stderr, gettext("\t\t\t\tdevice groups\n"));
	}
}

int
parse_parse_config(CFGFILE *cfg)
{
	FILE *fp;
	char	inbuf[CFG_MAX_BUF];
	char	*buff;
	int	rc;

	/*
	 * Open parser config file, use default if none specified
	 */
	buff = (input_file[0]) ? input_file : DEFAULT_PARSER_LOC;
	if ((fp = fopen(buff, "r")) == NULL) {
		(void) fprintf(stderr,
			gettext("parser config file (%s) not found\n"), buff);
		return (-1);
	}

	/*
	 * start at begining of configration database
	 */
	cfg_rewind(cfg, CFG_SEC_ALL);

	while (((buff = fgets(inbuf, (sizeof (inbuf) - 1), fp)) != NULL)) {
		if (*buff == '#' || *buff == '%')
			continue;
		/* overwrite newline */
		buff[strlen(buff) - 1] = '\0';
		rc = cfg_update_parser_config(cfg, buff, CFG_PARSE_CONF);
		if (rc < 0) {
			(void) fprintf(stderr,
			    gettext("update parser config rc %d key %s\n"),
			    rc, buff);
			(void) fclose(fp);
			return (-1);
		}
	}
	(void) fclose(fp);
	return (1);
}

void
parse_text_config(CFGFILE *cfg)
{
	FILE *fp;
	char	inbuf[CFG_MAX_BUF];
	char	*buff;
	char	*key;
	char	*p;
	int	rc;

	if ((fp = fopen(input_file, "r")) == NULL) {
		(void) fprintf(stderr,
			    gettext("Unable to open text config %s\n"),
				input_file);
		exit(2);
	}
	bzero(inbuf, sizeof (inbuf));
	cfg_rewind(cfg, CFG_SEC_CONF);
	while (((buff = fgets(inbuf, (sizeof (inbuf) - 1), fp)) != NULL)) {
		if (*buff == '#')
			continue;
		/* overwrite newline */
		buff[strlen(buff) - 1] = '\0';
		key = strtok(buff, ":");
		if (!key) {
			continue;
		}
		p = &buff[strlen(key)+2];
		while (*p && isspace(*p)) {
			++p;
		}
		if (!*p) {
			continue;
		}
		rc = cfg_put_cstring(cfg, key, p, strlen(p));
		if (rc < 0) {
			(void) fprintf(stderr,
			    gettext("update text config failed rc %d key %s"),
			    rc, buff);
			return;
		}
		bzero(inbuf, sizeof (inbuf));
	}
	(void) fclose(fp);
}
void
dump_status(CFGFILE *cfg)
{
	cfp_t *cfp = FP_SUN_CLUSTER(cfg);

	/*
	 * WARNING will robinson
	 * The following is using a non-exported internal interface
	 * to libcfg
	 * You may not use any of the following fields in MS software
	 */
	if (!locname)
		exit(2);
	if (!verbose)
		(void) printf("%s\n", locname);
	else {
#ifdef DEBUG
		(void) printf(gettext("Configuration location: %s\n"), locname);
		(void) printf(
		    gettext("Header info:\n\t\t\tmagic: %x\tstate: %x\n"),
		    cfp->cf_head->h_magic, cfp->cf_head->h_state);
		(void) printf(
		    gettext("Parser section:\t\t"
		    "Start: %x\tsize: %d offset: %d\n"),
		    cfp->cf_mapped, cfp->cf_head->h_parsesize,
		    cfp->cf_head->h_parseoff);
		(void) printf(
		    gettext("Config section:\t\t"
		    "Start: %x\tsize:%d\tacsize: %d\n"),
		    cfp->cf_head->h_cparse, cfp->cf_head->h_csize,
		    cfp->cf_head->h_acsize);
		(void) printf("\t\t\tccopy1: %s\tccopy2: %s\n",
			cfp->cf_head->h_ccopy1,
			cfp->cf_head->h_ccopy2);
		(void) printf(
		    gettext("Sequence:\t\tseq1: %d\t\tseq2: %d\n"),
			cfp->cf_head->h_seq1, cfp->cf_head->h_seq2);
#endif
	}
}

void
dump_lockstat(CFGFILE *cfg)
{
	pid_t pid;
	CFGLOCK lock;
	char	ps_str[1024];

	if (cfg_get_lock(cfg, &lock, &pid) == TRUE) {
		(void) printf("%s %ld\n",
		    lock == CFG_RDLOCK ?
			    gettext("Read locked by process id") :
			    gettext("Write locked by process id"),
		    pid);
		(void) sprintf(ps_str, "ps -p %ld", pid);
		system(ps_str);
	} else
		(void) printf("%s\n", gettext("Not locked."));
}


/*
 * dump current configuration section to stdout
 */

void
print_config(CFGFILE *cfg)
{
	time_t tloc = 0;
	int set = 0;
	char pconfig[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	char buf[CFG_MAX_BUF];
	char *cp, pbuf[CFG_MAX_BUF];
	FILE *fp;
	int rc;
	int end;

	(void) snprintf(pconfig, sizeof (pconfig),
	    "%s%s", altroot, DEFAULT_PARSER_LOC);
	if ((fp = fopen(pconfig, "r")) == NULL) {
		(void) fprintf(stderr,
		    gettext("dscfg: unable to open "
		    "parser configuration (%s): %s\n"),
		    pconfig, strerror(errno));
		exit(1);
	}

	(void) time(&tloc);
	(void) printf(gettext("# Consolidated Dataservice Configuration\n"));
	(void) printf(gettext("# Do not edit out whitespace or dashes\n"));
	(void) printf(gettext("# File created on: %s"), ctime(&tloc));

	while (fgets(pbuf, (sizeof (pbuf) - 1), fp) != NULL) {
		if (pbuf[0] == '#') {
			/* comment */
			continue;
		}
		/* force a NULL terminator */
		pbuf[sizeof (pbuf) - 1] = '\0';

		if (pbuf[0] == '%') {
			/*
			 * descriptive text
			 * - print it (with comment leader) and move on
			 */
			(void) printf("#%s", &pbuf[1]);
			continue;
		}

		/*
		 * truncate the parser config in pbuf[] to just the tag
		 */
		cp = strchr(pbuf, '.');
		if (cp != NULL) {
			*cp = '\0';
		}

		set = 1;
		/*CONSTCOND*/
		while (1) {
			bzero(buf, CFG_MAX_BUF);
			(void) snprintf(key,
			    sizeof (key), "%s.set%d", pbuf, set);
			rc = cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF);
			if (rc < 0) {
				break;
			}
			/* trim trailing space if necessary */
			end = strlen(buf) - 1;
			if (buf[end] == ' ')
				buf[end] = '\0';

			(void) printf("%s:%s\n", pbuf, buf);
			set++;
		}
	}

	(void) fclose(fp);
}

int
make_new_config(const char *fileloc)
{
	int fd;
	int rc;
	int skip;

	char buf[CFG_MAX_BUF];
	/*CONSTCOND*/
	assert((sizeof (buf) % 512) == 0);

	bzero(buf, CFG_MAX_BUF);

	if ((fd = open(fileloc, O_RDWR | O_CREAT, 0640)) == -1) {
		return (-1);
	}

	/* if this is a device, we may have to skip the vtoc */
	if ((skip = cfg_shldskip_vtoc(fd, fileloc)) == -1) {
		(void) fprintf(stderr,
			gettext("dscfg: unable to read vtoc on (%s)\n"),
				fileloc);
		return (-1);
	} else if (skip) {
		do {
			rc = lseek(fd, CFG_VTOC_SKIP, SEEK_SET);
		} while (rc == -1 && errno == EINTR);

		if (rc == -1) {
			(void) fprintf(stderr, gettext("dscfg: seek error"));
			return (-1);
		}
	}

	do {
		rc = write(fd, buf, sizeof (buf));
	} while (rc == -1 && errno == EINTR);

	close(fd);

	return ((rc < 0) ? 0 : 1);
}

/*
 * dscfg
 * configure or return dataservice persistent configuration
 *
 * options
 *		-i initialize file for first time
 *		-l dump current configuration to stdout in ascii
 *		-a add
 *		-C node	Set resource filter
 *		-p parser config specified input file
 *		-s set partition location or filename in default location
 *		-L print configuration lock status
 *		-u upgrade
 *		-r prepend bootdir to beginning of path for cfg_open
 *	no options    status
 *
 *
 */
#ifdef lint
int
dscfg_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	CFGFILE *cfg;
	extern char *optarg;
	char *loc;
	int offset = 0;
	int rc;
	char c;
	int local;
	int action_counts = 0;

	bzero(input_file, sizeof (input_file));
	(void) setlocale(LC_ALL, "");
	(void) textdomain("dscfg");
	logical_host[0] = '\0';
	cmdname = argv[0];
#ifdef DEBUG
	while ((c = getopt(argc, argv, "a:C:dD:ilLp:r:s:hvn")) != EOF) {
#else
	while ((c = getopt(argc, argv, "a:C:dD:ilLp:r:s:h")) != EOF) {
#endif
		switch (c) {
			case 'a':
				aflg++;
				strcpy(input_file, optarg);
				mustcommit++;
				action_counts++;
				break;
			case 'C':
				Cflg++;
				strcpy(logical_host, optarg);
				if (logical_host && *logical_host == '-')
				    if (argc == 3)
					action_counts++;
				break;
			case 'D':
				Dflg++;
				strcpy(device_group, optarg);
				action_counts++;
				break;
			case 'i':
				iflg++;
				mustcommit++;
				action_counts++;
				break;
			case 'l':
				lflg++;
				action_counts++;
				break;
			case 'L':
				Lflg++;
				action_counts++;
				break;
			case 'p':
				pflg++;
				strcpy(input_file, optarg);
				mustcommit++;
				break;
			case 's':
				sflg++;
				strcpy(config_file, optarg);
				action_counts++;
				break;
			case 'h':
				usage(NULL);
				exit(0);
			/*NOTREACHED*/
#ifdef DEBUG
			case 'v':
				verbose++;
				action_counts++;
				break;
#endif
#ifdef UPGRADE
			case 'u':
				uflg++;
				action_counts++;
				break;
#endif

			case 'r':
				rflg++;
				strcpy(altroot, optarg);
				break;

			case 'n':
				nflg++;
				break;

			default:
				usage(NULL);
				exit(1);
				break;
		};
	}

	switch (action_counts) {
	    case 0:
		if (argc > 1) {
		    if (pflg)
			usage(gettext(
			    "-p option must be used in conjunction with -i"));
		    else
			usage(gettext("must specify an action flag"));
		    exit(1);
		}
		break;
	    case 1:
		break;
	    case 2:
		if (lflg && sflg)
			break;
		else {
		    usage(gettext("too many action flags"));
		    exit(1);
		    break;
		}
	    default:
		usage(gettext("too many action flags"));
		exit(1);
		break;
	}

	if (argc == 1 || (argc == 2 && verbose) || (argc == 3 && (rflg|Cflg)))
		noflags++;

	if (Dflg) {
		/*
		 * Determine if the value specified is a device group
		 * that is active on this node
		 */
		char *other_node;
		if ((cfg_issuncluster() > 0) && (strlen(device_group) > 0)) {
		    local = cfg_dgname_islocal(device_group, &other_node);
		    if (local == 0)
			(void) fprintf(stderr, gettext(
			    "Device group %s active on %s\n"),
			    device_group, other_node);
		    else if (local == 1)
			(void) fprintf(stderr, gettext(
			    "Device group %s active on this node\n"),
			    device_group);
		    else
			(void) fprintf(stderr, gettext(
			    "Device group %s not found\n"), device_group);
		    return (local);
		} else {
			(void) fprintf(stderr, gettext(
			    "dscfg -D is only allowed in "
			    "Sun Cluster OE\n"));
			return (0);
		}
	}

	if (sflg && !lflg) {
		/*
		 * Only allow setting location on a non-sun cluster system
		 * if the cluster reference file is already present.
		 */
		struct stat dscfg_stat = {0};
		if (cfg_issuncluster() <= 0) {
			if (stat(CFG_CLUSTER_LOCATION, &dscfg_stat) != 0) {
				if (dscfg_stat.st_blocks == 0) {
					(void) fprintf(stderr, gettext(
						"dscfg -s is only allowed in "
						"Sun Cluster OE\n"));
					exit(1);
				}
			}
		}

		spcs_log("dscfg", NULL, gettext("dscfg -s %s"), config_file);
		locname = cfg_location(config_file, CFG_LOC_SET_CLUSTER,
		    rflg ? altroot : NULL);
		if (locname == NULL) {
			(void) fprintf(stderr, gettext("dscfg: %s\n"),
			    cfg_error(NULL));
			exit(1);
		} else
			exit(0);

	} else if (sflg && lflg) {
		/* s used with l for temporarily peeking at a dscfg database */
		loc = config_file;
	} else {
		locname = cfg_location(NULL,
			Cflg ? CFG_LOC_GET_CLUSTER : CFG_LOC_GET_LOCAL,
			rflg ? altroot : NULL);
		if (Cflg && (locname == NULL)) {
			(void) fprintf(stderr, gettext(
			    "dscfg: cluster config not set: %s\n"),
			    cfg_error(NULL));
			return (1);
		}
		loc = rflg ? locname : NULL;
	}

	/*
	 * the following hack forces the configuration file to initialize
	 */
	if (iflg && !pflg) {
		int fild;
		int c;
		char buf[CFG_MAX_BUF] = {0};
		cfp_t *cfp;

		if (!nflg) {
			(void) printf(
			    gettext("WARNING: This option will erase your "
				"Availability Suite configuration\n"));
			(void) printf(
			    gettext("Do you want to continue? (Y/N) [N] "));

			c = getchar();
			switch (c) {
			case 'y':
			case 'Y': break;
			case 'n':
			case 'N':
			case '\n':
				(void) fprintf(stderr, gettext(
				"dscfg: configuration not initialized\n"));
				exit(1);
			default:
				(void) fprintf(stderr, gettext(
				"dscfg: %d is not a valid response\n"), c);
				exit(1);
			}
		}

		spcs_log("dscfg", NULL, gettext("dscfg -i"));

		if ((cfg = cfg_open(loc)) == NULL) {
			/* this is not a good config, or non-existent so.. */
			if (!make_new_config(locname)) {
				(void) fprintf(stderr, gettext("dscfg: %s\n"),
				    cfg_error(NULL));
				exit(1);
			}
			if ((cfg = cfg_open(loc)) == NULL) {
				(void) fprintf(stderr, gettext("dscfg: %s\n"),
				    cfg_error(NULL));
				exit(1);
			}
		}

		/*
		 * Set cluster node if specified
		 */
		if (Cflg)
			cfg_resource(cfg, logical_host);

		if (cfg_is_cfg(cfg) != 1) {
			if (!make_new_config(locname)) {
				(void) fprintf(stderr, gettext("dscfg: unable "
				    " to create new config \n"));
				exit(1);
			}
		}

		if (!cfg_lock(cfg, CFG_WRLOCK)) {
			(void) fprintf(stderr, gettext("dscfg: %s\n"),
			    cfg_error(NULL));
			exit(1);
		}

		cfp = FP_SUN_CLUSTER(cfg);
		if ((fild = cfp->cf_fd) == 0) {
			(void) fprintf(stderr,
				gettext("dscfg: failure to access %s "
				"configuration database: %s\n"),
				(Cflg) ? gettext("cluster") : gettext("local"),
			cfg_error(NULL));
			exit(1);
		}

		if (cfg_shldskip_vtoc(fild, locname) > 0)
			offset += CFG_VTOC_SKIP;

		lseek(fild, offset, SEEK_SET);
		write(fild, buf, sizeof (buf));
		cfg_invalidate_hsizes(fild, locname);

		cfg_close(cfg);
		exit(0);
	}

	if (pflg && !iflg) {
		usage(gettext("-p option must be used in conjunction with -i"));
		exit(1);

	}

	if (uflg) {
		char cmd[CFG_MAX_BUF];
		if (rflg)
			(void) snprintf(cmd, sizeof (cmd),
			    "%s/usr/sbin/dscfg -r %s -l >"
			    " %s/var/tmp/.dscfg.bak", altroot,
			    altroot, altroot);
		else
			(void) snprintf(cmd, sizeof (cmd),
			    "/usr/sbin/dscfg -l >"
			    " /var/tmp/.dscfg.bak");

		if (system(cmd) != 0) {
			(void) fprintf(stderr,
			    "dscfg: unable to create backup\n");
			exit(1);
		}

		if ((cfg = cfg_open(loc)) == NULL) {
			(void) fprintf(stderr, gettext("dscfg: %s\n"),
			    cfg_error(NULL));
			exit(2);
		}

		if (!cfg_lock(cfg, CFG_UPGRADE)) {
			(void) fprintf(stderr,
			    gettext("dscfg: upgrade failed\n"));
			cfg_close(cfg);
			exit(1);
		}

		cfg_close(cfg);
		exit(0);
	}

	if ((cfg = cfg_open(loc)) == NULL) {
		(void) fprintf(stderr, gettext("dscfg: %s\n"), cfg_error(NULL));
		exit(2);
	}

	/*
	 * Set cluster node if specified
	 */
	if (Cflg)
		cfg_resource(cfg, logical_host);

	if ((!pflg) && (!noflags)) {
		if (cfg_is_cfg(cfg) != 1) {
			(void) fprintf(stderr,
				gettext("dscfg: %s\n"), cfg_error(NULL));
			cfg_close(cfg);
			exit(1);
		}
	}

	if (Lflg) {
		dump_lockstat(cfg);
		cfg_close(cfg);
		exit(0);
	}

	if (noflags) {
		dump_status(cfg);
		cfg_close(cfg);
		exit(0);
	}

	if (!cfg_lock(cfg, mustcommit? CFG_WRLOCK : CFG_RDLOCK)) {
		(void) fprintf(stderr, gettext("cfg_lock: lock failed\n"));
		cfg_close(cfg);
		exit(1);
	}

	if (lflg) {
		print_config(cfg);
		cfg_close(cfg);
		exit(0);
	}

	/*
	 * initialize configuration
	 */
	if (iflg) {
		spcs_log("dscfg", NULL, gettext("dscfg -i -p %s"), input_file);

		if (!pflg) {
			(void) fprintf(stderr,
			    gettext("dscfg: cannot init without "
			    "parser configuration file\n"));
			cfg_close(cfg);
			exit(1);
		} else if (parse_parse_config(cfg) < 0) {
			(void) fprintf(stderr, gettext("dscfg: cannot load "
				    "parser configuration file\n"));
			cfg_close(cfg);
			exit(1);
		}
	}

	/*
	 * read asci config file and write
	 */
	if (aflg) {
		spcs_log("dscfg", NULL, gettext("dscfg -a %s"), input_file);
		parse_text_config(cfg);
	}

	if (mustcommit) {
		rc = cfg_commit(cfg);
		if (rc < 0) {
			int sev = 0;
			(void) fprintf(stderr, gettext("dscfg: %s\n"),
			    cfg_error(&sev));
			if (sev == CFG_EFATAL) {
				cfg_close(cfg);
				exit(2);
			}
		}
	}

	cfg_close(cfg);
	return (0);
}

static int
check_cluster()
{
	static int is_cluster = -1;
	int rc;

	if (is_cluster != -1)
	    return (is_cluster);
	rc = cfg_iscluster();
	if (rc > 0) {
	    is_cluster = IS_CLUSTER;
	    return (is_cluster);
	} else if (rc == 0) {
	    is_cluster = IS_NOT_CLUSTER;
	    return (is_cluster);
	} else {
	    (void) fprintf(stderr,
		gettext("dscfg: unable to determin environment\n"));
	    /*NOTREACHED*/
	}

	/* gcc */
	return (is_cluster);
}
