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


#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <ctype.h>
#include <libnvpair.h>

#include "mms_mgmt.h"
#include "mgmt_util.h"
#include "mms_cfg.h"
#include "net_cfg_service.h"

static char *_SrcFile = __FILE__;
#define	HERE _SrcFile, __LINE__

typedef struct {
	char	port[10];
	char	user[256];
	char	bindir[MAXPATHLEN];
	char	path[MAXPATHLEN];
	char	logdir[MAXPATHLEN];
	char	dbname[MAXPATHLEN];
	char	dbhost[MAXHOSTNAMELEN];
	uid_t	dbuid;
	gid_t	dbgid;
} mmsdb_opts_t;

/* If this path changes, make sure similar changes are made to mmsexplorer */
static char *db_cli = "/var/mms/db/.pga";
static char db_cli_env[1024];

static int get_db_user(char *buf, int buflen, uid_t *uid, gid_t *gid);
static int configure_pgconf(char *port, char *logdir);
static int get_dbver_from_optfile(char *path, int *version);
static int mk_cmds_from_optfile(mmsdb_opts_t *opts, char *path, int vers,
	char cmdtype, int dopd, char **cmdfile);
static int mgmt_db_sql_exec(char *cmdfile, mmsdb_opts_t *opts);
static int set_mm_system_vars_db(nvlist_t *opts, char *cmdfile);
static int mgmt_get_db_opts(mmsdb_opts_t *opts);
static int create_db_dirs(char *dbpath, uid_t uid, gid_t gid, nvlist_t *errs);
static int update_pghba(boolean_t ismd5, mmsdb_opts_t *dbopts, nvlist_t *errs);


/*
 *  Functions to manage the MMS Database
 */

int
mgmt_set_db_opts(nvlist_t *opts, nvlist_t *errlist)
{
	int			st = 0;
	mmsdb_opts_t		oldopts;
	int			doconf = 0;
	uid_t			uid = 0;
	gid_t			gid = 0;
	char			*val;
	char			*port = NULL;
	char			*logdir = NULL;

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	/*
	 * check to see if any options have been set for the DB yet.  Only
	 * a few are user-configurable.   Changing the DB user is handled
	 * by the admin with SMF and chown -R. (i.e., outside of our CLI,
	 * at least for now)
	 */
	(void) memset(&oldopts, 0, sizeof (mmsdb_opts_t));

	st = mgmt_get_db_opts(&oldopts);
	if (st != 0) {
		return (st);
	}

	uid = oldopts.dbuid;
	gid = oldopts.dbgid;

	/* TODO - should we allow change after set?  Need to copy -R if so */
	st = nvlist_lookup_string(opts, O_DBDIR, &val);
	if (st == 0) {
		st = create_db_dirs(val, uid, gid, errlist);
		if (st != 0) {
			return (st);
		}
	}

	st = nvlist_lookup_string(opts, O_DBPORT, &port);
	if (st == 0) {
		/* update the conf file */
		doconf = 1;
	}

	st = nvlist_lookup_string(opts, O_DBLOG, &logdir);
	if (st == 0) {
		/* update the conf file */
		doconf = 1;
		/* create dblogdir if it doesn't exist */
		st = create_dir(logdir, 0711, NULL, uid, NULL, gid);
	}

	if ((st == 0) && (doconf)) {
		st = configure_pgconf(port, logdir);
	}

	return (st);
}

static int
create_db_dirs(char *dbpath, uid_t uid, gid_t gid, nvlist_t *errs)
{
	int		st;
	struct stat64	statbuf;
	char		*dbsubdirs[] = {"data", "dump", "log", NULL};
	int		i;
	char		buf[2048];

	if (!dbpath) {
		return (MMS_MGMT_NOARG);
	}

	st = stat64(dbpath, &statbuf);
	if ((st != 0) && (errno != ENOENT)) {
		st = errno;
		MGMT_ADD_ERR(errs, dbpath, st);
		return (st);
	}

	st = create_dir(dbpath, 0711, NULL, uid, NULL, gid);
	if (st != 0) {
		st = errno;
		MGMT_ADD_ERR(errs, dbpath, st);
		return (st);
	}

	for (i = 0; dbsubdirs[i] != NULL; i++) {
		(void) snprintf(buf, sizeof (buf), "%s/%s", dbpath,
		    dbsubdirs[i]);
		st = create_dir(buf, 0711, NULL, uid, NULL, gid);
		if (st != 0) {
			st = errno;
			MGMT_ADD_ERR(errs, buf, st);
			break;
		}
	}

	return (st);
}

int
mgmt_db_init(void)
{
	int		st;
	pid_t		pid;
	char		buf[2048];
	char		dbbuf[2048];
	mmsdb_opts_t	opts;
	char		*cmd[4];

	if (!mgmt_chk_auth("solaris.mms.create")) {
		return (EACCES);
	}

	st = mgmt_get_db_opts(&opts);
	if (st != 0) {
		return (st);
	}

	/* see if we've been initialized already, bail if so */
	(void) snprintf(buf, sizeof (buf), "%s/data/postgresql.conf",
	    opts.path);
	st = access(buf, F_OK);
	if (st == 0) {
		return (0);
	}

	(void) snprintf(dbbuf, sizeof (dbbuf), "%s/initdb", opts.bindir);
	(void) snprintf(buf, sizeof (buf), "%s/data", opts.path);

	cmd[0] = dbbuf;
	cmd[1] = "-D";
	cmd[2] = buf;
	cmd[3] = NULL;

	pid = exec_mgmt_cmd(NULL, NULL, opts.dbuid, opts.dbgid,
	    B_FALSE, cmd);

	st = check_exit(pid, NULL);

	return (st);
}

static int
mgmt_get_db_opts(mmsdb_opts_t *opts)
{
	int		st;
	struct passwd	pwd;
	struct passwd	*pwdp;
	char		buf[2048];
	char		*bufp;

	if (opts == NULL) {
		return (MMS_MGMT_NOARG);
	}

	st = mms_cfg_getvar(MMS_CFG_DB_DATA, opts->path);
	if (st == 0) {
		/*
		 * The *data* dir is stored in SMF.  We need the
		 * parent thereof.
		 */
		bufp = strrchr(opts->path, '/');
		if (bufp) {
			*bufp = '\0';
		}
		st = mms_cfg_getvar(MMS_CFG_MM_DB_USER, opts->user);
	}
	if (st == 0) {
		st = mms_cfg_getvar(MMS_CFG_MM_DB_HOST, opts->dbhost);
	}
	if (st == 0) {
		st = mms_cfg_getvar(MMS_CFG_MM_DB_PORT, opts->port);
	}
	if (st == 0) {
		st = mms_cfg_getvar(MMS_CFG_MM_DB_NAME, opts->dbname);
	}
	if (st == 0) {
		st = mms_cfg_getvar(MMS_CFG_DB_BIN, opts->bindir);
	}
#ifdef	MMS_VAR_CFG
	if (st == 0) {
		st = mms_cfg_getvar(MMS_CFG_DB_LOG, opts->logdir);
	}
#else
	if (st == 0) {
		(void) snprintf(opts->logdir, sizeof (opts->logdir),
		    "%s/log", opts->path);
	}
#endif	/* MMS_VAR_CFG */

	if (st != 0) {
		return (st);
	}

	(void) getpwnam_r(opts->user, &pwd, buf, sizeof (buf), &pwdp);
	if (pwdp == NULL) {
		return (MMS_MGMT_DB_USER_NOTFOUND);
	}

	opts->dbuid = pwdp->pw_uid;
	opts->dbgid = pwdp->pw_gid;

	/* set the envvar for PGPASSFILE */
	(void) snprintf(db_cli_env, sizeof (db_cli_env), "PGPASSFILE=%s",
	    db_cli);
	st = putenv(db_cli_env);

	return (st);
}

static int
get_db_user(char *buf, int buflen, uid_t *uid, gid_t *gid)
{
	int		st;
	struct passwd	pwd;
	struct passwd	*pwdp;

	if ((buf == NULL) || (uid == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	st = mms_cfg_getvar(MMS_CFG_MM_DB_USER, buf);
	if (st != 0) {
		return (st);
	}

	(void) getpwnam_r(buf, &pwd, buf, buflen, &pwdp);
	if (pwdp == NULL) {
		return (MMS_MGMT_DB_USER_NOTFOUND);
	}

	*uid = pwdp->pw_uid;
	if (gid != NULL) {
		*gid = pwdp->pw_gid;
	}

	return (0);
}

int
mgmt_db_create(int initialize, int populate, nvlist_t *optlist)
{
	int		st;
	pid_t		pid;
	mmsdb_opts_t	opts;
	int		oldver = -1;
	int		ver = -1;
	char		buf[MAXPATHLEN];
	char		*pkgfile = MMSETCDIR"/db/mms_db";
	char		*cmd[7];
	char		dbbuf[2048];

	mms_trace(MMS_DEBUG, "Creating the MMS Database");

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	st = mgmt_get_db_opts(&opts);
	if (st != 0) {
		return (st);
	}

	(void) snprintf(dbbuf, sizeof (dbbuf), "%s/createdb", opts.bindir);

	cmd[0] = dbbuf;
	cmd[1] = "-h";
	cmd[2] = opts.dbhost;
	cmd[3] = "-p";
	cmd[4] = opts.port;
	cmd[5] = opts.dbname;
	cmd[6] = NULL;

	if (initialize) {
		st = mgmt_db_check();
		if (st == 0) {
			/* db is alive, already inited */
			return (EALREADY);
		}

		/* check to see if files exist, even if svc is stopped */
		(void) snprintf(buf, sizeof (buf), "%s/data/%s", opts.path,
		    "base");
		if (access(buf, F_OK) == 0) {
			return (EALREADY);
		} else {
			/* create the dirs we need */
			st = create_db_dirs(opts.path, opts.dbuid, opts.dbgid,
			    NULL);
			if (st != 0) {
				return (st);
			}
		}

		st = mgmt_db_init();
		if (st == 0) {
			st = configure_pgconf(opts.port, opts.logdir);
		}

		if (st != 0) {
			return (st);
		}
	}

	/*
	 * some callers may wish to populate the DB themselves, as in
	 * upgrade or downgrade.
	 */
	if (populate) {
		st = get_dbver_from_optfile(pkgfile, &ver);
		if (st != 0) {
			return (st);
		}

		(void) snprintf(buf, sizeof (buf), "%s/%s", opts.path, "mmsdb");
		st = get_dbver_from_optfile(buf, &oldver);
		if (st != 0) {
			if (st != ENOENT) {
				return (st);
			}
			st = 0;
		}

		if (ver > oldver) {
			if (oldver != -1) {
				/* save the old mod file */
				char	newf[MAXPATHLEN];

				(void) snprintf(newf, sizeof (newf), "%s-%d",
				    buf, oldver);
				(void) rename(buf, newf);
			}
			st = cp_file(pkgfile, buf);
			if (st != 0) {
				return (st);
			}
			(void) chown(buf, opts.dbuid, opts.dbgid);
		}
	}

	/* make sure the DB is running */
	st = mgmt_set_svc_state(DBSVC, ENABLE, NULL);
	if (st != 0) {
		return (st);
	}

	pid = exec_mgmt_cmd(NULL, NULL, opts.dbuid, opts.dbgid,
	    B_FALSE, cmd);

	st = check_exit(pid, NULL);

	if ((st == 0) && (populate)) {
		/* import all the sql cmds */
		char		*cmdfile = NULL;

		st = mk_cmds_from_optfile(&opts, buf, ver, 'u', 1, &cmdfile);
		if ((st == 0) && optlist) {
			st = set_mm_system_vars_db(optlist, cmdfile);
		}
		if (st == 0) {
			st = mgmt_db_sql_exec(cmdfile, &opts);
		}

		if (cmdfile) {
			(void) unlink(cmdfile);
			free(cmdfile);
		}

		if (st == 0) {
			char	*passp;

			st = nvlist_lookup_string(optlist, O_MMPASS, &passp);
			if (st == 0) {
				(void) snprintf(buf, sizeof (buf),
				    "%s_dbadmin", passp);
				st = mgmt_set_db_pass(buf, NULL);
			}
		}
	}

	return (st);
}

int
mgmt_db_drop(void)
{
	int		st;
	pid_t		pid;
	mmsdb_opts_t	opts;
	char		*cmd[5];
	char		dbbuf[2048];

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	st = mgmt_get_db_opts(&opts);
	if (st != 0) {
		return (st);
	}

	(void) snprintf(dbbuf, sizeof (dbbuf), "%s/dropdb", opts.bindir);

	cmd[0] = dbbuf;
	cmd[1] = "-p";
	cmd[2] = opts.port;
	cmd[3] = opts.dbname;
	cmd[4] = NULL;

	pid = exec_mgmt_cmd(NULL, NULL, opts.dbuid, opts.dbgid,
	    B_FALSE, cmd);

	st = check_exit(pid, NULL);

	if (st != 0) {
		/* restart the service to force users to disconnect */

		(void) mgmt_set_svc_state(DBSVC, RESTART, NULL);

		pid = exec_mgmt_cmd(NULL, NULL, opts.dbuid, opts.dbgid,
		    B_FALSE, cmd);

		st = check_exit(pid, NULL);
	}

	return (st);
}

int
mgmt_db_check(void)
{
	int		st;
	pid_t		pid;
	char		buf[1024];
	FILE		*readf = NULL;
	mmsdb_opts_t	opts;
	char		*cmd[9];
	char		dbbuf[2048];

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	st = mgmt_get_db_opts(&opts);
	if (st != 0) {
		return (st);
	}

	(void) snprintf(dbbuf, sizeof (dbbuf), "%s/psql", dbbuf);

	cmd[0] = dbbuf;
	cmd[1] = "-h";
	cmd[2] = opts.dbhost;
	cmd[3] = "-p";
	cmd[4] = opts.port;
	cmd[5] = "-t";
	cmd[6] = "-c";
	cmd[7] = buf;
	cmd[8] = NULL;

	(void) snprintf(buf, sizeof (buf),
	    "SELECT datname FROM pg_database where datname = '%s'",
	    opts.dbname);

	pid = exec_mgmt_cmd(&readf, NULL, opts.dbuid, opts.dbgid,
	    B_FALSE, cmd);

	st = check_exit(pid, NULL);

	if (st == 0) {
		buf[0] = '\0';
		(void) fgets(buf, sizeof (buf), readf);
		if (buf[0] == '\0') {
			st = -1;
		}
	}

	(void) fclose(readf);

	return (st);
}

int
mgmt_db_dump(char *dumpdir, char *dumpfile, int len)
{
	int		st;
	char		datebuf[256];
	char		filbuf[MAXPATHLEN];
	time_t		now = time(NULL);
	struct tm	*tm = NULL;
	pid_t		pid;
	mmsdb_opts_t	opts;
	char		*cmd[11];
	char		dbbuf[2048];

	if (!dumpdir || !dumpfile) {
		return (MMS_MGMT_NOARG);
	}

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	st = mgmt_get_db_opts(&opts);
	if (st != 0) {
		return (st);
	}

	tm = localtime(&now);
	(void) strftime(datebuf, sizeof (datebuf),
	    "%Y-""%m-""%dT""%H""%M""%S", tm);

	(void) snprintf(filbuf, sizeof (filbuf), "%s/mmsdb_dump_%s", dumpdir,
	    datebuf);

	(void) snprintf(dbbuf, sizeof (dbbuf), "%s/pg_dump", opts.bindir);

	cmd[0] = dbbuf;
	cmd[1] = "-h";
	cmd[2] = opts.dbhost;
	cmd[3] = "-p";
	cmd[4] = opts.port;
	cmd[5] = "-F";
	cmd[6] = "p";
	cmd[7] = "-f";
	cmd[8] = filbuf;
	cmd[9] = opts.dbname;
	cmd[10] = NULL;

	if (dumpfile != NULL) {
		(void) strlcpy(dumpfile, filbuf, len);
	}

	st = create_dir(dumpdir, 0711, NULL, opts.dbuid, NULL, 0);

	if (st != 0) {
		return (st);
	}

	pid = exec_mgmt_cmd(NULL, NULL, opts.dbuid, opts.dbgid,
	    B_FALSE, cmd);

	st = check_exit(pid, NULL);

	return (st);
}


/*
 *  TODO:  Ensure this is done on the MM server host only when client
 *  configs are supported.
 */
int
mgmt_db_restore(char *dumpfile)
{
	int		st;
	struct stat64	statbuf;
	char		*mmstate = NULL;
	mmsdb_opts_t	opts;

	if (!mgmt_chk_auth("solaris.mms.modify")) {
		return (EACCES);
	}

	st = mgmt_get_db_opts(&opts);
	if (st != 0) {
		return (st);
	}

	st = stat64(dumpfile, &statbuf);
	if (st != 0) {
		return (MMS_MGMT_DBDUMP_MISSING);
	}
	if (!S_ISREG(statbuf.st_mode)) {
		return (MMS_MGMT_NOT_DBFILE);
	}

	/* shutdown MM */
	st = mgmt_set_svc_state(MMSVC, DISABLE, &mmstate);
	if (st != 0) {
		if (mmstate) {
			free(mmstate);
		}
		return (st);
	}

	st = mgmt_db_create(1, 0, NULL);
	if (st != 0) {
		free(mmstate);
		return (st);
	}

	st = mgmt_db_sql_exec(dumpfile, &opts);

	if ((st == 0) && (strcmp(mmstate, "online") == 0)) {
		st = mgmt_set_svc_state(MMSVC, ENABLE, NULL);
	}

	free(mmstate);
	return (st);
}

typedef struct {
	char	*optnam;
	char	*val;
} pgconf_t;

static pgconf_t pgconf_opts[] = {
	{"port", NULL},
	{"log_directory", NULL},
	{"external_pid_file", "'(none)'"},
	{"log_destination", "stderr"},
	{"redirect_stderr", "on"},
	{"log_filename", "'log.%a'"},
	{"log_rotation_size", "10000"},
	{"log_truncate_on_rotation", "on"},
	{"log_line_prefix", "'%m %p '"},
	{"client_min_messages", "WARNING"},
	{"log_min_messages", "INFO"},
	{"log_disconnections", "on"},
	{"autovacuum", "on"},
	{"autovacuum_naptime", "1200"},
	{"stats_start_collector", "on"},
	{"stats_row_level", "on"}
};

static int numpgopts = sizeof (pgconf_opts) / sizeof (pgconf_t);

static int
configure_pgconf(
	char	*port,
	char	*logdir)
{
	int		st = 0;
	struct stat64	statbuf;
	char		nambuf[256];
	char		buf[MAXPATHLEN];
	char		dbpath[MAXPATHLEN];
	char		logpath[MAXPATHLEN];
	uid_t		uid;
	size_t		sz;
	char		*bufp;
	struct tm	usetime;
	int		infd;
	int		outfd;
	FILE		*infp;
	FILE		*outfp;
	static char	datefmt[] = "%y""%m""%d""%H""%M""%S";
	time_t		now;
	char		filbuf[2048];
	int		i;
	char		*cptr;
	int		changed = 0;
	int		matched = 0;

	if ((port == NULL) || (logdir == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	pgconf_opts[0].val = port;

	/* add quotes around the path */
	(void) snprintf(logpath, sizeof (logpath), "'%s'", logdir);

	pgconf_opts[1].val = logpath;

	st = get_db_user(nambuf, sizeof (nambuf), &uid, NULL);
	if (st == 0) {
		st = mms_cfg_getvar(MMS_CFG_DB_DATA, dbpath);
	}

	if (st != 0) {
		return (st);
	}

	st = stat64(logdir, &statbuf);
	if (st != 0) {
		st = errno;
		if (st == ENOENT) {
			st = create_dir(logdir, 0711, NULL, uid, NULL, 0);
		}
		if (st != 0) {
			return (st);
		}
	} else {
		if (!S_ISDIR(statbuf.st_mode)) {
			return (ENOTDIR);
		}
	}

	sz = strlcat(dbpath, "/postgresql.conf", sizeof (dbpath));
	if (sz > sizeof (dbpath)) {
		return (ENAMETOOLONG);
	}

	st = stat64(dbpath, &statbuf);
	if (st != 0) {
		if (errno != ENOENT) {
			return (errno);
		} else {
			/*
			 * DB not initialized yet, bail without
			 * error as this function will be called
			 * later from db_create.
			 */
			return (0);
		}
	}

	/* construct the name of the new version of this file */
	now = time(NULL);
	(void) localtime_r(&now, &usetime);
	(void) strftime(nambuf, sizeof (nambuf), datefmt, &usetime);
	(void) snprintf(buf, sizeof (buf), "%s_%s", dbpath, nambuf);

	/* open the original */
	infd = open64(dbpath, O_RDONLY);
	if (infd == -1) {
		st = errno;
		return (st);
	}

	infp = fdopen(infd, "r");
	if (infp == NULL) {
		st = errno;
		(void) close(infd);
		return (st);
	}

	/* open the target file */
	outfd = open64(buf, O_CREAT|O_RDWR, statbuf.st_mode);
	if (outfd == -1) {
		st = errno;
		(void) close(infd);
		return (st);
	}

	outfp = fdopen(outfd, "w");
	if (outfp == NULL) {
		st = errno;
		(void) fclose(infp);
		(void) close(outfd);
		return (st);
	}

	/* preserve, as much as possible, the existing format of the file */
	while ((bufp = fgets(filbuf, sizeof (filbuf), infp)) != NULL) {
		matched = 0;
		cptr = NULL;

		for (; *bufp != '\0'; bufp++) {
			/* options are initially commented out */
			if (*bufp == '#') {
				continue;
			}
			if (!isspace(*bufp)) {
				break;
			}
		}

		if (*bufp == '\0') {
			(void) fprintf(outfp, "%s", filbuf);
			continue;
		}

		for (i = 0; i < numpgopts; i++) {
			sz = strlen(pgconf_opts[i].optnam);
			if (strncmp(bufp, pgconf_opts[i].optnam, sz) != 0) {
				continue;
			}
			bufp += sz;
			while ((*bufp != '\0') && (isspace(*bufp))) {
				bufp++;
				sz++;
			}
			if (*bufp == '=') {
				/* found a match - update it */
				matched++;

				/* TODO:  check really needed to change */
				(void) fprintf(outfp, "%s = %s\n",
				    pgconf_opts[i].optnam, pgconf_opts[i].val);
				cptr = strchr(bufp, '#');
				if (cptr) {
					(void) fprintf(outfp, "\t\t\t\t\t%s",
					    cptr);
				}
				changed++;
				break;
			} else {
				/* superstring or substring of another option */
				bufp -= sz;
			}
		}

		if (!matched) {
			(void) fprintf(outfp, "%s", filbuf);
		}
	}
	(void) fchown(outfd, statbuf.st_uid, statbuf.st_gid);
	(void) fclose(outfp);
	(void) fclose(infp);

	/* if we didn't change anything, we're done */
	if (!changed) {
		(void) unlink(buf);
		return (0);
	}

	/* construct the name of the backup copy of this file */
	(void) localtime_r(&(statbuf.st_mtime), &usetime);
	(void) strftime(nambuf, sizeof (nambuf), datefmt, &usetime);

	(void) snprintf(filbuf, sizeof (filbuf), "%s_%s", dbpath, nambuf);

	/* finally, swap em */
	st = rename(dbpath, filbuf);
	if (st != 0) {
		st = errno;
		(void) unlink(buf);
	} else {
		st = rename(buf, dbpath);
		if (st != 0) {
			st = errno;
		}
	}

	return (st);
}

static int
get_dbver_from_optfile(char *path, int *version)
{
	int			st = 0;
	FILE			*fp = NULL;
	char			buf[1024];
	char			*bufp;
	int			vers = -1;
	int			last = -1;

	if (!path || !version) {
		return (ENOENT);
	}

	st = access(path, R_OK);
	if (st != 0) {
		st = errno;
		return (st);
	}

	fp = fopen(path, "r");
	if (fp == NULL) {
		st = errno;
		return (errno);
	}

	while ((bufp = fgets(buf, sizeof (buf), fp)) != NULL) {
		if ((*bufp != '\0') && (!isdigit(*bufp))) {
			continue;
		}

		do {
			bufp++;
		} while (isdigit(*bufp));

		if (*bufp != 'u') {
			continue;
		}

		*bufp = '\0';

		vers = atoi(buf);
		if (vers > last) {
			last = vers;
		}
	}
	(void) fclose(fp);

	*version = last;

	return (st);
}

static int
mk_cmds_from_optfile(mmsdb_opts_t *opts, char *path, int vers, char cmdtype,
	int dopd, char **cmdfile)
{
	int			st = 0;
	int			fd = -1;
	FILE			*fp = NULL;
	FILE			*ofp = NULL;
	char			buf[MAXPATHLEN];
	char			*bufp;
	int			started = 0;
	char			*pass;

	if (!opts || !path || !cmdfile) {
		return (MMS_MGMT_NOARG);
	}

	st = access(path, R_OK);
	if (st != 0) {
		st = errno;
		return (st);
	}

	fp = fopen(path, "r");
	if (fp == NULL) {
		st = errno;
		return (errno);
	}

	/* create our cmdfile */
	(void) snprintf(buf, sizeof (buf), "/var/mms/db/mmsdbcmd-%c-%d",
	    cmdtype, time(NULL));

	fd = open(buf, O_CREAT|O_TRUNC|O_APPEND|O_WRONLY|O_NOFOLLOW|O_NOLINKS,
	    0600);
	if (fd == -1) {
		st = errno;
		goto done;
	}

	/* set this so the pguser can read it */
	(void) fchown(fd, opts->dbuid, opts->dbgid);

	ofp = fdopen(fd, "a");
	if (ofp == NULL) {
		st = errno;
		(void) close(fd);
		goto done;
	}

	*cmdfile = strdup(buf);

	(void) fprintf(ofp, "BEGIN;\n");

	while ((bufp = fgets(buf, sizeof (buf), fp)) != NULL) {
		if (*bufp == '#') {
			continue;
		}

		if (!isdigit(*bufp)) {
			if (started) {
				(void) fprintf(ofp, "%s", bufp);
			}
			continue;
		}

		while (isdigit(*bufp)) {
			bufp++;
		}

		if (*bufp++ == cmdtype) {
			started = 1;
			while (isspace(*buf)) {
				bufp++;
			}
			(void) fprintf(ofp, "%s", bufp);
		} else {
			started = 0;
		}
	}

	if (dopd) {
		(void) fclose(fp);

		/* override the junk password in the dbopts file */
		pass = mms_net_cfg_read_pass_file(MMS_NET_CFG_HELLO_FILE);
		if (pass != NULL) {
			(void) fprintf(ofp,
			    "UPDATE \"MMPASSWORD\" SET \"Password\" = '%s';\n",
			    pass);
			free(pass);
		}
	}

	/* Set the version and add commit statement */
	(void) fprintf(ofp,
	    "UPDATE \"MM\" SET \"DBVersion\" = '%d';\nCOMMIT;\n", vers);

done:
	if (st != 0) {
		if (*cmdfile) {
			(void) unlink(*cmdfile);
			free(cmdfile);
			*cmdfile = NULL;
		}
	}
	(void) fclose(fp);
	(void) fclose(ofp);

	return (st);
}

static int
mgmt_db_sql_exec(char *cmdfile, mmsdb_opts_t *opts)
{
	int	st;
	pid_t	pid;
	FILE	*dberr;
	char	buf[MAXPATHLEN];
	char	*cmd[10];
	char	dbbuf[2048];

	if (!cmdfile || !opts) {
		return (MMS_MGMT_NOARG);
	}

	(void) snprintf(dbbuf, sizeof (dbbuf), "%s/psql", opts->bindir);

	cmd[0] = dbbuf;
	cmd[1] = "-a";
	cmd[2] = "-h";
	cmd[3] = opts->dbhost;
	cmd[4] = "-p";
	cmd[5] = opts->port;
	cmd[6] = "-f";
	cmd[7] = cmdfile;
	cmd[8] = opts->dbname;
	cmd[9] = NULL;

	pid = exec_mgmt_cmd(NULL, &dberr, opts->dbuid, opts->dbgid,
	    B_FALSE, cmd);

	st = check_exit(pid, NULL);

	if (st == 0) {
		while (fgets(buf, sizeof (buf), dberr) != NULL) {
			if ((strstr(buf, " ERROR: ") != NULL) ||
			    (strstr(buf, "ROLLBACK") != NULL)) {
				st = 1;
				break;
			}
		}
	}
	(void) fclose(dberr);

	return (st);
}

/*
 * this should probably move to a header somewhere, but for
 * now, leave it where it's directly mapped
 */
typedef struct {
	char	*mm;
	char	*ui;
} mgmt_dbopt_map_t;

/*
 * map of MgmtUI-specified opts to MM options.  NULL indicates
 * not exposed by MgmtUI
 */
static mgmt_dbopt_map_t mm_sys_opts[] = {
	{"AttendanceMode", O_ATTENDED},
	{"SystemLogLevel", O_LOGLEVEL},
	{"SystemLogFile", O_LOGFILE},
	{"MessageLevel", O_MSGLEVEL},
	{"TraceLevel", O_TRACELEVEL},
	{"TraceFileSize", O_TRACESZ},
	{"SocketFdLimit", O_NUMSOCKET},
	{"SystemDiskMountTimeout", O_DKTIMEOUT},
	{"WatcherStartsLimit", O_NUMRESTART},
	{"SystemAcceptLevel", NULL},
	{"SystemMessageLimit", NULL},
	{"SystemMessageCount", NULL},
	{"SystemRequestLimit", NULL},
	{"SystemRequestCount", NULL},
	{"SystemSyncLimit", NULL},
	{"SystemDCALimit", NULL},
	{"SystemDCACount", NULL},
	{"ClearDriveAtLMConfig", NULL},
	{"AskClearDriveAtLMConfig", NULL},
	{"PreemptReservation", NULL},
	{"SystemLogFileSize", NULL},
	{"SystemName", NULL},
	{"SystemInstance", NULL},
	{"UnloadDelayTime", NULL},
	{"DefaultBlocksize", NULL},
	{"WatcherTimeLimit", NULL},
	{"DriveRecordRetention", NULL},
	{NULL, NULL}
};

/* add the MM options to the database before creation, if we know them */
static int
set_mm_system_vars_db(nvlist_t *opts, char *cmdfile)
{
	int		st;
	char		*val = NULL;
	int		i;
	int		fd = -1;
	FILE		*ofp = NULL;
	struct stat	sb;
	int		changed = 0;

	if (!opts) {
		return (0);
	}

	if (!cmdfile) {
		return (MMS_MGMT_NOARG);
	}

	fd = open(cmdfile, O_RDWR|O_NOFOLLOW|O_NOLINKS);
	if (fd == -1) {
		return (errno);
	}
	st = fstat(fd, &sb);
	if (st != 0) {
		st = errno;
		(void) close(fd);
		return (st);
	}

	ofp = fdopen(fd, "a");
	if (ofp == NULL) {
		st = errno;
		(void) close(fd);
		return (st);
	}

	for (i = 0; mm_sys_opts[i].mm != NULL; i++) {
		if (mm_sys_opts[i].ui == NULL) {
			continue;
		}
		st = nvlist_lookup_string(opts, mm_sys_opts[i].ui, &val);
		if ((st == 0) && val) {
			if (!changed) {
				(void) fprintf(ofp, "BEGIN;\n");
			}
			(void) fprintf(ofp,
			    "UPDATE \"SYSTEM\" SET \"%s\" = '%s';\n",
			    mm_sys_opts[i].mm, val);

			changed++;
		}
	}

	if (changed) {
		(void) fprintf(ofp, "COMMIT;\n");
	}

	(void) fclose(ofp);

	return (0);
}

int
mgmt_set_db_pass(char *dbpass, nvlist_t *errs)
{
	int		st;
	mmsdb_opts_t	opts;
	char		buf[2048];
	boolean_t	ismd5 = B_FALSE;
	int		fd = -1;
	int		wr = 0;
	char		*tfile = "/var/mms/db/tsql";

	/* no provided password means use 'trust' */
	if (dbpass) {
		ismd5 = B_TRUE;
	}

	st = mgmt_get_db_opts(&opts);
	if (st != 0) {
		return (st);
	}

	/* tell Postgres to use the new password */
	fd = open64(tfile, O_CREAT|O_TRUNC|O_WRONLY, 0600);
	if (fd == -1) {
		st = errno;
		MGMT_ADD_ERR(errs, tfile, st);
		return (st);
	}

	(void) fchown(fd, opts.dbuid, opts.dbgid);

	(void) snprintf(buf, sizeof (buf),
	    "alter user postgres with password '%s' valid until 'infinity';",
	    dbpass);
	wr = write_buf(fd, buf, strlen(buf));
	(void) close(fd);

	if (wr == -1) {
		MGMT_ADD_ERR(errs, tfile, EIO);
		(void) unlink(tfile);
		return (EIO);
	}

	st = mgmt_db_sql_exec(tfile, &opts);
	if (st != 0) {
		MGMT_ADD_ERR(errs, "postgres failure", st);
		(void) unlink(tfile);
		return (st);
	}

	(void) unlink(tfile);

	/* next, set up the conf file */
	st = update_pghba(ismd5, &opts, errs);
	if (st != 0) {
		return (st);
	}

	/* write the PGPASSFILE */
	fd = open64(db_cli, O_CREAT|O_TRUNC|O_WRONLY, 0600);
	if (fd == -1) {
		st = errno;
		MGMT_ADD_ERR(errs, db_cli, st);
		return (st);
	}
	(void) fchown(fd, opts.dbuid, opts.dbgid);

	(void) snprintf(buf, sizeof (buf), "*:*:*:*:%s", dbpass);
	wr = write_buf(fd, buf, strlen(buf));
	(void) close(fd);

	if (wr == -1) {
		MGMT_ADD_ERR(errs, db_cli, EIO);
		(void) unlink(db_cli);
		return (EIO);
	}

	st = mms_net_cfg_write_pass_file(MMS_NET_CFG_DB_FILE, dbpass);
	if (st != 0) {
		return (st);
	}

	/* restart the db */
	st = mgmt_set_svc_state(DBSVC, RESTART, NULL);

	return (st);
}

static int
update_pghba(boolean_t ismd5, mmsdb_opts_t *dbopts, nvlist_t *errs)
{
	int		st;
	char		buf[2048];
	char		*bufp;
	int		infd = -1;
	int		outfd = -1;
	FILE		*infp = NULL;
	FILE		*outfp = NULL;
	struct stat64	statbuf;
	char		confpath[2048];
	char		newconfpath[2048];
	time_t		now;
	struct tm	usetime;
	static char	datefmt[] = "%y""%m""%d""%H""%M""%S";
	boolean_t	changed = B_FALSE;
	char		timebuf[256];

	if (!dbopts) {
		return (MMS_MGMT_NOARG);
	}

	(void) snprintf(confpath, sizeof (confpath), "%s/data/%s", dbopts->path,
	    "pg_hba.conf");

	st = stat64(confpath, &statbuf);
	if (st != 0) {
		st = errno;
		MGMT_ADD_ERR(errs, confpath, st);
		return (st);
	}

	/* construct the name of the new version of this file */
	now = time(NULL);
	(void) localtime_r(&now, &usetime);
	(void) strftime(timebuf, sizeof (timebuf), datefmt, &usetime);
	(void) snprintf(newconfpath, sizeof (newconfpath), "%s_%s", confpath,
	    timebuf);

	/* open the original */
	infd = open64(confpath, O_RDONLY);
	if (infd == -1) {
		st = errno;
		MGMT_ADD_ERR(errs, confpath, st);
		return (st);
	}

	infp = fdopen(infd, "r");
	if (infp == NULL) {
		st = errno;
		MGMT_ADD_ERR(errs, confpath, st);
		(void) close(infd);
		return (st);
	}

	/* open the target file */
	outfd = open64(newconfpath, O_CREAT|O_RDWR, 0600);
	if (outfd == -1) {
		st = errno;
		(void) close(infd);
		MGMT_ADD_ERR(errs, newconfpath, st);
		return (st);
	}

	outfp = fdopen(outfd, "w");
	if (outfp == NULL) {
		st = errno;
		(void) fclose(infp);
		(void) close(outfd);
		MGMT_ADD_ERR(errs, newconfpath, st);
		return (st);
	}

	/* preserve, as much as possible, the existing format of the file */
	while ((bufp = fgets(buf, sizeof (buf), infp)) != NULL) {
		while (isspace(*bufp)) {
			bufp++;
		}

		if ((*bufp == '\0') || (*bufp == '#')) {
			(void) fprintf(outfp, "%s", buf);
			continue;
		}

		/* look for 'trust' or 'md5' */
		if (ismd5) {
			/* changing to password-protected */
			bufp = strstr(buf, "trust");
			if (bufp) {
				(void) strlcpy(bufp, "md5\n", 7);
				changed = B_TRUE;
			}
		} else {
			/* removing password protection */
			bufp = strstr(buf, "md5");
			if (bufp) {
				(void) strlcpy(bufp, "trust\n", 7);
				changed = B_TRUE;
			}
		}

		(void) fprintf(outfp, "%s", buf);
	}

	(void) fchown(outfd, dbopts->dbuid, dbopts->dbgid);
	(void) fclose(outfp);
	(void) fclose(infp);

	/* if we didn't change anything, we're done */
	if (!changed) {
		(void) unlink(newconfpath);
		return (0);
	}

	/* construct the name of the backup copy of this file */
	(void) localtime_r(&(statbuf.st_mtime), &usetime);
	(void) strftime(timebuf, sizeof (timebuf), datefmt, &usetime);

	(void) snprintf(buf, sizeof (buf), "%s_%s", confpath, timebuf);

	/* finally, swap em */
	st = rename(confpath, buf);
	if (st != 0) {
		st = errno;
		(void) unlink(buf);
		MGMT_ADD_ERR(errs, confpath, st);
	} else {
		st = rename(newconfpath, confpath);
		if (st != 0) {
			st = errno;
			MGMT_ADD_ERR(errs, newconfpath, st);
		}
	}

	return (st);
}
