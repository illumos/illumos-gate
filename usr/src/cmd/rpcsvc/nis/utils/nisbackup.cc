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
 *	nisbackup.cc
 *
 *	Copyright (c) 1988-1997 Sun Microsystems Inc
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nisbackup.cc
 *
 * A utility for performing database backups.
 */

#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <wait.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <rpcsvc/nis_db.h>
#include <rpcsvc/nis_tags.h>
#include "nis_bkrst.h"
#include "../rpc.nisd/nis_proc.h"
#include "../rpc.nisd/log.h"

/*
 * Global state variables.
 */
static bool_t		verbiage = FALSE;
static bool_t		root_dir = FALSE;
static bool_t		file_cleanup = FALSE;
static bool_t		backup_preserved = FALSE;
static bool_t		server_ro = FALSE;
static int 		flags = 0;
static char 		*nis_local_dir = __nis_rpc_domain();
static char 		*backupdir;
static directory_obj	slist;

static nis_error	set_ro(void);
static void		set_rw(void);
static void		abort_backup(char *);
static void 		abort_handler(int);

/*
 * Needs to be cleaned up in nislog as well as here. nis_log_common.o
 * is shared by rpc.nisd, nislog and nisbackup/nisrestore. map_log()
 * calls abort_transaction, which is defined in nis_svc_log.c. We can't
 * link with nis_log_svc, so we'll stub it here. It's not used, since
 * we are not modifying the transaction log.
 */
int
abort_transaction(int xid)
{
	xid = 0;
	return (0);
}

static void
init_signals()
{
	sigset(SIGHUP, abort_handler);
	sigset(SIGINT, abort_handler);
	sigset(SIGTERM, abort_handler);
}

static void
abort_handler(int sig)
{
	sig = 0;
	abort_backup(backupdir);
	exit(1);
}

void
usage()
{
	fprintf(stderr, "usage: nisbackup [ -v ] backup-dir directory...\n");
	fprintf(stderr, "       nisbackup [ -v ] -a backup-dir\n");
	exit(1);
}

struct file_set {
	char	**fs;
	u_int	fssize;
	u_int	fslen;
};

void
fspush(char *name, struct file_set *fset)
{
	if (fset == NULL) {
		syslog(LOG_ERR, "fspush: Internal error");
		exit(1);
	}
	if (fset->fs == 0)
		if ((fset->fs = (char **) calloc(fset->fssize,
					sizeof (char *))) == NULL) {
			syslog(LOG_ERR, "Unable to calloc memory: %m");
			exit(1);
		}
	if (fset->fslen == fset->fssize) {
		fset->fssize += 512;
		if ((fset->fs = (char **) realloc(fset->fs,
				fset->fssize * sizeof (char *))) == NULL) {
			syslog(LOG_ERR, "Unable to calloc memory: %m");
			exit(1);
		}
	}
	fset->fs[fset->fslen++] = name;
}

/*
 * This routine sets the rpc.nisd into a read-only state, so that the
 * nisbackup can take a snapshot of the database. We set a global (server_ro)
 * to indicate if we're sucessful. set_rw() is called on a kill signal (^C)
 * and we don't want to reset the server to read-write if we're being aborted
 * due to the existance of another nisbackup in progress!
 */
static nis_error
set_ro(void)
{
	nis_tag			*res = NULL;
	nis_error		error = NIS_SUCCESS;
	nis_tag 		tagctl;

	tagctl.tag_val = "";
	tagctl.tag_type = TAG_READONLY;
	error = nis_servstate(slist.do_servers.do_servers_val,
					&tagctl, 1, &res);
	if (res != NULL) {
		if (strlen(res->tag_val) != 0) {
			error = NIS_TRYAGAIN;
		} else {
			if (error == NIS_SUCCESS)
				server_ro = TRUE;
		}
		nis_freetags(res, 1);
	}
	return (error);
}

static void
set_rw(void)
{
	nis_tag			*res = NULL;
	nis_error		error;
	nis_tag			tagctl;

	/*
	 * If we never set the server to read-only, we don't want to try
	 * to set it to read-write. This could cause another instance of
	 * nisbackup to fail.
	 */
	if (server_ro == FALSE)
		return;
	tagctl.tag_val = "";
	tagctl.tag_type = TAG_READWRITE;
	error = nis_servstate(slist.do_servers.do_servers_val,
					&tagctl, 1, &res);
	if (error != NIS_SUCCESS) {
		syslog(LOG_ERR,
	"Unable to reset rpc.nisd to read/write, kill and restart! %s\n",
		nis_sperrno(error));
	}
	if (res != NULL)
		nis_freetags(res, 1);
}

#define	PRESERVE 0
#define	RESTORE 1

int
_mv_dir(char * name, int arg)
{
	struct stat	s;
	pid_t		child;
	siginfo_t	si;
	char		src[BUFSIZ], dst[BUFSIZ];

	if (arg == PRESERVE) {
		strcpy(src, name);
		sprintf(dst, "%stmp", name);
	} else {
		sprintf(src, "%stmp", name);
		strcpy(dst, name);
	}
	if (stat(src, &s) == -1) {
		syslog(LOG_ERR,
		"Directory %s does not exist: %m", src);
		return (1);
	}

	switch (child = vfork()) {
		case -1: /* error  */
			syslog(LOG_ERR, "Cannot move directory %s", name);
			return (1);
		case 0:  /* child  */
			if (execl("/bin/mv", "mv", src, dst, NULL) < 0)
				_exit(1);
			_exit(0); /* Since this is the child proc, we'll exit */
		default: /* parent, we'll wait for the cp to complete */
			if (waitid(P_PID, child, &si, WEXITED) == -1) {
				syslog(LOG_ERR, "Cannot move directory %s",
				src);
				return (1);
			} else {
				if (si.si_status != 0) {
					syslog(LOG_ERR,
					"Can't move directory: error = %d",
					si.si_status);
					return (1);
				}
			}
	}
	return (0);
}

int
_rm_dir(char * name)
{
	struct stat	s;
	pid_t		child;
	siginfo_t	si;

	if (stat(name, &s) == -1) {
		syslog(LOG_ERR,
		"nisbackup: directory %s does not exist: %m",
		name);
		return (1);
	}
	switch (child = vfork()) {
	case -1: /* error  */
		syslog(LOG_ERR, "Cannot remove files in %s", name);
		return (1);
	case 0:  /* child  */
		if (execl("/bin/rm", "rm",
			"-r",
			name,
			NULL) < 0)
			_exit(1);
		_exit(0); /* Since this is the child proc, we'll exit */
	default: /* parent, we'll wait for the cp to complete */
		if (waitid(P_PID, child, &si, WEXITED) == -1) {
			syslog(LOG_ERR, "Cannot remove files in %s", name);
			return (1);
		} else {
			if (si.si_status != 0) {
				syslog(LOG_ERR,
				"Can't remove files: error = %d",
				si.si_status);
				return (1);
			}
		}
	}
	return (0);
}

/*
 * bool_t is_master_of()
 *
 * Boolean function to check if local host is the master for the object
 * passed in nis_obj. If the passed in object is not fully qualified, then
 * nis_getnames() is called to resolve the object's full name. The parameter,
 * full_name, is used to return the fully qualified name (ignored if set to
 * NULL). The serving list is returned in srv_list.
 */

bool_t
is_master_of(char *nis_obj, char *full_name, directory_obj *srv_list)
{

	char		myname[NIS_MAXNAMELEN];
	nis_name	*namelist;
	nis_error	err;
	int		i;

	/*
	 * We will use __nis_CacheBind instead of nis_lookup() so that we
	 * can take advantage of the NIS_SHARED_DIRCACHE.
	 */
	if (nis_obj[strlen(nis_obj) - 1] != '.') { /* Partially qualified */
		namelist = nis_getnames(nis_obj);
		for (i = 0; namelist[i]; i++) {
#ifdef DEBUG
printf("name: %s\n", namelist[i]);
#endif
			err = __nis_CacheBind(namelist[i], srv_list);
			if (err == NIS_SUCCESS) {
				if (full_name)
					sprintf(full_name, "%s", namelist[i]);
				break;
			}
		}
	} else { /* Fully qualified */
		err = __nis_CacheBind(nis_obj, srv_list);
		if (err != NIS_SUCCESS) {
			if (verbiage)
				syslog(LOG_INFO,
				"Unable to lookup %s: %s", nis_obj,
				nis_sperrno(err));
			return (0);
		}
		if (full_name)
			sprintf(full_name, "%s", nis_obj);
	}

	if (err != NIS_SUCCESS) {
		if (verbiage)
			syslog(LOG_INFO,
			"Unable to lookup %s: %s", nis_obj, nis_sperrno(err));
		return (0);
	}
	/*
	 * If we can get a directory object, we check the master server name
	 * against the local host's name. This is the final result.
	 */
	if (err == NIS_SUCCESS) {
		sprintf(myname, "%s", nis_local_host());
		if (strcasecmp(myname,
				srv_list->do_servers.do_servers_val[0].name)
				== 0) {
			return (1);
		}
	}
	return (0);
}

/*
 * This is a link list of all the directories backed up on this server.
 */
struct nis_dir_list {
	char	*name;
	struct file_set obj_fs;
	struct nis_dir_list *next;
};
static struct nis_dir_list *dirlisthead = NULL;
enum CACHE_OP	{CACHE_INIT, CACHE_ADD, CACHE_SAVE, CACHE_FIND};
/*
 * dirobj_list() maintains list of directory objects that are backed up
 *            with the -a(ll) option of the nisbackup utility.
 *
 * The fclose() calls are checked for error returns, _except_ in the case
 * where an error has already occured, and we're returning FALSE.
 */
struct nis_dir_list *
dirobj_list(enum CACHE_OP op, char *argp)
{
	char	filename[BUFSIZ], tmpname[BUFSIZ];
	char	buf[BUFSIZ];
	FILE	*fr, *fw;
	char	*name, *end;
	int	ss;
	struct nis_dir_list *tmp = NULL;
	struct nis_dir_list *dlp = NULL;
	directory_obj sl;
	struct stat st;

	switch (op) {
	    case CACHE_INIT:
		/* Initialize cache with the serving list, for -a(ll) */
		strcpy(filename, nis_data("serving_list"));
		fr = fopen(filename, "r");
		if (fr == NULL) {
			ss = stat(filename, &st);
			if (ss == -1 && errno == ENOENT) {
				syslog(LOG_ERR, "Error opening %s: %m",
				filename);
				return (NULL);
			}
		}
		while (fgets(buf, BUFSIZ, fr)) {
			name = buf;
			while (isspace(*name))
				name++;
			end = name;
			while (!isspace(*end))
				end++;
			*end = NULL;
			tmp = (struct nis_dir_list *)
				XMALLOC(sizeof (struct nis_dir_list));
			if (tmp == NULL) {
				fclose(fr);
				syslog(LOG_ERR,
				"Internal error, no memory: %m");
				exit(1);
			}
		/*
		 * If we're the master, and it hasn't already been added...
		 */
			if (is_master_of(name, tmpname, &sl)) {
				for (dlp = dirlisthead; dlp; dlp = dlp->next)
					if (strcasecmp(dlp->name,
							(char *)tmpname) == 0) {
						XFREE(tmp);
						tmp = NULL;
						break;
					}
				if (tmp == NULL)
					continue;
				if ((tmp->name = strdup(tmpname)) == NULL) {
					XFREE(tmp);
					fclose(fr);
					syslog(LOG_ERR,
					"Internal error, no memory: %m");
					exit(1);
				}
				tmp->obj_fs.fssize = BUFSIZ;
				tmp->obj_fs.fslen = 0;
				tmp->obj_fs.fs = NULL;
				tmp->next = dirlisthead;
				dirlisthead = tmp;
			} else {
#ifdef DEBUG
fprintf(stderr, "dirobj_list: not master for %s\n", name);
#endif
				XFREE(tmp);
			}
		}
		if (fclose(fr) == EOF) {
			syslog(LOG_ERR, "Error closing %s", filename);
			exit(1);
		}
		return (dirlisthead);

	    case CACHE_ADD:
		if (argp == NULL)
			return (NULL);
		/* Check whether directory already added */
		for (tmp = dirlisthead; tmp; tmp = tmp->next)
			if (strcasecmp(tmp->name, (char *)argp) == 0)
				return (tmp);
		/* Add it to the cache */
		tmp = (struct nis_dir_list *)
					XMALLOC(sizeof (struct nis_dir_list));
		if (tmp == NULL) {
			syslog(LOG_ERR, "Could not allocate memory: %m");
			return (NULL);
		}
		if ((tmp->name = strdup((char *)argp)) == NULL) {
			syslog(LOG_ERR, "Could not allocate memory: %m");
			XFREE(tmp);
			return (NULL);
		}
		tmp->obj_fs.fssize = BUFSIZ;
		tmp->obj_fs.fslen = 0;
		tmp->obj_fs.fs = NULL;
		tmp->next = dirlisthead;
		dirlisthead = tmp;
#ifdef DEBUG
		fprintf(stderr, "objdir_list: added : %s\n", tmp->name);
#endif
		return (tmp);

	    case CACHE_SAVE:
		/*
		 * Save back'd up object(s) to a file. If argp set, then we're
		 * doing an individual object to the file:
		 * /backupdir/nis+object/backup_list. If argp is NULL, we're
		 * doing the whole cached list in /backupdir/backup_list.
		 */
		if (argp == NULL)
			return (NULL);
		fw = fopen(argp, "w");
		if (fw == NULL) {
			ss = stat(argp, &st);
			if (ss == -1 && errno == ENOENT) {
				fw = fopen(argp, "w+");
			}
			if (fw == NULL) {
				syslog(LOG_ERR,
				"Could not open file %s for updating: %m",
				argp);
				return (NULL);
			}
		}
		for (tmp = dirlisthead; tmp; tmp = tmp->next)
			fprintf(fw, "%s\n", (char *)tmp->name);
		if (fclose(fw) == EOF)
			return (NULL);
		return (dirlisthead);

	    case CACHE_FIND:	/* Search for object in cache */
		if (argp == NULL)
			return (NULL);
		for (tmp = dirlisthead; tmp; tmp = tmp->next)
			if (strcasecmp(tmp->name, (char *)argp) == 0)
				return (tmp);
		return (NULL);

	    default:
		return (NULL);
	}
}

void
abort_backup(char * backupdir)
{
	char		buf[NIS_MAXNAMELEN];
	struct	stat	s;
	struct nis_dir_list	*tmp = NULL;

	if (!backup_preserved) {
	/*
	 * If we didn't save an existing backup, then we didn't create anything
	 * either, so there's nothing to cleanup.
	 */
		return;
	}
	if (verbiage)
		syslog(LOG_WARNING,
			"Aborting NIS+ directory backup. Cleaning up files.");
	/*
	 * Check if backup/data directory exists. If yes, delete it.
	 */
	for (tmp = dirlisthead; tmp; tmp = tmp->next) {
		if (file_cleanup) {
			sprintf(buf, "%s/%s", backupdir, tmp->name);
			if (stat(buf, &s) != -1) {
				if (_rm_dir(buf)) {
					syslog(LOG_ERR,
					"Unable to remove directory %s", buf);
				}
			} else {
				if (errno != ENOENT) {
					syslog(LOG_ERR,
				"Unable to stat file system directory %s: %m",
					buf);
				}
			}
		}
		if (backup_preserved) {
			if (_mv_dir(buf, RESTORE)) {
				syslog(LOG_ERR,
					"Unable to restore old backup %s.tmp",
					buf);
			}
		}
	}
}

void
_cleanup(char * backupdir)
{
	char		buf[NIS_MAXNAMELEN];
	struct	stat	s;
	struct nis_dir_list 	*tmp = NULL;

	/*
	 * Check if preserved backup directories exists. If yes, delete them.
	 */
	for (tmp = dirlisthead; tmp; tmp = tmp->next) {
		sprintf(buf, "%s/%stmp", backupdir, tmp->name);
		if (stat(buf, &s) != -1) {
			if (_rm_dir(buf)) {
				syslog(LOG_ERR,
					"Unable to remove old backup %s", buf);
			}
		}
	}
}

bool_t
copyfile(char *srcfile, char *destfile)
{
	int	infd, outfd;
	char	buffer[4096];
	ssize_t	n;

	if ((infd = open(srcfile, O_RDONLY)) == -1)
		return (FALSE);
	if ((outfd = open(destfile, O_WRONLY|O_CREAT, 0664)) == -1) {
		close(infd);
		return (FALSE);
	}
	while (n = read(infd, buffer, sizeof (buffer))) {
		if (n == -1) {
			close(infd);
			close(outfd);
			return (FALSE);
		}
		if (write(outfd, buffer, n) != n) {
			close(infd);
			close(outfd);
			return (FALSE);
		}
	}
	if (close(infd))
		return (FALSE);
	if (close(outfd))
		return (FALSE);
	return (TRUE);
}


bool_t
backup(char * backup_path, struct nis_dir_list *dlp)
{
	char		logfile[NIS_MAXNAMELEN];
	char		srcfile[NIS_MAXNAMELEN], destfile[NIS_MAXNAMELEN];
	struct stat	s;
	char		*fs_p;
	char 		**fs;
	u_int		fslen;
	int		i;

	if (verbiage)
		syslog(LOG_INFO, "Copying files to backup partition: %s",
			backup_path);
	fs = dlp->obj_fs.fs;
	fslen = dlp->obj_fs.fslen;
	for (i = 0; i < fslen; ++i) {
		sprintf(logfile, "%s.log", fs[i]);
		fs_p = (fs[i]) + strlen(nis_data(NULL));
		sprintf(srcfile, "%s", fs[i]);
		sprintf(destfile, "%s%s", backup_path, fs_p);
		if ((stat(logfile, &s) == -1) && errno == ENOENT) {
		/*
		 * Simple copy of file.
		 */
			if (copyfile(srcfile, destfile) == FALSE)
				return (FALSE);
		} else {
		/*
		 * This loads the log file (if there is one) and copies all data
		 * to backup file. This esentially checkpoints the data file.
		 */
			if (db_copy_file(srcfile, destfile) == 0)
				return (FALSE);
		}
	}
	/*
	 * Finally, some special case files that need to be included, but that
	 * aren't part of the data dictionary.
	 */
	if ((root_dir) && (strcmp(dlp->name, nis_local_dir) == 0)) {
		sprintf(srcfile, "%s", nis_data(ROOT_OBJ));
		sprintf(destfile, "%s/%s", backup_path, ROOT_OBJ);
		return (copyfile(srcfile, destfile));
	}
	return (TRUE);
}


/*
 * bool_t is_this_a_dir()
 *
 * Boolean function to check if the object passed in is a directory object,
 * as opposed to a table object. This routine uses nis_lookup(), in nis_db.c,
 * to get a nis_object structure, which identifies the object type.
 */

bool_t
is_this_a_dir(nis_name name)
{
	nis_result	*res;
	char		fullname[NIS_MAXNAMELEN];

	sprintf(fullname, "%s.%s", name, nis_local_dir);
#ifdef DEBUG
	fprintf(stderr, "is_this_a_dir: looking up %s\n", fullname);
#endif
	if ((res = nis_lookup(fullname, MASTER_ONLY+USE_DGRAM)) == NULL)
		return (FALSE);
	if (res->status != NIS_SUCCESS) {
#ifdef DEBUG
			syslog(LOG_INFO, "Unable to lookup: %s: %s", fullname,
			nis_sperrno(res->status));
#endif
		return (FALSE);
	}
	if (res->status == NIS_SUCCESS) {
#ifdef DEBUG
	fprintf(stderr, "is_this_a_dir: %s found, type:%d\n", fullname,
		res->objects.objects_val);
#endif
		if (__type_of(res->objects.objects_val) == NIS_DIRECTORY_OBJ)
			return (TRUE);
		else
			return (FALSE);
	}
	return (FALSE);
}

void
sanity_checks(char *backupdir)
{
	struct stat		s;
	char			buf[NIS_MAXNAMELEN];
	struct	stat		st_t;
	nis_error		error = NIS_SUCCESS;
	struct nis_dir_list 	*tmp = NULL;

	if ((backupdir) && (*backupdir != '/')) {
		syslog(LOG_ERR, "%s is not a absolute path name.", backupdir);
		exit(1);
	}
	if (stat(backupdir, &s) == -1) {
		if (errno == ENOENT) {
			syslog(LOG_ERR,
			"Directory %s does not exist, please create.",
			backupdir);
			exit(1);
		} else {
			syslog(LOG_ERR,
			"An error occured while accessing %s: %m", backupdir);
			exit(1);
		}
	}

	/*
	 * Are we backing up a root-domain ? Note, either the root object
	 * has been specified, or the -a(ll) option. If so, check for the
	 * existence of a root object.
	 */

	sprintf(buf, "%s", nis_data(ROOT_OBJ));
	if ((dirobj_list(CACHE_FIND, nis_local_dir)) ||
		(flags & DOMAIN_ALL)) {
		if (stat(buf, &st_t) == -1) {
			if (errno == ENOENT)
				root_dir = FALSE;
		}
		else
			root_dir = TRUE;
	}

	/*
	 * We can initialize the object cache with the serving list if we
	 * are backing up -a(ll). If the directory object(s) to backup is
	 * specified (not -a(ll) option), add that in to initialize the cache.
	 */
	if (flags & DOMAIN_ALL) {
		if (dirobj_list(CACHE_INIT, NULL) == NULL) {
			syslog(LOG_ERR,
			"Could not initialize, is this a master server?");
			exit(1);
		}
		/*
		 * The cache is initialized, now we need initialize the server
		 * list.
		 */
		if (is_master_of(dirlisthead->name, NULL, &slist) == FALSE) {
			syslog(LOG_ERR, "Not master for %s", dirlisthead->name);
			exit(1);
		}
	}
#ifdef DEBUG
		for (tmp = dirlisthead; tmp; tmp = tmp->next)
			fprintf(stderr, "%s\n", tmp->name);
#endif

	/*
	 * Backup dirs setup, initialize signal handlers, which will cleanup
	 * if nisbackup is interupted from this point.
	 */
	init_signals();

	/*
	 * Make sure we reset the read-write flag in the server upon exit.
	 * set_rw() checks server_ro == TRUE, to make sure we actually set
	 * it to read-only!
	 */
	atexit(set_rw);

	/*
	 * Set server state to read-only. This must be done to take a backup.
	 */
	int slp_time = 2;
	int retries = 0;
	while (((error = set_ro()) != NIS_SUCCESS) &&
		(retries++ < MAXRETRIES)) {
		if (verbiage) {
			syslog(LOG_INFO,
				"Unable to set server to read-only: %s",
				nis_sperrno(error));
			syslog(LOG_INFO, "Retrying in %d seconds", slp_time);
		}
		sleep(slp_time);
		slp_time = slp_time * 2;
	}
	if (error != NIS_SUCCESS) {
		syslog(LOG_INFO,
		"Unable to set server to read-only mode, exiting.");
		abort_backup(backupdir);
		exit(1);
	}

	/*
	 * Check if backup directory(ies) exists. If not, create. If they
	 * do exist (old backup), save them off, until new backup created.
	 * Upon successful creation of a new backup, remove the saved copy.
	 */
	for (tmp = dirlisthead; tmp; tmp = tmp->next) {
		sprintf(buf, "%s/%s", backupdir, tmp->name);
		if (stat(buf, &s) == -1) {
			if (errno == ENOENT) {
				if (mkdir(buf, 0777)) {
					syslog(LOG_ERR,
					"Unable to create directory %s: %m",
					buf);
					exit(1);
				}
			} else {
				syslog(LOG_ERR,
				"Unable to stat file system directory %s: %m",
				buf);
				exit(1);
			}
		} else {
			/*
			 * Move old backup to backup-dir.tmp. Once backup
			 * successful, backup-dir.tmp will be removed. In
			 * case of failure, we will not lose old backup.
			 */
			if (_mv_dir(buf, PRESERVE)) {
				syslog(LOG_ERR,
					"Unable to save old backup %s", buf);
				exit(1);
			}
			backup_preserved = TRUE;
			if (mkdir(buf, 0777)) {
				syslog(LOG_ERR,
					"Unable to create directory %s: %m",
					buf);
				exit(1);
			}
			file_cleanup = TRUE;
		}

		/*
		 * Check for a "data" directory under each backup-dir.
		 */
		sprintf(buf, "%s/%s", buf, NIS_DIR);
		if (stat(buf, &s) == -1) {
			if (errno == ENOENT) {
				if (mkdir(buf, 0777)) {
					syslog(LOG_ERR,
					"Unable to create directory %s: %m",
					buf);
					abort_backup(backupdir);
					exit(1);
				}
			} else {
				syslog(LOG_ERR,
					"Unable to stat directory %s: %m", buf);
				abort_backup(backupdir);
				exit(1);
			}
		}
	}
}

void
determine_file_set()
{
	char		localdir[NIS_MAXNAMELEN];
	char		full_name[NIS_MAXNAMELEN];
	char		buf[NIS_MAXNAMELEN];
	char		*domainof;
	DIR		*dirptr;
	struct dirent	*dent;
	struct nis_dir_list *tmp = NULL;


	sprintf(localdir, "%s", nis_data(NULL));
	if ((dirptr = opendir(localdir)) == NULL) {
		syslog(LOG_ERR, "Unable to open %s: %m", localdir);
		exit(1);
	}

/* This assumes that the dictionary has been initialized */

	while ((dent = readdir(dirptr)) != NULL) {
		if (strcmp(dent->d_name, ".") == 0)
			continue; /* Ignore */
		if (strcmp(dent->d_name, "..") == 0)
			continue; /* Ignore */
		if (strstr(dent->d_name, ".log"))
			continue; /* Ignore log files */
		if (strcmp(dent->d_name, ROOT_OBJ) == 0)
			continue; /* Ignore root.object, we'll get it later */

		sprintf(buf, "%s/%s", nis_data(NULL), dent->d_name);
		sprintf(full_name, "%s.%s", dent->d_name, nis_local_dir);
#ifdef DEBUG
	printf("searching for: %s\n", buf);
	printf("full name:     %s\n", full_name);
#endif
/*
 * Look up the file in the data dictionary. It could be a stray ufs
 * file, that has nothing to do with NIS+.
 */
		if (db_in_dict_file(buf)) { /* In dictionary? */
/*
 * Check for the directory objects that are being backed up. Put them into
 * their own fileset, instead of the directory object that they belong
 * to. This insures that each object backup is autonomous, and can be restored
 * separately. Is it a DIRECTORY? Is it in list of objects to backup? fspush it!
 */
			if (is_this_a_dir(dent->d_name)) {
				if ((tmp = dirobj_list(CACHE_FIND, full_name))
								== NULL)
					continue;
			} else {
/*
 * Determine the which directory object this object belongs to.
 */
				domainof = nis_domain_of(full_name);
					if ((tmp = dirobj_list(CACHE_FIND,
							domainof)) == NULL)
						continue;
			}
			fspush(strdup(buf), &(tmp->obj_fs));
			continue;
		} /* In data dictionary */
	} /* while (readdir) */
	closedir(dirptr);
}


bool_t
create_perdir_translog(char *newlog, struct nis_dir_list *dlp)
{
	directory_obj	sl;
	char		fullname[NIS_MAXNAMELEN];
	char		*str_p = fullname;
	uint32_t	u_time;
	uint32_t	u_nl;
	FILE		*fw;
	int		ss;
	struct stat	st;
	int		i;

	fw = fopen(newlog, "w");
	if (fw == NULL) {
		ss = stat(newlog, &st);
		if (ss == -1 && errno == ENOENT)
			if ((fw = fopen(newlog, "w+")) == NULL) {
				syslog(LOG_ERR,
				"Cannot open file %s for updating: %m", newlog);
				return (FALSE);
			}
	}
/*
 * Write a backup revision number to the this file, so that nisrestore(1M)
 * will know if it can understand this backup.
 */
	u_nl = htonl(BACKUPREV);
	if (!fwrite(&u_nl, sizeof (u_nl), 1, fw)) {
		syslog(LOG_ERR, "Cannot write rev # to file %s: %d",
			newlog, ferror(fw));
		return (FALSE);
	}
/*
 * Find the last time stamp for the directory(ies) being modified.
 */
	if (is_master_of(dlp->name, str_p, &sl) == FALSE) {
		syslog(LOG_ERR, "Sorry, %s is not the master for %s",
			nis_local_host(), dlp->name);
		return (FALSE);
	}
/*
 * Since, we are running as root, the nis_local_principal() should be OK.
 */
	for (i = 0; i < MAXRETRIES; i++)
		if ((u_time = nis_cptime(sl.do_servers.do_servers_val,
					fullname)) != 0)
			break;
	if (u_time == 0) {
		syslog(LOG_ERR, "Unable to get last update time for %s",
			fullname);
		return (FALSE);
	}
	u_nl = htonl(u_time);
	if (!fwrite(&u_nl, sizeof (u_nl), 1, fw)) {
		syslog(LOG_ERR, "Cannot write update to file %s: error %d",
			newlog, ferror(fw));
		return (FALSE);
	}
#ifdef DEBUG
	fprintf(stderr, "create_perdir_translog: last update: %d\n", u_time);
#endif
	if (fclose(fw) == EOF) {
		syslog(LOG_ERR, "Error closing file %s", newlog);
		return (FALSE);
	}
	return (TRUE);
}

bool_t
merge_backup_list()
{
	char	buf[BUFSIZ];
	char	filename[BUFSIZ];
	FILE	*fr;
	char	*name, *end;
	int	ss;
	struct	stat st;

	sprintf(filename, "%s/%s", backupdir, BACKUPLIST);
	ss = stat(filename, &st);
	if (ss == -1 && errno == ENOENT) {
	/*
	 * If it doesn't exist, CACHE_SAVE will create it.
	 */
		return ((dirobj_list(CACHE_SAVE, filename) == dirlisthead));
	} else {
		fr = fopen(filename, "r");
		if (fr == NULL)
			return (FALSE);
		while (fgets(buf, BUFSIZ, fr)) {
			name = buf;
			while (isspace(*name))
				name++;
			end = name;
			while (!isspace(*end))
				end++;
			*end = NULL;
			if (dirobj_list(CACHE_ADD, name) == NULL) {
				fclose(fr);
				return (FALSE);
			}
		}
		fclose(fr);
		return ((dirobj_list(CACHE_SAVE, filename) == dirlisthead));
	}
}

int
main(int argc, char *argv[])
{
	char		nisdomain[NIS_MAXNAMELEN];
	char		buf[NIS_MAXNAMELEN];
	int		c;
	bool_t		dbstat;
	char		*tmp;
	struct nis_dir_list *dl = NULL;

	openlog("nisbackup", LOG_PID+LOG_NOWAIT, LOG_USER);
	if (geteuid() != 0) {
		syslog(LOG_ERR, "You must be root to run nisbackup.");
		exit(1);
	}
	if (argc < 3)
		usage();

	while ((c = getopt(argc, argv, "av")) != -1) {
		switch (c) {
		case 'a' :
			flags |= DOMAIN_ALL;
			break;
		case 'v' :
			verbiage = TRUE;
			break;
		default:
			usage();
		}
	}
	if (flags & DOMAIN_ALL) {
		if (argc - optind != 1)
			usage();
		backupdir = argv[optind++];
	} else {
		if (argc - optind < 2)
			usage();
		backupdir = argv[optind++];
		/*
		 * Yes, I really mean "=", not "==". tmp is assigned in while.
		 */
		while (tmp = argv[optind++]) {
			memset(nisdomain, 0, sizeof (nisdomain));
			if (is_master_of(tmp, nisdomain, &slist)) {
				if (dirobj_list(CACHE_ADD, nisdomain)
								== NULL) {
					syslog(LOG_ERR,
				"Internal error, unable to add to cache");
					exit(1);
				}
			} else {
				syslog(LOG_ERR,	"Not master for %s", tmp);
				exit(1);
			}
		}
	}
	sanity_checks(backupdir);
	sprintf(buf, "%s.dict", nis_data(NULL));
	dbstat = db_initialize(buf);
	if (dbstat == 0) {
		abort_backup(backupdir);
		syslog(LOG_ERR, "Unable to initialize %s", buf);
		exit(1);
	}
	determine_file_set();
/*
 * Loop through dirobj_list, creating the backup_path for each
 * object in the cache, then db_extrace_dict_entries, backup,
 * create_perdir_translog and write backup_list for each entry in the cache.
 */
	for (dl = dirlisthead; dl; dl = dl->next) {
		sprintf(buf, "%s/%s/%s.dict", backupdir, dl->name, NIS_DIR);
		if (!db_extract_dict_entries(buf, dl->obj_fs.fs,
						dl->obj_fs.fslen)) {
			abort_backup(backupdir);
			syslog(LOG_ERR, "Unable to create %s.", buf);
			exit(1);
		}
		sprintf(buf, "%s/%s/%s", backupdir, dl->name, NIS_DIR);
		if (!backup(buf, dl)) {
			abort_backup(backupdir);
			syslog(LOG_ERR, "Unable to backup files to %s.", buf);
			exit(1);
		}
		sprintf(buf, "%s/%s/%s", backupdir, dl->name, LASTUPDATE);
		if (!create_perdir_translog(buf, dl)) {
			abort_backup(backupdir);
			syslog(LOG_ERR, "Unable to create %s.", buf);
			exit(1);
		}
	}
	if (!merge_backup_list()) {
		abort_backup(backupdir);
		syslog(LOG_ERR, "Unable to create %s.", BACKUPLIST);
		exit(1);
	}
	_cleanup(backupdir);
	exit(0);
}
