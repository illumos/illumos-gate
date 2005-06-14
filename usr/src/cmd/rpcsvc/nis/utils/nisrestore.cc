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
 *	nisrestore.cc
 *
 *	Copyright (c) 1988-1998 by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nisrestore.cc
 *
 * A NIS+ utility for restoring archived databases, as well as an
 * out-of-band resync mechanism.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <wait.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <rpcsvc/nis_db.h>
#include <rpcsvc/nis.h>
#include "nis_bkrst.h"
#include "../rpc.nisd/log.h"
#include "../rpc.nisd/nis_proc.h"

/*
 * Global state variables.
 */
static bool_t		force = FALSE;
static bool_t		aflg = FALSE;
static bool_t		tocflg = FALSE;
static bool_t		olddata = TRUE;
static bool_t		verbiage = FALSE;
static nis_server	*srv_ptr = NULL;
static char		*syncfile = "/var/nis/nisrestore.pid";
static char		*tempdir = "/var/nis/.nisrestore";
static int		fd_sync;

static void		abort_handler(int);

/*
 * Extern variables related to the trans.log header.
 */
extern log_hdr  *__nis_log;
extern int	__nis_logfd;
extern unsigned long __maxloglen, __loghiwater, __nis_logsize, __nis_filesize;
extern "C" char *relative_name(char *);

/*
 * We are masquerading as the master server, so we can create and write
 * to a temporary transaction file. This will get us around the
 * CHILDPROC check.
 */
extern pid_t master_pid;

/*
 * This restoration utility assumes the backup was performed by the nisbackup
 * utility and not via some other tools. Using nisbackup will validate the
 * following assumptions being made during the restoration sequence:
 *
 *	- the backup directory is organized on a per-directory basis.
 *	- there are no log files. No table logs and no dictionary log.
 *		(the backup utility _simulates_ a checkpoint)
 *	- the dictionary file has entries only for the table files relevant
 *		to the directory being restored. In other words, the complete
 *		dictionary file is merged without validating each entry.
 *	- the transaction log has only entry and that is the UPD_TIME_STAMP
 *		entry for the directory being restored.
 *
 */

/*
 * Needs to be cleaned up in nislog as well as here. nis_log_common.o
 * is shared by rpc.nisd as well as nislog and nisbackup and rpc.nisd
 * source already defines this.
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
	exit(1);
}

/*
 * clean_up() called atexit()
 */
static void
clean_up()
{
	close(fd_sync);
	unlink(syncfile);
}

void
usage()
{
	fprintf(stderr, "usage: nisrestore [-fv] backup-dir directory...\n");
	fprintf(stderr, "       nisrestore [-fv] -a backup-dir\n");
	fprintf(stderr, "       nisrestore -t backup-dir\n");
	exit(1);
}

/*
 * This routine vforks "rm -r" to remove a non-empty directory, for cleanup.
 */
int
_rm_dir(char * name)
{
	struct stat	s;
	pid_t		child;
	siginfo_t	si;

	if (stat(name, &s) == -1) {
		fprintf(stderr,
		"nisbackup: directory %s does not exist.", name);
		return (1);
	}
	switch (child = vfork()) {
	case -1: /* error  */
		fprintf(stderr, "Cannot remove files in %s", name);
		return (1);
	case 0:  /* child  */
		if (execl("/bin/rm", "rm",
			"-r",
			name,
			NULL) < 0)
			_exit(1);
		_exit(0); /* Since this is the child proc, we'll exit */
	default: /* parent, we'll wait for the rm to complete */
		if (waitid(P_PID, child, &si, WEXITED) == -1) {
			fprintf(stderr, "Cannot remove files in %s", name);
			return (1);
		} else {
			if (si.si_status != 0) {
				fprintf(stderr,
				"Can't remove files: error = %d",
				si.si_status);
				return (1);
			}
		}
	}
	return (0);
}

/*
 * This routine takes the old name of the data file, a token to search for,
 * and the replacement string to replace the token with. This will change
 * names like org_dir.foo.bar to org_dir.foo (tok=.foo.bar, repl=.foo).
 */
char *
change_name(char *filename, char *tok, char *repl)
{
	char    *newname;
	char    *loc_end, *loc_beg;
	char	*s;

	newname = (char *) calloc(1, sizeof (char) * strlen(filename) +
				strlen(repl) - strlen(tok) + 1);
	if (!newname) {
		fprintf(stderr, "Unable to allocate memory.\n");
		return (NULL);
	}
	if (strlen(tok) == 0) {
		strcpy(newname, filename);
		strcat(newname, repl);
	} else {
		if (s = strstr(filename, tok)) {
			int sublen = s - filename;
			memcpy(newname, filename, sublen);
			strcat(newname, repl);
		} else {
			free(newname);
			return (NULL);
		}
	}
	return (newname);
}

/*
 * This routine checks the data file names in the backup with their relative
 * name on this server. If the master server that generated this backup lived
 * in a different domain than this (replica) server, the files will need to
 * be renamed and their names changed in the data dictionary.
 */
bool_t
files_need_renaming(char * full_obj_name, char * backup_data_dir,
			char ** oldsuf, char ** newsuf)
{

	char		buf[BUFSIZ];
	struct stat 	st;
	char		*domainof;
	DIR		*dirptr;
	struct dirent	*dent;
	char		*p;

	*oldsuf = NULL;
	*newsuf = NULL;
	/*
	 * If we're restoring a root domain server, no renaming.
	 */
	sprintf(buf, "%s/%s", backup_data_dir, ROOT_OBJ);
	if (stat(buf, &st) == 0) {
		return (FALSE);
	}
	/*
	 * The only way the localized name of the object is NULL is by
	 * using the -f(orce) option on a machine that's in the wrong
	 * domain for this object. All bets are off with the -f option. Punt.
	 */
	if (nis_name_of(full_obj_name) == NULL)
		return (FALSE);

	/*
	 * If localized name of directory exist in backup dir, no renaming.
	 */
	p = relative_name(full_obj_name);
	sprintf(buf, "%s/%s", backup_data_dir, p);
	if (stat(buf, &st) == 0) {
		free((void *)p);
		return (FALSE);
	}

	if ((dirptr = opendir(backup_data_dir)) == NULL) {
		fprintf(stderr, "Unable to open %s: %m", backup_data_dir);
		exit(1);
	}
	while ((dent = readdir(dirptr)) != NULL) {
		if (strcmp(dent->d_name, ".") == 0)
			continue; /* Ignore */
		if (strcmp(dent->d_name, "..") == 0)
			continue; /* Ignore */

	/*
	 * Extrace the domain part of the entry, which will be the old suffix.
	 * Then get the domain part of the entry as it would be stored on this
	 * server (new suffix).
	 */
		if (strcmp(nis_domain_of(dent->d_name), ".") == 0) {
			*oldsuf = strdup("");
		} else {
			sprintf(buf, ".%s", nis_domain_of(dent->d_name));
			*oldsuf = strdup(buf);
		}

		if (strcmp(nis_domain_of(p), ".") == 0) {
			*newsuf = strdup("");
		} else {
			sprintf(buf, ".%s", nis_domain_of(p));
			*newsuf = strdup(buf);
		}
		break;
	}
	return (TRUE);
}

bool_t
rename_data_files(char * oldsuf, char * newsuf)
{

	char		buf[BUFSIZ];
	char		oldname[BUFSIZ];
	char		newname[BUFSIZ];
	char		*newtablename;
	char		dotlog[BUFSIZ];
	DIR		*dirptr;
	struct dirent	*dent;

	sprintf(buf, "%s/data", tempdir);
	if ((dirptr = opendir(buf)) == NULL) {
		fprintf(stderr, "Unable to open %s: %m", buf);
		return (FALSE);
	}
	while ((dent = readdir(dirptr)) != NULL) {
		if (strcmp(dent->d_name, ".") == 0)
			continue; /* Ignore */
		if (strcmp(dent->d_name, "..") == 0)
			continue; /* Ignore */
	/*
	 * Take the leaf name of the table, append the new suffix, then rename
	 * the file. Attempt to unlink any .log file that may still be present.
	 */
		if ((newtablename = change_name(dent->d_name, oldsuf, newsuf))
						== FALSE) {
			fprintf(stderr, "Unable to rename data files\n");
			return (FALSE);
		}
		sprintf(newname, "/var/nis/data/%s", newtablename);
		sprintf(oldname, "%s/%s", buf, dent->d_name);
		rename(oldname, newname);
		sprintf(dotlog, "%s.log", newname);
		unlink(dotlog);
	}
	/* The temporary directory should be empty now, so we can remove it. */
	if (_rm_dir(tempdir)) {
		fprintf(stderr, "Unable to remove directory:%s", tempdir);
		return (FALSE);
	}

	return (TRUE);
}

/*
 * bool_t is_server_of()
 *
 * Boolean function to check if local host is a server for the object
 * passed in nis_obj. If the passed in object is not fully qualified, then
 * nis_getnames() is called to resolve the object's full name. The parameter,
 * full_name, is used to return the fully qualified name (ignored if set to
 * NULL). The nis_server struct is returned in *srv.
 */
bool_t
is_server_of(char *nis_obj, char *full_name, nis_server **srv)
{

	char		myname[NIS_MAXNAMELEN];
	nis_name	*namelist;
	nis_error	err;
	int		i;
	directory_obj 	d_obj;

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
			err = __nis_CacheBind(namelist[i], &d_obj);
			if (err == NIS_SUCCESS) {
				if (full_name)
					sprintf(full_name, "%s", namelist[i]);
				break;
			}
		}
	} else { /* Fully qualified */
		err = __nis_CacheBind(nis_obj, &d_obj);
		if (err == NIS_SUCCESS)
			if (full_name)
				sprintf(full_name, "%s", nis_obj);
	}
	if (err != NIS_SUCCESS) {
		fprintf(stderr, "Unable to lookup %s\n", nis_obj);
#ifdef DEBUG
fprintf(stderr, "Error code=%d\n", err);
#endif
		return (0);
	}
	/*
	 * If we can get a directory object, we check for membership.
	 */
	if (err == NIS_SUCCESS) {
		sprintf(myname, "%s", nis_local_host());
		for (i = 0; i < d_obj.do_servers.do_servers_len; i++) {
			if (strcasecmp(myname,
				d_obj.do_servers.do_servers_val[i].name)
			== 0) {
				*srv = &(d_obj.do_servers.do_servers_val[i]);
				return (1);
			}
		}
	}
	if (!force)
		fprintf(stderr, "Not server for %s\n", nis_obj);
	return (0);
}        

/*
 * This is a link list of the directories being restored on this server.
 */
struct nis_dir_list {
	char	*name;
	uint32_t	upd_time;
	struct nis_dir_list *next;
};
static struct nis_dir_list *dirlisthead = NULL;
enum CACHE_OP	{CACHE_INIT, CACHE_ADD, CACHE_SAVE, CACHE_FIND, CACHE_DUMP};
/*
 * dirobj_list() maintains list of directory objects that are backed up
 *            with the -a(ll) option of the nisbackup utility.
 */
struct nis_dir_list *
dirobj_list(enum CACHE_OP op, char *argp)
{
	char	buf[BUFSIZ];
	FILE	*fr, *fw;
	char	*name, *end;
	int	ss;
	struct nis_dir_list *tmp = NULL;
	struct stat st;

	switch (op) {
	case CACHE_INIT:
		/* Initialize cache with the file name passed in argp */
		fr = fopen(argp, "r");
		if (fr == NULL) {
			return ((struct nis_dir_list *) NULL);
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
				return ((struct nis_dir_list *) NULL);
			}
			if ((tmp->name = strdup(name)) == NULL) {
				free(tmp);
				fclose(fr);
				return ((struct nis_dir_list *) NULL);
			}
			tmp->next = dirlisthead;
			dirlisthead = tmp;
		}
		fclose(fr);
		return (dirlisthead);

	case CACHE_ADD:
		if (argp == NULL)
			return ((struct nis_dir_list *) NULL);
		/* Check whether already in cache */
		for (tmp = dirlisthead; tmp; tmp = tmp->next)
			if (strcasecmp(tmp->name, (char *)argp) == 0)
				return (tmp);

		/* Add it */
		tmp = (struct nis_dir_list *)
					malloc(sizeof (struct nis_dir_list));
		if (tmp == NULL) {
			return ((struct nis_dir_list *) NULL);
		}
		if ((tmp->name = strdup((char *)argp)) == NULL) {
			free(tmp);
			return ((struct nis_dir_list *) NULL);
		}
		tmp->next = dirlisthead;
		dirlisthead = tmp;
#ifdef DEBUG
		fprintf(stderr, "objdir_list: added : %s\n", tmp->name);
#endif
		return (tmp);

	case CACHE_SAVE:	/* Save back'd up objects to a file */
		if (argp == NULL)
			return (NULL);
		fw = fopen(argp, "w");
		if (fw == NULL) {
			ss = stat(argp, &st);
			if (ss == -1 && errno == ENOENT) {
				fw = fopen(argp, "w+");
			}
			if (fw == NULL) {
				fprintf(stderr,
					"Could not open file %s for updating\n",
						argp);
				return ((struct nis_dir_list *) NULL);
			}
		}
		for (tmp = dirlisthead; tmp; tmp = tmp->next)
			fprintf(fw, "%s\n", (char *)tmp->name);
		if (fclose(fw) == EOF)
			return (NULL);
		return (dirlisthead);

	case CACHE_FIND:    /* Search for object in cache */
		if (argp == NULL)
			return (NULL);
		for (tmp = dirlisthead; tmp; tmp = tmp->next)
			if (strcasecmp(tmp->name, (char *)argp) == 0)
				return (tmp);
		return (NULL);

	case CACHE_DUMP:    /* Show 'em what we've got */
			for (tmp = dirlisthead; tmp; tmp = tmp->next)
				fprintf(stderr, "%s : %d\n",
					tmp->name, tmp->upd_time);
			return ((struct nis_dir_list *) NULL);

	default:
		return ((struct nis_dir_list *) NULL);
	}
}

int
merge_trans_log()
{
	log_upd		*cur, *nxt;
	u_long		addr_p, upd_size;
	int		error;
	int		fd, num = 0;
	int		ret;
	char		backup[1024];
	char		buf[NIS_MAXNAMELEN];
	ulong		last_xid = 0;
	struct nis_dir_list *tmp = NULL;

	if (verbiage)
		fprintf(stderr, "Merging the transaction log.\n");

	/*
	 * Map in transaction log file.
	 */
	sprintf(buf, "%s", LOG_FILE);
	if (map_log(buf, FNISD)) {
		fprintf(stderr,
		"Unable to map transaction log : %s\n", buf);
		return (0);
	}

	if (__nis_log->lh_state != LOG_STABLE) {
		fprintf(stderr,
		"Unable to merge transaction log, log unstable.\n");
		return (0);
	}

	strcpy(backup, nis_data(BACKUP_LOG));

	fd = open(backup, O_WRONLY+O_SYNC+O_CREAT+O_TRUNC, 0600);
	if (fd == -1) {
		fprintf(stderr,
		"Unable to open backup log (%s).\n", backup);
		return (0);
	}

	/*
	 * Make a backup of the log in two steps, write the size of the log
	 * and then a copy of the log.
	 */
	__nis_logsize = (__nis_log->lh_tail) ? LOG_SIZE(__nis_log) :
							sizeof (log_hdr);
	if (write(fd, &__nis_logsize, sizeof (long)) != sizeof (long)) {
		fprintf(stderr,
			"Unable to merge transaction log, disk full.\n");
		close(fd);
		unlink(backup);
		return (0);
	}
	/*
	 * Now set the state to RESYNC so if we have to recover and read
	 * this back in, and we get screwed while reading it, we won't
	 * get into major trouble. This still leaves open one window :
	 * a) Start checkpoint
	 * b) Successfully backup to BACKUP
	 * c) Set log state to CHECKPOINT
	 * c) crash.
	 * d) Reboot and start reading in the backup log
	 * e) crash.
	 * f) reboot and now the log appears to be resync'ing without
	 *    all of its data.
	 */
	__nis_log->lh_state = LOG_RESYNC;
	if (write(fd, __nis_log, (size_t) __nis_logsize) != __nis_logsize) {
		fprintf(stderr,
			"Unable to merge transaction log, disk full.\n");
		close(fd);
		unlink(backup);
		__nis_log->lh_state = LOG_STABLE;
		sync_header();
		return (0);
	}
	close(fd);

	/* If we crash here we're ok since the log hasn't changed. */
	__nis_log->lh_state = LOG_CHECKPOINT;
	sync_header();

	addr_p = (u_long)(__nis_log->lh_head);
	for (cur = __nis_log->lh_head, num = 0; cur; cur = nxt) {
		nxt = cur->lu_next;
		for (tmp = dirlisthead; tmp; tmp = tmp->next) {
			if (nis_dir_cmp(cur->lu_dirname, tmp->name) ==
							SAME_NAME)
				break;
		}
		if (tmp == NULL) {
			upd_size = XID_SIZE(cur);
			memmove((char *)addr_p, (char *)cur, (size_t) upd_size);
			last_xid = cur->lu_xid;
			addr_p += upd_size;
			num++;
		}
	}

	if (num == 0) {
		/* Deleted all of the entries. */
#ifdef DEBUG
			fprintf(stderr,
				"merge_trans_log: all entries removed.\n");
#endif
		__nis_log->lh_head = NULL;
		__nis_log->lh_tail = NULL;
		__nis_log->lh_num = 0;
		sync_header();
		ret = ftruncate(__nis_logfd, FILE_BLK_SZ);
		if (ret == -1) {
			fprintf(stderr,
			"Cannot truncate transaction log file\n");
			return (0);
		}
		__nis_filesize = FILE_BLK_SZ;
		ret = (int)lseek(__nis_logfd, __nis_filesize, SEEK_SET);
		if (ret == -1) {
			fprintf(stderr,
		"merge_trans_log: cannot increase transaction log file size\n");
			return (0);
		}
		ret = (int) write(__nis_logfd, "+", 1);
		if (ret != 1) {
			fprintf(stderr,
			"cannot write one character to transaction log file\n");
			return (0);
		}
		__nis_logsize = sizeof (log_hdr);
		if (msync((caddr_t)__nis_log,
					(size_t) __nis_logsize, MS_SYNC)) {
			perror("msync:");
			fprintf(stderr, "unable to mysnc() LOG\n");
			return (0);
		}

	} else {
#ifdef DEBUG
			fprintf(stderr,
				"merge_trans_log: some entries removed.\n");
#endif
		__nis_log->lh_xid = last_xid;
		__nis_log->lh_num = num;
		sync_header();
		error = __log_resync(__nis_log, FCHKPT);
		if (error) {
			fprintf(stderr,
		"Transaction log merge failed, unable to resync.\n");
			return (0);
		}
	}

	/*
	 * Write back "last update" stamps for all of the directories
	 * we're restoring.
	 */
	__nis_log->lh_state = LOG_STABLE;
	sync_header();
	for (tmp = dirlisthead; tmp; tmp = tmp->next)
		make_stamp(tmp->name, (u_long) tmp->upd_time);
	unlink(backup);
	return (1);
}

int
copydir(char *src, bool_t rename_files)
{
	char		dest[1024];
	struct stat	s;
	pid_t		child;
	siginfo_t	si;

	if (stat(src, &s) == -1) {
		fprintf(stderr, "Directory %s does not exist.\n", src);
		exit(1);
	}
	if (rename_files) {
	/*
	 * We need to rename each file! We'll copy them into the temporary
	 * directory, to be renamed into the /var/nis/data directory in
	 * rename_data_files().
	 */
		strcpy(dest, tempdir);
		if (stat(dest, &s) == -1) {
			if (errno == ENOENT) {
				if (mkdir(dest, 0700)) {
					fprintf(stderr,
					"Unable to create NIS+ directory %s\n",
					dest);
					exit(1);
				}
			} else {
				fprintf(stderr,
				"Unable to stat NIS+ directory %s.\n", dest);
				exit(1);
			}
		} else {
			_rm_dir(dest);
			if (mkdir(dest, 0700)) {
				fprintf(stderr,
				"Unable to create NIS+ directory %s\n",
				dest);
				exit(1);
			}
		}
	} else {
		strcpy(dest, "/var/nis");
	}

	switch (child = vfork()) {
	case -1: /* error  */
		fprintf(stderr, "Can't copy backed up files\n");
		exit(1);
	case 0:  /* child  */
		if (execl("/bin/cp", "cp", "-r", src, dest, NULL) < 0)
			_exit(1);
		_exit(0);
	default: /* parent, we'll wait for the cp to complete */
		if (waitid(P_PID, child, &si, WEXITED) == -1) {
			fprintf(stderr, "Can't copy backed up files\n");
			exit(1);
		} else {
			if (si.si_status != 0) {
				fprintf(stderr,
				"Can't copy backed up files: error = %d\n",
				si.si_status);
				exit(1);
			}
		}
	}
	return (1);
}

void
sanity_checks(char *backupdir)
{
	struct stat		s;
	char			buf[NIS_MAXNAMELEN];
	char 			backup_path[NIS_MAXNAMELEN];
	char			trans_log[NIS_MAXNAMELEN];
	struct nis_dir_list	*tmp = NULL;
	nis_tag		*res = NULL;
	nis_error	error = NIS_SUCCESS;
	nis_tag		tagctl;
	unsigned char	u_nl[16];
	uint32_t	*unl_p;
	FILE		*fr = NULL;
	char		pid[16];
	int		fd_s;
#ifdef DEBUG
	struct timeval  ctime;
	int		elapse;
#endif

	/*
	 * Create a synchronization file, to prevent multiple invocations
	 * of nisrestore from running simultaneously.
	 */
	if ((fd_sync = open(syncfile, O_RDWR | O_CREAT, 0644)) == -1) {
		fprintf(stderr,
			"Unable to create pid file: %s\n", syncfile);
		exit(1);
	}
	/*
	 * Lock without blocking. If we can't get it, another nisrestore
	 * must have it.
	 */
	lseek(fd_sync, 0L, SEEK_SET);
	if ((fd_s = lockf(fd_sync, F_TLOCK, 1)) == -1) {
		close(fd_sync);
		fprintf(stderr, "Unable to lock pid file: %s\n", syncfile);
		fprintf(stderr, "Is nisrestore already running?\n");
		exit(1);
	}
	/*
	 * We'll write our pid to the file, for good measure. Leave the
	 * fd_sync open for the duration of the restore.
	 */
	sprintf(pid, "%d\n", getpid());
	if (write(fd_sync, pid, strlen(pid) + 1) < 0) {
		close(fd_sync);
		fprintf(stderr, "Cannot write pid file: %s\n", syncfile);
		exit(1);
	}

	/*
	 * Catch signals and clean up files before exit.
	 */
	init_signals();

	/*
	 * Clean up any files before we exit.
	 */
	atexit(clean_up);

	if (*backupdir != '/') {
		fprintf(stderr,
			"Backup directory %s is not a absolute path name.\n",
			backupdir);
		exit(1);
	}

	/*
	 * Check if backup directory exists.
	 */
	if (stat(backupdir, &s) == -1) {
		fprintf(stderr,
		"Backup directory %s does not exist.\n",
		backupdir);
		exit(1);
	}

	if (aflg) {
		sprintf(buf, "%s/%s", backupdir, BACKUPLIST);
		if (dirobj_list(CACHE_INIT, buf) == NULL) {
			fprintf(stderr,
				"Unable to access backup list : %s\n", buf);
			exit(1);
		}
	/*
	 * Sanity check: make sure that we serve the directory object(s)
	 * listed in the backup_list file. Note: backup_list is created by
	 * nisbackup(1), so we know the objects are fully qualified.
	 */
		for (tmp = dirlisthead; tmp; tmp = tmp->next) {
			if (!is_server_of(tmp->name, NULL, &srv_ptr) &&
				!force) {
				fprintf(stderr, "Use -f option to override.\n");
				exit(1);
			}

		}
	}

	/*
	 * Check if the NIS+ server is running. Report an error if it is.
	 * If srv_ptr is not set, they must be using the -f(orce), so all
	 * bets are off. Punt
	 */
	if (srv_ptr) {
		tagctl.tag_val = "";
		tagctl.tag_type = 0;
#ifdef DEBUG
		fprintf(stderr, "Server name: %s\n", srv_ptr->name);
		gettimeofday(&ctime, 0);
		elapse = ctime.tv_sec;
#endif
		if (verbiage)
			fprintf(stderr,
				"Verifying rpc.nisd process is not running\n");
		error = nis_servstate(srv_ptr, &tagctl, 1, &res);
		if (error == NIS_SUCCESS) {
			fprintf(stderr,
		"rpc.nisd is active, kill server before running nisrestore\n");
			exit(1);
		}
#ifdef DEBUG
		gettimeofday(&ctime, 0);
		fprintf(stderr, "Server access: %d seconds\n",
			ctime.tv_sec - elapse);
#endif
		if (res != NULL)
			nis_freetags(res, 1);
	}
#ifdef DEBUG
	else
		fprintf(stderr, "No Server found.\n");
#endif
	/*
	 * Check if backup directory(ies) exist and are valid.
	 */
	for (tmp = dirlisthead; tmp; tmp = tmp->next) {

		sprintf(backup_path, "%s/%s/%s", backupdir, tmp->name, NIS_DIR);
	/*
	 * Check for the "data" subdirectory in the backup.
	 */
		if (stat(backup_path, &s) == -1) {
			fprintf(stderr,
			"%s not found.\n", backup_path);
			exit(1);
		}
	/*
	 * Check for the existence of a dictionary file in the backup-dir.
	 */
		sprintf(buf, "%s.dict", backup_path);
		if (stat(buf, &s) == -1) {
			fprintf(stderr,
			"Dictionary file %s not found.\n", buf);
			exit(1);
		}

	/*
	 * Check for the last update transaction file in the backup-dir.
	 */
		sprintf(trans_log, "%s/%s/%s", backupdir, tmp->name,
			LASTUPDATE);
		if (stat(trans_log, &s) == -1) {
			fprintf(stderr, "Transaction log %s not found in.\n",
			trans_log);
			exit(1);
		}
	/*
	 * Read in the last update file, and cache the time stamp.
	 */
		if ((fr = fopen(trans_log, "r")) == NULL) {
			fprintf(stderr, "Error accessing file %s: %d\n",
				trans_log, errno);
			exit(1);
		}
	/*
	 * Read in the backup revision number, and verify.
	 */
		fread((void *) u_nl, sizeof (unsigned long), 1, fr);
		unl_p = (uint32_t *) u_nl;
		if (ntohl(*unl_p) != BACKUPREV) {
			fprintf(stderr,
				"Invalid backup version #%X, should be #%X\n",
				ntohl(*unl_p), BACKUPREV);
			exit(1);
		}

		fread((void *) u_nl, sizeof (uint32_t), 1, fr);
		unl_p = (uint32_t *) u_nl;
		tmp->upd_time = ntohl(*unl_p);
#ifdef DEBUG
fprintf(stderr, "sanity_checks: update time: %d\n", tmp->upd_time);
#endif
		if (fclose(fr) == EOF) {
			fprintf(stderr, "Error closing file\n");
			exit(1);
		}
	}
	/*
	 * Check for the local "data" directory existing. If not, create it.
	 */
	sprintf(buf, "%s", nis_data(NULL));
	if (stat(buf, &s) == -1) {
		if (errno == ENOENT) {
			sprintf(buf, nis_data(NULL));
			if (mkdir(buf, 0700)) {
				fprintf(stderr,
				"Unable to create NIS+ directory %s\n", buf);
				exit(1);
			}
			olddata = FALSE;
		} else {
			fprintf(stderr,
			"Unable to stat NIS+ directory %s.\n", buf);
			exit(1);
		}
	}
	strcat(buf, ".dict");
	if (!db_initialize(buf)) {
		fprintf(stderr,
		"Unable to initialize data dictionary %s.", buf);
		exit(1);
	}
}

bool_t
merge_serving_list()
{
	char	buf[BUFSIZ];
	char	filename[BUFSIZ];
	FILE	*fr;
	char	*name, *end;
	int	ss;
	struct	stat st;

	strcpy(filename, nis_data("serving_list"));
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

/*
 * rm_logs()
 *
 * This routine checks for each database file restored, if a .log file
 * exists. The .log files are removed from the /var/nis/data directory,
 * as they will be invalid after the restore is performed. As an optimization,
 * a flag is set in sanity_checks that indicates if the /var/nis/data
 * directory has been created (new install) and therefore this routine is
 * unnecessary.
 */
bool_t
rm_logs(char *src)
{
	char		localdir[NIS_MAXNAMELEN];
	char		buf[NIS_MAXNAMELEN];
	char		full_name[NIS_MAXNAMELEN];
	char		*domainof;
	DIR		*dirptr;
	struct dirent	*dent;
	struct	stat st;

#ifdef DEBUG
	printf("rm_logs: entry point\n");
#endif
	sprintf(localdir, "%s", nis_data(NULL));
	if ((dirptr = opendir(src)) == NULL) {
		fprintf(stderr, "Unable to open %s.\n", src);
		return (FALSE);
	}

	while ((dent = readdir(dirptr)) != NULL) {
		if (strcmp(dent->d_name, ".") == 0)
			continue; /* Ignore */
		if (strcmp(dent->d_name, "..") == 0)
			continue; /* Ignore */
		if (strcmp(dent->d_name, ROOT_OBJ) == 0)
			continue; /* root.object doesn't have log file */

		sprintf(buf, "%s/%s.log", localdir, dent->d_name);
		sprintf(full_name, "%s.%s", dent->d_name,
			nis_local_directory());
#ifdef DEBUG
	printf("rm_logs: stat'ng: %s\n", buf);
#endif
		if (stat(buf, &st) == -1)
			if (errno == ENOENT)
				continue;
/*
 * Determine if this .log file belongs to a directory object that has been
 * restored.
 */
		if (!dirobj_list(CACHE_FIND, full_name)) {
			domainof = nis_domain_of(full_name);
			if (!dirobj_list(CACHE_FIND, domainof))
				continue;
		}
/*
 * It's a match, delete it!
 */
		if (unlink(buf)) {
			fprintf(stderr, "Unable to remove %s.\n", buf);
			return (FALSE);
		}
	} /* while (readdir) */
	closedir(dirptr);
	return (TRUE);
}


bool_t
print_backuplist(char *backupdir)

{
	struct stat		s;
	char			buf[NIS_MAXNAMELEN];
	struct nis_dir_list	*dl = NULL;

	if (*backupdir != '/') {
		fprintf(stderr,
			"Backup directory %s is not a absolute path name.\n",
			backupdir);
		return (FALSE);
	}

	/*
	 * Check if backup directory exists.
	 */
	if (stat(backupdir, &s) == -1) {
		fprintf(stderr, "Backup directory %s does not exist.\n",
		backupdir);
		return (FALSE);
	}

	sprintf(buf, "%s/%s", backupdir, BACKUPLIST);
	if (dirobj_list(CACHE_INIT, buf) == NULL) {
		fprintf(stderr, "Unable to access backup list : %s\n", buf);
		return (FALSE);
	}
	for (dl = dirlisthead; dl; dl = dl->next)
		fprintf(stdout, "%s\n", dl->name);
	return (TRUE);
}

int
main(int argc, char *argv[])
{
	char		*backupdir;
	char		nisdomain[NIS_MAXNAMELEN];
	char		newdict[NIS_MAXNAMELEN];
	char		buf[NIS_MAXNAMELEN];
	int		c;
	db_status	dbstat;
	char		*oldsuf = NULL;
	char		*newsuf = NULL;
	char		*tmp;
	struct nis_dir_list *dl = NULL;
	bool_t		rename_files;

	if (geteuid() != 0) {
		fprintf(stderr, "You must be root to run nisrestore.\n");
		exit(1);
	}
	if (argc < 3)
		usage();

	while ((c = getopt(argc, argv, "aftv")) != -1) {
		switch (c) {
		case 'a' :
			aflg = TRUE;
			break;
		case 'f' :
			force = TRUE;
			break;
		case 't' :
			tocflg = TRUE;
			break;
		case 'v' :
			verbiage = TRUE;
			break;
		default:
			usage();
		}
	}
	if (aflg || tocflg) {
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
			if (!is_server_of(tmp, nisdomain, &srv_ptr) &&
				!force) { /* Not server for object specd */
				fprintf(stderr, "Use -f option to override.\n");
				exit(1);
			} else {
				if (dirobj_list(CACHE_ADD,
					((strlen(nisdomain)) ? nisdomain:tmp))
					== NULL) {
					fprintf(stderr,
				"Internal error, unable to add to cache\n");
					exit(1);
				}
			}
		}
	}

	if (tocflg) {
		if (!print_backuplist(backupdir)) {
			fprintf(stderr,
			"Could not list objects in backup directory %s\n",
			backupdir);
			exit(1);
		}
		exit(0);
	}
	master_pid = getpid();
	sanity_checks(backupdir);
/*
 * Loop through dirobj_list, merge in dictionary entries. After looping
 * through, close out the data dictionary, merge_trans_log(), update
 * the serving_list and were done!
 */
	for (dl = dirlisthead; dl; dl = dl->next) {
		sprintf(newdict, "%s/%s/%s.dict", backupdir, dl->name, NIS_DIR);
	/*
	 * Now, copy the contents of the backup directory to our local
	 * directory. Overwrite any local files if they exist. First we
	 * check to see if the files need to be renamed. If the master
	 * lives in a different domain than the server being restored,
	 * the database files have different names.
	 */
		if (verbiage)
			fprintf(stderr, "Restoring %s\n", dl->name);
		sprintf(buf, "%s/%s/%s", backupdir, dl->name, NIS_DIR);
		rename_files = files_need_renaming(dl->name, buf, &oldsuf,
							&newsuf);
		if (!copydir(buf, rename_files)) {
			fprintf(stderr,
			"Unable to copy file from backup directory %s.\n", buf);
			db_abort_merge_dict();
			exit(1);
		}
		if ((rename_files) && (rename_data_files(oldsuf, newsuf)
								== FALSE)) {
			fprintf(stderr,
			"Unable to move data files into place.\n");
			db_abort_merge_dict();
			exit(1);
		}
		if (verbiage)
			fprintf(stderr,
			"Adding the %s objects into the data dictionary.\n",
			dl->name);
		if ((dbstat = db_begin_merge_dict(newdict, oldsuf, newsuf))
								!= DB_SUCCESS) {
			fprintf(stderr, "Unable to merge dictionary %s: %s.\n",
				newdict, db_perror(dbstat));
			db_abort_merge_dict();
			exit(1);
		}
		/*
		 * Since the backup doesn't have any .log files, any reminant
		 * .log's need to be removed. This is taken care of by
		 * rename_data_files() if rename_files is TRUE.
		 */
		if ((olddata) && (!rename_files) && (!rm_logs(buf))) {
			fprintf(stderr, "Error from rm_logs.\n");
			db_abort_merge_dict();
			exit(1);
		}
		free(oldsuf);
		free(newsuf);
	}
	/*
	 * Now closeout the data dictionary.
	 */
	if ((dbstat = db_end_merge_dict()) != DB_SUCCESS) {
		fprintf(stderr, "Error from db_end_merge_dict: %d\n",
			dbstat);
		db_abort_merge_dict();
		exit(1);
	}
	if (verbiage)
		fprintf(stderr, "Updating the trans.log file.\n");
	if (!merge_trans_log()) {
		fprintf(stderr,
		"Unable to merge backed up transaction log.\n");
		exit(1);
	}
	if (!merge_serving_list()) {
		fprintf(stderr, "Error from merge_serving_list.\n");
		db_abort_merge_dict();
		exit(1);
	}
	exit(0);
}
