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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/systeminfo.h>
#include <syslog.h>
#include <errno.h>
#include <libintl.h>
#include <grp.h>

#include <job.h>
#include <misc.h>
#include <list.h>


#define	MAX_RETRIES	(5)

static char *_control_file_prefix =	CONTROL_FILE_PREFIX;
static char *_xfer_file_prefix =	XFER_FILE_PREFIX;


/*
 *  _job_unlink_data_file() will unlink the path for the jobfile passed in.
 *	this is only to be used with job_destroy() so it can iterate through
 *	the job_df_list.
 */
static int
_job_unlink_data_file(jobfile_t *file)
{
	syslog(LOG_DEBUG, "_job_unlink_data_file(%s)",
		((file != NULL) ? file->jf_spl_path : "NULL"));
	if (file && file->jf_spl_path)
		return (unlink(file->jf_spl_path));
	else
		return (-1);
}

/*
 *
 */
static void
_job_file_free(jobfile_t *file)
{
	if (file == NULL)
		return;
	if (file->jf_spl_path != NULL) free(file->jf_spl_path);
	if (file->jf_src_path != NULL) free(file->jf_src_path);
	if (file->jf_name != NULL)	free(file->jf_name);
	if (file->jf_data != NULL) {
		if (file->jf_mmapped)
			(void) munmap(file->jf_data, file->jf_size);
		else
			free(file->jf_data);
	}
	free(file);
}


/*
 *
 */
static void
_vjob_file_free(jobfile_t *file)
{
	_job_file_free(file);
}


/*
 *  job_free() frees up memory mmapped for malloced
 *	being used by the structure.
 */
void
job_free(job_t *job)
{
	if (job == NULL)
		return;

	syslog(LOG_DEBUG, "job_free(%d, %s, %s)", job->job_id,
		(job->job_printer ? job->job_printer : "NULL"),
		(job->job_server ? job->job_server : "NULL"));

	if (job->job_printer) free(job->job_printer);
	if (job->job_server) free(job->job_server);
	if (job->job_user) free(job->job_user);
	if (job->job_host) free(job->job_host);
	if (job->job_cf)
		_job_file_free(job->job_cf);
	(void) list_iterate((void *)job->job_df_list, (VFUNC_T)_vjob_file_free);

	if (job->job_df_list)
		free(job->job_df_list);

	if (job->job_spool_dir)
		free(job->job_spool_dir);

	free(job);
}
void
job_destroy(job_t *job)
{
	char	*name = NULL;
	jobfile_t *cf;

	if (job == NULL)
		return;

	syslog(LOG_DEBUG, "job_destroy(%d, %s, %s)", job->job_id,
		job->job_printer, job->job_server);
	if (chdir(job->job_spool_dir) < 0)
		return;
	(void) list_iterate((void *)job->job_df_list,
			(VFUNC_T)_job_unlink_data_file);

	/* lose privilege temporarily */
	(void) seteuid(get_user_id(job->job_user));

	if ((cf = job->job_cf) != NULL) {
		for (name = cf->jf_data; name != NULL;
				name = strchr(name, '\n')) {
			if (name[0] == '\n')
				name++;
			if (name[0] == CF_UNLINK) {
				struct stat st;
				char	*path = strcdup(&name[1], '\n'),
					*p;

				if (stat(path, &st) < 0) {
					free(path);
					continue;
				}

				if (st.st_uid == getuid()) {
					(void) unlink(path);
					free(path);
					continue;
				}

				p = strdup(path);
				if ((p = strrchr(p, '/')) != NULL)
					*++p = NULL;

				if (access(p, W_OK) == 0)
					(void) unlink(path);
				free(path);
			}
		}
	}
	(void) seteuid(0); /* get back privilege */

	(void) unlink(cf->jf_src_path);
	(void) _job_unlink_data_file(cf);
	job_free(job);
}

static int
get_job_from_cfile(jobfile_t *file, char *cFile, char *xFile, job_t *tmp)
{
	jobfile_t *file1;
	int	n_cnt;
	char	*p, *cfp;

	/* map in the control data */
	if ((file->jf_size = map_in_file(cFile, &file->jf_data, 0)) <= 0) {
		syslog(LOG_INFO, "could not read control file (%s): %m, "
		    "canceling %d destined for %s:%s",
		    (file->jf_spl_path ? file->jf_spl_path:"NULL"),
		    tmp->job_id,
		    (tmp->job_server ? tmp->job_server : "NULL"),
		    (tmp->job_printer ? tmp->job_printer : "NULL"));
		return (0);
	}
	file->jf_mmapped = 1;
	tmp->job_cf = file;

	/* look for usr, host, & data files */

	/*
	 * Bugid 4137904 - "File Name" can be
	 * anywhere in control file.
	 * Bugid 4179341 - "File Name" can be missing
	 * in control file.
	 * Keep a separate pointer to the control file.
	 * When a CF_UNLINK entry is found use the second
	 * pointer to search for a corresponding 'N' entry.
	 * The behavior is to associate the first CF_UNLINK
	 * entry with the first 'N' entry and so on.
	 * Note: n_cnt is only used to determine if we
	 *	should test for 'N' at the beginning of
	 *	the file.
	 */
	cfp = file->jf_data;
	n_cnt = 0;
	for (p = file->jf_data - 1; p != NULL; p = strchr(p, '\n')) {
		switch (*(++p)) {
		case CF_USER:
			tmp->job_user = strcdup(++p, '\n');
			break;
		case CF_HOST:
			tmp->job_host = strcdup(++p, '\n');
			break;
		case CF_UNLINK:
			if ((file1 = calloc(1, sizeof (*file))) == NULL) {
				syslog(LOG_DEBUG, "cf_unlink: calloc() failed");
				munmap(file->jf_data, file->jf_size);
				file->jf_mmapped = 0;
				return (0);
			}
			file1->jf_src_path = strdup(xFile);
			file1->jf_spl_path = strcdup(++p, '\n');
			file1->jf_size = file_size(file1->jf_spl_path);

			if (cfp != NULL) {
				/*
				 * Beginning of file. Check for first
				 * character == 'N'
				 */
				if ((n_cnt == 0) && (*cfp == 'N')) {
					cfp++;
					n_cnt++;
				} else {
					cfp = strstr(cfp, "\nN");
					if (cfp != NULL) {
						cfp += 2;
						n_cnt++;
					}
				}
				if (cfp != NULL) {
					file1->jf_name = strcdup(cfp, '\n');
					/*
					 * Move cfp to end of line or
					 * set to NULL if end of file.
					 */
					cfp = strchr(cfp, '\n');
				}
			}
			tmp->job_df_list = (jobfile_t **)list_append((void **)
			    tmp->job_df_list, (void *)file1);
			break;
		}
	}
	if (tmp->job_df_list == NULL) {
		munmap(file->jf_data, file->jf_size);
		file->jf_mmapped = 0;
		return (0);
	}

	return (1);
}

/*
 *  job_retrieve() will retrieve the disk copy of a job associated with the
 *	transfer file name passed in.  It returns a pointer to a job structure
 *	or a NULL if the job was not on disk.
 */
job_t *
job_retrieve(char *xFile, char *spool)
{
	int	retry_cnt = 0;
	char	*s;
	jobfile_t *file;
	char 	cFile[BUFSIZ];
	char	buf[BUFSIZ];
	int	fd;
	flock_t flk;
	job_t	*tmp;

	syslog(LOG_DEBUG, "job_retrieve(%s)", xFile);
	if ((tmp = (job_t *)calloc(1, sizeof (*tmp))) == NULL) {
		return (NULL);
	}

	if ((file = calloc(1, sizeof (*file))) == NULL) {
		free(tmp);
		return (NULL);
	}

	flk.l_type = F_RDLCK;
	flk.l_whence = 1;
	flk.l_start = 0;
	flk.l_len = 0;

	(void) memset(buf, NULL, sizeof (buf));
	/* get job id, from binding file name */
	(void) strlcpy(buf, xFile + strlen(_xfer_file_prefix) + 1,
	    sizeof (buf));

	buf[3] = NULL;
	tmp->job_id = atoi(buf);

	/* Construct data file and control file names */
	(void) strlcpy(cFile, _control_file_prefix, sizeof (cFile));
	(void) strlcat(cFile, xFile + strlen(_xfer_file_prefix),
	    sizeof (cFile));

	/* remove data file and control file whenever xFile is removed */
	if ((fd = open(xFile, O_RDONLY)) < 0) {
		syslog(LOG_DEBUG, "job_retrieve(%s) open failed errno=%d",
		    xFile, errno);
		if (get_job_from_cfile(file, cFile, xFile, tmp))
			job_destroy(tmp);
		free(file);
		free(tmp);
		(void) unlink(xFile);
		(void) unlink(cFile);
		return (NULL);
	}

	/*
	 * If failed to get a lock on the file, just return NULL. It will
	 * be retried later.
	 */
	if ((fcntl(fd, F_SETLK, &flk)) < 0) {
		syslog(LOG_DEBUG, "job_retrieve(%s) lock failed errno=%d",
		    xFile, errno);
		close(fd);
		free(file);
		free(tmp);
		return (NULL);
	}

	/*
	 * Retry a few times if we failed to read or read returns 0, just
	 * to make sure we tried hard before giving up. In practice,
	 * there were cases of read() returning 0. To handle that
	 * scenario just try a few times.
	 */
	for (retry_cnt = 0; retry_cnt < MAX_RETRIES; retry_cnt++) {
		if ((read(fd, buf, sizeof (buf))) > 0) {
			close(fd);
			if ((s = strtok(buf, ":\n")) != NULL)
				tmp->job_server = strdup(s);
			if ((s = strtok(NULL, ":\n")) != NULL)
				tmp->job_printer = strdup(s);
			syslog(LOG_DEBUG, "job_retrieve(%s) success - %s:%s",
			    xFile, tmp->job_server, tmp->job_printer);
			break;
		}
	}
	/*
	 * If failed to read after MAX_RETRIES, return NULL and remove xFile,
	 * and cFile.
	 */
	if (retry_cnt == MAX_RETRIES) {
		syslog(LOG_DEBUG, "job_retrieve(%s) unsuccessful", xFile);
		if (get_job_from_cfile(file, cFile, xFile, tmp))
			job_destroy(tmp);
		free(file);
		free(tmp);
		(void) unlink(xFile);
		(void) unlink(cFile);
		return (NULL);
	}

	file->jf_src_path = strdup(xFile);
	file->jf_spl_path = strdup(cFile);

	if (!get_job_from_cfile(file, cFile, xFile, tmp)) {
		(void) unlink(file->jf_spl_path);  /* control file */
		(void) unlink(file->jf_src_path);  /* binding file */
		free(file->jf_src_path);
		free(file->jf_spl_path);
		free(file);
		free(tmp);
		return (NULL);
	}

	tmp->job_spool_dir = strdup(spool);
	return (tmp);
}


/*
 * job_compar() compare 2 jobs for creation time ordering
 */
static int
job_compar(job_t **j1, job_t **j2)
{
	int	server;
	int	printer;
	struct stat	s1,
			s2;
	jobfile_t	*f1 = (*j1)->job_cf,
			*f2 = (*j2)->job_cf;

	/*
	 * If there is a null value, assume the job submitted remotely.
	 * Jobs submitted remotely take precedence over those submitted
	 * from the server.
	 */
	if (((*j1)->job_server) == NULL || ((*j1)->job_printer) == NULL ||
				((*j1)->job_cf) == NULL)
		return (-1);

	else if ((*j2)->job_server == NULL || (*j2)->job_printer == NULL ||
				(*j2)->job_cf == NULL)
		return (1);

	server = strcmp((*j1)->job_server, (*j2)->job_server);
	printer = strcmp((*j1)->job_printer, (*j2)->job_printer);

	if (server != 0)
		return (server);
	if (printer != 0)
		return (printer);

	if ((stat(f1->jf_spl_path, &s1) == 0) &&
	    (stat(f2->jf_spl_path, &s2) == 0))
		return (s1.st_ctime - s2.st_ctime);

	return (0);
}


/*
 *  job_list_append() reads all of the jobs associated with the printer passed
 *	in and appends them to the list of jobs passed in.  The returned result
 *	is a new list of jobs containing all jobs passed in and jobs for the
 *	printer specified.  If the printer is NULL, all jobs for all printers
 *	are added to the list.
 */
job_t **
job_list_append(job_t **list, char *printer, char *server, char *spool)
{
	struct dirent *d;
	DIR	*dirp;
	job_t	*job;
	int	i, found = 0;

	syslog(LOG_DEBUG, "job_list_append(0x%x, %s, %s)", list,
		((printer != NULL) ? printer : "NULL"),
		    ((server != NULL) ? server : "NULL"));

	/*
	 * 4239765 - in.lpd segfaults performing strcmp()
	 * in job_list_append()
	 */
	if (server == NULL) {
		server = "";
	}

	if ((dirp = opendir(spool)) == NULL)
		return (NULL);

	/* should use scandir */
	while ((d = readdir(dirp)) != NULL) {
		if (strncmp(d->d_name, _xfer_file_prefix,
				strlen(_xfer_file_prefix)) != 0)
			continue;
		if ((job = job_retrieve(d->d_name, spool)) == NULL)
			continue;
		syslog(LOG_DEBUG, "job_printer is (%s:%s)",
			job->job_printer, job->job_server);

		found = 0;

		if ((printer == NULL) ||
		    ((strcmp(printer, job->job_printer) == 0) &&
			(strcmp(server, job->job_server) == 0))) {
			if (list) {
			    for (i = 0; list[i] != NULL; i++) {
				if ((list[i]->job_cf != NULL) &&
				    (job->job_cf != NULL) &&
				    (strcmp(list[i]->job_cf->jf_spl_path,
				    job->job_cf->jf_spl_path) == 0))
					found = 1;
			    }
			} /* if (list) */

			if (!found)
				list = (job_t **)list_append((void **)list,
				    (void *)job);
		}
	} /* while */

	/* count the length of the list for qsort() */
	if (list) {
		for (i = 0; list[i] != NULL; i++)
			;

		qsort(list, i, sizeof (job_t *),
		    (int(*)(const void *, const void *))job_compar);
	}
	(void) closedir(dirp);
	return (list);
}



/*
 *
 * Shared routines for Canceling jobs.
 *
 */


/*
 *  vjob_match_attribute() checks to see if the attribute passed in
 *	matches the the user or id of the job passed in via stdargs.  This is
 *	intended for use with list_iterate().
 */
int
vjob_match_attribute(char *attribute, va_list ap)
{
	job_t *job = va_arg(ap, job_t *);

	if ((strcmp(attribute, job->job_user) == 0) ||
	    (job->job_id == atoi(attribute)))
		return (1);
	else
		return (0);
}


/*
 *  vjob_job() determines if the job passed in is for the printer and server
 *	of the cancel request, and if it is from the user requesting or the
 *	user is root, it checsk the attributes.  If the job matches all of this
 *	it cancels the job and prints a message.  It is intented to be called
 *	by list_iterate().
 */
int
vjob_cancel(job_t *job, va_list ap)
{
	int killed_process = 0;
	int lock;
	char	*user = va_arg(ap, char *),
		*printer = va_arg(ap, char *),
		*server = va_arg(ap, char *),
		**list = va_arg(ap, char **);

	syslog(LOG_DEBUG, "vjob_cancel((%s, %s, %d), %s, %s, %s)",
		job->job_printer, job->job_server, job->job_id, user, printer,
		server);
	if (((strcmp(user, "root") == 0) ||
	    (strcmp(user, job->job_user) == 0)) &&
	    ((strcmp(printer, job->job_printer) == 0) &&
	    (strcmp(server, job->job_server) == 0))) {
		if (list_iterate((void **)list,
		    (VFUNC_T)vjob_match_attribute, job) != 0) {
			while ((lock = get_lock(job->job_cf->jf_src_path,
						0)) < 0) {
				(void) kill_process(job->job_cf->jf_src_path);
				killed_process = 1;
			}
			job_destroy(job);
			syslog(LOG_DEBUG, "\t%s-%d: canceled\n", printer,
				job->job_id);
			(void) printf(
			    (char *)gettext("\t%s-%d: canceled\n"), printer,
			    (int)job->job_id);
			close(lock);
		}
	}
	return (killed_process);
}
