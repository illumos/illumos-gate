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
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <libintl.h>
#include <wait.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/buf.h>
#include <sys/stat.h>
#include <grp.h>
#include "addrem.h"
#include "errmsg.h"
#include "plcysubr.h"

static char *add_rem_lock;	/* lock file */
static char *tmphold;		/* temperary file for updating */
static int  add_rem_lock_fd = -1;

static int get_cached_n_to_m_file(char *filename, char ***cache);
static int get_name_to_major_entry(int *major_no, char *driver_name,
    char *file_name);

static int is_blank(char *);

/*ARGSUSED*/
void
log_minorperm_error(minorperm_err_t err, int key)
{
	switch (err) {
	case MP_FOPEN_ERR:
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE),
		    MINOR_PERM_FILE);
		break;
	case MP_FCLOSE_ERR:
		(void) fprintf(stderr, gettext(ERR_NO_UPDATE),
		    MINOR_PERM_FILE);
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		break;
	case MP_IGNORING_LINE_ERR:
		(void) fprintf(stderr, gettext(ERR_NO_UPDATE),
		    MINOR_PERM_FILE);
		break;
	case MP_ALLOC_ERR:
		(void) fprintf(stderr, gettext(ERR_NO_UPDATE),
		    MINOR_PERM_FILE);
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		break;
	case MP_NVLIST_ERR:
		(void) fprintf(stderr, gettext(ERR_NO_UPDATE),
		    MINOR_PERM_FILE);
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		break;
	case MP_CANT_FIND_USER_ERR:
		(void) fprintf(stderr, gettext(ERR_NO_UPDATE),
		    MINOR_PERM_FILE);
		break;
	case MP_CANT_FIND_GROUP_ERR:
		(void) fprintf(stderr, gettext(ERR_NO_UPDATE),
		    MINOR_PERM_FILE);
		break;
	}
}

/*
 *  open file
 * for each entry in list
 *	where list entries are separated by <list_separator>
 * 	append entry : driver_name <entry_separator> entry
 * close file
 * return error/noerr
 */
int
append_to_file(
	char *driver_name,
	char *entry_list,
	char *filename,
	char list_separator,
	char *entry_separator,
	int quoted)
{
	int	i, len;
	int	fpint;
	char	*current_head, *previous_head;
	char	*line, *one_entry;
	FILE	*fp;

	if ((fp = fopen(filename, "a")) == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE),
		    filename);
		return (ERROR);
	}

	len = strlen(entry_list);

	one_entry = calloc(len + 1, 1);
	if (one_entry == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_UPDATE), filename);
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		(void) fclose(fp);
		return (ERROR);
	}

	previous_head = entry_list;

	line = calloc(strlen(driver_name) + len + 4, 1);
	if (line == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		(void) fclose(fp);
		err_exit();
	}

	/*
	 * get one entry at a time from list and append to <filename> file
	 */

	do {

		for (i = 0; i <= len; i++)
			one_entry[i] = 0;

		for (i = 0; i <= (int)strlen(line); i++)
			line[i] = 0;

		current_head = get_entry(previous_head, one_entry,
		    list_separator, quoted);
		previous_head = current_head;

		(void) strcpy(line, driver_name);
		(void) strcat(line, entry_separator);
		if (quoted)
			(void) strcat(line, "\"");
		(void) strcat(line, one_entry);
		if (quoted)
			(void) strcat(line, "\"");
		(void) strcat(line, "\n");

		if ((fputs(line, fp)) == EOF) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_NO_UPDATE),
			    filename);
		}

	} while (*current_head != '\0');


	(void) fflush(fp);

	fpint = fileno(fp);
	(void) fsync(fpint);

	(void) fclose(fp);

	free(one_entry);
	free(line);

	return (NOERR);
}

/*
 * Require exact match to delete a driver alias/permission entry.
 * Note line argument does not remain unchanged.  Return 1 if matched.
 */
static int
match_entry(char *line, char *match)
{
	char	*token, *p;
	int	n;

	/* skip any leading white space */
	while (*line && ((*line == ' ') || (*line == '\t')))
		line++;
	/*
	 * Find separator for driver name, either space or colon
	 *	minor_perm: <driver>:<perm>
	 *	driver_aliases: <driver> <alias>
	 *	extra_privs: <driver>:<priv>
	 */
	if ((token = strpbrk(line, " :\t")) == NULL)
		return (0);
	token++;
	/* skip leading white space and quotes */
	while (*token && (*token == ' ' || *token == '\t' ||
	    *token == '"' || *token == '\''))
		token++;
	/* strip trailing newline, white space and quotes */
	n = strlen(token);
	p = token + n-1;
	while (n > 0 && (*p == '\n' || *p == ' ' || *p == '\t' ||
	    *p == '"' || *p == '\'')) {
		*p-- = 0;
		n--;
	}
	if (n == 0)
		return (0);
	return (strcmp(token, match) == 0);
}

/*
 *  open file
 * read thru file, deleting all entries if first
 *    entry = driver_name
 * close
 * if error, leave original file intact with message
 * assumption : drvconfig has been modified to work with clone
 *  entries in /etc/minor_perm as driver:mummble NOT
 *  clone:driver mummble
 * this implementation will NOT find clone entries
 * clone:driver mummble
 * match:
 *	delete just the matching entry
 *
 */
int
delete_entry(
	char *oldfile,
	char *driver_name,
	char *marker,
	char *match)
{
	int		rv, i;
	int		status = NOERR;
	int		drvr_found = 0;
	boolean_t 	nomatch = B_TRUE;
	char		*newfile, *tptr, *cp;
	char		line[MAX_DBFILE_ENTRY], drv[FILENAME_MAX + 1];
	FILE		*fp, *newfp;
	struct group	*sysgrp;
	char		*copy;		/* same size as line */

	/*
	 * check if match is specified and if it equals " "
	 */
	if (match && (*match == ' ' && strlen(match) == 1)) {
		(void) fprintf(stderr, gettext(ERR_INT_UPDATE), oldfile);
		return (ERROR);
	}

	if ((fp = fopen(oldfile, "r")) == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE), oldfile);
		return (ERROR);
	}

	/* Space for defensive copy of input line */
	copy = calloc(sizeof (line), 1);

	/* Build filename for temporary file */
	tptr = calloc(strlen(oldfile) + strlen(XEND) + 1, 1);
	if (tptr == NULL || copy == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		return (ERROR);
	}

	(void) strcpy(tptr, oldfile);
	(void) strcat(tptr, XEND);

	/*
	 * Set gid so we preserve group attribute.  Ideally we wouldn't
	 * assume a gid of "sys" but we can't undo the damage on already
	 * installed systems unless we force the issue.
	 */
	if ((sysgrp = getgrnam("sys")) != NULL) {
		(void) setgid(sysgrp->gr_gid);
	}

	newfile = mktemp(tptr);

	if ((newfp = fopen(newfile, "w")) == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE),
		    newfile);
		return (ERROR);
	}

	while ((fgets(line, sizeof (line), fp) != NULL) && status == NOERR) {
		/* copy the whole line */
		if (strlcpy(copy, line, sizeof (line)) >= sizeof (line)) {
			(void) fprintf(stderr, gettext(ERR_UPDATE), oldfile);
			status = ERROR;
			break;
		}
		/* cut off comments starting with '#' */
		if ((cp = strchr(copy, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(copy)) {
			if (fputs(line, newfp) == EOF) {
				(void) fprintf(stderr, gettext(ERR_UPDATE),
				    oldfile);
				status = ERROR;
			}
			continue;
		}

		/* get the driver name */
		if (sscanf(copy, "%s", drv) != 1) {
			(void) fprintf(stderr, gettext(ERR_BAD_LINE),
			    oldfile, line);
			status = ERROR;
			break;
		}

		for (i = strcspn(drv, marker); i < FILENAME_MAX; i++) {
			drv[i] =  '\0';
		}

		if (strcmp(driver_name, drv) != 0) {
			if ((fputs(line, newfp)) == EOF) {
				(void) fprintf(stderr, gettext(ERR_UPDATE),
				    oldfile);
				status = ERROR;
			}
		} else {
			drvr_found++;
			if (match) {	/* Just delete one entry */
				/* for now delete just minor_perm and aliases */
				if ((strcmp(oldfile, minor_perm) == 0) ||
				    (strcmp(oldfile, extra_privs) == 0) ||
				    (strcmp(oldfile, driver_aliases) == 0)) {

					/* make defensive copy */
					if (strlcpy(copy, line, sizeof (line))
					    >= sizeof (line)) {
						(void) fprintf(stderr,
						    gettext(ERR_UPDATE),
						    oldfile);
						status = ERROR;
						break;
					}
					if (match_entry(copy, match)) {
						nomatch = B_FALSE;
					} else {
						if ((fputs(line, newfp)) ==
						    EOF) {
							(void) fprintf(stderr,
							    gettext(ERR_UPDATE),
							    oldfile);
							status = ERROR;
						}
						if (nomatch != B_FALSE)
							nomatch = B_TRUE;
					}
				}
			}

		} /* end of else */
	} /* end of while */

	(void) fclose(fp);
	free(tptr);
	free(copy);

	/* Make sure that the file is on disk */
	if (fflush(newfp) != 0 || fsync(fileno(newfp)) != 0)
		status = ERROR;
	else
		rv = NOERR;

	(void) fclose(newfp);

	/* no matching driver found */
	rv = NOERR;
	if (!drvr_found ||
	    (nomatch == B_TRUE)) {
		rv = NONE_FOUND;
	}

	/*
	 * if error, leave original file, delete new file
	 * if noerr, replace original file with new file
	 */

	if (status == NOERR) {
		if (rename(oldfile, tmphold) == -1) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_UPDATE), oldfile);
			(void) unlink(newfile);
			return (ERROR);
		} else if (rename(newfile, oldfile) == -1) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_UPDATE), oldfile);
			(void) unlink(oldfile);
			(void) unlink(newfile);
			if (link(tmphold, oldfile) == -1) {
				perror(NULL);
				(void) fprintf(stderr, gettext(ERR_BAD_LINK),
				    oldfile, tmphold);
			}
			return (ERROR);
		}
		(void) unlink(tmphold);
	} else {
		/*
		 * since there's an error, leave file alone; remove
		 * new file
		 */
		if (unlink(newfile) == -1) {
			(void) fprintf(stderr, gettext(ERR_CANT_RM), newfile);
		}
		return (ERROR);
	}

	return (rv);
}


/*
 * wrapper for call to get_name_to_major_entry(): given driver name,
 * retrieve major number.
 */
int
get_major_no(char *driver_name, char *file_name)
{
	int major = UNIQUE;

	if (get_name_to_major_entry(&major, driver_name, file_name) == ERROR)
		return (ERROR);
	else
		return (major);
}

/*
 * wrapper for call to get_name_to_major_entry(): given major number,
 * retrieve driver name.
 */
int
get_driver_name(int major, char *file_name, char *buf)
{
	if (major < 0)
		return (ERROR);
	return (get_name_to_major_entry(&major, buf, file_name));
}


/*
 * return pointer to cached name_to_major file - reads file into
 * cache if this has not already been done.  Since there may be
 * requests for multiple name_to_major files (rem_name_to_major,
 * name_to_major), this routine keeps a list of cached files.
 */
static int
get_cached_n_to_m_file(char *filename, char ***cache)
{
	struct n_to_m_cache {
		char *file;
		char **cached_file;
		int size;
		struct n_to_m_cache *next;
	};
	static struct n_to_m_cache *head = NULL;
	struct n_to_m_cache *ptr;
	FILE *fp;
	char drv[FILENAME_MAX + 1];
	char entry[FILENAME_MAX + 1];
	char line[MAX_N2M_ALIAS_LINE], *cp;
	int maj;
	int size = 0;


	/*
	 * see if the file is already cached - either
	 * rem_name_to_major or name_to_major
	 */
	ptr = head;
	while (ptr != NULL) {
		if (strcmp(ptr->file, filename) == 0)
			break;
		ptr = ptr->next;
	}

	if (ptr == NULL) {	/* we need to cache the contents */
		if ((fp = fopen(filename, "r")) == NULL) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_CANT_OPEN),
			    filename);
			return (ERROR);
		}

		while (fgets(line, sizeof (line), fp) != NULL) {
			/* cut off comments starting with '#' */
			if ((cp = strchr(line, '#')) != NULL)
				*cp = '\0';
			/* ignore comment or blank lines */
			if (is_blank(line))
				continue;
			/* sanity-check */
			if (sscanf(line, "%s%s", drv, entry) != 2) {
				(void) fprintf(stderr, gettext(ERR_BAD_LINE),
				    filename, line);
				continue;
			}
			maj = atoi(entry);
			if (maj > size)
				size = maj;
		}

		/* allocate struct to cache the file */
		ptr = (struct n_to_m_cache *)calloc(1,
		    sizeof (struct n_to_m_cache));
		if (ptr == NULL) {
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			return (ERROR);
		}
		ptr->size = size + 1;
		/* allocate space to cache contents of file */
		ptr->cached_file = (char **)calloc(ptr->size, sizeof (char *));
		if (ptr->cached_file == NULL) {
			free(ptr);
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			return (ERROR);
		}

		rewind(fp);

		/*
		 * now fill the cache
		 * the cache is an array of char pointers indexed by major
		 * number
		 */
		while (fgets(line, sizeof (line), fp) != NULL) {
			/* cut off comments starting with '#' */
			if ((cp = strchr(line, '#')) != NULL)
				*cp = '\0';
			/* ignore comment or blank lines */
			if (is_blank(line))
				continue;
			/* sanity-check */
			if (sscanf(line, "%s%s", drv, entry) != 2) {
				(void) fprintf(stderr, gettext(ERR_BAD_LINE),
				    filename, line);
				continue;
			}
			maj = atoi(entry);
			if ((ptr->cached_file[maj] = strdup(drv)) == NULL) {
				(void) fprintf(stderr, gettext(ERR_NO_MEM));
				free(ptr->cached_file);
				free(ptr);
				return (ERROR);
			}
			(void) strcpy(ptr->cached_file[maj], drv);
		}
		(void) fclose(fp);
		/* link the cache struct into the list of cached files */
		ptr->file = strdup(filename);
		if (ptr->file == NULL) {
			for (maj = 0; maj <= ptr->size; maj++)
				free(ptr->cached_file[maj]);
			free(ptr->cached_file);
			free(ptr);
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			return (ERROR);
		}
		ptr->next = head;
		head = ptr;
	}
	/* return value pointer to contents of file */
	*cache = ptr->cached_file;

	/* return size */
	return (ptr->size);
}


/*
 * Using get_cached_n_to_m_file(), retrieve maximum major number
 * found in the specificed file (name_to_major/rem_name_to_major).
 *
 * The return value is actually the size of the internal cache including 0.
 */
int
get_max_major(char *file_name)
{
	char **n_to_m_cache = NULL;

	return (get_cached_n_to_m_file(file_name, &n_to_m_cache));
}


/*
 * searching name_to_major: if major_no == UNIQUE then the caller wants to
 * use the driver name as the key.  Otherwise, the caller wants to use
 * the major number as a key.
 *
 * This routine caches the contents of the name_to_major file on
 * first call.  And it could be generalized to deal with other
 * config files if necessary.
 */
static int
get_name_to_major_entry(int *major_no, char *driver_name, char *file_name)
{
	int maj;
	char **n_to_m_cache = NULL;
	int size = 0;

	int ret = NOT_UNIQUE;

	/*
	 * read the file in - we cache it in case caller wants to
	 * do multiple lookups
	 */
	size = get_cached_n_to_m_file(file_name, &n_to_m_cache);

	if (size == ERROR)
		return (ERROR);

	/* search with driver name as key */
	if (*major_no == UNIQUE) {
		for (maj = 0; maj < size; maj++) {
			if ((n_to_m_cache[maj] != NULL) &&
			    (strcmp(driver_name, n_to_m_cache[maj]) == 0)) {
				*major_no = maj;
				break;
			}
		}
		if (maj >= size)
			ret = UNIQUE;
	/* search with major number as key */
	} else {
		/*
		 * Bugid 1254588, drvconfig dump core after loading driver
		 * with major number bigger than entries defined in
		 * /etc/name_to_major.
		 */
		if (*major_no >= size)
			return (UNIQUE);

		if (n_to_m_cache[*major_no] != NULL) {
			(void) strcpy(driver_name, n_to_m_cache[*major_no]);
		} else
			ret = UNIQUE;
	}
	return (ret);
}

/*
 * Given pointer to begining of member 'n' in a space (or separator)
 * separated list, return pointer to member 'n+1', and establish member 'n'
 * in *current_entry.  If unquote, then we skip a leading quote and treat
 * the trailing quote as a separator (and skip).
 */
char *
get_entry(
	char *prev_member,
	char *current_entry,
	char separator,
	int  unquote)
{
	char	*ptr;
	int	quoted = 0;

	ptr = prev_member;

	/* skip white space */
	while (*ptr == '\t' || *ptr == ' ')
		ptr++;

	/* if unquote skip leading quote */
	if (unquote && *ptr == '"') {
		quoted++;
		ptr++;
	}

	/* read thru the current entry looking for end, separator, or unquote */
	while (*ptr &&
	    (*ptr != separator) &&
	    ((separator != ' ') || (*ptr != '\t')) &&
	    (!quoted || (*ptr != '"'))) {
		*current_entry++ = *ptr++;
	}
	*current_entry = '\0';

	if (separator && (*ptr == separator))
		ptr++;	/* skip over separator */
	if (quoted && (*ptr == '"'))
		ptr++;	/* skip over trailing quote */

	/* skip white space */
	while (*ptr == '\t' || *ptr == ' ') {
		ptr++;
	}

	return (ptr);
}

void
enter_lock(void)
{
	struct flock lock;

	/*
	 * attempt to create the lock file
	 */
	add_rem_lock_fd = open(add_rem_lock, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
	if (add_rem_lock_fd < 0) {
		(void) fprintf(stderr, gettext(ERR_CREAT_LOCK),
		    add_rem_lock, strerror(errno));
		exit(1);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	/* Try for the lock but don't wait. */
	if (fcntl(add_rem_lock_fd, F_SETLK, &lock) == -1) {
		if (errno == EACCES || errno == EAGAIN) {
			(void) fprintf(stderr, gettext(ERR_PROG_IN_USE));
		} else {
			(void) fprintf(stderr, gettext(ERR_LOCK),
			    add_rem_lock, strerror(errno));
		}
		exit(1);
	}
}

void
err_exit(void)
{
	/* release memory allocated for moddir */
	cleanup_moddir();
	/* remove add_drv/rem_drv lock */
	exit_unlock();
	exit(1);
}

void
cleanup_moddir(void)
{
	struct drvmod_dir *walk_ptr;
	struct drvmod_dir *free_ptr = moddir;

	while (free_ptr != NULL) {
		walk_ptr = free_ptr->next;
		free(free_ptr);
		free_ptr = walk_ptr;
	}
}

void
exit_unlock(void)
{
	struct flock unlock;

	if (add_rem_lock_fd < 0)
		return;

	unlock.l_type = F_UNLCK;
	unlock.l_whence = SEEK_SET;
	unlock.l_start = 0;
	unlock.l_len = 0;

	if (fcntl(add_rem_lock_fd, F_SETLK, &unlock) == -1) {
		(void) fprintf(stderr, gettext(ERR_UNLOCK),
		    add_rem_lock, strerror(errno));
	} else {
		(void) close(add_rem_lock_fd);
		add_rem_lock_fd = -1;
	}
}

/*
 * error adding driver; need to back out any changes to files.
 * check flag to see which files need entries removed
 * entry removal based on driver name
 */
void
remove_entry(
	int c_flag,
	char *driver_name)
{

	if (c_flag & CLEAN_NAM_MAJ) {
		if (delete_entry(name_to_major, driver_name, " ",
		    NULL) == ERROR) {
			(void) fprintf(stderr, gettext(ERR_NO_CLEAN),
			    name_to_major, driver_name);
		}
	}

	if (c_flag & CLEAN_DRV_ALIAS) {
		if (delete_entry(driver_aliases, driver_name, " ",
		    NULL) == ERROR) {
			(void) fprintf(stderr, gettext(ERR_DEL_ENTRY),
			    driver_name, driver_aliases);
		}
	}

	if (c_flag & CLEAN_DRV_CLASSES) {
		if (delete_entry(driver_classes, driver_name, "\t", NULL) ==
		    ERROR) {
			(void) fprintf(stderr, gettext(ERR_DEL_ENTRY),
			    driver_name, driver_classes);
		}
	}

	if (c_flag & CLEAN_MINOR_PERM) {
		if (delete_entry(minor_perm, driver_name, ":", NULL) == ERROR) {
			(void) fprintf(stderr, gettext(ERR_DEL_ENTRY),
			    driver_name, minor_perm);
		}
	}
	/*
	 * There's no point in removing entries from files that don't
	 * exist.  Prevent error messages by checking for file existence
	 * first.
	 */
	if ((c_flag & CLEAN_DEV_POLICY) != 0 &&
	    access(device_policy, F_OK) == 0) {
		if (delete_plcy_entry(device_policy, driver_name) == ERROR) {
			(void) fprintf(stderr, gettext(ERR_DEL_ENTRY),
			    driver_name, device_policy);
		}
	}
	if ((c_flag & CLEAN_DRV_PRIV) != 0 &&
	    access(extra_privs, F_OK) == 0) {
		if (delete_entry(extra_privs, driver_name, ":", NULL) ==
		    ERROR) {
			(void) fprintf(stderr, gettext(ERR_DEL_ENTRY),
			    driver_name, extra_privs);
		}
	}
}

int
check_perms_aliases(
	int m_flag,
	int i_flag)
{
	/*
	 * If neither i_flag nor m_flag are specified no need to check the
	 * files for access permissions
	 */
	if (!m_flag && !i_flag)
		return (NOERR);

	/* check minor_perm file : exits and is writable */
	if (m_flag) {
		if (access(minor_perm, R_OK | W_OK)) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE),
			    minor_perm);
			return (ERROR);
		}
	}

	/* check driver_aliases file : exits and is writable */
	if (i_flag) {
		if (access(driver_aliases, R_OK | W_OK)) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE),
			    driver_aliases);
			return (ERROR);
		}
	}

	return (NOERR);
}


int
check_name_to_major(int mode)
{
	/* check name_to_major file : exists and is writable */
	if (access(name_to_major, mode)) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE),
		    name_to_major);
		return (ERROR);
	}

	return (NOERR);
}


/*
 * All this stuff is to support a server installing
 * drivers on diskless clients.  When on the server
 * need to prepend the basedir
 */
int
build_filenames(char *basedir)
{
	int len;

	if (basedir == NULL) {
		driver_aliases = DRIVER_ALIAS;
		driver_classes = DRIVER_CLASSES;
		minor_perm = MINOR_PERM;
		name_to_major = NAM_TO_MAJ;
		rem_name_to_major = REM_NAM_TO_MAJ;
		add_rem_lock = ADD_REM_LOCK;
		tmphold = TMPHOLD;
		devfs_root = DEVFS_ROOT;
		device_policy = DEV_POLICY;
		extra_privs = EXTRA_PRIVS;

	} else {
		len = strlen(basedir);

		driver_aliases = malloc(len + sizeof (DRIVER_ALIAS));
		driver_classes = malloc(len + sizeof (DRIVER_CLASSES));
		minor_perm = malloc(len + sizeof (MINOR_PERM));
		name_to_major = malloc(len + sizeof (NAM_TO_MAJ));
		rem_name_to_major = malloc(len + sizeof (REM_NAM_TO_MAJ));
		add_rem_lock = malloc(len + sizeof (ADD_REM_LOCK));
		tmphold = malloc(len + sizeof (TMPHOLD));
		devfs_root = malloc(len + sizeof (DEVFS_ROOT));
		device_policy = malloc(len + sizeof (DEV_POLICY));
		extra_privs = malloc(len + sizeof (EXTRA_PRIVS));


		if ((driver_aliases == NULL) ||
		    (driver_classes == NULL) ||
		    (minor_perm == NULL) ||
		    (name_to_major == NULL) ||
		    (rem_name_to_major == NULL) ||
		    (add_rem_lock == NULL) ||
		    (tmphold == NULL) ||
		    (devfs_root == NULL) ||
		    (device_policy == NULL) ||
		    (extra_privs == NULL)) {
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			return (ERROR);
		}

		(void) sprintf(driver_aliases, "%s%s", basedir, DRIVER_ALIAS);
		(void) sprintf(driver_classes, "%s%s", basedir, DRIVER_CLASSES);
		(void) sprintf(minor_perm, "%s%s", basedir, MINOR_PERM);
		(void) sprintf(name_to_major, "%s%s", basedir, NAM_TO_MAJ);
		(void) sprintf(rem_name_to_major, "%s%s", basedir,
		    REM_NAM_TO_MAJ);
		(void) sprintf(add_rem_lock, "%s%s", basedir, ADD_REM_LOCK);
		(void) sprintf(tmphold, "%s%s", basedir, TMPHOLD);
		(void) sprintf(devfs_root, "%s%s", basedir, DEVFS_ROOT);
		(void) sprintf(device_policy, "%s%s", basedir, DEV_POLICY);
		(void) sprintf(extra_privs, "%s%s", basedir, EXTRA_PRIVS);
	}

	return (NOERR);
}

static int
exec_command(char *path, char *cmdline[MAX_CMD_LINE])
{
	pid_t pid;
	uint_t stat_loc;
	int waitstat;
	int exit_status;

	/* child */
	if ((pid = fork()) == 0) {
		(void) execv(path, cmdline);
		perror(NULL);
		return (ERROR);
	} else if (pid == -1) {
		/* fork failed */
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_FORK_FAIL), cmdline);
		return (ERROR);
	} else {
		/* parent */
		do {
			waitstat = waitpid(pid, (int *)&stat_loc, 0);

		} while ((!WIFEXITED(stat_loc) &&
		    !WIFSIGNALED(stat_loc)) || (waitstat == 0));

		exit_status = WEXITSTATUS(stat_loc);

		return (exit_status);
	}
}

/*
 * check that major_num doesn't exceed maximum on this machine
 * do this here to support add_drv on server for diskless clients
 */
int
config_driver(
	char *driver_name,
	major_t major_num,
	char *aliases,
	char *classes,
	int cleanup_flag,
	int verbose_flag)
{
	int max_dev;
	int n = 0;
	char *cmdline[MAX_CMD_LINE];
	char maj_num[128];
	char *previous;
	char *current;
	int exec_status;
	int len;

	if (modctl(MODRESERVED, NULL, &max_dev) < 0) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_MAX_MAJOR));
		return (ERROR);
	}

	if (major_num >= max_dev) {
		(void) fprintf(stderr, gettext(ERR_MAX_EXCEEDS),
		    major_num, max_dev);
		return (ERROR);
	}

	/* bind major number and driver name */

	/* build command line */
	cmdline[n++] = DRVCONFIG;
	if (verbose_flag) {
		cmdline[n++] = "-v";
	}
	cmdline[n++] = "-b";
	if (classes) {
		cmdline[n++] = "-c";
		cmdline[n++] = classes;
	}
	cmdline[n++] = "-i";
	cmdline[n++] = driver_name;
	cmdline[n++] = "-m";
	(void) sprintf(maj_num, "%lu", major_num);
	cmdline[n++] = maj_num;

	if (aliases != NULL) {
		len = strlen(aliases);
		previous = aliases;
		do {
			cmdline[n++] = "-a";
			cmdline[n] = calloc(len + 1, 1);
			if (cmdline[n] == NULL) {
				(void) fprintf(stderr,
				    gettext(ERR_NO_MEM));
				return (ERROR);
			}
			current = get_entry(previous,
			    cmdline[n++], ' ', 0);
			previous = current;

		} while (*current != '\0');

	}
	cmdline[n] = (char *)0;

	exec_status = exec_command(DRVCONFIG_PATH, cmdline);

	if (exec_status == NOERR)
		return (NOERR);
	perror(NULL);
	remove_entry(cleanup_flag, driver_name);
	return (ERROR);
}

void
load_driver(char *driver_name, int verbose_flag)
{
	int n = 0;
	char *cmdline[MAX_CMD_LINE];
	int exec_status;

	/* build command line */
	cmdline[n++] = DEVFSADM;
	if (verbose_flag) {
		cmdline[n++] = "-v";
	}
	cmdline[n++] = "-i";
	cmdline[n++] = driver_name;
	cmdline[n] = (char *)0;

	exec_status = exec_command(DEVFSADM_PATH, cmdline);

	if (exec_status != NOERR) {
		/* no clean : name and major number are bound */
		(void) fprintf(stderr, gettext(ERR_CONFIG), driver_name);
	}
}

void
get_modid(char *driver_name, int *mod)
{
	struct modinfo	modinfo;

	modinfo.mi_id = -1;
	modinfo.mi_info = MI_INFO_ALL;
	do {
		/*
		 * If we are at the end of the list of loaded modules
		 * then set *mod = -1 and return
		 */
		if (modctl(MODINFO, 0, &modinfo) < 0) {
			*mod = -1;
			return;
		}

		*mod = modinfo.mi_id;
	} while (strcmp(driver_name, modinfo.mi_name) != 0);
}

int
create_reconfig(char *basedir)
{
	char reconfig_file[MAXPATHLEN + FILENAME_MAX + 1];
	FILE *reconfig_fp;

	if (basedir != NULL) {
		(void) strcpy(reconfig_file, basedir);
		(void) strcat(reconfig_file, RECONFIGURE);
	} else {
		(void) strcpy(reconfig_file, RECONFIGURE);
	}
	if ((reconfig_fp = fopen(reconfig_file, "a")) == NULL)
		return (ERROR);

	(void) fclose(reconfig_fp);
	return (NOERR);
}


/*
 * update_minor_entry:
 *	open file
 *	for each entry in list
 *		where list entries are separated by <list_separator>
 * 		modify entry : driver_name <entry_separator> entry
 *	close file
 *
 *	return error/noerr
 */
int
update_minor_entry(char *driver_name, char *perm_list)
{
	FILE *fp;
	FILE *newfp;
	struct group *sysgrp;
	int match = 0;
	char line[MAX_DBFILE_ENTRY], *cp, *dup;
	char drv[FILENAME_MAX + 1], *drv_minor;
	char minor[FILENAME_MAX + 1], perm[OPT_LEN + 1];
	char own[OPT_LEN + 1], grp[OPT_LEN + 1];
	int status = NOERR, i;
	char *newfile, *tptr;

	if ((fp = fopen(minor_perm, "r")) == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE),
		    minor_perm);

		return (ERROR);
	}

	/*
	 * Build filename for temporary file
	 */
	if ((tptr = calloc(strlen(minor_perm) + strlen(XEND) + 1, 1)) == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
	}
	(void) strcpy(tptr, minor_perm);
	(void) strcat(tptr, XEND);

	/*
	 * Set gid so we preserve group attribute.  Ideally we wouldn't
	 * assume a gid of "sys" but we can't undo the damage on already
	 * installed systems unless we force the issue.
	 */
	if ((sysgrp = getgrnam("sys")) != NULL) {
		(void) setgid(sysgrp->gr_gid);
	}

	newfile = mktemp(tptr);
	if ((newfp = fopen(newfile, "w")) == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE),
		    newfile);
		return (ERROR);
	}

	if (sscanf(perm_list, "%s%s%s%s", minor, perm, own, grp) != 4) {
		status = ERROR;
	}

	while ((fgets(line, sizeof (line), fp) != NULL) && status == NOERR) {
		/* copy the whole line into dup */
		if ((dup = strdup(line)) == NULL) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_NO_MEM));
			status = ERROR;
			break;
		}
		/* cut off comments starting with '#' */
		if ((cp = strchr(dup, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(dup)) {
			if (fputs(line, newfp) == EOF) {
				(void) fprintf(stderr, gettext(ERR_UPDATE),
				    minor_perm);
				status = ERROR;
			}
			free(dup);
			continue;
		}

		/* get the driver name */
		if (sscanf(dup, "%s", drv) != 1) {
			(void) fprintf(stderr, gettext(ERR_BAD_LINE),
			    minor_perm, line);
			status = ERROR;
			free(dup);
			break;
		}

		/*
		 * get the minor name; place the NULL character at the
		 * end of the driver name, then make the drv_minor
		 * point to the first character of the minor name.
		 * the line missing ':' must be treated as a broken one.
		 */
		i = strcspn(drv, ":");
		if (i == strlen(drv)) {
			(void) fprintf(stderr, gettext(ERR_BAD_LINE),
			    minor_perm, line);
			status = ERROR;
			free(dup);
			break;
		}
		drv[i] =  '\0';
		drv_minor = &drv[strlen(drv) + 1];

		/*
		 * compare both of the driver name and the minor name.
		 * then the new line should be written to the file if
		 * both of them match
		 */
		if ((strcmp(drv, driver_name) == 0) &&
		    (strcmp(minor, drv_minor) == 0)) {
			/* if it has a comment, keep it */
			if (cp != NULL) {
				cp++; /* skip a terminator */
				(void) sprintf(line, "%s:%s %s %s %s #%s\n",
				    drv, minor, perm, own, grp, cp);
			} else {
				(void) sprintf(line, "%s:%s %s %s %s\n",
				    drv, minor, perm, own, grp);
			}
			match = 1;
		}
		free(dup);

		/* update the file */
		if ((fputs(line, newfp)) == EOF) {
			(void) fprintf(stderr, gettext(ERR_UPDATE),
			    minor_perm);
			status = ERROR;
		}
	}

	if (!match) {
		(void) bzero(line, sizeof (&line[0]));
		(void) sprintf(line, "%s:%s %s %s %s\n",
		    driver_name, minor, perm, own, grp);

		/* add the new entry */
		if ((fputs(line, newfp)) == EOF) {
			(void) fprintf(stderr, gettext(ERR_UPDATE), minor_perm);
			status = ERROR;
		}
	}

	(void) fclose(fp);

	if (fflush(newfp) != 0 || fsync(fileno(newfp)) != 0)
		status = ERROR;

	(void) fclose(newfp);

	/*
	 * if error, leave original file, delete new file
	 * if noerr, replace original file with new file
	 */
	if (status == NOERR) {
		if (rename(minor_perm, tmphold) == -1) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_UPDATE), minor_perm);
			(void) unlink(newfile);
			return (ERROR);
		} else if (rename(newfile, minor_perm) == -1) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_UPDATE), minor_perm);
			(void) unlink(minor_perm);
			(void) unlink(newfile);
			if (link(tmphold, minor_perm) == -1) {
				perror(NULL);
				(void) fprintf(stderr, gettext(ERR_BAD_LINK),
				    minor_perm, tmphold);
			}
			return (ERROR);
		}
		(void) unlink(tmphold);
	} else {
		/*
		 * since there's an error, leave file alone; remove
		 * new file
		 */
		if (unlink(newfile) == -1) {
			(void) fprintf(stderr, gettext(ERR_CANT_RM), newfile);
		}
		return (ERROR);
	}

	return (NOERR);

}


/*
 * list_entry:
 *	open file
 *	read thru file, listing all entries if first entry = driver_name
 *	close
 */
void
list_entry(
	char *oldfile,
	char *driver_name,
	char *marker)
{
	FILE	*fp;
	int	i;
	char	line[MAX_DBFILE_ENTRY], *cp;
	char	drv[FILENAME_MAX + 1];

	if ((fp = fopen(oldfile, "r")) == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE), oldfile);

		return;
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		/* cut off comments starting with '#' */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(line))
			continue;
		/* sanity-check */
		if (sscanf(line, "%s", drv) != 1) {
			(void) fprintf(stderr, gettext(ERR_BAD_LINE),
			    oldfile, line);
		}

		for (i = strcspn(drv, marker); i < FILENAME_MAX; i++) {
			drv[i] =  '\0';
		}

		if (strcmp(driver_name, drv) == 0) {
			(void) fprintf(stdout, "%s", line);
		}
	}

	(void) fclose(fp);
}

static boolean_t
is_token(char *tok)
{
	/*
	 * Check the token here. According to IEEE1275 Open Firmware Boot
	 * Standard, the name is composed of 1 to 31 letters,
	 * digits and punctuation characters from the set ",._+-", and
	 * uppercase and lowercase characters are considered distinct.
	 * (ie. token := [a-zA-Z0-9,._+-]+, length(token) <= 31)
	 * However, since either the definition of driver or aliase names is
	 * not known well, only '#' is avoided explicitly. (the kernel lexical
	 * analyzer treats it as a start of a comment)
	 */
	for (/* nothing */; *tok != '\0'; tok++)
		if (*tok == '#' || iscntrl(*tok))
			return (B_FALSE);

	return (B_TRUE);
}

/*
 * check each entry in perm_list for:
 *	4 arguments
 *	permission arg is in valid range
 * permlist entries separated by comma
 * return ERROR/NOERR
 */
int
check_perm_opts(char *perm_list)
{
	char *current_head;
	char *previous_head;
	char *one_entry;
	int i, len, scan_stat;
	char minor[FILENAME_MAX + 1];
	char perm[OPT_LEN + 1];
	char own[OPT_LEN + 1];
	char grp[OPT_LEN + 1];
	char dumb[OPT_LEN + 1];
	int status = NOERR;
	int intperm;

	len = strlen(perm_list);

	if (len == 0) {
		return (ERROR);
	}

	one_entry = calloc(len + 1, 1);
	if (one_entry == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		return (ERROR);
	}

	previous_head = perm_list;
	current_head = perm_list;

	while (*current_head != '\0') {

		for (i = 0; i <= len; i++)
			one_entry[i] = 0;

		current_head = get_entry(previous_head, one_entry, ',', 0);

		previous_head = current_head;
		scan_stat = sscanf(one_entry, "%s%s%s%s%s", minor, perm, own,
		    grp, dumb);

		if (scan_stat < 4) {
			(void) fprintf(stderr, gettext(ERR_MIS_TOK),
			    "-m", one_entry);
			status = ERROR;
		}
		if (scan_stat > 4) {
			(void) fprintf(stderr, gettext(ERR_TOO_MANY_ARGS),
			    "-m", one_entry);
			status = ERROR;
		}

		intperm = atoi(perm);
		if (intperm < 0000 || intperm > 4777) {
			(void) fprintf(stderr, gettext(ERR_BAD_MODE), perm);
			status = ERROR;
		}
	}

	free(one_entry);
	return (status);
}


/*
 * check each alias :
 *	alias list members separated by white space
 *	cannot exist as driver name in /etc/name_to_major
 *	cannot exist as driver or alias name in /etc/driver_aliases
 */
int
aliases_unique(char *aliases)
{
	char *current_head;
	char *previous_head;
	char *one_entry;
	int i, len;
	int is_unique;

	len = strlen(aliases);

	one_entry = calloc(len + 1, 1);
	if (one_entry == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		return (ERROR);
	}

	previous_head = aliases;

	do {
		for (i = 0; i <= len; i++)
			one_entry[i] = 0;

		current_head = get_entry(previous_head, one_entry, ' ', 1);
		previous_head = current_head;

		if ((unique_driver_name(one_entry, name_to_major,
		    &is_unique)) == ERROR) {
			free(one_entry);
			return (ERROR);
		}

		if (is_unique != UNIQUE) {
			(void) fprintf(stderr, gettext(ERR_ALIAS_IN_NAM_MAJ),
			    one_entry);
			free(one_entry);
			return (ERROR);
		}

		if (unique_drv_alias(one_entry) != NOERR) {
			free(one_entry);
			return (ERROR);
		}

		if (!is_token(one_entry)) {
			(void) fprintf(stderr, gettext(ERR_BAD_TOK),
			    "-i", one_entry);
			free(one_entry);
			return (ERROR);
		}

	} while (*current_head != '\0');

	free(one_entry);

	return (NOERR);

}


/*
 * check each alias :
 *	if path-oriented alias, path exists
 */
int
aliases_paths_exist(char *aliases)
{
	char *current_head;
	char *previous_head;
	char *one_entry;
	int i, len;
	char path[MAXPATHLEN];
	struct stat buf;

	len = strlen(aliases);

	one_entry = calloc(len + 1, 1);
	if (one_entry == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		return (ERROR);
	}

	previous_head = aliases;

	do {
		for (i = 0; i <= len; i++)
			one_entry[i] = 0;

		current_head = get_entry(previous_head, one_entry, ' ', 1);
		previous_head = current_head;

		/* if the alias is a path, ensure that the path exists */
		if (*one_entry != '/')
			continue;
		(void) snprintf(path, sizeof (path), "/devices/%s", one_entry);
		if (stat(path, &buf) == 0)
			continue;

		/* no device at specified path-oriented alias path */
		(void) fprintf(stderr, gettext(ERR_PATH_ORIENTED_ALIAS),
		    one_entry);
		free(one_entry);
		return (ERROR);

	} while (*current_head != '\0');

	free(one_entry);

	return (NOERR);
}


int
update_driver_aliases(
	char *driver_name,
	char *aliases)
{
	/* make call to update the aliases file */
	return (append_to_file(driver_name, aliases, driver_aliases,
	    ' ', " ", 1));
}


int
unique_drv_alias(char *drv_alias)
{
	FILE *fp;
	char drv[FILENAME_MAX + 1];
	char line[MAX_N2M_ALIAS_LINE + 1], *cp;
	char alias[FILENAME_MAX + 1];
	char *a;
	int status = NOERR;

	fp = fopen(driver_aliases, "r");

	if (fp != NULL) {
		while ((fgets(line, sizeof (line), fp) != 0) &&
		    status != ERROR) {
			/* cut off comments starting with '#' */
			if ((cp = strchr(line, '#')) != NULL)
				*cp = '\0';
			/* ignore comment or blank lines */
			if (is_blank(line))
				continue;
			/* sanity-check */
			if (sscanf(line, "%s %s", drv, alias) != 2)
				(void) fprintf(stderr, gettext(ERR_BAD_LINE),
				    driver_aliases, line);

			/* unquote for compare */
			if ((*alias == '"') &&
			    (*(alias + strlen(alias) - 1) == '"')) {
				a = &alias[1];
				alias[strlen(alias) - 1] = '\0';
			} else
				a = alias;

			if ((strcmp(drv_alias, drv) == 0) ||
			    (strcmp(drv_alias, a) == 0)) {
				(void) fprintf(stderr,
				    gettext(ERR_ALIAS_IN_USE),
				    drv_alias);
				status = ERROR;
			}
		}
		(void) fclose(fp);
		return (status);
	} else {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_OPEN), driver_aliases);
		return (ERROR);
	}
}


/*
 * search for driver_name in first field of file file_name
 * searching name_to_major and driver_aliases: name separated from rest of
 * line by blank
 * if there return
 * else return
 */
int
unique_driver_name(char *driver_name, char *file_name,
	int *is_unique)
{
	int ret;

	if ((ret = get_major_no(driver_name, file_name)) == ERROR) {
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE),
		    file_name);
	} else {
		/* XXX */
		/* check alias file for name collision */
		if (unique_drv_alias(driver_name) == ERROR) {
			ret = ERROR;
		} else {
			if (ret != UNIQUE)
				*is_unique = NOT_UNIQUE;
			else
				*is_unique = ret;
			ret = NOERR;
		}
	}
	return (ret);
}

/*
 * returns:
 *	SUCCESS - not an existing driver alias
 *	NOT_UNIQUE - matching driver alias exists
 *	ERROR - an error occurred
 */
int
check_duplicate_driver_alias(char *driver_name, char *drv_alias)
{
	FILE *fp;
	char drv[FILENAME_MAX + 1];
	char line[MAX_N2M_ALIAS_LINE + 1], *cp;
	char alias[FILENAME_MAX + 1];
	char *a;
	int status = SUCCESS;

	if ((fp = fopen(driver_aliases, "r")) == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_OPEN), driver_aliases);
		return (ERROR);
	}

	while (fgets(line, sizeof (line), fp) != 0) {
		/* cut off comments starting with '#' */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(line))
			continue;
		/* sanity-check */
		if (sscanf(line, "%s %s", drv, alias) != 2)
			(void) fprintf(stderr, gettext(ERR_BAD_LINE),
			    driver_aliases, line);

		/* unquote for compare */
		if ((*alias == '"') &&
		    (*(alias + strlen(alias) - 1) == '"')) {
			a = &alias[1];
			alias[strlen(alias) - 1] = '\0';
		} else
			a = alias;

		if ((strcmp(drv_alias, a) == 0) &&
		    (strcmp(drv, driver_name) == 0)) {
			status = NOT_UNIQUE;
		}

		if ((strcmp(drv_alias, drv) == 0) ||
		    ((strcmp(drv_alias, a) == 0) &&
		    (strcmp(drv, driver_name) != 0))) {
			(void) fprintf(stderr,
			    gettext(ERR_ALIAS_IN_USE),
			    drv_alias);
			status = ERROR;
			goto done;
		}
	}

done:
	(void) fclose(fp);
	return (status);
}

int
trim_duplicate_aliases(char *driver_name, char *aliases, char **aliases2p)
{
	char *current_head;
	char *previous_head;
	char *one_entry;
	char *aliases2;
	int rv, len;
	int n = 0;

	*aliases2p = NULL;
	len = strlen(aliases) + 1;

	one_entry = calloc(len, 1);
	aliases2 = calloc(len, 1);
	if (one_entry == NULL || aliases2 == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		return (ERROR);
	}

	previous_head = aliases;

	do {
		(void) bzero(one_entry, len);
		current_head = get_entry(previous_head, one_entry, ' ', 1);
		previous_head = current_head;

		rv = check_duplicate_driver_alias(driver_name, one_entry);
		switch (rv) {
		case SUCCESS:
			/* not an existing driver alias: add it */
			if (n > 0) {
				if (strlcat(aliases2, " ", len) >= len)
					goto err;
			}
			if (strlcat(aliases2, one_entry, len) >= len)
				goto err;
			n++;
			break;
		case NOT_UNIQUE:
			/* matching driver alias exists: do not add it */
			break;
		case ERROR:
			/* error reading the alias file */
			goto err;
		default:
			goto err;
		}

		if (!is_token(one_entry)) {
			(void) fprintf(stderr, gettext(ERR_BAD_TOK),
			    "-i", one_entry);
			goto err;
		}
	} while (*current_head != '\0');

	/*
	 * If all the aliases listed are already
	 * present we actually have none to do.
	 */
	if (n == 0) {
		free(aliases2);
	} else {
		*aliases2p = aliases2;
	}
	free(one_entry);
	return (NOERR);

err:
	free(aliases2);
	free(one_entry);
	return (ERROR);
}

int
check_space_within_quote(char *str)
{
	register int i;
	register int len;
	int quoted = 0;

	len = strlen(str);
	for (i = 0; i < len; i++, str++) {
		if (*str == '"') {
			if (quoted == 0)
				quoted++;
			else
				quoted--;
		} else if (*str == ' ' && quoted)
			return (ERROR);
	}

	return (0);
}


/*
 * get major number
 * write driver_name major_num to name_to_major file
 * major_num returned in major_num
 * return success/failure
 */
int
update_name_to_major(char *driver_name, major_t *major_num, int server)
{
	char major[MAX_STR_MAJOR + 1];
	struct stat buf;
	char *num_list;
	char drv_majnum_str[MAX_STR_MAJOR + 1];
	int new_maj = -1;
	int i, tmp = 0, is_unique, have_rem_n2m = 0;
	int max_dev = 0;

	/*
	 * if driver_name already in rem_name_to_major
	 * 	delete entry from rem_nam_to_major
	 *	put entry into name_to_major
	 */

	if (stat(rem_name_to_major, &buf) == 0) {
		have_rem_n2m = 1;
	}

	if (have_rem_n2m) {
		if ((is_unique = get_major_no(driver_name, rem_name_to_major))
		    == ERROR)
			return (ERROR);

		/*
		 * found a match in rem_name_to_major
		 */
		if (is_unique != UNIQUE) {
			char scratch[FILENAME_MAX];

			/*
			 * If there is a match in /etc/rem_name_to_major then
			 * be paranoid: is that major number already in
			 * /etc/name_to_major (potentially under another name)?
			 */
			if (get_driver_name(is_unique, name_to_major,
			    scratch) != UNIQUE) {
				/*
				 * nuke the rem_name_to_major entry-- it
				 * isn't helpful.
				 */
				(void) delete_entry(rem_name_to_major,
				    driver_name, " ", NULL);
			} else {
				(void) snprintf(major, sizeof (major),
				    "%d", is_unique);

				if (append_to_file(driver_name, major,
				    name_to_major, ' ', " ", 0) == ERROR) {
					(void) fprintf(stderr,
					    gettext(ERR_NO_UPDATE),
					    name_to_major);
					return (ERROR);
				}

				if (delete_entry(rem_name_to_major,
				    driver_name, " ", NULL) == ERROR) {
					(void) fprintf(stderr,
					    gettext(ERR_DEL_ENTRY), driver_name,
					    rem_name_to_major);
					return (ERROR);
				}

				/* found matching entry : no errors */
				*major_num = is_unique;
				return (NOERR);
			}
		}
	}

	/*
	 * Bugid: 1264079
	 * In a server case (with -b option), we can't use modctl() to find
	 *    the maximum major number, we need to dig thru client's
	 *    /etc/name_to_major and /etc/rem_name_to_major for the max_dev.
	 *
	 * if (server)
	 *    get maximum major number thru (rem_)name_to_major file on client
	 * else
	 *    get maximum major number allowable on current system using modctl
	 */
	if (server) {
		max_dev = 0;
		tmp = 0;

		max_dev = get_max_major(name_to_major);

		/* If rem_name_to_major exists, we need to check it too */
		if (have_rem_n2m) {
			tmp = get_max_major(rem_name_to_major);

			/*
			 * If name_to_major is missing, we can get max_dev from
			 * /etc/rem_name_to_major.  If both missing, bail out!
			 */
			if ((max_dev == ERROR) && (tmp == ERROR)) {
				(void) fprintf(stderr,
				    gettext(ERR_CANT_ACCESS_FILE),
				    name_to_major);
				return (ERROR);
			}

			/* guard against bigger maj_num in rem_name_to_major */
			if (tmp > max_dev)
				max_dev = tmp;
		} else {
			/*
			 * If we can't get major from name_to_major file
			 * and there is no /etc/rem_name_to_major file,
			 * then we don't have a max_dev, bail out quick!
			 */
			if (max_dev == ERROR)
				return (ERROR);
		}

		/*
		 * In case there is no more slack in current name_to_major
		 * table, provide at least 1 extra entry so the add_drv can
		 * succeed.  Since only one add_drv process is allowed at one
		 * time, and hence max_dev will be re-calculated each time
		 * add_drv is ran, we don't need to worry about adding more
		 * than 1 extra slot for max_dev.
		 */
		max_dev++;

	} else {
		if (modctl(MODRESERVED, NULL, &max_dev) < 0) {
			perror(NULL);
			(void) fprintf(stderr, gettext(ERR_MAX_MAJOR));
			return (ERROR);
		}
	}

	/*
	 * max_dev is really how many slots the kernel has allocated for
	 * devices... [0 , maxdev-1], not the largest available device num.
	 */
	if ((num_list = calloc(max_dev, 1)) == NULL) {
		(void) fprintf(stderr, gettext(ERR_NO_MEM));
		return (ERROR);
	}

	/*
	 * Populate the num_list array
	 */
	if (fill_n2m_array(name_to_major, &num_list, &max_dev) != 0) {
		return (ERROR);
	}
	if (have_rem_n2m) {
		if (fill_n2m_array(rem_name_to_major, &num_list, &max_dev) != 0)
			return (ERROR);
	}

	/* find first free major number */
	for (i = 0; i < max_dev; i++) {
		if (num_list[i] != 1) {
			new_maj = i;
			break;
		}
	}

	if (new_maj == -1) {
		(void) fprintf(stderr, gettext(ERR_NO_FREE_MAJOR));
		return (ERROR);
	}

	(void) sprintf(drv_majnum_str, "%d", new_maj);
	if (do_the_update(driver_name, drv_majnum_str) == ERROR) {
		return (ERROR);
	}

	*major_num = new_maj;
	return (NOERR);
}


int
fill_n2m_array(char *filename, char **array, int *nelems)
{
	FILE *fp;
	char line[MAX_N2M_ALIAS_LINE + 1], *cp;
	char drv[FILENAME_MAX + 1];
	u_longlong_t dnum;
	major_t drv_majnum;

	/*
	 * Read through the file, marking each major number found
	 * order is not relevant
	 */
	if ((fp = fopen(filename, "r")) == NULL) {
		perror(NULL);
		(void) fprintf(stderr, gettext(ERR_CANT_ACCESS_FILE), filename);
		return (ERROR);
	}

	while (fgets(line, sizeof (line), fp) != 0) {
		/* cut off comments starting with '#' */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(line))
			continue;
		/* sanity-check */
		if (sscanf(line, "%s %llu", drv, &dnum) != 2) {
			(void) fprintf(stderr, gettext(ERR_BAD_LINE),
			    filename, line);
			(void) fclose(fp);
			return (ERROR);
		}

		if (dnum > L_MAXMAJ32) {
			(void) fprintf(stderr, gettext(ERR_MAJ_TOOBIG), drv,
			    dnum, filename, L_MAXMAJ32);
			continue;
		}
		/*
		 * cast down to a major_t; we can be sure this is safe because
		 * of the above range-check.
		 */
		drv_majnum = (major_t)dnum;

		if (drv_majnum >= *nelems) {
			/*
			 * Allocate some more space, up to drv_majnum + 1 so
			 * we can accomodate 0 through drv_majnum.
			 *
			 * Note that in the failure case, we leak all of the
			 * old contents of array.  It's ok, since we just
			 * wind up exiting immediately anyway.
			 */
			*nelems = drv_majnum + 1;
			*array = realloc(*array, *nelems);
			if (*array == NULL) {
				(void) fprintf(stderr, gettext(ERR_NO_MEM));
				return (ERROR);
			}
		}
		(*array)[drv_majnum] = 1;
	}

	(void) fclose(fp);
	return (0);
}


int
do_the_update(char *driver_name, char *major_number)
{
	return (append_to_file(driver_name, major_number, name_to_major,
	    ' ', " ", 0));
}

/*
 * is_blank() returns 1 (true) if a line specified is composed of
 * whitespace characters only. otherwise, it returns 0 (false).
 *
 * Note. the argument (line) must be null-terminated.
 */
static int
is_blank(char *line)
{
	for (/* nothing */; *line != '\0'; line++)
		if (!isspace(*line))
			return (0);
	return (1);
}
