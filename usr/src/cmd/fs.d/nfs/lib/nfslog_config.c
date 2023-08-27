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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <nfs/nfs.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "nfslog_config.h"

#define	ERROR_BUFSZ	100

/*
 * This flag controls where error messages go.
 * Zero means that messages go to stderr.
 * Non-zero means that messages go to syslog.
 */
boolean_t nfsl_errs_to_syslog;

/*
 * Pointer to the global entry in the list
 */
static nfsl_config_t *global = NULL;

/*
 * Pointer to the raw global entry in the list, this is the
 * global entry without the expanded paths. This is used to
 * complete configurations.
 */
static nfsl_config_t *global_raw = NULL;

/*
 * Last modification time to config file.
 */
static timestruc_t config_last_modification = { 0 };

/*
 * Whitespace characters to delimit fields in a line.
 */
static const char *whitespace = " \t";

static int getconfiglist(nfsl_config_t **, boolean_t);
static nfsl_config_t *create_config(char *, char *, char *, char *, char *,
			char *, int, boolean_t, int *);
static nfsl_config_t *create_global_raw(int *);
static int update_config(nfsl_config_t *, char *, char *, char *,
			char *, char *, char *, int, boolean_t, boolean_t);
static int update_field(char **, char *, char *, boolean_t *);
static nfsl_config_t *findconfig(nfsl_config_t **, char *, boolean_t,
			nfsl_config_t **);
static nfsl_config_t *getlastconfig(nfsl_config_t *);
static void complete_with_global(char **, char **, char **, char **,
			char **, int *);
#ifdef DEBUG
static void remove_config(nfsl_config_t **, nfsl_config_t *, nfsl_config_t **);
void nfsl_printconfig(nfsl_config_t *);
#endif /* DEBUG */
static char *gataline(FILE *, char *, char *, int);
static int get_info(char *, char **, char **, char **, char **, char **,
			char **, int *);
static void free_config(nfsl_config_t *);
static int is_legal_tag(char *);
static boolean_t is_complete_config(char *, char *, char *, char *);

/*
 * Read the configuration file and create a list of configuration
 * parameters.  Returns zero for success or an errno value.
 * The caller is responsible for freeing the returned configlist by calling
 * nfsl_freeconfig_list().
 *
 * If the configuration file does not exist, *listpp points to a config entry
 * containing the hardwired defaults.
 */
int
nfsl_getconfig_list(nfsl_config_t **listpp)
{
	int error = 0;
	char *locale;

	/*
	 * Set the locale correctly so that we can correctly identify
	 * alphabetic characters.
	 */
	if ((locale = getenv("LC_ALL")) != NULL)
		(void) setlocale(LC_ALL, locale);
	else if ((locale = getenv("LC_CTYPE")) != NULL)
		(void) setlocale(LC_CTYPE, locale);
	else if ((locale = getenv("LANG")) != NULL)
		(void) setlocale(LC_CTYPE, locale);

	/*
	 * Allocate 'global_raw' structure, its contents are
	 * indirectly allocated by create_config().
	 */
	assert(global_raw == NULL);
	global_raw = create_global_raw(&error);
	if (global_raw == NULL)
		return (error);

	/*
	 * Build global entry with hardwired defaults first.
	 */
	assert(global == NULL);
	global = create_config(DEFAULTTAG, DEFAULTDIR, BUFFERPATH, NULL,
	    FHPATH, LOGPATH, TRANSLOG_BASIC, B_TRUE, &error);
	*listpp = global;
	if (global == NULL) {
		free_config(global_raw);
		return (error);
	}

	error = getconfiglist(listpp, B_FALSE);
	if (error != 0) {
		nfsl_freeconfig_list(listpp);
	} else {
		assert(global != NULL);
		/*
		 * The global entry was replaced with the one in the file,
		 * clear the UPDATED flag
		 */
		global->nc_flags &= ~NC_UPDATED;
	}
	return (error);
}

/*
 * Allocates memory for the 'global_raw' structure.
 * The actual allocation of values for its components happens in
 * update_config().
 */
static nfsl_config_t *
create_global_raw(int *error)
{
	nfsl_config_t *p;

	*error = 0;
	p = calloc(1, sizeof (*p));
	if (p == NULL)
		*error = ENOMEM;

	return (p);
}

/*
 * Checks if the the configuration file has been modified since we last
 * read it, if not simply returns, otherwise it re-reads it adding new
 * configuration entries. Note that existing entries that no longer
 * exist in the configuration file are not removed. Existing entries
 * that are modified in the configuration file are updated in the list
 * as well.
 * if 'updated' is defined then it is set to TRUE if the list was modified.
 *
 * Note that if an error occurs, the list may be corrupted.
 * It is the responsibility of the caller to free the list.
 * If the configuration file does not exist, we simply return the list
 * that we previously had, log a message and return success.
 */
int
nfsl_checkconfig_list(nfsl_config_t **listpp, boolean_t *updated)
{
	struct stat st;
	int error = 0;

	if (updated != NULL)
		*updated = B_FALSE;

	if (stat(NFSL_CONFIG_FILE_PATH, &st) == -1) {
		error = errno;
		if (nfsl_errs_to_syslog) {
			syslog(LOG_ERR, gettext(
			    "Can't stat %s - %s"), NFSL_CONFIG_FILE_PATH,
			    strerror(error));
		} else {
			(void) fprintf(stderr, gettext(
			    "Can't stat %s - %s\n"), NFSL_CONFIG_FILE_PATH,
			    strerror(error));
		}
		return (0);
	}

	if (config_last_modification.tv_sec == st.st_mtim.tv_sec &&
	    config_last_modification.tv_nsec == st.st_mtim.tv_nsec)
		return (0);

	if (updated != NULL)
		*updated = B_TRUE;

	return (getconfiglist(listpp, B_TRUE));
}

/*
 * Does the real work. Reads the configuration file and creates the
 * list of entries. Assumes that *listpp contains at least one entry.
 * The caller is responsible for freeing any config entries added to
 * the list whether this routine returns an error or not.
 *
 * Returns 0 on success and updates the '*listpp' config list,
 * Returns non-zero error value otherwise.
 */
static int
getconfiglist(nfsl_config_t **listpp, boolean_t updating)
{
	FILE *fp;
	int error = 0;
	nfsl_config_t *listp = NULL, *tail = NULL;
	char linebuf[MAX_LINESZ];
	char errorbuf[ERROR_BUFSZ];
	char *tag, *defaultdir, *bufferpath, *rpclogpath, *fhpath, *logpath;
	int logformat;
	flock_t flock;
	struct stat st;

	fp = fopen(NFSL_CONFIG_FILE_PATH, "r");
	if (fp == NULL) {
		if (updating) {
			(void) sprintf(errorbuf, "Can't open %s",
			    NFSL_CONFIG_FILE_PATH);
		} else {
			(void) sprintf(errorbuf,
			    "Can't open %s - using hardwired defaults",
			    NFSL_CONFIG_FILE_PATH);
		}

		/*
		 * Use hardwired config.
		 */
		if (nfsl_errs_to_syslog)
			syslog(LOG_ERR, gettext("%s"), errorbuf);
		else
			(void) fprintf(stderr, gettext("%s\n"), errorbuf);

		return (0);
	}

	(void) memset((void *) &flock, 0, sizeof (flock));
	flock.l_type = F_RDLCK;
	if (fcntl(fileno(fp), F_SETLKW, &flock) == -1) {
		error = errno;
		if (nfsl_errs_to_syslog) {
			syslog(LOG_ERR, gettext(
			    "Can't lock %s - %s"), NFSL_CONFIG_FILE_PATH,
			    strerror(error));
		} else {
			(void) fprintf(stderr, gettext(
			    "Can't lock %s - %s\n"), NFSL_CONFIG_FILE_PATH,
			    strerror(error));
		}
		goto done;
	}

	assert (*listpp != NULL);
	tail = getlastconfig(*listpp);

	while (gataline(fp, NFSL_CONFIG_FILE_PATH, linebuf, sizeof (linebuf))) {
		if (linebuf[0] == '\0') {
			/*
			 * ignore lines that exceed max size
			 */
			continue;
		}

		error = get_info(linebuf, &tag, &defaultdir, &bufferpath,
		    &rpclogpath, &fhpath, &logpath, &logformat);
		if (error != 0)
			break;

		listp = findconfig(listpp, tag, B_FALSE, &tail);
		if (listp != NULL) {
			/*
			 * An entry with the same tag name exists,
			 * update the fields that changed.
			 */
			error = update_config(listp, tag, defaultdir,
			    bufferpath, rpclogpath, fhpath, logpath,
			    logformat, B_TRUE, B_TRUE);
			if (error)
				break;
		} else {
			/*
			 * New entry, create it.
			 */
			listp = create_config(tag, defaultdir,
			    bufferpath, rpclogpath, fhpath,
			    logpath, logformat, B_TRUE, &error);
			if (listp == NULL)
				break;

			if (*listpp == NULL)
				*listpp = listp;
			else
				tail->nc_next = listp;
			tail = listp;
		}

		assert(global != NULL);
	}

	if (error == 0) {
		/*
		 * Get mtime while we have file locked
		 */
		error = fstat(fileno(fp), &st);
		if (error != 0) {
			error = errno;
			if (nfsl_errs_to_syslog) {
				syslog(LOG_ERR, gettext(
				    "Can't stat %s - %s"),
				    NFSL_CONFIG_FILE_PATH,
				    strerror(error));
			} else {
				(void) fprintf(stderr, gettext(
				    "Can't stat %s - %s\n"),
				    NFSL_CONFIG_FILE_PATH,
				    strerror(error));
			}
		}
		config_last_modification = st.st_mtim;
	}

done:
	(void) fclose(fp);
	return (error);
}

/*
 * Creates the config structure with the values specified by the
 * parameters. If defaultdir has been specified, all relative paths
 * are prepended with this defaultdir.
 * If 'complete' is set then this must represent a complete config entry
 * as specified by is_complete_config(), otherwise no work is perfomed, and
 * NULL is returned.
 *
 * Returns the newly created config structure on success.
 * Returns NULL on failure and sets error to the appropriate error.
 */
static nfsl_config_t *
create_config(
    char *tag,
    char *defaultdir,
    char *bufferpath,
    char *rpclogpath,
    char *fhpath,
    char *logpath,
    int   logformat,
    boolean_t complete,
    int  *error)
{
	nfsl_config_t *config;

	config = calloc(1, sizeof (*config));
	if (config == NULL) {
		*error = ENOMEM;
		return (NULL);
	}

	*error = update_config(config, tag, defaultdir, bufferpath, rpclogpath,
	    fhpath, logpath, logformat, complete, B_TRUE);
	if (*error) {
		free(config);
		return (NULL);
	}

	config->nc_flags &= ~NC_UPDATED;	/* This is a new entry */

	return (config);
}


/*
 * Updates the configuration entry with the new information provided,
 * sets NC_UPDATED to indicate so. The entry is left untouched if all
 * the fields are the same (except for 'nc_rpccookie', 'nc_transcookie'
 * and 'nc_next').
 * Prepends each path component with 'defauldir' if 'prepend' is set.
 *
 * Returns 0 on success, error otherwise.
 * On error, the config entry is left in an inconsistent state.
 * The only thing the caller can really do with it is free it.
 */
static int
update_config(
	nfsl_config_t *config,
	char *tag,
	char *defaultdir,
	char *bufferpath,
	char *rpclogpath,
	char *fhpath,
	char *logpath,
	int   logformat,
	boolean_t complete,
	boolean_t prepend)
{
	boolean_t updated, config_updated = B_FALSE;
	int error = 0;

	if (complete && !is_complete_config(tag, bufferpath, fhpath, logpath)) {
		/*
		 * Not a complete entry
		 */
		if (nfsl_errs_to_syslog) {
			syslog(LOG_ERR, gettext(
			    "update_config: \"%s\" not a complete "
			    "config entry."), tag);
		} else {
			(void) fprintf(stderr, gettext(
			    "update_config: \"%s\" not a complete "
			    "config entry.\n"), tag);
		}
		return (EINVAL);
	}

	assert(tag != NULL);
	if (config->nc_name == NULL) {
		/*
		 * New entry
		 */
		if ((config->nc_name = strdup(tag)) == NULL) {
			error = ENOMEM;
			goto errout;
		}
	} else {
		assert(strcmp(config->nc_name, tag) == 0);
	}

	error = update_field(
	    &config->nc_defaultdir, defaultdir, NULL, &updated);
	if (error != 0)
		goto errout;
	if (!prepend) {
		/*
		 * Do not prepend default directory.
		 */
		defaultdir = NULL;
	}
	config_updated |= updated;
	error = update_field(
	    &config->nc_bufferpath, bufferpath, defaultdir, &updated);
	if (error != 0)
		goto errout;
	config_updated |= updated;
	error = update_field(
	    &config->nc_rpclogpath, rpclogpath, defaultdir, &updated);
	if (error != 0)
		goto errout;
	config_updated |= updated;
	error = update_field(
	    &config->nc_fhpath, fhpath, defaultdir, &updated);
	if (error != 0)
		goto errout;
	config_updated |= updated;
	error = update_field(
	    &config->nc_logpath, logpath, defaultdir, &updated);
	if (error != 0)
		goto errout;
	config_updated |= updated;
	updated = (config->nc_logformat != logformat);
	if (updated)
		config->nc_logformat = logformat;
	config_updated |= updated;

	if (config_updated)
		config->nc_flags |= NC_UPDATED;

	if (strcmp(tag, DEFAULTTAG) == 0) {
		/*
		 * Have the default global config point to this entry.
		 */
		global = config;

		/*
		 * Update the global_raw configuration entry.
		 * Make sure no expanding of paths occurs.
		 */
		error = update_config(global_raw, DEFAULTRAWTAG, defaultdir,
		    bufferpath, rpclogpath, fhpath, logpath, logformat,
		    complete, B_FALSE);
		if (error != 0)
			goto errout;
	}

	return (error);

errout:
	if (nfsl_errs_to_syslog) {
		syslog(LOG_ERR, gettext(
		    "update_config: Can't process \"%s\" config entry: %s"),
		    tag, strerror(error));
	} else {
		(void) fprintf(stderr, gettext(
		    "update_config: Can't process \"%s\" config entry: %s\n"),
		    tag, strerror(error));
	}
	return (error);
}

/*
 * Prepends 'prependir' to 'new' if 'prependir' is defined.
 * Compares the value of '*old' with 'new', if it has changed,
 * then sets whatever 'old' references equal to 'new'.
 * Returns 0 on success, error otherwise.
 * Sets '*updated' to B_TRUE if field was modified.
 * The value of '*updated' is undefined on error.
 */
static int
update_field(
	char **old,		/* pointer to config field */
	char *new,		/* updated value */
	char *prependdir,	/* prepend this directory to new */
	boolean_t *updated)	/* field was modified */
{
	char *tmp_new = NULL;
	int need_update = 0;

	if (new != NULL) {
		if (prependdir != NULL && new[0] != '/') {
			tmp_new = malloc(strlen(prependdir) + strlen(new) + 2);
			if (tmp_new == NULL)
				return (ENOMEM);
			(void) sprintf(tmp_new, "%s/%s", prependdir, new);
		} else {
			if ((tmp_new = strdup(new)) == NULL)
				return (ENOMEM);
		}
	}

	if (tmp_new != NULL) {
		if (*old == NULL)
			need_update++;
		else if (strcmp(tmp_new, *old) != 0) {
			free(*old);
			need_update++;
		}
		if (need_update)
			*old = tmp_new;
	} else if (*old != NULL) {
		need_update++;
		free(*old);
		*old = NULL;
	}

	*updated = need_update != 0;
	return (0);
}

#ifdef DEBUG
/*
 * Removes and frees the 'config' entry from the list
 * pointed to by '*listpp'.
 * No error is reported if the entry does not exist.
 * Updates '*tail' to point to the last item in the list.
 */
static void
remove_config(
	nfsl_config_t **listpp,
	nfsl_config_t *config,
	nfsl_config_t **tail)
{
	nfsl_config_t *p, *prev;

	prev = *listpp;
	for (p = *listpp; p != NULL; p = p->nc_next) {
		if (p == config) {
			if (p == prev) {
				/*
				 * first element of the list
				 */
				*listpp = prev->nc_next;
			} else
				prev->nc_next = p->nc_next;
			free_config(p);
			break;
		}
		prev = p;
	}

	/*
	 * Find tail of the list.
	 */
	for (*tail = prev; (*tail)->nc_next != NULL; *tail = (*tail)->nc_next)
		;
}
#endif /* DEBUG */

static void
free_config(nfsl_config_t *config)
{
	if (config == NULL)
		return;
	if (config->nc_name)
		free(config->nc_name);
	if (config->nc_defaultdir)
		free(config->nc_defaultdir);
	if (config->nc_bufferpath)
		free(config->nc_bufferpath);
	if (config->nc_rpclogpath)
		free(config->nc_rpclogpath);
	if (config->nc_fhpath)
		free(config->nc_fhpath);
	if (config->nc_logpath)
		free(config->nc_logpath);
	if (config == global)
		global = NULL;
	if (config == global_raw)
		global_raw = NULL;
	free(config);
}

void
nfsl_freeconfig_list(nfsl_config_t **listpp)
{
	nfsl_config_t *next;

	if (*listpp == NULL)
		return;

	do {
		next = (*listpp)->nc_next;
		free_config(*listpp);
		*listpp = next;
	} while (*listpp);

	free_config(global_raw);
}

/*
 * Returns a pointer to the first instance of 'tag' in the list.
 * If 'remove' is true, then the entry is removed from the list and
 * a pointer to it is returned.
 * If '*tail' is not NULL, then it will point to the last element of
 * the list. Note that this function assumes that *tail already
 * points at the last element of the list.
 * Returns NULL if the entry does not exist.
 */
static nfsl_config_t *
findconfig(
	nfsl_config_t **listpp,
	char *tag, boolean_t remove,
	nfsl_config_t **tail)
{
	nfsl_config_t *p, *prev;

	prev = *listpp;
	for (p = *listpp; p != NULL; p = p->nc_next) {
		if (strcmp(p->nc_name, tag) == 0) {
			if (remove) {
				if (p == prev) {
					/*
					 * first element of the list
					 */
					*listpp = prev->nc_next;
				} else
					prev->nc_next = p->nc_next;

				if (tail != NULL && p == *tail) {
					/*
					 * Only update *tail if we removed
					 * the last element of the list, and we
					 * requested *tail to be updated.
					 */
					*tail = prev;
				}
			}
			return (p);
		}
		prev = p;
	}

	return (NULL);
}

static nfsl_config_t *
getlastconfig(nfsl_config_t *listp)
{
	nfsl_config_t *lastp = NULL;

	for (; listp != NULL; listp = listp->nc_next)
		lastp = listp;

	return (lastp);
}

/*
 * Returns a pointer to the first instance of 'tag' in the list.
 * Returns NULL if the entry does not exist.
 * Sets 'error' if the update of the list failed if necessary, and
 * returns NULL.
 */
nfsl_config_t *
nfsl_findconfig(nfsl_config_t *listp, char *tag, int *error)
{
	nfsl_config_t *config;
	boolean_t updated;

	*error = 0;
	config = findconfig(&listp, tag, B_FALSE, (nfsl_config_t **)NULL);
	if (config == NULL) {
		/*
		 * Rebuild our list if the file has changed.
		 */
		*error = nfsl_checkconfig_list(&listp, &updated);
		if (*error != 0) {
			/*
			 * List may be corrupted, notify caller.
			 */
			return (NULL);
		}
		if (updated) {
			/*
			 * Search for tag again.
			 */
			config = findconfig(&listp, tag, B_FALSE,
			    (nfsl_config_t **)NULL);
		}
	}

	return (config);
}

/*
 * Use the raw global values if any of the parameters is not defined.
 */
static void
complete_with_global(
	char **defaultdir,
	char **bufferpath,
	char **rpclogpath,
	char **fhpath,
	char **logpath,
	int  *logformat)
{
	if (*defaultdir == NULL)
		*defaultdir = global_raw->nc_defaultdir;
	if (*bufferpath == NULL)
		*bufferpath = global_raw->nc_bufferpath;
	if (*rpclogpath == NULL)
		*rpclogpath = global_raw->nc_rpclogpath;
	if (*fhpath == NULL)
		*fhpath = global_raw->nc_fhpath;
	if (*logpath == NULL)
		*logpath = global_raw->nc_logpath;
	if (*logformat == 0)
		*logformat = global_raw->nc_logformat;
}

/*
 * Parses 'linebuf'. Returns 0 if a valid tag is found, otherwise non-zero.
 * Unknown tokens are silently ignored.
 * It is the responsibility of the caller to make a copy of the non-NULL
 * parameters if they need to be used before linebuf is freed.
 */
static int
get_info(
	char *linebuf,
	char **tag,
	char **defaultdir,
	char **bufferpath,
	char **rpclogpath,
	char **fhpath,
	char **logpath,
	int  *logformat)
{
	char *tok;
	char *tmp;

	/* tag */
	*tag = NULL;
	tok = strtok(linebuf, whitespace);
	if (tok == NULL)
		goto badtag;
	if (!is_legal_tag(tok))
		goto badtag;
	*tag = tok;

	*defaultdir = *bufferpath = *rpclogpath = NULL;
	*fhpath = *logpath = NULL;
	*logformat = 0;

	while ((tok = strtok(NULL, whitespace)) != NULL) {
		if (strncmp(tok, "defaultdir=", strlen("defaultdir=")) == 0) {
			*defaultdir = tok + strlen("defaultdir=");
		} else if (strncmp(tok, "buffer=", strlen("buffer=")) == 0) {
			*bufferpath = tok + strlen("buffer=");
		} else if (strncmp(tok, "rpclog=", strlen("rpclog=")) == 0) {
			*rpclogpath = tok + strlen("rpclog=");
		} else if (strncmp(tok, "fhtable=", strlen("fhtable=")) == 0) {
			*fhpath = tok + strlen("fhtable=");
		} else if (strncmp(tok, "log=", strlen("log=")) == 0) {
			*logpath = tok + strlen("log=");
		} else if (strncmp(tok, "logformat=",
		    strlen("logformat=")) == 0) {
			tmp = tok + strlen("logformat=");
			if (strncmp(tmp, "extended", strlen("extended")) == 0) {
				*logformat = TRANSLOG_EXTENDED;
			} else {
				/*
				 * Use transaction log basic format if
				 * 'extended' was not specified.
				 */
				*logformat = TRANSLOG_BASIC;
			}
		}
	}

	if (strcmp(*tag, DEFAULTTAG) != 0) {
		/*
		 * Use global values for fields not specified if
		 * this tag is not the global tag.
		 */
		complete_with_global(defaultdir, bufferpath,
		    rpclogpath, fhpath, logpath, logformat);
	}

	return (0);

badtag:
	if (nfsl_errs_to_syslog) {
		syslog(LOG_ERR, gettext(
		    "Bad tag found in config file."));
	} else {
		(void) fprintf(stderr, gettext(
		    "Bad tag found in config file.\n"));
	}
	return (-1);
}

/*
 * Returns True if we have all the elements of a complete configuration
 * entry. A complete configuration has tag, bufferpath, fhpath and logpath
 * defined to non-zero strings.
 */
static boolean_t
is_complete_config(
	char *tag,
	char *bufferpath,
	char *fhpath,
	char *logpath)
{
	assert(tag != NULL);
	assert(strlen(tag) > 0);

	if ((bufferpath != NULL && strlen(bufferpath) > 0) &&
	    (fhpath != NULL && strlen(fhpath) > 0) &&
	    (logpath != NULL && strlen(logpath) > 0))
		return (B_TRUE);
	return (B_FALSE);
}

#ifdef DEBUG
/*
 * Prints the configuration entry to stdout.
 */
void
nfsl_printconfig(nfsl_config_t *config)
{
	if (config->nc_name)
		(void) printf("tag=%s\t", config->nc_name);
	if (config->nc_defaultdir)
		(void) printf("defaultdir=%s\t", config->nc_defaultdir);
	if (config->nc_logpath)
		(void) printf("logpath=%s\t", config->nc_logpath);
	if (config->nc_fhpath)
		(void) printf("fhpath=%s\t", config->nc_fhpath);
	if (config->nc_bufferpath)
		(void) printf("bufpath=%s\t", config->nc_bufferpath);
	if (config->nc_rpclogpath)
		(void) printf("rpclogpath=%s\t", config->nc_rpclogpath);
	if (config->nc_logformat == TRANSLOG_BASIC)
		(void) printf("logformat=basic");
	else if (config->nc_logformat == TRANSLOG_EXTENDED)
		(void) printf("logformat=extended");
	else
		(void) printf("config->nc_logformat=UNKNOWN");

	if (config->nc_flags & NC_UPDATED)
		(void) printf("\tflags=NC_UPDATED");
	(void) printf("\n");
}

/*
 * Prints the configuration list to stdout.
 */
void
nfsl_printconfig_list(nfsl_config_t *listp)
{
	for (; listp != NULL; listp = listp->nc_next) {
		nfsl_printconfig(listp);
		(void) printf("\n");
	}
}
#endif /* DEBUG */

/*
 * Returns non-zero if the given string is allowable for a tag, zero if
 * not.
 */
static int
is_legal_tag(char *tag)
{
	int i;
	int len;

	if (tag == NULL)
		return (0);
	len = strlen(tag);
	if (len == 0)
		return (0);

	for (i = 0; i < len; i++) {
		char c;

		c = tag[i];
		if (!(isalnum((unsigned char)c) || c == '_'))
			return (0);
	}

	return (1);
}

/*
 * gataline attempts to get a line from the configuration file,
 * upto LINESZ. A line in the file is a concatenation of lines if the
 * continuation symbol '\' is used at the end of the line. Returns
 * line on success, a NULL on EOF, and an empty string on lines > linesz.
 */
static char *
gataline(FILE *fp, char *path, char *line, int linesz)
{
	char *p = line;
	int len;
	int excess = 0;

	*p = '\0';

	for (;;) {
		if (fgets(p, linesz - (p-line), fp) == NULL) {
			return (*line ? line : NULL);   /* EOF */
		}

		len = strlen(line);
		if (len <= 0) {
			p = line;
			continue;
		}
		p = &line[len - 1];

		/*
		 * Is input line too long?
		 */
		if (*p != '\n') {
			excess = 1;
			/*
			 * Perhaps last char read was '\'. Reinsert it
			 * into the stream to ease the parsing when we
			 * read the rest of the line to discard.
			 */
			(void) ungetc(*p, fp);
			break;
		}
trim:

		/* trim trailing white space */
		while (p >= line && isspace(*(uchar_t *)p))
			*p-- = '\0';
		if (p < line) {			/* empty line */
			p = line;
			continue;
		}

		if (*p == '\\') {		/* continuation */
			*p = '\0';
			continue;
		}

		/*
		 * Ignore comments. Comments start with '#'
		 * which must be preceded by a whitespace, unless
		 * '#' is the first character in the line.
		 */
		p = line;

		while ((p = strchr(p, '#')) != NULL) {
			if (p == line || isspace(*(p-1))) {
				*p-- = '\0';
				goto trim;
			}
			p++;
		}

		break;
	}
	if (excess) {
		int c;

		/*
		 * discard rest of line and return an empty string.
		 * done to set the stream to the correct place when
		 * we are done with this line.
		 */
		while ((c = getc(fp)) != EOF) {
			*p = c;
			if (*p == '\n')		/* end of the long line */
				break;
			else if (*p == '\\') {		/* continuation */
				if (getc(fp) == EOF)	/* ignore next char */
					break;
			}
		}
		if (nfsl_errs_to_syslog) {
			syslog(LOG_ERR, gettext(
			    "%s: line too long - ignored (max %d chars)"),
			    path, linesz-1);
		} else {
			(void) fprintf(stderr, gettext(
			    "%s: line too long - ignored (max %d chars)\n"),
			    path, linesz-1);
		}
		*line = '\0';
	}

	return (line);
}
