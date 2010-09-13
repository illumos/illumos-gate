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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains the functions implementing the interface to the
 * /etc/inet/dhcpsvc.conf DHCP service configuration file.
 */

#include <thread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <alloca.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dhcp_svc_confkey.h>
#include <dhcp_svc_confopt.h>
#include <dhcp_svc_private.h>

/*
 * Finds the parameter called key, and returns a reference to it.  Returns
 * NULL if not found or an error occurred.
 */
static dhcp_confopt_t *
find_dhcp_confopt(dhcp_confopt_t *ddp, const char *key)
{
	unsigned int	i;

	if (ddp == NULL || key == NULL)
		return (NULL);

	for (i = 0; ddp[i].co_type != DHCP_END; i++) {
		if (ddp[i].co_type == DHCP_KEY &&
		    strcasecmp(ddp[i].co_key, key) == 0)
			return (&ddp[i]);
	}
	return (NULL);
}

/*
 * Adds a dhcp_confopt_t to the ddpp table. If the table is NULL, one is
 * created. The table is terminated by a NULL entry.  The key and value
 * arguments are copied, not referenced directly.  No check is done to see
 * if the parameter already exists.  Returns 0 for success, nonzero
 * otherwise.
 */
int
add_dsvc_conf(dhcp_confopt_t **ddpp, const char *key, const char *value)
{
	dhcp_confopt_t		*ndp, tdp;
	unsigned int		i;

	if (ddpp == NULL || key == NULL || value == NULL) {
		errno = EINVAL;
		return (-1);
	}

	tdp.co_key = strdup(key);
	tdp.co_type = DHCP_KEY;
	tdp.co_value = strdup(value);
	if (tdp.co_key == NULL || tdp.co_value == NULL) {
		free(tdp.co_key);
		free(tdp.co_value);
		errno = ENOMEM;
		return (-1);
	}

	for (i = 0; *ddpp && (*ddpp)[i].co_key != NULL; i++)
		;

	ndp = realloc(*ddpp, (i + 2) * sizeof (dhcp_confopt_t));
	if (ndp == NULL) {
		free(tdp.co_key);
		free(tdp.co_value);
		errno = ENOMEM;
		return (-1);
	}

	ndp[i] = tdp;
	(void) memset(&ndp[i + 1], 0, sizeof (dhcp_confopt_t));
	*ddpp = ndp;

	return (0);
}

/*
 * Reads the contents of the configuration file into a dynamically
 * allocated array of dhcp_confopt_t records.  A zeroed element marks the
 * end of the array.  Blank lines are ignored.  Caller is responsible for
 * freeing ddp.
 */
int
read_dsvc_conf(dhcp_confopt_t **ddpp)
{
	struct stat	sb;
	int		dd;
	int		error;
	unsigned int	entry;
	char		*cp, *dp, *eol, *value;
	dhcp_confopt_t	confopt, *tdp, *ddp = NULL;
	char		conf[MAXPATHLEN];

	if (ddpp == NULL) {
		errno = EINVAL;
		return (-1);
	}

	(void) snprintf(conf, sizeof (conf), "%s" DHCP_CONFOPT_FILE,
	    DHCP_CONFOPT_ROOT);

	if ((dd = open(conf, O_RDONLY)) == -1)
		return (-1);
	if (fstat(dd, &sb) == -1) {
		error = errno;
		(void) close(dd);
		errno = error;
		return (-1);
	}

	dp = alloca(sb.st_size);
	if (read(dd, dp, sb.st_size) != sb.st_size) {
		error = errno;
		(void) close(dd);
		errno = error;
		return (-1);
	}
	(void) close(dd);

	for (entry = 0, cp = dp; cp < &dp[sb.st_size]; cp = eol + 1) {
		eol = strchr(cp, '\n');
		if (eol == NULL)		/* done parsing file */
			break;
		if (eol == cp) 			/* blank line -- skip */
			continue;
		*eol = '\0';

		if (*cp == '#') {
			confopt.co_type = DHCP_COMMENT;
			confopt.co_comment = strdup(cp + 1);
			if (confopt.co_comment == NULL)
				goto nomem;
		} else {
			value = strchr(cp, '=');
			if (value == NULL)
				continue;
			*value = '\0';

			confopt.co_type = DHCP_KEY;
			confopt.co_key = strdup(cp);
			if (confopt.co_key == NULL)
				goto nomem;

			confopt.co_value = strdup(value + 1);
			if (confopt.co_value == NULL) {
				free(confopt.co_key);
				goto nomem;
			}
		}

		/* always allocate a spare slot for the zeroed entry */
		tdp = realloc(ddp, (entry + 2) * sizeof (dhcp_confopt_t));
		if (tdp == NULL)
			goto nomem;

		tdp[entry] = confopt;
		(void) memset(&tdp[entry + 1], 0, sizeof (dhcp_confopt_t));
		ddp = tdp;
		entry++;
	}

	if (ddp == NULL)
		return (-1);

	*ddpp = ddp;
	return (0);

nomem:
	if (ddp != NULL)
		free_dsvc_conf(ddp);

	errno = ENOMEM;
	return (-1);
}

/*
 * If the requested parameter exists, replace its value with the new
 * value. If it doesn't exist, then add the parameter with the new value.
 * Returns 0 for success, -1 otherwise (errno is set).
 */
int
replace_dsvc_conf(dhcp_confopt_t **ddpp, const char *key, const char *value)
{
	dhcp_confopt_t	*tdp;
	int		err;

	if (ddpp == NULL || key == NULL || value == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if ((tdp = find_dhcp_confopt(*ddpp, key)) != NULL) {
		char	*valp;

		if ((valp = strdup(value)) == NULL)
			return (-1); /* NOMEM */

		if (tdp->co_value != NULL)
			free(tdp->co_value);

		tdp->co_value = valp;

		errno = 0;
		err = 0;
	} else
		err = (add_dsvc_conf(ddpp, key, value) == 0) ? 0 : -1;

	return (err);
}

/*
 * Writes ddp array to the configuration file.  If the configuration file
 * already exists, its contents are replaced with the contents of the ddp
 * array.  If the configuration file does not exist, it is created using
 * the identity of the caller (euid/egid) with the permission bits
 * specified by the mode argument (and modified by the umask).  Caller is
 * responsible for freeing the array.
 */
int
write_dsvc_conf(dhcp_confopt_t *ddp, mode_t mode)
{
	int		tdd;
	ssize_t		bytes;
	size_t		i, size;
	char		*tmpbuf;
	char		tmpconf[MAXPATHLEN], conf[MAXPATHLEN];

	if (ddp == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* guess at final file size */
	for (i = 0, size = 0; ddp[i].co_type != DHCP_END; i++) {
		if (ddp[i].co_type == DHCP_KEY) {
			size += strlen(ddp[i].co_key) + 1; /* include = */
			size += strlen(ddp[i].co_value) + 1; /* include \n */
		} else
			size += strlen(ddp[i].co_comment) + 2; /* inc # + \n */
	}

	if (size == 0) {
		errno = EINVAL;
		return (-1);
	}

	(void) snprintf(conf, sizeof (conf), "%s" DHCP_CONFOPT_FILE,
	    DHCP_CONFOPT_ROOT);
	(void) snprintf(tmpconf, sizeof (tmpconf),
	    "%s" DHCP_CONFOPT_FILE ".%ld.%u", DHCP_CONFOPT_ROOT, getpid(),
	    thr_self());

	if ((tdd = open(tmpconf, O_CREAT | O_EXCL | O_WRONLY, mode)) < 0)
		return (-1);

	tmpbuf = alloca(size);
	for (i = 0; ddp[i].co_type != DHCP_END; i++) {
		if (ddp[i].co_type == DHCP_KEY)
			(void) snprintf(tmpbuf, size, "%s=%s\n", ddp[i].co_key,
			    ddp[i].co_value);
		else
			(void) snprintf(tmpbuf, size, "#%s\n",
			    ddp[i].co_comment);

		bytes = write(tdd, tmpbuf, strlen(tmpbuf));

		/* Nuke the file if we can't successfully update it */
		if (bytes != strlen(tmpbuf)) {
			(void) close(tdd);
			(void) unlink(tmpconf);
			return (-1);
		}
	}
	(void) close(tdd);

	/* Move new file into place */
	if (rename(tmpconf, conf) < 0) {
		(void) unlink(tmpconf);
		return (-1);
	}

	return (0);
}

/*
 * Frees the memory associated with the ddp array.
 */
void
free_dsvc_conf(dhcp_confopt_t *ddp)
{
	unsigned int	i;

	if (ddp == NULL)
		return;

	for (i = 0; ddp[i].co_type != DHCP_END; i++) {
		if (ddp[i].co_type == DHCP_KEY) {
			free(ddp[i].co_key);
			free(ddp[i].co_value);
		} else
			free(ddp[i].co_comment);
	}
	free(ddp);
}

/*
 * Deletes the configuration file.
 */
int
delete_dsvc_conf(void)
{
	char confpath[MAXPATHLEN];

	(void) snprintf(confpath, sizeof (confpath), "%s" DHCP_CONFOPT_FILE,
	    DHCP_CONFOPT_ROOT);
	return (unlink(confpath));
}

/*
 * Return a copy of the value portion of the named key.  Caller is
 * responsible for freeing value when they're finished using it.  Returns 0
 * for success, -1 otherwise (errno is set).
 */
int
query_dsvc_conf(dhcp_confopt_t *ddp, const char *key, char **value)
{
	dhcp_confopt_t	*tdp;

	if (key == NULL || value == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if ((tdp = find_dhcp_confopt(ddp, key)) != NULL) {
		*value = strdup(tdp->co_value);
		if (*value == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		errno = 0;
		return (0);
	}
	errno = ENOENT;
	*value = NULL;
	return (-1);
}

/*
 * Given a dhcp_confopt_t structure, fill in a dsvc_datastore_t.
 * Data is copied from dhcp_confopt_t structure.
 */
int
confopt_to_datastore(dhcp_confopt_t *ddp, dsvc_datastore_t *dsp)
{
	dhcp_confopt_t	*tdp;

	if (ddp == NULL || dsp == NULL)
		return (DSVC_INVAL);

	tdp = find_dhcp_confopt(ddp, DSVC_CK_CONVER);
	if (tdp == NULL || tdp->co_value == NULL)
		return (DSVC_BAD_CONVER);
	dsp->d_conver = atoi(tdp->co_value);

	if (query_dsvc_conf(ddp, DSVC_CK_RESOURCE, &dsp->d_resource) == -1)
		return (DSVC_BAD_RESOURCE);

	if (query_dsvc_conf(ddp, DSVC_CK_PATH, &dsp->d_location) == -1) {
		free(dsp->d_resource);
		return (DSVC_BAD_PATH);
	}

	/*
	 * RESOURCE_CONFIG is optional - underlying service will complain
	 * if it isn't right.
	 */
	(void) query_dsvc_conf(ddp, DSVC_CK_RESOURCE_CONFIG, &dsp->d_config);

	return (DSVC_SUCCESS);
}
