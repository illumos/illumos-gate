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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: lpd-job.c 157 2006-04-26 15:07:55Z ktou $ */


#define	__EXTENSIONS__	/* for strtok_r() */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <libintl.h>
#include <papi_impl.h>

enum { LPD_RFC, LPD_SVR4 };

static char
mime_type_to_rfc1179_type(char *mime)
{
	static struct { char *mime; char rfc; } cvt[] = {
		{ "text/plain", 'f' },
		{ "application/octet-stream", 'l' },
		{ "application/postscript", 'f' }, /* rfc incorrectly has 'o' */
		{ "application/x-pr", 'p' },
		{ "application/x-cif", 'c' },
		{ "application/x-dvi", 'd' },
		{ "application/x-fortran", 'r' },
		{ "application/x-plot", 'g' },
		{ "application/x-ditroff", 'n' },
		{ "application/x-troff", 't' },
		{ "application/x-raster", 'v' },
		{ NULL, 0}
	};
	char result = '\0';

	if (mime != NULL) {
		int i;

		for (i = 0; cvt[i].mime != NULL; i++)
			if (strcasecmp(cvt[i].mime, mime) == 0) {
				result = cvt[i].rfc;
				break;
			}
	}

	return (result);
}

static papi_status_t
add_lpd_control_line(char **metadata, char code, char *value)
{
	size_t size = 0;
	char line[BUFSIZ];

	if ((metadata == NULL) || (value == NULL))
		return (PAPI_BAD_REQUEST);

	if (*metadata != NULL)
		size = strlen(*metadata);
	size += strlen(value) + 3;

	if (*metadata == NULL) {
		*metadata = (char *)calloc(1, size);
	} else {
		void *tmp;
		tmp = calloc(1, size);
		if (tmp) {
			strlcpy(tmp, *metadata, size);
			free(*metadata);
			*metadata = (char *)tmp;
		} else {
			return (PAPI_TEMPORARY_ERROR);
		}
	}

	snprintf(line, sizeof (line), "%c%s\n", code, value);
	strlcat(*metadata, line, size);

	return (PAPI_OK);
}

static papi_status_t
add_svr4_control_line(char **metadata, char code, char *value)
{

	char line[BUFSIZ];

	if ((metadata == NULL) || (value == NULL))
		return (PAPI_BAD_REQUEST);

	snprintf(line, sizeof (line), "%c%s", code, value);

	return (add_lpd_control_line(metadata, '5', line));
}

static papi_status_t
add_hpux_control_line(char **metadata, char *value)
{

	char line[BUFSIZ];

	if ((metadata == NULL) || (value == NULL))
		return (PAPI_BAD_REQUEST);

	snprintf(line, sizeof (line), " O%s", value);

	return (add_lpd_control_line(metadata, 'N', line));
}

static papi_status_t
add_int_control_line(char **metadata, char code, int value, int flag)
{
	char buf[16];

	snprintf(buf, sizeof (buf), "%d", value);

	if (flag == LPD_SVR4)
		return (add_svr4_control_line(metadata, code, buf));
	else
		return (add_lpd_control_line(metadata, code, buf));
}

static papi_status_t
lpd_add_rfc1179_attributes(service_t *svc, papi_attribute_t **attributes,
    char **metadata, papi_attribute_t ***used)
{
	papi_status_t status = PAPI_OK;
	char *s;
	int integer;
	char bool;
	char host[BUFSIZ];
	char *user = "nobody";
	uid_t uid = getuid();
	struct passwd *pw;
	char *h1;

	if (svc == NULL)
		return (PAPI_BAD_REQUEST);

	/* There is nothing to do */
	if (attributes == NULL)
		return (PAPI_OK);

	gethostname(host, sizeof (host));
	if (papiAttributeListGetString(attributes, NULL,
	    "job-originating-host-name", &h1) == PAPI_OK) {
		papiAttributeListAddString(&attributes, PAPI_ATTR_APPEND,
		    "job-host", h1);
	}
	add_lpd_control_line(metadata, 'H', host);
	papiAttributeListAddString(used, PAPI_ATTR_EXCL,
	    "job-originating-host-name", host);

	if ((pw = getpwuid(uid)) != NULL)
		user = pw->pw_name;
	if (uid == 0)
		papiAttributeListGetString(svc->attributes, NULL, "username",
		    &user);
	add_lpd_control_line(metadata, 'P', user);
	papiAttributeListAddString(used, PAPI_ATTR_EXCL,
	    "job-originating-user-name", user);

	/* Class for Banner Page */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "rfc-1179-class", &s);
	if (s != NULL) {
		add_lpd_control_line(metadata, 'C', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "rfc-1179-class", s);
	}

	/* Print Banner Page */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "job-sheets", &s);
	if ((s != NULL) && (strcmp(s, "standard") == 0)) {
		add_lpd_control_line(metadata, 'L', user);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "job-sheets", s);
	}

	/* Jobname */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "job-name", &s);
	if (s != NULL) {
		add_lpd_control_line(metadata, 'J', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "job-name", s);
	}

	/* User to mail when job is done - lpr -m */
	bool = PAPI_FALSE;
	papiAttributeListGetBoolean(attributes, NULL, "rfc-1179-mail", &bool);
	if (bool == PAPI_TRUE) {
		add_lpd_control_line(metadata, 'M', user);
		papiAttributeListAddBoolean(used, PAPI_ATTR_EXCL,
		    "rfc-1179-mail", bool);
	}

	/* Title for pr */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "pr-title", &s);
	if (s != NULL) {
		add_lpd_control_line(metadata, 'T', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "pr-title", s);
	}

	/* Indent - used with pr filter */
	integer = 0;
	papiAttributeListGetInteger(attributes, NULL, "pr-indent", &integer);
	if (integer >= 1) {
		add_int_control_line(metadata, 'I', integer, LPD_RFC);
		papiAttributeListAddInteger(used, PAPI_ATTR_EXCL,
		    "pr-indent", integer);
	}

	/* Width - used with pr filter */
	integer = 0;
	papiAttributeListGetInteger(attributes, NULL, "pr-width", &integer);
	if (integer >= 1) {
		add_int_control_line(metadata, 'W', integer, LPD_RFC);
		papiAttributeListAddInteger(used, PAPI_ATTR_EXCL,
		    "pr-width", integer);
	}

	/* file with Times Roman font lpr -1	*/
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "rfc-1179-font-r", &s);
	if (s != NULL) {
		add_lpd_control_line(metadata, '1', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "rfc-1179-font-r", s);
	}

	/* file with Times Roman font lpr -2	*/
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "rfc-1179-font-i", &s);
	if (s != NULL) {
		add_lpd_control_line(metadata, '2', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "rfc-1179-font-i", s);
	}

	/* file with Times Roman font lpr -3	*/
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "rfc-1179-font-b", &s);
	if (s != NULL) {
		add_lpd_control_line(metadata, '3', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "rfc-1179-font-b", s);
	}

	/* file with Times Roman font lpr -4	*/
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "rfc-1179-font-s", &s);
	if (s != NULL) {
		add_lpd_control_line(metadata, '4', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "rfc-1179-font-s", s);
	}

	/*
	 * The document format needs to be added, but the control line
	 * should be added when the filenames are figured out.
	 */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "document-format", &s);
	if (s != NULL) {
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "document-format", s);
	}

	return (status);
}

static char *
unused_attributes(papi_attribute_t **list, papi_attribute_t **used)
{
	char *result = NULL;
	char **names = NULL;
	int i;

	if ((list == NULL) || (used == NULL))
		return (NULL);

	for (i = 0; used[i] != NULL; i++)
		list_append(&names, used[i]->name);

	if (names != NULL) {
		papi_attribute_t **unused = NULL;

		/* add these to the list of things to ignore */
		list_append(&names, "document-format");
		list_append(&names, "copies");

		split_and_copy_attributes(names, list, NULL, &unused);
		if (unused != NULL) {
			size_t size = 0;

			do {
				size += 1024;
				if (result != NULL)
					free(result);
				result = calloc(1, size);
			} while (papiAttributeListToString(unused, " ",
			    result, size) != PAPI_OK);
			papiAttributeListFree(unused);
		}
		free(names);
	}

	return (result);
}

/*
 * lpd_add_svr4_attributes
 *	Solaris 2.x LP - BSD protocol extensions
 */
static papi_status_t
lpd_add_svr4_attributes(service_t *svc, papi_attribute_t **attributes,
    char **metadata, papi_attribute_t ***used)
{
	papi_attribute_t *tmp[2];
	char *s;
	int integer;

	if (svc == NULL)
		return (PAPI_BAD_REQUEST);

	/* media */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "media", &s);
	if (s != NULL) {
		add_svr4_control_line(metadata, 'f', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "media", s);
	}

	/* Handling */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "job-hold-until", &s);
	if ((s != NULL) && (strcmp(s, "indefinite") == 0)) {
		add_svr4_control_line(metadata, 'H', "hold");
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "job-hold-until", "indefinite");
	} else if ((s != NULL) && (strcmp(s, "no-hold") == 0)) {
		add_svr4_control_line(metadata, 'H', "immediate");
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "job-hold-until", "no-hold");
	} else if (s != NULL) {
		add_svr4_control_line(metadata, 'H', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "job-hold-until", s);
	}

	/* Pages */
	s = NULL;
	memset(tmp, 0, sizeof (tmp));
	tmp[0] = papiAttributeListFind(attributes, "page-ranges");
	if (tmp[0] != NULL) {
		char buf[BUFSIZ];

		papiAttributeListToString(tmp, " ", buf, sizeof (buf));
		if ((s = strchr(buf, '=')) != NULL) {
			add_svr4_control_line(metadata, 'P', ++s);
			papiAttributeListAddString(used, PAPI_ATTR_EXCL,
			    "page-ranges", s);
		}
	}

	/* Priority : lp -q */
	integer = -1;
	papiAttributeListGetInteger(attributes, NULL, "job-priority", &integer);
	if (integer != -1) {
		integer = 40 - (integer / 2.5);
		add_int_control_line(metadata, 'q', integer, LPD_SVR4);
		papiAttributeListAddInteger(used, PAPI_ATTR_EXCL,
		    "job-priority", integer);
	}

	/* Charset : lp -S */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "lp-charset", &s);
	if (s != NULL) {
		add_svr4_control_line(metadata, 'S', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "lp-charset", s);
	}

	/* Type : done when adding file  */

	/* Mode : lp -y */
	s = NULL;
	papiAttributeListGetString(attributes, NULL, "lp-modes", &s);
	if (s != NULL) {
		add_svr4_control_line(metadata, 'y', s);
		papiAttributeListAddString(used, PAPI_ATTR_EXCL,
		    "lp-modes", s);
	}

	/* Options lp -o are handled elsewhere */
	if ((s = unused_attributes(attributes, *used)) != NULL) {
		add_lpd_control_line(metadata, 'O', s);
		free(s);
	}

	return (PAPI_OK);
}

papi_status_t
lpd_add_hpux_attributes(service_t *svc, papi_attribute_t **attributes,
    char **metadata, papi_attribute_t ***used)
{
	char *s = NULL;

	/* Options lp -o */
	if ((s = unused_attributes(attributes, *used)) != NULL) {
		add_hpux_control_line(metadata, s);
		free(s);
	}

	return (PAPI_OK);
}

papi_status_t
lpd_job_add_attributes(service_t *svc, papi_attribute_t **attributes,
    char **metadata, papi_attribute_t ***used)
{
	if ((svc == NULL) || (metadata == NULL))
		return (PAPI_BAD_REQUEST);

	lpd_add_rfc1179_attributes(svc, attributes, metadata, used);

	/* add protocol extensions if applicable */
	if (svc->uri->fragment != NULL) {
		if ((strcasecmp(svc->uri->fragment, "solaris") == 0) ||
		    (strcasecmp(svc->uri->fragment, "svr4") == 0))
			lpd_add_svr4_attributes(svc, attributes, metadata,
			    used);
		else if (strcasecmp(svc->uri->fragment, "hpux") == 0)
			lpd_add_hpux_attributes(svc, attributes, metadata,
			    used);
		/*
		 * others could be added here:
		 *	lprng, sco, aix, digital unix, xerox, ...
		 */
	}

	return (PAPI_OK);
}

papi_status_t
lpd_job_add_files(service_t *svc, papi_attribute_t **attributes,
    char **files, char **metadata, papi_attribute_t ***used)
{
	char *format = "text/plain";
	char rfc_fmt = 'l';
	int copies = 1;
	char host[BUFSIZ];
	int i;

	if ((svc == NULL) || (attributes == NULL) || (files == NULL) ||
	    (metadata == NULL))
		return (PAPI_BAD_ARGUMENT);

	papiAttributeListGetString(attributes, NULL, "document-format",
	    &format);
	papiAttributeListAddString(used, PAPI_ATTR_EXCL,
	    "document-format", format);
	if ((rfc_fmt = mime_type_to_rfc1179_type(format)) == '\0') {
		if ((svc->uri->fragment != NULL) &&
		    ((strcasecmp(svc->uri->fragment, "solaris") == 0) ||
		    (strcasecmp(svc->uri->fragment, "svr4") == 0)))
			add_svr4_control_line(metadata, 'T', format);
		rfc_fmt = 'l';
	}

	papiAttributeListGetInteger(attributes, NULL, "copies", &copies);
	if (copies < 1)
		copies = 1;
	papiAttributeListAddInteger(used, PAPI_ATTR_EXCL, "copies", copies);

	gethostname(host, sizeof (host));

	for (i = 0; files[i] != NULL; i++) {
		char name[BUFSIZ];
		struct stat statbuf;
		char key;
		int j;

		if ((strcmp("standard input", files[i]) != 0) &&
		    (access(files[i], R_OK) < 0)) {
			detailed_error(svc, gettext("aborting request, %s: %s"),
			    files[i], strerror(errno));
			return (PAPI_NOT_AUTHORIZED);
		}
		if (strcmp("standard input", files[i]) != 0) {
			if (stat(files[i], &statbuf) < 0) {
				detailed_error(svc,
				    gettext("Cannot access file: %s: %s"),
				    files[i], strerror(errno));
				return (PAPI_DOCUMENT_ACCESS_ERROR);
			}
			if (statbuf.st_size == 0) {
				detailed_error(svc,
				    gettext("Zero byte (empty) file: %s"),
				    files[i]);
				return (PAPI_BAD_ARGUMENT);
			}
		}

		if (i < 26)
			key = 'A' + i;
		else if (i < 52)
			key = 'a' + (i - 26);
		else if (i < 62)
			key = '0' + (i - 52);
		else {
			detailed_error(svc,
			    gettext("too many files, truncated at 62"));
			return (PAPI_OK_SUBST);
		}

		snprintf(name, sizeof (name), "df%cXXX%s", key, host);

		for (j = 0; j < copies; j++)
			add_lpd_control_line(metadata, rfc_fmt, name);
		add_lpd_control_line(metadata, 'U', name);
		add_lpd_control_line(metadata, 'N', (char *)files[i]);
	}

	return (PAPI_OK);
}

papi_status_t
lpd_submit_job(service_t *svc, char *metadata, papi_attribute_t ***attributes,
    int *ofd)
{
	papi_status_t status = PAPI_INTERNAL_ERROR;
	int fd;
	char path[32];
	char *list[2];

	if ((svc == NULL) || (metadata == NULL))
		return (PAPI_BAD_ARGUMENT);

	strcpy(path, "/tmp/lpd-job-XXXXXX");
	fd = mkstemp(path);
	write(fd, metadata, strlen(metadata));
	close(fd);

	list[0] = path;
	list[1] = NULL;

	if (((fd = lpd_open(svc, 's', list, 15)) < 0) && (errno != EBADMSG)) {
		switch (errno) {
		case ENOSPC:
			status = PAPI_TEMPORARY_ERROR;
			break;
		case EIO:
			status = PAPI_TEMPORARY_ERROR;
			break;
		case ECONNREFUSED:
			status = PAPI_SERVICE_UNAVAILABLE;
			break;
		case ENOENT:
			status = PAPI_NOT_ACCEPTING;
			break;
		case EBADMSG:
		case EBADF:
			status = PAPI_OK;
			break;
		default:
			status = PAPI_TIMEOUT;
			break;
		}
	} else {
		status = PAPI_OK;
	}

	if (ofd != NULL)
		*ofd = fd;
	else
		close(fd);

	/* read the ID and add it to to the job */
	if ((fd = open(path, O_RDONLY)) >= 0) {
		int job_id = 0;
		read(fd, &job_id, sizeof (job_id));
		papiAttributeListAddInteger(attributes, PAPI_ATTR_REPLACE,
		    "job-id", job_id);
		close(fd);
	}

	unlink(path);

	return (status);
}
