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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*LINTLIBRARY*/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <papi_impl.h>

/*
 * for an older application that may have been linked with a pre-v1.0
 * PAPI implementation.
 */
papi_status_t
papiAttributeListAdd(papi_attribute_t ***attrs, int flags, char *name,
		papi_attribute_value_type_t type, papi_attribute_value_t *value)
{
	return (papiAttributeListAddValue(attrs, flags, name, type, value));
}

#ifdef LP_USE_PAPI_ATTR
static papi_status_t psm_modifyAttrsFile(papi_attribute_t **attrs, char *file);
static papi_status_t psm_modifyAttrsList(char *file, papi_attribute_t **attrs,
					papi_attribute_t ***newAttrs);
#endif

int32_t
check_job_id(papi_service_t svc, char *printer, int32_t id)
{
	papi_job_t *jobs = NULL;
	papi_status_t status;
	int ret = -1;
	char *jattrs[] = { "job-id",
	    "job-id-requested", NULL };

	status = papiPrinterListJobs(svc, printer, jattrs, PAPI_LIST_JOBS_ALL,
	    0, &jobs);

	if (status != PAPI_OK) {
		detailed_error(svc,
		    gettext("Failed to query service for %s: %s\n"),
		    printer, lpsched_status_string(status));
		return (-1);
	}

	if (jobs != NULL) {
		int i = 0;

		for (i = 0; jobs[i] != NULL; i++) {
			int32_t rid = -1;
			int32_t jid = -1;
			papi_attribute_t **list =
			    papiJobGetAttributeList(jobs[i]);

			papiAttributeListGetInteger(list, NULL,
			    "job-id-requested", &rid);
			papiAttributeListGetInteger(list, NULL,
			    "job-id", &jid);

			/*
			 * check if id matches with either rid or jid
			 */
			if (rid == id) {
				/* get the actual id and return it */
				papiAttributeListGetInteger(list, NULL,
				    "job-id", &id);
				return (id);
			} else if (jid == id) {
				if (rid != -1) {
					/*
					 * It is a remote lpd job.
					 * It cannot be modified based on job-id
					 * or spool number
					 */
					return (-1);
				} else {
					/*
					 * It is either local job or
					 * remote ipp job
					 */
					return (id);
				}
			}
		}
	}
	return (id);
}

void
papiJobFree(papi_job_t job)
{
	job_t *tmp = (job_t *)job;

	if (tmp != NULL) {
		papiAttributeListFree(tmp->attributes);
		free(tmp);
	}
}

void
papiJobListFree(papi_job_t *jobs)
{
	if (jobs != NULL) {
		int i;

		for (i = 0; jobs[i] != NULL; i++) {
			papiJobFree(jobs[i]);
		}
		free(jobs);
	}
}

papi_attribute_t **
papiJobGetAttributeList(papi_job_t job)
{
	job_t *tmp = (job_t *)job;

	if (tmp != NULL)
		return (tmp->attributes);

	return (NULL);
}

char *
papiJobGetPrinterName(papi_job_t job)
{
	job_t *tmp = (job_t *)job;
	char *result = NULL;

	if (tmp != NULL)
		papiAttributeListGetString(tmp->attributes, NULL,
		    "printer-name", &result);

	return (result);
}

int32_t
papiJobGetId(papi_job_t job)
{
	job_t *tmp = (job_t *)job;
	int result = -1;

	if (tmp != NULL)
		papiAttributeListGetInteger(tmp->attributes, NULL, "job-id",
		    &result);

	return (result);
}

static REQUEST *
create_request(papi_service_t svc, char *printer, papi_attribute_t **attributes)
{
	REQUEST *r;

	if ((r = calloc(1, sizeof (*r))) != NULL) {
		char *hostname = NULL;

		r->priority = -1;
		r->destination = printer_name_from_uri_id(printer, -1);

		papiAttributeListGetString(attributes, NULL,
		    "job-originating-host-name", &hostname);

		if (hostname == NULL) {
			char host[BUFSIZ];

			if (gethostname(host, sizeof (host)) == 0)
				papiAttributeListAddString(&attributes,
				    PAPI_ATTR_REPLACE,
				    "job-originating-host-name",
				    host);
		}

		job_attributes_to_lpsched_request(svc, r, attributes);
	}

	return (r);
}

static papi_status_t
authorized(service_t *svc, int32_t id)
{
	papi_status_t result = PAPI_NOT_AUTHORIZED;	/* assume the worst */
	char file[32];
	REQUEST *r;

	snprintf(file, sizeof (file), "%d-0", id);
	if ((r = getrequest(file)) != NULL) {
		uid_t uid = getuid();
		struct passwd *pw = NULL;
		char *user = "intruder";	/* assume an intruder */

		if ((pw = getpwuid(uid)) != NULL)
			user = pw->pw_name;	/* use the process owner */

		if ((uid == 0) || (uid == 71)) { /* root/lp can forge this */
			papi_status_t s;
			s = papiAttributeListGetString(svc->attributes, NULL,
			    "user-name", &user);
			if (s != PAPI_OK)	/* true root/lp are almighty */
				result = PAPI_OK;
		}

		if (result != PAPI_OK) {
			if (strcmp(user, r->user) == 0)
				result = PAPI_OK;
			else {
				/*
				 * user and r->user might contain the
				 * host info also
				 */
				char *token1 = strtok(r->user, "@");
				char *token2 = strtok(NULL, "@");
				char *token3 = strtok(user, "@");
				char *token4 = strtok(NULL, "@");

				/*
				 * token1 and token3 contain usernames
				 * token2 and token4 contain hostnames
				 */
				if ((token1 == NULL) || (token3 == NULL))
					result = PAPI_NOT_AUTHORIZED;
				else if ((token4 != NULL) &&
				    (strcmp(token4, "localhost") == 0) &&
				    (strcmp(token3, "root") == 0) ||
				    (strcmp(token3, "lp") == 0)) {
					/*
					 * root/lp user on server can
					 * cancel any requset
					 */
					result = PAPI_OK;
				} else if (strcmp(token1, token3) == 0) {
					/*
					 * usernames are same
					 * compare the hostnames
					 */
					if ((token4 != NULL) &&
					    (token2 != NULL) &&
					    (strcmp(token4, "localhost") ==
					    0)) {
						/*
						 * Its server machine
						 */
						static char host[256];
						if (gethostname(host,
						    sizeof (host)) == 0) {
							if ((host != NULL) &&
							    (strcmp(host,
							    token2) == 0))
								result =
								    PAPI_OK;
						}

					} else if ((token4 != NULL) &&
					    (token2 != NULL) &&
					    (strcmp(token4, token2) == 0)) {
						result = PAPI_OK;
					} else if ((token4 == NULL) &&
					    (token2 != NULL)) {
						/*
						 * When the request is sent from
						 * client to server using ipp
						 * token4 is NULL
						 */
						result = PAPI_OK;
					}
				}
			}
		}

		freerequest(r);
	} else
		result = PAPI_NOT_FOUND;

	return (result);
}

static papi_status_t
copy_file(char *from, char *to)
{
	int ifd, ofd;
	char buf[BUFSIZ];
	int rc;

	if ((ifd = open(from, O_RDONLY)) < 0)
		return (PAPI_DOCUMENT_ACCESS_ERROR);

	if ((ofd = open(to, O_WRONLY)) < 0) {
		close(ifd);
		return (PAPI_NOT_POSSIBLE);
	}

	while ((rc = read(ifd, buf, sizeof (buf))) > 0)
		write(ofd, buf, rc);

	close(ifd);
	close(ofd);

	return (PAPI_OK);
}


#ifdef LP_USE_PAPI_ATTR
/*
 * *****************************************************************************
 *
 * Description: Create a file containing all the attributes in the attribute
 *              list passed to this function.
 *              This file is then passed through lpsched and given to either
 *              a slow-filter or to the printer's interface script to process
 *              the attributes.
 *
 * Parameters:  attrs - list of attributes and their values
 *              file  - file pathname to create and put the attributes into.
 *
 * *****************************************************************************
 */

static papi_status_t
psm_copy_attrsToFile(papi_attribute_t **attrs, char *file)

{
	papi_status_t result = PAPI_OK;

	if ((attrs != NULL) && (*attrs != NULL)) {
		FILE *out = NULL;

		if ((out = fopen(file, "w")) != NULL) {
			papiAttributeListPrint(out, attrs, "");
			fclose(out);
		} else {
			result = PAPI_NOT_POSSIBLE;
		}
	}

	return (result);
} /* psm_copy_attrsToFile */


/*
 * *****************************************************************************
 *
 * Description: Modify the given attribute 'file' with the attributes from the
 *              'attrs' list. Attributes already in the file will be replaced
 *              with the new value. New attributes will be added into the file.
 *
 * Parameters:  attrs - list of attributes and their values
 *              file  - file pathname to create and put the attributes into.
 *
 * *****************************************************************************
 */

static papi_status_t
psm_modifyAttrsFile(papi_attribute_t **attrs, char *file)

{
	papi_status_t result = PAPI_OK;
	papi_attribute_t **newAttrs = NULL;
	struct stat   tmpBuf;
	FILE *fd = NULL;

	if ((attrs != NULL) && (*attrs != NULL) && (file != NULL)) {

		/*
		 * check file exist before try to modify it, if it doesn't
		 * exist assume there is an error
		 */
		if (stat(file, &tmpBuf) == 0) {
			/*
			 * if file is currently empty just write the given
			 * attributes to the file otherwise exact the attributes
			 * from the file and modify them accordingly before
			 * writing them back to the file
			 */
			if (tmpBuf.st_size == 0) {
				newAttrs = (papi_attribute_t **)attrs;

				fd = fopen(file, "w");
				if (fd != NULL) {
					papiAttributeListPrint(fd,
							newAttrs, "");
					fclose(fd);
				} else {
					result = PAPI_NOT_POSSIBLE;
				}
			} else {
				result =
				    psm_modifyAttrsList(file, attrs, &newAttrs);

				fd = fopen(file, "w");
				if (fd != NULL) {
					papiAttributeListPrint(fd,
								newAttrs, "");
					fclose(fd);
				} else {
					result = PAPI_NOT_POSSIBLE;
				}

				papiAttributeListFree(newAttrs);
			}
		} else {
			result = PAPI_NOT_POSSIBLE;
		}
	}

	return (result);
} /* psm_modifyAttrsFile */


/*
 * *****************************************************************************
 *
 * Description: Extracts the attributes in the given attribute 'file' and
 *              creates a new list 'newAttrs' containing the modified list of
 *              attributes.
 *
 * Parameters:  file  - pathname of file containing attributes to be modified
 *              attrs - list of attributes and their values to modify
 *              newAttrs - returns the modified list of attributes
 *
 * *****************************************************************************
 */

static papi_status_t
psm_modifyAttrsList(char *file, papi_attribute_t **attrs,
    papi_attribute_t ***newAttrs)

{
	papi_status_t result = PAPI_OK;
	papi_attribute_t  *nextAttr = NULL;
	papi_attribute_value_t  **values = NULL;
	void *iter = NULL;
	FILE *fd = NULL;
	register int fD = 0;
	char aBuff[200];
	char *a = NULL;
	char *p = NULL;
	int count = 0;
	int n = 0;

	fd = fopen(file, "r");
	if (fd != NULL) {
		fD = fileno(fd);
		a = &aBuff[0];
		p = &aBuff[0];
		count = read(fD, &aBuff[0], sizeof (aBuff) - 1);
		while ((result == PAPI_OK) && (count > 0)) {
			aBuff[count+n] = '\0';
			if (count == sizeof (aBuff) - n - 1) {
				p = strrchr(aBuff, '\n');
				if (p != NULL) {
					/* terminate at last complete line */
					*p = '\0';
				}
			}
			result = papiAttributeListFromString(
				newAttrs, PAPI_ATTR_EXCL, aBuff);

			if (result == PAPI_OK) {
				/*
				 * handle any part lines and then read the next
				 * buffer from the file
				 */
				n = 0;
				if (p != a) {
					p++; /* skip NL */
					n = sizeof (aBuff) - 1 - (p - a);
					strncpy(aBuff, p, n);
				}
				count = read(fD, &aBuff[n],
					sizeof (aBuff) - n - 1);
				p = &aBuff[0];
			}
		}
		fclose(fd);
	}

	/* now modify the attribute list with the new attributes in 'attrs' */

	nextAttr = papiAttributeListGetNext((papi_attribute_t **)attrs, &iter);
	while ((result == PAPI_OK) && (nextAttr != NULL)) {
		values = nextAttr->values;

		if ((values != NULL) && (*values != NULL)) {
			result = papiAttributeListAddValue(newAttrs,
						    PAPI_ATTR_REPLACE,
						    nextAttr->name,
						    nextAttr->type, *values);
			values++;
		}

		while ((result == PAPI_OK) &&
			(values != NULL) && (*values != NULL)) {
			result = papiAttributeListAddValue(newAttrs,
						    PAPI_ATTR_APPEND,
						    nextAttr->name,
						    nextAttr->type, *values);
			values++;
		}
		nextAttr =
		    papiAttributeListGetNext((papi_attribute_t **)attrs, &iter);
	}

	return (result);
} /* papi_modifyAttrsList() */
#endif


papi_status_t
papiJobSubmit(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket,
		char **files, papi_job_t *job)
{
	papi_status_t status;
	service_t *svc = handle;
	struct stat statbuf;
	job_t *j;
	int file_no;
	char *request_id = NULL;
	REQUEST *request;
	int i;
	char *c;
	char *tmp = NULL;
	char lpfile[BUFSIZ];

	if ((svc == NULL) || (printer == NULL) || (files == NULL) ||
	    (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (job_ticket != NULL)
		return (PAPI_OPERATION_NOT_SUPPORTED);

	if (files != NULL)
		for (file_no = 0; files[file_no] != NULL; file_no++) {
			if (access(files[file_no], R_OK) < 0) {
				detailed_error(svc,
				    gettext("Cannot access file: %s: %s"),
				    files[file_no], strerror(errno));
				return (PAPI_BAD_ARGUMENT);
			}
			if (stat(files[file_no], &statbuf) < 0) {
				detailed_error(svc,
				    gettext("Cannot access file: %s: %s"),
				    files[file_no], strerror(errno));
				return (PAPI_DOCUMENT_ACCESS_ERROR);
			}
			if (statbuf.st_size == 0) {
				detailed_error(svc,
				    gettext("Zero byte (empty) file: %s"),
				    files[file_no]);
				return (PAPI_BAD_ARGUMENT);
			}
		}

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	/* file_no + 1 for the control file (-0) */
	status = lpsched_alloc_files(svc, file_no + 1, &request_id);
	if (status != PAPI_OK)
		return (status);

	request = create_request(svc, (char *)printer,
	    (papi_attribute_t **)job_attributes);

	for (i = 0; files[i] != NULL; i++) {
		papi_status_t status;
		snprintf(lpfile, sizeof (lpfile), "%s%s-%d",
		    "/var/spool/lp/temp/", request_id, i+1);
		status = copy_file(files[i], lpfile);
		if (status != PAPI_OK) {
			detailed_error(svc,
			    gettext("unable to copy: %s -> %s: %s"),
			    files[i], lpfile, strerror(errno));
				freerequest(request);
			return (PAPI_DEVICE_ERROR);
		}
		addlist(&(request->file_list), lpfile);
	}

#ifdef LP_USE_PAPI_ATTR
	/*
	 * store the job attributes in the PAPI job attribute file that was
	 * created by lpsched_alloc_files(), the attributes will then pass
	 * through lpsched and be given to the slow-filters and the printer's
	 * interface script to process them
	 */
	snprintf(lpfile, sizeof (lpfile), "%s%s-%s",
	    "/var/spool/lp/temp/", request_id, LP_PAPIATTRNAME);
	status = psm_copy_attrsToFile(job_attributes, lpfile);
	if (status != PAPI_OK) {
		detailed_error(svc, "unable to copy attributes to file: %s: %s",
		    lpfile, strerror(errno));
		return (PAPI_DEVICE_ERROR);
	}
#endif

	/* store the meta-data file */
	snprintf(lpfile, sizeof (lpfile), "%s-0", request_id);
	if (putrequest(lpfile, request) < 0) {
		detailed_error(svc, gettext("unable to save request: %s: %s"),
		    lpfile, strerror(errno));
		freerequest(request);
		return (PAPI_DEVICE_ERROR);
	}

	status = lpsched_commit_job(svc, lpfile, &tmp);
	if (status != PAPI_OK) {
		unlink(lpfile);
		freerequest(request);
		return (status);
	}

	lpsched_request_to_job_attributes(request, j);
	freerequest(request);

	if ((c = strrchr(tmp, '-')) != NULL)
		c++;
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
	    "job-id", atoi(c));
	papiAttributeListAddString(&j->attributes, PAPI_ATTR_REPLACE,
	    "job-uri", tmp);

	return (PAPI_OK);
}

papi_status_t
papiJobSubmitByReference(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket,
		char **files, papi_job_t *job)
{
	service_t *svc = handle;
	struct stat statbuf;
	job_t *j;
	int file_no;
	short status;
	char *request_id = NULL;
	REQUEST *request;
	char *c;
	char *tmp = NULL;
	char lpfile[BUFSIZ];
	char **file_list = NULL;

	if ((svc == NULL) || (printer == NULL) || (files == NULL) ||
	    (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (job_ticket != NULL)
		return (PAPI_OPERATION_NOT_SUPPORTED);

	if (files != NULL)
		for (file_no = 0; files[file_no] != NULL; file_no++) {
			if (access(files[file_no], R_OK) < 0) {
				detailed_error(svc,
				    gettext("Cannot access file: %s: %s"),
				    files[file_no], strerror(errno));
				return (PAPI_DOCUMENT_ACCESS_ERROR);
			}
			if (stat(files[file_no], &statbuf) < 0) {
				detailed_error(svc,
				    gettext("Cannot access file: %s: %s"),
				    files[file_no], strerror(errno));
				return (PAPI_DOCUMENT_ACCESS_ERROR);
			}
			if (statbuf.st_size == 0) {
				detailed_error(svc,
				    gettext("Zero byte (empty) file: %s"),
				    files[file_no]);
				return (PAPI_BAD_ARGUMENT);
			}

			if (files[file_no][0] != '/') {
				char path[MAXPATHLEN];

				if (getcwd(path, sizeof (path)) == NULL) {
					detailed_error(svc, gettext(
					    "getcwd for file: %s: %s"),
					    files[file_no],
					    strerror(errno));
					return (PAPI_DOCUMENT_ACCESS_ERROR);
				}
				strlcat(path, "/", sizeof (path));
				if (strlcat(path, files[file_no], sizeof (path))
				    >= sizeof (path)) {
					detailed_error(svc, gettext(
					    "pathname too long: %s"),
					    files[file_no]);
					return (PAPI_DOCUMENT_ACCESS_ERROR);
				}
				addlist(&file_list, path);
			} else
				addlist(&file_list, (char *)files[file_no]);
		}

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	/* 1 for the control file (-0) */
	status = lpsched_alloc_files(svc, 1, &request_id);
	if (status != PAPI_OK)
		return (status);

	request = create_request(svc, (char *)printer,
	    (papi_attribute_t **)job_attributes);
	request->file_list = file_list;

#ifdef LP_USE_PAPI_ATTR
	/*
	 * store the job attributes in the PAPI job attribute file that was
	 * created by lpsched_alloc_files(), the attributes will then pass
	 * through lpsched and be given to the slow-filters and the printer's
	 * interface script to process them
	 */
	snprintf(lpfile, sizeof (lpfile), "%s%s-%s",
	    "/var/spool/lp/temp/", request_id, LP_PAPIATTRNAME);
	status = psm_copy_attrsToFile(job_attributes, lpfile);
	if (status != PAPI_OK) {
		detailed_error(svc, "unable to copy attributes to file: %s: %s",
		    lpfile, strerror(errno));
		return (PAPI_DEVICE_ERROR);
	}
#endif

	/* store the meta-data file */
	snprintf(lpfile, sizeof (lpfile), "%s-0", request_id);
	if (putrequest(lpfile, request) < 0) {
		detailed_error(svc, gettext("unable to save request: %s: %s"),
		    lpfile, strerror(errno));
		freerequest(request);
		return (PAPI_DEVICE_ERROR);
	}

	status = lpsched_commit_job(svc, lpfile, &tmp);
	if (status != PAPI_OK) {
		unlink(lpfile);
		freerequest(request);
		return (status);
	}

	lpsched_request_to_job_attributes(request, j);

	freerequest(request);

	if ((c = strrchr(tmp, '-')) != NULL)
		c++;
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
	    "job-id", atoi(c));
	papiAttributeListAddString(&j->attributes, PAPI_ATTR_REPLACE,
	    "job-uri", tmp);

	return (PAPI_OK);
}

papi_status_t
papiJobValidate(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket,
		char **files, papi_job_t *job)
{
	papi_status_t status;
	papi_attribute_t **attributes = NULL;
	int i;

	papiAttributeListAddString(&attributes, PAPI_ATTR_REPLACE,
	    "job-hold-until", "indefinite");
	for (i = 0; job_attributes[i]; i++)
		list_append(&attributes, job_attributes[i]);

	status = papiJobSubmitByReference(handle, printer,
	    (papi_attribute_t **)attributes,
	    job_ticket, files, job);
	if (status == PAPI_OK) {
		int id = papiJobGetId(*job);

		if (id != -1)
			papiJobCancel(handle, printer, id);
	}

	attributes[1] = NULL;	/* after attr[0], they are in another list */
	papiAttributeListFree(attributes);

	return (status);
}

papi_status_t
papiJobStreamOpen(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, papi_stream_t *stream)
{
	papi_status_t status;
	service_t *svc = handle;
	job_stream_t *s = NULL;
	char *request_id = NULL;
	char lpfile[BUFSIZ];

	if ((svc == NULL) || (printer == NULL) || (stream == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (job_ticket != NULL)
		return (PAPI_OPERATION_NOT_SUPPORTED);

	if ((*stream = s = calloc(1, sizeof (*s))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	/* 1 for data, 1 for the meta-data (-0) */
	status = lpsched_alloc_files(svc, 2, &request_id);
	if (status != PAPI_OK)
		return (status);

	papiAttributeListAddString(&job_attributes, PAPI_ATTR_EXCL,
	    "job-name", "standard input");

	s->request = create_request(svc, (char *)printer,
	    (papi_attribute_t **)job_attributes);
	snprintf(lpfile, sizeof (lpfile), "/var/spool/lp/temp/%s-1",
	    request_id);
	s->fd = open(lpfile, O_WRONLY);
	addlist(&(s->request->file_list), lpfile);

#ifdef LP_USE_PAPI_ATTR
	/*
	 * store the job attributes in the PAPI job attribute file that was
	 * created by lpsched_alloc_files(), the attributes will then pass
	 * through lpsched and be given to the slow-filters and the printer's
	 * interface script to process them
	 */
	snprintf(lpfile, sizeof (lpfile), "%s%s-%s",
	    "/var/spool/lp/temp/", request_id, LP_PAPIATTRNAME);
	status = psm_copy_attrsToFile(job_attributes, lpfile);
	if (status != PAPI_OK) {
		detailed_error(svc, "unable to copy attributes to file: %s: %s",
		    lpfile, strerror(errno));
		close(s->fd);
		free(s);
		return (PAPI_DEVICE_ERROR);
	}
#endif

	/* store the meta-data file */
	snprintf(lpfile, sizeof (lpfile), "%s-0", request_id);
	s->meta_data_file = strdup(lpfile);
	if (putrequest(lpfile, s->request) < 0) {
		detailed_error(svc, gettext("unable to save request: %s: %s"),
		    lpfile, strerror(errno));
		s->request = NULL;
		return (PAPI_DEVICE_ERROR);
	}

	return (PAPI_OK);
}

papi_status_t
papiJobStreamWrite(papi_service_t handle,
		papi_stream_t stream, void *buffer, size_t buflen)
{
	service_t *svc = handle;
	job_stream_t *s = stream;

	if ((svc == NULL) || (stream == NULL) || (buffer == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (write(s->fd, buffer, buflen) != buflen)
		return (PAPI_DEVICE_ERROR);

	return (PAPI_OK);
}
papi_status_t
papiJobStreamClose(papi_service_t handle,
		papi_stream_t stream, papi_job_t *job)
{
	papi_status_t status = PAPI_OK;
	service_t *svc = handle;
	job_stream_t *s = stream;
	job_t *j = NULL;
	char *tmp = NULL, *c;

	if ((svc == NULL) || (stream == NULL) || (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	close(s->fd);

	lpsched_request_to_job_attributes(s->request, j);

	if (s->meta_data_file != NULL) {
		status = lpsched_commit_job(svc, s->meta_data_file, &tmp);
		if (status != PAPI_OK) {
			unlink(s->meta_data_file);
			return (status);
		}
		if ((c = strrchr(tmp, '-')) != NULL)
			c++;
		papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
		    "job-id", atoi(c));
		papiAttributeListAddString(&j->attributes, PAPI_ATTR_REPLACE,
		    "job-uri", tmp);
		free(s->meta_data_file);
	}
	freerequest(s->request);
	free(s);

	return (PAPI_OK);
}

papi_status_t
papiJobQuery(papi_service_t handle, char *printer, int32_t job_id,
		char **requested_attrs,
		papi_job_t *job)
{
	service_t *svc = handle;
	job_t *j;
	char *dest;
	char req_id[32];
	short rc;
	char *form = NULL,
	    *request_id = NULL,
	    *charset = NULL,
	    *user = NULL,
	    *slabel = NULL,
	    *file = NULL;
	time_t date = 0;
	size_t size = 0;
	short  rank = 0,
	    state = 0;

	if ((handle == NULL) || (printer == NULL) || (job_id < 0))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(printer, job_id);
	snprintf(req_id, sizeof (req_id), "%s-%d", dest, job_id);
	free(dest);

	rc = snd_msg(svc, S_INQUIRE_REQUEST_RANK, 0, "", "", req_id, "", "");
	if (rc < 0)
		return (PAPI_SERVICE_UNAVAILABLE);

	if (rcv_msg(svc, R_INQUIRE_REQUEST_RANK, &rc, &request_id,
	    &user, &slabel, &size, &date, &state, &dest, &form,
	    &charset, &rank, &file) < 0) {
		detailed_error(svc,
		    gettext("failed to read response from scheduler"));
		return (PAPI_DEVICE_ERROR);
	}

	if ((request_id == NULL) || (request_id[0] == '\0'))
		return (PAPI_NOT_FOUND);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	snprintf(req_id, sizeof (req_id), "%d-0", job_id);
	lpsched_read_job_configuration(svc, j, req_id);

	job_status_to_attributes(j, request_id, user, slabel, size, date, state,
	    dest, form, charset, rank, file);

	return (PAPI_OK);
}

papi_status_t
papiJobMove(papi_service_t handle, char *printer, int32_t job_id,
		char *destination)
{
	papi_status_t result = PAPI_OK;
	long bits;
	service_t *svc = handle;
	char req_id[64];
	char *queue;
	char *user = NULL;

	if ((svc == NULL) || (printer == NULL) || (job_id < 0) ||
	    (destination == NULL))
		return (PAPI_BAD_ARGUMENT);

	queue = printer_name_from_uri_id(printer, job_id);
	snprintf(req_id, sizeof (req_id), "%s-%d", queue, job_id);
	free(queue);

	if (papiAttributeListGetString(svc->attributes, NULL, "user-name",
	    &user) == PAPI_OK) {
		REQUEST *r = getrequest(req_id);

		if ((r != NULL) && (r->user != NULL) &&
		    (strcmp(r->user, user) != 0))
			result = PAPI_NOT_AUTHORIZED;
		freerequest(r);
	}

	if (result == PAPI_OK) {
		short status = MOK;
		char *dest = printer_name_from_uri_id(destination, -1);

		if ((snd_msg(svc, S_MOVE_REQUEST, req_id, dest) < 0) ||
		    (rcv_msg(svc, R_MOVE_REQUEST, &status, &bits) < 0))
			status = MTRANSMITERR;

		free(dest);

		result = lpsched_status_to_papi_status(status);
	}

	return (result);
}

papi_status_t
papiJobCancel(papi_service_t handle, char *printer, int32_t job_id)
{
	papi_status_t result = PAPI_OK;
	service_t *svc = handle;
	char req_id[64];
	char *dest;
	char *user = NULL;

	if ((svc == NULL) || (printer == NULL) || (job_id < 0))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(printer, job_id);
	snprintf(req_id, sizeof (req_id), "%s-%d", dest, job_id);
	free(dest);

	if (papiAttributeListGetString(svc->attributes, NULL, "user-name",
	    &user) == PAPI_OK) {
		REQUEST *r = getrequest(req_id);

		if ((result = authorized(handle, job_id)) != PAPI_OK)
			result = PAPI_NOT_AUTHORIZED;

		if ((r != NULL) && (r->user != NULL) &&
		    (strcmp(r->user, user) != 0))
			result = PAPI_NOT_AUTHORIZED;
		freerequest(r);
	}

	if (result == PAPI_OK) {
		short status = MOK;

		if ((snd_msg(svc, S_CANCEL_REQUEST, req_id) < 0) ||
		    (rcv_msg(svc, R_CANCEL_REQUEST, &status) < 0))
			status = MTRANSMITERR;

		result = lpsched_status_to_papi_status(status);
	}

	return (result);
}

papi_status_t
hold_release_job(papi_service_t handle, char *printer,
		int32_t job_id, int flag)
{
	papi_status_t status;
	service_t *svc = handle;
	REQUEST *r = NULL;
	char *file;
	char *dest;

	if ((svc == NULL) || (printer == NULL) || (job_id < 0))
		return (PAPI_BAD_ARGUMENT);

	if ((status = authorized(svc, job_id)) != PAPI_OK)
		return (status);

	dest = printer_name_from_uri_id(printer, job_id);
	status = lpsched_start_change(svc, dest, job_id, &file);
	if (status != PAPI_OK)
		return (status);

	if ((r = getrequest(file)) != NULL) {
		r->actions &= ~ACT_RESUME;
		switch (flag) {
		case 0:
			r->actions |= ACT_HOLD;
			break;
		case 1:
			r->actions |= ACT_RESUME;
			break;
		case 2:
			r->actions |= ACT_IMMEDIATE;
			break;
		}
		if (putrequest(file, r) < 0) {
			detailed_error(svc,
			    gettext("failed to write job: %s: %s"),
			    file, strerror(errno));
			freerequest(r);
			return (PAPI_DEVICE_ERROR);
		}
		freerequest(r);
	} else {
		detailed_error(svc, gettext("failed to read job: %s: %s"),
		    file, strerror(errno));
		return (PAPI_DEVICE_ERROR);
	}

	status = lpsched_end_change(svc, dest, job_id);

	return (status);
}

papi_status_t
papiJobHold(papi_service_t handle, char *printer, int32_t job_id)
{
	return (hold_release_job(handle, printer, job_id, 0));
}

papi_status_t
papiJobRelease(papi_service_t handle, char *printer, int32_t job_id)
{
	return (hold_release_job(handle, printer, job_id, 1));
}

papi_status_t
papiJobPromote(papi_service_t handle, char *printer, int32_t job_id)
{
	return (hold_release_job(handle, printer, job_id, 2));
}

papi_status_t
papiJobModify(papi_service_t handle, char *printer, int32_t job_id,
		papi_attribute_t **attributes, papi_job_t *job)
{
	papi_status_t status;
	job_t *j = NULL;
	service_t *svc = handle;
	char *file = NULL;
	char *dest;
	REQUEST *r = NULL;
	char lpfile[BUFSIZ];
	int32_t job_id_actual;

	if ((svc == NULL) || (printer == NULL) || (job_id < 0) ||
	    (attributes == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	dest = printer_name_from_uri_id(printer, job_id);

	/*
	 * job-id might be job-id-requested
	 * If it is job-id-requested then we need to
	 * look for corresponding job-id
	 */
	job_id_actual = check_job_id(svc, printer, job_id);

	if (job_id_actual < 0) {
		status = PAPI_NOT_FOUND;
		detailed_error(svc,
		    "failed to initiate change for job (%s-%d): %s",
		    dest, job_id, "no such resource");
		return (status);
	}

	status = lpsched_start_change(svc, dest, job_id_actual, &file);
	if (status != PAPI_OK)
		return (status);

	if ((r = getrequest(file)) != NULL) {
		job_attributes_to_lpsched_request(handle, r,
		    (papi_attribute_t **)attributes);
#ifdef LP_USE_PAPI_ATTR
		/*
		 * store the job attributes in the PAPI job attribute file
		 * that was created by the original job request. We need to
		 * modify the attributes in the file as per the new attributes
		 */
		snprintf(lpfile, sizeof (lpfile), "%s%d-%s",
		    "/var/spool/lp/temp/", job_id_actual, LP_PAPIATTRNAME);
		status = psm_modifyAttrsFile(attributes, lpfile);
		if (status != PAPI_OK) {
			detailed_error(svc,
			    "unable to modify the attributes file: %s: %s",
			    lpfile, strerror(errno));
			return (PAPI_DEVICE_ERROR);
		}
#endif

		if (putrequest(file, r) < 0) {
			detailed_error(svc,
			    gettext("failed to write job: %s: %s"),
			    file, strerror(errno));
			freerequest(r);
			return (PAPI_DEVICE_ERROR);
		}
	} else {
		detailed_error(svc, gettext("failed to read job: %s: %s"),
		    file, strerror(errno));
		return (PAPI_DEVICE_ERROR);
	}

	status = lpsched_end_change(svc, dest, job_id_actual);
	lpsched_request_to_job_attributes(r, j);

	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
	    "job-id", job_id_actual);

	freerequest(r);

	return (status);
}

/*
 * Extension to PAPI, a variation of this is slated for post-1.0
 */
#define	DUMMY_FILE	"/var/spool/lp/fifos/FIFO"

papi_status_t
papiJobCreate(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, papi_job_t *job)
{
	papi_status_t status;
	service_t *svc = handle;
	job_t *j = NULL;
	REQUEST *request;
	char *request_id = NULL;
	char *c;
	char *tmp = NULL;
	char metadata_file[MAXPATHLEN];

	if ((svc == NULL) || (printer == NULL) || (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (job_ticket != NULL)
		return (PAPI_JOB_TICKET_NOT_SUPPORTED);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	/* 1 for the control file (-0) */
	status = lpsched_alloc_files(svc, 1, &request_id);
	if (status != PAPI_OK)
		return (status);

	/* convert the attributes to an lpsched REQUEST structure */
	request = create_request(svc, (char *)printer,
	    (papi_attribute_t **)job_attributes);
	if (request == NULL)
		return (PAPI_TEMPORARY_ERROR);
	addlist(&request->file_list, DUMMY_FILE);	/* add a dummy file */
	request->actions |= ACT_HOLD;			/* hold the job */

#ifdef LP_USE_PAPI_ATTR
	/*
	 * store the job attributes in the PAPI job attribute file that was
	 * created by lpsched_alloc_files(), the attributes will then pass
	 * through lpsched and be given to the slow-filters and the printer's
	 * interface script to process them
	 */
	snprintf(metadata_file, sizeof (metadata_file), "%s%s-%s",
	    "/var/spool/lp/temp/", request_id, LP_PAPIATTRNAME);
	status = psm_copy_attrsToFile(job_attributes, metadata_file);
	if (status != PAPI_OK) {
		detailed_error(svc, "unable to copy attributes to file: %s: %s",
		    metadata_file, strerror(errno));
		free(request_id);
		return (PAPI_DEVICE_ERROR);
	}
#endif

	/* store the REQUEST on disk */
	snprintf(metadata_file, sizeof (metadata_file), "%s-0", request_id);
	free(request_id);
	if (putrequest(metadata_file, request) < 0) {
		detailed_error(svc, gettext("unable to save request: %s: %s"),
		    metadata_file, strerror(errno));
		return (PAPI_DEVICE_ERROR);
	}

	status = lpsched_commit_job(svc, metadata_file, &tmp);
	if (status != PAPI_OK) {
		unlink(metadata_file);
		return (status);
	}

	lpsched_request_to_job_attributes(request, j);

	if ((c = strrchr(tmp, '-')) != NULL)
		c++;
	papiAttributeListAddInteger(&j->attributes, PAPI_ATTR_REPLACE,
	    "job-id", atoi(c));
	papiAttributeListAddString(&j->attributes, PAPI_ATTR_REPLACE,
	    "job-uri", tmp);

	return (PAPI_OK);
}

papi_status_t
papiJobCommit(papi_service_t handle, char *printer, int32_t id)
{
	papi_status_t status = PAPI_OK;
	service_t *svc = handle;
	REQUEST *r = NULL;
	char *metadata_file;
	char *dest;

	if ((svc == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(printer, id);
	/* tell the scheduler that we want to change the job */
	status = lpsched_start_change(svc, dest, id, &metadata_file);
	if (status != PAPI_OK)
		return (status);

	if ((r = getrequest(metadata_file)) != NULL) {
		r->actions &= ~ACT_RESUME;
		r->actions |= ACT_RESUME;
		dellist(&r->file_list, DUMMY_FILE);

		if (putrequest(metadata_file, r) < 0) {
			detailed_error(svc,
			    gettext("failed to write job: %s: %s"),
			    metadata_file, strerror(errno));
			freerequest(r);
			return (PAPI_DEVICE_ERROR);
		}
	} else {
		detailed_error(svc, gettext("failed to read job: %s: %s"),
		    metadata_file, strerror(errno));
		return (PAPI_DEVICE_ERROR);
	}

	status = lpsched_end_change(svc, dest, id);
	freerequest(r);

	return (status);
}

papi_status_t
papiJobStreamAdd(papi_service_t handle, char *printer, int32_t id,
		papi_stream_t *stream)
{
	papi_status_t status;
	service_t *svc = handle;
	job_stream_t *s = NULL;
	char *metadata_file = NULL;
	char *dest;
	char path[MAXPATHLEN];

	/* allocate space for the stream */
	if ((*stream = s = calloc(1, sizeof (*s))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	dest = printer_name_from_uri_id(printer, id);
	/* create/open data file (only root or lp can really do this */
	snprintf(path, sizeof (path), "/var/spool/lp/temp/%d-XXXXXX", id);
	if ((s->fd = mkstemp(path)) < 0) {
		detailed_error(svc, gettext("unable to create sink (%s): %s"),
		    path, strerror(errno));
		free(s);
		return (PAPI_NOT_AUTHORIZED);
	}

	/* add data file to job */
	status = lpsched_start_change(svc, dest, id, &metadata_file);
	if (status != PAPI_OK) {
		close(s->fd);
		free(s);
		unlink(path);
		return (status);
	}

	if ((s->request = getrequest(metadata_file)) == NULL) {
		detailed_error(svc, gettext("unable to load request: %s: %s"),
		    metadata_file, strerror(errno));
		close(s->fd);
		free(s);
		unlink(path);
		return (PAPI_NOT_POSSIBLE);
	}

	addlist(&(s->request->file_list), path);

	if (putrequest(metadata_file, s->request) < 0) {
		detailed_error(svc, gettext("unable to save request: %s: %s"),
		    metadata_file, strerror(errno));
		close(s->fd);
		free(s);
		unlink(path);
		return (PAPI_NOT_POSSIBLE);
	}

	status = lpsched_end_change(svc, dest, id);

	if (status != PAPI_OK)
		return (status);

	return (PAPI_OK);
}
