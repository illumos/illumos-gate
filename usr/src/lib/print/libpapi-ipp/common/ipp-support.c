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

/* $Id: ipp-support.c 148 2006-04-25 16:54:17Z njacobs $ */


#include <papi_impl.h>
#include <stdlib.h>
#include <pwd.h>
#include <locale.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <md5.h>

#include <config-site.h>

#include <ipp.h>

static void ipp_add_printer_uri(service_t *svc, char *name,
		papi_attribute_t ***op);

papi_status_t
http_to_papi_status(http_status_t status)
{
	switch (status) {
	case HTTP_OK:
		return (PAPI_OK);
	case HTTP_BAD_REQUEST:
		return (PAPI_BAD_REQUEST);
	case HTTP_UNAUTHORIZED:
	case HTTP_FORBIDDEN:
		return (PAPI_NOT_AUTHORIZED);
	case HTTP_NOT_FOUND:
		return (PAPI_NOT_FOUND);
	case HTTP_GONE:
		return (PAPI_GONE);
	case HTTP_SERVICE_UNAVAILABLE:
		return (PAPI_SERVICE_UNAVAILABLE);
	default:
		return ((papi_status_t)status);
	}
}

papi_status_t
ipp_to_papi_status(uint16_t status)
{
	switch (status) {
	case IPP_OK:
		return (PAPI_OK);
	case IPP_OK_IGNORED_ATTRIBUTES:
		return (PAPI_OK);
	case IPP_OK_CONFLICTING_ATTRIBUTES:
		return (PAPI_OK);
	case IPP_OK_IGNORED_SUBSCRIPTIONS:
		return (PAPI_OK_IGNORED_SUBSCRIPTIONS);
	case IPP_OK_IGNORED_NOTIFICATIONS:
		return (PAPI_OK_IGNORED_NOTIFICATIONS);
	case IPP_CERR_BAD_REQUEST:
		return (PAPI_BAD_REQUEST);
	case IPP_CERR_FORBIDDEN:
		return (PAPI_FORBIDDEN);
	case IPP_CERR_NOT_AUTHENTICATED:
		return (PAPI_NOT_AUTHENTICATED);
	case IPP_CERR_NOT_AUTHORIZED:
		return (PAPI_NOT_AUTHORIZED);
	case IPP_CERR_NOT_POSSIBLE:
		return (PAPI_NOT_POSSIBLE);
	case IPP_CERR_TIMEOUT:
		return (PAPI_TIMEOUT);
	case IPP_CERR_NOT_FOUND:
		return (PAPI_NOT_FOUND);
	case IPP_CERR_GONE:
		return (PAPI_GONE);
	case IPP_CERR_REQUEST_ENTITY:
		return (PAPI_REQUEST_ENTITY);
	case IPP_CERR_REQUEST_VALUE:
		return (PAPI_REQUEST_VALUE);
	case IPP_CERR_DOCUMENT_FORMAT:
		return (PAPI_DOCUMENT_FORMAT);
	case IPP_CERR_ATTRIBUTES:
		return (PAPI_ATTRIBUTES);
	case IPP_CERR_URI_SCHEME:
		return (PAPI_URI_SCHEME);
	case IPP_CERR_CHARSET:
		return (PAPI_CHARSET);
	case IPP_CERR_CONFLICT:
		return (PAPI_CONFLICT);
	case IPP_CERR_COMPRESSION_NOT_SUPPORTED:
		return (PAPI_COMPRESSION_NOT_SUPPORTED);
	case IPP_CERR_COMPRESSION_ERROR:
		return (PAPI_COMPRESSION_ERROR);
	case IPP_CERR_DOCUMENT_FORMAT_ERROR:
		return (PAPI_DOCUMENT_FORMAT_ERROR);
	case IPP_CERR_DOCUMENT_ACCESS_ERROR:
		return (PAPI_DOCUMENT_ACCESS_ERROR);
	case IPP_CERR_ATTRIBUTES_NOT_SETTABLE:
		return (PAPI_ATTRIBUTES_NOT_SETTABLE);
	case IPP_CERR_IGNORED_ALL_SUBSCRIPTIONS:
		return (PAPI_IGNORED_ALL_SUBSCRIPTIONS);
	case IPP_CERR_TOO_MANY_SUBSCRIPTIONS:
		return (PAPI_TOO_MANY_SUBSCRIPTIONS);
	case IPP_CERR_IGNORED_ALL_NOTIFICATIONS:
		return (PAPI_IGNORED_ALL_NOTIFICATIONS);
	case IPP_CERR_PRINT_SUPPORT_FILE_NOT_FOUND:
		return (PAPI_PRINT_SUPPORT_FILE_NOT_FOUND);
	case IPP_SERR_INTERNAL:
		return (PAPI_INTERNAL_ERROR);
	case IPP_SERR_OPERATION_NOT_SUPPORTED:
		return (PAPI_OPERATION_NOT_SUPPORTED);
	case IPP_SERR_SERVICE_UNAVAILABLE:
		return (PAPI_SERVICE_UNAVAILABLE);
	case IPP_SERR_VERSION_NOT_SUPPORTED:
		return (PAPI_VERSION_NOT_SUPPORTED);
	case IPP_SERR_DEVICE_ERROR:
		return (PAPI_DEVICE_ERROR);
	case IPP_SERR_TEMPORARY_ERROR:
		return (PAPI_TEMPORARY_ERROR);
	case IPP_SERR_NOT_ACCEPTING:
		return (PAPI_NOT_ACCEPTING);
	case IPP_SERR_BUSY:
	case IPP_SERR_CANCELLED:
	default:
		return (PAPI_TEMPORARY_ERROR);
	}
}

void
ipp_initialize_request(service_t *svc, papi_attribute_t ***request,
		uint16_t operation)
{
	papiAttributeListAddInteger(request, PAPI_ATTR_EXCL,
	    "version-major", 1);
	papiAttributeListAddInteger(request, PAPI_ATTR_EXCL,
	    "version-minor", 1);
	papiAttributeListAddInteger(request, PAPI_ATTR_EXCL,
	    "request-id", (short)lrand48());
	papiAttributeListAddInteger(request, PAPI_ATTR_EXCL,
	    "operation-id", operation);
}

void
ipp_initialize_operational_attributes(service_t *svc, papi_attribute_t ***op,
		char *printer, int job_id)
{
	char *charset = "utf-8"; /* default to UTF-8 encoding */
	char *language = setlocale(LC_ALL, "");
	char *user = "nobody";
	struct passwd *pw = NULL;

	/*
	 * All IPP requests must contain the following:
	 * 	attributes-charset		(UTF-8)
	 *	attributes-natural-language	(our current locale)
	 *	(object identifier)		printer-uri/job-id or job-uri
	 *	requesting-user-name		(process user or none)
	 */
	papiAttributeListAddString(op, PAPI_ATTR_EXCL,
	    "attributes-charset", charset);

	papiAttributeListAddString(op, PAPI_ATTR_EXCL,
	    "attributes-natural-language", language);

	if (printer != NULL)
		ipp_add_printer_uri(svc, printer, op);

	if ((printer != NULL) && (job_id >= 0))
		papiAttributeListAddInteger(op, PAPI_ATTR_EXCL,
		    "job-id", job_id);

	if ((pw = getpwuid(getuid())) != NULL)
		user = pw->pw_name;
	/*
	 * if our euid is 0 "super user", we will allow the system supplied
	 * user name to be overridden, if the requestor wants to.
	 */
	if (geteuid() == 0) {
		if (svc->user != NULL)
			user = svc->user;
	}
	papiAttributeListAddString(op, PAPI_ATTR_REPLACE,
	    "requesting-user-name", user);
}

#ifndef OPID_CUPS_GET_DEFAULT	   /* for servers that will enumerate */
#define	OPID_CUPS_GET_DEFAULT	   0x4001
#endif  /* OPID_CUPS_GET_DEFAULT */

static papi_status_t
_default_destination(service_t *svc, char **uri)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	printer_t *p = NULL;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;
	char *tmp = NULL;

	if ((svc == NULL) || (uri == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* we must be connected to find the default destination */
	if (svc->connection == NULL)
		return (PAPI_NOT_POSSIBLE);

	if ((p = calloc(1, sizeof (*p))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	ipp_initialize_request(svc, &request, OPID_CUPS_GET_DEFAULT);
	ipp_initialize_operational_attributes(svc, &op, NULL, -1);
	papiAttributeListAddString(&op, PAPI_ATTR_APPEND,
	    "requested-attributes", "printer-uri-supported");
	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
	    "operational-attributes-group", op);
	papiAttributeListFree(op);
	result = ipp_send_request(svc, request, &response);
	papiAttributeListFree(request);

	op = NULL;
	papiAttributeListGetCollection(response, NULL,
	    "printer-attributes-group", &op);

	if (uri != NULL) {
		char *tmp = NULL;

		papiAttributeListGetString(op, NULL, "printer-uri", &tmp);
		papiAttributeListGetString(op, NULL,
		    "printer-uri-supported", &tmp);
		if (tmp != NULL)
			*uri = strdup(tmp);
	}

	papiAttributeListFree(response);

	return (result);
}

static void
ipp_add_printer_uri(service_t *svc, char *name, papi_attribute_t ***op)
{
	char *uri = name;
	char buf[BUFSIZ];
	uri_t *tmp = NULL;

	if (strstr(name, "://") == NULL) { /* not in URI form */
		if (strcmp(name, DEFAULT_DEST) != 0) {
			/* not the "default" */
			snprintf(buf, sizeof (buf), "%s/%s", svc->name, name);
			uri = buf;
		} else
			_default_destination(svc, &uri);
	}

	papiAttributeListAddString(op, PAPI_ATTR_EXCL, "printer-uri", uri);

	/* save the printer-uri's path to be used by http POST request */
	if ((uri_from_string(uri, &tmp) == 0) && (tmp != NULL)) {
		if (svc->post != NULL)
			free(svc->post);
		svc->post = strdup(tmp->path);
		uri_free(tmp);
	}
}


/*
 * don't actually write anything, just add to the total size and return the
 * size of what would be written, so we can figure out how big the request
 * is going to be.
 */
static ssize_t
size_calculate(void *fd, void *buffer, size_t length)
{
	ssize_t *size = (ssize_t *)fd;

	*size += length;
	return (length);
}


static ssize_t
build_chunk(void *fd, void *buffer, size_t length)
{
	char **s1 = fd;

	memcpy(*s1, buffer, length);
	*s1 = *s1 + length;

	return (length);
}

ssize_t
ipp_request_write(void *fd, void *buffer, size_t length)
{
	service_t *svc = (service_t *)fd;

#ifdef DEBUG
	printf("ipp_request_write(0x%8.8x, 0x%8.8x, %d)\n", fd, buffer, length);
	httpDumpData(stdout, "ipp_request_write:", buffer, length);
#endif
	return (httpWrite(svc->connection, buffer, length));
}

ssize_t
ipp_request_read(void *fd, void *buffer, size_t length)
{
	service_t *svc = (service_t *)fd;
	ssize_t rc, i = length;
	char *p = buffer;

	while ((rc = httpRead(svc->connection, p, i)) != i) {
		if (rc == 0)
			return (rc);
		if (rc < 0)
			return (rc);
		i -= rc;
		p += rc;
	}
#ifdef DEBUG
	printf("ipp_request_read(0x%8.8x, 0x%8.8x, %d) = %d\n",
	    fd, buffer, length, rc);
	httpDumpData(stdout, "ipp_request_read:", buffer, length);
#endif

	return (length);
}

papi_status_t
ipp_send_initial_request_block(service_t *svc, papi_attribute_t **request,
		ssize_t file_size)
{
	papi_status_t result = PAPI_OK;
	ssize_t chunk_size = 0;
	char length[32];
	void *chunk, *ptr;
	http_status_t status;

	/* calculate the request size */
	(void) ipp_write_message(&size_calculate, &chunk_size, request);

	/* Fill in the HTTP Header information */
	httpClearFields(svc->connection);
	if (svc->transfer_encoding == TRANSFER_ENCODING_CHUNKED)
		httpSetField(svc->connection, HTTP_FIELD_TRANSFER_ENCODING,
		    "chunked");
	else {
		sprintf(length, "%lu", (unsigned long)(file_size + chunk_size));
		httpSetField(svc->connection, HTTP_FIELD_CONTENT_LENGTH,
		    length);
	}
	httpSetField(svc->connection, HTTP_FIELD_CONTENT_TYPE,
	    "application/ipp");
	httpSetField(svc->connection, HTTP_FIELD_AUTHORIZATION,
	    svc->connection->authstring);

	/* flush any state information about this connection */
	httpFlush(svc->connection);

	/* if we have don't have a POST path, use the service uri path */
	if (svc->post == NULL)
		svc->post = strdup(svc->uri->path);
	/* send the HTTP POST message for the IPP request */
	/* if the POST fails, return the error */
	status = httpPost(svc->connection, svc->post);
	if (status != 0)
		return (http_to_papi_status(status));

	if (httpCheck(svc->connection) != 0) {
		status = httpUpdate(svc->connection);
		if (status != HTTP_OK)
			return (http_to_papi_status(status));
	}

	/* build the request chunk */
	chunk = ptr = calloc(1, chunk_size);
	result = ipp_write_message(&build_chunk, &ptr, request);
#ifdef DEBUG
	printf("request: %d (0x%x) bytes\n", chunk_size, chunk_size);
	httpDumpData(stdout, "request:", chunk, chunk_size);
#endif

	/* send the actual IPP request */
	if (ipp_request_write(svc, chunk, chunk_size) != chunk_size)
		result = PAPI_TEMPORARY_ERROR;
	free(chunk);

	if (httpCheck(svc->connection) != 0) {
		status = httpUpdate(svc->connection);
		if (status != HTTP_OK)
			return (http_to_papi_status(status));
	}

	return (result);
}

static int
setAuthString(service_t *svc)
{
	http_t *http;
	char *user, *passphrase;
	char encoded[BUFSIZ];

	if ((svc == NULL) || (svc->connection == NULL) || (svc->name == NULL))
		return (-1);

	http = svc->connection;

	if (svc->user == NULL) {
		struct passwd *p;

		if ((p = getpwuid(getuid())) != NULL) {
			user = p->pw_name;
		} else if ((user = getenv("LOGNAME")) == NULL)
			user = getenv("USER");
		if (user == NULL)
			user = "nobody";
	} else
		user = svc->user;

	/* if the passphrase is not set, use the Authentication Callback */
	if (((svc->password == NULL) || (svc->password[0] == '\0')) &&
	    (svc->authCB != NULL))
		(svc->authCB)(svc, svc->app_data);
	passphrase = svc->password;

	/* if there is still no passphrase, we have to fail */
	if ((passphrase == NULL) || (passphrase[0] == '\0'))
		return (-1);

	if (strncmp(http->fields[HTTP_FIELD_WWW_AUTHENTICATE],
	    "Basic", 5) == 0) {
		char plain[BUFSIZ];

		snprintf(plain, sizeof (plain), "%s:%s", user, passphrase);
		httpEncode64(encoded, plain);
		snprintf(http->authstring, sizeof (http->authstring),
		    "Basic %s", encoded);
	} else if (strncmp(http->fields[HTTP_FIELD_WWW_AUTHENTICATE],
	    "Digest", 6) == 0) {
		char realm[HTTP_MAX_VALUE];
		char nonce[HTTP_MAX_VALUE];
		char line [BUFSIZ];
		char urp[128];
		char mr[128];
		char *uri = svc->post;

		httpGetSubField(http, HTTP_FIELD_WWW_AUTHENTICATE,
		    "realm", realm);
		httpGetSubField(http, HTTP_FIELD_WWW_AUTHENTICATE,
		    "nonce", nonce);

		snprintf(line, sizeof (line), "%s:%s:%s", user, realm,
		    passphrase);
		md5_calc(urp, line, strlen(line));

		snprintf(line, sizeof (line), "POST:%s", uri);
		md5_calc(mr, line, strlen(line));

		snprintf(line, sizeof (line), "%s:%s:%s", urp, mr, nonce);
		md5_calc(encoded, line, strlen(line));

		snprintf(http->authstring, sizeof (http->authstring),
		    "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
		    "uri=\"%s\", response=\"%s\"", user, realm, nonce, uri,
		    encoded);
	}

	return (0);
}

papi_status_t
ipp_status_info(service_t *svc, papi_attribute_t **response)
{
	papi_attribute_t **operational = NULL;
	int32_t status = 0;

	papiAttributeListGetCollection(response, NULL,
	    "operational-attributes-group", &operational);
	if (operational != NULL) {
		char *message = NULL;

		papiAttributeListGetString(response, NULL,
		    "status-message", &message);
		papiAttributeListAddString(&svc->attributes, PAPI_ATTR_REPLACE,
		    "detailed-status-message", message);
	}
	papiAttributeListGetInteger(response, NULL, "status-code", &status);

	return (ipp_to_papi_status(status));
}

papi_status_t
ipp_send_request_with_file(service_t *svc, papi_attribute_t **request,
		papi_attribute_t ***response, char *file)
{
	papi_status_t result = PAPI_OK;
	ssize_t size = 0;
	struct stat statbuf;
	int fd;

#ifdef DEBUG
	fprintf(stderr, "\nIPP-REQUEST: (%s)", (file ? file : ""));
	papiAttributeListPrint(stderr, request, "    ");
	putc('\n', stderr);
	fflush(stderr);
#endif

	/*
	 * if we are sending a file, open it and include it's size in the
	 * message size.
	 */
	if (file != NULL) {
		if ((fd = open(file, O_RDONLY)) < 0) {
			detailed_error(svc, "%s: %s", file, strerror(errno));
			return (PAPI_DOCUMENT_ACCESS_ERROR);
		} else if (strcmp("standard input", file) != 0) {
			stat(file, &statbuf);
			if (statbuf.st_size == 0) {
				detailed_error(svc,
				    "Zero byte (empty) file: %s", file);
				return (PAPI_BAD_ARGUMENT);
			}
		} else if (svc->transfer_encoding !=
		    TRANSFER_ENCODING_CHUNKED) {
			struct stat st;

			if (fstat(fd, &st) >= 0)
				size = st.st_size;
		}
	}

	*response = NULL;
	while (*response == NULL) {
		http_status_t status = HTTP_CONTINUE;

		result = ipp_send_initial_request_block(svc, request, size);

		if (result == PAPI_OK) {
			if (file != NULL) {
				/* send the file contents if we have it */
				int rc;
				char buf[BUFSIZ];

				lseek(fd, 0L, SEEK_SET);
				while ((rc = read(fd, buf, sizeof (buf))) > 0) {
					if (ipp_request_write(svc, buf, rc)
					    < rc) {
						break;
					}
				}
			}

			(void) ipp_request_write(svc, "", 0);
		}

		/* update our connection info */
		while (status == HTTP_CONTINUE)
			status = httpUpdate(svc->connection);

		if (status == HTTP_UNAUTHORIZED) {
			httpFlush(svc->connection);
			if ((svc->connection->authstring[0] == '\0') &&
			    (setAuthString(svc) == 0)) {
				httpReconnect(svc->connection);
				continue;
			}
		} else if (status == HTTP_UPGRADE_REQUIRED) {
			/*
			 * If the transport was built with TLS support, we can
			 * try to use it.
			 */
			httpFlush(svc->connection);
			httpReconnect(svc->connection);
			httpEncryption(svc->connection, HTTP_ENCRYPT_REQUIRED);
			continue;
		}

		if (status != HTTP_OK)
			return (http_to_papi_status(status));

		/* read the IPP response */
		result = ipp_read_message(&ipp_request_read, svc, response,
		    IPP_TYPE_RESPONSE);

		if (result == PAPI_OK)
			result = ipp_status_info(svc, *response);
#ifdef DEBUG
		fprintf(stderr, "\nIPP-RESPONSE: (%s) (%s)", (file ? file : ""),
		    papiStatusString(result));
		papiAttributeListPrint(stderr, *response, "    ");
		putc('\n', stderr);
		fflush(stderr);
#endif
	}

	return (result);
}

papi_status_t
ipp_send_request(service_t *svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	return (ipp_send_request_with_file(svc, request, response, NULL));
}
