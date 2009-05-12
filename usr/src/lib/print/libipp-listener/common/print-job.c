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

/* $Id: print-job.c 146 2006-03-24 00:26:54Z njacobs $ */

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <papi.h>
#include <ipp.h>
#include <ipp-listener.h>

papi_status_t
ipp_print_job(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response, ipp_reader_t iread, void *fd)
{
	papi_status_t status;
	papi_stream_t s = NULL;
	papi_job_t j = NULL;
	papi_attribute_t **operational = NULL;
	papi_attribute_t **job_attributes = NULL;
	char *queue = NULL;
	ssize_t rc;
	char buf[BUFSIZ];
	char *host = NULL;
	char *keys[] = { "attributes-natural-language", "attributes-charset",
			"printer-uri", NULL };

	/* Get operational attributes from the request */
	(void) papiAttributeListGetCollection(request, NULL,
	    "operational-attributes-group", &operational);

	/*
	 * The operational-attributes-group must contain:
	 *	printer-uri
	 */
	get_printer_id(operational, &queue, NULL);
	if (queue == NULL) {
		ipp_set_status(response, status, "printer-uri: %s",
		    papiStatusString(status));
		return (PAPI_BAD_REQUEST);
	}

	/*
	 * The operational-attributes-group may contain:
	 *	job-name
	 *	ipp-attribute-fidelity
	 *	document-name
	 *	compression
	 *	document-format
	 *	document-natural-language
	 *	job-k-octets
	 *	job-impressions
	 *	job-media-sheets
	 * Simply copy the entire contents of the operational-attributes-group
	 * for the PAPI call's possible use.
	 */
	split_and_copy_attributes(keys, operational, NULL, &job_attributes);

	/* copy any job-attributes-group attributes for the PAPI call */
	if (papiAttributeListGetCollection(request, NULL,
	    "job-attributes-group", &operational) == PAPI_OK) {
		char *user = NULL;

		copy_attributes(&job_attributes, operational);

		if (papiAttributeListGetString(operational, NULL,
		    "requesting-user-name", &user) == PAPI_OK) {
			papiAttributeListAddString(&job_attributes,
			    PAPI_ATTR_REPLACE, "requesting-user-name", user);
		}
	}

	/* Set "job-originating-host-name" attribute if not set */
	papiAttributeListGetString(job_attributes, NULL,
	    "job-originating-host-name", &host);

	if (host == NULL) {
		int fd = -1;
		(void) papiAttributeListGetInteger(request, NULL,
		    "peer-socket", &fd);

		if (fd != -1) {
			struct sockaddr_in peer;
			int peer_len;

			peer_len = sizeof (peer);
			if (getpeername(fd, (struct sockaddr *)&peer,
			    &peer_len) == 0) {
				struct hostent *he;
				int error_num;

				he = getipnodebyaddr(&peer.sin_addr,
				    sizeof (peer.sin_addr),
				    peer.sin_family, &error_num);

				if ((he != NULL) && (he->h_name != NULL)) {
					papiAttributeListAddString(
					    &job_attributes,
					    PAPI_ATTR_REPLACE,
					    "job-originating-host-name",
					    he->h_name);
				} else {
					/*
					 * Node-name could not be read
					 * so set the ip-address
					 */
					papiAttributeListAddString(
					    &job_attributes,
					    PAPI_ATTR_REPLACE,
					    "job-originating-host-name",
					    inet_ntoa(peer.sin_addr));
				}
			}
		}
	}

	/* request job creation with a resulting stream that we can write to */
	status = papiJobStreamOpen(svc, queue, job_attributes, NULL, &s);
	papiAttributeListFree(job_attributes);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "job submission: %s",
		    ipp_svc_status_mesg(svc, status));
		return (status);
	}

	/* copy the document data from the IPP connection to the stream */
	while ((status == PAPI_OK) && ((rc = iread(fd, buf, sizeof (buf))) > 0))
		status = papiJobStreamWrite(svc, s, buf, rc);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "write job data: %s",
		    ipp_svc_status_mesg(svc, status));
		return (status);
	}

	/* close the stream, committing the job */
	status = papiJobStreamClose(svc, s, &j);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "close job stream: %s",
		    ipp_svc_status_mesg(svc, status));
		papiJobFree(j);	/* we shouldn't have a job, but just in case */
		return (status);
	}

	/* add the job attributes to the response in a job-attributes-group */
	if (j != NULL) {
		papi_to_ipp_job_group(response, request, PAPI_ATTR_REPLACE, j);
		papiJobFree(j);
	}

	return (status);
}
