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

/* $Id: in.lpd.c 170 2006-05-20 05:58:49Z njacobs $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <libintl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/systeminfo.h>

#include <papi.h>
#include <uri.h>
#include "common.h"

#define	ACK(fp)		{ (void) fputc('\0', fp); (void) fflush(fp); }
#define	NACK(fp)	{ (void) fputc('\1', fp); (void) fflush(fp); }

/*
 * This file contains the front-end of the BSD Print Protocol adaptor.  This
 * code assumes a BSD Socket interface to the networking side.
 */

static char *
remote_host_name(FILE *fp)
{
	struct hostent *hp;
	struct sockaddr_in6 peer;
	socklen_t peer_len = sizeof (peer);
	int fd = fileno(fp);
	int error_num;
	char tmp_buf[INET6_ADDRSTRLEN];
	char *hostname;

	/* who is our peer ? */
	if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) < 0) {
		if ((errno != ENOTSOCK) && (errno != EINVAL))
			return (NULL);
		else
			return (strdup("localhost"));
	}

	/* get their name or return a string containing their address */
	if ((hp = getipnodebyaddr((const char *)&peer.sin6_addr,
	    sizeof (struct in6_addr), AF_INET6,
	    &error_num)) == NULL) {
		return (strdup(inet_ntop(peer.sin6_family,
		    &peer.sin6_addr, tmp_buf, sizeof (tmp_buf))));
	}

	hostname = strdup(hp->h_name);
	if (is_localhost(hp->h_name) != 0)
		return (strdup("localhost"));

	/* It must be someone else */
	return (hostname);
}

static void
fatal(FILE *fp, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	exit(1);
}

static void
cleanup(char ***files, char **cf)
{
	if (*files != NULL) {
		int i;

		for (i = 0; (*files)[i] != NULL; i++) {
			(void) unlink((*files)[i]);
			free((*files)[i]);
		}
		free(*files);
		*files = NULL;
	}

	if (*cf != NULL) {
		free(*cf);
		*cf = NULL;
	}
}

static papi_attribute_t **
parse_cf(papi_service_t svc, char *cf, char **files)
{
	papi_attribute_t **list = NULL;
	char	previous = '\0';
	char	*entry;
	int	copies_set = 0;
	int	copies = 0;

	for (entry = strtok(cf, "\n"); entry != NULL;
	    entry = strtok(NULL, "\n")) {
		char *format = NULL;

		/* count the copies */
		if ((entry[0] >= 'a') && (entry[0] <= 'z') &&
		    (copies_set == 0) && (previous == entry[0]))
			copies++;
		else if ((previous >= 'a') && (previous <= 'z'))
			copies_set = 1;
		previous = entry[0];

		/* process the control message */
		switch (entry[0]) {
		/* RFC-1179 options */
		case 'J':	/* RFC-1179 Banner Job Name */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "job-name", ++entry);
			break;
		case 'C':	/* RFC-1179 Banner Class Name */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "rfc-1179-class", ++entry);
			break;
		case 'L':	/* RFC-1179 Banner toggle  */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "job-sheets", "standard");
			break;
		case 'T':	/* RFC-1179 Title (pr)  */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "pr-title", ++entry);
			break;
		case 'H':	/* RFC-1179 Host */
			/*
			 * use the host as known by us, not by them
			 *
			 * papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			 *		"job-originating-host-name", ++entry);
			 */
			break;
		case 'P':	/* RFC-1179 User */
			++entry;
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "job-originating-user-name", entry);
			papiServiceSetUserName(svc, entry);
			break;
		case 'M':	/* RFC-1179 Mail to User */
			papiAttributeListAddBoolean(&list, PAPI_ATTR_EXCL,
			    "rfc-1179-mail", 1);
			break;
		case 'W':	/* RFC-1179 Width (pr) */
			papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL,
			    "pr-width", atoi(++entry));
			break;
		case 'I':	/* RFC-1179 Indent (pr) */
			papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL,
			    "pr-indent", atoi(++entry));
			break;
		case 'N':	/* RFC-1179 Filename */
			/* could have HPUX extension embedded */
			if (entry[1] != ' ') {	/* real pathname */
#ifdef DEBUG
				papiAttributeListAddString(&list,
				    PAPI_ATTR_EXCL,
				    "flist", ++entry);
#endif
			} else if (entry[2] == 'O') /* HPUX lp -o options */
				papiAttributeListFromString(&list,
				    PAPI_ATTR_APPEND, ++entry);
			break;
		case 'U':	/* RFC-1179 Unlink */
			break;	/* ignored */
		case '1':	/* RFC-1179 TROFF Font R */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "rfc-1179-font-r", ++entry);
			break;
		case '2':	/* RFC-1179 TROFF Font I */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "rfc-1179-font-i", ++entry);
			break;
		case '3':	/* RFC-1179 TROFF Font B */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "rfc-1179-font-b", ++entry);
			break;
		case '4':	/* RFC-1179 TROFF Font S */
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "rfc-1179-font-s", ++entry);
			break;
		case 'f':	/* RFC-1179 ASCII file (print) */
			format = "text/plain";
			if (is_postscript(files[0]) == 1)
				format = "application/postscript";
			break;
		case 'l':	/* RFC-1179 CATV file (print) */
			format = "application/octet-stream";
			if (is_postscript(files[0]) == 1)
				format = "application/postscript";
			break;
		case 'o':	/* RFC-1179 Postscript file (print) */
			format = "application/postscript";
			break;
		case 'p':	/* RFC-1179 PR file (print) */
			format = "application/x-pr";
			papiAttributeListAddBoolean(&list, PAPI_ATTR_EXCL,
			    "pr-filter", 1);
			break;
		case 't':	/* RFC-1179 TROFF file (print) */
			format = "application/x-troff";
			break;
		case 'n':	/* RFC-1179 DITROFF file (print) */
			format = "application/x-ditroff";
			break;
		case 'd':	/* RFC-1179 DVI file (print) */
			format = "application/x-dvi";
			break;
		case 'g':	/* RFC-1179 GRAPH file (print) */
			format = "application/x-plot";
			break;
		case 'c':	/* RFC-1179 CIF file (print) */
			format = "application/x-cif";
			break;
		case 'v':	/* RFC-1179 RASTER file (print) */
			format = "application/x-raster";
			break;
		case 'r':	/* RFC-1179 FORTRAN file (print) */
			format = "application/x-fortran";
			break;
		/* Sun Solaris Extensions */
		case 'O':
			++entry;
			{
				int rd, wr;

				for (rd = wr = 0; entry[rd] != '\0'; rd++) {
					if (entry[rd] == '"')
						continue;
					if (rd != wr)
						entry[wr] = entry[rd];
					wr++;
				}
				entry[wr] = '\0';

				papiAttributeListFromString(&list,
				    PAPI_ATTR_APPEND, entry);
			}
			break;
		case '5':
			++entry;
			switch (entry[0]) {
			case 'f':	/* Solaris form */
				papiAttributeListAddString(&list,
				    PAPI_ATTR_EXCL,
				    "form", ++entry);
				break;
			case 'H':	/* Solaris handling */
				++entry;
				if (strcasecmp(entry, "hold") == 0)
					papiAttributeListAddString(&list,
					    PAPI_ATTR_EXCL,
					    "job-hold-until", "indefinite");
				else if (strcasecmp(entry, "immediate") == 0)
					papiAttributeListAddString(&list,
					    PAPI_ATTR_EXCL,
					    "job-hold-until", "no-hold");
				else
					papiAttributeListAddString(&list,
					    PAPI_ATTR_EXCL,
					    "job-hold-until", entry);
				break;
			case 'p':	/* Solaris notification */
				papiAttributeListAddBoolean(&list,
				    PAPI_ATTR_EXCL, "rfc-1179-mail", 1);
				break;
			case 'P': {	/* Solaris page list */
				char buf[BUFSIZ];

				snprintf(buf, sizeof (buf), "page-ranges=%s",
				    ++entry);
				papiAttributeListFromString(&list,
				    PAPI_ATTR_EXCL, buf);
				}
				break;
			case 'q': {	/* Solaris priority */
				int i = atoi(++entry);

				i = 100 - (i * 2.5);
				if ((i < 1) || (i > 100))
					i = 50;
				papiAttributeListAddInteger(&list,
				    PAPI_ATTR_EXCL, "job-priority", i);
				}
				break;
			case 'S':	/* Solaris character set */
				papiAttributeListAddString(&list,
				    PAPI_ATTR_EXCL, "lp-charset",
				    ++entry);
				break;
			case 'T':	/* Solaris type */
				format = lp_type_to_mime_type(++entry);
				break;
			case 'y':	/* Solaris mode */
				papiAttributeListAddString(&list,
				    PAPI_ATTR_APPEND, "lp-modes", ++entry);
				break;
			default:
				syslog(LOG_INFO|LOG_DEBUG,
				    "Warning: cf message (%s) ignored",
				    entry);
				break;
			}
			break;
		/* Undefined Extensions: SCO, Ultrix, AIX, ... */

		default:
			syslog(LOG_INFO|LOG_DEBUG,
			    "Warning: cf message (%s) ignored", entry);
			break;
		}

		if (format != NULL)
			papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
			    "document-format", format);
	}

	papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL,
	    "copies", ++copies);
	papiAttributeListAddString(&list, PAPI_ATTR_EXCL,
	    "job-sheets", "none");

	return (list);
}

static papi_status_t
submit_job(papi_service_t svc, FILE *ifp, char *printer, int rid, char *cf,
		char **files)
{
	papi_attribute_t **list = NULL;
	papi_status_t status;
	papi_job_t job = NULL;
	char *format = "";

	if ((list = parse_cf(svc, cf, files)) != NULL) {
		/* use the host as known by us, not by them */
		char *host = remote_host_name(ifp);

		if (host != NULL) {
			papiAttributeListAddString(&list, PAPI_ATTR_REPLACE,
			    "job-originating-host-name", host);
			free(host);
		}
		if (rid >= 0) {
			papiAttributeListAddInteger(&list, PAPI_ATTR_EXCL,
			    "job-id-requested", rid);
		}
	}

	status = papiJobSubmit(svc, printer, list, NULL, files, &job);
	syslog(LOG_DEBUG, "submit: %s", papiStatusString(status));
	if (status != PAPI_OK) {
		char *tmp = papiServiceGetStatusMessage(svc);

		syslog(LOG_DEBUG, "submit-detail: %s", tmp ? tmp : "none");
	}
	papiJobFree(job);

	return (status);
}

static char *
receive_control_file(papi_service_t svc, FILE *ifp, FILE *ofp, int size)
{
	char *ptr, *cf_data;

	if ((ptr = cf_data = calloc(1, size + 1)) == NULL) {
		NACK(ofp);
		return (NULL);
	} else
		ACK(ofp);

	while (size > 0) {
		int rc;

		if (((rc = fread(ptr, 1, size, ifp)) == 0) &&
		    (feof(ifp) != 0)) {
			free(cf_data);
			return (NULL);
		} else {
			ptr += rc;
			size -= rc;
		}
	}
	syslog(LOG_DEBUG, "cf_data(%s)", cf_data);

	if (fgetc(ifp) != 0) {
		free(cf_data);
		return (NULL);
	}
	ACK(ofp);

	return (cf_data);
}

static char *
receive_data_file(FILE *ifp, FILE *ofp, int size)
{
	char file[] = "lpdXXXXXX";
	char buf[BUFSIZ];
	int fd;

	if ((fd = mkstemp(file)) < 0) {
		NACK(ofp);
		return (NULL);
	} else
		ACK(ofp);

	while (size > 0) {
		int rc = ((size > BUFSIZ) ? BUFSIZ : size);

		if (((rc = fread(buf, 1, rc, ifp)) == 0) &&
		    (feof(ifp) != 0)) {
			close(fd);
			unlink(file);
			return (NULL);
		} else {
			char *ptr = buf;

			while (rc > 0) {
				int wrc = write(fd, ptr, rc);

				if (wrc < 0) {
					close(fd);
					unlink(file);
					return (NULL);
				}

				ptr += wrc;
				size -= wrc;
				rc -= wrc;
			}
		}
	}
	close(fd);
	if (fgetc(ifp) != 0) {
		unlink(file);
		return (NULL);
	}
	ACK(ofp);

	return (strdup(file));
}

static papi_status_t
berkeley_receive_files(papi_service_t svc, FILE *ifp, FILE *ofp, char *printer)
{
	papi_status_t status = PAPI_OK;
	char *file, **files = NULL;	/* the job data files */
	char *cf = NULL;
	int rid = 0;
	char buf[BUFSIZ];

	while (fgets(buf, sizeof (buf), ifp) != NULL) {
		int size;

		syslog(LOG_DEBUG, "XFER CMD: (%d)%s\n", buf[0], &buf[1]);
#ifdef DEBUG	/* translate [1-3]... messages to \[1-3] to run by hand */
		if ((buf[0] > '0') && (buf[0] < '4'))
			buf[0] -= '0';
#endif
		switch (buf[0]) {
		case 0x01:	/* Abort */
			cleanup(&files, &cf);
			break;
		case 0x02: {	/* Receive control file */
			if (((cf = strchr(buf, ' ')) != NULL) &&
			    (strlen(cf) > 4)) {
				while ((*cf != '\0') && (isdigit(*cf) == 0))
					cf++;
				rid = atoi(cf);
			}
			cf = receive_control_file(svc, ifp, ofp, atoi(&buf[1]));
			if (cf == NULL) {
				cleanup(&files, &cf);
				return (PAPI_BAD_REQUEST);
			} else if (files != NULL) {
				status = submit_job(svc, ifp, printer, rid, cf,
				    files);
				cleanup(&files, &cf);
			}
			}
			break;
		case 0x03: {	/* Receive data file */
			file = receive_data_file(ifp, ofp, atoi(&buf[1]));
			if (file == NULL) {
				cleanup(&files, &cf);
				return (PAPI_TEMPORARY_ERROR);
			}
			list_append(&files, file);
			}
			break;
		default:
			cleanup(&files, &cf);
			fatal(ofp, "protocol screwup");
			break;
		}
	}

	if ((cf != NULL) && (files != NULL))
		status = submit_job(svc, ifp, printer, rid, cf, files);

	cleanup(&files, &cf);

	return (status);
}

static papi_status_t
berkeley_transfer_files(papi_service_t svc, FILE *ifp, FILE *ofp,
		char *printer)
{
	papi_status_t status;
	papi_printer_t p = NULL;
	char *keys[] = { "printer-is-accepting-jobs", NULL };

	status = papiPrinterQuery(svc, printer, keys, NULL, &p);
	if ((status == PAPI_OK) && (p != NULL)) {
		papi_attribute_t **attrs = papiPrinterGetAttributeList(p);
		char accepting = PAPI_FALSE;

		papiAttributeListGetBoolean(attrs, NULL,
		    "printer-is-accepting-jobs", &accepting);

		if (accepting == PAPI_TRUE) {
			ACK(ofp);
			status = berkeley_receive_files(svc, ifp, ofp, printer);
		} else
			NACK(ofp);

		papiPrinterFree(p);
	} else
		NACK(ofp);

	return (status);
}

static int
cyclical_service_check(char *svc_name)
{
	papi_attribute_t **list;
	uri_t *uri = NULL;
	char *s = NULL;

	/* was there a printer? */
	if (svc_name == NULL)
		return (0);

	if ((list = getprinterbyname(svc_name, NULL)) == NULL)
		return (0);	/* if it doesnt' resolve, we will fail later */

	papiAttributeListGetString(list, NULL, "printer-uri-supported", &s);
	if ((s == NULL) || (strcasecmp(svc_name, s) != 0))
		return (0);	/* they don't match */

	/* is it in uri form? */
	if (uri_from_string(s, &uri) < 0)
		return (0);

	if ((uri == NULL) || (uri->scheme == NULL) || (uri->host == NULL)) {
		uri_free(uri);
		return (0);
	}

	/* is it in lpd form? */
	if (strcasecmp(uri->scheme, "lpd") != 0) {
		uri_free(uri);
		return (0);
	}

	/* is it the local host? */
	if (is_localhost(uri->host) != 0) {
		uri_free(uri);
		return (0);
	}

	uri_free(uri);
	return (1);
}


/*
 * This is the entry point for this program.  The program takes the
 * following options:
 * 	(none)
 */
int
main(int ac, char *av[])
{
	papi_status_t status;
	papi_service_t svc = NULL;
	papi_encryption_t encryption = PAPI_ENCRYPT_NEVER;
	FILE	*ifp = stdin;
	FILE	*ofp = stdout;
	int	c;
	char	buf[BUFSIZ];
	char	**args;
	char	*printer;
	char	*run_dir = "/var/run/in.lpd";
	char	*run_user = NULL;
	struct passwd *pw = NULL;

	(void) chdir("/tmp");		/* run in /tmp by default */
	openlog("bsd-gw", LOG_PID, LOG_LPR);

	while ((c = getopt(ac, av, "Ed:u:")) != EOF)
		switch (c) {
		case 'E':
			encryption = PAPI_ENCRYPT_ALWAYS;
			break;
		case 'd':	/* run where they tell you */
			run_dir = optarg;
			break;
		case 'u':	/* run as */
			run_user = optarg;
			break;
		default:
			;
		}

	if (run_user != NULL)	/* get the requested user info */
		pw = getpwnam(run_user);

	if (run_dir != NULL) {	/* setup the run_dir */
		(void) mkdir(run_dir, 0700);
		if (pw != NULL)
			(void) chown(run_dir, pw->pw_uid, pw->pw_gid);
	}

	if (pw != NULL) {	/* run as the requested user */
		syslog(LOG_DEBUG, "name: %s, uid: %d, gid: %d",
		    pw->pw_name, pw->pw_uid, pw->pw_gid);
		initgroups(pw->pw_name, pw->pw_gid);
		setgid(pw->pw_gid);
		setuid(pw->pw_uid);
	}

	if (run_dir != NULL)	/* move to the run_dir */
		if (chdir(run_dir) < 0) {
			syslog(LOG_DEBUG, "failed to chdir(%s)", run_dir);
			exit(1);
		}

	syslog(LOG_DEBUG, "$CWD = %s", getwd(NULL));

	if (fgets(buf, sizeof (buf), ifp) == NULL) {
		if (feof(ifp) == 0)
			syslog(LOG_ERR, "Error reading from connection: %s",
			    strerror(errno));
		exit(1);
	}

	syslog(LOG_DEBUG, "CMD: (%d)%s\n", buf[0], &buf[1]);

#ifdef DEBUG	/* translate [1-5]... messages to \[1-5] to run by hand */
	if ((buf[0] > '0') && (buf[0] < '6'))
		buf[0] -= '0';
#endif

	if ((buf[0] < 1) || (buf[0] > 5)) {
		fatal(ofp, "Invalid protocol request (%d): %c%s\n",
		    buf[0], buf[0], buf);
		exit(1);
	}

	args = strsplit(&buf[1], "\t\n ");
	printer = *args++;

	if (printer == NULL) {
		fatal(ofp, "Can't determine requested printer");
		exit(1);
	}

	if (cyclical_service_check(printer) != 0) {
		fatal(ofp, "%s is cyclical\n", printer);
		exit(1);
	}

	status = papiServiceCreate(&svc, printer, NULL, NULL, NULL,
	    encryption, NULL);
	if (status != PAPI_OK) {
		fatal(ofp, "Failed to contact service for %s: %s\n", printer,
		    verbose_papi_message(svc, status));
		exit(1);
	}

	/*
	 * Trusted Solaris can't be trusting of intermediaries.  Pass
	 * the socket connection to the print service to retrieve the
	 * sensativity label off of a multi-level port.
	 */
	(void) papiServiceSetPeer(svc, fileno(ifp));

	switch (buf[0]) {
	case '\1':	/* restart printer */
		ACK(ofp);	/* there is no equivalent */
		break;
	case '\2':	/* transfer job(s) */
		status = berkeley_transfer_files(svc, ifp, ofp, printer);
		break;
	case '\3':	/* show queue (short) */
	case '\4': {	/* show queue (long) */
		int count;

		for (count = 0; args[count] != 0; count++) {}

		berkeley_queue_report(svc, ofp, printer, buf[0], count, args);
		}
		break;
	case '\5': {	/* cancel job(s) */
		char *user = *args++;
		char *host = remote_host_name(ifp);
		int count;

		if (host != NULL) {
			char buf[BUFSIZ];

			snprintf(buf, sizeof (buf), "%s@%s", user, host);
			status = papiServiceSetUserName(svc, buf);
		} else
			status = papiServiceSetUserName(svc, user);

		for (count = 0; args[count] != 0; count++) {}

		berkeley_cancel_request(svc, ofp, printer, count, args);
		}
		break;
	default:
		fatal(ofp, "unsupported protocol request (%c), %s",
		    buf[0], &buf[1]);
	}

	(void) fflush(ofp);

	syslog(LOG_DEBUG, "protocol request(%d) for %s completed: %s",
	    buf[0], printer, papiStatusString(status));
	if (status != PAPI_OK)
		syslog(LOG_DEBUG, "detail: %s",
		    verbose_papi_message(svc, status));

	papiServiceDestroy(svc);

	return (0);
}
