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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/zone.h>
#include <string.h>
#include <libintl.h>

#include <syslog.h>
#include <stdarg.h>

#include <tsol/label.h>

#include "misc.h"

/* lpsched include files */
#if defined PS_FAULTED
#undef  PS_FAULTED
#endif /* PS_FAULTED */
#include "lp.h"
#include "msgs.h"
#include "printers.h"
#include "class.h"
#include "requests.h"
#include "secure.h"

#define	PROTOCOL_MAX	1000
#define	MAX_JOB_ID	(52 * PROTOCOL_MAX)
#define	LP_UID		71

/*
 * This function replaces characters in a string that might be used
 * to exploit a security hole.  Replace command seperators (`, &, ;, |, ^),
 * output redirection (>, |), variable expansion ($), and character
 * escape (\).  Taken directly from lpsched/exec.c.  If we ever build
 * a real library for LP, this should go in it.
 *
 * Bugid 4141687
 * Add ( ) < * ? [
 * Remove \
 */
static void clean_string(char *ptr)
{
	char *cp;
	wchar_t wc;
	size_t len;

	for (cp = ptr; *cp != NULL; ) {
		if ((len = mbtowc(&wc, cp, MB_CUR_MAX)) == -1) {
			cp++;
			continue;
		}

		if (len == 1 &&
		    ((wc == L'`') || (wc == L'&') || (wc == L';') ||
		    (wc == L'|') || (wc == L'>') || (wc == L'^') ||
		    (wc == L'$') || (wc == L'(') || (wc == L')') ||
		    (wc == L'<') || (wc == L'*') || (wc == L'?') ||
		    (wc == L'[')))
			*cp = '_';
		cp += len;
	}
}

/*
 * mail() will send a mail message to the requesting user in the event of an
 * error during job submission.
 */

static void
mail(REQUEST *request, char *req_file, char *fmt, ...)
{
	FILE *pp;
	char buf[BUFSIZ];
	char *uname;
	va_list ap;
	char	*mail_zonename = NULL;

	/*
	 * Clean-up user name so we don't pass flags to /bin/mail, or
	 * pass nothing at all (uname == '#') which causes /bin/mail
	 * to enter reader mode
	 */
	uname = request->user;
	while (*uname == ' ' || *uname == '-' || *uname == '#')
		uname++;

	if (*uname == '\0')
		return;		/* No username found */

	/*
	 * If in the global zone and the system is labeled, mail is
	 * handled via a local labeled zone that is the same label as the
	 * request.
	 */
	if ((getzoneid() == GLOBAL_ZONEID) && is_system_labeled() &&
	    slabel != NULL) {
		if ((mail_zonename = get_labeled_zonename(slabel)) ==
		    (char *)-1) {
			/* error during get_labeled_zonename, just return */
			return;
		}
	}

	/*
	 * If mail_zonename is not NULL, use zlogin to execute /bin/mail
	 * in the labeled zone 'mail_zonename'.
	 */

	if (mail_zonename != NULL) {
		syslog(LOG_DEBUG,
		    "lpsched: using '/usr/sbin/zlogin %s /bin/mail %s' to mail",
		    mail_zonename, uname);
		snprintf(buf, sizeof (buf),
		    "/usr/sbin/zlogin %s /bin/mail %s",
		    mail_zonename, uname);
		Free(mail_zonename);
	} else {
		syslog(LOG_DEBUG,
		    "lpsched: using '/bin/mail %s' to mail",
		    uname);
		snprintf(buf, sizeof (buf), "/bin/mail %s", uname);
	}
	clean_string(buf);
	if ((pp = popen(buf, "w+")) == NULL)
		return;
	fprintf(pp, gettext("Subject: print request for %s failed\n\n"),
	    request->destination);

	fprintf(pp, gettext("\n\tRequest File: %s"), req_file);
	fprintf(pp, gettext("\n\tDocument Type: %s"),
	    (request->input_type ? request->input_type :
	    gettext("(unknown)")));
	fprintf(pp, gettext("\n\tTitle:\t%s"),
	    (request->title ? request->title : gettext("(none)")));
	fprintf(pp, gettext("\n\tCopies:\t%d"), request->copies);
	fprintf(pp, gettext("\n\tPriority:\t%d"), request->priority);
	fprintf(pp, gettext("\n\tForm:\t%s"),
	    (request->form ? request->form : gettext("(none)")));
	fprintf(pp, gettext("\n\tOptions:\t%s"),
	    (request->options ? request->options : gettext("(none)")));
	fprintf(pp, gettext("\n\tModes:\t%s"),
	    (request->modes ? request->modes : gettext("(none)")));

	fprintf(pp, gettext("\n\tReason for Failure:\n\n\t\t"));
	va_start(ap, fmt);
	vfprintf(pp, fmt, ap);
	va_end(ap);
	fprintf(pp, "\n");

	pclose(pp);
}


/*
 * is_postscript() will detect if the file passed in contains postscript
 * data.  A one is returned if the file contains postscript, zero is returned
 * if the file is not postscript, and -1 is returned if an error occurs
 */
#define	PS_MAGIC	"%!"
#define	PC_PS_MAGIC	"%!"
static int
is_postscript(const char *file)
{
	char buf[3];
	int fd;

	if ((fd = open(file, O_RDONLY)) < 0)
		return (-1);

	if (read(fd, buf, sizeof (buf)) < 0) {
		close(fd);
		return (-1);
	}
	close(fd);

	if ((strncmp(buf, PS_MAGIC, sizeof (PS_MAGIC) - 1) == 0) ||
	    (strncmp(buf, PC_PS_MAGIC, sizeof (PC_PS_MAGIC) - 1) == 0))
		return (1);
	else
		return (0);
}


/*
 * name_to_id_no() will pull the id number out of a file name and attempt to
 * assign that ID to a print job.  If the ID collides with an existing one, it
 * will increment and try again.  This continues until an open ID is found, or
 * the ID space is exausted.
 */
static int
name_to_id_no(const char *name)
{
	char *tmp, buf[BUFSIZ];
	int done = 1;
	int start;
	int id;
	int fd;

	strncpy(buf, name, sizeof (buf));
	for (tmp = buf; ((*tmp != NULL) && (isdigit(*tmp) == 0)); tmp++);
	if (*tmp == NULL)
		return (-1);

	if ((start = atoi(tmp)) < 0)
		start = 0;
	id = start;

	do {
		sprintf(buf, "%d-0", id);
		if ((fd = open(buf, O_CREAT|O_EXCL, 0600)) < 0) {
			syslog(LOG_DEBUG, "ID Collision %d", id);
			if ((id += PROTOCOL_MAX) >= MAX_JOB_ID) {
				id %= PROTOCOL_MAX;
				if (--id < 0)
					id = PROTOCOL_MAX -1;
				if (id == start) {
					syslog(LOG_ERR,
						"No Request IDs available");
					return (-1);
				}
			}
		} else
			done = 0;
	} while (done != 0);

	close(fd);
	return (id);
}

static void
unlink_files(char **files)
{
	while ((files != NULL) && (*files != NULL))
		unlink(*files++);
}

/*
 * parse_cf() will pass through the BSD Control file data and fill in a
 * request structure will all the information it can.  The actual job data
 * files will not be placed in the request by this function.
 */
static REQUEST *
parse_cf(char *cf, const char *host)
{
	static REQUEST request;
	char	previous = NULL,
		*entry,
		*job_name = NULL,
		*class = NULL,
		*s,
		*user = NULL,
		**options = NULL,
		**file_list = NULL,
		**modes = NULL,
		*prtitle = NULL,	/* pr title */
		text[BUFSIZ],
		buf[BUFSIZ];
	int	copies_set = 0,
		count = 0,
		width = -1,		/* pr width */
		indent = -1,		/* pr indent */
		pr_specified = 0,
		banner = 0;

	memset(&request, 0, sizeof (request));
	request.priority = -1;
	request.copies = 1;

	entry = strdup(cf);	/* duplicate it just for grins */
	for (entry = strtok(entry, "\n"); entry != NULL;
	    entry = strtok(NULL, "\n")) {

		if (previous != entry[0]) {	/* set the copy count */
			if (request.copies != 1)
				copies_set++;
			previous = entry[0];
		} else if ((copies_set == 0) &&
			    ((entry[0] <= 'z') && (entry[0] >= 'a')))
			request.copies++;

		switch (entry[0]) {
		/* RFC-1179 options */
		case 'J':	/* RFC-1179 Banner Job Name */
			job_name = ++entry;
			break;
		case 'C':	/* RFC-1179 Banner Class Name */
			class = ++entry;
			break;
		case 'L':	/* RFC-1179 Banner toggle  */
			banner = 1;
			break;
		case 'T':	/* RFC-1179 Title (pr)  */
			prtitle = ++entry;
			break;
		case 'H':	/* RFC-1179 Host */
			/* use the host as known by us, not by them */
			break;
		case 'P':	/* RFC-1179 User */
			++entry;
			while ((s = strpbrk(entry, " ()")) != NULL)
				*s = '_';
			user = entry;
			break;
		case 'M':	/* RFC-1179 Mail to User */
			request.actions |= ACT_MAIL;
			break;
		case 'W':	/* RFC-1179 Width (pr) */
			width = atoi(++entry);
			break;
		case 'I':	/* RFC-1179 Indent (pr) */
			indent = atoi(++entry);
			break;
		case 'N':	/* RFC-1179 Filename */
			/* could have HP extension embedded */
			if (entry[1] != ' ')
				appendlist(&file_list, ++entry);
			else if (entry[2] == 'O') /* HP lp -o options */
				appendlist(&options, ++entry);
			break;
		case 'U':	/* RFC-1179 Unlink */
			break;	/* ignored */
		case '1':	/* RFC-1179 TROFF Font R */
		case '2':	/* RFC-1179 TROFF Font I */
		case '3':	/* RFC-1179 TROFF Font B */
		case '4':	/* RFC-1179 TROFF Font S */
			break;
		case 'f':	/* RFC-1179 ASCII file (print) */
		case 'l':	/* RFC-1179 CATV file (print) */
			if (request.input_type == NULL) {
				if (is_postscript(++entry) == 1)
					request.input_type = "postscript";
				else
					request.input_type = "simple";
			}
			break;
		case 'o':	/* RFC-1179 Postscript file (print) */
			if (request.input_type == NULL)
				request.input_type = "postscript";
			break;
		case 'p':	/* RFC-1179 PR file (print) */
			pr_specified = 1;
			if (request.input_type == NULL)
				request.input_type = "pr";
			break;
		case 't':	/* RFC-1179 TROFF file (print) */
			if (request.input_type == NULL)
				request.input_type = "otroff";
			break;
		case 'n':	/* RFC-1179 DITROFF file (print) */
			if (request.input_type == NULL)
				request.input_type = "troff";
			break;
		case 'd':	/* RFC-1179 DVI file (print) */
			if (request.input_type == NULL)
				request.input_type = "tex";
			break;
		case 'g':	/* RFC-1179 GRAPH file (print) */
			if (request.input_type == NULL)
				request.input_type = "plot";
			break;
		case 'c':	/* RFC-1179 CIF file (print) */
			if (request.input_type == NULL)
				request.input_type = "cif";
			break;
		case 'v':	/* RFC-1179 RASTER file (print) */
			if (request.input_type == NULL)
				request.input_type = "raster";
			break;
		case 'r':	/* RFC-1179 FORTRAN file (print) */
			if (request.input_type == NULL)
				request.input_type = "fortran";
			break;
		/* Sun Solaris Extensions */
		case 'O':
			++entry;
			do {
				if (*entry != '"')
					text[count++] = *entry;
			} while (*entry++);
			appendlist(&options, text);
			break;
		case '5':
			switch (entry[1]) {
			case 'f':	/* Solaris form */
				request.form = strdup(&entry[2]);
				break;
			case 'H':	/* Solaris handling */
				if (strcmp(&entry[2], NAME_IMMEDIATE) == 0)
					request.actions |= ACT_IMMEDIATE;
				else if (strcmp(&entry[2], NAME_RESUME) == 0)
					request.actions |= ACT_RESUME;
				else if (strcmp(&entry[2], NAME_HOLD) == 0)
					request.actions |= ACT_HOLD;
				else
					syslog(LOG_INFO,
						"handling (%s): unknown",
						entry[2]);
				break;
			case 'p':	/* Solaris notification */
				/* request.alert = strdup(&entry[2]); */
				request.actions |= ACT_MAIL;
				break;
			case 'P':	/* Solaris page list */
				request.pages = strdup(&entry[2]);
				break;
			case 'q':	/* Solaris priority */
				request.priority = atoi(&entry[2]);
				break;
			case 'S':	/* Solaris character set */
				request.charset = strdup(&entry[2]);
				break;
			case 'T':	/* Solaris type */
				if (request.input_type == NULL)
					request.input_type = strdup(&entry[2]);
				break;
			case 'y':	/* Solaris mode */
				appendlist(&modes, &entry[2]);
				break;
			default:
				syslog(LOG_INFO|LOG_DEBUG,
					"Warning: cf message (%s) ignored",
					entry);
				break;
			}
			break;
		/* HP Extensions */

		/* Undefined Extensions */
		default:
			syslog(LOG_INFO|LOG_DEBUG,
				"Warning: cf message (%s) ignored", entry);
			break;
		}
	}

	/* The -p option must be specified with the -T, -w, and -i options */
	if (prtitle != NULL)
		if (pr_specified == 1) {
			snprintf(buf, sizeof (buf), "prtitle='%s'",
				prtitle);
			appendlist(&modes, buf);
		} else
			syslog(LOG_DEBUG, "Warning: title option ignored "
				"as the pr filter option was not specified");
	if (width != -1)
		if (pr_specified == 1) {
			snprintf(buf, sizeof (buf), "prwidth=%d",
				width);
			appendlist(&modes, buf);
		} else
			syslog(LOG_DEBUG, "Warning: width option ignored "
				"as the pr filter option was not specified");
	if (indent != -1)
		if (pr_specified == 1) {
			snprintf(buf, sizeof (buf), "indent=%d",
				indent);
			appendlist(&modes, buf);
		} else
			syslog(LOG_DEBUG, "Warning: indent option ignored "
				"as the pr filter option was not specified");

	snprintf(buf, sizeof (buf), "%s%s%s", (user ? user : "nobody"),
		(host ? "@" : ""), (host ? host : ""));
	request.user = strdup(buf);

	if (banner != 0) {
		snprintf(buf, sizeof (buf), "%s%s%s",
			(job_name ? job_name : ""),
			(job_name && class ? "\\n#####\\n#####\\t\\t " : ""),
			(class ? class : ""));
		request.title = strdup(buf);
	} else
		appendlist(&options, "nobanner");

	if ((request.priority < 0) || (request.priority > 20))
		request.priority = 20;

	if (file_list != NULL) {
		char *tmp = sprintlist(file_list);

		snprintf(buf, sizeof (buf), "flist='%s'", tmp);
		appendlist(&options, buf);
		free(tmp);
		freelist(file_list);
	}
	if (options != NULL) {
		request.options = sprintlist(options);
		freelist(options);
	}
	if (modes != NULL) {
		request.modes = sprintlist(modes);
		freelist(modes);
	}
	request.version = VERSION_BSD;   /* this probably isn't necessary */

	return (&request);
}



/*
 * submit_job() takes in a printer, host, control file, and list of data files.
 * it attempts to submit the print job to the local spooler using the lpsched
 * local named pipe.  The routine will auto-detect if the first data file
 * is postscript, and set the job to "postscript".  If an error occurs, a
 * message is mailed back to the requestor.
 */
int
lpsched_submit_job(const char *printer, const char *host, char *cf,
			char **df_list)
{
	REQUEST *request = NULL;
	SECURE  secure;
	char	buf[MAXPATHLEN];
	int	file_no = 0;
	int	rc = -1;
	char 	*tmp_dir;
	char  *tmp;
	short status;
	long  bits;
	int request_id = 0;
	int job_size = 0;

	syslog(LOG_DEBUG, "lpsched_submit_job(%s, %s, 0x%x)",
		(printer ? printer : "NULL"), (cf ? cf : "NULL"), df_list);

	tmp_dir = (char *)lpsched_temp_dir(printer, host);

	if ((printer == NULL) || (host == NULL) || (cf == NULL) ||
	    (df_list == NULL))
		return (-1);

	if ((request_id = name_to_id_no(df_list[0])) < 0)
		return (-1);

	if ((request = parse_cf(cf, host)) == NULL) {
		syslog(LOG_ERR|LOG_DEBUG,
			"Error parsing control file, Contents:\n%s\n", cf);
		return (-1);
	}

	request->destination = strdup(printer);
	while ((df_list != NULL) && (*df_list != NULL)) {
		struct stat st;
		/* move/rename the file to req-%d */
		snprintf(buf, sizeof (buf), "%s/%d-%d", tmp_dir, request_id,
		    ++file_no);
		rename(*df_list++, buf);
		chown(buf, LP_UID, 0);
		if (stat(buf, &st) == 0)
			job_size += st.st_size;

		appendlist(&request->file_list, buf);
	}

	if (request->file_list == NULL) {
		syslog(LOG_ERR|LOG_DEBUG,
			"Job %d doesn't contain any data files", request_id);
		return (-1);
	}

	/* submit the request */
	memset(&secure, NULL, sizeof (secure));
	secure.size = job_size;
	secure.date = time(0);
	secure.system = strdup(host);
	secure.user = request->user;
	snprintf(buf, sizeof (buf), "%s-%d", printer, request_id);
	secure.req_id = strdup(buf);
	secure.uid = LP_UID;
	secure.gid = 0;
	secure.slabel = NULL;

	/* save the request file */
	snprintf(buf, sizeof (buf), "%s/%d-0", host, request_id);
	if (putrequest(buf, request) < 0) {
		mail(request, buf,
		    gettext("Can't save print request"));
		unlink_files(request->file_list);
		return (-1);
	}

	/* save the secure file */
	if (putsecure(buf, &secure) < 0) {
		mail(request, buf,
		    gettext("Can't save print secure file"));
		snprintf(buf, sizeof (buf), "%s/%s/%d-0", Lp_Tmp, host,
		    request_id);
		unlink(buf);
		unlink_files(request->file_list);
		return (-1);
	}

	/* kick lpsched */
	if ((snd_msg(S_PRINT_REQUEST, buf) < 0) ||
	    (rcv_msg(R_PRINT_REQUEST, &status, &tmp, &bits) < 0))
		status = MTRANSMITERR;

	/* how did we do ? */
	if (status != MOK) {
		rc = -1;
		switch (status) {
		case MNOMEM:
			mail(request, buf,
				gettext("lpsched: out of memory"));
			break;
		case MNOFILTER:
			mail(request, buf,
				gettext("No filter available to convert job"));
			break;
		case MNOOPEN:
			mail(request, buf,
				gettext("lpsched: could not open request"));
			break;
		case MERRDEST:
			mail(request, buf,
				gettext("An error occured in submission"));
			break;
		case MDENYDEST:
			mail(request, buf,
				gettext("Destination: %s, denied request"),
				printer);
			break;
		case MNOMEDIA:
			mail(request, buf,
				gettext("unknown form specified in job"));
			break;
		case MDENYMEDIA:
			mail(request, buf,
			gettext("access denied to form specified in job"));
			break;
		case MNOPERM:
			mail(request, buf,
			gettext("no permission for printer or job data empty"));
			break;
		case MTRANSMITERR:
			mail(request, buf,
				gettext("failure to communicate with lpsched"));
			break;
		default:
			mail(request, buf,
			    gettext("Unknown error: %d"),
				status);
			break;
		}

		/* clean it up */
		snprintf(buf, sizeof (buf), "%s/%s/%d-0", Lp_Requests, host,
		    request_id);
		unlink(buf);
		snprintf(buf, sizeof (buf), "%s/%s/%d-0", Lp_Tmp, host,
		    request_id);
		unlink(buf);
		unlink_files(request->file_list);
	} else {	/* It was OK */
		rc = 0;
		syslog(LOG_DEBUG, "Submit: %s", tmp);
	}

	return (rc);
}
