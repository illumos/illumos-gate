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
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <libintl.h>
#include <netdb.h>	/* for rcmd() */

#include <ns.h>
#include <list.h>

/*  escaped chars include delimiters and shell meta characters */
#define	ESCAPE_CHARS	"\\\n=: `&;|>^$()<*?["

/*
 * This modules contains all of the code nedessary to write back to each
 * printing configuration data repository.  The support is intended to
 * introduce the least number of dependencies in the library, so it doesn't
 * always perform it's operations in the cleanest fashion.
 */


/*
 * Generic Files support begins here.
 */
static char *
freadline(FILE *fp, char *buf, int buflen)
{
	char *s = buf;

	while (fgets(s, buflen, fp)) {
		if ((s == buf) && ((*s == '#') || (*s == '\n'))) {
			continue;
		} else {
			if ((*s == '#') || (*s == '\n')) {
				*s = '\0';
				break;
			}

			buflen -= strlen(s);
			s += strlen(s);

			if (*(s - 2) != '\\')
				break;
#ifdef STRIP_CONTINUATION
			buflen -= 2;
			s -= 2;
#endif
		}
	}

	if (s == buf)
		return (NULL);
	else
		return (buf);
}


static int
_file_put_printer(const char *file, const ns_printer_t *printer)
{
	FILE	*ifp,
	    *ofp;
	char *tmpfile;
	int fd;
	int exit_status = 0;
	int size;

	size = strlen(file) + 1 + 20;
	if ((tmpfile = malloc(size)) == NULL)
		return (-1);

	if (snprintf(tmpfile, size, "%sXXXXXX", file) >= size) {
		syslog(LOG_ERR, "_file_put_printer:buffer overflow:tmpfile");
		return (-1);
	}

	/* LINTED */
	while (1) {	/* syncronize writes */
		fd = open(file, O_RDWR | O_CREAT | O_EXCL, 0644);
		if ((fd < 0) && (errno == EEXIST))
			fd = open(file, O_RDWR);
		if (fd < 0) {
			if (errno == EAGAIN)
				continue;
			free(tmpfile);
			return (-1);
		}
		if (lockf(fd, F_TLOCK, 0) == 0)
			break;
		(void) close(fd);
	}

	if ((ifp = fdopen(fd, "r")) == NULL) {
		(void) close(fd);
		free(tmpfile);
		return (-1);
	}

	if ((fd = mkstemp(tmpfile)) < 0) {
		(void) fclose(ifp);
		free(tmpfile);
		return (-1);
	}

	(void) fchmod(fd, 0644);
	if ((ofp = fdopen(fd, "wb+")) != NULL) {
		char buf[4096];

		(void) fprintf(ofp,
	"#\n#\tIf you hand edit this file, comments and structure may change.\n"
	"#\tThe preferred method of modifying this file is through the use of\n"
	"#\tlpset(1M)\n#\n");

	/*
	 * Handle the special case of lpset -x all
	 * This deletes all entries in the file
	 * In this case, just don't write any entries to the tmpfile
	 */

		if (!((strcmp(printer->name, "all") == 0) &&
		    (printer->attributes == NULL))) {
			char *t, *entry, *pentry;

			(void) _cvt_printer_to_entry((ns_printer_t *)printer,
			    buf, sizeof (buf));
			t = pentry = strdup(buf);

			while (freadline(ifp, buf, sizeof (buf)) != NULL) {
				ns_printer_t *tmp = (ns_printer_t *)
				    _cvt_nss_entry_to_printer(buf, "");

				if (ns_printer_match_name(tmp, printer->name)
				    == 0) {
					entry = pentry;
					pentry = NULL;
				} else {
					entry = buf;
				}

				(void) fprintf(ofp, "%s\n", entry);
			}

			if (pentry != NULL)
				(void) fprintf(ofp, "%s\n", pentry);
			free(t);
		}

		(void) fclose(ofp);
		(void) rename(tmpfile, file);
	} else {
		(void) close(fd);
		(void) unlink(tmpfile);
		exit_status = -1;
	}

	(void) fclose(ifp);	/* releases the lock, after rename on purpose */
	(void) free(tmpfile);
	return (exit_status);
}


/*
 * Support for writing a printer into the FILES /etc/printers.conf
 * file.
 */
int
files_put_printer(const ns_printer_t *printer)
{
	static char *file = "/etc/printers.conf";

	return (_file_put_printer(file, printer));
}

/*
 * Support for writing a printer into the NIS printers.conf.byname
 * map.
 */

#include <rpc/rpc.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>

/*
 * Run the remote command.  We aren't interested in any io, Only the
 * return code.
 */
static int
remote_command(char *command, char *host)
{
	struct passwd *pw;

	if ((pw = getpwuid(getuid())) != NULL) {
		int fd;

		if ((fd = rcmd_af(&host, htons(514), pw->pw_name, "root",
		    command, NULL, AF_INET6)) < 0)
			return (-1);
		(void) close(fd);
		return (0);
	} else {
		return (-1);
	}
}


/*
 * This isn't all that pretty, but you can update NIS if the machine this
 * runs on is in the /.rhosts or /etc/hosts.equiv on the NIS master.
 *   copy it local, update it, copy it remote
 */
#define	TMP_PRINTERS_FILE	"/tmp/printers.NIS"
#define	NIS_MAKEFILE		"/var/yp/Makefile"
#define	MAKE_EXCERPT		"/usr/lib/print/Makefile.yp"
/*ARGSUSED*/
int
nis_put_printer(const ns_printer_t *printer)
{
	static char	*domain = NULL;
	char *map = "printers.conf.byname";
	char *tmp = NULL;
	char *host = NULL;
	char lfile[BUFSIZ];
	char rfile[BUFSIZ];
	char cmd[BUFSIZ];

	if (domain == NULL)
		(void) yp_get_default_domain(&domain);

	if ((yp_master(domain, (char *)map, &host) != 0) &&
	    (yp_master(domain, "passwd.byname", &host) != 0))
		return (-1);

	if (snprintf(lfile, sizeof (lfile), "/tmp/%s", map) >=
	    sizeof (lfile)) {
		syslog(LOG_ERR, "nis_put_printer:lfile buffer overflow");
		return (-1);
	}
	if (snprintf(rfile, sizeof (rfile), "root@%s:/etc/%s", host, map) >=
	    sizeof (rfile)) {
		syslog(LOG_ERR, "nis_put_printer:rfile buffer overflow");
		return (-1);
	}

	if (((tmp = strrchr(rfile, '.')) != NULL) &&
	    (strcmp(tmp, ".byname") == 0))
		*tmp = '\0';	/* strip the .byname */

	/* copy it local */
	if (snprintf(cmd, sizeof (cmd), "rcp %s %s >/dev/null 2>&1",
	    rfile, lfile) >= sizeof (cmd)) {
		syslog(LOG_ERR,
		    "nis_put_printer:buffer overflow building cmd");
		return (-1);
	}
	(void) system(cmd);	/* could fail because it doesn't exist */


	/* update it */
	if (_file_put_printer(lfile, printer) != 0)
		return (-1);

	/* copy it back */
	if (snprintf(cmd, sizeof (cmd), "rcp %s %s >/dev/null 2>&1",
	    lfile, rfile) >= sizeof (cmd)) {
		syslog(LOG_ERR,
		    "nis_put_printer:buffer overflow building cmd");
		return (-1);
	}
	if (system(cmd) != 0)
		return (-1);

	/* copy the Makefile excerpt */
	if (snprintf(cmd, sizeof (cmd),
	    "rcp %s root@%s:%s.print >/dev/null 2>&1",
	    MAKE_EXCERPT, host, NIS_MAKEFILE) >= sizeof (cmd)) {
		syslog(LOG_ERR,
		    "nis_put_printer:buffer overflow building cmd");
		return (-1);
	}

	if (system(cmd) != 0)
		return (-1);

	/* run the make */
	if (snprintf(cmd, sizeof (cmd),
	    "/bin/sh -c 'PATH=/usr/ccs/bin:/bin:/usr/bin:$PATH "
	    "make -f %s -f %s.print printers.conf >/dev/null 2>&1'",
	    NIS_MAKEFILE, NIS_MAKEFILE) >= sizeof (cmd)) {
		syslog(LOG_ERR,
		    "nis_put_printer:buffer overflow on make");
		return (-1);
	}

	return (remote_command(cmd, host));
}
