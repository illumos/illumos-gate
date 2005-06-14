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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/systeminfo.h>
#include <sys/param.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <termios.h>
#include <libintl.h>
#include <locale.h>
#include <pwd.h>
#include <grp.h>

#include <print/ns.h>
#include <print/network.h>
#include <print/misc.h>
#include <print/list.h>
#include <print/job.h>

/*
 *	 lpr/lp
 *	This program will submit print jobs to a spooler using the BSD
 *	printing protcol as defined in RFC1179, plus some extension for
 *	support of additional lp functionality.
 */

extern char *optarg;
extern int optind, opterr, optopt;
extern char *getenv(const char *);

#define	SEND_RETRY	-1
#define	SEND_ABORT	-2


static int	priority = -1,
		copies = 1,
		width = -1,		/* pr width */
		indent = -1,		/* pr indent */
		linked = 0,
		mail = 0,
		delete = 0,
		suppress = 1,
		banner = 1,
		connection_failed = 0;
static char	*printer = NULL,
		*form = NULL,
		*charset = NULL,
		*title = NULL,		/* pr title */
		*class = NULL,
		*jobName = NULL,
		*notification = NULL,
		*handling = NULL,
		*pages = NULL,
		**mode = NULL,
		**s5options = NULL,
		*s5type = NULL,
		*internal_type = NULL,
		*fontR = NULL,
		*fontI = NULL,
		*fontB = NULL,
		*fontS = NULL,
		type = CF_PRINT_ASCII;

static struct s5_types {
	char *name;
	char type;
} output_types[] = {			/* known LP "-T" types */
/*
 *	Switched to ASCII, because some BSD systems don't like the 'o' file
 *	type.
 */
	{ "postscript", CF_PRINT_ASCII },
	{ "ps", CF_PRINT_ASCII },
	{ "simple", CF_PRINT_ASCII },
	{ "ascii", CF_PRINT_ASCII },
	{ "raw", CF_PRINT_RAW },
	{ "dvi", CF_PRINT_DVI },
	{ "tex", CF_PRINT_DVI },
	{ "raster", CF_PRINT_RAS },
	{ "ditroff", CF_PRINT_DROFF },
	{ "otroff", CF_PRINT_TROFF },
	{ "troff", CF_PRINT_DROFF },
	{ "cif", CF_PRINT_CIF },
	{ "plot", CF_PRINT_PLOT },
	{ "fortran", CF_PRINT_FORT },
	{ "pr", CF_PRINT_PR },
	NULL
};

/*ARGSUSED*/
static void sigbus_handler(int i)
{
	(void) fprintf(stderr,
		gettext("No space in /var/spool/print to store job"));
	exit(-1);
}

/*ARGSUSED*/
static void sigpipe_handler(int i)
{
	syslog(LOG_ERR, "Warning: Received SIGPIPE; continuing");
	(void) signal(SIGPIPE, sigpipe_handler);
}


#define	OLD_LP "/usr/lib/lp/local/lp"	/* for local lpsched printers */
#ifdef OLD_LP
/*
 * this will submit the job to a local lpsched using the old interface.
 * the argument vector is rebuilt with a new destination, because
 * the old name may have been an alias or because it was actually
 * lpr(1b) that was called.
 */
static void
submit_local_lp(char *program, int ac, char *av[])
{
	uid_t ruid = getuid();
	struct passwd *pw;
	int argc = 0;
	char **argv;

	/*
	 * We allocate the space for ac+5 items, which include all the file
	 * arguments(ac), generic arguments(OLD_LP, "-d" and "printer") and
	 * "-s" option of lpr. The extra item is just a cushion.
	 */
	if ((argv = (char **)calloc(ac + 5, sizeof (char *))) == NULL) {
		(void) fprintf(stderr,
			gettext("not enough memory for argument vector\n"));
		exit(1);
	}
	argv[argc++] = OLD_LP;
	argv[argc++] = "-d";
	argv[argc++] = printer;

	if (strcmp(program, "lp") == 0) {
		int i = 0;

		while (++i < ac)
			if (strncmp(av[i], "-d", 2) != 0) {
				argv[argc++] = av[i];
			} else if (strlen(av[i]) == 2)
				i++;
	} else { /* convert lpr options */
		argv[argc++] = "-s";	/* supress id message */

		if (linked == 0)
			argv[argc++] = "-c";

		if (copies > 1) {
			char buf[12];
			(void) sprintf(buf, "%d", copies);
			argv[argc++] = "-n";
			argv[argc++] = strdup(buf);
		}
		if (banner == 0) {
			argv[argc++] = "-o";
			argv[argc++] = "nobanner";
		}
		if (title != NULL) {
			char buf[BUFSIZ];
			(void) snprintf(buf, sizeof (buf), "prtitle='%s'",
			    title);
			argv[argc++] = "-y";
			argv[argc++] = strdup(buf);
		}
		if (width > 0) {
			char buf[16];
			(void) sprintf(buf, "prwidth=%d", width);
			argv[argc++] = "-y";
			argv[argc++] = strdup(buf);
		}
		if (indent > 0) {
			char buf[16];
			(void) sprintf(buf, "indent=%d", indent);
			argv[argc++] = "-y";
			argv[argc++] = strdup(buf);
		}
		if (mail != 0)
			argv[argc++] = "-m";
		if ((jobName != NULL) || (class != NULL)) {
			char buf[128];
			snprintf(buf, sizeof (buf), "%s%s%s",
			    (jobName ? jobName : ""),
			    (jobName && class ? "\\n#####\\n#####\\t\\t "
			    : ""), (class ? class : ""));
			argv[argc++] = "-t";
			argv[argc++] = strdup(buf);
		}

		if (type != CF_PRINT_ASCII) {
			struct s5_types *tmp;

			for (tmp = output_types; tmp->name != NULL; tmp++)
				if (tmp->type == type) {
					argv[argc++] = "-T";
					argv[argc++] = tmp->name;
					break;
				}
		}

		while (optind < ac)
			argv[argc++] = av[optind++];

	}

	ruid = getuid();
	if ((pw = getpwuid(ruid)) != NULL)
		(void) initgroups(pw->pw_name, pw->pw_gid);
	(void) setuid(ruid);

	argv[argc++] = NULL;
	(void) execv(OLD_LP, argv);
}
#endif


/*
 * cheat and look in the LP interface to determine if a local printer is
 * rejecting.  If so, don't queue the job.  If the printer is remote or
 * accepting, queue it.  This approximates behaviour of previous releases
 * The check is being done this way for performance.
 */
static int
rejecting(char *printer)
{
	int rc = 0, found = 0;
	FILE *fp;

	if ((fp = fopen("/usr/spool/lp/system/pstatus", "r+")) != NULL) {
		char buf[BUFSIZ];

		while (fgets(buf, sizeof (buf), fp) != NULL) {
			buf[strlen(buf)-1] = NULL;
			if (strcmp(buf, printer) == 0) {
				char *ptr;

				found = 1;
				(void) fgets(buf, sizeof (buf), fp);
				buf[strlen(buf)-1] = NULL;
				ptr = strrchr(buf, ' ');
				if (ptr && (strcmp(++ptr, "rejecting") == 0)) {
					rc = 1;
					break;
				}
			}
		}
	}
	(void) fclose(fp);

	/* if we have'nt found the name it could be a class */
	if (!found) {
		if ((fp = fopen("/usr/spool/lp/system/cstatus",
		    "r+")) != NULL) {

			char buf2[BUFSIZ];

			while (fgets(buf2, sizeof (buf2), fp) != NULL) {
				buf2[strlen(buf2)-1] = NULL;
				if (strcmp(buf2, printer) == 0) {
					fgets(buf2, sizeof (buf2), fp);
					buf2[strlen(buf2)-1] = NULL;
					if (strcmp(buf2, "rejecting") == 0) {
						rc = 1;
						break;
					}
				}
			}

		}
	}

	(void) fclose(fp);
	return (rc);
}

/*
 * Remove special characters before popen (change them into '_').
 */
static void
clean_string(char *ptr)
{
	char *cp;
	wchar_t wc;
	int len;

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


static int _notified = 0;

static void
error_notify(char *user, int id, char *msg, ...)
{
	if (_notified++ == 0) {
		char *tmp;
		char cmd[BUFSIZ];
		FILE *fp;
		va_list ap;

		va_start(ap, msg);
		tmp = strdup(user);
		clean_string(tmp);
		(void) snprintf(cmd, sizeof (cmd),
		    "/bin/write %s >/dev/null 2>&1", tmp);
		free(tmp);
		fp = popen(cmd, "w+");
		(void) fprintf(fp,
			gettext("\n\tError transfering print job %d\n"), id);
		(void) vfprintf(fp, msg, ap);
		(void) pclose(fp);
		va_end(ap);
	}
}



/*
 *  bsd_options() parses the command line using the BSD lpr semantics and sets
 *	several global variables for use in building the print request.
 */
static void
bsd_options(int ac, char *av[])
{
	int c;

	while ((c = getopt(ac, av,
			"P:#:C:J:T:w:i:hplrstdgvcfmn1:2:3:4:")) != EOF)
		switch (c) {
		case 'P':
			printer = optarg;
			break;
		case '#':
			copies = atoi(optarg);
			break;
		case 'C':
			class = optarg;
			break;
		case 'J':
			jobName = optarg;
			break;
		case 'T':
			title = optarg;
			break;
		case 'w':
			width = atoi(optarg);
			break;
		case 'm':
			mail++;
			break;
		case 'i':	/* this may or may not have an arguement */
			if (isdigit(optarg[0]) == 0) {
				indent = 8;
				optind--;
			} else
				indent = atoi(optarg);
			break;
		case 'h':
			banner = 0;
			break;
		case 'r':
			delete = 1;
			break;
		case 's':
			linked = 1;
			break;
		case 'l' :
			type = CF_PRINT_RAW;
			break;
		case 'd' :
			type = CF_PRINT_DVI;
			break;
		case 't' :
			type = CF_PRINT_TROFF;
			break;
		case 'g' :
			type = CF_PRINT_PLOT;
			break;
		case 'v' :
			type = CF_PRINT_RAS;
			break;
		case 'c' :
			type = CF_PRINT_CIF;
			break;
		case 'f' :
			type = CF_PRINT_FORT;
			break;
		case 'n' :
			type = CF_PRINT_DROFF;
			break;
		case 'o' :
			type = CF_PRINT_PS;
			break;
		case 'p' :
			type = CF_PRINT_PR;
			break;
		case '1' :
			fontR = optarg;
			break;
		case '2' :
			fontI = optarg;
			break;
		case '3' :
			fontB = optarg;
			break;
		case '4' :
			fontS = optarg;
			break;
		default:
			(void) fprintf(stderr,
				gettext("Usage: %s [-Pprinter] [-#num] "
				"[-Cclass] [-Jjob] [-Ttitle] [-i [indent]] "
				"[-1234 font] [-wcols] [-m] [-h] [-s] "
				"[-pltndgvcf] files ...\n"),
				av[0]);
			exit(1);
		}

		/*
		 * The pr filter must be specified with the
		 * title, width, and indent options
		 */
		if ((title != NULL) && (type != CF_PRINT_PR))
			(void) fprintf(stderr, gettext(
				"Warning: title option ignored as the pr "
				"filter option was not specified\n"));
		if ((width > 0) && (type != CF_PRINT_PR))
			(void) fprintf(stderr, gettext(
				"Warning: width option ignored as the pr "
				"filter option was not specified\n"));
		if ((indent > 0) && (type != CF_PRINT_PR))
			(void) fprintf(stderr, gettext(
				"Warning: indent option ignored as the pr "
				"filter option was not specified\n"));
}

/*
 *  sysv_options() parses the command line using the BSD lpr semantics and sets
 *	several global variables for use in building the print request.
 */
static void
sysv_options(int ac, char *av[])
{
	int c;

#ifdef OLD_LP
	if ((ac > 2) && (strcmp(av[1], "-i") == 0)) {
		if (access(OLD_LP, F_OK) == 0) {
			/*
			 * limit ourselves to real user's perms before exec'ing
			 */
			(void) setuid(getuid());
			(void) execv(OLD_LP, av);
			perror("exec local modify");
		} else
			(void) printf(gettext(
				"job modification not supported on clients\n"));
		exit(-1);
	}
#endif

	linked = 1;
	suppress = 0;
	while ((c = getopt(ac, av, "H:P:S:T:d:f:i:o:q:t:y:cmwn:prs")) != EOF)
		switch (c) {
		case 'q':
			priority = atoi(optarg);
			break;
		case 'H':
			handling = optarg;
			break;
		case 'f':
			form = optarg;
			break;
		case 'd':
			printer = optarg;
			break;
		case 'T':
			{
			struct s5_types *tmp;
			int flag = 0;

			for (tmp = output_types;
			    ((flag == 0) && (tmp->name != NULL)); tmp++)
				if (strcasecmp(tmp->name, optarg) == 0) {
					type = tmp->type;
					flag++;
				}
			if (flag == 0)
				s5type = optarg;
			else
				internal_type = optarg;
			break;
			}
		case 'S':
			charset = optarg;
			break;
		case 'o':
			{
			char *p, *q = strdup(optarg);

			/*
			 * -o nobanner will no longer generate a warning or
			 * Onobanner in the control file.  If "nobanner" is
			 * embedded in an option list, the option list will
			 * still generate a warning or 'O' message in the
			 * control file.
			 */
			if (strcmp("nobanner", optarg) != 0)
				s5options = (char **)list_append(
						(void**)s5options,
						(void *)strdup(optarg));

			for (p = strtok(q, "\t ,"); p != NULL;
					p = strtok(NULL, "\t ,"))
				if (strcmp(p, "nobanner") == 0) {
					banner = 0;
					break;
				}
			}
			break;
		case 'y':
			{
			char *p, *q = strdup(optarg);

			for (p = strtok(q, "\t ,"); p != NULL;
					p = strtok(NULL, "\t ,"))
				if (strcmp(p, "catv_filter") == 0)
					type = CF_PRINT_RAW;
				else
					mode = (char **)list_append(
							    (void **)mode,
							    (void *)p);
			}
			break;
		case 'P':
			pages = optarg;
			break;
		case 'i':
			(void) printf(gettext(
			"job modification (-i) only supported on server\n"));
			break;
		case 'c':
			linked = 0;
			break;
		case 'm':
			mail++;
			break;
		case 'w':
			mail++;
			break;
		case 'p':
			notification = optarg;
			break;
		case 'n':
			if ((optarg == 0) || (*optarg == '-')) {
				(void) fprintf(stderr, gettext(
				"-n requires a positive integer argument\n"));
				exit(1);
			}
			copies = atoi(optarg);
			break;
		case 's':
			suppress = 1;
			break;
		case 't':
			jobName = optarg;
			break;
		case 'r':
			/* not supported - raw */
			break;
		default:
			(void) fprintf(stderr,
				gettext("Usage: %s [-d dest] [-cmwsr] [-n num] "
				"[-t title] [-p notification] [-P page-list] "
				"[-i job-id] [y modes] [-o options] "
				"[-S char-set] [-T input-type] [H handling] "
				"[-q priority] files ...\n"),
				av[0]);
			exit(1);
		}
}


/*
 *  stdin_to_file() reads standard input into a file and returns the file name
 *	to the caller
 */
static char *
stdin_to_file()
{
	int	fd,
		rc;
	char	*name,
		buf[BUFSIZ];

	(void) putenv("TMPDIR="); /* stop user moving the temp file */

	snprintf(buf, sizeof (buf), "/tmp/stdinXXXXXX");
	if ((fd = mkstemp(buf)) < 0)
		return (NULL);
	fchmod(fd, 0640);
	if ((name = strdup(buf)) == NULL) {
		close(fd);
		return (NULL);
	}
	syslog(LOG_DEBUG, "stdin_to_file: %s", name);
	while ((rc = read(0, buf, sizeof (buf))) > 0)
		(void) write(fd, buf, rc);
	(void) close(fd);
	return (name);
}


static int
sendfile(jobfile_t *file, int nd, int type)
{
	int rc = -1;

	syslog(LOG_DEBUG, "sendfile(%s, %d, %d)",
		((file != NULL) ? file->jf_spl_path : "NULL"), nd, type);
	if (file && file->jf_spl_path) {
		rc = net_send_file(nd, file->jf_spl_path, file->jf_data,
				file->jf_size, type);
	}
	return (rc);
}


/*
 *  send_job() sends a job to a remote print server.
 */
static int
send_job(job_t *job)
{
	int	lockfd,
		lock_size,
		nd,
		tmp,
		rc = 0;
	struct passwd *p = NULL;
	char	buf[BUFSIZ];

	syslog(LOG_DEBUG, "send_job(%s, %s, %d): called", job->job_printer,
		job->job_server, job->job_id);
	if ((lockfd = get_lock(job->job_cf->jf_src_path, 0)) < 0) {
		(void) close(lockfd);
		return (SEND_RETRY);
	}

	/* is job complete ? */

	lock_size = file_size(job->job_cf->jf_src_path);
	(void) sprintf(buf, "%ld\n", getpid());	/* add pid to lock file */
	(void) lseek(lockfd, 0, SEEK_END);
	(void) write(lockfd, buf, strlen(buf));

	syslog(LOG_DEBUG, "send_job(%s, %s, %d): have lock", job->job_printer,
		job->job_server, job->job_id);
	connection_failed = 0;
	if ((nd = net_open(job->job_server, 5)) < 0) {
		connection_failed = 1;
		if ((nd != NETWORK_ERROR_UNKNOWN) && (nd != NETWORK_ERROR_PORT))
			job_destroy(job);
		else
			(void) ftruncate(lockfd, lock_size);
		(void) close(lockfd);
		return ((nd == NETWORK_ERROR_UNKNOWN) ||
			(nd == NETWORK_ERROR_PORT) ? SEND_RETRY : SEND_ABORT);
	}

	if (net_send_message(nd, "%c%s\n", XFER_REQUEST, job->job_printer)
	    != 0) {
		(void) net_close(nd);
		syslog(LOG_WARNING,
			"send_job failed job %d (%s@%s) check status\n",
			job->job_id, job->job_printer, job->job_server);
		error_notify(job->job_user, job->job_id,
			gettext("\t\t check queue for (%s@%s)\n"),
			job->job_printer, job->job_server);
		(void) ftruncate(lockfd, lock_size);
		(void) close(lockfd);
		return (SEND_RETRY);
	}

	syslog(LOG_DEBUG, "send_job(%s, %s, %d): send data", job->job_printer,
		job->job_server, job->job_id);

	if ((p = getpwnam(job->job_user)) != NULL) {
		/*
		 * attempt to become the job owner: uid, euid, gid, and
		 * supplementary groups while we try to send the job data.
		 * The real uid is changed with setreuid() separately from
		 * changing the effective uid so that we retain the saved
		 * uid to elevate privilege later.  Combining these changes
		 * would result in a change to the saved uid also and a loss
		 * of the ability to elevate privilege later.
		 */
		(void) setuid(0);
		(void) initgroups(job->job_user, p->pw_gid);
		(void) setgid(p->pw_gid);
		(void) setreuid(p->pw_uid, -1);
		(void) seteuid(p->pw_uid);
	}

	for (tmp = 0; job->job_df_list[tmp] != NULL; tmp++)
		if ((rc = sendfile(job->job_df_list[tmp], nd, XFER_DATA)) < 0)
			break; /* there was an error, quit now */
	tmp = errno;
	if (p != NULL) {
		/*
		 * lose the supplemental groups and elevate our effective
		 * uid to root so that we can destroy jobs and/or become
		 * other job owners later on.
		 */
		(void) seteuid(0);
		(void) initgroups("root", 1);
	}
	errno = tmp;

	if (rc < 0) {
		if (errno == ENOENT) {
			(void) net_close(nd);
			error_notify(job->job_user, job->job_id, gettext(
				"\t\tdata removed before transfer, job "
				"canceled.\n\t\tTry \"lp -c\" or \"lpr\"\n"));
			job_destroy(job);
			(void) close(lockfd);
			return (SEND_ABORT);
		} else if (errno == EACCES) {
			/* probably trying to circumvent file security */
			(void) net_close(nd);
			error_notify(job->job_user, job->job_id, gettext(
				"\t\tunable to read job data.\n"));
			job_destroy(job);
			(void) close(lockfd);
			return (SEND_ABORT);
		} else {
			(void) net_close(nd);
			(void) ftruncate(lockfd, lock_size);
			error_notify(job->job_user, job->job_id,
				gettext("\t\t check queue for (%s@%s)\n"),
				job->job_printer, job->job_server);
			(void) close(lockfd);
			return (SEND_RETRY);
		}
	}

	if (sendfile(job->job_cf, nd, XFER_CONTROL) < 0) {
		(void) net_send_message(nd, "%c\n", XFER_CLEANUP);
		(void) net_close(nd);
		(void) ftruncate(lockfd, lock_size);
		error_notify(job->job_user, job->job_id,
			gettext("\t\t check queue for (%s@%s)\n"),
			job->job_printer, job->job_server);
		(void) close(lockfd);
		return (SEND_RETRY);
	}

	syslog(LOG_DEBUG, "send_job(%s, %s, %d): complete", job->job_printer,
		job->job_server, job->job_id);
	(void) net_close(nd);
	job_destroy(job);
	(void) close(lockfd);
	return (0);
}


/*
 *  xfer_daemon() attempts to start up a daemon for transfering jobs to a remote
 *	print server.  The daemon runs if it can get the master lock, and it
 *	runs until there are no jobs waiting for transfer.
 */
static void
xfer_daemon()
{
	job_t **list = NULL;
	int i,
	    rc;



	closelog();
	closefrom(0);

	_notified = 1;
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);

	(void) setuid(0);
	(void) setsid();
	openlog("printd", LOG_PID, LOG_LPR);
	if (fork() != 0)
		exit(0);

	if ((i = get_lock(MASTER_LOCK, 1)) < 0)
		exit(0);

	(void) chdir(SPOOL_DIR);
	while ((list = job_list_append(NULL, NULL, NULL, SPOOL_DIR)) != NULL) {
		job_t **tmp;

		syslog(LOG_DEBUG, "got the queue...");
		for (tmp = list; *tmp != NULL; tmp++) {
		/*
		 * Bugid: 4133175 printd dies when data is removed or
		 * permissions are changed.  Memory is freed twice.
		 * Fix: Do not process anything else in the list
		 * if the return code is SEND_ABORT as the memory
		 * has already been freed by job_destroy().
		 */
			rc = send_job(*tmp);
			if ((rc != 0) && (rc != SEND_ABORT)) {
				char *s = strdup((*tmp)->job_server);
				char *p = strdup((*tmp)->job_printer);

			if (rc != SEND_ABORT) /* already free */
				job_free(*tmp);

				for (tmp++; ((*tmp != NULL) &&
					(strcmp(s, (*tmp)->job_server) == 0));
					tmp++)
					if ((connection_failed == 0) &&
					    (strcmp(p,
						    (*tmp)->job_printer) == 0))
						job_free(*tmp);
					else
						break;
				tmp--;
				free(s);
				free(p);
			}
		}
		free(list);

		/* look for more work to do before we sleep */
		if ((list = job_list_append(NULL, NULL, NULL,
				SPOOL_DIR)) != NULL) {
			(void) list_iterate((void **)list, (VFUNC_T)job_free);
			free(list);
			(void) sleep(60);
		}
	}
	syslog(LOG_DEBUG, "daemon exiting...");
}

static void
append_string(char *s, va_list ap)
{
	char *buf = va_arg(ap, char *);

	if (strlen(buf) != 0)
		(void) strcat(buf, " ");
	(void) strcat(buf, s);
}


static char *
build_string(char **list)
{
	int size = 0;
	char *buf = NULL;

	if (list != NULL) {
		size = list_iterate((void **)list, (VFUNC_T)strlen);
		size += 16;
		buf = malloc(size);
		(void) memset(buf, NULL, size);
		(void) list_iterate((void **)list, (VFUNC_T)append_string, buf);
	}
	return (buf);
}


#define	ADD_PRIMATIVE(job, primative, value) \
	if ((job != NULL) && (value != NULL)) \
		(void) job_primative(job, primative, value);
#define	ADD_SVR4_PRIMATIVE(job, primative, value) \
	if ((job != NULL) && (value != NULL)) (void) job_svr4_primative(job, \
							primative, value);

#define	ADD_INT_PRIMATIVE(job, primative, value, ok) \
	if ((job != NULL) && (value != ok)) { \
				(void) sprintf(buf, "%d", value); \
				(void) job_primative(job, primative, buf); \
				}
#define	ADD_SVR4_INT_PRIMATIVE(job, primative, value, ok) \
	if ((job != NULL) && (value != ok)) { \
				(void) sprintf(buf, "%d", value); \
				(void) job_svr4_primative(job, primative, \
								buf); \
				}

#define	OPTION_ERROR(option, value) \
	if (value != NULL) \
		(void) fprintf(stderr, gettext("\tignoring: %s %s\n"), \
				option, value);

#define	OPTION_ERROR_INT(option, value) \
	if (value != -1) \
		(void) fprintf(stderr, gettext("\tignoring: %s %d\n"), \
				option, value);



/*
 * Main program.  if called with "lpr" use the BSD syntax, if called
 * with "lp", use the SYSV syntax.  If called by any other name,
 * become a transfer daemon.  In the lpr/lp case, build a job and
 * attempt to send it to the print server.  If the server doesn't
 * respond, become a daemon if none is currently running and attempt
 * to xfer all waiting jobs.
 */
main(int ac, char *av[])
{
	ns_bsd_addr_t *binding = NULL;
	int	numFiles = 0,
		queueStdin = 0,
		exit_code = 0;
	char	*program,
		*user,
		hostname[128],
		buf[BUFSIZ];
	job_t *job;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((program = strrchr(av[0], '/')) == NULL)
		program = av[0];
	else
		program++;

	openlog(program, LOG_PID, LOG_LPR);

	/*
	 * Bugid: 4013980 Application changed fd 1 to a pipe that has
	 * no reader; we write to stdout and catch a sigpipe and exit.
	 * Fix: catch signal, complain to syslog, and continue.
	 */
	(void) signal(SIGPIPE, sigpipe_handler);

	if (check_client_spool(NULL) < 0) {
		(void) fprintf(stderr,
			gettext("couldn't validate local spool area (%s)\n"),
			SPOOL_DIR);
		return (-1);
	}
	if (strcmp(program, "lpr") == 0) {
		if ((printer = getenv((const char *)"PRINTER")) == NULL)
			printer = getenv((const char *)"LPDEST");
		bsd_options(ac, av);
	} else if (strcmp(program, "lp") == 0) {
		if ((printer = getenv((const char *)"LPDEST")) == NULL)
			printer = getenv((const char *)"PRINTER");
		sysv_options(ac, av);
	} else {
		xfer_daemon();
		return (0);
	}

	if (printer == NULL) {
		ns_printer_t *pobj = ns_printer_get_name(NS_NAME_DEFAULT, NULL);

		if (pobj != NULL) {
			printer = ns_get_value_string(NS_KEY_USE, pobj);
			ns_printer_destroy(pobj);
		}

		if (printer == NULL)
			printer = NS_NAME_DEFAULT;
	}

	if (printer == NULL) {
		(void) fprintf(stderr, gettext("No default destination\n"));
		return (1);
	}

	if ((binding = ns_bsd_addr_get_name(printer)) == NULL) {
		(void) fprintf(stderr, gettext("%s: unknown printer\n"),
				printer);
		return (1);
	}

	if (rejecting(binding->printer) != 0) {
		(void) fprintf(stderr, gettext(
			"%s: requests are not being accepted\n"),
			printer);
		return (1);
	}

	(void) sysinfo(SI_HOSTNAME, hostname, sizeof (hostname));
#ifdef OLD_LP
	/*
	 * If the server is local, there is lp server configuration, and
	 * the old lp is still hanging around, use it to submit the job.
	 */
	{
		char	cpath[MAXPATHLEN],
			ppath[MAXPATHLEN];

		(void) snprintf(ppath, sizeof (ppath),
			"/etc/lp/printers/%s/configuration", binding->printer);
		(void) snprintf(cpath, sizeof (cpath),
			"/etc/lp/classes/%s", binding->printer);
		if ((strcasecmp(binding->server, hostname) == 0) &&
			((access(ppath, F_OK) == 0) ||
			(access(cpath, F_OK) == 0)) &&
			(access(OLD_LP, F_OK) == 0)) {
				printer = binding->printer;
				submit_local_lp(program, ac, av);
		}
	}
#endif

	if ((job = job_create(strdup(binding->printer), strdup(binding->server),
			SPOOL_DIR)) == NULL) {
		syslog(LOG_ERR,
			"Error creating job: check spooling directory: %s",
			SPOOL_DIR);
		(void) fprintf(stderr, gettext(
			"Error creating job: check spooling directory: %s\n"),
			SPOOL_DIR);
		return (-1);
	}

	(void) umask(0);
	user = get_user_name();

	ADD_PRIMATIVE(job, CF_HOST, hostname);
	ADD_PRIMATIVE(job, CF_USER, user);
	ADD_PRIMATIVE(job, CF_TITLE, title);


	if (banner != 0) {
		if (jobName != NULL) {
			ADD_PRIMATIVE(job, CF_JOBNAME, jobName);
		} else if ((av[optind] == NULL) ||
				(strcmp(av[optind], "-") == 0)) {
			ADD_PRIMATIVE(job, CF_JOBNAME, "standard input");
		} else {
			ADD_PRIMATIVE(job, CF_JOBNAME, av[optind]);
		}
		ADD_PRIMATIVE(job, CF_CLASS, (class ? class : hostname));
		ADD_PRIMATIVE(job, CF_PRINT_BANNER, user);
	}

	if (mail != 0) {
		(void) snprintf(buf, sizeof (buf), "%s@%s", user, hostname);
		ADD_PRIMATIVE(job, CF_MAIL, buf);
	}

	ADD_INT_PRIMATIVE(job, CF_INDENT, indent, -1); /* ASCII */
	ADD_INT_PRIMATIVE(job, CF_WIDTH, width, -1);

	if ((type == CF_PRINT_DVI) || (type == CF_PRINT_DROFF) ||
	    (type == CF_PRINT_TROFF)) {
		ADD_PRIMATIVE(job, CF_FONT_TROFF_R, fontR);
		ADD_PRIMATIVE(job, CF_FONT_TROFF_I, fontI);
		ADD_PRIMATIVE(job, CF_FONT_TROFF_B, fontB);
		ADD_PRIMATIVE(job, CF_FONT_TROFF_S, fontS);
	}

	if (binding->extension == NULL)
		binding->extension = "";

	if ((strcasecmp(binding->extension, NS_EXT_SOLARIS) == 0) ||
	    (strcasecmp(binding->extension, NS_EXT_GENERIC) == 0)) {
		/* RFC1179 compliant don't get this */
		syslog(LOG_DEBUG, "main(): add Solaris extensions");
		ADD_PRIMATIVE(job, CF_SYSV_OPTION, build_string(s5options));
		ADD_SVR4_INT_PRIMATIVE(job, CF_SYSV_PRIORITY, priority, -1);
		ADD_SVR4_PRIMATIVE(job, CF_SYSV_FORM, form);
		ADD_SVR4_PRIMATIVE(job, CF_SYSV_CHARSET, charset);
		ADD_SVR4_PRIMATIVE(job, CF_SYSV_NOTIFICATION, notification);
		ADD_SVR4_PRIMATIVE(job, CF_SYSV_HANDLING, handling);
		ADD_SVR4_PRIMATIVE(job, CF_SYSV_PAGES, pages);
		if (s5type != NULL) {
			ADD_SVR4_PRIMATIVE(job, CF_SYSV_TYPE, s5type);
		} else if (internal_type != NULL)
			ADD_SVR4_PRIMATIVE(job, CF_SYSV_TYPE, internal_type);
		ADD_SVR4_PRIMATIVE(job, CF_SYSV_MODE, build_string(mode));
	} else if (strcasecmp(binding->extension, NS_EXT_HPUX) == 0) {
		syslog(LOG_DEBUG, "main(): add HP-UX extensions");
		if (s5options != NULL) {
			char buf[BUFSIZ];

			(void) snprintf(buf, sizeof (buf), " O%s",
				build_string(s5options));
			ADD_PRIMATIVE(job, CF_SOURCE_NAME, buf);
		}
	} else {
		if ((s5options != NULL) || (form != NULL) || (pages != NULL) ||
		    (charset != NULL) || (notification != NULL) ||
		    (handling != NULL) || (s5type != NULL) || (mode != NULL) ||
		    (priority != -1))
			(void) fprintf(stderr, gettext(
		"Warning: %s not configured to handle all lp options:\n"),
			printer);
		OPTION_ERROR("-o", build_string(s5options));
		OPTION_ERROR("-f", form);
		OPTION_ERROR("-P", pages);
		OPTION_ERROR("-S", charset);
		OPTION_ERROR("-p", notification);
		OPTION_ERROR("-H", handling);
		OPTION_ERROR("-T", s5type);
		OPTION_ERROR("-y", build_string(mode));
		OPTION_ERROR_INT("-q", priority);
	}

	syslog(LOG_DEBUG, "main(): add files");
	if (ac-optind > 0) {
		while (optind < ac)
			if (strcmp(av[optind++], "-") == 0)
				queueStdin++;
			else if (job_add_data_file(job, av[optind-1], title,
					type, copies, linked, delete) < 0) {
				switch (errno) {
				case EISDIR:
					(void) fprintf(stderr, gettext(
						"%s: not a regular file\n"),
						av[optind-1]);
					break;
				case ESRCH:
					(void) fprintf(stderr, gettext(
						"%s: empty file\n"),
						av[optind-1]);
					break;
				case ENFILE:
					(void) fprintf(stderr, gettext(
					"too many files, ignoring %s\n"),
						av[optind-1]);
					break;
				case EOVERFLOW:
					(void) fprintf(stderr, gettext(
					"%s: largefile (>= 2GB), ignoring\n"),
						av[optind-1]);
					break;
				default:
					perror(av[optind-1]);
				}
				exit_code = -1;
			} else
				numFiles++;
	} else
		queueStdin++;

	if (queueStdin != 0) {
		char *name;

		/* standard input */
		if ((name = stdin_to_file()) != NULL) {
			if (job_add_data_file(job, name,
					gettext("standard input"),
					type, copies, 0, 0) < 0) {
				switch (errno) {
				case ESRCH:
					(void) fprintf(stderr, gettext(
						"standard input empty\n"));
					break;
				case ENFILE:
					(void) fprintf(stderr, gettext(
				"too many files, ignoring standard input\n"));
					break;
				default:
					perror(name);
				}
				exit_code = -1;
			} else
				numFiles++;
			(void) unlink(name);
			free(name);
		}
	}

	if (numFiles == 0)
		return (-1);

	if (seteuid(0) < 0)
		perror("seteuid(0)");

	(void) signal(SIGBUS, sigbus_handler);
	(void) chdir(SPOOL_DIR);
	(void) job_store(job);

	if (suppress == 0)
		if (numFiles == 1)
			(void) printf(
				gettext("request id is %s-%d (%d file)\n"),
				printer, job->job_id, numFiles);
		else
			(void) printf(
				gettext("request id is %s-%d (%d files)\n"),
				printer, job->job_id, numFiles);
	(void) fflush(stdout);

	/*
	 * bgolden 10/2/96
	 * BUG 1264627
	 * when executed from xemacs, a sighup will kill
	 * the child before the job is sent. ignore the signal
	 */
	(void) signal(SIGHUP, SIG_IGN);

	switch (fork()) {	/* for immediate response */
	case -1:
		syslog(LOG_ERR, "fork() failed: %m");
		break;
	case 0:
		break;
	default:
		return (exit_code);
	}

	if (send_job(job) == SEND_RETRY) {
		syslog(LOG_DEBUG, "main(): transfer failed");
		start_daemon(0);
	}
	else
		syslog(LOG_DEBUG, "main(): transfer succeeded");

	return (0);
}
