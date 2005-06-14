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
 * Copyright 1991-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Program to report that a volume has been requested.
 */

#include	<stdio.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/wait.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<fcntl.h>
#include	<string.h>
#include	<locale.h>
#include	<libintl.h>
#include	<syslog.h>
#include	<pwd.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/systeminfo.h>
#include	<errno.h>
#include	<limits.h>

#ifdef	bool_t
#undef	bool_t
#endif
typedef enum {false = 0, true = 1}	bool_t;

static char	*prog_name = NULL;

static char	*vol_user = NULL;
static char	*vol_username = NULL;
static bool_t	vol_user_is_root = false;
static char	*vol_volumename = NULL;
static char	*vol_mediatype = NULL;
static char	*vol_gecos = NULL;
static char	*vol_message1 = NULL;
static char	*vol_message1_nogecos = NULL;
static char	*vol_message1_system = NULL;
static char	*vol_syslogmessage = NULL;
static char	vol_hostname[MAXNAMELEN];


#define	SYSTEM_HANDLE		"The System"

#define	STD_MSG1		\
"User %s, (%s) has requested that a %s volume\n\
named %s be loaded into a drive on %s.\n"

#define	STD_MSG1_NOGECOS	\
"User %s has requested that a %s volume\n\
named %s be loaded into a drive on %s.\n"

#define	STD_MSG1_SYSTEM		\
"The system has requested that a %s volume\n\
named %s be loaded into a drive on %s.\n"

#define	STD_MSG_SYSLOG		"%s@%s requested %s named %s\n"

#define	ENV_ERROR_MSG		"failed due to undefined environment variables"

/* the windows popup program to call (by path and by name) */
#define	VOLMISSING_POPUP_PATH	"/usr/dt/lib/volmissing_popup"
#define	VOLMISSING_POPUP	"volmissing_popup"

/* the "check for windows" program to call (by path and by name) */
#define	OW_WINSYSCK_PATH	"/usr/openwin/bin/winsysck"
#define	OW_WINSYSCK		"winsysck"
#define	OW_WINSYSCK_PROTOCOL	"x11"

#define	CONSOLE			"/dev/console"
#define	BIT_BUCKET		"/dev/null"



int
main(int argc, char **argv)
{
	extern int	sysinfo(int, char *, long);
	static void	usage(void);
	static bool_t	winsysck(struct passwd *);
	static bool_t	popup_msg(struct passwd *);
	static void	console_msg(void);
	static void	syslog_msg(void);
	static void	mail_msg(char *);
	extern char 	*optarg;
	int		c;
	char		*m_alias;
	bool_t		do_console = false;
	bool_t		do_mail = false;
	bool_t		do_syslog = false;
	bool_t		do_popup = false;
	struct passwd	*pw;
#ifdef	DEBUG
	struct passwd	*orig_pw;
#endif
	struct stat	statbuf;
	bool_t		do_manual_message = false;



#ifdef DEBUG
	(void) fprintf(stderr, "BEGIN volmissing\n");

	if ((orig_pw = getpwuid(getuid())) == NULL) {
		(void) fprintf(stderr, "Couldn't get uid at startup\n");
	} else {

		(void) fprintf(stderr, "username at startup = '%s'\n",
		    orig_pw->pw_name);
		(void) fprintf(stderr, "uid at startup = %d\n",
		    orig_pw->pw_uid);
		(void) fprintf(stderr, "euid at startup = %ld\n", geteuid());
		(void) fprintf(stderr, "gid at startup = %d\n",
		    orig_pw->pw_gid);
		(void) fprintf(stderr, "egid at startup = %ld\n", getegid());

	}
#endif

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	prog_name = argv[0];

	/* process arguments */
	while ((c = getopt(argc, argv, "scpm:")) != EOF) {
		switch (c) {
		case 's':
			do_syslog = true;
			break;
		case 'c':
			do_console = true;
			break;
		case 'p':
			do_popup = true;
			break;
		case 'm':
			do_mail = true;
			m_alias = optarg;
			break;
		default:
			usage();
			return (-1);
		}
	}

	vol_user = getenv("VOLUME_USER");
	vol_volumename = getenv("VOLUME_NAME");
	vol_mediatype = getenv("VOLUME_MEDIATYPE");

	/*
	 * Can't run this puppy if no Environment variables
	 * are defined.
	 */

	if ((vol_user == NULL) || (vol_volumename == NULL) ||
	    (vol_mediatype == NULL)) {
		(void) fprintf(stderr, "%s: %s\n", prog_name,
		    gettext(ENV_ERROR_MSG));
		return (-1);
	}

	if ((pw = getpwnam(vol_user)) == NULL) {
		/* can't get an entry for this user name! */
		vol_username = vol_user;
		vol_gecos = NULL;
	} else {
		if (pw->pw_uid == 0) {
			/* root -- let's pretty that up */
			vol_username = strdup(SYSTEM_HANDLE);
			vol_user_is_root = true;
			vol_gecos = NULL;
		} else {
			/* non-root user who's name is found in passwd map */
			vol_username = strdup(pw->pw_name);
			vol_gecos = strdup(pw->pw_gecos);
		}
	}

#ifdef DEBUG
	(void) fprintf(stderr, "volmissing: BEGIN ENV VARS\n\n");
	(void) fprintf(stderr, "vol_user = '%s'\n", vol_user);
	(void) fprintf(stderr, "vol_username = '%s'\n", vol_username);
	(void) fprintf(stderr, "vol_gecos = '%s'\n",
	    vol_gecos ? vol_gecos : "No Gecos");
	(void) fprintf(stderr, "vol_volumename = '%s'\n", vol_volumename);
	(void) fprintf(stderr, "vol_mediatype = '%s'\n", vol_mediatype);
	(void) fprintf(stderr, "pw->pw_name = '%s'\n", pw->pw_name);
	(void) fprintf(stderr, "pw->pw_uid  = %d\n", pw->pw_uid);
	(void) fprintf(stderr, "euid        = %ld\n", geteuid());
	(void) fprintf(stderr, "pw->pw_gid         = %d\n", pw->pw_gid);
	(void) fprintf(stderr, "egid	     = %ld\n\n", getegid());
	(void) fprintf(stderr, "volmissing: END ENV VARS\n\n");
#endif

	/*
	 * If this is a volmissing event was caused by the system
	 * the user id will be "root". "root" processes will
	 * not be able to connect to a display owned by a non-root
	 * user. So, we have to fake it out and make it think
	 * the new process is really owned by the user. We'll
	 * figure out who owns /dev/console and make that user
	 * the user who'll own this process.
	 */

	if (pw->pw_uid == 0) {

#ifdef DEBUG
		(void) fprintf(stderr, "volmissing: event started by root\n");
#endif
		if (stat(CONSOLE, &statbuf) != 0) {
			perror("volmissing: stat of /dev/console failed");
			return (1);
		} else {
#ifdef DEBUG
			(void) fprintf(stderr,
			    "volmissing: stat on dev console worked\n");
#endif
			/*
			 * Now we need to get the passwd struct for the
			 * userid that owns /dev/console. This is for the
			 * setuid stuff later when we fork/exec. If
			 * getpwuid returns null we'll catch it later.
			 */

			if ((pw = getpwuid(statbuf.st_uid)) == NULL) {

#ifdef DEBUG
				(void) fprintf(stderr,
			"volmissing: getpwuid failed for console owner\n");
#endif
				/*
				 * We couldn't get the passwd struct for
				 * console owner. We better reset the vol env
				 * vars as they are dependent on pw struct
				 * contents. This way the console_msg()
				 * will still work.
				 */

				vol_username = vol_user;
				vol_gecos = NULL;
			}

		}

	}

	sysinfo(SI_HOSTNAME, vol_hostname, sizeof (vol_hostname));

	vol_message1 = gettext(STD_MSG1);
	vol_message1_nogecos = gettext(STD_MSG1_NOGECOS);
	vol_message1_system = gettext(STD_MSG1_SYSTEM);
	vol_syslogmessage = gettext(STD_MSG_SYSLOG);

	if (do_syslog) {
		syslog_msg();
	}

	if (do_console) {
		console_msg();
	}

	if (do_mail) {
		mail_msg(m_alias);
	}

	if (do_popup) {

		/*
		 * We can only display a popup if a windows session
		 * is running and we know the user's uid from the
		 * passwd structure. We need to know the uid so
		 * we can setuid to the user and get access to
		 * his X display for the popup.
		 *
		 * (To keep from having to actually check for X
		 * running, we'll just try to run the popup, assuming
		 * it will fail if windows are not running.)
		 */
		if ((access(VOLMISSING_POPUP_PATH, X_OK) != 0) ||
		    (access(OW_WINSYSCK_PATH, X_OK) != 0) ||
		    (pw == NULL)) {
			do_manual_message = true;
		}
		if (!do_manual_message) {
			if (!winsysck(pw)) {
				do_manual_message = true;
			}
		}
		if (!do_manual_message) {
			if (!popup_msg(pw)) {
				do_manual_message = true;
			}
		}
		if (do_manual_message) {

			/*
			 * Don't want to display the same message twice.
			 */

			if (!do_console) {
				console_msg();
			}
		}

	}

	if (!do_syslog && !do_mail && !do_console && !do_popup) {
		console_msg();
	}

#ifdef	DEBUG
	(void) fprintf(stderr, "END volmissing\n");
#endif
	return (0);
}


static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: %s [-c] [-s] [-m alias] \n"), prog_name);
}


static void
syslog_msg(void)
{
	openlog("volume management", 0, LOG_DAEMON);
	syslog(LOG_DAEMON|LOG_CRIT, vol_syslogmessage, vol_username,
		vol_hostname, vol_mediatype, vol_volumename);
	closelog();
}


static void
console_msg(void)
{
	FILE	*fp;


	if ((fp = fopen(CONSOLE, "w")) == NULL) {
		perror(CONSOLE);
		return;
	}

	if (vol_user_is_root) {
		(void) fprintf(fp, vol_message1_system, vol_mediatype,
		    vol_volumename, vol_hostname);
	} else if (vol_gecos) {
		(void) fprintf(fp, vol_message1, vol_username, vol_gecos,
		    vol_mediatype, vol_volumename, vol_hostname);
	} else {
		(void) fprintf(fp, vol_message1_nogecos, vol_username,
		    vol_mediatype, vol_volumename, vol_hostname);
	}
	(void) fprintf(fp, "\007\007\007");	/* beep at them */
	(void) fclose(fp);
}


/*
 * try to exec the popup message
 * return false on error, else true
 */
static bool_t
popup_msg(struct passwd *pw)
{

	pid_t		pid;
	int 		exit_code;
	int		fd;
	char		ld_lib_path[MAXNAMELEN];
	char		*home_dir;
	char		display_name[MAXNAMELEN+12];
	bool_t		ret_val = false;


	/*
	 * fork a simple X Windows program to display gui for
	 * notifying the user that the specified media is missing.
	 */

#ifdef DEBUG
	(void) fprintf(stderr, "In popup_msg()\n");
	(void) fprintf(stderr, "passwd struct - pw->pw_uid = %d\n",
	    pw->pw_uid);
	(void) fprintf(stderr, "passwd struct - pw->pw_gid = %d\n",
	    pw->pw_gid);
	(void) fprintf(stderr, "passwd struct - pw->pw_dir = '%s'\n",
	    pw->pw_dir);
#endif

	if ((pid = fork()) < 0) {
		(void) fprintf(stderr,
			gettext("volmissing: error: can't fork a process\n"));
		goto dun;
	}

	if (pid == 0) {

		/*
		 * Error messages to console
		 */

		if ((fd = open(CONSOLE, O_RDWR)) >= 0) {
			(void) dup2(fd, fileno(stdin));
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
		}

		/*
		 * Set up the users environment.
		 */

		(void) sprintf(display_name, "DISPLAY=%s:0.0", vol_hostname);
		(void) putenv(display_name);
		(void) putenv("OPENWINHOME=/usr/openwin");

		(void) sprintf(ld_lib_path, "LD_LIBRARY_PATH=%s",
		    "/usr/openwin/lib");
		(void) putenv(ld_lib_path);

		/*
		 * We need to set $HOME so the users .Xauthority file
		 * can be located. This is especially needed for a user
		 * user MIT Magic Cookie authentication security.
		 */

		home_dir = malloc(strlen(pw->pw_dir) + 6);
		if (home_dir == NULL) {
			perror("malloc");
			exit(1);
		}
		(void) strcpy(home_dir, "HOME=");
		(void) strcat(home_dir, pw->pw_dir);
		(void) putenv(home_dir);

		/*
		 * We need the volmissing popup to be owned
		 * by the owner of the X display.
		 * Don't want x program doing anything nasty.
		 *
		 * Note - have to set gid stuff first as effective uid
		 * must belong to root for this to work correctly.
		 */

		(void) setgid(pw->pw_gid);
		(void) setegid(pw->pw_gid);
		(void) setuid(pw->pw_uid);
		(void) seteuid(pw->pw_uid);

#ifdef DEBUG
		(void) fprintf(stderr, "%s being execl'ed\n",
		    VOLMISSING_POPUP_PATH);
#endif

		(void) execl(VOLMISSING_POPUP_PATH, VOLMISSING_POPUP, NULL);

		(void) fprintf(stderr,
		    gettext("exec of %s failed; errno = %d"),
		    VOLMISSING_POPUP_PATH, errno);

		exit(1);
	}

	/* the parent - will wait for child (volmissing_popup) to exit */
	if (waitpid(pid, &exit_code, 0) == pid) {
		if (WIFEXITED(exit_code)) {
			if (WEXITSTATUS(exit_code) == 0) {
				ret_val = true;		/* success */
			}
		}
	}

dun:
	return (ret_val);
}


static void
mail_msg(char *to)
{
	char	*subj = gettext("volume management request");
	int	p[2], outfd, status;
	pid_t	pid;
	char	mbuf[LINE_MAX];

	if (pipe(p) == -1) {
		perror("pipe");
		return;
	}

	if ((pid = fork()) == -1) {
		perror("fork");
		return;
	}
	if (pid == 0) {
		(void) dup2(p[0], 0);
		(void) close(p[1]);
		(void) execl("/bin/mail", "mail", to, NULL);
		perror("mail");
		exit(1);
	}
	(void) close(p[0]);
	outfd = p[1];

	(void) snprintf(mbuf, sizeof (mbuf), "Subject: %s\n\n", subj);
	(void) write(outfd, mbuf, strlen(mbuf));
	if (vol_user_is_root) {
		(void) snprintf(mbuf, sizeof (mbuf), vol_message1_system,
		    vol_mediatype, vol_volumename, vol_hostname);
		(void) write(outfd, mbuf, strlen(mbuf));
	} else if (vol_gecos) {
		(void) snprintf(mbuf, sizeof (mbuf), vol_message1,
		    vol_username, vol_gecos, vol_mediatype, vol_volumename,
		    vol_hostname);
		(void) write(outfd, mbuf, sizeof (mbuf));
	} else {
		(void) snprintf(mbuf, sizeof (mbuf), vol_message1_nogecos,
		    vol_username, vol_mediatype, vol_volumename, vol_hostname);
		(void) write(outfd, mbuf, sizeof (mbuf));
	}
	(void) close(outfd);
	(void) waitpid(pid, &status, 0);
}

/*
 * Use a popup window to display the "manually ejectable"
 * message for X86 machines.
 *
 * return flase if the popup fails, else return true
 */
static bool_t
winsysck(struct passwd *pw)
{
	pid_t		pid;
	int		exit_code = -1;
	bool_t		ret_val = false;
	int		fd;
	char		*home_dir;
	char		ld_lib_path[MAXNAMELEN];



	if ((pid = fork()) < 0) {
		(void) fprintf(stderr,
		    gettext("error: can't fork a process (errno %d)\n"),
		    errno);
		goto dun;
	}

	if (pid == 0) {

		/*
		 * error messages to console
		 */

#ifndef	DEBUG
		if ((fd = open(BIT_BUCKET, O_RDWR)) >= 0) {
			(void) dup2(fd, fileno(stdin));
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
		}
#endif

		/*
		 * set up the users environment
		 */
		(void) putenv("DISPLAY=:0.0");
		(void) putenv("OPENWINHOME=/usr/openwin");

		(void) sprintf(ld_lib_path, "LD_LIBRARY_PATH=%s",
		    "/usr/openwin/lib");
		(void) putenv(ld_lib_path);

		/*
		 * we need to set $HOME so the users .Xauthority file
		 * can be located. This is especially needed for a user
		 * user MIT Magic Cookie authentication security
		 */

		home_dir = malloc(strlen(pw->pw_dir) + 6);
		if (home_dir == NULL) {
			perror("malloc");
			exit(1);
		}
		(void) strcpy(home_dir, "HOME=");
		(void) strcat(home_dir, pw->pw_dir);
		(void) putenv(home_dir);

		/*
		 * We need the X application to be able to connect to
		 * the user's display so we better run as if we are
		 * the user (effectively).
		 * Don't want x program doing anything nasty.
		 *
		 * Note - have to set gid stuff first as effective uid
		 *	  must belong to root for this to work correctly.
		 */
		(void) setgid(pw->pw_gid);
		(void) setegid(pw->pw_gid);
		(void) setuid(pw->pw_uid);
		(void) seteuid(pw->pw_uid);

#ifdef DEBUG
		(void) fprintf(stderr,
		    "DEBUG: \"%s\" being execl'ed with protocol = \"%s\"\n",
		    OW_WINSYSCK_PATH, OW_WINSYSCK_PROTOCOL);
#endif

		(void) execl(OW_WINSYSCK_PATH, OW_WINSYSCK,
		    OW_WINSYSCK_PROTOCOL, NULL);

		(void) fprintf(stderr,
		    gettext("error: exec of \"%s\" failed (errno = %d)\n"),
		    OW_WINSYSCK_PATH, errno);
		exit(-1);

	}

	/* the parent -- wait for the child */
	if (waitpid(pid, &exit_code, 0) == pid) {
		if (WIFEXITED(exit_code)) {
			if (WEXITSTATUS(exit_code) == 0) {
				ret_val = true;
			}
		}
	}

dun:
	/* all done */
#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: winsysck() returning %s\n",
	    ret_val ? "true" : "false");
#endif
	return (ret_val);
}
