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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * This code has a lot in common with the original sys-suspend
 * code.  Windowing facilities have been removed, and it has been
 * updated to use more recent API's.
 */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <utility.h>
#include <signal.h>
#include <errno.h>
#include <setjmp.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/uadmin.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <secdb.h>
#include <security/pam_appl.h>
#include <utmpx.h>

/* For audit */
#include <bsm/adt.h>
#include <bsm/adt_event.h>

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/pm.h>
#include <dirent.h>
#include <sys/cpr.h>

/* STATICUSED */
struct utmpx 	utmp;
#define	NMAX		(sizeof (utmp.ut_name))

/*
 * Authorizations used by Power Management
 */
#define	AUTHNAME_SHUTDOWN	"solaris.system.shutdown"
#define	AUTHNAME_SUSPEND_RAM	"solaris.system.power.suspend.ram"
#define	AUTHNAME_SUSPEND_DISK	"solaris.system.power.suspend.disk"

/* Platform specific definitions */
#ifdef i386
#define	AD_CHECK_SUSPEND	AD_CHECK_SUSPEND_TO_RAM
#define	AD_SUSPEND		AD_SUSPEND_TO_RAM
#define	ADT_FCN			ADT_UADMIN_FCN_AD_SUSPEND_TO_RAM
#define	AUTHNAME_SUSPEND	AUTHNAME_SUSPEND_RAM
#else
#define	AD_CHECK_SUSPEND	AD_CHECK_SUSPEND_TO_DISK
#define	AD_SUSPEND		AD_SUSPEND_TO_DISK
#define	ADT_FCN			ADT_UADMIN_FCN_AD_SUSPEND_TO_DISK
#define	AUTHNAME_SUSPEND	AUTHNAME_SUSPEND_DISK
#endif

static	int		flags = 0;
static	int		no_tty = 0;
/*
 * Flag definitions - could go in a header file, but there are just a few
 */
#define	FORCE		0x001
#define	NO_WARN		0x002
#define	NO_XLOCK	0x004
#define	SHUTDOWN	0x008
#define	LOWPOWER	0x010
#define	TEST		0x800

static	sigjmp_buf	jmp_stack;
static	char	user[NMAX + 1];
static	char	**argvl;



/*
 *  Forward Declarations.
 */
static	void	pm_poweroff(void);
static	int	bringto_lowpower(void);
static	int	is_mou3(void);
static	void	suspend_error(int);
static	int	pm_check_suspend(void);
static	void	pm_suspend(void);
static	void	pm_do_auth(adt_session_data_t *);

/*
 *  External Declarations.
 */
extern	int	pam_tty_conv(int, struct pam_message **,
    struct pam_response **, void *);
extern	char	*optarg;

/*
 * Audit related code.  I would also think that some of this could be
 * in external code, as they could be useful of other apps.
 */
/*
 * Write audit event.  Could be useful in the PM library, so it is
 * included here.  For the most part it is only used by the PAM code.
 */
static void
pm_audit_event(adt_session_data_t *ah, au_event_t event_id, int status)
{
	adt_event_data_t	*event;


	if ((event = adt_alloc_event(ah, event_id)) == NULL) {
		return;
	}

	(void) adt_put_event(event,
	    status == PAM_SUCCESS ? ADT_SUCCESS : ADT_FAILURE,
	    status == PAM_SUCCESS ? ADT_SUCCESS : ADT_FAIL_PAM + status);

	adt_free_event(event);
}

#define	RETRY_COUNT 15
static int
change_audit_file(void)
{
	pid_t	pid;

	if (!adt_audit_state(AUC_AUDITING)) {
		/* auditd not running, just return */
		return (0);
	}

	if ((pid = fork()) == 0) {
		(void) execl("/usr/sbin/audit", "audit", "-n", NULL);
		(void) fprintf(stderr, gettext("error changing audit files: "
		    "%s\n"), strerror(errno));
		_exit(-1);
	} else if (pid == -1) {
		(void) fprintf(stderr, gettext("error changing audit files: "
		    "%s\n"), strerror(errno));
		return (-1);
	} else {
		pid_t	rc;
		int	retries = RETRY_COUNT;

		/*
		 * Wait for audit(1M) -n process to complete
		 *
		 */
		do {
			if ((rc = waitpid(pid, NULL, WNOHANG)) == pid) {
				return (0);
			} else if (rc == -1) {
				return (-1);
			} else {
				(void) sleep(1);
				retries--;
			}

		} while (retries != 0);
	}
	return (-1);
}

static void
wait_for_auqueue()
{
	au_stat_t	au_stat;
	int		retries = 10;

	while (retries-- && auditon(A_GETSTAT, (caddr_t)&au_stat, NULL) == 0) {
		if (au_stat.as_enqueue == au_stat.as_written) {
			break;
		}
		(void) sleep(1);
	}
}

/* End of Audit-related code */

/* ARGSUSED0 */
static void
alarm_handler(int sig)
{
	siglongjmp(jmp_stack, 1);
}

/*
 * These are functions that would be candidates for moving to a library.
 */

/*
 * pm_poweroff - similar to poweroff(1M)
 * This should do the same auditing as poweroff(1m) would do when it
 * becomes a libpower function.  Till then we use poweroff(1m).
 */
static void
pm_poweroff(void)
{
	if (chkauthattr(AUTHNAME_SHUTDOWN, user) != 1) {
		(void) printf(gettext("User %s does not have correct "
		    "authorizations to shutdown this machine.\n"), user);
		exit(1);
	}
	openlog("suspend", 0, LOG_DAEMON);
	syslog(LOG_NOTICE, "System is being shut down.");
	closelog();

	/*
	 * Call poweroff(1m) to shut down the system.
	 */
	(void) execl("/usr/sbin/poweroff", "poweroff", NULL);

}

/*
 * pm_check_suspend() - Check to see if suspend is supported/enabled
 * on this machine.
 * Ultimately, we would prefer to get the "default" suspend type from
 * a PM property or some other API, but for now, we know that STR is
 * only available on x86 and STD is only available on Sparc.  It does
 * make this function quite easy, though.
 */
static int
pm_check_suspend(void) {
	/*
	 * Use the uadmin(2) "CHECK" command to see if suspend is supported
	 */
	return (uadmin(A_FREEZE, AD_CHECK_SUSPEND, 0));
}

/*
 * This entry point _should_ be the common entry to suspend.  It is in
 * it's entirety here, but would be best moved to libpower when that
 * is available.
 */
static void
pm_suspend(void)
{
	int			cprarg = AD_SUSPEND;
	enum adt_uadmin_fcn	fcn_id = ADT_FCN;
	au_event_t		event_id = ADT_uadmin_freeze;
	adt_event_data_t	*event = NULL; /* event to be generated */
	adt_session_data_t	*ah = NULL;  /* audit session handle */

	/*
	 * Does the user have permission to use this command?
	 */
	if (chkauthattr(AUTHNAME_SUSPEND, user) != 1) {
		(void) printf(gettext("User %s does not have correct "
		    "authorizations to suspend this machine.\n"), user);
		exit(1);
	}

	if (flags & LOWPOWER) {
		if (bringto_lowpower() == -1) {
			(void) printf(gettext("LowPower Failed\n"));
			exit(1);
		}
	} else if (flags & TEST) {
		/*
		 * Test mode, do checks as if a real suspend, but
		 * don't actually do the suspend.
		 */
		/* Check if suspend is supported */
		if (pm_check_suspend() == -1) {
			suspend_error(errno);
		}

		(void) printf(gettext("TEST: Suspend would have been"
		    " performed\n"));

	} else {
		/* Check if suspend is supported */
		if (pm_check_suspend() == -1) {
			suspend_error(errno);
		}

		/*
		 * We are about to suspend this machine, try and
		 * lock the screen.  We don't really care if this
		 * succeeds or not, but that we actually tried. We
		 * also know that we have sufficient privileges to
		 * be here, so we lock the screen now, even if
		 * suspend actually fails.
		 * Note that garbage is sometimes displayed, and
		 * we don't really care about it, so we toss all
		 * text response.
		 * it would also be good if there were another option
		 * instead of launcing a file, as the disk might be
		 * spun down if we are suspending due to idle.
		 */
		if (!(flags & NO_XLOCK)) {
			(void) system("/usr/bin/xdg-screensaver lock "
			    " >/dev/null 2>&1");
		}

		/* Time to do the actual deed!  */
		/*
		 * Before we actually suspend, we need to audit and
		 * "suspend" the audit files.
		 */
		/* set up audit session and event */
		if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA) == 0) {
			if ((event = adt_alloc_event(ah, event_id)) != NULL) {
				event->adt_uadmin_freeze.fcn = fcn_id;
				event->adt_uadmin_freeze.mdep = NULL;
				if (adt_put_event(event, ADT_SUCCESS, 0) != 0) {
					(void) fprintf(stderr, gettext(
					    "%s: can't put audit event\n"),
					    argvl[0]);
				} else {
					wait_for_auqueue();
				}
			}
			(void) change_audit_file();
		} else {
			(void) fprintf(stderr, gettext(
			    "%s: can't start audit session\n"), argvl[0]);
		}

		if (uadmin(A_FREEZE, cprarg, 0) != 0) {
			(void) printf(gettext("Suspend Failed\n"));
			if (flags & FORCE) {
				/*
				 * Note, that if we actually poweroff,
				 * that the poweroff function will handle
				 * that audit trail, and the resume
				 * trail is effectively done.
				 */
				pm_poweroff();
			} else {
				/* suspend_error() will exit. */
				suspend_error(errno);
				/*
				 * Audit the suspend failure and
				 * reuse the event, but don't create one
				 * if we don't already have one.
				 */
				if (event != NULL) {
					(void) adt_put_event(event,
					    ADT_FAILURE, 0);
				}
			}
		}

		/*
		 * Write the thaw event.
		 */
		if (ah != NULL) {
			if ((event == NULL) &&
			    ((event = adt_alloc_event(ah, ADT_uadmin_thaw))
			    == NULL)) {
				(void) fprintf(stderr, gettext(
				    "%s: can't allocate thaw audit event\n"),
				    argvl[0]);
			} else {
				event->adt_uadmin_thaw.fcn = fcn_id;
				if (adt_put_event(event, ADT_SUCCESS, 0) != 0) {
					(void) fprintf(stderr, gettext(
					    "%s: can't put thaw audit event\n"),
					    argvl[0]);
				}
				(void) adt_free_event(event);
			}
		}
	}
	if ((no_tty ? 0 : 1) && !(flags & NO_XLOCK)) {
		pm_do_auth(ah);
	}

	(void) adt_end_session(ah);
}
/* End of "library" functions */

/*
 * Print an appropriate error message and exit.
 */

static void
suspend_error(int error) {

	switch (error) {
	case EBUSY:
		(void) printf(gettext("suspend: "
		    "Suspend already in progress.\n\n"));
		exit(1);
		/*NOTREACHED*/
	case ENOMEM:
		/*FALLTHROUGH*/
	case ENOSPC:
		(void) printf(gettext("suspend: "
		    "Not enough resources to suspend.\n\n"));
		exit(1);
		/*NOTREACHED*/
	case ENOTSUP:
		(void) printf(gettext("suspend: "
		    "Suspend is not supported.\n\n"));
		exit(1);
		/*NOTREACHED*/
	case EPERM:
		(void) printf(gettext("suspend: "
		    "Not sufficient privileges.\n\n"));
		exit(1);
		/*NOTREACHED*/
	default:
		(void) printf(gettext("suspend: "
		    "unknown error.\n\n"));
		exit(1);
	}

}

/*
 * refresh_dt() - Refresh screen when 'dtgreet' is running.
 * This is here for compatibility reasons, and could be removed once
 * dtgreet is no longer part of the system.
 */
static int
refresh_dt()
{
	int	status;
	struct stat	stat_buf;

	/*
	 * If dtgreet exists, HUP it, otherwise just let screenlock
	 * do it's thing.
	 */
	if ((stat("/usr/dt/bin/dtgreet", &stat_buf) == 0) &&
	    (stat_buf.st_mode & S_IXUSR)) {
		switch (fork()) {
		case -1:
			break;
		case 0:
			(void) close(1);
			(void) execl("/usr/bin/pkill", "pkill",
			    "-HUP", "-u", "0", "-x", "dtgreet", NULL);
			break;
		default:
			(void) wait(&status);
		}
	}

	return (0);
}

#define	DT_TMP	"/var/dt/tmp"

/*
 * On enter, the "xauthority" string has the value "XAUTHORITY=".  On
 * return, if a Xauthority file is found, concatenate it to this string,
 * otherwise, return "xauthority" as it is.
 */
static char *
get_xauthority(char *xauthority)
{
	pid_t uid;
	char *home_dir;
	struct passwd *pwd;
	char filepath[MAXPATHLEN];
	struct stat stat_buf;
	DIR *dirp;
	struct dirent *dp;
	char xauth[MAXPATHLEN] = "";
	time_t latest = 0;

	uid = getuid();

	/*
	 * Determine home directory of the user.
	 */
	if ((home_dir = getenv("HOME")) == NULL) {
		if ((pwd = getpwuid(uid)) == NULL) {
			(void) printf(gettext("Error: unable to get passwd "
			    "entry for user.\n"));
			exit(1);
		}
		home_dir = pwd->pw_dir;
	}
	if ((strlen(home_dir) + sizeof ("/.Xauthority")) >= MAXPATHLEN) {
		(void) printf(gettext("Error: path to home directory is too "
		    "long.\n"));
		exit(1);
	}

	/*
	 * If there is a .Xauthority file in home directory, reference it.
	 */
	/*LINTED*/
	(void) sprintf(filepath, "%s/.Xauthority", home_dir);
	if (stat(filepath, &stat_buf) == 0)
		return (strcat(xauthority, filepath));

	/*
	 * If Xsession can not access user's home directory, it creates the
	 * Xauthority file in "/var/dt/tmp" directory.  Since the exact
	 * name of the Xauthority is not known, search the directory and
	 * find the last changed file that starts with ".Xauth" and owned
	 * by the user.  Hopefully, that is the valid Xauthority file for
	 * the current X session.
	 */
	if ((dirp = opendir(DT_TMP)) == NULL)
		return (xauthority);

	while ((dp = readdir(dirp)) != NULL) {
		if (strstr(dp->d_name, ".Xauth") != NULL) {
			/*LINTED*/
			(void) sprintf(filepath, "%s/%s", DT_TMP, dp->d_name);
			if (stat(filepath, &stat_buf) == -1)
				continue;
			if (stat_buf.st_uid != uid)
				continue;
			if (stat_buf.st_ctime > latest) {
				(void) strcpy(xauth, filepath);
				latest = stat_buf.st_ctime;
			}
		}
	}
	(void) closedir(dirp);

	return (strcat(xauthority, xauth));
}

/*
 * suspend can be called in following ways:
 *	1. from daemon (powerd) for auto-shutdown.
 *		a. there might be a OW/CDE environment
 *		b. there might not be any windowing environment
 *      2. by a user entered command.
 *		a. the command can be entered from a cmdtool type OW/CDE tool
 *		b. the command can be entered by a user logged in on a dumb
 *		   terminal.
 *			i) there might be a OW/CDE running on console
 *			   and we have permission to talk to it.
 *			ii) there is no OW/CDE running on console or we
 *			   don't have permission to talk to it or console
 *			   itself is the dumb terminal we have logged into.
 *
 * In main(), we decide on the correct case and call appropriate functions.
 */

int
main(int argc, char **argv)
{
	int		c;
	char		display_name[MAXNAMELEN + 9] = "DISPLAY=";
	char		xauthority[MAXPATHLEN + 12] = "XAUTHORITY=";
	struct passwd 	*pw;

	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGTSTP, SIG_IGN);
	(void) signal(SIGTTIN, SIG_IGN);
	(void) signal(SIGTTOU, SIG_IGN);

	/*
	 * If suspend is invoked from a daemon (case 1 above), it
	 * will not have a working stdin, stdout and stderr. We need
	 * these to print proper error messages and possibly get user
	 * input. We attach them to console and hope that attachment
	 * works.
	 */
	if (ttyname(0) == NULL) {
		no_tty = 1;
		(void) dup2(open("/dev/console", O_RDONLY), 0);
		(void) dup2(open("/dev/console", O_WRONLY), 1);
		(void) dup2(open("/dev/console", O_WRONLY), 2);
	}

	while ((c = getopt(argc, argv, "fnxhtd:")) != EOF) {
		switch (c) {
			case 'f':
				/*
				 * Force machine to poweroff if
				 * suspend fails
				 */
				flags |= FORCE;
				break;
			case 'n':
				/* No warning popups - Obsolete */
				flags |= NO_WARN;
				break;
			case 'x':
				/* Don't try to screenlock */
				flags |= NO_XLOCK;
				break;
			case 'h':
				/* Do a shutdown instead of suspend */
				flags |= SHUTDOWN;
				break;
			case 'd':
				/* Needswork */
				/* Set the DISPLAY value in the environment */
				if (strlen(optarg) >= MAXNAMELEN) {
					(void) printf(gettext("Error: "
					    "display name is too long.\n"));
					return (1);
				}
				(void) strcat(display_name, optarg);
				if (putenv(display_name) != 0) {
					(void) printf(gettext("Error: "
					    "unable to set DISPLAY "
					    "environment variable.\n"));
					return (1);
				}
				break;
			case 't':
				/* Test, don't actually do any operation */
				flags |= TEST;
				break;
			default:
				(void) printf(gettext("USAGE: suspend "
				    "[-fnxh] [-d <display>]\n"));
				return (1);
		}
	}

	/*
	 * The action of pressing power key and power button on a MOU-3 machine
	 * causes suspend being invoked with SYSSUSPENDDODEFAULT
	 * enviromental variable set - indicating the default action is machine
	 * dependent: for MOU-3 type machine, "LowPower" mode is the default,
	 * for all the rest, "Suspend" is the default.  Existing suspend
	 * flags works the same.
	 */
	if (getenv("SYSSUSPENDDODEFAULT"))
		if (is_mou3())
			flags |= LOWPOWER;

	if ((flags & FORCE) && (flags & LOWPOWER))
		flags &= ~LOWPOWER;

	/*
	 * Flag "-h" overrides flag "-f".
	 */
	if ((flags & SHUTDOWN) && (flags & FORCE))
		flags &= ~(FORCE | LOWPOWER);

	if (flags & FORCE)
		flags |= NO_WARN;

	/*
	 * Check initally if the user has the authorizations to
	 * do either a suspend or shutdown.  pm_suspend() will also
	 * make this test, so we could defer till then, but if we
	 * do it now, we at least prevent a lot of unneeded setup.
	 */
	pw = getpwuid(getuid());
	(void) strncpy(user, pw->pw_name, NMAX);

	if ((flags & (FORCE|SHUTDOWN)) &&
	    (chkauthattr(AUTHNAME_SHUTDOWN, pw->pw_name) != 1)) {
		(void) printf(gettext("User does not have correct "
		    "authorizations to shutdown the machine.\n"));
		exit(1);
	}
	if (!(flags & SHUTDOWN) &&
	    (chkauthattr(AUTHNAME_SUSPEND, pw->pw_name) != 1)) {
		(void) printf(gettext("User does not have correct "
		    "authorizations to suspend.\n"));
		exit(1);
	}

	/*
	 * If we are only shutting down, there isn't much to do, just
	 * call pm_poweroff(), and let it do all the work.
	 */
	if (flags & SHUTDOWN) {
		/*
		 * pm_poweroff either powers off or exits,
		 * so there is no return.
		 */
		if (flags & TEST) {
			(void) printf("TEST: This machine would have "
			    "powered off\n");
			exit(1);
		} else {
			pm_poweroff();
		}
		/* NOTREACHED */
	}

	/*
	 * If XAUTHORITY environment variable is not set, try to set
	 * one up.
	 */
	if (getenv("XAUTHORITY") == NULL)
		(void) putenv(get_xauthority(xauthority));

	/*
	 * In case of "suspend" being called from daemon "powerd",
	 * signal SIGALRM is blocked so use "sigset()" instead of "signal()".
	 */
	(void) sigset(SIGALRM, alarm_handler);

	/* Call the "suspend" function to do the last of the work */
	pm_suspend();

	if (refresh_dt() == -1) {
		(void) printf("%s: Failed to refresh screen.\n", argv[0]);
		return (1);
	}
	return (0);
}

#include <sys/pm.h>

/*
 * Note that some of these functions are more relevant to Sparc platforms,
 * but they do function properly on other platforms, they just don't do
 * as much.
 */
/*
 * bringto_lowpower()
 * This tells the PM framework to put the devices it controls in an idle
 * state.  The framework only complains if a device that *must* be idle
 * doesn't succeed in getting there.
 */
static int
bringto_lowpower()
{
	int	fd;

	if ((fd = open("/dev/pm", O_RDWR)) < 0) {
		(void) printf(gettext("Can't open /dev/pm\n"));
		return (-1);
	}

	if (ioctl(fd, PM_IDLE_DOWN, NULL) < 0) {
		(void) printf(gettext("Failed to bring system "
		    "to low power mode.\n"));
		(void) close(fd);
		return (-1);
	}
	(void) close(fd);
	return (0);
}

#include <sys/cpr.h>

/*
 * Though this test is predominantly used on Sparc, it will run on other
 * platforms, and might be usefull one day on those.
 */
static int
is_mou3()
{
	struct cprconfig	cf;
	int			fd;
	int			found = 0;

	if ((fd = open(CPR_CONFIG, O_RDONLY)) < 0) {
		(void) printf(gettext("Can't open /etc/.cpr_config file."));
		return (found);
	}

	if (read(fd, (void *) &cf, sizeof (cf)) != sizeof (cf)) {
		(void) printf(gettext("Can't read /etc/.cpr_config file."));
	} else {
		found = cf.is_autopm_default;
	}

	(void) close(fd);
	return (found);
}

/*
 * Reauthenticate the user on return from suspend.
 * This is here and not in the PAM-specific file, as there are
 * items specific to sys-suspend, and not generic to PAM.  This may
 * become part of a future PM library.  The audit handle is passed,
 * as the pm_suspend code actually starts an audit session, so it
 * makes sense to just continue to use it.  If it were separated
 * from the pm_suspend code, it will need to open a new session.
 */
#define	DEF_ATTEMPTS	3
static void
pm_do_auth(adt_session_data_t *ah)
{
	pam_handle_t	*pm_pamh;
	int		err;
	int		pam_flag = 0;
	int		chpasswd_tries;
	struct pam_conv pam_conv = {pam_tty_conv, NULL};

	if (user[0] == '\0')
		return;

	if ((err = pam_start("sys-suspend", user, &pam_conv,
	    &pm_pamh)) != PAM_SUCCESS)
		return;

	pam_flag = PAM_DISALLOW_NULL_AUTHTOK;

	do {
		err = pam_authenticate(pm_pamh, pam_flag);

		if (err == PAM_SUCCESS) {
			err = pam_acct_mgmt(pm_pamh, pam_flag);

			if (err == PAM_NEW_AUTHTOK_REQD) {
				chpasswd_tries = 0;

				do {
					err = pam_chauthtok(pm_pamh,
					    PAM_CHANGE_EXPIRED_AUTHTOK);
					chpasswd_tries++;

				} while ((err == PAM_AUTHTOK_ERR ||
				    err == PAM_TRY_AGAIN) &&
				    chpasswd_tries < DEF_ATTEMPTS);
				pm_audit_event(ah, ADT_passwd, err);
			}
			err = pam_setcred(pm_pamh, PAM_REFRESH_CRED);
		}
		if (err != PAM_SUCCESS) {
			(void) fprintf(stdout, "%s\n",
			    pam_strerror(pm_pamh, err));
			pm_audit_event(ah, ADT_screenunlock, err);
		}
	} while (err != PAM_SUCCESS);
	pm_audit_event(ah, ADT_passwd, 0);

	(void) pam_end(pm_pamh, err);
}
