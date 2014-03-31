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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

/*
 * For a complete reference to login(1), see the manual page.  However,
 * login has accreted some intentionally undocumented options, which are
 * explained here:
 *
 * -a: This legacy flag appears to be unused.
 *
 * -f <username>: This flag was introduced by PSARC 1995/039 in support
 *    of Kerberos.  But it's not used by Sun's Kerberos implementation.
 *    It is however employed by zlogin(1), since it allows one to tell
 *    login: "This user is authenticated."  In the case of zlogin that's
 *    true because the zone always trusts the global zone.
 *
 * -z <zonename>: This flag is passed to login when zlogin(1) executes a
 *    zone login.  This tells login(1) to skip it's normal CONSOLE check
 *    (i.e. that the root login must be on /dev/console) and tells us the
 *    name of the zone from which the login is occurring.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>	/* For logfile locking */
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <deflt.h>
#include <grp.h>
#include <fcntl.h>
#include <lastlog.h>
#include <termio.h>
#include <utmpx.h>
#include <stdlib.h>
#include <wait.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
#include <ulimit.h>
#include <libgen.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <strings.h>
#include <libdevinfo.h>
#include <zone.h>
#include "login_audit.h"

#include <krb5_repository.h>
/*
 *
 *	    *** Defines, Macros, and String Constants  ***
 *
 *
 */

#define	ISSUEFILE "/etc/issue"	/* file to print before prompt */
#define	NOLOGIN	"/etc/nologin"	/* file to lock users out during shutdown */

/*
 * These need to be defined for UTMPX management.
 * If we add in the utility functions later, we
 * can remove them.
 */
#define	__UPDATE_ENTRY	1
#define	__LOGIN		2

/*
 * Intervals to sleep after failed login
 */
#ifndef	SLEEPTIME
#define	SLEEPTIME 4	/* sleeptime before login incorrect msg */
#endif
static int	Sleeptime = SLEEPTIME;

/*
 * seconds login disabled after allowable number of unsuccessful attempts
 */
#ifndef	DISABLETIME
#define	DISABLETIME	20
#endif
static int	Disabletime = DISABLETIME;

#define	MAXTRYS		5

static int	retry = MAXTRYS;

/*
 * Login logging support
 */
#define	LOGINLOG	"/var/adm/loginlog"	/* login log file */
#define	LNAME_SIZE	20	/* size of logged logname */
#define	TTYN_SIZE	15	/* size of logged tty name */
#define	TIME_SIZE	30	/* size of logged time string */
#define	ENT_SIZE	(LNAME_SIZE + TTYN_SIZE + TIME_SIZE + 3)
#define	L_WAITTIME	5	/* waittime for log file to unlock */
#define	LOGTRYS		10	/* depth of 'try' logging */

/*
 * String manipulation macros: SCPYN, SCPYL, EQN and ENVSTRNCAT
 * SCPYL is the safer version of SCPYN
 */
#define	SCPYL(a, b)	(void) strlcpy(a, b, sizeof (a))
#define	SCPYN(a, b)	(void) strncpy(a, b, sizeof (a))
#define	EQN(a, b)	(strncmp(a, b, sizeof (a)-1) == 0)
#define	ENVSTRNCAT(to, from) {int deflen; deflen = strlen(to); \
	(void) strncpy((to)+ deflen, (from), sizeof (to) - (1 + deflen)); }

/*
 * Other macros
 */
#define	NMAX	sizeof (((struct utmpx *)0)->ut_name)
#define	HMAX	sizeof (((struct utmpx *)0)->ut_host)
#define	min(a, b)	(((a) < (b)) ? (a) : (b))

/*
 * Various useful files and string constants
 */
#define	SHELL		"/usr/bin/sh"
#define	SHELL2		"/sbin/sh"
#define	SUBLOGIN	"<!sublogin>"
#define	LASTLOG		"/var/adm/lastlog"
#define	PROG_NAME	"login"
#define	HUSHLOGIN	".hushlogin"

/*
 * Array and Buffer sizes
 */
#define	PBUFSIZE 8	/* max significant characters in a password */
#define	MAXARGS 63	/* change value below if changing this */
#define	MAXARGSWIDTH 2	/* log10(MAXARGS) */
#define	MAXENV 1024
#define	MAXLINE 2048

/*
 * Miscellaneous constants
 */
#define	ROOTUID		0
#define	ERROR		1
#define	OK		0
#define	LOG_ERROR	1
#define	DONT_LOG_ERROR	0
#define	TRUE		1
#define	FALSE		0

/*
 * Counters for counting the number of failed login attempts
 */
static int trys = 0;
static int count = 1;

/*
 * error value for login_exit() audit output (0 == no audit record)
 */
static int	audit_error = 0;

/*
 * Externs a plenty
 */
extern	int	getsecretkey();

/*
 * The current user name
 */
static	char	user_name[NMAX];
static	char	minusnam[16] = "-";

/*
 * login_pid, used to find utmpx entry to update.
 */
static pid_t	login_pid;

/*
 * locale environments to be passed to shells.
 */
static char *localeenv[] = {
	"LANG",
	"LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE",
	"LC_MONETARY", "LC_MESSAGES", "LC_ALL", 0};
static int locale_envmatch(char *, char *);

/*
 * Environment variable support
 */
static	char	shell[256] = { "SHELL=" };
static	char	home[MAXPATHLEN] = { "HOME=" };
static	char	term[64] = { "TERM=" };
static	char	logname[30] = { "LOGNAME=" };
static	char	timez[100] = { "TZ=" };
static	char	hertz[10] = { "HZ=" };
static	char	path[MAXPATHLEN] = { "PATH=" };
static	char	*newenv[10+MAXARGS] =
	{home, path, logname, hertz, term, 0, 0};
static	char	**envinit = newenv;
static	int	basicenv;
static	char	*zero = (char *)0;
static	char 	**envp;
#ifndef	NO_MAIL
static	char	mail[30] = { "MAIL=/var/mail/" };
#endif
extern char **environ;
static	char inputline[MAXLINE];

#define	MAX_ID_LEN 256
#define	MAX_REPOSITORY_LEN 256
#define	MAX_PAMSERVICE_LEN 256

static char identity[MAX_ID_LEN];
static char repository[MAX_REPOSITORY_LEN];
static char progname[MAX_PAMSERVICE_LEN];


/*
 * Strings used to prompt the user.
 */
static	char	loginmsg[] = "login: ";
static	char	passwdmsg[] = "Password:";
static	char	incorrectmsg[] = "Login incorrect\n";

/*
 * Password file support
 */
static	struct	passwd *pwd = NULL;
static	char	remote_host[HMAX];
static	char	zone_name[ZONENAME_MAX];

/*
 * Illegal passwd entries.
 */
static	struct	passwd nouser = { "", "no:password", (uid_t)-1 };

/*
 * Log file support
 */
static	char	*log_entry[LOGTRYS];
static	int	writelog = 0;
static	int	lastlogok = 0;
static	struct lastlog ll;
static	int	dosyslog = 0;
static	int	flogin = MAXTRYS;	/* flag for SYSLOG_FAILED_LOGINS */

/*
 * Default file toggles
 */
static	char	*Pndefault	= "/etc/default/login";
static	char	*Altshell	= NULL;
static	char	*Console	= NULL;
static	int	Passreqflag	= 0;

#define	DEFUMASK	022
static	mode_t	Umask		= DEFUMASK;
static	char 	*Def_tz		= NULL;
static	char 	*tmp_tz		= NULL;
static	char 	*Def_hertz	= NULL;
#define	SET_FSIZ	2			/* ulimit() command arg */
static	long	Def_ulimit	= 0;
#define	MAX_TIMEOUT	(15 * 60)
#define	DEF_TIMEOUT	(5 * 60)
static	unsigned Def_timeout	= DEF_TIMEOUT;
static	char	*Def_path	= NULL;
static	char	*Def_supath	= NULL;
#define	DEF_PATH	"/usr/bin:" 	/* same as PATH */
#define	DEF_SUPATH	"/usr/sbin:/usr/bin" /* same as ROOTPATH */

/*
 * Defaults for updating expired passwords
 */
#define	DEF_ATTEMPTS	3

/*
 * ttyprompt will point to the environment variable TTYPROMPT.
 * TTYPROMPT is set by ttymon if ttymon already wrote out the prompt.
 */
static	char	*ttyprompt = NULL;
static	char 	*ttyn = NULL;

/*
 * Pass inherited environment.  Used by telnetd in support of the telnet
 * ENVIRON option.
 */
static	boolean_t pflag = B_FALSE;
static  boolean_t uflag = B_FALSE;
static  boolean_t Rflag = B_FALSE;
static  boolean_t sflag = B_FALSE;
static  boolean_t Uflag = B_FALSE;
static  boolean_t tflag = B_FALSE;
static	boolean_t hflag = B_FALSE;
static  boolean_t rflag = B_FALSE;
static  boolean_t zflag = B_FALSE;

/*
 * Remote login support
 */
static	char	rusername[NMAX+1], lusername[NMAX+1];
static	char	terminal[MAXPATHLEN];

/*
 * Pre-authentication flag support
 */
static	int	fflag;

static char ** getargs(char *);

static int login_conv(int, struct pam_message **,
    struct pam_response **, void *);

static struct pam_conv pam_conv = {login_conv, NULL};
static pam_handle_t *pamh;	/* Authentication handle */

/*
 * Function declarations
 */
static	void	turn_on_logging(void);
static	void	defaults(void);
static	void	usage(void);
static	void	process_rlogin(void);
static	void	login_authenticate();
static	void	setup_credentials(void);
static	void	adjust_nice(void);
static	void	update_utmpx_entry(int);
static	void	establish_user_environment(char **);
static	void	print_banner(void);
static	void	display_last_login_time(void);
static	void	exec_the_shell(void);
static	int	process_chroot_logins(void);
static 	void	chdir_to_dir_user(void);
static	void	check_log(void);
static	void	validate_account(void);
static	void	doremoteterm(char *);
static	int	get_options(int, char **);
static	void	getstr(char *, int, char *);
static 	int	legalenvvar(char *);
static	void	check_for_console(void);
static	void	check_for_dueling_unix(char *);
static	void	get_user_name(void);
static	uint_t	get_audit_id(void);
static	void	login_exit(int)__NORETURN;
static	int	logins_disabled(char *);
static	void	log_bad_attempts(void);
static	int	is_number(char *);

/*
 *			*** main ***
 *
 *	The primary flow of control is directed in this routine.
 *	Control moves in line from top to bottom calling subfunctions
 *	which perform the bulk of the work.  Many of these calls exit
 *	when a fatal error is encountered and do not return to main.
 *
 *
 */

int
main(int argc, char *argv[], char **renvp)
{
	int sublogin;
	int pam_rc;

	login_pid = getpid();

	/*
	 * Set up Defaults and flags
	 */
	defaults();
	SCPYL(progname, PROG_NAME);

	/*
	 * Set up default umask
	 */
	if (Umask > ((mode_t)0777))
		Umask = DEFUMASK;
	(void) umask(Umask);

	/*
	 * Set up default timeouts and delays
	 */
	if (Def_timeout > MAX_TIMEOUT)
		Def_timeout = MAX_TIMEOUT;
	if (Sleeptime < 0 || Sleeptime > 5)
		Sleeptime = SLEEPTIME;

	(void) alarm(Def_timeout);

	/*
	 * Ignore SIGQUIT and SIGINT and set nice to 0
	 */
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGINT, SIG_IGN);
	(void) nice(0);

	/*
	 * Set flag to disable the pid check if you find that you are
	 * a subsystem login.
	 */
	sublogin = 0;
	if (*renvp && strcmp(*renvp, SUBLOGIN) == 0)
		sublogin = 1;

	/*
	 * Parse Arguments
	 */
	if (get_options(argc, argv) == -1) {
		usage();
		audit_error = ADT_FAIL_VALUE_BAD_CMD;
		login_exit(1);
	}

	/*
	 * if devicename is not passed as argument, call ttyname(0)
	 */
	if (ttyn == NULL) {
		ttyn = ttyname(0);
		if (ttyn == NULL)
			ttyn = "/dev/???";
	}

	/*
	 * Call pam_start to initiate a PAM authentication operation
	 */

	if ((pam_rc = pam_start(progname, user_name, &pam_conv, &pamh))
	    != PAM_SUCCESS) {
		audit_error = ADT_FAIL_PAM + pam_rc;
		login_exit(1);
	}
	if ((pam_rc = pam_set_item(pamh, PAM_TTY, ttyn)) != PAM_SUCCESS) {
		audit_error = ADT_FAIL_PAM + pam_rc;
		login_exit(1);
	}
	if ((pam_rc = pam_set_item(pamh, PAM_RHOST, remote_host)) !=
	    PAM_SUCCESS) {
		audit_error = ADT_FAIL_PAM + pam_rc;
		login_exit(1);
	}

	/*
	 * We currently only support special handling of the KRB5 PAM repository
	 */
	if ((Rflag && strlen(repository)) &&
	    strcmp(repository, KRB5_REPOSITORY_NAME) == 0 &&
	    (uflag && strlen(identity))) {
		krb5_repository_data_t krb5_data;
		pam_repository_t pam_rep_data;

		krb5_data.principal = identity;
		krb5_data.flags = SUNW_PAM_KRB5_ALREADY_AUTHENTICATED;

		pam_rep_data.type = repository;
		pam_rep_data.scope = (void *)&krb5_data;
		pam_rep_data.scope_len = sizeof (krb5_data);

		(void) pam_set_item(pamh, PAM_REPOSITORY,
		    (void *)&pam_rep_data);
	}

	/*
	 * Open the log file which contains a record of successful and failed
	 * login attempts
	 */
	turn_on_logging();

	/*
	 * say "hi" to syslogd ..
	 */
	openlog("login", 0, LOG_AUTH);

	/*
	 * Do special processing for -r (rlogin) flag
	 */
	if (rflag)
		process_rlogin();

	/*
	 * validate user
	 */
	/* we are already authenticated. fill in what we must, then continue */
	if (fflag) {
		if ((pwd = getpwnam(user_name)) == NULL) {
			audit_error = ADT_FAIL_VALUE_USERNAME;

			log_bad_attempts();
			(void) printf("Login failed: unknown user '%s'.\n",
			    user_name);
			login_exit(1);
		}
	} else {
		/*
		 * Perform the primary login authentication activity.
		 */
		login_authenticate();
	}

	/* change root login, then we exec another login and try again */
	if (process_chroot_logins() != OK)
		login_exit(1);

	/*
	 * If root login and not on system console then call exit(2)
	 */
	check_for_console();

	/*
	 * Check to see if a shutdown is in progress, if it is and
	 * we are not root then throw the user off the system
	 */
	if (logins_disabled(user_name) == TRUE) {
		audit_error = ADT_FAIL_VALUE_LOGIN_DISABLED;
		login_exit(1);
	}

	if (pwd->pw_uid == 0) {
		if (Def_supath != NULL)
			Def_path = Def_supath;
		else
			Def_path = DEF_SUPATH;
	}

	/*
	 * Check account expiration and passwd aging
	 */
	validate_account();

	/*
	 * We only get here if we've been authenticated.
	 */

	/*
	 * Now we set up the environment for the new user, which includes
	 * the users ulimit, nice value, ownership of this tty, uid, gid,
	 * and environment variables.
	 */
	if (Def_ulimit > 0L && ulimit(SET_FSIZ, Def_ulimit) < 0L)
		(void) printf("Could not set ULIMIT to %ld\n", Def_ulimit);

	/* di_devperm_login() sends detailed errors to syslog */
	if (di_devperm_login((const char *)ttyn, pwd->pw_uid, pwd->pw_gid,
	    NULL) == -1) {
		(void) fprintf(stderr, "error processing /etc/logindevperm,"
		    " see syslog for more details\n");
	}

	adjust_nice();		/* passwd file can specify nice value */

	setup_credentials();	/* Set user credentials  - exits on failure */

	/*
	 * NOTE: telnetd and rlogind rely upon this updating of utmpx
	 * to indicate that the authentication completed  successfully,
	 * pam_open_session was called and therefore they are required to
	 * call pam_close_session.
	 */
	update_utmpx_entry(sublogin);

	/* set the real (and effective) UID */
	if (setuid(pwd->pw_uid) == -1) {
		login_exit(1);
	}

	/*
	 * Set up the basic environment for the exec.  This includes
	 * HOME, PATH, LOGNAME, SHELL, TERM, TZ, HZ, and MAIL.
	 */
	chdir_to_dir_user();

	establish_user_environment(renvp);

	(void) pam_end(pamh, PAM_SUCCESS);	/* Done using PAM */
	pamh = NULL;

	if (pwd->pw_uid == 0) {
		if (dosyslog) {
			if (remote_host[0]) {
				syslog(LOG_NOTICE, "ROOT LOGIN %s FROM %.*s",
				    ttyn, HMAX, remote_host);
			} else
				syslog(LOG_NOTICE, "ROOT LOGIN %s", ttyn);
		}
	}
	closelog();

	(void) signal(SIGQUIT, SIG_DFL);
	(void) signal(SIGINT, SIG_DFL);

	/*
	 * Display some useful information to the new user like the banner
	 * and last login time if not a quiet login.
	 */

	if (access(HUSHLOGIN, F_OK) != 0) {
		print_banner();
		display_last_login_time();
	}

	/*
	 * Set SIGXCPU and SIGXFSZ to default disposition.
	 * Shells inherit signal disposition from parent.
	 * And the shells should have default dispositions
	 * for the two below signals.
	 */
	(void) signal(SIGXCPU, SIG_DFL);
	(void) signal(SIGXFSZ, SIG_DFL);

	/*
	 * Now fire off the shell of choice
	 */
	exec_the_shell();

	/*
	 * All done
	 */
	login_exit(1);
	return (0);
}


/*
 *			*** Utility functions ***
 */



/*
 * donothing & catch	- Signal catching functions
 */

/*ARGSUSED*/
static void
donothing(int sig)
{
	if (pamh)
		(void) pam_end(pamh, PAM_ABORT);
}

#ifdef notdef
static	int	intrupt;

/*ARGSUSED*/
static void
catch(int sig)
{
	++intrupt;
}
#endif

/*
 *			*** Bad login logging support ***
 */

/*
 * badlogin() 		- log to the log file 'trys'
 *			  unsuccessful attempts
 */

static void
badlogin(void)
{
	int retval, count1, fildes;

	/*
	 * Tries to open the log file. If succeed, lock it and write
	 * in the failed attempts
	 */
	if ((fildes = open(LOGINLOG, O_APPEND|O_WRONLY)) != -1) {

		(void) sigset(SIGALRM, donothing);
		(void) alarm(L_WAITTIME);
		retval = lockf(fildes, F_LOCK, 0L);
		(void) alarm(0);
		(void) sigset(SIGALRM, SIG_DFL);
		if (retval == 0) {
			for (count1 = 0; count1 < trys; count1++)
				(void) write(fildes, log_entry[count1],
				    (unsigned)strlen(log_entry[count1]));
			(void) lockf(fildes, F_ULOCK, 0L);
		}
		(void) close(fildes);
	}
}


/*
 * log_bad_attempts 	- log each bad login attempt - called from
 *			  login_authenticate.  Exits when the maximum attempt
 *			  count is exceeded.
 */

static void
log_bad_attempts(void)
{
	time_t timenow;

	if (trys >= LOGTRYS)
		return;
	if (writelog) {
		(void) time(&timenow);
		(void) strncat(log_entry[trys], user_name, LNAME_SIZE);
		(void) strncat(log_entry[trys], ":", (size_t)1);
		(void) strncat(log_entry[trys], ttyn, TTYN_SIZE);
		(void) strncat(log_entry[trys], ":", (size_t)1);
		(void) strncat(log_entry[trys], ctime(&timenow), TIME_SIZE);
		trys++;
	}
	if (count > flogin) {
		if ((pwd = getpwnam(user_name)) != NULL) {
			if (remote_host[0]) {
				syslog(LOG_NOTICE,
				    "Login failure on %s from %.*s, "
				    "%.*s", ttyn, HMAX, remote_host,
				    NMAX, user_name);
			} else {
				syslog(LOG_NOTICE,
				    "Login failure on %s, %.*s",
				    ttyn, NMAX, user_name);
			}
		} else 	{
			if (remote_host[0]) {
				syslog(LOG_NOTICE,
				    "Login failure on %s from %.*s",
				    ttyn, HMAX, remote_host);
			} else {
				syslog(LOG_NOTICE,
				    "Login failure on %s", ttyn);
			}
		}
	}
}


/*
 * turn_on_logging 	- if the logfile exist, turn on attempt logging and
 *			  initialize the string storage area
 */

static void
turn_on_logging(void)
{
	struct stat dbuf;
	int i;

	if (stat(LOGINLOG, &dbuf) == 0) {
		writelog = 1;
		for (i = 0; i < LOGTRYS; i++) {
			if (!(log_entry[i] = malloc((size_t)ENT_SIZE))) {
				writelog = 0;
				break;
			}
			*log_entry[i] = '\0';
		}
	}
}


/*
 * login_conv():
 *	This is the conv (conversation) function called from
 *	a PAM authentication module to print error messages
 *	or garner information from the user.
 */
/*ARGSUSED*/
static int
login_conv(int num_msg, struct pam_message **msg,
    struct pam_response **response, void *appdata_ptr)
{
	struct pam_message	*m;
	struct pam_response	*r;
	char 			*temp;
	int			k, i;

	if (num_msg <= 0)
		return (PAM_CONV_ERR);

	*response = calloc(num_msg, sizeof (struct pam_response));
	if (*response == NULL)
		return (PAM_BUF_ERR);

	k = num_msg;
	m = *msg;
	r = *response;
	while (k--) {

		switch (m->msg_style) {

		case PAM_PROMPT_ECHO_OFF:
			errno = 0;
			temp = getpassphrase(m->msg);
			if (temp != NULL) {
				if (errno == EINTR)
					return (PAM_CONV_ERR);

				r->resp = strdup(temp);
				if (r->resp == NULL) {
					/* free responses */
					r = *response;
					for (i = 0; i < num_msg; i++, r++) {
						if (r->resp)
							free(r->resp);
					}
					free(*response);
					*response = NULL;
					return (PAM_BUF_ERR);
				}
			}

			m++;
			r++;
			break;

		case PAM_PROMPT_ECHO_ON:
			if (m->msg != NULL)
				(void) fputs(m->msg, stdout);
			r->resp = calloc(1, PAM_MAX_RESP_SIZE);
			if (r->resp == NULL) {
				/* free responses */
				r = *response;
				for (i = 0; i < num_msg; i++, r++) {
					if (r->resp)
						free(r->resp);
				}
				free(*response);
				*response = NULL;
				return (PAM_BUF_ERR);
			}
			/*
			 * The response might include environment variables
			 * information. We should store that information in
			 * envp if there is any; otherwise, envp is set to
			 * NULL.
			 */
			bzero((void *)inputline, MAXLINE);

			envp = getargs(inputline);

			/* If we read in any input, process it. */
			if (inputline[0] != '\0') {
				int len;

				if (envp != (char **)NULL)
					/*
					 * If getargs() did not return NULL,
					 * *envp is the first string in
					 * inputline. envp++ makes envp point
					 * to environment variables information
					 *  or be NULL.
					 */
					envp++;

				(void) strncpy(r->resp, inputline,
				    PAM_MAX_RESP_SIZE-1);
				r->resp[PAM_MAX_RESP_SIZE-1] = NULL;
				len = strlen(r->resp);
				if (r->resp[len-1] == '\n')
					r->resp[len-1] = '\0';
			} else {
				login_exit(1);
			}
			m++;
			r++;
			break;

		case PAM_ERROR_MSG:
			if (m->msg != NULL) {
				(void) fputs(m->msg, stderr);
				(void) fputs("\n", stderr);
			}
			m++;
			r++;
			break;
		case PAM_TEXT_INFO:
			if (m->msg != NULL) {
				(void) fputs(m->msg, stdout);
				(void) fputs("\n", stdout);
			}
			m++;
			r++;
			break;

		default:
			break;
		}
	}
	return (PAM_SUCCESS);
}

/*
 * verify_passwd - Authenticates the user.
 *	Returns: PAM_SUCCESS if authentication successful,
 *		 PAM error code if authentication fails.
 */

static int
verify_passwd(void)
{
	int error;
	char *user;
	int flag = (Passreqflag ? PAM_DISALLOW_NULL_AUTHTOK : 0);

	/*
	 * PAM authenticates the user for us.
	 */
	error = pam_authenticate(pamh, flag);

	/* get the user_name from the pam handle */
	(void) pam_get_item(pamh, PAM_USER, (void**)&user);

	if (user == NULL || *user == '\0')
		return (PAM_SYSTEM_ERR);

	SCPYL(user_name, user);
	check_for_dueling_unix(user_name);

	if (((pwd = getpwnam(user_name)) == NULL) &&
	    (error != PAM_USER_UNKNOWN)) {
		return (PAM_SYSTEM_ERR);
	}

	return (error);
}

/*
 * quotec		- Called by getargs
 */

static int
quotec(void)
{
	int c, i, num;

	switch (c = getc(stdin)) {

		case 'n':
			c = '\n';
			break;

		case 'r':
			c = '\r';
			break;

		case 'v':
			c = '\013';
			break;

		case 'b':
			c = '\b';
			break;

		case 't':
			c = '\t';
			break;

		case 'f':
			c = '\f';
			break;

		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
			for (num = 0, i = 0; i < 3; i++) {
				num = num * 8 + (c - '0');
				if ((c = getc(stdin)) < '0' || c > '7')
					break;
			}
			(void) ungetc(c, stdin);
			c = num & 0377;
			break;

		default:
			break;
	}
	return (c);
}

/*
 * getargs		- returns an input line.  Exits if EOF encountered.
 */
#define	WHITESPACE	0
#define	ARGUMENT	1

static char **
getargs(char *input_line)
{
	static char envbuf[MAXLINE];
	static char *args[MAXARGS];
	char *ptr, **answer;
	int c;
	int state;
	char *p = input_line;

	ptr = envbuf;
	answer = &args[0];
	state = WHITESPACE;

	while ((c = getc(stdin)) != EOF && answer < &args[MAXARGS-1]) {

		*(input_line++) = c;

		switch (c) {

		case '\n':
			if (ptr == &envbuf[0])
				return ((char **)NULL);
			*input_line = *ptr = '\0';
			*answer = NULL;
			return (&args[0]);

		case ' ':
		case '\t':
			if (state == ARGUMENT) {
				*ptr++ = '\0';
				state = WHITESPACE;
			}
			break;

		case '\\':
			c = quotec();

		default:
			if (state == WHITESPACE) {
				*answer++ = ptr;
				state = ARGUMENT;
			}
			*ptr++ = c;
		}

		/* Attempt at overflow, exit */
		if (input_line - p >= MAXLINE - 1 ||
		    ptr >= &envbuf[sizeof (envbuf) - 1]) {
			audit_error = ADT_FAIL_VALUE_INPUT_OVERFLOW;
			login_exit(1);
		}
	}

	/*
	 * If we left loop because an EOF was received or we've overflown
	 * args[], exit immediately.
	 */
	login_exit(0);
	/* NOTREACHED */
}

/*
 * get_user_name	- Gets the user name either passed in, or from the
 *			  login: prompt.
 */

static void
get_user_name(void)
{
	FILE	*fp;

	if ((fp = fopen(ISSUEFILE, "r")) != NULL) {
		char    *ptr, buffer[BUFSIZ];
		while ((ptr = fgets(buffer, sizeof (buffer), fp)) != NULL) {
			(void) fputs(ptr, stdout);
		}
		(void) fclose(fp);
	}

	/*
	 * if TTYPROMPT is not set, use our own prompt
	 * otherwise, use ttyprompt. We just set PAM_USER_PROMPT
	 * and let the module do the prompting.
	 */

	if ((ttyprompt == NULL) || (*ttyprompt == '\0'))
		(void) pam_set_item(pamh, PAM_USER_PROMPT, (void *)loginmsg);
	else
		(void) pam_set_item(pamh, PAM_USER_PROMPT, (void *)ttyprompt);

	envp = &zero; /* XXX: is this right? */
}


/*
 * Check_for_dueling_unix   -	Check to see if the another login is talking
 *				to the line we've got open as a login port
 *				Exits if we're talking to another unix system
 */

static void
check_for_dueling_unix(char *inputline)
{
	if (EQN(loginmsg, inputline) || EQN(passwdmsg, inputline) ||
	    EQN(incorrectmsg, inputline)) {
		(void) printf("Looking at a login line.\n");
		login_exit(8);
	}
}

/*
 * logins_disabled - 	if the file /etc/nologin exists and the user is not
 *			root then do not permit them to login
 */
static int
logins_disabled(char *user_name)
{
	FILE	*nlfd;
	int	c;
	if (!EQN("root", user_name) &&
	    ((nlfd = fopen(NOLOGIN, "r")) != (FILE *)NULL)) {
		while ((c = getc(nlfd)) != EOF)
			(void) putchar(c);
		(void) fflush(stdout);
		(void) sleep(5);
		return (TRUE);
	}
	return (FALSE);
}

#define	DEFAULT_CONSOLE	"/dev/console"

/*
 * check_for_console -  Checks if we're getting a root login on the
 *			console, or a login from the global zone. Exits if not.
 *
 * If CONSOLE is set to /dev/console in /etc/default/login, then root logins
 * on /dev/vt/# are permitted as well. /dev/vt/# does not exist in non-global
 * zones, but checking them does no harm.
 */
static void
check_for_console(void)
{
	const char *consoles[] = { "/dev/console", "/dev/vt/", NULL };
	int i;

	if (pwd == NULL || pwd->pw_uid != 0 || zflag != B_FALSE ||
	    Console == NULL)
		return;

	if (strcmp(Console, DEFAULT_CONSOLE) == 0) {
		for (i = 0; consoles[i] != NULL; i ++) {
			if (strncmp(ttyn, consoles[i],
			    strlen(consoles[i])) == 0)
				return;
		}
	} else {
		if (strcmp(ttyn, Console) == 0)
			return;
	}

	(void) printf("Not on system console\n");

	audit_error = ADT_FAIL_VALUE_CONSOLE;
	login_exit(10);

}

/*
 * List of environment variables or environment variable prefixes that should
 * not be propagated across logins, such as when the login -p option is used.
 */
static const char *const illegal[] = {
	"SHELL=",
	"HOME=",
	"LOGNAME=",
#ifndef	NO_MAIL
	"MAIL=",
#endif
	"CDPATH=",
	"IFS=",
	"PATH=",
	"LD_",
	"SMF_",
	NULL
};

/*
 * legalenvvar		- Is it legal to insert this environmental variable?
 */

static int
legalenvvar(char *s)
{
	const char *const *p;

	for (p = &illegal[0]; *p; p++) {
		if (strncmp(s, *p, strlen(*p)) == 0)
			return (0);
	}

	return (1);
}


/*
 * getstr		- Get a string from standard input
 *			  Calls exit if read(2) fails.
 */

static void
getstr(char *buf, int cnt, char *err)
{
	char c;

	do {
		if (read(0, &c, 1) != 1)
			login_exit(1);
		*buf++ = c;
	} while (--cnt > 1 && c != 0);

	*buf = 0;
	err = err; 	/* For lint */
}


/*
 * defaults 		- read defaults
 */

static void
defaults(void)
{
	int  flags;
	char *ptr;

	if (defopen(Pndefault) == 0) {
		/*
		 * ignore case
		 */
		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);

		if ((Console = defread("CONSOLE=")) != NULL)
			Console = strdup(Console);

		if ((Altshell = defread("ALTSHELL=")) != NULL)
			Altshell = strdup(Altshell);

		if ((ptr = defread("PASSREQ=")) != NULL &&
		    strcasecmp("YES", ptr) == 0)
				Passreqflag = 1;

		if ((Def_tz = defread("TIMEZONE=")) != NULL)
			Def_tz = strdup(Def_tz);

		if ((Def_hertz = defread("HZ=")) != NULL)
			Def_hertz = strdup(Def_hertz);

		if ((Def_path   = defread("PATH=")) != NULL)
			Def_path = strdup(Def_path);

		if ((Def_supath = defread("SUPATH=")) != NULL)
			Def_supath = strdup(Def_supath);

		if ((ptr = defread("ULIMIT=")) != NULL)
			Def_ulimit = atol(ptr);

		if ((ptr = defread("TIMEOUT=")) != NULL)
			Def_timeout = (unsigned)atoi(ptr);

		if ((ptr = defread("UMASK=")) != NULL)
			if (sscanf(ptr, "%lo", &Umask) != 1)
				Umask = DEFUMASK;

		if ((ptr = defread("SLEEPTIME=")) != NULL) {
			if (is_number(ptr))
				Sleeptime = atoi(ptr);
		}

		if ((ptr = defread("DISABLETIME=")) != NULL) {
			if (is_number(ptr))
				Disabletime = atoi(ptr);
		}

		if ((ptr = defread("SYSLOG=")) != NULL)
			dosyslog = strcmp(ptr, "YES") == 0;

		if ((ptr = defread("RETRIES=")) != NULL) {
			if (is_number(ptr))
				retry = atoi(ptr);
		}

		if ((ptr = defread("SYSLOG_FAILED_LOGINS=")) != NULL) {
			if (is_number(ptr))
				flogin = atoi(ptr);
			else
				flogin = retry;
		} else
			flogin = retry;
		(void) defopen((char *)NULL);
	}
}


/*
 * get_options(argc, argv)
 * 			- parse the cmd line.
 *			- return 0 if successful, -1 if failed.
 *			Calls login_exit() on misuse of -r, -h, and -z flags
 */

static	int
get_options(int argc, char *argv[])
{
	int	c;
	int	errflg = 0;
	char    sflagname[NMAX+1];
	const 	char *flags_message = "Only one of -r, -h and -z allowed\n";

	while ((c = getopt(argc, argv, "u:s:R:f:h:r:pad:t:U:z:")) != -1) {
		switch (c) {
		case 'a':
			break;

		case 'd':
			/*
			 * Must be root to pass in device name
			 * otherwise we exit() as punishment for trying.
			 */
			if (getuid() != 0 || geteuid() != 0) {
				audit_error = ADT_FAIL_VALUE_DEVICE_PERM;
				login_exit(1);	/* sigh */
				/*NOTREACHED*/
			}
			ttyn = optarg;
			break;

		case 'h':
			if (hflag || rflag || zflag) {
				(void) fprintf(stderr, flags_message);
				login_exit(1);
			}
			hflag = B_TRUE;
			SCPYL(remote_host, optarg);
			if (argv[optind]) {
				if (argv[optind][0] != '-') {
					SCPYL(terminal, argv[optind]);
					optind++;
				} else {
					/*
					 * Allow "login -h hostname -" to
					 * skip setting up an username as "-".
					 */
					if (argv[optind][1] == '\0')
						optind++;
				}

			}
			SCPYL(progname, "telnet");
			break;

		case 'r':
			if (hflag || rflag || zflag) {
				(void) fprintf(stderr, flags_message);
				login_exit(1);
			}
			rflag = B_TRUE;
			SCPYL(remote_host, optarg);
			SCPYL(progname, "rlogin");
			break;

		case 'p':
			pflag = B_TRUE;
			break;

		case 'f':
			/*
			 * Must be root to bypass authentication
			 * otherwise we exit() as punishment for trying.
			 */
			if (getuid() != 0 || geteuid() != 0) {
				audit_error = ADT_FAIL_VALUE_AUTH_BYPASS;

				login_exit(1);	/* sigh */
				/*NOTREACHED*/
			}
			/* save fflag user name for future use */
			SCPYL(user_name, optarg);
			fflag = B_TRUE;
			break;
		case 'u':
			if (!strlen(optarg)) {
				(void) fprintf(stderr,
				    "Empty string supplied with -u\n");
				login_exit(1);
			}
			SCPYL(identity, optarg);
			uflag = B_TRUE;
			break;
		case 's':
			if (!strlen(optarg)) {
				(void) fprintf(stderr,
				    "Empty string supplied with -s\n");
				login_exit(1);
			}
			SCPYL(sflagname, optarg);
			sflag = B_TRUE;
			break;
		case 'R':
			if (!strlen(optarg)) {
				(void) fprintf(stderr,
				    "Empty string supplied with -R\n");
				login_exit(1);
			}
			SCPYL(repository, optarg);
			Rflag =	B_TRUE;
			break;
		case 't':
			if (!strlen(optarg)) {
				(void) fprintf(stderr,
				    "Empty string supplied with -t\n");
				login_exit(1);
			}
			SCPYL(terminal, optarg);
			tflag = B_TRUE;
			break;
		case 'U':
			/*
			 * Kerberized rlogind may fork us with
			 * -U "" if the rlogin client used the "-a"
			 * option to send a NULL username.  This is done
			 * to force login to prompt for a user/password.
			 * However, if Kerberos auth was used, we dont need
			 * to prompt, so we will accept the option and
			 * handle the situation later.
			 */
			SCPYL(rusername, optarg);
			Uflag = B_TRUE;
			break;
		case 'z':
			if (hflag || rflag || zflag) {
				(void) fprintf(stderr, flags_message);
				login_exit(1);
			}
			(void) snprintf(zone_name, sizeof (zone_name),
			    "zone:%s", optarg);
			SCPYL(progname, "zlogin");
			zflag = B_TRUE;
			break;
		default:
			errflg++;
			break;
		} 	/* end switch */
	} 		/* end while */

	/*
	 * If the 's svcname' flag was used, override the progname
	 * value that is to be used in the pam_start call.
	 */
	if (sflag)
		SCPYL(progname, sflagname);

	/*
	 * get the prompt set by ttymon
	 */
	ttyprompt = getenv("TTYPROMPT");

	if ((ttyprompt != NULL) && (*ttyprompt != '\0')) {
		/*
		 * if ttyprompt is set, there should be data on
		 * the stream already.
		 */
		if ((envp = getargs(inputline)) != (char **)NULL) {
			/*
			 * don't get name if name passed as argument.
			 */
			SCPYL(user_name, *envp++);
		}
	} else if (optind < argc) {
		SCPYL(user_name, argv[optind]);
		(void) SCPYL(inputline, user_name);
		(void) strlcat(inputline, "   \n", sizeof (inputline));
		envp = &argv[optind+1];

		if (!fflag)
			SCPYL(lusername, user_name);
	}

	if (errflg)
		return (-1);
	return (0);
}

/*
 * usage		- Print usage message
 *
 */
static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage:\n"
	    "    login [-p] [-d device] [-R repository] [-s service]\n"
	    "\t[-t terminal]  [-u identity] [-U ruser]\n"
	    "\t[-h hostname [terminal] | -r hostname] [name [environ]...]\n");

}

/*
 * doremoteterm		- Sets the appropriate ioctls for a remote terminal
 */
static char	*speeds[] = {
	"0", "50", "75", "110", "134", "150", "200", "300",
	"600", "1200", "1800", "2400", "4800", "9600", "19200", "38400",
	"57600", "76800", "115200", "153600", "230400", "307200", "460800",
	"921600"
};

#define	NSPEEDS	(sizeof (speeds) / sizeof (speeds[0]))


static void
doremoteterm(char *term)
{
	struct termios tp;
	char *cp = strchr(term, '/'), **cpp;
	char *speed;

	(void) ioctl(0, TCGETS, &tp);

	if (cp) {
		*cp++ = '\0';
		speed = cp;
		cp = strchr(speed, '/');

		if (cp)
			*cp++ = '\0';

		for (cpp = speeds; cpp < &speeds[NSPEEDS]; cpp++)
			if (strcmp(*cpp, speed) == 0) {
				(void) cfsetospeed(&tp, cpp-speeds);
				break;
			}
	}

	tp.c_lflag |= ECHO|ICANON;
	tp.c_iflag |= IGNPAR|ICRNL;

	(void) ioctl(0, TCSETS, &tp);

}

/*
 * Process_rlogin		- Does the work that rlogin and telnet
 *				  need done
 */
static void
process_rlogin(void)
{
	/*
	 * If a Kerberized rlogin was initiated, then these fields
	 * must be read by rlogin daemon itself and passed down via
	 * cmd line args.
	 */
	if (!Uflag && !strlen(rusername))
		getstr(rusername, sizeof (rusername), "remuser");
	if (!strlen(lusername))
		getstr(lusername, sizeof (lusername), "locuser");
	if (!tflag && !strlen(terminal))
		getstr(terminal, sizeof (terminal), "Terminal type");

	if (strlen(terminal))
		doremoteterm(terminal);

	/* fflag has precedence over stuff passed by rlogind */
	if (fflag || getuid()) {
		pwd = &nouser;
		return;
	} else {
		if (pam_set_item(pamh, PAM_USER, lusername) != PAM_SUCCESS)
			login_exit(1);

		pwd = getpwnam(lusername);
		if (pwd == NULL) {
			pwd = &nouser;
			return;
		}
	}

	/*
	 * Update PAM on the user name
	 */
	if (strlen(lusername) &&
	    pam_set_item(pamh, PAM_USER, lusername) != PAM_SUCCESS)
		login_exit(1);

	if (strlen(rusername) &&
	    pam_set_item(pamh, PAM_RUSER, rusername) != PAM_SUCCESS)
		login_exit(1);

	SCPYL(user_name, lusername);
	envp = &zero;
	lusername[0] = '\0';
}

/*
 *		*** Account validation routines ***
 *
 */

/*
 * validate_account		- This is the PAM version of validate.
 */

static void
validate_account(void)
{
	int 	error;
	int	flag;
	int	tries;		/* new password retries */

	(void) alarm(0);	/* give user time to come up with password */

	check_log();

	if (Passreqflag)
		flag = PAM_DISALLOW_NULL_AUTHTOK;
	else
		flag = 0;

	if ((error = pam_acct_mgmt(pamh, flag)) != PAM_SUCCESS) {
		if (error == PAM_NEW_AUTHTOK_REQD) {
			tries = 1;
			error = PAM_AUTHTOK_ERR;
			while (error == PAM_AUTHTOK_ERR &&
			    tries <= DEF_ATTEMPTS) {
				if (tries > 1)
					(void) printf("Try again\n\n");

				(void) printf("Choose a new password.\n");

				error = pam_chauthtok(pamh,
				    PAM_CHANGE_EXPIRED_AUTHTOK);
				if (error == PAM_TRY_AGAIN) {
					(void) sleep(1);
					error = pam_chauthtok(pamh,
					    PAM_CHANGE_EXPIRED_AUTHTOK);
				}
				tries++;
			}

			if (error != PAM_SUCCESS) {
				if (dosyslog)
					syslog(LOG_CRIT,
					    "change password failure: %s",
					    pam_strerror(pamh, error));
				audit_error = ADT_FAIL_PAM + error;
				login_exit(1);
			} else {
				audit_success(ADT_passwd, pwd, zone_name);
			}
		} else {
			(void) printf(incorrectmsg);

			if (dosyslog)
				syslog(LOG_CRIT,
				    "login account failure: %s",
				    pam_strerror(pamh, error));
			audit_error = ADT_FAIL_PAM + error;
			login_exit(1);
		}
	}
}

/*
 * Check_log	- This is really a hack because PAM checks the log, but login
 *		  wants to know if the log is okay and PAM doesn't have
 *		  a module independent way of handing this info back.
 */

static void
check_log(void)
{
	int fdl;
	long long offset;

	offset = (long long) pwd->pw_uid * (long long) sizeof (struct lastlog);

	if ((fdl = open(LASTLOG, O_RDWR|O_CREAT, 0444)) >= 0) {
		if (llseek(fdl, offset, SEEK_SET) == offset &&
		    read(fdl, (char *)&ll, sizeof (ll)) == sizeof (ll) &&
		    ll.ll_time != 0)
			lastlogok = 1;
		(void) close(fdl);
	}
}

/*
 * chdir_to_dir_user	- Now chdir after setuid/setgid have happened to
 *			  place us in the user's home directory just in
 *			  case it was protected and the first chdir failed.
 *			  No chdir errors should happen at this point because
 *			  all failures should have happened on the first
 *			  time around.
 */

static void
chdir_to_dir_user(void)
{
	if (chdir(pwd->pw_dir) < 0) {
		if (chdir("/") < 0) {
			(void) printf("No directory!\n");
			/*
			 * This probably won't work since we can't get to /.
			 */
			if (dosyslog) {
				if (remote_host[0]) {
					syslog(LOG_CRIT,
					    "LOGIN FAILURES ON %s FROM %.*s ",
					    " %.*s", ttyn, HMAX,
					    remote_host, NMAX, pwd->pw_name);
				} else {
					syslog(LOG_CRIT,
					    "LOGIN FAILURES ON %s, %.*s",
					    ttyn, NMAX, pwd->pw_name);
				}
			}
			closelog();
			(void) sleep(Disabletime);
			exit(1);
		} else {
			(void) printf("No directory! Logging in with home=/\n");
			pwd->pw_dir = "/";
		}
	}
}


/*
 * login_authenticate	- Performs the main authentication work
 *			  1. Prints the login prompt
 *			  2. Requests and verifys the password
 *			  3. Checks the port password
 */

static void
login_authenticate(void)
{
	char *user;
	int err;
	int login_successful = 0;

	do {
		/* if scheme broken, then nothing to do but quit */
		if (pam_get_item(pamh, PAM_USER, (void **)&user) != PAM_SUCCESS)
			exit(1);

		/*
		 * only get name from utility if it is not already
		 * supplied by pam_start or a pam_set_item.
		 */
		if (!user || !user[0]) {
			/* use call back to get user name */
			get_user_name();
		}

		err = verify_passwd();

		/*
		 * If root login and not on system console then call exit(2)
		 */
		check_for_console();

		switch (err) {
		case PAM_SUCCESS:
		case PAM_NEW_AUTHTOK_REQD:
			/*
			 * Officially, pam_authenticate() shouldn't return this
			 * but it's probably the right thing to return if
			 * PAM_DISALLOW_NULL_AUTHTOK is set so the user will
			 * be forced to change password later in this code.
			 */
			count = 0;
			login_successful = 1;
			break;
		case PAM_MAXTRIES:
			count = retry;
			/*FALLTHROUGH*/
		case PAM_AUTH_ERR:
		case PAM_AUTHINFO_UNAVAIL:
		case PAM_USER_UNKNOWN:
			audit_failure(get_audit_id(), ADT_FAIL_PAM + err, pwd,
			    remote_host, ttyn, zone_name);
			log_bad_attempts();
			break;
		case PAM_ABORT:
			log_bad_attempts();
			(void) sleep(Disabletime);
			(void) printf(incorrectmsg);

			audit_error = ADT_FAIL_PAM + err;
			login_exit(1);
			/*NOTREACHED*/
		default:	/* Some other PAM error */
			audit_error = ADT_FAIL_PAM + err;
			login_exit(1);
			/*NOTREACHED*/
		}

		if (login_successful)
			break;

		/* sleep after bad passwd */
		if (count)
			(void) sleep(Sleeptime);
		(void) printf(incorrectmsg);
		/* force name to be null in this case */
		if (pam_set_item(pamh, PAM_USER, NULL) != PAM_SUCCESS)
			login_exit(1);
		if (pam_set_item(pamh, PAM_RUSER, NULL) != PAM_SUCCESS)
			login_exit(1);
	} while (count++ < retry);

	if (count >= retry) {
		audit_failure(get_audit_id(), ADT_FAIL_VALUE_MAX_TRIES, pwd,
		    remote_host, ttyn, zone_name);
		/*
		 * If logging is turned on, output the
		 * string storage area to the log file,
		 * and sleep for Disabletime
		 * seconds before exiting.
		 */
		if (writelog)
			badlogin();
		if (dosyslog) {
			if ((pwd = getpwnam(user_name)) != NULL) {
				if (remote_host[0]) {
					syslog(LOG_CRIT,
					    "REPEATED LOGIN FAILURES ON %s "
					    "FROM %.*s, %.*s",
					    ttyn, HMAX, remote_host, NMAX,
					    user_name);
				} else {
					syslog(LOG_CRIT,
					    "REPEATED LOGIN FAILURES ON "
					    "%s, %.*s",
					    ttyn, NMAX, user_name);
				}
			} else {
				if (remote_host[0]) {
					syslog(LOG_CRIT,
					    "REPEATED LOGIN FAILURES ON %s "
					    "FROM %.*s",
					    ttyn, HMAX, remote_host);
				} else {
					syslog(LOG_CRIT,
					    "REPEATED LOGIN FAILURES ON %s",
					    ttyn);
				}
			}
		}
		(void) sleep(Disabletime);
		exit(1);
	}

}

/*
 * 			*** Credential Related routines ***
 *
 */

/*
 * setup_credentials		- sets the group ID, initializes the groups
 *				  and sets up the secretkey.
 *				  Exits if a failure occurrs.
 */


/*
 * setup_credentials		- PAM does all the work for us on this one.
 */

static void
setup_credentials(void)
{
	int 	error = 0;

	/* set the real (and effective) GID */
	if (setgid(pwd->pw_gid) == -1) {
		login_exit(1);
	}

	/*
	 * Initialize the supplementary group access list.
	 */
	if ((user_name[0] == '\0') ||
	    (initgroups(user_name, pwd->pw_gid) == -1)) {
		audit_error = ADT_FAIL_VALUE_PROGRAM;
		login_exit(1);
	}

	if ((error = pam_setcred(pamh, zflag ? PAM_REINITIALIZE_CRED :
	    PAM_ESTABLISH_CRED)) != PAM_SUCCESS) {
		audit_error = ADT_FAIL_PAM + error;
		login_exit(error);
	}

	/*
	 * Record successful login and fork process that records logout.
	 * We have to do this after setting credentials because pam_setcred()
	 * loads key audit info into the cred, but before setuid() so audit
	 * system calls will work.
	 */
	audit_success(get_audit_id(), pwd, zone_name);
}

static uint_t
get_audit_id(void)
{
	if (rflag)
		return (ADT_rlogin);
	else if (hflag)
		return (ADT_telnet);
	else if (zflag)
		return (ADT_zlogin);

	return (ADT_login);
}

/*
 *
 *		*** Routines to get a new user set up and running ***
 *
 *			Things to do when starting up a new user:
 *				adjust_nice
 *				update_utmpx_entry
 *				establish_user_environment
 *				print_banner
 *				display_last_login_time
 *				exec_the_shell
 *
 */


/*
 * adjust_nice		- Set the nice (process priority) value if the
 *			  gecos value contains an appropriate value.
 */

static void
adjust_nice(void)
{
	int pri, mflg, i;

	if (strncmp("pri=", pwd->pw_gecos, 4) == 0) {
		pri = 0;
		mflg = 0;
		i = 4;

		if (pwd->pw_gecos[i] == '-') {
			mflg++;
			i++;
		}

		while (pwd->pw_gecos[i] >= '0' && pwd->pw_gecos[i] <= '9')
			pri = (pri * 10) + pwd->pw_gecos[i++] - '0';

		if (mflg)
			pri = -pri;

		(void) nice(pri);
	}
}

/*
 * update_utmpx_entry	- Searchs for the correct utmpx entry, making an
 *			  entry there if it finds one, otherwise exits.
 */

static void
update_utmpx_entry(int sublogin)
{
	int	err;
	char	*user;
	static char	*errmsg	= "No utmpx entry. "
	    "You must exec \"login\" from the lowest level \"shell\".";
	int	tmplen;
	struct utmpx  *u = (struct utmpx *)0;
	struct utmpx  utmpx;
	char	*ttyntail;

	/*
	 * If we're not a sublogin then
	 * we'll get an error back if our PID doesn't match the PID of the
	 * entry we are updating, otherwise if its a sublogin the flags
	 * field is set to 0, which means we just write a matching entry
	 * (without checking the pid), or a new entry if an entry doesn't
	 * exist.
	 */

	if ((err = pam_open_session(pamh, 0)) != PAM_SUCCESS) {
		audit_error = ADT_FAIL_PAM + err;
		login_exit(1);
	}

	if ((err = pam_get_item(pamh, PAM_USER, (void **) &user)) !=
	    PAM_SUCCESS) {
		audit_error = ADT_FAIL_PAM + err;
		login_exit(1);
	}

	(void) memset((void *)&utmpx, 0, sizeof (utmpx));
	(void) time(&utmpx.ut_tv.tv_sec);
	utmpx.ut_pid = getpid();

	if (rflag || hflag) {
		SCPYN(utmpx.ut_host, remote_host);
		tmplen = strlen(remote_host) + 1;
		if (tmplen < sizeof (utmpx.ut_host))
			utmpx.ut_syslen = tmplen;
		else
			utmpx.ut_syslen = sizeof (utmpx.ut_host);
	} else if (zflag) {
		/*
		 * If this is a login from another zone, put the
		 * zone:<zonename> string in the utmpx entry.
		 */
		SCPYN(utmpx.ut_host, zone_name);
		tmplen = strlen(zone_name) + 1;
		if (tmplen < sizeof (utmpx.ut_host))
			utmpx.ut_syslen = tmplen;
		else
			utmpx.ut_syslen = sizeof (utmpx.ut_host);
	} else {
		utmpx.ut_syslen = 0;
	}

	SCPYN(utmpx.ut_user, user);

	/* skip over "/dev/" */
	ttyntail = basename(ttyn);

	while ((u = getutxent()) != NULL) {
		if ((u->ut_type == INIT_PROCESS ||
		    u->ut_type == LOGIN_PROCESS ||
		    u->ut_type == USER_PROCESS) &&
		    ((sublogin && strncmp(u->ut_line, ttyntail,
		    sizeof (u->ut_line)) == 0) ||
		    u->ut_pid == login_pid)) {
			SCPYN(utmpx.ut_line, (ttyn+sizeof ("/dev/")-1));
			(void) memcpy(utmpx.ut_id, u->ut_id,
			    sizeof (utmpx.ut_id));
			utmpx.ut_exit.e_exit = u->ut_exit.e_exit;
			utmpx.ut_type = USER_PROCESS;
			(void) pututxline(&utmpx);
			break;
		}
	}
	endutxent();

	if (u == (struct utmpx *)NULL) {
		if (!sublogin) {
			/*
			 * no utmpx entry already setup
			 * (init or rlogind/telnetd)
			 */
			(void) puts(errmsg);

			audit_error = ADT_FAIL_VALUE_PROGRAM;
			login_exit(1);
		}
	} else {
		/* Now attempt to write out this entry to the wtmp file if */
		/* we were successful in getting it from the utmpx file and */
		/* the wtmp file exists.				   */
		updwtmpx(WTMPX_FILE, &utmpx);
	}
}



/*
 * process_chroot_logins 	- Chroots to the specified subdirectory and
 *				  re executes login.
 */

static int
process_chroot_logins(void)
{
	/*
	 * If the shell field starts with a '*', do a chroot to the home
	 * directory and perform a new login.
	 */

	if (*pwd->pw_shell == '*') {
		(void) pam_end(pamh, PAM_SUCCESS);	/* Done using PAM */
		pamh = NULL;				/* really done */
		if (chroot(pwd->pw_dir) < 0) {
			(void) printf("No Root Directory\n");

			audit_failure(get_audit_id(),
			    ADT_FAIL_VALUE_CHDIR_FAILED,
			    pwd, remote_host, ttyn, zone_name);

			return (ERROR);
		}
		/*
		 * Set the environment flag <!sublogin> so that the next login
		 * knows that it is a sublogin.
		 */
		envinit[0] = SUBLOGIN;
		envinit[1] = (char *)NULL;
		(void) printf("Subsystem root: %s\n", pwd->pw_dir);
		(void) execle("/usr/bin/login", "login", (char *)0,
		    &envinit[0]);
		(void) execle("/etc/login", "login", (char *)0, &envinit[0]);
		(void) printf("No /usr/bin/login or /etc/login on root\n");

		audit_error = ADT_FAIL_VALUE_PROGRAM;

		login_exit(1);
	}
	return (OK);
}

/*
 * establish_user_environment	- Set up the new users enviornment
 */

static void
establish_user_environment(char **renvp)
{
	int i, j, k, l_index, length, idx = 0;
	char *endptr;
	char **lenvp;
	char **pam_env;

	lenvp = environ;
	while (*lenvp++)
		;

	/* count the number of PAM environment variables set by modules */
	if ((pam_env = pam_getenvlist(pamh)) != 0) {
		for (idx = 0; pam_env[idx] != 0; idx++)
				;
	}

	envinit = (char **)calloc(lenvp - environ + 10 + MAXARGS + idx,
	    sizeof (char *));
	if (envinit == NULL) {
		(void) printf("Calloc failed - out of swap space.\n");
		login_exit(8);
	}

	/*
	 * add PAM environment variables first so they
	 * can be overwritten at login's discretion.
	 * check for illegal environment variables.
	 */
	idx = 0;	basicenv = 0;
	if (pam_env != 0) {
		while (pam_env[idx] != 0) {
			if (legalenvvar(pam_env[idx])) {
				envinit[basicenv] = pam_env[idx];
				basicenv++;
			}
			idx++;
		}
	}
	(void) memcpy(&envinit[basicenv], newenv, sizeof (newenv));

	/* Set up environment */
	if (rflag) {
		ENVSTRNCAT(term, terminal);
	} else if (hflag) {
		if (strlen(terminal)) {
			ENVSTRNCAT(term, terminal);
		}
	} else {
		char *tp = getenv("TERM");

		if ((tp != NULL) && (*tp != '\0'))
			ENVSTRNCAT(term, tp);
	}

	ENVSTRNCAT(logname, pwd->pw_name);

	/*
	 * There are three places to get timezone info.  init.c sets
	 * TZ if the file /etc/default/init contains a value for TZ.
	 * login.c looks in the file /etc/default/login for a
	 * variable called TIMEZONE being set.  If TIMEZONE has a
	 *  value, TZ is set to that value; no environment variable
	 * TIMEZONE is set, only TZ.  If neither of these methods
	 * work to set TZ, then the library routines  will default
	 * to using the file /usr/lib/locale/TZ/localtime.
	 *
	 * There is a priority set up here.  If /etc/default/init has
	 * a value for TZ, that value remains top priority.  If the
	 * file /etc/default/login has TIMEZONE set, that has second
	 * highest priority not overriding the value of TZ in
	 * /etc/default/init.  The reason for this priority is that the
	 * file /etc/default/init is supposed to be sourced by
	 * /etc/profile.  We are doing the "sourcing" prematurely in
	 * init.c.  Additionally, a login C shell doesn't source the
	 * file /etc/profile thus not sourcing /etc/default/init thus not
	 * allowing an adminstrator to globally set TZ for all users
	 */
	if (Def_tz != NULL)	/* Is there a TZ from defaults/login? */
		tmp_tz = Def_tz;

	if ((Def_tz = getenv("TZ")) != NULL) {
		ENVSTRNCAT(timez, Def_tz);
	} else if (tmp_tz != NULL) {
		Def_tz = tmp_tz;
		ENVSTRNCAT(timez, Def_tz);
	}

	if (Def_hertz == NULL)
		(void) sprintf(hertz + strlen(hertz), "%lu", HZ);
	else
		ENVSTRNCAT(hertz, Def_hertz);

	if (Def_path == NULL)
		(void) strlcat(path, DEF_PATH, sizeof (path));
	else
		ENVSTRNCAT(path, Def_path);

	ENVSTRNCAT(home, pwd->pw_dir);

	/*
	 * Find the end of the basic environment
	 */
	for (basicenv = 0; envinit[basicenv] != NULL; basicenv++)
		;

	/*
	 * If TZ has a value, add it.
	 */
	if (strcmp(timez, "TZ=") != 0)
		envinit[basicenv++] = timez;

	if (*pwd->pw_shell == '\0') {
		/*
		 * If possible, use the primary default shell,
		 * otherwise, use the secondary one.
		 */
		if (access(SHELL, X_OK) == 0)
			pwd->pw_shell = SHELL;
		else
			pwd->pw_shell = SHELL2;
	} else if (Altshell != NULL && strcmp(Altshell, "YES") == 0) {
		envinit[basicenv++] = shell;
		ENVSTRNCAT(shell, pwd->pw_shell);
	}

#ifndef	NO_MAIL
	envinit[basicenv++] = mail;
	(void) strlcat(mail, pwd->pw_name, sizeof (mail));
#endif

	/*
	 * Pick up locale environment variables, if any.
	 */
	lenvp = renvp;
	while (*lenvp != NULL) {
		j = 0;
		while (localeenv[j] != 0) {
			/*
			 * locale_envmatch() returns 1 if
			 * *lenvp is localenev[j] and valid.
			 */
			if (locale_envmatch(localeenv[j], *lenvp) == 1) {
				envinit[basicenv++] = *lenvp;
				break;
			}
			j++;
		}
		lenvp++;
	}

	/*
	 * If '-p' flag, then try to pass on allowable environment
	 * variables.  Note that by processing this first, what is
	 * passed on the final "login:" line may over-ride the invocation
	 * values.  XXX is this correct?
	 */
	if (pflag) {
		for (lenvp = renvp; *lenvp; lenvp++) {
			if (!legalenvvar(*lenvp)) {
				continue;
			}
			/*
			 * If this isn't 'xxx=yyy', skip it.  XXX
			 */
			if ((endptr = strchr(*lenvp, '=')) == NULL) {
				continue;
			}
			length = endptr + 1 - *lenvp;
			for (j = 0; j < basicenv; j++) {
				if (strncmp(envinit[j], *lenvp, length) == 0) {
					/*
					 * Replace previously established value
					 */
					envinit[j] = *lenvp;
					break;
				}
			}
			if (j == basicenv) {
				/*
				 * It's a new definition, so add it at the end.
				 */
				envinit[basicenv++] = *lenvp;
			}
		}
	}

	/*
	 * Add in all the environment variables picked up from the
	 * argument list to "login" or from the user response to the
	 * "login" request, if any.
	 */

	if (envp == NULL)
		goto switch_env;	/* done */

	for (j = 0, k = 0, l_index = 0;
	    *envp != NULL && j < (MAXARGS-1);
	    j++, envp++) {

		/*
		 * Scan each string provided.  If it doesn't have the
		 * format xxx=yyy, then add the string "Ln=" to the beginning.
		 */
		if ((endptr = strchr(*envp, '=')) == NULL) {
			/*
			 * This much to be malloc'd:
			 *   strlen(*envp) + 1 char for 'L' +
			 *   MAXARGSWIDTH + 1 char for '=' + 1 for null char;
			 *
			 * total = strlen(*envp) + MAXARGSWIDTH + 3
			 */
			int total = strlen(*envp) + MAXARGSWIDTH + 3;
			envinit[basicenv+k] = malloc(total);
			if (envinit[basicenv+k] == NULL) {
				(void) printf("%s: malloc failed\n", PROG_NAME);
				login_exit(1);
			}
			(void) snprintf(envinit[basicenv+k], total, "L%d=%s",
			    l_index, *envp);

			k++;
			l_index++;
		} else  {
			if (!legalenvvar(*envp)) { /* this env var permited? */
				continue;
			} else {

				/*
				 * Check to see whether this string replaces
				 * any previously defined string
				 */
				for (i = 0, length = endptr + 1 - *envp;
				    i < basicenv + k; i++) {
					if (strncmp(*envp, envinit[i], length)
					    == 0) {
						envinit[i] = *envp;
						break;
					}
				}

				/*
				 * If it doesn't, place it at the end of
				 * environment array.
				 */
				if (i == basicenv+k) {
					envinit[basicenv+k] = *envp;
					k++;
				}
			}
		}
	}		/* for (j = 0 ... ) */

switch_env:
	/*
	 * Switch to the new environment.
	 */
	environ = envinit;
}

/*
 * print_banner		- Print the banner at start up
 *			   Do not turn on DOBANNER ifdef.  This is not
 *			   relevant to SunOS.
 */

static void
print_banner(void)
{
#ifdef DOBANNER
	uname(&un);
#if i386
	(void) printf("UNIX System V/386 Release %s\n%s\n"
	    "Copyright (C) 1984, 1986, 1987, 1988 AT&T\n"
	    "Copyright (C) 1987, 1988 Microsoft Corp.\nAll Rights Reserved\n",
	    un.release, un.nodename);
#elif sun
	(void) printf("SunOS Release %s Sun Microsystems %s\n%s\n"
	    "Copyright (c) 1984, 1986, 1987, 1988 AT&T\n"
	    "Copyright (c) 1988, 1989, 1990, 1991 Sun Microsystems\n"
	    "All Rights Reserved\n",
	    un.release, un.machine, un.nodename);
#else
	(void) printf("UNIX System V Release %s AT&T %s\n%s\n"
	    "Copyright (c) 1984, 1986, 1987, 1988 AT&T\nAll Rights Reserved\n",
	    un.release, un.machine, un.nodename);
#endif /* i386 */
#endif /* DOBANNER */
}

/*
 * display_last_login_time	- Advise the user the time and date
 *				  that this login-id was last used.
 */

static void
display_last_login_time(void)
{
	if (lastlogok) {
		(void) printf("Last login: %.*s ", 24-5, ctime(&ll.ll_time));

		if (*ll.ll_host != '\0')
			(void) printf("from %.*s\n", sizeof (ll.ll_host),
			    ll.ll_host);
		else
			(void) printf("on %.*s\n", sizeof (ll.ll_line),
			    ll.ll_line);
	}
}

/*
 * exec_the_shell	- invoke the specified shell or start up program
 */

static void
exec_the_shell(void)
{
	char *endptr;
	int i;

	(void) strlcat(minusnam, basename(pwd->pw_shell),
	    sizeof (minusnam));

	/*
	 * Exec the shell
	 */
	(void) execl(pwd->pw_shell, minusnam, (char *)0);

	/*
	 * pwd->pw_shell was not an executable object file, maybe it
	 * is a shell proceedure or a command line with arguments.
	 * If so, turn off the SHELL= environment variable.
	 */
	for (i = 0; envinit[i] != NULL; ++i) {
		if ((envinit[i] == shell) &&
		    ((endptr = strchr(shell, '=')) != NULL))
			(*++endptr) = '\0';
		}

	if (access(pwd->pw_shell, R_OK|X_OK) == 0) {
		(void) execl(SHELL, "sh", pwd->pw_shell, (char *)0);
		(void) execl(SHELL2, "sh", pwd->pw_shell, (char *)0);
	}

	(void) printf("No shell\n");
}

/*
 * login_exit		- Call exit()  and terminate.
 *			  This function is here for PAM so cleanup can
 *			  be done before the process exits.
 */
static void
login_exit(int exit_code)
{
	if (pamh)
		(void) pam_end(pamh, PAM_ABORT);

	if (audit_error)
		audit_failure(get_audit_id(), audit_error,
		    pwd, remote_host, ttyn, zone_name);

	exit(exit_code);
	/*NOTREACHED*/
}

/*
 * Check if lenv and penv matches or not.
 */
static int
locale_envmatch(char *lenv, char *penv)
{
	while ((*lenv == *penv) && *lenv && *penv != '=') {
		lenv++;
		penv++;
	}

	/*
	 * '/' is eliminated for security reason.
	 */
	if (*lenv == '\0' && *penv == '=' && *(penv + 1) != '/')
		return (1);
	return (0);
}

static int
is_number(char *ptr)
{
	while (*ptr != '\0') {
		if (!isdigit(*ptr))
			return (0);
		ptr++;
	}
	return (1);
}
