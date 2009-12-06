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


#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <syslog.h>
#include <pwd.h>
#include <shadow.h>
#include <lastlog.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <signal.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <crypt.h>
#include <assert.h>
#include <deflt.h>
#include <libintl.h>
#include <passwdutil.h>

#define	LASTLOG		"/var/adm/lastlog"
#define	LOGINADMIN	"/etc/default/login"
#define	UNIX_AUTH_DATA		"SUNW-UNIX-AUTH-DATA"
#define	UNIX_AUTHTOK_DATA	"SUNW-UNIX-AUTHTOK-DATA"

/*
 * Function Declarations
 */
extern void		setusershell();
extern int		_nfssys(int, void *);

typedef struct _unix_authtok_data_ {
	int age_status;
}unix_authtok_data;

/*ARGSUSED*/
static void
unix_cleanup(
	pam_handle_t *pamh,
	void *data,
	int pam_status)
{
	free((unix_authtok_data *)data);
}

/*
 * check_for_login_inactivity	- Check for login inactivity
 *
 */

static int
check_for_login_inactivity(
	uid_t		pw_uid,
	struct 	spwd 	*shpwd)
{
	int		fdl;
	struct lastlog	ll;
	int		retval;
	offset_t	offset;

	offset = (offset_t)pw_uid * (offset_t)sizeof (struct lastlog);

	if ((fdl = open(LASTLOG, O_RDWR|O_CREAT, 0444)) >= 0) {
		/*
		 * Read the last login (ll) time
		 */
		if (llseek(fdl, offset, SEEK_SET) != offset) {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "pam_unix_acct: pam_sm_acct_mgmt: "
			    "can't obtain last login info on uid %d "
			    "(uid too large)", pw_uid);
			(void) close(fdl);
			return (0);
		}

		retval = read(fdl, (char *)&ll, sizeof (ll));

		/* Check for login inactivity */

		if ((shpwd->sp_inact > 0) && (retval == sizeof (ll)) &&
		    ll.ll_time) {
			/*
			 * account inactive too long.
			 * and no update password set
			 * and no last pwd change date in shadow file
			 * and last pwd change more than inactive time
			 * then account inactive too long and no access.
			 */
			if (((time_t)((ll.ll_time / DAY) + shpwd->sp_inact)
			    < DAY_NOW) &&
			    (shpwd->sp_lstchg != 0) &&
			    (shpwd->sp_lstchg != -1) &&
			    ((shpwd->sp_lstchg + shpwd->sp_inact) < DAY_NOW)) {
				/*
				 * Account inactive for too long
				 */
				(void) close(fdl);
				return (1);
			}
		}

		(void) close(fdl);
	}
	return (0);
}

/*
 * new_password_check()
 *
 * check to see if the user needs to change their password
 */

static int
new_password_check(shpwd, flags)
	struct 	spwd 	*shpwd;
	int 		flags;
{
	time_t	now  = DAY_NOW;

	/*
	 * We want to make sure that we change the password only if
	 * passwords are required for the system, the user does not
	 * have a password, AND the user's NULL password can be changed
	 * according to its password aging information
	 */

	if ((flags & PAM_DISALLOW_NULL_AUTHTOK) != 0) {
		if (shpwd->sp_pwdp[0] == '\0') {
			if (((shpwd->sp_max == -1) ||
				((time_t)shpwd->sp_lstchg > now) ||
				((now >= (time_t)(shpwd->sp_lstchg +
							shpwd->sp_min)) &&
				(shpwd->sp_max >= shpwd->sp_min)))) {
					return (PAM_NEW_AUTHTOK_REQD);
			}
		}
	}
	return (PAM_SUCCESS);
}

/*
 * perform_passwd_aging_check
 *		- Check for password exipration.
 */
static	int
perform_passwd_aging_check(
	pam_handle_t *pamh,
	struct 	spwd 	*shpwd,
	int	flags)
{
	time_t 	now = DAY_NOW;
	int	idledays = -1;
	char	*ptr;
	char	messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];
	void	*defp;


	if ((defp = defopen_r(LOGINADMIN)) != NULL) {
		if ((ptr = defread_r("IDLEWEEKS=", defp)) != NULL)
			idledays = 7 * atoi(ptr);
		defclose_r(defp);
	}

	/*
	 * if (sp_lstchg == 0), the administrator has forced the
	 * user to change his/her passwd
	 */
	if (shpwd->sp_lstchg == 0)
		return (PAM_NEW_AUTHTOK_REQD);

	/* If password aging is disabled (or min>max), all is well */
	if (shpwd->sp_max < 0 || shpwd->sp_max < shpwd->sp_min)
		return (PAM_SUCCESS);

	/* Password aging is enabled. See if the password has aged */
	if (now < (time_t)(shpwd->sp_lstchg + shpwd->sp_max))
		return (PAM_SUCCESS);

	/* Password has aged. Has it aged more than idledays ? */
	if (idledays < 0)			/* IDLEWEEKS not configured */
		return (PAM_NEW_AUTHTOK_REQD);

	/* idledays is configured */
	if (idledays > 0 && (now < (time_t)(shpwd->sp_lstchg + idledays)))
		return (PAM_NEW_AUTHTOK_REQD);

	/* password has aged more that allowed for by IDLEWEEKS */
	if (!(flags & PAM_SILENT)) {
		(void) strlcpy(messages[0], dgettext(TEXT_DOMAIN,
		    "Your password has been expired for too long."),
		    sizeof (messages[0]));
		(void) strlcpy(messages[1], dgettext(TEXT_DOMAIN,
		    "Please contact the system administrator."),
		    sizeof (messages[0]));
		(void) __pam_display_msg(pamh, PAM_ERROR_MSG, 2, messages,
		    NULL);
	}
	return (PAM_AUTHTOK_EXPIRED);
}

/*
 * warn_user_passwd_will_expire	- warn the user when the password will
 *					  expire.
 */

static void
warn_user_passwd_will_expire(
	pam_handle_t *pamh,
	struct 	spwd shpwd)
{
	time_t 	now	= DAY_NOW;
	char	messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE];
	time_t	days;


	if ((shpwd.sp_warn > 0) && (shpwd.sp_max > 0) &&
	    (now + shpwd.sp_warn) >= (time_t)(shpwd.sp_lstchg + shpwd.sp_max)) {
		days = (time_t)(shpwd.sp_lstchg + shpwd.sp_max) - now;
		if (days <= 0)
			(void) snprintf(messages[0],
			    sizeof (messages[0]),
			    dgettext(TEXT_DOMAIN,
			    "Your password will expire within 24 hours."));
		else if (days == 1)
			(void) snprintf(messages[0],
			    sizeof (messages[0]),
			    dgettext(TEXT_DOMAIN,
			    "Your password will expire in 1 day."));
		else
			(void) snprintf(messages[0],
			    sizeof (messages[0]),
			    dgettext(TEXT_DOMAIN,
			    "Your password will expire in %d days."),
			    (int)days);

		(void) __pam_display_msg(pamh, PAM_TEXT_INFO, 1, messages,
		    NULL);
	}
}

/*
 * pam_sm_acct_mgmt	- 	main account managment routine.
 *			  Returns: module error or specific error on failure
 */

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	uid_t			pw_uid;
	char			*repository_name = NULL;
	char    		*user;
	attrlist		attr_pw[3];
	attrlist		attr_spw[7];
	pwu_repository_t	*pwu_rep = PWU_DEFAULT_REP;
	pwu_repository_t	*auth_rep = NULL;
	int 			error = PAM_ACCT_EXPIRED;
	int			result;
	int			i;
	int			debug = 0;
	int			server_policy = 0;
	unix_authtok_data	*status;
	struct 	spwd		shpwd = {NULL, NULL,
					-1, -1, -1, -1, -1, -1, 0};

	for (i = 0; i < argc; i++) {
		if (strcasecmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strcasecmp(argv[i], "server_policy") == 0)
			server_policy = 1;
		else if (strcasecmp(argv[i], "nowarn") == 0) {
			flags = flags | PAM_SILENT;
		} else {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "ACCOUNT:pam_sm_acct_mgmt: illegal option %s",
			    argv[i]);
		}
	}

	if (debug)
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_unix_account: entering pam_sm_acct_mgmt()");

	if ((error = pam_get_item(pamh, PAM_USER, (void **)&user))
	    != PAM_SUCCESS)
		goto out;

	if (user == NULL) {
		error = PAM_USER_UNKNOWN;
		goto out;
	} else
		shpwd.sp_namp = user;

	if ((error = pam_get_item(pamh, PAM_REPOSITORY, (void **)&auth_rep))
	    != PAM_SUCCESS)
		goto out;

	if (auth_rep == NULL) {
		pwu_rep = PWU_DEFAULT_REP;
	} else {
		if ((pwu_rep = calloc(1, sizeof (*pwu_rep))) == NULL) {
			error = PAM_BUF_ERR;
			goto out;
		}
		pwu_rep->type = auth_rep->type;
		pwu_rep->scope = auth_rep->scope;
		pwu_rep->scope_len = auth_rep->scope_len;
	}

	/*
	 * First get the password information
	 */
	attr_pw[0].type =  ATTR_REP_NAME;	attr_pw[0].next = &attr_pw[1];
	attr_pw[1].type =  ATTR_UID;		attr_pw[1].next = &attr_pw[2];
	attr_pw[2].type =  ATTR_PASSWD;		attr_pw[2].next = NULL;
	result = __get_authtoken_attr(user, pwu_rep, attr_pw);

	if (result == PWU_NOT_FOUND) {
		error = PAM_USER_UNKNOWN;
		goto out;
	} else if (result == PWU_DENIED) {
		error = PAM_PERM_DENIED;
		goto out;
	} else if (result == PWU_NOMEM) {
		error = PAM_BUF_ERR;
		goto out;
	} else if (result != PWU_SUCCESS) {
		error = PAM_SERVICE_ERR;
		goto out;
	} else {
		repository_name = attr_pw[0].data.val_s;
		pw_uid = attr_pw[1].data.val_i;
		shpwd.sp_pwdp = attr_pw[2].data.val_s;
	}

	/*
	 * if repository is not files|nis, and user wants server_policy,
	 * we don't care about aging and hence return PAM_IGNORE
	 */
	if (server_policy &&
	    strcmp(repository_name, "files") != 0 &&
	    strcmp(repository_name, "nis") != 0) {
		error = PAM_IGNORE;
		goto out;
	}

	/*
	 * Now get the aging information
	 */
	attr_spw[0].type =  ATTR_LSTCHG;	attr_spw[0].next = &attr_spw[1];
	attr_spw[1].type =  ATTR_MIN;		attr_spw[1].next = &attr_spw[2];
	attr_spw[2].type =  ATTR_MAX;		attr_spw[2].next = &attr_spw[3];
	attr_spw[3].type =  ATTR_WARN;		attr_spw[3].next = &attr_spw[4];
	attr_spw[4].type =  ATTR_INACT;		attr_spw[4].next = &attr_spw[5];
	attr_spw[5].type =  ATTR_EXPIRE;	attr_spw[5].next = &attr_spw[6];
	attr_spw[6].type =  ATTR_FLAG;		attr_spw[6].next = NULL;

	result = __get_authtoken_attr(user, pwu_rep, attr_spw);
	if (result == PWU_SUCCESS) {
		shpwd.sp_lstchg = attr_spw[0].data.val_i;
		shpwd.sp_min = attr_spw[1].data.val_i;
		shpwd.sp_max = attr_spw[2].data.val_i;
		shpwd.sp_warn = attr_spw[3].data.val_i;
		shpwd.sp_inact = attr_spw[4].data.val_i;
		shpwd.sp_expire = attr_spw[5].data.val_i;
		shpwd.sp_flag = attr_spw[6].data.val_i;
	}

	if (debug) {
		char *pw = "Unix PW";

		if (shpwd.sp_pwdp == NULL)
			pw = "NULL";
		else if (strncmp(shpwd.sp_pwdp, LOCKSTRING,
		    sizeof (LOCKSTRING) - 1) == 0)
			pw = LOCKSTRING;
		else if (strcmp(shpwd.sp_pwdp, NOPWDRTR) == 0)
			pw = NOPWDRTR;

		if (result ==  PWU_DENIED) {
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "pam_unix_account: %s: permission denied "
			    "to access password aging information. "
			    "Using defaults.", user);
		}

		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "%s Policy:Unix, pw=%s, lstchg=%d, min=%d, max=%d, "
		    "warn=%d, inact=%d, expire=%d",
		    user, pw, shpwd.sp_lstchg, shpwd.sp_min, shpwd.sp_max,
		    shpwd.sp_warn, shpwd.sp_inact, shpwd.sp_expire);
	}

	if (pwu_rep != PWU_DEFAULT_REP) {
		free(pwu_rep);
		pwu_rep = PWU_DEFAULT_REP;
	}

	if (result == PWU_NOT_FOUND) {
		error = PAM_USER_UNKNOWN;
		goto out;
	} else if (result == PWU_NOMEM) {
		error = PAM_BUF_ERR;
		goto out;
	} else if (result != PWU_SUCCESS && result != PWU_DENIED) {
		error = PAM_SERVICE_ERR;
		goto out;
	}

	/*
	 * Check for locked account
	 */
	if (shpwd.sp_pwdp != NULL &&
	    strncmp(shpwd.sp_pwdp, LOCKSTRING, sizeof (LOCKSTRING) - 1) == 0) {
		char *service;
		char *rhost = NULL;

		(void) pam_get_item(pamh, PAM_SERVICE, (void **)&service);
		(void) pam_get_item(pamh, PAM_RHOST, (void **)&rhost);
		__pam_log(LOG_AUTH | LOG_NOTICE,
		    "pam_unix_account: %s attempting to validate locked "
		    "account %s from %s",
		    service, user,
		    (rhost != NULL && *rhost != '\0') ? rhost : "local host");
		error = PAM_PERM_DENIED;
		goto out;
	}

	/*
	 * Check for NULL password and, if so, see if such is allowed
	 */
	if (shpwd.sp_pwdp[0] == '\0' &&
	    (flags & PAM_DISALLOW_NULL_AUTHTOK) != 0) {
		char *service;
		char *rhost = NULL;

		(void) pam_get_item(pamh, PAM_SERVICE, (void **)&service);
		(void) pam_get_item(pamh, PAM_RHOST, (void **)&rhost);

		__pam_log(LOG_AUTH | LOG_NOTICE,
		    "pam_unix_account: %s: empty password not allowed for "
		    "account %s from %s", service, user,
		    (rhost != NULL && *rhost != '\0') ? rhost : "local host");
		error = PAM_PERM_DENIED;
		goto out;
	}

	/*
	 * Check for account expiration
	 */
	if (shpwd.sp_expire > 0 &&
	    (time_t)shpwd.sp_expire < DAY_NOW) {
		error = PAM_ACCT_EXPIRED;
		goto out;
	}

	/*
	 * Check for excessive login account inactivity
	 */
	if (check_for_login_inactivity(pw_uid, &shpwd)) {
		error = PAM_PERM_DENIED;
		goto out;
	}

	/*
	 * Check to see if the user needs to change their password
	 */
	if (error = new_password_check(&shpwd, flags)) {
		goto out;
	}

	/*
	 * Check to make sure password aging information is okay
	 */
	if ((error = perform_passwd_aging_check(pamh, &shpwd, flags))
	    != PAM_SUCCESS) {
		goto out;
	}

	/*
	 * Finally, warn the user if their password is about to expire.
	 */
	if (!(flags & PAM_SILENT)) {
		warn_user_passwd_will_expire(pamh, shpwd);
	}

	/*
	 * All done, return Success
	 */
	error = PAM_SUCCESS;

out:

	{
		int pam_res;
		unix_authtok_data *authtok_data;

		if (debug) {
			__pam_log(LOG_AUTH | LOG_DEBUG,
			    "pam_unix_account: %s: %s",
			    (user == NULL)?"NULL":user,
			    pam_strerror(pamh, error));
		}

		if (repository_name)
			free(repository_name);
		if (pwu_rep != PWU_DEFAULT_REP)
			free(pwu_rep);
		if (shpwd.sp_pwdp) {
			(void) memset(shpwd.sp_pwdp, 0, strlen(shpwd.sp_pwdp));
			free(shpwd.sp_pwdp);
		}

		/* store the password aging status in the pam handle */
		pam_res = pam_get_data(pamh, UNIX_AUTHTOK_DATA,
		    (const void **)&authtok_data);

		if ((status = (unix_authtok_data *)calloc(1,
		    sizeof (unix_authtok_data))) == NULL) {
			return (PAM_BUF_ERR);
		}

		if (pam_res == PAM_SUCCESS)
			(void) memcpy(status, authtok_data,
			    sizeof (unix_authtok_data));

		status->age_status = error;
		if (pam_set_data(pamh, UNIX_AUTHTOK_DATA, status, unix_cleanup)
		    != PAM_SUCCESS) {
			free(status);
			return (PAM_SERVICE_ERR);
		}
	}

	return (error);
}
