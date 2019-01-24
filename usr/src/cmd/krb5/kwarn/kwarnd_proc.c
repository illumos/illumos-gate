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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *  RPC server procedures for the usermode daemon kwarnd.
 */

#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <strings.h>
#include <string.h>
#include <sys/param.h>
#include <sys/syslog.h>
#include "kwarnd.h"
#include <rpc/rpc.h>
#include <stdlib.h>
#include <syslog.h>
#include <poll.h>
#include <utmpx.h>
#include <pwd.h>
#include <strings.h>
#include <ctype.h>

#include <k5-int.h>
#include <profile/prof_int.h>
#include <com_err.h>
#include <libintl.h>
#include <krb5.h>

extern char progname[];

struct k5_data
{
	krb5_context ctx;
	krb5_ccache cc;
	krb5_principal me;
	char *name;
};


#define	MAIL		"mail"
#define	MAILPATH	"/usr/bin/mail"
#define	DEFAULT_CONFIG	"* terminal 30m"
#define	CONF_FILENAME	"/etc/krb5/warn.conf"

/* warn.conf info */

typedef struct config_entry_s {
	struct config_entry_s		*next;
	int				seconds_to_warn;
	char				*principal;
	char				*where_to;
	char				*email;
	int				renew;
	int				log_success;
	int				log_failure;
} config_entry_list_t;
static config_entry_list_t		*config_entry_list;

/* list of principals to be warned */

typedef struct cred_warning_list_s {
	struct cred_warning_list_s 	*next;
	WARNING_NAME_T			warn_name;
	time_t				cred_exp_time;
	time_t				cred_warn_time;
	mutex_t				cwm;
} cred_warning_list_t;
static cred_warning_list_t		*cred_warning_list;
static rwlock_t				cred_lock = DEFAULTRWLOCK;

static bool_t
del_warning_pvt(char *);

static config_entry_list_t *
find_warning_info(char *);

static bool_t
parseConfigLine(char *buffer);

extern int warn_send(char *, char *);

extern int kwarnd_debug;

cred_warning_list_t *
find_cred_warning(WARNING_NAME_T warn_name)
{
	cred_warning_list_t	*cw;
	if (!cred_warning_list)
		return (NULL);
	for (cw = cred_warning_list; cw != NULL; cw = cw->next) {
		if (strcmp(warn_name, cw->warn_name) != 0)
			continue;
		return (cw);
	}
	return (NULL);
}

/*
 * add a principal to the principal warning list
 */

bool_t
kwarn_add_warning_1_svc(kwarn_add_warning_arg *argp,
			kwarn_add_warning_res *res,
			struct svc_req *rqstp)
{
	cred_warning_list_t	*cred_warning;
	config_entry_list_t *config_entry;

	if (kwarnd_debug) {
		printf("kwarn_add_warning_1_svc start; cWlist=%p\n",
		    cred_warning_list);

		printf("kwarn_add_warning_1_svc: principal %s",
		    argp->warning_name);
		printf(" exp time: %d\n", argp->cred_exp_time);
	}

/*
 *  if there is no entry in the config file that matches the principal to
 *  be added to the warning list, return true because we are not going to
 *  send a warning for this principal.
 */

	if ((config_entry = find_warning_info(argp->warning_name)) == NULL) {
		if (kwarnd_debug)
			printf(
		"kwarn_add_warning_1_svc find_warn_info: fails, cWlist=%p\n",
				cred_warning_list);

		return (TRUE);
	}

/*
 * see if a warning has already been created for this principal, if so
 * update the warning time.
 */

	rw_wrlock(&cred_lock);
	if (cred_warning = find_cred_warning(argp->warning_name)) {
		rw_unlock(&cred_lock);
		mutex_lock(&cred_warning->cwm);
		cred_warning->cred_exp_time = argp->cred_exp_time;
		cred_warning->cred_warn_time = argp->cred_exp_time
			- config_entry->seconds_to_warn;
		mutex_unlock(&cred_warning->cwm);
	} else {
		cred_warning = (cred_warning_list_t *)malloc(
				sizeof (*cred_warning_list));
		if (cred_warning == NULL) {
			rw_unlock(&cred_lock);
			res->status = 1;
			return (FALSE);
		}
		(void) memset((char *)cred_warning, 0,
			    sizeof (*cred_warning_list));
		cred_warning->cred_exp_time = argp->cred_exp_time;
		cred_warning->cred_warn_time = argp->cred_exp_time
			- config_entry->seconds_to_warn;
		cred_warning->warn_name = strdup(argp->warning_name);
		if (cred_warning->warn_name == NULL) {
			free(cred_warning);
			rw_unlock(&cred_lock);
			res->status = 1;
			return (FALSE);
		}
		mutex_init(&cred_warning->cwm,  USYNC_THREAD, NULL);
		cred_warning->next = cred_warning_list;
		cred_warning_list = cred_warning;
		rw_unlock(&cred_lock);
	}
	res->status = 0;

	if (kwarnd_debug)
		printf(
		"kwarn_add_warning_1_svc end: returns true; cWlist=%p\n",
		cred_warning_list);

	return (TRUE);
}

/*
 * delete a warning request for a given principal
 */

bool_t
kwarn_del_warning_1_svc(kwarn_del_warning_arg *argp,
			kwarn_del_warning_res *res,
			struct svc_req *rqstp)
{
	if (kwarnd_debug)
		printf(gettext("delete principal %s requested\n"),
		    argp->warning_name);

	if (del_warning_pvt(argp->warning_name) == TRUE) {
		res->status = 0;

		if (kwarnd_debug)
			printf(gettext("delete principal %s completed\n"),
			    argp->warning_name);

		return (TRUE);
	} else {
		res->status = 1;

		if (kwarnd_debug)
			printf(gettext("delete principal %s failed\n"),
				argp->warning_name);

		return (TRUE);
	}
}

static bool_t
del_warning_pvt(char *warning_name)
{
	cred_warning_list_t	*cred_warning, *prev;
	rw_wrlock(&cred_lock);
	for (prev = NULL, cred_warning = cred_warning_list;
		cred_warning != NULL; prev = cred_warning,
		cred_warning = cred_warning->next) {
		if (strcmp(cred_warning->warn_name, warning_name) == 0) {
			if (!prev)
				cred_warning_list = cred_warning->next;
			else
				prev->next = cred_warning->next;

			free(cred_warning->warn_name);
			free(cred_warning);
			rw_unlock(&cred_lock);
			return (TRUE);
		}
	}
	rw_unlock(&cred_lock);
	return (FALSE);
}

/*
 * load the warn.conf file into the config_entry list.
 */

bool_t
loadConfigFile(void)
{
	char	buffer[BUFSIZ];
	FILE	*cfgfile;
	bool_t	retval = TRUE;

	if ((cfgfile = fopen(CONF_FILENAME, "r")) == NULL) {
		syslog(LOG_ERR, gettext(
			"could not open config file \"%s\"\n"),
			CONF_FILENAME);
		syslog(LOG_ERR, gettext(
			"using default options \"%s\"\n"),
			DEFAULT_CONFIG);
		retval = parseConfigLine(DEFAULT_CONFIG);
	} else {
		(void) memset(buffer, 0, sizeof (buffer));
		while ((fgets(buffer, BUFSIZ, cfgfile) != NULL) &&
			(retval == TRUE))
			retval = parseConfigLine(buffer);
		fclose(cfgfile);
	}
	return (retval);
}

/*
 * Return TRUE if we get a valid opt and update flags appro.
 */
static bool_t
cmp_renew_opts(char *opt,
	    int *log_success, /* out */
	    int *log_failure) /* out */
{

	if (strncasecmp(opt, "log",
			sizeof ("log")) == 0) {
		*log_success = *log_failure = 1;
	} else if (strncasecmp(opt, "log-success",
			    sizeof ("log-success")) == 0) {
		*log_success = 1;
	} else if (strncasecmp(opt, "log-failure",
			    sizeof ("log-failure")) == 0) {
		*log_failure = 1;
	} else {
		if (kwarnd_debug)
			printf("cmp_renew_opts: renew bad opt=`%s'\n",
			    opt ? opt : "null");
		return (FALSE);
	}

	return (TRUE);
}

/*
 * Make the config_entry item for the config_entry_list, based on
 * buffer.  The formats are
 *
 *    <principal> [renew[:<opt1,...optN>]] syslog|terminal <time>
 *    <principal> [renew[:<opt1,...optN>]] mail <time> <e-mail address>
 *
 * where renew opts will be:
 *
 *     log-success
 *		- Log the result of the renew attempt on success using
 *		  the specified method (syslog|terminal|mail)
 *
 *      log-failure
 *		- Log the result of the renew attempt on failure using
 *		  the specified method (syslog|terminal|mail)
 *
 *      log
 *               - Same as specifing both log-failure and log-success
 *
 *		  Note if no log options are given, there will be no logging.
 *
 */

static bool_t
parseConfigLine(char *buffer)
{
	char *principal, *send_to, *emailid, *ends, *tm;
	char			*exptime;
	int			time_mode;
	time_t			etime;
	config_entry_list_t	*config_entry;
	int renew = 0;
	int log_success = 0;
	int log_failure = 0;

	/* ignore comments */
	if (*buffer == '#')
		return (TRUE);

	if (kwarnd_debug)
		printf("parseconf: buffer=%s", buffer);

	/* find end of principal */
	principal = buffer;
	for (send_to = buffer; *send_to && !isspace(*send_to);
		send_to++);

	/* find first non whitespace after principal (start of send_to) */
	if (*send_to) {
		*send_to = '\0';
		send_to++;
		while (*send_to && isspace(*send_to))
			send_to++;
	}

	/* if no send_to, continue, bad entry */
	if (! *send_to)
		return (TRUE);

	/* find end of send_to */
	for (ends = send_to; *ends && !isspace(*ends);
		ends++);
	if (*ends)
		*ends = '\0';


	if (strchr(send_to, ':')) {
		/* we've got renew opts */
		char *st = NULL, *op = NULL;

		op = strdup(send_to);
		if (!op)
			return (FALSE);
		st = strchr(op, ':');
		*st = '\0';

		if (strncasecmp(op, "renew", sizeof ("renew")) == 0) {
			renew = 1;
		} else {
			free(op);
			/* got a ':' but not preceeded w/renew, badent, skip */
			if (kwarnd_debug)
				printf("parseconf: colon badent, skip\n");
			return (TRUE);
		}
		free(op);
		op = NULL;

		st++;
		if (!st || !*st || isspace(*st)) {
			if (kwarnd_debug)
				printf("parseconf: st badent, skip\n");
			/* bad ent, skip */
			return (TRUE);
		}
		if (renew && strchr(st, ',')) {
			while (1) {
				/* loop thru comma seperated list-o-opts */
				char *comma = NULL, *c = NULL, *l = NULL;

				if (st && (comma = strchr(st, ','))) {
					l = strdup(st);
					if (!l)
						return (FALSE);
					c = strchr(l, ',');
					*c = '\0';
					if (!cmp_renew_opts(l, &log_success,
							    &log_failure)) {
						free(l);
						/* badent, skip */
						return (TRUE);
					}
					free(l);
					l = NULL;

					st = comma;
					st++;
				} else {
					if (st) {
						if (!cmp_renew_opts(st,
							    &log_success,
							    &log_failure)) {
							/* badent, skip */
							return (TRUE);
						}
					}
					break;
				}
			} /* while */
		} else if (st) {
			/* we just have one opt */
			if (!cmp_renew_opts(st, &log_success, &log_failure)) {
				/* badent, skip */
				return (TRUE);
			}
		}

		/* if send_to is "renew", note it and refind send_to */
	} else if (strncasecmp(send_to, "renew",
			    sizeof ("renew")) == 0) {
		renew = 1;

	}

	if (kwarnd_debug) {
		printf("parseconf: renew=%d, log failure=%d, log success=%d\n",
		    renew, log_failure, log_success);
	}

	if (renew) {
		/* find first non whitespace after send_to (start of exptime) */
		for (send_to = ends+1; *send_to && isspace(*send_to);
		    send_to++);

		/* if no send_to, continue, bad entry */
		if (! *send_to) {
			if (kwarnd_debug)
				printf("parseconf: no send_to, badent, skip\n");
			return (TRUE);
		}

		/* find end of send_to */
		for (ends = send_to; *ends && !isspace(*ends);
		    ends++);
		if (*ends)
			*ends = '\0';
	}


	/* find first non whitespace after send_to (start of exptime) */
	for (exptime = ends+1; *exptime && isspace(*exptime);
		exptime++);

	/* if no exptime, continue, bad entry */
	if (! *exptime) {
		if (kwarnd_debug)
			printf("parseconf: no exptime, badent, skip\n");
		return (TRUE);
	}

	/* find end of exptime */
	for (ends = exptime; *ends && !isspace(*ends); ends++);

	tm = ends - 1;
	if (*tm == 's')
		time_mode = 1;
	else if (*tm == 'm')
		time_mode = 2;
	else if (*tm == 'h')
		time_mode = 3;
	else
		time_mode = 1;

	if (*tm)
		*tm = '\0';

	if (kwarnd_debug) {
		printf("parseconf: send_to = '%s', exptime='%s'\n",
		    send_to, exptime);
	}

	/* find first non whitespace after exptime (start of emailid) */
	for (emailid = ends+1; *emailid && isspace(*emailid); emailid++);

	/* find end of emailid */
	if (*emailid) {
		for (ends = emailid; *ends && !isspace(*ends);
			ends++);

		if (*ends)
			*ends = '\0';
	}

	/* if send to mail and no mail address, bad entry */
	if ((strcmp(send_to, "mail") == 0) && (!*emailid)) {
		if (kwarnd_debug)
			printf("parseconf: returns true; no mail addr\n");

		syslog(LOG_ERR, gettext("missing mail address"
			" in config entry: \n%s %s %s "
			" cannot mail warning"), principal,
			send_to, exptime);
		return (TRUE);
	}

	/* create an entry */
	config_entry = (config_entry_list_t *)
		malloc(sizeof (*config_entry_list));
	if (config_entry == NULL)
		return (FALSE);
	(void) memset(config_entry, 0, sizeof (*config_entry_list));
	config_entry->principal = strdup(principal);
	if (config_entry->principal == NULL)
		return (FALSE);
	config_entry->where_to = strdup(send_to);
	if (config_entry->where_to == NULL)
		return (FALSE);
	etime = atol(exptime);
	if (time_mode == 1)
		config_entry->seconds_to_warn = etime;
	else if (time_mode == 2)
		config_entry->seconds_to_warn = etime * 60;
	else if (time_mode == 3)
		config_entry->seconds_to_warn = etime * 60 * 60;

	if (*emailid) {
		config_entry->email = strdup(emailid);
		if (config_entry->email == NULL)
			return (FALSE);
	}

	config_entry->renew = renew;
	config_entry->log_success = log_success;
	config_entry->log_failure = log_failure;
	config_entry->next = config_entry_list;
	config_entry_list = config_entry;
	if (kwarnd_debug)
		printf("parseconf: returns true; celist=%p\n",
		    config_entry_list);

	return (TRUE);
}

/*
 * find a specific warn.conf entry.
 */

static config_entry_list_t *
find_warning_info(char *principal)
{
	config_entry_list_t	*config_entry;
	/* look for a specific entry */
	for (config_entry = config_entry_list; config_entry;
		config_entry = config_entry->next) {
		if (strcmp(config_entry->principal, principal) == 0) {
			return (config_entry);
		}
	}
	/* look for a wild card entry */
	for (config_entry = config_entry_list; config_entry;
		config_entry = config_entry->next) {
		if (strcmp(config_entry->principal, "*") == 0) {
			return (config_entry);
		}
	}
	/* nothing found */
	return (NULL);

}

/*
 * create a pipe, fork and exec a command,
 */
static FILE *
safe_popen_w(char *path_to_cmd, char **argv)
{

	int fd[2];
	FILE *fp;
	char *envp[2];

	if (pipe(fd) == -1)
		return (NULL);


	switch (fork()) {
	case -1:
		(void) close(fd[0]);
		(void) close(fd[1]);
		return (NULL);

	case 0:
		close(fd[1]);
		/* fd[0] is the end we read from */
		if (fd[0] != 0) {
			close(0);
			dup(fd[0]);
		}
		close(1);
		close(2);
		envp[0] = "PATH=/usr/bin";
		envp[1] = NULL;
#ifdef	DEBUG
		{
			int fd;
			fd = open("/tmp/kwarn.out", O_WRONLY|O_TRUNC|O_CREAT,
				0666);
			if (fd != 1)
				dup(fd);
			if (fd != 2)
				dup(fd);
		}
#endif
		(void) execve(path_to_cmd, argv, envp);
		syslog(LOG_ERR, "warnd: %m");
		_exit(1);

	default:
		close(fd[0]);
		/* fd[1] is the end we write to */

		fp = fdopen(fd[1], "w");

		if (fp == NULL) {
			(void) close(fd[1]);
			return (NULL);
		}
		return (fp);
	}
}


static uid_t krb5_cc_uid;

void
set_warnd_uid(uid_t uid)
{
	/*
	 * set the value of krb5_cc_uid, so it can be retrieved when
	 * app_krb5_user_uid() is called by the underlying mechanism libraries.
	 */
	if (kwarnd_debug)
		printf("set_warnd_uid called with uid = %d\n", uid);
	krb5_cc_uid = uid;
}

uid_t
app_krb5_user_uid(void)
{

	/*
	 * return the value set when one of the kwarnd procedures was
	 * entered. This is the value of the uid under which the
	 * underlying mechanism library must operate in order to
	 * get the user's credentials. This call is necessary since
	 * kwarnd runs as root and credentials are many times stored
	 * in files and directories specific to the user
	 */
	if (kwarnd_debug)
		printf("app_krb5_user_uid called and returning uid = %d\n",
		    krb5_cc_uid);
	return (krb5_cc_uid);
}


static bool_t
getpruid(char *pr, uid_t *uid)
{
	char *rcp1 = NULL, *rcp2 = NULL, *rcp3 = NULL;
	struct passwd *pw;

	rcp1 = strdup(pr);
	if (!rcp1)
		return (FALSE);
	rcp2 = strtok(rcp1, "@");
	rcp3 = strtok(rcp2, "/");

	if (rcp3) {
		pw = getpwnam(rcp3);
		*uid = pw->pw_uid;
		free(rcp1);
		return (TRUE);
	}

	free(rcp1);
	return (FALSE);
}


static krb5_error_code
renew_creds(
	char *princ,
	time_t *new_exp_time) /* out */
{
	krb5_creds my_creds;
	krb5_error_code code = 0;
	struct k5_data k5;

	uid_t saved_u = app_krb5_user_uid();
	uid_t u;

	if (kwarnd_debug)
		printf("renew start: uid=%d\n", app_krb5_user_uid());

	if (!getpruid(princ, &u)) {
		if (kwarnd_debug)
			printf("renew: getpruid failed, princ='%s'\n",
			    princ ? princ : "<null>");

		return (-1); /* better err num? */
	}

	set_warnd_uid(u);

	(void) memset(&my_creds, 0, sizeof (my_creds));
	(void) memset(&k5, 0, sizeof (k5));

	if (code = krb5_init_context(&k5.ctx)) {
		com_err(progname, code,
			gettext("while initializing Kerberos 5 library"));
		goto out;
	}

	if ((code = krb5_cc_default(k5.ctx, &k5.cc))) {
		com_err(progname, code,
			gettext("while getting default ccache"));
		goto out;

	}

	if ((code = krb5_parse_name(k5.ctx, princ,
				    &k5.me))) {
		com_err(progname, code, gettext("when parsing name %s"),
			princ);
		goto out;
	}

	if ((code = krb5_get_renewed_creds(k5.ctx, &my_creds, k5.me, k5.cc,
					NULL))) {
		com_err(progname, code, gettext("while renewing creds"));
		goto out;
	}

	if (code = krb5_cc_initialize(k5.ctx, k5.cc, k5.me)) {
		com_err(progname, code, gettext("when initializing cache %s"),
			"defcc");
		goto out;
	}

	if (code = krb5_cc_store_cred(k5.ctx, k5.cc, &my_creds)) {
		com_err(progname, code, gettext("while storing credentials"));
		goto out;
	}

	/* "return" new expire time */
	*new_exp_time = my_creds.times.endtime;

out:
	krb5_free_cred_contents(k5.ctx, &my_creds);

	if (k5.name)
		krb5_free_unparsed_name(k5.ctx, k5.name);
	if (k5.me)
		krb5_free_principal(k5.ctx, k5.me);
	if (k5.cc)
		krb5_cc_close(k5.ctx, k5.cc);
	if (k5.ctx)
		krb5_free_context(k5.ctx);

	set_warnd_uid(saved_u);

	if (kwarnd_debug)
		printf("renew end: code=%s, uid=%d\n", error_message(code),
		    app_krb5_user_uid());

	return (code);
}

static bool_t
loggedon(char *name)
{
	register struct utmpx *ubuf;
	char    *rcp1 = NULL, *rcp2 = NULL, *rcp3 = NULL;

	/*
	 * strip any realm or instance from principal so we can match
	 * against unix userid.
	 */
	rcp1 = strdup(name);
	if (!rcp1)
		return (FALSE);
	rcp2 = strtok(rcp1, "@");
	rcp3 = strtok(rcp2, "/");

	/*
	 * Scan through the "utmpx" file for the
	 * entry for the person we want to send to.
	 */

	setutxent();
	while ((ubuf = getutxent()) != NULL) {
		if (ubuf->ut_type == USER_PROCESS) {
			if (strncmp(rcp3, ubuf->ut_user,
				    sizeof (ubuf->ut_user)) == 0) {
				free(rcp1);
				endutxent();
				return (TRUE);

			}
		}
	}
	free(rcp1);
	endutxent();

	if (kwarnd_debug)
		printf("loggedon: returning false for user `%s'\n", rcp1);

	return (FALSE);
}

/*
 * main loop to check the cred warning list and send the warnings
 * the appropriate location based on warn.conf or auto-renew creds.
 */

void
kwarnd_check_warning_list(void)
{ /* func */
	cred_warning_list_t	*cw;  /* cred warning */
	config_entry_list_t	*ce;  /* config entry */
	time_t			now;
	int			minutes;
	char			buff[256];
	char			cmdline[256];
	FILE			*fp;
	char			*subj = "Kerberos credentials expiring";
	char			*renew_subj = "Kerberos credentials renewed";

	if (kwarnd_debug)
		printf("check list: start: uid=%d, cw list=%p\n",
		    app_krb5_user_uid(), cred_warning_list);

	while (1) {
		(void) poll(NULL, 0, 60000);

		for (cw = cred_warning_list;
			cw != NULL;
			cw = cw->next) {
			int send_msg = 0;

			time(&now);
			if (now >= cw->cred_warn_time) {
				int renew_attempted = 0;
				int renew_failed = 0;
				int renew_tooclose = 0;

				if (kwarnd_debug)
					printf("checklist: now >= warn_t\n");

				ce = find_warning_info(cw->warn_name);
				minutes = (cw->cred_exp_time -
					now + 59) / 60;

				if (kwarnd_debug)
					printf("checklist: where_to=%s\n",
					    ce->where_to ?
					    ce->where_to : "null");

				if (ce->renew &&
				    loggedon(cw->warn_name)) {
					krb5_error_code code;
					time_t new_exp_time;

					renew_attempted = 1;
					code = renew_creds(
						cw->warn_name,
						&new_exp_time);
					if (!code) {
						/* krb5 api renew success */

						/*
						 * So we had api success
						 * but the new exp time
						 * is same as current one
						 * so we are too close
						 * to Renewable_life time.
						 */
						if (cw->cred_exp_time
						    == new_exp_time) {
							renew_tooclose = 1;
							if (kwarnd_debug)
								printf(
		"checklist: new expire time same as old expire time\n");

							if (ce->log_failure) {
								send_msg = 1;
								snprintf(buff,
								sizeof (buff),
					gettext("%s:\r\nYour kerberos"
					" credentials have not been renewed"
					" (too close to Renewable_life).\r\n"
					"Please run kinit(1).\r\n"),
								cw->warn_name);
							}
						} else {
							/* update times */
							cw->cred_exp_time =
								new_exp_time;
							cw->cred_warn_time =
							    new_exp_time -
							    ce->seconds_to_warn;
						}

						if (kwarnd_debug)
							printf(
						    "check list: new_w_t=%d\n",
						    cw->cred_warn_time);

						if (!renew_tooclose &&
						    ce->log_success) {
							if (kwarnd_debug)
								printf(
						"check list: log success\n");

							send_msg = 1;
							snprintf(buff,
								sizeof (buff),
						gettext("%s:\r\nYour kerberos"
					" credentials have been renewed.\r\n"),
								cw->warn_name);
						}

					}  /* !(code) */

					if (!renew_tooclose && code &&
					    ce->log_failure) {
						if (kwarnd_debug)
							printf(
						"check list: log FAIL\n");

						send_msg = 1;
						snprintf(buff,
							sizeof (buff),
					    gettext("%s:\r\nYour kerberos"
				" credentials failed to be renewed (%s).\r\n"),
							cw->warn_name,
							error_message(code));
					}
					renew_failed = code ? 1 : 0;

				} else if (minutes > 0) {
					send_msg = 1;
					snprintf(buff, sizeof (buff),
					gettext("%s:\r\nyour kerberos"
					" credentials expire in less than"
					" %d minutes.\r\n"),
					cw->warn_name,
					minutes);
				} else {
					send_msg = 1;
					snprintf(buff, sizeof (buff),
					gettext("%s:\r\nyour kerberos"
					" credentials have expired.\r\n"),
					cw->warn_name);
				}

				if (kwarnd_debug)
					printf("checklist: send_msg=%d\n",
					    send_msg);
				if (!send_msg)
					goto del_warning;

				if (strncmp(ce->where_to,
					    "mail", sizeof ("mail")) == 0) {
					char *argv[3];

					argv[0] = MAIL;
					(void) snprintf(cmdline,
							sizeof (cmdline),
							"%s",
							ce->email);
					argv[1] = cmdline;
					argv[2] = NULL;

					fp = safe_popen_w(MAILPATH, argv);

					if (fp) {

						(void) fprintf(fp,
						"To: %s\nSubject: %s\n\n%s\n",
							    ce->email,
							    renew_attempted
							    ? renew_subj : subj,
							    buff);

					    fclose(fp);
					} else {
					    syslog(LOG_ERR,
						gettext("could not fork "
						"mail program to e-mail "
						"warning to %s\n"),
						cmdline);
					}

				} else if (strncmp(ce->where_to,
						"terminal",
						sizeof ("terminal")) == 0) {

					warn_send(cw->warn_name,
						buff);

				} else if (send_msg && strncmp(ce->where_to,
							    "syslog",
						sizeof ("syslog")) == 0) {
					syslog(LOG_NOTICE|LOG_AUTH,
					    "%s",
					    buff);
#if 0
				} else if (strncmp(ce->where_to,
						"snmp",
						sizeof ("snmp")) == 0) {
#endif
				} else {
					if (kwarnd_debug)
						printf(
						"unknown msg method=`%s'\n",
						ce->where_to);

					exit(1);
				}

			del_warning:
				if (!renew_attempted || renew_failed ||
				    renew_tooclose) {
					if (del_warning_pvt(cw->warn_name)
					    == TRUE) {

						if (kwarnd_debug)
							printf(
						"check list: del warn succ\n");

						break;
					} else {
						if (kwarnd_debug)
							printf(
						"could not delete warning\n");

						syslog(LOG_ERR, gettext(
						"could not delete warning"));

						exit(1);
					    }
					}

				} /* if (now) */
		} /* for */
	} /* while */
}  /* func */
