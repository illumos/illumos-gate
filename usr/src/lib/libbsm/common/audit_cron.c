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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/systeminfo.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_private.h>
#include <unistd.h>
#include <wait.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libgen.h>

#include <locale.h>
#include "generic.h"

#define	F_AUID	"%u\n"
#define	F_SMASK	"%x\n"
#define	F_FMASK	"%x\n"
#define	F_PORT	"%lx\n"
#define	F_TYPE	"%x\n"
#define	F_MACH	"%x %x %x %x\n"
#define	F_ASID	"%u\n"

#define	AU_SUFFIX	".au"

#define	ANC_BAD_FILE	-1
#define	ANC_BAD_FORMAT	-2

#define	AUDIT_CRON_TEXTBUF	256
static char	textbuf[AUDIT_CRON_TEXTBUF];

int
audit_cron_mode()
{
	return (!cannot_audit(0));
}

static void
audit_cron_syslog(const char *message) {
	static	int	is_open = 0;

	if (!is_open) {
		openlog("Solaris_Audit", LOG_ODELAY, LOG_CRON);
		is_open = 1;
	}
	syslog(LOG_WARNING, "%s", message);
}

/*
 * audit_cron_getinfo returns the audit characteristics from the relevant
 * auxiliary file, it if exists.  If not, it creates them from the crontab
 * or atjob uid.
 */

static int
audit_cron_getinfo(char *fname, char *fname_aux, struct auditinfo_addr *info)
{
	int		fd;
	struct stat	st;
	au_mask_t mask;
	struct passwd	pwd;
	char		pwd_buff[1024];
	static char	*msg =
	    "Used defaults instead of ancilary audit file";

	if ((fd = open(fname_aux, O_RDONLY)) == -1) {
		/* no syslog here; common case */
		goto make_it_up;
	}
	if (fstat(fd, &st) == -1) {
		/* no syslog here either; common case */
		goto delete_first;
	}

	if (read(fd, textbuf, st.st_size) != st.st_size) {
		audit_cron_syslog(msg);
		goto delete_first;
	}

	if (sscanf(textbuf,
	    F_AUID
	    F_SMASK
	    F_FMASK
	    F_PORT
	    F_TYPE
	    F_MACH
	    F_ASID,
	    &(info->ai_auid),
	    &(info->ai_mask.am_success),
	    &(info->ai_mask.am_failure),
	    &(info->ai_termid.at_port),
	    &(info->ai_termid.at_type),
	    &(info->ai_termid.at_addr[0]),
	    &(info->ai_termid.at_addr[1]),
	    &(info->ai_termid.at_addr[2]),
	    &(info->ai_termid.at_addr[3]),
	    &(info->ai_asid)) != 10) {
		audit_cron_syslog(msg);
		goto delete_first;
	}
	(void) close(fd);
	return (0);

delete_first:
	(void) close(fd);
	if (unlink(fname_aux)) {
		if (errno != ENOENT)
			audit_cron_syslog(
			    "Failed to remove invalid ancilary audit file");
	}
	/* intentionally falls through */

make_it_up:
	if (stat(fname, &st))
		return (-1);

	/* port and IP are zero */
	(void) memset(&(info->ai_termid), 0, sizeof (au_tid_addr_t));
	info->ai_termid.at_type = AU_IPv4;

	/* the caller is the child of cron which will run the job. */
	info->ai_asid = getpid();

	info->ai_mask.am_success = 0;	/* cover error case */
	info->ai_mask.am_failure = 0;

	if (strstr(fname, "crontabs") != NULL) {
		if (getpwnam_r(basename(fname), &pwd, pwd_buff,
		    sizeof (pwd_buff)) == NULL)
			return (-1); /* getpwnam_r sets errno */
	} else {
		if (getpwuid_r(st.st_uid, &pwd, pwd_buff, sizeof (pwd_buff)) ==
		    NULL)
			return (-1); /* getpwuid_r sets errno */
	}

	info->ai_auid = pwd.pw_uid;

	if (au_user_mask(pwd.pw_name, &mask)) {
		errno = EINVAL; /* pw_name lookup failed */
		return (-1);
	}
	info->ai_mask.am_success = mask.am_success;
	info->ai_mask.am_failure = mask.am_failure;

	return (0);
}

int
audit_cron_setinfo(char *fname, struct auditinfo_addr *info)
{
	int		fd, len, r;
	int		save_err;

	r = chmod(fname, 0200);
	if (r == -1 && errno != ENOENT)
		return (-1);

	if ((fd = open(fname, O_CREAT|O_WRONLY|O_TRUNC, 0200)) == -1)
		return (-1);

	len = sprintf(textbuf,
	    F_AUID
	    F_SMASK
	    F_FMASK
	    F_PORT
	    F_TYPE
	    F_MACH
	    F_ASID,
	    info->ai_auid,
	    info->ai_mask.am_success,
	    info->ai_mask.am_failure,
	    info->ai_termid.at_port,
	    info->ai_termid.at_type,
	    info->ai_termid.at_addr[0],
	    info->ai_termid.at_addr[1],
	    info->ai_termid.at_addr[2],
	    info->ai_termid.at_addr[3],
	    info->ai_asid);

	if (write(fd, textbuf, len) != len)
		goto audit_setinfo_clean;

	if (fchmod(fd, 0400) == -1)
		goto audit_setinfo_clean;

	(void) close(fd);
	return (0);

audit_setinfo_clean:
	save_err = errno;
	(void) close(fd);
	(void) unlink(fname);
	errno = save_err;
	return (-1);
}

char *
audit_cron_make_anc_name(char *fname)
{
	char *anc_name;

	anc_name = (char *)malloc(strlen(fname) + strlen(AU_SUFFIX) + 1);
	if (anc_name == NULL)
		return (NULL);

	(void) strcpy(anc_name, fname);
	(void) strcat(anc_name, AU_SUFFIX);
	return (anc_name);
}

int
audit_cron_is_anc_name(char *name)
{
	int	pos;

	pos = strlen(name) - strlen(AU_SUFFIX);
	if (pos <= 0)
		return (0);

	if (strcmp(name + pos, AU_SUFFIX) == 0)
		return (1);

	return (0);
}

static void
audit_cron_session_failure(char *name, int type, char *err_str)
{
	const char	*mess;

	if (type == 0)
		mess = dgettext(bsm_dom,
		"at-job session for user %s failed: ancillary file: %s");
	else
		mess = dgettext(bsm_dom,
		"crontab job session for user %s failed: ancillary file: %s");

	(void) snprintf(textbuf, sizeof (textbuf), mess, name, err_str);

	aug_save_event(AUE_cron_invoke);
	aug_save_sorf(4);
	aug_save_text(textbuf);
	(void) aug_audit();
}


int
audit_cron_session(
		char *name,
		char *path,
		uid_t uid,
		gid_t gid,
		char *at_jobname)
{
	struct auditinfo_addr	info;
	au_mask_t		mask;
	char			*anc_file, *fname;
	int			r = 0;
	char			full_path[PATH_MAX];

	if (cannot_audit(0)) {
		return (0);
	}

	/* get auditinfo from ancillary file */
	if (at_jobname == NULL) {
		/*
		 *	this is a cron-event, so we can get
		 *	filename from "name" arg
		 */
		fname = name;
		if (path != NULL) {
			if (strlen(path) + strlen(fname) + 2 > PATH_MAX) {
				errno = ENAMETOOLONG;
				r = -1;
			}
			(void) strcat(strcat(strcpy(full_path, path), "/"),
			    fname);
			fname = full_path;
		}
	} else {
		/* this is an at-event, use "at_jobname" */
		fname = at_jobname;
	}

	if (r == 0) {
		anc_file = audit_cron_make_anc_name(fname);
		if (anc_file == NULL) {
			r = -1;
		} else {
			r = audit_cron_getinfo(fname, anc_file, &info);
		}
	}

	if (r != 0) {
		char *err_str;

		if (r == ANC_BAD_FORMAT)
			err_str = dgettext(bsm_dom, "bad format");
		else
			err_str = strerror(errno);

		audit_cron_session_failure(name,
		    at_jobname == NULL,
		    err_str);
		if (anc_file != NULL)
			free(anc_file);
		return (r);
	}

	free(anc_file);
	aug_init();

	/* get current audit masks */
	if (au_user_mask(name, &mask) == 0) {
		info.ai_mask.am_success  |= mask.am_success;
		info.ai_mask.am_failure  |= mask.am_failure;
	}

	/* save audit attributes for further use in current process */
	aug_save_auid(info.ai_auid);
	aug_save_asid(info.ai_asid);
	aug_save_tid_ex(info.ai_termid.at_port, info.ai_termid.at_addr,
	    info.ai_termid.at_type);
	aug_save_pid(getpid());
	aug_save_uid(uid);
	aug_save_gid(gid);
	aug_save_euid(uid);
	aug_save_egid(gid);

	/* set mixed audit masks */
	return (setaudit_addr(&info, sizeof (info)));
}

/*
 * audit_cron_new_job - create audit record with an information
 *			about new job started by cron.
 *	args:
 *	cmd  - command being run by cron daemon.
 *	type - type of job (0 - at-job, 1 - crontab job).
 *	event - not used. pointer to cron event structure.
 */
/*ARGSUSED*/
void
audit_cron_new_job(char *cmd, int type, void *event)
{
	if (cannot_audit(0))
		return;

	if (type == 0) {
		(void) snprintf(textbuf, sizeof (textbuf),
		    dgettext(bsm_dom, "at-job"));
	} else if (type == 1) {
		(void) snprintf(textbuf, sizeof (textbuf),
		    dgettext(bsm_dom, "batch-job"));
	} else if (type == 2) {
		(void) snprintf(textbuf, sizeof (textbuf),
		    dgettext(bsm_dom, "crontab-job"));
	} else if ((type > 2) && (type <= 25)) {	/* 25 from cron.h */
		(void) snprintf(textbuf, sizeof (textbuf),
		    dgettext(bsm_dom, "queue-job (%c)"), (type+'a'));
	} else {
		(void) snprintf(textbuf, sizeof (textbuf),
		    dgettext(bsm_dom, "unknown job type (%d)"), type);
	}

	aug_save_event(AUE_cron_invoke);
	aug_save_sorf(0);
	aug_save_text(textbuf);
	aug_save_text1(cmd);
	(void) aug_audit();
}

void
audit_cron_bad_user(char *name)
{
	if (cannot_audit(0))
		return;

	(void) snprintf(textbuf, sizeof (textbuf),
	    dgettext(bsm_dom, "bad user %s"), name);

	aug_save_event(AUE_cron_invoke);
	aug_save_sorf(2);
	aug_save_text(textbuf);
	(void) aug_audit();
}

void
audit_cron_user_acct_expired(char *name)
{
	if (cannot_audit(0))
		return;

	(void) snprintf(textbuf, sizeof (textbuf),
	    dgettext(bsm_dom,
	    "user %s account expired"), name);

	aug_save_event(AUE_cron_invoke);
	aug_save_sorf(3);
	aug_save_text(textbuf);
	(void) aug_audit();
}

int
audit_cron_create_anc_file(char *name, char *path, char *uname, uid_t uid)
{
	au_mask_t	msk;
	auditinfo_addr_t ai;
	int		pid;
	char		*anc_name;
	char		full_path[PATH_MAX];

	if (cannot_audit(0))
		return (0);

	if (name == NULL)
		return (0);

	if (path != NULL) {
		if (strlen(path) + strlen(name) + 2 > PATH_MAX)
			return (-1);
		(void) strcat(strcat(strcpy(full_path, path), "/"), name);
		name = full_path;
	}
	anc_name = audit_cron_make_anc_name(name);

	if (access(anc_name, F_OK) != 0) {
		if (au_user_mask(uname, &msk) != 0) {
			free(anc_name);
			return (-1);
		}

		ai.ai_mask = msk;
		ai.ai_auid = uid;
		ai.ai_termid.at_port = 0;
		ai.ai_termid.at_type = AU_IPv4;
		ai.ai_termid.at_addr[0] = 0;
		ai.ai_termid.at_addr[1] = 0;
		ai.ai_termid.at_addr[2] = 0;
		ai.ai_termid.at_addr[3] = 0;
		/* generate new pid to use it as asid */
		pid = vfork();
		if (pid == -1) {
			free(anc_name);
			return (-1);
		}
		if (pid == 0)
			exit(0);
		else {
		/*
		 * we need to clear status of children for
		 * wait() call in "cron"
		 */
			int lock;

			(void) waitpid(pid, &lock, 0);
		}
		ai.ai_asid = pid;
		if (audit_cron_setinfo(anc_name, &ai) != 0) {
			free(anc_name);
			return (-1);
		}
	}

	free(anc_name);
	return (0);
}

int
audit_cron_delete_anc_file(char *name, char *path)
{
	char	*anc_name;
	char	full_path[PATH_MAX];
	int	r;

	if (name == NULL)
		return (0);

	if (path != NULL) {
		if (strlen(path) + strlen(name) + 2 > PATH_MAX)
			return (-1);
		(void) strcat(strcat(strcpy(full_path, path), "/"), name);
		name = full_path;
	}
	anc_name = audit_cron_make_anc_name(name);
	r = unlink(anc_name);
	free(anc_name);
	return (r);
}
