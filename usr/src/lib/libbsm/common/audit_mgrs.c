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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include "generic.h"
#include <netinet/in.h>
#include <netdb.h>
#include <pwd.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <syslog.h>

#ifdef C2_DEBUG
#define	dprintf(x) { printf x; }
#else
#define	dprintf(x)
#endif

/* constant for user account enable/disable state change */

#define	AC_STATE_UNCHANGED -99

/* Constants used for password type interpretation in BSM auditing */

#define	PWD_NONE_CODE		0
#define	PWD_CLEARED_CODE	1
#define	PWD_LOCKED_CODE		2
#define	PWD_NORMAL_CODE		3
#define	PWD_UNCHANGED_CODE	4

#define	PWD_NONE_TEXT		"No password active"
#define	PWD_CLEARED_TEXT	"Cleared until first login"
#define	PWD_LOCKED_TEXT		"Account is locked"
#define	PWD_NORMAL_TEXT		"Normal password active"

static int  save_afunc();

static char *saved_uid_p;
static char *saved_username_p;
static char *saved_gid_p;
static char *saved_groups_p;
static char *saved_shell_p;
static char *saved_min_p;
static char *saved_max_p;
static char *saved_inactive_p;
static char *saved_expire_p;
static char *saved_warn_p;
static char *saved_home_path_p;
static char *saved_home_server_p;
static char *saved_home_mode_p;
static int   saved_passwd_type_code;

#define	String_max 511
static char		adm_name[String_max + 1];
static uid_t		adm_uid;
static uid_t		adm_euid;
static char		adm_host[String_max + 1];
static uint32_t		adm_session_id;

static int taudit_user_dde_event_setup(au_event_t, char *);
static int audit_user_generic(int);
static int audit_users_modified_by_group_generic(char *, char *, int);
static void admin_auth_init(char *, char *);
static void admin_record(int, char *, au_event_t);
static  int admin_selected(int, au_event_t);

/*
 * Save user information to audit log as text tokens
 */

static int
save_afunc(int ad)
{
	char *local_passwd_type_string;

	/* Work out the password type display string */

	switch (saved_passwd_type_code) {
	case PWD_CLEARED_CODE:
		local_passwd_type_string = PWD_CLEARED_TEXT;
		break;
	case PWD_LOCKED_CODE:
		local_passwd_type_string = PWD_LOCKED_TEXT;
		break;
	case PWD_NORMAL_CODE:
		local_passwd_type_string = PWD_NORMAL_TEXT;
		break;
	case PWD_NONE_CODE:
		local_passwd_type_string = PWD_NONE_TEXT;
		break;
	case PWD_UNCHANGED_CODE:
		local_passwd_type_string = NULL;
		break;
	default:
		/* Never reached, but if it is report as if none */
		/* to flag a potential hole in security */
		local_passwd_type_string = PWD_NONE_TEXT;
		break;
	}

	if (saved_uid_p != NULL) {
		(void) au_write(ad, au_to_text(saved_uid_p));
	}
	if (saved_username_p != NULL) {
		(void) au_write(ad, au_to_text(saved_username_p));
	}
	if (saved_gid_p != NULL) {
		(void) au_write(ad, au_to_text(saved_gid_p));
	}
	if (saved_groups_p != NULL) {
		(void) au_write(ad, au_to_text(saved_groups_p));
	}
	if (saved_shell_p != NULL) {
		(void) au_write(ad, au_to_text(saved_shell_p));
	}
	if (local_passwd_type_string != NULL) {
		(void) au_write(ad, au_to_text(local_passwd_type_string));
	}
	if (saved_min_p != NULL) {
		(void) au_write(ad, au_to_text(saved_min_p));
	}
	if (saved_max_p != NULL) {
		(void) au_write(ad, au_to_text(saved_max_p));
	}
	if (saved_inactive_p != NULL) {
		(void) au_write(ad, au_to_text(saved_inactive_p));
	}
	if (saved_expire_p != NULL) {
		(void) au_write(ad, au_to_text(saved_expire_p));
	}
	if (saved_warn_p != NULL) {
		(void) au_write(ad, au_to_text(saved_warn_p));
	}
	if (saved_home_path_p != NULL) {
		(void) au_write(ad, au_to_text(saved_home_path_p));
	}
	if (saved_home_server_p != NULL) {
		(void) au_write(ad, au_to_text(saved_home_server_p));
	}
	if (saved_home_mode_p != NULL) {
		(void) au_write(ad, au_to_text(saved_home_mode_p));
	}

	return (0);
}

/*
 * Set up data for audit of user Delete/Disable or Enable Event
 */

int
audit_user_dde_event_setup(char *uid_p)
{
	return (taudit_user_dde_event_setup(AUE_delete_user, uid_p));
}

static int
taudit_user_dde_event_setup(au_event_t id, char *uid_p)
{
	dprintf(("taudit_user_dde_event_setup()\n"));

	if (cannot_audit(0)) {
		return (0);
	}

	(void) aug_init();

	aug_save_event(id);
	aug_save_text(uid_p);

	(void) aug_save_me();

	return (0);
}

/*
 * Audit successful or failed user create
 */

int
audit_user_create_event(char *uid_p,
				char *username_p,
				char *gid_p,
				char *groups_p,
				char *shell_p,
				char *min_p,
				char *max_p,
				char *inactive_p,
				char *expire_p,
				char *warn_p,
				char *home_path_p,
				char *home_server_p,
				char *home_mode_p,
				int  passwd_type_code,
				int  ac_disabled,
				int  status)

{
	dprintf(("audit_user_create_event()\n"));

	if (cannot_audit(0)) {
		return (0);
	}

	saved_uid_p 		= uid_p;
	saved_username_p 	= username_p;
	saved_gid_p 		= gid_p;
	saved_groups_p 		= groups_p;
	saved_shell_p 		= shell_p;
	saved_min_p 		= min_p;
	saved_max_p 		= max_p;
	saved_inactive_p 	= inactive_p;
	saved_expire_p 		= expire_p;
	saved_warn_p 		= warn_p;
	saved_home_path_p 	= home_path_p;
	saved_home_server_p 	= home_server_p;
	saved_home_mode_p 	= home_mode_p;
	saved_passwd_type_code	= passwd_type_code;

	(void) aug_init();

	aug_save_event(AUE_create_user);

	(void) aug_save_me();

	aug_save_afunc(save_afunc);

	if (status != 0) {
		(void) audit_user_generic(-1);
	} else {
		(void) audit_user_generic(0);
	}

	if (ac_disabled != AC_STATE_UNCHANGED) {
		if (ac_disabled) {
			(void) taudit_user_dde_event_setup(AUE_disable_user,
			    saved_uid_p);
		} else {
			(void) taudit_user_dde_event_setup(AUE_enable_user,
			    saved_uid_p);
		}

		if (status != 0) {
			(void) audit_user_generic(-1);
		} else {
			(void) audit_user_generic(0);
		}
	}

	return (0);
}

/*
 * Audit user modification
 */

int
audit_user_modify_event(char *uid_p,
				char *username_p,
				char *gid_p,
				char *groups_p,
				char *shell_p,
				char *min_p,
				char *max_p,
				char *inactive_p,
				char *expire_p,
				char *warn_p,
				char *home_path_p,
				char *home_server_p,
				int  passwd_type_code,
				int  ac_disabled,
				int  status)

{
	dprintf(("audit_user_modify_event()\n"));

	if (cannot_audit(0)) {
		return (0);
	}

	saved_uid_p 		= uid_p;
	saved_username_p 	= username_p;
	saved_gid_p 		= gid_p;
	saved_groups_p 		= groups_p;
	saved_shell_p 		= shell_p;
	saved_min_p 		= min_p;
	saved_max_p 		= max_p;
	saved_inactive_p 	= inactive_p;
	saved_expire_p 		= expire_p;
	saved_warn_p 		= warn_p;
	saved_home_path_p 	= home_path_p;
	saved_home_server_p 	= home_server_p;
	saved_home_mode_p 	= NULL;
	saved_passwd_type_code	= passwd_type_code;

	(void) aug_init();

	aug_save_event(AUE_modify_user);

	(void) aug_save_me();

	aug_save_afunc(save_afunc);

	if (status != 0) {
		(void) audit_user_generic(-1);
	} else {
		(void) audit_user_generic(0);
	}

	if (ac_disabled != AC_STATE_UNCHANGED) {
		if (ac_disabled) {
			(void) taudit_user_dde_event_setup(AUE_disable_user,
			    saved_uid_p);
		} else {
			(void) taudit_user_dde_event_setup(AUE_enable_user,
			    saved_uid_p);
		}

		if (status != 0) {
			(void) audit_user_generic(-1);
		} else {
			(void) audit_user_generic(0);
		}
	}

	return (0);
}

int
audit_delete_user_fail()
{
	return (audit_user_generic(-1));
}

int
audit_delete_user_success()
{
	return (audit_user_generic(0));
}

static int
audit_user_generic(int sorf)
{
	dprintf(("audit_user_generic(%d)\n", sorf));

	if (cannot_audit(0)) {
		return (0);
	}

	aug_save_sorf(sorf);
	(void) aug_audit();

	return (0);
}

int
audit_users_modified_by_group_success(char *unique_members, char *ID)
{
	return (audit_users_modified_by_group_generic(unique_members, ID, 0));
}

int
audit_users_modified_by_group_fail(char *members, char *ID)
{
	return (audit_users_modified_by_group_generic(members, ID, -1));
}

static int
audit_users_modified_by_group_generic(char *member_list, char *ID, int sorf)
{
	char *member_start;
	char *member_finish;
	int  member_len;
	char *member;

	member_start = member_list;
	member_finish = member_list;

	while (member_finish != NULL) {
		member_finish = strchr(member_start, ',');
		if (member_finish == NULL) {
			(void) audit_user_modify_event(NULL,
						member_start,
						ID,
						NULL,
						NULL,
						NULL,
						NULL,
						NULL,
						NULL,
						NULL,
						NULL,
						NULL,
						PWD_UNCHANGED_CODE,
						AC_STATE_UNCHANGED,
						sorf);
		}
		else
		{
			member_len = member_finish - member_start;
			member = (char *)malloc(member_len + 1);

			if (member != NULL) {
				(void) strncpy(member, member_start,
				    member_len);
				member[member_len] = '\0';

				(void) audit_user_modify_event(NULL,
							member,
							ID,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL,
							PWD_UNCHANGED_CODE,
							AC_STATE_UNCHANGED,
							sorf);

				free(member);
			}

			member_start = member_finish + 1;
		}

	}
	return (0);
}

/*
 * Record result of administrator authentication
 */

int
audit_admin_auth_fail(char *user_name, char *host, int fail_status)
{
	if (cannot_audit(0)) {
		return (0);
	}
	adm_session_id = 0;

	admin_auth_init(user_name, host);

	if (fail_status == -1) {
		admin_record(1, dgettext(bsm_dom, "invalid user name"),
				AUE_admin_authenticate);
	} else {
		admin_record(2, dgettext(bsm_dom, "invalid password"),
				AUE_admin_authenticate);
	}
	return (0);
}

int
audit_admin_auth_success(char *user_name, char *host, uint32_t session_id)
{
	if (cannot_audit(0)) {
		return (0);
	}
	admin_auth_init(user_name, host);

	adm_session_id = session_id;

	admin_record(0, dgettext(bsm_dom, "successful authentication"),
				AUE_admin_authenticate);
	return (0);
}

static
void
admin_auth_init(char *user_name, char *host)
{
	struct passwd *pwd;

	adm_uid = getuid();

	(void) strncpy(adm_name, user_name, sizeof (adm_name) - 1);

	pwd = getpwnam(user_name);
	if (pwd == NULL) {
		adm_name[0] = '\0';
		adm_euid = -1;
	} else {
		adm_name[String_max] = '\0';
		adm_euid = pwd->pw_uid;
	}

	(void) strncpy(adm_host, host, sizeof (adm_host) - 1);
	adm_host[String_max] = '\0';
}

static void
admin_record(int type, char *string, au_event_t event)
{
	int		ad, rc;
	pid_t		pid;
	au_tid_addr_t	tid;

	rc = (type == 0) ? 0 : -1;
	if (!admin_selected(rc, event))
		return;

	pid = getpid();

	(void) aug_get_machine(adm_host, &(tid.at_addr[0]), &(tid.at_type));
	tid.at_port = 0;	/* not known */

	ad = au_open();

	/*
	 * to be consistent with admin_login, use uid, not gid...
	 */
	(void) au_write(ad, au_to_subject_ex(adm_euid, adm_uid,
				adm_uid, adm_uid, adm_uid,
				pid, adm_session_id, &tid));
	(void) au_write(ad, au_to_text(string));

	/*
	 * rc and type are reversed from how login works, but
	 * the output from praudit is correct for this code
	 * and wrong for login.
	 */
#ifdef _LP64
	(void) au_write(ad, au_to_return64((int64_t)rc, type));
#else
	(void) au_write(ad, au_to_return32((int32_t)rc, type));
#endif

	rc = au_close(ad, AU_TO_WRITE, event);
	if (rc < 0) {
		openlog("BSM-adminsuite", LOG_PID | LOG_CONS, LOG_AUTH);
		(void) setlogmask(LOG_UPTO(LOG_ALERT));
		syslog(LOG_ALERT, "au_close call failed: %m");
		closelog();
	}
}

static
int
admin_selected(int sf, au_event_t event)
{
	int	rc, sorf;
	char	naflags[String_max + 1];
	struct au_mask mask;

	mask.am_success = mask.am_failure = 0;
	if (adm_euid < 0) {		/* get non-attrib flags */
		rc = getacna(naflags, sizeof (naflags) - 1);
		if (rc) {
			return (rc);	/* don't audit if error */
		}
		rc = getauditflagsbin(naflags, &mask);
	} else {
		rc = au_user_mask(adm_name, &mask);
	}
	if (rc != 0) {
		return (0);		/* audit if error */
	}

	if (sf == 0) {
		sorf = AU_PRS_SUCCESS;
	} else {
		sorf = AU_PRS_FAILURE;
	}
	rc = au_preselect(event, &mask, sorf, AU_PRS_REREAD);

	return (rc);
}
