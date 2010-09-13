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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/errno.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <stdlib.h>
#include <tsol/label.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_record.h>

#define	AUC_NEVER	-2	/* audit module not loaded */

/* Private Functions */
static int selected(au_event_t, au_mask_t *, int);

int aug_selected();
int aug_na_selected();

/* Global Variables */
static au_id_t		aug_auid;	/* auid of user writing audit record */
static uid_t		aug_uid;	/* uid of user writing audit record */
static uid_t		aug_euid;	/* euid of user writing audit record */
static gid_t		aug_gid;	/* gid of user writing audit record */
static gid_t		aug_egid;	/* euid of user writing audit record */
static pid_t		aug_pid;	/* pid of user writing audit record */
static au_tid_addr_t	aug_tid;	/* tid of user writing audit record */
static int		aug_na;		/* 0 if event is attributable */
static au_mask_t	aug_namask;	/* not attributable flags */
static au_event_t	aug_event;	/* id of event being audited */
static int 		aug_sorf;	/* success or failure of aug_event */
static char		*aug_text;	/* misc text to be written to trail */
static char		*aug_text1;	/* misc text to be written to trail */
static char		*aug_text2;	/* misc text to be written to trail */
static au_asid_t	aug_asid;	/* asid of process writing record */
static int 		(*aug_afunc)();	/* write additional tokens if needed */
static char		*aug_path;	/* path token */
static uint32_t		aug_policy;	/* kernel audit policy */

/*
 * cannot_audit:
 *	Return 1 if audit module not loaded.
 *	Return 0 otherwise.
 *
 * The argument, force, should be set to 1 for long-lived processes
 * like some daemons.  Force should be set to 0 for most programs.
 */
int
cannot_audit(force)
	int force;
{
	static int auc = AUC_UNSET;
	int cond = 0;

	if (auc == AUC_UNSET || force) {
		if (auditon(A_GETCOND, (caddr_t)&cond, sizeof (cond))) {
			auc = AUC_NEVER;
		} else {
			auc = cond;
		}
	}
	return (auc == AUC_NEVER);
}

/*
 * aug_init():
 *	Initialize global variables.
 */
void
aug_init()
{
	aug_auid = (uid_t)-1;
	aug_uid = (uid_t)-1;
	aug_euid = (uid_t)-1;
	aug_gid = (gid_t)-1;
	aug_egid = (gid_t)-1;
	aug_pid = -1;
	aug_tid.at_port = 0;
	aug_tid.at_type = AU_IPv4;
	aug_tid.at_addr[0] = 0;
	aug_tid.at_addr[1] = 0;
	aug_tid.at_addr[2] = 0;
	aug_tid.at_addr[3] = 0;
	aug_namask.am_success = AU_MASK_ALL;
	aug_namask.am_failure = AU_MASK_ALL;
	aug_event = 0;
	aug_sorf = -2;
	aug_text = NULL;
	aug_text1 = NULL;
	aug_text2 = NULL;
	aug_na = 0;
	aug_asid = (au_asid_t)(-1);
	aug_afunc = NULL;
	aug_path = NULL;
}

/*
 * aug_get_port:
 *	Return the raw device number of the port to which the
 *	current process is attached (assumed to be attached
 *	through file descriptor 0) or 0 if can't stat the port.
 */
dev_t
aug_get_port()
{
	int	rc;
	char	*ttyn;
	struct stat sb;

	ttyn = ttyname(0);
	if (ttyn == 0 || *ttyn == '\0') {
		return (0);
	}

	rc = stat(ttyn, &sb);
	if (rc < 0) {
		perror("stat");
		return (0);
	}

	return ((dev_t)sb.st_rdev);
}

/*
 * aug_get_machine:
 *	Return internet address of host hostname,
 *	or 0 if can't do lookup.
 */

int
aug_get_machine(const char *hostname, uint32_t *buf, uint32_t *type)
{
	struct addrinfo *ai;
	int err;
	void *p;

	err = getaddrinfo(hostname, NULL, NULL, &ai);
	if (err != 0)
		return (0);

	switch (ai->ai_family) {
	case AF_INET:
		/* LINTED */
		p = &((struct sockaddr_in *)ai->ai_addr)->sin_addr,
		    (void) memcpy(buf, p,
		    sizeof (((struct sockaddr_in *)0)->sin_addr));
		*type = AU_IPv4;
		break;
	case AF_INET6:
		/* LINTED */
		p = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
		    (void) memcpy(buf, p,
		    sizeof (((struct sockaddr_in6 *)0)->sin6_addr));
		*type = AU_IPv6;
		break;
	default:
		return (0);
	}

	freeaddrinfo(ai);

	return (1);
}

void
aug_save_auid(au_id_t id)
{
	aug_auid = id;
}

void
aug_save_uid(uid_t id)
{
	aug_uid = id;
}

void
aug_save_euid(uid_t id)
{
	aug_euid = id;
}

void
aug_save_gid(gid_t id)
{
	aug_gid = id;
}

void
aug_save_egid(gid_t id)
{
	aug_egid = id;
}

void
aug_save_pid(pid_t id)
{
	aug_pid = id;
}

void
aug_save_asid(au_asid_t id)
{
	aug_asid = id;
}

void
aug_save_afunc(int (*afunc)())
{
	aug_afunc = afunc;
}

void
aug_save_tid(dev_t port, int machine)
{
	aug_tid.at_port = port;
	aug_tid.at_type = AU_IPv4;
	aug_tid.at_addr[0] = machine;
}

void
aug_save_tid_ex(dev_t port, uint32_t *machine, uint32_t type)
{
	int i;

	aug_tid.at_port = port;
	if ((type != AU_IPv4) && (type != AU_IPv6))
		type = AU_IPv4;

	aug_tid.at_type = type;
	for (i = 0; i < (type/4); i++)
		aug_tid.at_addr[i] = machine[i];
}

int
aug_save_me(void)
{
	auditinfo_addr_t ai;

	if (getaudit_addr(&ai, sizeof (ai)))
		return (-1);

	aug_save_auid(ai.ai_auid);
	aug_save_euid(geteuid());
	aug_save_egid(getegid());
	aug_save_uid(getuid());
	aug_save_gid(getgid());
	aug_save_pid(getpid());
	aug_save_asid(ai.ai_asid);
	aug_save_tid_ex(ai.ai_termid.at_port,
	    ai.ai_termid.at_addr,
	    ai.ai_termid.at_type);
	return (0);
}

/*
 * aug_save_namask():
 *	Save the namask using the naflags entry in the audit_control file.
 *	Return 0 if successful.
 *	Return -1, and don't change the namask, if failed.
 *	Side Effect: Sets aug_na to -1 if error, 1 if successful.
 */
int
aug_save_namask()
{
	au_mask_t mask;

	aug_na = -1;

	/*
	 * get non-attributable system event mask from kernel.
	 */
	if (auditon(A_GETKMASK, (caddr_t)&mask, sizeof (mask)) != 0) {
		return (-1);
	}

	aug_namask.am_success = mask.am_success;
	aug_namask.am_failure = mask.am_failure;
	aug_na = 1;
	return (0);
}

void
aug_save_event(au_event_t id)
{
	aug_event = id;
}

void
aug_save_sorf(int sorf)
{
	aug_sorf = sorf;
}

void
aug_save_text(char *s)
{
	if (aug_text != NULL)
		free(aug_text);
	if (s == NULL)
		aug_text = NULL;
	else
		aug_text = strdup(s);
}

void
aug_save_text1(char *s)
{
	if (aug_text1 != NULL)
		free(aug_text1);
	if (s == NULL)
		aug_text1 = NULL;
	else
		aug_text1 = strdup(s);
}

void
aug_save_text2(char *s)
{
	if (aug_text2 != NULL)
		free(aug_text2);
	if (s == NULL)
		aug_text2 = NULL;
	else
		aug_text2 = strdup(s);
}

void
aug_save_na(int flag)
{
	aug_na = flag;
}

void
aug_save_path(char *s)
{
	if (aug_path != NULL)
		free(aug_path);
	if (s == NULL)
		aug_path = NULL;
	aug_path = strdup(s);
}

int
aug_save_policy()
{
	uint32_t policy;

	if (auditon(A_GETPOLICY, (caddr_t)&policy, sizeof (policy))) {
		return (-1);
	}
	aug_policy = policy;
	return (0);
}

/*
 * aug_audit:
 *	Cut and audit record if it is selected.
 *	Return 0, if successfully written.
 *	Return 0, if not written, and not expected to write.
 *	Return -1, if not written because of unexpected error.
 */
int
aug_audit(void)
{
	int ad;

	if (cannot_audit(0)) {
		return (0);
	}

	if (aug_na) {
		if (!aug_na_selected()) {
			return (0);
		}
	} else if (!aug_selected()) {
		return (0);
	}

	if ((ad = au_open()) == -1) {
		return (-1);
	}

	(void) au_write(ad, au_to_subject_ex(aug_auid, aug_euid, aug_egid,
	    aug_uid, aug_gid, aug_pid, aug_asid, &aug_tid));
	if (is_system_labeled())
		(void) au_write(ad, au_to_mylabel());
	if (aug_policy & AUDIT_GROUP) {
		int ng;
		int maxgrp = getgroups(0, NULL);
		gid_t *grplst = alloca(maxgrp * sizeof (gid_t));

		if ((ng = getgroups(maxgrp, grplst)) > 0) {
			(void) au_write(ad, au_to_newgroups(ng, grplst));
		}
	}
	if (aug_text != NULL) {
		(void) au_write(ad, au_to_text(aug_text));
	}
	if (aug_text1 != NULL) {
		(void) au_write(ad, au_to_text(aug_text1));
	}
	if (aug_text2 != NULL) {
		(void) au_write(ad, au_to_text(aug_text2));
	}
	if (aug_path != NULL) {
		(void) au_write(ad, au_to_path(aug_path));
	}
	if (aug_afunc != NULL) {
		(*aug_afunc)(ad);
	}
#ifdef _LP64
	(void) au_write(ad, au_to_return64((aug_sorf == 0) ? 0 : -1,
	    (int64_t)aug_sorf));
#else
	(void) au_write(ad, au_to_return32((aug_sorf == 0) ? 0 : -1,
	    (int32_t)aug_sorf));
#endif
	if (au_close(ad, 1, aug_event) < 0) {
		(void) au_close(ad, 0, 0);
		return (-1);
	}

	return (0);
}

int
aug_na_selected()
{
	if (aug_na == -1) {
		return (-1);
	}

	return (selected(aug_event, &aug_namask, aug_sorf));
}

int
aug_selected()
{
	auditinfo_addr_t mask;

	if (aug_uid > MAXEPHUID) {
		(void) aug_save_namask();
		return (aug_na_selected());
	}
	if (getaudit_addr(&mask, sizeof (mask))) {
		return (-1);
	}

	return (selected(aug_event, &mask.ai_mask, aug_sorf));
}

static int
selected(au_event_t e, au_mask_t *m, int sorf)
{
	int prs_sorf;

	if (sorf == 0) {
		prs_sorf = AU_PRS_SUCCESS;
	} else if (sorf == -1) {
		prs_sorf = AU_PRS_FAILURE;
	} else {
		prs_sorf = AU_PRS_BOTH;
	}

	return (au_preselect(e, m, prs_sorf, AU_PRS_REREAD));
}
