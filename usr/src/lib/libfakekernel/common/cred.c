/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 RackTop Systems.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/thread.h>
#include <sys/cred.h>
#include <sys/sid.h>
#include <strings.h>

/*
 * This library does not implement real credentials. All contexts
 * use an opaque cred_t object, and all activity happens in the
 * context of the user who runs the program.
 */

extern struct zone zone0;

struct cred {
	uid_t		cr_uid;
	ksid_t		*cr_ksid;
	uint32_t	pad[100];
};

cred_t cred0;
cred_t *kcred = &cred0;

/*
 * Note that fksmbd uses CRED() for SMB user logons, but uses
 * zone_kcred() for operations done internally by the server.
 * Let CRED() (_curcred()) return &cred1, so it's different from
 * kcred, otherwise tests like: (cred == kcred) are always true.
 * Also, only cred1 will have a ksid (not kcred).
 * The UID and SID are both "nobody".
 */
ksiddomain_t ksdom1 = {1, 5, "S-1-0", {0}};
ksid_t ksid1 = { 60001, 0, 0, &ksdom1};
cred_t cred1 = { 60001, &ksid1 };

cred_t *
_curcred(void)
{
	/* Thread-specific data? */
	return (&cred1);
}

/*ARGSUSED*/
void
crfree(cred_t *cr)
{
}

/*ARGSUSED*/
void
crhold(cred_t *cr)
{
}

/*ARGSUSED*/
uid_t
crgetuid(const cred_t *cr)
{
	return (cr->cr_uid);
}

/*ARGSUSED*/
uid_t
crgetruid(const cred_t *cr)
{
	return (cr->cr_uid);
}

/*ARGSUSED*/
uid_t
crgetgid(const cred_t *cr)
{
	return (0);
}

/*ARGSUSED*/
int
crgetngroups(const cred_t *cr)
{
	return (0);
}

/*ARGSUSED*/
const gid_t *
crgetgroups(const cred_t *cr)
{
	return (NULL);
}

/*ARGSUSED*/
zoneid_t
crgetzoneid(const cred_t *cr)
{
	return (GLOBAL_ZONEID);
}

/*ARGSUSED*/
struct zone *
crgetzone(const cred_t *cr)
{
	return (&zone0);
}

cred_t *
zone_kcred(void)
{
	return (kcred);
}

/*ARGSUSED*/
ksid_t *
crgetsid(const cred_t *cr, int i)
{
	return (cr->cr_ksid);
}

cred_t *
ddi_get_cred(void)
{
	return (_curcred());
}
