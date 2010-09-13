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
 *
 */

#include <sys/types.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <bsm/audit_private.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <unistd.h>
#include <synch.h>
#include <generic.h>

#ifdef C2_DEBUG2
#define	dprintf(x) { (void) printf x; }
#else
#define	dprintf(x)
#endif

static mutex_t audit_mountd_lock = DEFAULTMUTEX;
static int cannotaudit = 0;

/*
 * This setup call is made only once at the start of mountd.
 * The call sets the auditing state off if appropriate, and is
 * made in single threaded code, hence no locking is required.
 */
void
audit_mountd_setup()
{
	dprintf(("audit_mountd_setup()\n"));


	if (cannot_audit(0))
		cannotaudit = 1;
}

void
audit_mountd_mount(clname, path, sorf)
char	*clname;	/* client name */
char	*path;		/* mount path */
int	sorf;		/* flag for success or failure */
{
	uint32_t buf[4], type;
	dprintf(("audit_mountd_mount()\n"));

	if (cannotaudit)
		return;

	(void) mutex_lock(&audit_mountd_lock);

	(void) aug_save_namask();

	(void) aug_save_me();
	aug_save_event(AUE_mountd_mount);
	aug_save_sorf(sorf);
	aug_save_text(clname);
	aug_save_path(path);
	(void) aug_get_machine(clname, buf, &type);
	aug_save_tid_ex(aug_get_port(), buf, type);
	(void) aug_audit();
	(void) mutex_unlock(&audit_mountd_lock);
}

void
audit_mountd_umount(clname, path)
char	*clname;	/* client name */
char	*path;		/* mount path */
{
	uint32_t buf[4], type;

	dprintf(("audit_mountd_mount()\n"));

	if (cannotaudit)
		return;

	(void) mutex_lock(&audit_mountd_lock);

	(void) aug_save_namask();

	(void) aug_save_me();
	aug_save_event(AUE_mountd_umount);
	aug_save_sorf(0);
	aug_save_text(clname);
	aug_save_path(path);
	(void) aug_get_machine(clname, buf, &type);
	aug_save_tid_ex(aug_get_port(), buf, type);
	(void) aug_audit();
	(void) mutex_unlock(&audit_mountd_lock);
}
