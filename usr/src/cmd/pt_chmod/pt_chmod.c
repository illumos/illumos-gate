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
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <grp.h>
#include <stdlib.h>
#include <stropts.h>
#include <sys/acl.h>
#include <libdevinfo.h>

#define	DEFAULT_TTY_GROUP	"tty"

/*
 * 1) change the owner and mode of the pseudo terminal slave device.
 * 2) (re)create nodes and devlinks for pseduo terminal slave device.
 */
int
main(int argc, char **argv)
{
	int	fd;
	gid_t	gid;
	char	*tty;
	di_devlink_handle_t pp;

	struct	group	*gr_name_ptr;

	if (argc > 2)
		return (1);

	if ((gr_name_ptr = getgrnam(DEFAULT_TTY_GROUP)) != NULL)
		gid = gr_name_ptr->gr_gid;
	else
		gid = getgid();

	/* create pts minor device nodes and symlinks */
	if (argc == 1) {
		pp = di_devlink_init("pts", DI_MAKE_LINK);
		if (pp != NULL) {
			(void) di_devlink_fini(&pp);
			return (0);
		}
		return (1);
	}

	fd = atoi(argv[1]);

	tty = ptsname(fd);

	if (tty == NULL)
		return (1);

	/*
	 * Detach all STREAMs.
	 * We need to continue to try this until we have succeeded
	 * in calling chown on the underlying node.  From that point
	 * onwards, no-one but root can fattach() as fattach() requires
	 * ownership of the node.
	 */
	do {
		if (chown(tty, 0, 0) != 0)
			exit(1);
	} while (fdetach(tty) == 0);

	/* Remove ACLs */
	if (acl(tty, GETACLCNT, 0, NULL) > MIN_ACL_ENTRIES) {
		aclent_t acls[3];

		acls[0].a_type = USER_OBJ;
		acls[0].a_id = 0;
		acls[0].a_perm = 6;

		acls[1].a_type = GROUP_OBJ;
		acls[1].a_id = gid;
		acls[1].a_perm = 2;

		acls[2].a_type = OTHER_OBJ;
		acls[2].a_id = 0;
		acls[2].a_perm = 0;

		(void) acl(tty, SETACL, 3, acls);
	}

	if (chown(tty, getuid(), gid))
		return (1);

	if (chmod(tty, 00620))
		return (1);

	return (0);
}
