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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is the smbfs/lsacl command.
 * (just for testing - not installed)
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/acl.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <netsmb/smb_lib.h>
#include <netsmb/smbfs_acl.h>

char *progname;

extern void acl_printacl(acl_t *, int, int);


void
usage(void)
{
	fprintf(stderr, "usage: %s file\n", progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	struct acl_info *acl;
	uid_t uid;
	gid_t gid;
	int error, fd;
	i_ntsd_t *sd;

	progname = argv[0];

	if (argc < 2)
		usage();

	fd = open(argv[1], O_RDONLY, 0);
	if (fd < 0) {
		perror(argv[1]);
		exit(1);
	}

	/* First, get the raw NT SD. */
	error = smbfs_acl_getsd(fd, 7, &sd);
	if (error) {
		fprintf(stderr, "getsd: %s\n",
		    smb_strerror(error));
		exit(1);
	}

	/*
	 * Print it first in Windows form.  This way,
	 * if any of the conversion has problems,
	 * one can try mapping each SID by hand, i.e.:
	 *    idmap show sid:S-1-xxx-yyy-zzz
	 */
	printf("CIFS security data:\n");
	smbfs_acl_print_sd(stdout, sd);
	printf("\n");

	/*
	 * Get it again as a ZFS-style ACL (ACE_T)
	 */
	error = smbfs_acl_get(fd, &acl, &uid, &gid);
	if (error) {
		fprintf(stderr, "getacl: %s\n",
		    smb_strerror(error));
		exit(1);
	}
	printf("Solaris security data:\n");
	if (uid == (uid_t)-1)
		printf("owner: -1\n");
	else
		printf("owner: %u\n", uid);
	if (gid == (gid_t)-1)
		printf("group: -1\n");
	else
		printf("group: %u\n", gid);
	acl_printacl(acl, 80, 0);
	printf("\n");

	return (0);
}
