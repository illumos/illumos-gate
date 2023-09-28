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

/*
 * This is the smbfs/lsacl command.
 * (just for testing - not installed)
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <sys/acl_impl.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <aclutils.h>

#include <netsmb/smbfs_acl.h>

extern acl_t *acl_alloc(acl_type_t);

char *progname;
int Vflag;

uint32_t selector =  DACL_SECURITY_INFORMATION |
	OWNER_SECURITY_INFORMATION |
	GROUP_SECURITY_INFORMATION;

void lsacl(char *);

void
usage(void)
{
	fprintf(stderr, "Usage: %s [-v] file ...\n", progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	int c;

	progname = argv[0];

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			Vflag++;
			break;

		default:
			fprintf(stderr, "%s: bad option: %c\n",
			    progname, c);
			usage();
			break;
		}
	}

	if (optind == argc)
		usage();
	for (; optind < argc; optind++)
		lsacl(argv[optind]);

	return (0);
}

void
lsacl(char *file)
{
	struct i_ntsd *sd;
	acl_t *acl;
	uid_t uid;
	gid_t gid;
	int error, fd;

	fd = open(file, O_RDONLY, 0);
	if (fd < 0) {
		perror(file);
		exit(1);
	}

	/* First, get the SD in internal form. */
	error = smbfs_acl_getsd(fd, selector, &sd);
	(void) close(fd);

	if (error) {
		fprintf(stderr, "%s: getsd, %s\n",
		    progname, strerror(error));
		exit(1);
	}

	if (Vflag) {
		/*
		 * Print it first in Windows form.  This way,
		 * if any of the conversion has problems,
		 * one can try mapping each SID by hand, i.e.:
		 *    idmap show sid:S-1-xxx-yyy-zzz
		 */
		printf("CIFS security data:\n");
		smbfs_acl_print_sd(stdout, sd);
		printf("\n");
	}

	/*
	 * Convert the internal SD to a ZFS ACL.
	 */
	acl = acl_alloc(ACE_T);
	error = smbfs_acl_sd2zfs(sd, acl, &uid, &gid);
	if (error) {
		fprintf(stderr, "%s: sd2zfs, %s\n",
		    progname, strerror(error));
		exit(1);
	}
	smbfs_acl_free_sd(sd);

	/*
	 * Print it as a ZFS-style ACL (ACE_T)
	 */
	printf("Solaris security data:\n");
	if (uid == (uid_t)-1)
		printf("owner: -1\n");
	else
		printf("owner: %u\n", uid);
	if (gid == (gid_t)-1)
		printf("group: -1\n");
	else
		printf("group: %u\n", gid);
	acl_printacl(acl, 80, 1);
	printf("\n");

	acl_free(acl);
}
