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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * This is the smbfs/chacl command.
 * (just for testing - not installed)
 *
 * Works like chmod(1), but only supporting A=... forms.
 * i.e. chacl A=everyone@:full_set:fd:allow /mnt/foo
 *
 * Some more test cases:
 *	/usr/lib/fs/smbfs/chacl -v
 *	A=user:2147483649:rwxpdDaARWcCos::allow,
 *	user:2147483653:raRcs::allow,
 *	everyone@:raRcs::allow
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

char *progname;
int Vflag;

void chacl(char *, uint32_t, uid_t, gid_t, acl_t *);

static const char Usage[] =
	"Usage: %s [-v] [-u UID] [-g GID] A=ACL... file ...\n"
	"\twhere A=ACL is like chmod(1)\n";

void
usage(void)
{
	fprintf(stderr, Usage, progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;
	acl_t *acl = NULL;
	char *acl_arg;
	ulong_t tl;
	int c, error;
	uint32_t selector;

	progname = argv[0];

	while ((c = getopt(argc, argv, "vu:g:")) != -1) {
		switch (c) {
		case 'v':
			Vflag++;
			break;
		case 'u':
			tl = strtoul(optarg, NULL, 10);
			if (tl == 0)
				goto badopt;
			uid = (uid_t)tl;
			break;
		case 'g':
			tl = strtoul(optarg, NULL, 10);
			if (tl == 0)
				goto badopt;
			gid = (gid_t)tl;
			break;
		case ':':
			fprintf(stderr, "%s: option %c requires arg\n",
			    progname, c);
			usage();
			break;

		badopt:
		default:
			fprintf(stderr, "%s: bad option: %c\n",
			    progname, c);
			usage();
			break;
		}
	}

	if (optind + 1 > argc)
		usage();
	acl_arg = argv[optind++];

	/*
	 * Ask libsec to parse the ACL arg.
	 */
	if (strncmp(acl_arg, "A=", 2) != 0)
		usage();
	error = acl_parse(acl_arg + 2, &acl);
	if (error) {
		fprintf(stderr, "%s: can not parse ACL: %s\n",
		    progname, acl_arg);
		exit(1);
	}
	if (acl->acl_type != ACE_T) {
		fprintf(stderr, "%s: ACL not ACE_T type: %s\n",
		    progname, acl_arg);
		exit(1);
	}

	/*
	 * Which parts of the SD are being modified?
	 */
	selector = DACL_SECURITY_INFORMATION;

	if (uid != (uid_t)-1)
		selector |= OWNER_SECURITY_INFORMATION;
	if (gid != (gid_t)-1)
		selector |= GROUP_SECURITY_INFORMATION;

	if (optind == argc)
		usage();
	for (; optind < argc; optind++)
		chacl(argv[optind], selector, uid, gid, acl);

	acl_free(acl);
	return (0);
}

void
chacl(char *file, uint32_t selector, uid_t uid, gid_t gid, acl_t *acl)
{
	struct stat st;
	struct i_ntsd *sd = NULL;
	int error, fd;

	/*
	 * OK, try setting the ACL (via ioctl).  Open
	 * read-only because we're NOT writing data.
	 * The driver will re-open with the necessary
	 * access rights to set the ACL.
	 */
	fd = open(file, O_RDONLY, 0);
	if (fd < 0) {
		perror(file);
		exit(1);
	}

	if (uid == (uid_t)-1 || gid == (gid_t)-1) {
		/*
		 * If not setting owner or group, we need the
		 * current owner and group for translating
		 * references via owner@ or group@ ACEs.
		 */
		if (fstat(fd, &st) != 0) {
			perror(file);
			exit(1);
		}
		if (uid == (uid_t)-1)
			uid = st.st_uid;
		if (gid == (gid_t)-1)
			gid = st.st_gid;
	}

	/*
	 * Convert the ZFS ACL to an NT SD.
	 */
	error = smbfs_acl_zfs2sd(acl, uid, gid, selector, &sd);
	if (error) {
		fprintf(stderr, "%s: failed to convert ACL\n", progname);
		exit(1);
	}

	if (Vflag) {

		/*
		 * Print the SD in ZFS form.
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

		/*
		 * Print the SD in Windows form.
		 */
		printf("CIFS security data:\n");
		smbfs_acl_print_sd(stdout, sd);
		printf("\n");
	}

	error = smbfs_acl_setsd(fd, selector, sd);
	(void) close(fd);

	if (error) {
		fprintf(stderr, "%s: ACL set failed, %s\n",
		    file, strerror(error));
		exit(1);
	}

	smbfs_acl_free_sd(sd);
}
