/*
 * Copyright (c) 1998, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * safechown changes the owner ship of src to uid. If the mode parameter
 * does not equal -1 changes the mode of src as well.
 *
 * return -1 on failure and 0 on success.
 */

int
safechown(const char *src, uid_t uid, gid_t gid, int mode)
{
int fd;
struct stat fdbuf;
struct stat lbuf;

	if ((fd = open(src, O_RDONLY, 0)) == -1)
		return (-1);

	if (fstat(fd, &fdbuf)) {
		close(fd);
		return (-1);
	}

	/* Make sure non directories are not hard links */
	if (!S_ISDIR(fdbuf.st_mode) && fdbuf.st_nlink != 1) {
		close(fd);
		return (-1);
	}

	if (lstat(src, &lbuf)) {
		close(fd);
		return (-1);
	}

	/* Make sure file is not a symlink */
	if (fdbuf.st_ino != lbuf.st_ino || fdbuf.st_dev != lbuf.st_dev ||
		fdbuf.st_mode != lbuf.st_mode) {

		close(fd);
		return (-1);
	}

	/* we should probably get the primary group id for uid here */
	if (fchown(fd, uid, gid)) {
		close(fd);
		return (-1);
	}

	if (mode != -1) {
		if (fchmod(fd, (mode_t)mode)) {
		    close(fd);
		    return (-1);
		}
	}

	close(fd);

	return (0);
}

#ifdef TEST
void
usage(char *prg)
{
	fprintf(stderr, "Usage %s [-u uid] [-m mode] source\n", prg);
	exit(1);
}

main(int argc, char *argv[])
{
	int opt;
	int mode = -1;
	uid_t uid = 0;

	while ((opt = getopt(argc, argv, "m:u:")) != EOF) {
		switch (opt) {
		case 'm':
			mode = strtol(optarg, 0, 8);
			break;
		case 'u':
			uid = atoi(optarg);
			break;
		default:
			usage(argv[0]);
	}
}

    if (argc - optind != 1)
	usage(argv[0]);

    if (safechown(argv[optind], uid, getgid(), mode)) {
	perror("safechown");
	exit(1);
    }

    return (0);
}

#endif  /* TEST */
