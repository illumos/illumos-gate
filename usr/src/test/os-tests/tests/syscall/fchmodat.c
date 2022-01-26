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
 * Copyright 2022 Marcel Telka <marcel@telka.sk>
 */

/*
 * Test for fchmodat(AT_SYMLINK_NOFOLLOW)
 */

#include <sys/param.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(void)
{
	int ret = 0;

	char template[MAXPATHLEN];
	char *path;
	char file[MAXPATHLEN];
	char link[MAXPATHLEN];

	/* prepare template for temporary directory */
	if (strlcpy(template, "/tmp/XXXXXX", sizeof (template))
	    >= sizeof (template)) {
		(void) printf("FAIL: Template copy failed\n");
		exit(EXIT_FAILURE);
	}

	/* create temporary directory */
	if ((path = mkdtemp(template)) == NULL) {
		(void) printf("FAIL: Temporary directory creation failed\n");
		exit(EXIT_FAILURE);
	}

	/* format file and link paths */
	(void) snprintf(file, sizeof (file), "%s/file", path);
	(void) snprintf(link, sizeof (link), "%s/link", path);

	/* create the file */
	int fd = open(file, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		(void) printf("FAIL: File %s creation failed\n", file);
		(void) rmdir(path);
		exit(EXIT_FAILURE);
	}
	(void) close(fd);

	/* create symlink */
	if (symlink("file", link) != 0) {
		(void) printf("FAIL: Symlink %s creation failed\n", link);
		(void) unlink(file);
		(void) rmdir(path);
		exit(EXIT_FAILURE);
	}

	/* test fchmodat(AT_SYMLINK_NOFOLLOW) for symlink */
	if (fchmodat(AT_FDCWD, link, 0666, AT_SYMLINK_NOFOLLOW) == 0) {
		(void) printf("FAIL: fchmodat(AT_SYMLINK_NOFOLLOW) "
		    "unexpectedly succeeded for symlink\n");
		ret = EXIT_FAILURE;
	}
	/* test fchmodat(AT_SYMLINK_NOFOLLOW) for regular file */
	if (fchmodat(AT_FDCWD, file, 0666, AT_SYMLINK_NOFOLLOW) != 0) {
		(void) printf("FAIL: fchmodat(AT_SYMLINK_NOFOLLOW) failed for "
		    "regular file\n");
		ret = EXIT_FAILURE;
	}

	/* cleanup */
	(void) unlink(link);
	(void) unlink(file);
	(void) rmdir(path);

	return (ret);
}
