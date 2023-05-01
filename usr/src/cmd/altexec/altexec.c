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
 * Copyright 2023 MNX Cloud, Inc.
 */

/*
 * Use a dedicated C program to exec() something in the pkgsrc paths.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <locale.h>

/* Remap table for when we have commands with than one name (e.g. tcsh/csh). */
static struct {
	const char *bin_name;
	const char *bin_needs;
} remap_table[] = {
	{ "csh", "tcsh" },
	/* login(1) invokes shells as -$SHELL. Cover that here. */
	{ "-csh", "tcsh" },
	{ "-tcsh", "tcsh" },
	{ "-zsh", "zsh" },
	{ NULL, NULL}
};

static const char *
remap_bin(const char *base_bin)
{
	uint_t index;

	for (index = 0; remap_table[index].bin_name != NULL; index++) {
		/* Can use strcmp() because remap_table entries are bounded. */
		if (strcmp(remap_table[index].bin_name, base_bin) == 0)
			return (remap_table[index].bin_needs);

	}
	return (base_bin);
}


/*
 * List the pkgsrc paths in desired search order. We are ignoring PATH
 * intentionally.
 */
static const char *pkgsrc_paths[] = {
	"/opt/tools/bin",
	"/opt/tools/sbin",
	"/opt/local/bin",
	"/opt/local/sbin",
	NULL
};

/*
 * This returns an allocated string.  Since we're exec()-ing or exit()-ing we
 * really don't need to worry about leaks, however.
 */
static char *
generate_pkgsrc_path(const char *desired_bin)
{
	const char *path = NULL;
	char *binpath;
	uint_t index;

	for (index = 0; pkgsrc_paths[index] != NULL; index++) {
		int dirfd;
		int cmdfd;

		/*
		 * NOTE: Any of dirfd or cmdfd that has an actual file
		 * descriptor from open(2) MUST be closed before this loop
		 * either exits or iterates.
		 */

		dirfd = open(pkgsrc_paths[index], O_RDONLY);
		if (dirfd == -1)
			continue; /* Try next one */
		cmdfd = openat(dirfd, desired_bin, O_RDONLY);
		(void) close(dirfd);
		if (cmdfd == -1)
			continue; /* Try next one */
		(void) close(cmdfd);
		path = pkgsrc_paths[index];
		break;	/* We're done. */
	}

	if (path == NULL)
		return (NULL); /* If we reach here, there's no such binary. */

	/*
	 * Okay, so we can now combine path and desired_bin into a string
	 * suitable for an exec()-family call.
	 */

	if (asprintf(&binpath, "%s/%s", path, desired_bin) == -1) {
		assert(binpath == NULL); /* man page says this must be true. */
	}

	return (binpath);
}

/* Don't let us run ourselves. */
static char *myname = "altexec";

int
main(int argc, char *argv[], char *envp[])
{
	const char *base_bin;
	const char *remapped_bin;
	char *pkgsrc_path;

	/*
	 * 1. Get the binary name in argv[0], remapping if need be.
	 * (e.g. csh -> tcsh, or -($SHELL) invocations.)
	 */
	base_bin = strrchr(argv[0], '/');
	if (base_bin == NULL)
		base_bin = argv[0];
	else
		base_bin++; /* Move past matched '/' */

	/*
	 * 2. Make sure we just aren't running ourselves!
	 * (Can use strcmp() because "myname" is bounded.)
	 */
	if (strcmp(myname, base_bin) == 0) {
		(void) fprintf(stderr, gettext("%s should not be run directly."
		    " See altexec(8) for more information\n"), myname);
		exit(3);
	}

	remapped_bin = remap_bin(base_bin);

	/* 3. See if the binary name is in one of the pkgsrc paths. */
	pkgsrc_path = generate_pkgsrc_path(remapped_bin);
	if (pkgsrc_path == NULL) {
		(void) fprintf(stderr, gettext("Please install %s from pkgsrc."
		    " See altexec(8) for more information.\n"), remapped_bin);
		exit(1);
	}

	/* 4. If so, launch it with our exact arg[vc] (assume env goes thru?) */
	if (execve(pkgsrc_path, argv, envp) == -1) {
		(void) fprintf(stderr,
		    gettext("Failed to execute %s: %s.\n"),
		    pkgsrc_path, strerror(errno));
		exit(2);
	}

	/* We shouldn't return here... */
	(void) fprintf(stderr,
	    gettext("execve bug with %s.\n"), pkgsrc_path);
	return (2);
}
