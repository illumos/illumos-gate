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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/modctl.h>
#include <zone.h>
#include <spawn.h>
#include <err.h>
#include <stdbool.h>


static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage:  modunload [-e <exec_file>] -i <id> | <name>\n");
	exit(EXIT_FAILURE);
}

/*
 * Execute the user file.
 */
static void
exec_userfile(char *execfile, const struct modinfo *modinfo, char **envp)
{
	char modid[8], mod0[8];
	char *child_args[] = {execfile, modid, mod0, NULL};

	(void) snprintf(modid, sizeof (modid), "%d", modinfo->mi_id);
	(void) snprintf(mod0, sizeof (mod0), "%d",
	    modinfo->mi_msinfo[0].msi_p0);

	const short desired_attrs =
	    POSIX_SPAWN_NOSIGCHLD_NP | POSIX_SPAWN_WAITPID_NP;
	posix_spawnattr_t attr;
	int res;
	if ((res = posix_spawnattr_init(&attr)) != 0 ||
	    (res = posix_spawnattr_setflags(&attr, desired_attrs)) != 0) {
		errc(EXIT_FAILURE, res, "could not set spawn attrs");
	}

	pid_t child;
	if (posix_spawn(&child, execfile, NULL, &attr, child_args, envp) != 0) {
		err(EXIT_FAILURE, "could not exec %s", execfile);
	}
	(void) posix_spawnattr_destroy(&attr);

	int status, error;
	do {
		error = waitpid(child, &status, 0);
	} while (error == -1 && errno == EINTR);
	if (error < 0) {
		err(EXIT_FAILURE, "error while waiting for child");
	}

	if (WEXITSTATUS(status) != 0) {
		errx(WEXITSTATUS(status),
		    "%s returned error %d.", execfile, status);
	}
}

/*
 * Unload a loaded module.
 */
int
main(int argc, char *argv[], char *envp[])
{
	int id = -1;
	char *execfile = NULL;
	char *unload_name = NULL;
	int opt;
	bool has_mod_id = false;

	if (argc < 2)
		usage();

	while ((opt = getopt(argc, argv, "i:e:")) != -1) {
		switch (opt) {
		case 'i':
			if (has_mod_id) {
				errx(EXIT_FAILURE,
				    "Only one module id can be specified");
			}
			if (sscanf(optarg, "%d", &id) != 1 || id < 0)
				errx(EXIT_FAILURE, "Invalid id %s", optarg);
			has_mod_id = true;
			break;
		case 'e':
			execfile = optarg;
			break;
		case '?':
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 1) {
		unload_name = argv[0];
	} else if (argc > 1) {
		errx(EXIT_FAILURE, "Only one module name can be specified");
	}

	/* One must specify a name (x)or an ID, not both */
	if (unload_name == NULL && !has_mod_id) {
		(void) fprintf(stderr,
		    "missing required module id or name\n");
		usage();
	} else if (unload_name != NULL && has_mod_id) {
		(void) fprintf(stderr,
		    "invalid to specify both module id and name\n");
		usage();
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		errx(EXIT_FAILURE,
		    "modunload can only be run from the global zone");
	}

	struct modinfo modinfo;
	if (execfile != NULL || unload_name != NULL) {
		modinfo.mi_id = modinfo.mi_nextid = id;
		modinfo.mi_info = MI_INFO_ONE;
		if (unload_name != NULL) {
			(void) strlcpy(modinfo.mi_name, unload_name,
			    sizeof (modinfo.mi_name));
			modinfo.mi_info |= MI_INFO_BY_NAME;
		}
		if (modctl(MODINFO, id, &modinfo) < 0) {
			err(EXIT_FAILURE, "can't get module information");
		}
		if (unload_name != NULL) {
			id = modinfo.mi_id;
		}
	}

	if (execfile) {
		exec_userfile(execfile, &modinfo, envp);
	}

	/*
	 * Unload the module.
	 */
	if (modctl(MODUNLOAD, id) < 0) {
		if (errno == EPERM) {
			errx(EXIT_FAILURE,
			    "Insufficient privileges to unload a module");
		} else if (id != 0) {
			err(EXIT_FAILURE, "can't unload the module");
		}
	}

	return (EXIT_SUCCESS);
}
