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

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <libproc.h>
#include <proc_service.h>

static	int	show_map(void *, const prmap_t *, const char *);

static	char	*command;

int
main(int argc, char **argv)
{
	int rc = 0;
	int opt;
	int errflg = 0;
	int Fflag = 0;
	int lflag = 0;
	core_content_t content = CC_CONTENT_DATA | CC_CONTENT_ANON;
	struct rlimit rlim;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	/* options */
	while ((opt = getopt(argc, argv, "Fl")) != EOF) {
		switch (opt) {
		case 'F':		/* force grabbing (no O_EXCL) */
			Fflag = PGRAB_FORCE;
			break;
		case 'l':		/* show unresolved link map names */
			lflag = 1;
			break;
		default:
			errflg = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (errflg || argc <= 0) {
		(void) fprintf(stderr,
		    "usage:\t%s [-Fl] { pid | core } ...\n", command);
		(void) fprintf(stderr,
		    "  (report process dynamic libraries)\n");
		(void) fprintf(stderr,
		    "  -F: force grabbing of the target process\n"
		    "  -l: show unresolved dynamic linker map names\n");
		return (2);
	}

	/*
	 * Make sure we'll have enough file descriptors to handle a target
	 * that has many many mappings.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	(void) proc_initstdio();

	while (argc-- > 0) {
		char *arg;
		int gcode;
		psinfo_t psinfo;
		struct ps_prochandle *Pr;

		(void) proc_flushstdio();

		if ((Pr = proc_arg_grab(arg = *argv++, PR_ARG_ANY,
		    PGRAB_RETAIN | Fflag, &gcode)) == NULL) {

			(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
			    command, arg, Pgrab_error(gcode));
			rc++;
			continue;
		}

		(void) memcpy(&psinfo, Ppsinfo(Pr), sizeof (psinfo_t));
		proc_unctrl_psinfo(&psinfo);

		if (Pstate(Pr) == PS_DEAD) {
			if ((Pcontent(Pr) & content) != content) {
				(void) fprintf(stderr, "%s: core '%s' has "
				    "insufficient content\n", command, arg);
				rc++;
				continue;
			}
			(void) printf("core '%s' of %d:\t%.70s\n",
			    arg, (int)psinfo.pr_pid, psinfo.pr_psargs);
		} else {
			(void) printf("%d:\t%.70s\n",
			    (int)psinfo.pr_pid, psinfo.pr_psargs);
		}

		if (Pgetauxval(Pr, AT_BASE) != -1L && Prd_agent(Pr) == NULL) {
			(void) fprintf(stderr, "%s: warning: librtld_db failed "
			    "to initialize; shared library information will "
			    "not be available\n", command);
		}

		if (lflag)
			rc += Pobject_iter(Pr, show_map, Pr);
		else
			rc += Pobject_iter_resolved(Pr, show_map, Pr);
		Prelease(Pr, 0);
	}
	(void) proc_finistdio();

	return (rc);
}

static int
show_map(void *cd, const prmap_t *pmap, const char *object_name)
{
	char pathname[PATH_MAX];
	struct ps_prochandle *Pr = cd;
	const auxv_t *auxv;
	int len;

	/* omit the executable file */
	if (strcmp(pmap->pr_mapname, "a.out") == 0)
		return (0);

	/* also omit the dynamic linker */
	if (ps_pauxv(Pr, &auxv) == PS_OK) {
		while (auxv->a_type != AT_NULL) {
			if (auxv->a_type == AT_BASE) {
				if (pmap->pr_vaddr == auxv->a_un.a_val)
					return (0);
				break;
			}
			auxv++;
		}
	}

	/* freedom from symlinks; canonical form */
	if ((len = resolvepath(object_name, pathname, sizeof (pathname))) > 0)
		pathname[len] = '\0';
	else
		(void) strncpy(pathname, object_name, sizeof (pathname));

	(void) printf("%s\n", pathname);
	return (0);
}
