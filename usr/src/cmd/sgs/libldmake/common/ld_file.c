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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <sys/param.h>
#include <link.h>

#pragma init(ld_support_init)

#define	SUNPRO_DEPENDENCIES	"SUNPRO_DEPENDENCIES"

/*
 * Linked list of strings - used to keep lists of names
 * of directories or files.
 */
struct Stritem {
	char	*str;
	void	*next;
};

typedef struct Stritem 	Stritem;

static char 	*depend_file = NULL;
static Stritem	*list = NULL;

void
ld_support_init()
{
	depend_file = getenv(SUNPRO_DEPENDENCIES);
}

static void
prepend_str(Stritem **list, const char *str)
{
	Stritem		*new;
	char		*newstr;
	const char	*lib = "libldmake.so";

	if (!(new = calloc(1, sizeof (Stritem)))) {
		perror(lib);
		return;
	}

	if (!(newstr = malloc(strlen(str) + 1))) {
		perror(lib);
		return;
	}

	new->str = strcpy(newstr, str);
	new->next = *list;
	*list = new;

}

/* ARGSUSED */
void
ld_file(const char *file, const Elf_Kind ekind, int flags, Elf *elf)
{
	/*
	 * SUNPRO_DEPENDENCIES wasn't set, we don't collect .make.state
	 * information.
	 */
	if (!depend_file)
		return;

	if ((flags & LD_SUP_DERIVED) && !(flags & LD_SUP_EXTRACTED))
		prepend_str(&list, file);
}

void
ld_file64(const char *file, const Elf_Kind ekind, int flags, Elf *elf)
{
	ld_file(file, ekind, flags, elf);
}

void
ld_atexit(int exit_code)
{
	Stritem 	*cur;
	char		lockfile[MAXPATHLEN], *err, *space, *target;
	FILE		*ofp;
	extern char 	*file_lock(char *, char *, int);

	if (!depend_file || exit_code)
		return;

	if ((space = strchr(depend_file, ' ')) == NULL)
		return;
	*space = '\0';
	target = &space[1];

	(void) snprintf(lockfile, MAXPATHLEN, "%s.lock", depend_file);
	if ((err = file_lock(depend_file, lockfile, 0))) {
		(void) fprintf(stderr, "%s\n", err);
		return;
	}

	if (!(ofp = fopen(depend_file, "a")))
		return;

	if (list)
		(void) fprintf(ofp, "%s: ", target);

	for (cur = list; cur; cur = cur->next)
		(void) fprintf(ofp, " %s", cur->str);

	(void) fputc('\n', ofp);

	(void) fclose(ofp);
	(void) unlink(lockfile);
	*space = ' ';
}

void
ld_atexit64(int exit_code)
{
	ld_atexit(exit_code);
}
