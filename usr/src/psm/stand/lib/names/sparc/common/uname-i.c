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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/idprom.h>
#include <sys/promif.h>
#include <sys/salib.h>

#include <sys/platnames.h>

/*
 * This source is (and should be ;-) shared between the boot blocks
 * and the boot programs.  So if you change it, be sure to test them all!
 */

#define	MAXNMLEN	1024		/* # of chars in a property */

/*
 * Supplied by modpath.c
 *
 * Making these externs here allows all sparc machines to share
 * get_impl_arch_name().
 */
extern char *default_name;
extern char *default_path;

enum ia_state_mach {
	STATE_NAME,
	STATE_COMPAT_INIT,
	STATE_COMPAT,
	STATE_DEFAULT,
	STATE_FINI
};

/*
 * Return the implementation architecture name (uname -i) for this platform.
 *
 * Use the named rootnode property to determine the iarch.
 */
static char *
get_impl_arch_name(enum ia_state_mach *state, int use_default)
{
	static char iarch[MAXNMLEN];
	static int len;
	static char *ia;

	pnode_t n;
	char *cp;
	char *namename;

newstate:
	switch (*state) {
	case STATE_NAME:
		*state = STATE_COMPAT_INIT;
		namename = OBP_NAME;
		n = (pnode_t)prom_rootnode();
		len = prom_getproplen(n, namename);
		if (len <= 0 || len >= MAXNMLEN)
			goto newstate;
		(void) prom_getprop(n, namename, iarch);
		iarch[len] = '\0';	/* fix broken clones */
		ia = iarch;
		break;

	case STATE_COMPAT_INIT:
		*state = STATE_COMPAT;
		namename = OBP_COMPATIBLE;
		n = (pnode_t)prom_rootnode();
		len = prom_getproplen(n, namename);
		if (len <= 0 || len >= MAXNMLEN) {
			*state = STATE_DEFAULT;
			goto newstate;
		}
		(void) prom_getprop(n, namename, iarch);
		iarch[len] = '\0';	/* ensure null termination */
		ia = iarch;
		break;

	case STATE_COMPAT:
		/*
		 * Advance 'ia' to point to next string in
		 * compatible property array (if any).
		 */
		while (*ia++)
			;
		if ((ia - iarch) >= len) {
			*state = STATE_DEFAULT;
			goto newstate;
		}
		break;

	case STATE_DEFAULT:
		*state = STATE_FINI;
		if (!use_default || default_name == NULL)
			goto newstate;
		(void) strcpy(iarch, default_name);
		ia = iarch;
		break;

	case STATE_FINI:
		return (NULL);
	}

	/*
	 * Crush filesystem-awkward characters.  See PSARC/1992/170.
	 * (Convert the property to a sane directory name in UFS)
	 */
	for (cp = ia; *cp; cp++)
		if (*cp == '/' || *cp == ' ' || *cp == '\t')
			*cp = '_';
	return (ia);
}

static void
make_platform_path(char *fullpath, char *iarch, char *filename)
{
	(void) strcpy(fullpath, "/platform/");
	(void) strcat(fullpath, iarch);
	if (filename != NULL) {
		(void) strcat(fullpath, "/");
		(void) strcat(fullpath, filename);
	}
}

/*
 * Generate impl_arch_name by searching the /platform hierarchy
 * for a matching directory.  We are not looking for any particular
 * file here, but for a directory hierarchy for the module path.
 */
int
find_platform_dir(int (*isdirfn)(char *), char *iarch, int use_default)
{
	char fullpath[MAXPATHLEN];
	char *ia;
	enum ia_state_mach state = STATE_NAME;

	/*
	 * Hunt the filesystem looking for a directory hierarchy.
	 */
	while ((ia = get_impl_arch_name(&state, use_default)) != NULL) {
		make_platform_path(fullpath, ia, NULL);
		if (((*isdirfn)(fullpath)) != 0) {
			(void) strcpy(iarch, ia);
			return (1);
		}
	}
	return (0);
}

/*
 * Search the /platform hierarchy looking for a particular file.
 *
 * impl_arch_name is given as an optional hint as to where the
 * file might be found.
 */
int
open_platform_file(
	char *filename,
	int (*openfn)(char *, void *),
	void *arg,
	char *fullpath)
{
	char *ia;
	int fd;
	enum ia_state_mach state = STATE_NAME;

	/*
	 * Hunt the filesystem for one that works ..
	 */
	while ((ia = get_impl_arch_name(&state, 1)) != NULL) {
		make_platform_path(fullpath, ia, filename);
		if ((fd = (*openfn)(fullpath, arg)) != -1)
			return (fd);
	}

	return (-1);
}
