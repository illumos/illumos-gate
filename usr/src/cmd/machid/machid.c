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
 * Copyright (c) 1993-1994, by Sun Microsystems, Inc.
 */

/*
 * This program replicates the function of the links from a machine name
 * (such as sun4c) through /usr/kvm to true or false as appropriate.  It
 * knows the correct special cases.
 *
 * IMPORTANT NOTE:
 *
 * Do not modify this program to know about additional special cases or
 * reflect new platforms or instruction set architectures.  This is a
 * deprecated interface and strictly for backwards compatibility.  This
 * is psarc/1992/171.  Note the following excerpt from the opinion:
 *
 *    It is most important to note that the manual page states in
 *    the NOTES section:  "The machid family of commands is
 *    obsolete.  Use uname -p and uname -m instead."
 *
 *    The intent of Kernel Architecture Project team is to provide
 *    only enough functionality to mimic the existing definitions
 *    on the SPARC and Intel x86 versions of Solaris 2.x.  No new
 *    identifiers will ever be added to the documented and
 *    undocumented identifiers listed above.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/systeminfo.h>

static char	static_buf[SYS_NMLN];
static char	*progname;

static void get_info_item(int command, char **buf, long *count);

/* ARGSUSED */
int
main(int argc, char *argv[], char *envp[])
{
	char	*buf = &static_buf[0];
	long	buflen = SYS_NMLN;

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	/*
	 * First possible match is on the processor type.
	 *
	 * Special case for architectures: i386 matches i486 and visa versa.
	 */
	get_info_item(SI_ARCHITECTURE, &buf, &buflen);
	if (strcmp(buf, progname) == 0)
		return (0);
	if ((strcmp(buf, "i386") == 0 && strcmp(progname, "i486") == 0) ||
	    (strcmp(buf, "i486") == 0 && strcmp(progname, "i386") == 0))
		return (0);

	/*
	 * Next possible match is the machine, or more exactly, the value
	 * which would be returned by uname(2) in the machine field or uname(1)
	 * with the -m option.  For historical reasons this is really is
	 * often a class of platforms which are identical to userland processes
	 * such as sun4c, sun4m, etc.
	 */
	get_info_item(SI_MACHINE, &buf, &buflen);
	if (strcmp(buf, progname) == 0)
		return (0);

	/*
	 * Finally, match the vendor.  We hardwire in one historical match.
	 */
	get_info_item(SI_HW_PROVIDER, &buf, &buflen);
	if (strcmp(buf, progname) == 0)
		return (0);
	if (strcasecmp(buf, "Sun_Microsystems") == 0 &&
	    strcmp("sun", progname) == 0)
		return (0);

	return (255);
}

/*
 * get_info_item is a wrapper around the sysinfo system call. It makes sure
 * the buffer is large enough, returning a larger buffer if needed.  On
 * unrecoverable error, it exits.  An error message doesn't help and makes
 * this tiny program link stdio and maybe deal with internationalization,
 * so the best thing is to die silently.  Note that the larger buffer is
 * retained for later use.  Reality is that the buffer will always be big
 * enough, but this is coded to the spec rather than implementation.
 */
static void
get_info_item(int command, char **buf, long *count)
{
	long	error;

	error = sysinfo(command, *buf, *count);
	if (error > *count) {
		*count = error;
		if (*buf != static_buf) {
			free(*buf);
		}
		*buf = (char *) malloc(*count);
		error = sysinfo(command, *buf, *count);
	}

	if (error == -1)
		exit(-1);
}
