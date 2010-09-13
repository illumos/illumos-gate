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
 * Copyright (c) 1991-1994, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

int
prom_devname_from_pathname(register char *pathname, register char *buffer)
{
	register char *p;

	if ((pathname == (char *)0) || (*pathname == (char)0))
		return (-1);

	p = prom_strrchr(pathname, '/');
	if (p == 0)
		return (-1);

	p++;
	while (*p != 0)  {
		*buffer++ = *p++;
		if ((*p == '@') || (*p == ':'))
			break;
	}
	*buffer = (char)0;

	return (0);
}

/*
 * Get base device name of stdin/stdout device into callers buffer.
 * Return 0 if successful; -1 otherwise.
 */

int
prom_stdin_devname(char *buffer)
{
	return (prom_devname_from_pathname(prom_stdinpath(), buffer));
}

int
prom_stdout_devname(char *buffer)
{
	return (prom_devname_from_pathname(prom_stdoutpath(), buffer));
}

/*
 * Return 1 if stdin/stdout are on the same device and subdevice.
 * Return 0, otherwise.
 */

int
prom_stdin_stdout_equivalence(void)
{
	register char *s, *p;

	s = prom_stdinpath();
	p = prom_stdoutpath();

	if ((s != (char *)0) && (p != (char *)0))  {
		return (prom_strcmp(s, p) == 0 ? 1:0);
	}

	return (0);
}

/*
 *	This just returns a pointer to the option's part of the
 *	last part of the string.  Useful for determining which is
 *	the boot partition, tape file or channel of the DUART.
 */
char *
prom_path_options(register char *path)
{
	register char *p, *s;

	s = prom_strrchr(path, '/');
	if (s == (char *)0)
		return ((char *)0);
	p = prom_strrchr(s, ':');
	if (p == (char *)0)
		return ((char *)0);
	return (p+1);
}
