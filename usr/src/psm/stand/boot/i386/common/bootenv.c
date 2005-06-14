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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/salib.h>
#include "debug.h"
#include "multiboot.h"
#include "bootprop.h"

extern void prom_init(char *, void *);
extern void prom_panic(char *);
extern int openfile(char *, char *);
extern int close(int);


#define	BOOTENV_BUFSIZE		4096
#define	BOOTENV_LINESIZE	256

/*
 * Note this path name must be consistent with that used
 * in the ramdisk construction.
 */
static char *f_bootenv = "/boot/solaris/bootenv.rc";


static void
get_bootenv_prop(char *line, int lineno)
{
	char *p;
	int inq;
	char *name;
	char *val;
	char **propp;

	/*
	 * Trim comments, respecting single quotes, then
	 * skip any blank lines and leading white space.
	 */
	inq = 0;
	for (p = line; *p; p++) {
		if (*p == '\'' || *p == '"') {
			inq ^= 1;
		} else if ((inq == 0 && *p == '#') ||
		    *p == '\r' || *p == '\n') {
			*p = 0;
			break;
		}
	}

	while (*line == ' ' || *line == '\t')
		line++;
	if (strlen(line) == 0)
		return;

	/*
	 * Anything remaining must be in a fixed format
	 */
	if ((name = strchr(line, ' ')) == NULL)
		goto err;
	*name++ = 0;
	if (strcmp(line, "setprop") != 0)
		goto err;
	if ((val = strchr(name, ' ')) == NULL)
		goto err;
	*val++ = 0;

	p = val + strlen(val) - 1;
	if (((*val == '\'' && *p == '\'') ||
	    (*val == '"' && *p == '"')) && val != p) {
		*p = 0;
		val++;
	}

	/*
	 * An empty name indicates a syntax error but
	 * an empty value should just be ignored.
	 */
	if (strlen(name) == 0)
		goto err;
	if (strlen(val) == 0)
		return;

	if (debug & D_BPROP)
		printf("%s(%d): %s %s\n", f_bootenv, lineno, name, val);

	(void) bsetprop(NULL, name, val, strlen(val) + 1);

	/*
	 * We respect certain eeprom(1M) properties internally
	 * if not overridden on the grub kernel cmdline.
	 * There should never be multiple definitions, but
	 * should that occur, the last one is the one that sticks.
	 */
	propp = NULL;
	if (strcmp(name, "boot-file") == 0)
		propp = &bootfile_prop;
	else if (strcmp(name, "console") == 0)
		propp = &console_prop;
	else if (strcmp(name, "input-device") == 0)
		propp = &inputdevice_prop;
	else if (strcmp(name, "output-device") == 0)
		propp = &outputdevice_prop;

	if (propp) {
		if (*propp)
			bkmem_free(*propp, strlen(*propp) + 1);
		*propp = bkmem_zalloc(strlen(val)+1);
		strcpy(*propp, val);
	}

	return;

err:
	printf("%s: syntax error on line %d\n", f_bootenv, lineno);
}

int
get_bootenv_props()
{
	int fd;
	char *line;
	char *buf;
	int n, bufcnt;
	int c, linecnt;
	char *bp, *lp;
	int lineno = 1;
	int err;

	fd = openfile(f_bootenv, 0);
	if (fd == -1) {
		printf("error opening %s\n", f_bootenv);
		return (0);
	}

	buf = bkmem_zalloc(BOOTENV_BUFSIZE);
	line = bkmem_zalloc(BOOTENV_LINESIZE);

	lp = line;
	*lp = 0;
	bufcnt = 0;
	linecnt = 0;
	err = 0;

	for (;;) {
		if (bufcnt == 0) {
			n = read(fd, buf, BOOTENV_BUFSIZE);
			if (n <= 0)
				goto exit;
			bufcnt = n;
			bp = buf;
		}
		while (bufcnt > 0) {
			if ((c = *bp++) == '\n') {
				get_bootenv_prop(line, lineno++);
				linecnt = 0;
				lp = line;
				err = 0;
			} else if (linecnt < BOOTENV_LINESIZE-1) {
				*lp++ = c;
				linecnt++;
			} else if (err == 0) {
				printf("%s: line %d exceeds maximum (%d)\n",
				    f_bootenv, lineno, BOOTENV_LINESIZE);
				err = 1;
			}
			bufcnt--;
			*lp = 0;
		}
	}

exit:

	bkmem_free(buf, BOOTENV_BUFSIZE);
	bkmem_free(line, BOOTENV_LINESIZE);

	close(fd);

	return (0);
}
