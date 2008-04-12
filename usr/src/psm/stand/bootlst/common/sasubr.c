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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#include <sys/salib.h>
#include <sys/promif.h>

#define	MINALLOC	8
#define	TOPMEM		((caddr_t)0x1000000)

extern caddr_t _end;
extern struct boot_fs_ops promfs_ops;

struct boot_fs_ops *boot_fsw[] = {
	&promfs_ops,
};
int boot_nfsw = sizeof (boot_fsw) / sizeof (boot_fsw[0]);

void *
bkmem_alloc(size_t s)
{
	static caddr_t next;
	caddr_t ret;

	if (next == NULL)
		next = (caddr_t)roundup((uintptr_t)&_end, MINALLOC);
	ret = next;
	next += roundup(s, MINALLOC);
	if (next >= TOPMEM)
		prom_panic("out of memory");
	return (ret);
}

/*ARGSUSED*/
void
bkmem_free(void *p, size_t s)
{
}

int
cons_getchar(void)
{
	register int c;

	while ((c = prom_mayget()) == -1)
		;
	if (c == '\r') {
		prom_putchar(c);
		c = '\n';
	}
	if (c == 0177 || c == '\b') {
		prom_putchar('\b');
		prom_putchar(' ');
		c = '\b';
	}
	prom_putchar(c);
	return (c);
}

char *
cons_gets(char *buf, int n)
{
	char *lp;
	char *limit;
	int c;

	lp = buf;
	limit = &buf[n - 1];
	for (;;) {
		c = cons_getchar() & 0177;
		switch (c) {
		case '\n':
		case '\r':
			*lp = '\0';
			return (buf);
		case '\b':
			if (lp > buf)
				lp--;
			continue;
		case 'u'&037:			/* ^U */
			lp = buf;
			prom_putchar('\r');
			prom_putchar('\n');
			continue;
		case 0:
			continue;
		default:
			if (lp < limit)
				*lp++ = (char)c;
			else
				prom_putchar('\a');	/* bell */
		}
	}
}
