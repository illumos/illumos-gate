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

#include <sys/param.h>
#include <sys/bootvfs.h>
#include <sys/varargs.h>
#include "console.h"
#include "util.h"
#include "bootprop.h"
#include "biosint.h"
#include "debug.h"

char filename[MAXPATHLEN];
char *impl_arch_name = "i86pc";
int pagesize = 0x1000;

extern void *memset(void *, int, size_t);


/*
 * Open the given filename, expanding to its
 * platform-dependent location if necessary.
 */
int
openfile(char *fname, char *kern)
{
	int fd;

	/*
	 * If the caller -specifies- an absolute pathname, then we just try to
	 * open it.
	 */
	if (*fname == '/') {
		(void) strcpy(filename, fname);
		return (open(fname, 0));
	}

	(void) strcpy(filename, "/platform/i86pc/");
	if (kern)
		(void) strcat(filename, kern);
	(void) strcat(filename, fname);
	if ((fd = open(filename, 0)) != -1)
		return (fd);

	/* try / */
	(void) strcpy(filename, "/");
	if (kern)
		(void) strcat(filename, kern);
	(void) strcat(filename, fname);
	return (open(filename, 0));
}

/*
 * Is path "/platform/"dir"/" ?
 */
static int
platcmp(char *path, char *dir)
{
	static char prefix[] = "/platform/";
	static char suffix[] = "/kernel";
	int len;

	if (strncmp(path, prefix, sizeof (prefix) - 1) != 0)
		return (0);
	len = strlen(dir);
	path += sizeof (prefix) - 1;
	if (strncmp(path, dir, len) != 0)
		return (0);
	path += len;
	if (strcmp(path, suffix) != 0)
		return (0);
	return (1);
}

void
mod_path_uname_m(char *mod_path, char *ia_name)
{
	/*
	 * If we found the kernel in the default "i86pc" dir, prepend the
	 * ia_name directory (e.g. /platform/SUNW,foo/kernel) to the mod_path
	 * unless ia_name is the same as the default dir.
	 *
	 * If we found the kernel in the ia_name dir, append the default
	 * directory to the modpath.
	 *
	 * If neither of the above are true, we were given a specific kernel
	 * to boot, so we leave things well enough alone.
	 */
	if (platcmp(mod_path, "i86pc")) {
		if (strcmp(ia_name, "i86pc") != 0) {
			char tmp[MAXPATHLEN];

			(void) strcpy(tmp, mod_path);
			(void) strcpy(tmp, mod_path);
			(void) strcpy(mod_path, "/platform/");
			(void) strcat(mod_path, ia_name);
			(void) strcat(mod_path, "/kernel ");
			(void) strcat(mod_path, tmp);
		}
	} else if (platcmp(mod_path, ia_name))
		(void) strcat(mod_path, " /platform/i86pc/kernel");
}

void
setup_aux(void)
{
	extern char *mmulist;
	static char mmubuf[16];
	int plen;

	if (((plen = bgetproplen(NULL, "mmu-modlist")) > 0) && (plen < 20))
		(void) bgetprop(NULL, "mmu-modlist", mmubuf);
	else
		(void) strcpy(mmubuf, "mmu32"); /* default to mmu32 */
	mmulist = mmubuf;
}

/* Print panic string, then blow up! */
/*PRINTFLIKE1*/
void
panic(const char *fmt, ...)
{
	va_list adx;

	/* turn on output */
	verbosemode = 1;
	printf("panic: ");
	va_start(adx, fmt);
	prom_vprintf(fmt, adx);
	va_end(adx);
	printf("Press any key to reboot\n");
	(void) getchar();
	printf("rebooting...\n");
	reset();
}

void
prom_panic(char *str)
{
	panic(str);
}

/*
 * stubs for heap_kmem (assuming they're actually even needed there)
 */

int
splimp()
{
	return (0);
}

/*ARGSUSED*/
void
splx(int rs)
{
}

int
splnet()
{
	return (0);
}

static uint_t
gettime(void)
{
	/*
	 * Read system timer:
	 *
	 * Return milliseconds since last time counter was reset.
	 * The timer ticks 18.2 times per second or approximately
	 * 55 milliseconds per tick.
	 *
	 * The counter will be reset to zero by the bios after 24 hours
	 * or 1,573,040 ticks. The first read after a counter
	 * reset will flag this condition in the %al register.
	 * Unfortunately, it is hard to take advantage of this
	 * fact because some broken bioses will return bogus
	 * counter values if the counter is in the process of
	 * updating. We protect against this race by reading the
	 * counter until we get consecutive identical readings.
	 * By doing so, we lose the counter reset bit. To make this
	 * highly unlikely, we reset the counter to zero on the
	 * first call and assume 24 hours is enough time to get this
	 * machine booted.
	 *
	 * An attempt is made to provide a unique number on each
	 * call by adding 1 millisecond if the 55 millisecond counter
	 * hasn't changed. If this happens more than 54 times, we
	 * return the same value until the next real tick.
	 */
	static uint_t lasttime = 0;
	static ushort_t fudge = 0;
	uint_t ticks, mills, first, tries;
	struct int_pb ic;

	if (lasttime == 0) {
		/*
		 * initialize counter to zero so we don't have to
		 * worry about 24 hour wrap.
		 */
		(void) memset(&ic, 0, sizeof (ic));
		ic.ax = 0x0100;
		(void) bios_doint(0x1a, &ic);
	}
	tries = 0;
	do {
		/*
		 * Loop until we trust the counter value.
		 */
		(void) memset(&ic, 0, sizeof (ic));
		(void) bios_doint(0x1a, &ic);
		first = (ic.cx << 16) + (ic.dx & 0xFFFF);
		(void) memset(&ic, 0, sizeof (ic));
		(void) bios_doint(0x1a, &ic);
		ticks = (ic.cx << 16) + (ic.dx & 0xFFFF);
	} while (first != ticks && ++tries < 10);
	if (tries == 10)
		printf("gettime: BAD BIOS TIMER\n");

	mills = ticks*55;
	if (mills > lasttime) {
		fudge = 0;
	} else {
		fudge += (fudge < 54) ? 1 : 0;
	}
	mills += fudge;
	lasttime = mills;
	return (mills);
}

void
mdelay(uint_t msec)
{
	uint_t time_now = gettime();
	uint_t time_end = time_now + msec;

	/* spin, we can't do anything else */
	while (gettime() < time_end)
		;
}
