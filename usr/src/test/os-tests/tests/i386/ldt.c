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
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/sysi86.h>
#include <sys/segments.h>
#include <sys/segment.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <err.h>

char foo[4096];

static void *
donothing(void *nothing)
{
	sleep(5);
	return (NULL);
}

int
main(void)
{
	pthread_t tid;

	/*
	 * This first is similar to what sbcl does in some variants.  Note the
	 * SDT_MEMRW (not SDT_MEMRWA) so we check that the kernel is forcing the
	 * 'accessed' bit too.
	 */
	int sel = SEL_LDT(7);

	struct ssd ssd = { sel, (unsigned long)&foo, 4096,
	    SDT_MEMRW | (SEL_UPL << 5) | (1 << 7), 0x4 };

	if (sysi86(SI86DSCR, &ssd) < 0)
		err(-1, "failed to setup segment");

	__asm__ __volatile__("mov %0, %%fs" : : "r" (sel));

	ssd.acc1 = 0;

	if (sysi86(SI86DSCR, &ssd) == 0)
		errx(-1, "removed in-use segment?");

	__asm__ __volatile__("mov %0, %%fs" : : "r" (0));

	if (sysi86(SI86DSCR, &ssd) < 0)
		err(-1, "failed to remove segment");

	for (int i = 0; i < MAXNLDT; i++) {
		ssd.sel = SEL_LDT(i);
		(void) sysi86(SI86DSCR, &ssd);
	}

	for (int i = 0; i < 10; i++)
		pthread_create(&tid, NULL, donothing, NULL);

	if (forkall() == 0) {
		sleep(2);
		_exit(0);
	}

	sleep(6);
	return (0);
}
