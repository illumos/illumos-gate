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
#include <sys/systm.h>
#include <sys/bootconf.h>
#include <sys/thread.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <vm/seg_kmem.h>

#define	VIDEOMEM	0xa0000

extern void outb(int, uchar_t);

static int graphics_mode;
static int cursor_y = 400;
static int cursor_x = 210;
static uchar_t bar[4][32];
static kthread_t *progressbar_tid;
static kmutex_t pbar_lock;
static kcondvar_t pbar_cv;
static char *videomem = (caddr_t)VIDEOMEM;
static int videomem_size;

static void
mapmask(int value)
{
	outb(0x3c4, 2);
	outb(0x3c5, value);
}

static void
bitmask(int value)
{
	outb(0x3ce, 8);
	outb(0x3cf, value);
}

static void
progressbar_show(void)
{
	int i, j, k, offset;
	uchar_t *mem, *ptr;

	offset = cursor_y * 80 + cursor_x / 8;
	mem = (uchar_t *)videomem + offset;

	for (i = 0; i < 4; i++) {
		mapmask(1 << i);
		for (j = 0; j < 16; j++) {   /* bar height 16 pixel */
			ptr = mem + j * 80;
			for (k = 0; k < 32; k++, ptr++)
				*ptr = bar[i][k];
		}
	}
	mapmask(15);
}

/*
 * Initialize a rectangle area for progress bar
 *
 * Multiboot has initialized graphics mode to 640x480
 * with 16 colors.
 */
void
progressbar_init()
{
	int i;
	char cons[10];

	/* see if we are in graphics mode */
	if (BOP_GETPROPLEN(bootops, "console") != sizeof ("graphics"))
		return;
	(void) BOP_GETPROP(bootops, "console", cons);
	if (strncmp(cons, "graphics", strlen("graphics")) != 0)
		return;

	graphics_mode = 1;
	bitmask(0xff);

	for (i = 0; i < 32; i++) {
		bar[0][i] = bar[1][i] = 0xf0;
		bar[2][i] = bar[3][i] = 0xf0;
	}

	progressbar_show();
}

static void
progressbar_step()
{
	static int limit = 0;
	int i;

	if (limit == 0) {	/* reset */
		for (i = 0; i < 32; i++)
			bar[3][i] = 0xf0;
	}
	bar[3][limit] = 0xff;
	limit++;
	if (limit == 32)
		limit = 0;

	progressbar_show();
}

/*ARGSUSED*/
static void
progressbar_thread(void *arg)
{
	clock_t end;

	mutex_enter(&pbar_lock);
	while (graphics_mode) {
		progressbar_step();
		end = ddi_get_lbolt() + drv_usectohz(200000);
		(void) cv_timedwait(&pbar_cv, &pbar_lock, end);
	}
	mutex_exit(&pbar_lock);
}

void
progressbar_start(void)
{
	extern pri_t minclsyspri;

	if (graphics_mode == 0)
		return;

	/* map video memory to kernel heap */
	videomem_size = ptob(btopr(38400));	/* 640 x 480 / 8 bytes */
	videomem = vmem_alloc(heap_arena, videomem_size, VM_SLEEP);
	if (videomem == NULL) {
		cmn_err(CE_NOTE, "!failed to start progress bar");
		graphics_mode = 0;
		return;
	}
	hat_devload(kas.a_hat, videomem, videomem_size,
	    btop(VIDEOMEM), (PROT_READ | PROT_WRITE),
	    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);

	progressbar_tid = thread_create(NULL, 0, progressbar_thread,
	    NULL, 0, &p0, TS_RUN, minclsyspri);
}

void
progressbar_stop(void)
{
	if (graphics_mode == 0)
		return;

	graphics_mode = 0;
	mutex_enter(&pbar_lock);
	cv_signal(&pbar_cv);
	mutex_exit(&pbar_lock);
	if (progressbar_tid != NULL)
		thread_join(progressbar_tid->t_did);

	/* unmap video memory */
	hat_unload(kas.a_hat, videomem, videomem_size, HAT_UNLOAD_UNLOCK);
	vmem_free(heap_arena, videomem, videomem_size);
}
