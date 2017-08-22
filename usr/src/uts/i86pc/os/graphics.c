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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/bootconf.h>
#include <sys/thread.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <vm/seg_kmem.h>
#include <sys/file.h>
#include <sys/kd.h>
#include <sys/sunldi.h>

#define	VIDEOMEM	0xa0000

extern void outb(int, uchar_t);

static int graphics_mode;
static int cursor_y = 309;
static int cursor_x = 136;

#define	BAR_STEPS 46

static uchar_t bar[BAR_STEPS];
static kthread_t *progressbar_tid;
static kmutex_t pbar_lock;
static kcondvar_t pbar_cv;
static char *videomem = (caddr_t)VIDEOMEM;
static int videomem_size;

/* select the plane(s) to draw to */
static void
mapmask(int plane)
{
	outb(0x3c4, 2);
	outb(0x3c5, plane);
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
	int j, k, offset;
	uchar_t *mem, *ptr;

	offset = cursor_y * 80 + cursor_x / 8;
	mem = (uchar_t *)videomem + offset;

	bitmask(0xff);
	mapmask(0xff); /* write to all planes at once? */
	for (j = 0; j < 4; j++) {   /* bar height: 4 pixels */
		ptr = mem + j * 80;
		for (k = 0; k < BAR_STEPS; k++, ptr++)
			*ptr = bar[k];
	}
	bitmask(0x00);
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
	if (BOP_GETPROPLEN(bootops, "efi-systab") > 0)
		return;

	graphics_mode = 1;

	for (i = 0; i < BAR_STEPS; i++) {
		bar[i] = 0x00;
	}

	progressbar_show();
}

static void
progressbar_step()
{
	static int limit = 0;

	bar[limit] = 0xff;

	if (limit > 3)
		bar[limit - 4] = 0x00;
	else
		bar[limit + BAR_STEPS - 4] = 0x00;

	limit++;
	if (limit == BAR_STEPS)
		limit = 0;

	progressbar_show();
}

/*ARGSUSED*/
static void
progressbar_thread(void *arg)
{
	clock_t end = drv_usectohz(150000);

	mutex_enter(&pbar_lock);
	while (graphics_mode) {
		progressbar_step();
		(void) cv_reltimedwait(&pbar_cv, &pbar_lock, end,
		    TR_CLOCK_TICK);
	}
	mutex_exit(&pbar_lock);
}

void
progressbar_start(void)
{
#if !defined(__xpv)
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
#endif
}

void
progressbar_stop(void)
{
#if !defined(__xpv)
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
#endif
}

/*ARGSUSED*/
void
progressbar_key_abort(ldi_ident_t li)
{
#if !defined(__xpv)
	char *fbpath;
	int ret;
	ldi_handle_t hdl;

	extern char *consconfig_get_plat_fbpath(void);

	if (graphics_mode == 0)
		return;

	fbpath = consconfig_get_plat_fbpath();

	if (ldi_open_by_name(fbpath, FWRITE, kcred, &hdl, li) != 0) {
		cmn_err(CE_NOTE, "!ldi_open_by_name failed");
	} else {
		if (ldi_ioctl(hdl, KDSETMODE, KD_RESETTEXT, FKIOCTL,
		    kcred, &ret)
		    != 0)
				cmn_err(CE_NOTE,
				    "!ldi_ioctl for KD_RESETTEXT failed");
		(void) ldi_close(hdl, NULL, kcred);
	}
#endif
}
