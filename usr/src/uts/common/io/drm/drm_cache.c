/*
 *
 * Copyright(c) 2006-2007 Tungsten Graphics, Inc., Cedar Park, TX., USA
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files(the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice(including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */
/*
 * Authors: Thomas HellstrÃ¶m <thomas-at-tungstengraphics-dot-com>
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/x86_archext.h>
#include <vm/seg_kmem.h>
#include "drmP.h"

extern void clflush_insn(caddr_t addr);
extern void mfence_insn(void);

static void
drm_clflush_page(caddr_t page)
{
	unsigned int i;

	if (page == NULL)
		return;

	for (i = 0; i < PAGE_SIZE; i += x86_clflush_size)
		clflush_insn(page + i);
	mfence_insn();
}

void
drm_clflush_pages(caddr_t *pages, unsigned long num_pages)
{

	if (x86_feature & X86_CLFSH) {
		unsigned long i;

		for (i = 0; i < num_pages; i++)
			drm_clflush_page(pages[i]);
	}
}
