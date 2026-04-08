/*
 * Copyright 2026 Edgecast Cloud LLC.
 * Copyright (c) 2016 The FreeBSD Foundation
 * All rights reserved.
 * Copyright (c) 1996
 *	Matthias Drochner.  All rights reserved.
 *
 * This software was developed by Konstantin Belousov under sponsorship
 * from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <stand.h>
#include <btxv86.h>
#include <common/bootargs.h>

/*
 * loader is laid out as:
 * physical address 0xa000
 *   text data bss _end stack space <free mem from 0x413>
 */
extern char _end[];

struct frame {
	struct frame	*fr_savfp;
	uintptr_t	fr_savpc;
};

static void
stack_trace(struct frame *fp, uintptr_t pc)
{
	char buf[80];
	uintptr_t freemem = *(uint16_t *)PTOV(0x413) << 10;
	uintptr_t stack_start;

	/*
	 * stack start is at freemem - __base - ARGSPACE.
	 */
	stack_start = (uintptr_t)PTOV(freemem - ARGSPACE);

	printf("Stack trace:\n");
	pager_open();
	while (fp != NULL || pc != 0) {
		struct frame *nfp;

		(void) snprintf(buf, sizeof (buf),
		    "FP 0x%08x: loader PC 0x%08x\n",
		    (uintptr_t)fp, pc);
		if (pager_output(buf))
			break;

		if (fp == NULL)
			break;

		nfp = fp->fr_savfp;
		if (nfp != NULL && nfp <= fp) {
			printf("FP 0x%08x: loop detected, stopping trace\n",
			    (uintptr_t)nfp);
			break;
		}
		fp = nfp;
		if ((char *)fp < _end ||
		    (uintptr_t)fp + sizeof (*fp) > stack_start)
			break;

		pc = fp->fr_savpc;
	}
	pager_close();
}

void
panic_action(void)
{
	struct frame *fp;
	uintptr_t eip;

	__asm __volatile("movl %%ebp,%0" : "=r" (fp));

	if (fp != NULL) {
		eip = fp->fr_savpc;
		stack_trace(fp, eip);
	}
	printf("--> Press a key on the console to reboot <--\n");
	getchar();
	printf("Rebooting...\n");
	exit(1);
}
