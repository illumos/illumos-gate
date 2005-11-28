/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer,
 * without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 * similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 * redistribution must be conditioned upon including a substantially
 * similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 * of any contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/varargs.h>
#include "ath_hal.h"
#include "ath_ieee80211.h"
#include "ath_impl.h"

struct ath_halfix {
	void *p;
	size_t size;
	int malloced;
	int freed;
};

static struct ath_halfix ath_halfix[32];

/* HAL layer needs these definitions */
int ath_hal_dma_beacon_response_time = 2;	/* in TU's */
int ath_hal_sw_beacon_response_time = 10;	/* in TU's */
int ath_hal_additional_swba_backoff = 0;	/* in TU's */

/*
 * Print/log message support.
 */

void
ath_hal_printf(struct ath_hal *ah, const char *fmt, ...)
{
	va_list ap;

	_NOTE(ARGUNUSED(ah))
	va_start(ap, fmt);
	vcmn_err(CE_CONT, fmt, ap);
	va_end(ap);
}

/*
 * Delay n microseconds.
 */
void
ath_hal_delay(int n)
{
	drv_usecwait(n);
}

/*
 * ath_hal_malloc() and ath_hal_free() are called
 * within ath_hal.o. We must record the size of
 * the memory alloced, so ath_hal_free() can get
 * the size and then calls kmem_free().
 */
void *
ath_hal_malloc(size_t size)
{
	void *p;
	int i;

	/* support 16 devices(max leakage of one device is 8) */
	for (i = 0; i < 32; i++) {
		if (ath_halfix[i].malloced == 0)
			break;
	}
	if (i >= 32) {
		ath_problem("ath: ath_hal_malloc(): too many malloc\n");
		return (NULL);
	}
	p = kmem_zalloc(size, KM_SLEEP);
	ath_halfix[i].p = p;
	ath_halfix[i].size = size;
	ath_halfix[i].malloced = 1;
	ath_halfix[i].freed = 0;
	ATH_DEBUG((ATH_DBG_OSDEP, "ath: ath_hal_malloc(): "
	    "%d: p=%p, size=%d\n", i, p, size));
	return (p);
}

void
ath_hal_free(void* p)
{
	int i;
	for (i = 0; i < 32; i++) {
		if (ath_halfix[i].p == p)
			break;
	}
	if (i >= 32) {
		ath_problem("ath: ath_hal_free(): no record for %p\n", p);
		return;
	}
	kmem_free(p, ath_halfix[i].size);
	ath_halfix[i].malloced = 0;
	ath_halfix[i].freed = 1;
	ATH_DEBUG((ATH_DBG_OSDEP, "ath: ath_hal_free(): %d: p=%p, size=%d\n",
	    i, p, ath_halfix[i].size));
}

void *
ath_hal_memcpy(void *dst, const void *src, size_t n)
{
	bcopy(src, dst, n);
	return (dst);
}

void
ath_hal_memzero(void *dst, size_t n)
{
	bzero(dst, n);
}

/*
 * So far as I know and test, hal.o has a bug that when attaching,
 * it calls ath_hal_malloc() four times while detaching it calls
 * ath_hal_free() only 3 times, so everytime when a pair of driver
 * load/unload is done, a memory leak occurs. The function
 * free_hal_leaked_mem() just help free the memory that alloced by
 * hal.o but not freed by it. In fact, when attaching, hal.o only
 * call ath_hal_alloc() four times, here assuming a maximum times of
 * 8 just considers some special cases, we have no source after all!
 */
void
ath_halfix_init(void)
{
	int i;

	for (i = 0; i < 32; i++) {
		ath_halfix[i].malloced = 0;
	}
}

void
ath_halfix_finit(void)
{
	int i;

	for (i = 0; i < 32; i++) {
		if ((ath_halfix[i].malloced == 1) &&
		    (ath_halfix[i].freed == 0)) {
			kmem_free(ath_halfix[i].p, ath_halfix[i].size);
		}
	}
}
