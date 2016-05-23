/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "sfxge.h"

void
sfxge_sram_init(sfxge_t *sp)
{
	sfxge_sram_t *ssp = &(sp->s_sram);
	dev_info_t *dip = sp->s_dip;
	char name[MAXNAMELEN];

	ASSERT3U(ssp->ss_state, ==, SFXGE_SRAM_UNINITIALIZED);

	mutex_init(&(ssp->ss_lock), NULL, MUTEX_DRIVER, NULL);

	(void) snprintf(name, MAXNAMELEN - 1, "%s%d_sram", ddi_driver_name(dip),
	    ddi_get_instance(dip));
	ssp->ss_buf_tbl_map = rmallocmap_wait(EFX_BUF_TBL_SIZE);
	rmfree(ssp->ss_buf_tbl_map, EFX_BUF_TBL_SIZE - 1, 1);
	ssp->ss_state = SFXGE_SRAM_INITIALIZED;
}

int
sfxge_sram_buf_tbl_alloc(sfxge_t *sp, size_t n, uint32_t *idp)
{
	sfxge_sram_t *ssp = &(sp->s_sram);
	unsigned long id;
	int rc;

	mutex_enter(&(ssp->ss_lock));

	ASSERT(ssp->ss_state != SFXGE_SRAM_UNINITIALIZED);

	if ((id = rmalloc(ssp->ss_buf_tbl_map, n)) == 0) {
		rc = ENOSPC;
		goto fail1;
	}
	*idp = (uint32_t)id - 1;
	mutex_exit(&(ssp->ss_lock));

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(ssp->ss_lock));

	return (rc);
}

int
sfxge_sram_start(sfxge_t *sp)
{
	sfxge_sram_t *ssp = &(sp->s_sram);

	mutex_enter(&(ssp->ss_lock));

	ASSERT3U(ssp->ss_state, ==, SFXGE_SRAM_INITIALIZED);
	ASSERT3U(ssp->ss_count, ==, 0);

	ssp->ss_state = SFXGE_SRAM_STARTED;

	mutex_exit(&(ssp->ss_lock));

	return (0);
}

int
sfxge_sram_buf_tbl_set(sfxge_t *sp, uint32_t id, efsys_mem_t *esmp,
    size_t n)
{
	sfxge_sram_t *ssp = &(sp->s_sram);
	int rc;

	mutex_enter(&(ssp->ss_lock));

	ASSERT3U(ssp->ss_state, ==, SFXGE_SRAM_STARTED);

	if ((rc = efx_sram_buf_tbl_set(sp->s_enp, id, esmp, n)) != 0)
		goto fail1;

	ssp->ss_count += n;

	mutex_exit(&(ssp->ss_lock));

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(ssp->ss_lock));

	return (rc);
}

void
sfxge_sram_buf_tbl_clear(sfxge_t *sp, uint32_t id, size_t n)
{
	sfxge_sram_t *ssp = &(sp->s_sram);

	mutex_enter(&(ssp->ss_lock));

	ASSERT3U(ssp->ss_state, ==, SFXGE_SRAM_STARTED);

	ASSERT3U(ssp->ss_count, >=, n);
	ssp->ss_count -= n;

	efx_sram_buf_tbl_clear(sp->s_enp, id, n);

	mutex_exit(&(ssp->ss_lock));
}

void
sfxge_sram_stop(sfxge_t *sp)
{
	sfxge_sram_t *ssp = &(sp->s_sram);

	mutex_enter(&(ssp->ss_lock));

	ASSERT3U(ssp->ss_state, ==, SFXGE_SRAM_STARTED);
	ASSERT3U(ssp->ss_count, ==, 0);

	ssp->ss_state = SFXGE_SRAM_INITIALIZED;

	mutex_exit(&(ssp->ss_lock));
}

void
sfxge_sram_buf_tbl_free(sfxge_t *sp, uint32_t id, size_t n)
{
	sfxge_sram_t *ssp = &(sp->s_sram);

	mutex_enter(&(ssp->ss_lock));

	ASSERT(ssp->ss_state != SFXGE_SRAM_UNINITIALIZED);

	rmfree(ssp->ss_buf_tbl_map, n, (unsigned long)id + 1);

	mutex_exit(&(ssp->ss_lock));
}

void
sfxge_sram_fini(sfxge_t *sp)
{
	sfxge_sram_t *ssp = &(sp->s_sram);

	ASSERT3U(ssp->ss_state, ==, SFXGE_SRAM_INITIALIZED);

	rmfreemap(ssp->ss_buf_tbl_map);
	ssp->ss_buf_tbl_map = NULL;

	mutex_destroy(&(ssp->ss_lock));

	ssp->ss_state = SFXGE_SRAM_UNINITIALIZED;
}
