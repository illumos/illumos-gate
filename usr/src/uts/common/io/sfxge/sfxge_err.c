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

#include "efx.h"

static const char *__sfxge_err[] = {
	"",
	"SRAM out-of-bounds",
	"Buffer ID out-of-bounds",
	"Internal memory parity",
	"Receive buffer ownership",
	"Transmit buffer ownership",
	"Receive descriptor ownership",
	"Transmit descriptor ownership",
	"Event queue ownership",
	"Event queue FIFO overflow",
	"Illegal address",
	"SRAM parity"
};

void
sfxge_err(efsys_identifier_t *arg, unsigned int code, uint32_t dword0,
    uint32_t dword1)
{
	sfxge_t *sp = (sfxge_t *)arg;
	dev_info_t *dip = sp->s_dip;

	ASSERT3U(code, <, EFX_ERR_NCODES);

	dev_err(dip, CE_WARN, SFXGE_CMN_ERR "FATAL ERROR: %s (0x%08x%08x)",
	    __sfxge_err[code], dword1, dword0);
}

void
sfxge_intr_fatal(sfxge_t *sp)
{
	efx_nic_t *enp = sp->s_enp;
	int err;

	efx_intr_disable(enp);
	efx_intr_fatal(enp);

	err = sfxge_restart_dispatch(sp, DDI_NOSLEEP, SFXGE_HW_ERR,
	    "Fatal Interrupt", 0);
	if (err != 0) {
		dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
		    "UNRECOVERABLE ERROR:"
		    " Could not schedule driver restart. err=%d",
		    err);
		ASSERT(B_FALSE);
	}
}
