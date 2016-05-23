/*
 * Copyright (c) 2009-2016 Solarflare Communications Inc.
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
#include <sys/stream.h>
#include <sys/dlpi.h>

#include "sfxge.h"

static int
sfxge_nvram_rw(sfxge_t *sp, sfxge_nvram_ioc_t *snip, efx_nvram_type_t type,
    boolean_t write)
{
	int (*op)(efx_nic_t *, efx_nvram_type_t, unsigned int, caddr_t, size_t);
	efx_nic_t *enp = sp->s_enp;
	size_t chunk_size;
	off_t off;
	int rc;

	op = (write) ? efx_nvram_write_chunk : efx_nvram_read_chunk;

	if ((rc = efx_nvram_rw_start(enp, type, &chunk_size)) != 0)
		goto fail1;

	off = 0;
	while (snip->sni_size) {
		size_t len = MIN(chunk_size, snip->sni_size);
		caddr_t buf = (caddr_t)(&snip->sni_data[off]);

		if ((rc = op(enp, type, snip->sni_offset + off, buf, len)) != 0)
			goto fail2;

		snip->sni_size -= len;
		off += len;
	}

	efx_nvram_rw_finish(enp, type);
	return (0);

fail2:
	DTRACE_PROBE(fail2);
	efx_nvram_rw_finish(enp, type);
fail1:
	DTRACE_PROBE1(fail1, int, rc);
	return (rc);
}


static int
sfxge_nvram_erase(sfxge_t *sp, sfxge_nvram_ioc_t *snip, efx_nvram_type_t type)
{
	efx_nic_t *enp = sp->s_enp;
	size_t chunk_size;
	int rc;
	_NOTE(ARGUNUSED(snip));

	if ((rc = efx_nvram_rw_start(enp, type, &chunk_size)) != 0)
		goto fail1;

	if ((rc = efx_nvram_erase(enp, type)) != 0)
		goto fail2;

	efx_nvram_rw_finish(enp, type);
	return (0);

fail2:
	DTRACE_PROBE(fail2);
	efx_nvram_rw_finish(enp, type);
fail1:
	DTRACE_PROBE1(fail1, int, rc);
	return (rc);
}

int
sfxge_nvram_ioctl(sfxge_t *sp, sfxge_nvram_ioc_t *snip)
{
	efx_nic_t *enp = sp->s_enp;
	efx_nvram_type_t type;
	int rc;

	switch (snip->sni_type) {
	case SFXGE_NVRAM_TYPE_BOOTROM:
		type = EFX_NVRAM_BOOTROM;
		break;
	case SFXGE_NVRAM_TYPE_BOOTROM_CFG:
		type = EFX_NVRAM_BOOTROM_CFG;
		break;
	case SFXGE_NVRAM_TYPE_MC:
		type = EFX_NVRAM_MC_FIRMWARE;
		break;
	case SFXGE_NVRAM_TYPE_MC_GOLDEN:
		type = EFX_NVRAM_MC_GOLDEN;
		if (snip->sni_op == SFXGE_NVRAM_OP_WRITE ||
		    snip->sni_op == SFXGE_NVRAM_OP_ERASE ||
		    snip->sni_op == SFXGE_NVRAM_OP_SET_VER) {
			rc = ENOTSUP;
			goto fail1;
		}
		break;
	case SFXGE_NVRAM_TYPE_PHY:
		type = EFX_NVRAM_PHY;
		break;
	case SFXGE_NVRAM_TYPE_NULL_PHY:
		type = EFX_NVRAM_NULLPHY;
		break;
	case SFXGE_NVRAM_TYPE_FPGA: /* PTP timestamping FPGA */
		type = EFX_NVRAM_FPGA;
		break;
	case SFXGE_NVRAM_TYPE_FCFW:
		type = EFX_NVRAM_FCFW;
		break;
	case SFXGE_NVRAM_TYPE_CPLD:
		type = EFX_NVRAM_CPLD;
		break;
	case SFXGE_NVRAM_TYPE_FPGA_BACKUP:
		type = EFX_NVRAM_FPGA_BACKUP;
		break;
	case SFXGE_NVRAM_TYPE_DYNAMIC_CFG:
		type = EFX_NVRAM_DYNAMIC_CFG;
		break;
	default:
		rc = EINVAL;
		goto fail2;
	}

	if (snip->sni_size > sizeof (snip->sni_data)) {
		rc = ENOSPC;
		goto fail3;
	}

	switch (snip->sni_op) {
	case SFXGE_NVRAM_OP_SIZE:
	{
		size_t size;
		if ((rc = efx_nvram_size(enp, type, &size)) != 0)
			goto fail4;
		snip->sni_size = (uint32_t)size;
		break;
	}
	case SFXGE_NVRAM_OP_READ:
		if ((rc = sfxge_nvram_rw(sp, snip, type, B_FALSE)) != 0)
			goto fail4;
		break;
	case SFXGE_NVRAM_OP_WRITE:
		if ((rc = sfxge_nvram_rw(sp, snip, type, B_TRUE)) != 0)
			goto fail4;
		break;
	case SFXGE_NVRAM_OP_ERASE:
		if ((rc = sfxge_nvram_erase(sp, snip, type)) != 0)
			goto fail4;
		break;
	case SFXGE_NVRAM_OP_GET_VER:
		if ((rc = efx_nvram_get_version(enp, type, &snip->sni_subtype,
		    &snip->sni_version[0])) != 0)
			goto fail4;
		break;
	case SFXGE_NVRAM_OP_SET_VER:
		if ((rc = efx_nvram_set_version(enp, type,
		    &snip->sni_version[0])) != 0)
			goto fail4;
		break;
	default:
		rc = ENOTSUP;
		goto fail5;
	}

	return (0);

fail5:
	DTRACE_PROBE(fail5);
fail4:
	DTRACE_PROBE(fail4);
fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}
