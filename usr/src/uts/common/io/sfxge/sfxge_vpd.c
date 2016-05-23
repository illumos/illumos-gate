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
#include <sys/kmem.h>
#include "sfxge.h"


static int
sfxge_vpd_get_keyword(sfxge_t *sp, sfxge_vpd_ioc_t *svip)
{
	efx_nic_t *enp = sp->s_enp;
	efx_vpd_value_t vpd;
	size_t size;
	void *buf;
	int rc;

	if ((rc = efx_vpd_size(enp, &size)) != 0)
		goto fail1;

	buf = kmem_zalloc(size, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	if ((rc = efx_vpd_read(enp, buf, size)) != 0)
		goto fail2;

	if ((rc = efx_vpd_verify(enp, buf, size)) != 0)
		goto fail3;

	vpd.evv_tag = svip->svi_tag;
	vpd.evv_keyword = svip->svi_keyword;

	if ((rc = efx_vpd_get(enp, buf, size, &vpd)) != 0)
		goto fail4;

	svip->svi_len = vpd.evv_length;
	EFX_STATIC_ASSERT(sizeof (svip->svi_payload) == sizeof (vpd.evv_value));
	bcopy(&vpd.evv_value[0], svip->svi_payload, sizeof (svip->svi_payload));

	kmem_free(buf, size);

	return (0);

fail4:
	DTRACE_PROBE(fail4);
fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
	kmem_free(buf, size);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}


static int
sfxge_vpd_set_keyword(sfxge_t *sp, sfxge_vpd_ioc_t *svip)
{
	efx_nic_t *enp = sp->s_enp;
	efx_vpd_value_t vpd;
	size_t size;
	void *buf;
	int rc;

	/* restriction on writable tags is in efx_vpd_hunk_set() */

	if ((rc = efx_vpd_size(enp, &size)) != 0)
		goto fail1;

	buf = kmem_zalloc(size, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	if ((rc = efx_vpd_read(enp, buf, size)) != 0)
		goto fail2;

	if ((rc = efx_vpd_verify(enp, buf, size)) != 0) {
		if ((rc = efx_vpd_reinit(enp, buf, size)) != 0)
			goto fail3;
		if ((rc = efx_vpd_verify(enp, buf, size)) != 0)
			goto fail4;
	}

	vpd.evv_tag = svip->svi_tag;
	vpd.evv_keyword = svip->svi_keyword;
	vpd.evv_length = svip->svi_len;

	EFX_STATIC_ASSERT(sizeof (svip->svi_payload) == sizeof (vpd.evv_value));
	bcopy(svip->svi_payload, &vpd.evv_value[0], sizeof (svip->svi_payload));

	if ((rc = efx_vpd_set(enp, buf, size, &vpd)) != 0)
		goto fail5;

	if ((rc = efx_vpd_verify(enp, buf, size)) != 0)
			goto fail6;

	/* And write the VPD back to the hardware */
	if ((rc = efx_vpd_write(enp, buf, size)) != 0)
		goto fail7;

	kmem_free(buf, size);

	return (0);

fail7:
	DTRACE_PROBE(fail7);
fail6:
	DTRACE_PROBE(fail6);
fail5:
	DTRACE_PROBE(fail5);
fail4:
	DTRACE_PROBE(fail4);
fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
	kmem_free(buf, size);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}


int
sfxge_vpd_ioctl(sfxge_t *sp, sfxge_vpd_ioc_t *svip)
{
	int rc;

	switch (svip->svi_op) {
	case SFXGE_VPD_OP_GET_KEYWORD:
		if ((rc = sfxge_vpd_get_keyword(sp, svip)) != 0)
			goto fail1;
		break;
	case SFXGE_VPD_OP_SET_KEYWORD:
		if ((rc = sfxge_vpd_set_keyword(sp, svip)) != 0)
			goto fail1;
		break;
	default:
		rc = EINVAL;
		goto fail2;
	}

	return (0);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}
