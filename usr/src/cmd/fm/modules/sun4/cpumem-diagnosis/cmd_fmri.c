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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <strings.h>

#include <cmd_fmri.h>
#include <cmd.h>

void
cmd_fmri_init(fmd_hdl_t *hdl, cmd_fmri_t *fmri, nvlist_t *nvl,
    const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	cmd_vbufname(fmri->fmri_packnm, sizeof (fmri->fmri_packnm), fmt, ap);
	va_end(ap);

	if ((errno = nvlist_dup(nvl, &fmri->fmri_nvl, 0)) != 0 ||
	    (errno = nvlist_size(nvl, &fmri->fmri_packsz,
	    NV_ENCODE_NATIVE)) != 0)
		fmd_hdl_abort(hdl, "failed to copy fmri for fmri create");

	fmri->fmri_packbuf = fmd_hdl_alloc(hdl, fmri->fmri_packsz, FMD_SLEEP);

	if ((errno = nvlist_pack(nvl, &fmri->fmri_packbuf, &fmri->fmri_packsz,
	    NV_ENCODE_NATIVE, 0)) != 0)
		fmd_hdl_abort(hdl, "failed to pack fmri for fmri create");

	cmd_fmri_write(hdl, fmri);
}

void
cmd_fmri_fini(fmd_hdl_t *hdl, cmd_fmri_t *fmri, int destroy)
{
	if (destroy)
		fmd_buf_destroy(hdl, NULL, fmri->fmri_packnm);

	fmd_hdl_free(hdl, fmri->fmri_packbuf, fmri->fmri_packsz);
	nvlist_free(fmri->fmri_nvl);
}

void
cmd_fmri_restore(fmd_hdl_t *hdl, cmd_fmri_t *fmri)
{
	if (fmd_buf_size(hdl, NULL, fmri->fmri_packnm) == 0) {
		bzero(fmri, sizeof (cmd_fmri_t));
		return;
	}

	if ((fmri->fmri_packbuf = cmd_buf_read(hdl, NULL, fmri->fmri_packnm,
	    fmri->fmri_packsz)) == NULL) {
		fmd_hdl_abort(hdl, "failed to read fmri buffer %s",
		    fmri->fmri_packnm);
	}

	if (nvlist_unpack(fmri->fmri_packbuf, fmri->fmri_packsz,
	    &fmri->fmri_nvl, 0) != 0) {
		fmd_hdl_abort(hdl, "failed to unpack fmri buffer %s\n",
		    fmri->fmri_packnm);
	}
}

void
cmd_fmri_write(fmd_hdl_t *hdl, cmd_fmri_t *fmri)
{
	size_t sz;

	if ((sz = fmd_buf_size(hdl, NULL, fmri->fmri_packnm)) !=
	    fmri->fmri_packsz && sz != 0)
		fmd_buf_destroy(hdl, NULL, fmri->fmri_packnm);

	fmd_buf_write(hdl, NULL, fmri->fmri_packnm, fmri->fmri_packbuf,
	    fmri->fmri_packsz);
}
