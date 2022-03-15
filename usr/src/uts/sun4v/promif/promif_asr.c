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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/promif_impl.h>

/*
 * The Automatic System Recovery (ASR) database present in some
 * versions of firmware is not supported on sun4v platforms.
 * However, there is an external interface to these prom interfaces
 * from the openprom(4D) driver. They are not documented in the
 * man page, but they should still be handled here, just enough
 * so the user gets a sensible error back if they stumble onto
 * them.
 */

int
promif_asr_list_keys_len(void *p)
{
	cell_t	*ci = (cell_t *)p;

	ci[3] = p1275_int2cell(-1);

	return (-1);
}

int
promif_asr_list_keys(void *p)
{
	_NOTE(ARGUNUSED(p))

	return (-1);
}

int
promif_asr_export_len(void *p)
{
	cell_t	*ci = (cell_t *)p;

	ci[3] = p1275_int2cell(-1);

	return (-1);
}

int
promif_asr_export(void *p)
{
	_NOTE(ARGUNUSED(p))

	return (-1);
}
