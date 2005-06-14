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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include "libtnf.h"

/*
 * Check a record datum
 */

void
_tnf_check_record(tnf_datum_t datum)
{
	CHECK_DATUM(datum);

	/* All records must be tagged */
	if (!INFO_TAGGED(DATUM_INFO(datum)))
		_tnf_error(DATUM_TNF(datum), TNF_ERR_TYPEMISMATCH);
}

/*
 * Retrieve the tag arg, encoded in low 16 bits of tag word
 */

tnf_datum_t
tnf_get_tag_arg(tnf_datum_t datum)
{
	TNF		*tnf;
	tnf_ref32_t	*arg;

	CHECK_RECORD(datum);

	tnf = DATUM_TNF(datum);

	/* Should not give an error if not found */
	/* LINTED pointer cast may result in improper alignment */
	arg = _tnf_get_tag_arg(tnf, DATUM_RECORD(datum));

	if (arg == TNF_NULL)
		return (TNF_DATUM_NULL);
	else			/* repackage the tag arg with its taginfo */
		return (RECORD_DATUM(tnf, arg));
}
