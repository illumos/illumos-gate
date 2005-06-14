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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mdb dcmds for selected structures from
 * usr/src/uts/common/sys/crypto/common.h
 */

#include <sys/mdb_modapi.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/crypto/api.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/impl.h>
#include "crypto_cmds.h"

/*ARGSUSED*/
int
crypto_mechanism(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	crypto_mechanism_t mch;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&mch, sizeof (crypto_mechanism_t), addr) == -1) {
		mdb_warn("cannot read %p", addr);
		return (DCMD_ERR);
	}
	/* XXX a future RFE will interpret cm_type */
	mdb_printf("cm_type\t%ll#x\n", mch.cm_type);
	mdb_printf("cm_param\t%p\n", mch.cm_param);
	mdb_printf("cm_param_len\t%u\n", mch.cm_param_len);
	return (DCMD_OK);
}

/*ARGSUSED*/
static void
iovec_prt(iovec_t *addr)
{
	mdb_printf("iov_base\t%p\n", addr->iov_base);
	mdb_printf("iov_len\t\t%d\n", addr->iov_len);
}

/*ARGSUSED*/
static void
uio_prt(uio_t *addr)
{
	char *segstrings[] = {
		"UIO_USERSPACE",
		"UIO_SYSSPACE",
		"UIO_USERISPACE"
	};
	iovec_t iov;
	uio_t uio;
	int i;

	mdb_printf("uio\t%p\n", addr);
	if (mdb_vread(&uio, sizeof (uio_t), (uintptr_t)addr)
		== -1) {
		mdb_warn("uio_prt: could not read uio");
	}
	mdb_inc_indent(4);
	for (i = 0; i < uio.uio_iovcnt; i++) {
		if (mdb_vread(&iov, sizeof (iovec_t),
		    (uintptr_t)(uio.uio_iov +i))
			== -1) {
			mdb_printf("uio_iov\t?????");
			mdb_warn("uio_prt: could not read uio_iov[%s]", i);
		} else
		    iovec_prt(&iov);
	}
	mdb_dec_indent(4);
	mdb_printf("uio_iovcnt\t%d\n", uio.uio_iovcnt);
	mdb_printf("uio_offset\t%lld\n", uio.uio_offset);
	mdb_printf("uio_segflg\t%s", segstrings[uio.uio_segflg]);
	mdb_printf("uio_fmode\t0%o", (int)uio.uio_fmode);
	mdb_printf("uio_limit\t%lld", uio.uio_limit);
	mdb_printf("uio_resid\t%ld", uio.uio_resid);
}

static char *cdstrings[] = {
	"INVALID FORMAT",
	"CRYPTO_DATA_RAW",
	"CRYPTO_DATA_UIO",
	"CRYPTO_DATA_MBLK"
};

/*
 * Routine to print either of two structrually identical sub-structures --
 * with different naming conventions.  Might be changed if we decide
 * to merge the two.  They are the cdu union from crypto_data_t and
 * the one from crypto_dual_data_t.
 */

typedef union crypto_data_union {
	iovec_t	cdu_raw;		/* Raw format */
	uio_t	*cdu_uio;		/* uio scatter-gather format */
	mblk_t	*cdu_mp;		/* The mblk chain */
} crypto_data_union_t;

/*ARGSUSED*/
static void
prt_cdu(crypto_data_union_t *cdu, int format, const char *prefix)
{

	switch (format) {
		case CRYPTO_DATA_RAW:
		    mdb_printf("%s_raw:\n", prefix);
		    mdb_inc_indent(4);
		    iovec_prt(&cdu->cdu_raw);
		    mdb_dec_indent(4);
		    break;

		case CRYPTO_DATA_UIO:
		    mdb_printf("%s_uio:\n", prefix);
		    mdb_inc_indent(4);
		    uio_prt(cdu->cdu_uio);
		    mdb_dec_indent(4);
		    break;

		case CRYPTO_DATA_MBLK:
		    mdb_printf("%s_mp:\t\t%p\n", prefix, cdu->cdu_mp);
		    break;

		default:
		    mdb_printf("cm_format\t??????\n");
		    break;
	}
}

/*ARGSUSED*/
int
crypto_data(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	crypto_data_t data;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&data, sizeof (crypto_data_t), addr) == -1) {
		mdb_warn("cannot read %p", addr);
		return (DCMD_ERR);
	}
	if ((data.cd_format >= CRYPTO_DATA_RAW) &&
	    (data.cd_format <= CRYPTO_DATA_MBLK))
		mdb_printf("cm_format\t%s\n", cdstrings[data.cd_format]);
	else
		mdb_printf("bad cm_format\t%d\n", data.cd_format);
	mdb_printf("cm_offset\t%ld\n", data.cd_offset);
	mdb_printf("cm_length\t%ld\n", data.cd_length);
	mdb_printf("cm_miscdata\t%p\n", data.cd_miscdata);
	mdb_inc_indent(4);
	prt_cdu((crypto_data_union_t *)&data.cdu, data.cd_format, "cdu");
	mdb_dec_indent(4);
	return (DCMD_OK);
}

/*ARGSUSED*/
int
crypto_dual_data(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	crypto_dual_data_t ddata;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&ddata, sizeof (crypto_dual_data_t), addr) == -1) {
		mdb_warn("cannot read %p", addr);
		return (DCMD_ERR);
	}
	if ((ddata.dd_format > CRYPTO_DATA_RAW) &&
	    (ddata.dd_format <= CRYPTO_DATA_MBLK))
		mdb_printf("dd_format\t%s\n", cdstrings[ddata.dd_format]);
	else
		mdb_printf("bad dd_format\t%d\n", ddata.dd_format);
	mdb_printf("dd_offset1\t%ld\n", ddata.dd_offset1);
	mdb_printf("dd_len1\t%ld\n", ddata.dd_len1);
	mdb_printf("dd_offset2\t%ld\n", ddata.dd_offset2);
	mdb_printf("dd_len2\t%ld\n", ddata.dd_len2);
	mdb_printf("dd_miscdata\t%p\n", ddata.dd_miscdata);
	mdb_printf("cdu:\n");
	mdb_inc_indent(4);
	prt_cdu((crypto_data_union_t *)&ddata.dd_data.cdu, ddata.dd_format,
	    "ddu");
	mdb_dec_indent(4);
	return (DCMD_OK);
}


/*ARGSUSED*/
int
crypto_key(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	crypto_key_t key;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&key, sizeof (crypto_key_t), addr) == -1) {
		mdb_warn("cannot read %p", addr);
		return (DCMD_ERR);
	}
	switch (key.ck_format) {
		case CRYPTO_KEY_RAW:
		    mdb_printf("ck_format:\tCRYPTO_KEY_RAW\n");
		    mdb_printf(
			"cku_data.cku_key_value.cku_data.cku_v_length:\t%d\n",
			    key.cku_data.cku_key_value.cku_v_length);
		    mdb_printf("cku_data.cku_key_value.cku_v_data:\t%p\n",
			key.cku_data.cku_key_value.cku_v_data);
		    break;
		case CRYPTO_KEY_REFERENCE:
		    mdb_printf("ck_format:\tCRYPTO_KEY_REFERENCE\n");
		    mdb_printf("cku_data.cku_key_id:\t%u\n",
			key.cku_data.cku_key_id);
		    break;
		case CRYPTO_KEY_ATTR_LIST:
			mdb_printf("ck_format:\tCRYPTO_KEY_ATTR_LIST\n");
			mdb_printf("cku_data.cku_key_attrs.cku_a_count:\t%u\n",
				key.cku_data.cku_key_attrs.cku_a_count);
			mdb_printf("cku_data.cku_key_attrs.cku_o_oattr:\t%p\n",
				key.cku_data.cku_key_attrs.cku_a_oattr);
			break;
		default:
			mdb_printf("ck_format:\t\t?????\n");
			break;
	}
	return (DCMD_OK);
}
