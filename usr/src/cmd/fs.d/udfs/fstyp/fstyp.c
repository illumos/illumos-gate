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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * libfstyp module for udfs
 */
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <locale.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <libnvpair.h>
#include <libfstyp_module.h>
#include <sys/fs/udf_volume.h>
#include "ud_lib.h"


typedef struct fstyp_udfs {
	int		fd;
	ud_handle_t	udh;
	nvlist_t	*attr;
} fstyp_udfs_t;

static int	is_udfs(fstyp_udfs_t *h);
static int	print_vds(fstyp_udfs_t *h, struct vds *,
		FILE *fout, FILE *ferr);
static int	get_attr(fstyp_udfs_t *h);

int	fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle);
void	fstyp_mod_fini(fstyp_mod_handle_t handle);
int	fstyp_mod_ident(fstyp_mod_handle_t handle);
int	fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp);
int	fstyp_mod_dump(fstyp_mod_handle_t handle, FILE *fout, FILE *ferr);


int
fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle)
{
	fstyp_udfs_t *h = (fstyp_udfs_t *)handle;

	if (offset != 0) {
		return (FSTYP_ERR_OFFSET);
	}

	if ((h = calloc(1, sizeof (fstyp_udfs_t))) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}
	h->fd = fd;

	if (ud_init(h->fd, &h->udh) != 0) {
		free(h);
		return (FSTYP_ERR_NOMEM);
	}

	*handle = (fstyp_mod_handle_t)h;
	return (0);
}

void
fstyp_mod_fini(fstyp_mod_handle_t handle)
{
	fstyp_udfs_t *h = (fstyp_udfs_t *)handle;

	if (h->attr == NULL) {
		nvlist_free(h->attr);
		h->attr = NULL;
	}
	ud_fini(h->udh);
	free(h);
}

int
fstyp_mod_ident(fstyp_mod_handle_t handle)
{
	fstyp_udfs_t *h = (fstyp_udfs_t *)handle;

	return (is_udfs(h));
}

int
fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp)
{
	fstyp_udfs_t *h = (fstyp_udfs_t *)handle;
	int error;

	if (h->attr == NULL) {
		if (nvlist_alloc(&h->attr, NV_UNIQUE_NAME_TYPE, 0)) {
			return (FSTYP_ERR_NOMEM);
		}
		if ((error = get_attr(h)) != 0) {
			nvlist_free(h->attr);
			h->attr = NULL;
			return (error);
		}
	}

	*attrp = h->attr;
	return (0);
}

int
fstyp_mod_dump(fstyp_mod_handle_t handle, FILE *fout, FILE *ferr)
{
	fstyp_udfs_t *h = (fstyp_udfs_t *)handle;
	struct udf *udfs = &h->udh->udfs;
	int ret;

	(void) fprintf(fout,
		"Standard Identifier %5s\n", udfs->ecma_id);

	if (udfs->flags & VALID_MVDS) {
		ret = print_vds(h, &udfs->mvds, fout, ferr);
	} else {
		ret = print_vds(h, &udfs->rvds, fout, ferr);
	}

	return (ret);
}


/*
 * Assumption is that we will confirm to level-1
 */
int
is_udfs(fstyp_udfs_t *h)
{
	struct udf *udfs = &h->udh->udfs;
	int32_t ret;

	if ((ret = ud_fill_udfs_info(h->udh)) != 0) {
		return (ret);
	}

	if ((udfs->flags & VALID_UDFS) == 0) {
		return (FSTYP_ERR_NO_MATCH);
	}

	return (0);
}

/*
 * For now, only return generic attributes.
 * Will open an RFE to add native attributes.
 */
static int
get_attr(fstyp_udfs_t *h)
{
	struct udf *udfs = &h->udh->udfs;
	struct vds *v;
	struct pri_vol_desc *pvd;
	uint32_t len;
	uint64_t off;
	uint8_t *buf;
	int8_t str[64];
	int ret = 0;

	v = (udfs->flags & VALID_MVDS) ? &udfs->mvds : &udfs->rvds;

	/* allocate buffer */
	len = udfs->lbsize;
	if (v->pvd_len > len) {
		len = v->pvd_len;
	}
	if ((buf = (uint8_t *)malloc(len)) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}

	(void) nvlist_add_boolean_value(h->attr, "gen_clean", B_TRUE);

	/* Primary Volume Descriptor */
	if (v->pvd_len != 0) {
		off = v->pvd_loc * udfs->lbsize;
		if (ud_read_dev(h->udh, off, buf, v->pvd_len) != 0) {
			ret = FSTYP_ERR_IO;
			goto out;
		}
		/* LINTED */
		pvd = (struct pri_vol_desc *)(uint32_t *)buf;

		ud_convert2local(pvd->pvd_vol_id, str, 32);
		str[32] = '\0';
		(void) nvlist_add_string(h->attr, "gen_volume_label", str);
	}

	ret = 0;

out:
	free(buf);
	return (ret);
}

/* ARGSUSED */
int
print_vds(fstyp_udfs_t *h, struct vds *v, FILE *fout, FILE *ferr)
{
	struct udf *udfs = &h->udh->udfs;
	int32_t i;
	uint32_t len;
	uint64_t off;
	uint8_t *buf;
	int	ret = 0;

	/*
	 * All descriptors are 512 bytes
	 * except lvd, usd and lvid
	 * findout the largest and allocate space
	 */
	len = udfs->lbsize;
	if (v->lvd_len > len) {
		len = v->lvd_len;
	}
	if (v->usd_len > len) {
		len = v->usd_len;
	}
	if (udfs->lvid_len > len) {
		len = udfs->lvid_len;
	}

	if ((buf = (uint8_t *)malloc(len)) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}

	/*
	 * Anchor Volume Descriptor
	 */
	if (udfs->avdp_len != 0) {
		off = udfs->avdp_loc * udfs->lbsize;
		if (ud_read_dev(h->udh, off, buf, udfs->avdp_len) != 0) {
			ret = FSTYP_ERR_IO;
			goto out;
		}

		/* LINTED */
		print_avd(fout, (struct anch_vol_desc_ptr *)buf);
	}

	/*
	 * Primary Volume Descriptor
	 */
	if (v->pvd_len != 0) {
		off = v->pvd_loc * udfs->lbsize;
		if (ud_read_dev(h->udh, off, buf, v->pvd_len) != 0) {
			ret = FSTYP_ERR_IO;
			goto out;
		}

		/* LINTED */
		print_pvd(fout, (struct pri_vol_desc *)buf);
	}

	/*
	 * Implementation Use descriptor
	 */
	if (v->iud_len != 0) {
		off = v->iud_loc * udfs->lbsize;
		if (ud_read_dev(h->udh, off, buf, v->iud_len) != 0) {
			ret = FSTYP_ERR_IO;
			goto out;
		}

		/* LINTED */
		print_iuvd(fout, (struct iuvd_desc *)buf);
	}

	/*
	 * Paritions
	 */
	for (i = 0; i < h->udh->n_parts; i++) {
		if (v->part_len[i] != 0) {
			off = v->part_loc[i] * udfs->lbsize;
			if (ud_read_dev(h->udh, off, buf,
			    v->part_len[i]) != 0) {
				ret = FSTYP_ERR_IO;
				goto out;
			}

			/* LINTED */
			print_part(fout, (struct part_desc *)buf);
		}
	}

	/*
	 * Logical Volume Descriptor
	 */
	if (v->lvd_len != 0) {
		off = v->lvd_loc * udfs->lbsize;
		if (ud_read_dev(h->udh, off, buf, v->lvd_len) != 0) {
			ret = FSTYP_ERR_IO;
			goto out;
		}

		/* LINTED */
		print_lvd(fout, (struct log_vol_desc *)buf);
	}

	/*
	 * Unallocated Space Descriptor
	 */
	if (v->usd_len != 0) {
		off = v->usd_loc * udfs->lbsize;
		if (ud_read_dev(h->udh, off, buf, v->usd_len) != 0) {
			ret = FSTYP_ERR_IO;
			goto out;
		}

		/* LINTED */
		print_usd(fout, (struct unall_spc_desc *)buf);
	}

	/*
	 * Logical Volume Integrity Descriptor
	 */
	if (udfs->lvid_len != 0) {
		off = udfs->lvid_loc * udfs->lbsize;
		if (ud_read_dev(h->udh, off, buf, udfs->lvid_len) != 0) {
			ret = FSTYP_ERR_IO;
			goto out;
		}

		/* LINTED */
		print_lvid(fout, (struct log_vol_int_desc *)buf);
	}

	/*
	 * File Set Descriptor
	 */
	if (udfs->fsd_len != 0) {
		off = udfs->fsd_loc * udfs->lbsize;
		if (ud_read_dev(h->udh, off, buf, udfs->fsd_len) != 0) {
			ret = FSTYP_ERR_IO;
			goto out;
		}

		/* LINTED */
		print_fsd(fout, h->udh, (struct file_set_desc *)buf);
	}
	ret = 0;

out:
	free(buf);
	return (ret);
}
