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
#include <sys/fs/udf_volume.h>
#include "ud_lib.h"


extern int optind;

static int verbose;

static int check_if_udfs(int32_t);
static int print_vds(struct vds *, int32_t);

int
main(int argc, char **argv)
{
	int errflag = 0, c, rval, fd;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "v")) != EOF) {
		switch (c) {
			case 'v':
				verbose++;
				break;
			default:
				errflag++;
				break;
		}
	}

	if (errflag || (argc <= optind)) {
		(void) fprintf(stderr,
			gettext("Usage: fstyp -v special\n"));
		exit(1);
	}

	if ((fd = ud_open_dev(argv[optind], O_RDONLY)) < 0) {
		(void) fprintf(stderr,
			gettext("udfs fstyp: cannot open <%s> errorno <%d>\n"),
					argv[optind], errno);
		exit(1);
	}

	/*
	 * check the volume
	 */
	rval = check_if_udfs(fd);

	ud_close_dev(fd);

	return (rval);
}


/*
 * Assumption is that we will confirm to level-1
 */
int
check_if_udfs(int32_t fd)
{
	int32_t ret;

	if ((ret = ud_fill_udfs_info(fd)) != 0) {
		return (ret);
	}

	if ((udfs.flags & VALID_UDFS) == 0) {
		return (1);
	}

	(void) fprintf(stdout, "udfs\n");

	if (verbose == 0) {
		return (0);
	}

	(void) fprintf(stdout,
		"Standard Identifier %5s\n", udfs.ecma_id);

	if (udfs.flags & VALID_MVDS) {
		ret = print_vds(&udfs.mvds, fd);
	} else {
		ret = print_vds(&udfs.rvds, fd);
	}

	return (ret);
}

int
print_vds(struct vds *v, int32_t fd)
{
	int32_t i;
	uint32_t len;
	uint64_t off;
	uint8_t *buf;

	/*
	 * All descriptors are 512 bytes
	 * except lvd, usd and lvid
	 * findout the largest and allocate space
	 */
	len = udfs.lbsize;
	if (v->lvd_len > len) {
		len = v->lvd_len;
	}
	if (v->usd_len > len) {
		len = v->usd_len;
	}
	if (udfs.lvid_len > len) {
		len = udfs.lvid_len;
	}

	if ((buf = (uint8_t *)malloc(len)) == NULL) {
		return (1);
	}

	/*
	 * Anchor Volume Descriptor
	 */
	if (udfs.avdp_len != 0) {
		off = udfs.avdp_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf, udfs.avdp_len) != 0) {
			return (2);
		}

		/* LINTED */
		print_avd((struct anch_vol_desc_ptr *)buf);
	}

	/*
	 * Primary Volume Descriptor
	 */
	if (v->pvd_len != 0) {
		off = v->pvd_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf, v->pvd_len) != 0) {
			return (3);
		}

		/* LINTED */
		print_pvd((struct pri_vol_desc *)buf);
	}

	/*
	 * Implementation Use descriptor
	 */
	if (v->iud_len != 0) {
		off = v->iud_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf, v->iud_len) != 0) {
			return (3);
		}

		/* LINTED */
		print_iuvd((struct iuvd_desc *)buf);
	}

	/*
	 * Paritions
	 */
	for (i = 0; i < n_parts; i++) {
		if (v->part_len[i] != 0) {
			off = v->part_loc[i] * udfs.lbsize;
			if (ud_read_dev(fd, off, buf, v->part_len[i]) != 0) {
				return (3);
			}

			/* LINTED */
			print_part((struct part_desc *)buf);
		}
	}

	/*
	 * Logical Volume Descriptor
	 */
	if (v->lvd_len != 0) {
		off = v->lvd_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf, v->lvd_len) != 0) {
			return (3);
		}

		/* LINTED */
		print_lvd((struct log_vol_desc *)buf);
	}

	/*
	 * Unallocated Space Descriptor
	 */
	if (v->usd_len != 0) {
		off = v->usd_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf, v->usd_len) != 0) {
			return (3);
		}

		/* LINTED */
		print_usd((struct unall_spc_desc *)buf);
	}

	/*
	 * Logical Volume Integrity Descriptor
	 */
	if (udfs.lvid_len != 0) {
		off = udfs.lvid_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf, udfs.lvid_len) != 0) {
			return (3);
		}

		/* LINTED */
		print_lvid((struct log_vol_int_desc *)buf);
	}

	/*
	 * File Set Descriptor
	 */
	if (udfs.fsd_len != 0) {
		off = udfs.fsd_loc * udfs.lbsize;
		if (ud_read_dev(fd, off, buf, udfs.fsd_len) != 0) {
			return (3);
		}

		/* LINTED */
		print_fsd((struct file_set_desc *)buf);
	}

	return (0);
}
