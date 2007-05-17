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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBFRUP_H
#define	_LIBFRUP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>

#include "libfru.h"
#include "../../libfruutils/fru_tag.h"

typedef uint64_t fru_seghdl_t;
typedef enum {FRU_ENCRYPT, FRU_DECRYPT} fru_encrypt_t;
typedef fru_errno_t
(*fru_encrypt_func_t)(fru_encrypt_t en_dec, unsigned char *buf, size_t buf_len);

/*
 * Type for pointers to functions for terminating the processing of a node
 * (after its children have been processed)
 */
typedef void	(*end_node_fp_t)(fru_nodehdl_t node, const char *path,
					const char *name, void *args);

/*
 * Project-private exported symbols
 */
extern	fru_encrypt_func_t encrypt_func;

extern	fru_errno_t fru_encryption_supported(void);

extern	fru_errno_t fru_walk_tree(fru_nodehdl_t node, const char *prior_path,
		fru_errno_t (*process_node)(fru_nodehdl_t node,
						const char *path,
						const char *name, void *args,
						end_node_fp_t *end_node,
						void **end_args),
		void *args);

extern	int fru_pathmatch(const char *path, const char *searchpath);

extern	fru_errno_t fru_for_each_segment(fru_nodehdl_t node,
					int (*function)(fru_seghdl_t segment,
						void *args),
					void *args);
extern	fru_errno_t fru_get_segment_name(fru_seghdl_t segment, char **name);
extern	fru_errno_t fru_for_each_packet(fru_seghdl_t segment,
				int (*function)(fru_tag_t *tag,
						uint8_t *payload,
						size_t length, void *args),
				void *args);

#ifdef __cplusplus
}
#endif

#endif /* _LIBFRUP_H */
