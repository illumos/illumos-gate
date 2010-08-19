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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_BBLKEINFO_H
#define	_BBLKEINFO_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <md5.h>

#define	BBLK_EINFO_VERSION	(1)

#define	EINFO_MAGIC		"EXTINFO"
#define	EINFO_MAGIC_SIZE	(7)

#pragma pack(1)
typedef struct _extended_info {
	char		magic[EINFO_MAGIC_SIZE];
	uint8_t		version;
	uint8_t		flags;
	uint32_t	str_off;
	uint16_t	str_size;
	uint8_t		hash_type;
	uint32_t	hash_off;
	uint16_t	hash_size;
	char		rsvd[32];
} bblk_einfo_t;
#pragma pack()

enum bblk_hash_types_t {
	BBLK_NO_HASH = 0,
	BBLK_HASH_MD5,
	BBLK_HASH_TOT
};

#define	EINFO_PRINT_HEADER	0x01
#define	EINFO_EASY_PARSE	0x02

typedef struct _hashing_function {
	unsigned int	type;
	unsigned int	size;
	char		name[16];
	void 		(*compute_hash)(void *, const void *, unsigned int);
} bblk_hash_t;

typedef struct _hashing_source {
	unsigned char	*src_buf;
	unsigned int	src_size;
} bblk_hs_t;

#define	BBLK_DEFAULT_HASH	BBLK_HASH_MD5

extern bblk_hash_t	bblk_no_hash;
extern bblk_hash_t	bblk_md5_hash;
extern bblk_hash_t	*bblk_hash_list[BBLK_HASH_TOT];

void print_einfo(uint8_t, bblk_einfo_t *, unsigned long);
int prepare_and_write_einfo(unsigned char *, char *, bblk_hs_t *,
    uint32_t, uint32_t *);
boolean_t einfo_should_update(bblk_einfo_t *, bblk_hs_t *, char *);
char *einfo_get_string(bblk_einfo_t *);
char *einfo_get_hash(bblk_einfo_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _BBLKEINFO_H */
