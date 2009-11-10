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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	_FRU_TAG_H
#define	_FRU_TAG_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_LITTLE_ENDIAN)

typedef union {
	uint64_t raw_data;
	unsigned char byte[8];
	struct {
		unsigned pl_len : 3;
		unsigned dense : 4;
		unsigned type : 1;
	} a;
	struct {
		unsigned pl_len : 3;
		unsigned dense : 11;
		unsigned type : 2;
	} b;
	struct {
		unsigned pl_len : 5;
		unsigned dense : 8;
		unsigned type : 3;
	} c;
	struct {
		unsigned pl_len : 3;
		unsigned dense : 17;
		unsigned type : 4;
	} d;
	struct {
		unsigned pl_len : 7;
		unsigned dense : 12;
		unsigned type : 5;
	} e;
	struct {
		unsigned pl_len : 12;
		unsigned dense : 14;
		unsigned type : 6;
	} f;
	struct {
		unsigned pl_len : 32;
		unsigned dense : 9;
		unsigned type : 7;
	} g;
} fru_tag_t;

#else

typedef union {
	uint64_t raw_data;
	char byte[8];
	struct {
		unsigned type : 1;
		unsigned dense : 4;
		unsigned pl_len : 3;
	} a;
	struct {
		unsigned type : 2;
		unsigned dense : 11;
		unsigned pl_len : 3;
	} b;
	struct {
		unsigned type : 3;
		unsigned dense : 8;
		unsigned pl_len : 5;
	} c;
	struct {
		unsigned type : 4;
		unsigned dense : 17;
		unsigned pl_len : 3;
	} d;
	struct {
		unsigned type : 5;
		unsigned dense : 12;
		unsigned pl_len : 7;
	} e;
	struct {
		unsigned type : 6;
		unsigned dense : 14;
		unsigned pl_len : 12;
	} f;
	struct {
		unsigned type : 7;
		unsigned dense : 9;
		unsigned pl_len : 32;
	} g;
} fru_tag_t;

#endif  /* LITTLE_ENDIAN */

#define	FRU_ID_MASK 0xFF
#define	FRU_A_ID 0x00
#define	FRU_B_ID 0x02
#define	FRU_C_ID 0x06
#define	FRU_D_ID 0x0E
#define	FRU_E_ID 0x1E
#define	FRU_F_ID 0x3E
#define	FRU_G_ID 0x7E

typedef enum { FRU_A = 0x00, FRU_B = 0x80, FRU_C = 0xc0,
		FRU_D = 0xe0, FRU_E = 0xf0, FRU_F = 0xf8,
		FRU_G = 0xfc, FRU_X = 0xfe } fru_tagtype_t;
char *get_tagtype_str(fru_tagtype_t e);
size_t get_tag_size(fru_tagtype_t tag);

/* Returns -1 on error */
int mk_tag(fru_tagtype_t type, uint32_t dense, size_t pl_len,
		fru_tag_t *tag);

fru_tagtype_t get_tag_type(fru_tag_t *tag);
uint32_t get_tag_dense(fru_tag_t *tag);
size_t get_payload_length(fru_tag_t *tag);

/* Returns 1 if equal, 0 if not */
int tags_equal(fru_tag_t t1, fru_tag_t t2);

#ifdef	__cplusplus
}
#endif

#endif /* _FRU_TAG_H */
