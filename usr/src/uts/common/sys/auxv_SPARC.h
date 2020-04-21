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

#ifndef	_SYS_AUXV_SPARC_H
#define	_SYS_AUXV_SPARC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Flags used to describe various instruction set extensions available
 * on different SPARC processors.
 *
 * [The first four are legacy descriptions.]
 */
#define	AV_SPARC_MUL32	0x0001	/* 32x32-bit smul/umul is efficient */
#define	AV_SPARC_DIV32	0x0002	/* 32x32-bit sdiv/udiv is efficient */
#define	AV_SPARC_FSMULD	0x0004	/* fsmuld is efficient */
#define	AV_SPARC_V8PLUS	0x0008	/* V9 instructions available to 32-bit apps */
#define	AV_SPARC_POPC	0x0010	/* popc is efficient */
#define	AV_SPARC_VIS	0x0020	/* VIS instruction set supported */
#define	AV_SPARC_VIS2	0x0040	/* VIS2 instruction set supported */
#define	AV_SPARC_ASI_BLK_INIT	0x0080	/* ASI_BLK_INIT_xxx ASI */
#define	AV_SPARC_FMAF	0x0100	/* Fused Multiply-Add */
/* Bit 9 is not in use */
#define	AV_SPARC_VIS3	0x0400  /* VIS3 instruction set extensions */
#define	AV_SPARC_HPC	0x0800  /* High Performance Computing insns */
#define	AV_SPARC_RANDOM	0x1000  /* random instruction */
#define	AV_SPARC_TRANS	0x2000  /* transactions supported */
#define	AV_SPARC_FJFMAU	0x4000	/* Fujitsu Unfused Multiply-Add */
#define	AV_SPARC_IMA	0x8000	/* Integer Multiply-add */
#define	AV_SPARC_ASI_CACHE_SPARING	0x10000
#define	AV_SPARC_PAUSE	0x20000	/* pause instruction */
#define	AV_SPARC_CBCOND	0x40000	/* compare and branch instructions */
#define	AV_SPARC_AES	0x80000	/* AES instructions */
#define	AV_SPARC_DES	0x100000	/* DES instructions */
#define	AV_SPARC_KASUMI	0x200000	/* Kasumi instructions */
#define	AV_SPARC_CAMELLIA	0x400000	/* Camellia instructions */
#define	AV_SPARC_MD5	0x800000	/* MD5 instructions */
#define	AV_SPARC_SHA1	0x1000000	/* SHA1 instructions */
#define	AV_SPARC_SHA256	0x2000000	/* SHA256 instructions */
#define	AV_SPARC_SHA512	0x4000000	/* SHA512 instructions */
#define	AV_SPARC_MPMUL	0x8000000	/* multiple precision multiply */
#define	AV_SPARC_MONT	0x10000000	/* Montgomery mult/sqr instructions */
#define	AV_SPARC_CRC32C	0x20000000	/* CRC32C instructions */

#define	FMT_AV_SPARC	\
	"\20" \
	"\36crc32c\35mont\34mpmul\33sha512\32sha256\31sha1"	\
	"\30md5\27camellia\26kasumi\25des\24aes\23cbcond\22pause\21cspare" \
	"\20ima\17fjfmau\16trans\15random\14hpc\13vis3\12-\11fmaf"	\
	"\10ASIBlkInit\7vis2\6vis\5popc\4v8plus\3fsmuld\2div32\1mul32"

/*
 * compatibility defines: Obsolete
 */
#define	AV_SPARC_HWMUL_32x32	AV_SPARC_MUL32
#define	AV_SPARC_HWDIV_32x32	AV_SPARC_DIV32
#define	AV_SPARC_HWFSMULD	AV_SPARC_FSMULD

#ifdef __cplusplus
}
#endif

#endif	/* !_SYS_AUXV_SPARC_H */
