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

/*
 *
 *                             Start of crcmodel.c
 *
 *
 * Author : Ross Williams (ross@guest.adelaide.edu.au.).
 * Date   : 3 June 1993.
 * Status : Public domain.
 *
 * Description : This is the implementation (.c) file for the reference
 * implementation of the Rocksoft^tm Model CRC Algorithm. For more
 * information on the Rocksoft^tm Model CRC Algorithm, see the document
 * titled "A Painless Guide to CRC Error Detection Algorithms" by Ross
 * Williams (ross@guest.adelaide.edu.au.). This document is likely to be in
 * "ftp.adelaide.edu.au/pub/rocksoft".
 *
 * Note: Rocksoft is a trademark of Rocksoft Pty Ltd, Adelaide, Australia.
 *
 *
 *
 * Implementation Notes
 * --------------------
 * To avoid inconsistencies, the specification of each function is not echoed
 * here. See the header file for a description of these functions.
 * This package is light on checking because I want to keep it short and
 * simple and portable (i.e. it would be too messy to distribute my entire
 * C culture (e.g. assertions package) with this package.
 *
 *
 */

#include "crcmodel.h"

/* The following definitions make the code more readable. */

#define	BITMASK(X) (1L << (X))
#define	MASK32 0xFFFFFFFFL
#define	LOCAL static

LOCAL uint32_t reflect P_((uint32_t v, int b));
LOCAL uint32_t
reflect(v, b)
/* Returns the value v with the bottom b [0,32] bits reflected. */
/* Example: reflect(0x3e23L,3) == 0x3e26 */
uint32_t v;
int   b;
{
	int i;
	uint32_t t = v;
	for (i = 0; i < b; i++) {
		if (t & 1L)
			v |=  BITMASK((b-1)-i);
		else
			v &= ~BITMASK((b-1)-i);
		t >>= 1;
	}
	return (v);
}

LOCAL uint32_t widmask P_((p_cm_t));
LOCAL uint32_t
widmask(p_cm)
/* Returns a longword whose value is (2^p_cm->cm_width)-1. */
/* The trick is to do this portably (e.g. without doing <<32). */
p_cm_t p_cm;
{
	return ((((1L<<(p_cm->cm_width-1))-1L)<<1)|1L);
}

void
cm_ini(p_cm)
p_cm_t p_cm;
{
	p_cm->cm_reg = p_cm->cm_init;
}

void
cm_nxt(p_cm, ch)
p_cm_t p_cm;
int    ch;
{
	int i;
	uint32_t uch = (uint32_t)ch;
	uint32_t topbit = BITMASK(p_cm->cm_width-1);

	if (p_cm->cm_refin)
		uch = reflect(uch, 8);

	p_cm->cm_reg ^= (uch << (p_cm->cm_width-8));
	for (i = 0; i < 8; i++) {
		if (p_cm->cm_reg & topbit)
			p_cm->cm_reg = (p_cm->cm_reg << 1) ^ p_cm->cm_poly;
		else
			p_cm->cm_reg <<= 1;

		p_cm->cm_reg &= widmask(p_cm);
	}
}

void
cm_blk(p_cm, blk_adr, blk_len)
p_cm_t   p_cm;
p_ubyte_ blk_adr;
uint32_t    blk_len;
{
	while (blk_len--)
		cm_nxt(p_cm, *blk_adr++);
}

uint32_t
cm_crc(p_cm)
p_cm_t p_cm;
{
	if (p_cm->cm_refot)
		return (p_cm->cm_xorot ^ reflect(p_cm->cm_reg, p_cm->cm_width));
	else
		return (p_cm->cm_xorot ^ p_cm->cm_reg);
}

uint32_t
cm_tab(p_cm, index)
p_cm_t p_cm;
int    index;
{
	int   i;
	uint32_t r;
	uint32_t topbit = BITMASK(p_cm->cm_width-1);
	uint32_t inbyte = (uint32_t)index;

	if (p_cm->cm_refin)
		inbyte = reflect(inbyte, 8);

	r = inbyte << (p_cm->cm_width-8);
	for (i = 0; i < 8; i++)
		if (r & topbit)
			r = (r << 1) ^ p_cm->cm_poly;
		else
			r <<= 1;

	if (p_cm->cm_refin)
		r = reflect(r, p_cm->cm_width);

	return (r & widmask(p_cm));
}
