/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Cylink Corporation © 1998
 * 
 * This software is licensed by Cylink to the Internet Software Consortium to
 * promote implementation of royalty free public key cryptography within IETF
 * standards.  Cylink wishes to expressly thank the contributions of Dr.
 * Martin Hellman, Whitfield Diffie, Ralph Merkle and Stanford University for
 * their contributions to Internet Security.  In accordance with the terms of
 * this license, ISC is authorized to distribute and sublicense this software
 * for the practice of IETF standards.  
 *
 * The software includes BigNum, written by Colin Plumb and licensed by Philip
 * R. Zimmermann for royalty free use and distribution with Cylink's
 * software.  Use of BigNum as a stand alone product or component is
 * specifically prohibited.
 *
 * Disclaimer of All Warranties. THIS SOFTWARE IS BEING PROVIDED "AS IS",
 * WITHOUT ANY EXPRESSED OR IMPLIED WARRANTY OF ANY KIND WHATSOEVER. IN
 * PARTICULAR, WITHOUT LIMITATION ON THE GENERALITY OF THE FOREGOING, CYLINK
 * MAKES NO REPRESENTATION OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 *
 * Cylink or its representatives shall not be liable for tort, indirect,
 * special or consequential damages such as loss of profits or loss of
 * goodwill from the use or inability to use the software for any purpose or
 * for any reason whatsoever.
 *
 * EXPORT LAW: Export of the Foundations Suite may be subject to compliance
 * with the rules and regulations promulgated from time to time by the Bureau
 * of Export Administration, United States Department of Commerce, which
 * restrict the export and re-export of certain products and technical data.
 * If the export of the Foundations Suite is controlled under such rules and
 * regulations, then the Foundations Suite shall not be exported or
 * re-exported, directly or indirectly, (a) without all export or re-export
 * licenses and governmental approvals required by any applicable laws, or (b)
 * in violation of any applicable prohibition against the export or re-export
 * of any part of the Foundations Suite. All export licenses for software
 * containing the Foundations Suite are the sole responsibility of the licensee.
 */
 
/*
 * bn.c - the high-level bignum interface
 *
 * Copyright (c) 1995  Colin Plumb.  All rights reserved.
 * For licensing and other legal details, see the file legal.c.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "port_before.h"
#include "bn.h"
#include "port_after.h"

/* Functions */
void
bnBegin(struct BigNum *bn)
{
	static int bninit = 0;

	if (!bninit) {
		bnInit();
		bninit = 1;
	}

	bn->ptr = 0;
	bn->size = 0;
	bn->allocated = 0;
}

void
bnSwap(struct BigNum *a, struct BigNum *b)
{
	void *p;
	unsigned t;

	p = a->ptr;
	a->ptr = b->ptr;
	b->ptr = p;

	t = a->size;
	a->size = b->size;
	b->size = t;

	t = a->allocated;
	a->allocated = b->allocated;
	b->allocated = t;
}

void (*bnEnd)(struct BigNum *bn);
int (*bnPrealloc)(struct BigNum *bn, unsigned bits);
int (*bnCopy)(struct BigNum *dest, struct BigNum const *src);
void (*bnNorm)(struct BigNum *bn);
void (*bnExtractBigBytes)(struct BigNum const *bn, unsigned char *dest,
	unsigned lsbyte, unsigned len);
int (*bnInsertBigBytes)(struct BigNum *bn, unsigned char const *src,
	unsigned lsbyte, unsigned len);
void (*bnExtractLittleBytes)(struct BigNum const *bn, unsigned char *dest,
	unsigned lsbyte, unsigned len);
int (*bnInsertLittleBytes)(struct BigNum *bn, unsigned char const *src,
	unsigned lsbyte, unsigned len);
unsigned (*bnLSWord)(struct BigNum const *src);
unsigned (*bnBits)(struct BigNum const *src);
int (*bnAdd)(struct BigNum *dest, struct BigNum const *src);
int (*bnSub)(struct BigNum *dest, struct BigNum const *src);
int (*bnCmpQ)(struct BigNum const *a, unsigned b);
int (*bnSetQ)(struct BigNum *dest, unsigned src);
int (*bnAddQ)(struct BigNum *dest, unsigned src);
int (*bnSubQ)(struct BigNum *dest, unsigned src);
int (*bnCmp)(struct BigNum const *a, struct BigNum const *b);
int (*bnSquare)(struct BigNum *dest, struct BigNum const *src);
int (*bnMul)(struct BigNum *dest, struct BigNum const *a,
	struct BigNum const *b);
int (*bnMulQ)(struct BigNum *dest, struct BigNum const *a, unsigned b);
int (*bnDivMod)(struct BigNum *q, struct BigNum *r, struct BigNum const *n,
	struct BigNum const *d);
int (*bnMod)(struct BigNum *dest, struct BigNum const *src,
	struct BigNum const *d);
unsigned (*bnModQ)(struct BigNum const *src, unsigned d);
int (*bnExpMod)(struct BigNum *result, struct BigNum const *n,
	struct BigNum const *exp, struct BigNum const *mod);
int (*bnDoubleExpMod)(struct BigNum *dest,
	struct BigNum const *n1, struct BigNum const *e1,
	struct BigNum const *n2, struct BigNum const *e2,
	struct BigNum const *mod);
int (*bnTwoExpMod)(struct BigNum *n, struct BigNum const *exp,
	struct BigNum const *mod);
int (*bnGcd)(struct BigNum *dest, struct BigNum const *a,
	struct BigNum const *b);
int (*bnInv)(struct BigNum *dest, struct BigNum const *src,
	struct BigNum const *mod);
int (*bnLShift)(struct BigNum *dest, unsigned amt);
void (*bnRShift)(struct BigNum *dest, unsigned amt);
unsigned (*bnMakeOdd)(struct BigNum *n);
