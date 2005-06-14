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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation of the mks M_INVARIANT family of mapping macros.
 * Based on the IBM C/370 getsyntx() and variant.h implementation.
 *
 * Copyright 1993 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char const rcsID[] = "$Header: /rd/src/libc/mks/rcs/m_varian.c 1.14 1994/12/08 23:14:58 ross Exp $";
#endif /* lint */
#endif /* M_RCSID */

#include <mks.h>
#include <m_invari.h>

#ifdef M_VARIANTS

#include <variant.h>

#define SHORT_STRING_LEN	100

void __m_setinvariant(void);

char	__m_invariant[M_CSETSIZE] = {
	  0,   1,   2,   3,   4,   5,   6,   7,
	  8,   9,  10,  11,  12,  13,  14,  15,
	 16,  17,  18,  19,  20,  21,  22,  23,
	 24,  25,  26,  27,  28,  29,  30,  31,
	 32,  33,  34,  35,  36,  37,  38,  39,
	 40,  41,  42,  43,  44,  45,  46,  47,
	 48,  49,  50,  51,  52,  53,  54,  55,
	 56,  57,  58,  59,  60,  61,  62,  63,
	 64,  65,  66,  67,  68,  69,  70,  71,
	 72,  73,  74,  75,  76,  77,  78,  79,
	 80,  81,  82,  83,  84,  85,  86,  87,
	 88,  89,  90,  91,  92,  93,  94,  95,
	 96,  97,  98,  99, 100, 101, 102, 103,
	104, 105, 106, 107, 108, 109, 110, 111,
	112, 113, 114, 115, 116, 117, 118, 119,
	120, 121, 122, 123, 124, 125, 126, 127,
	128, 129, 130, 131, 132, 133, 134, 135,
	136, 137, 138, 139, 140, 141, 142, 143,
	144, 145, 146, 147, 148, 149, 150, 151,
	152, 153, 154, 155, 156, 157, 158, 159,
	160, 161, 162, 163, 164, 165, 166, 167,
	168, 169, 170, 171, 172, 173, 174, 175,
	176, 177, 178, 179, 180, 181, 182, 183,
	184, 185, 186, 187, 188, 189, 190, 191,
	192, 193, 194, 195, 196, 197, 198, 199,
	200, 201, 202, 203, 204, 205, 206, 207,
	208, 209, 210, 211, 212, 213, 214, 215,
	216, 217, 218, 219, 220, 221, 222, 223,
	224, 225, 226, 227, 228, 229, 230, 231,
	232, 233, 234, 235, 236, 237, 238, 239,
	240, 241, 242, 243, 244, 245, 246, 247,
	248, 249, 250, 251, 252, 253, 254, 255,
#if M_CSETSIZE > 256
	256, 257, 258, 259, 260, 261, 262, 263,
	264, 265, 266, 267, 268, 269, 270, 271,
	272, 273, 274, 275, 276, 277, 278, 279,
	280, 281, 282, 283, 284, 285, 286, 287,
	288, 289, 290, 291, 292, 293, 294, 295,
	296, 297, 298, 299, 300, 301, 302, 303,
	304, 305, 306, 307, 308, 309, 310, 311,
	312, 313, 314, 315, 316, 317, 318, 319,
	320, 321, 322, 323, 324, 325, 326, 327,
	328, 329, 330, 331, 332, 333, 334, 335,
	336, 337, 338, 339, 340, 341, 342, 343,
	344, 345, 346, 347, 348, 349, 350, 351,
	352, 353, 354, 355, 356, 357, 358, 359,
	360, 361, 362, 363, 364, 365, 366, 367,
	368, 369, 370, 371, 372, 373, 374, 375,
	376, 377, 378, 379, 380, 381, 382, 383,
	384, 385, 386, 387, 388, 389, 390, 391,
	392, 393, 394, 395, 396, 397, 398, 399,
	400, 401, 402, 403, 404, 405, 406, 407,
	408, 409, 410, 411, 412, 413, 414, 415,
	416, 417, 418, 419, 420, 421, 422, 423,
	424, 425, 426, 427, 428, 429, 430, 431,
	432, 433, 434, 435, 436, 437, 438, 439,
	440, 441, 442, 443, 444, 445, 446, 447,
	448, 449, 450, 451, 452, 453, 454, 455,
	456, 457, 458, 459, 460, 461, 462, 463,
	464, 465, 466, 467, 468, 469, 470, 471,
	472, 473, 474, 475, 476, 477, 478, 479,
	480, 481, 482, 483, 484, 485, 486, 487,
	488, 489, 490, 491, 492, 493, 494, 495,
	496, 497, 498, 499, 500, 501, 502, 503,
	504, 505, 506, 507, 508, 509, 510, 511
#endif
#if M_CSETSIZE > 512
#error __m_invariant table needs to be extended
#endif
};
char	__m_unvariant[M_CSETSIZE] = {
	  0,   1,   2,   3,   4,   5,   6,   7,
	  8,   9,  10,  11,  12,  13,  14,  15,
	 16,  17,  18,  19,  20,  21,  22,  23,
	 24,  25,  26,  27,  28,  29,  30,  31,
	 32,  33,  34,  35,  36,  37,  38,  39,
	 40,  41,  42,  43,  44,  45,  46,  47,
	 48,  49,  50,  51,  52,  53,  54,  55,
	 56,  57,  58,  59,  60,  61,  62,  63,
	 64,  65,  66,  67,  68,  69,  70,  71,
	 72,  73,  74,  75,  76,  77,  78,  79,
	 80,  81,  82,  83,  84,  85,  86,  87,
	 88,  89,  90,  91,  92,  93,  94,  95,
	 96,  97,  98,  99, 100, 101, 102, 103,
	104, 105, 106, 107, 108, 109, 110, 111,
	112, 113, 114, 115, 116, 117, 118, 119,
	120, 121, 122, 123, 124, 125, 126, 127,
	128, 129, 130, 131, 132, 133, 134, 135,
	136, 137, 138, 139, 140, 141, 142, 143,
	144, 145, 146, 147, 148, 149, 150, 151,
	152, 153, 154, 155, 156, 157, 158, 159,
	160, 161, 162, 163, 164, 165, 166, 167,
	168, 169, 170, 171, 172, 173, 174, 175,
	176, 177, 178, 179, 180, 181, 182, 183,
	184, 185, 186, 187, 188, 189, 190, 191,
	192, 193, 194, 195, 196, 197, 198, 199,
	200, 201, 202, 203, 204, 205, 206, 207,
	208, 209, 210, 211, 212, 213, 214, 215,
	216, 217, 218, 219, 220, 221, 222, 223,
	224, 225, 226, 227, 228, 229, 230, 231,
	232, 233, 234, 235, 236, 237, 238, 239,
	240, 241, 242, 243, 244, 245, 246, 247,
	248, 249, 250, 251, 252, 253, 254, 255,
#if M_CSETSIZE > 256
	256, 257, 258, 259, 260, 261, 262, 263,
	264, 265, 266, 267, 268, 269, 270, 271,
	272, 273, 274, 275, 276, 277, 278, 279,
	280, 281, 282, 283, 284, 285, 286, 287,
	288, 289, 290, 291, 292, 293, 294, 295,
	296, 297, 298, 299, 300, 301, 302, 303,
	304, 305, 306, 307, 308, 309, 310, 311,
	312, 313, 314, 315, 316, 317, 318, 319,
	320, 321, 322, 323, 324, 325, 326, 327,
	328, 329, 330, 331, 332, 333, 334, 335,
	336, 337, 338, 339, 340, 341, 342, 343,
	344, 345, 346, 347, 348, 349, 350, 351,
	352, 353, 354, 355, 356, 357, 358, 359,
	360, 361, 362, 363, 364, 365, 366, 367,
	368, 369, 370, 371, 372, 373, 374, 375,
	376, 377, 378, 379, 380, 381, 382, 383,
	384, 385, 386, 387, 388, 389, 390, 391,
	392, 393, 394, 395, 396, 397, 398, 399,
	400, 401, 402, 403, 404, 405, 406, 407,
	408, 409, 410, 411, 412, 413, 414, 415,
	416, 417, 418, 419, 420, 421, 422, 423,
	424, 425, 426, 427, 428, 429, 430, 431,
	432, 433, 434, 435, 436, 437, 438, 439,
	440, 441, 442, 443, 444, 445, 446, 447,
	448, 449, 450, 451, 452, 453, 454, 455,
	456, 457, 458, 459, 460, 461, 462, 463,
	464, 465, 466, 467, 468, 469, 470, 471,
	472, 473, 474, 475, 476, 477, 478, 479,
	480, 481, 482, 483, 484, 485, 486, 487,
	488, 489, 490, 491, 492, 493, 494, 495,
	496, 497, 498, 499, 500, 501, 502, 503,
	504, 505, 506, 507, 508, 509, 510, 511
#endif
#if M_CSETSIZE > 512
#error __m_unvariant table needs to be extended
#endif
};

/*f
 * Initialize the variant <--> invariant tables.
 * May be called more than once -- successive calls ignored.
 * Void return -- can't fail.
 */
void
m_invariantinit(void)
{
	static int first = 1;

	if (!first)
		return;
	first = 0;
	__m_setinvariant();
	return;
}

/*f
 * Initialize the variant -> invariant tables.
 * Void return -- can't fail.
 */
void
__m_setinvariant(void)
{
	int i;
	struct variant *v;

	/* Initialize to identity mappings */
	for (i = 0; i < M_CSETSIZE; i++) {
		__m_invariant[i] = i;
		__m_unvariant[i] = i;
	}

	/*
	 * Find the set of variant characters
	 * On error, return success -- i.e. assume it wasn't specified, and
	 * hence it is the identity.
	 */
	if ((v = getsyntx()) == NULL)
		return;

	/*
	 * Build the invariant mapping tables: map from current codeset's
	 * variant locations, to the location that we were compiled in.
	 */
	__m_invariant[v->backslash] = '\\';
	__m_invariant[v->right_bracket] = ']';
	__m_invariant[v->left_bracket] = '[';
	__m_invariant[v->right_brace] = '}';
	__m_invariant[v->left_brace] = '{';
	__m_invariant[v->circumflex] = '^';
	__m_invariant[v->tilde] = '~';
	__m_invariant[v->exclamation_mark] = '!';
	__m_invariant[v->number_sign] = '#';
	__m_invariant[v->vertical_line] = '|';
	__m_invariant[v->dollar_sign] = '$';
	__m_invariant[v->commercial_at] = '@';
	__m_invariant[v->grave_accent] = '`';

	/*
	 * Build the unvariant mapping tables: map from compiled codeset
	 * to that of the current codeset.
	 */
	__m_unvariant['\\'] = v->backslash;
	__m_unvariant[']'] = v->right_bracket;
	__m_unvariant['['] = v->left_bracket;
	__m_unvariant['}'] = v->right_brace;
	__m_unvariant['{'] = v->left_brace;
	__m_unvariant['^'] = v->circumflex;
	__m_unvariant['~'] = v->tilde;
	__m_unvariant['!'] = v->exclamation_mark;
	__m_unvariant['#'] = v->number_sign;
	__m_unvariant['|'] = v->vertical_line;
	__m_unvariant['$'] = v->dollar_sign;
	__m_unvariant['@'] = v->commercial_at;
	__m_unvariant['`'] = v->grave_accent;

	return;
}

/*f
 * Convert a compiled in string to the external form.  Assumes a fixed
 * length short string which is available until another call to m_unvariantstr.
 * Uses 10 alternating strings to allow multiple calls on a printf.
 * The extra buffers are probably only required by yacc.
 */
char *
m_unvariantstr(char const *s)
{
	static char str[10][SHORT_STRING_LEN];
	static int buf = 0;
	char *ret;
	char c;
	int i = 0;

	ret = str[buf++];
	if (buf >= 10)
		buf = 0;

	while((ret[i++] = M_UNVARIANT(*s)) != '\0') {
		s++;
		if (i >= SHORT_STRING_LEN) {
			fprintf(stderr, "m_unvariantstr: internal error.\n"),
			abort();
		}
	}
	ret[i] = '\0';
	return ret;
}

/*f
 * Ditto, for wchar's
 */
wchar_t *
m_wunvariantstr(wchar_t const *s)
{
	static wchar_t str[SHORT_STRING_LEN];
	static wchar_t * const strend = str + sizeof(str);
	wchar_t *s1;
	int i = 0;

	for (s1 = str ; *s != '\0'; s++) {
		*s1++ = M_UNVARIANT(*s);
		if (str == strend) {
			fprintf(stderr, "m_wunvariantstr: internal error.\n"),
			abort();
		}
	}
	*s1 = '\0';

	return str;
}
#endif /* M_VARIANTS */
