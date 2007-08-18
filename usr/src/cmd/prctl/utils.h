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

#ifndef	_UTILS_H
#define	_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

extern void warn(const char *, ...);
extern char *setprogname(char *);

/*
 * scale_t
 *
 * Used to describe string modifiers and integer scales.
 *	modifiers:  NULL terminated array of modifier strings, such as
 *		    { "K", "M", NULL }, for strings like "100KB" or "100MB"
 *	scales:	    array of scales for each modifer string, such as
 *		    { 1000, 1000000 }
 */
typedef struct scale_struct {
	char	    **modifers;
	uint64_t	*scales;
} scale_t;

/*
 * pointers to standard scales.
 */
extern scale_t *scale_binary;
extern scale_t *scale_metric;

#define	SCALED_MODIFIER_CASE_INSENSITIVE_FLAG 	0x01
#define	SCALED_UNIT_CASE_INSENSITIVE_FLAG	0x02
#define	SCALED_UNIT_OPTIONAL_FLAG		0x04
#define	SCALED_PAD_WIDTH_FLAG			0x08
#define	SCALED_ALL_FLAGS			0x0F

/*
 * 20 characters for UINT64_MAX, 1 character for modifer, 1 character for
 * unit, 1 character for NULL, 1 extra.
 */
#define	SCALED_STRLEN (24)

#define	SCALED_INVALID_MODIFIER		1
#define	SCALED_INVALID_UNIT		2
#define	SCALED_INVALID_NUMBER		3
#define	SCALED_OVERFLOW			4

#define	SCALED_UNIT_BYTES "B"
#define	SCALED_UNIT_SECONDS "s"
#define	SCALED_UNIT_NONE ""

/*
 * scaledtouint64
 *
 * converts a string in one of the forms:
 *	 "[decimal number]][modifier][unit]"
 *	 "[integer number][unit]"
 *
 * to a uint64.  As seen from the two forms, If no modifier is present,
 * the number must be an integer.
 *
 * Inputs:
 *
 *	scaledin:   input string containing number string
 *	scale:	    pointer to scale_t to describe scaling modifiers and scales
 *	unit:	    expected unit string, such as "B", for the number "100MB"
 *	flags:	    one of:
 *			SCALED_MODIFIER_CASE_INSENSITIVE_FLAG
 *			SCALED_UNIT_CASE_INSENSITIVE_FLAG
 *			SCALED_UNIT_OPTIONAL_FLAG
 *		    which are pretty self explainatory.
 * Outputs:
 *
 *	return value:	0 on success, on errors:
 *		SCALED_INVALID_NUMBER	- string contains no valid number
 *		SCALED_INVALID_MODIFIER - string has unknown modifier
 *		SCALED_INVALID_UNIT	- string has unknown or missing unit
 *		SCALED_OVERFLOW		- number exceeds MAX_UINT64
 *
 *	uint64out:	uint64_t value of input string
 *	widthout:	width of number (not including modifier and unit)
 *			in the input string.  "10.0MB" has a width of 4.
 *	modiferout:	pointer to the string in the modifiers array which
 *			was found in the input string.  If no modifer was
 *			found, this well be set to NULL;
 *	unitout:	If unit string was present in the input string, this
 *			will be set to point to unit, otherwise NULL.
 */
int scaledtouint64(char *scaledin, uint64_t *uint64out,
    int *widthout, char **modifierout, char **unitout,
    scale_t *scale, char *unit, int flags);

/*
 * uint64toscaled
 *
 * converts a uint64 to a string in one of the forms:
 *	 "[decimal number]][modifier][unit]"
 *	 "[integer number][unit]"
 * (no modifier means number will be an integer)
 *
 * Inputs:
 *
 *	uint64in:    input number to convert to scaled string
 *	widthin:     character width of desired string, not including modifier
 *		     and unit.  Eg:  1.00MB has a width of 4 for the "1.00".
 *		     unit.
 *	maxmodifier: The maximium scaling to use.  For instance, to limit the
 *		     scaling to megabytes (no GB or higher), use "M"
 *	scale:	     pointer to scale_t to describe modifiers and scales
 *	unit:	     unit string, such as "B", for the number "100MB"
 *	flags:	     one of:
 *			SCALED_PAD_WIDTH_FLAG
 *			    If the length of the scaled string is less than
 *			    widthin, pad to the left with spaces.
 * Outputs:
 *
 *	return value:	0 on success, no error conditions.
 *	scaledout:   Pointer to a string buffer to fill with the scaled string.
 *	widthout:    Used to return the actual character length of the produced
 *		     string, not including modifier and unit.
 *	modifierout: pointer to modifier used in scaled string.
 */
int uint64toscaled(uint64_t uint64in, int widthin, char *maxmodifier,
    char *scaledout, int *widthout, char **modifierout,
    scale_t *scale, char *unit, int flags);

/*
 * scaledtoscaled
 *
 * Used to rescale a string from/to the following forms:
 *	 "[decimal number]][modifier][unit]"
 *	 "[integer number][unit]"
 *
 * This is used ensure the desired width and letter casing.
 *
 * As seen from the two forms, If no modifier is present,
 * the number must be an integer.
 *
 * Inputs:
 *	scaledin:   input string containing number string
 *	widthin:     character width of desired string, not including modifier
 *		     and unit.  Eg:  1.00MB has a width of 4 for the "1.00".
 *		     unit.
 *	maxmodifier: The maximium scaling to use.  For instance, to limit the
 *		     scaling to megabytes (no GB or higher), use "M"
 *	scale:	     pointer to scale_t to describe modifiers and scales
 *	unit:	     unit string, such as "B", for the number "100MB"
 *	flags:	     one of:
 *			SCALED_PAD_WIDTH_FLAG
 *			    If the length of the scaled string is less than
 *			    widthin, pad to the left with spaces.
 *			SCALED_MODIFIER_CASE_INSENSITIVE_FLAG
 *			SCALED_UNIT_CASE_INSENSITIVE_FLAG
 *			SCALED_UNIT_OPTIONAL_FLAG
 *			    which are pretty self explainatory.
 *
 * Outputs:
 *
 *	return value:	0 on success, on errors:
 *		SCALED_INVALID_NUMBER	- string contains no valid number
 *		SCALED_INVALID_MODIFIER - string has unknown modifier
 *		SCALED_INVALID_UNIT	- string has unknown or missing unit
 *		SCALED_OVERFLOW		- number exceeds MAX_UINT64
 *
 *	scaledout:   Pointer to a string buffer to fill with the scaled string.
 *	widthout:	width of number (not including modifier and unit)
 *			in the input string.  "10.0MB" has a width of 4.
 *	modiferout:	pointer to the string in the modifiers array which
 *			was found in the input string.  If no modifer was
 *			found, this well be set to NULL;
 */
int scaledtoscaled(char *scaledin, int widthin, char *maxmodifier,
    char *scaledout, int *widthout, char ** modifierout,
    scale_t *scale, char *unit, int flags);

/*
 * scaledeqscaled
 *
 * Determine if two scaled strings are equivalent.  Flags are same as
 * scaledtouint64.
 */
int scaledeqscaled(char *scale1, char *scale2,
    scale_t *scale, char *unit, int flags);

/*
 * scaledequint64
 *
 * Determine if a scaled number is equal to an uint64.  The uint64 is scaled
 * to the same scale and width as the scaled strings.  If the resultant string
 * is equal, then the numbers are considered equal.
 *
 * minwidth:  minimum number width to scale string and number to for
 *	      comparision.
 * flags are same as scaledtouint64.
 */
int scaledequint64(char *scaled, uint64_t uint64, int minwidth,
    scale_t *scale, char *unit, int flags);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTILS_H */
