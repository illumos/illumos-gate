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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.
 */

#ifndef _ELFCAP_DOT_H
#define	_ELFCAP_DOT_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Type used to represent capability bitmasks. This 32-bit type cannot be
 * widened without breaking the ability to use them in ELFCLASS32 objects.
 */
typedef uint32_t elfcap_mask_t;

/*
 * The elfcap code handles mappings to and from several string styles.
 * The caller uses elfcap_style_t to specify the style to use.
 *
 * The bottom 16 bits are used to represent styles, and the upper 16
 * bits are used for flags to modify default behavior.
 */
#define	ELFCAP_STYLE_MASK(_style) (_style & 0xff)

typedef enum {
	ELFCAP_STYLE_FULL =	1,	/* Full formal name (e.g. AV_386_SSE) */
	ELFCAP_STYLE_UC = 	2,	/* Informal upper case (e.g. SSE) */
	ELFCAP_STYLE_LC = 	3,	/* Informal lower case (e.g. sse) */

	ELFCAP_STYLE_F_ICMP =	0x0100	 /* Use case insensitive strcmp */
} elfcap_style_t;

/*
 * String descriptor: Contains the string and strlen(string). elfcap can
 * be used in contexts (ld.so.1) where we do not want to make calls to
 * string processing functions, so the length is calculated at compile time.
 */
typedef	struct {
	const char	*s_str;
	size_t		s_len;
} elfcap_str_t;

/*
 * Capabilities descriptor: This maps the integer bit value
 * (c_val) to/from the various strings that represent it.
 *
 * c_val is normally expected to be a non-zero power of 2
 * value (i.e. a single set bit). The value 0 is special, and
 * used to represent a "reserved" placeholder in an array of
 * capabilities. These reserved values have NULL string pointers,
 * and are intended to be ignored by the processing code.
 */
typedef	struct {
	elfcap_mask_t	c_val;		/* Bit value */
	elfcap_str_t	c_full;		/* ELFCAP_STYLE_FULL */
	elfcap_str_t	c_uc;		/* ELFCAP_STYLE_UC */
	elfcap_str_t	c_lc;		/* ELFCAP_STYLE_LC */
} elfcap_desc_t;

/*
 * Valid format values: The various formats in which a generated
 * string representing bitmap values can be displayed.
 *
 * This must be kept in sync with the format[] array in elfcap.c.
 */
typedef enum {
	ELFCAP_FMT_SNGSPACE =		0,
	ELFCAP_FMT_DBLSPACE =		1,
	ELFCAP_FMT_PIPSPACE =		2
} elfcap_fmt_t;

/*
 * Error codes:
 */
typedef enum {
	ELFCAP_ERR_NONE =		0,	/* no error */
	ELFCAP_ERR_BUFOVFL =		1,	/* buffer overfow */
	ELFCAP_ERR_INVFMT =		2,	/* invalid format */
	ELFCAP_ERR_UNKTAG =		3,	/* unknown capabilities tag */
	ELFCAP_ERR_UNKMACH =		4,	/* unknown machine type */
	ELFCAP_ERR_INVSTYLE =		5	/* unknown style */
} elfcap_err_t;


/*
 * # of each type of capability known to the system. These values
 * must be kept in sync with the arrays found in elfcap.c.
 */
#define	ELFCAP_NUM_SF1			3
#define	ELFCAP_NUM_HW1_SPARC		17
#define	ELFCAP_NUM_HW1_386		32
#define	ELFCAP_NUM_HW2_386		8


/*
 * Given a capability section tag and value, call the proper underlying
 * "to str" function to generate the string description.
 */
extern elfcap_err_t elfcap_tag_to_str(elfcap_style_t, uint64_t,
    elfcap_mask_t, char *, size_t, elfcap_fmt_t, ushort_t);

/*
 * The functions that convert from a specific capability value to
 * a string representation all use the same common prototype.
 */
typedef elfcap_err_t elfcap_to_str_func_t(elfcap_style_t, elfcap_mask_t, char *,
    size_t, elfcap_fmt_t, ushort_t);

extern elfcap_to_str_func_t elfcap_hw1_to_str;
extern elfcap_to_str_func_t elfcap_hw2_to_str;
extern elfcap_to_str_func_t elfcap_sf1_to_str;

/*
 * The reverse mapping: Given a string representation, turn it back into
 * integer form.
 */
typedef elfcap_mask_t elfcap_from_str_func_t(elfcap_style_t,
    const char *, ushort_t mach);

/*
 * Given a capability section tag and string, call the proper underlying
 * "from str" function to generate the numeric value.
 */
extern elfcap_mask_t elfcap_tag_from_str(elfcap_style_t, uint64_t,
    const char *, ushort_t);

extern elfcap_from_str_func_t elfcap_hw1_from_str;
extern elfcap_from_str_func_t elfcap_hw2_from_str;
extern elfcap_from_str_func_t elfcap_sf1_from_str;

/*
 * These functions give access to the individual descriptor arrays.
 * The caller is allowed to copy and use the string pointers contained
 * in the descriptors, but must not alter them. Functions are used instead
 * of making the arrays directly visible to preclude copy relocations in
 * non-pic code.
 */
extern const elfcap_desc_t *elfcap_getdesc_hw1_sparc(void);
extern const elfcap_desc_t *elfcap_getdesc_hw1_386(void);
extern const elfcap_desc_t *elfcap_getdesc_sf1(void);

#ifdef	__cplusplus
}
#endif

#endif /* _ELFCAP_DOT_H */
