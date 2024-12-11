/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _HEXDUMP_H_
#define	_HEXDUMP_H_

/*
 * Header file for the generic hexdump implementation in
 * common/hexdump/hexdump.c
 */

#include <sys/types.h>

#ifndef _KERNEL
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	/*
	 * Include a header row showing byte positions.
	 */
	HDF_HEADER		= 1 << 0,
	/*
	 * Include the address of the first byte for each row at the left.
	 */
	HDF_ADDRESS		= 1 << 1,
	/*
	 * Include an ASCII table at the right hand side with unprintable bytes
	 * displayed as '.'.
	 */
	HDF_ASCII		= 1 << 2,
	/*
	 * If the data is not naturally aligned to the paragraph size, start
	 * the table from an aligned address and indicate where the data starts
	 * with a marker in the table header (if enabled). Missing data are
	 * shown with space characters.
	 */
	HDF_ALIGN		= 1 << 3,
	/*
	 * Suppress duplicate lines in the output, replacing them with a single
	 * "*".
	 */
	HDF_DEDUP		= 1 << 4,
	/*
	 * When laying out byte columns, use two spaces instead of one. This
	 * results in the data being more spread out and easier to read in some
	 * circumstances.
	 */
	HDF_DOUBLESPACE		= 1 << 5,
} hexdump_flag_t;

/*
 * Most consumers of the hexdump routines should use this default set of flags
 * so we have consistent output across the gate.
 */
#define	HDF_DEFAULT	(HDF_HEADER | HDF_ADDRESS | HDF_ASCII)

/*
 * Consumers of this code should treat this as an opaque type and initialise it
 * with a call to hexdump_init(). It is defined here so that it can be placed
 * on the stack which is particularly useful during early boot, before the kmem
 * system is ready.
 */
typedef struct {
	uint64_t	h_addr;		/* display address */
	uint8_t		h_addrwidth;	/* Minimum address width */
	uint8_t		h_width;	/* bytes per row */
	uint8_t		h_grouping;	/* display bytes in groups of.. */
	uint8_t		h_indent;	/* Left indent */
	uint8_t		h_marker;	/* marker offset */
	uint8_t		*h_buf;		/* optional pre-allocated buffer... */
	size_t		h_buflen;	/* ...and its size */
} hexdump_t;

/*
 * Initialise and finalise a hexdump_t.
 */
extern void hexdump_init(hexdump_t *);
extern void hexdump_fini(hexdump_t *);

/*
 * Set the start address that corresponds to the provided data. This is used to
 * display addresses in conjunction with the HDF_ADDRESS option.
 */
extern void hexdump_set_addr(hexdump_t *, uint64_t);

/*
 * Set a minimum width, in characters, for the addresses shown in conjunction
 * with the HDF_ADDRESS option. The default behaviour is to calculate the width
 * required to show all addresses and use that for all rows.
 */
extern void hexdump_set_addrwidth(hexdump_t *, uint8_t);

/*
 * Select the number of bytes per line. The default is 16.
 */
extern void hexdump_set_width(hexdump_t *, uint8_t);

/*
 * Group bytes together. The default grouping is 1 which results in each byte
 * being displayed surrounded by space. As a readability improvement an extra
 * space is added after every 8 bytes when using a grouping of 1.
 */
extern void hexdump_set_grouping(hexdump_t *, uint8_t);

/*
 * Set a number of spaces that should precede each row as an indent.
 */
extern void hexdump_set_indent(hexdump_t *, uint8_t);

/*
 * Set a marker in the header for the start of interesting data. This will only
 * be displayed if the header is enabled with the HDF_HEADER option, and if the
 * marker value is less than the configured row width.
 */
extern void hexdump_set_marker(hexdump_t *, uint8_t);

/*
 * Provide a scratch space working buffer. This is necessary in early boot,
 * before kmem is ready.
 */
extern void hexdump_set_buf(hexdump_t *, uint8_t *, size_t);

/*
 * The hexdump() function that does the work. It takes the following arguments:
 *
 *	const uint8_t *addr	- a pointer to the data to be dumped
 *	size_t len		- the length of the data
 *	hexdump_flag_t flags	- flags as per the definitions above
 *	hexdump_cb_f callback	- fucntion called for each table row
 *	void *callback_arg	- pointer passed to callback function
 *
 * More customisation can be achieved by using hexdumph() which takes an
 * additional hexdump_t *.
 */
typedef int (*hexdump_cb_f)(void *, uint64_t, const char *, size_t);
extern int hexdump(const uint8_t *, size_t, hexdump_flag_t,
    hexdump_cb_f, void *);

/*
 * A version that takes a hexdump_t allowing for more customisation.
 */
extern int hexdumph(hexdump_t *, const uint8_t *, size_t, hexdump_flag_t,
    hexdump_cb_f, void *);

#ifndef _KERNEL
/*
 * Convenience wrappers in non-kernel context that output each table row to
 * the provided FILE *.
 */
extern int hexdump_file(const uint8_t *, size_t, hexdump_flag_t, FILE *);
extern int hexdump_fileh(hexdump_t *, const uint8_t *, size_t, hexdump_flag_t,
    FILE *);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _HEXDUMP_H_ */
