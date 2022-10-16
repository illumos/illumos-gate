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
 * Copyright 2022 Oxide Computer Company
 */

#ifndef _SYS_GPIO_DPIO_H
#define	_SYS_GPIO_DPIO_H

/*
 * Definitions that consumers of DPIOs should likely know about.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is the general size of names in the dpio structures. Actual name lengths
 * and limits are potentially less.
 */
#define	DPIO_NAMELEN	64

/*
 * Basic IOCTL information
 */
#define	DPIO_IOC	(('d' << 24) | ('p' << 16) | ('i' << 8))

/*
 * This is the set of values that are expected on a write(2) to a DPIO to set
 * the output state. Each write(2) must be a uint32_t (4 bytes) in size.
 */
typedef enum {
	DPIO_OUTPUT_LOW	= 0,
	DPIO_OUTPUT_HIGH = 1,
	DPIO_OUTPUT_DISABLE = UINT32_MAX
} dpio_output_t;

/*
 * This is the set of values that are expected on a read(2) of a DPIO to get the
 * input state. Each read(2) must be a uint32_t (4 bytes) in size.
 */
typedef enum {
	DPIO_INPUT_LOW = 0,
	DPIO_INPUT_HIGH = 1
} dpio_input_t;

/*
 * This indicates features that the DPIO is set up for and supports.
 */
typedef enum {
	DPIO_C_READ	= 1 << 0,
	DPIO_C_WRITE	= 1 << 1,
	DPIO_C_POLL	= 1 << 2
} dpio_caps_t;

typedef enum {
	DPIO_F_KERNEL	= 1 << 0,
} dpio_flags_t;

/*
 * This is the basic information structure for a DPIO. It reports information
 * about what is supported and usable. This is accessible via the dpinfo
 * interface or via the dpio itself. If this is called directly on a dpio
 * itself, then the dpi_dpio field will be the DPIO's name.
 */
#define	DPIO_IOC_INFO	(DPIO_IOC | 1)
typedef struct {
	char		dpi_dpio[DPIO_NAMELEN];
	char		dpi_ctrl[DPIO_NAMELEN];
	uint32_t	dpi_gpio;
	dpio_caps_t	dpi_caps;
	dpio_flags_t	dpi_flags;
	uint32_t	dpi_pad;
} dpio_info_t;

/*
 * This is used to get information about the current timing information. If the
 * system supports interrupts on changes and it has been enabled, then this will
 * be used to indicate the last time we received an update.
 */
#define	DPIO_IOC_TIMING	(DPIO_IOC | 2)
typedef struct {
	hrtime_t	dpt_last_input_intr;
	hrtime_t	dpt_last_write;
} dpio_timing_t;

/*
 * This is used to get access to the current output state that has been set on
 * the DPIO. This is only available via the dpio itself, it is not available via
 * dpinfo as it is information specific to current consumers.
 */
#define	DPIO_IOC_CUROUT	(DPIO_IOC | 3)
typedef struct {
	dpio_output_t	dps_curout;
	uint32_t	dps_pad;
} dpio_curout_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GPIO_DPIO_H */
