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
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _TSC_H
#define	_TSC_H

#ifndef _ASM
#include <sys/linker_set.h>
#include <sys/types.h>
#endif

/*
 * flags to patch tsc_read routine.
 */
#define	TSC_NONE		0x0
#define	TSC_RDTSC_CPUID		0x1
/* formerly TSC_RDTSC_MFENCE	0x2 */
#define	TSC_RDTSC_LFENCE	0x3
#define	TSC_TSCP		0x4

#ifndef _ASM

/*
 * To register a TSC calibration source, a tsc_calibrate_t instance
 * should be created for the source, and then use
 * `TSC_CALIBRATION_SOURCE(<name_of_tsc_calibrate_t_instance_for_source>);`
 * to include it in the list of known sources.
 */
typedef struct tsc_calibrate {
	/*
	 * A descriptive name for the source. While this is mostly for the
	 * benefit of an operator, it may also be used to explicitly pick
	 * a specific source (vs. trying sources in order of preference).
	 * Each name should be unique (ignoring case).
	 */
	const char	*tscc_source;

	/*
	 * A preference value for this source. These values are largely
	 * arbitrary and are just to impose an order the sequence of
	 * sources to try (higher values of preference are tried before
	 * lower values of preference).
	 *
	 * Typically, any hypervisor provided sources will be preferred
	 * over hardware provided sources (i.e. cpuid), and higher precision
	 * hardware counters will be preferred over lower precision counters
	 * (e.g. HPET over PIT).
	 */
	uint_t		tscc_preference;

	/*
	 * The function that attempts calibration of the TSC. If the source
	 * cannot calibrate the TSC for any reason (e.g. the calibration source
	 * is not present or not supported on this machine), it should return
	 * B_FALSE.
	 *
	 * If the source is successful in measuring the TSC frequency, it
	 * should write the frequency of the TSC (in Hz) into the argument
	 * passed, e.g.
	 *
	 * boolean_t
	 * my_source(uint64_t *freq)
	 * {
	 *	...
	 *	*freq = measured_tsc_frequency;
	 *	return (B_TRUE);
	 * }
	 *
	 */
	boolean_t	(*tscc_calibrate)(uint64_t *);
} tsc_calibrate_t;
#define	TSC_CALIBRATION_SOURCE(x) DATA_SET(tsc_calibration_set, x)

uint64_t tsc_calibrate(void);
uint64_t tsc_get_freq(void);

#endif /* _ASM */

#endif /* _TSC_H */
