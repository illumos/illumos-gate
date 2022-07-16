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

/*
 * This tool is used to try and figure out what the value of various static
 * buffers should be and if the current compile time defaults are correct. In
 * particular, this covers the various elfcap values and is used to drive how we
 * calculate the overall size definition.
 *
 * To calculate this, we assume the following:
 *
 *   o We are using the ELFCAP_FMT_PIPSPACE as that is the longest. We don't
 *     have access to the actual strings right now.
 *   o We are using the ELFCAP_STYLE_FULL variant of the name as that's the
 *     longest.
 *   o We are going to have leftover bits that we don't know (unless we have
 *     32-bits defined). This uses the 0x%x format and therefore is 10
 *     characters.
 *   o We check all architectures set of values and take the largest.
 *
 * While elfcap related information is in multiple places in the build, sgs and
 * libconv are the places that seem most intertwined. In particular, we believe
 * it's important that this program execute as part of make check and also get
 * rebuilt normally as part of a build. This also allows one to iterate in
 * cmd/sgs which is the most common place that you're working in when adding new
 * hardware capabilities. By making it a part of the cmd/sgs suite, that also
 * ensures that normal build logic always rebuilds this program with changes to
 * elfcap.[ch].
 */

#include <stdio.h>
#include <elfcap.h>
#include <sys/sysmacros.h>
#include <stdlib.h>

/*
 * The length of 0x%x.
 */
#define	ECS_UNKNOWN	10

typedef const elfcap_desc_t *(*elfcap_getdesc_f)(void);

typedef struct elfcap_getdesc {
	uint32_t eg_nents;
	elfcap_getdesc_f eg_func;
} elfcap_getdesc_t;

typedef struct elfcap_case {
	const char *ec_tag;
	size_t ec_header;
	elfcap_getdesc_t ec_descs[2];
} elfcap_case_t;

const elfcap_case_t elfcaps[] = {
	{ "ELFCAP_SF1_BUFSIZE", ELFCAP_SF1_BUFSIZE, {
	    { ELFCAP_NUM_SF1, elfcap_getdesc_sf1 },
	    { 0, NULL }
	} },
	{ "ELFCAP_HW1_BUFSIZE", ELFCAP_HW1_BUFSIZE, {
	    { ELFCAP_NUM_HW1_386, elfcap_getdesc_hw1_386 },
	    { ELFCAP_NUM_HW1_SPARC, elfcap_getdesc_hw1_sparc }
	} },
	{ "ELFCAP_HW1_BUFSIZE", ELFCAP_HW2_BUFSIZE, {
	    { ELFCAP_NUM_HW2_386, elfcap_getdesc_hw2_386 },
	    { 0, NULL }
	} },
	{ "ELFCAP_HW1_BUFSIZE", ELFCAP_HW3_BUFSIZE, {
	    { ELFCAP_NUM_HW3_386, elfcap_getdesc_hw3_386 },
	    { 0, NULL }
	} },
};

static size_t
elfcap_calc_len(const elfcap_desc_t *desc, uint32_t nents, size_t space)
{
	size_t len = 0;

	for (uint32_t i = 0; i < nents; i++) {
		len += desc[i].c_full.s_len;
		if (i > 0) {
			len += space;
		}
	}

	if (nents < 32) {
		len += space + ECS_UNKNOWN;
	}

	/*
	 * Finally, add one for a terminator and we add an 8 character buffer in
	 * case we screwed up.
	 */
	len += 9;

	return (len);
}

static size_t
elfcap_max_len(const elfcap_case_t *ec, size_t slen)
{
	size_t max = 0;

	for (size_t i = 0; i < ARRAY_SIZE(ec->ec_descs); i++) {
		const elfcap_desc_t *desc;
		size_t len;

		if (ec->ec_descs[i].eg_func == NULL)
			continue;

		desc = ec->ec_descs[i].eg_func();
		len = elfcap_calc_len(desc, ec->ec_descs[i].eg_nents, slen);
		if (len > max)
			max = len;
	}

	return (max);
}

int
main(void)
{
	size_t slen;
	const elfcap_str_t *strs;
	int ret = EXIT_SUCCESS;

	strs = elfcap_getdesc_formats();
	slen = strs[ELFCAP_FMT_PIPSPACE].s_len;

	for (size_t i = 0; i < ARRAY_SIZE(elfcaps); i++) {
		size_t out = elfcap_max_len(&elfcaps[i], slen);

		if (out != elfcaps[i].ec_header) {
			(void) fprintf(stderr, "elfcap size for %s is not "
			    "expected value!\n\tCurrent value is %zu, should "
			    "be %zu\n", elfcaps[i].ec_tag, elfcaps[i].ec_header,
			    out);
			ret = EXIT_FAILURE;
		}
	}

	if (ret != EXIT_SUCCESS) {
		(void) fprintf(stderr, "please update $SRC/common/elfcap/"
		    "elfcap.h and $SRC/cmd/sgs/include/conv.h with the new "
		    "values reported above\n");
	}

	return (ret);
}
