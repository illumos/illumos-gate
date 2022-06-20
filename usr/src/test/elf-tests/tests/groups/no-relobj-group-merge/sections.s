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

/* Copyright 2022, Richard Lowe. */

/*
 * We want to verify that if two sections which otherwise will be merged during
 * the link-edit are members of groups that they are not merged
 * but that if they are of the same group they will be discarded.
 */

	/*
	 * .test_data_conflict
	 * A member of group1, one copy will be kept
	 */
	.section	.test_data_conflict,"aG",@progbits,group1,comdat
	.string "2: test_data_conflict (group 1)"

	/*
	 * .test_data_conflict
	 * A member of group2.  One copy will be kept, and that copy will _not_
	 * be merged into a single .test_data_conflict section
	 */
	.section	.test_data_conflict,"aG",@progbits,group2,comdat
	.string "3: test_data_conflict (group 2)"

	/*
	 * .test_data_conflict
	 * Not a member of any group.  Both copies will be kept and will be
	 * merged, but will _not_ be merged into a section that is part of
	 * a group.
	 */
	.section	.test_data_conflict,"a",@progbits
	.string "4: test_data_conflict (two copies not in group)"
