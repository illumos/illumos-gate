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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <stdlib.h>

#include "volume_error.h"
#include "volume_output.h"
#include "volume_string.h"

#include "layout_messages.h"

/*
 * FUNCTION:	print_layout_volume_msg(char *type, uint64_t nbytes)
 *
 * PURPOSE:	Prints a generic message indicating the start of the
 *		layout process for a volume of the indicated type and
 *		capacity.
 */
void
print_layout_volume_msg(
	char *type,
	uint64_t nbytes)
{
	char *spstr = NULL;

	(void) bytes_to_sizestr(nbytes, &spstr, universal_units, B_FALSE);

	oprintf(OUTPUT_VERBOSE,
		gettext("  ->Layout a %s with capacity %s\n"),
		type, spstr);

	free(spstr);
}

/*
 * FUNCTION:	print_layout_explicit_msg(char *type)
 *
 * PURPOSE:	Prints a generic message indicating the start of the
 *		layout population process using explicit components
 *		for a volume of the indicated type.
 */
void
print_layout_explicit_msg(
	char *type)
{
	oprintf(OUTPUT_TERSE,
		gettext("  ->Layout a %s with explicitly specified "
			"components\n"),
		type);
}

/*
 * FUNCTION:	print_layout_explicit_added_msg(char *comp)
 *
 * PURPOSE:	Prints a generic message indicating the named component
 *		was added to a volume.
 */
void
print_layout_explicit_added_msg(
	char *comp)
{
	oprintf(OUTPUT_TERSE, gettext("  ---->added '%s'\n"), comp);
}

/*
 * FUNCTION:	print_success_msg()
 *
 * PURPOSE:	Prints a generic layout success message.
 */
void
print_layout_success_msg()
{
	oprintf(OUTPUT_TERSE, gettext("  <-Success!\n"));
}

/*
 * FUNCTION:	print_insufficient_resources_msg(char *type)
 *
 * PURPOSE:	Prints a message indicating that there are insufficient
 *		resources.
 *
 *		Also sets the metassist error string indicating why
 *		the metassist command failed.  The volume type is included
 *		for context in this message.
 */
void
print_insufficient_resources_msg(
	char *type)
{
	oprintf(OUTPUT_TERSE,
		gettext("  <-Failed: insufficient resources available\n"));

	volume_set_error(
		gettext("insufficient resources available to complete "
			"requested %s\n"),
		type);
}

/*
 * FUNCTION:	print_insufficient_hbas_msg(int n)
 *
 * PURPOSE:	Prints a status message indicating that there are insufficient
 *		HBAs and that only 'n' are available.
 *
 *		Used to indicate strategy selection during layouts.
 */
void
print_insufficient_hbas_msg(
	int n)
{
	if (n == 0) {
	    oprintf(OUTPUT_VERBOSE,
		gettext("  <--Failed: no HBA has sufficient disks\n"));
	} else if (n == 1) {
	    oprintf(OUTPUT_VERBOSE,
		gettext("  <--Failed: only 1 HBA has sufficient disks\n"));
	} else {
	    oprintf(OUTPUT_VERBOSE,
		gettext("  <--Failed: only %d HBAs have sufficient disks\n"),
		n);
	}
}

/*
 * FUNCTION:	print_insufficient_disks_msg(int n)
 *
 * PURPOSE:	Prints a status message indicating that there are insufficient
 *		disks and that only 'n' are available.
 *
 *		Used to indicate strategy selection during layouts.
 */
void
print_insufficient_disks_msg(
	int n)
{
	if (n == 0) {
	    oprintf(OUTPUT_VERBOSE,
		    gettext("  <--Failed: no disks available\n"),
		    n);
	} else if (n == 1) {
	    oprintf(OUTPUT_VERBOSE,
		gettext("  <--Failed: only 1 disk available\n"),
		    n);
	} else {
	    oprintf(OUTPUT_VERBOSE,
		    gettext("  <--Failed: only %d disks available\n"),
		    n);
	}
}

/*
 * FUNCTION:	print_no_hbas_msg()
 *
 * PURPOSE:	Prints a layout failure due to no usable HBAs message.
 */
void
print_no_hbas_msg()
{
	oprintf(OUTPUT_TERSE,
		gettext("  There are no usable HBAs.\n"));
}

/*
 * FUNCTION:	print_debug_failure_msg(char *type, char *err)
 *
 * PURPOSE:	Prints a generic message for unexpected failures
 *		during layout.
 */
void
print_debug_failure_msg(
	char *type,
	char *err)
{
	oprintf(OUTPUT_DEBUG,
		gettext("    layout of %s failed: %s\n"),
		type, err);
}

/*
 * FUNCTION:	print_insufficient_components_msg(int ncomp)
 *
 * INPUT:	ncomp	- number of available components
 *
 * PURPOSE:	Helper to print out a message indicating that there
 *		are insufficient components for a volume, only ncomps
 *		are actually available.
 */
void
print_insufficient_components_msg(
	int	ncomp)
{
	oprintf(OUTPUT_VERBOSE,
		gettext("  <---Failed: only found %d components\n"), ncomp);
}

/*
 * FUNCTION:	print_hba_insufficient_space_msg(char *name, uint64_t nbytes)
 *
 * INPUT:	name	- a char * HBA name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Helper to print out a message indicating the the HBA has
 *		insufficient space for use by the mirror layout strategy.
 */
void
print_hba_insufficient_space_msg(
	char		*name,
	uint64_t	nbytes)
{
	char *spstr = NULL;

	(void) bytes_to_sizestr(nbytes, &spstr, universal_units, B_FALSE);

	oprintf(OUTPUT_VERBOSE,
		gettext("  <--Failed: '%s' only has %s available\n"),
		name, spstr);

	free(spstr);
}

/*
 * FUNCTION:	print_insufficient_capacity_msg(uint64_t nbytes)
 *
 * INPUT:	nbytes	- available capacity in bytes
 *
 * PURPOSE:	Helper to print out a message indicating that there
 *		is insufficient space for a volume, only nbytes are
 *		actually available.
 */
void
print_insufficient_capacity_msg(
	uint64_t nbytes)
{
	char *spstr = NULL;

	(void) bytes_to_sizestr(nbytes, &spstr, universal_units, B_FALSE);

	oprintf(OUTPUT_VERBOSE,
		gettext("  <---Failed: only found %s capacity\n"), spstr);

	free(spstr);
}

/*
 * FUNCTION:	print_layout_submirrors_msg(char *type, uint64_t nbytes,
 *		int nsubs)
 *
 * PURPOSE:	Prints a generic status message indicating that layout of
 *		nsub submirrors of the indicated type and size has begun.
 */
void
print_layout_submirrors_msg(
	char	*type,
	uint64_t nbytes,
	int	nsubs)
{
	char *spstr = NULL;

	(void) bytes_to_sizestr(nbytes, &spstr, universal_units, B_FALSE);

	oprintf(OUTPUT_TERSE,
		gettext("  -->Layout %d %s submirrors with capacity %s\n"),
		nsubs, type, spstr);

	free(spstr);
}

/*
 * FUNCTION:	print_layout_submirrors_failed_msg(char *type, int count,
 *			int nsubs)
 *
 * PURPOSE:	Prints a generic status message indicating that only count
 *		submirrors (out of nsubs) of the indicated type could be
 *		composed.
 */
void
print_layout_submirrors_failed_msg(
	char	*type,
	int	count,
	int	nsubs)
{
	if (count == 0) {
	    oprintf(OUTPUT_VERBOSE,
		    gettext("  <---Failed, no %s submirrors could "
			    "be composed.\n"),
		    type);
	} else {
	    oprintf(OUTPUT_VERBOSE,
		    gettext("  <---Failed, only %d of %d %s submirror(s) "
			    "could be composed.\n"),
		    count, nsubs, type);
	}
}

/*
 * FUNCTION:	print_populate_volume_msg(char *type, uint64_t nbytes)
 *
 * PURPOSE:	Prints a generic message indicating a population process
 *		for a volume of the indicated type and size is beginning.
 */
void
print_populate_volume_msg(
	char *type,
	uint64_t nbytes)
{
	char *spstr = NULL;

	(void) bytes_to_sizestr(nbytes, &spstr, universal_units, B_FALSE);

	oprintf(OUTPUT_TERSE,
		gettext("  --->Populate a %s of capacity %s\n"),
		type, spstr);

	free(spstr);
}

/*
 * FUNCTION:	print_populate_volume_ncomps_msg(char *type, uint64_t nbytes,
 *			int ncomps)
 *
 * PURPOSE:	Prints a generic message indicating a population process
 *		for a volume of the indicated type, size and number of
 *		components is beginning.
 */
void
print_populate_volume_ncomps_msg(
	char *type,
	uint64_t nbytes,
	int ncomps)
{
	char *spstr = NULL;

	(void) bytes_to_sizestr(nbytes, &spstr, universal_units, B_FALSE);

	oprintf(OUTPUT_TERSE,
		gettext("  --->Populate a %s of capacity %s (%d components)\n"),
		type, spstr, ncomps);

	free(spstr);
}

/*
 * FUNCTION:	print_populate_success_msg()
 *
 * PURPOSE:	Prints a generic message indicating a population process
 *		completed successfully.
 */
void
print_populate_success_msg()
{
	oprintf(OUTPUT_TERSE,
		gettext("  <---Success!\n"));
}

/*
 * FUNCTION:	print_populate_choose_slices_msg()
 *
 * PURPOSE:	Prints a generic message indicating a population process
 *		is beginning to choose slices.
 */
void
print_populate_choose_slices_msg()
{
	oprintf(OUTPUT_VERBOSE,
		gettext("      choosing \"best\" slices from "
			"those available...\n"));
}

/*
 * FUNCTION:	print_populate_no_slices_msg()
 *
 * PURPOSE:	Prints a layout failure due to no available slices message.
 */
void
print_populate_no_slices_msg()
{
	oprintf(OUTPUT_VERBOSE,
		gettext("  <---Failed: there are no slices available.\n"));
}
