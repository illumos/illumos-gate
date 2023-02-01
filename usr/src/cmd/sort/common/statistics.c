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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "statistics.h"

static sort_statistics_t *run_stats;

void
stats_init(sort_statistics_t *s)
{
	run_stats = s;
	memset(s, 0, sizeof (sort_statistics_t));
}

void
stats_display()
{
	(void) fprintf(stderr,
	    "Lines fetched:      %20llu\n"
	    "Lines shelved:      %20llu\n"
	    "Lines put:          %20llu\n"
	    "Lines put uniquely: %20llu\n"
	    "Lines not unique:   %20llu\n"
	    "Input files:        %20u\n"
	    "Merge files:        %20u\n"
	    "Subfiles:           %20llu\n"
	    "TQS calls:          %20llu\n"
	    "Swaps:              %20llu\n"
	    "Available memory:   %20llu\n"
	    "Insert filled input:%20llu\n"
	    "Insert filled up:   %20llu\n"
	    "Insert filled down: %20llu\n"
	    "TQS calls:          %20llu\n"
	    "Convert reallocs:   %20llu\n"
	    "Line conversions:   %20llu\n",
	    run_stats->st_fetched_lines,
	    run_stats->st_shelved_lines,
	    run_stats->st_put_lines,
	    run_stats->st_put_unique_lines,
	    run_stats->st_not_unique_lines,
	    run_stats->st_input_files,
	    run_stats->st_merge_files,
	    run_stats->st_subfiles,
	    run_stats->st_tqs_calls,
	    run_stats->st_swaps,
	    run_stats->st_avail_mem,
	    run_stats->st_insert_full_input,
	    run_stats->st_insert_full_up,
	    run_stats->st_insert_full_down,
	    run_stats->st_tqs_calls,
	    run_stats->st_convert_reallocs,
	    run_stats->st_line_conversions);
}

void
stats_incr_subfiles()
{
	run_stats->st_subfiles++;
}

void
stats_incr_fetches()
{
	run_stats->st_fetched_lines++;
}

void
stats_incr_shelves()
{
	run_stats->st_shelved_lines++;
}

void
stats_incr_puts()
{
	run_stats->st_put_lines++;
}

void
stats_incr_swaps()
{
	run_stats->st_swaps++;
}

void
stats_set_input_files(uint_t n)
{
	run_stats->st_input_files = n;
}

void
stats_incr_input_files()
{
	run_stats->st_input_files++;
}

void
stats_set_merge_files(uint_t n)
{
	run_stats->st_merge_files = n;
}

void
stats_incr_merge_files()
{
	run_stats->st_merge_files++;
}

void
stats_set_available_memory(uint64_t a)
{
	run_stats->st_avail_mem = a;
}

void
stats_incr_insert_filled_input()
{
	run_stats->st_insert_full_input++;
}

void
stats_incr_insert_filled_upward()
{
	run_stats->st_insert_full_up++;
}

void
stats_incr_insert_filled_downward()
{
	run_stats->st_insert_full_down++;
}

void
stats_incr_tqs_calls()
{
	run_stats->st_tqs_calls++;
}

void
stats_incr_put_unique()
{
	run_stats->st_put_unique_lines++;
}

void
stats_incr_not_unique()
{
	run_stats->st_not_unique_lines++;
}

void
stats_incr_convert_reallocs()
{
	run_stats->st_convert_reallocs++;
}

void
stats_incr_line_conversions()
{
	run_stats->st_line_conversions++;
}
