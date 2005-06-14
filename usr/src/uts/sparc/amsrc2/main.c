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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * main.c - A pseudo-kernel to use when analyzing am_src2.c with warlock.
 *
 * The main idea here is to represent all of the ways that the kernel can
 * call into the amsrc2, so that warlock has the correct view of the call
 * graph.
 */

#include <sys/modctl.h>
#include <sys/note.h>
#include <sys/audio.h>
#include <sys/audio/audio_src.h>
#include <sys/audio/am_src2.h>
#include <sys/audio/impl/am_src2_impl.h>

am_ad_src_entry_t *src = &am_src2;

main() {

	_init();
	_fini();
	_info(NULL);

	/*
	 * ad_src_init() is called by am_open() before audio may begin playing
	 * or recording. So this can be viewed as single threaded.
	 */
	src->ad_src_init(NULL, 0);

	_NOTE(COMPETING_THREADS_NOW)

	src->ad_src_adjust(NULL, 0, 0);
	src->ad_src_convert(NULL, 0, 0, NULL, NULL, NULL, NULL);
	src->ad_src_size(NULL, NULL, 0, 0, 0);
	src->ad_src_update(NULL, NULL, NULL, NULL, 0);

	_NOTE(NO_COMPETING_THREADS_NOW)

	/*
	 * ad_src_exit() is called by am_close() only when play and record have
	 * stopped, thus it also is single threaded.
	 */
	src->ad_src_exit(NULL, 0);

	return (0);
}
