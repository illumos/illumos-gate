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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "initialize.h"

#ifndef TEXT_DOMAIN
/*
 * TEXT_DOMAIN should have been set by build environment.
 */
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

/*
 * /dev/zero, output file, stdin, stdout, and stderr
 */
#define	N_FILES_ALREADY_OPEN	5

static const char *filename_stdin = "STDIN";
const char *filename_stdout = "STDOUT";

static sigjmp_buf signal_jmp_buf;
static volatile sig_atomic_t signal_delivered;

static void
set_signal_jmp(void)
{
	if (sigsetjmp(signal_jmp_buf, 1))
		exit(127 + signal_delivered);
}

static void
sig_handler(int signo)
{
	signal_delivered = signo;
	siglongjmp(signal_jmp_buf, 1);
}

void
initialize_pre(sort_t *S)
{
	/*
	 * Initialize sort structure.
	 */
	(void) memset(S, 0, sizeof (sort_t));

	S->m_stats = safe_realloc(NULL, sizeof (sort_statistics_t));
	__S(stats_init(S->m_stats));

	S->m_default_species = ALPHA;

	/*
	 * Simple localization issues.
	 */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

#ifndef DEBUG_FORCE_WIDE
	S->m_c_locale = xstreql("C", setlocale(LC_COLLATE, NULL));
	S->m_single_byte_locale = SGN(MB_CUR_MAX == 1);
#else /* DEBUG_FORCE_WIDE */
	S->m_c_locale = 0;
	S->m_single_byte_locale = 0;
#endif /* DEBUG_FORCE_WIDE */

	/*
	 * We use a constant seed so that our sorts on a given file are
	 * reproducible.
	 */
	srand(3459871433U);

	if (atexit(atexit_handler) < 0)
		warn(gettext("atexit() handler installation failed"));

	/*
	 * Establish signal handlers and sufficient state for clean up.
	 */
	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		die(EMSG_SIGNAL, "SIGTERM");
	if (signal(SIGHUP, sig_handler) == SIG_ERR)
		die(EMSG_SIGNAL, "SIGHUP");
	if (signal(SIGPIPE, sig_handler) == SIG_ERR)
		die(EMSG_SIGNAL, "SIGPIPE");

	set_signal_jmp();
}

void
initialize_post(sort_t *S)
{
	field_t	*F;

	S->m_memory_available = available_memory(S->m_memory_limit);

	set_file_template(&S->m_tmpdir_template);

	/*
	 * Initialize locale-specific ops vectors.
	 */
	field_initialize(S);

	if (S->m_single_byte_locale) {
		S->m_compare_fn = (cmp_fcn_t)strcoll;
		S->m_coll_convert = field_convert;
		F = S->m_fields_head;

		while (F != NULL) {
			switch (F->f_species) {
			case ALPHA:
				if (F->f_options &
				    (FIELD_IGNORE_NONPRINTABLES |
				    FIELD_DICTIONARY_ORDER |
				    FIELD_FOLD_UPPERCASE))
					F->f_convert = field_convert_alpha;
				else
					F->f_convert =
					    field_convert_alpha_simple;
				break;
			case NUMERIC:
				F->f_convert = field_convert_numeric;
				break;
			case MONTH:
				F->f_convert = field_convert_month;
				break;
			default:
				die(EMSG_UNKN_FIELD, F->f_species);
				break;
			}
			F = F->f_next;
		}
	} else {
		S->m_compare_fn = (cmp_fcn_t)wcscoll;
		S->m_coll_convert = field_convert_wide;

		F = S->m_fields_head;
		while (F != NULL) {
			switch (F->f_species) {
			case ALPHA:
				F->f_convert = field_convert_alpha_wide;
				break;
			case NUMERIC:
				F->f_convert =
				    field_convert_numeric_wide;
				break;
			case MONTH:
				F->f_convert = field_convert_month_wide;
				break;
			default:
				die(EMSG_UNKN_FIELD, F->f_species);
				break;
			}
			F = F->f_next;
		}
	}

	/*
	 * Validate and obtain sizes, inodes for input streams.
	 */
	stream_stat_chain(S->m_input_streams);
	__S(stats_set_input_files(stream_count_chain(S->m_input_streams)));

	/*
	 * Output guard.
	 */
	establish_output_guard(S);

	/*
	 * Ready stdin for usage as stream.
	 */
	if (S->m_input_from_stdin) {
		stream_t *str;

		if (S->m_single_byte_locale) {
			str = stream_new(STREAM_SINGLE | STREAM_NOTFILE);
			str->s_element_size = sizeof (char);
		} else {
			str = stream_new(STREAM_WIDE | STREAM_NOTFILE);
			str->s_element_size = sizeof (wchar_t);
		}
		str->s_filename = (char *)filename_stdin;
		stream_push_to_chain(&S->m_input_streams, str);
		__S(stats_incr_input_files());
	}
}
