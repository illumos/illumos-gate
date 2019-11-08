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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


/*
 *	globals.cc
 *
 *	This declares all global variables
 */

/*
 * Included files
 */
#include <mksh/globals.h>

/*
 * Defined macros
 */

/*
 * typedefs & structs
 */

/*
 * Global variables
 */
char		char_semantics[CHAR_SEMANTICS_ENTRIES];
wchar_t		char_semantics_char[] = {
	ampersand_char,
	asterisk_char,
	at_char,
	backquote_char,
	backslash_char,
	bar_char,
	bracketleft_char,
	bracketright_char,
	colon_char,
	dollar_char,
	doublequote_char,
	equal_char,
	exclam_char,
	greater_char,
	hat_char,
	hyphen_char,
	less_char,
	newline_char,
	numbersign_char,
	parenleft_char,
	parenright_char,
	percent_char,
	plus_char,
	question_char,
	quote_char,
	semicolon_char,
	nul_char
};
Macro_list	cond_macro_list;
Boolean		conditional_macro_used;
Boolean		do_not_exec_rule;		/* `-n' */
Boolean		dollarget_seen;
Boolean		dollarless_flag;
Name		dollarless_value;
Envvar		envvar;
int		exit_status;
wchar_t		*file_being_read;
/* Variable gnu_style=true if env. var. SUN_MAKE_COMPAT_MODE=GNU (RFE 4866328) */
Boolean		gnu_style = false;
Name_set	hashtab;
Name		host_arch;
Name		host_mach;
int		line_number;
char		*make_state_lockfile;
Boolean		make_word_mentioned;
Makefile_type	makefile_type = reading_nothing;
char		mbs_buffer[(MAXPATHLEN * MB_LEN_MAX)];
Name		path_name;
Boolean		posix = true;
Name		hat;
Name		query;
Boolean		query_mentioned;
Boolean		reading_environment;
Name		shell_name;
Boolean		svr4 = false;
Name		target_arch;
Name		target_mach;
Boolean		tilde_rule;
Name		virtual_root;
Boolean		vpath_defined;
Name		vpath_name;
wchar_t		wcs_buffer[MAXPATHLEN];
Boolean		working_on_targets;
Boolean		out_err_same;
pid_t		childPid = -1;	// This variable is used for killing child's process
				// Such as qrsh, running command, etc.

/*
 * timestamps defined in defs.h
 */
const timestruc_t file_no_time		= { -1, 0 };
const timestruc_t file_doesnt_exist	= { 0, 0 };
const timestruc_t file_is_dir		= { 1, 0 };
const timestruc_t file_min_time		= { 2, 0 };
const timestruc_t file_max_time		= { INT_MAX, 0 };
