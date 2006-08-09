#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libtecla/spec/tecla.spec

function        libtecla_version
include         <libtecla.h>
declaration     void libtecla_version(int *, int *, int *)
version         tecla_1.4
end             

function        new_GetLine
include         <libtecla.h>
declaration     GetLine *new_GetLine(size_t, size_t)
version         tecla_1.2
end             

function        del_GetLine
include         <libtecla.h>
declaration     GetLine *del_GetLine(GetLine *)
version         tecla_1.2
end             

function        gl_get_line
include         <libtecla.h>
declaration     char *gl_get_line(GetLine *, const char *, const char *, int)
version         tecla_1.2
end             

function        gl_configure_getline
include         <libtecla.h>
declaration     int gl_configure_getline(GetLine *, const char *, const char *, const char *)
version         tecla_1.4
end             

function        gl_bind_keyseq
include         <libtecla.h>
declaration     int gl_bind_keyseq(GetLine *, GlKeyOrigin, const char *, const char *)
version         tecla_l.5
end             

function        new_ExpandFile
include         <libtecla.h>
declaration     ExpandFile *new_ExpandFile(void)
version         tecla_1.2
end             

function        del_ExpandFile
include         <libtecla.h>
declaration     ExpandFile *del_ExpandFile(ExpandFile *)
version         tecla_1.2
end             

function        ef_expand_file
include         <libtecla.h>
declaration     FileExpansion *ef_expand_file(ExpandFile *, const char *, int)
version         tecla_1.2
end             

function        ef_list_expansions
include         <libtecla.h>
declaration     int ef_list_expansions(FileExpansion *, FILE *, int)
version         tecla_1.3
end             

function        ef_last_error
include         <libtecla.h>
declaration     const char *ef_last_error(ExpandFile *)
version         tecla_1.2
end             

function        new_WordCompletion
include         <libtecla.h>
declaration     WordCompletion *new_WordCompletion(void)
version         tecla_1.2
end             

function        del_WordCompletion
include         <libtecla.h>
declaration     WordCompletion *del_WordCompletion(WordCompletion *)
version         tecla_1.2
end             

function        cpl_check_exe
include         <libtecla.h>
declaration     int cpl_check_exe(void *, const char *)
version         tecla_1.2
end             

function        cpl_file_completions
include         <libtecla.h>
declaration     int cpl_file_completions(WordCompletion *, void *, const char *, int)
version         tecla_1.2
end             

function        cfc_literal_escapes
include         <libtecla.h>
declaration     void cfc_literal_escapes(CplFileConf *, int)
version         tecla_1.2
end             

function        cfc_file_start
include         <libtecla.h>
declaration     void cfc_file_start(CplFileConf *, int)
version         tecla_1.2
end             

function        cfc_set_check_fn
include         <libtecla.h>
declaration     void cfc_set_check_fn(CplFileConf *, CplCheckFn *, void *)
version         tecla_1.2
end             

function        new_CplFileConf
include         <libtecla.h>
declaration     CplFileConf *new_CplFileConf(void)
version         tecla_1.2
end             

function        del_CplFileConf
include         <libtecla.h>
declaration     CplFileConf *del_CplFileConf(CplFileConf *)
version         tecla_1.2
end             

function        cpl_init_FileArgs
include         <libtecla.h>
declaration     void cpl_init_FileArgs(CplFileArgs *)
version         tecla_1.2
end             

function        cpl_record_error
include         <libtecla.h>
declaration     void cpl_record_error(WordCompletion *, const char *)
version         tecla_1.2
end             

function        gl_customize_completion
include         <libtecla.h>
declaration     int gl_customize_completion(GetLine *, void *, CplMatchFn *)
version         tecla_1.2
end             

function        gl_completion_action
include         <libtecla.h>
declaration     int gl_completion_action(GetLine *, void *, CplMatchFn *, int, const char *, const char *)
version         tecla_1.2
end             

function        gl_change_terminal
include         <libtecla.h>
declaration     int gl_change_terminal(GetLine *, FILE *, FILE *, const char *)
version         tecla_1.2
end             

function        gl_save_history
include         <libtecla.h>
declaration     int gl_save_history(GetLine *, const char *, const char *, int)
version         tecla_1.4
end             

function        gl_load_history
include         <libtecla.h>
declaration     int gl_load_history(GetLine *, const char *, const char *)
version         tecla_1.4
end             

function        gl_watch_fd
include         <libtecla.h>
declaration     int gl_watch_fd(GetLine *, int, GlFdEvent, GlFdEventFn *, void *)
version         tecla_1.4
end             

function        gl_inactivity_timeout
include         <libtecla.h>
declaration     int gl_inactivity_timeout(GetLine *, GlTimeoutFn *, void *, unsigned long, unsigned long)
version         tecla_l.5
end             

function        gl_group_history
include         <libtecla.h>
declaration     int gl_group_history(GetLine *, unsigned)
version         tecla_1.4
end             

function        gl_show_history
include         <libtecla.h>
declaration     int gl_show_history(GetLine *, FILE *, const char *, int, int)
version         tecla_1.4
end             

function        gl_resize_history
include         <libtecla.h>
declaration     int gl_resize_history(GetLine *, size_t)
version         tecla_1.4
end             

function        gl_limit_history
include         <libtecla.h>
declaration     void gl_limit_history(GetLine *, int)
version         tecla_1.4
end             

function        gl_clear_history
include         <libtecla.h>
declaration     void gl_clear_history(GetLine *, int)
version         tecla_1.4
end             

function        gl_toggle_history
include         <libtecla.h>
declaration     void gl_toggle_history(GetLine *, int)
version         tecla_1.4
end             

function        gl_terminal_size
include         <libtecla.h>
declaration     GlTerminalSize gl_terminal_size(GetLine *, int, int)
version         tecla_1.4
end             

function        gl_set_term_size
include         <libtecla.h>
declaration     int gl_set_term_size(GetLine *, int, int)
version         tecla_1.4
end             

function        gl_lookup_history
include         <libtecla.h>
declaration     int gl_lookup_history(GetLine *, unsigned long, GlHistoryLine *)
version         tecla_1.4
end             

function        gl_state_of_history
include         <libtecla.h>
declaration     void gl_state_of_history(GetLine *, GlHistoryState *)
version         tecla_1.4
end             

function        gl_range_of_history
include         <libtecla.h>
declaration     void gl_range_of_history(GetLine *, GlHistoryRange *)
version         tecla_1.4
end             

function        gl_size_of_history
include         <libtecla.h>
declaration     void gl_size_of_history(GetLine *, GlHistorySize *)
version         tecla_1.4
end             

function        gl_echo_mode
include         <libtecla.h>
declaration     int gl_echo_mode(GetLine *, int)
version         tecla_1.4
end             

function        gl_replace_prompt
include         <libtecla.h>
declaration     void gl_replace_prompt(GetLine *, const char *)
version         tecla_1.4
end             

function        gl_prompt_style
include         <libtecla.h>
declaration     void gl_prompt_style(GetLine *, GlPromptStyle)
version         tecla_1.4
end             

function        gl_ignore_signal
include         <libtecla.h>
declaration     int gl_ignore_signal(GetLine *, int)
version         tecla_1.4
end             

function        gl_trap_signal
include         <libtecla.h>
declaration     int gl_trap_signal(GetLine *, int, unsigned, GlAfterSignal, int)
version         tecla_1.4
end             

function        gl_catch_blocked
include         <libtecla.h>
declaration     void gl_catch_blocked(GetLine *)
version         tecla_l.5
end             

function        gl_tty_signals
include         <libtecla.h>
declaration     int gl_tty_signals(void (*)(int), void (*)(int), void (*)(int), void (*)(int))
version         tecla_l.5
end             

function        gl_last_signal
include         <libtecla.h>
declaration     int gl_last_signal(GetLine *)
version         tecla_1.4
end             

function        gl_list_signals
include         <libtecla.h>
declaration     int gl_list_signals(GetLine *, sigset_t *)
version         tecla_l.5
end             

function        gl_handle_signal
include         <libtecla.h>
declaration     void gl_handle_signal(int, GetLine *, int)
version         tecla_l.5
end             

function        gl_error_message
include         <libtecla.h>
declaration     const char *gl_error_message(GetLine *, char *, size_t)
version         tecla_l.5
end             

function        gl_erase_terminal
include         <libtecla.h>
declaration     int gl_erase_terminal(GetLine *)
version         tecla_l.5
end             

function        gl_display_text
include         <libtecla.h>
declaration     int gl_display_text(GetLine *, int, const char *, const char *, int, int, int, const char *)
version         tecla_l.5
end             

function        gl_io_mode
include         <libtecla.h>
declaration     int gl_io_mode(GetLine *, GlIOMode)
version         tecla_l.5
end             

function        gl_raw_io
include         <libtecla.h>
declaration     int gl_raw_io(GetLine *)
version         tecla_l.5
end             

function        gl_normal_io
include         <libtecla.h>
declaration     int gl_normal_io(GetLine *)
version         tecla_l.5
end             

function        gl_abandon_line
include         <libtecla.h>
declaration     void gl_abandon_line(GetLine *)
version         tecla_l.5
end             

function        gl_return_status
include         <libtecla.h>
declaration     GlReturnStatus gl_return_status(GetLine *)
version         tecla_l.5
end             

function        gl_pending_io
include         <libtecla.h>
declaration     GlPendingIO gl_pending_io(GetLine *)
version         tecla_l.5
end             

function        gl_register_action
include         <libtecla.h>
declaration     int gl_register_action(GetLine *, void *, GlActionFn *, const char *, const char *)
version         tecla_l.5
end             

function        cpl_add_completion
include         <libtecla.h>
declaration     int cpl_add_completion(WordCompletion *, const char *, int, int, const char *, const char *, const char *)
version         tecla_1.2
end             

function        cpl_complete_word
include         <libtecla.h>
declaration     CplMatches *cpl_complete_word(WordCompletion *, const char *, int, void *, CplMatchFn *)
version         tecla_1.2
end             

function        cpl_recall_matches
include         <libtecla.h>
declaration     CplMatches *cpl_recall_matches(WordCompletion *)
version         tecla_l.5
end             

function        cpl_list_completions
include         <libtecla.h>
declaration     int cpl_list_completions(CplMatches *, FILE *, int)
version         tecla_1.2
end             

function        cpl_last_error
include         <libtecla.h>
declaration     const char *cpl_last_error(WordCompletion *)
version         tecla_1.2
end             

function        new_PathCache
include         <libtecla.h>
declaration     PathCache *new_PathCache(void)
version         tecla_1.2
end             

function        del_PathCache
include         <libtecla.h>
declaration     PathCache *del_PathCache(PathCache *)
version         tecla_1.2
end             

function        pca_last_error
include         <libtecla.h>
declaration     const char *pca_last_error(PathCache *)
version         tecla_1.2
end             

function        pca_scan_path
include         <libtecla.h>
declaration     int pca_scan_path(PathCache *, const char *)
version         tecla_1.2
end             

function        pca_set_check_fn
include         <libtecla.h>
declaration     void pca_set_check_fn(PathCache *, CplCheckFn *, void *)
version         tecla_1.2
end             

function        pca_lookup_file
include         <libtecla.h>
declaration     char *pca_lookup_file(PathCache *, const char *, int, int)
version         tecla_1.2
end             

function        new_PcaPathConf
include         <libtecla.h>
declaration     PcaPathConf *new_PcaPathConf(PathCache *)
version         tecla_1.2
end             

function        del_PcaPathConf
include         <libtecla.h>
declaration     PcaPathConf *del_PcaPathConf(PcaPathConf *)
version         tecla_1.2
end             

function        ppc_literal_escapes
include         <libtecla.h>
declaration     void ppc_literal_escapes(PcaPathConf *, int)
version         tecla_1.2
end             

function        ppc_file_start
include         <libtecla.h>
declaration     void ppc_file_start(PcaPathConf *, int)
version         tecla_1.2
end             

function        gl_append_history
include         <libtecla.h>
declaration     int gl_append_history(GetLine *, const char *)
version         tecla_1.6
end             

function        gl_automatic_history
include         <libtecla.h>
declaration     int gl_automatic_history(GetLine *, int)
version         tecla_1.6
end             

function        gl_query_char
include         <libtecla.h>
declaration     int gl_query_char(GetLine *, const char *, char)
version         tecla_1.6
end             

function        gl_read_char
include         <libtecla.h>
declaration     int gl_read_char(GetLine *)
version         tecla_1.6
end             
