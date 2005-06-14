#
# Copyright (c) 1998-1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/ss/spec/ss.spec

function	debugDisplaySS
declaration	void debugDisplaySS(int onOff)
version		SUNWprivate_1.1
end		

function	ss_abort_subsystem
declaration	void ss_abort_subsystem(int sci_idx, int code)
version		SUNWprivate_1.1
end		

function	ss_add_info_dir
declaration	void ss_add_info_dir(int sci_idx, char *info_dir, int *code_ptr)
version		SUNWprivate_1.1
end		

function	ss_add_request_table
include		<ss.h>
declaration	void ss_add_request_table(int sci_idx, \
			ss_request_table *rqtbl_ptr, \
			int position, int *code_ptr)
version		SUNWprivate_1.1
end		

function	ss_create_invocation
declaration	int ss_create_invocation(char *subsystem_name, \
			char *version_string, char *info_ptr, \
			ss_request_table *request_table_ptr, int *code_ptr)

version		SUNWprivate_1.1
end		

function	ss_delete_info_dir
declaration	void ss_delete_info_dir(int sci_idx, char *info_dir, \
			int *code_ptr)
version		SUNWprivate_1.1
end		

function	ss_delete_invocation
declaration	void ss_delete_invocation(int sci_idx)
version		SUNWprivate_1.1
end		

function	ss_delete_request_table
declaration	void ss_delete_request_table(int sci_idx, \
			ss_request_table *rqtbl_ptr, int *code_ptr)
version		SUNWprivate_1.1
end		

function	ss_error
declaration	void ss_error (int sci_idx, long code, const char * fmt, ...)
version		SUNWprivate_1.1
end		

function	ss_execute_command
declaration	int ss_execute_command(int sci_idx, register char *argv[])
version		SUNWprivate_1.1
end		

function	ss_execute_line
declaration	int ss_execute_line (int sci_idx, char *line_ptr)
version		SUNWprivate_1.1
end		

function	ss_get_prompt
declaration	char *ss_get_prompt(int sci_idx)
version		SUNWprivate_1.1
end		

function	ss_help
include		<ss_internal.h>
declaration	void ss_help (int argc, char const * const *argv, \
			int sci_idx, pointer info_ptr)
version		SUNWprivate_1.1
end		

function	ss_list_requests
include		<ss_internal.h>
declaration	void ss_list_requests(int argc, char **argv, int sci_idx, \
			pointer info_ptr)
version		SUNWprivate_1.1
end		

function	ss_listen
declaration	int ss_listen (int sci_idx)
version		SUNWprivate_1.1
end		

function	ss_name
declaration	char *ss_name(int sci_idx)
version		SUNWprivate_1.1
end		

function	ss_page_stdin
declaration	void ss_page_stdin()
version		SUNWprivate_1.1
end		

function	ss_pager_create
declaration	int ss_pager_create()
version		SUNWprivate_1.1
end		

function	ss_parse
declaration	char **ss_parse (int sci_idx, register char *line_ptr, \
			int *argc_ptr)
version		SUNWprivate_1.1
end		

function	ss_perror
declaration	void ss_perror (int sci_idx, long code, char const *msg)
version		SUNWprivate_1.1
end		

function	ss_quit
include		<ss_internal.h>
declaration	int ss_quit(int argc, char **argv, int sci_idx, pointer infop)
version		SUNWprivate_1.1
end		

function	ss_self_identify
declaration	void ss_self_identify(int argc, char **argv, int sci_idx)
version		SUNWprivate_1.1
end		

function	ss_set_prompt
declaration	void ss_set_prompt(int sci_idx, char *new_prompt)
version		SUNWprivate_1.1
end		

function	ss_std_requests
version		SUNWprivate_1.1
end		

function	ss_subsystem_name
declaration	void ss_subsystem_name (int argc, char **argv, int sci_idx)
version		SUNWprivate_1.1
end		

function	ss_subsystem_version
declaration	void ss_subsystem_version (int argc, char **argv, int sci_idx)
version		SUNWprivate_1.1
end		

function	ss_unimplemented
declaration	void ss_unimplemented (int argc, char **argv, int sci_idx)
version		SUNWprivate_1.1
end		
