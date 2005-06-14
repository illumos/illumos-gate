#
# Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_profile.spec
#

function	profile_add_node
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_add_node (struct profile_node *section, \
			const char *name, const char *value, \
			struct profile_node **ret_node)
version		SUNWprivate_1.1
end

function	profile_close_file
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_close_file (prf_file_t prf)
version		SUNWprivate_1.1
end

function	profile_create_node
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_create_node (const char *name,\
			const char *value, struct profile_node **ret_node)
version		SUNWprivate_1.1
end

function	profile_find_node_relation
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_find_node_relation ( \
			struct profile_node *section, const char *name, \
			void **state, char **ret_name, char **value)
version		SUNWprivate_1.1
end

function	profile_find_node_subsection
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_find_node_subsection ( \
			struct profile_node *section, const char *name, \
			void **state, char **ret_name, \
			struct profile_node **subsection)
version		SUNWprivate_1.1
end

function	profile_free_node
include		<stdio.h>, <prof_int.h>
declaration	void profile_free_node (struct profile_node *node)
version		SUNWprivate_1.1
end

function	profile_get_integer
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_get_integer (profile_t profile, \
		const char *name, const char *subname, const char *subsubname, \
		int def_val, int *ret_int)
version		SUNWprivate_1.1
end

function	profile_get_node_parent
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_get_node_parent ( \
			struct profile_node *section, \
			struct profile_node **parent)
version		SUNWprivate_1.1
end

function	profile_get_options_boolean
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_get_options_boolean (profile_t profile, \
			char **section, profile_options_boolean *options)
version		SUNWprivate_1.1
end

function	profile_get_options_string
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_get_options_string (profile_t profile, \
			char **section, profile_option_strings *options)
version		SUNWprivate_1.1
end

function	profile_get_string
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_get_string ( \
			profile_t profile, const char *name, \
			const char *subname, const char *subsubname, \
			const char  *def_val, char **ret_string)
version		SUNWprivate_1.1
end

function	profile_get_values
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_get_values (profile_t profile, \
			const char **names, char ***ret_values)
version		SUNWprivate_1.1
end

function	profile_init
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_init (const char **filenames, \
			profile_t *ret_profile)
version		SUNWprivate_1.1
end

function	profile_init_path
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_init_path (const char *filepath, \
			profile_t *ret_profile)
version		SUNWprivate_1.1
end

function	profile_open_file
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_open_file (const char *filename, \
			prf_file_t *ret_prof)
version		SUNWprivate_1.1
end

function	profile_parse_file
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_parse_file (FILE    *f, \
			struct profile_node **root)
version		SUNWprivate_1.1
end

function	profile_release
include		<stdio.h>, <prof_int.h>
declaration	void profile_release (profile_t profile)
version		SUNWprivate_1.1
end

function	profile_ser_externalize
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_ser_externalize (const char *unused, \
			profile_t profile, unsigned char **bufpp, \
			size_t *remainp)
version		SUNWprivate_1.1
end

function	profile_ser_internalize
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_ser_internalize (const char *unused, \
			profile_t *profilep, unsigned char **bufpp, \
			size_t *remainp)
version		SUNWprivate_1.1
end

function	profile_ser_size
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_ser_size (const char *unused, \
			profile_t profile, size_t *sizep)
version		SUNWprivate_1.1
end

function	profile_update_file
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_update_file (prf_file_t prf)
version		SUNWprivate_1.1
end

function	profile_verify_node
include		<stdio.h>, <prof_int.h>
declaration	errcode_t profile_verify_node (struct profile_node *node)
version		SUNWprivate_1.1
end

# spec2trace RFE
function	reset_com_err_hook
version		SUNWprivate_1.1
end

# spec2trace RFE
function	set_com_err_hook
version		SUNWprivate_1.1
end
