#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# Copyright (c) 2019, Joyent, Inc.
#

#
# The src/ sub-directory is un-modified copy of
# https://github.com/illumos/smatch/tree/0.5.1-il-1
#
# This Makefile installs just enough for us to be able to run smatch
# locally.
#

PROG = smatch
SPARSE_VERSION = 0.5.1-il-1

include ../Makefile.tools

# We have to build smatch before we can use cw
i386_CC = $(GNUC_ROOT)/bin/gcc
sparc_CC = $(GNUC_ROOT)/bin/gcc

CFLAGS = -O -D__sun -Wall -Wno-unknown-pragmas -std=gnu99 -nodefaultlibs

SMATCHDATADIR = $(ROOTONBLDSHARE)/smatch

CFLAGS += -DSMATCHDATADIR='"$(SMATCHDATADIR)"'
CFLAGS += -DGCC_BASE='"/no/such/dir"'
CFLAGS += -DMULTIARCH_TRIPLET=NULL

LDLIBS += -lsqlite3 -lcrypto -lm -lgcc -lc
LDFLAGS = $(MAPFILE.NES:%=-Wl,-M%)
LDFLAGS += -L$(NATIVE_ADJUNCT)/lib -R$(NATIVE_ADJUNCT)/lib

CPPFLAGS += -nostdinc
CPPFLAGS += -Isrc/
CPPFLAGS += -I$(NATIVE_ADJUNCT)/include

# no install.bin
INS.file = $(RM) $@; $(CP) $< $(@D); $(CHMOD) $(FILEMODE) $@
INS.dir = mkdir -p $@; $(CHMOD) $(DIRMODE) $@

SMATCH_CHECK_OBJS:sh=ls src/check_*.c | sed -e 's+\.c+.o+;s+src/++;'

OBJS = smatch.o $(SMATCH_CHECK_OBJS)

OBJS += smatch_flow.o smatch_conditions.o smatch_slist.o smatch_states.o \
	smatch_helper.o smatch_type.o smatch_hooks.o smatch_function_hooks.o \
	smatch_modification_hooks.o smatch_extra.o smatch_estate.o smatch_math.o \
	smatch_sval.o smatch_ranges.o smatch_implied.o smatch_ignore.o smatch_project.o \
	smatch_var_sym.o smatch_tracker.o smatch_files.o smatch_expression_stacks.o \
	smatch_equiv.o smatch_buf_size.o smatch_strlen.o smatch_capped.o smatch_db.o \
	smatch_expressions.o smatch_returns.o smatch_parse_call_math.o \
	smatch_param_limit.o smatch_param_filter.o \
	smatch_param_set.o smatch_comparison.o smatch_param_compare_limit.o smatch_local_values.o \
	smatch_function_ptrs.o smatch_annotate.o smatch_string_list.o \
	smatch_param_cleared.o smatch_start_states.o \
	smatch_recurse.o smatch_data_source.o smatch_type_val.o \
	smatch_common_functions.o smatch_struct_assignment.o \
	smatch_unknown_value.o smatch_stored_conditions.o avl.o \
	smatch_function_info.o smatch_links.o smatch_auto_copy.o \
	smatch_type_links.o smatch_untracked_param.o smatch_impossible.o \
	smatch_strings.o smatch_param_used.o smatch_container_of.o smatch_address.o \
	smatch_buf_comparison.o smatch_real_absolute.o smatch_scope.o \
	smatch_imaginary_absolute.o smatch_parameter_names.o \
	smatch_return_to_param.o smatch_passes_array_size.o \
	smatch_constraints.o smatch_constraints_required.o \
	smatch_fn_arg_link.o smatch_about_fn_ptr_arg.o smatch_mtag.o \
	smatch_mtag_map.o smatch_mtag_data.o \
	smatch_param_to_mtag_data.o smatch_mem_tracker.o smatch_array_values.o \
	smatch_nul_terminator.o smatch_assigned_expr.o smatch_kernel_user_data.o \
	smatch_statement_count.o

OBJS += target.o parse.o tokenize.o pre-process.o symbol.o lib.o scope.o \
	expression.o show-parse.o evaluate.o expand.o inline.o linearize.o \
	char.o sort.o allocate.o compat-linux.o ptrlist.o \
	builtin.o \
	stats.o \
	flow.o cse.o simplify.o memops.o liveness.o storage.o unssa.o \
	dissect.o \
	macro_table.o token_store.o hashtable.o

SMATCH_DATA = \
	illumos_kernel.no_return_funcs \
	illumos_kernel.skipped_functions \
	illumos_user.no_return_funcs \
	illumos_user.skipped_functions

SMATCH_DB_DATA = \
	return_states.schema \
	call_implies.schema \
	type_value.schema \
	param_map.schema \
	function_type_size.schema \
	parameter_name.schema \
	fn_ptr_data_link.schema \
	constraints.schema \
	mtag_about.schema \
	type_info.schema \
	function_type_info.schema \
	caller_info.schema \
	function_type_value.schema \
	return_implies.schema \
	type_size.schema \
	constraints_required.schema \
	fn_data_link.schema \
	mtag_alias.schema \
	common_caller_info.schema \
	data_info.schema \
	function_type.schema \
	db.schema \
	mtag_data.schema \
	function_ptr.schema \
	sink_info.schema \
	local_values.schema \
	mtag_map.schema

ROOTONBLDDATAFILES = $(SMATCH_DATA:%=$(SMATCHDATADIR)/smatch_data/%)
ROOTONBLDDATAFILES += $(SMATCH_DB_DATA:%=$(SMATCHDATADIR)/smatch_data/db/%)

BUILT_HEADERS = src/version.h src/check_list_local.h

.KEEP_STATE:

.PARALLEL: $(OBJS)

all: $(PROG)

install: all .WAIT $(ROOTONBLDMACHPROG) $(ROOTONBLDDATAFILES)

clean:
	rm -f $(OBJS) $(BUILT_HEADERS)

$(ROOTONBLDDATAFILES): $(SMATCHDATADIR)/smatch_data/db

$(SMATCHDATADIR)/smatch_data/%: src/smatch_data/%
	$(INS.file)

$(SMATCHDATADIR)/smatch_data/db:
	$(INS.dir)

$(SMATCHDATADIR)/smatch_data:
	$(INS.dir)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o: src/%.c $(BUILT_HEADERS)
	$(COMPILE.c) -o $@ $<

%.o: src/cwchash/%.c
	$(COMPILE.c) -o $@ $<

src/check_list_local.h:
	touch src/check_list_local.h

src/version.h:
	echo '#define SPARSE_VERSION "$(SPARSE_VERSION)"' > src/version.h

include ../Makefile.targ
