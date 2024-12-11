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
# Copyright 2020 Joyent, Inc.
#

#
# The src/ sub-directory is un-modified copy of
# https://github.com/illumos/smatch/tree/$SPARSE_VERSION
#
# This Makefile installs just enough for us to be able to run smatch
# locally.
#

PROG = smatch
SPARSE_VERSION = 0.6.1-rc1-il-7

include ../Makefile.tools

# We have to build smatch before we can use cw
NATIVECC = $(GNUC_ROOT)/bin/gcc
# sparc doesn't recognise -msave-args
i386_SMATCHFLAGS = -msave-args
sparc_SMATCHFLAGS =

# When we use builtins, then ld's -zguidance will complain that libm is
# unused on x86 because the compiler will replace ceil(3M) with its own copy.
# However, on SPARC, it doesn't. So for now we disable builtins to make it
# consistent.
CFLAGS = -O -m64 -std=gnu99 -nodefaultlibs -D__sun $($(NATIVE_MACH)_SMATCHFLAGS)
CFLAGS += -fno-builtin
CFLAGS += -Wall -Wno-psabi

SMATCHDATADIR = $(ROOTONBLDSHARE)/smatch

CFLAGS += -DSMATCHDATADIR='"$(SMATCHDATADIR)"'
CFLAGS += -DGCC_BASE='"/no/such/dir"'
CFLAGS += -DMULTIARCH_TRIPLET=NULL

LDCHECKS = $(ZASSERTDEFLIB) $(ZGUIDANCE) $(ZFATALWARNINGS)
LDLIBS += $(ZLAZYLOAD) $(ZDIRECT) -lsqlite3 -lmd -lgcc -lm -lc
LDFLAGS = $(MAPFILE.NES:%=-Wl,-M%)
LDFLAGS += -L$(NATIVE_ADJUNCT)/lib -R$(NATIVE_ADJUNCT)/lib

NATIVE_LIBS += libsqlite3.so libmd.so libm.so libc.so
LDFLAGS += $(NATIVE_LIBS:%=$(ZASSERTDEFLIB)=%)

CPPFLAGS += -nostdinc
CPPFLAGS += -Isrc/
CPPFLAGS += -I$(NATIVE_ADJUNCT)/include

# no install.bin
INS.file = $(RM) $@; $(CP) $< $(@D); $(CHMOD) $(FILEMODE) $@
INS.dir = mkdir -p $@; $(CHMOD) $(DIRMODE) $@

# fine for us
OS=linux

LIB_OBJS =
LIB_OBJS += allocate.o
LIB_OBJS += builtin.o
LIB_OBJS += char.o
LIB_OBJS += compat-$(OS).o
LIB_OBJS += cse.o
LIB_OBJS += dissect.o
LIB_OBJS += dominate.o
LIB_OBJS += evaluate.o
LIB_OBJS += expand.o
LIB_OBJS += expression.o
LIB_OBJS += flow.o
LIB_OBJS += flowgraph.o
LIB_OBJS += inline.o
LIB_OBJS += ir.o
LIB_OBJS += lib.o
LIB_OBJS += linearize.o
LIB_OBJS += liveness.o
LIB_OBJS += memops.o
LIB_OBJS += opcode.o
LIB_OBJS += optimize.o
LIB_OBJS += parse.o
LIB_OBJS += pre-process.o
LIB_OBJS += ptrlist.o
LIB_OBJS += ptrmap.o
LIB_OBJS += scope.o
LIB_OBJS += show-parse.o
LIB_OBJS += simplify.o
LIB_OBJS += sort.o
LIB_OBJS += ssa.o
LIB_OBJS += sset.o
LIB_OBJS += stats.o
LIB_OBJS += storage.o
LIB_OBJS += symbol.o
LIB_OBJS += target.o
LIB_OBJS += tokenize.o
LIB_OBJS += unssa.o
LIB_OBJS += utils.o
LIB_OBJS += macro_table.o
LIB_OBJS += token_store.o
LIB_OBJS += hashtable.o

SMATCH_OBJS =
SMATCH_OBJS += avl.o
SMATCH_OBJS += smatch_about_fn_ptr_arg.o
SMATCH_OBJS += smatch_address.o
SMATCH_OBJS += smatch_annotate.o
SMATCH_OBJS += smatch_array_values.o
SMATCH_OBJS += smatch_assigned_expr.o
SMATCH_OBJS += smatch_bits.o
SMATCH_OBJS += smatch_buf_comparison.o
SMATCH_OBJS += smatch_buf_size.o
SMATCH_OBJS += smatch_capped.o
SMATCH_OBJS += smatch_common_functions.o
SMATCH_OBJS += smatch_comparison.o
SMATCH_OBJS += smatch_conditions.o
SMATCH_OBJS += smatch_constraints.o
SMATCH_OBJS += smatch_constraints_required.o
SMATCH_OBJS += smatch_container_of.o
SMATCH_OBJS += smatch_data_source.o
SMATCH_OBJS += smatch_db.o
SMATCH_OBJS += smatch_equiv.o
SMATCH_OBJS += smatch_estate.o
SMATCH_OBJS += smatch_expressions.o
SMATCH_OBJS += smatch_expression_stacks.o
SMATCH_OBJS += smatch_extra.o
SMATCH_OBJS += smatch_files.o
SMATCH_OBJS += smatch_flow.o
SMATCH_OBJS += smatch_fresh_alloc.o
SMATCH_OBJS += smatch_fn_arg_link.o
SMATCH_OBJS += smatch_function_hooks.o
SMATCH_OBJS += smatch_function_info.o
SMATCH_OBJS += smatch_function_ptrs.o
SMATCH_OBJS += smatch_helper.o
SMATCH_OBJS += smatch_hooks.o
SMATCH_OBJS += smatch_ignore.o
SMATCH_OBJS += smatch_imaginary_absolute.o
SMATCH_OBJS += smatch_implied.o
SMATCH_OBJS += smatch_impossible.o
SMATCH_OBJS += smatch_integer_overflow.o
SMATCH_OBJS += smatch_kernel_user_data.o
SMATCH_OBJS += smatch_links.o
SMATCH_OBJS += smatch_math.o
SMATCH_OBJS += smatch_mem_tracker.o
SMATCH_OBJS += smatch_modification_hooks.o
SMATCH_OBJS += smatch_mtag_data.o
SMATCH_OBJS += smatch_mtag_map.o
SMATCH_OBJS += smatch_mtag.o
SMATCH_OBJS += smatch_nul_terminator.o
SMATCH_OBJS += smatch_param_cleared.o
SMATCH_OBJS += smatch_param_compare_limit.o
SMATCH_OBJS += smatch_parameter_names.o
SMATCH_OBJS += smatch_param_filter.o
SMATCH_OBJS += smatch_param_limit.o
SMATCH_OBJS += smatch_param_set.o
SMATCH_OBJS += smatch_param_to_mtag_data.o
SMATCH_OBJS += smatch_param_used.o
SMATCH_OBJS += smatch_parse_call_math.o
SMATCH_OBJS += smatch_passes_array_size.o
SMATCH_OBJS += smatch_project.o
SMATCH_OBJS += smatch_ranges.o
SMATCH_OBJS += smatch_real_absolute.o
SMATCH_OBJS += smatch_recurse.o
SMATCH_OBJS += smatch_returns.o
SMATCH_OBJS += smatch_return_to_param.o
SMATCH_OBJS += smatch_scope.o
SMATCH_OBJS += smatch_slist.o
SMATCH_OBJS += smatch_start_states.o
SMATCH_OBJS += smatch_statement_count.o
SMATCH_OBJS += smatch_states.o
SMATCH_OBJS += smatch_stored_conditions.o
SMATCH_OBJS += smatch_string_list.o
SMATCH_OBJS += smatch_strings.o
SMATCH_OBJS += smatch_strlen.o
SMATCH_OBJS += smatch_struct_assignment.o
SMATCH_OBJS += smatch_sval.o
SMATCH_OBJS += smatch_tracker.o
SMATCH_OBJS += smatch_type_links.o
SMATCH_OBJS += smatch_type.o
SMATCH_OBJS += smatch_type_val.o
SMATCH_OBJS += smatch_unknown_value.o
SMATCH_OBJS += smatch_untracked_param.o
SMATCH_OBJS += smatch_var_sym.o
SMATCH_OBJS += smatch_parsed_conditions.o

SMATCH_CHECK_OBJS:sh=ls src/check_*.c | sed -e 's+\.c+.o+;s+src/++;'

OBJS = smatch.o $(LIB_OBJS) $(SMATCH_OBJS) $(SMATCH_CHECK_OBJS)

SMATCH_DATA = \
	illumos_kernel.skipped_functions \
	illumos_user.skipped_functions

SMATCH_DB_DATA =
SMATCH_DB_DATA += call_implies.schema
SMATCH_DB_DATA += function_ptr.schema
SMATCH_DB_DATA += mtag_map.schema
SMATCH_DB_DATA += caller_info.schema
SMATCH_DB_DATA += function_type.schema
SMATCH_DB_DATA += param_map.schema
SMATCH_DB_DATA += common_caller_info.schema
SMATCH_DB_DATA += function_type_info.schema
SMATCH_DB_DATA += parameter_name.schema
SMATCH_DB_DATA += constraints.schema
SMATCH_DB_DATA += function_type_size.schema
SMATCH_DB_DATA += return_implies.schema
SMATCH_DB_DATA += constraints_required.schema
SMATCH_DB_DATA += function_type_value.schema
SMATCH_DB_DATA += return_states.schema
SMATCH_DB_DATA += data_info.schema
SMATCH_DB_DATA += local_values.schema
SMATCH_DB_DATA += sink_info.schema
SMATCH_DB_DATA += db.schema
SMATCH_DB_DATA += mtag_about.schema
SMATCH_DB_DATA += type_info.schema
SMATCH_DB_DATA += fn_data_link.schema
SMATCH_DB_DATA += mtag_alias.schema
SMATCH_DB_DATA += type_size.schema
SMATCH_DB_DATA += fn_ptr_data_link.schema
SMATCH_DB_DATA += mtag_data.schema
SMATCH_DB_DATA += mtag_info.schema
SMATCH_DB_DATA += type_value.schema

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
