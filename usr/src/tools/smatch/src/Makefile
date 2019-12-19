VERSION=0.6.1-rc1-il-3

########################################################################
# The following variables can be overwritten from the command line
OS = linux


CC ?= gcc
LD = $(CC)
AR = ar

CFLAGS ?= -g

DESTDIR ?=
PREFIX ?= $(HOME)
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

PKG_CONFIG ?= pkg-config

CHECKER_FLAGS ?= -Wno-vla

# Allow users to override build settings without dirtying their trees
# For debugging, put this in local.mk:
#
#     CFLAGS += -O0 -DDEBUG -g3 -gdwarf-2
#
SPARSE_LOCAL_CONFIG ?= local.mk
-include ${SPARSE_LOCAL_CONFIG}
########################################################################


LIB_OBJS :=
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
LIB_OBJS += cwchash/hashtable.o

PROGRAMS :=
PROGRAMS += compile
PROGRAMS += ctags
PROGRAMS += example
PROGRAMS += graph
PROGRAMS += obfuscate
PROGRAMS += sparse
PROGRAMS += test-dissect
PROGRAMS += test-lexing
PROGRAMS += test-linearize
PROGRAMS += test-parsing
PROGRAMS += test-unssa

INST_PROGRAMS=smatch sparse cgcc
INST_MAN1=sparse.1 cgcc.1


all:

########################################################################
# common flags/options/...

cflags = -fno-strict-aliasing
cflags += -Wall -Wwrite-strings -Wno-switch -Wno-psabi

GCC_BASE := $(shell $(CC) --print-file-name=)
cflags += -DGCC_BASE=\"$(GCC_BASE)\"

MULTIARCH_TRIPLET := $(shell $(CC) -print-multiarch 2>/dev/null)
cflags += -DMULTIARCH_TRIPLET=\"$(MULTIARCH_TRIPLET)\"


bindir := $(DESTDIR)$(BINDIR)
man1dir := $(DESTDIR)$(MANDIR)/man1

########################################################################
# target specificities

compile: compile-i386.o
EXTRA_OBJS += compile-i386.o

# Can we use GCC's generated dependencies?
HAVE_GCC_DEP:=$(shell touch .gcc-test.c && 				\
		$(CC) -c -Wp,-MP,-MMD,.gcc-test.d .gcc-test.c 2>/dev/null && \
		echo 'yes'; rm -f .gcc-test.d .gcc-test.o .gcc-test.c)
ifeq ($(HAVE_GCC_DEP),yes)
cflags += -Wp,-MP,-MMD,$(@D)/.$(@F).d
endif

# Can we use libxml (needed for c2xml)?
HAVE_LIBXML:=$(shell $(PKG_CONFIG) --exists libxml-2.0 2>/dev/null && echo 'yes')
ifeq ($(HAVE_LIBXML),yes)
PROGRAMS+=c2xml
INST_PROGRAMS+=c2xml
c2xml-ldlibs := $(shell $(PKG_CONFIG) --libs libxml-2.0)
c2xml-cflags := $(shell $(PKG_CONFIG) --cflags libxml-2.0)
else
$(warning Your system does not have libxml, disabling c2xml)
endif

# Can we use gtk (needed for test-inspect)
GTK_VERSION:=3.0
HAVE_GTK:=$(shell $(PKG_CONFIG) --exists gtk+-$(GTK_VERSION) 2>/dev/null && echo 'yes')
ifneq ($(HAVE_GTK),yes)
GTK_VERSION:=2.0
HAVE_GTK:=$(shell $(PKG_CONFIG) --exists gtk+-$(GTK_VERSION) 2>/dev/null && echo 'yes')
endif
ifeq ($(HAVE_GTK),yes)
GTK_CFLAGS := $(shell $(PKG_CONFIG) --cflags gtk+-$(GTK_VERSION))
ast-view-cflags := $(GTK_CFLAGS)
ast-model-cflags := $(GTK_CFLAGS)
ast-inspect-cflags := $(GTK_CFLAGS)
test-inspect-cflags := $(GTK_CFLAGS)
test-inspect-ldlibs := $(shell $(PKG_CONFIG) --libs gtk+-$(GTK_VERSION))
test-inspect: ast-model.o ast-view.o ast-inspect.o
EXTRA_OBJS += ast-model.o ast-view.o ast-inspect.o
PROGRAMS += test-inspect
INST_PROGRAMS += test-inspect
else
$(warning Your system does not have gtk3/gtk2, disabling test-inspect)
endif

# Can we use LLVM (needed for ... sparse-llvm)?
LLVM_CONFIG:=llvm-config
HAVE_LLVM:=$(shell $(LLVM_CONFIG) --version >/dev/null 2>&1 && echo 'yes')
ifeq ($(HAVE_LLVM),yes)
arch := $(shell uname -m)
ifeq (${MULTIARCH_TRIPLET},x86_64-linux-gnux32)
arch := x32
endif
ifneq ($(filter ${arch},i386 i486 i586 i686 x86_64 amd64),)
LLVM_VERSION:=$(shell $(LLVM_CONFIG) --version)
ifeq ($(shell expr "$(LLVM_VERSION)" : '[3-9]\.'),2)
LLVM_PROGS := sparse-llvm
$(LLVM_PROGS): LD := g++
LLVM_LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags)
LLVM_CFLAGS := -I$(shell $(LLVM_CONFIG) --includedir)
LLVM_LIBS := $(shell $(LLVM_CONFIG) --libs)
LLVM_LIBS += $(shell $(LLVM_CONFIG) --system-libs 2>/dev/null)
LLVM_LIBS += $(shell $(LLVM_CONFIG) --cxxflags | grep -F -q -e '-stdlib=libc++' && echo -lc++)
PROGRAMS += $(LLVM_PROGS)
INST_PROGRAMS += sparse-llvm sparsec
sparse-llvm-cflags := $(LLVM_CFLAGS) -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS
sparse-llvm-ldflags := $(LLVM_LDFLAGS)
sparse-llvm-ldlibs := $(LLVM_LIBS)
else
$(warning LLVM 3.0 or later required. Your system has version $(LLVM_VERSION) installed.)
endif
else
$(warning sparse-llvm disabled on ${arch})
endif
else
$(warning Your system does not have llvm, disabling sparse-llvm)
endif

########################################################################
LIBS := libsparse.a
OBJS := $(LIB_OBJS) $(EXTRA_OBJS) $(PROGRAMS:%=%.o)

# Pretty print
V := @
Q := $(V:1=)

########################################################################

SMATCHDATADIR=$(INSTALL_PREFIX)/share/smatch

SMATCH_OBJS :=
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
SMATCH_OBJS += smatch_parsed_conditions.o
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

SMATCH_CHECKS=$(shell ls check_*.c | sed -e 's/\.c/.o/')
SMATCH_DATA=smatch_data/kernel.allocation_funcs \
	smatch_data/kernel.frees_argument smatch_data/kernel.puts_argument \
	smatch_data/kernel.dev_queue_xmit smatch_data/kernel.returns_err_ptr \
	smatch_data/kernel.dma_funcs smatch_data/kernel.returns_held_funcs \
	smatch_data/kernel.no_return_funcs

SMATCH_SCRIPTS=smatch_scripts/add_gfp_to_allocations.sh \
	smatch_scripts/build_kernel_data.sh \
	smatch_scripts/call_tree.pl smatch_scripts/filter_kernel_deref_check.sh \
	smatch_scripts/find_expanded_holes.pl smatch_scripts/find_null_params.sh \
	smatch_scripts/follow_params.pl smatch_scripts/gen_allocation_list.sh \
	smatch_scripts/gen_bit_shifters.sh smatch_scripts/gen_dma_funcs.sh \
	smatch_scripts/generisize.pl smatch_scripts/gen_err_ptr_list.sh \
	smatch_scripts/gen_expects_err_ptr.sh smatch_scripts/gen_frees_list.sh \
	smatch_scripts/gen_gfp_flags.sh smatch_scripts/gen_no_return_funcs.sh \
	smatch_scripts/gen_puts_list.sh smatch_scripts/gen_returns_held.sh \
	smatch_scripts/gen_rosenberg_funcs.sh smatch_scripts/gen_sizeof_param.sh \
	smatch_scripts/gen_unwind_functions.sh smatch_scripts/kchecker \
	smatch_scripts/kpatch.sh smatch_scripts/new_bugs.sh \
	smatch_scripts/show_errs.sh smatch_scripts/show_ifs.sh \
	smatch_scripts/show_unreachable.sh smatch_scripts/strip_whitespace.pl \
	smatch_scripts/summarize_errs.sh smatch_scripts/test_kernel.sh \
	smatch_scripts/trace_params.pl smatch_scripts/unlocked_paths.pl \
	smatch_scripts/whitespace_only.sh smatch_scripts/wine_checker.sh \

SMATCH_LDFLAGS := -lsqlite3  -lssl -lcrypto -lm

smatch: smatch.o $(SMATCH_OBJS) $(SMATCH_CHECKS) $(LIBS)
	$(Q)$(LD) -o $@ $< $(SMATCH_OBJS) $(SMATCH_CHECKS) $(LIBS) $(SMATCH_LDFLAGS)

check_list_local.h:
	touch check_list_local.h

smatch.o: smatch.c $(LIB_H) smatch.h check_list.h check_list_local.h
	$(CC) $(CFLAGS) -c smatch.c -DSMATCHDATADIR='"$(SMATCHDATADIR)"'

$(SMATCH_OBJS) $(SMATCH_CHECKS): smatch.h smatch_slist.h smatch_extra.h avl.h

########################################################################
all: $(PROGRAMS) smatch

ldflags += $($(@)-ldflags) $(LDFLAGS)
ldlibs  += $($(@)-ldlibs)  $(LDLIBS) -lm
$(PROGRAMS): % : %.o $(LIBS)
	@echo "  LD      $@"
	$(Q)$(LD) $(ldflags) $^ $(ldlibs) -o $@

libsparse.a: $(LIB_OBJS)
	@echo "  AR      $@"
	$(Q)$(AR) rcs $@ $^


cflags   += $($(*)-cflags) $(CPPFLAGS) $(CFLAGS)
%.o: %.c
	@echo "  CC      $@"
	$(Q)$(CC) $(cflags) -c -o $@ $<

%.sc: %.c sparse
	@echo "  CHECK   $<"
	$(Q)CHECK=./sparse ./cgcc -no-compile $(CHECKER_FLAGS) $(cflags) -c $<

selfcheck: $(OBJS:.o=.sc)


SPARSE_VERSION:=$(shell git describe --dirty 2>/dev/null || echo '$(VERSION)')
lib.o: version.h
version.h: FORCE
	@echo '#define SPARSE_VERSION "$(SPARSE_VERSION)"' > version.h.tmp
	@if cmp -s version.h version.h.tmp; then \
		rm version.h.tmp; \
	else \
		echo "  GEN     $@"; \
		mv version.h.tmp version.h; \
	fi


check: all
	$(Q)cd validation && ./test-suite
validation/%.t: $(PROGRAMS)
	@validation/test-suite single $*.c


clean: clean-check
	@rm -f *.[oa] .*.d $(PROGRAMS) version.h smatch
clean-check:
	@echo "  CLEAN"
	@find validation/ \( -name "*.c.output.*" \
			  -o -name "*.c.error.*" \
			  -o -name "*.o" \
	                  \) -exec rm {} \;


install: install-bin install-man
install-bin: $(INST_PROGRAMS:%=$(bindir)/%)
install-man: $(INST_MAN1:%=$(man1dir)/%)

$(bindir)/%: %
	@echo "  INSTALL $@"
	$(Q)install -D        $< $@ || exit 1;
$(man1dir)/%: %
	@echo "  INSTALL $@"
	$(Q)install -D -m 644 $< $@ || exit 1;

.PHONY: FORCE

# GCC's dependencies
-include $(OBJS:%.o=.%.o.d)
