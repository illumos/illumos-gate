VERSION=0.5.1

# Generating file version.h if current version has changed
SPARSE_VERSION:=$(shell git describe 2>/dev/null || echo '$(VERSION)')
VERSION_H := $(shell cat version.h 2>/dev/null)
ifneq ($(lastword $(VERSION_H)),"$(SPARSE_VERSION)")
$(info $(shell echo '     GEN      'version.h))
$(shell echo '#define SPARSE_VERSION "$(SPARSE_VERSION)"' > version.h)
endif

OS = linux

ifeq ($(CC),"")
CC = gcc
endif

CFLAGS += -O2 -finline-functions -fno-strict-aliasing -g
CFLAGS += -Wall -Wwrite-strings -Wno-switch
LDFLAGS += -g -lm -lsqlite3 -lssl -lcrypto
LD = gcc
AR = ar
PKG_CONFIG = pkg-config
COMMON_CFLAGS = -O2 -finline-functions -fno-strict-aliasing -g
COMMON_CFLAGS += -Wall -Wwrite-strings

ALL_CFLAGS = $(COMMON_CFLAGS) $(PKG_CFLAGS) $(CFLAGS)
#
# For debugging, put this in local.mk:
#
#     CFLAGS += -O0 -DDEBUG -g3 -gdwarf-2
#

HAVE_LIBXML:=$(shell $(PKG_CONFIG) --exists libxml-2.0 2>/dev/null && echo 'yes')
HAVE_GCC_DEP:=$(shell touch .gcc-test.c && 				\
		$(CC) -c -Wp,-MD,.gcc-test.d .gcc-test.c 2>/dev/null && \
		echo 'yes'; rm -f .gcc-test.d .gcc-test.o .gcc-test.c)

GTK_VERSION:=3.0
HAVE_GTK:=$(shell $(PKG_CONFIG) --exists gtk+-$(GTK_VERSION) 2>/dev/null && echo 'yes')
ifneq ($(HAVE_GTK),yes)
	GTK_VERSION:=2.0
	HAVE_GTK:=$(shell $(PKG_CONFIG) --exists gtk+-$(GTK_VERSION) 2>/dev/null && echo 'yes')
endif

LLVM_CONFIG:=llvm-config
HAVE_LLVM:=$(shell $(LLVM_CONFIG) --version >/dev/null 2>&1 && echo 'yes')

GCC_BASE := $(shell $(CC) --print-file-name=)
COMMON_CFLAGS += -DGCC_BASE=\"$(GCC_BASE)\"

MULTIARCH_TRIPLET := $(shell $(CC) -print-multiarch 2>/dev/null)
COMMON_CFLAGS += -DMULTIARCH_TRIPLET=\"$(MULTIARCH_TRIPLET)\"

ifeq ($(HAVE_GCC_DEP),yes)
COMMON_CFLAGS += -Wp,-MD,$(@D)/.$(@F).d
endif

DESTDIR=
INSTALL_PREFIX ?=$(HOME)
BINDIR=$(INSTALL_PREFIX)/bin
LIBDIR=$(INSTALL_PREFIX)/lib
MANDIR=$(INSTALL_PREFIX)/share/man
MAN1DIR=$(MANDIR)/man1
INCLUDEDIR=$(INSTALL_PREFIX)/include
PKGCONFIGDIR=$(LIBDIR)/pkgconfig
SMATCHDATADIR=$(INSTALL_PREFIX)/share/smatch

SMATCH_FILES=smatch_flow.o smatch_conditions.o smatch_slist.o smatch_states.o \
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

PROGRAMS=test-lexing test-parsing obfuscate compile graph sparse \
	 test-linearize example test-unssa test-dissect ctags
INST_PROGRAMS=smatch cgcc

INST_MAN1=sparse.1 cgcc.1

ifeq ($(HAVE_LIBXML),yes)
PROGRAMS+=c2xml
INST_PROGRAMS+=c2xml
c2xml_EXTRA_OBJS = `$(PKG_CONFIG) --libs libxml-2.0`
LIBXML_CFLAGS := $(shell $(PKG_CONFIG) --cflags libxml-2.0)
else
$(warning Your system does not have libxml, disabling c2xml)
endif

ifeq ($(HAVE_GTK),yes)
GTK_CFLAGS := $(shell $(PKG_CONFIG) --cflags gtk+-$(GTK_VERSION))
GTK_LIBS := $(shell $(PKG_CONFIG) --libs gtk+-$(GTK_VERSION))
PROGRAMS += test-inspect
INST_PROGRAMS += test-inspect
test-inspect_EXTRA_DEPS := ast-model.o ast-view.o ast-inspect.o
test-inspect_OBJS := test-inspect.o $(test-inspect_EXTRA_DEPS)
$(test-inspect_OBJS) $(test-inspect_OBJS:.o=.sc): PKG_CFLAGS += $(GTK_CFLAGS)
test-inspect_EXTRA_OBJS := $(GTK_LIBS)
else
$(warning Your system does not have gtk3/gtk2, disabling test-inspect)
endif

ifeq ($(HAVE_LLVM),yes)
ifeq ($(shell uname -m | grep -q '\(i386\|x86\)' && echo ok),ok)
LLVM_VERSION:=$(shell $(LLVM_CONFIG) --version)
ifeq ($(shell expr "$(LLVM_VERSION)" : '[3-9]\.'),2)
LLVM_PROGS := sparse-llvm
$(LLVM_PROGS): LD := g++
LLVM_LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags)
LLVM_CFLAGS := $(shell $(LLVM_CONFIG) --cflags | sed -e "s/-DNDEBUG//g" | sed -e "s/-pedantic//g")
LLVM_LIBS := $(shell $(LLVM_CONFIG) --libs)
LLVM_LIBS += $(shell $(LLVM_CONFIG) --system-libs 2>/dev/null)
PROGRAMS += $(LLVM_PROGS)
INST_PROGRAMS += sparse-llvm sparsec
sparse-llvm.o sparse-llvm.sc: PKG_CFLAGS += $(LLVM_CFLAGS)
sparse-llvm_EXTRA_OBJS := $(LLVM_LIBS) $(LLVM_LDFLAGS)
else
$(warning LLVM 3.0 or later required. Your system has version $(LLVM_VERSION) installed.)
endif
else
$(warning sparse-llvm disabled on $(shell uname -m))
endif
else
$(warning Your system does not have llvm, disabling sparse-llvm)
endif

LIB_H=    token.h parse.h lib.h symbol.h scope.h expression.h target.h \
	  linearize.h bitmap.h ident-list.h compat.h flow.h allocate.h \
	  storage.h ptrlist.h dissect.h

LIB_OBJS= target.o parse.o tokenize.o pre-process.o symbol.o lib.o scope.o \
	  expression.o show-parse.o evaluate.o expand.o inline.o linearize.o \
	  char.o sort.o allocate.o compat-$(OS).o ptrlist.o \
	  builtin.o \
	  stats.o \
	  flow.o cse.o simplify.o memops.o liveness.o storage.o unssa.o \
	  dissect.o \
	  macro_table.o token_store.o cwchash/hashtable.o

LIB_FILE= libsparse.a
SLIB_FILE= libsparse.so

# If you add $(SLIB_FILE) to this, you also need to add -fpic to BASIC_CFLAGS above.
# Doing so incurs a noticeable performance hit, and Sparse does not have a
# stable shared library interface, so this does not occur by default.  If you
# really want a shared library, you may want to build Sparse twice: once
# without -fpic to get all the Sparse tools, and again with -fpic to get the
# shared library.
LIBS=$(LIB_FILE)

#
# Pretty print
#
V	      = @
Q	      = $(V:1=)
QUIET_CC      = $(Q:@=@echo    '     CC       '$@;)
QUIET_CHECK   = $(Q:@=@echo    '     CHECK    '$<;)
QUIET_AR      = $(Q:@=@echo    '     AR       '$@;)
QUIET_GEN     = $(Q:@=@echo    '     GEN      '$@;)
QUIET_LINK    = $(Q:@=@echo    '     LINK     '$@;)
# We rely on the -v switch of install to print 'file -> $install_dir/file'
QUIET_INST_SH = $(Q:@=echo -n  '     INSTALL  ';)
QUIET_INST    = $(Q:@=@echo -n '     INSTALL  ';)

define INSTALL_EXEC
	$(QUIET_INST)install -v $1 $(DESTDIR)$2/$1 || exit 1;

endef

define INSTALL_FILE
	$(QUIET_INST)install -v -m 644 $1 $(DESTDIR)$2/$1 || exit 1;

endef

SED_PC_CMD = 's|@version@|$(VERSION)|g;		\
	      s|@prefix@|$(INSTALL_PREFIX)|g;		\
	      s|@libdir@|$(LIBDIR)|g;		\
	      s|@includedir@|$(INCLUDEDIR)|g'



# Allow users to override build settings without dirtying their trees
-include local.mk


all: $(PROGRAMS) sparse.pc smatch

all-installable: $(INST_PROGRAMS) $(LIBS) $(LIB_H) sparse.pc

install: all-installable
	$(Q)install -d $(DESTDIR)$(BINDIR)
	$(Q)install -d $(DESTDIR)$(LIBDIR)
	$(Q)install -d $(DESTDIR)$(MAN1DIR)
	$(Q)install -d $(DESTDIR)$(INCLUDEDIR)/sparse
	$(Q)install -d $(DESTDIR)$(PKGCONFIGDIR)
	$(Q)install -d $(DESTDIR)$(SMATCHDATADIR)/smatch_data
	$(Q)install -d $(DESTDIR)$(SMATCHDATADIR)/smatch_scripts
	$(foreach f,$(INST_PROGRAMS),$(call INSTALL_EXEC,$f,$(BINDIR)))
	$(foreach f,$(INST_MAN1),$(call INSTALL_FILE,$f,$(MAN1DIR)))
	$(foreach f,$(LIBS),$(call INSTALL_FILE,$f,$(LIBDIR)))
	$(foreach f,$(LIB_H),$(call INSTALL_FILE,$f,$(INCLUDEDIR)/sparse))
	$(call INSTALL_FILE,sparse.pc,$(PKGCONFIGDIR))
	$(foreach f,$(SMATCH_DATA),$(call INSTALL_FILE,$f,$(SMATCHDATADIR)))
	$(foreach f,$(SMATCH_SCRIPTS),$(call INSTALL_EXEC,$f,$(SMATCHDATADIR)))

sparse.pc: sparse.pc.in
	$(QUIET_GEN)sed $(SED_PC_CMD) sparse.pc.in > sparse.pc


compile_EXTRA_DEPS = compile-i386.o

$(foreach p,$(PROGRAMS),$(eval $(p): $($(p)_EXTRA_DEPS) $(LIBS)))
$(PROGRAMS): % : %.o 
	$(QUIET_LINK)$(LD) -o $@ $^ $($@_EXTRA_OBJS) $(LDFLAGS)

smatch: smatch.o $(SMATCH_FILES) $(SMATCH_CHECKS) $(LIBS) 
	$(QUIET_LINK)$(LD) -o $@ $< $(SMATCH_FILES) $(SMATCH_CHECKS) $(LIBS) $(LDFLAGS)

$(LIB_FILE): $(LIB_OBJS)
	$(QUIET_AR)$(AR) rcs $@ $(LIB_OBJS)

$(SLIB_FILE): $(LIB_OBJS)
	$(QUIET_LINK)$(CC) -Wl,-soname,$@ -shared -o $@ $(LIB_OBJS) $(LDFLAGS)

check_list_local.h:
	touch check_list_local.h

smatch.o: smatch.c $(LIB_H) smatch.h check_list.h check_list_local.h
	$(CC) $(CFLAGS) -c smatch.c -DSMATCHDATADIR='"$(SMATCHDATADIR)"'
$(SMATCH_CHECKS): smatch.h smatch_slist.h smatch_extra.h avl.h
DEP_FILES := $(wildcard .*.o.d)

ifneq ($(DEP_FILES),)
include $(DEP_FILES)
endif

c2xml.o c2xml.sc: PKG_CFLAGS += $(LIBXML_CFLAGS)

pre-process.sc: CHECKER_FLAGS += -Wno-vla

%.o: %.c $(LIB_H)
	$(QUIET_CC)$(CC) -o $@ -c $(ALL_CFLAGS) $<

%.sc: %.c sparse
	$(QUIET_CHECK) $(CHECKER) $(CHECKER_FLAGS) -c $(ALL_CFLAGS) $<

ALL_OBJS :=  $(LIB_OBJS) $(foreach p,$(PROGRAMS),$(p).o $($(p)_EXTRA_DEPS))
selfcheck: $(ALL_OBJS:.o=.sc)


clean: clean-check
	rm -f *.[oa] .*.d *.so cwchash/*.o cwchash/.*.d cwchash/tester \
		$(PROGRAMS) $(SLIB_FILE) pre-process.h sparse.pc version.h

dist:
	@if test "$(SPARSE_VERSION)" != "v$(VERSION)" ; then \
		echo 'Update VERSION in the Makefile before running "make dist".' ; \
		exit 1 ; \
	fi
	git archive --format=tar --prefix=sparse-$(VERSION)/ HEAD^{tree} | gzip -9 > sparse-$(VERSION).tar.gz

check: all
	$(Q)cd validation && ./test-suite

clean-check:
	find validation/ \( -name "*.c.output.expected" \
	                 -o -name "*.c.output.got" \
	                 -o -name "*.c.output.diff" \
	                 -o -name "*.c.error.expected" \
	                 -o -name "*.c.error.got" \
	                 -o -name "*.c.error.diff" \
	                 \) -exec rm {} \;
