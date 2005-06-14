pkglibdir = $(libdir)/$(PACKAGE)/$(host_cpu)-$(host_vendor)
nodist_pkglib_DATA = stage1

CLEANFILES = $(nodist_pkglib_DATA)

# We can't use builtins or standard includes.
AM_CCASFLAGS = $(STAGE1_CFLAGS) -fno-builtin -nostdinc
LDFLAGS = -nostdlib -Wl,-N,-Ttext,7C00

noinst_PROGRAMS = stage1.exec
stage1_exec_SOURCES = stage1.S stage1.h

SUFFIXES = .exec
.exec:
	$(OBJCOPY) -O binary $< $@
