#!/bin/ksh -p

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This script extracts values from the passed config.sh file and prints them to
# stdout in a form that is suitable for including in a Makefile.  This removes
# the requirement to manually keep the various Makefile macros in step with the
# contents of config.sh.
#

if  [ -z "$1" -o ! -r "$1" ]; then
	printf 'No config.sh file specified\n' >&2
	exit 1
fi
typeset -r config=$1
typeset -r perlsrc=cmd/perl/5.8.4

# Pull in config.sh.
set -e
. $config
set +e

printf '# This file was automatically generated from %s by %s\n\n' \
    $config $(basename $0)

#
# ON Makefile flag macro adjustments.  Perl needs to build/ship with a
# consistent set of flags, and needs to build with the selected compilers.
#
printf 'C99MODE = $(C99_ENABLE)\n'
printf 'COPTFLAG = %s\n' "$optimize"
printf 'SPACEFLAG =\n'
printf 'ILDOFF =\n'
printf 'CERRWARN =\n'
printf 'G_SHARED = %s\n' "$lddlflags"
printf 'sparc_C_PICFLAGS = %s\n' "$cccdlflags"
printf 'i386_C_PICFLAGS = %s\n' "$cccdlflags"
printf 'C_PICFLAGS = %s\n' "$cccdlflags"
printf 'DYNFLAGS += $(ZIGNORE)\n'
printf 'CFLAGS += -_gcc=-w\n'

# Global stuff.
printf 'PERL_VERSION = %s\n' $version
printf 'PERL_DISTRIB = $(SRC)/%s/distrib\n' $perlsrc
printf 'PERL_CONTRIB = $(SRC)/%s/contrib\n' $perlsrc
printf 'PERL_UTILS = $(SRC)/%s/utils\n' $perlsrc
printf 'MINIPERL = $(PERL_DISTRIB)/miniperl\n'
printf 'PERL_CONFIG_PM = $(PERL_DISTRIB)/lib/Config.pm\n'
printf 'PERL_CONFIG_H = $(PERL_DISTRIB)/config.h\n'
printf 'PERL_CONFIGDEP = $(PERL_CONFIG_H) $(PERL_CONFIG_PM)\n'

# Directory locations.
printf 'PERL_REAL_ROOT_STEM = %s\n' ${prefix%/$version}
printf 'PERL_REAL_ROOT_DIR = %s\n' $prefix
printf 'PERL_REAL_BIN_DIR = %s\n' $binexp
printf 'PERL_REAL_ARCHLIB_DIR = %s\n' $archlibexp
printf 'PERL_REAL_CORE_DIR = %s/CORE\n' $archlibexp
printf 'PERL_REAL_SITE_DIR = %s\n' $sitearchexp
printf 'PERL_REAL_VENDOR_DIR = %s\n' $vendorarchexp
printf 'PERL_REAL_POD_DIR = %s/pod\n' $privlibexp

# Directory locations relative to the current build $ROOT.
printf 'PERL_ROOT_STEM = $(ROOT)%s\n' ${prefix%/$version}
printf 'PERL_ROOT_DIR = $(ROOT)%s\n' $prefix
printf 'PERL_BIN_DIR = $(ROOT)%s\n' $binexp
printf 'PERL_ARCHLIB_DIR = $(ROOT)%s\n' $archlibexp
printf 'PERL_CORE_DIR = $(ROOT)%s/CORE\n' $archlibexp
printf 'PERL_SITE_DIR = $(ROOT)%s\n' $sitearchexp
printf 'PERL_VENDOR_DIR = $(ROOT)%s\n' $vendorarchexp
printf 'PERL_POD_DIR = $(ROOT)%s/pod\n' $privlibexp

# Compilation environment flags.
printf 'KEEP_STATE_OFF = unset KEEP_STATE SUNPRO_DEPENDENCIES || true\n'
printf 'PERL_COREFLAGS = -DPERL_CORE\n'
printf 'PERL_LFFLAGS = %s\n' "$ccflags_uselargefiles"
printf 'PERL_LDLIBS = %s\n' "$perllibs"
printf 'PERL_LD_ENV = LD_LIBRARY_PATH=$(PERL_DISTRIB); export LD_LIBRARY_PATH\n'
printf 'PERL_LIB_ENV = PERL5LIB=$(PERL_UTILS)/lib:$(PERL_DISTRIB)/lib; '
printf 'export PERL5LIB\n'
printf 'PERL_MM_ENV = $(KEEP_STATE_OFF); unset VERSION || true; '
printf '$(PERL_LIB_ENV)\n'
printf "PERL_MM_ARGS = PERL_CORE=1 DEFINE='\$(DTEXTDOM)'\n"

# Make sure we always run miniperl with the correct environment.
printf 'RUN_MINIPERL = $(PERL_LD_ENV); $(PERL_LIB_ENV); $(MINIPERL)\n'
