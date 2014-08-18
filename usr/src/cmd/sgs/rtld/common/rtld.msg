#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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

#
# Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2014, Joyent, Inc.  All rights reserved.
#

@ _START_

# Message file for cmd/sgs/rtld (ld.so.1)

@ MSG_ID_RTLD

# Usage error
@ MSG_USG_BADOPT	"usage: ld.so.1 [-e option,...] \
			 dynamic-object [object args,...]"

# Message formatting error.
@ MSG_EMG_BUFOVRFLW	"ld.so.1: internal: message buffer overflow"

# Argument processing errors

@ MSG_ARG_ILLMODE_1	"illegal mode: RTLD_NOW or RTLD_LAZY or RTLD_NOLOAD \
			 required"
@ MSG_ARG_ILLMODE_2	"illegal mode: RTLD_NOW cannot be combined with \
			 RTLD_LAZY"
@ MSG_ARG_ILLMODE_3	"illegal mode: LM_ID_NEWLM requires non-zero path"
@ MSG_ARG_ILLMODE_4	"illegal mode: LM_ID_NEWLM cannot be combined with \
			 RTLD_PARENT"
@ MSG_ARG_ILLMODE_5	"illegal mode: potential multiple path expansion \
			 requires RTLD_FIRST"

@ MSG_ARG_ILLPATH	"illegal pathname"
@ MSG_ARG_ILLSYM	"illegal symbol name"
@ MSG_ARG_ILLNAME	"illegal name"
@ MSG_ARG_INVADDR	"address 0x%llx does not fall within any mapped object"
@ MSG_ARG_INVHNDL	"invalid handle: 0x%llx"
@ MSG_ARG_ILLVAL	"illegal request value"
@ MSG_ARG_NOCONFIG	"no configuration file in use"
@ MSG_ARG_NOPROFNAME	"no profile target specified"
@ MSG_ARG_ATEXIT	"purge of atexit() registrations failed: %d"
@ MSG_ARG_SERCNT	"information path count (%d) insufficient"
@ MSG_ARG_SERSIZE	"information buffer size (%lld) insufficient"
@ MSG_ARG_ILLFLAGS	"illegal flags value: %d"
@ MSG_ARG_ILLINFO	"non-null info field required for flags value: %d"
@ MSG_ARG_INVSIG	"invalid signal supplied: %d"

# General error diagnostics

@ MSG_GEN_NOOPEN	"DF_1_NOOPEN tagged object may not be dlopen()'ed"

@ MSG_GEN_NOFILE	"%s: can't find file"
@ MSG_GEN_ALTER		"%s: alternate file in use"
@ MSG_GEN_NOSYM		"%s: can't find symbol"
@ MSG_GEN_NODUMP	"%s: DF_1_NODUMP tagged object may not be dldump()'ed"

# Move related messages

@ MSG_MOVE_ERR1		"move entry with illegal size; ignored"


# Relocation processing messages (some of these are required to satisfy
# do_reloc(), which is common code used by cmd/sgs/libld - make sure both
# message files remain consistent).

@ MSG_REL_NOSYM		"relocation error: file %s: symbol %s: \
			 referenced symbol not found"
@ MSG_REL_PLTREF	"relocation error: %s: unidentifiable procedure \
			 reference: link-map 0x%llx, offset 0x%llx, \
			 called from 0x%llx"
@ MSG_REL_UNSUPSZ	"relocation error: %s: file %s: symbol %s: \
			 offset size (%d bytes) is not supported"
@ MSG_REL_BADTLS	"relocation error: %s: file %s: symbol %s: \
			 file contains insufficient TLS support information"

# System call messages.

@ MSG_SYS_BRK		"%s: brk failed: %s"
@ MSG_SYS_OPEN		"%s: open failed: %s"
@ MSG_SYS_MMAP		"%s: mmap failed: %s"
@ MSG_SYS_MPROT		"%s: mprotect failed: %s"
@ MSG_SYS_MMAPANON	"mmap anon failed: %s"

# Secure path failures

@ MSG_SEC_OPEN		"%s: open failed: No such file in secure directories"
@ MSG_SEC_ILLEGAL	"%s: open failed: illegal insecure pathname"

# Toxic failures

@ MSG_TOXIC_FILE	"%s: dependency marked as toxic"

# Configuration failures

@ MSG_CONF_APP		"configuration file: %s: is specific to application: %s"
@ MSG_CONF_DSTAT	"configuration file: %s: original directory %s: stat \
			 failed: %s"
@ MSG_CONF_FSTAT	"configuration file: %s: original file %s: stat \
			 failed: %s"
@ MSG_CONF_FCMP		"configuration file: %s: original file %s: modified \
			 since configuration file creation"

# Link Audit diagnostic message formats

@ MSG_AUD_BADVERS	"version mismatch: current %d: required %d"
@ MSG_AUD_DISABLED	"%s: audit initialization failure: disabled"


# Versioning diagnostics.

@ MSG_VER_NFOUND	"%s: version '%s' not found (required by file %s)"


# Diagnostics generated under the control of ldd(1).

@ MSG_LDD_VER_FIND	"   find version=%s\n"
@ MSG_LDD_VER_NFOUND	"\t%s (%s) =>\t (version not found)\n"

@ MSG_LDD_SYM_NFOUND	"\tsymbol not found: %s\t\t(%s)\n"

@ MSG_LDD_PTH_TRYING	"    trying path=%s%s\n"
@ MSG_LDD_PTH_LIBPATH	"    search path=%s  (LD_LIBRARY_PATH)\n"
@ MSG_LDD_PTH_LIBPATHC	"    search path=%s  (configuration \
			 LD_LIBRARY_PATH - %s)\n"
@ MSG_LDD_PTH_RUNPATH	"    search path=%s  (RUNPATH/RPATH from file %s)\n"
@ MSG_LDD_PTH_BGNDFL	"    search path="
@ MSG_LDD_PTH_ENDDFL	"  (default)\n"
@ MSG_LDD_PTH_ENDDFLC	"  (configuration default - %s)\n"
@ MSG_LDD_PTH_IGNORE	"    ignore path=%s  (insecure directory name)\n"

@ MSG_LDD_FIL_FILTER	"\n   object=%s; filter for %s\n"
@ MSG_LDD_FIL_FIND	"\n   find object=%s; required by %s\n"
@ MSG_LDD_FIL_NFOUND	"\t%s =>\t (file not found)\n"
@ MSG_LDD_FIL_ILLEGAL	"\t%s =>\t (illegal insecure pathname)\n"
@ MSG_LDD_FIL_ALTER	"  (alternate)"

@ MSG_LDD_CAP_NFOUND	"\t%s =>\t (no capability objects found)\n"

@ MSG_LDD_SEC_NFOUND	"\t%s =>\t (file not found in secure directories)\n"

@ MSG_LDD_REL_ERR1	"\trelocation %s offset invalid: %s: offset=0x%llx \
			 lies outside memory image; relocation discarded\n"
@ MSG_LDD_REL_ERR2	"\tloading after relocation has started: interposition \
			 request (DF_1_INTERPOSE) ignored: %s\n"
@ MSG_LDD_MOVE_ERR	"\tmove %lld offset invalid: %s: offset=0x%llx \
			 lies outside memory image; move discarded\n"
@ MSG_LDD_CPY_SIZDIF	"\trelocation %s sizes differ: %s\n\
			 \t\t(file %s size=0x%llx; file %s size=0x%llx)\n"
@ MSG_LDD_CPY_INSDATA	"\t\t%s size used; possible insufficient data copied\n"
@ MSG_LDD_CPY_DATRUNC	"\t\t%s size used; possible data truncation\n"
@ MSG_LDD_CPY_PROT	"\trelocation %s symbol: %s: file %s: relocation bound \
			 to a symbol with STV_PROTECTED visibility\n"

@ MSG_LDD_INIT_FMT_01	"\n   cyclic dependencies detected, group [%d]:\n"
@ MSG_LDD_INIT_FMT_02	"   init object=%s\n"
@ MSG_LDD_INIT_FMT_03	"   init object=%s - cyclic group [%d], referenced \
			 by:\n"

@ MSG_LDD_UNUSED_FMT	"   unused object=%s\n"
@ MSG_LDD_UNCYC_FMT	"   unused object=%s; member of cyclic group [%d]\n"
@ MSG_LDD_UNREF_FMT	"   unreferenced object=%s; unused dependency of %s\n"

@ MSG_LDD_REL_CPYDISP	"\tsymbol %s: file %s: copy relocation symbol may \
			 have been displacement relocated\n"

@ MSG_LDD_REJ_MACH	"  - wrong ELF machine type: %s"
@ MSG_LDD_REJ_CLASS	"  - wrong ELF class: %s"
@ MSG_LDD_REJ_DATA	"  - wrong ELF data format: %s"
@ MSG_LDD_REJ_TYPE	"  - bad ELF type: %s"
@ MSG_LDD_REJ_BADFLAG	"  - bad ELF flags value: %s"
@ MSG_LDD_REJ_MISFLAG	"  - mismatched ELF flags value: %s"
@ MSG_LDD_REJ_VERSION	"  - mismatched ELF/lib version: %s"
@ MSG_LDD_REJ_HAL	"  - HAL R1 extensions required"
@ MSG_LDD_REJ_US3	"  - Sun UltraSPARC III extensions required"
@ MSG_LDD_REJ_STR	"  - %s"
@ MSG_LDD_REJ_UNKFILE	"  - unknown file type"
@ MSG_LDD_REJ_UNKCAP	"  - unknown capability: %d"
@ MSG_LDD_REJ_HWCAP_1	"  - hardware capability (CA_SUNW_HW_1) unsupported: %s"
@ MSG_LDD_REJ_SFCAP_1	"  - software capability (CA_SUNW_SF_1) unsupported: %s"
@ MSG_LDD_REJ_MACHCAP	"  - machine capability (CA_SUNW_MACH) unsupported: %s"
@ MSG_LDD_REJ_PLATCAP	"  - platform capability (CA_SUNW_PLAT) unsupported: %s"
@ MSG_LDD_REJ_HWCAP_2	"  - hardware capability (CA_SUNW_HW_2) unsupported: %s"
@ MSG_LDD_REJ_ARCHIVE	"  - invalid archive use"

@ MSG_LDD_WARN_UNKCAP	"%s: unknown capability: %d"
@ MSG_LDD_WARN_HWCAP_1	"%s: warning: hardware capability (CA_SUNW_HW_1) \
			 unsupported: %s\n"
@ MSG_LDD_WARN_SFCAP_1	"%s: warning: software capability (CA_SUNW_SF_1) \
			 unsupported: %s\n"
@ MSG_LDD_WARN_MACHCAP	"%s: warning: machine capability (CA_SUNW_MACH) \
			 unsupported: %s\n"
@ MSG_LDD_WARN_PLATCAP	"%s: warning: platform capability (CA_SUNW_PLAT) \
			 unsupported: %s\n"
@ MSG_LDD_WARN_HWCAP_2	"%s: warning: hardware capability (CA_SUNW_HW_2) \
			 unsupported: %s\n"

# Error rejection messages.

@ MSG_ERR_REJ_MACH	"%s: wrong ELF machine type: %s"
@ MSG_ERR_REJ_CLASS	"%s: wrong ELF class: %s"
@ MSG_ERR_REJ_DATA	"%s: wrong ELF data format: %s"
@ MSG_ERR_REJ_TYPE	"%s: bad ELF type: %s"
@ MSG_ERR_REJ_BADFLAG	"%s: bad ELF flags value: %s"
@ MSG_ERR_REJ_MISFLAG	"%s: mismatched ELF flags value: %s"
@ MSG_ERR_REJ_VERSION	"%s: mismatched ELF/lib version: %s"
@ MSG_ERR_REJ_HAL	"%s: HAL R1 extensions required"
@ MSG_ERR_REJ_US3	"%s: Sun UltraSPARC III extensions required"
@ MSG_ERR_REJ_STR	"%s: %s"
@ MSG_ERR_REJ_UNKFILE	"%s: unknown file type"
@ MSG_ERR_REJ_UNKCAP	"%s: unknown capability: %d"
@ MSG_ERR_REJ_HWCAP_1	"%s: hardware capability (CA_SUNW_HW_1) unsupported: %s"
@ MSG_ERR_REJ_SFCAP_1	"%s: software capability (CA_SUNW_SF_1) unsupported: %s"
@ MSG_ERR_REJ_MACHCAP	"%s: machine capability (CA_SUNW_MACH) unsupported: %s"
@ MSG_ERR_REJ_PLATCAP	"%s: platform capability (CA_SUNW_PLAT) unsupported: %s"
@ MSG_ERR_REJ_HWCAP_2	"%s: hardware capability (CA_SUNW_HW_2) unsupported: %s"
@ MSG_ERR_REJ_ARCHIVE	"%s: invalid archive use"

# Error TLS failures

@ MSG_TLS_NOSUPPORT	"%s: TLS requirement failure : TLS support is \
			 unavailable"
@ MSG_TLS_STATBASE	"%s: static TLS failure: object is not part of primary \
			 link-map list"
@ MSG_TLS_STATSIZE	"%s: static TLS failure: object loaded after process \
			 initialization: size (%#llx) exceeds available backup \
			 reservation (%#llx)"  
@ MSG_TLS_STATINIT	"%s: static TLS failure: object loaded after process \
			 initialization: can not accommodate initialized data"

# Error expand()

@ MSG_ERR_EXPAND1	"%s: %s: path name too long"
@ MSG_ERR_EXPAND2	"%s: %s: token %s could not be expanded"

# Specific dlinfo() messages.

@ MSG_DEF_NODEPFOUND	"%s: no deferred dependency found"
@ MSG_DEF_NOSYMFOUND	"%s: no deferred symbol found"
@ MSG_DEF_DEPLOADED	"%s: deferred dependency is already loaded"

# Error diagnostic standard prefixes.

@ MSG_ERR_WARNING	"warning: "
@ MSG_ERR_GUIDANCE	"guidance: "
@ MSG_ERR_FATAL		"fatal: "
@ MSG_ERR_ELF		"elf error: "

@ MSG_STR_UNKNOWN	"(unknown)"
@ MSG_STR_NULL		"(null)"

# Unused errors - used by ldd.

@ MSG_USD_LDLIBPATH	"   unused search path=%s  (LD_LIBRARY_PATH)\n"
@ MSG_DUP_LDLIBPATH	"   unused (duplicate) search path=%s  \
			 (LD_LIBRARY_PATH)\n"
@ MSG_USD_LDLIBPATHC	"   unused search path=%s  (configuration \
			 LD_LIBRARY_PATH - %s)\n"
@ MSG_DUP_LDLIBPATHC	"   unused (duplicate) search path=%s  (configuration \
			 LD_LIBRARY_PATH - %s)\n"
@ MSG_USD_RUNPATH	"   unused search path=%s  (RUNPATH/RPATH from \
			 file %s)\n"

@ MSG_CAP_IGN_UNKCAP	"ignoring unknown capability: %s"

@ _END_

# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_LDD_FIL_PATH	"\t%s%s%s\n"
@ MSG_LDD_FIL_EQUIV	"\t%s =>\t %s%s%s\n"
@ MSG_LDD_FMT_PATH1	"%s"
@ MSG_LDD_FMT_PATHN	":%s"
@ MSG_LDD_INIT_FMT_FILE	"\t%s\n"
@ MSG_LDD_VER_FOUND	"\t%s (%s) =>\t %s\n"

@ MSG_STR_EMPTY		""
@ MSG_STR_NEGATE	"-"
@ MSG_STR_ZERO		"0"
@ MSG_STR_HEX		"0x"
@ MSG_STR_ELF		"ELF"
@ MSG_STR_EMSGFOR1	"%s: %s: %s"
@ MSG_STR_EMSGFOR2	"%s: %s"
@ MSG_STR_HEXNUM	"0123456789abcdef"
@ MSG_STR_NL		"\n"
@ MSG_STR_SLASH		"/"
@ MSG_STR_DELIMIT	": "
@ MSG_STR_ONE		"1"

@ MSG_CAP_DELIMIT	","

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"
@ MSG_SUNW_OST_OSLIB	"SUNW_OST_OSLIB"

@ MSG_TKN_CAPABILITY	"CAPABILITY"
@ MSG_TKN_MACHINE	"MACHINE"
@ MSG_TKN_PLATFORM	"PLATFORM"
@ MSG_TKN_ORIGIN	"ORIGIN"
@ MSG_TKN_ISALIST	"ISALIST"
@ MSG_TKN_OSNAME	"OSNAME"
@ MSG_TKN_OSREL		"OSREL"
@ MSG_TKN_HWCAP		"HWCAP"
@ MSG_TKN_BINDINGS	"bindings"
@ MSG_TKN_POSIX		"POSIX"
@ MSG_TKN_DOTDOT	".."

@ MSG_FMT_CWD		"."
@ MSG_FMT_MSGFILE	"/usr/lib/locale/%s/LC_MESSAGES/%s.mo"

@ MSG_FIL_RTLD		"ld.so.1"
@ MSG_FIL_LIBC		"libc.so.1"

@ MSG_SYM_ELFERRMSG	"elf_errmsg"
@ MSG_SYM_ELFERRNO	"elf_errno"
@ MSG_SYM_ELFPLTTRACE	"elf_plt_trace"
@ MSG_SYM_ENVIRON	"_environ"

@ MSG_SYM_LAPREINIT	"la_preinit"
@ MSG_SYM_LAVERSION	"la_version"
@ MSG_SYM_LAACTIVITY	"la_activity"
@ MSG_SYM_LAOBJSEARCH	"la_objsearch"
@ MSG_SYM_LAOBJOPEN	"la_objopen"
@ MSG_SYM_LAOBJFILTER	"la_objfilter"
@ MSG_SYM_LAOBJCLOSE	"la_objclose"
@ MSG_SYM_LADYNDATA	"la_dyndata"

@ MSG_SYM_START		"_START_"

@ MSG_SPECFIL_DYNPLT	"dyn_plt(ld.so.1)"

@ MSG_PTH_LDPROF	"/usr/lib/link_audit/ldprof.so.1"
@ MSG_PTH_LDPROFSE	"/usr/lib/secure/ldprof.so.1"
@ MSG_PTH_LIBSYS	"/usr/lib/libsys.so.1"
@ MSG_PTH_RTLD		"/usr/lib/ld.so.1"
@ MSG_PTH_LIB		"/lib"
@ MSG_PTH_USRLIB	"/usr/lib"
@ MSG_PTH_LIBSE		"/lib/secure"
@ MSG_PTH_USRLIBSE	"/usr/lib/secure"
@ MSG_PTH_DEVNULL	"/dev/null"
@ MSG_PTH_CONFIG	"/var/ld/ld.config"
@ MSG_PTH_VARTMP	"/var/tmp"

@ MSG_ORG_CONFIG	"$ORIGIN/ld.config.%s"

@ MSG_LD_AUDIT		"AUDIT"
@ MSG_LD_AUDIT_ARGS	"AUDIT_ARGS"
@ MSG_LD_BIND_LAZY	"BIND_LAZY"
@ MSG_LD_BIND_NOW	"BIND_NOW"
@ MSG_LD_BIND_NOT	"BIND_NOT"
@ MSG_LD_BINDINGS	"BINDINGS"
@ MSG_LD_CONFGEN	"CONFGEN"
@ MSG_LD_CAP_FILES	"CAP_FILES"
@ MSG_LD_CONFIG		"CONFIG"
@ MSG_LD_DEBUG		"DEBUG"
@ MSG_LD_DEBUG_OUTPUT	"DEBUG_OUTPUT"
@ MSG_LD_DEMANGLE	"DEMANGLE"
@ MSG_LD_FLAGS		"FLAGS"
@ MSG_LD_HWCAP		"HWCAP"
@ MSG_LD_INIT		"INIT"
@ MSG_LD_LIBPATH	"LIBRARY_PATH"
@ MSG_LD_LOADAVAIL	"LOADAVAIL"
@ MSG_LD_LOADFLTR	"LOADFLTR"
@ MSG_LD_MACHCAP	"MACHCAP"
@ MSG_LD_NOAUDIT	"NOAUDIT"
@ MSG_LD_NOAUXFLTR	"NOAUXFLTR"
@ MSG_LD_NOBAPLT	"NOBAPLT"
@ MSG_LD_NOCONFIG	"NOCONFIG"
@ MSG_LD_NODIRCONFIG	"NODIRCONFIG"
@ MSG_LD_NODIRECT	"NODIRECT"
@ MSG_LD_NOENVCONFIG	"NOENVCONFIG"
@ MSG_LD_NOENVIRON	"NOENVIRON"
@ MSG_LD_NOFLTCONFIG	"NOFLTCONFIG"
@ MSG_LD_NOLAZY		"NOLAZYLOAD"
@ MSG_LD_NOOBJALTER	"NOOBJALTER"
@ MSG_LD_NOPAREXT	"NOPAREXT"
@ MSG_LD_NOUNRESWEAK	"NOUNRESWEAK"
@ MSG_LD_NOVERSION	"NOVERSION"
@ MSG_LD_PLATCAP	"PLATCAP"
@ MSG_LD_PRELOAD	"PRELOAD"
@ MSG_LD_PROFILE	"PROFILE"
@ MSG_LD_PROFILE_OUTPUT	"PROFILE_OUTPUT"
@ MSG_LD_SFCAP		"SFCAP"
@ MSG_LD_SIGNAL		"SIGNAL"
@ MSG_LD_TOXICPATH	"TOXIC_PATH"
@ MSG_LD_TRACE_OBJS	"TRACE_LOADED_OBJECTS"
@ MSG_LD_TRACE_OBJS_E	"TRACE_LOADED_OBJECTS_E"
@ MSG_LD_TRACE_OBJS_A	"TRACE_LOADED_OBJECTS_A"
@ MSG_LD_TRACE_PTHS	"TRACE_SEARCH_PATHS"
@ MSG_LD_UNREF		"UNREF"
@ MSG_LD_UNUSED		"UNUSED"
@ MSG_LD_VERBOSE	"VERBOSE"
@ MSG_LD_DEFERRED	"DEFERRED"
@ MSG_LD_WARN		"WARN"

@ MSG_LD_BRAND_PREFIX	"BRAND_"

@ MSG_LC_ALL		"ALL="
@ MSG_LC_MESSAGES	"MESSAGES="

@ MSG_EMG_ENOMEM	"internal: Not enough space"

@ MSG_DBG_PID		"%5.5d: "
@ MSG_DBG_RESET		"---------\n"
@ MSG_DBG_UNDEF		"debug: "
@ MSG_DBG_LMID		"%s: "
@ MSG_DBG_THREAD	"%d: "
@ MSG_DBG_FILE		"%s.%5.5d"

@ MSG_LMID_BASE		"BASE"
@ MSG_LMID_LDSO		"LDSO"
@ MSG_LMID_ALT		"ALT"

@ MSG_LMID_FMT		"%s%d"
@ MSG_LMID_MAXED	"ALTMAXEDOUT"
