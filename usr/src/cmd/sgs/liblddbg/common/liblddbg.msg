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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

@ _START_

# Message file for cmd/sgs/liblddbg.

@ MSG_ID_LIBLDDBG


# Usage messages

@ MSG_USE_UNRECOG	"warning: unrecognized debug option `%s' (try help)"

# TRANSLATION_NOTE - Use the following output in C as a reference, 1.
#
# Runtime Linking
#    Diagnostics that trace the runtime linking of an application can be
#    enabled to stderr by using the environment variable setting:
# 	LD_DEBUG=token1,token2
#    Alternatively, the diagnostics can be redirected to an output file
#    using the additional environment variable:
# 	LD_DEBUG_OUTPUT=file
#    The output file is given the specified name and the process id as a
#    suffix.
#
#    By default, all diagnostics are prepended with the process id,
#    together with the thread id.  Note, all applications are effectively
#    thread aware, and once thread capabilities are enabled, even a single
#    threaded application is labeled as thread 1.
#
#    The token `lmid' prepends a link-map list identifier to each
#    diagnostic.
#
#    The tokens `base', `ldso' and `newlm[0-9]*' can be used to isolate
#    diagnostics to the associated link-map lists.   Note, by default, any
#    diagnostics associated with loading components for the runtime linker
#    itself are suppressed, unless `ldso' is explicitly specified.
# 
# Link-Editing
#    Diagnostics that trace the link-editing of an application can be
#    enabled to stderr using the -D option:
#	ld -Dtoken1,token2 -o prog ...
#    As the -D option can also be meaningful to compiler drivers, an
#    alternative mechanism to enable diagnostics is to use the environment
#    variable:
#	LD_OPTIONS=-Dtoken1,token2 cc -o prog ...
#
#    The use of -D on the link-edit command line is significant.
#    Diagnostics are enabled when a debug token is first encountered, and
#    can be switched off by prepending the token with `!'.
#
#    By default, all diagnostics are prepended with the string `debug'.
#
#    The tokens `name', `fullname' and `class' can be used to prepend the
#    output file basename, fullname, and class respectively, to each
#    diagnostic.


# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.  Use tabs and space alignment characters as needed.
#
@ MSG_USE_RTLD_A	"Runtime Linking"
@ MSG_USE_RTLD_B	"    Diagnostics that trace the runtime linking of an \
			 application can be"
@ MSG_USE_RTLD_C	"    enabled to stderr by using the environment \
			 variable setting:"
@ MSG_USE_RTLD_D	" 	LD_DEBUG=token1,token2 app ..."
@ MSG_USE_RTLD_E	"    Alternatively, the diagnostics can be redirected \
			 to an output file"
@ MSG_USE_RTLD_F	"    using the additional environment variable:"
@ MSG_USE_RTLD_G	" 	LD_DEBUG_OUTPUT=file"
@ MSG_USE_RTLD_H	"    The output file is given the specified name and \
			 the process id as a"
@ MSG_USE_RTLD_I	"    suffix."
@ MSG_USE_RTLD_J	"    By default, all diagnostics are prepended with \
			 the process id,"
@ MSG_USE_RTLD_K	"    together with the thread id.  Note, all \
			 applications are effectively"
@ MSG_USE_RTLD_L	"    thread aware, and once thread capabilities are \
			 enabled, even a single"
@ MSG_USE_RTLD_M	"    threaded application is labeled as thread 1."
@ MSG_USE_RTLD_N	"    The token `lmid' prepends a link-map list \
			 identifier to each"
@ MSG_USE_RTLD_O	"    diagnostic."
@ MSG_USE_RTLD_P	"    The tokens `base', `ldso' and `newlm[0-9]*' can \
			 be used to isolate"
@ MSG_USE_RTLD_Q	"    diagnostics to the associated link-map lists.  \
			 Note, by default, any"
@ MSG_USE_RTLD_R	"    diagnostics associated with loading components \
			 for the runtime linker"
@ MSG_USE_RTLD_S	"    itself are suppressed, unless `ldso' is \
			 explicitly specified."

@ MSG_USE_LD_A		"Link-Editing"
@ MSG_USE_LD_B		"    Diagnostics that trace the link-editing of an \
			 application can be"
@ MSG_USE_LD_C		"    enabled to stderr using the -D option:"
@ MSG_USE_LD_D		"       ld -Dtoken1,token2 -o prog ..."
@ MSG_USE_LD_E		"    As the -D option can also be meaningful to \
			 compiler drivers, an"
@ MSG_USE_LD_F		"    alternative mechanism to enable diagnostics is to \
			 use the environment"
@ MSG_USE_LD_G		"    variable:"
@ MSG_USE_LD_H		"       LD_OPTIONS=-Dtoken1,token2 cc -o prog ..."
@ MSG_USE_LD_I		"    The use of -D on the link-edit command line is \
			 significant."
@ MSG_USE_LD_J		"    Diagnostics are enabled when a debug token is \
			 first encountered, and"
@ MSG_USE_LD_K		"    can be switched off by prepending the token \
			 with `!'."
@ MSG_USE_LD_L		"    By default, all diagnostics are prepended with \
			 the string `debug'."
@ MSG_USE_LD_M		"    The tokens `name', `fullname' and `class' can be \
			 used to prepend"
@ MSG_USE_LD_N		"    the output file basename, fullname, and class \
			 respectively, to each"
@ MSG_USE_LD_O		"    diagnostic."

# TRANSLATION_NOTE - End of reference 1


# TRANSLATION_NOTE - The next series of messages makes the following usage
# table.  Use tabs and space alignment characters as needed.
#
# args		display input argument processing (ld only)
# audit		display runtime link-audit processing (ld.so.1 only)
# basic		provide basic trace information/warnings
# bindings	display symbol binding; detail flag shows absolute:relative
# 		    addresses (ld.so.1 only)
# cap		display hardware/software capability processing
# demangle	display C++ symbol names in their demangled form
# detail	provide more information in conjunction with other options
# entry		display entrance criteria descriptors (ld only)
# files		display input file processing (files and libraries)
# got		display GOT symbol information (ld only)
# help		display this help message
# init		display init and fini processing (ld.so.1 only)
# libs		display library search paths; detail flag shows actual
#		    library lookup (-l) processing
# long		display long object names without truncation
# map		display map file processing (ld only)
# move		display Move section information
# reloc		display relocation processing
# sections	display input section processing (ld only)
# segments	display available output segments and address/offset
#		    processing; detail flag shows associated sections (ld only)
# support	display support library processing (ld only)
# symbols	display symbol table processing; detail flag shows internal
#		    symbol table addition and resolution (ld only)
# statistics	display processing statistics (ld only)
# strtab	display information about string table compression (ld only)
#		    detail shows layout of string tables
# tls		display TLS processing
# unused	display unused/unreferenced files; detail flag shows unused
#		   sections (ld only)
# versions	display version processing
#
#
# TRANSLATION_NOTE -- do not translate the first token `args'.
@ MSG_USE_ARGS		"args\t  display input argument processing (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `audit'.
@ MSG_USE_AUDIT		"audit\t  display runtime link-audit processing \
			 (ld.so.1 only)"

# TRANSLATION_NOTE -- do not translate the first token `basic'.
@ MSG_USE_BASIC		"basic\t  provide basic trace information/warnings"

# TRANSLATION_NOTE -- do not translate the first token `bindings'.
@ MSG_USE_BINDINGS	"bindings\t  display symbol binding; detail flag shows \
			 absolute:relative"
@ MSG_USE_BINDINGS_2	"\t\t    addresses (ld.so.1 only)"

# TRANSLATION_NOTE -- do not translate the first token `cap'
@ MSG_USE_CAP		"cap\t  display hardware/software capability \
			 processing"

# TRANSLATION_NOTE -- do not translate the first token `detail'.
@ MSG_USE_DETAIL	"detail\t  provide more information in conjunction \
			 with other options"

# TRANSLATION_NOTE -- do not translate the first token `demangle'.
@ MSG_USE_DEMANGLE	"demangle\t  display C++ symbol names in their \
			 demangled form"

# TRANSLATION_NOTE -- do not translate the first token `entry'.
@ MSG_USE_ENTRY		"entry\t  display entrance criteria descriptors \
			 (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `files'.
@ MSG_USE_FILES		"files\t  display input file processing \
			 (files and libraries)"

# TRANSLATION_NOTE -- do not translate the first token `got'.
@ MSG_USE_GOT		"got\t  display GOT symbol information (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `help'.
@ MSG_USE_HELP		"help\t  display this help message"

# TRANSLATION_NOTE -- do not translate the first token `init'.
@ MSG_USE_INIT		"init\t  display init and fini processing \
			 (ld.so.1 only)"

# TRANSLATION_NOTE -- do not translate the first token `libs'.
@ MSG_USE_LIBS		"libs\t  display library search paths; detail flag \
			 shows actual"
@ MSG_USE_LIBS_2	"\t\t    library lookup (-l) processing"

# TRANSLATION_NOTE -- do not translate the first token `lmid'.
@ MSG_USE_LMID		"lmid\t  display link-map list identifier \
			(ld.so.1 only)"

# TRANSLATION_NOTE -- do not translate the first token `long'.
@ MSG_USE_LONG		"long\t  display long object names without truncation"

# TRANSLATION_NOTE -- do not translate the first token `map'.
@ MSG_USE_MAP		"map\t  display map file processing (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `move'.
@ MSG_USE_MOVE		"move\t  display move section processing"

# TRANSLATION_NOTE -- do not translate the first token `reloc'.
@ MSG_USE_RELOC		"reloc\t  display relocation processing"

# TRANSLATION_NOTE -- do not translate the first token `sections'.
@ MSG_USE_SECTIONS	"sections   display input section processing (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `segments'.
@ MSG_USE_SEGMENTS	"segments   display available output segments and \
			 address/offset"
@ MSG_USE_SEGMENTS_2	"\t\t    processing; detail flag shows associated \
			 sections (ld only)"
# TRANSLATION_NOTE -- do not translate the first token `support'.
@ MSG_USE_SUPPORT	"support\t  display support library processing (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `symbols'.
@ MSG_USE_SYMBOLS	"symbols\t  display symbol table processing; detail \
			 flag shows internal"
@ MSG_USE_SYMBOLS_2	"\t\t    symbol table addition and resolution (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `statistics'.
@ MSG_USE_STATS		"statistics display processing statistics (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `strtab'.
@ MSG_USE_STRTAB	"strtab\t  display information about string table \
			 compression; detail"
@ MSG_USE_STRTAB_2	"\t\t    shows layout of string tables (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `tls/TLS'.
@ MSG_USE_TLS		"tls\t  display TLS processing info"

# TRANSLATION_NOTE -- do not translate the first token `unused'.
@ MSG_USE_UNUSED	"unused\t  display unused/unreferenced files; detail \
			 flag shows unused"
@ MSG_USE_UNUSED_2	"\t\t    sections (ld only)"

# TRANSLATION_NOTE -- do not translate the first token `versions'.
@ MSG_USE_VERSIONS	"versions\t  display version processing"

# Argument messages

@ MSG_ARG_FLAG		"arg[%d]\tflag=-%c"
@ MSG_ARG_FILE		"arg[%d]\tfile=%s"


# Bindings messages
# NOTE: these are used by appcert(1) and lari(1), use care when changing.

@ MSG_BND_BASIC		"binding file=%s to file=%s: symbol `%s'"
@ MSG_BND_PLT		"binding file=%s (%#llx:%#llx) at plt[%lld]:%s to \
			 file=%s (%#llx:%#llx): symbol `%s'%s"
@ MSG_BND_DLSYM		"binding file=%s (dlsym) to file=%s \
			 (%#llx:%#llx): symbol `%s'%s"
@ MSG_BND_DEFAULT	"binding file=%s (%#llx:%#llx) to file=%s \
			 (%#llx:%#llx): symbol `%s'%s"
@ MSG_BND_WEAK_1	"binding file=%s to 0x0 (undefined weak): symbol `%s'"
@ MSG_BND_WEAK_2	"binding file=%s (%#llx:%#llx) to 0x0 \
			 (undefined weak): symbol `%s'"

@ MSG_BND_PLTPAD_TO	"   pltpad: %#llx: file=%s bound to file=%s: \
			 symbol `%s'"
@ MSG_BND_PLTPAD_FROM	"   pltpad: %#llx: bound from file=%s: symbol `%s'"

@ MSG_BND_PSUM_SPARCV9	"Summary of PLT types bound: 21d=%d, 24d=%d, u32=%d, \
			 u44=%d, full=%d, far=%d, Total=%d"
@ MSG_BND_PSUM_SPARC	"Summary of PLT types bound: 21d=%d, 24d=%d, \
			 full=%d, Total=%d"
@ MSG_BND_PSUM_DEFAULT	"Summary of PLT types bound: total=%d"

# Relocation messages

@ MSG_REL_GENERATE	"generating input relocations: section=%s"
@ MSG_REL_COLLECT	"collecting input relocations: section=%s, file=%s"
@ MSG_REL_ACTIVE	"performing active relocations"
@ MSG_REL_CREATING	"creating output relocations"
@ MSG_REL_START		"relocation processing: file=%s%s"
@ MSG_REL_FINISH	"relocation processing: file=%s; finished%s"
@ MSG_REL_NONE		"relocation processing: file=%s%s; nothing to do"

@ MSG_REL_PLT		"  (plt processing only)"
@ MSG_REL_FAIL		"  (failed)"

@ MSG_REL_BADROFFSET	"<offset lies outside memory image; \
			 relocation discarded>"

@ MSG_REL_TRANSITION	"relocation: %s: section=%s; input from file=%s; \
			 offset=0x%llx; symbol=%s; transitioned to: %s"
@ MSG_REL_DISCARDED	"relocation against discarded section=%s from file=%s; \
			 relocation type=%s offset=0x%llx; relocation discarded"
@ MSG_REL_COPY		"copy data from file=%s to file=%s: symbol `%s'%s"
@ MSG_REL_SLOPPYCOMDAT	"the following relocation references a discarded \
			 section; relocation redirected to section %s in \
			 file %s"

# Entrance criteria messages

@ MSG_ECR_TITLE		"%s Entrance Descriptor List (available)"
@ MSG_ECR_DYNAMIC	"Dynamic"
@ MSG_ECR_STATIC	"Static"
@ MSG_ECR_DESC		"entrance descriptor[%d]"


# Elf Data (section) messages
# TRANSLATION_NOTE - the following two entries provide for a series of one or
# more standard 32-bit Elf_Data entries that align with the initial title.

@ MSG_EDATA_TITLE_32	"            addr type        size   offset al file"
@ MSG_EDATA_ENTRY_32	"  %3s %#10llx %-5s %#10llx %#8llx %2lld %s%s"

# TRANSLATION_NOTE - the following two entries provide for a series of one or
# more standard 64-bit Elf_Data entries that align with the initial title.

@ MSG_EDATA_TITLE_64	"                    addr type                \
			 size           offset al file"
@ MSG_EDATA_ENTRY_64	"  %3s %#18llx %-5s %#18llx %#16llx %2lld %s%s"

@ MSG_EDATA_IGNSCN	"  (section ignored)"

# File messages

@ MSG_FIL_BASIC		"file=%s  [ %s ]"
@ MSG_FIL_ARCHIVE	"file=%s  [ archive ] %s"
@ MSG_FIL_SKIP_1	"file=%s;  skipped: already processed as %s"
@ MSG_FIL_SKIP_2	"file=%s;  skipped: already processed"
@ MSG_FIL_REUSE		"file=%s;  reusing: originally processed as %s"
@ MSG_FIL_PROT		"file=%s;  modifying memory protections (%c PROT_WRITE)"
@ MSG_FIL_DELETE	"file=%s;  deleting"
@ MSG_FIL_DLOPEN	"file=%s;  dlopen() called from file=%s  %s"
@ MSG_FIL_DLCLOSE	"file=%s;  dlclose()  %s"
@ MSG_FIL_CLEANUP	"file=%s;  loading failed: cleaning up lmco 0x%llx"
@ MSG_FIL_DLDUMP	"file=%s;  dldump() to file=%s  %s"
@ MSG_FIL_LAZYLOAD	"file=%s;  lazy loading from file=%s: symbol=%s"
@ MSG_FIL_PRELOAD	"file=%s;  preloading"
@ MSG_FIL_NEEDED	"file=%s;  needed by %s"
@ MSG_FIL_FILTER_1	"file=%s;  filter for %s  (configuration definition)"
@ MSG_FIL_FILTER_2	"file=%s;  filter for %s"
@ MSG_FIL_FILTEE_2	"file=%s;  filtee processing failed"
@ MSG_FIL_FILTEE_3	"file=%s;  filtee skipped  (auditing directed)"
@ MSG_FIL_FIXNAME	"file=%s;  required name=%s"
@ MSG_FIL_PROMOTE	"file=%s;  promoting mode to %s"
@ MSG_FIL_AOUT		"file=%s  [ AOUT ]; generating link map"
@ MSG_FIL_ELF		"file=%s  [ ELF ]; generating link map%s"
@ MSG_FIL_LDSO		"file=%s  [ ELF ]"

# NOTE: these are used by lari(1), use care when changing.
@ MSG_FIL_ANALYZE	"file=%s;  analyzing  %s"
@ MSG_FIL_FILTEE_1	"file=%s;  filtered by %s"
@ MSG_FIL_CONFIG	"file=%s  [ ELF ]; configuration alternate found: %s"


@ MSG_FIL_DATA_DB	"    dynamic:  %#18llx  base:   %#18llx"
@ MSG_FIL_DATA_SE	"    size:     %#18llx  entry:  %#18llx"
@ MSG_FIL_DATA_S	"    size:     %#18llx"
@ MSG_FIL_DATA_LL	"    lmid:     %18.18s  lmco:   %#18llx"
@ MSG_FIL_DATA_EA	"    envp:     %#18llx  auxv:   %#18llx"

@ MSG_FIL_BND_ADD	"file=%s;  add binding to:"
@ MSG_FIL_BND_FILE	"    file=%s   %s"

@ MSG_FIL_DEP_TITLE	"processing %s dependencies  %s:"
@ MSG_FIL_DEP_NONE	"  file=%s;  has no dependencies"
@ MSG_FIL_DEP_ENT	"  file=%s;  depends on:"

@ MSG_FIL_DEP_ADD	"    file=%s;  object added  %s  %s"
@ MSG_FIL_DEP_UPDATE	"    file=%s;  object updated  %s  %s"
@ MSG_FIL_DEP_DELETE	"    file=%s;  object deleting  %s"
@ MSG_FIL_DEP_REMOVE	"    file=%s;  object removed from handle  %s"
@ MSG_FIL_DEP_REMAIN	"    file=%s;  object must remain on handle  %s"
@ MSG_FIL_DEP_ORPHAN	"    file=%s;  object remains on orphan handle  %s"
@ MSG_FIL_DEP_REINST	"    file=%s;  object reinstated  %s"

@ MSG_FIL_HDL_CREATE	"handle=%s;  creating:"
@ MSG_FIL_HDL_ADD	"handle=%s;  adding dependent objects:"
@ MSG_FIL_HDL_DELETE	"handle=%s;  inspecting for deletion:"
@ MSG_FIL_HDL_ORPHAN	"handle=%s;  deletion cannot be completed: moving to \
			 orphan list:"
@ MSG_FIL_HDL_REINST	"handle=%s;  reinstating from orphan list:"

@ MSG_FIL_HDL_COLLECT	"handle=%s;  collected for possible removal  %s"
@ MSG_FIL_HDL_RETAIN	"handle=%s;  externally referenced from %s: handle \
			 retained"
@ MSG_FIL_DEL_RESCAN	"pending deletions; rescanning orphan list for \
			 available deletions"

@ MSG_FIL_AR_RESCAN	"rescanning archive list; additional members may \
			 satisfy prior extractions"

@ MSG_FIL_CONFIG_ERR	"configuration file=%s: %s"
@ MSG_FIL_CONFIG_ERR_1	"ignored (configuration building)"
@ MSG_FIL_CONFIG_ERR_2	"invalid version"
@ MSG_FIL_CONFIG_ERR_3	"unable to process file"
@ MSG_FIL_CONFIG_ERR_4	"corrupt or truncated file"
@ MSG_FIL_CONFIG_ERR_5	"incompatible ELF class, byte order, or machine \
			 architecture"

@ MSG_FIL_MODIFIED	"file=%s; open modified by support library: %s"
@ MSG_FIL_NAMECHANGE	"    name changed to: %s"
@ MSG_FIL_FDCHANGE	"    file descriptor changed from: %d to: %d %s"
@ MSG_FIL_ELFCHANGE	"    ELF descriptor changed from: 0x%llx to: 0x%llx %s"
@ MSG_FIL_IGNORE	" (file will be ignored)"

@ MSG_CNTL_TITLE	"control list processing complete: moving lmco 0x%llx \
			 to lmco 0x%llx"

@ MSG_REJ_MACH		"file=%s;  rejected: wrong machine type: %s"
@ MSG_REJ_CLASS		"file=%s;  rejected: wrong ELF class: %s"
@ MSG_REJ_DATA		"file=%s;  rejected: wrong ELF data format: %s"
@ MSG_REJ_TYPE		"file=%s;  rejected: bad ELF type: %s"
@ MSG_REJ_BADFLAG	"file=%s;  rejected: bad ELF flags value: %s"
@ MSG_REJ_MISFLAG	"file=%s;  rejected: mismatched ELF flags value: %s"
@ MSG_REJ_VERSION	"file=%s;  rejected: mismatched ELF/lib version: %s"
@ MSG_REJ_HAL		"file=%s;  rejected: HAL R1 extensions required"
@ MSG_REJ_US3		"file=%s;  rejected: Sun UltraSPARC III extensions \
			 required"
@ MSG_REJ_STR		"obj=%s;  rejected: %s"
@ MSG_REJ_UNKFILE	"obj=%s;  rejected: unknown file type"
@ MSG_REJ_HWCAP_1	"obj=%s;  rejected: hardware capability unsupported: \
			 %s"

# Libs messages

@ MSG_LIB_INITPATH	"Library Search Paths (initial)"
@ MSG_LIB_UPPATH	"Library Search Paths (-L updated)"
@ MSG_LIB_LOPT		"find lib=-l%s; path=%s"
@ MSG_LIB_REQUIRED	"find lib=%s; path=%s (required by %s)"
@ MSG_LIB_LDLIBPATH	" search path=%s  (LD_LIBRARY_PATH)"
@ MSG_LIB_LDLIBPATHC	" search path=%s  (configuration LD_LIBRARY_PATH - %s)"
@ MSG_LIB_RUNPATH	" search path=%s  (RUNPATH/RPATH from file %s)"
@ MSG_LIB_DEFAULT	" search path=%s  (default)"
@ MSG_LIB_DEFAULTC	" search path=%s  (configuration default - %s)"
@ MSG_LIB_LIBPATH	" search path=%s  (LIBPATH or -YP)"
@ MSG_LIB_YPATH		" search path=%s  replaces  path=%s  (-Y%c)"

@ MSG_LIB_FIND		"find object=%s; searching"
@ MSG_LIB_TRYING	" trying path=%s%s"
@ MSG_LIB_ALTER		" trying path=%s  (auditing supplied alternative)"
@ MSG_LIB_SKIP		"   skip path=%s  (auditing directed)"
@ MSG_LIB_IGNORE	" ignore path=%s  (insecure directory name)"


# Mapfile messages

@ MSG_MAP_MAPFILE	"map file=%s"

@ MSG_MAP_SEG_DECL_1	"segment declaration (=), segment added:"
@ MSG_MAP_SEG_DECL_2	"segment declaration (=), segment updated:"
@ MSG_MAP_SEG_DECL_3	"implicit segment declaration (:), segment added:"
@ MSG_MAP_SEG_DECL_4	"implicit segment declaration (@), segment added:"
@ MSG_MAP_SEG_DECL_5	"size-symbol declaration (@), segment updated:"

@ MSG_MAP_CAP		"hardware/software declaration (=), capabilities added:"

@ MSG_MAP_MAP_DIR	"mapping directive (:), entrance criteria added:"

@ MSG_MAP_SEC_ORDER	"map section ordering, segment: %s section: \
			 %s index: %d"

@ MSG_MAP_SYM_SCOPE	"symbol scope definition ({})"
@ MSG_MAP_SYM_SIZE	"size-symbol declaration (@), symbol=%s; %s"
@ MSG_MAP_SYM_VER_1	"%s, %s; symbol=%s  (%s)"
@ MSG_MAP_SYM_VER_2	"%s; symbol=%s  (%s)"

@ MSG_MAP_CNT_DEF_1	"library control definition (-), %s; needed=%s"
@ MSG_MAP_CNT_DEF_2	"library control definition (-), %s; needed"

@ MSG_MAP_SORTSEG	"map sort_seg_list(): original=%s"
@ MSG_MAP_SEGSORT	"map sort_seg_list(): sorted=%s"

# Move messages

@ MSG_MOVE_FILE		"file=%s  processing move data"

@ MSG_MOVE_TITLE1	"  i/o      offset       value  repeat  stride  symbol"
@ MSG_MOVE_TITLE2	"          address       value  repeat  stride  symbol"

@ MSG_MOVE_ENTRYIN	"   in  %#10llx  %#10llx  %6d  %6d  %s"
@ MSG_MOVE_ENTRYOUT	"  out  %#10llx  %#10llx  %6d  %6d  %s"
@ MSG_MOVE_EXPAND	"       %#10llx  %#10llx  (expanded)"

@ MSG_MOVE_ADJEXPAND	"for symbol=%s roffset: new=0x%llx"
@ MSG_MOVE_ADJMOVE	"for symbol=%s roffset: from=0x%llx, to=0x%llx"
@ MSG_MOVE_OUTSCTADJ	"adjusting addend for symbol=%s"
@ MSG_MOVE_PAREXPN	"expanding %s into .SUNW_data1: %s"
@ MSG_MOVE_OUTMOVE	"copying move entries for %s into .SUNW_move"
@ MSG_MOVE_INPUT	"collecting move entries: file=%s"

# Section header messages

@ MSG_SHD_MODIFIED	"section=%s; section header modified by support \
			 library: %s"
@ MSG_SHD_ORIG		"  original:"
@ MSG_SHD_NEW		"  new:"

# TRANSLATION_NOTE - The following two items are used following a number in
# the MSG_SHD_OFFSET_ENT_XX format strings below. For example "1 entry"
# or "23 entries".
# 
@ MSG_SHD_ENTRY_1	"entry"
@ MSG_SHD_ENTRY_N	"entries"


# Section messages

@ MSG_SEC_INPUT		"section=%s; input from file=%s"
@ MSG_SEC_ADDED		"section=%s; added to segment=%s"
@ MSG_SEC_CREATED	"section=%s; added to segment=%s (created)"
@ MSG_SEC_DISCARDED	"section=%s; input from file=%s; \
			 discarded in favor of section=%s from file=%s"
@ MSG_SEC_GRP_INPUT	"section=%s; input from file=%s; \
			 member of group: %s:%s"
@ MSG_SEC_GRP_DISCARDED	"section=%s; input from file=%s; \
			 discarded: member of existing group: %s:%s"

@ MSG_SEC_STRTAB_STND	"strtab=%s; full size: %d; uncompressed"
@ MSG_SEC_STRTAB_COMP	"strtab=%s; full size: %d -> compressed down to: %d"
@ MSG_SEC_STRTAB_HD	"Compressed String Table: %s \
			 [%d buckets]:"
@ MSG_SEC_STRTAB_BCKT	" Bucket[%3d]:"
@ MSG_SEC_STRTAB_MSTR	"   ref[%2d] %s <master>"
@ MSG_SEC_STRTAB_SUFSTR	"   ref[%2d] %s <suffix of> %s"

# Unused messages

@ MSG_USD_SEC		"section=%s; size=0x%llx; input from file=%s; \
			 unused: does not satisfy any references%s"
@ MSG_USD_SECDISCARD	"; discarded"
@ MSG_USD_FILE		"file=%s  unused: does not satisfy any references"
@ MSG_USD_NEEDSTR	"file=%s  unused: unable to determine use" 
@ MSG_USD_UNREF		"file=%s  unreferenced: unused dependency of %s"
@ MSG_USD_FILECYCLIC	"file=%s  unused: cyclic group [%d] member: \
			 unreferenced outside of group"
@ MSG_USD_LCINTERFACE	"file=%s  unused interface [%s]: using interface \
			 from previously loaded object: file=%s"

# Segment messages

@ MSG_SEG_DESC_INUSE	"Segment Descriptor List (in use)"
@ MSG_SEG_DESC_AVAIL	"Segment Descriptor List (available)"


# Support messages

@ MSG_SUP_REQ		"support object request=%s  (%s)"
@ MSG_SUP_REQ_ENV	"supplied via SGS_SUPPORT"
@ MSG_SUP_REQ_CMD	"supplied via -S"
@ MSG_SUP_REQ_DEF	"default"

@ MSG_SUP_ROUTINE	"  support object=%s:  provides routine %s"

@ MSG_SUP_CALLING_1	"  calling routine=%s (%s)"
@ MSG_SUP_CALLING_2	"  calling routine=%s (%s)  %s=%s"
@ MSG_SUP_OUTFILE	"output file"
@ MSG_SUP_INFILE	"input file"
@ MSG_SUP_INSEC		"input section"
@ MSG_SUP_SEC		"section"

# Symbol strings
@ MSG_SYM_AR_FILE	"symbol table processing; input file=%s  [ archive ] %s"
@ MSG_SYM_AR_ENTRY	"archive[%lld]=%s"
@ MSG_SYM_AR_CHECK	"archive[%lld]=%s  (%s) checking for tentative or \
			 restricted visibility override"
@ MSG_SYM_AR_RESOLVE	"archive[%lld]=%s  (%s) resolves undefined or tentative \
			 symbol"
@ MSG_SYM_AR_FORCEDEXRT	"archive[%lld]=%s  (%s) forced extraction"

@ MSG_SYM_SPECIAL	"symbol table processing; building special symbols"
@ MSG_SYM_PROCESS	"symbol table processing; input file=%s  [ %s ]"
@ MSG_SYM_FINAL		"symbol table processing; final update"
@ MSG_SYM_INDEX		"symbol table processing; determining section \
			 symbol's index"
@ MSG_SYM_BSS		"symbol table processing; assigning to bss \
			 (possible copy relocations)"
@ MSG_SYM_REDUCED	"symbol table processing; reducing global symbols"
@ MSG_SYM_RETAINING	"symbol table processing; retaining local symbols"
@ MSG_SYM_VERSION	"symbol table processing; adding version symbols"

@ MSG_SYM_BASIC		"symbol[%d]=%s"
@ MSG_SYM_ADDING	"symbol[%d]=%s  (global); adding"
@ MSG_SYM_SECTION	"symbol[%d]=%s  (section); segment=%s"
@ MSG_SYM_RESOLVING	"symbol[%d]=%s  (global); resolving [%d][%d]"
@ MSG_SYM_UPDATE	"symbol=%s;  updated"
@ MSG_SYM_CREATE	"symbol=%s;  creating"
@ MSG_SYM_REDUCING	"symbol=%s;  reducing to local"
@ MSG_SYM_ELIMINATING	"symbol=%s;  eliminating"
@ MSG_SYM_NOTELIMINATE	"symbol=%s;  not eliminated: referenced by \
			 section=%s, entry[%d]"
@ MSG_SYM_DISCARDED	"symbol=%s;  discarded because it is part of \
			 discarded section=%s from file=%s"

@ MSG_SYM_AOUT		"symbol=%s;  (original AOUT name)"
@ MSG_SYM_LOOKUP	"symbol=%s;  lookup in file=%s  [ %s ]"
@ MSG_SYM_DLSYM_1 	"symbol=%s;  dlsym() called from file=%s  %s"
@ MSG_SYM_DLSYM_2	"symbol=%s;  dlsym() called from file=%s; starting at \
			 file=%s  %s"

@ MSG_SYM_LAZY_RESCAN	"rescanning for lazy dependencies for symbol: %s"

@ MSG_SYM_DUPSORTADDR	"section %s: symbol `%s' and symbol `%s' have the \
			 same address: %#llx"

@ MSG_SYM_IGNGNUVER	"symbol=%s;  hash index=%d;  version=%d;  skipping \
			 symbol with GNU version hidden bit set in file=%s"

# Syminfo string

@ MSG_SYMINFO_INFO	"syminfo information"


# Version strings

@ MSG_VER_AVAIL_1	"version availability: file=%s"
@ MSG_VER_AVAIL_2	" available  version                     selected from"
@ MSG_VER_DEF_TITLE	"version definition processing: file=%s"
@ MSG_VER_NEED_TITLE	"version needed processing: file=%s"
@ MSG_VER_NOINTERFACE	"version definition has no interface symbols: %s"

# SHF_ORDERED related messages. Token used is sections.

@ MSG_ORD_SORT_BEFORE	"section=%s; requires output section reordering:"
@ MSG_ORD_SORT_AFTER	"section=%s; output section reordered:"
@ MSG_ORD_HDR_1		" number of SHN_BEGIN=%u, SHN_AFTER=%u, \
			 sh_info/sh_link=%u"
@ MSG_ORD_TITLE_0	" section=%s from %s is not an ordered section"
@ MSG_ORD_TITLE_1	" section=%s from %s, %s=SHN_BEGIN"
@ MSG_ORD_TITLE_2	" section=%s from %s, %s=SHN_AFTER"
@ MSG_ORD_TITLE_3	" section=%s from %s, %s=%s, sort_val=%d"

@ MSG_ORD_ERR_TITLE	"the SHF_ORDERED section %s from %s has \
			 an error;  flag ignored"

@ MSG_ORD_ERR_INFORANGE	" the sh_info field is out of range"
@ MSG_ORD_ERR_ORDER	" the section pointed by sh_info is an ordered section"
@ MSG_ORD_ERR_LINKRANGE	" the sh_link field is out of range"
@ MSG_ORD_ERR_FLAGS	" the sh_flag is incorrect"
@ MSG_ORD_ERR_CYCLIC	" the sh_link is cyclic"
@ MSG_ORD_ERR_LINKINV	" a section pointed to by sh_link has an error"

# Link-Auditing Messages

@ MSG_AUD_INIT		"audit library %s: processing"
@ MSG_AUD_VERSION	"audit library %s: running at version: %d"
@ MSG_AUD_INTERFACE	"audit library %s: provides interface: %s"
@ MSG_AUD_OBJECT	"audit library %s: offered object: %s"
@ MSG_AUD_SYM		"audit library %s: %s: symbol: %s: value: 0x%llx %s"
@ MSG_AUD_SYMNEW	"modified to: 0x%llx"

@ MSG_AUD_IGNORE	"file=%s;  global auditing request ignored: object \
			 did not initiate process" 
@ MSG_AUD_SKIP		"file=%s;  skipped: using auditor from %s"
@ MSG_AUD_TERM		"file=%s;  auditing terminated search"

# GOT Messages

@ MSG_GOT_INFO		"Global Offset Table information:  (%u entries)"

# TRANSLATION_NOTE
#	Do not translate .init or .fini, they represent reserved section names.

@ MSG_UTL_INIT		"calling .init (%s): %s"
@ MSG_UTL_FINI		"calling .fini: %s"
@ MSG_UTL_ARRAY		"calling %s[%d]:0x%llx: %s"
@ MSG_UTL_TRANS		"transferring control: %s"
@ MSG_UTL_WAIT		"suspending thread: %s from %s for completion of init \
			 for %s"
@ MSG_UTL_BROAD		"signal suspended threads: %s init complete"
@ MSG_UTL_INTOOLATE	"loading after relocation has started: interposition \
			 request (DF_1_INTERPOSE) ignored: %s"

@ MSG_UTL_EDGE_TITLE_I	"traversing %s dependency edge for interposer:"
@ MSG_UTL_EDGE_TITLE_S	"traversing %s dependency edge:"
@ MSG_UTL_EDGE_START	"  node (%d): file=%s"
@ MSG_UTL_EDGE_IN	"  node (%d): file=%s: referenced by %s  %s"
@ MSG_UTL_EDGE_OUT	"  node (%d): file=%s; cyclic dependency on %s"
@ MSG_UTL_COLLECT	"    [%d]  %s;  collecting %s section"

@ MSG_UTL_SORT		"from sorted order"
@ MSG_UTL_PEND		"pending"
@ MSG_UTL_DYN		"dynamically triggered"
@ MSG_UTL_DONE		"done"

@ MSG_UTL_NOINIT	"warning: calling %s whose init has not completed"

@ MSG_UTL_DBNOTIFY	"notify debugger: event: %s state: %s"

@ MSG_UTL_SCC_TITLE	"  cycle detected - sorting cyclic dependencies in %s"
@ MSG_UTL_SCC_SUBI	"reverse load-order"
@ MSG_UTL_SCC_SUBF	"load-order"

@ MSG_UTL_LCINTERFACE	"file=%s;  provides interface [%s]: 0x%llx"

# Generic strings

@ MSG_STR_IGNORE	"ignored"
@ MSG_STR_ENTERED	"entered"
@ MSG_STR_INITIAL	"initialized"
@ MSG_STR_IN		" in"
@ MSG_STR_OUT		"out"
@ MSG_STR_ACT		"act"
@ MSG_STR_OLD		"old"
@ MSG_STR_NEW		"new"
@ MSG_STR_RESOLVED	"resolved"
@ MSG_STR_ADD		"adding"
@ MSG_STR_UP_1		"updating"
@ MSG_STR_UP_2		"updated"
@ MSG_STR_SYMBOL	"symbol binding"

@ MSG_STR_UNKNOWN	"<unknown>"
@ MSG_STR_ORPHAN	"<orphan>"

@ MSG_STR_UNUSED	"(unused)"
@ MSG_STR_AGAIN		"(again)"
@ MSG_STR_NULL		"(null)"
@ MSG_STR_ALTER		"  (alternate)"
@ MSG_STR_COPYZERO	"  (copy zero's unnecessary)"
@ MSG_STR_TEMPORARY	"  (temporary)"

# TLS related messages

@ MSG_TLS_STATBLOCK1	"static TLS module: [%ld] %s"
@ MSG_TLS_STATBLOCK2	"static TLS reservation: in use %#llx: \
			 additional backup: %#llx"
@ MSG_TLS_STATBLOCK3	"static TLS requirement: [%ld] %s: size %#llx: \
			 satisfied from backup reservation: remaining %#llx"
@ MSG_TLS_MODENT1	"    block:  %#18llx    soff:   %#10llx  flags:  %#llx \
			 %s"
@ MSG_TLS_MODENT2	"    filesz: %#18llx    memsz:  %#10llx  modid:  %lld"
@ MSG_TLS_MODACT	"%s TLS module: %s"
@ MSG_TLS_ADD		"add"
@ MSG_TLS_REMOVE	"remove"

# Statistics related messages

@ MSG_STATS_AR		"archive %s: count=%d, used=%d  (%d%%)"

@ MSG_STATS_GENERAL	"General Statistics:"
@ MSG_STATS_FILES	"  Input files: relocatables=%lld  \
			 shared objects=%lld  archives=%lld"
@ MSG_STATS_SYMBOLS_OUT	"      Symbols output: globals=%-10lld locals=%lld"
@ MSG_STATS_SYMBOLS_IN	"      Symbols  input: globals=%-10lld scoped=%-10lld \
			 eliminated=%lld"
@ MSG_STATS_RELOCS_OUT	"  Relocations output: records=%lld"
@ MSG_STATS_RELOCS_IN	"  Relocations  input: records=%-10lld applied=%lld"

# Hardware/Software capabilities messages

@ MSG_CAP_VAL_HW1	"hardware capabilities - %s"

@ MSG_CAP_SEC_TITLE	"hardware/software capabilities; input file=%s"
@ MSG_CAP_SEC_ENTRY	"%12.12s  %-15.15s  %s"

@ MSG_CAP_HW_CANDIDATE	"obj=%s;  hardware capabilities candidate"

@ MSG_CAP_HWFILTR_1	"dir=%s;  hardware capability directory filtered by %s"
@ MSG_CAP_HWFILTR_2	"dir=%s;  no hardware capability objects found"



@ MSG_ELF_HEADER	"ELF Header"

# Capabilities entries.
# TRANSLATION_NOTE - the following two entries provide for a series of one or
# more capabilities table entries that align with the initial title.

@ MSG_CAP_ELF_TITLE	"     index  tag               value"
@ MSG_CAP_ELF_ENTRY	"%10.10s  %-15.15s  %s"


# Dynamic entries.
# TRANSLATION_NOTE - the following two entries provide for a series of one or
# more dynamic table entries that align with the initial title.

@ MSG_DYN_TITLE		"     index  tag                value"
@ MSG_DYN_ENTRY		"%10.10s  %-16.16s  %-#16llx    %s"


# Symbol table entries.
# TRANSLATION_NOTE - the following entries provide for a series of one or more
# standard 32-bit symbol table entries that align with the initial title.

@ MSG_SYM_EFS_TITLE_32	"     index    value      size      type bind \
			 oth ver shndx          name"
@ MSG_SYM_LDS_TITLE_32	"              value      size      type bind \
			 oth ver shndx"
@ MSG_SYM_EFS_ENTRY_32	"%10.10s  %10.10s 0x%8.8x  %4s %4s %2s %4s \
			 %-14.14s %s"

# TRANSLATION_NOTE - the following entries provide for a series of one or more
# long 32-bit symbol table entries that align with the initial title.

@ MSG_SYM_EFL_TITLE_32	"     index    value      size      type bind \
			 oth ver shndx / name"
@ MSG_SYM_LDL_TITLE_32	"              value      size      type bind \
			 oth ver shndx"
@ MSG_SYM_EFL_ENTRY_32	"%10.10s  %10.10s 0x%8.8x  %4s %4s %2s %4s \
			 %-14s %s"

# TRANSLATION_NOTE - the following entries provide for a series of one or more
# standard 64-bit symbol table entries that align with the initial title.

@ MSG_SYM_EFS_TITLE_64	"     index    value              size              \
			 type bind oth ver shndx          name"
@ MSG_SYM_LDS_TITLE_64	"              value              size              \
			 type bind oth ver shndx"
@ MSG_SYM_EFS_ENTRY_64	"%10.10s  %18.18s 0x%16.16llx  %4s %4s %2s %4s \
			 %-14.14s %s"

# TRANSLATION_NOTE - the following entries provide for a series of one or more
# long 64-bit symbol table entries that align with the initial title.

@ MSG_SYM_EFL_TITLE_64	"     index    value              size              \
			 type bind oth ver shndx / name"
@ MSG_SYM_LDL_TITLE_64	"              value              size              \
			 type bind oth ver shndx"
@ MSG_SYM_EFL_ENTRY_64	"%10.10s  %18.18s 0x%16.16llx  %4s %4s %2s %4s \
			 %-14s %s"


# Syminfo entries.
# TRANSLATION_NOTE - the following two entries provide for a series of one or
# more symbol information table entries that align with the initial title.

@ MSG_SYMINFO_TITLE	"     index  flags            \
			 bound to                 symbol"
@ MSG_SYMINFO_ENTRY	"%10.10s  %-8s %7s %-24s %s"

@ MSG_SYMINFO_SELF	"<self>"
@ MSG_SYMINFO_PARENT	"<parent>"
@ MSG_SYMINFO_EXTERN	"<extern>"


# Global offset table entries.
# TRANSLATION_NOTE - the following two entries are used by elfdump(1), and
# provide for a series of one or more 32-bit got table entries that align with
# the initial title.

@ MSG_GOT_TITLE_32	"     index    addr        value     \
			 pending relocation"
@ MSG_GOT_ENTRY_RE_32	"%10.10s  0x%08llx  0x%08llx  %-24s  %s"
@ MSG_GOT_ENTRY_NR_32	"%10.10s  0x%08llx  0x%08llx"

# TRANSLATION_NOTE - the following two entries are used by elfdump(1), and
# provide for a series of one or more 64-bit got table entries that align with
# the initial title.

@ MSG_GOT_TITLE_64	"     index    addr                \
			 value             pending relocation"
@ MSG_GOT_ENTRY_RE_64	"%10.10s  0x%016llx  0x%016llx  %-24s  %s"
@ MSG_GOT_ENTRY_NR_64	"%10.10s  0x%016llx  0x%016llx"

# TRANSLATION_NOTE - the following three entries are used by ld(1), and provide
# for a series of one or more 32-bit got table entries that align with one of
# the initial titles.

@ MSG_GOT_COLUMNS1_32	"     index ref      offset    addend    symbol"
@ MSG_GOT_COLUMNS2_32	"     index ref      offset    value     symbol"
@ MSG_GOT_FORMAT1_32	"%10.10s %3s  0x%08llx  0x%08llx  %s"
@ MSG_GOT_FORMAT2_32	"%10.10s %3s  0x%08llx  0x%08llx  %s:%s"

# TRANSLATION_NOTE - the following three entries are used by ld(1), and provide
# for a series of one or more 64-bit got table entries that align with one of
# the initial titles.

@ MSG_GOT_COLUMNS1_64	"     index ref    offset              \
			 addend            symbol"
@ MSG_GOT_COLUMNS2_64	"     index ref    offset              \
			 value             symbol"
@ MSG_GOT_FORMAT1_64	"%10.10s %3s  0x%016llx  0x%016llx  %s"
@ MSG_GOT_FORMAT2_64	"%10.10s %3s  0x%016llx  0x%016llx  %s:%s"

# Version table entries.
@ MSG_VER_DEF		"     index  version                     dependency"
@ MSG_VER_NEED		"            file                        version"
@ MSG_VER_NEED_GNUVER	"     index  file                        version"

@ MSG_VER_LINE_1	"%10.10s  %-26.26s  %-20s %s"
@ MSG_VER_LLINE_1	"%10s  %-26s  %-20s %s"
@ MSG_VER_LINE_2	"%47s  %s"
@ MSG_VER_LINE_3	"%38s  %-20s %s"
@ MSG_VER_LINE_4	"                                        %s"
@ MSG_VER_LINE_5	"            %-26.26s  %s"
@ MSG_VER_LLINE_5	"            %-26s  %s"


# Relocation entries.
# TRANSLATION_NOTE - the following strings are used by elfdump(1).  These
# strings provide for a series of one or more 32-bit relocation table entries,
# using truncated section names, that align with one of the initial titles.

@ MSG_REL_EFSA_TITLE_32	"    type                       offset     addend  \
			 section        symbol"
@ MSG_REL_EFSN_TITLE_32	"    type                       offset             \
			 section        symbol"
@ MSG_REL_EFSA_ENTRY_32	"  %-24s %#10llx %#10llx  %-14.14s %s"
@ MSG_REL_EFSN_ENTRY_32	"  %-24s %#10llx             %-14.14s %s"

# TRANSLATION_NOTE - the following strings are used by elfdump(1).  These
# strings provide for a series of one or more 32-bit relocation table entries,
# using long section names, that align with one of the initial titles.

@ MSG_REL_EFLA_TITLE_32	"    type                       offset     addend  \
			 section / symbol"
@ MSG_REL_EFLN_TITLE_32	"    type                       offset             \
			 section / symbol"
@ MSG_REL_EFLA_ENTRY_32	"  %-24s %#10llx %#10llx  %-14s %s"
@ MSG_REL_EFLN_ENTRY_32	"  %-24s %#10llx             %-14s %s"


# TRANSLATION_NOTE - the following strings are used by ld.so.1(1).  These
# strings provide for a series of one or more 32-bit relocation table entries,
# that align with the initial titles.

@ MSG_REL_RTA_TITLE_32	"         type                       offset     \
			 addend  symbol"
@ MSG_REL_RTN_TITLE_32	"         type                       offset      \
			 value  symbol"
@ MSG_REL_RTV_TITLE_32	"                                                value"
@ MSG_REL_RTA_ENTRY_32	" %5s %-24s %#10llx %#10llx  %s  %s"
@ MSG_REL_RTN_ENTRY_32	" %5s %-24s %#10llx             %s  %s"
@ MSG_REL_RT_APLVAL_32	" apply                          %#10llx %#10llx"
@ MSG_REL_RT_APLREG_32	" apply                          %10.10s %#10llx"


# TRANSLATION_NOTE - the following strings are used by ld(1).  These strings
# provide for a series of one or more 32-bit relocation table entries, using
# truncated section names, that align with one of the initial titles.

@ MSG_REL_LDSA_TITLE_32	"         type                       \
			 offset     addend  section        symbol"
@ MSG_REL_LDSN_TITLE_32	"         type                       \
			 offset             section        symbol"
@ MSG_REL_LDSV_TITLE_32	"         type                       \
			 offset      value  section        symbol"
@ MSG_REL_LDSA_ENTRY_32	" %5s %-24s %#10llx %#10llx  %-14.14s %s  %s"
@ MSG_REL_LDSN_ENTRY_32	" %5s %-24s %#10llx             %-14.14s %s  %s"

# TRANSLATION_NOTE - the following strings are used by ld(1).  These strings
# provide for a series of one or more 32-bit relocation table entries, using
# long section names, that align with one of the initial titles.

@ MSG_REL_LDLA_TITLE_32	"         type                       \
			 offset     addend  section / symbol"
@ MSG_REL_LDLN_TITLE_32	"         type                       \
			 offset             section / symbol"
@ MSG_REL_LDLV_TITLE_32	"         type                       \
			 offset      value  section / symbol"
@ MSG_REL_LDLA_ENTRY_32	" %5s %-24s %#10llx %#10llx  %-14s %s  %s"
@ MSG_REL_LDLN_ENTRY_32	" %5s %-24s %#10llx             %-14s %s  %s"


# TRANSLATION_NOTE - the following strings are used by elfdump(1).  These
# strings provide for a series of one or more 64-bit relocation table entries,
# using truncated section names, that align with one of the initial titles.

@ MSG_REL_EFSA_TITLE_64	"    type                               \
			 offset             addend  section        symbol"
@ MSG_REL_EFSN_TITLE_64	"    type                               \
			 offset                     section        symbol"
@ MSG_REL_EFSA_ENTRY_64	"  %-24s %#18llx %#18llx  %-14.14s %s"
@ MSG_REL_EFSN_ENTRY_64	"  %-24s %#18llx                     %-14.14s %s"

# TRANSLATION_NOTE - the following strings are used by elfdump(1).  These
# strings provide for a series of one or more 64-bit relocation table entries,
# using long section names, that align with one of the initial titles.

@ MSG_REL_EFLA_TITLE_64	"    type                               \
			 offset             addend  section / symbol"
@ MSG_REL_EFLN_TITLE_64	"    type                               \
			 offset                     section / symbol"
@ MSG_REL_EFLA_ENTRY_64	"  %-24s %#18llx %#18llx  %-14s %s"
@ MSG_REL_EFLN_ENTRY_64	"  %-24s %#18llx                     %-14s %s"


# TRANSLATION_NOTE - the following strings are used by ld.so.1(1).  These
# strings provide for a series of one or more 64-bit relocation table entries,
# that align with the initial titles.

@ MSG_REL_RTA_TITLE_64	"         type                               \
			 offset             addend  symbol"
@ MSG_REL_RTN_TITLE_64	"         type                               \
			 offset              value  symbol"
@ MSG_REL_RTV_TITLE_64	"                                                                value"
@ MSG_REL_RTA_ENTRY_64	" %5s %-24s %#18llx %#18llx  %s  %s"
@ MSG_REL_RTN_ENTRY_64	" %5s %-24s %#18llx                    %s  %s"
@ MSG_REL_RT_APLVAL_64	" apply                          %#18llx %#18llx"
@ MSG_REL_RT_APLREG_64	" apply                          %18.18s %#18llx"

# TRANSLATION_NOTE - the following strings are used by ld(1).  These strings
# provide for a series of one or more 64-bit relocation table entries, using
# truncated section names, that align with one of the initial titles.

@ MSG_REL_LDSA_TITLE_64	"         type                               \
			 offset             addend  section        symbol"
@ MSG_REL_LDSN_TITLE_64	"         type                               \
			 offset                     section        symbol"
@ MSG_REL_LDSV_TITLE_64	"         type                               \
			 offset              value  section        symbol"
@ MSG_REL_LDSA_ENTRY_64	" %5s %-24s %#18llx %#18llx  %-14.14s %s  %s"
@ MSG_REL_LDSN_ENTRY_64	" %5s %-24s %#18llx                     %-14.14s %s  %s"

# TRANSLATION_NOTE - the following strings are used by ld(1).  These strings
# provide for a series of one or more 64-bit relocation table entries, using
# long section names, that align with one of the initial titles.

@ MSG_REL_LDLA_TITLE_64	"         type                               \
			 offset             addend  section / symbol"
@ MSG_REL_LDLN_TITLE_64	"         type                               \
			 offset                     section / symbol"
@ MSG_REL_LDLV_TITLE_64	"         type                               \
			 offset              value  section / symbol"
@ MSG_REL_LDLA_ENTRY_64	" %5s %-24s %#18llx %#18llx  %-14s %s  %s"
@ MSG_REL_LDLN_ENTRY_64	" %5s %-24s %#18llx                     %-14s %s  %s"

@ _END_

# Debug enabling tokens (for now these are untranslated)

@ MSG_TOK_ALL		"all"
@ MSG_TOK_ARGS		"args"
@ MSG_TOK_BINDINGS	"bindings"
@ MSG_TOK_CAP		"cap"
@ MSG_TOK_BASIC		"basic"
@ MSG_TOK_ENTRY		"entry"
@ MSG_TOK_FILES		"files"
@ MSG_TOK_HELP		"help"
@ MSG_TOK_INIT		"init"
@ MSG_TOK_LIBS		"libs"
@ MSG_TOK_MAP		"map"
@ MSG_TOK_RELOC		"reloc"
@ MSG_TOK_SECTIONS	"sections"
@ MSG_TOK_SEGMENTS	"segments"
@ MSG_TOK_SUPPORT	"support"
@ MSG_TOK_SYMBOLS	"symbols"
@ MSG_TOK_TLS		"tls"
@ MSG_TOK_VERSIONS	"versions"
@ MSG_TOK_AUDIT		"audit"
@ MSG_TOK_GOT		"got"
@ MSG_TOK_MOVE		"move"
@ MSG_TOK_DEMANGLE	"demangle"
@ MSG_TOK_STRTAB	"strtab"
@ MSG_TOK_STATS		"statistics"
@ MSG_TOK_UNUSED	"unused"

@ MSG_TOK_DETAIL	"detail"
@ MSG_TOK_LONG		"long"
@ MSG_TOK_NAME		"name"
@ MSG_TOK_FULLNAME	"fullname"
@ MSG_TOK_CLASS		"class"
@ MSG_TOK_LMID		"lmid"
@ MSG_TOK_BASE		"base"
@ MSG_TOK_LDSO		"ldso"
@ MSG_TOK_NEWLM		"newlm"

# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_STR_EMPTY		""
@ MSG_STR_DELIMIT	",:"

@ MSG_SCN_GOT		".got"
@ MSG_SCN_PLT		".plt"
@ MSG_SCN_BSS		".bss"
@ MSG_SCN_INIT		".init"
@ MSG_SCN_FINI		".fini"
@ MSG_SCN_INITARRAY	".initarray"
@ MSG_SCN_FINIARRAY	".finiarray"
@ MSG_SCN_PREINITARRAY	".preinitarray"

@ MSG_SH_INFO		"sh_info"
@ MSG_SH_LINK		"sh_link"

@ MSG_UTL_SCC_ENTRY	"    [%d]  %s"

@ MSG_FMT_INDEX		" [%d]"
@ MSG_FMT_INDEX_RANGE	" [%d-%d]"
@ MSG_FMT_STR		"%s"
@ MSG_FMT_PATH		"%s/%s"

@ MSG_PTH_OBJECT	"/tmp/ld.so-OBJECT-"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

# Entrance criteria messages

@ MSG_ECR_NAME		"  ec_name:       %-8s  ec_attrmask:  %s"
@ MSG_ECR_SEGMENT	"  ec_segment:    %-8s  ec_attrbits:  %s"
@ MSG_ECR_NDX		"  ec_ndx:        %-8d  ec_type:      %s"
@ MSG_ECR_FILES		"  ec_files:"
@ MSG_ECR_FILE		"    %s"

# Libs messages

@ MSG_LIB_FILE		"  %s"

# PLT binding methods

@ MSG_PLT_21D		"21d"
@ MSG_PLT_24D		"24d"
@ MSG_PLT_U32		"u32"
@ MSG_PLT_U44		"u44"
@ MSG_PLT_FULL		"full"
@ MSG_PLT_FAR		"far"

# Segment messages

@ MSG_SEG_NAME		"segment[%d] sg_name:  %s"
@ MSG_SEG_LENGTH	"    sg_length:    %#llx"
@ MSG_SEG_FLAGS		"    sg_flags:     %s"
@ MSG_SEG_SIZESYM	"    sg_sizesym:   %s"
@ MSG_SEG_ORDER		"    sec_order:"
@ MSG_SEG_SECTION	"       sec_name:    %-8s  sec_index:   %u"

# Section messages (used when expanding segment information)

@ MSG_SEC_NAME		"  section[%d] os_name:  %s"

# Symbol strings

@ MSG_SYM_GLOBAL	"global"
@ MSG_SYM_LOCAL		"local"
@ MSG_SYM_COPY		"copy rel"
@ MSG_SYM_NEXT		"[ RTLD_NEXT ]"
@ MSG_SYM_DEFAULT	"[ RTLD_DEFAULT ]"
@ MSG_SYM_SELF		"[ RTLD_SELF ]"
@ MSG_SYM_PROBE		"[ RTLD_PROBE ]"

# Link-map mode strings

@ MSG_MODE_GLOBNODEL	"[ GLOBAL  NODELETE ]"
@ MSG_MODE_GLOB		"[ GLOBAL ]"
@ MSG_MODE_NODEL	"[ NODELETE ]"

# NOTE: these are used by lari(1), use care when changing.
@ MSG_BINFO_START	"  ("
@ MSG_BINFO_DIRECT	"direct"
@ MSG_BINFO_INTERPOSE	"interpose"
@ MSG_BINFO_COPYREF	"copy-ref"
@ MSG_BINFO_FILTEE	"filtee"
@ MSG_BINFO_PLTADDR	"plt-addr"
@ MSG_BINFO_END		")"
@ MSG_BINFO_SEP		","

# Utility messages

@ MSG_UTL_EVNT_PREINIT	"RD_PREINIT"
@ MSG_UTL_EVNT_POSTINIT	"RD_POSTINIT"
@ MSG_UTL_EVNT_DLACT	"RD_DLACTIVITY"

@ MSG_UTL_STA_ADD	"RT_ADD"
@ MSG_UTL_STA_DELETE	"RT_DELETE"
@ MSG_UTL_STA_CONSIST	"RT_CONSISTENT"

# Version messages

@ MSG_VER_SELECTED	"  SELECTED  %-26.26s  %s"
@ MSG_VER_L_SELECTED	"  SELECTED  %-26s  %s"
@ MSG_VER_ALL		"       ALL  %-26.26s"
@ MSG_VER_L_ALL		"       ALL  %-26s"

# Global offset table entries.

@ MSG_GOT_INDEX		" [%ld]"
@ MSG_GOT_SMALL_PIC	"pic"
@ MSG_GOT_BIG_PIC	"PIC"

@ MSG_CNTL_ENTRY	"   [0x%llx]  %s"

@ MSG_STR_NL		"\n"

@ MSG_FMT_INDEX		" [%d]"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

@ MSG_ELF_MAGIC		"  ei_magic:   { 0x%x, %c, %c, %c }"
@ MSG_ELF_CLASS		"  ei_class:   %-18s  ei_data:      %s"
@ MSG_ELF_MACHINE	"  e_machine:  %-18s  e_version:    %s"
@ MSG_ELF_TYPE		"  e_type:     %s"
@ MSG_ELF_FLAGS		"  e_flags:    %18s"
@ MSG_ELF_FLAGS_FMT	"  e_flags:    %s"
@ MSG_ELF_ESIZE		"  e_entry:    %#18llx  e_ehsize:     %2d  \
			 e_shstrndx:  %d"
@ MSG_ELFX_ESIZE	"  e_entry:    %#18llx  e_ehsize:     %2d  \
			 e_shstrndx:  SHN_XINDEX  (see shdr[0].sh_link)"
@ MSG_ELF_SHOFF		"  e_shoff:    %#18llx  e_shentsize:  %2d  \
			 e_shnum:     %d"
@ MSG_ELFX_SHOFF	"  e_shoff:    %#18llx  e_shentsize:  %2d  \
			 e_shnum:     0  (see shdr[0].sh_size)"
@ MSG_ELF_PHOFF		"  e_phoff:    %#18llx  e_phentsize:  %2d  \
			 e_phnum:     %d"
@ MSG_ELFX_PHOFF	"  e_phoff:    %#18llx  e_phentsize:  %2d  \
			 e_phnum:     PN_XNUM  (see shdr[0].sh_info)"

# Shdr[0] messages

@ MSG_SHD0_TITLE	"Section Header[0]:  (ELF Ehdr extensions)"
@ MSG_SHD0_ADDR		"    sh_addr:      %-6lld               sh_flags:   %s"
@ MSG_SHD0_SIZE		"    sh_size:      %-6lld (e_shnum)     sh_type:    %s"
@ MSG_SHD0_OFFSET	"    sh_offset:    %-6lld               \
			 sh_entsize: %lld"
@ MSG_SHD0_LINK		"    sh_link:      %-6d (e_shstrndx)  sh_info:    \
			 %d (e_phnum)"
@ MSG_SHD0_ALIGN	"    sh_addralign: %-6lld"

# Section header messages

@ MSG_SHD_ADDR_32	"    sh_addr:      %#-10llx      sh_flags:   %s"
@ MSG_SHD_SIZE_32	"    sh_size:      %#-10llx      sh_type:    %s"
@ MSG_SHD_OFFSET_32	"    sh_offset:    %#-10llx      sh_entsize: %#llx"
@ MSG_SHD_OFFSET_ENT_32	"    sh_offset:    %#-10llx      sh_entsize: %#llx \
			 (%lld %s)"
@ MSG_SHD_LINK_32	"    sh_link:      %-14s  sh_info:    %s"
@ MSG_SHD_ALIGN_32	"    sh_addralign: %#-10llx"

@ MSG_SHD_ADDR_64	"    sh_addr:      %#-18llx  sh_flags:   %s"
@ MSG_SHD_SIZE_64	"    sh_size:      %#-18llx  sh_type:    %s"
@ MSG_SHD_OFFSET_64	"    sh_offset:    %#-18llx  sh_entsize: %#llx"
@ MSG_SHD_OFFSET_ENT_64	"    sh_offset:    %#-18llx  sh_entsize: %#llx \
			 (%lld %s)"
@ MSG_SHD_LINK_64	"    sh_link:      %-18s  sh_info:    %s"
@ MSG_SHD_ALIGN_64	"    sh_addralign: %#-18llx"

# Program header messages

@ MSG_PHD_VADDR_32	"    p_vaddr:      %#-10llx  p_flags:    %s"
@ MSG_PHD_PADDR_32	"    p_paddr:      %#-10llx  p_type:     %s"
@ MSG_PHD_FILESZ_32	"    p_filesz:     %#-10llx  p_memsz:    %#llx"
@ MSG_PHD_OFFSET_32	"    p_offset:     %#-10llx  p_align:    %#llx"

@ MSG_PHD_VADDR_64	"    p_vaddr:      %#-18llx  p_flags:    %s"
@ MSG_PHD_PADDR_64	"    p_paddr:      %#-18llx  p_type:     %s"
@ MSG_PHD_FILESZ_64	"    p_filesz:     %#-18llx  p_memsz:    %#llx"
@ MSG_PHD_OFFSET_64	"    p_offset:     %#-18llx  p_align:    %#llx"

# Syminfo formats

@ MSG_SYMINFO_UNKFLAG	"[0x%x]"

# Lc_interface interface tags.

@ MSG_CI_NULL		"NULL"
@ MSG_CI_VERSION	"VERSION"
@ MSG_CI_ATEXIT		"ATEXIT"
@ MSG_CI_LCMESSAGES	"LCMESSAGES"
@ MSG_CI_BIND_GUARD	"BIND_GUARD"
@ MSG_CI_BIND_CLEAR	"BIND_CLEAR"
@ MSG_CI_THR_SELF	"THR_SELF"
@ MSG_CI_TLS_MODADD	"TLS_MODADD"
@ MSG_CI_TLS_MODREM	"TLS_MODREM"
@ MSG_CI_TLS_STATMOD	"TLS_STATMOD"
@ MSG_CI_THRINIT	"THRINIT"

# TLS information flags

@ MSG_TLS_FLAG_STATIC	"STATIC-TLS"
