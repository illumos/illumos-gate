#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"

@ _START_

# Message file for cmd/sgs/liblddbg.

@ MSG_ID_LIBLDDBG


# Usage messages

@ MSG_USE_UNRECOG	"warning: unrecognized debug option `%s' (try help)"

# TRANSLATION_NOTE - Use the following output in C as a reference, 1.
#
# 		 For debugging the runtime linking of an application:
# 			LD_DEBUG=token1,token2  prog
# 		 enables diagnostics to the stderr.  The additional option:
# 			LD_DEBUG_OUTPUT=file
# 		 redirects the diagnostics to an output file created using
# 		 the specified name and the process id as a suffix.  All
# 		 diagnostics are prepended with the process id.
# 
# 		 For debugging the link-editing of an application:
# 			LD_OPTIONS=-Dtoken1,token2 cc -o prog ...
# 		 or,
# 			ld -Dtoken1,token2 -o prog ...
# 		 where placement of -D on the command line is significant,
# 		 and options can be switched off by prepending with `!'.  All
#		 diagnostics are prepended with the string `debug', and
#		 optionally with the output file basename or fullname, and
#		 its class, if the `name' or `fullname', and `class' tokens
#		 are specified respectively.
#
#	The next 13 messages makes the above output in C locale.
#	Use the tabs as alignment characters as needed.
#
@ MSG_USE_RTLD_A	"\t\t  For debugging the runtime linking of an \
			 application:"
#
# Be warned that the next two messages make a sentence.
# That is:
# 			LD_DEBUG=token1,token2  prog
# 		 enables diagnostics to the stderr.  The additional option:
# So do not translate the msgid separately, but handle them together
# Same kind of sentences appear in this block of messages.
#
@ MSG_USE_RTLD_B	"\t\t\tLD_DEBUG=token1,token2  prog"
@ MSG_USE_RTLD_C	"\t\t  enables diagnostics to the stderr.  \
			 The additional option:"
@ MSG_USE_RTLD_D	"\t\t\tLD_DEBUG_OUTPUT=file"
@ MSG_USE_RTLD_E	"\t\t  redirects the diagnostics to an output file \
			 created using"
@ MSG_USE_RTLD_F	"\t\t  the specified name and the process id as a \
			 suffix.  All"
@ MSG_USE_RTLD_G	"\t\t  diagnostics are prepended with the process id."

@ MSG_USE_LD_A		"\t\t  For debugging the link-editing of an application:"
@ MSG_USE_LD_B		"\t\t\tLD_OPTIONS=-Dtoken1,token2 cc -o prog ..."
@ MSG_USE_LD_C		"\t\t  or,"
@ MSG_USE_LD_D		"\t\t\tld -Dtoken1,token2 -o prog ..."
@ MSG_USE_LD_E		"\t\t  where placement of -D on the command line is \
			 significant,"
@ MSG_USE_LD_F		"\t\t  and options can be switched off by prepending \
			 with `!'.  All"
@ MSG_USE_LD_G		"\t\t  diagnostics are prepended with the string \
			 `debug', and"
@ MSG_USE_LD_H		"\t\t  optionally with the output file basename or \
			 fullname, and"
@ MSG_USE_LD_I		"\t\t  its class, if the `name' or `fullname', and \
			 `class' tokens"
@ MSG_USE_LD_J		"\t\t  are specified respectively."
#
#	END OF reference 1
#


# TRANSLATION_NOTE
#	The next 23 messages make the following usage table.
#	Tabs are used for alignment.
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

# TRANSLATION_NOTE -- do not translate the first token `libs'.
@ MSG_USE_LIBS		"libs\t  display library search paths; detail flag \
			 shows actual"
@ MSG_USE_LIBS_2	"\t\t    library lookup (-l) processing"

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
@ MSG_USE_STATISTICS	"statistics display processing statistics (ld only)"

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
@ MSG_BND_PLT		"binding file=%s (%#llx:%#llx) at plt[%d]:%s to \
			 file=%s (%#llx:%#llx): symbol `%s'%s"
@ MSG_BND_DLSYM		"binding file=%s (dlsym) to file=%s \
			 (%#llx:%#llx): symbol `%s'%s"
@ MSG_BND_DEFAULT	"binding file=%s (%#llx:%#llx) to file=%s \
			 (%#llx:%#llx): symbol `%s'%s"
@ MSG_BND_WEAK_1	"binding file=%s to 0x0 (undefined weak): symbol `%s'"
@ MSG_BND_WEAK_2	"binding file=%s (%#llx:%#llx) to 0x0 \
			 (undefined weak): symbol `%s'"

@ MSG_BND_PROFILE	"    profiling symbol[%d];  call count=%d"

@ MSG_BND_PSUM_SPARCV9	"Summary of PLT types bound: 21d=%d, 24d=%d, u32=%d, \
			 u44=%d, full=%d, far=%d, Total=%d"
@ MSG_BND_PSUM_SPARC	"Summary of PLT types bound: 21d=%d, 24d=%d, \
			 full=%d, Total=%d"
@ MSG_BND_PSUM_DEFAULT	"Summary of PLT types bound: Total=%d"

# Relocation messages

@ MSG_REL_GENERATE	"generating input relocations: section=%s"
@ MSG_REL_COLLECT	"collecting input relocations: section=%s, file=%s"
@ MSG_REL_ACTIVE	"performing active relocations"
@ MSG_REL_CREATING	"creating output relocations"
@ MSG_REL_RELOC_START	"relocation processing: file=%s%s"
@ MSG_REL_RELOC_FINISH	"relocation processing: file=%s; finished%s"
@ MSG_REL_RELOC_NONE	"relocation processing: file=%s%s; nothing to do"

@ MSG_REL_RELOC_PLT	"  (plt processing only)"
@ MSG_REL_RELOC_FAIL	"  (failed)"

@ MSG_REL_TRANS		"relocation transition: offset: %#llx old reloc: %s \
			 new reloc: %s symbol `%s'"
@ MSG_REL_DISCARDED	"relocation against discarded section=%s from file=%s; \
			 relocation type=%s offset=0x%llx; relocation discarded"
@ MSG_REL_COPY		"copy data from file=%s to file=%s: symbol `%s'%s"

# Dynamic section messages

@ MSG_DYN_TITLE		"     index  tag               value"
@ MSG_DYN_ENTRY		"%10.10s  %-15.15s  %-#14llx    %s"

# Entrance criteria messages

@ MSG_ECR_TITLE		"%s Entrance Descriptor List (available)"
@ MSG_ECR_DYNAMIC	"Dynamic"
@ MSG_ECR_STATIC	"Static"
@ MSG_ECR_DESC		"entrance descriptor[%d]"


# Elf section messages

@ MSG_ELF_TITLE		"            addr type        size   offset al file"
@ MSG_ELF_ENTRY		"  %3s %#10llx %-5s %#10llx %#8llx %2lld %s%s"
@ MSG_ELF_HEADER	"ELF Header"
@ MSG_ELF_IGNSCN	"  (section ignored)"


# File messages

@ MSG_FIL_BASIC		"file=%s  [ %s ]"
@ MSG_FIL_ARCHIVE	"file=%s  [ archive ] %s"
@ MSG_FIL_SKIP_1	"file=%s  skipped: already processed as %s"
@ MSG_FIL_SKIP_2	"file=%s  skipped: already processed"
@ MSG_FIL_REUSE		"file=%s  reusing: originally processed as %s"
@ MSG_FIL_PROT		"file=%s;  modifying memory protections (%c PROT_WRITE)"
@ MSG_FIL_DELETE	"file=%s;  deleting"
@ MSG_FIL_DLOPEN	"file=%s;  dlopen() called from file=%s  %s"
@ MSG_FIL_DLCLOSE	"file=%s;  dlclose()  %s"
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


@ MSG_FIL_DATA_1	"    dynamic:  %#10llx  base:  %#10llx  size:   %#10llx"
@ MSG_FIL_DATA_2	"    entry:    %#10llx  lmid:  %#10llx  lmco:   %#10llx"
@ MSG_FIL_DATA_3	"    dynamic:  %#10llx  base:  %#10llx"
@ MSG_FIL_DATA_4	"    envp:     %#10llx  auxv:  %#10llx"

@ MSG_FIL_BND_ADD	"file=%s;  add binding to:"
@ MSG_FIL_BND_FILE	"    file=%s   %s"

@ MSG_FIL_DEP_ADD	"    file=%s;  object added  %s"
@ MSG_FIL_DEP_DELETE	"    file=%s;  object deleting  %s"
@ MSG_FIL_DEP_REMOVE	"    file=%s;  object removed from handle  %s"
@ MSG_FIL_DEP_REMAIN	"    file=%s;  object remains on handle  %s"

@ MSG_FIL_HDL_CREATE	"handle=%s;  creating:"
@ MSG_FIL_HDL_COLLECT	"handle=%s;  collected for possible removal  %s"
@ MSG_FIL_HDL_RETAIN	"handle=%s;  externally referenced from %s: handle \
			 retained"
@ MSG_FIL_HDL_ADD	"handle=%s;  adding dependent objects:"
@ MSG_FIL_HDL_DELETE	"handle=%s;  deleting:"
@ MSG_FIL_HDL_ORPHAN	"handle=%s;  deletion cannot be completed: moving to \
			 orphan list:"
@ MSG_FIL_HDL_REINST	"handle=%s;  reinstating from orphan list:"

@ MSG_FIL_DEL_RESCAN	"pending deletions; rescanning orphan list for \
			 available deletions"

@ MSG_FIL_AR_RESCAN	"rescanning archive list; additional members may \
			 satisfy prior extractions"

@ MSG_FIL_CONFIG_ERR	"configuration file=%s: %s"
@ MSG_FIL_CONFIG_ERR_1	"ignored (configuration building)"
@ MSG_FIL_CONFIG_ERR_2	"invalid version"
@ MSG_FIL_CONFIG_ERR_3	"unable to process file"
@ MSG_FIL_CONFIG_ERR_4	"corrupt or truncated file"

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
@ MSG_LIB_RPATH		" search path=%s  (RPATH from file %s)"
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

@ MSG_MV_ADJEXPAND1	"for symbol=%s new roffset=0x%llx"
@ MSG_MV_ADJMOVE1	"for symbol=%s roffset(from/to)=\
			 (0x%llx/0x%llx)"
@ MSG_MV_OUTSCTADJ1	"adjusting addend for symbol=%s"
@ MSG_MV_MOVEDATA	"file=%s  processing move data"
@ MSG_MV_EXPAND0	"expanding %s into .SUNW_data1: %s"
@ MSG_MV_OUTMOVE0	"copying move entries for %s into .SUNW_move"
@ MSG_MV_EXPAND1	"\t     0x%llx\t0x%llx    (expanded)"

@ MSG_MOVE_INPUT1	"collecting move entries: file=%s"
@ MSG_MOVE_TITLE1	"\t i/o offset\tvalue\trepeat\tstride\tsymbol"
@ MSG_MOVE_TITLE2	"\t     address\tvalue\trepeat\tstride\tsymbol"
@ MSG_MOVE_MVENTRY1	"\t  in 0x%llx\t0x%llx\t0x%x\t0x%x\t%s"
@ MSG_MOVE_MVENTRY2	"\t out 0x%llx\t0x%llx\t0x%x\t0x%x\t%s"

# Section messages

@ MSG_SEC_INPUT		"section=%s; input from file=%s"
@ MSG_SEC_ADDED		"section=%s; added to segment=%s"
@ MSG_SEC_CREATED	"section=%s; added to segment=%s (created)"
@ MSG_SEC_DISCARDED	"section=%s; input from file=%s; \
			 discarded in favor of section=%s from file=%s"
@ MSG_SEC_GRP		"section=%s; input from file=%s; \
			 section member of group: %s:%s"
@ MSG_SEC_GRP_DISCARDED	"section=%s; input from file=%s; \
			 discarded because it is a member of group: %s:%s"

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
@ MSG_USD_UNREF		"file=%s  unreferenced: unused dependency of %s"
@ MSG_USD_FILECYCLIC	"file=%s  unused: cyclic group [%d] member: \
			 unreferenced outside of group"
@ MSG_USD_RTLDINFO	"file=%s  unused RTLDINFO: using RTLDINFO \
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
@ MSG_SYM_AR_CHECK	"archive[%lld]=%s  (%s) checking for tentative override"
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

@ MSG_SYM_BASIC		"symbol[%lld]=%s"
@ MSG_SYM_ADDING	"symbol[%lld]=%s  (global); adding"
@ MSG_SYM_SECTION	"symbol[%d]=%s  (section); segment=%s"
@ MSG_SYM_RESOLVING	"symbol[%lld]=%s  (global); resolving [%d][%d]"
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

# Syminfo strings
@ MSG_SYMI_TITLE1	"syminfo information"
@ MSG_SYMI_TITLE2	"     index  flgs         bound to           symbol"
@ MSG_SYMI_SELF		"<self>"
@ MSG_SYMI_PARENT	"<parent>"
@ MSG_SYMI_EXTERN	"<extern>"

# Version strings

@ MSG_VER_AVAIL_1	"version availability: file=%s"
@ MSG_VER_AVAIL_2	" available  version                     selected from"
@ MSG_VER_DEF_1		"version definition processing: file=%s"
@ MSG_VER_NEED_1	"version needed processing: file=%s"
@ MSG_VER_NOINTERFACE	"version definition has no interface symbols: %s"

# SHF_ORDERED related messages. Token used is sections.

@ MSG_ORD_SORT_BEFORE	"Output section to be sorted=%s"
@ MSG_ORD_SORT_AFTER	"Output section sorted=%s"
@ MSG_ORD_HDR_1		" No. of SHN_BEGIN=%u, SHN_AFTER=%u, sh_info/sh_link=%u"
@ MSG_ORD_TITLE_0	" section=%s from %s is not an ordered section"
@ MSG_ORD_TITLE_1	" section=%s from %s, sh_info=SHN_BEGIN"
@ MSG_ORD_TITLE_2	" section=%s from %s, sh_info=SHN_AFTER"
@ MSG_ORD_TITLE_3	" section=%s from %s, sh_info=%s, sort_val=%d"
@ MSG_ORD_TITLE_4	" section=%s from %s, sh_link=%s, sort_val=%d"

@ MSG_ORD_ERR_TITLE	"The SHF_ORDERED section %s from %s has \
			 an error;  flag ignored"

@ MSG_ORD_ERR_INFORANGE	" The sh_info field is out of range"
@ MSG_ORD_ERR_ORDER	" The section pointed by sh_info is an ordered section"
@ MSG_ORD_ERR_LINKRANGE	" The sh_link field is out of range"
@ MSG_ORD_ERR_FLAGS	" The sh_flag is incorrect"
@ MSG_ORD_ERR_CYCLIC	" The sh_link is cyclic"
@ MSG_ORD_ERR_LINKINV	" A section pointed to by sh_link has an error"

# Link-Auditing Messages

@ MSG_AUD_INIT		"audit library %s: processing"
@ MSG_AUD_VERSION	"audit library %s: running at version: %d"
@ MSG_AUD_INTERFACE	"audit library %s: provides interface: %s"
@ MSG_AUD_OBJECT	"audit library %s: offered object: %s"
@ MSG_AUD_SYM		"audit library %s: %s: symbol: %s: value: 0x%llx %s"
@ MSG_AUD_SYMNEW	"modified to: 0x%llx"

# GOT Messages

@ MSG_GOT_TITLE		"Global Offset Table information:  (%u entries)"

# TRANSLATION_NOTE
#	Do not translate .init or .fini, they represent reserved section names.

@ MSG_UTL_INIT		"calling .init (%s): %s"
@ MSG_UTL_FINI		"calling .fini: %s"
@ MSG_UTL_ARRAY		"calling %s:%s[%d]:0x%llx"
@ MSG_UTL_TRANS		"transferring control: %s"
@ MSG_UTL_WAIT		"suspending thread: %s from %s for completion of .init \
			 for %s"
@ MSG_UTL_BROAD		"signal suspended threads: %s .init complete"
@ MSG_UTL_INTOOLATE	"loading after relocation has started: interposition \
			 request (DF_1_INTERPOSE) ignored: %s"

@ MSG_UTL_SORT		"from sorted order"
@ MSG_UTL_PEND		"pending"
@ MSG_UTL_DYN		"dynamically triggered"
@ MSG_UTL_DONE		"done"

@ MSG_UTL_NOINIT	"warning: calling %s whose .init has not completed"

@ MSG_UTL_DBNOTIFY	"notify debugger: event: %s state: %s"

@ MSG_SCC_TITLE		"%s cyclic dependencies detected:"

# Generic strings

@ MSG_STR_IGNORE	"ignored"
@ MSG_STR_ENTERED	"entered"
@ MSG_STR_INITIAL	"initialized"
@ MSG_STR_IN		" in"
@ MSG_STR_OUT		"out"
@ MSG_STR_ERROR		"error"
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

# PLT padding messages

@ MSG_REL_PADBOUNDTO	"   pltpad file=%s pad: 0x%8.8llx bound to \
			 file=%s symbol `%s'"
@ MSG_REL_PADBINDTO	"   pltpad file=%s symbol `%s' binds to pad: 0x%8.8llx"

# TLS related messages

@ MSG_TLS_STATBLOCK1	"static TLS module: [%2d] %s"
@ MSG_TLS_STATBLOCK2	"static TLS module: Total Static Size: %#llx"
@ MSG_TLS_STMODENT1	"    block:  %#10llx    soff:  %#10llx  flags: %#4llx"
@ MSG_TLS_STMODENT2	"    filesz: %#10llx    memsz: %#10llx  modid: %#4llx"
@ MSG_TLS_MODACT	"%s TLS module: %s"
@ MSG_TLS_ADD		"add"
@ MSG_TLS_REMOVE	"remove"

# Statistics related messages

@ MSG_STATS_AR		"archive %s: count=%d, used=%d  (%d%%)"

@ MSG_STATS_GENERAL	"General Statistics:"
@ MSG_STATS_FILES	"  Input files: relocatables=%lld  \
			 shared objects=%lld  archives=%lld"
@ MSG_STATS_SYMBOLS	"      Symbols: locals=%lld  globals=%lld  \
			 (processed=%lld)"
@ MSG_STATS_RELOCS	"  Relocations: output=%lld  (active=%lld)"

# Hardware/Software capabilities messages
@ MSG_CAP_ELF_TITLE	"     index  tag               value"
@ MSG_CAP_ELF_ENTRY	"%10.10s  %-15.15s  %s"

@ MSG_CAP_HW_1		"hardware capabilities - %s"

@ MSG_CAP_SEC_TITLE	"hardware/software capabilities; input file=%s"
@ MSG_CAP_SEC_ENTRY	"%12.12s  %-15.15s  %s"

@ MSG_CAP_HW_CANDIDATE	"obj=%s;  hardware capabilities candidate"

@ MSG_CAP_HWFILTR_1	"dir=%s;  hardware capability directory filtered by %s"
@ MSG_CAP_HWFILTR_2	"dir=%s;  no hardware capability objects found"

@ _END_

# Debug enabling tokens (for now these are untranslated)

@ MSG_TOK_ALL		"all"
@ MSG_TOK_ARGS		"args"
@ MSG_TOK_BINDINGS	"bindings"
@ MSG_TOK_CAP		"cap"
@ MSG_TOK_BASIC		"basic"
@ MSG_TOK_DETAIL	"detail"
@ MSG_TOK_ENTRY		"entry"
@ MSG_TOK_FILES		"files"
@ MSG_TOK_HELP		"help"
@ MSG_TOK_LIBS		"libs"
@ MSG_TOK_LONG		"long"
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
@ MSG_TOK_STATISTICS	"statistics"
@ MSG_TOK_UNUSED	"unused"

@ MSG_TOK_NAME		"name"
@ MSG_TOK_FULLNAME	"fullname"
@ MSG_TOK_CLASS		"class"

# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_STR_EMPTY		""
@ MSG_STR_DELIMIT	",:"
@ MSG_STR_OSQBRKT	"["
@ MSG_STR_CSQBRKT	"]"

@ MSG_SCN_GOT		".got"
@ MSG_SCN_PLT		".plt"
@ MSG_SCN_BSS		".bss"
@ MSG_SCN_INIT		".init"
@ MSG_SCN_FINI		".fini"
@ MSG_SCN_INITARRAY	".initarray"
@ MSG_SCN_FINIARRAY	".finiarray"
@ MSG_SCN_PREINITARRAY	".preinitarray"

@ MSG_SCC_ENTRY		"    [%d]  %s"

@ MSG_FMT_INDEX		" [%d]"
@ MSG_FMT_STR		"%s"
@ MSG_FMT_PATH		"%s/%s"

@ MSG_PTH_OBJECT	"/tmp/ld.so-OBJECT-"
@ MSG_FIL_RTLD		"ld.so.1"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

# Entrance criteria messages

@ MSG_ECR_NAME		"  ec_name:       %-8s  ec_attrmask:  %s"
@ MSG_ECR_SEGMENT	"  ec_segment:    %-8s  ec_attrbits:  %s"
@ MSG_ECR_NDX		"  ec_ndx:        %-8d  ec_type:      %s"
@ MSG_ECR_FILES		"  ec_files:"
@ MSG_ECR_FILE		"    %s"

# Elf section messages

@ MSG_ELF_MAGIC		"  ei_magic:   { 0x%x, %c, %c, %c }"
@ MSG_ELF_CLASS		"  ei_class:   %-18s  ei_data:      %s"
@ MSG_ELF_MACHINE	"  e_machine:  %-18s  e_version:    %s"
@ MSG_ELF_TYPE		"  e_type:     %s"
@ MSG_ELF_FLAGS		"  e_flags:    %18s"
@ MSG_ELF_FLAGS_FMT	"  e_flags:    %s"
@ MSG_ELF_ESIZE		"  e_entry:    %#18llx  e_ehsize:     %2d  \
			 e_shstrndx:   %2d"
@ MSG_ELFX_ESIZE	"  e_entry:    %#18llx  e_ehsize:     %2d  \
			 e_shstrndx: [sh[0].sh_link]"
@ MSG_ELF_SHOFF		"  e_shoff:    %#18llx  e_shentsize:  %2d  \
			 e_shnum:      %2d"
@ MSG_ELFX_SHOFF	"  e_shoff:    %#18llx  e_shentsize:  %2d  \
			 e_shnum:    [sh[0].sh_size]"
@ MSG_ELF_PHOFF		"  e_phoff:    %#18llx  e_phentsize:  %2d  \
			 e_phnum:      %2d"

# Shdr[0] messages
@ MSG_SHD0_TITLE	"Section Header[0]: {ELF Ehdr extensions}"
@ MSG_SHD0_SIZE		"    sh_size:      %-6lld [shnum]  sh_type:    %s"
@ MSG_SHD0_LINK		"    sh_link:      %-6d [strndx] sh_info:    %s"

# Section header messages

@ MSG_SHD_ADDR		"    sh_addr:      %#-14llx  sh_flags:   %s"
@ MSG_SHD_SIZE		"    sh_size:      %#-14llx  sh_type:    %s"
@ MSG_SHD_OFFSET	"    sh_offset:    %#-14llx  sh_entsize: %#llx"
@ MSG_SHD_ALIGN		"    sh_addralign: %#-14llx"
@ MSG_SHD_LINK		"    sh_link:      %-14d  sh_info:    %s"

# Libs messages

@ MSG_LIB_FILE		"  %s"

# Program header messages

@ MSG_PHD_VADDR		"    p_vaddr:      %#-14llx  p_flags:    %s"
@ MSG_PHD_PADDR		"    p_paddr:      %#-14llx  p_type:     %s"
@ MSG_PHD_FILESZ	"    p_filesz:     %#-14llx  p_memsz:    %#llx"
@ MSG_PHD_OFFSET	"    p_offset:     %#-14llx  p_align:    %#llx"


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

# Binding mode strings

@ MSG_BND_NEEDED	" NEEDED "
@ MSG_BND_REFER		" REFERENCED "

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

#
# The following messages are placed here because:
# 	*) it is difficult to keep the table aligned, and to document them,
#	*) the information here are mainly for programmers, and not for
#	   regular end-users.
#

# Relocation messages
@ MSG_REL_TITLE_1	"        type                        \
			 offset      value  section        symbol"
@ MSG_REL_REL_TITLE_2	"        type                        \
			 offset             section        symbol"
@ MSG_REL_RELA_TITLE_2	"        type                        \
			 offset     addend  section        symbol"
@ MSG_REL_REL_TITLE_3	"        type                        \
			 offset      value                 symbol"
@ MSG_REL_RELA_TITLE_3	"        type                        \
			 offset     addend                 symbol"
@ MSG_REL_RELA_TITLE_4	"                                           \
			 value"
@ MSG_REL_ARGS_2	"                       %#14llx %#10llx"
@ MSG_REL_ARGS_6	"  %5s %-21s %#14llx %#10llx  %-14.14s %s  %s"
@ MSG_REL_L_ARGS_6	"  %5s %-21s %#14llx %#10llx  %-14s %s  %s"
@ MSG_REL_ARGS_5	"  %5s %-21s %#14llx             %-14.14s %s  %s"
@ MSG_REL_L_ARGS_5	"  %5s %-21s %#14llx             %-14s %s  %s"
@ MSG_REL_REGSYM	"                       %14.14s %#10llx"

# Symbol strings
@ MSG_SYM_TITLE		"%10.10s    value       size     type bind \
			 oth ver shndx       %s"
@ MSG_SYM_L_TITLE	"%10.10s    value       size     type bind \
			 oth ver shndx/%s"
@ MSG_SYM_ENTRY		"%10.10s  %10.10s 0x%8.8llx  %4s %4s %2s %4d \
			 %-11.11s %s"
@ MSG_SYM_L_ENTRY	"%10.10s  %10.10s 0x%8.8llx  %4s %4s %2s %4d \
			 %-11s %s"

@ MSG_SYM_TITLE_64	"%10.10s        value           size     type bind \
			 oth ver shndx       %s"
@ MSG_SYM_L_TITLE_64	"%10.10s        value           size     type bind \
			 oth ver shndx/%s"
@ MSG_SYM_ENTRY_64	"%10.10s  %14.14s 0x%12.12llx  %4s %4s %2s %4d \
			 %-11.11s %s"
@ MSG_SYM_L_ENTRY_64	"%10.10s  %14.14s 0x%12.12llx  %4s %4s %2s %4d \
			 %-11s %s"

# Version messages
@ MSG_VER_SELECTED	"  SELECTED  %-26.26s  %s"
@ MSG_VER_L_SELECTED	"  SELECTED  %-26s  %s"
@ MSG_VER_ALL		"       ALL  %-26.26s"
@ MSG_VER_L_ALL		"       ALL  %-26s"
@ MSG_VER_DEF_2		"     index  version                     dependency"
@ MSG_VER_NEED_2	"            file                        version"
@ MSG_VER_LINE_1	"%10.10s  %-26.26s  %-20s %s"
@ MSG_VER_L_LINE_1	"%10s  %-26s  %-20s %s"
@ MSG_VER_LINE_2	"%47s  %s"
@ MSG_VER_LINE_3	"%38s  %-20s %s"
@ MSG_VER_LINE_4	"%38s  %s"
@ MSG_VER_LINE_5	"            %-26.26s  %s"
@ MSG_VER_L_LINE_5	"            %-26s  %s"


# GOT messages
@ MSG_GOT_COLUMNS	"index\tref\taddend\t\tsymbol"
@ MSG_GOT_SMALL_PIC	"pic"
@ MSG_GOT_PIC		"PIC"
@ MSG_GOT_FORMAT1	"[%05d] %3s  0x%08llx  %s"
@ MSG_GOT_FORMAT2	"[%05d] %3s  0x%08llx  %s:%s"
@ MSG_GOT_ECOLUMNS	" ndx     addr      value    reloc              \
			 addend   symbol"
@ MSG_GOT_ECOLUMNS_64	" ndx     addr          value        reloc              \
			 addend       symbol"
@ MSG_GOT_EFORMAT	"[%05d]  %08llx  %08llx %-18s %08llx %s"
@ MSG_GOT_EFORMAT_64	"[%05d]  %012llx  %012llx %-18s %012llx %s"

@ MSG_SYMI_FMT		"%10.10s  %-4s %7s %-18s %s"

@ MSG_CNTL_ENTRY	"   [0x%llx]  %s"
