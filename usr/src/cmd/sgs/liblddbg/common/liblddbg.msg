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
# Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
#

@ _START_

# Message file for cmd/sgs/liblddbg.

@ MSG_ID_LIBLDDBG


# Usage messages

@ MSG_USE_UNRECOG	"warning: unrecognized debug option (try help): %s"
@ MSG_USE_CNTNEGOPT	"warning: ignoring non-negatable debug option: %s"

@ MSG_USE_HDR_DCT	"Display Control Tokens:"
@ MSG_USE_HDR_CST	"Category Selection Tokens:"
@ MSG_USE_HDR_BOTH	"    [ld and ld.so.1]"
@ MSG_USE_HDR_RTLD	"    [ld.so.1 only]"
@ MSG_USE_HDR_LD	"    [ld only]"

# TRANSLATION_NOTE - Use the following output in the C locale as reference 1.
#
# The runtime linker and link-editor support a shared debugging
# facility. Options are selected via a comma separated list of tokens,
# each of which specifies a display option or a category for which
# information is desired. Many tokens apply to both linker components,
# while some are specific to one or the other. Diagnostics are printed,
# one per line, with a standard prefix prepended to each one. Diagnostic
# output is sent to stderr unless otherwise redirected.

# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.

@ MSG_USE_R1_A	"The runtime linker and link-editor support a \
		 shared debugging"
@ MSG_USE_R1_B	"facility. Options are selected via a comma separated list \
		 of tokens,"
@ MSG_USE_R1_C	"each of which specifies a display option or a category \
		 for which"
@ MSG_USE_R1_D	"information is desired. Many tokens apply to both linker \
		 components,"
@ MSG_USE_R1_E	"while some are specific to one or the other. Diagnostics \
		 are printed,"
@ MSG_USE_R1_F	"one per line, with a standard prefix prepended to each one. \
		 Diagnostic"

# TRANSLATION_NOTE -- do not translate "stderr"
@ MSG_USE_R1_G	"output is sent to stderr unless otherwise redirected."

# TRANSLATION_NOTE - End of reference 1


# TRANSLATION_NOTE - Use the following output in the C locale as reference 2.
#
# Runtime Linking (ld.so.1):
#     Diagnostics that trace the runtime linking of an application
#     can be enabled via the LD_DEBUG environment variable:
#          LD_DEBUG=token1,token2 app ...
#     In addition to the "output" token described below, diagnostic
#     output from the runtime linker can be redirected to an output
#     file using the additional environment variable:
#          LD_DEBUG_OUTPUT=file
#     If the "output" token and LD_DEBUG_OUTPUT are both specified,
#     the file specified by LD_DEBUG_OUTPUT is used. If LD_DEBUG_OUTPUT
#     is used, the output file name is suffixed with the process id.
#     An output file specified via the "output" token is used as
#     specified, without a process id suffix. Use of the "output"
#     token with programs that call fork() results in each process
#     writing debug output to the same file. The debug output will be
#     jumbled and incomplete. LD_DEBUG_OUTPUT should be used in such
#     cases to direct debug output for each process to a unique file.
#
#     All runtime linker diagnostics are prepended with the process
#     id. If thread capabilities are enabled for the process, the
#     thread id is also shown. All Solaris applications are thread
#     capable, and a single threaded application may use threads via
#     the libraries it links to. Diagnostics from such applications
#     reference thread id 1.

# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.

@ MSG_USE_R2_A	"Runtime Linking (ld.so.1):"
@ MSG_USE_R2_B	"    Diagnostics that trace the runtime linking \
		 of an application"

# TRANSLATION_NOTE -- do not translate "LD_DEBUG"
@ MSG_USE_R2_C	"    can be enabled via the LD_DEBUG environment variable:"

# TRANSLATION_NOTE -- do not translate "LD_DEBUG"
@ MSG_USE_R2_D	"         LD_DEBUG=token1,token2 app ..."

# TRANSLATION_NOTE -- do not translate "output"
@ MSG_USE_R2_E	"    In addition to the \"output\" token described \
		 below, diagnostic"
@ MSG_USE_R2_F	"    output from the runtime linker can be redirected to \
		 an output"
@ MSG_USE_R2_G	"    file using the additional environment variable:"

# TRANSLATION_NOTE -- do not translate "LD_DEBUG_OUTPUT"
@ MSG_USE_R2_H	"         LD_DEBUG_OUTPUT=file"

# TRANSLATION_NOTE -- do not translate "output" or "LD_DEBUG_OUTPUT"
@ MSG_USE_R2_I	"    If the \"output\" token and LD_DEBUG_OUTPUT are \
		 both specified,"

# TRANSLATION_NOTE -- do not translate "LD_DEBUG_OUTPUT"
@ MSG_USE_R2_J	"    the file specified by LD_DEBUG_OUTPUT is used. \
		 If LD_DEBUG_OUTPUT"
@ MSG_USE_R2_K	"    is used, the output file name is suffixed with \
		     the process id."

# TRANSLATION_NOTE -- do not translate "output"
@ MSG_USE_R2_L	"    An output file specified via the \"output\" token \
		     is used as"

# TRANSLATION_NOTE -- do not translate "output"
@ MSG_USE_R2_M	"    specified, without a process id suffix. Use \
		     of the \"output\""

# TRANSLATION_NOTE -- do not translate "fork"
@ MSG_USE_R2_N	"    token with programs that call fork() results in \
		     each process"
@ MSG_USE_R2_O	"    writing debug output to the same file. The debug \
		     output will be"
@ MSG_USE_R2_P	"    jumbled and incomplete. LD_DEBUG_OUTPUT should be \
		     used in such"
@ MSG_USE_R2_Q	"    cases to direct debug output for each process to \
		     a unique file."


@ MSG_USE_R2_R	"    All runtime linker diagnostics are prepended with \
		 the process"
@ MSG_USE_R2_S	"    id. If thread capabilities are enabled for the \
		 process, the"
@ MSG_USE_R2_T	"    thread id is also shown. All Solaris applications are \
		 thread"
@ MSG_USE_R2_U	"    capable, and a single threaded application may \
		 use threads via"
@ MSG_USE_R2_V	"    the libraries it links to. Diagnostics from such \
		 applications"
@ MSG_USE_R2_W	"    reference thread id 1."

# TRANSLATION_NOTE - End of reference 2


# TRANSLATION_NOTE - Use the following output in the C locale as reference 3.
#
# Link-Editing (ld):
#     Diagnostics that trace the link-editing of an application are
#     enabled using the -D option:
#        ld -Dtoken1,token2 -o prog ...
#     As compiler drivers may assign -D a different meaning, the
#     LD_OPTIONS environment variable is often used:
#        LD_OPTIONS=-Dtoken1,token2 cc -o prog ...
# 
#     The position of -D on the link-edit command line is significant.
#     Diagnostics are enabled when a debug token is first encountered,
#     and can be switched off by prepending the token with "!".
# 
#     Diagnostic output can be directed to a file using the "output"
#     token, The output file is used as specified, without a process
#     id suffix.
# 
#     All link-editor diagnostics are prepended with the string "debug".
# 

# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.

@ MSG_USE_R3_A	" Link-Editing (ld):"
@ MSG_USE_R3_B	"    Diagnostics that trace the link-editing of an \
		 application are"
@ MSG_USE_R3_C	"    enabled using the -D option:"
@ MSG_USE_R3_D	"       ld -Dtoken1,token2 -o prog ..."
@ MSG_USE_R3_E	"    As compiler drivers may assign -D a different meaning, the"

# TRANSLATION_NOTE -- do not translate "LD_OPTIONS"
@ MSG_USE_R3_F	"    LD_OPTIONS environment variable is often used:"

# TRANSLATION_NOTE -- do not translate "LD_OPTIONS"
@ MSG_USE_R3_G	"       LD_OPTIONS=-Dtoken1,token2 cc -o prog ..."

@ MSG_USE_R3_H	"    The position of -D on the link-edit command line \
		 is significant."
@ MSG_USE_R3_I	"    Diagnostics are enabled when a debug token is \
		 first encountered,"
@ MSG_USE_R3_J	"    and can be switched off by prepending the token \
		 with \"!\"."

# TRANSLATION_NOTE -- do not translate "output"
@ MSG_USE_R3_K	"    Diagnostic output can be directed to a file using \
		 the \"output\""

@ MSG_USE_R3_L	"    token, The output file is used as specified, \
		 without a process"
@ MSG_USE_R3_M	"    id suffix."


# TRANSLATION_NOTE -- do not translate "debug"
@ MSG_USE_R3_N	"    All link-editor diagnostics are prepended with the \
		 string \"debug\"."

# TRANSLATION_NOTE - End of reference 3


# TRANSLATION_NOTE - Use the following output in the C locale as reference 4.
#
#         demangle         show C++ symbol names in their demangled form
#         detail           provide more information in conjunction with
#                            other options
#         dtime            prepend a time delta to diagnostics. The value
#                            appears as seconds.fraction, and represents
#                            the elapsed time since that last diagnostic.
#         long             display long object names without truncation
#         output=file      debug output is sent to the named file
#                            instead of stderr. If file is empty (\"\"),
#                            following output will be sent to stderr.
#         ttime            prepend a time stamp to diagnostics. The value
#                            appears as seconds.fraction, and represents
#                            the time since entering ld or ld.so.1.
#                            Note, all diagnostics induce a probe affect,
#                            which should be taken into account when
#                            interpreting dtime and ttime information.
#

# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.

# TRANSLATION_NOTE -- do not translate the first token "demangle".
@ MSG_USE_R4_A	"        demangle         show C++ symbol names in their \
					  demangled form"

# TRANSLATION_NOTE -- do not translate the first token "detail".
@ MSG_USE_R4_B	"        detail           provide more information in \
					  conjunction with"
@ MSG_USE_R4_B2	"                           other options"

# TRANSLATION_NOTE -- do not translate the first token "dtime".
@ MSG_USE_R4_C	"        dtime            prepend a time delta to diagnostics. \
					  The value"
@ MSG_USE_R4_C2	"                           appears as seconds.fraction, and \
					  represents"
@ MSG_USE_R4_C3	"                           the elapsed time since that last \
					  diagnostic."

# TRANSLATION_NOTE -- do not translate the first token "long".
@ MSG_USE_R4_D	"        long             display long object names without \
					  truncation"

# TRANSLATION_NOTE -- do not translate the first token "output".
@ MSG_USE_R4_E	"        output=file      debug output is sent to the \
					  named file"
@ MSG_USE_R4_E2	"                           instead of stderr. If file is \
					  empty (\"\"),"
@ MSG_USE_R4_E3	"                           following output will be \
					    sent to stderr."

# TRANSLATION_NOTE -- do not translate the first token "ttime".
@ MSG_USE_R4_F	"        ttime            prepend a time stamp to diagnostics. \
					  The value"
@ MSG_USE_R4_F2	"                           appears as seconds.fraction, and \
					  represents"
@ MSG_USE_R4_F3	"                           the time since entering ld or \
					  ld.so.1."
@ MSG_USE_R4_F4 "                           Note all diagnostics induce a \
					  probe affect,"
@ MSG_USE_R4_F5 "                           which should be taken into \
					  account when"
@ MSG_USE_R4_F6 "                           interpreting dtime and ttime \
                                          information."

# TRANSLATION_NOTE - End of reference 4


# TRANSLATION_NOTE - Use the following output in the C locale as reference 5.
#
#         lmid[=name]      prepend link-map list id to diagnostics, and
#                          optionally filter the lists: By default,
#                          diagnostics are produced for all link-map
#                          lists except that of the runtime linker
#                          (ldso), without identification. "lmid" causes
#                          the link-map list id to be prepended.
#                          "name" limits diagnostics to the named
#                          link-map list. Additional "lmid" tokens
#                          can specify multiple link-map lists.
#                          Valid names are:
#                              all        all link-map lists except ldso
#                              alt        all alternative link-map lists
#                              alt[0-9]+  specific alternative link-map list
#                              base       the base, or main, link-map list
#                              ldso       the runtime linker link-map list 
# 

# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.


# TRANSLATION_NOTE -- do not translate the first token "lmid".
@ MSG_USE_R5_A	"        lmid[=name]      prepend link-map list id to \
					  diagnostics, and"
@ MSG_USE_R5_A2	"                         optionally filter the lists: By \
					  default,"
@ MSG_USE_R5_A3	"                         diagnostics are produced for all \
					  link-map"
@ MSG_USE_R5_A4	"                         lists except that of the runtime \
					  linker"
@ MSG_USE_R5_A5	"                         (ldso), without identification. \
					  \"lmid\" causes"

# TRANSLATION_NOTE -- do not translate "name"
@ MSG_USE_R5_A6	"                         the link-map list id to be prepended."
@ MSG_USE_R5_A7	"                         \"name\" limits diagnostics to the \
					  named"
@ MSG_USE_R5_A8	"                         link-map list. Additional \"lmid\" \
					  tokens"
@ MSG_USE_R5_A9	"                         can specify multiple link-map \
					  lists."
@ MSG_USE_R5_A0	"                         Valid names are:"

# TRANSLATION_NOTE -- do not translate the token "all".
@ MSG_USE_R5_B	"                             all        all link-map lists \
							 except ldso"

# TRANSLATION_NOTE -- do not translate the token "alt".
@ MSG_USE_R5_C	"                             alt        all alternative \
							 link-map lists"

# TRANSLATION_NOTE -- do not translate the token "alt".
@ MSG_USE_R5_D	"                             alt[0-9]+  specific alt \
							 link-map list"

# TRANSLATION_NOTE -- do not translate the token "base".
@ MSG_USE_R5_E	"                             base       base (main) \
							 link-map list"
@ MSG_USE_R5_F	"                             ldso       runtime linker \
							 link-map list "
# TRANSLATION_NOTE - End of reference 5


# TRANSLATION_NOTE - Use the following output in the C locale as reference 6.
#
#         name             prepend output file basename to diagnostics
#         fullname         prepend full output file name to diagnostics
#         class            prepend output file elfclass (32/64) to
#                            diagnostics
# 

# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.

# TRANSLATION_NOTE -- do not translate the first token "name".
@ MSG_USE_R6_A	"        name             prepend output file basename \
					  to diagnostics"

# TRANSLATION_NOTE -- do not translate the first token "fullname".
@ MSG_USE_R6_B	"        fullname         prepend full output file name \
					  to diagnostics"

# TRANSLATION_NOTE -- do not translate the first token "class".
@ MSG_USE_R6_C	"        class            prepend output file elfclass \
					  (32/64) to"
@ MSG_USE_R6_C2	"                           diagnostics"

# TRANSLATION_NOTE - End of reference 6


# TRANSLATION_NOTE - Use the following output in the C locale as reference 7.
#
#         all              display information for all categories
#         basic            basic trace information/warnings
#         cap              platform/machine/hardware/software capabilities
#         files            input file processing (files and libraries)
#         help             this help message
#         libs             library search paths; detail flag shows
#                            actual library lookup (-l) processing
#         move             move sections
#         reloc            relocations
#         symbols          symbol tables; detail flag shows internal
#                            symbol table addition and resolution (ld only)
#         tls              thread local storage (TLS)
#         unused           unused/unreferenced files; detail flag
#                            shows unused sections (ld only)
#         versions         ELF versioning

# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.


# TRANSLATION_NOTE -- do not translate the first token "all".
@ MSG_USE_R7_A	"        all              display information for \
					  all categories"

# TRANSLATION_NOTE -- do not translate the first token "basic".
@ MSG_USE_R7_B	"        basic            basic trace information/warnings"

# TRANSLATION_NOTE -- do not translate the first token "cap".
@ MSG_USE_R7_C	"        cap              platform/machine/hardware/software \
					  capabilities"

# TRANSLATION_NOTE -- do not translate the first token "files".
@ MSG_USE_R7_D	"        files            input file processing (files \
					  and libraries)"

# TRANSLATION_NOTE -- do not translate the first token "help".
@ MSG_USE_R7_E	"        help             this help message"

# TRANSLATION_NOTE -- do not translate the first token "libs".
@ MSG_USE_R7_F	"        libs             library search paths; detail \
					  flag shows"
@ MSG_USE_R7_F2	"                           actual library lookup (-l) \
					    processing"

# TRANSLATION_NOTE -- do not translate the first token "move".
@ MSG_USE_R7_G	"        move             move sections"

# TRANSLATION_NOTE -- do not translate the first token "reloc".
@ MSG_USE_R7_H	"        reloc            relocations"

# TRANSLATION_NOTE -- do not translate the first token "symbols".
@ MSG_USE_R7_I	"        symbols          symbol tables; detail flag shows \
					  internal"
@ MSG_USE_R7_I2	"                           symbol table addition/resolution \
					    (ld only)"

# TRANSLATION_NOTE -- do not translate the first token "tls".
@ MSG_USE_R7_J	"        tls              thread local storage (TLS)"

# TRANSLATION_NOTE -- do not translate the first token "unused".
@ MSG_USE_R7_K	"        unused           unused/unreferenced files; \
					  detail flag"
@ MSG_USE_R7_K2	"                           shows unused sections (ld only)"

# TRANSLATION_NOTE -- do not translate the first token "versions".
@ MSG_USE_R7_L	"        versions         ELF versioning"

# TRANSLATION_NOTE - End of reference 7


# TRANSLATION_NOTE - Use the following output in the C locale as reference 8.
#
#         audit            runtime link-audit processing
#         bindings         symbol binding; detail flag shows
#                            absolute:relative addresses
#         callback         user supplied code executed by ld.so.1
#                            (i.e. dl_iterate_phdr)
#         init             init and fini processing


# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.


# TRANSLATION_NOTE -- do not translate the first token "audit".
@ MSG_USE_R8_A	"        audit            runtime link-audit processing"

# TRANSLATION_NOTE -- do not translate the first token "bindings".
@ MSG_USE_R8_B	"        bindings         symbol binding; detail flag shows"
@ MSG_USE_R8_B2	"                           absolute:relative addresses"

# TRANSLATION_NOTE -- do not translate the first token "dl".
@ MSG_USE_R8_C	"        dl               user calls to the dl*() family"

# TRANSLATION_NOTE -- do not translate the first token "init".
@ MSG_USE_R8_D	"        init             init and fini processing"

# TRANSLATION_NOTE - End of reference 8


# TRANSLATION_NOTE - Use the following output in the C locale as reference 9.
#
#         args             input arguments
#         entry            entrance criteria descriptors
#         got              GOT symbol information
#         map              mapfile processing
#         sections         input sections
#         segments         output segments and address/offset processing;
#                            detail flag shows associated sections
#         statistics       symbol table and relocation statistics
#         strtab           string table compression statistics;
#                            detail flag shows layout of string tables
#         support          support libraries

# TRANSLATION_NOTE - The next series of messages makes the above output in C
# locale.

# TRANSLATION_NOTE -- do not translate the first token "args".
@ MSG_USE_R9_A	"        args             input arguments"

# TRANSLATION_NOTE -- do not translate the first token "entry".
@ MSG_USE_R9_B	"        entry            entrance criteria descriptors"

# TRANSLATION_NOTE -- do not translate the first token "got".
@ MSG_USE_R9_C	"        got              GOT symbol information"

# TRANSLATION_NOTE -- do not translate the first token "map".
@ MSG_USE_R9_D	"        map              mapfile processing"

# TRANSLATION_NOTE -- do not translate the first token "sections".
@ MSG_USE_R9_E	"        sections         input sections"

# TRANSLATION_NOTE -- do not translate the first token "segments".
@ MSG_USE_R9_F	"        segments         output segments and address/offset \
					  processing;"
@ MSG_USE_R9_F2	"                           detail flag shows associated \
					    sections"

# TRANSLATION_NOTE -- do not translate the first token "statistics".
@ MSG_USE_R9_G	"        statistics       symbol table and relocation \
					  statistics"

# TRANSLATION_NOTE -- do not translate the first token "strtab".
@ MSG_USE_R9_H	"        strtab           string table compression statistics;"
@ MSG_USE_R9_H2	"                           detail flag shows layout of \
					    string tables"

# TRANSLATION_NOTE -- do not translate the first token "support".
@ MSG_USE_R9_I	"        support          support libraries"

# TRANSLATION_NOTE - End of reference 9


# Basic processing (ld).

@ MSG_BASIC_COLLECT	"collect relocations"
@ MSG_BASIC_CREATE	"create output image"
@ MSG_BASIC_FILES	"process files"
@ MSG_BASIC_FINISHED	"processing finished"
@ MSG_BASIC_OPTIONS	"process options"
@ MSG_BASIC_RELOCATE	"relocate output image"
@ MSG_BASIC_VALIDATE	"validating symbols"

# Argument messages

@ MSG_ARG_OPTION	"arg[%d]\toption=-%c"
@ MSG_ARG_OPTARG	"arg[%d]\toption=-%c:  option-argument: %s"
@ MSG_ARG_STR2CHR	"arg[%d]\toption=-%s:  translated: new option=-%c"
@ MSG_ARG_WLDEL		"arg[%d]\toption=-W%s:  translated: prefix -Wl,: \
			 removed"
@ MSG_ARG_FILE		"arg[%d]\tfile=%s"

@ MSG_ARG_NG_UNKNOWN	"warning: unrecognized -z guidance item: %s"


# Bindings messages
# NOTE: these are used by appcert(1) and lari(1), use care when changing.

@ MSG_BND_BASIC		"binding file=%s to file=%s: symbol '%s'"
@ MSG_BND_PLT		"binding file=%s (%#llx:%#llx) at plt[%lld]:%s to \
			 file=%s (%#llx:%#llx): symbol '%s'%s"
@ MSG_BND_DLSYM		"binding file=%s (dlsym) to file=%s \
			 (%#llx:%#llx): symbol '%s'%s"
@ MSG_BND_DEFAULT	"binding file=%s (%#llx:%#llx) to file=%s \
			 (%#llx:%#llx): symbol '%s'%s"
@ MSG_BND_WEAK_1	"binding file=%s to 0x0 (undefined weak): symbol '%s'"
@ MSG_BND_WEAK_2	"binding file=%s (%#llx:%#llx) to 0x0 \
			 (undefined weak): symbol '%s'"

# NOTE: the rejected message is used by lari(1), use care when changing.  This
# message is formatted to conform to the pattern used by the MSG_BINFO messages.
@ MSG_BND_REJECT	"binding file=%s to file=%s: symbol '%s'  \
			 (rejected: %s)"
@ MSG_BNDREJ_DIRECT	"attempt to directly bind to a NODIRECT definition"
@ MSG_BNDREJ_GROUP	"attempt to bind within a group to a NODIRECT \
			 definition"
@ MSG_BNDREJ_SINGLE	"attempt to bind to a SINGLETON definition without \
			 following default search model"

@ MSG_BND_PLTPAD_TO	"   pltpad: %#llx: file=%s bound to file=%s: \
			 symbol '%s'"
@ MSG_BND_PLTPAD_FROM	"   pltpad: %#llx: bound from file=%s: symbol '%s'"

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
@ MSG_REL_COPY		"copy data from file=%s to file=%s: symbol '%s'%s"
@ MSG_REL_SLOPPYCOMDAT	"the following relocation references a discarded \
			 section; relocation redirected to section %s in \
			 file %s"

# Entrance criteria messages

@ MSG_ECR_TITLE		"Segment Entrance Criteria Descriptor List"
@ MSG_ECR_DESC		"entrance descriptor[%u]"


# Elf Data (section) messages
# TRANSLATION_NOTE - the following two entries provide for a series of one or
# more standard 32-bit Elf_Data entries that align with the initial title.

@ MSG_EDATA_TITLE_32	"            addr type        size   offset al file"
@ MSG_EDATA_ENTRY_32	"  %3s %#10llx %-5s %#10llx %#8llx %2lld %s %s%s"

# TRANSLATION_NOTE - the following two entries provide for a series of one or
# more standard 64-bit Elf_Data entries that align with the initial title.

@ MSG_EDATA_TITLE_64	"                    addr type                \
			 size           offset al file"
@ MSG_EDATA_ENTRY_64	"  %3s %#18llx %-5s %#18llx %#16llx %2lld %s %s%s"

@ MSG_EDATA_IGNSCN	"  (section ignored)"

# File messages

@ MSG_FIL_BASIC		"file=%s  [ %s ]"
@ MSG_FIL_ARCHIVE	"file=%s  [ archive ] %s"
@ MSG_FIL_SKIP_1	"file=%s;  skipped: already processed as %s"
@ MSG_FIL_SKIP_2	"file=%s;  skipped: already processed"
@ MSG_FIL_REUSE		"file=%s;  reusing: originally processed as %s"
@ MSG_FIL_PROT		"file=%s;  modifying memory protections (%c PROT_WRITE)"
@ MSG_FIL_DELETE	"file=%s;  deleting"
@ MSG_FIL_CLEANUP	"file=%s;  loading failed: cleaning up lmco 0x%llx"
@ MSG_FIL_LAZYLOAD	"file=%s;  lazy loading from file=%s: symbol=%s"
@ MSG_FIL_PRELOAD	"file=%s;  preloading"
@ MSG_FIL_NEEDED	"file=%s;  needed by %s"
@ MSG_FIL_FILTER_1	"file=%s;  filter for %s  (configuration definition)"
@ MSG_FIL_FILTER_2	"file=%s;  filter for %s"
@ MSG_FIL_FILTEE_2	"file=%s;  filtee processing failed"
@ MSG_FIL_FILTEE_3	"file=%s;  filtee skipped  (auditor directed)"
@ MSG_FIL_FIXNAME	"file=%s;  required name=%s"
@ MSG_FIL_PROMOTE	"file=%s;  promoting mode to %s"
@ MSG_FIL_DEFERRED	"file=%s;  deferred dependency exchanged for file=%s"
@ MSG_FIL_AOUT		"file=%s  [ AOUT ]; generating link map"
@ MSG_FIL_ELF		"file=%s  [ ELF ]; generating link map%s"
@ MSG_FIL_LDSO		"file=%s  [ ELF ]"

# NOTE: these are used by lari(1), use care when changing.
@ MSG_FIL_ANALYZE	"file=%s;  analyzing  %s"
@ MSG_FIL_FILTEE_1	"file=%s;  filtered by %s"
@ MSG_FIL_CONFIG	"file=%s  [ ELF ]; configuration alternate found: %s"


@ MSG_FIL_DATA_AS	"    addr:     %#18llx  size:   %#18llx"
@ MSG_FIL_DATA_LL	"    lmid:     %18.18s  lmco:   %#18llx"
@ MSG_FIL_DATA_EA	"    envp:     %#18llx  auxv:   %#18llx"

@ MSG_FIL_MMAPOBJ	"file=%s  mmapobj entries=%d"
@ MSG_FIL_MMAPOBJ_1	"  [%d]: addr:  %#18llx  fsize:  %#18llx  %s"
@ MSG_FIL_MMAPOBJ_2	"       offset: %#17llx  msize:  %#18llx"

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

@ MSG_FIL_HDL_CREATE	"handle=%s;  creating  %s  0x%llx:"
@ MSG_FIL_HDL_ADD	"handle=%s;  adding dependent objects  %s:"
@ MSG_FIL_HDL_DELETE	"handle=%s;  inspecting for deletion:"
@ MSG_FIL_HDL_ORPHAN	"handle=%s;  deletion cannot be completed: moving to \
			 orphan list:"
@ MSG_FIL_HDL_REINST	"handle=%s;  reinstating from orphan list:"

@ MSG_FIL_HDL_COLLECT	"handle=%s;  collected for possible removal  %s"
@ MSG_FIL_HDL_RETAIN	"handle=%s;  externally referenced from %s: handle \
			 retained"
@ MSG_FIL_DEL_RESCAN	"pending deletions; rescanning orphan list for \
			 available deletions"

@ MSG_FIL_AR_RESCAN	"rescanning archives from args[%d-%d]; additional \
			 members may satisfy prior extractions"

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
@ MSG_REJ_UNKCAP	"obj=%s;  rejected: unknown capability: %d"
@ MSG_REJ_HWCAP_1	"obj=%s;  rejected: hardware capability (CA_SUNW_HW_1) \
			 unsupported: %s"
@ MSG_REJ_SFCAP_1	"obj=%s;  rejected: software capability (CA_SUNW_SF_1) \
			 unsupported: %s"
@ MSG_REJ_MACHCAP	"obj=%s;  rejected: machine capability (CA_SUNW_MACH) \
			 unsupported: %s"
@ MSG_REJ_PLATCAP	"obj=%s;  rejected: platform capability (CA_SUNW_PLAT) \
			 unsupported: %s"
@ MSG_REJ_HWCAP_2	"obj=%s;  rejected: hardware capability (CA_SUNW_HW_2) \
			 unsupported: %s"

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
@ MSG_LIB_TDEFAULT	" search path=%s  (trusted default)"
@ MSG_LIB_TDEFAULTC	" search path=%s  (trusted configuration default - %s)"
@ MSG_LIB_LIBPATH	" search path=%s  (LIBPATH or -YP)"
@ MSG_LIB_YPATH		" search path=%s  replaces  path=%s  (-Y%c)"

@ MSG_LIB_FIND		"find object=%s; searching"
@ MSG_LIB_TRYING	" trying path=%s%s"
@ MSG_LIB_ALTER		" trying path=%s  (auditor returned alternative)"
@ MSG_LIB_SKIP		"   skip path=%s  (auditor directed)"
@ MSG_LIB_IGNORE	" ignore path=%s  (insecure directory name)"
@ MSG_LIB_INUSE		"    use path=%s  (implicitly secure, as directory \
			 has already provided dependencies)"

# Mapfile messages

@ MSG_MAP_MAPFILE	"mapfile=%s; version=%d (%s)"
@ MSG_MAP_SEG		"segment directive; line=%llu; %s"
@ MSG_MAP_SEG_ORDER	"segment order directive; line=%llu; list_cnt=%lld; %s"
@ MSG_MAP_CAP		"capability directive; line=%llu"
@ MSG_MAP_EC		"entrance criteria; line=%llu; added"
@ MSG_MAP_OS_ORDER	"output section ordering; line=%llu; segment=%s \
			 section=%s; index=%d"
@ MSG_MAP_HDR_NOALLOC	"header noalloc directive; line=%llu; first loadable \
			 segment will not contain ELF and program headers"

@ MSG_MAP_SYM_SCOPE	"symbol scope definition"
@ MSG_MAP_SYM_SIZE	"size-symbol directive; line=%llu; segment=%s; \
			 symbol=%s; %s"
@ MSG_MAP_SYM_VER_1	"%s, %s; symbol=%s  (%s)"
@ MSG_MAP_SYM_VER_2	"%s; symbol=%s  (%s)"

@ MSG_MAP_DV		"depend versions directive; line=%llu, object=%s"
@ MSG_MAP_DV_ENTRY	"%12.12s  %s; line=%llu"

@ MSG_MAP_SORT_TITLE	"mapfile additions: segment sorting required" 
@ MSG_MAP_SORT_TITLE_O	"before:" 
@ MSG_MAP_SORT_TITLE_S	"after:" 
@ MSG_MAP_POST_TITLE	"mapfile post processing"
@ MSG_MAP_ENT_ORD_TITLE	"set entrance criteria input section sort keys; \
			 segment=%s"

@ MSG_MAP_ID_ADD	"%s: %lld: enter conditional expression id: %s"
@ MSG_MAP_ID_CLEAR	"%s: %lld: delete conditional expression id: %s"
@ MSG_MAP_PASS		"%s: %lld: input enabled by %s"
@ MSG_MAP_NOPASS	"%s: %lld: input disabled by %s"

# Move messages

@ MSG_MOVE_FILE		"file=%s  processing move data"

@ MSG_MOVE_TITLE1	"  i/o     offset   size repeat stride            \
			 value  with respect to"
@ MSG_MOVE_TITLE2	"  i/o    address   size repeat stride            \
			 value  with respect to"

@ MSG_MOVE_ENTRYIN	"   in %#10llx %6d %6d %6d %#16llx  %s"
@ MSG_MOVE_ENTRYOUT	"  out %#10llx %6d %6d %6d %#16llx  %s"
@ MSG_MOVE_EXPAND	"      %#10llx                      %#16llx  (expanded)"

@ MSG_MOVE_ADJEXPAND	"for symbol=%s roffset: new=0x%llx"
@ MSG_MOVE_ADJMOVE	"for symbol=%s roffset: from=0x%llx, to=0x%llx"
@ MSG_MOVE_OUTSCTADJ	"adjusting addend for symbol=%s"
@ MSG_MOVE_PAREXPN	"expanding symbol=%s into .data: %s"
@ MSG_MOVE_OUTMOVE	"copying move entries for symbol=%s into .SUNW_move"
@ MSG_MOVE_INPUT	"collecting move entries: file=%s"
@ MSG_MOVE_BAD		"move %lld offset invalid: %s: offset=0x%llx \
			 lies outside memory image; move discarded"

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

@ MSG_SEC_BACKING	"mapfile symbol definitions: create backing storage:"

@ MSG_SEC_INPUT		"section=%s; input from file=%s"
@ MSG_SEC_INPUT_GEN	"section=%s"
@ MSG_SEC_INPUT_GENSTR	"section=%s; input generated merged string section"
@ MSG_SEC_ADDED		"section=%s; added to segment=%s"
@ MSG_SEC_CREATED	"section=%s; added to segment=%s (created)"
@ MSG_SEC_REDIRECTED	"section=%s; redirected to section=%s"
@ MSG_SEC_DISCARDED	"section=%s; input from file=%s; \
			 discarded in favor of section=%s; file=%s"

@ MSG_SEC_GNU_COMDAT_1	"section=%s; identified as COMDAT with \
			 relaxed relocations enabled" 
@ MSG_SEC_GNU_COMDAT_2	"section=%s; identified as COMDAT"
@ MSG_SEC_GNU_COMDAT_3	"section=%s; relaxed relocations enabled" 

@ MSG_SEC_GRP_DEFINE	"section=%s; input from file=%s; defines %s\
			 group: signature symbol: %s"
@ MSG_SEC_GRP_MEMBER	"section=%s; input from file=%s; member of %s\
			 group: signature symbol: %s"
@ MSG_SEC_GRP_DISCARDED	"section=%s; input from file=%s; discarded in \
			 favor of group: signature symbol: %s: file=%s"

@ MSG_SEC_STRMERGE_DISCARDED "section=%s; input from file=%s; \
			 discarded in favor of generated merged string section"
@ MSG_SEC_STRMERGE_UNSUP "section=%s; input from file=%s; sh_addralign=%lld; \
			  sh_entsize=%lld; unable to merge sections with this \
			  size and alignment"

@ MSG_SEC_STRTAB_STND	"strtab=%s; full size: %lld; uncompressed"
@ MSG_SEC_STRTAB_COMP	"strtab=%s; full size: %lld; compressed down to: %lld"
@ MSG_SEC_GENSTR_COMP	"section=%s (generated merged string section); \
			 full size: %lld; compressed down to: %lld"
@ MSG_SEC_STRTAB_HD	"strtab=%s; compression information [%d buckets]:"
@ MSG_SEC_STRTAB_BCKT	" bucket[%d]:"
@ MSG_SEC_STRTAB_MSTR	"   [%lld] %s  <master>"
@ MSG_SEC_STRTAB_SUFSTR	"   [%lld] %s  <suffix of: %s>"

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

@ MSG_USD_LDLIBPATH	" search path=%s  unused: LD_LIBRARY_PATH entry"
@ MSG_DUP_LDLIBPATH	" search path=%s  unused: (duplicate) LD_LIBRARY_PATH \
			 entry"
@ MSG_USD_LDLIBPATHC	" search path=%s  unused: configuration \
			 LD_LIBRARY_PATH entry - %s"
@ MSG_DUP_LDLIBPATHC	" search path=%s  unused: (duplicate) configuration \
			 LD_LIBRARY_PATH entry - %s"
@ MSG_USD_RUNPATH	" search path=%s  unused: RUNPATH/RPATH from file %s"

# Segment messages

@ MSG_SEG_DESC_INUSE	"Program Header / Segment Descriptor List (in use)"
@ MSG_SEG_DESC_AVAIL	"Program Header / Segment Descriptor List (available)"


# Support messages

@ MSG_SUP_REQ		"support object request=%s  (%s)"
@ MSG_SUP_REQ_ENV	"supplied via SGS_SUPPORT"
@ MSG_SUP_REQ_CMD	"supplied via -S"

@ MSG_SUP_ROUTINE	"  support object=%s:  provides routine %s"

@ MSG_SUP_CALLING_1	"  calling routine=%s (%s)"
@ MSG_SUP_CALLING_2	"  calling routine=%s (%s)  %s=%s"
@ MSG_SUP_VNONE		"  unloading object=%s: version=LD_SUP_VNONE"
@ MSG_SUP_OUTFILE	"output file"
@ MSG_SUP_INFILE	"input file"
@ MSG_SUP_INSEC		"input section"
@ MSG_SUP_SEC		"section"

# Symbol strings
@ MSG_SYM_AR_FILE	"symbol table processing; input file=%s  [ archive ] %s"
@ MSG_SYM_AR_SKIP	"file=%s, symbol=%s, skipped"
@ MSG_SYM_AR_CHECK	"file=%s(%s), symbol=%s, checking for tentative or \
			 restricted visibility override"
@ MSG_SYM_AR_RESOLVE	"file=%s(%s), symbol=%s, resolves undefined or \
			 tentative symbol"
@ MSG_SYM_AR_FORCE	"file=%s(%s), forced extraction"

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
@ MSG_SYM_CAPABILITIES	"symbol table processing; adding local capabilities \
			 symbols"

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
@ MSG_SYM_DISCARD_SEC	"symbol=%s;  discarded: originates from unused or \
			 discarded section=%s from file=%s"
@ MSG_SYM_DISCARD_FILE	"symbol=%s;  discarded: originates from unused or \
			 discarded file=%s"
@ MSG_SYM_DISCARD_DUP	"symbol[%d]=%s;  discarded duplicate: originates from \
			 file=%s"
@ MSG_SYM_WRAP		"symbol[%d]=%s  renamed to %s (-z wrap)"
@ MSG_SYM_CAP_ORIG	"symbol[%d]=%s  converting to symbol capability \
			 (-z symbolcap)"
@ MSG_SYM_CAP_LOCAL	"symbol[%d]=%s  creating local capability \
			 (-z symbolcap)"
@ MSG_SYM_COPY_DST	"symbol=%s;  copy destination: alignment: 0x%x"
@ MSG_SYM_COPY_REF	"symbol=%s;  copy reference"

@ MSG_SYM_AOUT		"symbol=%s;  (original AOUT name)"
@ MSG_SYM_LOOKUP	"symbol=%s;  lookup in file=%s  [ %s ]"

@ MSG_DLSYM_1		"symbol=%s;  dlsym() called from file=%s %s %s"
@ MSG_DLSYM_2		"symbol=%s;  dlsym() called from file=%s; starting \
			 at file=%s %s %s"

@ MSG_CAP_SYM_DEFAULT	"  symbol=%s[%u]:  capability family default"
@ MSG_CAP_SYM_USED	"  symbol=%s[%u]:  used"
@ MSG_CAP_SYM_CANDIDATE	"  symbol=%s[%u]:  capability candidate"
@ MSG_CAP_SYM_REJECTED	"  symbol=%s[%u]:  capability rejected"
@ MSG_CAP_SYM_HW_1	"  symbol=%s[%u]:  capability specific \
			 (CA_SUNW_HW_1):  [ %s ]"
@ MSG_CAP_SYM_SF_1	"  symbol=%s[%u]:  capability specific \
			 (CA_SUNW_SF_1):  [ %s ]"
@ MSG_CAP_SYM_MACH	"  symbol=%s[%u]:  capability specific \
			 (CA_SUNW_MACH):  [ %s ]"
@ MSG_CAP_SYM_PLAT	"  symbol=%s[%u]:  capability specific \
			 (CA_SUNW_PLAT):  [ %s ]"
@ MSG_CAP_SYM_HW_2	"  symbol=%s[%u]:  capability specific \
			 (CA_SUNW_HW_2):  [ %s ]"

@ MSG_SYM_LAZY_RESCAN	"rescanning for lazy dependencies for symbol: %s"

@ MSG_SYM_DUPSORTADDR	"section %s: symbol '%s' and symbol '%s' have the \
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
@ MSG_ORD_HDR_1		" number of SHN_BEGIN=%u, ordered=%u, default=%u, \
			 SHN_AFTER=%u"
@ MSG_ORD_TITLE_1	" %s=SHN_BEGIN: section=%s from %s"
@ MSG_ORD_TITLE_2	" %s=SHN_AFTER: section=%s from %s"
@ MSG_ORD_TITLE_3	" sort key=%u: section=%s from %s, %s=%s"

@ MSG_ORD_ERR_TITLE	"the SHF_ORDERED section %s from %s has \
			 an error;  flag ignored"

@ MSG_ORD_ERR_INFORANGE	" the sh_info field is out of range"
@ MSG_ORD_ERR_ORDER	" the section pointed by sh_info is an ordered section"
@ MSG_ORD_ERR_LINKRANGE	" the sh_link field is out of range"
@ MSG_ORD_ERR_FLAGS	" the sh_flag is incorrect"
@ MSG_ORD_ERR_CYCLIC	" the sh_link is cyclic"
@ MSG_ORD_ERR_LINKINV	" a section pointed to by sh_link has an error"

# Link-Auditing Messages

@ MSG_AUD_LIB		"auditor %s: required by: %s  %s"
@ MSG_AUD_INTERFACE	"auditor %s: provides interface: %s"

@ MSG_AUD_VERSION	"auditor %s: la_version(): %d: returned %d"
@ MSG_AUD_ACTIVITY	"auditor %s: la_activity(): %s  %s"
@ MSG_AUD_PREINIT	"auditor %s: la_preinit(): %s"
@ MSG_AUD_OBJFILTER	"auditor %s: la_objfilter(): %s: filtee=%s  [ %s ]"
@ MSG_AUD_OBJFILTER_R	"auditor %s: la_objfilter(): %s: returned 0  (filtee \
			 ignored)"
@ MSG_AUD_OBJOPEN	"auditor %s: la_objopen(): %s"
@ MSG_AUD_OBJOPEN_R	"auditor %s: la_objopen(): %s: returned %s"
@ MSG_AUD_OBJOPEN_RI	"auditor %s: la_objopen(): %s: returned %s  (flags \
			 ignored)"
@ MSG_AUD_OBJSEARCH	"auditor %s: la_objsearch(): %s  %s"
@ MSG_AUD_OBJSEARCH_R	"auditor %s: la_objsearch(): %s: alternative path \
			 returned: %s"
@ MSG_AUD_OBJSEARCH_S	"auditor %s: la_objsearch(): %s: alternative path \
			 returned: 0  (path skipped)"
@ MSG_AUD_OBJCLOSE	"auditor %s: la_objclose(): %s"
@ MSG_AUD_SYMBIND	"auditor %s: la_symbind(): %s: value: 0x%llx  %s"
@ MSG_AUD_SYMBIND_R	"auditor %s: la_symbind(): %s: returned value: \
			 0x%llx  %s"
@ MSG_AUD_PLTENTER	"auditor %s: la_pltenter(): %s: value: 0x%llx"
@ MSG_AUD_PLTENTER_R	"auditor %s: la_pltenter(): %s: returned value: 0x%llx"
@ MSG_AUD_PLTEXIT	"auditor %s: la_pltexit(): %s"

@ MSG_AUD_IGNORE	"file=%s;  global auditing request ignored: object \
			 did not initiate process" 
@ MSG_AUD_SKIP		"file=%s;  skipped: using auditor from %s"
@ MSG_AUD_TERM		"file=%s;  auditor has indicated path should be skipped"

# GOT Messages

@ MSG_GOT_INFO		"Global Offset Table information:  (%u entries)"

# TRANSLATION_NOTE
#	Do not translate .init or .fini, they represent reserved section names.

@ MSG_UTL_INIT		"calling .init (%s): %s"
@ MSG_UTL_FINI		"calling .fini: %s"
@ MSG_UTL_ARRAY		"calling %s[%d]:0x%llx: %s"
@ MSG_UTL_TRANS		"transferring control: %s"
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

@ MSG_UTL_DBNOTIFY	"notify debugger: event: %s state: %s"

@ MSG_UTL_SCC_TITLE	"  cycle detected - sorting cyclic dependencies in %s"
@ MSG_UTL_SCC_SUBI	"reverse load-order"
@ MSG_UTL_SCC_SUBF	"load-order"

@ MSG_UTL_LCINTERFACE	"file=%s;  provides interface [%s]: 0x%llx"

# Generic strings

@ MSG_STR_IGNORE	"ignored"
@ MSG_STR_ENTERED	"entered"
@ MSG_STR_ORIGINAL	"original"
@ MSG_STR_EXCLUDE	"exclude"
@ MSG_STR_RESET		"reset"
@ MSG_STR_IN		" in"
@ MSG_STR_OUT		"out"
@ MSG_STR_ACT		"act"
@ MSG_STR_CURRENT	"current"
@ MSG_STR_ADD		"add"
@ MSG_STR_OLD		"old"
@ MSG_STR_NEW		"new"
@ MSG_STR_NEW_IMPLICIT	"new (implicit)"
@ MSG_STR_RESOLVED	"resolved"
@ MSG_STR_ADDING	"adding"
@ MSG_STR_UP_1		"updating"
@ MSG_STR_UP_2		"updated"
@ MSG_STR_ALLOW		"allow"
@ MSG_STR_REQUIRE	"require"
@ MSG_STR_MOD_BEFORE	"modify (before)"
@ MSG_STR_MOD_AFTER	"modify (after)"

@ MSG_STR_UNKNOWN	"<unknown>"
@ MSG_STR_ORPHAN	"<orphan>"

@ MSG_STR_UNUSED	"(unused)"
@ MSG_STR_AGAIN		"(again)"
@ MSG_STR_NULL		"(null)"
@ MSG_STR_ALTER		"  (alternate)"
@ MSG_STR_COPYZERO	"  (copy zero's unnecessary)"
@ MSG_STR_TEMPORARY	"  (temporary)"
@ MSG_STR_RETRY		" (retry) "

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
@ MSG_STATS_REL_OUT	"  Relocations output: records=%lld"
@ MSG_STATS_REL_IN	"  Relocations  input: records=%-10lld applied=%lld"
@ MSG_STATS_REL_TICACHE	"  Relocation Cache"
@ MSG_STATS_REL_TIACT	"Active"
@ MSG_STATS_REL_TIOUT	"Output"
@ MSG_STATS_REL_CACHE	"      %s: buffers=%d, used=%lld/%lld (%d%%), \
			 size=%lld%s"
@ MSG_STATS_REL_ACACHE	"      Aux:    buffers=%d, used=%lld/%lld (%d%%), \
			 size=%lld%s"

# Capabilities messages

@ MSG_CAP_SYS_HW_1	"hardware capabilities (CA_SUNW_HW_1) - %s"
@ MSG_CAP_SYS_SF_1	"software capabilities (CA_SUNW_SF_1) - %s"
@ MSG_CAP_SYS_MACH	"machine capability (CA_SUNW_MACH) - %s"
@ MSG_CAP_SYS_PLAT	"platform capability (CA_SUNW_PLAT) - %s"
@ MSG_CAP_SYS_HW_2	"hardware capabilities (CA_SUNW_HW_2) - %s"

@ MSG_CAP_ALT_HW_1	"alternative hardware capabilities (CA_SUNW_HW_1) - %s"
@ MSG_CAP_ALT_SF_1	"alternative software capabilities (CA_SUNW_SF_1) - %s"
@ MSG_CAP_ALT_MACH	"alternative machine capability (CA_SUNW_MACH) - %s"
@ MSG_CAP_ALT_PLAT	"alternative platform capability (CA_SUNW_PLAT) - %s"
@ MSG_CAP_ALT_HW_2	"alternative hardware capabilities (CA_SUNW_HW_2) - %s"

@ MSG_CAP_SEC_TITLE	"capabilities; input file=%s"
@ MSG_CAP_SEC_ENTRY     "%12.12s  %-15.15s  %s"

@ MSG_CAP_CANDIDATE	"obj=%s;  capabilities candidate"
@ MSG_CAP_POST_TITLE	"capabilities post processing"

@ MSG_CAP_FILTER_1	"dir=%s;  capability directory filtered by %s"
@ MSG_CAP_FILTER_2	"dir=%s;  no capability objects found"

@ MSG_CAP_IDENTICAL	"obj=%s and obj=%s: have identical capabilities: both \
			 objects ignored"

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

@ MSG_SYMINFO_CAP	"<symbol capabilities>"
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
@ MSG_REL_LDSA_ENTRY_32	" %5s %-24s %#10llx %#10llx  %-14.14s %s  %s"
@ MSG_REL_LDSN_ENTRY_32	" %5s %-24s %#10llx             %-14.14s %s  %s"

@ MSG_REL_LDSV_TITLE_32	"         type                       \
			 offset      value  section        symbol"

# TRANSLATION_NOTE - the following strings are used by ld(1).  These strings
# provide for a series of one or more 32-bit relocation table entries, using
# long section names, that align with one of the initial titles.

@ MSG_REL_LDLA_TITLE_32	"         type                       \
			 offset     addend  section / symbol"
@ MSG_REL_LDLN_TITLE_32	"         type                       \
			 offset             section / symbol"
@ MSG_REL_LDLA_ENTRY_32	" %5s %-24s %#10llx %#10llx  %-14s %s  %s"
@ MSG_REL_LDLN_ENTRY_32	" %5s %-24s %#10llx             %-14s %s  %s"

@ MSG_REL_LDLV_TITLE_32	"         type                       \
			 offset      value  section / symbol"

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
@ MSG_REL_LDSA_ENTRY_64	" %5s %-24s %#18llx %#18llx  %-14.14s %s  %s"
@ MSG_REL_LDSN_ENTRY_64	" %5s %-24s %#18llx                     %-14.14s %s  %s"

@ MSG_REL_LDSV_TITLE_64	"         type                               \
			 offset              value  section        symbol"

# TRANSLATION_NOTE - the following strings are used by ld(1).  These strings
# provide for a series of one or more 64-bit relocation table entries, using
# long section names, that align with one of the initial titles.

@ MSG_REL_LDLA_TITLE_64	"         type                               \
			 offset             addend  section / symbol"
@ MSG_REL_LDLN_TITLE_64	"         type                               \
			 offset                     section / symbol"
@ MSG_REL_LDLA_ENTRY_64	" %5s %-24s %#18llx %#18llx  %-14s %s  %s"
@ MSG_REL_LDLN_ENTRY_64	" %5s %-24s %#18llx                     %-14s %s  %s"

@ MSG_REL_LDLV_TITLE_64	"         type                               \
			 offset              value  section / symbol"

# dl*() family messages

@ MSG_DL_IPHDR_ENTER	"dl_iterate_phdr() called from file=%s"
@ MSG_DL_IPHDR_MAPCNG	"dl_iterate_phdr() object map/unmap in callback"
@ MSG_DL_IPHDR_UNMAP	"dl_iterate_phdr() early return due to object unmap"
@ MSG_DL_IPHDR_CALLBACK	"dl_iterate_phdr() callback"
@ MSG_DL_IPHDR_NAME	"    dlpi_name:    %s"
@ MSG_DL_IPHDR_MAPCNT	"    dlpi_adds:    %-18llu   dlpi_subs:   %-18llu"

@ MSG_DL_IPHDR_ADDR_32	"    dlpi_addr:    %#-10llx"
@ MSG_DL_IPHDR_PHDR_32	"    dlpi_phdr:    %#-10llx  dlpi_phnum:  %u"

@ MSG_DL_IPHDR_ADDR_64	"    dlpi_addr:    %#-18llx"
@ MSG_DL_IPHDR_PHDR_64	"    dlpi_phdr:    %#-18llx   dlpi_phnum:  %u"

@ MSG_DL_DLCLOSE	"file=%s;  dlclose() called from file=%s  %s"
@ MSG_DL_DLDUMP		"file=%s;  dldump() called from file=%s: dumping to \
			 file=%s  %s"
@ MSG_DL_DLOPEN		"file=%s;  dlopen() called from file=%s %s %s"

@ MSG_DL_DLADDR		"dladdr() called from file=%s: %#llx"
@ MSG_DL_DLERROR	"dlerror() called from file=%s: %s"
@ MSG_DL_DLINFO		"dlinfo() called from file=%s: handle=%s, request=%s, \
			 user data=%#llx"

@ _END_

# Debug enabling tokens (for now these are untranslated)

@ MSG_TOK_ALL		"all"
@ MSG_TOK_ARGS		"args"
@ MSG_TOK_BINDINGS	"bindings"
@ MSG_TOK_DL		"dl"
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
@ MSG_TOK_TTIME		"ttime"
@ MSG_TOK_DTIME		"dtime"

@ MSG_TOK_OUTFILE	"output"

@ MSG_TOK_LMID_ALL	"ALL"
@ MSG_TOK_LMID_ALT	"ALT"
@ MSG_TOK_LMID_BASE	"BASE"
@ MSG_TOK_LMID_LDSO	"LDSO"


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_STR_EMPTY		""
@ MSG_STR_DELIMIT	",:"
@ MSG_STR_COMDAT	"COMDAT "

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

@ MSG_ECR_NAME		"  ec_name:       %s"
@ MSG_ECR_FLAGS		"  ec_flags:      %s"
@ MSG_ECR_IS_NAME	"  ec_is_name:    %-8s  ec_attrmask:  %s"
@ MSG_ECR_SEGMENT	"  ec_segment:    %-8s  ec_attrbits:  %s"
@ MSG_ECR_NDX		"  ec_ordndx:     %-8d  ec_type:      %s"
@ MSG_ECR_FILES		"  ec_files:"
@ MSG_ECR_FILE		"    %-21s  %s"

@ MSG_MAP_SORT_SEG	"    %s"
@ MSG_MAP_SORT_SEG_NAME	"    %-20s  %s"
@ MSG_MAP_SORT_SEG_V	"    %-20s  %-20s  p_vaddr=0x%llx"
@ MSG_MAP_SORT_SEG_O	"    %-20s  %-20s  order=%d"

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

@ MSG_SEG_DESC		"segment[%d]"
@ MSG_SEG_NAME		"    sg_name:      %s"
@ MSG_SEG_LENGTH	"    sg_length:    %#llx"
@ MSG_SEG_ROUND		"    sg_round:     %#llx"
@ MSG_SEG_ALIGN		"    sg_align:     %#llx"
@ MSG_SEG_FLAGS		"    sg_flags:     %s"
@ MSG_SEG_SIZESYM_TITLE	"    sg_sizesym:"
@ MSG_SEG_SIZESYM	"        %s"
@ MSG_SEG_IS_ORDER_TITLE "    sg_is_order:"
@ MSG_SEG_OS_ORDER_TITLE "    sg_os_order:"
@ MSG_SEG_LIST_ITEM	"        %s"

# Section messages (used when expanding segment information)

@ MSG_SEC_NAME		"  section[%d] os_name:  %s"

# Symbol strings

@ MSG_SYM_GLOBAL	"global"
@ MSG_SYM_LOCAL		"local"
@ MSG_SYM_COPY		"copy"

@ MSG_DLSYM_NEXT	"[ RTLD_NEXT ]"
@ MSG_DLSYM_DEFAULT	"[ RTLD_DEFAULT ]"
@ MSG_DLSYM_SELF	"[ RTLD_SELF ]"
@ MSG_DLSYM_PROBE	"[ RTLD_PROBE ]"
@ MSG_DLSYM_SINGLETON	"( singleton reference )"

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

@ MSG_GOT_INDEX		" [%d]"
@ MSG_GOT_SMALL_PIC	"pic"
@ MSG_GOT_BIG_PIC	"PIC"

@ MSG_CNTL_ENTRY	"   [0x%llx]  %s"

@ MSG_STR_NL		"\n"
@ MSG_STR_LDVER		"Solaris Linkers: %s"

@ MSG_FMT_INDEX		" [%d]"
@ MSG_FMT_ISEC_NAME	"[%u]%s"
@ MSG_FMT_MEMUNIT	" (%lld%c)"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"

@ MSG_ELF_MAGIC		"  ei_magic:   { 0x%x, %c, %c, %c }"
@ MSG_ELF_CLASS		"  ei_class:   %-18s  ei_data:       %s"
@ MSG_ELF_OSABI		"  ei_osabi:   %-18s  ei_abiversion: %s"
@ MSG_ELF_MACHINE	"  e_machine:  %-18s  e_version:     %s"
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
@ MSG_CI_CRITICAL	"CRITICAL"

# TLS information flags

@ MSG_TLS_FLAG_STATIC	"STATIC-TLS"

# mmapobj() mr_flags.

@ MSG_MR_PADDING	"[ PADDING ]"
@ MSG_MR_HDR_ELF	"[ HDR_ELF ]"
@ MSG_MR_HDR_AOUT	"[ HDR_AOUT ]"

# audit originator

@ MSG_AUD_PRELOAD	"[ LD_AUDIT ]"
@ MSG_AUD_GLOBAL	"[ GLOBAL AUDIT ]"
