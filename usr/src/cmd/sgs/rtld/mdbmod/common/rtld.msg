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
# Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
#

@ _START_

@ _END_

#
# Misc. Strings
#
@ MSG_STR_NAME		"NAME"
@ MSG_STR_PATHNAME	"PATHNAME"
@ MSG_STR_REFNAME	"REFNAME"
@ MSG_STR_RPATH		"RPATH"
@ MSG_STR_DASHES	"----------------------------------------------\n"
@ MSG_STR_LDSO1		"ld.so.1"
@ MSG_STR_DYNLMLIST	"dynlm_list"
@ MSG_STR_ALIST		"Alist"
@ MSG_STR_APLIST	"APlist"
@ MSG_STR_EMPTY		""
@ MSG_STR_ORPHANED	"<orphaned>"
@ MSG_STR_SETENV	"setenv"

#
# mdb_dcmd_t.dc_usage's
#
@ MSG_USG_ADDREQ	":"			# Address required
@ MSG_USG_ADDREQ_V	":[-v]"			# Address required plus -v
@ MSG_USG_ADDOPT_V	"?[-v]"			# Address optional plus -v
@ MSG_USG_SETENV	"name[=value]"		# Setenv argument

#
# mdb_walker.walk_descr's
#
@ MSG_WWD_RTMAP		"Walk a List of Rt_maps"

#
# Flag Strings
#
@ MSG_FLG_ISMAIN	"IS-MAIN"
@ MSG_FLG_IMGALLOC	"IMAGE-ALLOCATED"
@ MSG_FLG_RELOCED	"RELOCED"
@ MSG_FLG_SETGROUP	"SET-GROUP"
@ MSG_FLG_CAP		"CAP"
@ MSG_FLG_OBJECT	"OBJECT"
@ MSG_FLG_NEWLOAD	"NEWLOAD"
@ MSG_FLG_NODUMP	"NODUMP"
@ MSG_FLG_DELETE	"DELETE"
@ MSG_FLG_ANALYZED	"ANALYZED"
@ MSG_FLG_INITDONE	"INIT-DONE"
@ MSG_FLG_TRANS		"TRANS"
@ MSG_FLG_FIXED		"FIXED"
@ MSG_FLG_PRELOAD	"PRELOAD"
@ MSG_FLG_ALTER		"ALTERNATE"
@ MSG_FLG_LOADFLTR	"LOAD-FILTERS"
@ MSG_FLG_AUDIT		"AUDIT"
@ MSG_FLG_MODESET	"MODE-SET"
@ MSG_FLG_ANALZING	"ANALYZING"
@ MSG_FLG_INITFRST	"INIT-FIRST"
@ MSG_FLG_NOOPEN	"NO-OPEN"
@ MSG_FLG_FINICLCT	"FINI-COLLECTED"
@ MSG_FLG_INITCALL	"INIT-CALLED"
@ MSG_FLG_OBJINTPO	"OBJECT-INTERPOSE"
@ MSG_FLG_SYMINTPO	"SYMBOL-INTERPOSE"
@ MSG_FLG_MOVE		"MOVE"
@ MSG_FLG_RELOCING	"RELOCATING"
@ MSG_FLG_REGSYMS	"REGISTER-SYMS"
@ MSG_FLG_INITCLCT	"INIT-COLLECTED"
@ MSG_FLG_PUBHDL	"PUBLIC-HANDLE"
@ MSG_FLG_PRIHDL	"PRIVATE-HANDLE"

@ MSG_FL1_COPYTOOK	"COPYTOOK"
@ MSG_FL1_ALTCHECK	"ALT-CAP-CHECKED"
@ MSG_FL1_ALTCAP	"ALT-CAP-REQUIRED"
@ MSG_FL1_CONFSET	"CONFSET"
@ MSG_FL1_NODEFLIB	"NO-DEFAULT-LIBPATH"
@ MSG_FL1_ENDFILTE	"END-FILTEE"
@ MSG_FL1_DISPREL	"DISPLACEMENT-RELOCATED"
@ MSG_FL1_DTFLAGS	"DTFLAGS-AVAILABLE"
@ MSG_FL1_LDDSTUB	"LDDSTUB"
@ MSG_FL1_NOINIFIN	"NO-INITFINI"
@ MSG_FL1_USED		"USED"
@ MSG_FL1_SYMBOLIC	"SYMBOLIC"
@ MSG_FL1_OBJSFLTR	"OBJ-STD-FILTER"
@ MSG_FL1_OBJAFLTR	"OBJ-AUX-FILTER"
@ MSG_FL1_SYMSFLTR	"SYM-STD-FILTER"
@ MSG_FL1_SYMAFLTR	"SYM-AUX-FILTER"
@ MSG_FL1_TLSADD	"TLS-ADD"
@ MSG_FL1_TLSSTAT	"TLS-STAT"
@ MSG_FL1_DIRECT	"DIRECT"
@ MSG_FL1_GLOBAUD	"GLOBAL-AUDITING"
@ MSG_FL1_DEPAUD	"DT-DEPAUDIT"

@ MSG_MODE_LAZY		"LAZY"
@ MSG_MODE_NOW		"NOW"
@ MSG_MODE_NOLOAD	"NOLOAD"
@ MSG_MODE_GLOBAL	"GLOBAL"
@ MSG_MODE_PARENT	"PARENT"
@ MSG_MODE_GROUP	"GROUP"
@ MSG_MODE_WORLD	"WORLD"
@ MSG_MODE_NODELETE	"NODELETE"
@ MSG_MODE_FIRST	"FIRST"
@ MSG_MODE_CONFGEN	"CONFGEN"

@ MSG_BFL_NEEDED	"NEEDED"
@ MSG_BFL_REFER		"REFERENCED"
@ MSG_BFL_FILTER	"FILTER"

@ MSG_GPH_PUBLIC	"PUBLIC-HANDLE"
@ MSG_GPH_PRIVATE	"PRIVATE-HANDLE"
@ MSG_GPH_ZERO		"ZERO"
@ MSG_GPH_LDSO		"LD.SO.1"
@ MSG_GPH_FIRST		"FIRST-ONLY"
@ MSG_GPH_FILTEE	"FILTEE"
@ MSG_GPH_INITIAL	"INITIALIZED"

@ MSG_GPD_DLSYM		"AVAIL-TO-DLSYM"
@ MSG_GPD_RELOC		"AVAIL-FOR-RELOCATION"
@ MSG_GPD_ADDEPS	"ADD-DEPENDENCIES"
@ MSG_GPD_PARENT	"PARENT"
@ MSG_GPD_FILTER	"FILTER"
@ MSG_GPD_REMOVE	"REMOVAL-CANDIDATE"

@ MSG_LFL_BASELM		"BASELM"
@ MSG_LFL_RTLDLM		"RTLDLM"
@ MSG_LFL_PLTREL		"DEFERRED-PLT-RELOCATION"
@ MSG_LFL_HOLDLOCK		"HOLD-LOCK"
@ MSG_LFL_ENVIRON		"ENVIRON"
@ MSG_LFL_INTRPOSE		"INTERPOSE"
@ MSG_LFL_LOCAUDIT		"LOCAL-AUDIT"
@ MSG_LFL_LOADAVAIL		"LOAD-AVAILABLE"
@ MSG_LFL_IGNRELERR		"IGNORE-RELOCATION-ERROR"
@ MSG_LFL_STARTREL		"START-RELOCATION"
@ MSG_LFL_ATEXIT		"ATEXIT"
@ MSG_LFL_OBJADDED		"OBJECT-ADDED"
@ MSG_LFL_OBJDELETED		"OBJECT-DELETED"
@ MSG_LFL_OBJREEVAL		"OBJECT-REEVALUATE"
@ MSG_LFL_INTRPOSETSORT		"INTERPOSE-TSORTING-DONE"
@ MSG_LFL_AUDITNOTIFY		"AUDIT-CONSISTENT-REQUIRED"
@ MSG_LFL_GROUPSEXIST		"LOCAL-GROUPS-EXIST"

@ MSG_LFL_TRC_LDDSTUB		"LDDSTUB"
@ MSG_LFL_TRC_ENABLE		"TRACING-ENABLED"
@ MSG_LFL_TRC_WARN		"TRACE-WARNINGS"
@ MSG_LFL_TRC_VERBOSE		"TRACE-VERBOSE"
@ MSG_LFL_TRC_SEARCH		"TRACE-SEARCH"
@ MSG_LFL_TRC_UNREF		"TRACE-UNREFERENCED"
@ MSG_LFL_TRC_UNUSED		"TRACE-UNUSED"
@ MSG_LFL_TRC_INIT		"TRACE-INIT"
@ MSG_LFL_TRC_NOUNRESWEAK	"TRACE-NO-UNRESOLVED-WEAKS"
@ MSG_LFL_TRC_NOPAREXT		"TRACE-NO-PARENT-OR-EXTERN"

@ MSG_LTFL_NOLAZYLD		"NO-LAZY-LOADING"
@ MSG_LTFL_NODIRECT		"NO-DIRECT"
@ MSG_LTFL_NOAUDIT		"NO-AUDIT"
@ MSG_LTFL_LOADFLTR		"LOAD-FILTER"

@ MSG_LTFL_AUD_PREINIT		"AUD_PREINIT"
@ MSG_LTFL_AUD_OBJSEARCH	"AUD_OBJSEARCH"
@ MSG_LTFL_AUD_OBJOPEN		"AUD_OBJOPEN"
@ MSG_LTFL_AUD_OBJFILTER	"AUD_OBJFILTER"
@ MSG_LTFL_AUD_OBJCLOSE		"AUD_OBJCLOSE"
@ MSG_LTFL_AUD_SYMBIND		"AUD_SYMBIND"
@ MSG_LTFL_AUD_PLTENTER		"AUD_PLTENTER"
@ MSG_LTFL_AUD_PLTEXIT		"AUD_PLTEXIT"
@ MSG_LTFL_AUD_ACTIVITY		"AUD_ACTIVITY"

@ MSG_LMC_ANALYZING		"ANALYZING"
@ MSG_LMC_RELOCATING		"RELOCATING"
@ MSG_LMC_REANALYZE		"REANALYZE"

#
# Error messages
#
@ MSG_ERR_NAS		"%s:: no address specified\n"
@ MSG_ERR_READ		"%s:: failed to read from: 0x%p\n"	
@ MSG_ERR_SYMFAILED	"rtmaps:: lookup of %s`%s failed\n"

#
# Various generic format strings
#
@ MSG_FMT_RT		"[0x%x]\t0x%0?p 0x%0?p %s\n"

#
# Elf header messages.
#
@ MSG_EHDR_STR		"ElfEhdr"

@ MSG_EHDR_DCD		"Display Elf_Ehdr entry"

@ MSG_EHDR_TITLE	"Elf Header located at: 0x%p\n"
@ MSG_EHDR_LINE1	" ei_magic:    { 0x%x, %c, %c, %c }\n"
@ MSG_EHDR_LINE2	" ei_class:    %-18s  ei_data:     %s\n"
@ MSG_EHDR_LINE3	" e_machine:   %-18s  e_version:   %s\n"
@ MSG_EHDR_LINE4	" e_type:      %s\n"
@ MSG_EHDR_LINE5	" e_flags:     %s\n"
@ MSG_EHDR_LINE6	" e_flags:     %18s\n"
@ MSG_EHDR_LINE7	" e_entry:     %#18lx  e_ehsize:     %2d  \
			  e_shstrndx:   %2d\n"
@ MSG_EHDR_LINE8	" e_shoff:     %#18lx  e_shentsize:  %2d  \
			  e_shnum:      %2d\n"
@ MSG_EHDR_LINE9	" e_phoff:     %#18lx  e_phentsize:  %2d  \
			  e_phnum:      %2d\n"

@ MSG_EHDR_HELP		"\
   Decode an ELF Header (Elf_Ehdr) structure.\n\
   \n\
   Example:\n\n\
   \t> 0x10000::ElfEhdr \n\
   \tElf Header located at: 0x10000\n\
   \t ei_magic:    { 0x7f, E, L, F }\n\
   \t ei_class:    ELFCLASS32          ei_data:     ELFDATA2MSB\n\
   \t e_machine:   EM_SPARC            e_version:   EV_CURRENT\n\
   \t e_type:      ET_EXEC\n\
   \t e_flags:                      0\n\
   \t e_entry:                0x10640  e_ehsize:     52  e_shstrndx:   27\n\
   \t e_shoff:                 0x1390  e_shentsize:  40  e_shnum:      29\n\
   \t e_phoff:                   0x34  e_phentsize:  32  e_phnum:       5\n"

#
# Elf Program Header messages.
#

@ MSG_EPHDR_STR		"ElfPhdr"

@ MSG_EPHDR_DCD		"Display Elf_Phdr entry"

@ MSG_EPHDR_TITLE	"Program Header located at: 0x%p\n"
@ MSG_EPHDR_LINE1	"    p_vaddr:      %#-14lx  p_flags:    %s\n"
@ MSG_EPHDR_LINE2	"    p_paddr:      %#-14lx  p_type:     %s\n"
@ MSG_EPHDR_LINE3	"    p_filesz:     %#-14lx  p_memsz:    %#lx\n"
@ MSG_EPHDR_LINE4	"    p_offset:     %#-14lx  p_align:    %#lx\n"

@ MSG_EPHDR_HELP	"\
   Decode an ELF Program Header (Elf_Phdr) structure.\n\
   \n\
   Example 1 - a single entry:\n\n\
   \t> 0x10000+0x34::ElfPhdr\n\
   \tProgram Header located at: 0x10034\n\
   \t    p_vaddr:      0x10034         p_flags:    [ PF_X  PF_R ]\n\
   \t    p_paddr:      0               p_type:     [ PT_PHDR ]\n\
   \t    p_filesz:     0xa0            p_memsz:    0xa0\n\
   \t    p_offset:     0x34            p_align:    0\n\
   \n\
   Example 2 - multiple entries:\n\n\
   \t> 0x10034,2::ElfPhdr\n\
   \tProgram Header located at: 0x10034\n\
   \t    p_vaddr:      0x10034         p_flags:    [ PF_X  PF_R ]\n\
   \t    p_paddr:      0               p_type:     [ PT_PHDR ]\n\
   \t    p_filesz:     0xa0            p_memsz:    0xa0\n\
   \t    p_offset:     0x34            p_align:    0\n\
   \tProgram Header located at: 0x10054\n\
   \t    p_vaddr:      0               p_flags:    [ PF_R ]\n\
   \t    p_paddr:      0               p_type:     [ PT_INTERP ]\n\
   \t    p_filesz:     0x11            p_memsz:    0\n\
   \t    p_offset:     0xd4            p_align:    0\n"


#
# Elf_Dyn messages.
#

@ MSG_ELFDYN_STR	"ElfDyn"

@ MSG_ELFDYN_DCD	"Display Elf_Dyn entry"

@ MSG_ELFDYN_TITLE	"Elf_Dyn located at: 0x%p\n"
@ MSG_ELFDYN_LINE1	"    %a  %s\t  0x%0?p\n"

@ MSG_ELFDYN_HELP	"\
   Decode an ELF dynamic section (Elf_Dyn) entry.\n\
   \n\
   Example 1 - a single entry:\n\n\
   \t> 0xff33a478::ElfDyn\n\
   \tElf_Dyn located at: 0xff33a478\n\
   \t    0xff33a478  NEEDED  0x00004013\n\
   \n\
   Example 2 - multiple entries:\n\n\
   \t> 0xff33a478,4::ElfDyn\n\
   \tElf_Dyn located at: 0xff33a478\n\
   \t    0xff33a478  NEEDED  0x00004013\n\
   \tElf_Dyn located at: 0xff33a480\n\
   \t    0xff33a480  INIT    0x0009b484\n\
   \tElf_Dyn located at: 0xff33a488\n\
   \t    0xff33a488  FINI    0x0009b4dc\n\
   \tElf_Dyn located at: 0xff33a490\n\
   \t    0xff33a490  SONAME  0x00004009\n"


#
# Lm_list messages.
#

@ MSG_LMLIST_STR	"Lm_list"

@ MSG_LMLIST_DCD	"Display Lm_list structure"

@ MSG_LMLIST_BASE	"(LM_ID_BASE)"
@ MSG_LMLIST_LDSO	"(LM_ID_LDSO)"
@ MSG_LMLIST_NEWLM	"(LM_ID_NEWLM)"

@ MSG_LMLIST_TITLE0	"Link-map lists (%s): 0x0\n";
@ MSG_LMLIST_TITLE1	"Link-map lists (%s): 0x%p Alist[used %u: total %u]\n";
@ MSG_LMLIST_TITLE2	"Lm_list: 0x%p  %s\n"

@ MSG_LMLIST_LINE0	"   lists: 0x%0?p Alist[used %u: total %u]\n"

@ MSG_LMC_LINE1		"Lm_cntl: 0x%p\n"
@ MSG_LMC_LINE2		"   head: 0x%0?p\t      tail: 0x%0?p\n"
@ MSG_LMC_LINE3		"  flags: 0x%08x\t       now: 0x%0?p\n"
@ MSG_LMC_LINE4		"         [ %#b ]\n"

@ MSG_LMLIST_LINE1	"    head: 0x%0?p\t      tail: 0x%0?p\n"
@ MSG_LMLIST_LINE2	"   audit: 0x%0?p\t  rtldinfo: 0x%0?p\n"
@ MSG_LMLIST_LINE3	"  handle: 0x%0?p\t       obj: %4d  init: %4d  \
			 lazy: %4d\n"
@ MSG_LMLIST_LINE4	"   flags: 0x%08x\n"
@ MSG_LMLIST_LINE5	"  tflags: 0x%08x\n"
@ MSG_LMLIST_LINE6	"          [ %#b ]\n"

@ MSG_LMLIST_HELP	"\
   Display a link-map list header.  If no address is specified, the \
   dynlm_list\nmaster link-map list is searched and all link-map headers \
   displayed.\n\
   \n\
   A link-map list header points to a family of link-map control lists, \
   together\nwith other state information. The initial control list represents \
   those\nobjects that have been completely analyzed and relocated, and are \
   presently in\nuse.  \
   Additional control lists may exist as families of objects are processed\nin \
   preparation for joining the main control list.  These families are created\n\
   from events such as dlopen(3c), lazy loading, and filtee processing, once\n\
   the initial process that started the application has been relocated.\n\
   \n\
   The -v option walks all link-map control lists displaying each member.\n\
   \n\
   Example 1 - a single, verbose entry, starting from a specified address:\n\n\
   \n\
   \t> 0xff3ee0f0::Lm_list -v\n\
   \tLm_list: 0xff3ee0f0  (LM_ID_BASE)\n\
   \t----------------------------------------------\n\
   \t   lists: 0xff3f0b00 Alist[used 1: total 4]\n\
   \t  ----------------------------------------------\n\
   \t    Lm_cntl: 0xff3f0b0c\n\
   \t       head: 0xff3f0fdc      tail: 0xff3f13bc\n\
   \t      flags: 0x00000000       now: 0x00000000\n\
   \t             [ 0 ]\n\
   \t    ----------------------------------------------\n\
   \t    lmco        rtmap       ADDR()     NAME()\n\
   \t    ----------------------------------------------\n\
   \t    [0xc]       0xff3f0fdc 0x00010000 main\n\
   \t    [0xc]       0xff3f13bc 0xff280000 /lib/libc.so.1\n\
   \t    ----------------------------------------------\n\
   \t    head: 0xff3f0f84        tail: 0xff3f1794\n\
   \t   audit: 0x00000000     preexec: 0xff3f1794\n\
   \t  handle: 0x00000000         obj:    3  init:    0  lazy:    0\n\
   \t   flags: 0x00008041\n\
   \t          [ BASELM,ENVIRON,STARTREL ]\n\
   \t  tflags: 0x00000000\n\
   \n\
   Example 2 - all link-map headers:\n\n\
   \t> ::Lm_list\n\
   \tLink-map lists (dynlm_list): 0xffbfdbf8\n\
   \t----------------------------------------------\n\
   \t  Lm_list: 0xff3ee0f0  (LM_ID_BASE)\n\
   \t  ----------------------------------------------\n\
   \t     lists: 0xff3f0b68 Alist[used 1: total 4]\n\
   \t    ----------------------------------------------\n\
   \t      head: 0xff3f0f84        tail: 0xff3f1794\n\
   \t     audit: 0x00000000     preexec: 0xff3f1794\n\
   \t    handle: 0x00000000         obj:    3  init:    0  lazy:    0\n\
   \t     flags: 0x00008041\n\
   \t            [ BASELM,ENVIRON,STARTREL ]\n\
   \t    tflags: 0x00000000\n\
   \t  ----------------------------------------------\n\
   \t  Lm_list: 0xff3ee134  (LM_ID_LDSO)\n\
   \t  ----------------------------------------------\n\
   \t     lists: 0xff3f0ba4 Alist[used 1: total 4]\n\
   \t    ----------------------------------------------\n\
   \t      head: 0xff3f0c20        tail: 0xff3f0c20\n\
   \t     audit: 0x00000000     preexec: 0x00000000\n\
   \t    handle: 0x00000000         obj:    0  init:    0  lazy:    0\n\
   \t     flags: 0x00000006\n\
   \t            [ RTLDLM,NOAUDIT ]\n\
   \t    tflags: 0x00000000\n"

#
# Rt_maps messages.
#

@ MSG_RTMAPS_STR	"Rt_maps"

@ MSG_RTMAPS_DCD	"Display list of Rt_map structures"

@ MSG_RTMAPS_TITLE0	"lmco \trtmap       ADDR()     NAME()\n"

@ MSG_RTMAPS_HELP "\
   Walk a list of Rt_map's starting with a specified Rt_map entry.  If no\n\
   address is specified, the dynlm_list master Rt_map list is searched and\n\
   all objects listed.\n\
   \n\
   The -v option expands each Rt_map in detail.  See Rt_map.\n\
   \n\
   Example 1 - a single entry, starting from a specified address:\n\n\
   \t> 0xff3b0214::Rt_maps\n\
   \tlmco    rtmap      ADDR()     NAME()\n\
   \t---------------------------------------------\n\
   \t[0xc]   0xff3b0214 0x00010000 prog\n\
   \t[0xc]   0xff3b065c 0xff3a0000 /lib/libdl.so.1\n\
   \t[0xc]   0xff3b0a04 0xff280000 /lib/libc.so.1\n\
   \n\
   Example 2 - all Rt_map entries:\n\n\
   \t> ::Rt_maps\n\
   \tLink-map lists (dynlm_list): 0xffbfe080\n\
   \t---------------------------------------------\n\
   \t  Lm_list: 0xff3f60c8  (LM_ID_BASE)\n\
   \t  ---------------------------------------------\n\
   \t    lmco    rtmap      ADDR()     NAME()\n\
   \t    ---------------------------------------------\n\
   \t    [0xc]   0xff3b0214 0x00010000 prog\n\
   \t    [0xc]   0xff3b065c 0xff3a0000 /lib/libdl.so.1\n\
   \t    [0xc]   0xff3b0a04 0xff280000 /lib/libc.so.1\n\
   \t  ---------------------------------------------\n\
   \t  Lm_list: 0xff3f60e8  (LM_ID_LDSO)\n\
   \t  ---------------------------------------------\n\
   \t    lmco    rtmap      ADDR()     NAME()\n\
   \t    ---------------------------------------------\n\
   \t    [0xc]   0xff3f7cc0 0xff3c0000 /lib/ld.so.1\n"
 

#
# Rt_map messages.
#

@ MSG_RTMAP_STR		"Rt_map"

@ MSG_RTMAP_DCD		"Display Rt_map structure"

@ MSG_RTMAP_TITLE	"Rt_map located at: 0x%0?p\n"
@ MSG_RTMAP_LINE1	"     NAME: %s\n"
@ MSG_RTMAP_LINE2	" PATHNAME: %s\n"
@ MSG_RTMAP_LINE3	"     ADDR: 0x%0?p\t      DYN: 0x%0?p\n"
@ MSG_RTMAP_LINE4	"     NEXT: 0x%0?p\t     PREV: 0x%0?p\n"
@ MSG_RTMAP_LINE5	"      FCT: 0x%0?p\t TLSMODID:   %?ld\n"
@ MSG_RTMAP_LINE6	"     INIT: 0x%0?p\t     FINI: 0x%0?p\n"
@ MSG_RTMAP_LINE7	"   GROUPS: 0x%0?p\t  HANDLES: 0x%0?p\n"
@ MSG_RTMAP_LINE8	"  DEPENDS: 0x%0?p\t  CALLERS: 0x%0?p\n"
@ MSG_RTMAP_LINE9	"  DYNINFO: 0x%0?p\t  REFNAME: %s\n"
@ MSG_RTMAP_LINE10	"    RLIST: 0x%0?p\t    RPATH: %s\n"
@ MSG_RTMAP_LINE11	"     LIST: 0x%0?p [%a]\n"
@ MSG_RTMAP_LINE12	"    FLAGS: 0x%08x\n"
@ MSG_RTMAP_LINE13	"   FLAGS1: 0x%08x\n"
@ MSG_RTMAP_LINE14	"   AFLAGS: 0x%08x\n"
@ MSG_RTMAP_LINE15	"     MODE: 0x%08x\n"
@ MSG_RTMAP_LINE20	"           [ %#b ]\n"

@ MSG_RTMAP_HELP "\
   Display the contents of selected fields of an Rt_map structure.\n\
   \n\
   Example:\n\n\
   \t0xff3b0214::Rt_map\n\
   \tRt_map located at: 0xff3b0214\n\
   \t      NAME: prog\n\
   \t  PATHNAME: /home/developer/bin/prog\n\
   \t      ADDR: 0x00010000         DYN: 0x00020b1\n\
   \t      NEXT: 0xff3b065c        PREV: 0x0000000\n\
   \t       FCT: 0xff3f6080    TLSMODID:         0\n\
   \t      INIT: 0x00010960        FINI: 0x000109b\n\
   \t      .....\n"

#
# Bind messages.
#

@ MSG_BND_STR		"Bind"

@ MSG_BND_DCD		"Display a Binding Descriptor"

@ MSG_BND_TITLE		"Binding descriptor located at: 0x%0?p\n"
@ MSG_BND_LINE1		"   caller: 0x%0?p    %s\n"
@ MSG_BND_LINE2		"   depend: 0x%0?p    %s\n"
@ MSG_BND_LINE3		"    flags: 0x%08x    [ %#b ]\n"

@ MSG_BND_HELP		"\
   Decode the binding descriptor specified by addr.\n\
   \n\
   Relationships between Rt_map objects are maintained by a binding dis-\n\
   cripter.  The descriptor contains a pointer to the Rt_map of the caller,\n\
   a pointer to the Rt_map of the dependency, and a flags field indicating\n\
   the relationship between the two Rt_map objects.\n\
   \n\
   The -v option expands each Rt_map.\n\
   \n\
   Example:\n\n\
   \t> 0xff3b0410::Bind\n\
   \tBinding Descriptor located at: 0xff3b0410\n\
   \t   caller: 0xff3b0030    main\n\
   \t   depend: 0xff3b0460    /lib/libelf.so.1\n\
   \t    flags: 0x00000001    [ NEEDED ]\n"


#
# Depends messages.
#

@ MSG_DEPENDS_STR	"Depends"

@ MSG_DEPENDS_DCD	"Display Rt_map DEPENDS binding descriptors"

@ MSG_DEPENDS_LINE1	"DEPENDS for %s\n"
@ MSG_DEPENDS_LINE2	"  Depends: 0x%0?p APlist[used %u: total %u]\n"

@ MSG_DEPENDS_HELP	"\
   Display the binding descriptor list of DEPENDS() of the Rt_map\n\
   specified by addr.  A DEPENDS() entry consists of an APlist\n\
   defining each dependency.\n\
   \n\
   The -v option walks the APlist descriptor displaying each dependency.\n\
   \n\
   Example:\n\n\
   \t> 0xff3b0554::Depends -v\n\
   \tDEPENDS for /lib/libc.so.1\n\
   \t----------------------------------------------\n\
   \t  Depends: 0xff3b0bc4 APlist[used 2: total 4]\n\
   \t    ----------------------------------------------\n\
   \t    Binding descriptor located at: 0xff3b08f8\n\
   \t       caller: 0xff3b0554    /lib/libc.so.1\n\
   \t       depend: 0xff3b0938    /lib/libdl.so.1\n\
   \t        flags: 0x00000003    [ NEEDED,REFERENCED ]\n\
   \t    ----------------------------------------------\n\
   \t    Binding descriptor located at: 0xff3b07a8\n\
   \t       caller: 0xff3b0554    /lib/libc.so.1\n\
   \t       depend: 0xff3f7cc0    /lib/ld.so.1\n\
   \t        flags: 0x00000002    [ REFERENCED ]\n"

#
# Callers messages.
#

@ MSG_CALLERS_STR	"Callers"

@ MSG_CALLERS_DCD	"Display Rt_map CALLERS binding descriptors"

@ MSG_CALLERS_LINE1	"CALLERS for %s\n"
@ MSG_CALLERS_LINE2	"  Callers: 0x%0?p APlist[used %u: total %u]\n"

@ MSG_CALLERS_HELP	"\
   Display the binding descriptor list of CALLERS() of the Rt_map\n\
   specified by addr.  A CALLERS() entry consists of an APlist\n\
   defining each caller.\n\
   \n\
   The -v option walks the APlist descriptor displaying each caller.\n\
   \n\
   Example:\n\n\
   \t> 0xff3b0554::Callers -v\n\
   \tCALLERS for /lib/libc.so.1\n\
   \t----------------------------------------------\n\
   \t  Callers: 0xff3b08cc APlist[used 1: total 4]\n\
   \t    ----------------------------------------------\n\
   \t    Binding descriptor located at: 0xff3b0514\n\
   \t       caller: 0xff3b0214    a.out\n\
   \t       depend: 0xff3b0554    /lib/libc.so.1\n\
   \t        flags: 0x00000003    [ NEEDED,REFERENCED ]\n"


#
# Handle messages.
#

@ MSG_HANDLES_STR	"Handles"

@ MSG_HANDLES_DCD	"Display Rt_map HANDLES group descriptors"

@ MSG_HANDLES_LINE1	"HANDLES for %s\n"
@ MSG_HANDLES_LINE2	"  HANDLE: 0x%0?p APlist[used %u: total %u]\n"

@ MSG_HANDLES_HELP	"\
   Display the list of HANDLES() that the Rt_map, specified by addr, is the\n\
   owner of.  A HANDLES() entry consists of an APlist of Grp_hdl descriptors.\n\
   See GrpHdl.  Each Grp_hdl() consists of an APlist of Grp_desc descriptors\n\
   that define each caller.  See GrpDesc.\n\
   \n\
   The -v option walks all APlists displaying each member of the handle.\n\
   \n\
   Example:\n\n\
   \t> 0xff3b0f6c::Handles -v\n\
   \tHANDLES for ./sub.so\n\
   \t----------------------------------------------\n\
   \t  HANDLE: 0xff3b1310 APlist[used 1: total 1]\n\
   \t    ----------------------------------------------\n\
   \t    Group Handle located at: 0xff3b1270\n\
   \t    ----------------------------------------------\n\
   \t       owner:               ./sub.so\n\
   \t       flags: 0x00000000    [ 0 ]\n\
   \t      refcnt:          1    depends: 0xff3b12c8 Alist[used 3: total 4]\n\
   \t       ----------------------------------------------\n\
   \t       Group Descriptor located at: 0xff3b12d4\n\
   \t          depend: 0xff3b0f6c    ./sub.so\n\
   \t           flags: 0x00000003    [ AVAIL-TO-DLSYM,ADD-DEPENDENCIES ]\n\
   \t       ----------------------------------------------\n\
   \t       Group Descriptor located at: 0xff3b12dc\n\
   \t          depend: 0xff3b0a04    /lib/libc.so.1\n\
   \t           flags: 0x00000003    [ AVAIL-TO-DLSYM,ADD-DEPENDENCIES ]\n\
   \t       ----------------------------------------------\n\
   \t       Group Descriptor located at: 0xff3b12e4\n\
   \t          depend: 0xff3b065c    /lib/libdl.so.1\n\
   \t           flags: 0x00000003    [ AVAIL-TO-DLSYM,ADD-DEPENDENCIES ]\n"

#
# Group messages.
#

@ MSG_GROUPS_STR	"Groups"

@ MSG_GROUPS_DCD	"Display Rt_map GROUPS group handles"

@ MSG_GROUPS_LINE1	"GROUPS for %s\n"
@ MSG_GROUPS_LINE2	"  Groups: 0x%0?p APlist[used %u: total %u]\n"

@ MSG_GROUPS_HELP	"\
   Display the list of GROUPS() that the Rt_map, specified by addr, is a \
   member\nof.  A GROUPS() entry consists of an APlist of Grp_hdl entries.  \
   See GrpHdl.\n\
   \n\
   The -v option walks the APlist descriptor displaying each member of the\n\
   handle.\n\
   \n\
   Example:\n\n\
   \t> 0xff3b0f6c::Groups -v\n\
   \tGROUPS for ./sub.so\n\
   \t----------------------------------------------\n\
   \t  Groups: 0xff3b12a8 APlist[used 1: total 1]\n\
   \t    ----------------------------------------------\n\
   \t    Group Handle located at: 0xff3b1270\n\
   \t    ----------------------------------------------\n\
   \t        owner:               ./sub.so\n\
   \t        flags: 0x00000000    [ 0 ]\n\
   \t       refcnt:          1    depends: 0xff3b12c8 Alist[used 3: total 4]\n\
   \t        ----------------------------------------------\n\
   \t        Group Descriptor located at: 0xff3b12d4\n\
   \t           depend: 0xff3b0f6c    ./sub.so\n\
   \t            flags: 0x00000003    [ AVAIL-TO-DLSYM,ADD-DEPENDENCIES ]\n\
   \t        ----------------------------------------------\n\
   \t        Group Descriptor located at: 0xff3b12dc\n\
   \t           depend: 0xff3b0a04    /lib/libc.so.1\n\
   \t            flags: 0x00000004    [ AVAIL-TO-DLSYM,ADD-DEPENDENCIES ]\n\
   \t        ----------------------------------------------\n\
   \t        Group Descriptor located at: 0xff3b12e4\n\
   \t           depend: 0xff3b065c    /lib/libdl.so.1\n\
   \t            flags: 0x00000004    [ AVAIL-TO-DLSYM,ADD-DEPENDENCIES ]\n"


#
# Group handle and group descriptor messages.
#

@ MSG_GRPHDL_STR	"GrpHdl"

@ MSG_GRPHDL_DCD	"Display a Group Handle"

@ MSG_GRPHDL_LINE1	"Group Handle located at: 0x%0?p\n"
@ MSG_GRPHDL_LINE2	"    owner:               %s\n"
@ MSG_GRPHDL_LINE3	"    flags: 0x%08x    [ %#b ]\n"
@ MSG_GRPHDL_LINE4	"   refcnt:   %8d    depends: 0\n"
@ MSG_GRPHDL_LINE5	"   refcnt:   %8d    depends: 0x%0?p \
			 Alist[used %u: total %u]\n"

@ MSG_GRPHDL_HELP	"\
   Decode a group handle.  A successful dlopen() of an object returns a\n\
   handle applicable for subsequent dlsym() requests.  The handle maintains\n\
   a reference count, flags and a table of group descriptors that define the\n\
   dependencies associated with this group of objects.\n\
   \n\
   The -v option expands each group descriptor.\n\
   \n\
   Example:\n\n\
   \t> 0xff3a0c58::GrpHdl\n\
   \tGroup Handle located at: 0xff3a0c58\n\
   \t----------------------------------------------\n\
   \t   refcnt:          1    main\n\
   \t    flags: 0x00000001    [ DLOPEN-ZERO ]\n\
   \t  depends: 0xff3a0c89 Alist[next 1: cnt 2]\n"



@ MSG_GRPDESC_STR	"GrpDesc"

@ MSG_GRPDESC_DCD	"Display a Group Descriptor"

@ MSG_GRPDESC_LINE1	"Group Descriptor located at: 0x%0?p\n"
@ MSG_GRPDESC_LINE2	"   depend: 0x%0?p    %s\n"
@ MSG_GRPDESC_LINE3	"    flags: 0x%08x    [ %#b ]\n"

@ MSG_GRPDESC_HELP	"\
   Decode a group descriptor.  A GrpHdl created by dlopen() maintains a\n\
   list of group descriptors for each dependency.  See GrpHdl.\n\
   \n\
   Example\n\n\
   \t> 0xff3b12d4::GrpDesc -v\n\
   \tGroup Descriptor located at: 0xff3b12d4\n\
   \t   depend: 0xff3b0f6c    ./sub.so\n\
   \t    flags: 0x00000003    [ AVAIL-TO-DLSYM,ADD-DEPENDENCIES ]\n"


@ MSG_BNDDESC_STR	"BndDesc"

#
# General purpose environment addition.
#

@ MSG_SETENV_STR	"Setenv"

@ MSG_SETENV_DCD	"Set an environment variable"

@ MSG_SETENV_HELP	"\
   Set the associated environment variable.  This can be useful to establish\n\
   runtime linker environment variables without affecting the debugger itself.\n\
   \n\
   Note, newer versions of mdb(1) provide setenv.  The mdb(1) implementation\n\
   provides the ability to make environment changes at any point during\n\
   application monitoring.  Where available, Setenv calls through to setenv.\n\
   On older environments, Setenv only provides for changing the applications\n\
   environment before it is invoked.\n\
   \n\
   Example\n\n\
   \t> ::Setenv LD_DEBUG=files\n"
