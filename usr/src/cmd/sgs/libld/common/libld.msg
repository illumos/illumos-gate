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
#

#
# Copyright (c) 2012, Joyent, Inc.  All rights reserved.
#

@ _START_

# Message file for cmd/sgs/libld.

@ MSG_ID_LIBLD

#
# TRANSLATION_NOTE -- Beginning of USAGE message
# 	The following messages are the usage messages for the ld command.
#	Tab characters (\t) are used to align the messages.
#
#	Each usage message starts with \t, and if the message has more than one
#		line, the following messages are aligned by 3 tab characters.
#		When you see \n\t\t\t, the first \n is used to change the line,
#		and following 3 tab characters are used to align the line.
#
#	Each usage message option is surrounded by [ and ].  Then the
#	description of the option follows. The descriptions should be aligned,
#	so tab characters are padded as needed after the closing bracket ].
#
#	How to align the messages are up to the translators and the
#	localization engineers.
#
#	In C locale, the first 3 messages would look like the following:
#
#	usage: ld [-6:abc:.....] file(s)
#        	[-a]            create an absolute file
#        	[-b]            do not do special PIC relocations in a.out
#        	[-c file]       record configuration 'file'
#
@ MSG_ARG_USAGE		"usage: ld [-%s] file(s)\n"
@ MSG_ARG_DETAIL_3	"\t[-32]\t\tenforce a 32-bit link-edit\n"
@ MSG_ARG_DETAIL_6	"\t[-64]\t\tenforce a 64-bit link-edit\n"
@ MSG_ARG_DETAIL_A	"\t[-a]\t\tcreate an absolute file\n"
@ MSG_ARG_DETAIL_B	"\t[-b]\t\tdo not do special PIC relocations in a.out\n"
@ MSG_ARG_DETAIL_CBDR	"\t[-B direct | nodirect]\n\
			 \t\t\testablish direct bindings, or inhibit direct \
			 binding\n\
			 \t\t\tto, the object being created\n"
@ MSG_ARG_DETAIL_CBDY	"\t[-B dynamic | static]\n\
			 \t\t\tsearch for shared libraries|archives\n"
@ MSG_ARG_DETAIL_CBE	"\t[-B eliminate]\teliminate unqualified global \
			 symbols from the\n\t\t\tsymbol table\n"
@ MSG_ARG_DETAIL_CBG	"\t[-B group]\trelocate object from within group\n"
@ MSG_ARG_DETAIL_CBL	"\t[-B local]\treduce unqualified global symbols to \
			 local\n"
@ MSG_ARG_DETAIL_CBR	"\t[-B reduce]\tprocess symbol reductions\n"
@ MSG_ARG_DETAIL_CBS	"\t[-B symbolic]\tbind external references to \
			 definitions when creating\n\
			 \t\t\tshared objects\n"
@ MSG_ARG_DETAIL_C	"\t[-c name]\trecord configuration file 'name'\n"
@ MSG_ARG_DETAIL_CC	"\t[-C]\t\tdemangle C++ symbol name diagnostics\n"
@ MSG_ARG_DETAIL_D	"\t[-d y | n]\toperate in dynamic|static mode\n"
@ MSG_ARG_DETAIL_CD	"\t[-D token,...]\tprint diagnostic messages\n"
@ MSG_ARG_DETAIL_E	"\t[-e epsym], [--entry epsym]\n\
			 \t\t\tuse 'epsym' as entry point address\n"
@ MSG_ARG_DETAIL_F	"\t[-f name], [--auxiliary name]\n\
			 \t\t\tspecify library for which this file is an \
			 auxiliary\n\t\t\tfilter\n"
@ MSG_ARG_DETAIL_CF	"\t[-F name], [--filter name]\n\
			 \t\t\tspecify library for which this file is a filter\n"
@ MSG_ARG_DETAIL_CG	"\t[-G], [-shared]\n\
			 \t\t\tcreate a shared object\n"
@ MSG_ARG_DETAIL_H	"\t[-h name], [--soname name]\n\
			 \t\t\tuse 'name' as internal shared object identifier\n"
@ MSG_ARG_DETAIL_I	"\t[-i]\t\tignore LD_LIBRARY_PATH setting\n"
@ MSG_ARG_DETAIL_CI	"\t[-I name]\tuse 'name' as path of interpreter\n"
@ MSG_ARG_DETAIL_L	"\t[-l x], [--library x]\n\
			 \t\t\tsearch for libx.so or libx.a\n"
@ MSG_ARG_DETAIL_CL	"\t[-L path], [--library-path path]\n\
			 \t\t\tsearch for libraries in directory 'path'\n"
@ MSG_ARG_DETAIL_M	"\t[-m]\t\tprint memory map\n"
@ MSG_ARG_DETAIL_CM	"\t[-M mapfile]\tuse processing directives contained \
			 in 'mapfile'\n"
@ MSG_ARG_DETAIL_CN	"\t[-N string]\tcreate a dynamic dependency for \
			 'string'\n"
@ MSG_ARG_DETAIL_O	"\t[-o outfile], [--output outfile]\n\
			 \t\t\tname the output file 'outfile'\n"
@ MSG_ARG_DETAIL_P	"\t[-p auditlib]\tidentify audit library to accompany \
			 this object\n"
@ MSG_ARG_DETAIL_CP	"\t[-P auditlib]\tidentify audit library for \
			 processing the dependencies\n\
			 \t\t\tof this object\n"
@ MSG_ARG_DETAIL_CQ	"\t[-Q y | n]\tdo|do not place version information in \
			 output file\n"
@ MSG_ARG_DETAIL_R	"\t[-r], [--relocatable]\n\
			 \t\t\tcreate a relocatable object\n"
@ MSG_ARG_DETAIL_CR	"\t[-R path], [-rpath path]\n\
			 \t\t\tspecify a library search path to be used at run \
			 time\n"
@ MSG_ARG_DETAIL_S	"\t[-s], [--strip-all]\n\
			 \t\t\tstrip any symbol and debugging information\n"
@ MSG_ARG_DETAIL_CS	"\t[-S supportlib]\n\
			 \t\t\tspecify a link-edit support library\n"
@ MSG_ARG_DETAIL_T	"\t[-t]\t\tdo not warn of multiply-defined symbols \
			 that have\n\t\t\tdifferent sizes or alignments\n"
@ MSG_ARG_DETAIL_U	"\t[-u symname], [--undefined symname]\n\
			 \t\t\tcreate an undefined symbol 'symname'\n"
@ MSG_ARG_DETAIL_CV	"\t[-V], [--version]\n\
			 \t\t\tprint version information\n"
@ MSG_ARG_DETAIL_CY	"\t[-Y P,dirlist]\tuse 'dirlist' as a default path \
			 when searching for\n\
			 \t\t\tlibraries\n"
@ MSG_ARG_DETAIL_ZA	"\t[-z absexec]\twhen building an executable absolute \
			 symbols\n \
			 \t\t\treferenced in dynamic objects are promoted to\n \
			 \t\t\tthe executable\n"
@ MSG_ARG_DETAIL_ZAE	"\t[-z allextract | defaultextract | weakextract],\n\
			 \t[--whole-archive | --no-whole-archive]\n\
			 \t\t\textract all member files, only members that \
			 resolve\n\
			 \t\t\tundefined or tentative symbols, or \
			 allow extraction of\n\
			 \t\t\tarchive members to resolve weak references from \
			 \n\t\t\t\archive files\n"
@ MSG_ARG_DETAIL_ZAL	"\t[-z altexec64]\texecute the 64-bit link-editor\n"
@ MSG_ARG_DETAIL_ZADLIB	"\t[-z assert-deflib]\n\
			\t\t\tenables warnings for linking with libraries in \
			the \n\t\t\tdefault search path\n\
			\t[-z assert-deflib=libname]\n\
			\t\t\tenables warnings for linking with libraries in \
			the \n\t\t\tdefault search path, but 'libname' is exempt\n"
@ MSG_ARG_DETAIL_ZC	"\t[-z combreloc | nocombreloc]\n\
			 \t\t\tcombine|do not combine multiple relocation \
			 sections\n"
@ MSG_ARG_DETAIL_ZNC	"\t[-z nocompstrtab]\n\t\t\tdisable compression of \
			 string tables\n"
@ MSG_ARG_DETAIL_ZDEF	"\t[-z deferred | nodeferred]\n\
			 \t\t\tenable|disable deferred identification of \
			 shared object\n\t\t\tdependencies\n"
@ MSG_ARG_DETAIL_ZDFS	"\t[-z defs], [--no-undefined]\n\
			 \t\t\tdisallow undefined symbol references\n"
@ MSG_ARG_DETAIL_ZDRS	"\t[-z direct | nodirect]\n\
			 \t\t\tenable|disable direct binding to shared object\n\
			 \t\t\tdependencies\n"
@ MSG_ARG_DETAIL_ZE	"\t[-z endfiltee]\tmarks a filtee such that it will \
			 terminate a filters\n\t\t\tsearch\n"
@ MSG_ARG_DETAIL_ZFATW	"\t[-z fatal-warnings | nofatal-warnings],\n\
			 \t[--fatal-warnings | --no-fatal-warnings]\n\
			 \t\tenable|disable treatment of warnings as fatal\n"
@ MSG_ARG_DETAIL_ZFA	"\t[-z finiarray=function]\n\
			 \t\t\tname of function to be appended to the \
			 .fini_array\n"
@ MSG_ARG_DETAIL_ZGP	"\t[-z groupperm | nogroupperm]\n\
			 \t\t\tenable|disable setting of group permissions\n\
			 \t\t\ton dynamic dependencies\n"
@ MSG_ARG_DETAIL_ZGUIDE	"\t[-z guidance | -z guidance=item1,item2,...]\n\
			 \t\t\tenable guidance warnings. items: \
			 noall, nodefs,\n\
			 \t\t\tnodirect, nolazyload, nomapfile, notext, \
			 nounused\n"
@ MSG_ARG_DETAIL_ZH	"\t[-z help], [--help]\n\
			 \t\t\tprint this usage message\n"
@ MSG_ARG_DETAIL_ZIG	"\t[-z ignore | record]\n\
			 \t\t\tignore|record unused dynamic dependencies\n"
@ MSG_ARG_DETAIL_ZINA	"\t[-z initarray=function]\n\
			 \t\t\tname of function to be appended to the \
			 .init_array\n"
@ MSG_ARG_DETAIL_ZINI	"\t[-z initfirst]\tmark object to indicate that its \
			 .init section should\n\
			 \t\t\tbe executed before the .init section of any \
			 other\n\t\t\tobjects\n"
@ MSG_ARG_DETAIL_ZINT	"\t[-z interpose]\
			 \tdynamic object is to be an 'interposer' on direct\n\
			 \t\t\tbindings\n"
@ MSG_ARG_DETAIL_ZLAZY	"\t[-z lazyload | nolazyload]\n\
			 \t\t\tenable|disable delayed loading of shared \
			 object\n\t\t\tdependencies\n"
@ MSG_ARG_DETAIL_ZLD32	"\t[-z ld32=arg1,arg2,...]\n\
			 \t\t\tdefine arguments applicable to the \
			 32-bit class of ld(1)\n"
@ MSG_ARG_DETAIL_ZLD64	"\t[-z ld64=arg1,arg2,...]\n\
			 \t\t\tdefine arguments applicable to the \
			 64-bit class of ld(1)\n"
@ MSG_ARG_DETAIL_ZLO	"\t[-z loadfltr]\tmark filter as requiring immediate \
			 loading of its\n\
			 \t\t\tfiltees at runtime\n"
@ MSG_ARG_DETAIL_ZM	"\t[-z muldefs], [--allow-multiple-definition]\n\
			 \t\t\tallow multiply-defined symbols\n"
@ MSG_ARG_DETAIL_ZNDFS	"\t[-z nodefs]\tallow undefined symbol references\n"
@ MSG_ARG_DETAIL_ZNDEF	"\t[-z nodefaultlib]\n\
			 \t\t\tmark object to ignore any default library \
			 search path\n"
@ MSG_ARG_DETAIL_ZNDEL	"\t[-z nodelete]\tmark object as non-deletable\n"
@ MSG_ARG_DETAIL_ZNDLO	"\t[-z nodlopen]\tmark object as non-dlopen()'able\n"
@ MSG_ARG_DETAIL_ZNDU	"\t[-z nodump]\tmark object as non-dldump()'able\n"
@ MSG_ARG_DETAIL_ZNLD	"\t[-z noldynsym]\tdo not add a .SUNW_ldynsym section\n"
@ MSG_ARG_DETAIL_ZNPA	"\t[-z nopartial]\texpand any partially initialized \
			 symbols\n"
@ MSG_ARG_DETAIL_ZNV	"\t[-z noversion]\tdo not record any version sections\n"
@ MSG_ARG_DETAIL_ZNOW	"\t[-z now]\tmark object as requiring non-lazy \
			 binding\n"
@ MSG_ARG_DETAIL_ZO	"\t[-z origin]\tmark object as requiring $ORIGIN \
			 processing\n"
@ MSG_ARG_DETAIL_ZPIA	"\t[-z preinitarray=function]\n\
			 \t\t\tname of function to be appended to the \
			 .preinit_array\n"
@ MSG_ARG_DETAIL_ZRL	"\t[-z redlocsym]\treduce local syms in .symtab to \
			 a minimum\n"
@ MSG_ARG_DETAIL_ZRREL	"\t[-z relaxreloc]\trelax rules used for relocations \
			 against COMDAT sections\n"
@ MSG_ARG_DETAIL_ZRS	"\t[-z rescan]\tafter processing all arguments, rescan \
			 archive list\n\
			 \t\t\tuntil no further member extraction occurs\n"
@ MSG_ARG_DETAIL_ZRSN	"\t[-z rescan-now]\timmediately rescan archive list \
			 until\n\
			 \t\t\tno further member extraction occurs\n"
@ MSG_ARG_DETAIL_ZRSGRP	"\t[-z rescan-start archives... -z rescan-end],\n\
			 \t[--start-group archives... --end-group], \
			 [-( archives... -)]\n\
			 \t\t\trescan specified archive group upon reaching\n\
			 \t\t\tthe end of the group, until no further\n\
			 \t\t\tmember extraction occurs\n"
@ MSG_ARG_DETAIL_ZSCAP	"\t[-z symbolcap]\tconvert object capabilities to \
			 symbol capabilities\n"
@ MSG_ARG_DETAIL_ZTARG	"\t[-z target=platform]\n\
			 \t\t\ttarget machine for cross linking\n"
@ MSG_ARG_DETAIL_ZT	"\t[-z text]\tdisallow output relocations against \
			 text\n"
@ MSG_ARG_DETAIL_ZTO	"\t[-z textoff]\tallow output relocations against \
			 text\n"
@ MSG_ARG_DETAIL_ZTW	"\t[-z textwarn]\twarn if there are relocations \
			 against text\n"
@ MSG_ARG_DETAIL_ZWRAP	"\t[-z wrap=symbol], [-wrap=symbol], [--wrap=symbol]\n\
			 \t\t\twrap symbol references\n"
@ MSG_ARG_DETAIL_ZVER	"\t[-z verbose]\t\
			 generate warnings for suspicious processings\n"

#
# TRANSLATION_NOTE -- End of USAGE message
#
@ MSG_GRP_INVALNDX	"file %s: group section [%u]%s: entry %d: \
			 invalid section index: %d"
@ MSG_GRP_INVALSYM	"file %s: group section [%u]%s: invalid group symbol %s"

# Relocation processing messages (some of these are required to satisfy
# do_reloc(), which is common code used by cmd/sgs/rtld - make sure both
# message files remain consistent).

@ MSG_REL_NOFIT		"relocation error: %s: file %s: symbol %s: \
			 value 0x%llx does not fit"
@ MSG_REL_NONALIGN	"relocation error: %s: file %s: symbol %s: \
			 offset 0x%llx is non-aligned"
@ MSG_REL_NULL		"relocation error: file %s: section [%u]%s: \
			 skipping null relocation record"
@ MSG_REL_NOTSUP	"relocation error: %s: file %s: section [%u]%s: \
			 relocation not currently supported"
@ MSG_REL_PICREDLOC	"relocation error: %s: file %s symbol %s: \
			 -z redlocsym may not be used for pic code"
@ MSG_REL_TLSLE		"relocation error: %s: file %s: symbol %s: \
			 relocation illegal when building a shared object"
@ MSG_REL_TLSBND	"relocation error: %s: file %s: symbol %s: \
			 bound to: %s: relocation illegal when not bound \
			 to object being created"
@ MSG_REL_TLSSTAT	"relocation error: %s: file %s: symbol %s: \
			 relocation illegal when building a static object"
@ MSG_REL_TLSBADSYM	"relocation error: %s: file %s: symbol %s: \
			 bad symbol type %s: symbol type must be TLS"
@ MSG_REL_BADTLS	"relocation error: %s: file %s: symbol %s: \
			 relocation illegal for TLS symbol"
@ MSG_REL_BADGOTBASED	"relocation error: %s: file %s: symbol %s: a GOT \
			 relative relocation must reference a local symbol"
@ MSG_REL_UNKNWSYM	"relocation error: %s: file %s: section [%u]%s: \
			 attempt to relocate with respect to unknown \
			 symbol %s: offset 0x%llx, symbol index %d"
@ MSG_REL_UNSUPSZ	"relocation error: %s: file %s: symbol %s: \
			 offset size (%d bytes) is not supported"
@ MSG_REL_INVALOFFSET	"relocation error: %s: file %s section [%u]%s: \
			 invalid offset symbol '%s': offset 0x%llx"
@ MSG_REL_INVALRELT	"relocation error: file %s: section [%u]%s: \
			 invalid relocation type: 0x%x"
@ MSG_REL_EMPTYSEC	"relocation error: %s: file %s: symbol %s: \
			 attempted against empty section [%u]%s"
@ MSG_REL_EXTERNSYM	"relocation error: %s: file %s: symbol %s: \
			 external symbolic relocation against non-allocatable \
			 section %s; cannot be processed at runtime: \
			 relocation ignored"
@ MSG_REL_UNEXPREL	"relocation error: %s: file %s: symbol %s: \
			 unexpected relocation; generic processing performed"
@ MSG_REL_UNEXPSYM	"relocation error: %s: file %s: symbol %s: \
			 unexpected symbol referenced from file %s"
@ MSG_REL_SYMDISC	"relocation error: %s: file %s: section [%u]%s: \
			 symbol %s: symbol has been discarded with discarded \
			 section: [%u]%s"
@ MSG_REL_NOSYMBOL	"relocation error: %s: file %s: section: [%u]%s: \
			 offset: 0x%llx: relocation requires reference symbol"
@ MSG_REL_DISPREL1	"relocation error: %s: file %s: symbol %s: \
			 displacement relocation applied to the symbol \
			 %s at 0x%llx: symbol %s is a copy relocated symbol"
@ MSG_REL_UNSUPSIZE	"relocation error: %s: file %s: section [%u]%s: \
			 relocation against section symbol unsupported"

@ MSG_REL_DISPREL2	"relocation warning: %s: file %s: symbol %s: \
			 may contain displacement relocation"
@ MSG_REL_DISPREL3	"relocation warning: %s: file %s: symbol %s: \
			 displacement relocation applied to the symbol \
			 %s: at 0x%llx: displacement relocation will not be \
			 visible in output image"
@ MSG_REL_DISPREL4	"relocation warning: %s: file %s: symbol %s: \
			 displacement relocation to be applied to the symbol \
			 %s: at 0x%llx: displacement relocation will be \
			 visible in output image"
@ MSG_REL_COPY		"relocation warning: %s: file %s: symbol %s: \
			 relocation bound to a symbol with STV_PROTECTED \
			 visibility"
@ MSG_RELINVSEC		"relocation warning: %s: file %s: section: [%u]%s: \
			 against suspicious section [%u]%s; relocation ignored"
@ MSG_REL_TLSIE		"relocation warning: %s: file %s: symbol %s: \
			 relocation has restricted use when building a shared \
			 object"

@ MSG_REL_SLOPCDATNONAM	"relocation warning: %s: file %s: section [%u]%s: \
			 relocation against discarded COMDAT section [%u]%s: \
			 redirected to file %s"
@ MSG_REL_SLOPCDATNAM	"relocation warning: %s: file %s: section [%u]%s: \
			 symbol %s: relocation against discarded COMDAT \
			 section [%u]%s: redirected to file %s"
@ MSG_REL_SLOPCDATNOSYM	"relocation warning: %s: file %s: section [%u]%s: \
			 symbol %s: relocation against discarded COMDAT \
			 section [%u]%s: symbol not found, relocation ignored"

@ MSG_REL_NOREG		"relocation error: REGISTER relocation not supported \
			 on target architecture"

#
# TRANSLATION_NOTE
# 	The following 7 messages are the message to print the
#	following example messages.
#
#Text relocation remains		      referenced
#    against symbol		    offset	in file
#str                                 0x14      	main.o
#printf                              0x1c      	main.o
#
#	The first two lines are the header, and the next msgid
#	is the format string for the header.
#	Tabs and spaces are used for alignment.
#	The first and third %s are for: "Text relocation remains against symbol"
#	The second %s and fourth %s are for: "referenced in file"
#	The third %s is for: "offset"
#
@ MSG_REL_REMAIN_FMT_1	"%-40s\t%s\n    %s\t\t    %s\t%s"
#
# TRANSLATION_NOTE
#	The next two msdid make a sentence. So translate:
#		"Text relocation remain against symbol"
#	And separate them into two msgstr considering the proper
#	alignment.
@ MSG_REL_RMN_ITM_11	"Text relocation remains"
@ MSG_REL_RMN_ITM_12	"against symbol"
@ MSG_REL_RMN_ITM_13	"warning: Text relocation remains"

@ MSG_REL_RMN_ITM_2	"offset"

#
# TRANSLATION_NOTE
#	The next two msdid make a sentence. So translate:
#		"referenced in file"
#	And separate them into two msgstr considering the proper
#	alignment.
@ MSG_REL_RMN_ITM_31	"referenced"
@ MSG_REL_RMN_ITM_32	"in file"
@ MSG_REL_REMAIN_2	"%-35s 0x%-8llx\t%s"
@ MSG_REL_REMAIN_3	"relocations remain against allocatable but \
			 non-writable sections"

# Files processing messages

@ MSG_FIL_MULINC_1	"file %s: attempted multiple inclusion of file"
@ MSG_FIL_MULINC_2	"file %s: linked to %s: attempted multiple inclusion \
			 of file"
@ MSG_FIL_SOINSTAT	"input of shared object '%s' in static mode"
@ MSG_FIL_INVALSEC	"file %s: section [%u]%s has invalid type %s"
@ MSG_FIL_NOTFOUND	"file %s: required by %s, not found"
@ MSG_FIL_MALSTR	"file %s: section [%u]%s: malformed string table, \
			 initial or final byte"
@ MSG_FIL_PTHTOLONG	"'%s/%s' pathname too long"
@ MSG_FIL_EXCLUDE	"file %s: section [%u]%s contains both SHF_EXCLUDE and \
			 SHF_ALLOC flags: SHF_EXCLUDE ignored"
@ MSG_FIL_INTERRUPT	"file %s: creation interrupted: %s"
@ MSG_FIL_INVRELOC1	"file %s: section [%u]%s: relocations can not be \
			 applied against section [%u]%s"
@ MSG_FIL_INVSHINFO	"file %s: section [%u]%s: has invalid sh_info: %lld"
@ MSG_FIL_INVSHLINK	"file %s: section [%u]%s: has invalid sh_link: %lld"
@ MSG_FIL_INVSHENTSIZE	"file %s: section [%u]%s: has invalid sh_entsize: %lld"
@ MSG_FIL_NOSTRTABLE	"file %s: section [%u]%s: symbol[%d]: specifies string \
			 table offset 0x%llx: no string table is available"
@ MSG_FIL_EXCSTRTABLE	"file %s: section [%u]%s: symbol[%d]: specifies string \
			 table offset 0x%llx: exceeds string table %s: \
			 size 0x%llx"
@ MSG_FIL_NONAMESYM	"file %s: section [%u]%s: symbol[%d]: global symbol has \
			 no name"
@ MSG_FIL_UNKCAP	"file %s: section [%u]%s: unknown capability tag: %d"
@ MSG_FIL_BADSF1	"file %s: section [%u]%s: unknown software \
			 capabilities: 0x%llx; ignored"
@ MSG_FIL_INADDR32SF1	"file %s: section [%u]%s: software capability ADDR32: is \
			 ineffective when building 32-bit object; ignored"
@ MSG_FIL_EXADDR32SF1	"file %s: section [%u]%s: software capability ADDR32: \
			 requires executable be built with ADDR32 capability"

@ MSG_FIL_BADORDREF	"file %s: section [%u]%s: contains illegal reference \
			 to discarded section: [%u]%s"

# Recording name conflicts

@ MSG_REC_OPTCNFLT	"recording name conflict: file '%s' and %s provide \
			 identical dependency names: %s"
@ MSG_REC_OBJCNFLT	"recording name conflict: file '%s' and file '%s' \
			 provide identical dependency names: %s  %s"
@ MSG_REC_CNFLTHINT	"(possible multiple inclusion of the same file)"

# System call messages

@ MSG_SYS_OPEN		"file %s: open failed: %s"
@ MSG_SYS_UNLINK	"file %s: unlink failed: %s"
@ MSG_SYS_MMAPANON	"mmap anon failed: %s"
@ MSG_SYS_MALLOC	"malloc failed: %s"


# Messages related to platform support

@ MSG_TARG_UNSUPPORTED	"unsupported ELF machine type: %s"


# ELF processing messages

@ MSG_ELF_LIBELF	"libelf: version not supported: %d"

@ MSG_ELF_ARMEM		"file %s: unable to locate archive member;\n\t\
			 offset=%x, symbol=%s"

@ MSG_ELF_ARSYM		"file %s ignored: unable to locate archive symbol table"

@ MSG_ELF_VERSYM	"file %s: version symbol section entry mismatch:\n\t\
			 (section [%u]%s entries=%d; section [%u]%s entries=%d)"

@ MSG_ELF_NOGROUPSECT	"file %s: section [%u]%s: SHF_GROUP flag set, but no \
			 corresponding SHT_GROUP section found"

# Section processing errors

@ MSG_SCN_NONALLOC	"%s: non-allocatable section '%s' directed to a \
			 loadable segment: %s"

@ MSG_SCN_MULTICOMDAT	"file %s: section [%u]%s: cannot be susceptible to multiple \
			 COMDAT mechanisms: %s"

@ MSG_SCN_DWFOVRFLW	"%s: section %s: encoded DWARF data exceeds \
			 section size"
@ MSG_SCN_DWFBADENC	"%s: section %s: invalid DWARF encoding: %#x"                         

# Symbol processing errors

@ MSG_SYM_NOSECDEF	"symbol '%s' in file %s has no section definition"
@ MSG_SYM_INVSEC	"symbol '%s' in file %s associated with invalid \
			 section[%lld]"
@ MSG_SYM_TLS		"symbol '%s' in file %s (STT_TLS), is defined \
			 in a non-SHF_TLS section"
@ MSG_SYM_BADADDR	"symbol '%s' in file %s: section [%u]%s: size %#llx: \
			 symbol (address %#llx, size %#llx) lies outside \
			 of containing section"
@ MSG_SYM_BADADDR_ROTXT	"symbol '%s' in file %s: readonly text section \
			 [%u]%s: size %#llx: symbol (address %#llx, \
			 size %#llx) lies outside of containing section"
@ MSG_SYM_MULDEF	"symbol '%s' is multiply-defined:"
@ MSG_SYM_CONFVIS	"symbol '%s' has conflicting visibilities:"
@ MSG_SYM_DIFFTYPE	"symbol '%s' has differing types:"
@ MSG_SYM_DIFFATTR	"symbol '%s' has differing %s:\n\
			 \t(file %s value=0x%llx; file %s value=0x%llx);"
@ MSG_SYM_FILETYPES	"\t(file %s type=%s; file %s type=%s);"
@ MSG_SYM_VISTYPES	"\t(file %s visibility=%s; file %s visibility=%s);"
@ MSG_SYM_DEFTAKEN	"\t%s definition taken"
@ MSG_SYM_DEFUPDATE	"\t%s definition taken and updated with larger size"
@ MSG_SYM_LARGER	"\tlargest value applied"
@ MSG_SYM_TENTERR	"\ttentative symbol cannot override defined symbol \
			 of smaller size"

@ MSG_SYM_INVSHNDX	"symbol %s has invalid section index; \
			 ignored:\n\t(file %s value=%s);"
@ MSG_SYM_NONGLOB	"global symbol %s has non-global binding:\n\
			 \t(file %s value=%s);"
@ MSG_SYM_RESERVE	"reserved symbol '%s' already defined in file %s"
@ MSG_SYM_NOTNULL	"undefined symbol '%s' with non-zero value encountered \
			 from file %s"
@ MSG_SYM_DUPSORTADDR	"section %s: symbol '%s' and symbol '%s' have the \
			 same address: %#llx: remove duplicate with \
			 NOSORTSYM mapfile directive"

@ MSG_PSYM_INVMINFO1	"file %s: section [%u]%s: entry[%d] has invalid m_info: \
			 0x%llx for symbol index"
@ MSG_PSYM_INVMINFO2	"file %s: section [%u]%s: entry[%d] has invalid m_info: \
			 0x%llx for size"
@ MSG_PSYM_INVMREPEAT	"file %s: section [%u]%s: entry[%d] has invalid m_repeat: \
			 0x%llx"
@ MSG_PSYM_CANNOTEXPND	"file %s: section [%u]%s: entry[%d] can not be expanded: \
			 associated symbol size is unknown %s"
@ MSG_PSYM_NOSTATIC	"and partial initialization cannot be deferred to \
			 a static object"
@ MSG_MOVE_OVERLAP	"file %s: section [%u]%s: symbol '%s' overlapping move \
			 initialization: start=0x%llx, length=0x%llx: \
			 start=0x%llx, length=0x%llx"
@ MSG_PSYM_EXPREASON1	"output file is static object"
@ MSG_PSYM_EXPREASON2	"-z nopartial option in effect"
@ MSG_PSYM_EXPREASON3	"move infrastructure size is greater than move data"

#
# Support library failures
#
@ MSG_SUP_NOLOAD	"dlopen() of support library (%s) failed with \
			 error: %s"
@ MSG_SUP_BADVERSION	"initialization of support library (%s) failed with \
			 bad version.  supported: %d returned: %d"


#
# TRANSLATION_NOTE
# 	The following 7 messages are the message to print the
#	following example messages.
#
#Undefined			first referenced
# symbol  			    in file
#inquire                            halt_hold.o
#
@ MSG_SYM_FMT_UNDEF	"%s\t\t\t%s\
			 \n %s  \t\t\t    %s"

#
# TRANSLATION_NOTE
#	The next two msdid make a sentence. So translate:
#		"Undefined symbol"
#	And separate them into two msgstr considering the proper
#	alignment.
@ MSG_SYM_UNDEF_ITM_11	"Undefined"
@ MSG_SYM_UNDEF_ITM_12	"symbol"
#
# TRANSLATION_NOTE
#	The next two msdid make a sentence. So translate:
#		"first referenced in file"
#	And separate them into two msgstr considering the proper
#	alignment.
@ MSG_SYM_UNDEF_ITM_21	"first referenced"
@ MSG_SYM_UNDEF_ITM_22	"in file"
#

@ MSG_SYM_UND_UNDEF	"%-35s %s"
@ MSG_SYM_UND_NOVER	"%-35s %s  (symbol has no version assigned)"
@ MSG_SYM_UND_IMPL	"%-35s %s  (symbol belongs to implicit dependency %s)"
@ MSG_SYM_UND_NOTA	"%-35s %s  (symbol belongs to unavailable version %s \
			 (%s))"
@ MSG_SYM_UND_BNDLOCAL	"%-35s %s  (symbol scope specifies local binding)"

@ MSG_SYM_ENTRY		"entry point"
@ MSG_SYM_UNDEF		"%s symbol '%s' is undefined"
@ MSG_SYM_EXTERN	"%s symbol '%s' is undefined  (symbol belongs to \
			 dependency %s)"
@ MSG_SYM_NOCRT		"symbol '%s' not found, but %s section exists - \
			 possible link-edit without using the compiler driver"

# Output file update messages

@ MSG_UPD_NOREADSEG	"No read-only segments found.  Setting '_etext' to 0"
@ MSG_UPD_NORDWRSEG	"No read-write segments found.  Setting '_edata' to 0"
@ MSG_UPD_NOSEG		"Setting 'end' and '_end' to 0"

@ MSG_UPD_SEGOVERLAP	"%s: segment address overlap;\n\
			 \tprevious segment ending at address 0x%llx overlaps\n\
			 \tuser defined segment '%s' starting at address 0x%llx"
@ MSG_UPD_LARGSIZE	"%s: segment %s calculated size 0x%llx\n\
			 \tis larger than user-defined size 0x%llx"

@ MSG_UPD_NOBITS	"NOBITS section found before end of initialized data"
@ MSG_SEG_FIRNOTLOAD	"First segment has type %s, PT_LOAD required: %s"
@ MSG_UPD_MULEHFRAME	"file %s; section [%u]%s and file %s; section [%u]%s \
			 have incompatibile attributes and cannot \
			 be merged into a single output section"


# Version processing messages

@ MSG_VER_HIGHER	"file %s: version revision %d is higher than \
			 expected %d"
@ MSG_VER_NOEXIST	"file %s: version '%s' does not exist:\n\
			 \trequired by file %s"
@ MSG_VER_UNDEF		"version '%s' undefined, referenced by version '%s':\n\
			 \trequired by file %s"
@ MSG_VER_UNAVAIL	"file %s: version '%s' is unavailable:\n\
			 \trequired by file %s"
@ MSG_VER_DEFINED	"version symbol '%s' already defined in file %s"
@ MSG_VER_INVALNDX	"version symbol '%s' from file %s has an invalid \
			 version index (%d)"
@ MSG_VER_ADDVERS	"unused $ADDVERS specification from file '%s' \
			 for object '%s'\nversion(s):"
@ MSG_VER_ADDVER	"\t%s"
@ MSG_VER_CYCLIC	"following versions generate cyclic dependency:"

# Capabilities messages

@ MSG_CAP_MULDEF	"capabilities symbol '%s' has multiply-defined members:"
@ MSG_CAP_MULDEFSYMS	"\t(file %s symbol '%s'; file %s symbol '%s');"
@ MSG_CAP_REDUNDANT	"file %s: section [%u]%s: symbol capabilities \
			 redundant, as object capabilities are more restrictive"
@ MSG_CAP_NOSYMSFOUND	"no global symbols have been found that are associated \
			 with capabilities identified relocatable objects: \
			 -z symbolcap has no effect"

@ MSG_CAPINFO_INVALSYM	"file %s: capabilities info section [%u]%s: index %d: \
			 family member symbol '%s': invalid"
@ MSG_CAPINFO_INVALLEAD	"file %s: capabilities info section [%u]%s: index %d: \
			 family lead symbol '%s': invalid symbol index %d"

# Basic strings

@ MSG_STR_ALIGNMENTS	"alignments"
@ MSG_STR_COMMAND	"(command line)"
@ MSG_STR_TLSREL	"(internal TLS relocation requirement)"
@ MSG_STR_SIZES		"sizes"
@ MSG_STR_UNKNOWN       "<unknown>"
@ MSG_STR_SECTION	"%s (section)"
@ MSG_STR_SECTION_MSTR	"%s (merged string section)"

#
# TRANSLATION_NOTE
#	The elf_ function name represents a man page reference and should not
#	be translated.
@ MSG_ELF_BEGIN		"file %s: elf_begin"
@ MSG_ELF_CNTL		"file %s: elf_cntl"
@ MSG_ELF_GETARHDR	"file %s: elf_getarhdr"
@ MSG_ELF_GETARSYM	"file %s: elf_getarsym"
@ MSG_ELF_GETDATA	"file %s: elf_getdata"
@ MSG_ELF_GETEHDR	"file %s: elf_getehdr"
@ MSG_ELF_GETPHDR	"file %s: elf_getphdr"
@ MSG_ELF_GETSCN	"file %s: elf_getscn: scnndx: %d"
@ MSG_ELF_GETSHDR	"file %s: elf_getshdr"
@ MSG_ELF_MEMORY	"file %s: elf_memory"
@ MSG_ELF_NDXSCN	"file %s: elf_ndxscn"
@ MSG_ELF_NEWDATA	"file %s: elf_newdata"
@ MSG_ELF_NEWEHDR	"file %s: elf_newehdr"
@ MSG_ELF_NEWSCN	"file %s: elf_newscn"
@ MSG_ELF_NEWPHDR	"file %s: elf_newphdr"
@ MSG_ELF_STRPTR	"file %s: elf_strptr"
@ MSG_ELF_UPDATE	"file %s: elf_update"
@ MSG_ELF_SWAP_WRIMAGE	"file %s: _elf_swap_wrimage"


@ MSG_REJ_MACH		"file %s: wrong ELF machine type: %s"
@ MSG_REJ_CLASS		"file %s: wrong ELF class: %s"
@ MSG_REJ_DATA		"file %s: wrong ELF data format: %s"
@ MSG_REJ_TYPE		"file %s: bad ELF type: %s"
@ MSG_REJ_BADFLAG	"file %s: bad ELF flags value: %s"
@ MSG_REJ_MISFLAG	"file %s: mismatched ELF flags value: %s"
@ MSG_REJ_VERSION	"file %s: mismatched ELF/lib version: %s"
@ MSG_REJ_HAL		"file %s: HAL R1 extensions required"
@ MSG_REJ_US3		"file %s: Sun UltraSPARC III extensions required"
@ MSG_REJ_STR		"file %s: %s"
@ MSG_REJ_UNKFILE	"file %s: unknown file type"
@ MSG_REJ_UNKCAP	"file=%s; unknown capability: %d"
@ MSG_REJ_HWCAP_1	"file %s: hardware capability (CA_SUNW_HW_1) \
			 unsupported: %s"
@ MSG_REJ_SFCAP_1	"file %s: software capability (CA_SUNW_SF_1) \
			 unsupported: %s"
@ MSG_REJ_MACHCAP	"file %s: machine capability (CA_SUNW_MACH) \
			 unsupported: %s"
@ MSG_REJ_PLATCAP	"file %s: platform capability (CA_SUNW_PLAT) \
			 unsupported: %s"
@ MSG_REJ_HWCAP_2	"file %s: hardware capability (CA_SUNW_HW_2) \
			 unsupported: %s"
@ MSG_REJ_ARCHIVE	"file %s: invalid archive use"

# Guidance messages
@ MSG_GUIDE_SUMMARY	"see ld(1) -z guidance for more information"
@ MSG_GUIDE_DEFS	"-z defs option recommended for shared objects"
@ MSG_GUIDE_DIRECT	"-B direct or -z direct option recommended before \
			 first dependency"
@ MSG_GUIDE_LAZYLOAD	"-z lazyload option recommended before \
			 first dependency"
@ MSG_GUIDE_MAPFILE	"version 2 mapfile syntax recommended: %s"
@ MSG_GUIDE_TEXT	"position independent (PIC) code recommended for \
			 shared objects"
@ MSG_GUIDE_UNUSED	"removal of unused dependency recommended: %s"

@ _END_


# The following strings represent reserved names.  Reference to these strings
# is via the MSG_ORIG() macro, and thus translations are not required.

@ MSG_STR_EOF		"<eof>"
@ MSG_STR_ERROR		"<error>"
@ MSG_STR_EMPTY		""
@ MSG_QSTR_BANG		"'!'"
@ MSG_STR_COLON		":"
@ MSG_QSTR_COLON	"':'"
@ MSG_QSTR_SEMICOLON	"';'"
@ MSG_QSTR_EQUAL	"'='"
@ MSG_QSTR_PLUSEQ	"'+='"
@ MSG_QSTR_MINUSEQ	"'-='"
@ MSG_QSTR_ATSIGN	"'@'"
@ MSG_QSTR_DASH		"'-'"
@ MSG_QSTR_LEFTBKT	"'{'"
@ MSG_QSTR_RIGHTBKT	"'}'"
@ MSG_QSTR_PIPE		"'|'"
@ MSG_QSTR_STAR		"'*'"
@ MSG_STR_DOT		"."
@ MSG_STR_SLASH		"/"
@ MSG_STR_DYNAMIC	"(.dynamic)"
@ MSG_STR_ORIGIN	"$ORIGIN"
@ MSG_STR_MACHINE	"$MACHINE"
@ MSG_STR_PLATFORM	"$PLATFORM"
@ MSG_STR_ISALIST	"$ISALIST"
@ MSG_STR_OSNAME	"$OSNAME"
@ MSG_STR_OSREL		"$OSREL"
@ MSG_STR_UU_REAL_U	"__real_"
@ MSG_STR_UU_WRAP_U	"__wrap_"
@ MSG_STR_UELF32	"_ELF32"
@ MSG_STR_UELF64	"_ELF64"
@ MSG_STR_USPARC	"_sparc"
@ MSG_STR_UX86		"_x86"
@ MSG_STR_TRUE		"true"

@ MSG_STR_CDIR_ADD	"$add"
@ MSG_STR_CDIR_CLEAR	"$clear"
@ MSG_STR_CDIR_ERROR	"$error"
@ MSG_STR_CDIR_MFVER	"$mapfile_version"
@ MSG_STR_CDIR_IF	"$if"
@ MSG_STR_CDIR_ELIF	"$elif"
@ MSG_STR_CDIR_ELSE	"$else"
@ MSG_STR_CDIR_ENDIF	"$endif"

@ MSG_STR_GROUP		"GROUP"
@ MSG_STR_SUNW_COMDAT	"SUNW_COMDAT"

@ MSG_FMT_ARMEM		"%s(%s)"
@ MSG_FMT_COLPATH	"%s:%s"
@ MSG_FMT_SYMNAM	"'%s'"
@ MSG_FMT_NULLSYMNAM	"%s[%d]"
@ MSG_FMT_STRCAT	"%s%s"

@ MSG_PTH_RTLD		"/usr/lib/ld.so.1"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"


# Section strings

@ MSG_SCN_BSS		".bss"
@ MSG_SCN_DATA		".data"
@ MSG_SCN_COMMENT	".comment"
@ MSG_SCN_DEBUG		".debug"
@ MSG_SCN_DEBUG_INFO	".debug_info"
@ MSG_SCN_DYNAMIC	".dynamic"
@ MSG_SCN_DYNSYMSORT	".SUNW_dynsymsort"
@ MSG_SCN_DYNTLSSORT	".SUNW_dyntlssort"
@ MSG_SCN_DYNSTR	".dynstr"
@ MSG_SCN_DYNSYM	".dynsym"
@ MSG_SCN_DYNSYM_SHNDX	".dynsym_shndx"
@ MSG_SCN_LDYNSYM	".SUNW_ldynsym"
@ MSG_SCN_LDYNSYM_SHNDX	".SUNW_ldynsym_shndx"
@ MSG_SCN_EX_SHARED	".ex_shared"
@ MSG_SCN_EX_RANGES	".exception_ranges"
@ MSG_SCN_EXCL		".excl"
@ MSG_SCN_FINI		".fini"
@ MSG_SCN_FINIARRAY	".fini_array"
@ MSG_SCN_GOT		".got"
@ MSG_SCN_GNU_LINKONCE	".gnu.linkonce."
@ MSG_SCN_HASH		".hash"
@ MSG_SCN_INDEX		".index"
@ MSG_SCN_INIT		".init"
@ MSG_SCN_INITARRAY	".init_array"
@ MSG_SCN_INTERP	".interp"
@ MSG_SCN_LBSS		".lbss"
@ MSG_SCN_LDATA		".ldata"
@ MSG_SCN_LINE		".line"
@ MSG_SCN_LRODATA	".lrodata"
@ MSG_SCN_PLT		".plt"
@ MSG_SCN_PREINITARRAY	".preinit_array"
@ MSG_SCN_REL		".rel"
@ MSG_SCN_RELA		".rela"
@ MSG_SCN_RODATA	".rodata"
@ MSG_SCN_SBSS		".sbss"
@ MSG_SCN_SBSS2		".sbss2"
@ MSG_SCN_SDATA		".sdata"
@ MSG_SCN_SDATA2	".sdata2"
@ MSG_SCN_SHSTRTAB	".shstrtab"
@ MSG_SCN_STAB		".stab"
@ MSG_SCN_STABEXCL	".stab.exclstr"
@ MSG_SCN_STRTAB	".strtab"
@ MSG_SCN_SUNWMOVE	".SUNW_move"
@ MSG_SCN_SUNWRELOC	".SUNW_reloc"
@ MSG_SCN_SUNWSYMINFO	".SUNW_syminfo"
@ MSG_SCN_SUNWVERSION	".SUNW_version"
@ MSG_SCN_SUNWVERSYM	".SUNW_versym"
@ MSG_SCN_SUNWCAP	".SUNW_cap"
@ MSG_SCN_SUNWCAPINFO	".SUNW_capinfo"
@ MSG_SCN_SUNWCAPCHAIN	".SUNW_capchain"
@ MSG_SCN_SYMTAB	".symtab"
@ MSG_SCN_SYMTAB_SHNDX	".symtab_shndx"
@ MSG_SCN_TBSS		".tbss"
@ MSG_SCN_TDATA		".tdata"
@ MSG_SCN_TEXT		".text"

@ MSG_SYM_FINIARRAY	"finiarray"
@ MSG_SYM_INITARRAY	"initarray"
@ MSG_SYM_PREINITARRAY	"preinitarray"

#
# GNU section names
#
@ MSG_SCN_CTORS		".ctors"
@ MSG_SCN_DTORS		".dtors"
@ MSG_SCN_EHFRAME	".eh_frame"
@ MSG_SCN_EHFRAME_HDR	".eh_frame_hdr"
@ MSG_SCN_GCC_X_TBL	".gcc_except_table"
@ MSG_SCN_JCR		".jcr"

# Segment names for segments referenced by entrance criteria

@ MSG_ENT_BSS		"bss"
@ MSG_ENT_DATA		"data"
@ MSG_ENT_EXTRA		"extra"
@ MSG_ENT_LDATA		"ldata"
@ MSG_ENT_LRODATA	"lrodata"
@ MSG_ENT_NOTE		"note"
@ MSG_ENT_TEXT		"text"

# Symbol names

@ MSG_SYM_START		"_start"
@ MSG_SYM_MAIN		"main"

@ MSG_SYM_FINI_U	"_fini"
@ MSG_SYM_INIT_U	"_init"
@ MSG_SYM_DYNAMIC	"DYNAMIC"
@ MSG_SYM_DYNAMIC_U	"_DYNAMIC"
@ MSG_SYM_EDATA		"edata"
@ MSG_SYM_EDATA_U	"_edata"
@ MSG_SYM_END		"end"
@ MSG_SYM_END_U		"_end"
@ MSG_SYM_ETEXT		"etext"
@ MSG_SYM_ETEXT_U	"_etext"
@ MSG_SYM_GOFTBL	"GLOBAL_OFFSET_TABLE_"
@ MSG_SYM_GOFTBL_U	"_GLOBAL_OFFSET_TABLE_"
@ MSG_SYM_PLKTBL	"PROCEDURE_LINKAGE_TABLE_"
@ MSG_SYM_PLKTBL_U	"_PROCEDURE_LINKAGE_TABLE_"
@ MSG_SYM_TLSGETADDR_U	"__tls_get_addr"
@ MSG_SYM_TLSGETADDR_UU	"___tls_get_addr"

@ MSG_SYM_L_END		"END_"
@ MSG_SYM_L_END_U	"_END_"
@ MSG_SYM_L_START	"START_"
@ MSG_SYM_L_START_U	"_START_"

# Support functions

@ MSG_SUP_VERSION	"ld_version"
@ MSG_SUP_INPUT_DONE	"ld_input_done"

@ MSG_SUP_START_64	"ld_start64"
@ MSG_SUP_ATEXIT_64	"ld_atexit64"
@ MSG_SUP_OPEN_64	"ld_open64"
@ MSG_SUP_FILE_64	"ld_file64"
@ MSG_SUP_INSEC_64	"ld_input_section64"
@ MSG_SUP_SEC_64	"ld_section64"

@ MSG_SUP_START		"ld_start"
@ MSG_SUP_ATEXIT	"ld_atexit"
@ MSG_SUP_OPEN		"ld_open"
@ MSG_SUP_FILE		"ld_file"
@ MSG_SUP_INSEC		"ld_input_section"
@ MSG_SUP_SEC		"ld_section"

# 
# Message previously in 'ld'
#
# 
@ _START_

# System error messages

@ MSG_SYS_STAT		"file %s: stat failed: %s"
@ MSG_SYS_READ		"file %s: read failed: %s"
@ MSG_SYS_NOTREG	"file %s: is not a regular file"

# Argument processing messages

@ MSG_ARG_DY_INCOMP	"%s option is incompatible with building a dynamic \
			 executable"
@ MSG_MARG_DY_INCOMP	"%s is incompatible with building a dynamic \
			 executable"
@ MSG_ARG_ST_INCOMP	"%s option is incompatible with building a static \
			 object (-dn, -r, --relocatable)"
@ MSG_MARG_ST_INCOMP	"%s is incompatible with building a static \
			 object (-dn, -r, --relocatable)"
@ MSG_MARG_ST_ONLYAVL	"%s is only available when building a shared object"
@ MSG_ARG_INCOMP	"option %s and %s are incompatible"
@ MSG_MARG_INCOMP	"%s and %s are incompatible"
@ MSG_ARG_MTONCE	"option %s appears more than once, first setting taken"
@ MSG_MARG_MTONCE	"%s appears more than once, first setting taken"
@ MSG_ARG_ILLEGAL	"option %s has illegal argument '%s'"
@ MSG_ARG_YP		"option -YP and -Y%c may not be specified concurrently"
@ MSG_ARG_STRIP		"%s specified with %s; only debugging \
			 information stripped"
@ MSG_ARG_NOFILES	"no files on input command line"
@ MSG_ARG_NOFLTR	"option %s is only meaningful when building a filter"
@ MSG_ARG_NODEFLIB	"the default library search path has been suppressed, \
			 but no runpaths have been specified via %s"
@ MSG_ARG_NOENTRY	"entry point symbol '%s' is undefined"
@ MSG_ARG_UNSUPPORTED	"option %s is no longer supported; ignored"
@ MSG_MARG_ONLY		"option %s can only be used with a %s"
@ MSG_ARG_UNKNOWN	"unrecognized option '-%c'"
@ MSG_ARG_LONG_UNKNOWN	"unrecognized option '%s'"
@ MSG_ARG_USEHELP	"use the -z help option for usage information"


@ MSG_ARG_FLAGS		"flags processing errors"
@ MSG_ARG_FILES		"file processing errors. No output written to %s"
@ MSG_ARG_SYM_WARN	"symbol referencing errors"
@ MSG_ARG_SYM_FATAL	"symbol referencing errors. No output written to %s"
@ MSG_ARG_AR_GRP_OLAP	"%s cannot be nested"
@ MSG_ARG_AR_GRP_BAD	"%s used without corresponding %s"


# Messages used to refer to options where there is more than
# one name accepted.

@ MSG_MARG_AR_GRPS	"archive rescan groups \
			 (-z rescan-start, -(, --start-group)"
@ MSG_MARG_AR_GRP_END	"archive rescan group end option \
			 (-z rescan-end, -), --end-group)"
@ MSG_MARG_AR_GRP_START	"archive rescan group start option \
			 (-z rescan-start, -(, --start-group)"
@ MSG_MARG_ENTRY	"entry point option (-e, --entry)"
@ MSG_MARG_FILTER_AUX	"auxiliary filter option (-f, --auxiliary)"
@ MSG_MARG_FILTER	"filter option (-F, --filter)"
@ MSG_MARG_OUTFILE	"output object option (-o, --output)"
@ MSG_MARG_REL		"relocatable object option (-r, --relocatable)"
@ MSG_MARG_RPATH	"runpath option (-R, -rpath)"
@ MSG_MARG_SO		"shared object option (-G, -shared)"
@ MSG_MARG_SONAME	"soname option (-h, --soname)"
@ MSG_MARG_STRIP	"strip option (-s, --strip-all)"

# Entrance criteria messages

@ MSG_ENT_MAP_FMT_TIL_1	"\t\t%s\n\n"
@ MSG_ENT_MAP_TITLE_1	"LINK EDITOR MEMORY MAP"

#
# TRANSLATION_NOTE -- Entry map header
#
# The next message is a format string for a title. The title is composed of
# two lines. In C locale, it would look like:
#
# 	output		input		new
#	section		section		displacement	size
#
# The \t characters are used for alignment.  (output section), (input section),
# and (new displacement) have to be aligned.
#
@ MSG_ENT_MAP_FMT_TIL_2	"\n%s\t\t%s\t\t%s\n%s\t\t%s\t\t%s\t%s\n\n"
@ MSG_ENT_MAP_FMT_TIL_3	"\n%s\t\t%s\t\t%s\n%s\t\t%s\t\t%s\t\t%s\n\n"
@ MSG_ENT_ITM_OUTPUT	"output"
@ MSG_ENT_ITM_INPUT	"input"
@ MSG_ENT_ITM_NEW	"new"
@ MSG_ENT_ITM_SECTION	"section"
@ MSG_ENT_ITM_DISPMNT	"displacement"
@ MSG_ENT_ITM_SIZE	"size"
@ MSG_ENT_ITM_VIRTUAL	"virtual"
@ MSG_ENT_ITM_ADDRESS	"address"

@ MSG_ENT_MAP_ENTRY_1	"%-8.8s\t\t\t%08.2llx\t%08.2llx\n"
@ MSG_ENT_MAP_ENTRY_2	"\t\t%-8.8s\t%08.2llx\t%08.2llx %s\n"

#
# TRANSLATION_NOTE -- multiple defined symbol table header
#
# In C locale, an example output is:
#
#		MULTIPLY DEFINED SYMBOLS
#
#
#symbol				  definition used     also defined in
#
#variable1                           main.o
#							./libfred.so
@ MSG_ENT_MUL_FMT_TIL_0	"\n\n\t\t%s\n\n\n"
@ MSG_ENT_MUL_TIL_0	"MULTIPLY DEFINED SYMBOLS"

#
# TRANSLATION_NOTE -- This is the format string for:
#
#symbol				  definition used     also defined in
#
@ MSG_ENT_MUL_FMT_TIL_1	"%s\t\t\t\t  %s     %s\n\n"
@ MSG_ENT_MUL_ITM_SYM	"symbol"
@ MSG_ENT_MUL_ITM_DEF_0	"definition used"
@ MSG_ENT_MUL_ITM_DEF_1	"also defined in"

#
# TRANSLATION_NOTE -- This is the format string for the second item:
#
@ MSG_ENT_MUL_ENTRY_1	"%-35s %s\n"

#
# TRANSLATION_NOTE -- This is the format string for the third item:
#
@ MSG_ENT_MUL_ENTRY_2	"\t\t\t\t\t\t\t%s\n"

@ MSG_ENT_NOSEC_1	"mapfile: %s segment: section '%s' does not appear \
			 in mapfile specified input file(s)"
@ MSG_ENT_NOSEC_2	"mapfile: %s segment: section '%s' does not appear \
			 in any input file"

# Library messages

@ MSG_LIB_NOTFOUND	"library -l%s: not found"
@ MSG_LIB_MALFORM	"LD_LIBRARY_PATH malformed"
@ MSG_LIB_BADYP		"-YP library path malformed"


# Mapfile processing messages

@ MSG_MAP_BADAUTORED	"%s: %llu: auto-reduction ('*') can only be used in \
			 hidden/local, or eliminate scope"
@ MSG_MAP_BADFLAG	"%s: %llu: badly formed section flags '%s'"
@ MSG_MAP_BADBNAME	"%s: %llu: basename cannot contain path \
			 separator ('/'): %s"
@ MSG_MAP_BADONAME	"%s: %llu: object name cannot contain path \
			 separator ('/'): %s"
@ MSG_MAP_REDEFATT	"%s: %llu: redefining %s attribute for '%s'"
@ MSG_MAP_PREMEOF	"%s: %llu: premature EOF"
@ MSG_MAP_ILLCHAR	"%s: %llu: illegal character '\\%03o'"
@ MSG_MAP_MALFORM	"%s: %llu: malformed entry"
@ MSG_MAP_NONLOAD	"%s: %llu: %s not allowed on non-LOAD segments"
@ MSG_MAP_NOSTACK1	"%s: %llu: %s not allowed on STACK segment"
@ MSG_MAP_MOREONCE	"%s: %llu: %s set more than once on same line"
@ MSG_MAP_NOTERM	"%s: %llu: unterminated quoted string: %s"
@ MSG_MAP_SECINSEG	"%s: %llu: section within segment ordering done on \
			 a non-existent segment '%s'"
@ MSG_MAP_UNEXINHERIT	"%s: %llu: unnamed version cannot inherit from other \
			 versions: %s"
@ MSG_MAP_UNEXTOK	"%s: %llu: unexpected occurrence of '%c' token"

@ MSG_MAP_SEGEMPLOAD	"%s: %llu: empty segment must be of type LOAD or NULL"
@ MSG_MAP_SEGEMPEXE	"%s: %llu: a LOAD empty segment definition is only \
			 allowed when creating a dynamic executable"
@ MSG_MAP_SEGEMPATT	"%s: %llu: a LOAD empty segment must have an address \
			 and size"
@ MSG_MAP_SEGEMPNOATT	"%s: %llu: a NULL empty segment must not have an \
			 address or size"
@ MSG_MAP_SEGEMPSEC	"%s: %llu: empty segment can not have sections \
			 assigned to it"
@ MSG_MAP_SEGEMNOPERM	"%s: %llu: empty segment must not have \
			 p_flags set: 0x%x"

@ MSG_MAP_CNTADDRORDER	"%s: %llu: segment cannot have an explicit address \
			 and also be in the SEGMENT_ORDER list: %s"
@ MSG_MAP_CNTDISSEG	"%s: %llu: segment cannot be disabled: %s"
@ MSG_MAP_DUPNAMENT	"%s: %llu: cannot redefine entrance criteria: %s"
@ MSG_MAP_DUPORDSEG	"%s: %llu: segment is already in %s list: %s"
@ MSG_MAP_DUP_OS_ORD	"%s: %llu: section is already in OS_ORDER list: %s"
@ MSG_MAP_DUP_IS_ORD	"%s: %llu: entrance criteria is already in \
			 IS_ORDER list: %s"
@ MSG_MAP_UNKENT	"%s: %llu: unknown entrance criteria \
			 (ASSIGN_SECTION): %s"
@ MSG_MAP_UNKSEG	"%s: %llu: unknown segment: %s"
@ MSG_MAP_UNKSYMDEF	"%s: %llu: unknown symbol definition: %s"
@ MSG_MAP_UNKSEGTYP	"%s: %llu: unknown internal segment type %d"
@ MSG_MAP_UNKSOTYP	"%s: %llu: unknown shared object type: %s"
@ MSG_MAP_UNKSEGATT	"%s: %llu: unknown segment attribute: %s"
@ MSG_MAP_UNKSEGFLG	"%s: %llu: unknown segment flag: ?%c"
@ MSG_MAP_UNKSECTYP	"%s: %llu: unknown section type: %s"

@ MSG_MAP_SEGSIZE	"%s: %lld: existing segment size symbols cannot \
			 be reset: %s"
@ MSG_MAP_SEGADDR	"%s: %llu: segment address or length '%s' %s"
@ MSG_MAP_BADCAPVAL	"%s: %llu: bad capability value: %s"
@ MSG_MAP_UNKCAPATTR	"%s: %llu: unknown capability attribute '%s'"
@ MSG_MAP_EMPTYCAP	"%s: %llu: empty capability definition; ignored"

@ MSG_MAP_SYMDEF1	"%s: %llu: symbol '%s' is already defined in file: \
			 %s: %s"
@ MSG_MAP_SYMDEF2	"%s: %llu: symbol '%s': %s"

@ MSG_MAP_EXPSCOL	"%s: %llu: expected a ';'"
@ MSG_MAP_EXPEQU	"%s: %llu: expected a '=', ':', '|', or '@'"
@ MSG_MAP_EXPSEGATT	"%s: %llu: expected one or more segment attributes \
			 after an '='"
@ MSG_MAP_EXPSEGNAM	"%s: %llu: expected a segment name at the beginning \
			 of a line"
@ MSG_MAP_EXPSEGTYPE	"%s: %llu: %s segment cannot be used with %s \
			 directive: %s"
@ MSG_MAP_EXPSYM_1	"%s: %llu: expected a symbol name after '@'"
@ MSG_MAP_EXPSYM_2	"%s: %llu: expected a symbol name after '{'"
@ MSG_MAP_EXPSEC	"%s: %llu: expected a section name after '|'"
@ MSG_MAP_EXPSO		"%s: %llu: expected a shared object definition \
			 after '-'"
@ MSG_MAP_MULTFILTEE	"%s: %llu: multiple filtee definitions are unsupported"
@ MSG_MAP_NOFILTER	"%s: %llu: filtee definition required"
@ MSG_MAP_BADSF1	"%s: %llu: unknown software capabilities: 0x%llx; \
			 ignored"
@ MSG_MAP_INADDR32SF1	"%s: %llu: software capability ADDR32: is ineffective \
			 when building 32-bit object: ignored"
@ MSG_MAP_NOINTPOSE	"%s: %llu: interposition symbols can only be defined \
			 when building a dynamic executable"
@ MSG_MAP_NOEXVLSZ	"%s: %llu: value and size attributes are incompatible \
			 with extern or parent symbols"
@ MSG_MAP_FLTR_ONLYAVL	"%s: %llu: symbol filtering is only available when \
			 building a shared object"

@ MSG_MAP_SEGSAME	"segments '%s' and '%s' have the same assigned \
			 virtual address"
@ MSG_MAP_EXCLIMIT	"exceeds internal limit"
@ MSG_MAP_NOBADFRM	"number is badly formed"

@ MSG_MAP_SEGTYP	"segment type"
@ MSG_MAP_SEGVADDR	"segment virtual address"
@ MSG_MAP_SEGPHYS	"segment physical address"
@ MSG_MAP_SEGLEN	"segment length"
@ MSG_MAP_SEGFLAG	"segment flags"
@ MSG_MAP_SEGALIGN	"segment alignment"
@ MSG_MAP_SEGROUND	"segment rounding"

@ MSG_MAP_SECTYP	"section type"
@ MSG_MAP_SECFLAG	"section flags"
@ MSG_MAP_SECNAME	"section name"

@ MSG_MAP_SYMVAL	"symbol value"
@ MSG_MAP_SYMSIZE	"symbol size"

@ MSG_MAP_DIFF_SYMVAL	"symbol values differ"
@ MSG_MAP_DIFF_SYMSZ	"symbol sizes differ"
@ MSG_MAP_DIFF_SYMTYP	"symbol types differ"
@ MSG_MAP_DIFF_SYMNDX	"symbol indexes differ"
@ MSG_MAP_DIFF_SYMLCL	"symbol scope conflict against local and non-local"
@ MSG_MAP_DIFF_SYMGLOB	"symbol scope conflict against singleton/exported"
@ MSG_MAP_DIFF_SYMPROT	"symbol scope conflict against protected"
@ MSG_MAP_DIFF_SYMVER	"symbol version conflict"
@ MSG_MAP_DIFF_SYMMUL	"symbol multiple definition"
@ MSG_MAP_DIFF_SNGLDIR	"singleton scope and direct declaration are \
			 incompatible"
@ MSG_MAP_DIFF_PROTNDIR	"protected scope and no-direct declaration \
			 are incompatible"


@ MSG_MAP_SECORDER	"section ordering requested, but no matching section \
			 found: segment: %s section: %s"


# Mapfile Directives

@ MSG_MAP_EXP_ATTR	"%s: %llu: expected attribute name (%s), or \
			 terminator (';', '}'): %s"
@ MSG_MAP_EXP_CAPMASK	"%s: %llu: expected capability name, integer value, or \
			 terminator (';', '}'): %s"
@ MSG_MAP_EXP_CAPNAME	"%s: %llu: expected name, or terminator (';', '}'): %s"
@ MSG_MAP_EXP_CAPID	"%s: %llu: expected name, or '{' following %s: %s"
@ MSG_MAP_EXP_CAPHW	"%s: %llu: expected hardware capability, or \
			 terminator (';', '}'): %s"
@ MSG_MAP_EXP_CAPSF	"%s: %llu: expected software capability, or \
			 terminator (';', '}'): %s"
@ MSG_MAP_EXP_EQ	"%s: %llu: expected '=' following %s: %s"
@ MSG_MAP_EXP_EQ_ALL	"%s: %llu: expected '=', '+=', or '-=' following %s: %s"
@ MSG_MAP_EXP_EQ_PEQ	"%s: %llu: expected '=' following %s: %s"
@ MSG_MAP_EXP_DIR	"%s: %llu: expected mapfile directive (%s): %s"
@ MSG_MAP_SFLG_EXBANG	"%s: %llu: '!' appears without corresponding flag"
@ MSG_MAP_EXP_FILNAM	"%s: %llu: expected file name following %s: %s"
@ MSG_MAP_EXP_FILPATH	"%s: %llu: expected file path following %s: %s"
@ MSG_MAP_EXP_INT	"%s: %llu: expected integer value following %s: %s"
@ MSG_MAP_EXP_LBKT	"%s: %llu: expected '{' following %s: %s"
@ MSG_MAP_EXP_OBJNAM	"%s: %llu: expected object name following %s: %s"
@ MSG_MAP_SFLG_ONEBANG	"%s: %llu: '!' can only be specified once per flag"
@ MSG_MAP_EXP_SECFLAG	"%s: %llu: expected section flag (%s), '!', or \
			 terminator (';', '}'): %s"
@ MSG_MAP_EXP_SECNAM	"%s: %llu: expected section name following %s: %s"
@ MSG_MAP_EXP_SEGFLAG	"%s: %llu: expected segment flag (%s), or \
			 terminator (';', '}'): %s"
@ MSG_MAP_EXP_ECNAM	"%s: %llu: expected entrance criteria (ASSIGN_SECTION) \
			 name, or terminator (';', '}'): %s"
@ MSG_MAP_EXP_SEGNAM	"%s: %llu: expected segment name following %s: %s"
@ MSG_MAP_EXP_SEM	"%s: %llu: expected ';' to terminate %s: %s"
@ MSG_MAP_EXP_SEMLBKT	"%s: %llu: expected ';' or '{' following %s: %s"
@ MSG_MAP_EXP_SEMRBKT	"%s: %llu: expected ';' or '}' to terminate %s: %s"
@ MSG_MAP_EXP_SHTYPE	"%s: %llu: expected section type: %s"
@ MSG_MAP_EXP_SYM	"%s: %llu: expected symbol name, symbol scope, \
			 or '*': %s"
@ MSG_MAP_EXP_SYMEND	"%s: %llu: expected inherited version name, or \
			 terminator (';'): %s"
@ MSG_MAP_EXP_SYMDELIM	"%s: %llu: expected one of ':', ';', or '{': %s"
@ MSG_MAP_EXP_SYMFLAG	"%s: %llu: expected symbol flag (%s), or \
			 terminator (';', '}'): %s"
@ MSG_MAP_EXP_SYMNAM	"%s: %llu: expected symbol name following %s: %s"
@ MSG_MAP_EXP_SYMSCOPE	"%s: %llu: expected symbol scope (%s): %s"
@ MSG_MAP_EXP_SYMTYPE	"%s: %llu: expected symbol type (%s): %s"
@ MSG_MAP_EXP_VERSION	"%s: %llu: expected version name following %s: %s"
@ MSG_MAP_BADEXTRA	"%s: %llu: unexpected text found following %s directive"
@ MSG_MAP_VALUELIMIT	"%s: %llu: numeric value exceeds word size: %s"
@ MSG_MAP_MALVALUE	"%s: %llu: malformed numeric value: %s"
@ MSG_MAP_BADVALUETAIL	"%s: %llu: unexpected characters following numeric \
			 constant: %s"
@ MSG_MAP_WSNEEDED	"%s: %llu: whitespace needed before token: %s"
@ MSG_MAP_BADCHAR	"%s: %llu: unexpected text: %s"
@ MSG_MAP_BADKWQUOTE	"%s: %llu: mapfile keywords should not be quoted: %s"
@ MSG_MAP_CDIR_NOTBOL	"%s: %llu: mapfile control directive not at start of \
			 line: %s"
@ MSG_MAP_NOATTR	"%s: %llu: %s specified no attributes (empty {})"
@ MSG_MAP_NOVALUES	"%s: %llu: %s specified without values"
@ MSG_MAP_INTERR	"<internal error>"
@ MSG_MAP_ISORDVER	"%s: %llu: version 0 mapfile ?O flag and version 1 \
			 segment IS_ORDER attribute are mutually exclusive: %s"
@ MSG_MAP_SYMATTR	"symbol attributes";

# Mapfile Control Directives

@ MSG_MAP_CDIR_BADVDIR	"%s: %llu: $mapfile_version directive must specify \
			 version 2 or higher: %d"
@ MSG_MAP_CDIR_BADVER	"%s: %llu: unknown mapfile version: %d"
@ MSG_MAP_CDIR_REPVER	"%s: %llu: $mapfile_version must be first directive \
			 in file"
@ MSG_MAP_CDIR_REQARG	"%s: %llu: %s directive requires an argument"
@ MSG_MAP_CDIR_REQNOARG	"%s: %llu: %s directive does not accept arguments"
@ MSG_MAP_CDIR_BAD	"%s: %llu: unrecognized mapfile control directive"
@ MSG_MAP_CDIR_NOIF	"%s: %llu: %s directive used without opening $if"
@ MSG_MAP_CDIR_ELSE	"%s: %llu: %s directive preceded by $else on line %d"
@ MSG_MAP_CDIR_NOEND	"%s: %llu: EOF encountered without closing $endif \
			 for $if on line %d"
@ MSG_MAP_CDIR_ERROR	"%s: %llu: error: %s"


# Mapfile Conditional Expressions

@ MSG_MAP_CEXP_TOKERR	"%s: %llu: syntax error in conditional expression at: %s"
@ MSG_MAP_CEXP_SEMERR	"%s: %llu: malformed conditional expression"
@ MSG_MAP_CEXP_BADOPUSE	"%s: %llu: invalid operator use in conditional \
			 expression"
@ MSG_MAP_CEXP_UNBALPAR	"%s: %llu: unbalanced parenthesis in conditional \
			 expression"
@ MSG_MAP_BADCESC	"%s: %llu: unrecognized escape in double quoted \
			 token: \\%c\n"

# Generic error diagnostic labels

@ MSG_STR_NULL		"(null)"

@ MSG_DBG_DFLT_FMT	"debug: "
@ MSG_DBG_AOUT_FMT	"debug: a.out: "
@ MSG_DBG_NAME_FMT	"debug: %s: "

# -z assert-deflib strings

@ MSG_ARG_ASSDEFLIB_MALFORMED	"library name malformed: %s"
@ MSG_ARG_ASSDEFLIB_FOUND	"dynamic library found on default search path \
				(%s): lib%s.so"

@ _END_


# Software identification.  Note, the SGU strings is historic, and has
# little relevance.  It is preserved as applications have used this
# string to identify the Solaris link-editor.

@ MSG_SGS_ID		"ld: Software Generation Utilities - \
			 Solaris Link Editors: "

# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_DBG_FOPEN_MODE	"w"

@ MSG_DBG_CLS32_FMT	"32: "
@ MSG_DBG_CLS64_FMT	"64: "

@ MSG_STR_PATHTOK	";:"
@ MSG_STR_AOUT		"a.out"

@ MSG_STR_LIB_A		"%s/lib%s.a"
@ MSG_STR_LIB_SO	"%s/lib%s.so"
@ MSG_STR_PATH		"%s/%s"
@ MSG_STR_STRNL		"%s\n"
@ MSG_STR_NL		"\n"
@ MSG_STR_CAPGROUPID 	"CAP_GROUP_%d"

@ MSG_STR_LD_DYNAMIC	"dynamic"
@ MSG_STR_SYMBOLIC	"symbolic"
@ MSG_STR_ELIMINATE	"eliminate"
@ MSG_STR_LOCAL		"local"
@ MSG_STR_PROGBITS	"progbits"
@ MSG_STR_SYMTAB	"symtab"
@ MSG_STR_DYNSYM	"dynsym"
@ MSG_STR_REL		"rel"
@ MSG_STR_RELA		"rela"
@ MSG_STR_STRTAB	"strtab"
@ MSG_STR_HASH		"hash"
@ MSG_STR_LIB		"lib"
@ MSG_STR_NOTE		"note"
@ MSG_STR_NOBITS	"nobits"
@ MSG_STR_HWCAP_1	"hwcap_1"
@ MSG_STR_SFCAP_1	"sfcap_1"
@ MSG_STR_SOEXT		".so"

@ MSG_STR_OPTIONS	"3:6:abc:d:e:f:h:il:mo:p:rstu:z:B:CD:F:GI:L:M:N:P:Q:R:\
			 S:VW:Y:?"

# Argument processing strings

@ MSG_ARG_3		"-3"
@ MSG_ARG_6		"-6"
@ MSG_ARG_A		"-a"
@ MSG_ARG_B		"-b"
@ MSG_ARG_CB		"-B"
@ MSG_ARG_BDIRECT	"-Bdirect"
@ MSG_ARG_BDYNAMIC	"-Bdynamic"
@ MSG_ARG_BELIMINATE	"-Beliminate"
@ MSG_ARG_BGROUP	"-Bgroup"
@ MSG_ARG_BLOCAL	"-Blocal"
@ MSG_ARG_BNODIRECT	"-Bnodirect"
@ MSG_ARG_BSYMBOLIC	"-Bsymbolic"
@ MSG_ARG_BTRANSLATOR	"-Btranslator"
@ MSG_ARG_C		"-c"
@ MSG_ARG_D		"-d"
@ MSG_ARG_DY		"-dy"
@ MSG_ARG_CI		"-I"
@ MSG_ARG_CN		"-N"
@ MSG_ARG_P		"-p"
@ MSG_ARG_CP		"-P"
@ MSG_ARG_CQ		"-Q"
@ MSG_ARG_CY		"-Y"
@ MSG_ARG_CYL		"-YL"
@ MSG_ARG_CYP		"-YP"
@ MSG_ARG_CYU		"-YU"
@ MSG_ARG_Z		"-z"
@ MSG_ARG_ZDEFNODEF	"-z[defs|nodefs]"
@ MSG_ARG_ZGUIDE	"-zguidance"
@ MSG_ARG_ZNODEF	"-znodefs"
@ MSG_ARG_ZNOINTERP	"-znointerp"
@ MSG_ARG_ZRELAXRELOC	"-zrelaxreloc"
@ MSG_ARG_ZNORELAXRELOC	"-znorelaxreloc"
@ MSG_ARG_ZTEXT		"-ztext"
@ MSG_ARG_ZTEXTOFF	"-ztextoff"
@ MSG_ARG_ZTEXTWARN	"-ztextwarn"
@ MSG_ARG_ZTEXTALL	"-z[text|textwarn|textoff]"
@ MSG_ARG_ZLOADFLTR	"-zloadfltr"
@ MSG_ARG_ZCOMBRELOC	"-zcombreloc"
@ MSG_ARG_ZSYMBOLCAP	"-zsymbolcap"
@ MSG_ARG_ZFATWNOFATW	"-z[fatal-warnings|nofatalwarnings]"

@ MSG_ARG_ABSEXEC	"absexec"
@ MSG_ARG_ALTEXEC64	"altexec64"
@ MSG_ARG_NOCOMPSTRTAB	"nocompstrtab"
@ MSG_ARG_GROUPPERM	"groupperm"
@ MSG_ARG_NOGROUPPERM	"nogroupperm"
@ MSG_ARG_LAZYLOAD	"lazyload"
@ MSG_ARG_NOLAZYLOAD	"nolazyload"
@ MSG_ARG_INTERPOSE	"interpose"
@ MSG_ARG_DIRECT	"direct"
@ MSG_ARG_NODIRECT	"nodirect"
@ MSG_ARG_IGNORE	"ignore"
@ MSG_ARG_RECORD	"record"
@ MSG_ARG_INITFIRST	"initfirst"
@ MSG_ARG_INITARRAY	"initarray="
@ MSG_ARG_FINIARRAY	"finiarray="
@ MSG_ARG_PREINITARRAY	"preinitarray="
@ MSG_ARG_RTLDINFO	"rtldinfo="
@ MSG_ARG_DTRACE	"dtrace="
@ MSG_ARG_TRANSLATOR	"translator"
@ MSG_ARG_NOOPEN	"nodlopen"
@ MSG_ARG_NOW		"now"
@ MSG_ARG_ORIGIN	"origin"
@ MSG_ARG_DEFS		"defs"
@ MSG_ARG_NODEFS	"nodefs"
@ MSG_ARG_NODUMP	"nodump"
@ MSG_ARG_NOVERSION	"noversion"
@ MSG_ARG_TEXT		"text"
@ MSG_ARG_TEXTOFF	"textoff"
@ MSG_ARG_TEXTWARN	"textwarn"
@ MSG_ARG_MULDEFS	"muldefs"
@ MSG_ARG_NODELETE	"nodelete"
@ MSG_ARG_NOINTERP	"nointerp"
@ MSG_ARG_NOPARTIAL	"nopartial"
@ MSG_ARG_NORELOC	"noreloc"
@ MSG_ARG_REDLOCSYM	"redlocsym"
@ MSG_ARG_VERBOSE	"verbose"
@ MSG_ARG_WEAKEXT	"weakextract"
@ MSG_ARG_LOADFLTR	"loadfltr"
@ MSG_ARG_ALLEXTRT	"allextract"
@ MSG_ARG_DFLEXTRT	"defaultextract"
@ MSG_ARG_COMBRELOC	"combreloc"
@ MSG_ARG_NOCOMBRELOC	"nocombreloc"
@ MSG_ARG_NODEFAULTLIB	"nodefaultlib"
@ MSG_ARG_ENDFILTEE	"endfiltee"
@ MSG_ARG_LD32		"ld32="
@ MSG_ARG_LD64		"ld64="
@ MSG_ARG_RESCAN	"rescan"
@ MSG_ARG_RESCAN_NOW	"rescan-now"
@ MSG_ARG_RESCAN_START	"rescan-start"
@ MSG_ARG_RESCAN_END	"rescan-end"
@ MSG_ARG_GUIDE		"guidance"
@ MSG_ARG_NOLDYNSYM	"noldynsym"
@ MSG_ARG_RELAXRELOC	"relaxreloc"
@ MSG_ARG_NORELAXRELOC	"norelaxreloc"
@ MSG_ARG_NOSIGHANDLER	"nosighandler"
@ MSG_ARG_GLOBAUDIT	"globalaudit"
@ MSG_ARG_TARGET	"target="
@ MSG_ARG_WRAP		"wrap="
@ MSG_ARG_FATWARN	"fatal-warnings"
@ MSG_ARG_NOFATWARN	"nofatal-warnings"
@ MSG_ARG_HELP		"help"
@ MSG_ARG_GROUP		"group"
@ MSG_ARG_REDUCE	"reduce"
@ MSG_ARG_STATIC	"static"
@ MSG_ARG_SYMBOLCAP	"symbolcap"
@ MSG_ARG_DEFERRED	"deferred"
@ MSG_ARG_NODEFERRED	"nodeferred"
@ MSG_ARG_ASSDEFLIB	"assert-deflib"

@ MSG_ARG_LCOM		"L,"
@ MSG_ARG_PCOM		"P,"
@ MSG_ARG_UCOM		"U,"

@ MSG_ARG_T_RPATH	"rpath"
@ MSG_ARG_T_SHARED	"shared"
@ MSG_ARG_T_SONAME	"soname"
@ MSG_ARG_T_WL		"l,-"

@ MSG_ARG_T_AUXFLTR	"-auxiliary"
@ MSG_ARG_T_MULDEFS	"-allow-multiple-definition"
@ MSG_ARG_T_INTERP	"-dynamic-linker"
@ MSG_ARG_T_ENDGROUP	"-end-group"
@ MSG_ARG_T_ENTRY	"-entry"
@ MSG_ARG_T_STDFLTR	"-filter"
@ MSG_ARG_T_FATWARN	"-fatal-warnings"
@ MSG_ARG_T_NOFATWARN	"-no-fatal-warnings"
@ MSG_ARG_T_HELP	"-help"
@ MSG_ARG_T_LIBRARY	"-library"
@ MSG_ARG_T_LIBPATH	"-library-path"
@ MSG_ARG_T_NOUNDEF	"-no-undefined"
@ MSG_ARG_T_NOWHOLEARC	"-no-whole-archive"
@ MSG_ARG_T_OUTPUT	"-output"
@ MSG_ARG_T_RELOCATABLE	"-relocatable"
@ MSG_ARG_T_STARTGROUP	"-start-group"
@ MSG_ARG_T_STRIP	"-strip-all"
@ MSG_ARG_T_UNDEF	"-undefined"
@ MSG_ARG_T_VERSION	"-version"
@ MSG_ARG_T_WHOLEARC	"-whole-archive"
@ MSG_ARG_T_WRAP	"-wrap"
@ MSG_ARG_T_OPAR	"("
@ MSG_ARG_T_CPAR	")"

# -z guidance=item strings
@ MSG_ARG_GUIDE_DELIM		",: \t"
@ MSG_ARG_GUIDE_NO_ALL		"noall"
@ MSG_ARG_GUIDE_NO_DEFS		"nodefs"
@ MSG_ARG_GUIDE_NO_DIRECT	"nodirect"
@ MSG_ARG_GUIDE_NO_LAZYLOAD	"nolazyload"
@ MSG_ARG_GUIDE_NO_MAPFILE	"nomapfile"
@ MSG_ARG_GUIDE_NO_TEXT		"notext"
@ MSG_ARG_GUIDE_NO_UNUSED	"nounused"

# Environment variable strings

@ MSG_LD_RUN_PATH	"LD_RUN_PATH"
@ MSG_LD_LIBPATH_32	"LD_LIBRARY_PATH_32"
@ MSG_LD_LIBPATH_64	"LD_LIBRARY_PATH_64"
@ MSG_LD_LIBPATH	"LD_LIBRARY_PATH"

@ MSG_LD_NOVERSION_32	"LD_NOVERSION_32"
@ MSG_LD_NOVERSION_64	"LD_NOVERSION_64"
@ MSG_LD_NOVERSION	"LD_NOVERSION"

@ MSG_SGS_SUPPORT_32	"SGS_SUPPORT_32"
@ MSG_SGS_SUPPORT_64	"SGS_SUPPORT_64"
@ MSG_SGS_SUPPORT	"SGS_SUPPORT"


# Symbol names

@ MSG_SYM_LIBVER_U	"_lib_version"


# Mapfile tokens

@ MSG_MAP_LOAD		"load"
@ MSG_MAP_NOTE		"note"
@ MSG_MAP_NULL		"null"
@ MSG_MAP_STACK		"stack"
@ MSG_MAP_ADDVERS	"addvers"
@ MSG_MAP_FUNCTION	"function"
@ MSG_MAP_DATA		"data"
@ MSG_MAP_COMMON	"common"
@ MSG_MAP_PARENT	"parent"
@ MSG_MAP_EXTERN	"extern"
@ MSG_MAP_DIRECT	"direct"
@ MSG_MAP_NODIRECT	"nodirect"
@ MSG_MAP_FILTER	"filter"
@ MSG_MAP_AUXILIARY	"auxiliary"
@ MSG_MAP_OVERRIDE	"override"
@ MSG_MAP_INTERPOSE	"interpose"
@ MSG_MAP_DYNSORT	"dynsort"
@ MSG_MAP_NODYNSORT	"nodynsort"

@ MSG_MAPKW_ALIGN		"ALIGN"
@ MSG_MAPKW_ALLOC		"ALLOC"
@ MSG_MAPKW_ALLOW		"ALLOW"
@ MSG_MAPKW_AMD64_LARGE		"AMD64_LARGE"
@ MSG_MAPKW_ASSIGN_SECTION	"ASSIGN_SECTION"
@ MSG_MAPKW_AUX			"AUXILIARY"
@ MSG_MAPKW_CAPABILITY		"CAPABILITY"
@ MSG_MAPKW_COMMON		"COMMON"
@ MSG_MAPKW_DATA		"DATA"
@ MSG_MAPKW_DEFAULT		"DEFAULT"
@ MSG_MAPKW_DEPEND_VERSIONS	"DEPEND_VERSIONS"
@ MSG_MAPKW_DIRECT		"DIRECT"
@ MSG_MAPKW_DISABLE		"DISABLE"
@ MSG_MAPKW_DYNSORT		"DYNSORT"
@ MSG_MAPKW_ELIMINATE		"ELIMINATE"
@ MSG_MAPKW_EXECUTE		"EXECUTE"
@ MSG_MAPKW_EXPORTED		"EXPORTED"
@ MSG_MAPKW_EXTERN		"EXTERN"
@ MSG_MAPKW_FILTER		"FILTER"
@ MSG_MAPKW_FILE_BASENAME	"FILE_BASENAME"
@ MSG_MAPKW_FILE_PATH		"FILE_PATH"
@ MSG_MAPKW_FILE_OBJNAME	"FILE_OBJNAME"
@ MSG_MAPKW_FUNCTION		"FUNCTION"
@ MSG_MAPKW_FLAGS		"FLAGS"
@ MSG_MAPKW_GLOBAL		"GLOBAL"
@ MSG_MAPKW_INTERPOSE		"INTERPOSE"
@ MSG_MAPKW_HIDDEN		"HIDDEN"
@ MSG_MAPKW_HDR_NOALLOC		"HDR_NOALLOC"
@ MSG_MAPKW_HW			"HW"
@ MSG_MAPKW_HW_1		"HW_1"
@ MSG_MAPKW_HW_2		"HW_2"
@ MSG_MAPKW_IS_NAME		"IS_NAME"
@ MSG_MAPKW_IS_ORDER		"IS_ORDER"
@ MSG_MAPKW_LOAD_SEGMENT	"LOAD_SEGMENT"
@ MSG_MAPKW_LOCAL		"LOCAL"
@ MSG_MAPKW_MACHINE		"MACHINE"
@ MSG_MAPKW_MAX_SIZE		"MAX_SIZE"
@ MSG_MAPKW_NOHDR		"NOHDR"
@ MSG_MAPKW_NODIRECT		"NODIRECT"
@ MSG_MAPKW_NODYNSORT		"NODYNSORT"
@ MSG_MAPKW_NOTE_SEGMENT	"NOTE_SEGMENT"
@ MSG_MAPKW_NULL_SEGMENT	"NULL_SEGMENT"
@ MSG_MAPKW_OS_ORDER		"OS_ORDER"
@ MSG_MAPKW_PADDR		"PADDR"
@ MSG_MAPKW_PARENT		"PARENT"
@ MSG_MAPKW_PHDR_ADD_NULL	"PHDR_ADD_NULL"
@ MSG_MAPKW_PLATFORM		"PLATFORM"
@ MSG_MAPKW_PROTECTED		"PROTECTED"
@ MSG_MAPKW_READ		"READ"
@ MSG_MAPKW_ROUND		"ROUND"
@ MSG_MAPKW_REQUIRE		"REQUIRE"
@ MSG_MAPKW_SEGMENT_ORDER	"SEGMENT_ORDER"
@ MSG_MAPKW_SF			"SF"
@ MSG_MAPKW_SF_1		"SF_1"
@ MSG_MAPKW_SINGLETON		"SINGLETON"
@ MSG_MAPKW_SIZE		"SIZE"
@ MSG_MAPKW_SIZE_SYMBOL		"SIZE_SYMBOL"
@ MSG_MAPKW_STACK		"STACK"
@ MSG_MAPKW_SYMBOL_SCOPE	"SYMBOL_SCOPE"
@ MSG_MAPKW_SYMBOL_VERSION	"SYMBOL_VERSION"
@ MSG_MAPKW_SYMBOLIC		"SYMBOLIC"
@ MSG_MAPKW_TYPE		"TYPE"
@ MSG_MAPKW_VADDR		"VADDR"
@ MSG_MAPKW_VALUE		"VALUE"
@ MSG_MAPKW_WRITE		"WRITE"


@ MSG_STR_DTRACE	"PT_SUNWDTRACE"
