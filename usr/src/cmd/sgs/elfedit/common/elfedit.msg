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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

@ _START_

# Message file for cmd/sgs/elfedit.

@ MSG_ID_ELFEDIT


# Usage Messages

@ MSG_USAGE_BRIEF	"usage: elfedit [-adrw] [-e cmd] [-L modpath] \
			 [-o style] [file] [outfile]\n"
@ MSG_USAGE_DETAIL1	"\t[-a]          Autoprint (show edit results)\n"
@ MSG_USAGE_DETAIL2	"\t[-d]          Issue messages describing internal \
			 operations\n"
@ MSG_USAGE_DETAIL3	"\t[-e cmd]      edit command\n"
@ MSG_USAGE_DETAIL4	"\t[-L modpath]  Set module path\n"
@ MSG_USAGE_DETAIL5	"\t[-o ostyle]   Output style (default|simple|num)\n"
@ MSG_USAGE_DETAIL6	"\t[-r]          Readonly session (outfile not \
			 allowed)\n"
@ MSG_USAGE_DETAIL_LAST	"\n\tExtensive help for edit commands is available.\n\
			 \tEnter 'help' at the elfedit prompt.\n"
@ MSG_USAGE_CMD		"usage: %s\n"


# sys:set option names

@ MSG_SYSSET_A		"autoprint flag"
@ MSG_SYSSET_D		"debug flag"


# Names of things we allocate dynamically

@ MSG_ALLOC_OBJSTATE	"object state"
@ MSG_ALLOC_SYMTABOS	"symbol table information buffer"
@ MSG_ALLOC_MODDEF	"module definition"
@ MSG_ALLOC_UCMD	"user command state"
@ MSG_ALLOC_UCMDSTR	"user command string buffer"
@ MSG_ALLOC_TOKBUF	"user command token buffer"
@ MSG_ALLOC_BATCHLST	"list of -e commands"
@ MSG_ALLOC_EXPATH	"expanded module search path"
@ MSG_ALLOC_PATHARR	"search path array"
@ MSG_ALLOC_HELPITEM	"help state"
@ MSG_ALLOC_SECMSGPRE	"section message prefix string"
@ MSG_ALLOC_ELFCONDESC	"ELF constant string descriptors"

# Format strings

@ MSG_FMT_BUILTIN	"<built in>"
@ MSG_FMT_UNKNOWN	"<unknown>"

# Debug messages

@ MSG_DEBUG_ADDDYNFLG	"[%d: %s][%d]: Set DF_1_EDITED flag\n"
@ MSG_DEBUG_SEEDYNFLG	"[%d: %s][%d]: Previously edited file \
			 (DF_1_EDITED flag is set) \n"
@ MSG_DEBUG_CMDALIAS	"Command %s:%s is an alias for %s:%s\n"
@ MSG_DEBUG_MODLOAD	"load module: %s: %s\n"
@ MSG_DEBUG_MODUNLOAD	"unload module: %s: %s\n"
@ MSG_DEBUG_CPFILE	"copied %s to output file: %s\n";
@ MSG_DEBUG_UNLINKFILE	"unlink unsaved output file: %s\n";
@ MSG_DEBUG_VERSION	"%d-bit version\n"
@ MSG_DEBUG_READONLY	"session is readonly\n";
@ MSG_DEBUG_NOFILE	"no ELF object specified. Limited functionality is \
			 available\n";
@ MSG_DEBUG_DIRTYEXIT	"discarding unsaved edits\n";
@ MSG_DEBUG_FNDSEC	"[%d: %s]: section\n"
@ MSG_DEBUG_FNDCAP	"[%d: %s]: capabilities section\n"
@ MSG_DEBUG_FNDDYN	"[%d: %s]: dynamic section\n"
@ MSG_DEBUG_FNDSTR	"[%d: %s][%d]: string: %s\n"
@ MSG_DEBUG_FNDSTRTAB	"[%d: %s]: string table section (SHT_STRTAB)\n"
@ MSG_DEBUG_FNDSTRTABFL	"[%d: %s]: string table section (SHF_STRINGS)\n"
@ MSG_DEBUG_FNDSYMTAB	"[%d: %s]: %s symbol table section\n"
@ MSG_DEBUG_FNDSYMINFO	"[%d: %s]: syminfo section\n"
@ MSG_DEBUG_FNDVERSYM	"[%d: %s]: versym section: [%d: %s]\n"
@ MSG_DEBUG_FNDXSHNDX	"[%d: %s]: extended section index section: [%d: %s]\n"
@ MSG_DEBUG_EXISTSTR	"[%d: %s][%d]: Found existing string in section: %s\n"
@ MSG_DEBUG_ADDSTR	"[%d: %s][%d]: Using %d/%d bytes from reserved area \
			 to add string: %s\n"
@ MSG_DEBUG_NULL2DYNFL1	"[%d: %s]: No existing flags1 field to modify. \
			 Will use extra DT_NULL in slot [%d] \n"
@ MSG_DEBUG_AUX_LINK	"[%d: %s]: Ignoring section: sh_link field references \
			 non-symbol table section: [%d]\n"
@ MSG_DEBUG_AUX_SIZE "[%d: %s][%d]: Ignoring section: Not enough elements \
			 for corresponding symbol table: [%d: %s][%d]\n"
@ MSG_DEBUG_EXECCMD	"command: %s\n"
@ MSG_DEBUG_SHNAM2NDX	"[%d: %s]: section name: %s\n"
@ MSG_DEBUG_SYMNAM2NDX	"[%d: %s][%d]: symbol \"%s\"\n"
@ MSG_DEBUG_INPLACEWARN	"warning: editing input file in place is not \
			 recommended: %s\n"
@ MSG_DEBUG_SHNDX_RANGE	"Specified section index [%d] is outside of valid \
			 of range for this object: 0-%d\n"
@ MSG_DEBUG_ARRCPY_1	"%s: copy array element [%d] to [%d]\n"
@ MSG_DEBUG_ARRCPY_N	"%s: copy array elements [%d-%d] to [%d-%d]\n"
@ MSG_DEBUG_ARRZERO_1	"%s[%d]: zero array element\n"
@ MSG_DEBUG_ARRZERO_N	"%s[%d-%d]: zero %d array elements\n"
@ MSG_DEBUG_ARRMOVE_1	"%s: moved element [%d] to [%d]\n"
@ MSG_DEBUG_ARRMOVE_N	"%s: moved %d elements from [%d-%d] to [%d-%d]\n"

# Errors

@ MSG_ERR_NOFILSYSONLY	"No ELF object specified. Only commands from \
			 module sys: are allowed: %s:%s\n"
@ MSG_ERR_BADOSTYLE	"Unrecognized output style \
			 (default|simple|num): %s\n"
@ MSG_ERR_BADCONST	"internal error: bad constant value in \
			 elfedit_const_to_atoui()\n"
@ MSG_ERR_BADGETVAL	"internal error: bad required value passed to \
			 elfedit_XXX_get_value()\n"
@ MSG_ERR_PATHTOOLONG	"path too long: %s/%s.so\n"
@ MSG_ERR_CNTDLOPEN	"unable to load module sharable object %s: %s\n"
@ MSG_ERR_CNTDLCLOSE	"unable to unload module sharable object %s: %s\n"
@ MSG_ERR_ESCEOL	"backslash escape cannot be used at end of line\n"
@ MSG_ERR_BADCESC	"unrecognized escape in double quoted token: \\%c\n"
@ MSG_ERR_UNTERMQUOTE	"command is missing closing quote: %c\n"
@ MSG_ERR_UNRECMOD	"no such module: %s\n"
@ MSG_ERR_UNRECCMD	"no such command: %s:%s\n"
@ MSG_ERR_SONOTMOD	"sharable object is not a valid elfedit module: %s\n"
@ MSG_ERR_CNTULSMOD	"cannot unload built in module: %s\n"
@ MSG_ERR_NULLPRICMDNAM	"module has empty string for primary command: %s\n"
@ MSG_ERR_BADMODLOAD	"elfedit module failed to initialize: %s\n"
@ MSG_ERR_BADMODNAME	"sharable library provides module '%s' rather \
			 than expected '%s': %s\n"
@ MSG_ERR_OPT_MODPRE	"command option name must start with \
			 a '-': %s : %s:%s %s\n"
@ MSG_ERR_OPT_MODLEN	"command option name must have at least one character: \
			 %s : %s:%s %s\n"
@ MSG_ERR_OPT_EXCMASKN0	"command option oa_excmask is non-zero when \
			 oa_idmask is zero: %s : %s:%s %s\n"
@ MSG_ERR_OPT_IDMASKPOW2 "command option oa_idmask must be 0 or power \
			 of 2: %s : %s:%s %s\n"
@ MSG_ERR_OPT_IDMASKUNIQ "command option oa_idmask must be 0 or must be unique \
			 value: %s : %s:%s %s\n"
@ MSG_ERR_ARG_MODPRE	"command argument name may not start with \
			 a '-': %s : %s:%s %s\n"
@ MSG_ERR_ARG_MODLEN	"command argument name must have at least one \
			 character: %s : %s:%s %s\n"
@ MSG_ERR_ARG_CMDOA_VAL	"command argument has ELFEDIT_CMDOA_F_VALUE set, \
			 which is only allowed for command \
			 options: %s : %s:%s %s\n"
@ MSG_ERR_ARG_MASKNOT0	"command argument oa_idmask and oa_excmask fields \
			 must both be set to 0: %s : %s:%s %s\n"
@ MSG_ERR_BADSTDOA	"internal error: argument or option uses \
			 ELFEDIT_CMDOA_F_VALUE incorrectly: %s : %s:%s\n"
@ MSG_ERR_CMDOA_VALNAM	"ELFEDIT_CMDOA_F_VALUE optarg has NULL \
			 oa_name: %s : %s:%s %s\n"
@ MSG_ERR_CMDOA_VALNOT0	"ELFEDIT_CMDOA_F_VALUE optarg has non-0 oa_help, \
			 oa_flags, oa_idmask or oa_excmask \
			 field: %s : %s:%s %s\n"
@ MSG_ERR_BADMODOPTVAL	"command option has ELFEDIT_CMDOA_F_VALUE bit set, \
			 but following value item is missing: %s : %s:%s %s\n"
@ MSG_ERR_CNTOPNFILE	"open failed: %s: %s\n"
@ MSG_ERR_CNTOPNDIR	"unable to read directory: %s: %s\n"
@ MSG_ERR_SIGACTION	"unable to set signal handler: %s\n"
@ MSG_ERR_NOAR		"unable to edit ELF archive: %s\n"
@ MSG_ERR_UNRECELFFILE	"unable to edit non-ELF file: %s\n"
@ MSG_ERR_BADELFCLASS	"unable to edit file with unknown ELFCLASS: %s\n"
@ MSG_ERR_MALLOC	"%s: malloc: %s\n"
@ MSG_ERR_LIBELF	"%s: %s failed: %s\n"
@ MSG_ERR_MODNOCMD	"module '%s' specified without a command\n"
@ MSG_ERR_CNTFORK	"unable to execute child process: %s\n"
@ MSG_ERR_CNTWAIT	"unable to wait for child process: %s\n"
@ MSG_ERR_CNTEXEC	"%sunable to exec %s: %s\n"
@ MSG_ERR_CNTSTAT	"unable to stat %s: %s\n"
@ MSG_ERR_CNTCHMOD	"unable to chmod %s: %s\n"
@ MSG_ERR_BADSECNDX	"Specified section index [%d] is outside valid \
			 range: 1-%d\n"
@ MSG_ERR_NOCAP		"ELF object does not have a capabilities section\n"
@ MSG_ERR_NODYN		"ELF object does not have a dynamic section\n"
@ MSG_ERR_NOSYM		"[%d: %s]: Symbol table does not contain symbol: %s\n"
@ MSG_ERR_NOSYMTAB	"symbol table section not found\n"
@ MSG_ERR_NOSYMINFO	"ELF object does not have a syminfo section\n"
@ MSG_ERR_NOTSYMTAB	"[%d: %s]: section is not a symbol table\n"
@ MSG_ERR_STRSHNDX	"string section index %d is outside expected \
			 range 1 - %d\n"
@ MSG_ERR_NOTSTRSH	"[%d: %s]: Section is not a string table as expected\n"
@ MSG_ERR_NOSTRPAD	"[%d: %s]: String table does not have room to add \
			 string\n"
@ MSG_ERR_BADSTROFF	"[%d: %s]: String offset [%d] is outside valid \
			 range: 0-%d\n"
@ MSG_ERR_NOVERSYMSEC	"[%d: %s]: symbol table does not have an associated \
			 versym section\n"
@ MSG_ERR_NOXSHSEC	"[%d: %s]: symbol table does not have an associated \
			 extended index section\n"
@ MSG_ERR_BADATOISTR	"not a valid numeric value: '%s'\n"
@ MSG_ERR_ATOIRANGE	"%s value is out of range [%lld - %lld]: %lld\n"
@ MSG_ERR_ATOUIRANGE	"%s value is out of range [%llu - %llu]: %llu\n"
@ MSG_ERR_BADPATHCODE	"Unrecognized code encountered in module \
			 search path: %%%c\n"
@ MSG_ERR_UNKNOWNSYSERR	"<unknown>"
@ MSG_ERR_PAGERFINI	"Error encountered closing pager process\n"
@ MSG_ERR_PRINTF	"Error encountered writing output\n"
@ MSG_ERR_FWRITE	"Error encountered writing output: %s\n"
@ MSG_ERR_MODNAMTOOLONG	"module name too long: %s\n"
@ MSG_ERR_CNTGETORIGIN	"Unable to determine elfedit $ORIGIN\n"
@ MSG_ERR_GLREAD	"error reading from stdin: %s\n"
@ MSG_ERR_READONLY	"Operation not allowed in readonly session\n"
@ MSG_ERR_NODIRTYQUIT	"Output ELF file has changes pending. Use 'write' \
			 to save them, or 'quit -f' to exit without saving\n"
@ MSG_ERR_NOSECNAM	"File does not contain section of name: %s\n"
@ MSG_ERR_NOSECTYP	"File does not contain section of type: %s\n"
@ MSG_ERR_ARRBNDS	"%s[%d]: attempt to access elements outside \
			 of valid of range for this section: 0-%d\n"
@ MSG_ERR_ARRMVOVERLAP	"%s: Array source [%d-%d] and destination \
			 [%d-%d] regions overlap\n"
@ MSG_ERR_BADOSABI	"Operation not supported by current OS ABI: %s\n";

# Format strings for sys:help
@ MSG_HLPFMT_MOD	"\nMODULE\n   %s - %s\n"
@ MSG_HLPFMT_NAME	"\nNAME\n   %s - %s\n"
@ MSG_HLPFMT_SYNOPSIS	"\nSYNOPSIS\n   %s\n"
@ MSG_HLPFMT_ALIASES	"\nALIASES\n"
@ MSG_HLPFMT_MODDEFCMD	"module default";
@ MSG_HLPFMT_DEFCMD	"\t\t(Default Command For Module)";
@ MSG_HLPFMT_DESC	"\nDESCRIPTION\n"
@ MSG_HLPFMT_ARGS	"\nARGUMENTS\n"
@ MSG_HLPFMT_OPT	"\nOPTIONS\n"
@ MSG_HLPFMT_MULTIEND	"[End: %s, Next: %s]\n"
@ MSG_HLPFMT_INFILE	"Input File:  %s\n"
@ MSG_HLPFMT_INFILERO	"Input File:  %s (readonly)\n"
@ MSG_HLPFMT_INFILENONE	"Input File: <not present>\n"
@ MSG_HLPFMT_OUTFILE	"Output File: %s\n"
@ MSG_HLPFMT_CNGPENDING	"    (changes pending)\n"
@ MSG_HLPFMT_VARHDR	"\nOptions:\n"
@ MSG_HLPFMT_AFLG	"    a (Autoprint):    %s\n"
@ MSG_HLPFMT_DFLG	"    d (Debug):        %s\n"
@ MSG_HLPFMT_OFLG	"    o (Output Style): %s\n"
@ MSG_HLPFMT_PATHHDR	"\nModule Load Path:\n"
@ MSG_HLPFMT_MODHDR	"\nCurrently Loaded Modules:\n"
@ MSG_HLPFMT_SUMSYNOPSIS	"\n           %s\n"


# Names we use when an ELF item lacks a name

@ MSG_UNKNOWNSECNAM	"<unknown section name>"
@ MSG_BADSYMOFFSETNAM	"<bad symbol name>"


# builtin sys: module description

@ MSG_MOD_SYS_DESC	"Built in elfedit commands"


# 1-line description strings for builtin commands.

@ MSG_SYS_DESC_HELP	"Display module information and/or command \
			 documentation"
@ MSG_SYS_DESC_LOAD	"Load module(s)"
@ MSG_SYS_DESC_SET	"Set elfedit options"
@ MSG_SYS_DESC_STATUS	"Session status (files, modules, options)"
@ MSG_SYS_DESC_QUIT	"Exit elfedit session"
@ MSG_SYS_DESC_UNLOAD	"Unload module(s)"
@ MSG_SYS_DESC_WRITE	"Flush any changes back to current ELF file"


# Command option description strings for builtin commands

@ MSG_SYS_OPTDESC_HELP_S	"\
   Generate a command synopsis rather than full command help.\n"

@ MSG_SYS_OPTDESC_LOAD_A	"\
   Load every module that can be found by following the module\n\
   load path.\n"
@ MSG_SYS_OPTDESC_QUIT_F	"\
   Exit the elfedit session without first requiring changes to\n\
   be saved. Any modifications made to the output file will be\n\
   quietly discarded, and will be lost."
@ MSG_SYS_OPTDESC_UNLOAD_A	"\
   Unload every currently loaded module. Loaded modules can be\n\
   displayed using the \"status\" command.\n"


# Command option description strings for builtin commands

@ MSG_ARGDESC_HELP_ARG		"\
   Items for which help is desired. Module names and/or command\n\
   names are allowed, as described above.\n"
@ MSG_ARGDESC_LOAD_MODNAME	"Name(s) of modules to be loaded.\n"
@ MSG_ARGDESC_SET_OPTION	"Name of option to be set.\n"
@ MSG_ARGDESC_SET_VALUE		"Value to be set for option.\n"
@ MSG_ARGDESC_UNLOAD_MODNAME	"Name(s) of modules to be loaded.\n"


# Help text for builtin commands.

@ MSG_SYS_HELP_HELP_NOARG	"   \
   Welcome to elfedit, a utility for examining and editing\n\
   ELF objects. This brief discussion will tell you the basics\n\
   you need to know in order to use the elfedit help facility.\n\
   With that, you will be able to find desired information about\n\
   elfedit and its available commands.\n\
   \n\
   To reach the point where you are reading this text, you entered\n\
   the elfedit command \"help\", without any arguments. Actually, you\n\
   may have entered any of the following:\n\
   \n\
   \t?, help, man, sys:?, sys:help, sys:man\n\
   \n\
   As we will see below, these are simply different names for the\n\
   help command.\n\
   \n\
   You use elfedit by issuing commands for it to execute.\n\
   The syntax is similar to that used by Unix command line\n\
   utilities, and follows the general form:\n\
   \n\
   \t> module:command [-opt]... arg...\n\
   \n\
   The '>' character is the elfedit prompt, and not part of the\n\
   command. We show elfedit commands with the prompt, but you\n\
   should not type the prompt in. elfedit supplies it to let\n\
   you know when it is expecting a command to process.\n\
   \n\
   As with a Unix utility, there are options (which start with a '-'\n\
   character) and plain arguments (which do not start with a '-').\n\
   The plain arguments follow the options. The options and plain\n\
   arguments differ from command to command. Each command sets its own\n\
   rules for whether it accepts options and arguments, as well as\n\
   which ones and how many. These details are found in the online\n\
   help that is available for each command. To learn more about\n\
   any command, use the help command:\n\
   \n\
   \t> help cmdname\n\
   \n\
   where 'cmdname' is the name of the command you are interested in.\n\
   help is simply an elfedit command, like any other. As such, you\n\
   can read the full documentation for help by entering the command:\n\
   \n\
   \t> help sys:help\n\
   \n\
   elfedit functionality is organized as \"modules\", which are\n\
   dynamically loadable ELF objects that contain related editing\n\
   commands. To refer to a command, you enter its module name,\n\
   a colon (:), and the command name, all as a single unit without\n\
   any intervening white-space. The 'sys' module is special: It is\n\
   a built in module that contains the core commands required for\n\
   elfedit to work. As a convenience, if you omit the module name\n\
   from a command, elfedit assumes that you are referring to the sys\n\
   module. This is why sys:help and help are really the same command,\n\
   and why we did not have to write the above help command as:\n\
   \n\
   \t> sys:help sys:help\n\
   \n\
   In fact, we could have written it even more simply, as:\n\
   \n\
   \t> help help\n\
   \n\
   To access a command from any module other than sys, you must\n\
   enter both the module and command names. This means that if\n\
   you write your own module, the module name needs to be unique,\n\
   but the command names it supplies can be the same names used by\n\
   other modules. For instance, most elfedit modules supply a command\n\
   named dump to display information about their part of the ELF \n\
   file in a style similar to that used by the Unix elfdump command.\n\
   Despite having the same name (dump), these are all distinct and\n\
   separate commands. elfedit uses the module/command pair to know\n\
   which one you mean.\n\
   \n\
   elfedit commands can sometimes have more than one name, or alias.\n\
   Usually, each command only has one name, but there are some\n\
   exceptions. For example, as we have already seen, sys:?, and \n\
   sys:man are aliases of sys:help. These are all common names\n\
   that different programs use to supply help. elfedit accepts all\n\
   of these names in the hope that a new user who doesn't know\n\
   elfedit yet will try one of them, and find this information.\n\
   \n\
   Most modules provide a \"default command\". This command will be\n\
   run if you provide only the module name. Most modules use this\n\
   feature to provide a shortcut for their \"dump\" command. For\n\
   instance, both of the following commands run dyn:dump:\n\
   \n\
   \t> dyn:\n\
   \t> dyn:dump\n\
   \n\
   Although the command name dump was not required, the colon\n\
   (:) character is. Without it, elfedit will think you mean the\n\
    command sys:dyn.\n\
   \n\
   Using the help command (sys:help), you can easily learn about\n\
   the other commands that are available. To see which modules\n\
   are available and a synopsis of the commands they provide:\n\
   \n\
   \t> help -s\n\
   \n\
   To see the full documentation for a command, you give the\n\
   name of the command to the help command as a plain argument.\n\
   As we saw above, this command will show you the detailed\n\
   documentation for the help command itself:\n\
   \n\
   \t> help help\n\
   \n\
   The arguments to help can also be module names, without the\n\
   command. In that case, output similar to that from the -s\n\
   option will be displayed for that module.\n\
   \n\
   If you are new to elfedit, we recommend that you start by learning\n\
   about the commands in the sys module. This will provide you with\n\
   such basic knowledge as how to find out the status of your session\n\
   (sys:status) or how to exit the elfedit program (sys:quit). Once\n\
   you understand the basic commands, you can branch out and learn\n\
   about the available modules and commands and how they can be used\n\
   to edit ELF files.\n"

@ MSG_SYS_HELP_HELP	"   \
   The sys:help command provides information on elfedit modules\n\
   and commands:\n\
   \n\
   o\tIf called with command names as arguments, documentation\n\
   \tfor each given command is displayed. If the -s option is\n\
   \tspecified, a basic synopsis for the command is given.\n\
   \tOtherwise, the full documentation is shown.\n\
   \n\
   o\tIf called with module names as arguments, the name and\n\
   \tpurpose of each module is shown, along with a brief synopsis\n\
   \tof the commands the module provides.\n\
   \n\
   o\tIf called with the -s option, and no arguments, a brief\n\
   \tsynopsis of every command is shown, organized by module,\n\
   \tfor every module visible from the module load path.\n\
   \n\
   o\tIf called with no arguments, and the -s option is not\n\
   \tused, a brief welcome message is displayed, giving basic\n\
   \tinformation on elfedit operation and the use of the\n\
   \thelp command.\n"

@ MSG_SYS_HELP_LOAD	"\
   The sys:load command is used to explicitly load elfedit modules.\n\
   \n\
   Most of the functionality available in elfedit is not built\n\
   into the elfedit program directly. Instead, functionality\n\
   is contained in \"modules\", which are implemented as dynamically\n\
   loadable ELF sharable objects. This design allows for easy\n\
   extensibility of elfedit's abilities, and it is also efficient,\n\
   since it allows elfedit to be a relatively small program.\n\
   \n\
   elfedit will automatically load a module under the following\n\
   circumstances:\n\
   \n   \
   o\tA command from the module needs to be run.\n\
   \n   \
   o\tTo display help information about the module or a command\n\
   \tfound in the module.\n\
   \n   \
   o\tTo perform command completion in an interactive session.\n\
   \tCommand completion can cause many, or all modules visible\n\
   \tin the module path to be loaded.\n\
   \n\
   There is usually little need for explicit module loading.\n\
   It is usually best to allow elfedit to load modules as they\n\
   are needed.\n"

@ MSG_SYS_HELP_SET	"\
   Set options that control how elfedit works.\n\
   \n\
   Most variables accept boolean (true/false) values. The sys:set\n\
   command accepts any of the following as a boolean value:\n\
   0/1, true/false, t/f, yes/no, y/n, on/off.\n\
   \n\
   The variables, and their allowed values, are as follows:\n\
   \n\
   a\tAutoprint [boolean]\n\
   \tWhen autoprint is active, elfedit automatically displays\n\
   \tthe results of any edits after carrying them out. By default,\n\
   \tautoprint is on for interactive sessions, and false for\n\
   \tsessions where the input is not a tty. The elfedit -a option\n\
   \tcan be used to enable autoprint at session start.\n\
   \n\
   d\tDebug [boolean]\n\
   \tWhen enabled, elfedit issues detailed messages showing\n\
   \twhere ELF data is being accessed, and how specific edits\n\
   \tare being carried out. Debug mode is off by default. The\n\
   \telfedit -d option can be used to enable debug mode at\n\
   \tsession start.\n\
   \n\
   o\tOutput Style [default, simple, num]\n\
   \tControls the format in which elfedit prints ELF data:\n\
   \n\
   \tdefault\n\
   \tInformation is displayed in a style similar to that used by\n\
   \tthe elfdump utility. This style is best for interactive use.\n\
   \n\
   \tsimple\n\
   \tData is displayed in a simple format, without extraneous\n\
   \tinformation or formatting. Strings are displayed as is.\n\
   \tNumbers are displayed as symbolic constants when possible,\n\
   \tand in integer form otherwise.\n\
   \n\
   \tnum\n\
   \tInteger values are always shown in integer form. Strings\n\
   \tare shown as the integer offset into the containing string\n\
   \ttable.\n"

@ MSG_SYS_HELP_STATUS	"\
   The status of the current elfedit session is shown:\n\
   \n\
   o\tInput and output files\n\
   \n\
   o\tCurrent settings of the elfedit options (See 'help set'\n\
   \tfor more information on elfedit options)\n\
   \n\
   o\tModule load path\n\
   \n\
   o\tLoaded modules and the paths of the sharable objects\n\
   \tthat provide them\n"

@ MSG_SYS_HELP_QUIT	"\
   Exits the elfedit session.\n\
   \n\
   elfedit will normally refuse to exit a non-readonly session\n\
   while there are unsaved edits pending. The sys:write command\n\
   can be used to save such edits, or the -f option can be used to\n\
   discard pending edits and exit immediately.\n"

@ MSG_SYS_HELP_UNLOAD	"\
   The sys:unload command is used to explicitly unload elfedit modules.\n\
   \n\
   There is usually little need to explicitly unload modules.\n\
   \n\
   The description of the sys:load command discusses module loading\n\
   in more detail.\n"

@ MSG_SYS_HELP_WRITE	"\
   Writes all pending edits to the output file. Until this is done,\n\
   the edits are not permanent, and can be abandoned by exiting the\n\
   session using the -f option to sys:quit. Once sys:write is used,\n\
   these changes become permanent.\n"



# Command option description strings for inheritable option strings

@ MSG_STDOA_OPTDESC_AND	"\
   The new value should be bitwised AND'd against the\n\
   existing value.\n"

@ MSG_STDOA_OPTDESC_CMP	"\
   The new value should be bitwise complemented\n\
   (1 values set to 0, and 0 values set to 1) before being\n\
   applied to the existing value.\n"

@ MSG_STDOA_OPTDESC_O "\
   Overrides the global output style (as set via the sys:set\n\
   command) for the duration of the call to this command.\n\
   The valid values for the outstyle argument are: default,\n\
   simple, or num.\n\
   \n\
   Output styles are described in more detail in the documentation\n\
   for the sys:set command.\n"

@ MSG_STDOA_OPTDESC_OR	"\
   The new value should be bitwised OR'd against the\n\
   existing value.\n"




@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

# Names of libelf functions

@ MSG_ELF_BEGIN		"elf_begin"
@ MSG_ELF_GETEHDR	"elf_getehdr"
@ MSG_ELF_GETDATA	"elf_getdata"
@ MSG_ELF_GETPHDRNUM	"elf_getphdrnum"
@ MSG_ELF_GETPHDR	"elf_getphdr"
@ MSG_ELF_GETSCN	"elf_getscn"
@ MSG_ELF_GETSHDR	"elf_getshdr"
@ MSG_ELF_GETSHDRNUM	"elf_getshdrnum"
@ MSG_ELF_GETSHDRSTRNDX	"elf_getshdrstrndx"
@ MSG_ELF_UPDATE	"elf_update"


# Names of sh_type SHT_* type constants

@ MSG_SHT_SYMTAB		"SHT_SYMTAB"		# 2
@ MSG_SHT_SYMTAB_ALT1		"symtab"
@ MSG_SHT_STRTAB		"SHT_STRTAB"		# 3
@ MSG_SHT_STRTAB_ALT1		"strtab"
@ MSG_SHT_DYNSYM		"SHT_DYNSYM"		# 11
@ MSG_SHT_DYNSYM_ALT1		"dynsym"
@ MSG_SHT_SUNW_LDYNSYM		"SHT_SUNW_LDYNSYM"	# 0x6ffffff3
@ MSG_SHT_SUNW_LDYNSYM_ALT1	"sunw_ldynsym"


# ISA strings. These could be separated into separate message modules
# on a per-platform basis if their size became large, but this is probably
# cheaper for this small set of strings.
@ MSG_ISA_SPARC_32	"sparc"
@ MSG_ISA_SPARC_64	"sparcv9"
@ MSG_ISA_X86_32	"i386"
@ MSG_ISA_X86_64	"amd64"

# Format strings

@ MSG_FMT_BLDPATH	"%s/%s"
@ MSG_FMT_BLDSOPATH	"%s/%s.so"
@ MSG_FMT_MODCMD	"%s:%s"
@ MSG_FMT_SYSCMD	"[sys]:%s"
@ MSG_FMT_WORDVAL	"%u"
@ MSG_FMT_WRAPUSAGE	"\n%s"
@ MSG_FMT_SECMSGPRE	"[%d: %s]"

# Miscellaneous clutter

@ MSG_STR_NULL		""
@ MSG_STR_ARG		"arg"
@ MSG_STR_SP_BAR_SP	" | "
@ MSG_STR_ELIPSES	"..."
@ MSG_STR_OPTIONS	"ade:L:o:r"
@ MSG_STR_ELFEDIT	"elfedit: "
@ MSG_STR_PROMPT	"> "
@ MSG_STR_NL		"\n"
@ MSG_STR_TAB		"\t"
@ MSG_STR_BINCP		"/bin/cp"
@ MSG_STR_BINMORE	"/bin/more"
@ MSG_STR_PAGER		"PAGER"
@ MSG_STR_ELFEDITINIT32	"elfedit32_init"
@ MSG_STR_ELFEDITINIT64	"elfedit64_init"
@ MSG_STR_HLPINDENT	"   ";
@ MSG_STR_HLPUSEINDENT	"        ";
@ MSG_STR_HLPSUMINDENT	"              ";
@ MSG_STR_HLPOPTARG	"%s";
@ MSG_STR_HLPOPTARG2	"%s %s";
@ MSG_STR_ENVVAR	"ELFEDIT_PATH"
@ MSG_STR_MODPATH	"%r/usr/lib/elfedit/%I"
@ MSG_STR_EMPTY		""
@ MSG_STR_DOT		"."
@ MSG_STR_COLON		":"
@ MSG_STR_SPACE		" "
@ MSG_STR_COMMA_SP	", "
@ MSG_STR_CPAREN	")"
@ MSG_STR_DOTSO		".so"
@ MSG_STR_MINUS_MINUS	"--"
@ MSG_STR_MINUS_A	"-a"
@ MSG_STR_MINUS_AND	"-and"
@ MSG_STR_MINUS_CMP	"-cmp"
@ MSG_STR_MINUS_F	"-f"
@ MSG_STR_MINUS_S	"-s"
@ MSG_STR_MINUS_O	"-o"
@ MSG_STR_MINUS_OR	"-or"
@ MSG_STR_MODNAME	"modname"
@ MSG_STR_TRUE		"true"
@ MSG_STR_FALSE		"false"
@ MSG_STR_ON		"on"
@ MSG_STR_OFF		"off"
@ MSG_STR_YES		"yes"
@ MSG_STR_NO		"no"
@ MSG_STR_0		"0"
@ MSG_STR_1		"1"
@ MSG_STR_A		"a"
@ MSG_STR_D		"d"
@ MSG_STR_F		"f"
@ MSG_STR_N		"n"
@ MSG_STR_O		"o"
@ MSG_STR_OPTION	"option"
@ MSG_STR_T		"t"
@ MSG_STR_VALUE		"value"
@ MSG_STR_W		"w"
@ MSG_STR_Y		"y"
@ MSG_STR_DEFAULT		"default"
@ MSG_STR_MINUS_O_DEFAULT	"-odefault"
@ MSG_STR_SIMPLE		"simple"
@ MSG_STR_MINUS_O_SIMPLE	"-osimple"
@ MSG_STR_NUM			"num"
@ MSG_STR_MINUS_O_NUM		"-onum"
@ MSG_STR_OUTSTYLE	"outstyle"


# Format strings for sys:help
@ MSG_HLPFMT_MULTIHDR	"::::::::::::::\n%s\n::::::::::::::\n"
@ MSG_HLPFMT_NAMDSCCOL	"   %-15s%s\n"
@ MSG_HLPFMT_NAMDSCHDR	"%s - %s\n"
@ MSG_HLPFMT_NAMSUMHDR	"      %s - %s\n"
@ MSG_HLPFMT_PATHELT	"       %s\n"
@ MSG_HLPFMT_MULTNAM	"%s ("

# name of builtin sys: module

@ MSG_MOD_SYS		"sys"

# Names of sys: builtin commands
@ MSG_SYS_CMD_HELP	"help"
@ MSG_SYS_CMD_HELP_A1	"?"
@ MSG_SYS_CMD_HELP_A2	"man"
@ MSG_SYS_CMD_LOAD	"load"
@ MSG_SYS_CMD_QUIT	"quit"
@ MSG_SYS_CMD_QUIT_A1	"exit"
@ MSG_SYS_CMD_QUIT_A2	"bye"
@ MSG_SYS_CMD_SET	"set"
@ MSG_SYS_CMD_STATUS	"status"
@ MSG_SYS_CMD_UNLOAD	"unload"
@ MSG_SYS_CMD_WRITE	"write"
@ MSG_SYS_CMD_WRITE_A1	"flush"
@ MSG_SYS_CMD_WRITE_A2	"save"
