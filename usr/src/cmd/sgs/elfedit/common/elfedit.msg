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
@ MSG_DEBUG_NOFILE	"no ELF object specified. Limited functionalty is available\n";
@ MSG_DEBUG_DIRTYEXIT	"discarding unsaved edits\n";
@ MSG_DEBUG_FNDCAP	"[%d: %s]: capabilities section\n"
@ MSG_DEBUG_FNDDYN	"[%d: %s]: dynamic section\n"
@ MSG_DEBUG_FNDSTR	"[%d: %s][%d]: string: %s\n"
@ MSG_DEBUG_FNDSTRTAB	"[%d: %s]: string table section\n"
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
			 range %d - %d\n"
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
   Most variables accept boolen (true/false) values. The sys:set\n\
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
@ MSG_ELF_GETPHNUM	"elf_getphnum"
@ MSG_ELF_GETPHDR	"elf_getphdr"
@ MSG_ELF_GETSCN	"elf_getscn"
@ MSG_ELF_GETSHDR	"elf_getshdr"
@ MSG_ELF_GETSHNUM	"elf_getshnum"
@ MSG_ELF_GETSHSTRNDX	"elf_getshstrndx"
@ MSG_ELF_UPDATE	"elf_update"


# Names of special section indexes

@ MSG_SHN_UNDEF			"SHN_UNDEF"		# 0
@ MSG_SHN_UNDEF_ALT1		"undef"
@ MSG_SHN_SUNW_IGNORE		"SHN_SUNW_IGNORE"	# 0xff3f
@ MSG_SHN_SUNW_IGNORE_ALT1	"sunw_ignore"
@ MSG_SHN_BEFORE		"SHN_BEFORE"		# 0xff00
@ MSG_SHN_BEFORE_ALT1		"before"
@ MSG_SHN_AFTER			"SHN_AFTER"		# 0xff01
@ MSG_SHN_AFTER_ALT1		"after"
@ MSG_SHN_AMD64_LCOMMON		"SHN_AMD64_LCOMMON"	# 0xff02
@ MSG_SHN_AMD64_LCOMMON_ALT1	"amd64_lcommon"
@ MSG_SHN_ABS			"SHN_ABS"		# 0xfff1
@ MSG_SHN_ABS_ALT1		"abs"
@ MSG_SHN_COMMON		"SHN_COMMON"		# 0xfff2
@ MSG_SHN_COMMON_ALT1		"common"
@ MSG_SHN_XINDEX		"SHN_XINDEX"		# 0xffff
@ MSG_SHN_XINDEX_ALT1		"xindex"


# Names of sh_type SHT_* type constants

@ MSG_SHT_NULL			"SHT_NULL"		# 0
@ MSG_SHT_NULL_ALT1		"null"
@ MSG_SHT_PROGBITS		"SHT_PROGBITS"		# 1
@ MSG_SHT_PROGBITS_ALT1		"progbits"
@ MSG_SHT_SYMTAB		"SHT_SYMTAB"		# 2
@ MSG_SHT_SYMTAB_ALT1		"symtab"
@ MSG_SHT_STRTAB		"SHT_STRTAB"		# 3
@ MSG_SHT_STRTAB_ALT1		"strtab"
@ MSG_SHT_RELA			"SHT_RELA"		# 4
@ MSG_SHT_RELA_ALT1		"rela"
@ MSG_SHT_HASH			"SHT_HASH"		# 5
@ MSG_SHT_HASH_ALT1		"hash"
@ MSG_SHT_DYNAMIC		"SHT_DYNAMIC"		# 6
@ MSG_SHT_DYNAMIC_ALT1		"dynamic"
@ MSG_SHT_NOTE			"SHT_NOTE"		# 7
@ MSG_SHT_NOTE_ALT1		"note"
@ MSG_SHT_NOBITS		"SHT_NOBITS"		# 8
@ MSG_SHT_NOBITS_ALT1		"nobits"
@ MSG_SHT_REL			"SHT_REL"		# 9
@ MSG_SHT_REL_ALT1		"rel"
@ MSG_SHT_SHLIB			"SHT_SHLIB"		# 10
@ MSG_SHT_SHLIB_ALT1		"shlib"
@ MSG_SHT_DYNSYM		"SHT_DYNSYM"		# 11
@ MSG_SHT_DYNSYM_ALT1		"dynsym"
@ MSG_SHT_INIT_ARRAY		"SHT_INIT_ARRAY"	# 14
@ MSG_SHT_INIT_ARRAY_ALT1	"init_array"
@ MSG_SHT_FINI_ARRAY		"SHT_FINI_ARRAY"	# 15
@ MSG_SHT_FINI_ARRAY_ALT1	"fini_array"
@ MSG_SHT_PREINIT_ARRAY		"SHT_PREINIT_ARRAY"	# 16
@ MSG_SHT_PREINIT_ARRAY_ALT1	"preinit_ARRAY"
@ MSG_SHT_GROUP			"SHT_GROUP"		# 17
@ MSG_SHT_GROUP_ALT1		"group"
@ MSG_SHT_SYMTAB_SHNDX		"SHT_SYMTAB_SHNDX"	# 18
@ MSG_SHT_SYMTAB_SHNDX_ALT1	"symtab_shndx"
@ MSG_SHT_SUNW_SYMSORT		"SHT_SUNW_symsort"	# 0x6ffffff1
@ MSG_SHT_SUNW_SYMSORT_ALT1	"sunw_symsort"
@ MSG_SHT_SUNW_TLSSORT		"SHT_SUNW_tlssort"	# 0x6ffffff2
@ MSG_SHT_SUNW_TLSSORT_ALT1	"sunw_tlssort"
@ MSG_SHT_SUNW_LDYNSYM		"SHT_SUNW_LDYNSYM"	# 0x6ffffff3
@ MSG_SHT_SUNW_LDYNSYM_ALT1	"sunw_ldynsym"
@ MSG_SHT_SUNW_DOF		"SHT_SUNW_dof"		# 0x6ffffff4
@ MSG_SHT_SUNW_DOF_ALT1		"sunw_dof"
@ MSG_SHT_SUNW_CAP		"SHT_SUNW_cap"		# 0x6ffffff5
@ MSG_SHT_SUNW_CAP_ALT1		"sunw_cap"
@ MSG_SHT_SUNW_SIGNATURE	"SHT_SUNW_SIGNATURE"	# 0x6ffffff6
@ MSG_SHT_SUNW_SIGNATURE_ALT1	"sunw_signature"
@ MSG_SHT_SUNW_ANNOTATE		"SHT_SUNW_ANNOTATE"	# 0x6ffffff7
@ MSG_SHT_SUNW_ANNOTATE_ALT1	"sunw_annotate"
@ MSG_SHT_SUNW_DEBUGSTR		"SHT_SUNW_DEBUGSTR"	# 0x6ffffff8
@ MSG_SHT_SUNW_DEBUGSTR_ALT1	"sunw_debugstr"
@ MSG_SHT_SUNW_DEBUG		"SHT_SUNW_DEBUG"	# 0x6ffffff9
@ MSG_SHT_SUNW_DEBUG_ALT1	"sunw_debug"
@ MSG_SHT_SUNW_MOVE		"SHT_SUNW_move"		# 0x6ffffffa
@ MSG_SHT_SUNW_MOVE_ALT1	"sunw_move"
@ MSG_SHT_SUNW_COMDAT		"SHT_SUNW_COMDAT"	# 0x6ffffffb
@ MSG_SHT_SUNW_COMDAT_ALT1	"sunw_comdat"
@ MSG_SHT_SUNW_SYMINFO		"SHT_SUNW_syminfo"	# 0x6ffffffc
@ MSG_SHT_SUNW_SYMINFO_ALT1	"sunw_syminfo"
@ MSG_SHT_SUNW_VERDEF		"SHT_SUNW_verdef"	# 0x6ffffffd
@ MSG_SHT_SUNW_VERDEF_ALT1	"sunw_verdef"
@ MSG_SHT_GNU_VERDEF		"SHT_GNU_verdef"	# 0x6ffffffd
@ MSG_SHT_GNU_VERDEF_ALT1	"gnu_verdef"
@ MSG_SHT_SUNW_VERNEED		"SHT_SUNW_verneed"	# 0x6ffffffe
@ MSG_SHT_SUNW_VERNEED_ALT1	"sunw_verneed"
@ MSG_SHT_GNU_VERNEED		"SHT_GNU_verneed"	# 0x6ffffffe
@ MSG_SHT_GNU_VERNEED_ALT1	"gnu_verneed"
@ MSG_SHT_SUNW_VERSYM		"SHT_SUNW_versym"	# 0x6fffffff
@ MSG_SHT_SUNW_VERSYM_ALT1	"sunw_versym"
@ MSG_SHT_GNU_VERSYM		"SHT_GNU_versym"	# 0x6fffffff
@ MSG_SHT_GNU_VERSYM_ALT1	"gnu_versym"
@ MSG_SHT_SPARC_GOTDATA		"SHT_SPARC_GOTDATA"	# 0x7000000
@ MSG_SHT_SPARC_GOTDATA_ALT1	"sparc_gotdata"
@ MSG_SHT_AMD64_UNWIND		"SHT_AMD64_UNWIND"	# 0x7000000
@ MSG_SHT_AMD64_UNWIND_ALT1	"amd64_unwind"


# Names of dynamic section entry tags

@ MSG_DT_NULL			"DT_NULL"		# 0
@ MSG_DT_NULL_ALT1		"null"
@ MSG_DT_NEEDED			"DT_NEEDED"		# 1
@ MSG_DT_NEEDED_ALT1		"needed"
@ MSG_DT_PLTRELSZ		"DT_PLTRELSZ"		# 2
@ MSG_DT_PLTRELSZ_ALT1		"pltrelsz"
@ MSG_DT_PLTGOT			"DT_PLTGOT"		# 3
@ MSG_DT_PLTGOT_ALT1		"pltgot"
@ MSG_DT_HASH			"DT_HASH"		# 4
@ MSG_DT_HASH_ALT1		"hash"
@ MSG_DT_STRTAB			"DT_STRTAB"		# 5
@ MSG_DT_STRTAB_ALT1		"strtab"
@ MSG_DT_SYMTAB			"DT_SYMTAB"		# 6
@ MSG_DT_SYMTAB_ALT1		"symtab"
@ MSG_DT_RELA			"DT_RELA"		# 7
@ MSG_DT_RELA_ALT1		"rela"
@ MSG_DT_RELASZ			"DT_RELASZ"		# 8
@ MSG_DT_RELASZ_ALT1		"relasz"
@ MSG_DT_RELAENT		"DT_RELAENT"		# 9
@ MSG_DT_RELAENT_ALT1		"relaent"
@ MSG_DT_STRSZ			"DT_STRSZ"		# 10
@ MSG_DT_STRSZ_ALT1		"strsz"
@ MSG_DT_SYMENT			"DT_SYMENT"		# 11
@ MSG_DT_SYMENT_ALT1		"syment"
@ MSG_DT_INIT			"DT_INIT"		# 12
@ MSG_DT_INIT_ALT1		"init"
@ MSG_DT_FINI			"DT_FINI"		# 13
@ MSG_DT_FINI_ALT1		"fini"
@ MSG_DT_SONAME			"DT_SONAME"		# 14
@ MSG_DT_SONAME_ALT1		"soname"
@ MSG_DT_RPATH			"DT_RPATH"		# 15
@ MSG_DT_RPATH_ALT1		"rpath"
@ MSG_DT_SYMBOLIC		"DT_SYMBOLIC"		# 16
@ MSG_DT_SYMBOLIC_ALT1		"symbolic"
@ MSG_DT_REL			"DT_REL"		# 17
@ MSG_DT_REL_ALT1		"rel"
@ MSG_DT_RELSZ			"DT_RELSZ"		# 18
@ MSG_DT_RELSZ_ALT1		"relsz"
@ MSG_DT_RELENT			"DT_RELENT"		# 19
@ MSG_DT_RELENT_ALT1		"relent"
@ MSG_DT_PLTREL			"DT_PLTREL"		# 20
@ MSG_DT_PLTREL_ALT1		"pltrel"
@ MSG_DT_DEBUG			"DT_DEBUG"		# 21
@ MSG_DT_DEBUG_ALT1		"debug"
@ MSG_DT_TEXTREL		"DT_TEXTREL"		# 22
@ MSG_DT_TEXTREL_ALT1		"textrel"
@ MSG_DT_JMPREL			"DT_JMPREL"		# 23
@ MSG_DT_JMPREL_ALT1		"jmprel"
@ MSG_DT_BIND_NOW		"DT_BIND_NOW"		# 24
@ MSG_DT_BIND_NOW_ALT1		"bind_now"
@ MSG_DT_INIT_ARRAY		"DT_INIT_ARRAY"		# 25
@ MSG_DT_INIT_ARRAY_ALT1	"init_array"
@ MSG_DT_FINI_ARRAY		"DT_FINI_ARRAY"		# 26
@ MSG_DT_FINI_ARRAY_ALT1	"fini_array"
@ MSG_DT_INIT_ARRAYSZ		"DT_INIT_ARRAYSZ"	# 27
@ MSG_DT_INIT_ARRAYSZ_ALT1	"init_arraysz"
@ MSG_DT_FINI_ARRAYSZ		"DT_FINI_ARRAYSZ"	# 28
@ MSG_DT_FINI_ARRAYSZ_ALT1	"fini_arraysz"
@ MSG_DT_RUNPATH		"DT_RUNPATH"		# 29
@ MSG_DT_RUNPATH_ALT1		"runpath"
@ MSG_DT_FLAGS			"DT_FLAGS"		# 30
@ MSG_DT_FLAGS_ALT1		"flags"
@ MSG_DT_PREINIT_ARRAY		"DT_PREINIT_ARRAY"	# 32
@ MSG_DT_PREINIT_ARRAY_ALT1	"preinit_array"
@ MSG_DT_PREINIT_ARRAYSZ	"DT_PREINIT_ARRAYSZ"	# 33
@ MSG_DT_PREINIT_ARRAYSZ_ALT1	"preinit_arraysz"
@ MSG_DT_SUNW_AUXILIARY		"DT_SUNW_AUXILIARY"	# 0x6000000d
@ MSG_DT_SUNW_AUXILIARY_ALT1	"sunw_auxiliary"
@ MSG_DT_SUNW_RTLDINF		"DT_SUNW_RTLDINF"	# 0x6000000e
@ MSG_DT_SUNW_RTLDINF_ALT1	"sunw_rtldinf"
@ MSG_DT_SUNW_FILTER		"DT_SUNW_FILTER"	# 0x6000000f
@ MSG_DT_SUNW_FILTER_ALT1	"sunw_filter"
@ MSG_DT_SUNW_CAP		"DT_SUNW_CAP"		# 0x60000010
@ MSG_DT_SUNW_CAP_ALT1		"sunw_cap"
@ MSG_DT_SUNW_SYMTAB		"DT_SUNW_SYMTAB"	# 0x60000011
@ MSG_DT_SUNW_SYMTAB_ALT1	"sunw_symtab"
@ MSG_DT_SUNW_SYMSZ		"DT_SUNW_SYMSZ"		# 0x60000012
@ MSG_DT_SUNW_SYMSZ_ALT1	"sunw_symsz"
@ MSG_DT_SUNW_SORTENT		"DT_SUNW_SORTENT"	# 0x60000013
@ MSG_DT_SUNW_SORTENT_ALT1	"sunw_sortent"
@ MSG_DT_SUNW_SYMSORT		"DT_SUNW_SYMSORT"	# 0x60000014
@ MSG_DT_SUNW_SYMSORT_ALT1	"sunw_symsort"
@ MSG_DT_SUNW_SYMSORTSZ		"DT_SUNW_SYMSORTSZ"	# 0x60000015
@ MSG_DT_SUNW_SYMSORTSZ_ALT1	"sunw_symsortsz"
@ MSG_DT_SUNW_TLSSORT		"DT_SUNW_TLSSORT"	# 0x60000016
@ MSG_DT_SUNW_TLSSORT_ALT1	"sunw_tlssort"
@ MSG_DT_SUNW_TLSSORTSZ		"DT_SUNW_TLSSORTSZ"	# 0x60000017
@ MSG_DT_SUNW_TLSSORTSZ_ALT1	"sunw_tlssortsz"
@ MSG_DT_SUNW_STRPAD		"DT_SUNW_STRPAD"	# 0x60000019
@ MSG_DT_SUNW_STRPAD_ALT1	"sunw_strpad"
@ MSG_DT_SPARC_REGISTER		"DT_SPARC_REGISTER"	# 0x70000001
@ MSG_DT_SPARC_REGISTER_ALT1	"sparc_register"
@ MSG_DT_DEPRECATED_SPARC_REGISTER "DT_DEPRECATED_SPARC_REGISTER" # 0x7000001
@ MSG_DT_DEPRECATED_SPARC_REGISTER_ALT1 "deprecated_sparc_register"
@ MSG_DT_CHECKSUM		"DT_CHECKSUM"		# 0x6ffffdf8
@ MSG_DT_CHECKSUM_ALT1		"checksum"
@ MSG_DT_PLTPADSZ		"DT_PLTPADSZ"		# 0x6ffffdf9
@ MSG_DT_PLTPADSZ_ALT1		"pltpadsz"
@ MSG_DT_MOVEENT		"DT_MOVEENT"		# 0x6ffffdfa
@ MSG_DT_MOVEENT_ALT1		"moveent"
@ MSG_DT_MOVESZ			"DT_MOVESZ"		# 0x6ffffdfb
@ MSG_DT_MOVESZ_ALT1		"movesz"
@ MSG_DT_FEATURE_1		"DT_FEATURE_1"		# 0x6ffffdfc
@ MSG_DT_FEATURE_1_ALT1		"feature_1"
@ MSG_DT_POSFLAG_1		"DT_POSFLAG_1"		# 0x6ffffdfd
@ MSG_DT_POSFLAG_1_ALT1		"posflag_1"
@ MSG_DT_SYMINSZ		"DT_SYMINSZ"		# 0x6ffffdfe
@ MSG_DT_SYMINSZ_ALT1		"syminsz"
@ MSG_DT_SYMINENT		"DT_SYMINENT"		# 0x6ffffdff
@ MSG_DT_SYMINENT_ALT1		"syminent"
@ MSG_DT_CONFIG			"DT_CONFIG"		# 0x6ffffefa
@ MSG_DT_CONFIG_ALT1		"config"
@ MSG_DT_DEPAUDIT		"DT_DEPAUDIT"		# 0x6ffffefb
@ MSG_DT_DEPAUDIT_ALT1		"depaudit"
@ MSG_DT_AUDIT			"DT_AUDIT"		# 0x6ffffefc
@ MSG_DT_AUDIT_ALT1		"audit"
@ MSG_DT_PLTPAD			"DT_PLTPAD"		# 0x6ffffefd
@ MSG_DT_PLTPAD_ALT1		"pltpad"
@ MSG_DT_MOVETAB		"DT_MOVETAB"		# 0x6ffffefe
@ MSG_DT_MOVETAB_ALT1		"movetab"
@ MSG_DT_SYMINFO		"DT_SYMINFO"		# 0x6ffffeff
@ MSG_DT_SYMINFO_ALT1		"syminfo"
@ MSG_DT_VERSYM			"DT_VERSYM"		# 0x6ffffff0
@ MSG_DT_VERSYM_ALT1		"versym"
@ MSG_DT_RELACOUNT		"DT_RELACOUNT"		# 0x6ffffff9
@ MSG_DT_RELACOUNT_ALT1		"relacount"
@ MSG_DT_RELCOUNT		"DT_RELCOUNT"		# 0x6ffffffa
@ MSG_DT_RELCOUNT_ALT1		"relcount"
@ MSG_DT_FLAGS_1		"DT_FLAGS_1"		# 0x6ffffffb
@ MSG_DT_FLAGS_1_ALT1		"flags_1"
@ MSG_DT_VERDEF			"DT_VERDEF"		# 0x6ffffffc
@ MSG_DT_VERDEF_ALT1		"verdef"
@ MSG_DT_VERDEFNUM		"DT_VERDEFNUM"		# 0x6ffffffd
@ MSG_DT_VERDEFNUM_ALT1		"verdefnum"
@ MSG_DT_VERNEED		"DT_VERNEED"		# 0x6ffffffe
@ MSG_DT_VERNEED_ALT1		"verneed"
@ MSG_DT_VERNEEDNUM		"DT_VERNEEDNUM"		# 0x6fffffff
@ MSG_DT_VERNEEDNUM_ALT1	"verneednum"
@ MSG_DT_AUXILIARY		"DT_AUXILIARY"		# 0x7ffffffd
@ MSG_DT_AUXILIARY_ALT1		"auxiliary"
@ MSG_DT_USED			"DT_USED"		# 0x7ffffffe
@ MSG_DT_USED_ALT1		"used"
@ MSG_DT_FILTER			"DT_FILTER"		# 0x7fffffff
@ MSG_DT_FILTER_ALT1		"filter"


# DT_FLAGS .dynamic entry
@ MSG_DF_ORIGIN			"DF_ORIGIN"		# 0x00000001
@ MSG_DF_ORIGIN_ALT1		"origin"
@ MSG_DF_SYMBOLIC		"DF_SYMBOLIC"		# 0x00000002
@ MSG_DF_SYMBOLIC_ALT1		"symbolic"
@ MSG_DF_TEXTREL		"DF_TEXTREL"		# 0x00000004
@ MSG_DF_TEXTREL_ALT1		"textrel"
@ MSG_DF_BIND_NOW		"DF_BIND_NOW"		# 0x00000008
@ MSG_DF_BIND_NOW_ALT1		"bind_now"
@ MSG_DF_STATIC_TLS		"DF_STATIC_TLS"		# 0x00000010
@ MSG_DF_STATIC_TLS_ALT1	"static_tls"


# DT_POSFLAG_1 .dynamic entry

@ MSG_DF_P1_LAZYLOAD		"DF_P1_LAZYLOAD"	# 0x00000001
@ MSG_DF_P1_LAZYLOAD_ALT1	"lazyload"
@ MSG_DF_P1_GROUPPERM		"DF_P1_GROUPPERM"	# 0x00000002
@ MSG_DF_P1_GROUPPERM_ALT1	"groupperm"


# DT_FLAGS_1 .dynamic entry

@ MSG_DF_1_NOW			"DF_1_NOW"		# 0x00000001
@ MSG_DF_1_NOW_ALT1		"now"
@ MSG_DF_1_GLOBAL		"DF_1_GLOBAL"		# 0x00000002
@ MSG_DF_1_GLOBAL_ALT1		"global"
@ MSG_DF_1_GROUP		"DF_1_GROUP"		# 0x00000004
@ MSG_DF_1_GROUP_ALT1		"group"
@ MSG_DF_1_NODELETE		"DF_1_NODELETE"		# 0x00000008
@ MSG_DF_1_NODELETE_ALT1	"nodelete"
@ MSG_DF_1_LOADFLTR		"DF_1_LOADFLTR"		# 0x00000010
@ MSG_DF_1_LOADFLTR_ALT1	"loadfltr"
@ MSG_DF_1_INITFIRST		"DF_1_INITFIRST"	# 0x00000020
@ MSG_DF_1_INITFIRST_ALT1	"initfirst"
@ MSG_DF_1_NOOPEN		"DF_1_NOOPEN"		# 0x00000040
@ MSG_DF_1_NOOPEN_ALT1		"noopen"
@ MSG_DF_1_ORIGIN		"DF_1_ORIGIN"		# 0x00000080
@ MSG_DF_1_ORIGIN_ALT1		"origin"
@ MSG_DF_1_DIRECT		"DF_1_DIRECT"		# 0x00000100
@ MSG_DF_1_DIRECT_ALT1		"direct"
@ MSG_DF_1_TRANS		"DF_1_TRANS"		# 0x00000200
@ MSG_DF_1_TRANS_ALT1		"trans"
@ MSG_DF_1_INTERPOSE		"DF_1_INTERPOSE"	# 0x00000400
@ MSG_DF_1_INTERPOSE_ALT1	"interpose"
@ MSG_DF_1_NODEFLIB		"DF_1_NODEFLIB"		# 0x00000800
@ MSG_DF_1_NODEFLIB_ALT1	"nodeflib"
@ MSG_DF_1_NODUMP		"DF_1_NODUMP"		# 0x00001000
@ MSG_DF_1_NODUMP_ALT1		"nodump"
@ MSG_DF_1_CONFALT		"DF_1_CONFALT"		# 0x00002000
@ MSG_DF_1_CONFALT_ALT1		"confalt"
@ MSG_DF_1_ENDFILTEE		"DF_1_ENDFILTEE"	# 0x00004000
@ MSG_DF_1_ENDFILTEE_ALT1	"endfiltee"
@ MSG_DF_1_DISPRELDNE		"DF_1_DISPRELDNE"	# 0x00008000
@ MSG_DF_1_DISPRELDNE_ALT1	"dispreldne"
@ MSG_DF_1_DISPRELPND		"DF_1_DISPRELPND"	# 0x00010000
@ MSG_DF_1_DISPRELPND_ALT1	"disprelpnd"
@ MSG_DF_1_NODIRECT		"DF_1_NODIRECT"		# 0x00020000
@ MSG_DF_1_NODIRECT_ALT1	"nodirect"
@ MSG_DF_1_IGNMULDEF		"DF_1_IGNMULDEF"	# 0x00040000
@ MSG_DF_1_IGNMULDEF_ALT1	"ignmuldef"
@ MSG_DF_1_NOKSYMS		"DF_1_NOKSYMS"		# 0x00080000
@ MSG_DF_1_NOKSYMS_ALT1		"noksyms"
@ MSG_DF_1_NOHDR		"DF_1_NOHDR"		# 0x00100000
@ MSG_DF_1_NOHDR_ALT1		"nohdr"
@ MSG_DF_1_EDITED		"DF_1_EDITED"		# 0x00200000
@ MSG_DF_1_EDITED_ALT1		"edited"
@ MSG_DF_1_NORELOC		"DF_1_NORELOC"		# 0x00400000
@ MSG_DF_1_NORELOC_ALT1		"noreloc"
@ MSG_DF_1_SYMINTPOSE		"DF_1_SYMINTPOSE"	# 0x00800000
@ MSG_DF_1_SYMINTPOSE_ALT1	"symintpose"
@ MSG_DF_1_GLOBAUDIT		"DF_1_GLOBAUDIT"	# 0x01000000
@ MSG_DF_1_GLOBAUDIT_ALT1	"globaudit"


# DT_FEATURE_1 .dynamic entry

@ MSG_DTF_1_PARINIT		"DTF_1_PARINIT"		# 0x00000001
@ MSG_DTF_1_PARINIT_ALT1	"parinit"
@ MSG_DTF_1_CONFEXP		"DTF_1_CONFEXP"		# 0x00000002
@ MSG_DTF_1_CONFEXP_ALT1	"confexp"


# EI_* indexes into ELF header e_ident[] array

@ MSG_EI_MAG0			"EI_MAG0"		# 0
@ MSG_EI_MAG0_ALT1		"mag0"
@ MSG_EI_MAG1			"EI_MAG1"		# 1
@ MSG_EI_MAG1_ALT1		"mag1"
@ MSG_EI_MAG2			"EI_MAG2"		# 2
@ MSG_EI_MAG2_ALT1		"mag2"
@ MSG_EI_MAG3			"EI_MAG3"		# 3
@ MSG_EI_MAG3_ALT1		"mag3"
@ MSG_EI_CLASS			"EI_CLASS"		# 4
@ MSG_EI_CLASS_ALT1		"class"
@ MSG_EI_DATA			"EI_DATA"		# 5
@ MSG_EI_DATA_ALT1		"data"
@ MSG_EI_VERSION		"EI_VERSION"		# 6
@ MSG_EI_VERSION_ALT1		"version"
@ MSG_EI_OSABI			"EI_OSABI"		# 7
@ MSG_EI_OSABI_ALT1		"osabi"
@ MSG_EI_ABIVERSION		"EI_ABIVERSION"		# 8
@ MSG_EI_ABIVERSION_ALT1	"abiversion"


# ET_* type constants

@ MSG_ET_NONE			"ET_NONE"		# 0
@ MSG_ET_NONE_ALT1		"none"
@ MSG_ET_REL			"ET_REL"		# 1
@ MSG_ET_REL_ALT1		"rel"
@ MSG_ET_EXEC			"ET_EXEC"		# 2
@ MSG_ET_EXEC_ALT1		"exec"
@ MSG_ET_DYN			"ET_DYN"		# 3
@ MSG_ET_DYN_ALT1		"dyn"
@ MSG_ET_CORE			"ET_CORE"		# 4
@ MSG_ET_CORE_ALT1		"core"


# ELFCLASS* constants

@ MSG_ELFCLASSNONE	"ELFCLASSNONE"			# 0
@ MSG_ELFCLASSNONE_ALT1	"none"
@ MSG_ELFCLASS32	"ELFCLASS32"			# 1
@ MSG_ELFCLASS32_ALT1	"32"
@ MSG_ELFCLASS64	"ELFCLASS64"			# 2
@ MSG_ELFCLASS64_ALT1	"64"


# ELFDATA* constants

@ MSG_ELFDATANONE	"ELFDATANONE"			# 0
@ MSG_ELFDATANONE_ALT1	"none"
@ MSG_ELFDATA2LSB	"ELFDATA2LSB"			# 1
@ MSG_ELFDATA2LSB_ALT1	"lsb"
@ MSG_ELFDATA2MSB	"ELFDATA2MSB"			# 2
@ MSG_ELFDATA2MSB_ALT1	"msb"


# Elf header EF_* flags

@ MSG_EF_SPARC_32PLUS		"EF_SPARC_32PLUS"	# 0x000100
@ MSG_EF_SPARC_32PLUS_ALT1	"sparc_32plus"
@ MSG_EF_SPARC_SUN_US1		"EF_SPARC_SUN_US1"	# 0x000200
@ MSG_EF_SPARC_SUN_US1_ALT1	"sparc_sun_us1"
@ MSG_EF_SPARC_HAL_R1		"EF_SPARC_HAL_R1"	# 0x000400
@ MSG_EF_SPARC_HAL_R1_ALT1	"sparc_hal_r1"
@ MSG_EF_SPARC_SUN_US3		"EF_SPARC_SUN_US3"	# x000800
@ MSG_EF_SPARC_SUN_US3_ALT1	"sparc_sun_us3"
@ MSG_EF_SPARCV9_MM		"EF_SPARCV9_MM"		# 0x3
@ MSG_EF_SPARCV9_MM_ALT1	"sparcv9_mm"
@ MSG_EF_SPARCV9_TSO		"EF_SPARCV9_TSO"	# 0x0
@ MSG_EF_SPARCV9_TSO_ALT1	"sparcv9_tso"
@ MSG_EF_SPARCV9_PSO		"EF_SPARCV9_PSO"	# 0x1
@ MSG_EF_SPARCV9_PSO_ALT1	"sparcv9_pso"
@ MSG_EF_SPARCV9_RMO		"EF_SPARCV9_RMO"	# 0x2
@ MSG_EF_SPARCV9_RMO_ALT1	"sparcv9_rmo"


# Elf header EV_* versions

@ MSG_EV_NONE		"EV_NONE"			# 0
@ MSG_EV_NONE_ALT1	"none"
@ MSG_EV_CURRENT	"EV_CURRENT"			# 1
@ MSG_EV_CURRENT_ALT1	"current"


# EM_* machine names. Note that there is more than one string for some
# of these. The main name for each one is the same as it's constant
# name in sys/elf.h, and start with the EM_ prefix. The alternative names
# are the alternative names provided by libconv.

@ MSG_EM_NONE			"EM_NONE"		# 0
@ MSG_EM_NONE_ALT1		"none"
@ MSG_EM_M32			"EM_M32"		# 1
@ MSG_EM_M32_ALT1		"m32"
@ MSG_EM_M32_ALT2		"WE32100"
@ MSG_EM_SPARC			"EM_SPARC"		# 2
@ MSG_EM_SPARC_ALT1		"sparc"
@ MSG_EM_386			"EM_386"		# 3
@ MSG_EM_386_ALT1		"386"
@ MSG_EM_386_ALT2		"80386"
@ MSG_EM_68K			"EM_68K"		# 4
@ MSG_EM_68K_ALT1		"68k"
@ MSG_EM_68K_ALT2		"68000"
@ MSG_EM_88K			"EM_88K"		# 5
@ MSG_EM_88K_ALT1		"88k"
@ MSG_EM_88K_ALT2		"88000"
@ MSG_EM_486			"EM_486"		# 6
@ MSG_EM_486_ALT1		"486"
@ MSG_EM_486_ALT2		"80486"
@ MSG_EM_860			"EM_860"		# 7
@ MSG_EM_860_ALT1		"860"
@ MSG_EM_860_ALT2		"i860"
@ MSG_EM_MIPS			"EM_MIPS"		# 8
@ MSG_EM_MIPS_ALT1		"mips"
@ MSG_EM_MIPS_ALT2		"rs3000_be"
@ MSG_EM_S370			"EM_S370"		# 9
@ MSG_EM_S370_ALT1		"s370"
@ MSG_EM_MIPS_RS3_LE		"EM_MIPS_RS3_LE"	# 10
@ MSG_EM_MIPS_RS3_LE_ALT1	"mips_rs3_le"
@ MSG_EM_MIPS_RS3_LE_ALT2	"RS3000_LE"
@ MSG_EM_RS6000			"EM_RS6000"		# 11
@ MSG_EM_RS6000_ALT1		"rs6000"
@ MSG_EM_PA_RISC		"EM_PA_RISC"		# 15
@ MSG_EM_PA_RISC_ALT1		"pa_risc"
@ MSG_EM_NCUBE			"EM_nCUBE"		# 16
@ MSG_EM_NCUBE_ALT1		"ncube"
@ MSG_EM_VPP500			"EM_VPP500"		# 17
@ MSG_EM_VPP500_ALT1		"vpp500"
@ MSG_EM_SPARC32PLUS		"EM_SPARC32PLUS"	# 18
@ MSG_EM_SPARC32PLUS_ALT1	"sparc32plus"
@ MSG_EM_960			"EM_960"		# 19
@ MSG_EM_960_ALT1		"960"
@ MSG_EM_PPC			"EM_PPC"		# 20
@ MSG_EM_PPC_ALT1		"ppc"
@ MSG_EM_PPC_ALT2		"PowerPC"
@ MSG_EM_PPC64			"EM_PPC64"		#21
@ MSG_EM_PPC64_ALT1		"ppc64"
@ MSG_EM_PPC64_ALT2		"PowerPC64"
@ MSG_EM_S390			"EM_S390"		#22
@ MSG_EM_S390_ALT1		"s390"
@ MSG_EM_V800			"EM_V800"		#36
@ MSG_EM_V800_ALT1		"v800"
@ MSG_EM_FR20			"EM_FR20"		#37
@ MSG_EM_FR20_ALT1		"fr20"
@ MSG_EM_RH32			"EM_RH32"		#38
@ MSG_EM_RH32_ALT1		"rh32"
@ MSG_EM_RCE			"EM_RCE"		#39
@ MSG_EM_RCE_ALT1		"rce"
@ MSG_EM_ARM			"EM_ARM"		#40
@ MSG_EM_ARM_ALT1		"arm"
@ MSG_EM_ALPHA			"EM_ALPHA"		#41
@ MSG_EM_ALPHA_ALT1		"alpha"
@ MSG_EM_SH			"EM_SH"			#42
@ MSG_EM_SH_ALT1		"sh"
@ MSG_EM_SPARCV9		"EM_SPARCV9"		#43
@ MSG_EM_SPARCV9_ALT1		"sparcv9"
@ MSG_EM_TRICORE		"EM_TRICORE"		#44
@ MSG_EM_TRICORE_ALT1		"tricore"
@ MSG_EM_ARC			"EM_ARC"		#45
@ MSG_EM_ARC_ALT1		"arc"
@ MSG_EM_H8_300			"EM_H8_300"		#46
@ MSG_EM_H8_300_ALT1		"h8_300"
@ MSG_EM_H8_300H		"EM_H8_300H"		#47
@ MSG_EM_H8_300H_ALT1		"h8_300h"
@ MSG_EM_H8S			"EM_H8S"		#48
@ MSG_EM_H8S_ALT1		"h8s"
@ MSG_EM_H8_500			"EM_H8_500"		#49
@ MSG_EM_H8_500_ALT1		"h8_500"
@ MSG_EM_IA_64			"EM_IA_64"		#50
@ MSG_EM_IA_64_ALT1		"ia_64"
@ MSG_EM_MIPS_X			"EM_MIPS_X"		#51
@ MSG_EM_MIPS_X_ALT1		"mips_x"
@ MSG_EM_COLDFIRE		"EM_COLDFIRE"		#52
@ MSG_EM_COLDFIRE_ALT1		"coldfire"
@ MSG_EM_68HC12			"EM_68HC12"		#53
@ MSG_EM_68HC12_ALT1		"68hc12"
@ MSG_EM_MMA			"EM_MMA"		#54
@ MSG_EM_MMA_ALT1		"mma"
@ MSG_EM_PCP			"EM_PCP"		#55
@ MSG_EM_PCP_ALT1		"pcp"
@ MSG_EM_NCPU			"EM_NCPU"		#56
@ MSG_EM_NCPU_ALT1		"ncpu"
@ MSG_EM_NDR1			"EM_NDR1"		#57
@ MSG_EM_NDR1_ALT1		"ndr1"
@ MSG_EM_STARCORE		"EM_STARCORE"		#58
@ MSG_EM_STARCORE_ALT1		"starcore"
@ MSG_EM_ME16			"EM_ME16"		#59
@ MSG_EM_ME16_ALT1		"me16"
@ MSG_EM_ST100			"EM_ST100"		#60
@ MSG_EM_ST100_ALT1		"st100"
@ MSG_EM_TINYJ			"EM_TINYJ"		#61
@ MSG_EM_TINYJ_ALT1		"tinyj"
@ MSG_EM_AMD64			"EM_AMD64"		#62
@ MSG_EM_AMD64_ALT1		"amd64"
@ MSG_EM_PDSP			"EM_PDSP"		#63
@ MSG_EM_PDSP_ALT1		"pdsp"
@ MSG_EM_FX66			"EM_FX66"		#66
@ MSG_EM_FX66_ALT1		"fx66"
@ MSG_EM_ST9PLUS		"EM_ST9PLUS"		#67
@ MSG_EM_ST9PLUS_ALT1		"st9plus"
@ MSG_EM_ST7			"EM_ST7"		#68
@ MSG_EM_ST7_ALT1		"st7"
@ MSG_EM_68HC16			"EM_68HC16"		#69
@ MSG_EM_68HC16_ALT1		"68hc16"
@ MSG_EM_68HC11			"EM_68HC11"		#70
@ MSG_EM_68HC11_ALT1		"68hc11"
@ MSG_EM_68HC08			"EM_68HC08"		#71
@ MSG_EM_68HC08_ALT1		"68hc08"
@ MSG_EM_68HC05			"EM_68HC05"		#72
@ MSG_EM_68HC05_ALT1		"68hc05"
@ MSG_EM_SVX			"EM_SVX"		#73
@ MSG_EM_SVX_ALT1		"svx"
@ MSG_EM_ST19			"EM_ST19"		#74
@ MSG_EM_ST19_ALT1		"st19"
@ MSG_EM_VAX			"EM_VAX"		#75
@ MSG_EM_VAX_ALT1		"vax"
@ MSG_EM_CRIS			"EM_CRIS"		#76
@ MSG_EM_CRIS_ALT1		"cris"
@ MSG_EM_JAVELIN		"EM_JAVELIN"		#77
@ MSG_EM_JAVELIN_ALT1		"javelin"
@ MSG_EM_FIREPATH		"EM_FIREPATH"		#78
@ MSG_EM_FIREPATH_ALT1		"firepath"
@ MSG_EM_ZSP			"EM_ZSP"		#79
@ MSG_EM_ZSP_ALT1		"zsp"
@ MSG_EM_MMIX			"EM_MMIX"		#80
@ MSG_EM_MMIX_ALT1		"mmix"
@ MSG_EM_HUANY			"EM_HUANY"		#81
@ MSG_EM_HUANY_ALT1		"huany"
@ MSG_EM_PRISM			"EM_PRISM"		#82
@ MSG_EM_PRISM_ALT1		"prism"
@ MSG_EM_AVR			"EM_AVR"		#83
@ MSG_EM_AVR_ALT1		"avr"
@ MSG_EM_FR30			"EM_FR30"		#84
@ MSG_EM_FR30_ALT1		"fr30"
@ MSG_EM_D10V			"EM_D10V"		#85
@ MSG_EM_D10V_ALT1		"d10v"
@ MSG_EM_D30V			"EM_D30V"		#86
@ MSG_EM_D30V_ALT1		"d30v"
@ MSG_EM_V850			"EM_V850"		#87
@ MSG_EM_V850_ALT1		"v850"
@ MSG_EM_M32R			"EM_M32R"		#88
@ MSG_EM_M32R_ALT1		"m32r"
@ MSG_EM_MN10300		"EM_MN10300"		#89
@ MSG_EM_MN10300_ALT1		"mn10300"
@ MSG_EM_MN10200		"EM_MN10200"		#90
@ MSG_EM_MN10200_ALT1		"mn10200"
@ MSG_EM_PJ			"EM_PJ"			#91
@ MSG_EM_PJ_ALT1		"pj"
@ MSG_EM_OPENRISC		"EM_OPENRISC"		#92
@ MSG_EM_OPENRISC_ALT1		"openrisc"
@ MSG_EM_ARC_A5			"EM_ARC_A5"		#93
@ MSG_EM_ARC_A5_ALT1		"arc_a5"
@ MSG_EM_XTENSA			"EM_XTENSA"		#94
@ MSG_EM_XTENSA_ALT1		"xtensa"



# ELFOSABI names

@ MSG_ELFOSABI_NONE		"ELFOSABI_NONE"
@ MSG_ELFOSABI_NONE_ALT1	"none"
@ MSG_ELFOSABI_SYSV		"ELFOSABI_SYSV"
@ MSG_ELFOSABI_SYSV_ALT1	"sysv"
@ MSG_ELFOSABI_HPUX		"ELFOSABI_HPUX"
@ MSG_ELFOSABI_HPUX_ALT1	"hpux"
@ MSG_ELFOSABI_NETBSD		"ELFOSABI_NETBSD"
@ MSG_ELFOSABI_NETBSD_ALT1	"netbsd"
@ MSG_ELFOSABI_LINUX		"ELFOSABI_LINUX"
@ MSG_ELFOSABI_LINUX_ALT1	"linux"
@ MSG_ELFOSABI_SOLARIS		"ELFOSABI_SOLARIS"
@ MSG_ELFOSABI_SOLARIS_ALT1	"solaris"
@ MSG_ELFOSABI_AIX		"ELFOSABI_AIX"
@ MSG_ELFOSABI_AIX_ALT1		"aix"
@ MSG_ELFOSABI_IRIX		"ELFOSABI_IRIX"
@ MSG_ELFOSABI_IRIX_ALT1	"irix"
@ MSG_ELFOSABI_FREEBSD		"ELFOSABI_FREEBSD"
@ MSG_ELFOSABI_FREEBSD_ALT1	"freebsd"
@ MSG_ELFOSABI_TRU64		"ELFOSABI_TRU64"
@ MSG_ELFOSABI_TRU64_ALT1	"tru64"
@ MSG_ELFOSABI_MODESTO		"ELFOSABI_MODESTO"
@ MSG_ELFOSABI_MODESTO_ALT1	"modesto"
@ MSG_ELFOSABI_OPENBSD		"ELFOSABI_OPENBSD"
@ MSG_ELFOSABI_OPENBSD_ALT1	"openbsd"
@ MSG_ELFOSABI_OPENVMS		"ELFOSABI_OPENVMS"
@ MSG_ELFOSABI_OPENVMS_ALT1	"openvms"
@ MSG_ELFOSABI_NSK		"ELFOSABI_NSK"
@ MSG_ELFOSABI_NSK_ALT1		"nsk"
@ MSG_ELFOSABI_AROS		"ELFOSABI_AROS"
@ MSG_ELFOSABI_AROS_ALT1	"aros"
@ MSG_ELFOSABI_ARM		"ELFOSABI_ARM"
@ MSG_ELFOSABI_ARM_ALT1		"arm"
@ MSG_ELFOSABI_STANDALONE	"ELFOSABI_STANDALONE"
@ MSG_ELFOSABI_STANDALONE_ALT1	"standalone"


# Program header PT_ segment types

@ MSG_PT_NULL			"PT_NULL"		# 0
@ MSG_PT_NULL_ALT1		"null"
@ MSG_PT_LOAD			"PT_LOAD"		# 1
@ MSG_PT_LOAD_ALT1		"load"
@ MSG_PT_DYNAMIC		"PT_DYNAMIC"		# 2
@ MSG_PT_DYNAMIC_ALT1		"dynamic"
@ MSG_PT_INTERP			"PT_INTERP"		# 3
@ MSG_PT_INTERP_ALT1		"interp"
@ MSG_PT_NOTE			"PT_NOTE"		# 4
@ MSG_PT_NOTE_ALT1		"note"
@ MSG_PT_SHLIB			"PT_SHLIB"		# 5
@ MSG_PT_SHLIB_ALT1		"shlib"
@ MSG_PT_PHDR			"PT_PHDR"		# 6
@ MSG_PT_PHDR_ALT1		"phdr"
@ MSG_PT_TLS			"PT_TLS"		# 7
@ MSG_PT_TLS_ALT1		"tls"
@ MSG_PT_SUNW_UNWIND		"PT_SUNW_UNWIND"	# 0x6464e550
@ MSG_PT_SUNW_UNWIND_ALT1	"sunw_unwind"
@ MSG_PT_SUNWBSS		"PT_SUNWBSS"		# 0x6ffffffa
@ MSG_PT_SUNWBSS_ALT1		"sunwbss"
@ MSG_PT_SUNWSTACK		"PT_SUNWSTACK"		# 0x6ffffffb
@ MSG_PT_SUNWSTACK_ALT1		"sunwstack"
@ MSG_PT_SUNWDTRACE		"PT_SUNWDTRACE"		# 0x6ffffffc
@ MSG_PT_SUNWDTRACE_ALT1	"sunwdtrace"
@ MSG_PT_SUNWCAP		"PT_SUNWCAP"		# 0x6ffffffd
@ MSG_PT_SUNWCAP_ALT1		"sunwcap"


# Program header PF_ segment flags

@ MSG_PF_X			"PF_X"			# 0x1
@ MSG_PF_X_ALT1			"x"
@ MSG_PF_W			"PF_W"			# 0x2
@ MSG_PF_W_ALT1			"w"
@ MSG_PF_R			"PF_R"			# 0x4
@ MSG_PF_R_ALT1			"r"


# Section header SHF_* flags

@ MSG_SHF_WRITE			"SHF_WRITE"		# 0x01
@ MSG_SHF_WRITE_ALT1		"write"
@ MSG_SHF_ALLOC			"SHF_ALLOC"		# 0x02
@ MSG_SHF_ALLOC_ALT1		"alloc"
@ MSG_SHF_EXECINSTR		"SHF_EXECINSTR"		# 0x04
@ MSG_SHF_EXECINSTR_ALT1	"execinstr"
@ MSG_SHF_MERGE			"SHF_MERGE"		# 0x10
@ MSG_SHF_MERGE_ALT1		"merge"
@ MSG_SHF_STRINGS		"SHF_STRINGS"		# 0x20
@ MSG_SHF_STRINGS_ALT1		"strings"
@ MSG_SHF_INFO_LINK		"SHF_INFO_LINK"		# 0x40
@ MSG_SHF_INFO_LINK_ALT1	"info_link"
@ MSG_SHF_LINK_ORDER		"SHF_LINK_ORDER"	# 0x80
@ MSG_SHF_LINK_ORDER_ALT1	"link_order"
@ MSG_SHF_OS_NONCONFORMING	"SHF_OS_NONCONFORMING"	# 0x100
@ MSG_SHF_OS_NONCONFORMING_ALT1	"os_nonconforming"
@ MSG_SHF_GROUP			"SHF_GROUP"		# 0x200
@ MSG_SHF_GROUP_ALT1		"group"
@ MSG_SHF_TLS			"SHF_TLS"		# 0x400
@ MSG_SHF_TLS_ALT1		"tls"


# Names of st_info ELF_ST_BIND symbol binding constants

@ MSG_STB_LOCAL			"STB_LOCAL"		# 0
@ MSG_STB_LOCAL_ALT1		"local"
@ MSG_STB_GLOBAL		"STB_GLOBAL"		# 1
@ MSG_STB_GLOBAL_ALT1		"global"
@ MSG_STB_WEAK			"STB_WEAK"		# 2
@ MSG_STB_WEAK_ALT1		"weak"


# Names of st_info ELF_ST_TYPE symbol type constants

@ MSG_STT_NOTYPE		"STT_NOTYPE"		# 0
@ MSG_STT_NOTYPE_ALT1		"notype"
@ MSG_STT_OBJECT		"STT_OBJECT"		# 1
@ MSG_STT_OBJECT_ALT1		"object"
@ MSG_STT_FUNC			"STT_FUNC"		# 2
@ MSG_STT_FUNC_ALT1		"func"
@ MSG_STT_SECTION		"STT_SECTION"		# 3
@ MSG_STT_SECTION_ALT1		"section"
@ MSG_STT_FILE			"STT_FILE"		# 4
@ MSG_STT_FILE_ALT1		"file"
@ MSG_STT_COMMON		"STT_COMMON"		# 5
@ MSG_STT_COMMON_ALT1		"common"
@ MSG_STT_TLS			"STT_TLS"		# 6
@ MSG_STT_TLS_ALT1		"tls"


# Names of st_other ELF_ST_VISIBILITY symbol visibility constants

@ MSG_STV_DEFAULT		"STV_DEFAULT"		# 0
@ MSG_STV_DEFAULT_ALT1		"default"
@ MSG_STV_INTERNAL		"STV_INTERNAL"		# 1
@ MSG_STV_INTERNAL_ALT1		"internal"
@ MSG_STV_HIDDEN		"STV_HIDDEN"		# 2
@ MSG_STV_HIDDEN_ALT1		"hidden"
@ MSG_STV_PROTECTED		"STV_PROTECTED"		# 3
@ MSG_STV_PROTECTED_ALT1	"protected"
@ MSG_STV_EXPORTED		"STV_EXPORTED"		# 4
@ MSG_STV_EXPORTED_ALT1		"exported"
@ MSG_STV_SINGLETON		"STV_SINGLETON"		# 5
@ MSG_STV_SINGLETON_ALT1	"singleton"
@ MSG_STV_ELIMINATE		"STV_ELIMINATE"		# 6
@ MSG_STV_ELIMINATE_ALT1	"eliminate"


# Names of si_boundto SYMINFO_BT_ symbol type constants

@ MSG_SYMINFO_BT_SELF		"SYMINFO_BT_SELF"	# 0xffff
@ MSG_SYMINFO_BT_SELF_ALT1	"self"
@ MSG_SYMINFO_BT_PARENT		"SYMINFO_BT_PARENT"	# 0xfffe
@ MSG_SYMINFO_BT_PARENT_ALT1	"parent"
@ MSG_SYMINFO_BT_NONE		"SYMINFO_BT_NONE"	# 0xfffd
@ MSG_SYMINFO_BT_NONE_ALT1	"none"


# Names of si_flags SYMINFO_FLG_ symbol type constants

@ MSG_SYMINFO_FLG_DIRECT		"SYMINFO_FLG_DIRECT"		# 0x01
@ MSG_SYMINFO_FLG_DIRECT_ALT1		"direct"
@ MSG_SYMINFO_FLG_COPY			"SYMINFO_FLG_COPY"		# 0x04
@ MSG_SYMINFO_FLG_COPY_ALT1		"copy"
@ MSG_SYMINFO_FLG_LAZYLOAD		"SYMINFO_FLG_LAZYLOAD"		# 0x08
@ MSG_SYMINFO_FLG_LAZYLOAD_ALT1		"lazyload"
@ MSG_SYMINFO_FLG_DIRECTBIND		"SYMINFO_FLG_DIRECTBIND"	# 0x10
@ MSG_SYMINFO_FLG_DIRECTBIND_ALT1	"directbind"
@ MSG_SYMINFO_FLG_NOEXTDIRECT		"SYMINFO_FLG_NOEXTDIRECT"	# 0x20
@ MSG_SYMINFO_FLG_NOEXTDIRECT_ALT1	"noextdirect"


# Names of capabilities section CA_ tag

@ MSG_CA_SUNW_NULL		"CA_SUNW_NULL"		# 0
@ MSG_CA_SUNW_NULL_ALT1		"null"
@ MSG_CA_SUNW_HW_1		"CA_SUNW_HW_1"		# 1
@ MSG_CA_SUNW_HW_1_ALT1		"hw_1"
@ MSG_CA_SUNW_SF_1		"CA_SUNW_SF_1"		# 2
@ MSG_CA_SUNW_SF_1_ALT1		"sf_1"

# AV_386 flags used for CA_SUNW_HW_1 capabilities

@ MSG_AV_386_FPU		"AV_386_FPU"		# 0x00001
@ MSG_AV_386_FPU_ALT1		"fpu"
@ MSG_AV_386_TSC		"AV_386_TSC"		# 0x00002
@ MSG_AV_386_TSC_ALT1		"tsc"
@ MSG_AV_386_CX8		"AV_386_CX8"		# 0x00004
@ MSG_AV_386_CX8_ALT1		"cx8"
@ MSG_AV_386_SEP		"AV_386_SEP"		# 0x00008
@ MSG_AV_386_SEP_ALT1		"sep"
@ MSG_AV_386_AMD_SYSC		"AV_386_AMD_SYSC"	# 0x00010
@ MSG_AV_386_AMD_SYSC_ALT1	"amd_sysc"
@ MSG_AV_386_CMOV		"AV_386_CMOV"		# 0x00020
@ MSG_AV_386_CMOV_ALT1		"cmov"
@ MSG_AV_386_MMX		"AV_386_MMX"		# 0x00040
@ MSG_AV_386_MMX_ALT1		"mmx"
@ MSG_AV_386_AMD_MMX		"AV_386_AMD_MMX"	# 0x00080
@ MSG_AV_386_AMD_MMX_ALT1	"amd_mmx"
@ MSG_AV_386_AMD_3DNOW		"AV_386_AMD_3DNow"	# 0x00100
@ MSG_AV_386_AMD_3DNOW_ALT1	"amd_3dnow"
@ MSG_AV_386_AMD_3DNOWX		"AV_386_AMD_3DNowx"	# 0x00200
@ MSG_AV_386_AMD_3DNOWX_ALT1	"amd_3dnowx"
@ MSG_AV_386_FXSR		"AV_386_FXSR"		# 0x00400
@ MSG_AV_386_FXSR_ALT1		"fxsr"
@ MSG_AV_386_SSE		"AV_386_SSE"		# 0x00800
@ MSG_AV_386_SSE_ALT1		"sse"
@ MSG_AV_386_SSE2		"AV_386_SSE2"		# 0x01000
@ MSG_AV_386_SSE2_ALT1		"sse2"
@ MSG_AV_386_PAUSE		"AV_386_PAUSE"		# 0x02000
@ MSG_AV_386_PAUSE_ALT1		"pause"
@ MSG_AV_386_SSE3		"AV_386_SSE3"		# 0x04000
@ MSG_AV_386_SSE3_ALT1		"sse3"
@ MSG_AV_386_MON		"AV_386_MON"		# 0x08000
@ MSG_AV_386_MON_ALT1		"mon"
@ MSG_AV_386_CX16		"AV_386_CX16"		# 0x10000
@ MSG_AV_386_CX16_ALT1		"cx16"
@ MSG_AV_386_AHF		"AV_386_AHF"		# 0x20000
@ MSG_AV_386_AHF_ALT1		"ahf"
@ MSG_AV_386_TSCP		"AV_386_TSCP"		# 0x40000
@ MSG_AV_386_TSCP_ALT1		"tscp"
@ MSG_AV_386_AMD_SSE4A		"AV_386_AMD_SSE4A"	# 0x80000
@ MSG_AV_386_AMD_SSE4A_ALT1	"amd_sse4a"
@ MSG_AV_386_POPCNT		"AV_386_POPCNT"		# 0x100000
@ MSG_AV_386_POPCNT_ALT1	"popcnt"
@ MSG_AV_386_AMD_LZCNT		"AV_386_AMD_LZCNT"	# 0x200000
@ MSG_AV_386_AMD_LZCNT_ALT1	"amd_lzcnt"


# AV_SPARC flags used for CA_SUNW_HW_1 capabilities

@ MSG_AV_SPARC_MUL32		"AV_SPARC_MUL32"	# 0x0001
@ MSG_AV_SPARC_MUL32_ALT1	"mul32"
@ MSG_AV_SPARC_DIV32		"AV_SPARC_DIV32"	# 0x0002
@ MSG_AV_SPARC_DIV32_ALT1	"div32"
@ MSG_AV_SPARC_FSMULD		"AV_SPARC_FSMULD"	# 0x0004
@ MSG_AV_SPARC_FSMULD_ALT1	"fsmuld"
@ MSG_AV_SPARC_V8PLUS		"AV_SPARC_V8PLUS"	# 0x0008
@ MSG_AV_SPARC_V8PLUS_ALT1	"v8plus"
@ MSG_AV_SPARC_POPC		"AV_SPARC_POPC"		# 0x0010
@ MSG_AV_SPARC_POPC_ALT1	"popc"
@ MSG_AV_SPARC_VIS		"AV_SPARC_VIS"		# 0x0020
@ MSG_AV_SPARC_VIS_ALT1		"vis"
@ MSG_AV_SPARC_VIS2		"AV_SPARC_VIS2"		# 0x0040
@ MSG_AV_SPARC_VIS2_ALT1	"vis2"
@ MSG_AV_SPARC_ASI_BLK_INIT	"AV_SPARC_ASI_BLK_INIT"	# 0x0080
@ MSG_AV_SPARC_ASI_BLK_INIT_ALT1 "asi_blk_init"
@ MSG_AV_SPARC_FMAF		"AV_SPARC_FMAF"		# 0x0100
@ MSG_AV_SPARC_FMAF_ALT1	"fmaf"
@ MSG_AV_SPARC_FJFMAU		"AV_SPARC_FJFMAU"	# 0x4000
@ MSG_AV_SPARC_FJFMAU_ALT1	"fjfmau"


# SF1_SUNW flags used for CA_SUNW_SF_1 capabilities

@ MSG_SF1_SUNW_FPKNWN		"SF1_SUNW_FPKNWN"	# 0x001
@ MSG_SF1_SUNW_FPKNWN_ALT1	"fpknwn"
@ MSG_SF1_SUNW_FPUSED		"SF1_SUNW_FPUSED"	# 0x002
@ MSG_SF1_SUNW_FPUSED_ALT1	"fpused"


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
@ MSG_STR_OPTIONS	"ade:L:o:rw"
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
