/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ELFEDIT_H
#define	_ELFEDIT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<libelf.h>
#include	<stdarg.h>

/* The following are here to support use of elfedit_msg() */
#include	<sys/machelf.h>		/* EC_ macros */
#include	<libintl.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * elfedit uses elfedit_printf() to produce generic output to stdout.
 * elfedit_msg() is used to produce error message, or specific types
 * of terse informational messages:
 *
 *	ELFEDIT_MSG_ERR:
 *		Issues an error to stderr. elfedit_msg() does not return
 *		to the caller. Control returns to the outer loop in
 *		interactive use. elfedit exits in non-interactive use.
 *
 *	ELFEDIT_MSG_FATAL:
 *		Issues an error to stderr. elfedit_msg() exits the process,
 *		and does not return to the caller.
 *
 *	ELFEDIT_MSG_USAGE:
 *		Issues an elfedit usage message to stderr, and
 *		returns to the caller.
 *
 *	ELFEDIT_MSG_CMDUSAGE
 *		Issues an elfedit usage message to stderr, and
 *		does not return to the caller.
 *
 *	ELFEDIT_MSG_DEBUG
 *		If the ELFEDIT_F_DEBUG flag is set, the message
 *		is printed to stdout, otherwise no output is produced.
 *		elfedit_msg() returns to the caller.
 *
 *	ELFEDIT_MSG_QUIET
 *		This is a very special case, intended to handle the
 *		case where the pager subprocess exits before we are
 *		done producing output (the user presses 'q'). It acts
 *		just like ELFEDIT_MSG_ERR, except that no message is
 *		actually printed.
 *
 * In the cases where elfedit_msg() does not return to the caller, the
 * behavior depends on the mode of execution. If running in interactive
 * mode (reading from a tty), control is returned directly to the outer
 * elfedit control loop to read another command. If not running in interactive
 * mode, elfedit exits with a non-zero status.
 */
typedef enum {
	ELFEDIT_MSG_ERR = 0,
	ELFEDIT_MSG_FATAL = 1,
	ELFEDIT_MSG_USAGE = 2,
	ELFEDIT_MSG_CMDUSAGE = 3,
	ELFEDIT_MSG_DEBUG = 4,
	ELFEDIT_MSG_QUIET = 5
} elfedit_msg_t;


/*
 * Information for a single ELF section.
 *
 * NOTE: sec_xshndx
 *	A symbol table can have an associated SHT_SYMTAB_SHNDX section. This
 *	happens when the number of sections is too large to fit in the
 *	ELF symbol st_shndx field, which is a 16-bit value. The sec_xshndx
 *	field will be SHN_UNDEF if there is no such section, and will be
 *	the section index of the extended section index section assocated
 *	with the symbol table otherwise.
 *
 * NOTE: sec_versym
 *	Symbol table sections can have an SHT_SUNW_VERSYM section that
 *	contains its version indices. Other types of section will have
 *	this field set to SHN_UNDEF.
 */
typedef struct {
	Elf32_Word	sec_shndx;	/* Section index */
	Elf_Scn		*sec_scn;	/* Section descriptor */
	Elf32_Shdr	*sec_shdr;	/* Section header */
	Elf_Data	*sec_data;	/* Data region of section */
	const char	*sec_name;	/* Name of section */
} elfedit32_section_t;

typedef struct {
	Elf64_Word	sec_shndx;
	Elf_Scn		*sec_scn;
	Elf64_Shdr	*sec_shdr;
	Elf_Data	*sec_data;
	const char	*sec_name;
} elfedit64_section_t;

#ifdef _ELF64
#define	elfedit_section_t	elfedit64_section_t
#else
#define	elfedit_section_t	elfedit32_section_t
#endif


/*
 * We maintain extra information for symbol tables. We look them
 * up frequently, so we want to eliminate expensive linear searches
 * of the entire section header array. Also, symbol tables usually
 * have associated parallal sections (syminfo, versym, extended indexes, etc)
 * and we want to eliminate repeated linear lookups for them, as well as
 * the basic error checking that is necessary to ensure they match the
 * symbol table they're given.
 *
 * This extra information is kept in elfedit_symtab_t structs. Each field
 * is a section index, with SHN_UNDEF used for those that do not apply.
 */
typedef struct {
	Elf32_Word	symt_shndx;	/* Symbol table section index */
	Elf32_Word	symt_xshndx;	/* Index of extended index section */
	Elf32_Word	symt_syminfo;	/* Index of versym section */
	Elf32_Word	symt_versym;	/* Index of versym section */
} elfedit32_symtab_t;

typedef struct {
	Elf64_Word	symt_shndx;
	Elf64_Word	symt_xshndx;
	Elf64_Word	symt_versym;
	Elf64_Word	symt_syminfo;
} elfedit64_symtab_t;

#ifdef _ELF64
#define	elfedit_symtab_t	elfedit64_symtab_t
#else
#define	elfedit_symtab_t	elfedit32_symtab_t
#endif


/*
 * Information for a single ELF object.
 *
 * note:
 *	elfedit is intended to be an expert's tool, capable of modifying
 *	nearly everything in the file, whether or not such modifications
 *	are a good idea. At the same time, elfedit, via libelf, relies
 *	on the contents of the object to properly locate information in
 *	the file. As this is the same information that elfedit allows the
 *	user to modify, it should be obvious that the potential exists
 *	for users to corrupt the file to the degree that elfedit itself
 *	may fail, or produce spurious results. We allow such changes for
 *	several reasons:
 *
 *	1) Such corruption does not happen in the most obvious and
 *		useful operations elfedit supports, but comes as a result
 *		of modifying fields that contain size and offset information
 *		used to navigate the file. Non-ELF developers have
 *		little practical reason to change such things.
 *
 *	2) Producing a corrupt ELF file can be very useful
 *		for R&D and/or testing purposes.
 *
 *	3) ELF is sufficiently complex that no absolute guarantees can
 *		be made about "safe" operations, beyond the basic
 *		and obvious things that are of practical use.
 *
 *	One way we protect ourselves is via the information cached in
 *	the elfedit_obj_state_t structure at startup. By using this
 *	information, rather than constantly fetching it via libelf,
 *	we protect ourselves against many user changes, such as changing the
 *	program or section header offsets, or similar size/position fields.
 *
 *	Of course, we make no assurances that that we will be able to
 *	read the resulting file in a subsequent session.
 */
typedef struct {
	const char		*os_file;	/* Path to ELF file */
	int			os_fd;		/* Open file descriptor */
	Elf			*os_elf;	/* ELF descriptor */
	Elf32_Ehdr		*os_ehdr;	/* ELF header */
	Elf32_Word		os_dynndx;	/* Index of dynamic section */
	size_t			os_shstrndx;	/* Index of section header */
						/*	string table section */
	size_t			os_shnum;	/* # of sections in file */
	elfedit32_section_t	*os_secarr;	/* Section data */
	size_t			os_phnum;	/* # of program headers */
	Elf32_Phdr		*os_phdr;	/* Program header array */
	size_t			os_symtabnum;	/* # items in os_symtab[] */
	elfedit32_symtab_t	*os_symtab;	/* Array of symbol tbl info  */
} elfedit32_obj_state_t;

typedef struct {
	const char		*os_file;
	int			os_fd;
	Elf			*os_elf;
	Elf64_Ehdr		*os_ehdr;
	Elf64_Word		os_dynndx;
	size_t			os_shstrndx;
	size_t			os_shnum;
	elfedit64_section_t	*os_secarr;
	size_t			os_phnum;
	Elf64_Phdr		*os_phdr;
	size_t			os_symtabnum;
	elfedit64_symtab_t	*os_symtab;
} elfedit64_obj_state_t;

#ifdef _ELF64
#define	elfedit_obj_state_t	elfedit64_obj_state_t
#else
#define	elfedit_obj_state_t	elfedit32_obj_state_t
#endif


/*
 * Bit values for editor state.
 */
typedef enum {
	ELFEDIT_F_AUTOPRINT = 1, /* Print informational text about edits */
	ELFEDIT_F_DEBUG = 2,	/* Print informational text about operations */
	ELFEDIT_F_READONLY = 4,	/* File is processed readonly */
} elfedit_flag_t;

/*
 * Type used to represent the output style for printing ELF values.
 *
 * DEFAULT - Output is in 'elfdump' style, designed for human eyes.
 *	Headers, and additional information are shown.
 * SIMPLE - Output is simple, consisting only of the target item.
 *	Integer values are shown as symbolic constants when possible,
 *	and integers otherwise.
 * NUM - Like SIMPLE, except integer values are always shown as
 *	integer constants, and strings are shown as the integer
 *	offset into the string table.
 */
typedef enum {
	ELFEDIT_OUTSTYLE_DEFAULT = 0,
	ELFEDIT_OUTSTYLE_SIMPLE = 1,
	ELFEDIT_OUTSTYLE_NUM = 2
} elfedit_outstyle_t;


/*
 * The elfedit_module_t, and the types it references, are defined
 * by loadable elfedit modules, and used by elfedit. These structures
 * need to communicate internationalized strings for elfedit to print.
 *
 * We want to leave the choice of internationalization APIs, as well as
 * the decision about whether or not to even to it to the individual
 * modules. Hence, we do not use a simple (const char *) pointer to
 * communicate potentially internationalized strings. Instead, we define
 * elfedit_i18nhdl_t, an opaque type guaranteed to be large enough
 * to hold a pointer. Each module casts the handle needed to access the
 * string to this type. Each module also supplies a function
 * (mod_i18nhdl_to_str field of elfedit_module_t) that given one
 * of these opaque keys, will return a (const char *) pointer to the
 * actual string, for elfedit to print.
 *
 * If the underlying module doesn't want to implement i18n support,
 * all it has to do is cast the strings to elfedit_i18nhdl_t and
 * back.
 */
typedef uintptr_t elfedit_i18nhdl_t;



/*
 * Macro to handle casting international string "handles" to the
 * elfedit_i18nhdl_t opaque type.
 */
#define	ELFEDIT_I18NHDL(_i18n_str_ref) ((elfedit_i18nhdl_t)_i18n_str_ref)


/*
 * Return values from command functions
 */
typedef enum {
	ELFEDIT_CMDRET_NONE = 0,	/* Nothing to report */
	ELFEDIT_CMDRET_MOD = 1,		/* Command modified output ELF file */
	ELFEDIT_CMDRET_FLUSH = 2	/* Output file flushed: elf_update() */
} elfedit_cmdret_t;

/*
 * Prototype of an implementation function for an edit command. Note that
 * commands do not return a status:
 *	- Success is indicated by a normal return.
 *	- The command indicates a fatal error by calling elfedit_msg() with the
 *		ELFEDIT_MSG_ERR type, in which case execution does not return
 *		to the command, and the elfedit command loop knows that an
 *		error occurred.
 *	- The command is responsible for using the standard libelf
 *		mechanisms to indicate when changes have been made to
 *		the ELF file.
 */
typedef elfedit_cmdret_t elfedit32_cmd_func_t(elfedit32_obj_state_t *state,
    int argc, const char *argv[]);
typedef elfedit_cmdret_t elfedit64_cmd_func_t(elfedit64_obj_state_t *state,
    int argc, const char *argv[]);
#ifdef _ELF64
#define	elfedit_cmd_func_t	elfedit64_cmd_func_t
#else
#define	elfedit_cmd_func_t	elfedit32_cmd_func_t
#endif


/*
 * An elfedit command (elfedit_cmd_t) has a cmd_cpl field that
 * can be set to a command completion function. If such a function
 * is present (non-NULL), and the user presses the tab key at the
 * command line while the cursor is at a plain (non option) argument,
 * elfedit calls the function, passing it all the tokens up through
 * the one needing completion.  The function can use elfedit_cpl_match()
 * to enter possible alternatives.  Additionally, there are helper
 * functions built on top of elfedit_cpl_match() that simplify common cases.
 *
 *	elfedit_cpl_ato[iu]() - enter matches from elfedit_ato[iu]_sym_t
 *		mappings.
 *	elfedit_cpl_atoconst() - Enter matches for well known constants
 *	elfedit_cpl_command() - enter matches for all known commands
 *	elfedit_cpl_mod() - enter matches for all known modules.
 *	elfedit_cpl_ndx() - enter numeric index as a match
 *
 * The completion function is passed the following arguments:
 *
 *	obj_state - Object state. Will be NULL if elfedit session does not
 *		have an active object. The completion function must test
 *		the pointer before using it.
 *	cpldata - Completion data, to be passed to elfedit_cpl_match()
 *		or the helper functions built on it to register alternative
 *		strings.
 *	argc, argv - The tokens from the start of the line throught
 *		the one needing completion, which will always
 *		be cmdcpl_argv[cmdcpl_argc - 1].
 *	num_opt - A count of the optional arguments (those starting with
 *		'-' at the beginning of argv. This means that argv[num_opt]
 *		is the first plain argument, and the 1-based positional
 *		number of the plain argument for which command completion
 *		is needed is (argc - num_opt).
 */
typedef void elfedit32_cmdcpl_func_t(elfedit32_obj_state_t *state,
    void *cpldata, int argc, const char *argv[], int num_opt);
typedef void elfedit64_cmdcpl_func_t(elfedit64_obj_state_t *state,
    void *cpldata, int argc, const char *argv[], int num_opt);
#ifdef _ELF64
#define	elfedit_cmdcpl_func_t	elfedit64_cmdcpl_func_t
#else
#define	elfedit_cmdcpl_func_t	elfedit32_cmdcpl_func_t
#endif




/*
 * Command option/argument descriptor. These structures
 * are used to represent each option and plain argument accepted
 * by a command, via the cmd_opt and cmd_args fields in the
 * command definition (elfedit_cmd_t). Each descriptor consists
 * of a name, a help string (formatted for display via sys:help),
 * and a flags field that conveys extra information about the
 * item:
 *
 *	ELFEDIT_CMDOA_F_OPT
 *	The item is optional. This flag is implicit for options
 *	and need only be set for plain arguments.
 *
 *	ELFEDIT_CMDOA_F_VALUE
 *	The item has a value, which is found in the following
 *	item. This flag only has meaning for options, and should
 *	not be set for plain arguments. The descriptor for the
 *	value is found in the next array element, and only the
 *	oa_name field is used (the other should be set t 0).
 *
 *	ELFEDIT_CMDOA_F_MULT
 *	More than one of the specified items may be specified
 *
 *	ELFEDIT_CMDOA_F_INHERIT
 *	This is an item for which a common definition exists.
 *	Elfedit will substitute the standard values for the
 *	name, help text, and flags. This enforces consistency
 *	in documentation, plus it is easier for the module author.
 *	When ELFEDIT_CMDOA_F_INHERIT is set:
 *		- oa_name should be set to one of the ELFEDIT_STDOA_
 *			values to specifiy which standard item is being
 *			inherited.
 *		- oa_help must be set to NULL.
 *		- It is an error to set any other flags with
 *			ELFEDIT_CMDOA_F_INHERIT.
 *		- oa_idmask and oa_excmask are used in the normal way.
 *
 * The oa_idmask and oa_excmask fields are used to identify options,
 * and to support mutual exclusion (when two or more options cannot be
 * used together). They are ignored for arguments, and should be set to 0.
 * oa_idmask is used to uniquely identify each item. When elfedit_getopt()
 * matches an option, it returns the value of oa_idmask to the caller to
 * indicate which option was matched. elfedit enforces the following rules
 * for oa_idmask, and will refuse to load a module that does not follow them:
 *	- The value of oa_idmask must be 0, or have a value that
 *		is a power of 2 (i.e. only has one bit set).
 *	- Each item that sets a non-0 value for oa_idmask must have
 *		a unique value.
 *	- If oa_idmask is 0, oa_excmask must be 0 also.
 *	- oa_excmask is set to 0 if an item is not mutually exclusive
 *		to any other item. Otherwise, it should set the bit
 *		values representing the items it is mutually exclusive to.
 *	- An oa_idmask value of 0 can be used for any item that
 *		the module does not need to identify, and which
 *		is not mutually exclusive to any other item.
 * As elfedit_getopt() processes items, it maintains a bitmask combining the
 * oa_idmask fields of all the options already seen. For each option, it uses
 * oa_excmask to check for conflicts.
 *
 * note: elfedit enforces the rule that options consist of a '-'
 *	character followed by at least one character when a module
 *	is loaded.
 */
typedef enum {
	ELFEDIT_CMDOA_F_OPT =	1,	/* Item is optional */
	ELFEDIT_CMDOA_F_VALUE =	2,	/* Item has a value arg following */
	ELFEDIT_CMDOA_F_MULT =	4,	/* More than one are allowed */
	ELFEDIT_CMDOA_F_INHERIT = 8,	/* Inherit definition: See above */
} elfedit_cmd_oa_flag_t;

typedef u_longlong_t elfedit_cmd_oa_mask_t;

typedef struct {
	const char		*oa_name;	/* Name of option */
	elfedit_i18nhdl_t	oa_help;	/* Help text for option */
	elfedit_cmd_oa_flag_t	oa_flags;	/* Additional attributes */
	elfedit_cmd_oa_mask_t	oa_idmask;	/* Unique id, returned by */
						/* 	elfedit_getopt */
						/*	for use by caller */
	elfedit_cmd_oa_mask_t	oa_excmask;	/* Mutual exclusion mask */
} elfedit_cmd_optarg_t;



/*
 * These values define the standard options and arguments that a module
 * can inherit using the ELFEDIT_CMDOA_F_INHERIT flag (described above).
 * New items must be added at the end --- reordering the list will
 * require all modules to be rebuilt.
 *
 * Note: 0 cannot be used as a ELFEDIT_STDOA_ value, because a NULL
 *	value of oa_name is used to terminate argument and options lists.
 *	Therefore, these values start at 1.
 */
#define	ELFEDIT_STDOA_OPT_O		((const char *) 1)	/* -o ostyle */
#define	ELFEDIT_STDOA_OPT_AND		((const char *) 2)	/* -and */
#define	ELFEDIT_STDOA_OPT_CMP		((const char *) 3)	/* -cmp */
#define	ELFEDIT_STDOA_OPT_OR		((const char *) 4)	/* -or */

#define	ELFEDIT_NUM_STDOA	4	/* # of ELFEDIT_STDOA_ definitions */



/*
 * Definition of a command
 *
 * This structure includes an elfedit_cmd_func_t pointer, which has
 * different definitions for different ELFCLASS. Rather than needlessly
 * complicate the code with three versions of this type, and any
 * type that uses it, we simply use the GenericClass type. elfedit
 * will always cast this to the correct type before calling a module.
 *
 * cmd_name is an array of pointers to the names for the command.
 * The "primary" name should always be first, followed by any alias
 * names. The final element of the array must be a NULL pointer,
 * which terminates the list. Every command is required to have at
 * least one name, so code is allowed to assume that the first element
 * of cmd_name is non-NULL, and contains the primary name.
 *
 * Many modules provide a "default" command, which is a command
 * that is run if only the module name is specified, followed
 * by a colon (i.e. "sym:"). The way this is implemented is to
 * give the desired default command an empty string as an alias.
 * Note that the primary name cannot be an empty string, only the
 * alias name.
 *
 * cmd_opts and cmd_args are each an array of elfedit_cmd_argdesc_t
 * structures, that describe the options and plain arguments accepted
 * by the command. These arrays are used to general help text for
 * the commands. The cmd_opts array is also used to provide command
 * completion for options. Both of these arrays are terminated by
 * a final NULL element (all fields zero).
 */
typedef struct {
	elfedit32_cmd_func_t	*cmd_func;	/* Implementation */
	elfedit32_cmdcpl_func_t	*cmd_cplfunc;	/* Completion function */
	const char		**cmd_name;	/* Cmd names (null term.) */
	elfedit_i18nhdl_t	cmd_desc;	/* Short desc. of cmd purpose */
	elfedit_i18nhdl_t	cmd_help;	/* Help text for the command */
	elfedit_cmd_optarg_t	*cmd_opt;	/* Options */
	elfedit_cmd_optarg_t	*cmd_args;	/* Plain arguments */
} elfedit32_cmd_t;

typedef struct {
	elfedit64_cmd_func_t	*cmd_func;
	elfedit64_cmdcpl_func_t	*cmd_cplfunc;
	const char		**cmd_name;
	elfedit_i18nhdl_t	cmd_desc;
	elfedit_i18nhdl_t	cmd_help;
	elfedit_cmd_optarg_t	*cmd_opt;
	elfedit_cmd_optarg_t	*cmd_args;
} elfedit64_cmd_t;

#ifdef _ELF64
#define	elfedit_cmd_t		elfedit64_cmd_t
#else
#define	elfedit_cmd_t		elfedit32_cmd_t
#endif



/*
 * elfedit modules version themselves so that we can alter the definition
 * of elfedit_module_t in a backward compatible way.
 */
typedef enum {
	ELFEDIT_VER_NONE = 0,
	ELFEDIT_VER_CURRENT = 1,
	ELFEDIT_VER_NUM = 2
} elfedit_module_version_t;


/*
 * Each module returns a pointer to an elfedit_module_t, describing
 * what commands the module provides.
 *
 * Note: mod_cmds is a NULL terminated array of command defs. This
 * means that the final element in the array should have all of its
 * fields set to NULL.
 *
 * The mod_i18nhdl_to_str function pointer is explained above
 * with the definition of elfedit_i18nhdl_t.
 */
typedef const char *(* elfedit_mod_i18nhdl_to_str_func_t)(elfedit_i18nhdl_t);

typedef struct {
	elfedit_module_version_t mod_version;	/* version */
	const char		*mod_name;	/* Name of module */
	elfedit_i18nhdl_t	mod_desc;	/* Short desc. of mod purpose */
	elfedit32_cmd_t		*mod_cmds;	/* Array of command defs */
						/* i18n -> (char *) fcn */
	elfedit_mod_i18nhdl_to_str_func_t mod_i18nhdl_to_str;
} elfedit32_module_t;

typedef struct {
	elfedit_module_version_t mod_version;
	const char		*mod_name;
	elfedit_i18nhdl_t	mod_desc;
	elfedit64_cmd_t		*mod_cmds;
	elfedit_mod_i18nhdl_to_str_func_t mod_i18nhdl_to_str;
} elfedit64_module_t;

#ifdef _ELF64
#define	elfedit_module_t	elfedit64_module_t
#else
#define	elfedit_module_t	elfedit32_module_t
#endif


/*
 * Each module is a sharable library, expected to provide a single global
 * function, named elfedit_init(), with the following prototype.
 */
typedef elfedit_module_t *elfedit_init_func_t(elfedit_module_version_t version);


/*
 * Prototype for elfedit_write(), and for outfunc argument
 * to elfedit_str_to_c_literal().
 */
typedef void elfedit_write_func_t(const void *ptr, size_t size);


/*
 * Core elfedit functions exported for use by modules
 */
extern void elfedit_command_usage(void);
extern void elfedit_cpl_command(void *cpldata);
extern void elfedit_cpl_match(void *cpldata, const char *str, int casefold);
extern void elfedit_cpl_ndx(void *cpldata, uint_t ndx);
extern void elfedit_elferr(const char *file, const char *libelf_rtn_name);
extern elfedit_flag_t elfedit_flags(void);
extern void *elfedit_malloc(const char *item_name, size_t size);
extern void elfedit_msg(elfedit_msg_t type, const char *format, ...);
extern elfedit_outstyle_t elfedit_outstyle(void);
extern void elfedit_pager_init(void);
extern void elfedit_printf(const char *format, ...);
extern void *elfedit_realloc(const char *item_name, void *ptr, size_t size);
extern void elfedit_str_to_c_literal(const char *str,
    elfedit_write_func_t *outfunc);
extern elfedit_write_func_t elfedit_write;

/*
 * Core elfedit functions exported for use by sys: module only
 */
extern void elfedit_cpl_module(void *cpldata, int load_all_modules);


/*
 * elfedit modules are expected to define two functions, one for
 * each ELFCLASS. Define a generic name for this function, based on
 * the class being supported by the including module.
 */
#ifdef _ELF64
#define	elfedit_init		elfedit64_init
#else
#define	elfedit_init		elfedit32_init
#endif



/*
 * It is common to search the dynamic section for specific elements.
 * Structures of this type are used to represent the contents of such
 * elements in a systematic way. The elfedit_dyn_elt_init() function
 * is used to prepare these strucutres for use.
 */
typedef struct {
	int		dn_seen;	/* True if this item has been seen */
	Elf32_Word	dn_ndx;		/* Index of item in dynamic array */
	Elf32_Dyn	dn_dyn;		/* Contents of dynamic item */
} elfedit32_dyn_elt_t;

typedef struct {
	int		dn_seen;
	Elf64_Word	dn_ndx;
	Elf64_Dyn	dn_dyn;
} elfedit64_dyn_elt_t;

#ifdef _ELF64
#define	elfedit_dyn_elt_t	elfedit64_dyn_elt_t
#else
#define	elfedit_dyn_elt_t	elfedit32_dyn_elt_t
#endif

/*
 * The elfedit_atoi() and elfedit_atoui() functions can optionally
 * accept an array of these structures, giving symbolic names that
 * will be accepted instead of numeric codes. If such an array is
 * present, the supplied string has it's leading and trailing whitespace
 * removed and is then compared to the list, and if there is a match,
 * the corresponding integer value is returned.
 *
 * The final array element must have its name field set to NULL.
 */
typedef u_longlong_t elfedit_atoui_t;
typedef struct {
	const char	*sym_name;
	elfedit_atoui_t	sym_value;
} elfedit_atoui_sym_t;
typedef longlong_t elfedit_atoi_t;
typedef struct {
	const char	*sym_name;
	elfedit_atoi_t	sym_value;
} elfedit_atoi_sym_t;


/*
 * The elfedit_atoconst*() functions are built on top of the atoui routines.
 * These routines accept an elfedit_const_t code instead of a
 * pointer to an elfedit_atoui_sym_t array, and use internally
 * predefined tables of elfedit_atoui_sym_t in order to do the desired
 * mappings. elfedit modules are encouraged to use these standard
 * tables instead of defining their own elfedit_atoui_sym_t arrays.
 *
 * note:
 *	- The values assigned here must be in agreement with the
 *		sym_table[] array defined in elfconst.c.
 *	- Once defined, these values must not change. Reordering the
 *		list will require all modules to be rebuilt, and will
 *		break backward compatability. New items should be
 *		added to the end.
 */
typedef enum {
	ELFEDIT_CONST_OUTSTYLE =	0,	/* elfedit output styles  */
	ELFEDIT_CONST_OUTSTYLE_MO =	1,	/* ostyles with -o prefix */
	ELFEDIT_CONST_BOOL =		2,	/* boolean names */
	ELFEDIT_CONST_SHN =		3,	/* ELF SHN_ section indexes  */
	ELFEDIT_CONST_SHT =		4,	/* ELF SHT_ section types  */
	ELFEDIT_CONST_SHT_STRTAB =	5,	/* ELF SHT_STRTAB */
	ELFEDIT_CONST_SHT_ALLSYMTAB =	6,	/* ELF SHT_ symbol table */
						/*	section types */
	ELFEDIT_CONST_SHT_SYMTAB =	7,	/* ELF SHT_SYMTAB */
	ELFEDIT_CONST_SHT_DYNSYM =	8,	/* ELF SHT_DYNSYM */
	ELFEDIT_CONST_SHT_LDYNSYM =	9,	/* ELF SHT_SUNW_LDYNSYM */
	ELFEDIT_CONST_DT =		10,	/* Dynamic tags: DT_ */
	ELFEDIT_CONST_DF =		11,	/* DT_FLAGS bits */
	ELFEDIT_CONST_DF_P1 =		12,	/* DF_POSFLAG_1 bits */
	ELFEDIT_CONST_DF_1 =		13,	/* DT_FLAGS_1 bits */
	ELFEDIT_CONST_DTF_1 =		14,	/* DT_FEATURE_1 bits */
	ELFEDIT_CONST_EI =		15,	/* ELF header e_ident indexes */
	ELFEDIT_CONST_ET =		16,	/* Ehdr obj type */
	ELFEDIT_CONST_ELFCLASS =	17,	/* Ehdr wordsize (32,64) */
	ELFEDIT_CONST_ELFDATA =		18,	/* Ehdr endian */
	ELFEDIT_CONST_EF =		19,	/* Ehdr flags */
	ELFEDIT_CONST_EV =		20,	/* Ehdr version */
	ELFEDIT_CONST_EM =		21,	/* Ehdr machine */
	ELFEDIT_CONST_ELFOSABI =	22,	/* Ehdr ABI */
	ELFEDIT_CONST_PT =		23,	/* Phdr type */
	ELFEDIT_CONST_PF =		24,	/* Phdr flags */
	ELFEDIT_CONST_SHF =		25,	/* Shdr flags */
	ELFEDIT_CONST_STB =		26,	/* Sym binding */
	ELFEDIT_CONST_STT =		27,	/* Sym type */
	ELFEDIT_CONST_STV =		28,	/* Sym visibility */
	ELFEDIT_CONST_SYMINFO_BT =	29,	/* Syminfo boundto */
	ELFEDIT_CONST_SYMINFO_FLG =	30,	/* Syminfo flags */
	ELFEDIT_CONST_CA =		31,	/* Capabilities tags: CA_ */
	ELFEDIT_CONST_AV_386 =		32,	/* X86 hardware caps */
	ELFEDIT_CONST_AV_SPARC =	33,	/* sparc hardware caps */
	ELFEDIT_CONST_SF1_SUNW =	34,	/* software capabilities */
} elfedit_const_t;

/*
 * Given an elfedit_const_t, return the array of elfedit_atoui_sym_t
 * entries that it represents.
 */
extern elfedit_atoui_sym_t *elfedit_const_to_atoui(elfedit_const_t const_type);

/*
 * Return the elfedit_atoui_t array that corresponds to the
 * CA_SUNW_HW_1 hardware capabiliies field for a given
 * machine type.
 */
extern elfedit_atoui_sym_t *elfedit_mach_sunw_hw1_to_atoui(int mach);

/*
 * ato[u]i and const routines, used to turn strings into numeric values,
 * with support for mapping symbol names to numbers, and range checking.
 */
extern elfedit_atoi_t elfedit_atoi(const char *str,
    const elfedit_atoi_sym_t *sym);
extern elfedit_atoui_t elfedit_atoui(const char *str,
    const elfedit_atoui_sym_t *sym);
extern elfedit_atoui_t elfedit_atoconst(const char *str,
    elfedit_const_t const_type);

extern int elfedit_atoi2(const char *str, const elfedit_atoi_sym_t *sym,
    elfedit_atoi_t *v);
extern int elfedit_atoui2(const char *str, const elfedit_atoui_sym_t *sym,
    elfedit_atoui_t *);
extern int elfedit_atoconst2(const char *str, elfedit_const_t const_type,
    elfedit_atoui_t *);

extern elfedit_atoi_t elfedit_atoi_range(const char *str,
    const char *item_name, elfedit_atoi_t min, elfedit_atoi_t max,
    const elfedit_atoi_sym_t *sym);
extern elfedit_atoui_t elfedit_atoui_range(const char *str,
    const char *item_name, elfedit_atoui_t min, elfedit_atoui_t max,
    const elfedit_atoui_sym_t *sym);
extern elfedit_atoui_t elfedit_atoconst_range(const char *str,
    const char *item_name, elfedit_atoui_t min, elfedit_atoui_t max,
    elfedit_const_t const_type);

extern int elfedit_atoi_range2(const char *str, elfedit_atoi_t min,
    elfedit_atoi_t max, const elfedit_atoi_sym_t *sym, elfedit_atoi_t *v);
extern int elfedit_atoui_range2(const char *str, elfedit_atoui_t min,
    elfedit_atoui_t max, const elfedit_atoui_sym_t *sym, elfedit_atoui_t *v);
extern int elfedit_atoconst_range2(const char *str, elfedit_atoui_t min,
    elfedit_atoui_t max, elfedit_const_t const_type, elfedit_atoui_t *v);

extern const char *elfedit_atoi_value_to_str(const elfedit_atoi_sym_t *sym,
    elfedit_atoi_t value, int required);
extern const char *elfedit_atoui_value_to_str(const elfedit_atoui_sym_t *sym,
    elfedit_atoui_t value, int required);
extern const char *elfedit_atoconst_value_to_str(elfedit_const_t const_type,
    elfedit_atoui_t value, int required);

extern void elfedit_cpl_atoi(void *cpldata, const elfedit_atoi_sym_t *sym);
extern void elfedit_cpl_atoui(void *cpldata, const elfedit_atoui_sym_t *sym);
extern void elfedit_cpl_atoconst(void *cpldata, elfedit_const_t const_type);


/*
 * Convenience functions built on top of the ato[u]i routines.
 */
extern int elfedit_atobool(const char *str, const char *item_name);
extern elfedit_atoui_t elfedit_atoshndx(const char *str, size_t shnum);


/*
 * elfedit provides a getopt utility for use by the module commands.
 * elfedit_getopt_state_t is the state block used by elfedit_getopt().
 * elfedit_getopt_ret_t is the definition of the values returned to
 * the user by elfedit_getopt() when an option is matched. Elfedit
 * getopt processing is done as follows:
 *
 * 1) The caller initializes an elfedit_getopt_state_t struct via
 *	a call to elfedit_getopt_init(). The contents of this structure
 *	must not be accessed by the caller, as they are all private and
 *	subject to change.
 * 2) Repeated calls are made to elfedit_getopt(), as long as it returns
 *	a non-NULL pointer to an elfedit_getopt_ret_t structure. If the
 *	matched option has a value (ELFEDIT_CMDOA_F_VALUE), then the gor_value
 *	field contains the pointer to the string. Otherwise, gor_value is NULL.
 * 3) As elfedit_getopt() consumes optional arguments from the argc/argv
 *	passed to elfedit_getopt_init(), it adjusts argc/argc to skip over
 *	them. Once elfedit_getopt() returns NULL to indicate that there are no
 *	more options to match, argc/argv have been adjusted so that they
 *	reference the plain arguments.
 */
typedef struct {
	elfedit_cmd_oa_mask_t gor_idmask;	/* oa_idmask from matching */
					/*	elfedit_cmd_optarg_t. Can be */
					/*	used to quickly identify opt */
	const char	*gor_value;	/* Opt value if ELFEDIT_CMDOA_F_VALUE */
					/*	Otherwise, NULL */
} elfedit_getopt_ret_t;
typedef struct {
	int			*go_argc;	/* Pointer to # of options */
	const char		***go_argv;	/* Ptr to array of opt strs */
	elfedit_cmd_optarg_t	*go_optarg;	/* Array of allowed options */
	elfedit_cmd_oa_mask_t	go_idmask;	/* Combined id masks of all */
						/*	seen options */
	int			go_done;	/* True if last option seen */
	const char		*go_sglgrp;	/* Group of 1-letter opts */
	elfedit_getopt_ret_t	go_ret;		/* Data returned to user */
} elfedit_getopt_state_t;



/*
 * getopt related routines
 */
extern void elfedit_getopt_init(elfedit_getopt_state_t *,
    int *, const char ***);
extern elfedit_getopt_ret_t *elfedit_getopt(elfedit_getopt_state_t *);



/*
 * Additional utility functions exported for use by modules
 */
extern void elfedit_array_elts_delete(const char *name_str, void *data_start,
    size_t entsize, size_t num_ent, size_t start_ndx, size_t cnt);

extern void elfedit_array_elts_move(const char *name_str, void *data_start,
    size_t entsize, size_t num_ent, size_t srcndx,
    size_t dstndx, size_t cnt, void *scr_item);

extern int elfedit_bits_set(u_longlong_t v, int sizeof_orig_v);

extern void elfedit32_dyn_elt_init(elfedit32_dyn_elt_t *dyn_elt);
extern void elfedit64_dyn_elt_init(elfedit64_dyn_elt_t *dyn_elt);

extern void elfedit32_dyn_elt_save(elfedit32_dyn_elt_t *elt, Elf32_Word ndx,
    Elf32_Dyn *dyn);
extern void elfedit64_dyn_elt_save(elfedit64_dyn_elt_t *elt, Elf64_Word ndx,
    Elf64_Dyn *dyn);

const char *elfedit32_dyn_offset_to_str(elfedit32_section_t *strsec,
    elfedit32_dyn_elt_t *dynelt);
const char *elfedit64_dyn_offset_to_str(elfedit64_section_t *strsec,
    elfedit64_dyn_elt_t *dynelt);

extern int elfedit32_dynstr_getpad(elfedit32_section_t *dynsec,
    elfedit32_dyn_elt_t *dyn_strpad);
extern int elfedit64_dynstr_getpad(elfedit64_section_t *dynsec,
    elfedit64_dyn_elt_t *dyn_strpad);

extern Elf32_Word elfedit32_dynstr_insert(elfedit32_section_t *dynsec,
    elfedit32_section_t *strsec, elfedit32_dyn_elt_t *dyn_strpad,
    const char *str);
extern Elf64_Word elfedit64_dynstr_insert(elfedit64_section_t *dynsec,
    elfedit64_section_t *strsec, elfedit64_dyn_elt_t *dyn_strpad,
    const char *str);

extern void elfedit32_modified_data(elfedit32_section_t *s);
extern void elfedit64_modified_data(elfedit64_section_t *s);

extern void elfedit32_modified_ehdr(elfedit32_obj_state_t *obj_state);
extern void elfedit64_modified_ehdr(elfedit64_obj_state_t *obj_state);

extern void elfedit32_modified_phdr(elfedit32_obj_state_t *obj_state);
extern void elfedit64_modified_phdr(elfedit64_obj_state_t *obj_state);

extern void elfedit32_modified_shdr(elfedit32_section_t *s);
extern void elfedit64_modified_shdr(elfedit64_section_t *s);

extern Elf32_Word elfedit32_name_to_shndx(elfedit32_obj_state_t *obj_state,
    const char *shnam);
extern Elf64_Word elfedit64_name_to_shndx(elfedit64_obj_state_t *obj_state,
    const char *shnam);

extern Elf32_Word elfedit32_type_to_shndx(elfedit32_obj_state_t *obj_state,
    Elf32_Word shtype);
extern Elf64_Word elfedit64_type_to_shndx(elfedit64_obj_state_t *obj_state,
    Elf64_Word shtype);

extern int elfedit32_name_to_symndx(elfedit32_section_t *symsec,
    elfedit32_section_t *strsec, const char *name, elfedit_msg_t msg_type,
    Elf32_Word *ret_symndx);
extern int elfedit64_name_to_symndx(elfedit64_section_t *symsec,
    elfedit64_section_t *strsec, const char *name, elfedit_msg_t msg_type,
    Elf64_Word *ret_symndx);

extern const char *elfedit32_offset_to_str(elfedit32_section_t *strsec,
    Elf32_Word offset, elfedit_msg_t msg_type, int debug_msg);
extern const char *elfedit64_offset_to_str(elfedit64_section_t *strsec,
    Elf64_Word offset, elfedit_msg_t msg_type, int debug_msg);

extern int elfedit32_sec_findstr(elfedit32_section_t *sec, Elf32_Word tail_ign,
    const char *str, Elf32_Word *ret_offset);
extern int elfedit64_sec_findstr(elfedit64_section_t *sec, Elf64_Word tail_ign,
    const char *str, Elf64_Word *ret_offset);

extern elfedit32_section_t *elfedit32_sec_get(
    elfedit32_obj_state_t *obj_state, Elf32_Word shndx);
extern elfedit64_section_t *elfedit64_sec_get(
    elfedit64_obj_state_t *obj_state, Elf64_Word shndx);

extern elfedit32_section_t *elfedit32_sec_getcap(
    elfedit32_obj_state_t *obj_state, Elf32_Cap **cap, Elf32_Word *num);
extern elfedit64_section_t *elfedit64_sec_getcap(
    elfedit64_obj_state_t *obj_state, Elf64_Cap **cap, Elf64_Word *num);

extern elfedit32_section_t *elfedit32_sec_getdyn(
    elfedit32_obj_state_t *obj_state, Elf32_Dyn **dyn, Elf32_Word *num);
extern elfedit64_section_t *elfedit64_sec_getdyn(
    elfedit64_obj_state_t *obj_state, Elf64_Dyn **dyn, Elf64_Word *num);

extern elfedit32_section_t *elfedit32_sec_getstr(
    elfedit32_obj_state_t *obj_state, Elf32_Word shndx, int);
extern elfedit64_section_t *elfedit64_sec_getstr(
    elfedit64_obj_state_t *obj_state, Elf64_Word shndx, int);

extern elfedit32_section_t *elfedit32_sec_getsyminfo(
    elfedit32_obj_state_t *obj_state, Elf32_Syminfo **syminfo, Elf32_Word *num);
extern elfedit64_section_t *elfedit64_sec_getsyminfo(
    elfedit64_obj_state_t *obj_state, Elf64_Syminfo **syminfo, Elf64_Word *num);

extern elfedit32_section_t *elfedit32_sec_getsymtab(
    elfedit32_obj_state_t *obj_state, int by_index, Elf32_Word index,
    const char *name, Elf32_Sym **sym, Elf32_Word *num,
    elfedit32_symtab_t **aux_info);
extern elfedit64_section_t *elfedit64_sec_getsymtab(
    elfedit64_obj_state_t *obj_state, int by_index, Elf64_Word index,
    const char *name, Elf64_Sym **sym, Elf64_Word *num,
    elfedit64_symtab_t **aux_info);

extern elfedit32_section_t *elfedit32_sec_getversym(
    elfedit32_obj_state_t *obj_state, elfedit32_section_t *symsec,
    Elf32_Versym **versym, Elf32_Word *num);
extern elfedit64_section_t *elfedit64_sec_getversym(
    elfedit64_obj_state_t *obj_state, elfedit64_section_t *symsec,
    Elf64_Versym **versym, Elf64_Word *num);

extern elfedit32_section_t *elfedit32_sec_getxshndx(
    elfedit32_obj_state_t *obj_state, elfedit32_section_t *symsec,
    Elf32_Word **xshndx, Elf32_Word *num);
extern elfedit64_section_t *elfedit64_sec_getxshndx(
    elfedit64_obj_state_t *obj_state, elfedit64_section_t *symsec,
    Elf64_Word **xshndx, Elf64_Word *num);

extern int elfedit32_sec_issymtab(elfedit32_section_t *sec, int issue_err,
    elfedit_atoui_sym_t **atoui_list);
extern int elfedit64_sec_issymtab(elfedit64_section_t *sec, int issue_err,
    elfedit_atoui_sym_t **atoui_list);

extern const char *elfedit32_sec_msgprefix(elfedit32_section_t *sec);
extern const char *elfedit64_sec_msgprefix(elfedit64_section_t *sec);

extern const char *elfedit32_shndx_to_name(elfedit32_obj_state_t *obj_state,
    Elf32_Word shndx);
extern const char *elfedit64_shndx_to_name(elfedit64_obj_state_t *obj_state,
    Elf64_Word shndx);

extern Elf32_Word elfedit32_strtab_insert(elfedit32_obj_state_t *obj_state,
    elfedit32_section_t *strsec, elfedit32_section_t *dynsec, const char *str);
extern Elf64_Word elfedit64_strtab_insert(elfedit64_obj_state_t *obj_state,
    elfedit64_section_t *strsec, elfedit64_section_t *dynsec, const char *str);

extern void elfedit32_strtab_insert_test(elfedit32_obj_state_t *obj_state,
    elfedit32_section_t *strsec, elfedit32_section_t *dynsec, const char *str);
extern void elfedit64_strtab_insert_test(elfedit64_obj_state_t *obj_state,
    elfedit64_section_t *strsec, elfedit64_section_t *dynsec, const char *str);

extern Elf32_Word elfedit32_type_to_shndx(elfedit32_obj_state_t *obj_state,
    Elf32_Word shtype);
extern Elf64_Word elfedit64_type_to_shndx(elfedit64_obj_state_t *obj_state,
    Elf64_Word shtype);



/*
 * Map the generic names for each of the ELFCLASS specific routines
 * above to reference the proper routine for the current compilation.
 */
#ifdef _ELF64
#define	elfedit_dyn_elt_init		elfedit64_dyn_elt_init
#define	elfedit_dyn_elt_save		elfedit64_dyn_elt_save
#define	elfedit_dyn_offset_to_str	elfedit64_dyn_offset_to_str
#define	elfedit_dynstr_getpad		elfedit64_dynstr_getpad
#define	elfedit_dynstr_insert		elfedit64_dynstr_insert
#define	elfedit_modified_data		elfedit64_modified_data
#define	elfedit_modified_ehdr		elfedit64_modified_ehdr
#define	elfedit_modified_phdr		elfedit64_modified_phdr
#define	elfedit_modified_shdr		elfedit64_modified_shdr
#define	elfedit_name_to_shndx		elfedit64_name_to_shndx
#define	elfedit_name_to_symndx		elfedit64_name_to_symndx
#define	elfedit_offset_to_str		elfedit64_offset_to_str
#define	elfedit_sec_findstr		elfedit64_sec_findstr
#define	elfedit_sec_get			elfedit64_sec_get
#define	elfedit_sec_getcap		elfedit64_sec_getcap
#define	elfedit_sec_getdyn		elfedit64_sec_getdyn
#define	elfedit_sec_getstr		elfedit64_sec_getstr
#define	elfedit_sec_getsyminfo		elfedit64_sec_getsyminfo
#define	elfedit_sec_getsymtab		elfedit64_sec_getsymtab
#define	elfedit_sec_getversym		elfedit64_sec_getversym
#define	elfedit_sec_getxshndx		elfedit64_sec_getxshndx
#define	elfedit_sec_issymtab		elfedit64_sec_issymtab
#define	elfedit_shndx_to_name		elfedit64_shndx_to_name
#define	elfedit_sec_msgprefix		elfedit64_sec_msgprefix
#define	elfedit_strtab_insert		elfedit64_strtab_insert
#define	elfedit_strtab_insert_test	elfedit64_strtab_insert_test
#define	elfedit_type_to_shndx		elfedit64_type_to_shndx
#else
#define	elfedit_dyn_elt_init		elfedit32_dyn_elt_init
#define	elfedit_dyn_elt_save		elfedit32_dyn_elt_save
#define	elfedit_dyn_offset_to_str	elfedit32_dyn_offset_to_str
#define	elfedit_dynstr_getpad		elfedit32_dynstr_getpad
#define	elfedit_dynstr_insert		elfedit32_dynstr_insert
#define	elfedit_modified_data		elfedit32_modified_data
#define	elfedit_modified_ehdr		elfedit32_modified_ehdr
#define	elfedit_modified_phdr		elfedit32_modified_phdr
#define	elfedit_modified_shdr		elfedit32_modified_shdr
#define	elfedit_name_to_shndx		elfedit32_name_to_shndx
#define	elfedit_name_to_symndx		elfedit32_name_to_symndx
#define	elfedit_offset_to_str		elfedit32_offset_to_str
#define	elfedit_sec_findstr		elfedit32_sec_findstr
#define	elfedit_sec_get			elfedit32_sec_get
#define	elfedit_sec_getcap		elfedit32_sec_getcap
#define	elfedit_sec_getdyn		elfedit32_sec_getdyn
#define	elfedit_sec_getstr		elfedit32_sec_getstr
#define	elfedit_sec_getsyminfo		elfedit32_sec_getsyminfo
#define	elfedit_sec_getsymtab		elfedit32_sec_getsymtab
#define	elfedit_sec_getversym		elfedit32_sec_getversym
#define	elfedit_sec_getxshndx		elfedit32_sec_getxshndx
#define	elfedit_sec_issymtab		elfedit32_sec_issymtab
#define	elfedit_shndx_to_name		elfedit32_shndx_to_name
#define	elfedit_sec_msgprefix		elfedit32_sec_msgprefix
#define	elfedit_strtab_insert		elfedit32_strtab_insert
#define	elfedit_strtab_insert_test	elfedit32_strtab_insert_test
#define	elfedit_type_to_shndx		elfedit32_type_to_shndx
#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _ELFEDIT_H */
