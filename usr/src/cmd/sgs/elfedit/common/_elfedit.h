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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__ELFEDIT_H
#define	__ELFEDIT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<setjmp.h>
#include	<libtecla.h>
#include	<elfedit.h>

/*
 * Local include file for elfedit.
 */
#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Maximum command line, and history
 */
#define	ELFEDIT_MAXCMD	1024
#define	ELFEDIT_MAXHIST	1024

/* Maximum number of command completion arguments */
#define	ELFEDIT_MAXCPLARGS	128

/* Maximum length of a module name */
#define	ELFEDIT_MAXMODNAM	64


/*
 * In elfedit.h, you will find elfedit32_cmd_t and elfedit64_cmd_t
 * typedefs. These types are identical, except for the definition
 * of the cmd_func and cmd_cplfunc function pointers. These function
 * pointers have different argument definitions that reflect the
 * different object state definition blocks for the 32 and 64-bit cases.
 * Yet, From a strictly machine based view, these two types are identical
 * in size and layout:
 *
 *	- At the machine level, all function pointers are simply
 *		machine sized words containing an address.
 *
 *	- Other than the function pointers, the remaining fields
 *		are exactly the same in both cases.
 *
 * The vast majority of elfedit's internals that examine elfedit_cmd_t
 * are looking at the non-function pointer fields. It simplfiies
 * a great deal of code if we can treat elfedit32_cmd_t and elfedit64_cmd_t
 * as equivalent types for this purpose. In C++, we would do this with
 * a superclass. In C, we do it by defining another variant named
 * elfeditGC_cmd_t (GC stands for "Generic Class"). The function pointers
 * are replaced with (void *) pointers. This variant has the same size
 * and layout as the others. We use it internally to represent either type.
 * In the cases where we need to use the function pointers, we first cast
 * them to the proper type for the ELFCLASS being processed.
 *
 * The existance of elfeditGC_cmd_t implies the need for elfeditGC_module_t,
 * for the same reasons.
 *
 * It is extremely important that these definitions exactly mirror the
 * definitions in elfedit.h.
 */
typedef struct {
	void			*cmd_func;
	void			*cmd_cplfunc;
	const char		**cmd_name;
	elfedit_i18nhdl_t	cmd_desc;
	elfedit_i18nhdl_t	cmd_help;
	elfedit_cmd_optarg_t	*cmd_opt;
	elfedit_cmd_optarg_t	*cmd_args;
} elfeditGC_cmd_t;


typedef struct {
	elfedit_module_version_t mod_version;
	const char		*mod_name;
	elfedit_i18nhdl_t	mod_desc;
	elfeditGC_cmd_t		*mod_cmds;
	elfedit_mod_i18nhdl_to_str_func_t mod_i18nhdl_to_str;
} elfeditGC_module_t;


/*
 * The result of parsing a user command is one of these blocks entered
 * at the end of state.user_cmd. They encapsulate the arguments and
 * the command function to call. In combination with an elfedit_obj_state_t,
 * they contain everything needed to execute a specified operation. A single
 * call to free() suffices to release the ELFEDIT_USER_CMD and any memory
 * it references.
 */
typedef struct user_cmd_t {
	struct user_cmd_t *ucmd_next;	/* Commands are kept in linked list */
	int		ucmd_argc;	/* # of arguments to command */
	const char	**ucmd_argv;	/* Argument strings */
	char		*ucmd_orig_str;	/* Command string as entered by user */
	elfeditGC_module_t *ucmd_mod;	/* Module defining command */
	elfeditGC_cmd_t	*ucmd_cmd;	/* Command to call */
	int		ucmd_ostyle_set;	/* True if there is a per-cmd */
						/* 	output style active */
	elfedit_outstyle_t ucmd_ostyle; /* Per-cmd output style, if active */
} USER_CMD_T;

/*
 * MODLIST_T is used to manage module definitions. Note that a simple linked
 * list is used to maintain the set of active modules. This can be easily
 * changed if the number of modules grows to a point where the lookup
 * time is noticible.
 */
typedef struct moddef_t {
	struct moddef_t		*ml_next;	/* Used for list of open mods */
	elfeditGC_module_t	*ml_mod;	/* The module definition */
	void			*ml_dl_hdl;	/* dlopen() handle for lib */
	const char		*ml_path;	/* Path used to open lib */
} MODLIST_T;


/*
 * Type of the global variable used to maintain elfedit state.
 */
typedef struct {
	MODLIST_T *modlist;		/* List of loaded commands */
	elfedit_flag_t	flags;		/* ELFEDIT_F_ command line options */
	elfedit_outstyle_t outstyle;	/* Output style */
	struct {
		int present;		/* True if there is a source file. */
					/*	 False otherwise */
		/*
		 * The remaining file fields are not to be accessed
		 * unless present is True.
		 */
		const char *infile;	/* Name of source file */
		const char *outfile;	/* Name of file being edited */
		int unlink_on_exit;	/* TRUE to unlink outfile on exit  */
		int dirty;		/* TRUE if outfile needs to be saved */
	} file;
	struct {		/* Jump buffer used for ELFEDIT_MSG_ERR */
		int active;	/*	True if MSG_ERR jumps to outer loop */
		sigjmp_buf env;	/*	jump environment buffer */
	} msg_jbuf;
	struct {			/* Search path used to find modules */
		size_t n;		/*	# of path segments */
		const char **seg;	/*	path segments */
	} modpath;
	struct {		/* Linked list of user commands to execute */
		size_t n;		/* # of commands */
		USER_CMD_T *list;	/* head of list */
		USER_CMD_T *tail;	/* points at last element of list */
	} ucmd;
	struct {			/* Pager related state */
		FILE *fptr;		/* Output file */
	} pager;
	struct {
		int	is_tty;		/* True in stdin is a tty */
		int	full_tty;	/* True if stdin and stdout are tty */
		int	in_tecla;	/* gl_get_line() is active */
		GetLine	*gl;		/* getline object */
	} input;
	struct {		/* ELF file state */
		int elfclass;		/* ELFCLASS of file being edited */
		/*
		 * Information for the ELF object being edited.
		 * The value of elfclass determines which of these
		 * fields is valid in the current session. This is
		 * only usable if file.present is True. Otherwise, there
		 * is no object state, and these pointers will be NULL.
		 */
		union {
			elfedit32_obj_state_t *s32;	/* ELFCLASS32 */
			elfedit64_obj_state_t *s64;	/* ELFCLASS64 */
		} obj_state;
	} elf;
	USER_CMD_T *cur_cmd;	 /* NULL, or currently executing command */
} STATE_T;



/*
 * Type of item argument to elfedit_next_optarg(), used to pull together
 * the information for a single command option or argument, handling
 * the ELFEDIT_CMDOA_F_VALUE and ELFEDIT_CMDOA_F_INHERIT cases.
 */
typedef struct {
	const char		*oai_name;	/* Name of option */
	const char		*oai_vname;	/* Name of value field if */
						/* ELFEDIT_CMDOA_F_VALUE */
	elfedit_i18nhdl_t	oai_help;	/* Help text for option */
	elfedit_cmd_oa_flag_t	oai_flags;	/* Additional attributes */
	elfedit_cmd_oa_mask_t	oai_idmask;	/* Returned by elfedit_getopt */
	elfedit_cmd_oa_mask_t	oai_excmask;	/* mutual exclusion mask */
} elfedit_optarg_item_t;



/* Global state is accessible between elfedit files */
extern STATE_T state;

/* Exported by sys.c, used in elfedit.c to initialize builtin sys module */
extern MODLIST_T *elfedit_sys_init(elfedit_module_version_t version);

/* Exported by util.c, used by elfedit.c and sys.c to process output style */
extern int elfedit_atooutstyle(const char *str, elfedit_outstyle_t *outstyle);

/*
 * getopt related routines that are not public
 */
extern void elfedit_set_cmd_outstyle(const char *str);

/* elfedit internal functions used by sys module */
extern void elfedit_exit(int status);
extern elfeditGC_cmd_t *elfedit_find_command(const char *name, int must_exist,
    elfeditGC_module_t **mod_ret);
extern const char *elfedit_format_command_usage(elfeditGC_module_t *mod,
    elfeditGC_cmd_t *cmd, const char *wrap_str, size_t cur_col);
extern elfeditGC_module_t *elfedit_load_module(const char *name, int must_exist,
    int allow_abs_path);
extern void elfedit_load_moddir(const char *dirpath, int must_exist,
    int abs_path);
extern void elfedit_load_modpath(void);
extern void elfedit_unload_module(const char *name);
extern void elfedit_next_optarg(elfedit_cmd_optarg_t **optarg,
    elfedit_optarg_item_t *item);
extern const char *elfedit_optarg_helpstr(elfeditGC_module_t *mod,
    elfedit_optarg_item_t *item);


/* Used by elfedit_getopt_init() to access options array for command */
elfeditGC_cmd_t *elfedit_curcmd(void);

/* elfedit_machelf functions used by elfedit */
extern	void elfedit32_init_obj_state(const char *file, int fd, Elf *elf);
extern	void elfedit64_init_obj_state(const char *file, int fd, Elf *elf);

#ifdef	__cplusplus
}
#endif

#endif	/* __ELFEDIT_H */
