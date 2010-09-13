/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *      Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _TNFCTL_H
#define	_TNFCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <gelf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	TNFCTL_LIBTNFPROBE	"libtnfprobe.so.1"

/*
 * data model dependent defs
 */
#if defined(_LP64)
#define	ELF3264_R_SYM	GELF_R_SYM
typedef	GElf_Shdr	Elf3264_Shdr;
typedef GElf_Dyn	Elf3264_Dyn;
typedef GElf_Sword	Elf3264_Sword;
typedef GElf_Sym	Elf3264_Sym;
typedef GElf_Word	Elf3264_Word;
typedef GElf_Addr	Elf3264_Addr;
typedef GElf_Rela	Elf3264_Rela;
typedef GElf_Rel	Elf3264_Rel;
#else
#define	ELF3264_R_SYM	ELF32_R_SYM
typedef	Elf32_Shdr	Elf3264_Shdr;
typedef Elf32_Dyn	Elf3264_Dyn;
typedef Elf32_Sword	Elf3264_Sword;
typedef Elf32_Sym	Elf3264_Sym;
typedef Elf32_Word	Elf3264_Word;
typedef Elf32_Addr	Elf3264_Addr;
typedef Elf32_Rela	Elf3264_Rela;
typedef Elf32_Rel	Elf3264_Rel;
#endif
/*
 * Opaque tnfctl handle
 */
typedef	struct tnfctl_handle tnfctl_handle_t;

/*
 * Opaque probe handle
 */
typedef struct tnfctl_probe_handle tnfctl_probe_t;

/*
 * Trace attributes and probe state
 */
typedef enum {
	TNFCTL_BUF_OK,
	TNFCTL_BUF_NONE,
	TNFCTL_BUF_BROKEN
} tnfctl_bufstate_t;

typedef struct tnfctl_trace_attrs {
	pid_t		targ_pid;		/* user process only */
	const char	*trace_file_name;	/* user process only */
	size_t		trace_buf_size;
	size_t		trace_min_size;
	tnfctl_bufstate_t trace_buf_state;
	boolean_t	trace_state;
	boolean_t	filter_state;		/* kernel mode only */
	long		pad;
} tnfctl_trace_attrs_t;

typedef struct tnfctl_probe_state {
	ulong_t		id;
	const char	*attr_string;
	boolean_t	enabled;
	boolean_t	traced;
	boolean_t	new_probe;
	const char	*obj_name;		/* user process only */
	const char * const *func_names;		/* array of func names ptrs */
	const uintptr_t	*func_addrs;		/* array of func addresses */
	void		*client_registered_data;
	long		pad;
} tnfctl_probe_state_t;

/*
 * error codes
 */
typedef enum {
	TNFCTL_ERR_NONE = 0,	/* success */
	TNFCTL_ERR_ACCES,	/* permission denied */
	TNFCTL_ERR_NOTARGET,	/* target process finished */
	TNFCTL_ERR_ALLOCFAIL,	/* memory allocation failure */
	TNFCTL_ERR_INTERNAL,	/* internal error */
	TNFCTL_ERR_SIZETOOSMALL, /* requested trace size is too small */
	TNFCTL_ERR_SIZETOOBIG,	/* requested trace size is too big */
	TNFCTL_ERR_BADARG,	/* Bad Input Argument */
	TNFCTL_ERR_NOTDYNAMIC,	/* Target is not a dynamic executable */
	TNFCTL_ERR_NOLIBTNFPROBE, /* libtnfprobe not linked in target */
	TNFCTL_ERR_BUFBROKEN,	/* tracing broken */
	TNFCTL_ERR_BUFEXISTS,	/* buffer already exists */
	TNFCTL_ERR_NOBUF,	/* no buffer */
	TNFCTL_ERR_BADDEALLOC,	/* can't deallocate buffer */
	TNFCTL_ERR_NOPROCESS,	/* no such target process */
	TNFCTL_ERR_FILENOTFOUND, /* file not found */
	TNFCTL_ERR_BUSY,	/* kernel/process already tracing */
	TNFCTL_ERR_INVALIDPROBE, /* probe no longer valid (dlclos'ed) */
	TNFCTL_ERR_USR1,	/* error extensions - semantics */
	TNFCTL_ERR_USR2,	/* 	set by user */
	TNFCTL_ERR_USR3,
	TNFCTL_ERR_USR4,
	TNFCTL_ERR_USR5
} tnfctl_errcode_t;

/*
 * event codes
 */
typedef enum {
	TNFCTL_EVENT_EINTR,	/* target was interrupted by a signal */
	TNFCTL_EVENT_TARGGONE,	/* target finished - did not call exit */
	TNFCTL_EVENT_DLOPEN,	/* target did a dlopen */
	TNFCTL_EVENT_DLCLOSE,	/* target did a dlclose */
	TNFCTL_EVENT_EXEC,	/* target did an exec */
	TNFCTL_EVENT_FORK,	/* target did a fork */
	TNFCTL_EVENT_EXIT	/* target called exit */
} tnfctl_event_t;

/*
 * action to perform on target process
 */

typedef enum {
	TNFCTL_TARG_DEFAULT,	/* kills target if it was started with */
				/* 	tnfctl_exec_open() */
	TNFCTL_TARG_KILL,	/* kills target */
	TNFCTL_TARG_RESUME,	/* target is let free */
	TNFCTL_TARG_SUSPEND	/* target is suspended */
} tnfctl_targ_op_t;

/*
 * data structures needed when using tnfctl_indirect_open() interface i.e. for
 * clients that will supply callback functions for inspecting target image.
 */
typedef struct tnfctl_ind_obj_info {
	int	objfd;		/* -1 indicates fd not available */
	uintptr_t text_base;	/* address where text of loadobj was mapped */
	uintptr_t data_base;	/* address where data of loadobj was mapped */
	const char *objname;	/* null terminated full pathname to loadobj */
} tnfctl_ind_obj_info_t;

typedef int tnfctl_ind_obj_f(
	void *,					/* opaque prochandle */
	const struct tnfctl_ind_obj_info *, 	/* info about this object */
	void *);				/* client supplied data */

typedef struct tnfctl_ind_config {
	int (*p_read)(void *, uintptr_t, void *, size_t);
	int (*p_write)(void *, uintptr_t, void *, size_t);
	pid_t (*p_getpid)(void *);
	int (*p_obj_iter)(void *, tnfctl_ind_obj_f *, void * /* client_data */);
} tnfctl_ind_config_t;

/*
 * maps an errcode to a string
 */
const char *tnfctl_strerror(tnfctl_errcode_t);

/*
 * interfaces to open a tnfctl handle
 */
tnfctl_errcode_t tnfctl_pid_open(
	pid_t, 			/* pid */
	tnfctl_handle_t **);	/* return value */

tnfctl_errcode_t tnfctl_indirect_open(
	void *,			/* prochandle */
	tnfctl_ind_config_t *,	/* config */
	tnfctl_handle_t **);	/* return value */

tnfctl_errcode_t tnfctl_exec_open(
	const char *,		/* pgm name */
	char * const *,		/* argv */
	char * const *,		/* envp */
	const char *,		/* ld_preload */
	const char *,		/* libtnfprobe_path */
	tnfctl_handle_t **);	/* return value */

tnfctl_errcode_t tnfctl_internal_open(tnfctl_handle_t **);

tnfctl_errcode_t tnfctl_kernel_open(tnfctl_handle_t **);

/*
 * direct mode - to continue process
 */
tnfctl_errcode_t tnfctl_continue(
	tnfctl_handle_t *,
	tnfctl_event_t *,	/* return value - why did process stop ? */
	tnfctl_handle_t **);	/* return value - if fork, handle on child */

/*
 * informs libtnfctl that libraries may have changed
 */
tnfctl_errcode_t tnfctl_check_libs(tnfctl_handle_t *);

/*
 *
 */
tnfctl_errcode_t tnfctl_close(tnfctl_handle_t *, tnfctl_targ_op_t);
tnfctl_errcode_t tnfctl_trace_attrs_get(
	tnfctl_handle_t *,
	tnfctl_trace_attrs_t *);
tnfctl_errcode_t tnfctl_buffer_alloc(
	tnfctl_handle_t *,
	const char *,		/* filename - ignored if kernel handle */
	uint_t);		/* buffer size */

/*
 * kernel tracing only
 */
tnfctl_errcode_t tnfctl_buffer_dealloc(tnfctl_handle_t *);
tnfctl_errcode_t tnfctl_trace_state_set(tnfctl_handle_t *, boolean_t);
tnfctl_errcode_t tnfctl_filter_state_set(tnfctl_handle_t *, boolean_t);
tnfctl_errcode_t tnfctl_filter_list_get(tnfctl_handle_t *, pid_t **, int *);
tnfctl_errcode_t tnfctl_filter_list_add(tnfctl_handle_t *, pid_t);
tnfctl_errcode_t tnfctl_filter_list_delete(tnfctl_handle_t *, pid_t);

/*
 * probe operation interface
 */
typedef tnfctl_errcode_t (*tnfctl_probe_op_t)(
	tnfctl_handle_t *,
	tnfctl_probe_t *,		/* opaque probe handle */
	void *);			/* client supplied data */

tnfctl_errcode_t tnfctl_probe_apply(
	tnfctl_handle_t *,
	tnfctl_probe_op_t,	/* func to apply to each of the probes */
	void *);		/* client data - arg to pass to func */

tnfctl_errcode_t tnfctl_probe_apply_ids(
	tnfctl_handle_t *,
	ulong_t,		/* # of probe id's in array */
	ulong_t *,		/* array of probe id's */
	tnfctl_probe_op_t,	/* func to apply to each those probes */
	void *);		/* client data - arg to pass to func */

tnfctl_errcode_t tnfctl_register_funcs(
	tnfctl_handle_t *,
	void *(*)(tnfctl_handle_t *, tnfctl_probe_t *),	/* create_func */
	void (*)(void *));				/* destroy_func */

tnfctl_errcode_t tnfctl_probe_state_get(tnfctl_handle_t *, tnfctl_probe_t *,
		tnfctl_probe_state_t *);

/*
 * supplied probe functions that can be used with tnfctl_probe_apply()
 * and tnfctl_probe_apply_ids(). last argument is ignored when it is "void *"
 */
tnfctl_errcode_t tnfctl_probe_enable(tnfctl_handle_t *, tnfctl_probe_t *,
					void *);
tnfctl_errcode_t tnfctl_probe_disable(tnfctl_handle_t *, tnfctl_probe_t *,
					void *);
tnfctl_errcode_t tnfctl_probe_trace(tnfctl_handle_t *, tnfctl_probe_t *,
					void *);
tnfctl_errcode_t tnfctl_probe_untrace(tnfctl_handle_t *, tnfctl_probe_t *,
					void *);
tnfctl_errcode_t tnfctl_probe_disconnect_all(tnfctl_handle_t *,
					tnfctl_probe_t *, void *);
tnfctl_errcode_t tnfctl_probe_connect(
	tnfctl_handle_t *,
	tnfctl_probe_t *,
	const char *,		/* library base name */
	const char *);		/* function name */

#ifdef __cplusplus
}
#endif

#endif /* _TNFCTL_H */
