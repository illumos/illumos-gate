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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_FCODE_ENGINE_H
#define	_FCODE_ENGINE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_ORDER	32
#define	CONVERT_HANDLES

#ifdef BIGSTACK
typedef long long		fstack_t;
typedef unsigned long long	ufstack_t;
#else
typedef long			fstack_t;
typedef unsigned long		ufstack_t;
#endif
typedef long			*acf_t;		/* pointer to execution token */
typedef long			token_t;	/* sizeof a forth token */

/* x@, x! type */
typedef uint64_t		u_xforth_t;
typedef int64_t			s_xforth_t;
typedef uint64_t		xforth_t;

/* l@, l! type */
typedef uint32_t		u_lforth_t;
typedef int32_t			s_lforth_t;
typedef uint32_t		lforth_t;

/* w@, w! type */
typedef uint16_t		u_wforth_t;
typedef int16_t			s_wforth_t;
typedef uint16_t		wforth_t;

/* Double type */
typedef uint64_t		u_dforth_t;
typedef int64_t			s_dforth_t;
typedef	uint64_t		dforth_t;

/* Variable/Value/Constant type */
typedef token_t			variable_t;

typedef struct PROPERTY {
	char		*name;
	uchar_t		*data;
	int		size;
	struct PROPERTY *next;
} prop_t;

typedef struct RESOURCE {
	struct RESOURCE *next;
	void		*data;
} fc_resource_t;

#define	INIT_DATA	0
#define	UINIT_DATA	1

typedef struct FCODE_ENV fcode_env_t;

typedef struct DEVICE_VECTOR {
	/*
	 * If there is private data associated with a node this vector
	 * table contains the routines that will be called to augment the
	 * device.
	 * These two routines allow the interpreter to use a different
	 *
	 * Interface Note:
	 * Any routine installed here is assumed to have the standard forth
	 * call state. It must be a void function call taking a forth execution
	 * environment, returning any data on the stack. In general the
	 * vector call should have the same semantics as the original routine
	 * it is replacing. (see get_prop as an example).
	 *
	 * The caller has the responsibility of converting the resulting data
	 * back to a form it requires.
	 *
	 */
	void		(*get_package_prop)(fcode_env_t *);
	void		(*get_inherited_prop)(fcode_env_t *);
} device_vector_t;

typedef struct DEVICE device_t;

#define	MAX_MY_ADDR	4

struct DEVICE {
	device_t	*parent;
	device_t	*child;
	device_t	*peer;
	prop_t		*properties;
	token_t		*vocabulary;
	fstack_t	parent_adr_cells;
	fstack_t	my_space;
	fstack_t	my_addr[MAX_MY_ADDR];
	fstack_t	frame_buffer_adr;
	int		data_size[2];
	token_t		*init_data;		/* initialised instance data */
	void		*private;		/* app private data */
	device_vector_t	vectors;
};

typedef struct INSTANCE  {
	struct INSTANCE *parent;
	device_t	*device;
	/*
	 * These are copies of the same structures from the device definition
	 * however changes here will be thrown away when the instance is
	 * destroyed.
	 */
	char		*my_args;
	int		my_args_len;
	fstack_t	my_space;
	fstack_t	my_addr[MAX_MY_ADDR];
	fstack_t	frame_buffer_adr;
	token_t		*data[2];
} instance_t;

typedef struct FCODE_TOKEN {
	ulong_t		flags;
	char		*name;
	acf_t		apf;	/* pointer to acf in dictionary */
#ifdef DEBUG
	int		usage;
#endif
} fcode_token;

typedef struct {
	char		*buffer;
	char		*scanptr;
	int		maxlen;
	int		separator;
} input_typ;

typedef struct ERROR_FRAME {
	struct ERROR_FRAME *next;
	fstack_t	*ds;
	fstack_t	*rs;
	instance_t	*myself;
	token_t		*ip;
	fstack_t	code;
} error_frame;

struct FCODE_ENV  {
	fcode_token	*table;		 /* token table */
	uchar_t		*base;		 /* dictionary base */
	uchar_t		*here;		 /* current dp */
	char		*name;		 /* last name */
	long		level;		 /* level */
	token_t		*ip;		 /* instruction pointer */
	token_t		*wa;		 /* word address */
	fstack_t	*ds0;		 /* base of dats stack */
	fstack_t	*rs0;		 /* base of return stack */
	fstack_t	*ds;		 /* data stack base */
	fstack_t	*rs;		 /* return stack base */
	variable_t	num_base;	 /* current base */
	token_t		*current;	 /* current voc */
	long		order_depth;
	token_t		**order;	 /* Voc. search order */
	token_t		*lastlink;	 /* last forth def */
	token_t		*forth_voc_link; /* Storage location for 'forth' voc */
	int		last_token;	 /* last defined token */
	device_t	*root_node;	 /* root node */
	device_t	*attachment_pt;
	device_t	*current_device; /*  */
	instance_t	*my_self;	 /* pointer to my data */
	int		offset_incr;	 /* size of FCODE token offsets */
	error_frame	*catch_frame;
	uchar_t		*fcode_buffer;	 /* pointer to fcode buffer */
	uchar_t		*fcode_ptr;	 /* pointer into fcode buffer */
	uchar_t		*last_fcode_ptr; /* pointer to last fcode fetched */
	fstack_t	last_fcode;	 /* last fcode# executed */
	fstack_t	last_error;	 /* last throw code executed */
	int		fcode_incr;	 /* space between bytecodes */
	int		interpretting;
	variable_t	state;		 /* compile or run? */
	int		fcode_debug;
	int		diagnostic_mode;
	fstack_t	instance_mode;
	int		interactive;	 /* DEBUG, interact variable */
	int		num_actions;
	int		action_count;
	token_t		*action_ptr;
	int		strict_fcode;
	fstack_t	control;	 /* control VM behaviour */
	input_typ	*input;		 /* input buffer pointer */
	variable_t	span;
	char		*picturebufpos;	 /* pictured string buffer position */
	char		*picturebuf;	 /* pictured string buffer */
	int		picturebuflen;	 /* pictured string buffer length */
	variable_t	output_column;	 /* output column# (#out) */
	variable_t	output_line;	 /* output line# (#line) */
#ifdef CONVERT_HANDLES
	device_t	*(*convert_phandle)(fcode_env_t *, fstack_t);
	fstack_t	(*revert_phandle)(fcode_env_t *, device_t *);
	void		(*allocate_phandle)(fcode_env_t *);
#endif
	fc_resource_t	*propbufs;
	void		*private;	 /* private data ptr for app use. */
};

#define	MAX_FCODE	0xfff		/* max no. of Fcode entries in table */


typedef unsigned char flag_t;

#define	DS		(env->ds)
#define	RS		(env->rs)
#define	TOS		*DS
#define	IP		(env->ip)
#define	WA		(env->wa)
#define	DEPTH		(DS-env->ds0)
#define	CURRENT		(env->current)
#define	ORDER		(env->order)
#define	BASE		(env->base)
#define	HERE		(env->here)
#define	CONTEXT		env->order[env->order_depth]
#define	MYSELF		(env->my_self)

#ifdef FCODE_INTERNAL
#include <fcode/proto.h>
#endif
#include <fcode/public.h>

#define	SIGN_SHIFT	((8*(sizeof (fstack_t)))-1)
#define	SIGN_BIT	(((ufstack_t)1)<<SIGN_SHIFT)

/*
 * Note that sizeof (token_t) MUST equal sizeof (token_t *).  If it doesn't,
 * many things will break.
 */
#define	_ALIGN(x, y)		(((long)(x)) & ~(sizeof (y)-1))
#define	TOKEN_ROUNDUP(x)	_ALIGN((x + ((sizeof (token_t)-1))), token_t)

#define	min(x, y)	((x) < (y) ? (x) : (y))
#define	max(x, y)	((x) > (y) ? (x) : (y))

/* values for flag_t */
#define	ANSI_WORD		0x01
#define	P1275_WORD		0x02
#define	FLAG_NONAME		0x04
#define	IMMEDIATE		0x08
#define	FLAG_VALUE		0x10
#define	FLAG_DEBUG		0x20
#define	DEFINER			(FLAG_NONAME|IMMEDIATE)

#define	FORTH(fl, nm, fnc)	define_word(env, fl, nm, fnc);

#define	LINK_TO_ACF(x)		(((token_t *)(x))+1)
#define	LINK_TO_FLAGS(x)	(((flag_t *)(x))-1)
#define	ACF_TO_LINK(x)		(((token_t *)(x))-1)
#define	ACF_TO_BODY(x)		(((acf_t)(x))+1)
#define	BODY_TO_LINK(x)		(((acf_t)(x))-1)
#define	BODY_TO_FLAGS(x)	(((flag_t *)(BODY_TO_LINK(x))) - 1)
#define	EXPOSE_ACF		*((acf_t)env->current) = \
				    (token_t)(env->lastlink)

#define	COMPILE_TOKEN(x)	PUSH(DS, (fstack_t)(x)); compile_comma(env);
#define	CHECK_DEPTH(env, x, w)	if ((x) > (env->ds - env->ds0)) \
    forth_abort(env, "%s: stack underflow\n", w);
#define	CHECK_RETURN_DEPTH(env, x, w)	if ((x) > (env->rs - env->rs0)) \
    forth_abort(env, "%s: return stack underflow\n", w);

#define	FCRP_NOERROR		0x80000000	/* fc_run_priv: no err msg. */

#ifdef CONVERT_HANDLES
#define	CONVERT_PHANDLE(e, x, y)	x = env->convert_phandle(e, y)
#define	REVERT_PHANDLE(e, x, y)	x = env->revert_phandle(e, y)
#define	ALLOCATE_PHANDLE(e)	env->allocate_phandle(e)
#else
#define	CONVERT_PHANDLE(e, x, y)	x = (device_t *)(y)
#define	REVERT_PHANDLE(e, x, y)	x = (fstack_t)(y)
#define	ALLOCATE_PHANDLE(e)
#endif

extern fcode_env_t *env;
extern int dict_size;
extern int in_forth_abort;
extern int stack_size;
extern token_t value_defines[][3];
extern void (*bbranch_ptrs[3])(fcode_env_t *);
extern void (*blit_ptr)(fcode_env_t *);
extern void (*create_ptr)(fcode_env_t *);
extern void (*do_bdo_ptr)(fcode_env_t *);
extern void (*do_bqdo_ptr)(fcode_env_t *);
extern void (*do_leave_ptr)(fcode_env_t *);
extern void (*do_loop_ptr)(fcode_env_t *);
extern void (*do_ploop_ptr)(fcode_env_t *);
extern void (*does_ptr)(fcode_env_t *);
extern void (*quote_ptr)(fcode_env_t *);
extern void (*quote_ptr)(fcode_env_t *);
extern void (*semi_ptr)(fcode_env_t *);
extern void (*tlit_ptr)(fcode_env_t *);
extern void (*to_ptr)(fcode_env_t *);
extern void (*to_ptr)(fcode_env_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _FCODE_ENGINE_H */
