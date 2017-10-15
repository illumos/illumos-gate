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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MODEL_H
#define	_SYS_MODEL_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL) && !defined(_ASM)
#include <sys/debug.h>
#endif /* _KERNEL && !_ASM */

#include <sys/isa_defs.h>

#if defined(_KERNEL) || defined(_KMEMUSER)

/*
 * These bits are used in various places to specify the data model
 * of the originator (and/or consumer) of data items.  See <sys/conf.h>
 * <sys/file.h>, <sys/stream.h> and <sys/sunddi.h>.
 *
 * This state should only be known to the kernel implementation.
 */
#define	DATAMODEL_MASK	0x0FF00000

#define	DATAMODEL_ILP32	0x00100000
#define	DATAMODEL_LP64	0x00200000

#define	DATAMODEL_NONE	0

#if	defined(_LP64)
#define	DATAMODEL_NATIVE	DATAMODEL_LP64
#elif	defined(_ILP32)
#define	DATAMODEL_NATIVE	DATAMODEL_ILP32
#else
#error	"No DATAMODEL_NATIVE specified"
#endif	/* _LP64 || _ILP32 */

#endif	/* _KERNEL || _KMEMUSER */

#ifndef _ASM
/*
 * XXX	Ick.  This type needs to be visible outside the above guard because
 * the proc structure is visible outside the _KERNEL | _KMEMUSER guard.
 * If we can make proc internals less visible, (which we obviously should)
 * then this can be invisible too.
 */
typedef unsigned int model_t;

#endif	/* _ASM */

#if defined(_KERNEL) && !defined(_ASM)
/*
 * These macros allow two views of the same piece of memory depending
 * on the originating user-mode program's data model.  See the STRUCT_DECL(9F)
 * man page.
 */
#if defined(_LP64)

#define	STRUCT_HANDLE(struct_type, handle)				\
	struct {							\
		union {							\
			struct struct_type##32	*m32;			\
			struct struct_type	*m64;			\
		}	ptr;						\
		model_t	model;						\
	} handle = { NULL, DATAMODEL_ILP32 }

#define	STRUCT_DECL(struct_type, handle)				\
	struct struct_type __##handle##_buf;				\
	STRUCT_HANDLE(struct_type, handle)

#define	STRUCT_SET_HANDLE(handle, umodel, addr)				\
	(handle).model = (model_t)(umodel) & DATAMODEL_MASK;		\
	ASSERT(((umodel) & DATAMODEL_MASK) != DATAMODEL_NONE);		\
	((handle).ptr.m64) = (addr)

#define	STRUCT_INIT(handle, umodel)					\
	STRUCT_SET_HANDLE(handle, umodel, &__##handle##_buf)

#define	STRUCT_SIZE(handle)						\
	((handle).model == DATAMODEL_ILP32 ?				\
	    sizeof (*(handle).ptr.m32) :				\
	    sizeof (*(handle).ptr.m64))

/*
 * In STRUCT_FADDR and STRUCT_FGETP a sleight of hand is employed to make
 * the compiler cope with having two different pointer types within ?:.
 * The (void *) case on the ILP32 case makes it a pointer which can be
 * converted to the pointer on the LP64 case, thus quieting the compiler.
 */
#define	STRUCT_FADDR(handle, field)					\
	((handle).model == DATAMODEL_ILP32 ?				\
	    (void *)&(handle).ptr.m32->field :				\
	    &(handle).ptr.m64->field)

#define	STRUCT_FGET(handle, field)					\
	(((handle).model == DATAMODEL_ILP32) ?				\
	    (handle).ptr.m32->field :					\
	    (handle).ptr.m64->field)

#define	STRUCT_FGETP(handle, field)					\
	((handle).model == DATAMODEL_ILP32 ?				\
	    (void *)(uintptr_t)(handle).ptr.m32->field :		\
	    (handle).ptr.m64->field)

#define	STRUCT_FSET(handle, field, val)					\
	((handle).model == DATAMODEL_ILP32 ?				\
	    ((handle).ptr.m32->field = (val)) :				\
	    ((handle).ptr.m64->field = (val)))

#define	STRUCT_FSETP(handle, field, val)				\
	((handle).model == DATAMODEL_ILP32 ?				\
	    (void) ((handle).ptr.m32->field = (caddr32_t)(uintptr_t)(val)) : \
	    (void) ((handle).ptr.m64->field = (val)))

#define	STRUCT_BUF(handle)	((handle).ptr.m64)

#define	SIZEOF_PTR(umodel)						\
	(((umodel) & DATAMODEL_MASK) == DATAMODEL_ILP32 ?		\
	    sizeof (caddr32_t) :					\
	    sizeof (caddr_t))

#define	SIZEOF_STRUCT(struct_type, umodel)				\
	(((umodel) & DATAMODEL_MASK) == DATAMODEL_ILP32 ?		\
	    sizeof (struct struct_type##32) :				\
	    sizeof (struct struct_type))

#else	/*  _LP64 */

#define	STRUCT_HANDLE(struct_type, handle)				\
	struct {							\
		struct struct_type *ptr;				\
		model_t	model;						\
	} handle = { NULL, DATAMODEL_ILP32 }

#define	STRUCT_DECL(struct_type, handle)				\
	struct struct_type __##handle##_buf;				\
	STRUCT_HANDLE(struct_type, handle)

#define	STRUCT_SET_HANDLE(handle, umodel, addr)				\
	(handle).model = (model_t)(umodel) & DATAMODEL_MASK;		\
	ASSERT(((umodel) & DATAMODEL_MASK) == DATAMODEL_ILP32);		\
	(handle).ptr = (addr)

#define	STRUCT_INIT(handle, umodel)					\
	STRUCT_SET_HANDLE(handle, umodel, &__##handle##_buf)

#define	STRUCT_SIZE(handle)		(sizeof (*(handle).ptr))

#define	STRUCT_FADDR(handle, field)	(&(handle).ptr->field)

#define	STRUCT_FGET(handle, field)	((handle).ptr->field)

#define	STRUCT_FGETP			STRUCT_FGET

#define	STRUCT_FSET(handle, field, val)	((handle).ptr->field = (val))

#define	STRUCT_FSETP			STRUCT_FSET

#define	STRUCT_BUF(handle)		((handle).ptr)

#define	SIZEOF_PTR(umodel)		sizeof (caddr_t)

#define	SIZEOF_STRUCT(struct_type, umodel)	sizeof (struct struct_type)

#endif	/* _LP64 */

#if defined(_LP64) || defined(__lint)

struct _klwp;

extern	model_t lwp_getdatamodel(struct _klwp *);
extern	model_t get_udatamodel(void);

#else

/*
 * If we're the 32-bit kernel, the result of these function
 * calls is completely predictable, so let's just cheat.  A
 * good compiler should be able to elide all the unreachable code
 * that results.  Optimism about optimization reigns supreme ;-)
 */
#define	lwp_getdatamodel(t)		DATAMODEL_ILP32
#define	get_udatamodel()		DATAMODEL_ILP32

#endif	/* _LP64 || __lint */

#endif	/* _KERNEL && !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MODEL_H */
