/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _XNEW_H
#define	_XNEW_H

#ifndef xnew_INCLUDED
#define	xnew_INCLUDED 1

#ifdef SP_NEW_H_MISSING

typedef void (*VFP)();

#ifdef SP_SET_NEW_HANDLER_EXTERN_C
extern "C"
#endif

namespace std {
    void set_new_handler(VFP);
}

#ifndef SP_DECLARE_PLACEMENT_OPERATOR_NEW
#define	SP_DECLARE_PLACEMENT_OPERATOR_NEW
#endif

#else /* not SP_NEW_H_MISSING */

#ifdef SP_ANSI_LIB
#include <new>
#else
#include <new.h>
#endif

#endif /* not SP_NEW_H_MISSING */

#ifdef SP_DECLARE_PLACEMENT_OPERATOR_NEW

inline
void
*operator new(size_t, void *p)
{
	return (p);
}

#endif /* SP_DECLARE_PLACEMENT_OPERATOR_NEW */

#endif /* not xnew_INCLUDED */

#endif /* _XNEW_H */
