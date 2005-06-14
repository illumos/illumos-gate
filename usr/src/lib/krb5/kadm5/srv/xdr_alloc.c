#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING 
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/* @(#)xdr_mem.c	2.1 88/07/29 4.0 RPCSRC */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
#if !defined(lint) && defined(SCCSIDS)
static char sccsid[] = "@(#)xdr_mem.c 1.19 87/08/11 Copyr 1984 Sun Micro";
#endif

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Header: /afs/athena.mit.edu/astaff/project/krbdev/.cvsroot/src/lib/rpc/xdr_alloc.c,v 1.6 1996/07/22 20:41:21 marc Exp $
 * 
 * $Log: xdr_alloc.c,v $
 * Revision 1.6  1996/07/22 20:41:21  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.5.4.1  1996/07/18 04:19:49  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.5.2.1  1996/06/20  23:40:30  marc
 * File added to the repository on a branch
 *
 * Revision 1.5  1996/05/12  06:19:25  marc
 * renamed lots of types: u_foo to unsigned foo, and foo32 to rpc_foo32.  This is to make autoconfiscation less painful.
 *
 * Revision 1.4  1995/12/13  14:03:14  grier
 * Longs to ints for Alpha
 *
 * Revision 1.3  1993/12/09  18:57:25  bjaspan
 * [secure-releng/833] misc bugfixes to admin library
 *
 * Revision 1.3  1993/12/06  21:23:08  bjaspan
 * add xdralloc_release
 *
 * Revision 1.2  1993/10/26  21:13:19  bjaspan
 * add casts for correctness
 *
 * Revision 1.1  1993/10/19  03:11:39  bjaspan
 * Initial revision
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header: /afs/athena.mit.edu/astaff/project/krbdev/.cvsroot/src/lib/rpc/xdr_alloc.c,v 1.6 1996/07/22 20:41:21 marc Exp $";
#endif

#include "admin.h"
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <dyn/dyn.h>

static bool_t	xdralloc_putlong();
static bool_t	xdralloc_putbytes();
static unsigned int	xdralloc_getpos();
static rpc_inline_t *	xdralloc_inline();
static void	xdralloc_destroy();
static bool_t	xdralloc_notsup();

static struct	xdr_ops xdralloc_ops = {
     xdralloc_notsup,
     xdralloc_putlong,
     xdralloc_notsup,
     xdralloc_putbytes,
     xdralloc_getpos,
     xdralloc_notsup,
     xdralloc_inline,
     xdralloc_destroy,
};

/*
 * The procedure xdralloc_create initializes a stream descriptor for a
 * memory buffer.  
 */
void xdralloc_create(xdrs, op)
   register XDR *xdrs;
   enum xdr_op op;
{
     xdrs->x_op = op;
     xdrs->x_ops = &xdralloc_ops;
     xdrs->x_private = (caddr_t) DynCreate(sizeof(char), -4);
     /* not allowed to fail */
}

caddr_t xdralloc_getdata(xdrs)
   XDR *xdrs;
{
     return (caddr_t) DynGet((DynObject) xdrs->x_private, 0);
}

void xdralloc_release(xdrs)
   XDR *xdrs;
{
     DynRelease((DynObject) xdrs->x_private);
}

static void xdralloc_destroy(xdrs)
   XDR *xdrs;
{
     DynDestroy((DynObject) xdrs->x_private);
}

static bool_t xdralloc_notsup()
{
     return FALSE;
}

static bool_t xdralloc_putlong(xdrs, lp)
   register XDR *xdrs;
   rpc_int32 *lp;
{
     int l = htonl((rpc_u_int32) *(int *)lp);
     
     if (DynInsert((DynObject) xdrs->x_private,
		   DynSize((DynObject) xdrs->x_private), &l,
		   sizeof(int)) != DYN_OK)
	  return FALSE;
     return (TRUE);
}

static bool_t xdralloc_putbytes(xdrs, addr, len)
   register XDR *xdrs;
   caddr_t addr;
   register unsigned int len;
{
     if (DynInsert((DynObject) xdrs->x_private,
		   DynSize((DynObject) xdrs->x_private),
		   addr, len) != DYN_OK)
	  return FALSE;
     return TRUE;
}

static unsigned int xdralloc_getpos(xdrs)
   register XDR *xdrs;
{
     return DynSize((DynObject) xdrs->x_private);
}


static rpc_inline_t *xdralloc_inline(xdrs, len)
   register XDR *xdrs;
   int len;
{
     return (rpc_inline_t *) 0;
}
