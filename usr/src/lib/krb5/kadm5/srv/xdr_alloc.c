
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
 */

#include "admin.h"
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <dyn/dyn.h>

/* Solaris Kerberos - 116 resync */
static bool_t	xdralloc_putlong();
static bool_t	xdralloc_putbytes();
static unsigned int	xdralloc_getpos();
static rpc_inline_t *	xdralloc_inline();
static void	xdralloc_destroy();
static bool_t	xdralloc_notsup_getlong();
static bool_t	xdralloc_notsup_getbytes();
static bool_t	xdralloc_notsup_setpos();
static struct	xdr_ops xdralloc_ops = {
     xdralloc_notsup_getlong,
     xdralloc_putlong,
     xdralloc_notsup_getbytes,
     xdralloc_putbytes,
     xdralloc_getpos,
     xdralloc_notsup_setpos,
     xdralloc_inline,
     xdralloc_destroy,
};

/*
 * The procedure xdralloc_create initializes a stream descriptor for a
 * memory buffer.
 */
void xdralloc_create(XDR *xdrs, enum xdr_op op)
{
     xdrs->x_op = op;
     xdrs->x_ops = &xdralloc_ops;
     xdrs->x_private = (caddr_t) DynCreate(sizeof(char), -4);
     /* not allowed to fail */
}

caddr_t xdralloc_getdata(XDR *xdrs)
{
     return (caddr_t) DynGet((DynObject) xdrs->x_private, 0);
}

void xdralloc_release(XDR *xdrs)
{
     DynRelease((DynObject) xdrs->x_private);
}

static void xdralloc_destroy(XDR *xdrs)
{
     DynDestroy((DynObject) xdrs->x_private);
}

static bool_t xdralloc_notsup_getlong(
     register XDR *xdrs,
     long *lp)
{
     return FALSE;
}

static bool_t xdralloc_putlong(
     register XDR *xdrs,
     long *lp)
{
     int l = htonl((uint32_t) *lp); /* XXX need bounds checking */

     /* XXX assumes sizeof(int)==4 */
     if (DynInsert((DynObject) xdrs->x_private,
		   DynSize((DynObject) xdrs->x_private), &l,
		   sizeof(int)) != DYN_OK)
	  return FALSE;
     return (TRUE);
}


static bool_t xdralloc_notsup_getbytes(
     register XDR *xdrs,
     caddr_t addr,
     register unsigned int len)
{
     return FALSE;
}


static bool_t xdralloc_putbytes(
     register XDR *xdrs,
     caddr_t addr,
     register unsigned int len)
{
     if (DynInsert((DynObject) xdrs->x_private,
		   DynSize((DynObject) xdrs->x_private),
		   addr, (int) len) != DYN_OK)
	  return FALSE;
     return TRUE;
}

static unsigned int xdralloc_getpos(XDR *xdrs)
{
     return DynSize((DynObject) xdrs->x_private);
}

static bool_t xdralloc_notsup_setpos(
     register XDR *xdrs,
     unsigned int lp)
{
     return FALSE;
}



static rpc_inline_t *xdralloc_inline(
     register XDR *xdrs,
     int len)
{
     return (rpc_inline_t *) 0;
}
