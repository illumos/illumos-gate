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


/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header: /cvs/krbdev/krb5/src/lib/kadm5/admin_xdr.h,v 1.5 1996/07/22 20:35:33 marc Exp $
 * 
 * $Log: admin_xdr.h,v $
 * Revision 1.5  1996/07/22 20:35:33  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.4.4.1  1996/07/18 03:08:25  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.4.2.1  1996/06/20  02:16:37  marc
 * File added to the repository on a branch
 *
 * Revision 1.4  1996/05/30  16:36:34  bjaspan
 * finish updating to kadm5 naming (oops)
 *
 * Revision 1.3  1996/05/22 00:28:19  bjaspan
 * rename to kadm5
 *
 * Revision 1.2  1996/05/12 06:30:10  marc
 *  - fixup includes and data types to match beta6
 *
 * Revision 1.1  1993/11/09  04:06:01  shanzer
 * Initial revision
 *
 */

#include    <kadm5/admin.h>
#include    "kadm_rpc.h"

bool_t	    xdr_nullstring(XDR *xdrs, char **objp);
bool_t	    xdr_krb5_timestamp(XDR *xdrs, krb5_timestamp *objp);
bool_t	    xdr_krb5_kvno(XDR *xdrs, krb5_kvno *objp);
bool_t	    xdr_krb5_deltat(XDR *xdrs, krb5_deltat *objp);
bool_t	    xdr_krb5_flags(XDR *xdrs, krb5_flags *objp);
bool_t	    xdr_kadm5_ret_t(XDR *xdrs, kadm5_ret_t *objp);
bool_t	    xdr_kadm5_principal_ent_rec(XDR *xdrs, kadm5_principal_ent_rec *objp);
bool_t	    xdr_kadm5_policy_ent_rec(XDR *xdrs, kadm5_policy_ent_rec *objp);
bool_t	    xdr_kadm5_policy_ent_t(XDR *xdrs, kadm5_policy_ent_t *objp);
bool_t	    xdr_kadm5_principal_ent_t(XDR *xdrs, kadm5_principal_ent_t *objp);
bool_t	    xdr_cprinc_arg(XDR *xdrs, cprinc_arg *objp);
bool_t	    xdr_dprinc_arg(XDR *xdrs, dprinc_arg *objp);
bool_t	    xdr_mprinc_arg(XDR *xdrs, mprinc_arg *objp);
bool_t	    xdr_rprinc_arg(XDR *xdrs, rprinc_arg *objp);
bool_t	    xdr_chpass_arg(XDR *xdrs, chpass_arg *objp);
bool_t	    xdr_chrand_arg(XDR *xdrs, chrand_arg *objp);
bool_t	    xdr_chrand_ret(XDR *xdrs, chrand_ret *objp);
bool_t	    xdr_gprinc_arg(XDR *xdrs, gprinc_arg *objp);
bool_t	    xdr_gprinc_arg(XDR *xdrs, gprinc_arg *objp);
bool_t	    xdr_cpol_arg(XDR *xdrs, cpol_arg *objp);
bool_t	    xdr_dpol_arg(XDR *xdrs, dpol_arg *objp);
bool_t	    xdr_mpol_arg(XDR *xdrs, mpol_arg *objp);
bool_t	    xdr_gpol_arg(XDR *xdrs, gpol_arg *objp);
bool_t	    xdr_gpol_ret(XDR *xdrs, gpol_ret *objp);
bool_t	    xdr_krb5_principal(XDR *xdrs, krb5_principal *objp);
bool_t	    xdr_krb5_octet(XDR *xdrs, krb5_octet *objp);
bool_t	    xdr_krb5_int32(XDR *xdrs, krb5_int32 *objp);
bool_t	    xdr_krb5_enctype(XDR *xdrs, krb5_enctype *objp);
bool_t	    xdr_krb5_keyblock(XDR *xdrs, krb5_keyblock *objp);
