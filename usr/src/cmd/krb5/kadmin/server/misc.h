/*
 * Copyright (c) 1997-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MISC_H
#define	_MISC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

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
 * Copyright 1994 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header: /afs/athena.mit.edu/astaff/project/krbdev/.cvsroot/src/kadmin/\
 * server/misc.h,v 1.6 1996/07/22 20:28:56 marc Exp $
 *
 * $Log: misc.h,v $
 * Revision 1.6  1996/07/22 20:28:56  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.5.4.1  1996/07/18 03:03:40  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.5.2.1  1996/06/20  21:57:20  marc
 * File added to the repository on a branch
 *
 * Revision 1.5  1996/05/30  21:13:24  bjaspan
 * kadm5_get_principal_v1 takes a kadm5_principal_ent_t_v1
 * add kadm5_get_policy_v1
 *
 * Revision 1.4  1996/05/20 21:39:05  bjaspan
 * rename to kadm5
 * add kadm5_get_principal_v1
 *
 * Revision 1.3  1994/09/13 18:24:41  jik
 * Back out randkey changes.
 *
 * Revision 1.2  1994/09/12  20:26:12  jik
 * randkey_principal_wrapper now takes a new_kvno option.
 *
 * Revision 1.1  1994/08/11  17:00:44  jik
 * Initial revision
 *
 */

kadm5_ret_t
chpass_principal_wrapper(void *server_handle,
    krb5_principal principal,
    char *password);

kadm5_ret_t
randkey_principal_wrapper(void *server_handle,
    krb5_principal principal,
    krb5_keyblock ** key,
    int *n_keys);

kadm5_ret_t
kadm5_get_principal_v1(void *server_handle,
    krb5_principal principal,
    kadm5_principal_ent_t_v1 * ent);

kadm5_ret_t
kadm5_get_policy_v1(void *server_handle, kadm5_policy_t name,
    kadm5_policy_ent_t * ent);

/* BSM */
extern void audit_kadmind_auth(SVCXPRT *, in_port_t, char *, char *,
			    char *, int);
extern void audit_kadmind_unauth(SVCXPRT *, in_port_t, char *, char *, char *);

#ifdef	__cplusplus
}
#endif

#endif	/* !_MISC_H */
