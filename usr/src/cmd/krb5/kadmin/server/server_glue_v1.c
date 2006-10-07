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


#include <kadm5/admin.h>
#include "misc.h"

/*
 * In server_stubs.c, kadmind has to be able to call kadm5 functions
 * with the arguments appropriate for any api version.  Because of the
 * prototypes in admin.h, however, the compiler will only allow one
 * set of arguments to be passed.  This file exports the old api
 * definitions with a different name, so they can be called from
 * server_stubs.c, and just passes on the call to the real api
 * function; it uses the old api version, however, so it can actually
 * call the real api functions whereas server_stubs.c cannot.
 *
 * This is most useful for functions like kadm5_get_principal that
 * take a different number of arguments based on API version.  For
 * kadm5_get_policy, the same thing could be accomplished with
 * typecasts instead.
 */

kadm5_ret_t kadm5_get_principal_v1(void *server_handle,
				  krb5_principal principal, 
				  kadm5_principal_ent_t_v1 *ent)
{
     return kadm5_get_principal(server_handle, principal,(kadm5_principal_ent_t) ent, 0);
}

kadm5_ret_t kadm5_get_policy_v1(void *server_handle, kadm5_policy_t name,
				kadm5_policy_ent_t *ent)
{
     return kadm5_get_policy(server_handle, name,(kadm5_policy_ent_t) ent);
}
