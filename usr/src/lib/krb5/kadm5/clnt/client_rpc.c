/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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


#include <rpc/rpc.h> /* SUNWresync121 XXX */
#include <kadm5/kadm_rpc.h>
#include <krb5.h>
#include <kadm5/admin.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

generic_ret *
create_principal_1(argp, clnt)
	cprinc_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CREATE_PRINCIPAL, (xdrproc_t) xdr_cprinc_arg, 
		(caddr_t) argp, (xdrproc_t) xdr_generic_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
create_principal3_1(argp, clnt)
	cprinc3_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CREATE_PRINCIPAL3, xdr_cprinc3_arg,
		      (caddr_t) argp, /* SUNWresync121 XXX */
		      xdr_generic_ret,
		      (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
delete_principal_1(argp, clnt)
	dprinc_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, DELETE_PRINCIPAL, xdr_dprinc_arg, (caddr_t) argp,
		xdr_generic_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
modify_principal_1(argp, clnt)
	mprinc_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, MODIFY_PRINCIPAL, xdr_mprinc_arg, (caddr_t) argp,
		xdr_generic_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
rename_principal_1(argp, clnt)
	rprinc_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, RENAME_PRINCIPAL, xdr_rprinc_arg, (caddr_t) argp,
		xdr_generic_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

gprinc_ret *
get_principal_1(argp, clnt)
	gprinc_arg *argp;
	CLIENT *clnt;
{
	static gprinc_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, GET_PRINCIPAL, xdr_gprinc_arg, (caddr_t) argp,
		xdr_gprinc_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

gprincs_ret *
get_princs_1(argp, clnt)
	gprincs_arg *argp;
	CLIENT *clnt;
{
	static gprincs_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, GET_PRINCS, xdr_gprincs_arg, (caddr_t) argp,
		      xdr_gprincs_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) { 
	     return (NULL);
	}
	return (&res);
}

generic_ret *
chpass_principal_1(argp, clnt)
	chpass_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CHPASS_PRINCIPAL, xdr_chpass_arg, (caddr_t) argp,
		xdr_generic_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
chpass_principal3_1(argp, clnt)
	chpass3_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CHPASS_PRINCIPAL3, xdr_chpass3_arg,
		      (caddr_t) argp, /* SUNWresync 121 XXX */ 
		      xdr_generic_ret, (caddr_t) &res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
setv4key_principal_1(argp, clnt)
	setv4key_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, SETV4KEY_PRINCIPAL, xdr_setv4key_arg,
		      (caddr_t) argp, /* SUNWresync121 XXX */
		      xdr_generic_ret, (caddr_t) &res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
setkey_principal_1(argp, clnt)
	setkey_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, SETKEY_PRINCIPAL, xdr_setkey_arg,
		      (caddr_t) argp, /* SUNWresync121 XXX */
		      xdr_generic_ret, (caddr_t) &res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
setkey_principal3_1(argp, clnt)
	setkey3_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, SETKEY_PRINCIPAL3, xdr_setkey3_arg,
		      (caddr_t) argp, /* SUNWresync121 XXX */
		      xdr_generic_ret, (caddr_t) &res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

chrand_ret *
chrand_principal_1(argp, clnt)
	chrand_arg *argp;
	CLIENT *clnt;
{
	static chrand_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CHRAND_PRINCIPAL, xdr_chrand_arg, (caddr_t) argp,
		xdr_chrand_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

chrand_ret *
chrand_principal3_1(argp, clnt)
	chrand3_arg *argp;
	CLIENT *clnt;
{
	static chrand_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CHRAND_PRINCIPAL3, xdr_chrand3_arg, 
		      (caddr_t) argp, /* SUNWresync121 XXX */
		      xdr_chrand_ret, (caddr_t) &res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
create_policy_1(argp, clnt)
	cpol_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CREATE_POLICY, xdr_cpol_arg, (caddr_t) argp,
		xdr_generic_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
delete_policy_1(argp, clnt)
	dpol_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, DELETE_POLICY, xdr_dpol_arg, (caddr_t) argp,
		xdr_generic_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
modify_policy_1(argp, clnt)
	mpol_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, MODIFY_POLICY, xdr_mpol_arg, (caddr_t) argp,
		xdr_generic_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

gpol_ret *
get_policy_1(argp, clnt)
	gpol_arg *argp;
	CLIENT *clnt;
{
	static gpol_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, GET_POLICY, xdr_gpol_arg, (caddr_t) argp,
		xdr_gpol_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

gpols_ret *
get_pols_1(argp, clnt)
	gpols_arg *argp;
	CLIENT *clnt;
{
	static gpols_ret res;

	if (clnt == NULL)
		return (NULL);
	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, GET_POLS, xdr_gpols_arg, (caddr_t) argp,
		      xdr_gpols_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) { 
	     return (NULL);
	}
	return (&res);
}

getprivs_ret *get_privs_1(argp, clnt)
   void *argp;
   CLIENT *clnt;
{
     static getprivs_ret res;

	if (clnt == NULL)
		return (NULL);
     memset((char *)&res, 0, sizeof(res));
     if (clnt_call(clnt, GET_PRIVS, xdr_u_int, (caddr_t) argp,
		   xdr_getprivs_ret, (caddr_t) &res, TIMEOUT) != RPC_SUCCESS) {
	  return (NULL);
     }
     return (&res);
}

generic_ret *
init_1(argp, clnt, rpc_err_code)
   void *argp;
   CLIENT *clnt;
   enum clnt_stat *rpc_err_code;
{
     static generic_ret res;

     enum clnt_stat retval;

	if (clnt == NULL)
		return (NULL);
     memset((char *)&res, 0, sizeof(res));
     retval = clnt_call(clnt, INIT, xdr_u_int, (caddr_t) argp,
		   xdr_generic_ret, (caddr_t) &res, TIMEOUT);

     if (retval != RPC_SUCCESS) {
	  *rpc_err_code = retval;
	  return (NULL);
     }
     return (&res);
}
