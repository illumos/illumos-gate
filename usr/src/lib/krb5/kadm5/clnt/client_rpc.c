/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


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
create_principal_2(cprinc_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, CREATE_PRINCIPAL,
		      (xdrproc_t) xdr_cprinc_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
create_principal3_2(cprinc3_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, CREATE_PRINCIPAL3,
		      (xdrproc_t) xdr_cprinc3_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
delete_principal_2(dprinc_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, DELETE_PRINCIPAL,
		      (xdrproc_t) xdr_dprinc_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
modify_principal_2(mprinc_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, MODIFY_PRINCIPAL,
		      (xdrproc_t) xdr_mprinc_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
rename_principal_2(rprinc_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, RENAME_PRINCIPAL,
		      (xdrproc_t) xdr_rprinc_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

gprinc_ret *
get_principal_2(gprinc_arg *argp, CLIENT *clnt)
{
	static gprinc_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, GET_PRINCIPAL,
		      (xdrproc_t) xdr_gprinc_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_gprinc_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

gprincs_ret *
get_princs_2(gprincs_arg *argp, CLIENT *clnt)
{
	static gprincs_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, GET_PRINCS,
		      (xdrproc_t) xdr_gprincs_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_gprincs_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
	     return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
chpass_principal_2(chpass_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, CHPASS_PRINCIPAL,
		      (xdrproc_t) xdr_chpass_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
chpass_principal3_2(chpass3_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, CHPASS_PRINCIPAL3,
		      (xdrproc_t) xdr_chpass3_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
setv4key_principal_2(setv4key_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, SETV4KEY_PRINCIPAL,
		      (xdrproc_t) xdr_setv4key_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
setkey_principal_2(setkey_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, SETKEY_PRINCIPAL,
		      (xdrproc_t) xdr_setkey_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
setkey_principal3_2(setkey3_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, SETKEY_PRINCIPAL3,
		      (xdrproc_t) xdr_setkey3_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

chrand_ret *
chrand_principal_2(chrand_arg *argp, CLIENT *clnt)
{
	static chrand_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, CHRAND_PRINCIPAL,
		      (xdrproc_t) xdr_chrand_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_chrand_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

chrand_ret *
chrand_principal3_2(chrand3_arg *argp, CLIENT *clnt)
{
	static chrand_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, CHRAND_PRINCIPAL3,
		      (xdrproc_t) xdr_chrand3_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_chrand_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
create_policy_2(cpol_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, CREATE_POLICY,
		      (xdrproc_t) xdr_cpol_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
delete_policy_2(dpol_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, DELETE_POLICY,
		      (xdrproc_t) xdr_dpol_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

generic_ret *
modify_policy_2(mpol_arg *argp, CLIENT *clnt)
{
	static generic_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, MODIFY_POLICY,
		      (xdrproc_t) xdr_mpol_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

gpol_ret *
get_policy_2(gpol_arg *argp, CLIENT *clnt)
{
	static gpol_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, GET_POLICY,
		      (xdrproc_t) xdr_gpol_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_gpol_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

gpols_ret *
get_pols_2(gpols_arg *argp, CLIENT *clnt)
{
	static gpols_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call(clnt, GET_POLS,
		      (xdrproc_t) xdr_gpols_arg, (caddr_t) argp,
		      (xdrproc_t) xdr_gpols_ret, (caddr_t) &clnt_res,
		      TIMEOUT) != RPC_SUCCESS) {
	     return (NULL);
	}
	return (&clnt_res);
}

getprivs_ret *
get_privs_2(void *argp, CLIENT *clnt)
{
     static getprivs_ret clnt_res;

	/* Solaris Kerberos */
	if (clnt == NULL)
		return (NULL);
     memset((char *)&clnt_res, 0, sizeof(clnt_res));
     if (clnt_call(clnt, GET_PRIVS,
		   (xdrproc_t) xdr_u_int, (caddr_t) argp,
		   (xdrproc_t) xdr_getprivs_ret, (caddr_t) &clnt_res,
		   TIMEOUT) != RPC_SUCCESS) {
	  return (NULL);
     }
     return (&clnt_res);
}

generic_ret *
init_2(void *argp, CLIENT *clnt)
{
     static generic_ret clnt_res;

	/* Solaris Kerberos */
     if (clnt == NULL)
         return (NULL);

     memset((char *)&clnt_res, 0, sizeof(clnt_res));
     if (clnt_call(clnt, INIT,
		   (xdrproc_t) xdr_u_int, (caddr_t) argp,
		   (xdrproc_t) xdr_generic_ret, (caddr_t) &clnt_res,
		   TIMEOUT) != RPC_SUCCESS) {
	  return (NULL);
     }
     return (&clnt_res);
}
