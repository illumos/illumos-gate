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

#ifndef __KADM_RPC_H__
#define __KADM_RPC_H__

#include <rpc/types.h>

#include	<krb5.h>
#include	<kadm5/admin.h>

struct cprinc_arg {
	krb5_ui_4 api_version;
	kadm5_principal_ent_rec rec;
	long mask;
	char *passwd;
};
typedef struct cprinc_arg cprinc_arg;
bool_t xdr_cprinc_arg();

struct cprinc3_arg {
	krb5_ui_4 api_version;
	kadm5_principal_ent_rec rec;
	long mask;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
	char *passwd;
};
typedef struct cprinc3_arg cprinc3_arg;
bool_t xdr_cprinc3_arg();

struct generic_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
};
typedef struct generic_ret generic_ret;
bool_t xdr_generic_ret();

struct dprinc_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
};
typedef struct dprinc_arg dprinc_arg;
bool_t xdr_dprinc_arg();

struct mprinc_arg {
	krb5_ui_4 api_version;
	kadm5_principal_ent_rec rec;
	long mask;
};
typedef struct mprinc_arg mprinc_arg;
bool_t xdr_mprinc_arg();

struct rprinc_arg {
	krb5_ui_4 api_version;
	krb5_principal src;
	krb5_principal dest;
};
typedef struct rprinc_arg rprinc_arg;
bool_t xdr_rprinc_arg();

struct gprincs_arg {
        krb5_ui_4 api_version;
	char *exp;
};
typedef struct gprincs_arg gprincs_arg;
bool_t xdr_gprincs_arg();

struct gprincs_ret {
        krb5_ui_4 api_version;
	kadm5_ret_t code;
	char **princs;
	int count;
};
typedef struct gprincs_ret gprincs_ret;
bool_t xdr_gprincs_ret();

struct chpass_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	char *pass;
};
typedef struct chpass_arg chpass_arg;
bool_t xdr_chpass_arg();

struct chpass3_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_boolean keepold;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
	char *pass;
};
typedef struct chpass3_arg chpass3_arg;
bool_t xdr_chpass3_arg();

struct setv4key_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
        krb5_keyblock *keyblock;
};
typedef struct setv4key_arg setv4key_arg;
bool_t xdr_setv4key_arg();

struct setkey_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
        krb5_keyblock *keyblocks;
        int n_keys;
};
typedef struct setkey_arg setkey_arg;
bool_t xdr_setkey_arg();

struct setkey3_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_boolean keepold;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
        krb5_keyblock *keyblocks;
        int n_keys;
};
typedef struct setkey3_arg setkey3_arg;
bool_t xdr_setkey3_arg();

struct chrand_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
};
typedef struct chrand_arg chrand_arg;
bool_t xdr_chrand_arg();

struct chrand3_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_boolean keepold;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
};
typedef struct chrand3_arg chrand3_arg;
bool_t xdr_chrand3_arg();

struct chrand_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	krb5_keyblock key;
	krb5_keyblock *keys;
	int n_keys;
};
typedef struct chrand_ret chrand_ret;
bool_t xdr_chrand_ret();

struct gprinc_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	long mask;
};
typedef struct gprinc_arg gprinc_arg;
bool_t xdr_gprinc_arg();

struct gprinc_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	kadm5_principal_ent_rec rec;
};
typedef struct gprinc_ret gprinc_ret;
bool_t xdr_gprinc_ret();
bool_t xdr_kadm5_ret_t();
bool_t xdr_kadm5_principal_ent_rec();
bool_t xdr_kadm5_policy_ent_rec();
bool_t	xdr_krb5_keyblock();
bool_t	xdr_krb5_principal();
bool_t	xdr_krb5_enctype();
bool_t	xdr_krb5_octet();
bool_t	xdr_krb5_int32();
bool_t	xdr_u_int32();

struct cpol_arg {
	krb5_ui_4 api_version;
	kadm5_policy_ent_rec rec;
	long mask;
};
typedef struct cpol_arg cpol_arg;
bool_t xdr_cpol_arg();

struct dpol_arg {
	krb5_ui_4 api_version;
	char *name;
};
typedef struct dpol_arg dpol_arg;
bool_t xdr_dpol_arg();

struct mpol_arg {
	krb5_ui_4 api_version;
	kadm5_policy_ent_rec rec;
	long mask;
};
typedef struct mpol_arg mpol_arg;
bool_t xdr_mpol_arg();

struct gpol_arg {
	krb5_ui_4 api_version;
	char *name;
};
typedef struct gpol_arg gpol_arg;
bool_t xdr_gpol_arg();

struct gpol_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	kadm5_policy_ent_rec rec;
};
typedef struct gpol_ret gpol_ret;
bool_t xdr_gpol_ret();

struct gpols_arg {
        krb5_ui_4 api_version;
	char *exp;
};
typedef struct gpols_arg gpols_arg;
bool_t xdr_gpols_arg();

struct gpols_ret {
        krb5_ui_4 api_version;
	kadm5_ret_t code;
	char **pols;
	int count;
};
typedef struct gpols_ret gpols_ret;
bool_t xdr_gpols_ret();

struct getprivs_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	long privs;
};
typedef struct getprivs_ret getprivs_ret;
bool_t xdr_getprivs_ret();

#define KADM ((krb5_ui_4)2112)
#define KADMVERS ((krb5_ui_4)2)
#define CREATE_PRINCIPAL ((krb5_ui_4)1)
extern generic_ret *create_principal_1_svc(cprinc_arg *arg, 
					   struct svc_req *rqstp);
extern generic_ret *create_principal_1(cprinc_arg *argp, CLIENT *clnt);

#define DELETE_PRINCIPAL ((krb5_ui_4)2)
extern generic_ret *delete_principal_1_svc(dprinc_arg *arg, 
					   struct svc_req *rqstp);
extern generic_ret *delete_principal_1(dprinc_arg *argp, CLIENT *clnt);

#define MODIFY_PRINCIPAL ((krb5_ui_4)3)
extern generic_ret *modify_principal_1_svc(mprinc_arg *arg,
					   struct svc_req *rqstp);
extern generic_ret *modify_principal_1(mprinc_arg *argp, CLIENT *clnt);

#define RENAME_PRINCIPAL ((krb5_ui_4)4)
extern generic_ret *rename_principal_1_svc(rprinc_arg *arg, 
					   struct svc_req *rqstp);
extern generic_ret *rename_principal_1(rprinc_arg *argp, CLIENT *clnt);

#define GET_PRINCIPAL ((krb5_ui_4)5)
extern gprinc_ret *get_principal_1_svc(gprinc_arg *arg, struct svc_req *rqstp);
extern gprinc_ret *get_principal_1(gprinc_arg *argp, CLIENT *clnt);

#define CHPASS_PRINCIPAL ((krb5_ui_4)6)
extern generic_ret *chpass_principal_1_svc(chpass_arg *arg, 
					   struct svc_req *rqstp);
extern generic_ret *chpass_principal_1(chpass_arg *argp, CLIENT *clnt);

#define CHRAND_PRINCIPAL ((krb5_ui_4)7)
extern chrand_ret *chrand_principal_1_svc(chrand_arg *arg, 
					  struct svc_req *rqstp);
extern chrand_ret *chrand_principal_1(chrand_arg *argp, CLIENT *clnt);

#define CREATE_POLICY ((krb5_ui_4)8)
extern generic_ret *create_policy_1_svc(cpol_arg *arg, struct svc_req *rqstp);
extern generic_ret *create_policy_1(cpol_arg *argp, CLIENT *clnt);

#define DELETE_POLICY ((krb5_ui_4)9)
extern generic_ret *delete_policy_1_svc(dpol_arg *arg, struct svc_req *rqstp);
extern generic_ret *delete_policy_1(dpol_arg *argp, CLIENT *clnt);

#define MODIFY_POLICY ((krb5_ui_4)10)
extern generic_ret *modify_policy_1_svc(mpol_arg *arg, struct svc_req *rqstp);
extern generic_ret *modify_policy_1(mpol_arg *argp, CLIENT *clnt);

#define GET_POLICY ((krb5_ui_4)11)
extern gpol_ret *get_policy_1_svc(gpol_arg *arg, struct svc_req *rqstp);
extern gpol_ret *get_policy_1(gpol_arg *argp, CLIENT *clnt);

#define GET_PRIVS ((krb5_ui_4)12)
extern getprivs_ret *get_privs_1_svc(krb5_ui_4 *arg, struct svc_req *rqstp);
extern getprivs_ret *get_privs_1(void *argp, CLIENT *clnt);

#define INIT ((krb5_ui_4)13)
extern generic_ret *init_1_svc(krb5_ui_4 *arg, struct svc_req *rqstp);
extern generic_ret *init_1();

#define GET_PRINCS ((krb5_ui_4) 14)
extern gprincs_ret *get_princs_1_svc(gprincs_arg *arg, struct svc_req *rqstp);
extern gprincs_ret *get_princs_1(gprincs_arg *argp, CLIENT *clnt);

#define GET_POLS ((krb5_ui_4) 15)
extern gpols_ret *get_pols_1_svc(gpols_arg *arg, struct svc_req *rqstp);
extern gpols_ret *get_pols_1(gpols_arg *argp, CLIENT *clnt);

#define SETKEY_PRINCIPAL ((krb5_ui_4) 16)
extern generic_ret *setkey_principal_1_svc(setkey_arg *arg, 
					   struct svc_req *rqstp);
extern generic_ret *setkey_principal_1(setkey_arg *argp, CLIENT *clnt);

#define SETV4KEY_PRINCIPAL ((krb5_ui_4) 17)
extern generic_ret *setv4key_principal_1_svc(setv4key_arg *arg, 
					     struct svc_req *rqstp);
extern generic_ret *setv4key_principal_1(setv4key_arg *argp, CLIENT *clnt);

#define CREATE_PRINCIPAL3 ((krb5_ui_4) 18)
extern generic_ret *create_principal3_1_svc(cprinc3_arg *arg, 
					    struct svc_req *rqstp);
extern generic_ret *create_principal3_1(cprinc3_arg *argp, CLIENT *clnt);

#define CHPASS_PRINCIPAL3 ((krb5_ui_4) 19)
extern generic_ret *chpass_principal3_1_svc(chpass3_arg *arg, 
					    struct svc_req *rqstp);
extern generic_ret *chpass_principal3_1(chpass3_arg *argp, CLIENT *clnt);

#define CHRAND_PRINCIPAL3 ((krb5_ui_4) 20)
extern chrand_ret *chrand_principal3_1_svc(chrand3_arg *arg, 
					   struct svc_req *rqstp);
extern chrand_ret *chrand_principal3_1(chrand3_arg *argp, CLIENT *clnt);

#define SETKEY_PRINCIPAL3 ((krb5_ui_4) 21)
extern generic_ret *setkey_principal3_1_svc(setkey3_arg *arg, 
					    struct svc_req *rqstp);
extern generic_ret *setkey_principal3_1(setkey3_arg *argp, CLIENT *clnt);

#endif /* __KADM_RPC_H__ */
