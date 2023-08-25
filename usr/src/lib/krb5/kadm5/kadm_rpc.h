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

#include	<kadm5/admin.h>
#include	<krb5.h>

struct cprinc_arg {
	krb5_ui_4 api_version;
	kadm5_principal_ent_rec rec;
	long mask;
	char *passwd;
};
typedef struct cprinc_arg cprinc_arg;

struct cprinc3_arg {
	krb5_ui_4 api_version;
	kadm5_principal_ent_rec rec;
	long mask;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
	char *passwd;
};
typedef struct cprinc3_arg cprinc3_arg;

struct generic_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
};
typedef struct generic_ret generic_ret;

struct dprinc_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
};
typedef struct dprinc_arg dprinc_arg;

struct mprinc_arg {
	krb5_ui_4 api_version;
	kadm5_principal_ent_rec rec;
	long mask;
};
typedef struct mprinc_arg mprinc_arg;

struct rprinc_arg {
	krb5_ui_4 api_version;
	krb5_principal src;
	krb5_principal dest;
};
typedef struct rprinc_arg rprinc_arg;

struct gprincs_arg {
        krb5_ui_4 api_version;
	char *exp;
};
typedef struct gprincs_arg gprincs_arg;

struct gprincs_ret {
        krb5_ui_4 api_version;
	kadm5_ret_t code;
	char **princs;
	int count;
};
typedef struct gprincs_ret gprincs_ret;

struct chpass_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	char *pass;
};
typedef struct chpass_arg chpass_arg;

struct chpass3_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_boolean keepold;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
	char *pass;
};
typedef struct chpass3_arg chpass3_arg;

struct setv4key_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
        krb5_keyblock *keyblock;
};
typedef struct setv4key_arg setv4key_arg;

struct setkey_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
        krb5_keyblock *keyblocks;
        int n_keys;
};
typedef struct setkey_arg setkey_arg;

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

struct chrand_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
};
typedef struct chrand_arg chrand_arg;

struct chrand3_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	krb5_boolean keepold;
	int n_ks_tuple;
	krb5_key_salt_tuple *ks_tuple;
};
typedef struct chrand3_arg chrand3_arg;

struct chrand_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	krb5_keyblock key;
	krb5_keyblock *keys;
	int n_keys;
};
typedef struct chrand_ret chrand_ret;

struct gprinc_arg {
	krb5_ui_4 api_version;
	krb5_principal princ;
	long mask;
};
typedef struct gprinc_arg gprinc_arg;

struct gprinc_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	kadm5_principal_ent_rec rec;
};
typedef struct gprinc_ret gprinc_ret;

struct cpol_arg {
	krb5_ui_4 api_version;
	kadm5_policy_ent_rec rec;
	long mask;
};
typedef struct cpol_arg cpol_arg;

struct dpol_arg {
	krb5_ui_4 api_version;
	char *name;
};
typedef struct dpol_arg dpol_arg;

struct mpol_arg {
	krb5_ui_4 api_version;
	kadm5_policy_ent_rec rec;
	long mask;
};
typedef struct mpol_arg mpol_arg;

struct gpol_arg {
	krb5_ui_4 api_version;
	char *name;
};
typedef struct gpol_arg gpol_arg;

struct gpol_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	kadm5_policy_ent_rec rec;
};
typedef struct gpol_ret gpol_ret;

struct gpols_arg {
        krb5_ui_4 api_version;
	char *exp;
};
typedef struct gpols_arg gpols_arg;

struct gpols_ret {
        krb5_ui_4 api_version;
	kadm5_ret_t code;
	char **pols;
	int count;
};
typedef struct gpols_ret gpols_ret;

struct getprivs_ret {
	krb5_ui_4 api_version;
	kadm5_ret_t code;
	long privs;
};
typedef struct getprivs_ret getprivs_ret;

#define KADM 2112
#define KADMVERS 2
#define CREATE_PRINCIPAL 1
extern  generic_ret * create_principal_2(cprinc_arg *, CLIENT *);
extern  generic_ret * create_principal_2_svc(cprinc_arg *, struct svc_req *);
#define DELETE_PRINCIPAL 2
extern  generic_ret * delete_principal_2(dprinc_arg *, CLIENT *);
extern  generic_ret * delete_principal_2_svc(dprinc_arg *, struct svc_req *);
#define MODIFY_PRINCIPAL 3
extern  generic_ret * modify_principal_2(mprinc_arg *, CLIENT *);
extern  generic_ret * modify_principal_2_svc(mprinc_arg *, struct svc_req *);
#define RENAME_PRINCIPAL 4
extern  generic_ret * rename_principal_2(rprinc_arg *, CLIENT *);
extern  generic_ret * rename_principal_2_svc(rprinc_arg *, struct svc_req *);
#define GET_PRINCIPAL 5
extern  gprinc_ret * get_principal_2(gprinc_arg *, CLIENT *);
extern  gprinc_ret * get_principal_2_svc(gprinc_arg *, struct svc_req *);
#define CHPASS_PRINCIPAL 6
extern  generic_ret * chpass_principal_2(chpass_arg *, CLIENT *);
extern  generic_ret * chpass_principal_2_svc(chpass_arg *, struct svc_req *);
#define CHRAND_PRINCIPAL 7
extern  chrand_ret * chrand_principal_2(chrand_arg *, CLIENT *);
extern  chrand_ret * chrand_principal_2_svc(chrand_arg *, struct svc_req *);
#define CREATE_POLICY 8
extern  generic_ret * create_policy_2(cpol_arg *, CLIENT *);
extern  generic_ret * create_policy_2_svc(cpol_arg *, struct svc_req *);
#define DELETE_POLICY 9
extern  generic_ret * delete_policy_2(dpol_arg *, CLIENT *);
extern  generic_ret * delete_policy_2_svc(dpol_arg *, struct svc_req *);
#define MODIFY_POLICY 10
extern  generic_ret * modify_policy_2(mpol_arg *, CLIENT *);
extern  generic_ret * modify_policy_2_svc(mpol_arg *, struct svc_req *);
#define GET_POLICY 11
extern  gpol_ret * get_policy_2(gpol_arg *, CLIENT *);
extern  gpol_ret * get_policy_2_svc(gpol_arg *, struct svc_req *);
#define GET_PRIVS 12
extern  getprivs_ret * get_privs_2(void *, CLIENT *);
extern  getprivs_ret * get_privs_2_svc(krb5_ui_4 *, struct svc_req *);
#define INIT 13
extern  generic_ret * init_2(void *, CLIENT *);
extern  generic_ret * init_2_svc(krb5_ui_4 *, struct svc_req *);
#define GET_PRINCS 14
extern  gprincs_ret * get_princs_2(gprincs_arg *, CLIENT *);
extern  gprincs_ret * get_princs_2_svc(gprincs_arg *, struct svc_req *);
#define GET_POLS 15
extern  gpols_ret * get_pols_2(gpols_arg *, CLIENT *);
extern  gpols_ret * get_pols_2_svc(gpols_arg *, struct svc_req *);
#define SETKEY_PRINCIPAL 16
extern  generic_ret * setkey_principal_2(setkey_arg *, CLIENT *);
extern  generic_ret * setkey_principal_2_svc(setkey_arg *, struct svc_req *);
#define SETV4KEY_PRINCIPAL 17
extern  generic_ret * setv4key_principal_2(setv4key_arg *, CLIENT *);
extern  generic_ret * setv4key_principal_2_svc(setv4key_arg *, struct svc_req *);
#define CREATE_PRINCIPAL3 18
extern  generic_ret * create_principal3_2(cprinc3_arg *, CLIENT *);
extern  generic_ret * create_principal3_2_svc(cprinc3_arg *, struct svc_req *);
#define CHPASS_PRINCIPAL3 19
extern  generic_ret * chpass_principal3_2(chpass3_arg *, CLIENT *);
extern  generic_ret * chpass_principal3_2_svc(chpass3_arg *, struct svc_req *);
#define CHRAND_PRINCIPAL3 20
extern  chrand_ret * chrand_principal3_2(chrand3_arg *, CLIENT *);
extern  chrand_ret * chrand_principal3_2_svc(chrand3_arg *, struct svc_req *);
#define SETKEY_PRINCIPAL3 21
extern  generic_ret * setkey_principal3_2(setkey3_arg *, CLIENT *);
extern  generic_ret * setkey_principal3_2_svc(setkey3_arg *, struct svc_req *);

extern bool_t xdr_cprinc_arg ();
extern bool_t xdr_cprinc3_arg ();
extern bool_t xdr_generic_ret ();
extern bool_t xdr_dprinc_arg ();
extern bool_t xdr_mprinc_arg ();
extern bool_t xdr_rprinc_arg ();
extern bool_t xdr_gprincs_arg ();
extern bool_t xdr_gprincs_ret ();
extern bool_t xdr_chpass_arg ();
extern bool_t xdr_chpass3_arg ();
extern bool_t xdr_setv4key_arg ();
extern bool_t xdr_setkey_arg ();
extern bool_t xdr_setkey3_arg ();
extern bool_t xdr_chrand_arg ();
extern bool_t xdr_chrand3_arg ();
extern bool_t xdr_chrand_ret ();
extern bool_t xdr_gprinc_arg ();
extern bool_t xdr_gprinc_ret ();
extern bool_t xdr_kadm5_ret_t ();
extern bool_t xdr_kadm5_principal_ent_rec ();
extern bool_t xdr_kadm5_policy_ent_rec ();
extern bool_t	xdr_krb5_keyblock ();
extern bool_t	xdr_krb5_principal ();
extern bool_t	xdr_krb5_enctype ();
extern bool_t	xdr_krb5_octet ();
extern bool_t	xdr_krb5_int32 ();
extern bool_t	xdr_u_int32 ();
extern bool_t xdr_cpol_arg ();
extern bool_t xdr_dpol_arg ();
extern bool_t xdr_mpol_arg ();
extern bool_t xdr_gpol_arg ();
extern bool_t xdr_gpol_ret ();
extern bool_t xdr_gpols_arg ();
extern bool_t xdr_gpols_ret ();
extern bool_t xdr_getprivs_ret ();


#endif /* __KADM_RPC_H__ */
