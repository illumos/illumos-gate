#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_mech1.spec
#

function	krb5_425_conv_principal
include		<krb5.h>
declaration	krb5_error_code krb5_425_conv_principal \
			(krb5_context context, const char *name, \
			const char *instance, \
			const char *realm, \
			krb5_principal *princ)
version		SUNWprivate_1.1
end

function	krb5_524_conv_principal
include		<krb5.h>
declaration	krb5_error_code krb5_524_conv_principal \
			(krb5_context context, \
			const krb5_principal princ, \
			char *name, char *inst, char *realm)
version		SUNWprivate_1.1
end

function	krb5_address_compare
include		<krb5.h>, <k5-int.h>
declaration	krb5_boolean krb5_address_compare ( \
			krb5_context context, \
			const krb5_address *addr1, \
			const krb5_address *addr2)
version		SUNWprivate_1.1
end

function	krb5_address_order
include		<krb5.h>, <k5-int.h>
declaration	int krb5_address_order ( \
			krb5_context context, \
			register const krb5_address *addr1, \
			register const krb5_address *addr2)
version		SUNWprivate_1.1
end

function	krb5_address_search
include		<krb5.h>, <k5-int.h>
declaration	krb5_boolean krb5_address_search ( \
			krb5_context context, \
			const krb5_address *addr, \
			krb5_address * const * addrlist)
version		SUNWprivate_1.1
end

function	krb5_aname_to_localname
include		<krb5.h>
declaration	krb5_error_code krb5_aname_to_localname \
			(krb5_context context, \
			krb5_const_principal aname, \
			const int lnsize, char *lname)
version		SUNWprivate_1.1
end

function	krb5_auth_con_free
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_free \
			(krb5_context context, \
			krb5_auth_context auth_context)
version		SUNWprivate_1.1
end

function	krb5_auth_con_genaddrs
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_genaddrs \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			int infd, int flags)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getaddrs
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getaddrs \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_address **local_addr, \
			krb5_address **remote_addr)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getauthenticator
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getauthenticator \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_authenticator **authenticator)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getflags
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getflags \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_int32 *flags)
version		SUNWprivate_1.1
end

function	krb5_auth_con_set_checksum_func
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_set_checksum_func ( \
			krb5_context, krb5_auth_context, \
			krb5_mk_req_checksum_func, void *)
version		SUNWprivate_1.1
end

function	krb5_auth_con_get_checksum_func
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_get_checksum_func ( \
			krb5_context, krb5_auth_context, \
			krb5_mk_req_checksum_func *, void **)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getivector
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getivector \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_pointer *ivector)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getkey
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getkey \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_keyblock **keyblock)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getsendsubkey
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getsendsubkey( \
			krb5_context, \
			krb5_auth_context, \
			krb5_keyblock **)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getrecvsubkey
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getrecvsubkey( \
			krb5_context, \
			krb5_auth_context, \
			krb5_keyblock **)
version		SUNWprivate_1.1
end

function	krb5_auth_con_setsendsubkey
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_setsendsubkey( \
			krb5_context, \
			krb5_auth_context, \
			krb5_keyblock *)
version		SUNWprivate_1.1
end

function	krb5_auth_con_setrecvsubkey
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_setrecvsubkey( \
			krb5_context, \
			krb5_auth_context, \
			krb5_keyblock *)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getlocalseqnumber
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getlocalseqnumber \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_int32 *seqnumber)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getlocalsubkey
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getlocalsubkey \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_keyblock **keyblock)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getrcache
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getrcache \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_rcache *rcache)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getremoteseqnumber
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getremoteseqnumber \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_int32 *seqnumber)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getremotesubkey
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getremotesubkey \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_keyblock **keyblock)
version		SUNWprivate_1.1
end

function	krb5_auth_con_init
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_init \
			(krb5_context context, \
			krb5_auth_context *auth_context)
version		SUNWprivate_1.1
end

function	krb5_auth_con_initivector
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_initivector \
			(krb5_context context, \
			krb5_auth_context auth_context)
version		SUNWprivate_1.1
end

function	krb5_auth_con_set_req_cksumtype
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_set_req_cksumtype \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_cksumtype cksumtype)
version		SUNWprivate_1.1
end

function	krb5_auth_con_set_safe_cksumtype
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_set_safe_cksumtype \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_cksumtype cksumtype)
version		SUNWprivate_1.1
end

function	krb5_auth_con_setaddrs
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_setaddrs \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_address *local_addr, \
			krb5_address *remote_addr)
version		SUNWprivate_1.1
end

function	krb5_auth_con_setflags
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_setflags \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_int32 flags)
version		SUNWprivate_1.1
end

function	krb5_auth_con_setivector
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_setivector \
			(krb5_context context, krb5_auth_context auth_context, \
			krb5_pointer ivector)
version		SUNWprivate_1.1
end

function	krb5_auth_con_setports
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_setports \
			(krb5_context context, krb5_auth_context auth_context, \
			krb5_address *local_port, krb5_address *remote_port)
version		SUNWprivate_1.1
end

function	krb5_auth_con_setrcache
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_setrcache \
			(krb5_context context, krb5_auth_context auth_context, \
			krb5_rcache rcache)
version		SUNWprivate_1.1
end

function	krb5_auth_con_setuseruserkey
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_setuseruserkey \
			(krb5_context context, krb5_auth_context auth_context, \
			krb5_keyblock *keyblock)
version		SUNWprivate_1.1
end

function	krb5_auth_to_rep
include		<krb5.h>
declaration	krb5_error_code krb5_auth_to_rep ( \
			krb5_context context, \
			krb5_tkt_authent *auth, \
			krb5_donot_replay *rep)
version		SUNWprivate_1.1
end

# spec2trace RFE
function	krb5_build_principal
version		SUNWprivate_1.1
end

# spec2trace RFE
function	krb5_build_principal_ext
version		SUNWprivate_1.1
end

# spec2trace RFE
function	krb5_build_principal_va
version		SUNWprivate_1.1
end

function	krb5_check_transited_list
include		<krb5.h>
declaration	krb5_error_code krb5_check_transited_list \
			(krb5_context context, krb5_data *trans, \
			const krb5_data *realm1, const krb5_data *realm2)
version		SUNWprivate_1.1
end

data		krb5_cksumtypes_list
declaration	const struct krb5_cksumtypes krb5_cksumtypes_list[]
version		SUNWprivate_1.1
end

data		krb5_cksumtypes_length
declaration	const int krb5_cksumtypes_length
version		SUNWprivate_1.1
end

function	krb5_copy_addr
include		<krb5.h>
declaration	krb5_error_code krb5_copy_addr \
			(krb5_context context, \
			const krb5_address *inad, krb5_address **outad)
version		SUNWprivate_1.1
end

function	krb5_copy_addresses
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_copy_addresses ( \
			krb5_context context, \
			krb5_address * const * inaddr, \
			krb5_address ***outaddr)
version		SUNWprivate_1.1
end

function	krb5_copy_authdata
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_copy_authdata ( \
			krb5_context context, \
			krb5_authdata * const * inauthdat, \
			krb5_authdata ***outauthdat)
version		SUNWprivate_1.1
end

function	krb5_copy_authenticator
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_copy_authenticator ( \
			krb5_context context, \
			const krb5_authenticator *authfrom, \
			krb5_authenticator **authto)
version		SUNWprivate_1.1
end

function	krb5_copy_checksum
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_copy_checksum ( \
			krb5_context context, \
			const krb5_checksum *ckfrom, \
			krb5_checksum **ckto)
version		SUNWprivate_1.1
end

function	krb5_copy_creds
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_copy_creds ( \
			krb5_context context, \
			const krb5_creds *incred, \
			krb5_creds **outcred)
version		SUNWprivate_1.1
end

function	krb5_copy_data
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_copy_data ( \
			krb5_context context, \
			const krb5_data *indata, \
			krb5_data **outdata)
version		SUNWprivate_1.1
end

function	krb5_copy_keyblock
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_copy_keyblock ( \
			krb5_context contexti, \
			const krb5_keyblock *from, \
			krb5_keyblock **to)
version		SUNWprivate_1.1
end

function	krb5_copy_keyblock_contents
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_copy_keyblock_contents ( \
			krb5_context context, \
			const krb5_keyblock *from, \
			krb5_keyblock *to)
version		SUNWprivate_1.1
end

function	krb5_copy_keyblock_data
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_copy_keyblock_data ( \
			krb5_context context, \
			const krb5_keyblock *from, \
			krb5_keyblock *to)
version		SUNWprivate_1.1
end

function	krb5_copy_principal
include		<krb5.h>
declaration	krb5_error_code krb5_copy_principal ( \
			krb5_context context, \
			krb5_const_principal inprinc, \
			krb5_principal *outprinc)
version		SUNWprivate_1.1
end

function	krb5_copy_ticket
declaration	krb5_error_code krb5_copy_ticket ( \
			krb5_context context, \
			const krb5_ticket *from, \
			krb5_ticket **pto)
version		SUNWprivate_1.1
end

function	krb5_create_secure_file
include		<k5-int.h>
declaration	krb5_error_code krb5_create_secure_file \
			(krb5_context context, const char * pathname)
version		SUNWprivate_1.1
end

function	krb5_decode_kdc_rep
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_decode_kdc_rep ( \
			krb5_context context, \
			krb5_data * enc_rep, \
			const krb5_keyblock * key, \
			krb5_kdc_rep ** dec_rep)
version		SUNWprivate_1.1
end

function	krb5_decrypt_tkt_part
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_decrypt_tkt_part ( \
			krb5_context context, \
			const krb5_keyblock *srv_key, \
			register krb5_ticket *ticket)
version		SUNWprivate_1.1
end

data		krb5_default_pwd_prompt1
declaration	char *krb5_default_pwd_prompt1
version		SUNWprivate_1.1
end

data		krb5_default_pwd_prompt2
declaration	char *krb5_default_pwd_prompt2
version		SUNWprivate_1.1
end

data		krb5_defkeyname
declaration	char *krb5_defkeyname
version		SUNWprivate_1.1
end

# Uncomment if SUNW_INC_DEAD_CODE is set
#function	krb5_deltat_to_string
#include		<krb5.h>, <k5-int.h>
#declaration	krb5_error_code krb5_deltat_to_string ( \
#			krb5_deltat deltat, \
#			char * buffer, \
#			size_t buflen)
#version		SUNWprivate_1.1
#end

function	krb5_encode_kdc_rep
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_encode_kdc_rep ( \
			krb5_context context, \
			const krb5_msgtype type, \
			const krb5_enc_kdc_rep_part * encpart, \
			int using_subkey, \
			const krb5_keyblock * client_key, \
			krb5_kdc_rep * dec_rep, \
			krb5_data ** enc_rep)
version		SUNWprivate_1.1
end

function	krb5_encrypt_tkt_part
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_encrypt_tkt_part ( \
			krb5_context context, \
			const krb5_keyblock *srv_key, \
			register krb5_ticket *dec_ticket)
version		SUNWprivate_1.1
end

data		krb5_enctypes_list
declaration	const struct krb5_keytypes krb5_enctypes_list[]
version		SUNWprivate_1.1
end

data		krb5_enctypes_length
declaration	const int krb5_enctypes_length
version		SUNWprivate_1.1
end

function	krb5_externalize_data
include		<k5-int.h>
declaration	krb5_error_code krb5_externalize_data ( \
			krb5_context context, krb5_pointer arg, \
			krb5_octet **bufpp, size_t *sizep)
version		SUNWprivate_1.1
end

function	krb5_externalize_opaque
include		<k5-int.h>
declaration	krb5_error_code krb5_externalize_opaque ( \
			krb5_context context, krb5_magic odtype, \
			krb5_pointer arg, krb5_octet **bufpp, \
			size_t *sizep)
version		SUNWprivate_1.1
end
