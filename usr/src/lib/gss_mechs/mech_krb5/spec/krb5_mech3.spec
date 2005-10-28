#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_mech3.spec
#

function	krb5_kuserok
include		<krb5.h>
declaration	krb5_boolean krb5_kuserok (krb5_context context, \
			krb5_principal principal, const char *luser)
version		SUNWprivate_1.1
end

function	krb5_locate_kdc
include		<k5-int.h>, <os-proto.h>, <sys/socket.h>
declaration	krb5_error_code krb5_locate_kdc (krb5_context context, \
			const krb5_data *realm, \
			struct addrlist *addrlist, \
			int get_masters, int socktype, int family)
version		SUNWprivate_1.1
end

function	krb5_get_servername
include		<k5-int.h>, <os-proto.h>, <sys/socket.h>
declaration	krb5_error_code krb5_get_servername (krb5_context context, \
			const krb5_data *realm, \
			const char *name, const char *proto, \
			char *srvhost, \
			unsigned short *port)
version		SUNWprivate_1.1
end

function	krb5_getenv
declaration	char * krb5_getenv (const char *name)
version		SUNWprivate_1.1
end

function	krb5_lock_file
include		<gssapi_krb5.h>, <ktfile.h>
declaration	krb5_error_code krb5_lock_file \
			(krb5_context context, int fd, int mode)
version		SUNWprivate_1.1
end

function	krb5_make_full_ipaddr
include		<krb5.h>, <os-proto.h>
declaration	krb5_error_code krb5_make_full_ipaddr \
			(krb5_context context, krb5_int32 adr, \
			int port,  krb5_address **outaddr)
version		SUNWprivate_1.1
end

function	krb5_make_fulladdr
include		<krb5.h>
declaration	krb5_error_code krb5_make_fulladdr \
			(krb5_context context, krb5_address *kaddr, \
			krb5_address *kport, krb5_address *raddr)
version		SUNWprivate_1.1
end

data		krb5_max_dgram_size
declaration	int krb5_max_dgram_size
version		SUNWprivate_1.1
end

data		krb5_max_skdc_timeout
declaration	int krb5_max_skdc_timeout
version		SUNWprivate_1.1
end

function	krb5_mk_1cred
declaration	krb5_error_code krb5_mk_1cred \
			(krb5_context cotext, krb5_auth_context auth_context, \
			krb5_creds *pcreds, krb5_data **ppdata, \
			krb5_replay_data *outdata)
version		SUNWprivate_1.1
end

function	krb5_mk_error
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_mk_error (krb5_context context, \
			const krb5_error *dec_err, \
			krb5_data *enc_err)
version		SUNWprivate_1.1
end

function	krb5_mk_ncred
include		<krb5.h>
declaration	krb5_error_code krb5_mk_ncred \
			(krb5_context context, krb5_auth_context auth_context, \
			krb5_creds **ppcreds, krb5_data **ppdata, \
			krb5_replay_data *outdata)
version		SUNWprivate_1.1
end

function	krb5_mk_priv
include		<krb5.h>
declaration	krb5_error_code krb5_mk_priv (krb5_context context, \
			krb5_auth_context auth_context, \
			const krb5_data * userdata, \
			krb5_data * outbuf, \
			krb5_replay_data * outdata)
version		SUNWprivate_1.1
end

function	krb5_mk_rep
include		<krb5.h>
declaration	krb5_error_code krb5_mk_rep \
			(krb5_context context, krb5_auth_context auth_context, \
			krb5_data *outbuf)
version		SUNWprivate_1.1
end

function	krb5_mk_req
include		<krb5.h>
declaration	krb5_error_code krb5_mk_req (krb5_context context, \
			krb5_auth_context * auth_context, \
			const krb5_flags ap_req_options, \
			char * service, char * hostname, \
			krb5_data * in_data, krb5_ccache ccache, \
			krb5_data * outbuf)
version		SUNWprivate_1.1
end

function	krb5_mk_req_extended
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_mk_req_extended ( \
			krb5_context context, \
			krb5_auth_context * auth_context, \
			const krb5_flags ap_req_options, \
			krb5_data * in_data, \
			krb5_creds * in_creds, \
			krb5_data * outbuf)
version		SUNWprivate_1.1
end

function	krb5_mk_safe
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_mk_safe ( \
			krb5_context context, \
			krb5_auth_context auth_context, \
			const krb5_data * userdata, \
			krb5_data * outbuf, \
			krb5_replay_data * outdata)
version		SUNWprivate_1.1
end

# spec2trace RFE
data		krb5_mutex
version		SUNWprivate_1.1
end

function	krb5_net_read
include		<k5-int.h>
declaration	int krb5_net_read \
			(krb5_context context, int fd, \
			char *buf, int len)
version		SUNWprivate_1.1
end

function	krb5_net_write
include		<k5-int.h>
declaration	int krb5_net_write \
			(krb5_context context, int fd, \
			const char *buf, int len)
version		SUNWprivate_1.1
end

function	krb5_nfold
include		<k5-int.h>
declaration	void krb5_nfold( \
			int inbits, \
			const unsigned char *in, \
			int outbits, \
			unsigned char *out)
version		SUNWprivate_1.1
end

function	krb5_os_free_context
include		<k5-int.h>
declaration	void krb5_os_free_context (krb5_context context)
version		SUNWprivate_1.1
end

# spec2trace RFE
function	krb5_os_get_tty_uio
version		SUNWprivate_1.1
end

function	krb5_os_hostaddr
include		<krb5.h>
declaration	krb5_error_code krb5_os_hostaddr \
			(krb5_context context, const char *name, \
			krb5_address ***ret_addrs)
version		SUNWprivate_1.1
end

function	krb5_os_init_context
include		<k5-int.h>
declaration	krb5_error_code krb5_os_init_context \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_os_localaddr
include		<krb5.h>
declaration	krb5_error_code krb5_os_localaddr \
			(krb5_context context, krb5_address ***addr)
version		SUNWprivate_1.1
end

function	krb5_parse_name
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_parse_name ( \
			krb5_context context, \
			const char *name, \
			krb5_principal *nprincipal)
version		SUNWprivate_1.1
end

function	krb5_principal2salt
include		<krb5.h>
declaration	krb5_error_code krb5_principal2salt \
			(krb5_context conteXt, \
			krb5_const_principal pr, \
			krb5_data *ret)
version		SUNWprivate_1.1
end

function	krb5_principal2salt_norealm
include		<krb5.h>
declaration	krb5_error_code krb5_principal2salt_norealm \
			(krb5_context context, \
			krb5_const_principal pr, \
			krb5_data *ret)
version		SUNWprivate_1.1
end

function	krb5_principal_compare
include		<krb5.h>
declaration	krb5_boolean krb5_principal_compare \
			(krb5_context context, \
			krb5_const_principal princ1, \
			krb5_const_principal princ2)
version		SUNWprivate_1.1
end

function	krb5_privacy_allowed
include		<krb5.h>
declaration	krb5_boolean krb5_privacy_allowed (void)
version		SUNWprivate_1.1
end

function	krb5_pname_to_uid
include		<gssapiP_krb5.h>
declaration	OM_uint32 krb5_pname_to_uid \
			(void *ctxt, OM_uint32 *minor, \
			const gss_name_t pname, uid_t *uidOut)
version		SUNWprivate_1.1
end

function	krb5_gss_userok
include		<gssapi/gssapi.h>, <gssapi/gssapi_ext.h>, <gssapiP_krb5.h>, \
		<gssapi_krb5.h>
declaration	OM_uint32 krb5_gss_userok \
			(void *ctxt, OM_uint32 *minor, \
			const gss_name_t pname, \
			const char *user, int *user_ok)
version			SUNWprivate_1.1
end

function	krb5_rd_cred
include		<krb5.h>
declaration	krb5_error_code krb5_rd_cred \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_data *pcreddata, krb5_creds ***pppcreds, \
			krb5_replay_data *outdata)
version		SUNWprivate_1.1
end

function	krb5_rd_error
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_rd_error ( \
			krb5_context context, \
			const krb5_data *enc_errbuf, \
			krb5_error **dec_error)
version		SUNWprivate_1.1
end

function	krb5_rd_priv
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_rd_priv ( \
			krb5_context context, \
			krb5_auth_context auth_context, \
			const krb5_data * inbuf, \
			krb5_data * outbuf, \
			krb5_replay_data * outdata)
version		SUNWprivate_1.1
end

function	krb5_rd_rep
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_rd_rep ( \
			krb5_context context, \
			krb5_auth_context auth_context, \
			const krb5_data * inbuf, \
			krb5_ap_rep_enc_part **repl)
version		SUNWprivate_1.1
end

function	krb5_rd_req
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_rd_req ( \
			krb5_context context, \
			krb5_auth_context * auth_context, \
			const krb5_data * inbuf, \
			krb5_const_principal server, \
			krb5_keytab keytab, \
			krb5_flags * ap_req_options, \
			krb5_ticket ** ticket)
version		SUNWprivate_1.1
end

function	krb5_rd_req_decoded
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_rd_req_decoded ( \
			krb5_context context, \
			krb5_auth_context * auth_context, \
			const krb5_ap_req * req, \
			krb5_const_principal server, \
			krb5_keytab keytab, \
			krb5_flags * ap_req_options, \
			krb5_ticket ** ticket)
version		SUNWprivate_1.1
end

function	krb5_rd_req_decoded_anyflag
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_rd_req_decoded_anyflag ( \
			krb5_context context, \
			krb5_auth_context * auth_context, \
			const krb5_ap_req * req, \
			krb5_const_principal server, \
			krb5_keytab keytab, \
			krb5_flags * ap_req_options, \
			krb5_ticket ** ticket)
version		SUNWprivate_1.1
end

function	krb5_rd_safe
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_rd_safe ( \
			krb5_context context, \
			krb5_auth_context auth_context, \
			const krb5_data * inbuf, \
			krb5_data * outbuf, \
			krb5_replay_data * outdata)
version		SUNWprivate_1.1
end

function	krb5_read_message
include		<k5-int.h>
declaration	krb5_error_code krb5_read_message \
			(krb5_context context, krb5_pointer fdp, \
			krb5_data *inbuf)
version		SUNWprivate_1.1
end

function	krb5_read_password
include		<krb5.h>
declaration	krb5_error_code krb5_read_password \
			(krb5_context context, const char *prompt, \
			const char *prompt2, char *return_pwd, \
			unsigned int *size_return)
version		SUNWprivate_1.1
end

function	krb5_realm_compare
include		<krb5.h>
declaration	krb5_boolean krb5_realm_compare \
			(krb5_context context, \
			krb5_const_principal princ1, \
			krb5_const_principal princ2)
version		SUNWprivate_1.1
end

function	krb5_recvauth
include		<krb5.h>
declaration	krb5_error_code krb5_recvauth \
			(krb5_context context, krb5_auth_context *auth_context, \
			krb5_pointer fd, char *appl_version, \
			krb5_principal server, krb5_int32 flags, \
			krb5_keytab keytab, krb5_ticket **ticket)
version		SUNWprivate_1.1
end

function	krb5_register_serializer
include		<k5-int.h>
declaration	krb5_error_code krb5_register_serializer \
			(krb5_context context, const krb5_ser_entry *entry)
version		SUNWprivate_1.1
end

function	krb5_salttype_to_string
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_salttype_to_string ( \
			krb5_int32 salttype, \
			char * buffer, \
			size_t buflen)
version		SUNWprivate_1.1
end

function	krb5_secure_config_files
include		<krb5.h>
declaration	krb5_error_code krb5_secure_config_files \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_send_tgs
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_send_tgs ( \
			krb5_context context, \
			const krb5_flags kdcoptions, \
			const krb5_ticket_times * timestruct, \
			const krb5_enctype * ktypes, \
			krb5_const_principal sname, \
			krb5_address * const * addrs, \
			krb5_authdata * const * authorization_data, \
			krb5_pa_data * const * padata, \
			const krb5_data * second_ticket, \
			krb5_creds * in_cred, \
			krb5_response * rep)
version		SUNWprivate_1.1
end

function	krb5_sendauth
include		<krb5.h>
declaration	krb5_error_code krb5_sendauth (krb5_context context, \
			krb5_auth_context *auth_context, \
			krb5_pointer fd, char *appl_version, \
			krb5_principal client, krb5_principal server, \
			krb5_flags ap_req_options, krb5_data *in_data, \
			krb5_creds *in_creds, krb5_ccache cache, \
			krb5_error **error, krb5_ap_rep_enc_part **rep_result, \
			krb5_creds **out_creds)
version		SUNWprivate_1.1
end

function	krb5_sendto_kdc
include		<k5-int.h>
declaration	krb5_error_code krb5_sendto_kdc \
			(krb5_context context, const krb5_data *message, \
			const krb5_data *realm, krb5_data *reply, \
			int use_master, int tcp_only)
version		SUNWprivate_1.1
end

function	krb5_ser_address_init
declaration	krb5_error_code krb5_ser_address_init \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_ser_auth_context_init
include		<k5-int.h>
declaration	krb5_error_code krb5_ser_auth_context_init \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_ser_authdata_init
declaration	krb5_error_code krb5_ser_authdata_init \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_ser_authenticator_init
declaration	krb5_error_code krb5_ser_authenticator_init \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_ser_ccache_init
include		<k5-int.h>
declaration	krb5_error_code krb5_ser_ccache_init \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_ser_checksum_init
declaration	krb5_error_code krb5_ser_checksum_init \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_ser_context_init
include		<k5-int.h>
declaration	krb5_error_code krb5_ser_context_init \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_ser_keyblock_init
declaration	krb5_error_code krb5_ser_keyblock_init \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_ser_keytab_init
include		<k5-int.h>
declaration	krb5_error_code krb5_ser_keytab_init \
			(krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_ser_pack_bytes
include		<k5-int.h>
declaration	krb5_error_code krb5_ser_pack_bytes \
			(krb5_octet *osstring, size_t osize, \
			krb5_octet **bufp, size_t *remainp)
version		SUNWprivate_1.1
end

function	krb5_ser_pack_int32
include		<k5-int.h>
declaration	krb5_error_code krb5_ser_pack_int32 \
			(krb5_int32 iarg, krb5_octet **bufp, \
			size_t *remainp)
version		SUNWprivate_1.1
end

function	krb5_ser_principal_init
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_ser_principal_init \
			(krb5_context kcontext)
version		SUNWprivate_1.1
end

function	krb5_ser_rcache_init
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_ser_rcache_init \
			(krb5_context kcontext)
version		SUNWprivate_1.1
end

function	krb5_ser_unpack_bytes
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_ser_unpack_bytes \
			(krb5_octet *istring, size_t isize, \
			krb5_octet **bufp, size_t *remainp)
version		SUNWprivate_1.1
end

function	krb5_ser_unpack_int32
include		<krb5.h>
declaration	krb5_error_code krb5_ser_unpack_int32 \
			(krb5_int32 *intp, krb5_octet **bufp, \
			size_t *remainp)
version		SUNWprivate_1.1
end

function	krb5_set_config_files
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_set_config_files \
			(krb5_context ctx, const char **filenames)
version		SUNWprivate_1.1
end

function	krb5_set_debugging_time
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_set_debugging_time \
			(krb5_context context, \
			krb5_int32 seconds, \
			krb5_int32 microseconds)
version		SUNWprivate_1.1
end

function	krb5_set_default_in_tkt_ktypes
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_set_default_in_tkt_ktypes \
			(krb5_context context, \
			const krb5_enctype *ktypes)
version		SUNWprivate_1.1
end

function	krb5_set_default_realm
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_set_default_realm \
			(krb5_context context, const char *lrealm)
version		SUNWprivate_1.1
end

function	krb5_set_default_tgs_ktypes
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_set_default_tgs_ktypes \
			(krb5_context context, \
			const krb5_enctype *ktypes)
version		SUNWprivate_1.1
end

function	krb5_set_real_time
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_set_real_time \
			(krb5_context context, krb5_int32 seconds, \
			krb5_int32 microseconds)
version		SUNWprivate_1.1
end

function	krb5_set_time_offsets
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_set_time_offsets \
			(krb5_context context, krb5_int32 seconds, \
			krb5_int32 microseconds)
version		SUNWprivate_1.1
end

function	krb5_setenv
declaration	int krb5_setenv (register const char *name, \
			register const char *value, int rewrite)
version		SUNWprivate_1.1
end

function	krb5_size_opaque
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_size_opaque ( \
			krb5_context kcontext, krb5_magic odtype, \
			krb5_pointer arg, size_t *sizep)
version		SUNWprivate_1.1
end

data		krb5_skdc_timeout_1
declaration	int krb5_skdc_timeout_shift
version		SUNWprivate_1.1
end

data		krb5_skdc_timeout_shift
declaration	int krb5_skdc_timeout_shift
version		SUNWprivate_1.1
end

function	krb5_sname_to_principal
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_sname_to_principal ( \
			krb5_context context, const char *hostname, \
			const char *sname, krb5_int32 type, \
			krb5_principal *ret_princ)
version		SUNWprivate_1.1
end

function	krb5_string_to_deltat
include		<krb5.h>
declaration	krb5_error_code krb5_string_to_deltat ( \
			char *string, krb5_deltat *deltatp)
version		SUNWprivate_1.1
end

function	krb5_string_to_salttype
include		<krb5.h>
declaration	krb5_error_code krb5_string_to_salttype ( \
			char *string, krb5_int32 *salttypep)
version		SUNWprivate_1.1
end

function	krb5_string_to_timestamp
include		<krb5.h>
declaration	krb5_error_code krb5_string_to_timestamp ( \
			char *string, krb5_timestamp *timestampp)
version		SUNWprivate_1.1
end

function	krb5_sync_disk_file
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_sync_disk_file ( \
			krb5_context context, FILE *fp)
version		SUNWprivate_1.1
end

function	krb5_tgtname
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_tgtname (krb5_context context, \
			const krb5_data *server, const krb5_data *client, \
			krb5_principal *tgtprinc)
version		SUNWprivate_1.1
end

function	krb5_timeofday
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_timeofday (krb5_context context, \
			register krb5_int32 *timeret)
version		SUNWprivate_1.1
end

function	krb5_timestamp_to_sfstring
include		<krb5.h>
declaration	krb5_error_code krb5_timestamp_to_sfstring ( \
			krb5_timestamp timestamp, char * buffer, \
			size_t buflen, char *pad)
version		SUNWprivate_1.1
end

function	krb5_timestamp_to_string
include		<krb5.h>
declaration	krb5_error_code krb5_timestamp_to_string ( \
			krb5_timestamp timestamp, \
			char *buffer, size_t buflen)
version		SUNWprivate_1.1
end

function	krb5_unlock_file
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_unlock_file \
			(krb5_context context, int fd)
version		SUNWprivate_1.1
end

function	krb5_unpack_full_ipaddr
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_unpack_full_ipaddr ( \
			krb5_context context, const krb5_address *inaddr, \
			krb5_int32 *adr, krb5_int16 *port)
version		SUNWprivate_1.1
end

function	krb5_unparse_name
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_unparse_name (krb5_context context, \
			krb5_const_principal principal, register char **name)
version		SUNWprivate_1.1
end

function	krb5_unparse_name_ext
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_unparse_name_ext ( \
			krb5_context context, krb5_const_principal principal, \
			register char **name, int *size)
version		SUNWprivate_1.1
end

function	krb5_unsetenv
declaration	void krb5_unsetenv (const char *name)
version		SUNWprivate_1.1
end

function	krb5_us_timeofday
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_us_timeofday (krb5_context context, \
			krb5_int32 *seconds, krb5_int32 *microseconds)
version		SUNWprivate_1.1
end

function	krb5_use_natural_time
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_use_natural_time (krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_validate_times
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_validate_times (krb5_context context, \
			krb5_ticket_times *times)
version		SUNWprivate_1.1
end

function	krb5_walk_realm_tree
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_walk_realm_tree (krb5_context context, \
			const krb5_data *client, const krb5_data *server, \
			krb5_principal **tree, int realm_branch_char)
version		SUNWprivate_1.1
end

function	krb5_write_message
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_write_message (krb5_context context, \
			krb5_pointer fdp, krb5_data *outbuf)
version		SUNWprivate_1.1
end

function	krb5int_cm_call_select
include		<cm.h>, <k5-int.h>, <os-proto.h>
declaration	krb5_error_code krb5int_cm_call_select ( \
            const struct select_state *in, \
			struct select_state *out, \
            int *sret)
version		SUNWprivate_1.1
end

function	krb5int_sendtokdc_debug_handler
include		<cm.h>, <k5-int.h>, <os-proto.h>
declaration	void * krb5int_sendtokdc_debug_handler (const void *, \
            size_t)
version		SUNWprivate_1.1
end

function	foreach_localaddr
include		<fake-addrinfo.h>, <k5-int.h>
declaration	int foreach_localaddr (void *, \
		    int (*pass1fn)(void *, struct sockaddr *), \
		    int (*betweenfn)(void *), \
		    int (*pass2fn)(void *, struct sockaddr *))
version		SUNWprivate_1.1
end
