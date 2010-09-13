
#ifndef KRB5_AUTH_CONTEXT
#define KRB5_AUTH_CONTEXT

struct _krb5_auth_context {
    krb5_magic		magic;
    krb5_address      *	remote_addr;
    krb5_address      *	remote_port;
    krb5_address      *	local_addr;
    krb5_address      *	local_port;
    krb5_keyblock     * keyblock;
    krb5_keyblock     * send_subkey;
    krb5_keyblock     * recv_subkey;

    krb5_int32		auth_context_flags;
    krb5_ui_4		remote_seq_number;
    krb5_ui_4		local_seq_number;
    krb5_authenticator *authentp;		/* mk_req, rd_req, mk_rep, ...*/
    krb5_cksumtype	req_cksumtype;		/* mk_safe, ... */
    krb5_cksumtype	safe_cksumtype;		/* mk_safe, ... */
    krb5_pointer	i_vector;		/* mk_priv, rd_priv only */
    krb5_rcache		rcache;
    krb5_enctype      * permitted_etypes;	/* rd_req */
  krb5_mk_req_checksum_func checksum_func;
  void *checksum_func_data;
};


/* Internal auth_context_flags */
#define KRB5_AUTH_CONN_INITIALIZED	0x00010000
#define KRB5_AUTH_CONN_USED_W_MK_REQ	0x00020000
#define KRB5_AUTH_CONN_USED_W_RD_REQ	0x00040000
#define KRB5_AUTH_CONN_SANE_SEQ		0x00080000
#define KRB5_AUTH_CONN_HEIMDAL_SEQ	0x00100000

#endif
