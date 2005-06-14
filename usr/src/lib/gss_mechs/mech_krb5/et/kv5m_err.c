/*
 * Copyright (c) 1998, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
 
#include <locale.h>
const char *
kv5m_error_table(long errorno) {

switch (errorno) {
	case 0:
		return(dgettext(TEXT_DOMAIN,
			"Kerberos V5 magic number table"));
	case 1:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_principal structure"));
	case 2:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_data structure"));
	case 3:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_keyblock structure"));
	case 4:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_checksum structure"));
	case 5:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_encrypt_block structure"));
	case 6:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_enc_data structure"));
	case 7:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_cryptosystem_entry structure"));
	case 8:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_cs_table_entry structure"));
	case 9:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_checksum_entry structure"));
	case 10:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_authdata structure"));
	case 11:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_transited structure"));
	case 12:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_enc_tkt_part structure"));
	case 13:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_ticket structure"));
	case 14:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_authenticator structure"));
	case 15:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_tkt_authent structure"));
	case 16:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_creds structure"));
	case 17:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_last_req_entry structure"));
	case 18:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_pa_data structure"));
	case 19:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_kdc_req structure"));
	case 20:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_enc_kdc_rep_part structure"));
	case 21:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_kdc_rep structure"));
	case 22:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_error structure"));
	case 23:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_ap_req structure"));
	case 24:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_ap_rep structure"));
	case 25:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_ap_rep_enc_part structure"));
	case 26:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_response structure"));
	case 27:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_safe structure"));
	case 28:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_priv structure"));
	case 29:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_priv_enc_part structure"));
	case 30:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_cred structure"));
	case 31:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_cred_info structure"));
	case 32:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_cred_enc_part structure"));
	case 33:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_pwd_data structure"));
	case 34:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_address structure"));
	case 35:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_keytab_entry structure"));
	case 36:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_context structure"));
	case 37:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_os_context structure"));
	case 38:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_alt_method structure"));
	case 39:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_etype_info_entry structure"));
	case 40:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_db_context structure"));
	case 41:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_auth_context structure"));
	case 42:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_keytab structure"));
	case 43:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_rcache structure"));
	case 44:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_ccache structure"));
	case 45:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_preauth_ops"));
	case 46:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_sam_challenge"));
	case 47:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_sam_key"));
	case 48:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_enc_sam_response_enc"));
	case 49:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_sam_response"));
	case 50:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_predicted_sam_response"));
	case 51:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for passwd_phrase_element"));
	case 52:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for GSSAPI OID"));
	case 53:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for GSSAPI QUEUE"));
	default:
		return("unknown error");
	}
}
