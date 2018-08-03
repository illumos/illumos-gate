/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
** set password functions added by Paul W. Nelson, Thursby Software Systems, Inc.
*/
#include <string.h>

#include "k5-int.h"
/* Solaris Kerberos */
/* #include "krb5_err.h" */
#include "auth_con.h"


krb5_error_code 
krb5int_mk_chpw_req(
	krb5_context context, 
	krb5_auth_context auth_context, 
	krb5_data *ap_req,
	char *passwd, 
	krb5_data *packet)
{
    krb5_error_code ret = 0;
    krb5_data clearpw;
    krb5_data cipherpw;
    krb5_replay_data replay;
    char *ptr;

    cipherpw.data = NULL;

    if ((ret = krb5_auth_con_setflags(context, auth_context,
				      KRB5_AUTH_CONTEXT_DO_SEQUENCE)))
	  goto cleanup;

    clearpw.length = strlen(passwd);
    clearpw.data = passwd;

    if ((ret = krb5_mk_priv(context, auth_context,
			    &clearpw, &cipherpw, &replay)))
      goto cleanup;

    packet->length = 6 + ap_req->length + cipherpw.length;
    packet->data = (char *) malloc(packet->length);
    if (packet->data == NULL)
	{
	    ret = ENOMEM;
	    goto cleanup;
	}
    ptr = packet->data;

    /* length */

    *ptr++ = (packet->length>> 8) & 0xff;
    *ptr++ = packet->length & 0xff;

    /* version == 0x0001 big-endian */

    *ptr++ = 0;
    *ptr++ = 1;

    /* ap_req length, big-endian */

    *ptr++ = (ap_req->length>>8) & 0xff;
    *ptr++ = ap_req->length & 0xff;

    /* ap-req data */

    memcpy(ptr, ap_req->data, ap_req->length);
    ptr += ap_req->length;

    /* krb-priv of password */

    memcpy(ptr, cipherpw.data, cipherpw.length);

cleanup:
    if(cipherpw.data != NULL)  /* allocated by krb5_mk_priv */
      free(cipherpw.data);
      
    return(ret);
}

krb5_error_code 
krb5int_rd_chpw_rep(krb5_context context, krb5_auth_context auth_context, krb5_data *packet, int *result_code, krb5_data *result_data)
{
    char *ptr;
    int plen, vno;
    krb5_data ap_rep;
    krb5_ap_rep_enc_part *ap_rep_enc;
    krb5_error_code ret;
    krb5_data cipherresult;
    krb5_data clearresult;
    /* Solaris Kerberos */
    krb5_error *krberror = NULL;
    krb5_replay_data replay;
    krb5_keyblock *tmp;

    if (packet->length < 4)
	/* either this, or the server is printing bad messages,
	   or the caller passed in garbage */
	return(KRB5KRB_AP_ERR_MODIFIED);

    ptr = packet->data;

    /* verify length */

    plen = (*ptr++ & 0xff);
    plen = (plen<<8) | (*ptr++ & 0xff);

    if (plen != packet->length) 
	{
		/*
		 * MS KDCs *may* send back a KRB_ERROR.  Although
		 * not 100% correct via RFC3244, it's something
		 * we can workaround here.
		 */
		if (krb5_is_krb_error(packet)) {

			if ((ret = krb5_rd_error(context, packet, &krberror)))
			return(ret);

			if (krberror->e_data.data  == NULL) {
				ret = ERROR_TABLE_BASE_krb5 + (krb5_error_code) krberror->error;
				krb5_free_error(context, krberror);
				return (ret);
			}
		}
		else
		{
			return(KRB5KRB_AP_ERR_MODIFIED);
		}
	}

    /* Solaris Kerberos */
    if (krberror != NULL) {
	krb5_free_error(context, krberror);
	krberror = NULL;
    }

    /* verify version number */

    vno = (*ptr++ & 0xff);
    vno = (vno<<8) | (*ptr++ & 0xff);

    if (vno != 1)
	return(KRB5KDC_ERR_BAD_PVNO);

    /* read, check ap-rep length */

    ap_rep.length = (*ptr++ & 0xff);
    ap_rep.length = (ap_rep.length<<8) | (*ptr++ & 0xff);

    if (ptr + ap_rep.length >= packet->data + packet->length)
	return(KRB5KRB_AP_ERR_MODIFIED);

    if (ap_rep.length) {
	/* verify ap_rep */
	ap_rep.data = ptr;
	ptr += ap_rep.length;

	/*
	 * Save send_subkey to later smash recv_subkey.
	 */
	ret = krb5_auth_con_getsendsubkey(context, auth_context, &tmp);
	if (ret)
	    return ret;

	ret = krb5_rd_rep(context, auth_context, &ap_rep, &ap_rep_enc);
	if (ret) {
	    krb5_free_keyblock(context, tmp);
	    return(ret);
	}

	krb5_free_ap_rep_enc_part(context, ap_rep_enc);

	/* extract and decrypt the result */

	cipherresult.data = ptr;
	cipherresult.length = (packet->data + packet->length) - ptr;

	/*
	 * Smash recv_subkey to be send_subkey, per spec.
	 */
	ret = krb5_auth_con_setrecvsubkey(context, auth_context, tmp);
	krb5_free_keyblock(context, tmp);
	if (ret)
	    return ret;

	ret = krb5_rd_priv(context, auth_context, &cipherresult, &clearresult,
			   &replay);

	if (ret)
	    return(ret);
    } else {
	cipherresult.data = ptr;
	cipherresult.length = (packet->data + packet->length) - ptr;

	if ((ret = krb5_rd_error(context, &cipherresult, &krberror)))
	    return(ret);

	clearresult = krberror->e_data;
    }

    if (clearresult.length < 2) {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }

    ptr = clearresult.data;

    *result_code = (*ptr++ & 0xff);
    *result_code = (*result_code<<8) | (*ptr++ & 0xff);

    if ((*result_code < KRB5_KPASSWD_SUCCESS) ||
	(*result_code > KRB5_KPASSWD_INITIAL_FLAG_NEEDED)) {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }

    /* all success replies should be authenticated/encrypted */

    if ((ap_rep.length == 0) && (*result_code == KRB5_KPASSWD_SUCCESS)) {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }

    result_data->length = (clearresult.data + clearresult.length) - ptr;

    if (result_data->length) {
	result_data->data = (char *) malloc(result_data->length);
	if (result_data->data == NULL) {
	    ret = ENOMEM;
	    goto cleanup;
	}
	memcpy(result_data->data, ptr, result_data->length);
    } else {
	result_data->data = NULL;
    }

    ret = 0;

cleanup:
    if (ap_rep.length) {
	krb5_xfree(clearresult.data);
    } else {
	krb5_free_error(context, krberror);
    }

    return(ret);
}

krb5_error_code KRB5_CALLCONV
krb5_chpw_result_code_string(krb5_context context, int result_code, char **code_string)
{
   switch (result_code) {
   case KRB5_KPASSWD_MALFORMED:
      *code_string = "Malformed request error";
      break;
   case KRB5_KPASSWD_HARDERROR:
      *code_string = "Server error";
      break;
   case KRB5_KPASSWD_AUTHERROR:
      *code_string = "Authentication error";
      break;
   case KRB5_KPASSWD_SOFTERROR:
      *code_string = "Password change rejected";
      break;
   default:
      *code_string = "Password change failed";
      break;
   }

   return(0);
}

krb5_error_code 
krb5int_mk_setpw_req(
     krb5_context context,
     krb5_auth_context auth_context,
     krb5_data *ap_req,
     krb5_principal targprinc,
     char *passwd,
     krb5_data *packet )
{
    krb5_error_code ret;
    krb5_data	cipherpw;
    krb5_data	*encoded_setpw;
    struct krb5_setpw_req req;

    char *ptr;

    cipherpw.data = NULL;
    cipherpw.length = 0;
     
    if ((ret = krb5_auth_con_setflags(context, auth_context,
				      KRB5_AUTH_CONTEXT_DO_SEQUENCE)))
		return(ret);

    req.target = targprinc;
    req.password.data = passwd;
    req.password.length = strlen(passwd);
    ret = encode_krb5_setpw_req(&req, &encoded_setpw);
    if (ret) {
	return ret;
    }

    if ( (ret = krb5_mk_priv(context, auth_context, encoded_setpw, &cipherpw, NULL)) != 0) {
	krb5_free_data( context, encoded_setpw);
	return(ret);
    }
    krb5_free_data( context, encoded_setpw);
    

    packet->length = 6 + ap_req->length + cipherpw.length;
    packet->data = (char *) malloc(packet->length);
    if (packet->data  == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    ptr = packet->data;
/*
** build the packet -
*/
/* put in the length */
    *ptr++ = (packet->length>>8) & 0xff;
    *ptr++ = packet->length & 0xff;
/* put in the version */
    *ptr++ = (char)0xff;
    *ptr++ = (char)0x80;
/* the ap_req length is big endian */
    *ptr++ = (ap_req->length>>8) & 0xff;
    *ptr++ = ap_req->length & 0xff;
/* put in the request data */
    memcpy(ptr, ap_req->data, ap_req->length);
    ptr += ap_req->length;
/*
** put in the "private" password data -
*/
    memcpy(ptr, cipherpw.data, cipherpw.length);
    ret = 0;
 cleanup:
    if (cipherpw.data)
	krb5_free_data_contents(context, &cipherpw);
    if ((ret != 0) && packet->data) {
	free( packet->data);
	packet->data = NULL;
    }
    return ret;
}

krb5_error_code 
krb5int_rd_setpw_rep( krb5_context context, krb5_auth_context auth_context, krb5_data *packet,
     int *result_code, krb5_data *result_data )
{
    char *ptr;
    unsigned int message_length, version_number;
    krb5_data ap_rep;
    krb5_ap_rep_enc_part *ap_rep_enc;
    krb5_error_code ret;
    krb5_data cipherresult;
    krb5_data clearresult;
    krb5_keyblock *tmpkey;
/*
** validate the packet length -
*/
    if (packet->length < 4)
	return(KRB5KRB_AP_ERR_MODIFIED);

    ptr = packet->data;

/*
** see if it is an error
*/
    if (krb5_is_krb_error(packet)) {
	krb5_error *krberror;
	if ((ret = krb5_rd_error(context, packet, &krberror)))
	    return(ret);
	if (krberror->e_data.data  == NULL) {
	    ret = ERROR_TABLE_BASE_krb5 + (krb5_error_code) krberror->error;
	    krb5_free_error(context, krberror);
	    return (ret);
	}
	clearresult = krberror->e_data;
	krberror->e_data.data  = NULL; /*So we can free it later*/
	krberror->e_data.length = 0;
	krb5_free_error(context, krberror);
		
    } else { /* Not an error*/

/*
** validate the message length -
** length is big endian 
*/
	message_length = (((ptr[0] << 8)&0xff) | (ptr[1]&0xff));
	ptr += 2;
/*
** make sure the message length and packet length agree -
*/
	if (message_length != packet->length)
	    return(KRB5KRB_AP_ERR_MODIFIED);
/*
** get the version number -
*/
	version_number = (((ptr[0] << 8)&0xff) | (ptr[1]&0xff));
	ptr += 2;
/*
** make sure we support the version returned -
*/
/*
** set password version is 0xff80, change password version is 1
*/
	if (version_number != 1 && version_number != 0xff80)
	    return(KRB5KDC_ERR_BAD_PVNO);
/*
** now fill in ap_rep with the reply -
*/
/*
** get the reply length -
*/
	ap_rep.length = (((ptr[0] << 8)&0xff) | (ptr[1]&0xff));
	ptr += 2;
/*
** validate ap_rep length agrees with the packet length -
*/
	if (ptr + ap_rep.length >= packet->data + packet->length)
	    return(KRB5KRB_AP_ERR_MODIFIED);
/*
** if data was returned, set the ap_rep ptr -
*/
	if( ap_rep.length ) {
	    ap_rep.data = ptr;
	    ptr += ap_rep.length;

	    /*
	     * Save send_subkey to later smash recv_subkey.
	     */
	    ret = krb5_auth_con_getsendsubkey(context, auth_context, &tmpkey);
	    if (ret)
		return ret;

	    ret = krb5_rd_rep(context, auth_context, &ap_rep, &ap_rep_enc);
	    if (ret) {
		krb5_free_keyblock(context, tmpkey);
		return(ret);
	    }

	    krb5_free_ap_rep_enc_part(context, ap_rep_enc);
/*
** now decrypt the result -
*/
	    cipherresult.data = ptr;
	    cipherresult.length = (packet->data + packet->length) - ptr;

	    /*
	     * Smash recv_subkey to be send_subkey, per spec.
	     */
	    ret = krb5_auth_con_setrecvsubkey(context, auth_context, tmpkey);
	    krb5_free_keyblock(context, tmpkey);
	    if (ret)
		return ret;

	    ret = krb5_rd_priv(context, auth_context, &cipherresult, &clearresult,
			       NULL);
	    if (ret)
		return(ret);
	} /*We got an ap_rep*/
	else
	    return (KRB5KRB_AP_ERR_MODIFIED);
    } /*Response instead of error*/

/*
** validate the cleartext length 
*/
    if (clearresult.length < 2) {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }
/*
** now decode the result -
*/
    ptr = clearresult.data;

    *result_code = (((ptr[0] << 8)&0xff) | (ptr[1]&0xff));
    ptr += 2;

/*
** result code 5 is access denied
*/
    if ((*result_code < KRB5_KPASSWD_SUCCESS) || (*result_code > 5))
    {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }
/*
** all success replies should be authenticated/encrypted
*/
    if( (ap_rep.length == 0) && (*result_code == KRB5_KPASSWD_SUCCESS) )
    {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }

    if (result_data) {
	result_data->length = (clearresult.data + clearresult.length) - ptr;

	if (result_data->length)
	{
	    result_data->data = (char *) malloc(result_data->length);
	    if (result_data->data)
		memcpy(result_data->data, ptr, result_data->length);
	}
	else
	    result_data->data = NULL;
    }
    ret = 0;

 cleanup:
    krb5_free_data_contents(context, &clearresult);
    return(ret);
}

krb5_error_code 
krb5int_setpw_result_code_string( krb5_context context, int result_code, const char **code_string )
{
   switch (result_code)
   {
   case KRB5_KPASSWD_MALFORMED:
      *code_string = "Malformed request error";
      break;
   case KRB5_KPASSWD_HARDERROR:
      *code_string = "Server error";
      break;
   case KRB5_KPASSWD_AUTHERROR:
      *code_string = "Authentication error";
      break;
   case KRB5_KPASSWD_SOFTERROR:
      *code_string = "Password change rejected";
      break;
   case 5: /* access denied */
      *code_string = "Access denied";
      break;
   case 6:	/* bad version */
      *code_string = "Wrong protocol version";
      break;
   case 7: /* initial flag is needed */
      *code_string = "Initial password required";
      break;
   case 0:
      *code_string = "Success";
      break;
   default:
      *code_string = "Password change failed";
      break;
   }

   return(0);
}

