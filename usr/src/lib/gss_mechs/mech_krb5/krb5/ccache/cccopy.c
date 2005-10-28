#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "k5-int.h"

krb5_error_code KRB5_CALLCONV
krb5_cc_copy_creds(krb5_context context, krb5_ccache incc, krb5_ccache outcc)
{
    krb5_error_code code;
    krb5_flags flags;
    krb5_cc_cursor cur = 0;
    krb5_creds creds;

    flags = 0;				/* turns off OPENCLOSE mode */
    if ((code = krb5_cc_set_flags(context, incc, flags)))
	return(code);
    /* the code for this will open the file for reading only, which
       is not what I had in mind.  So I won't turn off OPENCLOSE
       for the output ccache */
#if 0
    if ((code = krb5_cc_set_flags(context, outcc, flags)))
	return(code);
#endif

    if ((code = krb5_cc_start_seq_get(context, incc, &cur)))
	goto cleanup;

    while (!(code = krb5_cc_next_cred(context, incc, &cur, &creds))) {
	code = krb5_cc_store_cred(context, outcc, &creds);
	krb5_free_cred_contents(context, &creds);
	if (code)
	    goto cleanup;
    }

    if (code != KRB5_CC_END)
	goto cleanup;

    code = krb5_cc_end_seq_get(context, incc, &cur);
    cur = 0;
    if (code)
        goto cleanup;

    code = 0;

cleanup:
    flags = KRB5_TC_OPENCLOSE;

    /* If set then we are in an error pathway */
    if (cur) 
      krb5_cc_end_seq_get(context, incc, &cur);

    if (code)
	krb5_cc_set_flags(context, incc, flags);
    else
	code = krb5_cc_set_flags(context, incc, flags);

#if 0
    if (code)
	krb5_cc_set_flags(context, outcc, flags);
    else
	code = krb5_cc_set_flags(context, outcc, flags);
#endif

    return(code);
}
