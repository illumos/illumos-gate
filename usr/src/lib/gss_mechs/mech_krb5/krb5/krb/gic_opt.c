#pragma ident	"%Z%%M%	%I%	%E% SMI"
#include <k5-int.h>

void KRB5_CALLCONV
krb5_get_init_creds_opt_init(krb5_get_init_creds_opt *opt)
{
   opt->flags = 0;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_tkt_life(krb5_get_init_creds_opt *opt, krb5_deltat tkt_life)
{
   opt->flags |= KRB5_GET_INIT_CREDS_OPT_TKT_LIFE;
   opt->tkt_life = tkt_life;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_renew_life(krb5_get_init_creds_opt *opt, krb5_deltat renew_life)
{
   opt->flags |= KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE;
   opt->renew_life = renew_life;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_forwardable(krb5_get_init_creds_opt *opt, int forwardable)
{
   opt->flags |= KRB5_GET_INIT_CREDS_OPT_FORWARDABLE;
   opt->forwardable = forwardable;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_proxiable(krb5_get_init_creds_opt *opt, int proxiable)
{
   opt->flags |= KRB5_GET_INIT_CREDS_OPT_PROXIABLE;
   opt->proxiable = proxiable;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_etype_list(krb5_get_init_creds_opt *opt, krb5_enctype *etype_list, int etype_list_length)
{
   opt->flags |= KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST;
   opt->etype_list = etype_list;
   opt->etype_list_length = etype_list_length;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_address_list(krb5_get_init_creds_opt *opt, krb5_address **addresses)
{
   opt->flags |= KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST;
   opt->address_list = addresses;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_preauth_list(krb5_get_init_creds_opt *opt, krb5_preauthtype *preauth_list, int preauth_list_length)
{
   opt->flags |= KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST;
   opt->preauth_list = preauth_list;
   opt->preauth_list_length = preauth_list_length;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_salt(krb5_get_init_creds_opt *opt, krb5_data *salt)
{
   opt->flags |= KRB5_GET_INIT_CREDS_OPT_SALT;
   opt->salt = salt;
}
