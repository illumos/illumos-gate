#pragma ident	"%Z%%M%	%I%	%E% SMI"
#include <k5-int.h>

KRB5_DLLIMP void KRB5_CALLCONV
krb5_verify_init_creds_opt_init(opt)
     krb5_verify_init_creds_opt *opt;
{
   opt->flags = 0;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_verify_init_creds_opt_set_ap_req_nofail(opt, ap_req_nofail)
     krb5_verify_init_creds_opt *opt;
     int ap_req_nofail;
{
   opt->flags |= KRB5_VERIFY_INIT_CREDS_OPT_AP_REQ_NOFAIL;
   opt->ap_req_nofail = ap_req_nofail;
}
