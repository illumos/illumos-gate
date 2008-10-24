/*
 * lib/krb5/rcache/rc_conv.c
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */


/*
 * An implementation for the default replay cache type.
 */

/* Solaris Kerberos - resync */
#define FREE_RC(x) ((void) free((char *) (x)))

#include "rc_base.h"

/*
Local stuff:
 krb5_auth_to_replay(context, krb5_tkt_authent *auth,krb5_donot_replay *rep)
  given auth, take important information and make rep; return -1 if failed
*/

krb5_error_code
krb5_auth_to_rep(krb5_context context, krb5_tkt_authent *auth, krb5_donot_replay *rep)
{
 krb5_error_code retval;
 rep->cusec = auth->authenticator->cusec;
 rep->ctime = auth->authenticator->ctime;
 if ((retval = krb5_unparse_name(context, auth->ticket->server, &rep->server)))
   return retval; /* shouldn't happen */
 if ((retval = krb5_unparse_name(context, auth->authenticator->client,
				 &rep->client))) {
     FREE_RC(rep->server);
     return retval; /* shouldn't happen. */
 }
 return 0;
}
