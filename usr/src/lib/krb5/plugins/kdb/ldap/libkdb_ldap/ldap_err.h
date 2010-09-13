#ifndef _LDAP_ERR_H_
#define _LDAP_ERR_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define OP_INIT 1
#define OP_BIND 2
#define OP_UNBIND 3
#define OP_ADD 4
#define OP_MOD 5
#define OP_DEL 6
#define OP_SEARCH 7
#define OP_CMP 8
#define OP_ABANDON 9


int translate_ldap_error(int err, int op);
#endif /* _LDAP_ERR_H_ */
