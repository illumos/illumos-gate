/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/rcache/rc_base.c
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 */


/*
 * Base "glue" functions for the replay cache.
 */

#ifdef SEMAPHORE
#include <semaphore.h>
#endif
#include "rc_base.h"
#include "rc_common.h"
#include "rc_mem.h"
#include "rc_file.h"

#define FREE_RC(x) ((void) free((char *) (x)))

struct krb5_rc_typelist
 {
  krb5_rc_ops *ops;
  struct krb5_rc_typelist *next;
 };
static struct krb5_rc_typelist rc_mem_type = { &krb5_rc_mem_ops, 0 };
static struct krb5_rc_typelist krb5_rc_typelist_dfl =
	{ &krb5_rc_file_ops, &rc_mem_type };
static struct krb5_rc_typelist *typehead = &krb5_rc_typelist_dfl;

#ifdef SEMAPHORE
semaphore ex_typelist = 1;
#endif

/*ARGSUSED*/
krb5_error_code krb5_rc_register_type(context, ops)
    krb5_context context;
    krb5_rc_ops *ops;
{
 struct krb5_rc_typelist *t;
#ifdef SEMAPHORE
 down(&ex_typelist);
#endif
 for (t = typehead;t && strcmp(t->ops->type,ops->type);t = t->next)
   ;
#ifdef SEMAPHORE
 up(&ex_typelist);
#endif
 if (t)
   return KRB5_RC_TYPE_EXISTS;
 if (!(t = (struct krb5_rc_typelist *) malloc(sizeof(struct krb5_rc_typelist))))
   return KRB5_RC_MALLOC;
#ifdef SEMAPHORE
 down(&ex_typelist);
#endif
 t->next = typehead;
 t->ops = ops;
 typehead = t;
#ifdef SEMAPHORE
 up(&ex_typelist);
#endif
 return 0;
}

/*ARGSUSED*/
char * krb5_rc_get_type(context, id)
    krb5_context context;
    krb5_rcache id;
{
 return id->ops->type;
}

/*ARGSUSED*/
char * krb5_rc_default_name(context)
    krb5_context context;
{
 char *s;
 if ((s = getenv("KRB5RCNAME")))
   return s;
 else
   return (char *) 0;
}

krb5_error_code
krb5_rc_resolve(krb5_context context, krb5_rcache id, char *name)
{
	struct krb5_rc_typelist *tlist;
	char *cp, *pfx, *resid;
	int pfxlen;

	cp = strchr(name, ':');
	if (!cp)
		if (krb5_rc_dfl_ops) {
			id->ops = krb5_rc_dfl_ops;
			return ((*krb5_rc_dfl_ops->resolve)(context, id, name));
		} else
			return (KRB5_RC_BADNAME);

	pfxlen = cp - name;
	resid = name + pfxlen + 1;

	pfx = malloc(pfxlen + 1);
	if (!pfx)
		return (ENOMEM);

	memcpy(pfx, name, pfxlen);
	pfx[pfxlen] = '\0';

	for (tlist = typehead; tlist; tlist = tlist->next)
		if (strcmp(tlist->ops->type, pfx) == 0) {
			free(pfx);
			id->ops = tlist->ops;
			return ((*tlist->ops->resolve)(context, id, resid));
		}
	if (krb5_rc_dfl_ops && !strcmp(pfx, krb5_rc_dfl_ops->type)) {
		free(pfx);
		id->ops = krb5_rc_dfl_ops;
		return ((*krb5_rc_dfl_ops->resolve)(context, id, resid));
	}
	free(pfx);
	return (KRB5_RC_TYPE_NOTFOUND);
}

krb5_error_code
krb5_rc_default(context, id)
    krb5_context context;
    krb5_rcache *id;
{
    krb5_error_code retval;

    if (!(*id = (krb5_rcache )malloc(sizeof(**id))))
	return KRB5_RC_MALLOC;

    retval = krb5_rc_resolve(context, *id, 
				 krb5_rc_default_name(context));
    if (retval)
	FREE_RC(*id);
    (*id)->magic = KV5M_RCACHE;
    return retval;
}


krb5_error_code krb5_rc_resolve_full(context, id, string_name)
    krb5_context context;
    krb5_rcache *id;
    char *string_name;
{
    char *type;
    char *residual;
    krb5_error_code retval;

    if (!(residual = strchr(string_name,':')))
	return KRB5_RC_PARSE;
 
    if (!(type = malloc(residual - string_name + 1)))
	return KRB5_RC_MALLOC;
    (void) strncpy(type,string_name,residual - string_name);
    type[residual - string_name] = '\0';

    if (!(*id = (krb5_rcache) malloc(sizeof(**id)))) {
	FREE_RC(type);
	return KRB5_RC_MALLOC;
    }

    FREE_RC(type);
    retval = krb5_rc_resolve(context, *id, residual + 1);
    if (retval)
	FREE_RC(*id);
    (*id)->magic = KV5M_RCACHE;
    return retval;
}

