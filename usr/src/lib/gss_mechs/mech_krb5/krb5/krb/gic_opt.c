#include "k5-int.h"
#include "int-proto.h"

static void
init_common(krb5_get_init_creds_opt *opt)
{
    opt->flags |= KRB5_GET_INIT_CREDS_OPT_CHG_PWD_PRMPT;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_init(krb5_get_init_creds_opt *opt)
{
    opt->flags = 0;
    init_common(opt);
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

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_change_password_prompt(krb5_get_init_creds_opt *opt, int prompt)
{
   if (prompt)
     opt->flags |= KRB5_GET_INIT_CREDS_OPT_CHG_PWD_PRMPT;
   else
     opt->flags &= ~KRB5_GET_INIT_CREDS_OPT_CHG_PWD_PRMPT;
}

/*
 * Extending the krb5_get_init_creds_opt structure.  The original
 * krb5_get_init_creds_opt structure is defined publicly.  The
 * new extended version is private.  The original interface
 * assumed a pre-allocated structure which was passed to
 * krb5_get_init_creds_init().  The new interface assumes that
 * the caller will call krb5_get_init_creds_alloc() and
 * krb5_get_init_creds_free().
 *
 * Callers MUST NOT call krb5_get_init_creds_init() after allocating an
 * opts structure using krb5_get_init_creds_alloc().  To do so will
 * introduce memory leaks.  Unfortunately, there is no way to enforce
 * this behavior.
 *
 * Two private flags are added for backward compatibility.
 * KRB5_GET_INIT_CREDS_OPT_EXTENDED says that the structure was allocated
 * with the new krb5_get_init_creds_opt_alloc() function.
 * KRB5_GET_INIT_CREDS_OPT_SHADOWED is set to indicate that the extended
 * structure is a shadow copy of an original krb5_get_init_creds_opt
 * structure.
 * If KRB5_GET_INIT_CREDS_OPT_SHADOWED is set after a call to
 * krb5int_gic_opt_to_opte(), the resulting extended structure should be
 * freed (using krb5_get_init_creds_free).  Otherwise, the original
 * structure was already extended and there is no need to free it.
 */

/* Forward prototype */
static void
free_gic_opt_ext_preauth_data(krb5_context context,
			      krb5_gic_opt_ext *opte);

static krb5_error_code
krb5int_gic_opte_private_alloc(krb5_context context, krb5_gic_opt_ext *opte)
{
    if (NULL == opte || !krb5_gic_opt_is_extended(opte))
	return EINVAL;

    opte->opt_private = calloc(1, sizeof(*opte->opt_private));
    if (NULL == opte->opt_private) {
	return ENOMEM;
    }
    /* Allocate any private stuff */
    opte->opt_private->num_preauth_data = 0;
    opte->opt_private->preauth_data = NULL;
    return 0;
}

static krb5_error_code
krb5int_gic_opte_private_free(krb5_context context, krb5_gic_opt_ext *opte)
{
    if (NULL == opte || !krb5_gic_opt_is_extended(opte))
	return EINVAL;

    /* Free up any private stuff */
    if (opte->opt_private->preauth_data != NULL)
	free_gic_opt_ext_preauth_data(context, opte);
    free(opte->opt_private);
    opte->opt_private = NULL;
    return 0;
}

static krb5_gic_opt_ext *
krb5int_gic_opte_alloc(krb5_context context)
{
    krb5_gic_opt_ext *opte;
    krb5_error_code code;

    opte = calloc(1, sizeof(*opte));
    if (NULL == opte)
	return NULL;
    opte->flags = KRB5_GET_INIT_CREDS_OPT_EXTENDED;

    code = krb5int_gic_opte_private_alloc(context, opte);
    if (code) {
	krb5int_set_error(&context->err, code,
		"krb5int_gic_opte_alloc: krb5int_gic_opte_private_alloc failed");
	free(opte);
	return NULL;
    }
    return(opte);
}

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_opt_alloc(krb5_context context,
			      krb5_get_init_creds_opt **opt)
{
    krb5_gic_opt_ext *opte;

    if (NULL == opt)
	return EINVAL;
    *opt = NULL;

    /*
     * We return a new extended structure cast as a krb5_get_init_creds_opt
     */
    opte = krb5int_gic_opte_alloc(context);
    if (NULL == opte)
	return ENOMEM;

    *opt = (krb5_get_init_creds_opt *) opte;
    init_common(*opt);
    return 0;
}

void KRB5_CALLCONV
krb5_get_init_creds_opt_free(krb5_context context,
			     krb5_get_init_creds_opt *opt)
{
    krb5_gic_opt_ext *opte;

    if (NULL == opt)
	return;

    /* Don't touch it if we didn't allocate it */
    if (!krb5_gic_opt_is_extended(opt))
	return;

    opte = (krb5_gic_opt_ext *)opt;
    if (opte->opt_private)
	krb5int_gic_opte_private_free(context, opte);

    free(opte);
}

static krb5_error_code
krb5int_gic_opte_copy(krb5_context context,
		      krb5_get_init_creds_opt *opt,
		      krb5_gic_opt_ext **opte)
{
    krb5_gic_opt_ext *oe;

    oe = krb5int_gic_opte_alloc(context);
    if (NULL == oe)
	return ENOMEM;

    if (opt)
        memcpy(oe, opt, sizeof(*opt));

    /*
     * Fix the flags -- the EXTENDED flag would have been
     * overwritten by the copy if there was one.  The
     * SHADOWED flag is necessary to ensure that the
     * krb5_gic_opt_ext structure that was allocated
     * here will be freed by the library because the
     * application is unaware of its existence.
     */
    oe->flags |= ( KRB5_GET_INIT_CREDS_OPT_EXTENDED |
		   KRB5_GET_INIT_CREDS_OPT_SHADOWED);

    *opte = oe;
    return 0;
}

/*
 * Convert a krb5_get_init_creds_opt pointer to a pointer to
 * an extended, krb5_gic_opt_ext pointer.  If the original
 * pointer already points to an extended structure, then simply
 * return the original pointer.  Otherwise, if 'force' is non-zero,
 * allocate an extended structure and copy the original over it.
 * If the original pointer did not point to an extended structure
 * and 'force' is zero, then return an error.  This is used in
 * cases where the original *should* be an extended structure.
 */
krb5_error_code
krb5int_gic_opt_to_opte(krb5_context context,
			krb5_get_init_creds_opt *opt,
			krb5_gic_opt_ext **opte,
			unsigned int force,
			const char *where)
{
    if (!krb5_gic_opt_is_extended(opt)) {
	if (force) {
	    return krb5int_gic_opte_copy(context, opt, opte);
	} else {
	    krb5int_set_error(&context->err, EINVAL,
		    "%s: attempt to convert non-extended krb5_get_init_creds_opt",
		    where);
	    return EINVAL;
	}
    }
    /* If it is already extended, just return it */
    *opte = (krb5_gic_opt_ext *)opt;
    return 0;
}

static void
free_gic_opt_ext_preauth_data(krb5_context context,
			      krb5_gic_opt_ext *opte)
{
    int i;

    if (NULL == opte || !krb5_gic_opt_is_extended(opte))
	return;
    if (NULL == opte->opt_private || NULL == opte->opt_private->preauth_data)
	return;

    for (i = 0; i < opte->opt_private->num_preauth_data; i++) {
	if (opte->opt_private->preauth_data[i].attr != NULL)
	    free(opte->opt_private->preauth_data[i].attr);
	if (opte->opt_private->preauth_data[i].value != NULL)
	    free(opte->opt_private->preauth_data[i].value);
    }
    free(opte->opt_private->preauth_data);
    opte->opt_private->preauth_data = NULL;
    opte->opt_private->num_preauth_data = 0;
}

static krb5_error_code
add_gic_opt_ext_preauth_data(krb5_context context,
			     krb5_gic_opt_ext *opte,
			     const char *attr,
			     const char *value)
{
    size_t newsize;
    int i;
    krb5_gic_opt_pa_data *newpad;

    newsize = opte->opt_private->num_preauth_data + 1;
    newsize = newsize * sizeof(*opte->opt_private->preauth_data);
    if (opte->opt_private->preauth_data == NULL)
	newpad = malloc(newsize);
    else
	newpad = realloc(opte->opt_private->preauth_data, newsize);
    if (newpad == NULL)
	return ENOMEM;

    i = opte->opt_private->num_preauth_data;
    newpad[i].attr = strdup(attr);
    if (newpad[i].attr == NULL)
	return ENOMEM;
    newpad[i].value = strdup(value);
    if (newpad[i].value == NULL) {
	free(newpad[i].attr);
	return ENOMEM;
    }
    opte->opt_private->num_preauth_data += 1;
    opte->opt_private->preauth_data = newpad;
    return 0;
}

/*
 * This function allows the caller to supply options to preauth
 * plugins.  Preauth plugin modules are given a chance to look
 * at each option at the time this function is called in ordre
 * to check the validity of the option.
 * The 'opt' pointer supplied to this function must have been
 * obtained using krb5_get_init_creds_opt_alloc()
 */
krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_opt_set_pa(krb5_context context,
			       krb5_get_init_creds_opt *opt,
			       const char *attr,
			       const char *value)
{
    krb5_error_code retval;
    krb5_gic_opt_ext *opte;

    retval = krb5int_gic_opt_to_opte(context, opt, &opte, 0,
				     "krb5_get_init_creds_opt_set_pa");
    if (retval)
	return retval;

    /*
     * Copy the option into the extended get_init_creds_opt structure
     */
    retval = add_gic_opt_ext_preauth_data(context, opte, attr, value);
    if (retval)
	return retval;

    /*
     * Give the plugins a chance to look at the option now.
     */
    retval = krb5_preauth_supply_preauth_data(context, opte, attr, value);
    return retval;
}

/*
 * This function allows a preauth plugin to obtain preauth
 * options.  The preauth_data returned from this function
 * should be freed by calling krb5_get_init_creds_opt_free_pa().
 *
 * The 'opt' pointer supplied to this function must have been
 * obtained using krb5_get_init_creds_opt_alloc()
 */
krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_opt_get_pa(krb5_context context,
			       krb5_get_init_creds_opt *opt,
			       int *num_preauth_data,
			       krb5_gic_opt_pa_data **preauth_data)
{
    krb5_error_code retval;
    krb5_gic_opt_ext *opte;
    krb5_gic_opt_pa_data *p = NULL;
    int i;
    size_t allocsize;

    retval = krb5int_gic_opt_to_opte(context, opt, &opte, 0,
				     "krb5_get_init_creds_opt_get_pa");
    if (retval)
	return retval;

    if (num_preauth_data == NULL || preauth_data == NULL)
	return EINVAL;

    *num_preauth_data = 0;
    *preauth_data = NULL;

    if (opte->opt_private->num_preauth_data == 0)
	return 0;

    allocsize =
	    opte->opt_private->num_preauth_data * sizeof(krb5_gic_opt_pa_data);
    p = malloc(allocsize);
    if (p == NULL)
	return ENOMEM;

    /* Init these to make cleanup easier */
    for (i = 0; i < opte->opt_private->num_preauth_data; i++) {
	p[i].attr = NULL;
	p[i].value = NULL;
    }

    for (i = 0; i < opte->opt_private->num_preauth_data; i++) {
	p[i].attr = strdup(opte->opt_private->preauth_data[i].attr);
	p[i].value = strdup(opte->opt_private->preauth_data[i].value);
	if (p[i].attr == NULL || p[i].value == NULL)
	    goto cleanup;
    }
    *num_preauth_data = i;
    *preauth_data = p;
    return 0;
cleanup:
    for (i = 0; i < opte->opt_private->num_preauth_data; i++) {
	if (p[i].attr != NULL)
	    free(p[i].attr);
	if (p[i].value != NULL)
	    free(p[i].value);
    }
    free(p);
    return ENOMEM;
}

/*
 * This function frees the preauth_data that was returned by
 * krb5_get_init_creds_opt_get_pa().
 */
void KRB5_CALLCONV
krb5_get_init_creds_opt_free_pa(krb5_context context,
				int num_preauth_data,
				krb5_gic_opt_pa_data *preauth_data)
{
    int i;

    if (num_preauth_data <= 0 || preauth_data == NULL)
	return;

    for (i = 0; i < num_preauth_data; i++) {
	if (preauth_data[i].attr != NULL)
	    free(preauth_data[i].attr);
	if (preauth_data[i].value != NULL)
	    free(preauth_data[i].value);
    }
    free(preauth_data);
}
