/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains api's for conversion of the kdb_incr_update_t
 * struct(s) into krb5_db_entry struct(s) and vice-versa.
 */
#include <sys/types.h>
#include <com_err.h>
#include <locale.h>
#include <errno.h>
#include <iprop_hdr.h>
#include "iprop.h"
#include <k5-int.h>
#include <kdb.h>
#include <kdb_log.h>

/* BEGIN CSTYLED */
#define	ULOG_ENTRY_TYPE(upd, i)	((kdb_incr_update_t *)upd)->kdb_update.kdbe_t_val[i]

#define	ULOG_ENTRY(upd, i) ((kdb_incr_update_t *)upd)->kdb_update.kdbe_t_val[i].kdbe_val_t_u

#define	ULOG_ENTRY_KEYVAL(upd, i, j) ((kdb_incr_update_t *)upd)->kdb_update.kdbe_t_val[i].kdbe_val_t_u.av_keydata.av_keydata_val[j]

#define	ULOG_ENTRY_PRINC(upd, i, j) ((kdb_incr_update_t *)upd)->kdb_update.kdbe_t_val[i].kdbe_val_t_u.av_princ.k_components.k_components_val[j]

#define	ULOG_ENTRY_MOD_PRINC(upd, i, j)	((kdb_incr_update_t *)upd)->kdb_update.kdbe_t_val[i].kdbe_val_t_u.av_mod_princ.k_components.k_components_val[j]
/* END CSTYLED */

typedef enum {
	REG_PRINC = 0,
	MOD_PRINC = 1
} princ_type;


/*
 * This routine tracks the krb5_db_entry fields that have been modified
 * (by comparing it to the db_entry currently present in principal.db)
 * in the update.
 */
static void
find_changed_attrs(krb5_db_entry *current, krb5_db_entry *new,
		   kdbe_attr_type_t *attrs, int *nattrs)
{
	int i = 0, j = 0;

	krb5_tl_data *first, *second;

	if (current->attributes != new->attributes)
		attrs[i++] = AT_ATTRFLAGS;

	if (current->max_life != new->max_life)
		attrs[i++] = AT_MAX_LIFE;

	if (current->max_renewable_life != new->max_renewable_life)
		attrs[i++] = AT_MAX_RENEW_LIFE;

	if (current->expiration != new->expiration)
		attrs[i++] = AT_EXP;

	if (current->pw_expiration != new->pw_expiration)
		attrs[i++] = AT_PW_EXP;

	if (current->last_success != new->last_success)
		attrs[i++] = AT_LAST_SUCCESS;

	if (current->last_failed != new->last_failed)
		attrs[i++] = AT_LAST_FAILED;

	if (current->fail_auth_count != new->fail_auth_count)
		attrs[i++] = AT_FAIL_AUTH_COUNT;

	if ((current->princ->type == new->princ->type) &&
	    (current->princ->length == new->princ->length)) {
		if ((current->princ->realm.length ==
			new->princ->realm.length) &&
				strncmp(current->princ->realm.data,
					new->princ->realm.data,
					current->princ->realm.length)) {
			for (j = 0; j < current->princ->length; j++) {
				if ((current->princ->data[j].data != NULL) &&
					(strncmp(current->princ->data[j].data,
					    new->princ->data[j].data,
					    current->princ->data[j].length))) {
					attrs[i++] = AT_PRINC;
					break;
				}
			}
		} else {
			attrs[i++] = AT_PRINC;
		}
	} else {
		attrs[i++] = AT_PRINC;
	}

	if (current->n_key_data == new->n_key_data) {
		/* Assuming key ordering is the same in new & current */
		for (j = 0; j < new->n_key_data; j++) {
			if (current->key_data[j].key_data_kvno !=
			    new->key_data[j].key_data_kvno) {
				attrs[i++] = AT_KEYDATA;
				break;
			}
		}
	} else {
		attrs[i++] = AT_KEYDATA;
	}

	if (current->n_tl_data == new->n_tl_data) {
		/* Assuming we preserve the TL_DATA ordering between updates */
		for (first = current->tl_data, second = new->tl_data;
				first; first = first->tl_data_next,
					second = second->tl_data_next) {
			if ((first->tl_data_length == second->tl_data_length) &&
				(first->tl_data_type == second->tl_data_type)) {
				if ((memcmp((char *)first->tl_data_contents,
					(char *)second->tl_data_contents,
					first->tl_data_length)) != 0) {
					attrs[i++] = AT_TL_DATA;
					break;
				}
			} else {
				attrs[i++] = AT_TL_DATA;
				break;
			}
		}

	} else {
		attrs[i++] = AT_TL_DATA;
	}

	if (current->len != new->len)
		attrs[i++] = AT_LEN;
	/*
	 * Store the no. of (possibly :)) changed attributes
	 */
	*nattrs = i;
}

static int
data_to_utf8str(utf8str_t *u, krb5_data d)
{
	u->utf8str_t_len = d.length;
	if (d.data) {
		u->utf8str_t_val = malloc(d.length);
		if (u->utf8str_t_val == NULL)
			return -1;
		memcpy(u->utf8str_t_val, d.data, d.length);
	} else
		u->utf8str_t_val = NULL;
	return 0;
}

/*
 * Converts the krb5_principal struct from db2 to ulog format.
 */
static krb5_error_code
conv_princ_2ulog(krb5_principal princ, kdb_incr_update_t *upd,
		 int cnt, princ_type tp) {
	int i = 0;
	kdbe_princ_t *p;
	kdbe_data_t *components;

	if ((upd == NULL) || !princ)
		return (KRB5KRB_ERR_GENERIC);

	switch (tp) {
	case REG_PRINC:
	case MOD_PRINC:
		p = &ULOG_ENTRY(upd, cnt).av_princ; /* or av_mod_princ */
		p->k_nametype = (int32_t)princ->type;

		if (data_to_utf8str(&p->k_realm, princ->realm) < 0) {
			return ENOMEM;
		}

		p->k_components.k_components_len = princ->length;

		p->k_components.k_components_val = components
		    = malloc(princ->length * sizeof (kdbe_data_t));
		if (p->k_components.k_components_val == NULL) {
			free(p->k_realm.utf8str_t_val);
			p->k_realm.utf8str_t_val = NULL;
			return (ENOMEM);
		}

		memset(components, 0, princ->length * sizeof(kdbe_data_t));
		for (i = 0; i < princ->length; i++)
			components[i].k_data.utf8str_t_val = NULL;
		for (i = 0; i < princ->length; i++) {
			components[i].k_magic = princ->data[i].magic;
			if (data_to_utf8str(&components[i].k_data,
			    princ->data[i]) < 0) {
				int j;
				for (j = 0; j < i; j++) {
					free(components[j].k_data.utf8str_t_val);
					components[j].k_data.utf8str_t_val = NULL;
				}
			free(components);
			p->k_components.k_components_val = NULL;
			free(p->k_realm.utf8str_t_val);
			p->k_realm.utf8str_t_val = NULL;
			return ENOMEM;
			}
		}
		break;

	default:
		break;
	}
	return (0);
}

/*
 * Copies a UTF-8 string from ulog to a krb5_data object, which may
 * already have allocated storage associated with it.
 *
 * Maybe a return value should indicate success/failure?
 */
static void
set_from_utf8str(krb5_data *d, utf8str_t u)
{
	if (u.utf8str_t_len > INT_MAX-1 || u.utf8str_t_len >= SIZE_MAX-1) {
		d->data = NULL;
		return;
	}
	d->length = u.utf8str_t_len;
	d->data = malloc(d->length + 1);
	if (d->data == NULL)
		return;
	if (d->length)   /* Pointer may be null if length = 0.  */
		strncpy(d->data, u.utf8str_t_val, d->length);
	d->data[d->length] = 0;
}

/*
 * Converts the krb5_principal struct from ulog to db2 format.
 */
static krb5_principal
conv_princ_2db(krb5_context context, kdbe_princ_t *kdbe_princ)
{
	int i;
	krb5_principal princ;
	kdbe_data_t *components;

	princ = calloc(1, sizeof (krb5_principal_data));
	if (princ == NULL) {
		return NULL;
	}
	princ->length = 0;
	princ->data = NULL;

	components = kdbe_princ->k_components.k_components_val;

	princ->type = (krb5_int32) kdbe_princ->k_nametype;
	princ->realm.data = NULL;
	set_from_utf8str(&princ->realm, kdbe_princ->k_realm);
	if (princ->realm.data == NULL)
		goto error;

	princ->data = calloc(kdbe_princ->k_components.k_components_len,
			     sizeof (krb5_data));
	if (princ->data == NULL)
		goto error;
	for (i = 0; i < kdbe_princ->k_components.k_components_len; i++)
		princ->data[i].data = NULL;
	princ->length = (krb5_int32)kdbe_princ->k_components.k_components_len;

	for (i = 0; i < princ->length; i++) {
		princ->data[i].magic = components[i].k_magic;
		set_from_utf8str(&princ->data[i], components[i].k_data);
		if (princ->data[i].data == NULL)
			goto error;
	}

	return princ;
error:
	krb5_free_principal(context, princ);
	return NULL;
}

/*
 * This routine converts one or more krb5 db2 records into update
 * log (ulog) entry format. Space for the update log entries should
 * be allocated prior to invocation of this routine.
 */
krb5_error_code
ulog_conv_2logentry(krb5_context context, krb5_db_entry *entries,
				kdb_incr_update_t *updates,
				int nentries)
{
	int i, j, k, cnt, final, nattrs, tmpint, nprincs;
	unsigned int more;
	krb5_principal tmpprinc;
	krb5_tl_data *newtl;
	krb5_db_entry curr;
	krb5_error_code ret;
	kdbe_attr_type_t *attr_types;
	kdb_incr_update_t *upd;
	krb5_db_entry *ent;
	int kadm_data_yes;

	if ((updates == NULL) || (entries == NULL))
		return (KRB5KRB_ERR_GENERIC);

	upd = updates;
	ent = entries;

	for (k = 0; k < nentries; k++) {
		nprincs = nattrs = tmpint = 0;
		final = -1;
		kadm_data_yes = 0;
		attr_types = NULL;

		if ((upd->kdb_update.kdbe_t_val = (kdbe_val_t *)
				malloc(MAXENTRY_SIZE)) == NULL) {
			return (ENOMEM);
		}

		/*
		 * Find out which attrs have been modified
		 */
		if ((attr_types = (kdbe_attr_type_t *)malloc(
			    sizeof (kdbe_attr_type_t) * MAXATTRS_SIZE))
					== NULL) {
			return (ENOMEM);
		}

		if ((ret = krb5_db_get_principal_nolock(context, ent->princ, &curr,
						 &nprincs, &more))) {
			free(attr_types);
			return (ret);
		}

		if (nprincs == 0) {
			/*
			 * This is a new entry to the database, hence will
			 * include all the attribute-value pairs
			 *
			 * We leave out the TL_DATA types which we model as
			 * attrs in kdbe_attr_type_t, since listing AT_TL_DATA
			 * encompasses these other types-turned-attributes
			 *
			 * So, we do *NOT* consider AT_MOD_PRINC, AT_MOD_TIME,
			 * AT_MOD_WHERE, AT_PW_LAST_CHANGE, AT_PW_POLICY,
			 * AT_PW_POLICY_SWITCH, AT_PW_HIST_KVNO and AT_PW_HIST,
			 * totalling 8 attrs.
			 */
			while (nattrs < MAXATTRS_SIZE - 8) {
				attr_types[nattrs] = nattrs;
				nattrs++;
			}
		} else {
			find_changed_attrs(&curr, ent, attr_types, &nattrs);

			krb5_db_free_principal(context, &curr, nprincs);
		}

		for (i = 0; i < nattrs; i++) {
			switch (attr_types[i]) {
			case AT_ATTRFLAGS:
				if (ent->attributes >= 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_ATTRFLAGS;
					ULOG_ENTRY(upd, final).av_attrflags =
						(uint32_t)ent->attributes;
				}
				break;

			case AT_MAX_LIFE:
				if (ent->max_life >= 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_MAX_LIFE;
					ULOG_ENTRY(upd, final).av_max_life =
						(uint32_t)ent->max_life;
				}
				break;

			case AT_MAX_RENEW_LIFE:
				if (ent->max_renewable_life >= 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_MAX_RENEW_LIFE;
					ULOG_ENTRY(upd,
					    final).av_max_renew_life =
					    (uint32_t)ent->max_renewable_life;
				}
				break;

			case AT_EXP:
				if (ent->expiration >= 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_EXP;
					ULOG_ENTRY(upd, final).av_exp =
						(uint32_t)ent->expiration;
				}
				break;

			case AT_PW_EXP:
				if (ent->pw_expiration >= 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_PW_EXP;
					ULOG_ENTRY(upd, final).av_pw_exp =
						(uint32_t)ent->pw_expiration;
				}
				break;

			case AT_LAST_SUCCESS:
				if (ent->last_success >= 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_LAST_SUCCESS;
					ULOG_ENTRY(upd,
						final).av_last_success =
						    (uint32_t)ent->last_success;
				}
				break;

			case AT_LAST_FAILED:
				if (ent->last_failed >= 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_LAST_FAILED;
					ULOG_ENTRY(upd,
						final).av_last_failed =
						(uint32_t)ent->last_failed;
				}
				break;

			case AT_FAIL_AUTH_COUNT:
				if (ent->fail_auth_count >= (krb5_kvno)0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_FAIL_AUTH_COUNT;
					ULOG_ENTRY(upd,
						final).av_fail_auth_count =
						(uint32_t)ent->fail_auth_count;
				}
				break;

			case AT_PRINC:
				if (ent->princ->length > 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_PRINC;
					if ((ret = conv_princ_2ulog(ent->princ,
						upd, final, REG_PRINC))) {
						free(attr_types);
						return (ret);
					}
				}
				break;

			case AT_KEYDATA:
/* BEGIN CSTYLED */
				if (ent->n_key_data >= 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_KEYDATA;
					ULOG_ENTRY(upd, final).av_keydata.av_keydata_len = ent->n_key_data;

					ULOG_ENTRY(upd, final).av_keydata.av_keydata_val = malloc(ent->n_key_data * sizeof (kdbe_key_t));
					if (ULOG_ENTRY(upd, final).av_keydata.av_keydata_val == NULL) {
						free(attr_types);
						return (ENOMEM);
					}

					for (j = 0; j < ent->n_key_data; j++) {
						ULOG_ENTRY_KEYVAL(upd, final, j).k_ver = ent->key_data[j].key_data_ver;
						ULOG_ENTRY_KEYVAL(upd, final, j).k_kvno = ent->key_data[j].key_data_kvno;
						ULOG_ENTRY_KEYVAL(upd, final, j).k_enctype.k_enctype_len = ent->key_data[j].key_data_ver;
						ULOG_ENTRY_KEYVAL(upd, final, j).k_contents.k_contents_len = ent->key_data[j].key_data_ver;

						ULOG_ENTRY_KEYVAL(upd, final, j).k_enctype.k_enctype_val = malloc(ent->key_data[j].key_data_ver * sizeof(int32_t));
						if (ULOG_ENTRY_KEYVAL(upd, final, j).k_enctype.k_enctype_val == NULL) {
							free(attr_types);
							return (ENOMEM);
						}

						ULOG_ENTRY_KEYVAL(upd, final, j).k_contents.k_contents_val = malloc(ent->key_data[j].key_data_ver * sizeof(utf8str_t));
						if (ULOG_ENTRY_KEYVAL(upd, final, j).k_contents.k_contents_val == NULL) {
							free(attr_types);
							return (ENOMEM);
						}

						for (cnt = 0; cnt < ent->key_data[j].key_data_ver; cnt++) {
							ULOG_ENTRY_KEYVAL(upd, final, j).k_enctype.k_enctype_val[cnt] = ent->key_data[j].key_data_type[cnt];
							ULOG_ENTRY_KEYVAL(upd, final, j).k_contents.k_contents_val[cnt].utf8str_t_len = ent->key_data[j].key_data_length[cnt];
							ULOG_ENTRY_KEYVAL(upd, final, j).k_contents.k_contents_val[cnt].utf8str_t_val = malloc(ent->key_data[j].key_data_length[cnt] * sizeof (char));
							if (ULOG_ENTRY_KEYVAL(upd, final, j).k_contents.k_contents_val[cnt].utf8str_t_val == NULL) {
								free(attr_types);
								return (ENOMEM);
							}
							(void) memcpy(ULOG_ENTRY_KEYVAL(upd, final, j).k_contents.k_contents_val[cnt].utf8str_t_val, ent->key_data[j].key_data_contents[cnt], ent->key_data[j].key_data_length[cnt]);
						}
					}
				}
				break;

			case AT_TL_DATA:
				ret = krb5_dbe_lookup_last_pwd_change(context,
								ent, &tmpint);
				if (ret == 0) {
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_PW_LAST_CHANGE;
					ULOG_ENTRY(upd, final).av_pw_last_change = tmpint;
				}
				tmpint = 0;

				if(!(ret = krb5_dbe_lookup_mod_princ_data(
					context, ent, &tmpint, &tmpprinc))) {

					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_MOD_PRINC;

					ret = conv_princ_2ulog(tmpprinc,
					    upd, final, MOD_PRINC);
					krb5_free_principal(context, tmpprinc);
					if (ret) {
						free(attr_types);
						return (ret);
					}
					ULOG_ENTRY_TYPE(upd, ++final).av_type =
						AT_MOD_TIME;
					ULOG_ENTRY(upd, final).av_mod_time =
						tmpint;
				}

				newtl = ent->tl_data;
				while (newtl) {
					switch (newtl->tl_data_type) {
					case KRB5_TL_LAST_PWD_CHANGE:
					case KRB5_TL_MOD_PRINC:
						break;

					case KRB5_TL_KADM_DATA:
					default:
						if (kadm_data_yes == 0) {
							ULOG_ENTRY_TYPE(upd, ++final).av_type = AT_TL_DATA;
							ULOG_ENTRY(upd, final).av_tldata.av_tldata_len = 0;
							ULOG_ENTRY(upd, final).av_tldata.av_tldata_val = malloc(ent->n_tl_data * sizeof(kdbe_tl_t));

							if (ULOG_ENTRY(upd, final).av_tldata.av_tldata_val == NULL) {
								free(attr_types);
								return (ENOMEM);
							}
							kadm_data_yes = 1;
						}

						tmpint = ULOG_ENTRY(upd, final).av_tldata.av_tldata_len;
						ULOG_ENTRY(upd, final).av_tldata.av_tldata_len++;
						ULOG_ENTRY(upd, final).av_tldata.av_tldata_val[tmpint].tl_type = newtl->tl_data_type;
						ULOG_ENTRY(upd, final).av_tldata.av_tldata_val[tmpint].tl_data.tl_data_len = newtl->tl_data_length;
						ULOG_ENTRY(upd, final).av_tldata.av_tldata_val[tmpint].tl_data.tl_data_val = malloc(newtl->tl_data_length * sizeof (char));
						if (ULOG_ENTRY(upd, final).av_tldata.av_tldata_val[tmpint].tl_data.tl_data_val == NULL) {
							free(attr_types);
							return (ENOMEM);
						}
						(void) memcpy(ULOG_ENTRY(upd, final).av_tldata.av_tldata_val[tmpint].tl_data.tl_data_val, newtl->tl_data_contents, newtl->tl_data_length);
						break;
					}
					newtl = newtl->tl_data_next;
				}
				break;
/* END CSTYLED */

			case AT_LEN:
				ULOG_ENTRY_TYPE(upd, ++final).av_type =
					AT_LEN;
				ULOG_ENTRY(upd, final).av_len =
					(int16_t)ent->len;
				break;

			default:
				break;
			}

		}

		if (attr_types)
			free(attr_types);

		/*
		 * Update len field in kdb_update
		 */
		upd->kdb_update.kdbe_t_len = ++final;

		/*
		 * Bump up to next struct
		 */
		upd++;
		ent++;
	}
	return (0);
}

/*
 * This routine converts one or more update log (ulog) entries into
 * kerberos db2 records. Required memory should be allocated
 * for the db2 records (pointed to by krb5_db_entry *ent), prior
 * to calling this routine.
 */
krb5_error_code
ulog_conv_2dbentry(krb5_context context, krb5_db_entry *entries,
				kdb_incr_update_t *updates,
				int nentries)
{
	int k;
	krb5_db_entry *ent;
	kdb_incr_update_t *upd;

	if ((updates == NULL) || (entries == NULL))
		return (KRB5KRB_ERR_GENERIC);

	ent = entries;
	upd = updates;

	for (k = 0; k < nentries; k++) {
		krb5_principal mod_princ = NULL;
		int i, j, cnt = 0, mod_time = 0, nattrs, nprincs = 0;
		krb5_principal dbprinc;
		char *dbprincstr = NULL;

		krb5_tl_data *newtl = NULL;
		krb5_error_code ret;
		unsigned int more;
		unsigned int prev_n_keys = 0;

		/*
		 * If the ulog entry represents a DELETE update,
		 * just skip to the next entry.
		 */
		if (upd->kdb_deleted == TRUE)
			goto next;

		/*
		 * Store the no. of changed attributes in nattrs
		 */
		nattrs = upd->kdb_update.kdbe_t_len;

		dbprincstr = malloc((upd->kdb_princ_name.utf8str_t_len + 1)
					* sizeof (char));
		if (dbprincstr == NULL)
			return (ENOMEM);
		strncpy(dbprincstr, (char *)upd->kdb_princ_name.utf8str_t_val,
		    upd->kdb_princ_name.utf8str_t_len);
		dbprincstr[upd->kdb_princ_name.utf8str_t_len] = 0;
		ret = krb5_parse_name(context, dbprincstr, &dbprinc);
		free(dbprincstr);
		if (ret)
			return (ret);

		ret = krb5_db_get_principal(context, dbprinc, ent, &nprincs,
		    &more);
		krb5_free_principal(context, dbprinc);
		if (ret)
			return (ret);

		/*
		 * Set ent->n_tl_data = 0 initially, if this is an ADD update
		 */
		if (nprincs == 0)
			ent->n_tl_data = 0;

		for (i = 0; i < nattrs; i++) {
			krb5_principal tmpprinc = NULL;

#define u (ULOG_ENTRY(upd, i))
			switch (ULOG_ENTRY_TYPE(upd, i).av_type) {
			case AT_ATTRFLAGS:
				ent->attributes = (krb5_flags) u.av_attrflags;
				break;

			case AT_MAX_LIFE:
				ent->max_life = (krb5_deltat) u.av_max_life;
				break;

			case AT_MAX_RENEW_LIFE:
				ent->max_renewable_life = (krb5_deltat) u.av_max_renew_life;
				break;

			case AT_EXP:
				ent->expiration = (krb5_timestamp) u.av_exp;
				break;

			case AT_PW_EXP:
				ent->pw_expiration = (krb5_timestamp) u.av_pw_exp;
				break;

			case AT_LAST_SUCCESS:
				ent->last_success = (krb5_timestamp) u.av_last_success;
				break;

			case AT_LAST_FAILED:
				ent->last_failed = (krb5_timestamp) u.av_last_failed;
				break;

			case AT_FAIL_AUTH_COUNT:
				ent->fail_auth_count = (krb5_kvno) u.av_fail_auth_count;
				break;

			case AT_PRINC:
				tmpprinc = conv_princ_2db(context, &u.av_princ);
				if (tmpprinc == NULL)
					return ENOMEM;
				if (nprincs)
					krb5_free_principal(context, ent->princ);
				ent->princ = tmpprinc;
				break;

			case AT_KEYDATA:

				if (nprincs != 0)
					prev_n_keys = ent->n_key_data;
				else
					prev_n_keys = 0;
				ent->n_key_data = (krb5_int16)u.av_keydata.av_keydata_len;
				if (nprincs == 0)
					ent->key_data = NULL;

				ent->key_data = (krb5_key_data *)realloc(ent->key_data,
						(ent->n_key_data *
						sizeof (krb5_key_data)));
				 /* XXX Memory leak: Old key data in
				    records eliminated by resizing to
				    smaller size. */
				if (ent->key_data == NULL)
					/* XXX Memory leak: old storage.  */
					return (ENOMEM);

/* BEGIN CSTYLED */
				for (j = prev_n_keys; j < ent->n_key_data; j++) {
					for (cnt = 0; cnt < 2; cnt++) {
						ent->key_data[j].key_data_contents[cnt] = NULL;
					}
				}
				for (j = 0; j < ent->n_key_data; j++) {
					krb5_key_data *kp = &ent->key_data[j];
					kdbe_key_t *kv = &ULOG_ENTRY_KEYVAL(upd, i, j);
					kp->key_data_ver = (krb5_int16)kv->k_ver;
					kp->key_data_kvno = (krb5_int16)kv->k_kvno;
					if (kp->key_data_ver > 2) {
						return EINVAL; /* XXX ? */
					}

					for (cnt = 0; cnt < kp->key_data_ver; cnt++) {
						void *newptr;
						kp->key_data_type[cnt] = (krb5_int16)kv->k_enctype.k_enctype_val[cnt];
						kp->key_data_length[cnt] = (krb5_int16)kv->k_contents.k_contents_val[cnt].utf8str_t_len;
						newptr = realloc(kp->key_data_contents[cnt],
								 kp->key_data_length[cnt]);
						if (newptr == NULL)
							return ENOMEM;
						kp->key_data_contents[cnt] = newptr;

						(void) memset(kp->key_data_contents[cnt], 0,
						    	      kp->key_data_length[cnt]);
						(void) memcpy(kp->key_data_contents[cnt],
						    	      kv->k_contents.k_contents_val[cnt].utf8str_t_val,
						    	      kp->key_data_length[cnt]);
					}
				}
				break;

			case AT_TL_DATA:
				cnt = u.av_tldata.av_tldata_len;
				newtl = malloc(cnt * sizeof (krb5_tl_data));
				(void) memset(newtl, 0, (cnt * sizeof (krb5_tl_data)));
				if (newtl == NULL)
					return (ENOMEM);

				for (j = 0; j < cnt; j++) {
					newtl[j].tl_data_type = (krb5_int16)u.av_tldata.av_tldata_val[j].tl_type;
					newtl[j].tl_data_length = (krb5_int16)u.av_tldata.av_tldata_val[j].tl_data.tl_data_len;
					newtl[j].tl_data_contents = NULL;
					newtl[j].tl_data_contents = malloc(newtl[j].tl_data_length * sizeof (krb5_octet));
					if (newtl[j].tl_data_contents == NULL)
						/* XXX Memory leak: newtl
						   and previously
						   allocated elements.  */
						return (ENOMEM);

					(void) memset(newtl[j].tl_data_contents, 0, (newtl[j].tl_data_length * sizeof (krb5_octet)));
					(void) memcpy(newtl[j].tl_data_contents, u.av_tldata.av_tldata_val[j].tl_data.tl_data_val, newtl[j].tl_data_length);
					newtl[j].tl_data_next = NULL;
					if (j > 0)
						newtl[j - 1].tl_data_next = &newtl[j];
				}

				if ((ret = krb5_dbe_update_tl_data(context, ent, newtl)))
					return (ret);
				for (j = 0; j < cnt; j++)
					if (newtl[j].tl_data_contents) {
						free(newtl[j].tl_data_contents);
						newtl[j].tl_data_contents = NULL;
					}
				if (newtl) {
					free(newtl);
					newtl = NULL;
				}
				break;
/* END CSTYLED */

			case AT_PW_LAST_CHANGE:
				if ((ret = krb5_dbe_update_last_pwd_change(context, ent,
				    					   u.av_pw_last_change)))
						return (ret);
				break;

			case AT_MOD_PRINC:
				tmpprinc = conv_princ_2db(context, &u.av_mod_princ);
				if (tmpprinc == NULL)
					return ENOMEM;
				mod_princ = tmpprinc;
				break;

			case AT_MOD_TIME:
				mod_time = u.av_mod_time;
				break;

			case AT_LEN:
				ent->len = (krb5_int16) u.av_len;
				break;

			default:
				break;
			}
#undef u
		}

		/*
		 * process mod_princ_data request
		 */
		if (mod_time && mod_princ) {
			ret = krb5_dbe_update_mod_princ_data(context, ent,
			    mod_time, mod_princ);
			krb5_free_principal(context, mod_princ);
			mod_princ = NULL;
			if (ret)
				return (ret);
		}

next:
		/*
		 * Bump up to next struct
		 */
		upd++;
		ent++;
	}
	return (0);
}



/*
 * This routine frees up memory associated with the bunched ulog entries.
 */
void
ulog_free_entries(kdb_incr_update_t *updates, int no_of_updates)
{

	kdb_incr_update_t *upd;
	int i, j, k, cnt;

	if (updates == NULL)
		return;

	upd = updates;

	/*
	 * Loop thru each ulog entry
	 */
	for (cnt = 0; cnt < no_of_updates; cnt++) {

		/*
		 * ulog entry - kdb_princ_name
		 */
		free(upd->kdb_princ_name.utf8str_t_val);

/* BEGIN CSTYLED */

		/*
		 * ulog entry - kdb_kdcs_seen_by
		 */
		if (upd->kdb_kdcs_seen_by.kdb_kdcs_seen_by_val) {
			for (i = 0; i < upd->kdb_kdcs_seen_by.kdb_kdcs_seen_by_len; i++)
				free(upd->kdb_kdcs_seen_by.kdb_kdcs_seen_by_val[i].utf8str_t_val);
			free(upd->kdb_kdcs_seen_by.kdb_kdcs_seen_by_val);
		}

		/*
		 * ulog entry - kdb_futures
		 */
		free(upd->kdb_futures.kdb_futures_val);

		/*
		 * ulog entry - kdb_update
		 */
		if (upd->kdb_update.kdbe_t_val) {
			/*
			 * Loop thru all the attributes and free up stuff
			 */
			for (i = 0; i < upd->kdb_update.kdbe_t_len; i++) {

				/*
				 * Free av_key_data
				 */
				if ((ULOG_ENTRY_TYPE(upd, i).av_type == AT_KEYDATA) && ULOG_ENTRY(upd, i).av_keydata.av_keydata_val) {

					for (j = 0; j < ULOG_ENTRY(upd, i).av_keydata.av_keydata_len; j++) {
						free(ULOG_ENTRY_KEYVAL(upd, i, j).k_enctype.k_enctype_val);
						if (ULOG_ENTRY_KEYVAL(upd, i, j).k_contents.k_contents_val) {
							for (k = 0; k < ULOG_ENTRY_KEYVAL(upd, i, j).k_ver; k++) {
								free(ULOG_ENTRY_KEYVAL(upd, i, j).k_contents.k_contents_val[k].utf8str_t_val);
							}
							free(ULOG_ENTRY_KEYVAL(upd, i, j).k_contents.k_contents_val);
						}
					}
					free(ULOG_ENTRY(upd, i).av_keydata.av_keydata_val);
				}


				/*
				 * Free av_tl_data
				 */
				if ((ULOG_ENTRY_TYPE(upd, i).av_type == AT_TL_DATA) && ULOG_ENTRY(upd, i).av_tldata.av_tldata_val) {
					for (j = 0; j < ULOG_ENTRY(upd, i).av_tldata.av_tldata_len; j++) {
						free(ULOG_ENTRY(upd, i).av_tldata.av_tldata_val[j].tl_data.tl_data_val);
					}
					free(ULOG_ENTRY(upd, i).av_tldata.av_tldata_val);
				}

				/*
				 * Free av_princ
				 */
				if (ULOG_ENTRY_TYPE(upd, i).av_type == AT_PRINC) {
					free(ULOG_ENTRY(upd, i).av_princ.k_realm.utf8str_t_val);
					if (ULOG_ENTRY(upd, i).av_princ.k_components.k_components_val) {
						for (j = 0; j < ULOG_ENTRY(upd, i).av_princ.k_components.k_components_len; j++) {
							free(ULOG_ENTRY_PRINC(upd, i, j).k_data.utf8str_t_val);
						}
						free(ULOG_ENTRY(upd, i).av_princ.k_components.k_components_val);
					}
				}

				/*
				 * Free av_mod_princ
				 */
				if (ULOG_ENTRY_TYPE(upd, i).av_type == AT_MOD_PRINC) {
					free(ULOG_ENTRY(upd, i).av_mod_princ.k_realm.utf8str_t_val);
					if (ULOG_ENTRY(upd, i).av_mod_princ.k_components.k_components_val) {
						for (j = 0; j < ULOG_ENTRY(upd, i).av_mod_princ.k_components.k_components_len; j++) {
							free(ULOG_ENTRY_MOD_PRINC(upd, i, j).k_data.utf8str_t_val);
						}
						free(ULOG_ENTRY(upd, i).av_mod_princ.k_components.k_components_val);
					}
				}

				/*
				 * Free av_mod_where
				 */
				if ((ULOG_ENTRY_TYPE(upd, i).av_type == AT_MOD_WHERE) && ULOG_ENTRY(upd, i).av_mod_where.utf8str_t_val)
					free(ULOG_ENTRY(upd, i).av_mod_where.utf8str_t_val);

				/*
				 * Free av_pw_policy
				 */
				if ((ULOG_ENTRY_TYPE(upd, i).av_type == AT_PW_POLICY) && ULOG_ENTRY(upd, i).av_pw_policy.utf8str_t_val)
					free(ULOG_ENTRY(upd, i).av_pw_policy.utf8str_t_val);

				/*
				 * XXX: Free av_pw_hist
				 *
				 * For now, we just free the pointer
				 * to av_pw_hist_val, since we aren't
				 * populating this union member in
				 * the conv api function(s) anyways.
				 */
				if ((ULOG_ENTRY_TYPE(upd, i).av_type == AT_PW_HIST) && ULOG_ENTRY(upd, i).av_pw_hist.av_pw_hist_val)
					free(ULOG_ENTRY(upd, i).av_pw_hist.av_pw_hist_val);

			 }

			/*
			 * Free up the pointer to kdbe_t_val
			 */
			free(upd->kdb_update.kdbe_t_val);
		}

/* END CSTYLED */

		/*
		 * Bump up to next struct
		 */
		upd++;
	}


	/*
	 * Finally, free up the pointer to the bunched ulog entries
	 */
	free(updates);
}
