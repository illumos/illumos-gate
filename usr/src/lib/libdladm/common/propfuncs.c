/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <fcntl.h>
#include <unistd.h>
#include <libdladm_impl.h>
#include <libdlflow_impl.h>

/*
 * XXX duplicate defines
 */
#define	DLADM_PROP_VAL_MAX	32
#define	DLADM_MAX_PROPS		32

static void
free_props(prop_db_info_t *lip)
{
	prop_db_info_t	*lip_next;
	prop_val_t	*lvp, *lvp_next;

	for (; lip != NULL; lip = lip_next) {
		lip_next = lip->li_nextprop;
		for (lvp = lip->li_val; lvp != NULL; lvp = lvp_next) {
			lvp_next = lvp->lv_nextval;
			free(lvp);
		}
		free(lip);
	}
}

/*
 * Generate an entry in the property database.
 * Each entry has this format:
 * <name>	<prop0>=<val0>,...,<valn>;...;<propn>=<val0>,...,<valn>;
 */
static void
generate_prop_line(const char *name, char *buf,
    prop_db_info_t *listp, dladm_status_t *statusp)
{
	char		tmpbuf[MAXLINELEN];
	char		*ptr, *lim = tmpbuf + MAXLINELEN;
	prop_db_info_t	*lip = listp;
	prop_val_t	*lvp = NULL;

	/*
	 * Delete line if there are no properties left.
	 */
	if (lip == NULL ||
	    (lip->li_val == NULL && lip->li_nextprop == NULL)) {
		buf[0] = '\0';
		return;
	}
	ptr = tmpbuf;
	ptr += snprintf(ptr, BUFLEN(lim, ptr), "%s\t", name);
	for (; lip != NULL; lip = lip->li_nextprop) {
		/*
		 * Skip properties without values.
		 */
		if (lip->li_val == NULL)
			continue;

		ptr += snprintf(ptr, BUFLEN(lim, ptr), "%s=", lip->li_name);
		for (lvp = lip->li_val; lvp != NULL; lvp = lvp->lv_nextval) {
			ptr += snprintf(ptr, BUFLEN(lim, ptr), "%s%c",
			    lvp->lv_name,
			    ((lvp->lv_nextval == NULL) ? ';' : ','));
		}
	}
	if (ptr > lim) {
		*statusp = DLADM_STATUS_TOOSMALL;
		return;
	}
	(void) snprintf(buf, MAXLINELEN, "%s\n", tmpbuf);
}

/*
 * This function is used to update or create an entry in the persistent db.
 * process_prop_db() will first scan the db for an entry matching the
 * specified name. If a match is found, this function is invoked with the
 * entry's contents (buf) and its linked-list representation (listp). lsp
 * holds the name and values of the property to be added or updated; this
 * information will be merged with listp. Subsequently, an updated entry
 * will be written to buf, which will in turn be written to disk by
 * process_prop_db(). If no entry matches the specified name, listp
 * will be NULL; a new entry will be generated in this case and it will
 * contain only the property information in lsp.
 */
boolean_t
process_prop_set(dladm_handle_t handle __unused, prop_db_state_t *lsp,
    char *buf, prop_db_info_t *listp, dladm_status_t *statusp)
{
	dladm_status_t	status;
	prop_db_info_t	*lastp = NULL, *lip = listp, *nlip = NULL;
	prop_val_t	**lvpp;
	uint_t		i;

	if (lsp->ls_propname == NULL) {
		buf[0] = '\0';
		return (B_FALSE);
	}

	/*
	 * Find the prop we want to change.
	 */
	for (; lip != NULL; lip = lip->li_nextprop) {
		if (strcmp(lip->li_name, lsp->ls_propname) == 0)
			break;

		lastp = lip;
	}

	if (lip == NULL) {
		/*
		 * If the prop is not found, append it to the list.
		 */
		if ((nlip = malloc(sizeof (prop_db_info_t))) == NULL) {
			status = DLADM_STATUS_NOMEM;
			goto fail;
		}
		/*
		 * nlip will need to be freed later if there is no list to
		 * append to.
		 */
		if (lastp != NULL)
			lastp->li_nextprop = nlip;
		nlip->li_name = lsp->ls_propname;
		nlip->li_nextprop = NULL;
		nlip->li_val = NULL;
		lvpp = &nlip->li_val;
	} else {
		prop_val_t	*lvp, *lvp_next;

		/*
		 * If the prop is found, delete the existing values from it.
		 */
		for (lvp = lip->li_val; lvp != NULL; lvp = lvp_next) {
			lvp_next = lvp->lv_nextval;
			free(lvp);
		}
		lip->li_val = NULL;
		lvpp = &lip->li_val;
	}

	/*
	 * Fill our prop with the specified values.
	 */
	for (i = 0; i < *lsp->ls_valcntp; i++) {
		if ((*lvpp = malloc(sizeof (prop_val_t))) == NULL) {
			status = DLADM_STATUS_NOMEM;
			goto fail;
		}
		(*lvpp)->lv_name = lsp->ls_propval[i];
		(*lvpp)->lv_nextval = NULL;
		lvpp = &(*lvpp)->lv_nextval;
	}

	if (listp != NULL) {
		generate_prop_line(lsp->ls_name, buf, listp, statusp);
	} else {
		generate_prop_line(lsp->ls_name, buf, nlip, statusp);
		free_props(nlip);
	}
	return (B_FALSE);

fail:
	*statusp = status;
	if (listp == NULL)
		free_props(nlip);

	return (B_FALSE);
}

/*
 * This function is used for retrieving the values for a specific property.
 * It gets called if an entry matching the specified name exists in the db.
 * The entry is converted into a linked-list listp. This list is then scanned
 * for the specified property name; if a matching property exists, its
 * associated values are copied to the array lsp->ls_propval.
 */
boolean_t
process_prop_get(dladm_handle_t handle __unused, prop_db_state_t *lsp,
    char *buf __unused, prop_db_info_t *listp, dladm_status_t *statusp)
{
	prop_db_info_t	*lip = listp;
	prop_val_t	*lvp;
	uint_t		valcnt = 0;

	/*
	 * Find the prop we want to get.
	 */
	for (; lip != NULL; lip = lip->li_nextprop) {
		if (strcmp(lip->li_name, lsp->ls_propname) == 0)
			break;
	}
	if (lip == NULL) {
		*statusp = DLADM_STATUS_NOTFOUND;
		return (B_FALSE);
	}

	for (lvp = lip->li_val; lvp != NULL; lvp = lvp->lv_nextval) {
		(void) strncpy(lsp->ls_propval[valcnt], lvp->lv_name,
		    DLADM_PROP_VAL_MAX);

		if (++valcnt >= *lsp->ls_valcntp && lvp->lv_nextval != NULL) {
			*statusp = DLADM_STATUS_TOOSMALL;
			return (B_FALSE);
		}
	}
	/*
	 * This function is meant to be called at most once for each call
	 * to process_prop_db(). For this reason, it's ok to overwrite
	 * the caller's valcnt array size with the actual number of values
	 * returned.
	 */
	*lsp->ls_valcntp = valcnt;
	return (B_FALSE);
}

/*
 * This is used for initializing properties.
 * Unlike the other routines, this gets called for every entry in the
 * database. lsp->ls_name is not user-specified but instead is set to
 * the current name being processed.
 */
boolean_t
process_prop_init(dladm_handle_t handle, prop_db_state_t *lsp,
    char *buf __unused, prop_db_info_t *listp, dladm_status_t *statusp)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	prop_db_info_t	*lip = listp;
	prop_val_t	*lvp;
	uint_t		valcnt, i;
	char		**propval;

	for (; lip != NULL; lip = lip->li_nextprop) {
		/*
		 * Construct the propval array and fill it with
		 * values from listp.
		 */
		for (lvp = lip->li_val, valcnt = 0;
		    lvp != NULL; lvp = lvp->lv_nextval, valcnt++) {
		}

		propval = malloc(sizeof (char *) * valcnt);
		if (propval == NULL) {
			*statusp = DLADM_STATUS_NOMEM;
			break;
		}
		lvp = lip->li_val;
		for (i = 0; i < valcnt; i++, lvp = lvp->lv_nextval)
			propval[i] = (char *)lvp->lv_name;

		status = (*lsp->ls_initop)(handle, lsp->ls_name, lip->li_name,
		    propval, valcnt, DLADM_OPT_ACTIVE, NULL);

		/*
		 * We continue with initializing other properties even
		 * after encountering an error. This error will be
		 * propagated to the caller via 'statusp'.
		 */
		if (status != DLADM_STATUS_OK)
			*statusp = status;

		free(propval);
	}
	return (B_TRUE);
}

static int
parse_props(char *buf, prop_db_info_t **lipp)
{
	int			i, len;
	char			*curr;
	prop_db_info_t		*lip = NULL;
	prop_db_info_t		**tailp = lipp;
	prop_val_t		*lvp = NULL;
	prop_val_t		**vtailp = NULL;

	curr = buf;
	len = strlen(buf);
	for (i = 0; i < len; i++) {
		char		c = buf[i];
		boolean_t	match = (c == '=' || c == ',' || c == ';');

		/*
		 * Move to the next character if there is no match and
		 * if we have not reached the last character.
		 */
		if (!match && i != len - 1)
			continue;

		if (match) {
			/*
			 * Nul-terminate the string pointed to by 'curr'.
			 */
			buf[i] = '\0';
			if (*curr == '\0')
				goto fail;
		}

		if (lip != NULL) {
			/*
			 * We get here after we have processed the "<prop>="
			 * pattern. The pattern we are now interested in is
			 * "<val0>,<val1>,...,<valn>;". For each value we
			 * find, a prop_val_t will be allocated and
			 * added to the current 'lip'.
			 */
			if (c == '=')
				goto fail;

			lvp = malloc(sizeof (*lvp));
			if (lvp == NULL)
				goto fail;

			lvp->lv_name = curr;
			lvp->lv_nextval = NULL;
			*vtailp = lvp;
			vtailp = &lvp->lv_nextval;

			if (c == ';') {
				tailp = &lip->li_nextprop;
				vtailp = NULL;
				lip = NULL;
			}
		} else {
			/*
			 * lip == NULL indicates that 'curr' must be refering
			 * to a property name. We allocate a new prop_db_info_t
			 * append it to the list given by the caller.
			 */
			if (c != '=')
				goto fail;

			lip = malloc(sizeof (*lip));
			if (lip == NULL)
				goto fail;

			lip->li_name = curr;
			lip->li_val = NULL;
			lip->li_nextprop = NULL;
			*tailp = lip;
			vtailp = &lip->li_val;
		}
		curr = buf + i + 1;
	}
	/*
	 * The list must be non-empty and the last character must be ';'.
	 */
	if (*lipp == NULL || lip != NULL)
		goto fail;

	return (0);

fail:
	free_props(*lipp);
	*lipp = NULL;
	return (-1);
}

static boolean_t
process_prop_line(dladm_handle_t handle, prop_db_state_t *lsp, char *buf,
    dladm_status_t *statusp)
{
	prop_db_info_t		*lip = NULL;
	int			i, len, llen;
	char			*str, *lasts;
	boolean_t		cont, noname = B_FALSE;

	/*
	 * Skip leading spaces, blank lines, and comments.
	 */
	len = strlen(buf);
	for (i = 0; i < len; i++) {
		if (!isspace(buf[i]))
			break;
	}
	if (i == len || buf[i] == '#')
		return (B_TRUE);

	str = buf + i;
	if (lsp->ls_name != NULL) {
		/*
		 * Skip names we're not interested in.
		 * Note that strncmp() and isspace() are used here
		 * instead of strtok() and strcmp() because we don't
		 * want to modify buf in case it does not contain the
		 * specified name.
		 */
		llen = strlen(lsp->ls_name);
		if (strncmp(str, lsp->ls_name, llen) != 0 ||
		    !isspace(str[llen]))
			return (B_TRUE);
	} else {
		/*
		 * If a name is not specified, find the name
		 * and assign it to lsp->ls_name.
		 */
		if (strtok_r(str, " \n\t", &lasts) == NULL)
			goto fail;

		llen = strlen(str);
		lsp->ls_name = str;
		noname = B_TRUE;
	}
	str += llen + 1;
	if (str >= buf + len)
		goto fail;

	/*
	 * Now find the list of properties.
	 */
	if ((str = strtok_r(str, " \n\t", &lasts)) == NULL)
		goto fail;

	if (parse_props(str, &lip) < 0)
		goto fail;

	cont = (*lsp->ls_op)(handle, lsp, buf, lip, statusp);
	free_props(lip);
	if (noname)
		lsp->ls_name = NULL;
	return (cont);

fail:
	free_props(lip);
	if (noname)
		lsp->ls_name = NULL;

	/*
	 * Delete corrupted line.
	 */
	buf[0] = '\0';
	return (B_TRUE);
}

dladm_status_t
process_prop_db(dladm_handle_t handle, void *arg, FILE *fp, FILE *nfp)
{
	prop_db_state_t	*lsp = arg;
	dladm_status_t		status = DLADM_STATUS_OK;
	char			buf[MAXLINELEN];
	boolean_t		cont = B_TRUE;

	/*
	 * This loop processes each line of the configuration file.
	 * buf can potentially be modified by process_prop_line().
	 * If this is a write operation and buf is not truncated, buf will
	 * be written to disk. process_prop_line() will no longer be
	 * called after it returns B_FALSE; at which point the remainder
	 * of the file will continue to be read and, if necessary, written
	 * to disk as well.
	 */
	while (fgets(buf, MAXLINELEN, fp) != NULL) {
		if (cont)
			cont = process_prop_line(handle, lsp, buf, &status);

		if (nfp != NULL && buf[0] != '\0' && fputs(buf, nfp) == EOF) {
			status = dladm_errno2status(errno);
			break;
		}
	}

	if (status != DLADM_STATUS_OK || !cont)
		return (status);

	if (lsp->ls_op == process_prop_set) {
		/*
		 * If the specified name is not found above, we add the
		 * name and its properties to the configuration file.
		 */
		(void) (*lsp->ls_op)(handle, lsp, buf, NULL, &status);
		if (status == DLADM_STATUS_OK && fputs(buf, nfp) == EOF)
			status = dladm_errno2status(errno);
	}

	if (lsp->ls_op == process_prop_get)
		status = DLADM_STATUS_NOTFOUND;

	return (status);
}

dladm_status_t
i_dladm_get_prop_temp(dladm_handle_t handle, const char *name, prop_type_t type,
    const char *prop_name, char **prop_val, uint_t *val_cntp,
    prop_table_t *prop_tbl)
{
	uint_t		i;
	dladm_status_t	status;
	uint_t		cnt;
	fprop_desc_t	*pdp;

	if (name == NULL || prop_name == NULL || prop_val == NULL ||
	    val_cntp == NULL || *val_cntp == 0)
		return (DLADM_STATUS_BADARG);

	for (i = 0; i < prop_tbl->pt_size; i++)
		if (strcasecmp(prop_name, prop_tbl->pt_table[i].pd_name) == 0)
			break;

	if (i == prop_tbl->pt_size)
		return (DLADM_STATUS_NOTFOUND);

	pdp = &prop_tbl->pt_table[i];
	status = DLADM_STATUS_OK;

	switch (type) {
	case DLADM_PROP_VAL_CURRENT:
		status = pdp->pd_get(handle, name, prop_val, val_cntp);
		break;
	case DLADM_PROP_VAL_DEFAULT:
		if (pdp->pd_defval.vd_name == NULL) {
			status = DLADM_STATUS_NOTSUP;
			break;
		}
		(void) strcpy(*prop_val, pdp->pd_defval.vd_name);
		*val_cntp = 1;
		break;

	case DLADM_PROP_VAL_MODIFIABLE:
		if (pdp->pd_getmod != NULL) {
			status = pdp->pd_getmod(handle, name, prop_val,
			    val_cntp);
			break;
		}
		cnt = pdp->pd_nmodval;
		if (cnt == 0) {
			status = DLADM_STATUS_NOTSUP;
		} else if (cnt > *val_cntp) {
			status = DLADM_STATUS_TOOSMALL;
		} else {
			for (i = 0; i < cnt; i++) {
				(void) strcpy(prop_val[i],
				    pdp->pd_modval[i].vd_name);
			}
			*val_cntp = cnt;
		}
		break;
	default:
		status = DLADM_STATUS_BADARG;
		break;
	}

	return (status);
}

static dladm_status_t
i_dladm_set_one_prop_temp(dladm_handle_t handle, const char *name,
    fprop_desc_t *pdp, char **prop_val, uint_t val_cnt, uint_t flags)
{
	dladm_status_t	status;
	val_desc_t	*vdp = NULL;
	uint_t		cnt;

	if (pdp->pd_temponly && (flags & DLADM_OPT_PERSIST) != 0)
		return (DLADM_STATUS_TEMPONLY);

	if (pdp->pd_set == NULL)
		return (DLADM_STATUS_PROPRDONLY);

	if (prop_val != NULL) {
		if (pdp->pd_check != NULL)
			status = pdp->pd_check(pdp, prop_val, val_cnt, &vdp);
		else
			status = DLADM_STATUS_BADARG;

		if (status != DLADM_STATUS_OK)
			return (status);

		cnt = val_cnt;
	} else {
		if (pdp->pd_defval.vd_name == NULL)
			return (DLADM_STATUS_NOTSUP);

		if ((vdp = malloc(sizeof (val_desc_t))) == NULL)
			return (DLADM_STATUS_NOMEM);

		(void) memcpy(vdp, &pdp->pd_defval, sizeof (val_desc_t));
		cnt = 1;
	}

	status = pdp->pd_set(handle, name, vdp, cnt);

	free(vdp);
	return (status);
}

dladm_status_t
i_dladm_set_prop_temp(dladm_handle_t handle, const char *name,
    const char *prop_name, char **prop_val, uint_t val_cnt, uint_t flags,
    char **errprop, prop_table_t *prop_tbl)
{
	uint_t		i;
	dladm_status_t	status = DLADM_STATUS_OK;
	boolean_t	found = B_FALSE;

	for (i = 0; i < prop_tbl->pt_size; i++) {
		fprop_desc_t	*pdp = &prop_tbl->pt_table[i];
		dladm_status_t	s;

		if (prop_name != NULL &&
		    (strcasecmp(prop_name, pdp->pd_name) != 0))
			continue;

		found = B_TRUE;
		s = i_dladm_set_one_prop_temp(handle, name, pdp, prop_val,
		    val_cnt, flags);

		if (prop_name != NULL) {
			status = s;
			break;
		} else {
			if (s != DLADM_STATUS_OK &&
			    s != DLADM_STATUS_NOTSUP) {
				if (errprop != NULL)
					*errprop = pdp->pd_name;
				status = s;
				break;
			}
		}
	}

	if (!found)
		status = DLADM_STATUS_NOTFOUND;

	return (status);
}

boolean_t
i_dladm_is_prop_temponly(const char *prop_name, char **errprop,
    prop_table_t *prop_tbl)
{
	uint_t		i;

	if (prop_name == NULL)
		return (B_FALSE);

	for (i = 0; i < prop_tbl->pt_size; i++) {
		fprop_desc_t	*pdp = &prop_tbl->pt_table[i];

		if (strcasecmp(prop_name, pdp->pd_name) != 0)
			continue;

		if (errprop != NULL)
			*errprop = pdp->pd_name;

		if (pdp->pd_temponly)
			return (B_TRUE);
	}

	return (B_FALSE);
}
void
dladm_free_props(dladm_arg_list_t *list)
{
	dladm_free_args(list);
}

dladm_status_t
dladm_parse_props(char *str, dladm_arg_list_t **listp, boolean_t novalues)
{
	if (dladm_parse_args(str, listp, novalues) != DLADM_STATUS_OK)
		goto fail;

	return (DLADM_STATUS_OK);

fail:
	dladm_free_args(*listp);
	return (DLADM_STATUS_PROP_PARSE_ERR);
}
