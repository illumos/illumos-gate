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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <sys/zone.h>
#include <fcntl.h>
#include <unistd.h>
#include <libdevinfo.h>
#include <zone.h>
#include <libdllink.h>
#include <libdladm_impl.h>
#include <libdlwlan.h>
#include <dlfcn.h>
#include <link.h>

static dladm_status_t	i_dladm_set_prop_db(const char *, const char *,
			    char **, uint_t);
static dladm_status_t	i_dladm_get_prop_db(const char *, const char *,
			    char **, uint_t *);
static dladm_status_t	i_dladm_get_prop_temp(const char *, dladm_prop_type_t,
			    const char *, char **, uint_t *);
static dladm_status_t	i_dladm_set_prop_temp(const char *, const char *,
			    char **, uint_t, uint_t, char **);
static boolean_t	i_dladm_is_prop_temponly(const char *prop_name,
			    char **);

typedef struct val_desc {
	char	*vd_name;
	void	*vd_val;
} val_desc_t;

struct prop_desc;

typedef dladm_status_t	pd_getf_t(const char *, char **, uint_t *);
typedef dladm_status_t	pd_setf_t(const char *, val_desc_t *, uint_t);
typedef dladm_status_t	pd_checkf_t(struct prop_desc *, char **,
			    uint_t, val_desc_t **);

static pd_getf_t	do_get_zone;
static pd_setf_t	do_set_zone;
static pd_checkf_t	do_check_zone;

typedef struct prop_desc {
	char		*pd_name;
	val_desc_t	pd_defval;
	val_desc_t	*pd_modval;
	uint_t		pd_nmodval;
	boolean_t	pd_temponly;
	pd_setf_t	*pd_set;
	pd_getf_t	*pd_getmod;
	pd_getf_t	*pd_get;
	pd_checkf_t	*pd_check;
} prop_desc_t;

static prop_desc_t	prop_table[] = {
	{ "zone",	{ "", NULL }, NULL, 0, B_TRUE,
	    do_set_zone, NULL,
	    do_get_zone, do_check_zone}
};

#define	MAX_PROPS	(sizeof (prop_table) / sizeof (prop_desc_t))

dladm_status_t
dladm_set_prop(const char *link, const char *prop_name, char **prop_val,
    uint_t val_cnt, uint_t flags, char **errprop)
{
	dladm_status_t		status = DLADM_STATUS_BADARG;

	if (link == NULL || (prop_val == NULL && val_cnt > 0) ||
	    (prop_val != NULL && val_cnt == 0) || flags == 0)
		return (DLADM_STATUS_BADARG);

	if ((flags & DLADM_OPT_TEMP) != 0) {
		status = i_dladm_set_prop_temp(link, prop_name, prop_val,
		    val_cnt, flags, errprop);
		if (status == DLADM_STATUS_TEMPONLY &&
		    (flags & DLADM_OPT_PERSIST) != 0)
			return (DLADM_STATUS_TEMPONLY);

		if (status == DLADM_STATUS_NOTFOUND) {
			status = DLADM_STATUS_BADARG;
			if (dladm_wlan_is_valid(link)) {
				status = dladm_wlan_set_prop(link, prop_name,
				    prop_val, val_cnt, errprop);
			}
		}
		if (status != DLADM_STATUS_OK)
			return (status);
	}
	if ((flags & DLADM_OPT_PERSIST) != 0) {
		if (i_dladm_is_prop_temponly(prop_name, errprop))
			return (DLADM_STATUS_TEMPONLY);

		status = i_dladm_set_prop_db(link, prop_name,
		    prop_val, val_cnt);
	}
	return (status);
}

dladm_status_t
dladm_walk_prop(const char *link, void *arg,
    boolean_t (*func)(void *, const char *))
{
	int	i;

	if (link == NULL || func == NULL)
		return (DLADM_STATUS_BADARG);

	/* For wifi links, show wifi properties first */
	if (dladm_wlan_is_valid(link)) {
		dladm_status_t	status;

		status = dladm_wlan_walk_prop(link, arg, func);
		if (status != DLADM_STATUS_OK)
			return (status);
	}

	/* Then show data-link properties if there are any */
	for (i = 0; i < MAX_PROPS; i++) {
		if (!func(arg, prop_table[i].pd_name))
			break;
	}
	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_get_prop(const char *link, dladm_prop_type_t type,
    const char *prop_name, char **prop_val, uint_t *val_cntp)
{
	dladm_status_t status;

	if (link == NULL || prop_name == NULL || prop_val == NULL ||
	    val_cntp == NULL || *val_cntp == 0)
		return (DLADM_STATUS_BADARG);

	if (type == DLADM_PROP_VAL_PERSISTENT) {
		if (i_dladm_is_prop_temponly(prop_name, NULL))
			return (DLADM_STATUS_TEMPONLY);
		return (i_dladm_get_prop_db(link, prop_name,
		    prop_val, val_cntp));
	}

	status = i_dladm_get_prop_temp(link, type, prop_name,
	    prop_val, val_cntp);
	if (status != DLADM_STATUS_NOTFOUND)
		return (status);

	if (dladm_wlan_is_valid(link)) {
		return (dladm_wlan_get_prop(link, type, prop_name,
		    prop_val, val_cntp));
	}
	return (DLADM_STATUS_BADARG);
}

/*
 * Data structures used for implementing persistent link properties
 */
typedef struct linkprop_val {
	const char		*lv_name;
	struct linkprop_val	*lv_nextval;
} linkprop_val_t;

typedef struct linkprop_info {
	const char		*li_name;
	struct linkprop_info	*li_nextprop;
	struct linkprop_val	*li_val;
} linkprop_info_t;

typedef struct linkprop_db_state	linkprop_db_state_t;

typedef boolean_t (*linkprop_db_op_t)(linkprop_db_state_t *,
    char *, linkprop_info_t *, dladm_status_t *);

struct linkprop_db_state {
	linkprop_db_op_t	ls_op;
	const char		*ls_link;
	const char		*ls_propname;
	char			**ls_propval;
	uint_t			*ls_valcntp;
};

static void
free_linkprops(linkprop_info_t *lip)
{
	linkprop_info_t	*lip_next;
	linkprop_val_t	*lvp, *lvp_next;

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
 * Generate an entry in the link property database.
 * Each entry has this format:
 * <linkname>	<prop0>=<val0>,...,<valn>;...;<propn>=<val0>,...,<valn>;
 */
static void
generate_linkprop_line(linkprop_db_state_t *lsp, char *buf,
    linkprop_info_t *listp, dladm_status_t *statusp)
{
	char		tmpbuf[MAXLINELEN];
	char		*ptr, *lim = tmpbuf + MAXLINELEN;
	linkprop_info_t	*lip = listp;
	linkprop_val_t	*lvp = NULL;

	/*
	 * Delete line if there are no properties left.
	 */
	if (lip == NULL ||
	    (lip->li_val == NULL && lip->li_nextprop == NULL)) {
		buf[0] = '\0';
		return;
	}
	ptr = tmpbuf;
	ptr += snprintf(ptr, BUFLEN(lim, ptr), "%s\t", lsp->ls_link);
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
 * process_linkprop_db() will first scan the db for an entry matching the
 * specified link. If a match is found, this function is invoked with the
 * entry's contents (buf) and its linked-list representation (listp). lsp
 * holds the name and values of the property to be added or updated; this
 * information will be merged with listp. Subsequently, an updated entry
 * will be written to buf, which will in turn be written to disk by
 * process_linkprop_db(). If no entry matches the specified link, listp
 * will be NULL; a new entry will be generated in this case and it will
 * contain only the property information in lsp.
 */
static boolean_t
process_linkprop_set(linkprop_db_state_t *lsp, char *buf,
    linkprop_info_t *listp, dladm_status_t *statusp)
{
	dladm_status_t	status;
	linkprop_info_t	*lastp = NULL, *lip = listp, *nlip = NULL;
	linkprop_val_t	**lvpp;
	int		i;

	if (lsp->ls_propname == NULL) {
		buf[0] = '\0';
		return (B_FALSE);
	}

	/*
	 * Find the linkprop we want to change.
	 */
	for (; lip != NULL; lip = lip->li_nextprop) {
		if (strcmp(lip->li_name, lsp->ls_propname) == 0)
			break;

		lastp = lip;
	}

	if (lip == NULL) {
		/*
		 * If the linkprop is not found, append it to the list.
		 */
		if ((nlip = malloc(sizeof (linkprop_info_t))) == NULL) {
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
		linkprop_val_t	*lvp, *lvp_next;

		/*
		 * If the linkprop is found, delete the existing values from it.
		 */
		for (lvp = lip->li_val; lvp != NULL; lvp = lvp_next) {
			lvp_next = lvp->lv_nextval;
			free(lvp);
		}
		lip->li_val = NULL;
		lvpp = &lip->li_val;
	}

	/*
	 * Fill our linkprop with the specified values.
	 */
	for (i = 0; i < *lsp->ls_valcntp; i++) {
		if ((*lvpp = malloc(sizeof (linkprop_val_t))) == NULL) {
			status = DLADM_STATUS_NOMEM;
			goto fail;
		}
		(*lvpp)->lv_name = lsp->ls_propval[i];
		(*lvpp)->lv_nextval = NULL;
		lvpp = &(*lvpp)->lv_nextval;
	}

	if (listp != NULL) {
		generate_linkprop_line(lsp, buf, listp, statusp);
	} else {
		generate_linkprop_line(lsp, buf, nlip, statusp);
		free_linkprops(nlip);
	}
	return (B_FALSE);

fail:
	*statusp = status;
	if (listp == NULL)
		free_linkprops(nlip);

	return (B_FALSE);
}

/*
 * This function is used for retrieving the values for a specific property.
 * It gets called if an entry matching the specified link exists in the db.
 * The entry is converted into a linked-list listp. This list is then scanned
 * for the specified property name; if a matching property exists, its
 * associated values are copied to the array lsp->ls_propval.
 */
/* ARGSUSED */
static boolean_t
process_linkprop_get(linkprop_db_state_t *lsp, char *buf,
    linkprop_info_t *listp, dladm_status_t *statusp)
{
	linkprop_info_t	*lip = listp;
	linkprop_val_t	*lvp;
	uint_t		valcnt = 0;

	/*
	 * Find the linkprop we want to get.
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
	 * to process_linkprop_db(). For this reason, it's ok to overwrite
	 * the caller's valcnt array size with the actual number of values
	 * returned.
	 */
	*lsp->ls_valcntp = valcnt;
	return (B_FALSE);
}

/*
 * This is used for initializing link properties.
 * Unlike the other routines, this gets called for every entry in the
 * database. lsp->ls_link is not user-specified but instead is set to
 * the current link being processed.
 */
/* ARGSUSED */
static boolean_t
process_linkprop_init(linkprop_db_state_t *lsp, char *buf,
    linkprop_info_t *listp, dladm_status_t *statusp)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	linkprop_info_t	*lip = listp;
	linkprop_val_t	*lvp;
	uint_t		valcnt, i;
	char		**propval;

	for (; lip != NULL; lip = lip->li_nextprop) {
		/*
		 * Construct the propval array and fill it with
		 * values from listp.
		 */
		for (lvp = lip->li_val, valcnt = 0;
		    lvp != NULL; lvp = lvp->lv_nextval, valcnt++)
			;

		propval = malloc(sizeof (char *) * valcnt);
		if (propval == NULL) {
			*statusp = DLADM_STATUS_NOMEM;
			break;
		}
		lvp = lip->li_val;
		for (i = 0; i < valcnt; i++, lvp = lvp->lv_nextval)
			propval[i] = (char *)lvp->lv_name;

		status = dladm_set_prop(lsp->ls_link, lip->li_name,
		    propval, valcnt, DLADM_OPT_TEMP, NULL);

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
parse_linkprops(char *buf, linkprop_info_t **lipp)
{
	int			i, len;
	char			*curr;
	linkprop_info_t		*lip = NULL;
	linkprop_info_t		**tailp = lipp;
	linkprop_val_t		*lvp = NULL;
	linkprop_val_t		**vtailp = NULL;

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
			 * find, a linkprop_val_t will be allocated and
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
			 * to a property name. We allocate a new linkprop_info_t
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
	free_linkprops(*lipp);
	*lipp = NULL;
	return (-1);
}

static boolean_t
process_linkprop_line(linkprop_db_state_t *lsp, char *buf,
    dladm_status_t *statusp)
{
	linkprop_info_t		*lip = NULL;
	int			i, len, llen;
	char			*str, *lasts;
	boolean_t		cont, nolink = B_FALSE;

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
	if (lsp->ls_link != NULL) {
		/*
		 * Skip links we're not interested in.
		 * Note that strncmp() and isspace() are used here
		 * instead of strtok() and strcmp() because we don't
		 * want to modify buf in case it does not contain the
		 * specified link.
		 */
		llen = strlen(lsp->ls_link);
		if (strncmp(str, lsp->ls_link, llen) != 0 ||
		    !isspace(str[llen]))
			return (B_TRUE);
	} else {
		/*
		 * If a link is not specified, find the link name
		 * and assign it to lsp->ls_link.
		 */
		if (strtok_r(str, " \n\t", &lasts) == NULL)
			goto fail;

		llen = strlen(str);
		lsp->ls_link = str;
		nolink = B_TRUE;
	}
	str += llen + 1;
	if (str >= buf + len)
		goto fail;

	/*
	 * Now find the list of link properties.
	 */
	if ((str = strtok_r(str, " \n\t", &lasts)) == NULL)
		goto fail;

	if (parse_linkprops(str, &lip) < 0)
		goto fail;

	cont = (*lsp->ls_op)(lsp, buf, lip, statusp);
	free_linkprops(lip);
	if (nolink)
		lsp->ls_link = NULL;
	return (cont);

fail:
	free_linkprops(lip);
	if (nolink)
		lsp->ls_link = NULL;

	/*
	 * Delete corrupted line.
	 */
	buf[0] = '\0';
	return (B_TRUE);
}

static dladm_status_t
process_linkprop_db(void *arg, FILE *fp, FILE *nfp)
{
	linkprop_db_state_t	*lsp = arg;
	dladm_status_t		status = DLADM_STATUS_OK;
	char			buf[MAXLINELEN];
	boolean_t		cont = B_TRUE;

	/*
	 * This loop processes each line of the configuration file.
	 * buf can potentially be modified by process_linkprop_line().
	 * If this is a write operation and buf is not truncated, buf will
	 * be written to disk. process_linkprop_line() will no longer be
	 * called after it returns B_FALSE; at which point the remainder
	 * of the file will continue to be read and, if necessary, written
	 * to disk as well.
	 */
	while (fgets(buf, MAXLINELEN, fp) != NULL) {
		if (cont)
			cont = process_linkprop_line(lsp, buf, &status);

		if (nfp != NULL && buf[0] != '\0' && fputs(buf, nfp) == EOF) {
			status = dladm_errno2status(errno);
			break;
		}
	}

	if (status != DLADM_STATUS_OK || !cont)
		return (status);

	if (lsp->ls_op == process_linkprop_set) {
		/*
		 * If the specified link is not found above, we add the
		 * link and its properties to the configuration file.
		 */
		(void) (*lsp->ls_op)(lsp, buf, NULL, &status);
		if (status == DLADM_STATUS_OK && fputs(buf, nfp) == EOF)
			status = dladm_errno2status(errno);
	}

	if (lsp->ls_op == process_linkprop_get)
		status = DLADM_STATUS_NOTFOUND;

	return (status);
}

#define	LINKPROP_RW_DB(statep, writeop) \
	(i_dladm_rw_db("/etc/dladm/linkprop.conf", \
	S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, process_linkprop_db, \
	(statep), (writeop)))

static dladm_status_t
i_dladm_set_prop_db(const char *link, const char *prop_name,
    char **prop_val, uint_t val_cnt)
{
	linkprop_db_state_t	state;

	state.ls_op = process_linkprop_set;
	state.ls_link = link;
	state.ls_propname = prop_name;
	state.ls_propval = prop_val;
	state.ls_valcntp = &val_cnt;

	return (LINKPROP_RW_DB(&state, B_TRUE));
}

static dladm_status_t
i_dladm_get_prop_db(const char *link, const char *prop_name,
    char **prop_val, uint_t *val_cntp)
{
	linkprop_db_state_t	state;

	state.ls_op = process_linkprop_get;
	state.ls_link = link;
	state.ls_propname = prop_name;
	state.ls_propval = prop_val;
	state.ls_valcntp = val_cntp;

	return (LINKPROP_RW_DB(&state, B_FALSE));
}

dladm_status_t
dladm_init_linkprop(void)
{
	linkprop_db_state_t	state;

	state.ls_op = process_linkprop_init;
	state.ls_link = NULL;
	state.ls_propname = NULL;
	state.ls_propval = NULL;
	state.ls_valcntp = NULL;

	return (LINKPROP_RW_DB(&state, B_FALSE));
}

static dladm_status_t
i_dladm_get_zoneid(const char *link, zoneid_t *zidp)
{
	int fd;
	dld_hold_vlan_t	dhv;

	if ((fd = open(DLD_CONTROL_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	bzero(&dhv, sizeof (dld_hold_vlan_t));
	(void) strlcpy(dhv.dhv_name, link, IFNAMSIZ);
	dhv.dhv_zid = -1;

	if (i_dladm_ioctl(fd, DLDIOCZIDGET, &dhv, sizeof (dhv)) < 0)  {
		if (errno == ENOENT) {
			*zidp = GLOBAL_ZONEID;
		} else {
			dladm_status_t status = dladm_errno2status(errno);
			(void) close(fd);
			return (status);
		}
	} else {
		*zidp = dhv.dhv_zid;
	}

	(void) close(fd);
	return (DLADM_STATUS_OK);
}

typedef int (*zone_get_devroot_t)(char *, char *, size_t);

static int
i_dladm_get_zone_dev(char *zone_name, char *dev, size_t devlen)
{
	char			root[MAXPATHLEN];
	zone_get_devroot_t	real_zone_get_devroot;
	void			*dlhandle;
	void			*sym;
	int			ret;

	if ((dlhandle = dlopen("libzonecfg.so.1", RTLD_LAZY)) == NULL)
		return (-1);

	if ((sym = dlsym(dlhandle, "zone_get_devroot")) == NULL) {
		(void) dlclose(dlhandle);
		return (-1);
	}

	real_zone_get_devroot = (zone_get_devroot_t)sym;

	if ((ret = real_zone_get_devroot(zone_name, root, sizeof (root))) == 0)
		(void) snprintf(dev, devlen, "%s%s", root, "/dev");
	(void) dlclose(dlhandle);
	return (ret);
}

static dladm_status_t
i_dladm_add_deventry(zoneid_t zid, const char *link)
{
	char		path[MAXPATHLEN];
	di_prof_t	prof = NULL;
	char		zone_name[ZONENAME_MAX];
	dladm_status_t	status;

	if (getzonenamebyid(zid, zone_name, sizeof (zone_name)) < 0)
		return (dladm_errno2status(errno));
	if (i_dladm_get_zone_dev(zone_name, path, sizeof (path)) != 0)
		return (dladm_errno2status(errno));
	if (di_prof_init(path, &prof) != 0)
		return (dladm_errno2status(errno));

	status = DLADM_STATUS_OK;
	if (di_prof_add_dev(prof, link) != 0) {
		status = dladm_errno2status(errno);
		goto cleanup;
	}
	if (di_prof_commit(prof) != 0)
		status = dladm_errno2status(errno);
cleanup:
	if (prof)
		di_prof_fini(prof);

	return (status);
}

static dladm_status_t
i_dladm_remove_deventry(zoneid_t zid, const char *link)
{
	char		path[MAXPATHLEN];
	di_prof_t	prof = NULL;
	char		zone_name[ZONENAME_MAX];
	dladm_status_t	status;

	if (getzonenamebyid(zid, zone_name, sizeof (zone_name)) < 0)
		return (dladm_errno2status(errno));
	if (i_dladm_get_zone_dev(zone_name, path, sizeof (path)) != 0)
		return (dladm_errno2status(errno));
	if (di_prof_init(path, &prof) != 0)
		return (dladm_errno2status(errno));

	status = DLADM_STATUS_OK;
	if (di_prof_add_exclude(prof, link) != 0) {
		status = dladm_errno2status(errno);
		goto cleanup;
	}
	if (di_prof_commit(prof) != 0)
		status = dladm_errno2status(errno);
cleanup:
	if (prof)
		di_prof_fini(prof);

	return (status);
}

static dladm_status_t
do_get_zone(const char *link, char **prop_val, uint_t *val_cnt)
{
	char		zone_name[ZONENAME_MAX];
	zoneid_t	zid;
	dladm_status_t	status;

	status = i_dladm_get_zoneid(link, &zid);
	if (status != DLADM_STATUS_OK)
		return (status);

	*val_cnt = 1;
	if (zid != GLOBAL_ZONEID) {
		if (getzonenamebyid(zid, zone_name, sizeof (zone_name)) < 0)
			return (dladm_errno2status(errno));

		(void) strncpy(*prop_val, zone_name, DLADM_PROP_VAL_MAX);
	} else {
		*prop_val[0] = '\0';
	}

	return (DLADM_STATUS_OK);
}

static dladm_status_t
do_set_zone(const char *link, val_desc_t *vdp, uint_t val_cnt)
{
	dladm_status_t	status;
	zoneid_t	zid_old, zid_new;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	status = i_dladm_get_zoneid(link, &zid_old);
	if (status != DLADM_STATUS_OK)
		return (status);

	/* Do nothing if setting to current value */
	zid_new = (intptr_t)(void *)vdp->vd_val;
	if (zid_new == zid_old)
		return (DLADM_STATUS_OK);

	if (zid_old != GLOBAL_ZONEID) {
		if (dladm_rele_link(link, GLOBAL_ZONEID, B_TRUE) < 0)
			return (dladm_errno2status(errno));

		if (zone_remove_datalink(zid_old, (char *)link) != 0 &&
		    errno != ENXIO) {
			status = dladm_errno2status(errno);
			goto rollback1;
		}

		status = i_dladm_remove_deventry(zid_old, link);
		if (status != DLADM_STATUS_OK)
			goto rollback2;
	}

	if (zid_new != GLOBAL_ZONEID) {
		if (zone_add_datalink(zid_new, (char *)link) != 0) {
			status = dladm_errno2status(errno);
			goto rollback3;
		}

		if (dladm_hold_link(link, zid_new, B_TRUE) < 0) {
			(void) zone_remove_datalink(zid_new, (char *)link);
			status = dladm_errno2status(errno);
			goto rollback3;
		}

		status = i_dladm_add_deventry(zid_new, link);
		if (status != DLADM_STATUS_OK) {
			(void) dladm_rele_link(link, GLOBAL_ZONEID, B_FALSE);
			(void) zone_remove_datalink(zid_new, (char *)link);
			goto rollback3;
		}
	}
	return (DLADM_STATUS_OK);

rollback3:
	if (zid_old != GLOBAL_ZONEID)
		(void) i_dladm_add_deventry(zid_old, link);
rollback2:
	if (zid_old != GLOBAL_ZONEID)
		(void) zone_add_datalink(zid_old, (char *)link);
rollback1:
	(void) dladm_hold_link(link, zid_old, B_FALSE);
cleanexit:
	return (status);
}

/* ARGSUSED */
static dladm_status_t
do_check_zone(prop_desc_t *pdp, char **prop_val, uint_t val_cnt,
    val_desc_t **vdpp)
{
	zoneid_t 	zid;
	val_desc_t	*vdp = NULL;

	if (val_cnt != 1)
		return (DLADM_STATUS_BADVALCNT);

	if ((zid = getzoneidbyname(*prop_val)) == -1)
		return (DLADM_STATUS_BADVAL);

	if (zid != GLOBAL_ZONEID) {
		ushort_t	flags;

		if (zone_getattr(zid, ZONE_ATTR_FLAGS, &flags,
		    sizeof (flags)) < 0) {
			return (dladm_errno2status(errno));
		}

		if (!(flags & ZF_NET_EXCL)) {
			return (DLADM_STATUS_BADVAL);
		}
	}

	vdp = malloc(sizeof (val_desc_t));
	if (vdp == NULL)
		return (DLADM_STATUS_NOMEM);

	vdp->vd_val = (void *)(uintptr_t)zid;
	*vdpp = vdp;
	return (DLADM_STATUS_OK);
}

static dladm_status_t
i_dladm_get_prop_temp(const char *link, dladm_prop_type_t type,
    const char *prop_name, char **prop_val, uint_t *val_cntp)
{
	int 		i;
	dladm_status_t	status;
	uint_t		cnt;
	prop_desc_t	*pdp;

	if (link == NULL || prop_name == NULL || prop_val == NULL ||
	    val_cntp == NULL || *val_cntp == 0)
		return (DLADM_STATUS_BADARG);

	for (i = 0; i < MAX_PROPS; i++)
		if (strcasecmp(prop_name, prop_table[i].pd_name) == 0)
			break;

	if (i == MAX_PROPS)
		return (DLADM_STATUS_NOTFOUND);

	pdp = &prop_table[i];
	status = DLADM_STATUS_OK;

	switch (type) {
	case DLADM_PROP_VAL_CURRENT:
		status = pdp->pd_get(link, prop_val, val_cntp);
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
			status = pdp->pd_getmod(link, prop_val, val_cntp);
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
i_dladm_set_one_prop_temp(const char *link, prop_desc_t *pdp, char **prop_val,
    uint_t val_cnt, uint_t flags)
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

	status = pdp->pd_set(link, vdp, cnt);

	free(vdp);
	return (status);
}

static dladm_status_t
i_dladm_set_prop_temp(const char *link, const char *prop_name, char **prop_val,
    uint_t val_cnt, uint_t flags, char **errprop)
{
	int 		i;
	dladm_status_t	status = DLADM_STATUS_OK;
	boolean_t	found = B_FALSE;

	for (i = 0; i < MAX_PROPS; i++) {
		prop_desc_t	*pdp = &prop_table[i];
		dladm_status_t	s;

		if (prop_name != NULL &&
		    (strcasecmp(prop_name, pdp->pd_name) != 0))
			continue;

		found = B_TRUE;
		s = i_dladm_set_one_prop_temp(link, pdp, prop_val, val_cnt,
		    flags);

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

static boolean_t
i_dladm_is_prop_temponly(const char *prop_name, char **errprop)
{
	int 		i;

	for (i = 0; i < MAX_PROPS; i++) {
		prop_desc_t	*pdp = &prop_table[i];

		if (prop_name != NULL &&
		    (strcasecmp(prop_name, pdp->pd_name) != 0))
			continue;

		if (errprop != NULL)
			*errprop = pdp->pd_name;

		if (pdp->pd_temponly)
			return (B_TRUE);
	}

	return (B_FALSE);
}
