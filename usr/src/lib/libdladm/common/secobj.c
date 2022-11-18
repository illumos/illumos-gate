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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/dld.h>
#include <sys/dld_ioc.h>
#include <libinetutil.h>
#include <libdllink.h>
#include <libdladm_impl.h>

static dladm_status_t	i_dladm_set_secobj_db(dladm_handle_t, const char *,
			    dladm_secobj_class_t, uint8_t *, uint_t);
static dladm_status_t	i_dladm_get_secobj_db(dladm_handle_t, const char *,
			    dladm_secobj_class_t *, uint8_t *, uint_t *);
static dladm_status_t	i_dladm_unset_secobj_db(dladm_handle_t, const char *);
static dladm_status_t	i_dladm_walk_secobj_db(dladm_handle_t, void *,
			    boolean_t (*)(dladm_handle_t, void *,
			    const char *));

typedef struct secobj_class_info {
	const char		*sc_name;
	dld_secobj_class_t	sc_dldclass;
} secobj_class_info_t;

static secobj_class_info_t secobj_class_table[] = {
	{"wep",	DLD_SECOBJ_CLASS_WEP},
	{"wpa",	DLD_SECOBJ_CLASS_WPA}
};

#define	SECOBJ_MAXBUFSZ	65536
#define	NSECOBJCLASS \
	(sizeof (secobj_class_table) / sizeof (secobj_class_info_t))

static boolean_t
dladm_check_secobjclass(dladm_secobj_class_t class)
{
	return (class >= 0 && (uint_t)class < NSECOBJCLASS);
}

dladm_status_t
dladm_str2secobjclass(const char *str, dladm_secobj_class_t *class)
{
	uint_t			i;
	secobj_class_info_t	*sp;

	for (i = 0; i < NSECOBJCLASS; i++) {
		sp = &secobj_class_table[i];
		if (strcasecmp(str, sp->sc_name) == 0) {
			*class = i;
			return (DLADM_STATUS_OK);
		}
	}
	return (DLADM_STATUS_BADARG);
}

const char *
dladm_secobjclass2str(dladm_secobj_class_t class, char *buf)
{
	const char		*s;

	if (!dladm_check_secobjclass(class))
		s = "";
	else
		s = secobj_class_table[class].sc_name;

	(void) snprintf(buf, DLADM_STRSIZE, "%s", s);
	return (buf);
}

static boolean_t
dladm_convert_secobjclass(dladm_secobj_class_t class,
    dld_secobj_class_t *dldclass)
{
	if (!dladm_check_secobjclass(class))
		return (B_FALSE);

	*dldclass = secobj_class_table[class].sc_dldclass;
	return (B_TRUE);
}

static boolean_t
dladm_convert_dldsecobjclass(dld_secobj_class_t dldclass,
    dladm_secobj_class_t *class)
{
	uint_t			i;
	secobj_class_info_t	*sp;

	for (i = 0; i < NSECOBJCLASS; i++) {
		sp = &secobj_class_table[i];
		if (dldclass == sp->sc_dldclass) {
			*class = i;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

dladm_status_t
dladm_set_secobj(dladm_handle_t handle, const char *obj_name,
    dladm_secobj_class_t class, uint8_t *obj_val, uint_t obj_len, uint_t flags)
{
	dladm_status_t		status = DLADM_STATUS_OK;
	dld_ioc_secobj_set_t	secobj_set;
	dld_secobj_t		*objp;

	if (!dladm_valid_secobj_name(obj_name))
		return (DLADM_STATUS_BADARG);

	if (!dladm_check_secobjclass(class) || flags == 0 ||
	    obj_name == NULL || strlen(obj_name) > DLD_SECOBJ_NAME_MAX ||
	    obj_val == NULL || obj_len == 0 || obj_len > DLD_SECOBJ_VAL_MAX)
		return (DLADM_STATUS_BADARG);

	if ((flags & DLADM_OPT_ACTIVE) == 0)
		goto persist;

	bzero(&secobj_set, sizeof (secobj_set));
	objp = &secobj_set.ss_obj;
	if (!dladm_convert_secobjclass(class, &objp->so_class))
		return (DLADM_STATUS_BADARG);

	(void) strlcpy(objp->so_name, obj_name, DLD_SECOBJ_NAME_MAX);
	bcopy(obj_val, objp->so_val, obj_len);
	objp->so_len = obj_len;

	if ((flags & DLADM_OPT_CREATE) != 0)
		secobj_set.ss_flags = DLD_SECOBJ_OPT_CREATE;

	if (ioctl(dladm_dld_fd(handle), DLDIOC_SECOBJ_SET, &secobj_set) < 0)
		status = dladm_errno2status(errno);

	if (status != DLADM_STATUS_OK)
		return (status);

persist:
	if ((flags & DLADM_OPT_PERSIST) != 0) {
		status = i_dladm_set_secobj_db(handle, obj_name, class,
		    obj_val, obj_len);
	}
	return (status);
}

dladm_status_t
dladm_get_secobj(dladm_handle_t handle, const char *obj_name,
    dladm_secobj_class_t *classp, uint8_t *obj_val, uint_t *obj_lenp,
    uint_t flags)
{
	dladm_status_t		status = DLADM_STATUS_OK;
	dld_ioc_secobj_get_t	secobj_get;
	dld_secobj_t		*objp;

	if (obj_name == NULL || strlen(obj_name) > DLD_SECOBJ_NAME_MAX ||
	    obj_val == NULL || obj_lenp == NULL || *obj_lenp == 0 ||
	    *obj_lenp > DLD_SECOBJ_VAL_MAX)
		return (DLADM_STATUS_BADARG);

	if ((flags & DLADM_OPT_PERSIST) != 0) {
		return (i_dladm_get_secobj_db(handle, obj_name, classp,
		    obj_val, obj_lenp));
	}

	bzero(&secobj_get, sizeof (secobj_get));
	objp = &secobj_get.sg_obj;
	(void) strlcpy(objp->so_name, obj_name, DLD_SECOBJ_NAME_MAX);

	secobj_get.sg_size = sizeof (secobj_get);
	if (ioctl(dladm_dld_fd(handle), DLDIOC_SECOBJ_GET, &secobj_get) < 0)
		status = dladm_errno2status(errno);

	if (objp->so_len > *obj_lenp)
		return (DLADM_STATUS_TOOSMALL);

	if (!dladm_convert_dldsecobjclass(objp->so_class, classp))
		return (DLADM_STATUS_FAILED);

	*obj_lenp = objp->so_len;
	bcopy(objp->so_val, obj_val, *obj_lenp);
	return (status);
}

dladm_status_t
dladm_unset_secobj(dladm_handle_t handle, const char *obj_name, uint_t flags)
{
	dladm_status_t		status = DLADM_STATUS_OK;
	dld_ioc_secobj_unset_t	secobj_unset;

	if (obj_name == NULL || strlen(obj_name) > DLD_SECOBJ_NAME_MAX ||
	    flags == 0)
		return (DLADM_STATUS_BADARG);

	if ((flags & DLADM_OPT_ACTIVE) == 0)
		goto persist;

	bzero(&secobj_unset, sizeof (secobj_unset));
	(void) strlcpy(secobj_unset.su_name, obj_name, DLD_SECOBJ_NAME_MAX);

	if (ioctl(dladm_dld_fd(handle), DLDIOC_SECOBJ_UNSET, &secobj_unset) < 0)
		status = dladm_errno2status(errno);

	if (status != DLADM_STATUS_OK)
		return (status);

persist:
	if ((flags & DLADM_OPT_PERSIST) != 0)
		status = i_dladm_unset_secobj_db(handle, obj_name);

	return (status);
}

dladm_status_t
dladm_walk_secobj(dladm_handle_t handle, void *arg,
    boolean_t (*func)(dladm_handle_t, void *, const char *), uint_t flags)
{
	dladm_status_t		status = DLADM_STATUS_OK;
	dld_ioc_secobj_get_t	*secobj_getp;
	dld_secobj_t		*objp;
	size_t			secobj_bufsz;

	if ((flags & DLADM_OPT_PERSIST) != 0)
		return (i_dladm_walk_secobj_db(handle, arg, func));

	/* Start with enough room for 10 objects, increase if necessary. */
	secobj_bufsz = sizeof (*secobj_getp) + (10 * sizeof (*objp));
	secobj_getp = calloc(1, secobj_bufsz);
	if (secobj_getp == NULL) {
		status = dladm_errno2status(errno);
		goto done;
	}

tryagain:
	secobj_getp->sg_size = secobj_bufsz;
	if (ioctl(dladm_dld_fd(handle), DLDIOC_SECOBJ_GET, secobj_getp) < 0) {
		if (errno == ENOSPC) {
			/* Increase the buffer size and try again. */
			secobj_bufsz *= 2;
			if (secobj_bufsz > SECOBJ_MAXBUFSZ) {
				status = dladm_errno2status(errno);
				goto done;
			}
			secobj_getp = realloc(secobj_getp, secobj_bufsz);
			if (secobj_getp == NULL) {
				status = dladm_errno2status(errno);
				goto done;
			}
			bzero(secobj_getp, secobj_bufsz);
			goto tryagain;
		}
		status = dladm_errno2status(errno);
		goto done;
	}

	objp = (dld_secobj_t *)(secobj_getp + 1);
	while (secobj_getp->sg_count > 0) {
		if (!func(handle, arg, objp->so_name))
			goto done;
		secobj_getp->sg_count--;
		objp++;
	}
done:
	free(secobj_getp);
	return (status);
}

/*
 * Data structures used for implementing persistent secure objects
 */
typedef struct secobj_info {
	const char		*si_name;
	dladm_secobj_class_t	*si_classp;
	uint8_t			*si_val;
	uint_t			*si_lenp;
} secobj_info_t;

typedef struct secobj_name {
	char			*sn_name;
	struct secobj_name	*sn_next;
} secobj_name_t;

typedef struct secobj_db_state	secobj_db_state_t;

typedef boolean_t (*secobj_db_op_t)(dladm_handle_t, struct secobj_db_state *,
    char *, secobj_info_t *, dladm_status_t *);

struct secobj_db_state {
	secobj_db_op_t		ss_op;
	secobj_info_t		ss_info;
	secobj_name_t		**ss_namelist;
};

/*
 * Update or generate a secobj entry using the info in ssp->ss_info.
 */
static boolean_t
process_secobj_set(dladm_handle_t handle __unused, secobj_db_state_t *ssp,
    char *buf, secobj_info_t *sip, dladm_status_t *statusp)
{
	char	tmpbuf[MAXLINELEN];
	char	classbuf[DLADM_STRSIZE];
	char	*ptr = tmpbuf, *lim = tmpbuf + MAXLINELEN;
	uint_t	i;

	sip = &ssp->ss_info;

	ptr += snprintf(ptr, BUFLEN(lim, ptr), "%s\t", sip->si_name);
	ptr += snprintf(ptr, BUFLEN(lim, ptr), "%s\t",
	    dladm_secobjclass2str(*sip->si_classp, classbuf));

	ptr += snprintf(ptr, BUFLEN(lim, ptr), "0x");
	for (i = 0; i < *sip->si_lenp; i++) {
		ptr += snprintf(ptr, BUFLEN(lim, ptr), "%02x",
		    sip->si_val[i] & 0xff);
	}
	if (ptr > lim) {
		*statusp = DLADM_STATUS_TOOSMALL;
		return (B_FALSE);
	}
	(void) snprintf(buf, MAXLINELEN, "%s\n", tmpbuf);
	return (B_FALSE);
}

static boolean_t
process_secobj_get(dladm_handle_t handle __unused, secobj_db_state_t *ssp,
    char *buf __unused, secobj_info_t *sip, dladm_status_t *statusp)
{
	if (*sip->si_lenp > *ssp->ss_info.si_lenp) {
		*statusp = DLADM_STATUS_TOOSMALL;
		return (B_FALSE);
	}
	bcopy(sip->si_val, ssp->ss_info.si_val, *sip->si_lenp);
	*ssp->ss_info.si_lenp = *sip->si_lenp;
	*ssp->ss_info.si_classp = *sip->si_classp;
	return (B_FALSE);
}

static boolean_t
process_secobj_unset(dladm_handle_t handle __unused,
    secobj_db_state_t *ssp __unused, char *buf,
    secobj_info_t *sip __unused, dladm_status_t *statusp __unused)
{
	/*
	 * Delete line.
	 */
	buf[0] = '\0';
	return (B_FALSE);
}

static boolean_t
process_secobj_walk(dladm_handle_t handle __unused, secobj_db_state_t *ssp,
    char *buf __unused, secobj_info_t *sip, dladm_status_t *statusp __unused)
{
	secobj_name_t	*snp;

	if ((snp = malloc(sizeof (*snp))) == NULL)
		return (B_TRUE);

	if ((snp->sn_name = strdup(sip->si_name)) == NULL) {
		free(snp);
		return (B_TRUE);
	}

	snp->sn_next = NULL;
	*ssp->ss_namelist = snp;
	ssp->ss_namelist = &snp->sn_next;
	return (B_TRUE);
}

static boolean_t
process_secobj_init(dladm_handle_t handle, secobj_db_state_t *ssp __unused,
    char *buf __unused, secobj_info_t *sip, dladm_status_t *statusp)
{
	*statusp = dladm_set_secobj(handle, sip->si_name, *sip->si_classp,
	    sip->si_val, *sip->si_lenp,
	    DLADM_OPT_ACTIVE | DLADM_OPT_CREATE);
	return (B_TRUE);
}

static int
parse_secobj_val(char *buf, secobj_info_t *sip)
{
	if (strncmp(buf, "0x", 2) != 0)
		return (EINVAL);

	return (hexascii_to_octet(buf + 2, strlen(buf) - 2,
	    sip->si_val, sip->si_lenp));
}

static boolean_t
process_secobj_line(dladm_handle_t handle, secobj_db_state_t *ssp, char *buf,
    dladm_status_t *statusp)
{
	secobj_info_t		sinfo;
	dladm_secobj_class_t	class;
	uint8_t			val[DLADM_SECOBJ_VAL_MAX];
	uint_t			vlen;
	int			i, len, nlen;
	char			*str, *lasts;

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
	if (ssp->ss_info.si_name != NULL) {
		/*
		 * Skip objects we're not interested in.
		 */
		nlen = strlen(ssp->ss_info.si_name);
		if (strncmp(str, ssp->ss_info.si_name, nlen) != 0 ||
		    !isspace(str[nlen]))
			return (B_TRUE);

		sinfo.si_name = ssp->ss_info.si_name;
	} else {
		/*
		 * If an object is not specified, find the object name
		 * and assign it to sinfo.si_name.
		 */
		if (strtok_r(str, " \n\t", &lasts) == NULL)
			goto fail;

		nlen = strlen(str);
		sinfo.si_name = str;
	}
	str += nlen + 1;
	if (str >= buf + len)
		goto fail;

	/*
	 * Find the class name.
	 */
	if ((str = strtok_r(str, " \n\t", &lasts)) == NULL)
		goto fail;

	*statusp = dladm_str2secobjclass(str, &class);
	if (*statusp != DLADM_STATUS_OK)
		goto fail;

	/*
	 * Find the object value.
	 */
	if ((str = strtok_r(NULL, " \n\t", &lasts)) == NULL)
		goto fail;

	vlen = DLADM_SECOBJ_VAL_MAX;
	sinfo.si_classp = &class;
	sinfo.si_val = val;
	sinfo.si_lenp = &vlen;
	if (parse_secobj_val(str, &sinfo) != 0)
		goto fail;

	return ((*ssp->ss_op)(handle, ssp, buf, &sinfo, statusp));

fail:
	/*
	 * Delete corrupted line.
	 */
	buf[0] = '\0';
	return (B_TRUE);
}

static dladm_status_t
process_secobj_db(dladm_handle_t handle, void *arg, FILE *fp, FILE *nfp)
{
	secobj_db_state_t	*ssp = arg;
	dladm_status_t		status = DLADM_STATUS_OK;
	char			buf[MAXLINELEN];
	boolean_t		cont = B_TRUE;

	/*
	 * This loop processes each line of the configuration file.
	 * buf can potentially be modified by process_secobj_line().
	 * If this is a write operation and buf is not truncated, buf will
	 * be written to disk. process_secobj_line() will no longer be
	 * called after it returns B_FALSE; at which point the remainder
	 * of the file will continue to be read and, if necessary, written
	 * to disk as well.
	 */
	while (fgets(buf, MAXLINELEN, fp) != NULL) {
		if (cont)
			cont = process_secobj_line(handle, ssp, buf, &status);

		if (nfp != NULL && buf[0] != '\0' && fputs(buf, nfp) == EOF) {
			status = dladm_errno2status(errno);
			break;
		}
	}
	if (status != DLADM_STATUS_OK || !cont)
		return (status);

	if (ssp->ss_op == process_secobj_set) {
		/*
		 * If the specified object is not found above, we add the
		 * object to the configuration file.
		 */
		(void) (*ssp->ss_op)(handle, ssp, buf, NULL, &status);
		if (status == DLADM_STATUS_OK && fputs(buf, nfp) == EOF)
			status = dladm_errno2status(errno);
	}

	if (ssp->ss_op == process_secobj_unset ||
	    ssp->ss_op == process_secobj_get)
		status = DLADM_STATUS_NOTFOUND;

	return (status);
}

#define	SECOBJ_RW_DB(handle, statep, writeop)			\
	(i_dladm_rw_db(handle, "/etc/dladm/secobj.conf",	\
	S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,			\
	process_secobj_db, (statep), (writeop)))

static dladm_status_t
i_dladm_set_secobj_db(dladm_handle_t handle, const char *obj_name,
    dladm_secobj_class_t class, uint8_t *obj_val, uint_t obj_len)
{
	secobj_db_state_t	state;

	state.ss_op = process_secobj_set;
	state.ss_info.si_name = obj_name;
	state.ss_info.si_classp = &class;
	state.ss_info.si_val = obj_val;
	state.ss_info.si_lenp = &obj_len;
	state.ss_namelist = NULL;

	return (SECOBJ_RW_DB(handle, &state, B_TRUE));
}

static dladm_status_t
i_dladm_get_secobj_db(dladm_handle_t handle, const char *obj_name,
    dladm_secobj_class_t *classp, uint8_t *obj_val, uint_t *obj_lenp)
{
	secobj_db_state_t	state;

	state.ss_op = process_secobj_get;
	state.ss_info.si_name = obj_name;
	state.ss_info.si_classp = classp;
	state.ss_info.si_val = obj_val;
	state.ss_info.si_lenp = obj_lenp;
	state.ss_namelist = NULL;

	return (SECOBJ_RW_DB(handle, &state, B_FALSE));
}

static dladm_status_t
i_dladm_unset_secobj_db(dladm_handle_t handle, const char *obj_name)
{
	secobj_db_state_t	state;

	state.ss_op = process_secobj_unset;
	state.ss_info.si_name = obj_name;
	state.ss_info.si_classp = NULL;
	state.ss_info.si_val = NULL;
	state.ss_info.si_lenp = NULL;
	state.ss_namelist = NULL;

	return (SECOBJ_RW_DB(handle, &state, B_TRUE));
}

static dladm_status_t
i_dladm_walk_secobj_db(dladm_handle_t handle, void *arg,
    boolean_t (*func)(dladm_handle_t, void *, const char *))
{
	secobj_db_state_t	state;
	secobj_name_t		*snp = NULL, *fsnp;
	dladm_status_t		status;
	boolean_t		cont = B_TRUE;

	state.ss_op = process_secobj_walk;
	state.ss_info.si_name = NULL;
	state.ss_info.si_classp = NULL;
	state.ss_info.si_val = NULL;
	state.ss_info.si_lenp = NULL;
	state.ss_namelist = &snp;

	status = SECOBJ_RW_DB(handle, &state, B_FALSE);
	if (status != DLADM_STATUS_OK)
		return (status);

	while (snp != NULL) {
		fsnp = snp;
		snp = snp->sn_next;
		if (cont)
			cont = func(handle, arg, fsnp->sn_name);
		free(fsnp->sn_name);
		free(fsnp);
	}
	return (status);
}

dladm_status_t
dladm_init_secobj(dladm_handle_t handle)
{
	secobj_db_state_t	state;

	state.ss_op = process_secobj_init;
	state.ss_info.si_name = NULL;
	state.ss_info.si_classp = NULL;
	state.ss_info.si_val = NULL;
	state.ss_info.si_lenp = NULL;
	state.ss_namelist = NULL;

	return (SECOBJ_RW_DB(handle, &state, B_FALSE));
}

boolean_t
dladm_valid_secobj_name(const char *secobj_name)
{
	size_t len = strlen(secobj_name);
	const char *cp;

	if (len + 1 > DLADM_SECOBJ_NAME_MAX)
		return (B_FALSE);

	/*
	 * The legal characters in a secobj name are:
	 * alphanumeric (a-z, A-Z, 0-9), '.', '_', '-'.
	 */
	for (cp = secobj_name; *cp != '\0'; cp++) {
		if (!isalnum(*cp) &&
		    (*cp != '.') && (*cp != '_') && (*cp != '-'))
			return (B_FALSE);
	}

	return (B_TRUE);
}
