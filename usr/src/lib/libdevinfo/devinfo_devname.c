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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <libnvpair.h>
#include <libdevinfo.h>
#include <syslog.h>
#include <sys/param.h>
#include <errno.h>
#include <assert.h>
#include <sys/systeminfo.h>
#include <sys/modctl.h>
#include <sys/fs/sdev_node.h>


#define	LINEMAX		1024
#define	SPC		" \t\n"
#define	QUOTES		"\'\""

/*
 * This is for local file supports of DBNR configurations.
 */
static int di_devname_getmapent_files(char *, char *, nvlist_t **);
static int di_devname_get_mapinfo_files(char *, nvlist_t **);
static int parse_mapinfo_file(FILE *, nvlist_t **);
static FILE *open_local_map(char *);
static void unquote(char *, char *);

static int msglog = 1;
typedef enum {
	DBG_ERR = 1,
	DBG_INFO,
	DBG_STEP,
	DBG_ALL
} debug_level_t;
static int devname_debug = 1;
static void dprintf(debug_level_t, const char *, ...);

extern int isspace(int);

/* exported interfaces */
void di_devname_print_mapinfo(nvlist_t *);
int di_devname_get_mapinfo(char *, nvlist_t **);
int di_devname_get_mapent(char *, char *, nvlist_t **);
int di_devname_action_on_key(nvlist_t *, uint8_t, char *, void *);

/*
 * Returns 0 and the valid maplist, otherwise errno.
 */
int
di_devname_get_mapinfo_files(char *mapname, nvlist_t **maplist)
{
	FILE *fp;
	int rval = 0;
	nvlist_t *nvl = NULL;

	fp = open_local_map(mapname);
	if (fp == NULL) {
		dprintf(DBG_INFO, "di_devname_get_mapinfo_files: file %s does"
		    "not exist\n", mapname);
		return (ENOENT);
	}

	rval = parse_mapinfo_file(fp, &nvl);
	if (rval == 0) {
		*maplist = nvl;
	}
	(void) fclose(fp);

	return (rval);
}

static FILE *
open_local_map(char *mapname)
{
	char filename[LINEMAX];

	if (*mapname != '/') {
		(void) snprintf(filename, sizeof (filename), "/etc/dev/%s",
		    mapname);
	} else {
		(void) snprintf(filename, sizeof (filename), "%s", mapname);
	}

	return (fopen(filename, "r"));
}

static void
unquote(char *str, char *qbuf)
{
	register int escaped, inquote, quoted;
	register char *ip, *bp, *qp;
	char buf[LINEMAX];

	escaped = inquote = quoted = 0;

	for (ip = str, bp = buf, qp = qbuf; *ip; ip++) {
		if (!escaped) {
			if (*ip == '\\') {
				escaped = 1;
				quoted ++;
				continue;
			} else if (*ip == '"') {
				inquote = !inquote;
				quoted ++;
				continue;
			}
		}

		*bp++ = *ip;
		*qp++ = (inquote || escaped) ? '^' : ' ';
		escaped = 0;
	}
	*bp = '\0';
	*qp = '\0';
	if (quoted)
		(void) strcpy(str, buf);
}

/*
 * gets the qualified characters in *p into w, which has space allocated
 * already
 */
static int
getword(char *w, char *wq, char **p, char **pq, char delim, int wordsz)
{
	char *tmp = w;
	char *tmpq = wq;
	int count = wordsz;

	if (wordsz <= 0) {
		return (-1);
	}

	while ((delim == ' ' ? isspace(**p) : **p == delim) && **pq == ' ') {
		(*p)++;
		(*pq)++;
	}

	while (**p &&
		!((delim == ' ' ? isspace(**p) : **p == delim) &&
			**pq == ' ')) {
		if (--count <= 0) {
			*tmp = '\0';
			*tmpq = '\0';
			dprintf(DBG_INFO, "maximum word length %d exceeded\n",
				wordsz);
			return (-1);
		}
		*w++ = *(*p)++;
		*wq++ = *(*pq)++;
	}
	*w = '\0';
	*wq = '\0';
	return (0);
}

static int
parse_mapinfo_file(FILE *fp, nvlist_t **ret_nvlp)
{
	int error = 0;
	nvlist_t *nvl = NULL, *attrs = NULL;
	char line[LINEMAX], lineq[LINEMAX];
	char word[MAXPATHLEN+1], wordq[MAXPATHLEN+1];
	char *lp, *lq;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		return (EFAULT);
	}

	while (fgets(line, sizeof (line), fp)) {
		char *name, *key, *val;

		lp = (char *)line;
		lq = (char *)lineq;
		unquote(lp, lq);
		if ((getword(word, wordq, &lp, &lq, ' ',
		    sizeof (word)) == -1) || (word[0] == '\0'))
			continue;

		if (word[0] == '#')
			continue;

		name = strtok(line, SPC);
		if (name == NULL)
			continue;

		(void) dprintf(DBG_INFO, "get a line for %s\n", name);
		key = strtok(NULL, "=");
		if (key == NULL) {
			(void) dprintf(DBG_INFO, "no attributes specified for "
			    "%s\n", name);
			continue;
		}

		attrs = NULL;
		if (nvlist_alloc(&attrs, NV_UNIQUE_NAME, 0) != 0) {
			error = EFAULT;
			goto fail1;
		}

		while (key && *key) {
			char *rest;
			rest = strtok(NULL, "\n");
			if (rest == NULL) {
				(void) dprintf(DBG_INFO, "no value for key "
				    "%s\n", key);
				break;
			}
			if (rest[0] == ';') {
				val = strdup("devname_null");
				rest++;
			} else {
				val = strtok(rest, ";");
				rest = strtok(NULL, "");
			}
			(void) dprintf(DBG_INFO, "parse_map_info: one entry "
			    "key=%s val=%s\n", key, val);
			if (nvlist_add_string(attrs, key, val) != 0) {
				error = EFAULT;
				goto fail;
			}

			key = strtok(rest, "=");
		}
		(void) dprintf(DBG_INFO, "parse_map_info: add entry name=%s\n",
		    name);
		if (nvlist_add_nvlist(nvl, name, attrs) != 0) {
			error = EFAULT;
			goto fail;
		}
	}

done:
	*ret_nvlp = nvl;
	return (0);

fail:
	nvlist_free(attrs);
fail1:
	nvlist_free(nvl);
	return (error);
}

void
di_devname_print_mapinfo(nvlist_t *nvl)
{
	char *name, *key, *val;
	nvlist_t *attrs;
	nvpair_t *nvp, *kvp;

	nvp = nvlist_next_nvpair(nvl, NULL);
	while (nvp) {
		name = nvpair_name(nvp);
		(void) nvpair_value_nvlist(nvp, &attrs);
		(void) printf("name = %s, binding attributes:\n", name);
		kvp = nvlist_next_nvpair(attrs, NULL);
		while (kvp) {
			key = nvpair_name(kvp);
			(void) nvpair_value_string(kvp, &val);
			(void) printf("\t%s = %s\n", key, val);
			kvp = nvlist_next_nvpair(attrs, kvp);
		}
		nvp = nvlist_next_nvpair(nvl, nvp);
	}
}

static int
action_mklink(char *target, char *source)
{
	(void) dprintf(DBG_INFO, "mklink for source %s target %s\n",
	    source, target);
	return (symlink(source, target));
}

static struct actions {
	char *key;
	devname_spec_t spec;
	int (*action)(char *, char *);
} actions[] = {
	{"devices-path", DEVNAME_NS_PATH, action_mklink},
	{"dev-path", DEVNAME_NS_DEV, action_mklink},
	{NULL, DEVNAME_NS_NONE, NULL}
};

static int
action_on_key(uint_t cmd, char *dir_name, char *devname, nvpair_t *attr,
    uint32_t  *nsmapcount, char **devfsadm_link, devname_spec_t *devfsadm_spec)
{
	int i = 0;
	int error = 0;
	char *attrname, *attrval;
	int len = 0;
	char *path = NULL;

	attrname = nvpair_name(attr);
	(void) nvpair_value_string(attr, &attrval);
	(void) dprintf(DBG_INFO, "key = %s; value = %s\n", attrname, attrval);

	while (actions[i].key) {
		if (strcmp(actions[i].key, attrname) == 0) {
			switch (cmd) {
			case DEVFSADMD_NS_READDIR:
				len = strlen(dir_name) + strlen(devname) + 2;
				path = malloc(len);
				(void) snprintf(path, len, "%s/%s", dir_name,
				    devname);
				error = actions[i].action(path, attrval);
				free(path);
				if (error) {
					(void) dprintf(DBG_INFO, "action "
					    "failed %d\n", error);
					return (error);
				} else {
					(*nsmapcount)++;
					(void) dprintf(DBG_INFO,
					    "mapcount %d\n", *nsmapcount);
				}
				break;
			case DEVFSADMD_NS_LOOKUP:
				*devfsadm_link = strdup(attrval);
				*devfsadm_spec = actions[i].spec;
				break;
			default:
				break;
			}
		}
		i++;
	}
	return (0);
}

int
di_devname_action_on_key(nvlist_t *map, uint8_t cmd, char *dir_name, void *hdl)
{
	char *name = NULL;
	nvpair_t *entry;
	nvlist_t *attrs;
	int32_t error = 0;
	uint32_t ns_mapcount = 0;
	char *devfsadm_link = NULL;
	devname_spec_t devfsadm_spec = DEVNAME_NS_NONE;
	sdev_door_res_t *resp;

	entry = nvlist_next_nvpair(map, NULL);
	while (entry) {
		nvpair_t *attr;
		name = nvpair_name(entry);
		(void) dprintf(DBG_INFO, "di_devname_action_on_key: name %s\n",
		    name);
		(void) nvpair_value_nvlist(entry, &attrs);

		attr = nvlist_next_nvpair(attrs, NULL);
		while (attr) {
			error = action_on_key(cmd, dir_name, name, attr,
			    &ns_mapcount, &devfsadm_link, &devfsadm_spec);

			/* do not continue if encountered the first error */
			if (error) {
				(void) dprintf(DBG_INFO, "error %d\n", error);
				return ((int32_t)error);
			}
			attr = nvlist_next_nvpair(attrs, attr);
		}
		entry = nvlist_next_nvpair(map, entry);
	}

	resp = (sdev_door_res_t *)hdl;
	(void) dprintf(DBG_INFO, "cmd is %d\n", cmd);
	switch (cmd) {
	case DEVFSADMD_NS_READDIR:
		resp->ns_rdr_hdl.ns_mapcount = (uint32_t)ns_mapcount;
		(void) dprintf(DBG_INFO, "mapcount is %d\n", ns_mapcount);
		break;
	case DEVFSADMD_NS_LOOKUP:
		if (devfsadm_link && devfsadm_spec != DEVNAME_NS_NONE) {
			(void) dprintf(DBG_INFO, "devfsadm_link is %s\n",
			    devfsadm_link);
			(void) snprintf(resp->ns_lkp_hdl.devfsadm_link,
			    strlen(devfsadm_link) + 1, "%s", devfsadm_link);
			resp->ns_lkp_hdl.devfsadm_spec = devfsadm_spec;
		} else {
			(void) dprintf(DBG_INFO, "error out\n");
			return (1);
		}
		break;
	default:
		(void) dprintf(DBG_INFO, "error NOTSUP out\n");
		return (ENOTSUP);
	}

	return (0);
}


static nvlist_t *
getent_mapinfo_file(FILE *fp, char *match)
{
	nvlist_t *nvl, *attrs;
	char line[LINEMAX], lineq[LINEMAX];
	char word[MAXPATHLEN+1], wordq[MAXPATHLEN+1];
	int count = 0;
	char *lp, *lq;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		return (NULL);

	while (fgets(line, sizeof (line), fp)) {
		char *name, *key, *val;

		if (line[0] == '#')
			continue;

		dprintf(DBG_INFO, "getent_mapinfo_file: get a line %s\n", line);
		lp = (char *)line;
		lq = (char *)lineq;
		unquote(lp, lq);
		if ((getword(word, wordq, &lp, &lq, ' ', sizeof (word))
			== -1) || (word[0] == '\0'))
			continue;

		name = strtok(line, SPC);
		if (name == NULL)
			continue;

		dprintf(DBG_INFO, "macthing with the key %s match %s\n",
		    name, match);
		/* bypass the non-related entries */
		if (strcmp(name, match) != 0)
			continue;

		/* get a matched entry */
		key = strtok(NULL, "=");
		if (key == NULL) {
			(void) dprintf(DBG_INFO, "no attributes specified "
			    "for %s\n", name);
			goto fail1;
		}

		attrs = NULL;
		if (nvlist_alloc(&attrs, NV_UNIQUE_NAME, 0) != 0)
			goto fail1;
		while (key && *key) {
			char *rest;
			rest = strtok(NULL, "\n");
			if (rest == NULL) {
				(void) dprintf(DBG_INFO, "no value for key "
				    "%s\n", key);
				goto fail;
			}
			if (rest[0] == ';') {
				val = strdup("devname_null");
				rest++;
			} else {
				val = strtok(rest, ";");
				rest = strtok(NULL, "");
			}
			(void) dprintf(DBG_INFO, "found entry %s %s for %s\n",
			    key, val, name);
			if (nvlist_add_string(attrs, key, val) != 0)
				goto fail;

			key = strtok(rest, "=");
		}
		(void) dprintf(DBG_INFO, "adding nvlist for %s\n", name);
		if (nvlist_add_nvlist(nvl, name, attrs) != 0)
			goto fail;
		count++;
		break;
	}

	if (count == 0)
		goto fail1;

	return (nvl);

fail:
	nvlist_free(attrs);
fail1:
	nvlist_free(nvl);
	errno = EFAULT;
	return (NULL);
}

static int
di_devname_getmapent_files(char *key, char *mapname, nvlist_t **map)
{
	FILE *fp;
	int rval = 0;
	nvlist_t *nvl = NULL;

	fp = open_local_map(mapname);
	if (fp == NULL)
		return (1);

	nvl = getent_mapinfo_file(fp, key);
	if (nvl != NULL) {
		*map = nvl;
	} else {
		rval = errno;
	}
	(void) fclose(fp);

	return (rval);
}

int
di_devname_get_mapent(char *key, char *mapname, nvlist_t **map)
{
	dprintf(DBG_INFO, "di_devname_get_mapent: called for %s in %s\n",
	    key, mapname);

	return (di_devname_getmapent_files(key, mapname, map));

}

int
di_devname_get_mapinfo(char *mapname, nvlist_t **maps)
{
	dprintf(DBG_INFO, "di_devname_get_mapinfo: called for %s\n", mapname);

	return (di_devname_get_mapinfo_files(mapname, maps));
}

static void
debug_print(debug_level_t msglevel, const char *fmt, va_list ap)
{
	if (devname_debug < msglevel)
		return;

	/* Print a distinctive label for error msgs */
	if (msglevel == DBG_ERR) {
		(void) fprintf(stderr, "[ERROR]: ");
	}

	if (msglog == TRUE) {
		(void) vsyslog(LOG_NOTICE, fmt, ap);
	} else {
		(void) vfprintf(stderr, fmt, ap);
	}
}

/* ARGSUSED */
/* PRINTFLIKE2 */
static void
dprintf(debug_level_t msglevel, const char *fmt, ...)
{
	va_list ap;

	assert(msglevel > 0);

	if (!devname_debug)
		return;

	va_start(ap, fmt);
	debug_print(msglevel, fmt, ap);
	va_end(ap);
}


/*
 * Private interfaces for non-global /dev profile
 */

/*
 * Allocate opaque data structure for passing profile to the kernel for
 * the given mount point.
 *
 * Note that this interface returns an empty, initialized, profile.
 * It does not return what may have been previously committed.
 */
int
di_prof_init(const char *mountpt, di_prof_t *profp)
{
	nvlist_t	*nvl;

	if (nvlist_alloc(&nvl, 0, 0))
		return (-1);

	if (nvlist_add_string(nvl, SDEV_NVNAME_MOUNTPT, mountpt)) {
		nvlist_free(nvl);
		return (-1);
	}

	*profp = (di_prof_t)nvl;
	return (0);
}

/*
 * Free space allocated by di_prof_init().
 */
void
di_prof_fini(di_prof_t prof)
{
	nvlist_free((nvlist_t *)prof);
}

/*
 * Sends profile to the kernel.
 */
int
di_prof_commit(di_prof_t prof)
{
	char	*buf = NULL;
	size_t	buflen = 0;
	int	rv;

	if (nvlist_pack((nvlist_t *)prof, &buf, &buflen, NV_ENCODE_NATIVE, 0))
		return (-1);
	rv = modctl(MODDEVNAME, MODDEVNAME_PROFILE, buf, buflen);
	free(buf);
	return (rv);
}

/*
 * Add a device or directory to profile's include list.
 *
 * Note that there is no arbitration between conflicting
 * include and exclude profile entries, most recent
 * is the winner.
 */
int
di_prof_add_dev(di_prof_t prof, const char *dev)
{
	if (nvlist_add_string((nvlist_t *)prof, SDEV_NVNAME_INCLUDE, dev))
		return (-1);
	return (0);
}

/*
 * Add a device or directory to profile's exclude list.
 * This can effectively remove a previously committed device.
 */
int
di_prof_add_exclude(di_prof_t prof, const char *dev)
{
	if (nvlist_add_string((nvlist_t *)prof, SDEV_NVNAME_EXCLUDE, dev))
		return (-1);
	return (0);
}

/*
 * Add a symlink to profile.
 */
int
di_prof_add_symlink(di_prof_t prof, const char *linkname, const char *target)
{
	nvlist_t	*nvl = (nvlist_t *)prof;
	char		*syml[2];

	syml[0] = (char *)linkname;	/* 1st entry must be the symlink */
	syml[1] = (char *)target;	/* 2nd entry must be the target */
	if (nvlist_add_string_array(nvl, SDEV_NVNAME_SYMLINK, syml, 2))
		return (-1);
	return (0);
}

/*
 * Add a name mapping to profile.
 */
int
di_prof_add_map(di_prof_t prof, const char *source, const char *target)
{
	nvlist_t	*nvl = (nvlist_t *)prof;
	char		*map[2];

	map[0] = (char *)source;	/* 1st entry must be the source */
	map[1] = (char *)target;	/* 2nd entry must be the target */
	if (nvlist_add_string_array(nvl, SDEV_NVNAME_MAP, map, 2))
		return (-1);
	return (0);
}
