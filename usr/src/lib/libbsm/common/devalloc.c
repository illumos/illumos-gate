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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>
#include <synch.h>
#include <strings.h>
#include <string.h>
#include <libintl.h>
#include <errno.h>
#include <auth_list.h>
#include <syslog.h>
#include <bsm/devices.h>
#include <bsm/devalloc.h>
#include <tsol/label.h>

#define	DA_DEFS	"/etc/security/tsol/devalloc_defaults"

extern int _readbufline(char *, int, char *, int, int *);
extern char *strtok_r(char *, const char *, char **);
extern char *_strtok_escape(char *, char *, char **);
extern int getdaon(void);
extern int da_matchname(devalloc_t *, char *);
extern int da_match(devalloc_t *, da_args *);
extern int dmap_matchname(devmap_t *, char *);
extern int dm_match(devmap_t *, da_args *);
extern int dmap_matchtype(devmap_t *dmap, char *type);
extern int dmap_matchdev(devmap_t *dmap, char *dev);
extern int dmap_exact_dev(devmap_t *dmap, char *dev, int *num);
extern char *dmap_physname(devmap_t *dmap);

/*
 * The following structure is for recording old entries to be retained.
 * We read the entries from the database into a linked list in memory,
 * then turn around and write them out again.
 */
typedef struct strentry {
	struct strentry	*se_next;
	char		se_str[4096 + 1];
} strentry_t;

/*
 * da_check_longindevperm -
 *	reads /etc/logindevperm and checks if specified device is in the file.
 *	returns 1 if specified device found in /etc/logindevperm, else returns 0
 */
int
da_check_logindevperm(char *devname)
{
	int		ret = 0;
	int		fd = -1;
	int		nlen, plen, slen, lineno, fsize;
	char		line[MAX_CANON];
	char		*field_delims = " \t\n";
	char		*fbuf = NULL;
	char		*ptr, *device;
	char		*lasts = NULL;
	FILE		*fp;
	struct stat	f_stat;

	/*
	 * check if /etc/logindevperm exists and get its size
	 */
	if ((fd = open(LOGINDEVPERM, O_RDONLY)) == -1)
		return (0);
	if (fstat(fd, &f_stat) != 0) {
		(void) close(fd);
		return (0);
	}
	fsize = f_stat.st_size;
	if ((fbuf = (char *)malloc(fsize)) == NULL) {
		(void) close(fd);
		return (0);
	}
	if ((fp = fdopen(fd, "rF")) == NULL) {
		free(fbuf);
		(void) close(fd);
		return (0);
	}

	/*
	 * read and parse /etc/logindevperm
	 */
	plen = nlen = lineno = 0;
	while (fgets(line, MAX_CANON, fp) != NULL) {
		lineno++;
		if ((ptr = strchr(line, '#')) != NULL)
			*ptr = '\0';	/* handle comments */
		if (strtok_r(line, field_delims, &lasts) == NULL)
			continue;	/* ignore blank lines */
		if (strtok_r(NULL, field_delims, &lasts) == NULL)
			/* invalid entry */
			continue;
		if ((ptr = strtok_r(NULL, field_delims, &lasts)) == NULL)
			/* empty device list */
			continue;
		nlen = strlen(ptr) + 1;		/* +1 terminator */
		nlen += (plen + 1);
		if (plen == 0)
			slen = snprintf(fbuf, nlen, "%s", ptr);
		else
			slen = snprintf(fbuf + plen, nlen - plen, ":%s", ptr);
		if (slen >= fsize) {
			fbuf[0] = '\0';
			(void) fclose(fp);
			return (slen);
		}
		plen += slen;
	}
	(void) fclose(fp);

	/*
	 * check if devname exists in /etc/logindevperm
	 */
	device = strtok_r(fbuf, ":", &lasts);
	while (device != NULL) {
		/*
		 * device and devname may be one of these types -
		 *    /dev/xx
		 *    /dev/xx*
		 *    /dev/dir/xx
		 *    /dev/dir/xx*
		 *    /dev/dir/"*"
		 */
		if (strcmp(device, devname) == 0) {
			/* /dev/xx, /dev/dir/xx */
			free(fbuf);
			return (1);
		}
		if ((ptr = strrchr(device, KV_WILDCHAR)) != NULL) {
			/* all wildcard types */
			*ptr = '\0';
			if (strncmp(device, devname, strlen(device)) == 0) {
				free(fbuf);
				return (1);
			}
		}
		device = strtok_r(NULL, ":", &lasts);
	}

	return (ret);
}

/*
 * _da_read_file -
 *	establishes readers/writer lock on fname; reads in the file if its
 *	contents changed since the last time we read it.
 *	returns size of buffer read, or -1 on failure.
 */
int
_da_read_file(char *fname, char **fbuf, time_t *ftime, rwlock_t *flock,
    int flag)
{
	int		fd = -1;
	int		fsize = 0;
	time_t		newtime;
	struct stat	f_stat;

	if (flag & DA_FORCE)
		*ftime = 0;

	/* check the size and the time stamp on the file */
	if (rw_rdlock(flock) != 0)
		return (-1);
	if (stat(fname, &f_stat) != 0) {
		(void) rw_unlock(flock);
		return (-1);
	}
	fsize = f_stat.st_size;
	newtime = f_stat.st_mtime;
	(void) rw_unlock(flock);

	while (newtime > *ftime) {
		/*
		 * file has been modified since we last read it; or this
		 * is a forced read.
		 * read file into the buffer with rw lock.
		 */
		if (rw_wrlock(flock) != 0)
			return (-1);
		if ((fd = open(fname, O_RDONLY)) == -1) {
			(void) rw_unlock(flock);
			return (-1);
		}
		if (*fbuf != NULL) {
			free(*fbuf);
			*fbuf = NULL;
		}
		if ((*fbuf = malloc(fsize)) == NULL) {
			(void) rw_unlock(flock);
			(void) close(fd);
			return (-1);
		}
		if (read(fd, *fbuf, fsize) < fsize) {
			free(*fbuf);
			(void) rw_unlock(flock);
			(void) close(fd);
			return (-1);
		}
		(void) rw_unlock(flock);
		/*
		 * verify that the file did not change just after we read it.
		 */
		if (rw_rdlock(flock) != 0) {
			free(*fbuf);
			(void) close(fd);
			return (-1);
		}
		if (stat(fname, &f_stat) != 0) {
			free(*fbuf);
			(void) rw_unlock(flock);
			(void) close(fd);
			return (-1);
		}
		fsize = f_stat.st_size;
		newtime = f_stat.st_mtime;
		(void) rw_unlock(flock);
		(void) close(fd);
		*ftime = newtime;
	}

	return (fsize);
}

/*
 * _update_zonename -
 *	add/remove current zone's name to the given devalloc_t.
 */
void
_update_zonename(da_args *dargs, devalloc_t *dap)
{
	int		i, j;
	int		oldsize, newsize;
	int		has_zonename = 0;
	char		*zonename;
	kva_t		*newkva, *oldkva;
	kv_t		*newdata, *olddata;
	devinfo_t	*devinfo;

	devinfo = dargs->devinfo;
	oldkva = dap->da_devopts;
	if (oldkva == NULL) {
		if (dargs->optflag & DA_REMOVE_ZONE)
			return;
		if (dargs->optflag & DA_ADD_ZONE) {
			newkva = _str2kva(devinfo->devopts, KV_ASSIGN,
			    KV_TOKEN_DELIMIT);
			if (newkva != NULL)
				dap->da_devopts = newkva;
			return;
		}
	}
	newsize = oldsize = oldkva->length;
	if (kva_match(oldkva, DAOPT_ZONE))
		has_zonename = 1;
	if (dargs->optflag & DA_ADD_ZONE) {
		if ((zonename = index(devinfo->devopts, '=')) == NULL)
			return;
		zonename++;
		if (has_zonename) {
			(void) _insert2kva(oldkva, DAOPT_ZONE, zonename);
			return;
		}
		newsize += 1;
	} else if (dargs->optflag & DA_REMOVE_ZONE) {
		if (has_zonename) {
			newsize -= 1;
			if (newsize == 0) {
				/*
				 * If zone name was the only key/value pair,
				 * put 'reserved' in the empty slot.
				 */
				_kva_free(oldkva);
				dap->da_devopts = NULL;
				return;
			}
		} else {
			return;
		}
	}
	newkva = _new_kva(newsize);
	newkva->length = 0;
	newdata = newkva->data;
	olddata = oldkva->data;
	for (i = 0, j = 0; i < oldsize; i++) {
		if ((dargs->optflag & DA_REMOVE_ZONE) &&
		    (strcmp(olddata[i].key, DAOPT_ZONE) == 0))
			continue;
		newdata[j].key = strdup(olddata[i].key);
		newdata[j].value = strdup(olddata[i].value);
		newkva->length++;
		j++;
	}
	if (dargs->optflag & DA_ADD_ZONE) {
		newdata[j].key = strdup(DAOPT_ZONE);
		newdata[j].value = strdup(zonename);
		newkva->length++;
	}
	_kva_free(oldkva);
	dap->da_devopts = newkva;
}

/*
 * _dmap2str -
 *	converts a device_map entry into a printable string
 *	returns 0 on success, -1 on error.
 */
/*ARGSUSED*/
static int
_dmap2str(devmap_t *dmp, char *buf, int size, const char *sep)
{
	int	length;

	length = snprintf(buf, size, "%s%s", dmp->dmap_devname, sep);
	if (length >= size)
		return (-1);
	length += snprintf(buf + length, size - length, "%s%s",
	    dmp->dmap_devtype, sep);
	if (length >= size)
		return (-1);
	length += snprintf(buf + length, size - length, "%s\n",
	    dmp->dmap_devlist);
	if (length >= size)
		return (-1);
	return (0);
}

/*
 * _dmap2strentry -
 *	calls dmap2str to break given devmap_t into printable entry.
 *	returns pointer to decoded entry, NULL on error.
 */
static strentry_t *
_dmap2strentry(devmap_t *devmapp)
{
	strentry_t	*sep;

	if ((sep = (strentry_t *)malloc(sizeof (strentry_t))) == NULL)
		return (NULL);
	if (_dmap2str(devmapp, sep->se_str, sizeof (sep->se_str),
	    KV_TOKEN_DELIMIT"\\\n\t") != 0) {
		free(sep);
		return (NULL);
	}
	return (sep);
}

/*
 * fix_optstr -
 * 	removes trailing ':' from buf.
 */
void
fix_optstr(char *buf)
{
	char	*p = NULL;

	if (p = rindex(buf, ':'))
		*p = ';';
}

/*
 * _da2str -
 *	converts a device_allocate entry into a printable string
 *	returns 0 on success, -1 on error.
 */
static int
_da2str(da_args *dargs, devalloc_t *dap, char *buf, int size, const char *sep,
    const char *osep)
{
	int	length;
	int	matching_entry = 0;
	char	**dnames;

	if (dargs->optflag & DA_UPDATE &&
	    (dargs->optflag & DA_ADD_ZONE ||
	    dargs->optflag & DA_REMOVE_ZONE) &&
	    dargs->devnames) {
		for (dnames = dargs->devnames; *dnames != NULL; dnames++) {
			if (da_matchname(dap, *dnames)) {
				matching_entry = 1;
				break;
			}
		}
	}
	length = snprintf(buf, size, "%s%s", dap->da_devname, sep);
	if (length >= size)
		return (-1);
	length += snprintf(buf + length, size - length, "%s%s",
	    dap->da_devtype, sep);
	if (length >= size)
		return (-1);
	if (matching_entry)
		_update_zonename(dargs, dap);
	if ((dap->da_devopts == NULL) || ((dap->da_devopts->length == 1) &&
	    (strcmp(dap->da_devopts->data->key, DA_RESERVED) == 0))) {
		length += snprintf(buf + length, size - length, "%s%s",
		    DA_RESERVED, sep);
	} else {
		if (_kva2str(dap->da_devopts, buf + length, size - length,
		    KV_ASSIGN, (char *)osep) != 0)
			return (-1);
		length = strlen(buf);
	}
	if (dap->da_devopts)
		fix_optstr(buf);
	if (length >= size)
		return (-1);
	length += snprintf(buf + length, size - length, "%s%s",
	    DA_RESERVED, sep);
	if (length >= size)
		return (-1);
	length += snprintf(buf + length, size - length, "%s%s",
	    dap->da_devauth ? dap->da_devauth : DA_ANYUSER, sep);
	if (length >= size)
		return (-1);
	length += snprintf(buf + length, size - length, "%s\n",
	    dap->da_devexec ? dap->da_devexec : "");
	if (length >= size)
		return (-1);

	return (0);
}

/*
 * _da2strentry -
 *	calls da2str to break given devalloc_t into printable entry.
 *	returns pointer to decoded entry, NULL on error.
 */
static strentry_t *
_da2strentry(da_args *dargs, devalloc_t *dap)
{
	strentry_t	*sep;

	if ((sep = (strentry_t *)malloc(sizeof (strentry_t))) == NULL)
		return (NULL);
	if (_da2str(dargs, dap, sep->se_str, sizeof (sep->se_str),
	    KV_DELIMITER "\\\n\t", KV_TOKEN_DELIMIT "\\\n\t") != 0) {
		free(sep);
		return (NULL);
	}
	return (sep);
}

/*
 * _def2str
 *	converts da_defs_t into a printable string.
 *	returns 0 on success, -1 on error.
 */
static int
_def2str(da_defs_t *da_defs, char *buf, int size, const char *sep)
{
	int length;

	length = snprintf(buf, size, "%s%s", da_defs->devtype, sep);
	if (length >= size)
		return (-1);
	if (da_defs->devopts) {
		if (_kva2str(da_defs->devopts, buf + length, size - length,
		    KV_ASSIGN, KV_DELIMITER) != 0)
			return (-1);
		length = strlen(buf);
	}
	if (length >= size)
		return (-1);

	return (0);
}

/*
 * _def2strentry
 *	calls _def2str to break given da_defs_t into printable entry.
 *	returns pointer decoded entry, NULL on error.
 */
static strentry_t *
_def2strentry(da_defs_t *da_defs)
{
	strentry_t	*sep;

	if ((sep = (strentry_t *)malloc(sizeof (strentry_t))) == NULL)
		return (NULL);
	if (_def2str(da_defs, sep->se_str, sizeof (sep->se_str),
	    KV_TOKEN_DELIMIT) != 0) {
		free(sep);
		return (NULL);
	}

	return (sep);
}

/*
 * _build_defattrs
 *	cycles through all defattr entries, stores them in memory. removes
 *	entries with the given search_key (device type).
 *	returns 0 if given entry not found, 1 if given entry removed, 2 on
 *	error.
 */
static int
_build_defattrs(da_args *dargs, strentry_t **head_defent)
{
	int		rc = 0;
	da_defs_t	*da_defs;
	strentry_t	*tail_str, *tmp_str;

	setdadefent();
	while ((da_defs = getdadefent()) != NULL) {
		rc = !(strcmp(da_defs->devtype, dargs->devinfo->devtype));
		if (rc && dargs->optflag & DA_ADD &&
		    !(dargs->optflag & DA_FORCE)) {
			/*
			 * During DA_ADD, we keep an existing entry unless
			 * we have DA_FORCE set to override that entry.
			 */
			dargs->optflag |= DA_NO_OVERRIDE;
			rc = 0;
		}
		if (rc == 0) {
			tmp_str = _def2strentry(da_defs);
			if (tmp_str == NULL) {
				freedadefent(da_defs);
				enddadefent();
				return (2);
			}
			/* retaining defattr entry: tmp_str->se_str */
			tmp_str->se_next = NULL;
			if (*head_defent == NULL) {
				*head_defent = tail_str = tmp_str;
			} else {
				tail_str->se_next = tmp_str;
				tail_str = tmp_str;
			}
		}
		freedadefent(da_defs);
	}
	enddadefent();

	return (rc);
}

/*
 * We have to handle the "standard" types in devlist differently than
 * other devices, which are not covered by our auto-naming conventions.
 *
 * buf must be a buffer of size DA_MAX_NAME + 1
 */
int
da_std_type(da_args *dargs, char *namebuf)
{
	char *type = dargs->devinfo->devtype;
	int system_labeled;

	system_labeled = is_system_labeled();

	/* check safely for sizes */
	if (strcmp(DA_AUDIO_TYPE, type) == 0) {
		(void) strlcpy(namebuf, DA_AUDIO_NAME, DA_MAXNAME);
		return (1);
	}
	if (strcmp(DA_CD_TYPE, type) == 0) {
		if (system_labeled)
			(void) strlcpy(namebuf, DA_CD_NAME, DA_MAXNAME);
		else
			(void) strlcpy(namebuf, DA_CD_TYPE, DA_MAXNAME);
		return (1);
	}
	if (strcmp(DA_FLOPPY_TYPE, type) == 0) {
		if (system_labeled)
			(void) strlcpy(namebuf, DA_FLOPPY_NAME, DA_MAXNAME);
		else
			(void) strlcpy(namebuf, DA_FLOPPY_TYPE, DA_MAXNAME);
		return (1);
	}
	if (strcmp(DA_TAPE_TYPE, type) == 0) {
		if (system_labeled)
			(void) strlcpy(namebuf, DA_TAPE_NAME, DA_MAXNAME);
		else
			(void) strlcpy(namebuf, DA_TAPE_TYPE, DA_MAXNAME);
		return (1);
	}
	if (strcmp(DA_RMDISK_TYPE, type) == 0) {
		(void) strlcpy(namebuf, DA_RMDISK_NAME, DA_MAXNAME);
		return (1);
	}
	namebuf[0] = '\0';
	return (0);
}

/*
 * allocatable: returns
 * -1 if no auths field,
 * 0 if not allocatable (marked '*')
 * 1 if not marked '*'
 */
static int
allocatable(da_args *dargs)
{

	if (!dargs->devinfo->devauths)
		return (-1);
	if (strcmp("*", dargs->devinfo->devauths) == 0)
		return (0);
	return (1);
}

/*
 * _rebuild_lists -
 *
 *	If dargs->optflag & DA_EVENT, does not assume the dargs list is
 *	complete or completely believable, since devfsadm caches
 *	ONLY what it has been exposed to via syseventd.
 *
 *	Cycles through all the entries in the /etc files, stores them
 *	in memory, takes note of device->dname numbers (e.g. rmdisk0,
 *	rmdisk12)
 *
 *	Cycles through again, adds dargs entry
 *	with the name tname%d (lowest unused number for the device type)
 *	to the list of things for the caller to write out to a file,
 *	IFF it is a new entry.
 *
 *	It is an error for it to already be there, if it is allocatable.
 *
 *	Add:
 *	    Returns 0 if successful and 2 on error.
 *	Remove:
 *	    Returns 0 if not found, 1 if found,  2 on error.
 */
static int
_rebuild_lists(da_args *dargs, strentry_t **head_devallocp,
    strentry_t **head_devmapp)
{
	int		rc = 0;
	devalloc_t	*devallocp;
	devmap_t	*devmapp;
	strentry_t	*tail_str;
	strentry_t	*tmp_str;
	uint64_t	tmp_bitmap = 0;
	uint_t		tmp = 0;
	char		*realname;
	int		suffix;
	int		found = 0;
	int		stdtype = 1;
	int		is_allocatable = 1;
	char		new_devname[DA_MAXNAME + 1];
	char		defname[DA_MAXNAME + 1]; /* default name for type */
	char		errmsg[DA_MAXNAME + 1 + (PATH_MAX * 2) + 80];

	if (dargs->optflag & (DA_MAPS_ONLY | DA_ALLOC_ONLY))
		return (2);

	if (dargs->optflag & DA_FORCE)
		return (2);

	if (dargs->optflag & DA_ADD) {
		stdtype = da_std_type(dargs, defname);
		is_allocatable = allocatable(dargs);
	}

	/* read both files, maps first so we can compare actual devices */

	/* build device_maps */
	setdmapent();
	while ((devmapp = getdmapent()) != NULL) {
		suffix = DA_MAX_DEVNO + 1;
		if ((rc = dmap_matchtype(devmapp, dargs->devinfo->devtype))
		    == 1) {
			if (dargs->optflag & DA_REMOVE) {
				if ((devmapp->dmap_devarray == NULL) ||
				    (devmapp->dmap_devarray[0] == NULL)) {
					freedmapent(devmapp);
					enddmapent();
					return (2);
				}
				realname = dmap_physname(devmapp);
				if (realname == NULL) {
					freedmapent(devmapp);
					enddmapent();
					return (2);
				}
				if (strstr(realname, dargs->devinfo->devlist)
				    != NULL) {
					/* if need to free and safe to free */
					if (dargs->devinfo->devname != NULL &&
					    (dargs->optflag & DA_EVENT) != 0)
						free(dargs->devinfo->devname);
					dargs->devinfo->devname =
					    strdup(devmapp->dmap_devname);
					found = 1;
					freedmapent(devmapp);
					continue; /* don't retain */
				}
			} else if (dargs->optflag & DA_ADD) {
				/*
				 * Need to know which suffixes are in use
				 */
				rc = (dmap_exact_dev(devmapp,
				    dargs->devinfo->devlist, &suffix));

				if (rc == 0) {
					/*
					 * Same type, different device.  Record
					 * device suffix already in use, if
					 * applicable.
					 */
					if ((suffix < DA_MAX_DEVNO &&
					    suffix != -1) && stdtype)
						tmp_bitmap |=
						    (uint64_t)(1LL << suffix);
				} else if ((rc == 1) && !is_allocatable) {
					rc = 0;
				} else {
					/*
					 * Match allocatable on add is an error
					 * or mapping attempt returned error
					 */
					(void) snprintf(errmsg, sizeof (errmsg),
					    "Cannot add %s on node %s",
					    dargs->devinfo->devtype,
					    devmapp->dmap_devname);
					syslog(LOG_ERR, "%s", errmsg);
					freedmapent(devmapp);
					enddmapent();
					return (2);
				}
			} else
				/* add other transaction types as needed */
				return (2);
		} else if ((dargs->optflag & DA_ADD) &&
		    (stdtype || is_allocatable) &&
		    dmap_exact_dev(devmapp, dargs->devinfo->devlist,
		    &suffix)) {
			/*
			 * no dups w/o DA_FORCE, even if type differs,
			 * if there is a chance this operation is
			 * machine-driven.  The 5 "standard types"
			 * can be machine-driven adds, and tend to
			 * be allocatable.
			 */
			(void) snprintf(errmsg, sizeof (errmsg),
			    "Cannot add %s on node %s type %s",
			    dargs->devinfo->devtype,
			    devmapp->dmap_devname,
			    devmapp->dmap_devtype);
			syslog(LOG_ERR, "%s", errmsg);
			freedmapent(devmapp);
			enddmapent();
			return (2);
		}

		tmp_str = _dmap2strentry(devmapp);
		if (tmp_str == NULL) {
			freedmapent(devmapp);
			enddmapent();
			return (2);
		}
		/* retaining devmap entry: tmp_str->se_str */
		tmp_str->se_next = NULL;
		if (*head_devmapp == NULL) {
			*head_devmapp = tail_str = tmp_str;
		} else {
			tail_str->se_next = tmp_str;
			tail_str = tmp_str;
		}
		freedmapent(devmapp);
	}
	enddmapent();

	/*
	 * No need to rewrite the files if the item to be removed is not
	 * in the files -- wait for another call on another darg.
	 */
	if ((dargs->optflag & DA_REMOVE) && !found)
		return (0);


	if (dargs->optflag & DA_ADD) {
		int len;
		/*
		 * If we got here from an event, or from devfsadm,
		 * we know the stored devname is a useless guess,
		 * since the files had not been read when the name
		 * was chosen, and we don't keep them anywhere else
		 * that is sufficiently definitive.
		 */

		for (tmp = 0; tmp <= DA_MAX_DEVNO; tmp++)
			if (!(tmp_bitmap & (1LL << tmp)))
				break;
		/* Future: support more than 64 hotplug devices per type? */
		if (tmp > DA_MAX_DEVNO)
			return (2);

		/*
		 * Let the caller choose the name unless BOTH the name and
		 * device type one of: cdrom, floppy, audio, rmdisk, or tape.
		 * (or sr, fd for unlabeled)
		 */
		len = strlen(defname);
		if (stdtype &&
		    (strncmp(dargs->devinfo->devname, defname, len) == 0)) {
			(void) snprintf(new_devname, DA_MAXNAME + 1, "%s%u",
			    defname, tmp);
			/* if need to free and safe to free */
			if (dargs->devinfo->devname != NULL &&
			    (dargs->optflag & DA_EVENT) != 0)
				free(dargs->devinfo->devname);
			dargs->devinfo->devname = strdup(new_devname);
		}
	}

	/*
	 * Now adjust devalloc list to match devmaps
	 * Note we now have the correct devname for da_match to use.
	 */
	setdaent();
	while ((devallocp = getdaent()) != NULL) {
		rc = da_match(devallocp, dargs);
		if (rc == 1) {
			if (dargs->optflag & DA_ADD) {
				/* logging is on if DA_EVENT is set */
				if (dargs->optflag & DA_EVENT) {
					(void) snprintf(errmsg, sizeof (errmsg),
					    "%s and %s out of sync,"
					    "%s only in %s.",
					    DEVALLOC, DEVMAP,
					    devallocp->da_devname, DEVALLOC);
					syslog(LOG_ERR, "%s", errmsg);
				}
				freedaent(devallocp);
				enddaent();
				return (2);
			} else if (dargs->optflag & DA_REMOVE) {
				/* make list w/o this entry */
				freedaent(devallocp);
				continue;
			}
		}
		tmp_str = _da2strentry(dargs, devallocp);
		if (tmp_str == NULL) {
			freedaent(devallocp);
			enddaent();
			return (2);
		}
		/* retaining devalloc entry: tmp_str->se_str */
		tmp_str->se_next = NULL;
		if (*head_devallocp == NULL) {
			*head_devallocp = tail_str = tmp_str;
		} else {
			tail_str->se_next = tmp_str;
			tail_str = tmp_str;
		}
		freedaent(devallocp);
	}
	enddaent();

	/* the caller needs to know if a remove needs to rewrite files */
	if (dargs->optflag & DA_REMOVE)
		return (1);  /* 0 and 2 cases returned earlier */

	return (0);  /* Successful DA_ADD */
}

/*
 * _build_lists -
 *	Cycles through all the entries, stores them in memory. removes entries
 *	with the given search_key (device name or type).
 *	returns 0 if given entry not found, 1 if given entry removed, 2 on
 *	error.
 */
static int
_build_lists(da_args *dargs, strentry_t **head_devallocp,
    strentry_t **head_devmapp)
{
	int		rc = 0;
	int		found = 0;
	devalloc_t	*devallocp;
	devmap_t	*devmapp;
	strentry_t	*tail_str;
	strentry_t	*tmp_str;

	if (dargs->optflag & DA_MAPS_ONLY)
		goto dmap_only;

	/* build device_allocate */
	setdaent();
	while ((devallocp = getdaent()) != NULL) {
		rc = da_match(devallocp, dargs);
		/* if in _build_lists and DA_ADD is set, so is DA_FORCE */
		if (rc == 0) {
			tmp_str = _da2strentry(dargs, devallocp);
			if (tmp_str == NULL) {
				freedaent(devallocp);
				enddaent();
				return (2);
			}
			/* retaining devalloc entry: tmp_str->se_str */
			tmp_str->se_next = NULL;
			if (*head_devallocp == NULL) {
				*head_devallocp = tail_str = tmp_str;
			} else {
				tail_str->se_next = tmp_str;
				tail_str = tmp_str;
			}
		} else if (rc == 1)
			found = 1;

		freedaent(devallocp);
	}
	enddaent();

dmap_only:
	if (dargs->optflag & DA_ALLOC_ONLY)
		return (rc);

	/* build device_maps */
	rc = 0;
	setdmapent();
	while ((devmapp = getdmapent()) != NULL) {
		rc = dm_match(devmapp, dargs);
		if (rc == 0) {
			tmp_str = _dmap2strentry(devmapp);
			if (tmp_str == NULL) {
				freedmapent(devmapp);
				enddmapent();
				return (2);
			}
			/* retaining devmap entry: tmp_str->se_str */
			tmp_str->se_next = NULL;
			if (*head_devmapp == NULL) {
				*head_devmapp = tail_str = tmp_str;
			} else {
				tail_str->se_next = tmp_str;
				tail_str = tmp_str;
			}
		}
		freedmapent(devmapp);
	}
	enddmapent();

	/* later code cleanup may cause the use of "found" in other cases */
	if (dargs->optflag & DA_REMOVE)
		return (found);
	return (rc);
}

/*
 * _write_defattrs
 *	writes current entries to devalloc_defaults.
 */
static void
_write_defattrs(FILE *fp, strentry_t *head_defent)
{
	strentry_t *tmp_str;

	for (tmp_str = head_defent; tmp_str != NULL;
	    tmp_str = tmp_str->se_next) {
		(void) fputs(tmp_str->se_str, fp);
		(void) fputs("\n", fp);
	}

}

/*
 * _write_device_allocate -
 *	writes current entries in the list to device_allocate.
 *	frees the strings
 */
static void
_write_device_allocate(char *odevalloc, FILE *dafp, strentry_t *head_devallocp)
{
	int		is_on = -1;
	strentry_t	*tmp_str, *old_str;
	struct stat	dastat;

	(void) fseek(dafp, (off_t)0, SEEK_SET);

	/*
	 * if the devalloc on/off string existed before,
	 * put it back before anything else.
	 * we need to check for the string only if the file
	 * exists.
	 */
	if (stat(odevalloc, &dastat) == 0) {
		is_on = da_is_on();
		if (is_on == 0)
			(void) fputs(DA_OFF_STR, dafp);
		else if (is_on == 1)
			(void) fputs(DA_ON_STR, dafp);
	}
	tmp_str = head_devallocp;
	while (tmp_str) {
		(void) fputs(tmp_str->se_str, dafp);
		(void) fputs("\n", dafp);
		old_str = tmp_str;
		tmp_str = tmp_str->se_next;
		free(old_str);
	}
}

/*
 * _write_device_maps -
 *	writes current entries in the list to device_maps.
 *	and frees the strings
 */
static void
_write_device_maps(FILE *dmfp, strentry_t *head_devmapp)
{
	strentry_t	*tmp_str, *old_str;

	(void) fseek(dmfp, (off_t)0, SEEK_SET);

	tmp_str = head_devmapp;
	while (tmp_str) {
		(void) fputs(tmp_str->se_str, dmfp);
		(void) fputs("\n", dmfp);
		old_str = tmp_str;
		tmp_str = tmp_str->se_next;
		free(old_str);
	}
}

/*
 * _write_new_defattrs
 *	writes the new entry to devalloc_defaults.
 *	returns 0 on success, -1 on error.
 */
static int
_write_new_defattrs(FILE *fp, da_args *dargs)
{
	int		count;
	char		*tok = NULL, *tokp = NULL;
	char		*lasts;
	devinfo_t	*devinfo = dargs->devinfo;

	if (fseek(fp, (off_t)0, SEEK_END) == (off_t)-1)
		return (-1);
	if (!devinfo->devopts)
		return (0);
	(void) fprintf(fp, "%s%s", (devinfo->devtype ? devinfo->devtype : ""),
	    KV_TOKEN_DELIMIT);
	if ((tokp = (char *)malloc(strlen(devinfo->devopts) +1)) != NULL) {
		(void) strcpy(tokp, devinfo->devopts);
		if ((tok = strtok_r(tokp, KV_DELIMITER, &lasts)) != NULL) {
			(void) fprintf(fp, "%s", tok);
			count = 1;
		}
		while ((tok = strtok_r(NULL, KV_DELIMITER, &lasts)) != NULL) {
			if (count)
				(void) fprintf(fp, "%s", KV_DELIMITER);
			(void) fprintf(fp, "%s", tok);
			count++;
		}
	} else {
		(void) fprintf(fp, "%s", devinfo->devopts);
	}

	return (0);
}

/*
 * _write_new_entry -
 *	writes the new devalloc_t to device_allocate or the new devmap_t to
 *	device_maps.
 *	returns 0 on success, -1 on error.
 */
static int
_write_new_entry(FILE *fp, da_args *dargs, int flag)
{
	int		count;
	char		*tok = NULL, *tokp = NULL;
	char		*lasts;
	devinfo_t	*devinfo = dargs->devinfo;

	if (flag & DA_MAPS_ONLY)
		goto dmap_only;

	if (fseek(fp, (off_t)0, SEEK_END) == (off_t)-1)
		return (-1);

	(void) fprintf(fp, "%s%s\\\n\t",
	    (devinfo->devname ? devinfo->devname : ""), KV_DELIMITER);
	(void) fprintf(fp, "%s%s\\\n\t",
	    (devinfo->devtype ? devinfo->devtype : ""), KV_DELIMITER);
	if (devinfo->devopts == NULL) {
		(void) fprintf(fp, "%s%s\\\n\t", DA_RESERVED,
		    KV_DELIMITER);
	} else {
		if ((tokp = (char *)malloc(strlen(devinfo->devopts) + 1))
		    != NULL) {
			(void) strcpy(tokp, devinfo->devopts);
			if ((tok = strtok_r(tokp, KV_TOKEN_DELIMIT, &lasts)) !=
			    NULL) {
				(void) fprintf(fp, "%s", tok);
				count = 1;
			}
			while ((tok = strtok_r(NULL, KV_TOKEN_DELIMIT,
			    &lasts)) != NULL) {
				if (count)
					(void) fprintf(fp, "%s",
					    KV_TOKEN_DELIMIT "\\\n\t");
				(void) fprintf(fp, "%s", tok);
				count++;
			}
			if (count)
				(void) fprintf(fp, "%s",
				    KV_DELIMITER "\\\n\t");
		} else {
			(void) fprintf(fp, "%s%s", devinfo->devopts,
			    KV_DELIMITER "\\\n\t");
		}
	}
	(void) fprintf(fp, "%s%s\\\n\t", DA_RESERVED, KV_DELIMITER);
	(void) fprintf(fp, "%s%s\\\n\t",
	    (devinfo->devauths ? devinfo->devauths : DA_ANYUSER),
	    KV_DELIMITER);
	(void) fprintf(fp, "%s\n",
	    (devinfo->devexec ? devinfo->devexec : KV_DELIMITER));

dmap_only:
	if (flag & DA_ALLOC_ONLY)
		return (0);

	if (fseek(fp, (off_t)0, SEEK_END) == (off_t)-1)
		return (-1);

	(void) fprintf(fp, "%s%s\\\n",
	    (devinfo->devname ? devinfo->devname : ""), KV_TOKEN_DELIMIT);
	(void) fprintf(fp, "\t%s%s\\\n",
	    (devinfo->devtype ? devinfo->devtype : ""), KV_TOKEN_DELIMIT);
	(void) fprintf(fp, "\t%s\n",
	    (devinfo->devlist ? devinfo->devlist : KV_TOKEN_DELIMIT));

	return (0);
}

/*
 * _da_lock_devdb -
 *	locks the database files; lock can be either broken explicitly by
 *	closing the fd of the lock file, or it expires automatically at process
 *	termination.
 * 	returns fd of the lock file or -1 on error.
 */
int
_da_lock_devdb(char *rootdir)
{
	int		lockfd = -1;
	int		ret;
	int		count = 0;
	int		retry = 10;
	int		retry_sleep;
	uint_t		seed;
	char		*lockfile;
	char		path[MAXPATHLEN];
	int		size = sizeof (path);

	if (rootdir == NULL) {
		lockfile = DA_DB_LOCK;
	} else {
		path[0] = '\0';
		if (snprintf(path, size, "%s%s", rootdir, DA_DB_LOCK) >= size)
			return (-1);
		lockfile = path;
	}

	if ((lockfd = open(lockfile, O_RDWR | O_CREAT, 0600)) == -1)
		/* cannot open lock file */
		return (-1);

	(void) fchown(lockfd, DA_UID, DA_GID);

	if (lseek(lockfd, (off_t)0, SEEK_SET) == -1) {
		/* cannot position lock file */
		(void) close(lockfd);
		return (-1);
	}
	errno = 0;
	while (retry > 0) {
		count++;
		seed = (uint_t)gethrtime();
		ret = lockf(lockfd, F_TLOCK, 0);
		if (ret == 0) {
			(void) utime(lockfile, NULL);
			return (lockfd);
		}
		if ((errno != EACCES) && (errno != EAGAIN)) {
			/* cannot set lock */
			(void) close(lockfd);
			return (-1);
		}
		retry--;
		retry_sleep = rand_r(&seed)/((RAND_MAX + 2)/3) + count;
		(void) sleep(retry_sleep);
		errno = 0;
	}

	return (-1);
}

/*
 * da_open_devdb -
 *	opens one or both database files - device_allocate, device_maps - in
 *	the specified mode.
 *	locks the database files; lock is either broken explicitly by the
 *	caller by closing the lock file fd, or it expires automatically at
 *	process termination.
 *	writes the file pointer of opened file in the input args - dafp, dmfp.
 *	returns fd of the lock file on success, -2 if database file does not
 *	exist, -1 on other errors.
 */
int
da_open_devdb(char *rootdir, FILE **dafp, FILE **dmfp, int flag)
{
	int	oflag = 0;
	int	fda = -1;
	int	fdm = -1;
	int	lockfd = -1;
	char	*fname;
	char	*fmode;
	char	path[MAXPATHLEN];
	FILE	*devfile;

	if ((dafp == NULL) && (dmfp == NULL))
		return (-1);

	if (flag & DA_RDWR) {
		oflag = DA_RDWR;
		fmode = "r+F";
	} else if (flag & DA_RDONLY) {
		oflag = DA_RDONLY;
		fmode = "rF";
	}

	if ((lockfd = _da_lock_devdb(rootdir)) == -1)
		return (-1);

	if ((dafp == NULL) || (flag & DA_MAPS_ONLY))
		goto dmap_only;

	path[0] = '\0';

	/*
	 * open the device allocation file
	 */
	if (rootdir == NULL) {
		fname = DEVALLOC;
	} else {
		if (snprintf(path, sizeof (path), "%s%s", rootdir,
		    DEVALLOC) >= sizeof (path)) {
			if (lockfd != -1)
				(void) close(lockfd);
			return (-1);
		}
		fname = path;
	}
	if ((fda = open(fname, oflag, DA_DBMODE)) == -1) {
		if (lockfd != -1)
			(void) close(lockfd);
		return ((errno == ENOENT) ? -2 : -1);
	}
	if ((devfile = fdopen(fda, fmode)) == NULL) {
		(void) close(fda);
		if (lockfd != -1)
			(void) close(lockfd);
		return (-1);
	}
	*dafp = devfile;
	(void) fchmod(fda, DA_DBMODE);

	if ((flag & DA_ALLOC_ONLY))
		goto out;

dmap_only:
	path[0] = '\0';
	/*
	 * open the device map file
	 */
	if (rootdir == NULL) {
		fname = DEVMAP;
	} else {
		if (snprintf(path, sizeof (path), "%s%s", rootdir,
		    DEVMAP) >= sizeof (path)) {
			(void) close(fda);
			if (lockfd != -1)
				(void) close(lockfd);
			return (-1);
		}
		fname = path;
	}

	if ((fdm = open(fname, oflag, DA_DBMODE)) == -1) {
		if (lockfd != -1)
			(void) close(lockfd);
		return ((errno == ENOENT) ? -2 : -1);
	}

	if ((devfile = fdopen(fdm, fmode)) == NULL) {
		(void) close(fdm);
		(void) close(fda);
		if (lockfd != -1)
			(void) close(lockfd);
		return (-1);
	}
	*dmfp = devfile;
	(void) fchmod(fdm, DA_DBMODE);

out:
	return (lockfd);
}

/*
 * _record_on_off -
 *	adds either DA_ON_STR or DA_OFF_STR to device_allocate
 *	returns 0 on success, -1 on error.
 */
static int
_record_on_off(da_args *dargs, FILE *tafp, FILE *dafp)
{
	int		dafd;
	int		nsize;
	int		nitems = 1;
	int		actionlen;
	int		str_found = 0;
	int		len = 0, nlen = 0, plen = 0;
	char		*ptr = NULL;
	char		*actionstr;
	char		*nbuf = NULL;
	char		line[MAX_CANON];
	struct stat	dastat;

	if (dargs->optflag & DA_ON)
		actionstr = DA_ON_STR;
	else
		actionstr = DA_OFF_STR;
	actionlen = strlen(actionstr);
	dafd = fileno(dafp);
	if (fstat(dafd, &dastat) == -1)
		return (-1);

	/* check the old device_allocate for on/off string */
	ptr = fgets(line, MAX_CANON, dafp);
	if (ptr != NULL) {
		if ((strcmp(line, DA_ON_STR) == 0) ||
		    (strcmp(line, DA_OFF_STR) == 0)) {
			str_found = 1;
			nsize = dastat.st_size;
		}
	}
	if (!ptr || !str_found) {
		/*
		 * the file never had either the on or the off string;
		 * make room for it.
		 */
		str_found = 0;
		nsize = dastat.st_size + actionlen + 1;
	}
	if ((nbuf = (char *)malloc(nsize + 1)) == NULL)
		return (-1);
	nbuf[0] = '\0';
	/* put the on/off string */
	(void) strcpy(nbuf, actionstr);
	nlen = strlen(nbuf);
	plen = nlen;
	if (ptr && !str_found) {
		/* now put the first line that we read in fgets */
		nlen = plen + strlen(line) + 1;
		len = snprintf(nbuf + plen, nlen - plen, "%s", line);
		if (len >= nsize) {
			free(nbuf);
			return (-1);
		}
		plen += len;
	}

	/* now get the rest of the old file */
	while (fgets(line, MAX_CANON, dafp) != NULL) {
		nlen = plen + strlen(line) + 1;
		len = snprintf(nbuf + plen, nlen - plen, "%s", line);
		if (len >= nsize) {
			free(nbuf);
			return (-1);
		}
		plen += len;
	}
	len = strlen(nbuf) + 1;
	if (len < nsize)
		nbuf[len] = '\n';

	/* write the on/off str + the old device_allocate to the temp file */
	if (fwrite(nbuf, nsize, nitems, tafp) < nitems) {
		free(nbuf);
		return (-1);
	}

	free(nbuf);

	return (0);
}

/*
 * da_update_defattrs -
 *	writes default attributes to devalloc_defaults
 *	returns 0 on success, -1 on error.
 */
int
da_update_defattrs(da_args *dargs)
{
	int		rc = 0, lockfd = 0, tmpfd = 0;
	char		*defpath = DEFATTRS;
	char		*tmpdefpath = TMPATTRS;
	FILE		*tmpfp = NULL;
	struct stat	dstat;
	strentry_t	*head_defent = NULL;

	if (dargs == NULL)
		return (0);
	if ((lockfd = _da_lock_devdb(NULL)) == -1)
		return (-1);
	if ((tmpfd = open(tmpdefpath, O_RDWR|O_CREAT, DA_DBMODE)) == -1) {
		(void) close(lockfd);
		return (-1);
	}
	(void) fchown(tmpfd, DA_UID, DA_GID);
	if ((tmpfp = fdopen(tmpfd, "r+")) == NULL) {
		(void) close(tmpfd);
		(void) unlink(tmpdefpath);
		(void) close(lockfd);
		return (-1);
	}
	/*
	 * examine all entries, remove an old one if required, check
	 * if a new one needs to be added.
	 */
	if (stat(defpath, &dstat) == 0) {
		if ((rc = _build_defattrs(dargs, &head_defent)) != 0) {
			if (rc == 1) {
				(void) close(tmpfd);
				(void) unlink(tmpdefpath);
				(void) close(lockfd);
				return (rc);
			}
		}
	}
	/*
	 * write back any existing entries.
	 */
	_write_defattrs(tmpfp, head_defent);

	if (dargs->optflag & DA_ADD && !(dargs->optflag & DA_NO_OVERRIDE)) {
		/* add new entries */
		rc = _write_new_defattrs(tmpfp, dargs);
		(void) fclose(tmpfp);
	} else {
		(void) fclose(tmpfp);
	}
	if (rename(tmpdefpath, defpath) != 0) {
		rc = -1;
		(void) unlink(tmpdefpath);
	}
	(void) close(lockfd);

	return (rc);
}

/*
 * da_update_device -
 *	Writes existing entries and the SINGLE change requested by da_args,
 *	to device_allocate and device_maps.
 *	Returns 0 on success, -1 on error.
 */
int
da_update_device(da_args *dargs)
{
	int		rc;
	int		tafd = -1, tmfd = -1;
	int		lockfd = -1;
	char		*rootdir = NULL;
	char		*apathp = NULL, *mpathp = NULL;
	char		*dapathp = NULL, *dmpathp = NULL;
	char		apath[MAXPATHLEN], mpath[MAXPATHLEN];
	char		dapath[MAXPATHLEN], dmpath[MAXPATHLEN];
	FILE		*tafp = NULL, *tmfp = NULL, *dafp = NULL;
	struct stat	dastat;
	devinfo_t	*devinfo;
	strentry_t	*head_devmapp = NULL;
	strentry_t	*head_devallocp = NULL;

	if (dargs == NULL)
		return (0);

	rootdir = dargs->rootdir;
	devinfo = dargs->devinfo;

	/*
	 * adding/removing entries should be done in both
	 * device_allocate and device_maps. updates can be
	 * done in both or either of the files.
	 */
	if (dargs->optflag & DA_ADD || dargs->optflag & DA_REMOVE) {
		if (dargs->optflag & DA_ALLOC_ONLY ||
		    dargs->optflag & DA_MAPS_ONLY)
			return (0);
	}

	/*
	 * name, type and list are required fields for adding a new
	 * device.
	 */
	if ((dargs->optflag & DA_ADD) &&
	    ((devinfo->devname == NULL) ||
	    (devinfo->devtype == NULL) ||
	    (devinfo->devlist == NULL))) {
		return (-1);
	}

	if (rootdir != NULL) {
		if (snprintf(apath, sizeof (apath), "%s%s", rootdir,
		    TMPALLOC) >= sizeof (apath))
			return (-1);
		apathp = apath;
		if (snprintf(dapath, sizeof (dapath), "%s%s", rootdir,
		    DEVALLOC) >= sizeof (dapath))
			return (-1);
		dapathp = dapath;
		if (!(dargs->optflag & DA_ALLOC_ONLY)) {
			if (snprintf(mpath, sizeof (mpath), "%s%s", rootdir,
			    TMPMAP) >= sizeof (mpath))
				return (-1);
			mpathp = mpath;
			if (snprintf(dmpath, sizeof (dmpath), "%s%s", rootdir,
			    DEVMAP) >= sizeof (dmpath))
				return (-1);
			dmpathp = dmpath;
		}
	} else {
		apathp = TMPALLOC;
		dapathp = DEVALLOC;
		mpathp = TMPMAP;
		dmpathp = DEVMAP;
	}

	if (dargs->optflag & DA_MAPS_ONLY)
		goto dmap_only;

	/*
	 * Check if we are here just to record on/off status of
	 * device_allocation.
	 */
	if (dargs->optflag & DA_ON || dargs->optflag & DA_OFF)
		lockfd = da_open_devdb(dargs->rootdir, &dafp, NULL,
		    DA_RDONLY|DA_ALLOC_ONLY);
	else
		lockfd = _da_lock_devdb(rootdir);
	if (lockfd == -1)
		return (-1);

	if ((tafd = open(apathp, O_RDWR|O_CREAT, DA_DBMODE)) == -1) {
		(void) close(lockfd);
		(void) fclose(dafp);
		return (-1);
	}
	(void) fchown(tafd, DA_UID, DA_GID);
	if ((tafp = fdopen(tafd, "r+")) == NULL) {
		(void) close(tafd);
		(void) unlink(apathp);
		(void) fclose(dafp);
		(void) close(lockfd);
		return (-1);
	}

	/*
	 * We don't need to parse the file if we are here just to record
	 * on/off status of device_allocation.
	 */
	if (dargs->optflag & DA_ON || dargs->optflag & DA_OFF) {
		if (_record_on_off(dargs, tafp, dafp) == -1) {
			(void) close(tafd);
			(void) unlink(apathp);
			(void) fclose(dafp);
			(void) close(lockfd);
			return (-1);
		}
		(void) fclose(dafp);
		goto out;
	}

	/*
	 * If reacting to a hotplug, read the file entries,
	 * figure out what dname (tname + a new number) goes to the
	 * device being added/removed, and create a good head_devallocp and
	 * head_devmapp with everything good still in it (_rebuild_lists)
	 *
	 * Else examine all the entries, remove an old one if it is
	 * a duplicate with a device being added, returning the
	 * remaining list (_build_lists.)
	 *
	 * We need to do this only if the file exists already.
	 *
	 * Once we have built these lists, we need to free the strings
	 * in the head_* arrays before returning.
	 */
	if (stat(dapathp, &dastat) == 0) {
		/* for device allocation, the /etc files are the "master" */
		if ((dargs->optflag & (DA_ADD| DA_EVENT)) &&
		    (!(dargs->optflag & DA_FORCE)))
			rc = _rebuild_lists(dargs, &head_devallocp,
			    &head_devmapp);
		else
			rc = _build_lists(dargs, &head_devallocp,
			    &head_devmapp);

		if (rc != 0 && rc != 1) {
			(void) close(tafd);
			(void) unlink(apathp);
			(void) close(lockfd);
			return (-1);
		}
	} else
		rc = 0;

	if ((dargs->optflag & DA_REMOVE) && (rc == 0)) {
		(void) close(tafd);
		(void) unlink(apathp);
		(void) close(lockfd);
		return (0);
	}
	/*
	 * TODO: clean up the workings of DA_UPDATE.
	 * Due to da_match looking at fields that are missing
	 * in dargs for DA_UPDATE, the da_match call returns no match,
	 * but due to the way _da2str combines the devalloc_t info with
	 * the *dargs info, the DA_ADD_ZONE and DA_REMOVE_ZONE work.
	 *
	 * This would not scale if any type of update was ever needed
	 * from the daemon.
	 */

	/*
	 * Write out devallocp along with the devalloc on/off string.
	 */
	_write_device_allocate(dapathp, tafp, head_devallocp);

	if (dargs->optflag & DA_ALLOC_ONLY)
		goto out;

dmap_only:
	if ((tmfd = open(mpathp, O_RDWR|O_CREAT, DA_DBMODE)) == -1) {
		(void) close(tafd);
		(void) unlink(apathp);
		(void) close(lockfd);
		return (-1);
	}
	(void) fchown(tmfd, DA_UID, DA_GID);
	if ((tmfp = fdopen(tmfd, "r+")) == NULL) {
		(void) close(tafd);
		(void) unlink(apathp);
		(void) close(tmfd);
		(void) unlink(mpathp);
		(void) close(lockfd);
		return (-1);
	}

	/*
	 * Write back any non-removed pre-existing entries.
	 */
	if (head_devmapp != NULL)
		_write_device_maps(tmfp, head_devmapp);

out:
	/*
	 * Add any new entries here.
	 */
	if (dargs->optflag & DA_ADD && !(dargs->optflag & DA_NO_OVERRIDE)) {
		/* add any new entries */
		rc = _write_new_entry(tafp, dargs, DA_ALLOC_ONLY);
		(void) fclose(tafp);

		if (rc == 0)
			rc = _write_new_entry(tmfp, dargs, DA_MAPS_ONLY);
		(void) fclose(tmfp);
	} else {
		if (tafp)
			(void) fclose(tafp);
		if (tmfp)
			(void) fclose(tmfp);
	}

	rc = 0;
	if (!(dargs->optflag & DA_MAPS_ONLY)) {
		if (rename(apathp, dapathp) != 0) {
			rc = -1;
			(void) unlink(apathp);
		}
	}
	if (!(dargs->optflag & DA_ALLOC_ONLY)) {
		if (rename(mpathp, dmpathp) != 0) {
			rc = -1;
			(void) unlink(mpathp);
		}
	}

	(void) close(lockfd);

	return (rc);
}

/*
 * da_add_list -
 *	adds new /dev link name to the linked list of devices.
 *	returns 0 if link added successfully, -1 on error.
 */
int
da_add_list(devlist_t *dlist, char *link, int new_instance, int flag)
{
	int		instance;
	int		nlen, plen;
	int		new_entry = 0;
	char		*dtype, *dexec, *tname, *kval;
	char		*minstr = NULL, *maxstr = NULL;
	char		dname[DA_MAXNAME + 1];
	kva_t		*kva;
	deventry_t	*dentry = NULL, *nentry = NULL, *pentry = NULL;
	da_defs_t	*da_defs;

	if (dlist == NULL || link == NULL)
		return (-1);

	dname[0] = '\0';
	if (flag & DA_AUDIO) {
		dentry = dlist->audio;
		tname = DA_AUDIO_NAME;
		dtype = DA_AUDIO_TYPE;
		dexec = DA_DEFAULT_AUDIO_CLEAN;
	} else if (flag & DA_CD) {
		dentry = dlist->cd;
		tname = DA_CD_NAME;
		dtype = DA_CD_TYPE;
		dexec = DA_DEFAULT_DISK_CLEAN;
	} else if (flag & DA_FLOPPY) {
		dentry = dlist->floppy;
		tname = DA_FLOPPY_NAME;
		dtype = DA_FLOPPY_TYPE;
		dexec = DA_DEFAULT_DISK_CLEAN;
	} else if (flag & DA_TAPE) {
		dentry = dlist->tape;
		tname = DA_TAPE_NAME;
		dtype = DA_TAPE_TYPE;
		dexec = DA_DEFAULT_TAPE_CLEAN;
	} else if (flag & DA_RMDISK) {
		dentry = dlist->rmdisk;
		tname = DA_RMDISK_NAME;
		dtype = DA_RMDISK_TYPE;
		dexec = DA_DEFAULT_DISK_CLEAN;
	} else {
		return (-1);
	}

	for (nentry = dentry; nentry != NULL; nentry = nentry->next) {
		pentry = nentry;
		(void) sscanf(nentry->devinfo.devname, "%*[a-z]%d", &instance);
		if (nentry->devinfo.instance == new_instance)
			/*
			 * Add the new link name to the list of links
			 * that the device 'dname' has.
			 */
			break;
	}

	if (nentry == NULL) {
		/*
		 * Either this is the first entry ever, or no matching entry
		 * was found. Create a new one and add to the list.
		 */
		if (dentry == NULL)		/* first entry ever */
			instance = 0;
		else				/* no matching entry */
			instance++;
		(void) snprintf(dname, sizeof (dname), "%s%d", tname, instance);
		if ((nentry = (deventry_t *)malloc(sizeof (deventry_t))) ==
		    NULL)
			return (-1);
		if (pentry != NULL)
			pentry->next = nentry;
		new_entry = 1;
		nentry->devinfo.devname = strdup(dname);
		nentry->devinfo.devtype = dtype;
		nentry->devinfo.devauths = DEFAULT_DEV_ALLOC_AUTH;
		nentry->devinfo.devexec = dexec;
		nentry->devinfo.instance = new_instance;
		/*
		 * Look for default label range, authorizations and cleaning
		 * program in devalloc_defaults. If label range is not
		 * specified in devalloc_defaults, assume it to be admin_low
		 * to admin_high.
		 */
		minstr = DA_DEFAULT_MIN;
		maxstr = DA_DEFAULT_MAX;
		setdadefent();
		if (da_defs = getdadeftype(nentry->devinfo.devtype)) {
			kva = da_defs->devopts;
			if ((kval = kva_match(kva, DAOPT_MINLABEL)) != NULL)
				minstr = strdup(kval);
			if ((kval = kva_match(kva, DAOPT_MAXLABEL)) != NULL)
				maxstr = strdup(kval);
			if ((kval = kva_match(kva, DAOPT_AUTHS)) != NULL)
				nentry->devinfo.devauths = strdup(kval);
			if ((kval = kva_match(kva, DAOPT_CSCRIPT)) != NULL)
				nentry->devinfo.devexec = strdup(kval);
			freedadefent(da_defs);
		}
		enddadefent();
		kval = NULL;
		nlen = strlen(DAOPT_MINLABEL) + strlen(KV_ASSIGN) +
		    strlen(minstr) + strlen(KV_TOKEN_DELIMIT) +
		    strlen(DAOPT_MAXLABEL) + strlen(KV_ASSIGN) + strlen(maxstr)
		    + 1;			/* +1 for terminator */
		if (kval = (char *)malloc(nlen))
			(void) snprintf(kval, nlen, "%s%s%s%s%s%s%s",
			    DAOPT_MINLABEL, KV_ASSIGN, minstr, KV_TOKEN_DELIMIT,
			    DAOPT_MAXLABEL, KV_ASSIGN, maxstr);
		nentry->devinfo.devopts = kval;

		nentry->devinfo.devlist = NULL;
		nentry->next = NULL;
	}

	nlen = strlen(link) + 1;		/* +1 terminator */
	if (nentry->devinfo.devlist) {
		plen = strlen(nentry->devinfo.devlist);
		nlen = nlen + plen + 1;	/* +1 for blank to separate entries */
	} else {
		plen = 0;
	}

	if ((nentry->devinfo.devlist =
	    (char *)realloc(nentry->devinfo.devlist, nlen)) == NULL) {
		if (new_entry) {
			free(nentry->devinfo.devname);
			free(nentry);
			if (pentry != NULL)
				pentry->next = NULL;
		}
		return (-1);
	}

	if (plen == 0)
		(void) snprintf(nentry->devinfo.devlist, nlen, "%s", link);
	else
		(void) snprintf(nentry->devinfo.devlist + plen, nlen - plen,
		    " %s", link);

	if (pentry == NULL) {
		/*
		 * This is the first entry of this device type.
		 */
		if (flag & DA_AUDIO)
			dlist->audio = nentry;
		else if (flag & DA_CD)
			dlist->cd = nentry;
		else if (flag & DA_FLOPPY)
			dlist->floppy = nentry;
		else if (flag & DA_TAPE)
			dlist->tape = nentry;
		else if (flag & DA_RMDISK)
			dlist->rmdisk = nentry;
	}

	return (0);
}

/*
 * da_remove_list -
 *	removes a /dev link name from the linked list of devices.
 *	returns type of device if link for that device removed
 *	successfully, else returns -1 on error.
 *	if all links for a device are removed, stores that device
 *	name in devname.
 */
int
da_remove_list(devlist_t *dlist, char *link, int type, char *devname, int size)
{
	int		flag;
	int		remove_dev = 0;
	int		nlen, plen, slen;
	char		*lasts, *lname, *oldlist;
	struct stat	rmstat;
	deventry_t	*dentry, *current, *prev;

	if (type != NULL)
		flag = type;
	else if (link == NULL)
		return (-1);
	else if (strstr(link, DA_AUDIO_NAME) || strstr(link, DA_SOUND_NAME))
		flag = DA_AUDIO;
	else if (strstr(link, "dsk") || strstr(link, "rdsk") ||
	    strstr(link, "sr") || strstr(link, "rsr"))
		flag = DA_CD;
	else if (strstr(link, "fd") || strstr(link, "rfd") ||
	    strstr(link, "diskette") || strstr(link, "rdiskette"))
		flag = DA_FLOPPY;
	else if (strstr(link, DA_TAPE_NAME))
		flag = DA_TAPE;
	else
		flag = DA_RMDISK;

	switch (type) {
	case DA_AUDIO:
		dentry = dlist->audio;
		break;
	case DA_CD:
		dentry = dlist->cd;
		break;
	case DA_FLOPPY:
		dentry = dlist->floppy;
		break;
	case DA_TAPE:
		dentry = dlist->tape;
		break;
	case DA_RMDISK:
		dentry = dlist->rmdisk;
		break;
	default:
		return (-1);
	}

	if ((type != NULL) && (link == NULL)) {
		for (current = dentry, prev = dentry; current != NULL;
		    current = current->next) {
			oldlist = strdup(current->devinfo.devlist);
			for (lname = strtok_r(oldlist, " ", &lasts);
			    lname != NULL;
			    lname = strtok_r(NULL, " ", &lasts)) {
				if (stat(lname, &rmstat) != 0) {
					remove_dev = 1;
					goto remove_dev;
				}
			}
			prev = current;
		}
		return (-1);
	}

	for (current = dentry, prev = dentry; current != NULL;
	    current = current->next) {
		plen = strlen(current->devinfo.devlist);
		nlen = strlen(link);
		if (plen == nlen) {
			if (strcmp(current->devinfo.devlist, link) == 0) {
				/* last name in the list */
				remove_dev = 1;
				break;
			}
		}
		if (strstr(current->devinfo.devlist, link)) {
			nlen = plen - nlen + 1;
			oldlist = strdup(current->devinfo.devlist);
			if ((current->devinfo.devlist =
			    (char *)realloc(current->devinfo.devlist,
			    nlen)) == NULL) {
				free(oldlist);
				return (-1);
			}
			current->devinfo.devlist[0] = '\0';
			nlen = plen = slen = 0;
			for (lname = strtok_r(oldlist, " ", &lasts);
			    lname != NULL;
			    lname = strtok_r(NULL, " ", &lasts)) {
				if (strcmp(lname, link) == 0)
					continue;
				nlen = strlen(lname) + plen + 1;
				if (plen == 0) {
					slen =
					    snprintf(current->devinfo.devlist,
					    nlen, "%s", lname);
				} else {
					slen =
					    snprintf(current->devinfo.devlist +
					    plen, nlen - plen, " %s", lname);
				}
				plen = plen + slen + 1;
			}
			free(oldlist);
			break;
		}
		prev = current;
	}

remove_dev:
	if (remove_dev == 1) {
		(void) strlcpy(devname, current->devinfo.devname, size);
		free(current->devinfo.devname);
		free(current->devinfo.devlist);
		current->devinfo.devname = current->devinfo.devlist = NULL;
		prev->next = current->next;
		free(current);
		current = NULL;
	}
	if ((remove_dev == 1) && (prev->devinfo.devname == NULL)) {
		if (prev->next) {
			/*
			 * what we removed above was the first entry
			 * in the list. make the next entry to be the
			 * first.
			 */
			current = prev->next;
		} else {
			/*
			 * the matching entry was the only entry in the list
			 * for this type.
			 */
			current = NULL;
		}
		if (flag & DA_AUDIO)
			dlist->audio = current;
		else if (flag & DA_CD)
			dlist->cd = current;
		else if (flag & DA_FLOPPY)
			dlist->floppy = current;
		else if (flag & DA_TAPE)
			dlist->tape = current;
		else if (flag & DA_RMDISK)
			dlist->rmdisk = current;
	}

	return (flag);
}

/*
 * da_rm_list_entry -
 *
 *	The adding of devnames to a devlist and the removal of a
 *	device are not symmetrical -- hot_cleanup gives a /devices
 *	name which is used to remove the dentry whose links all point to
 *	that /devices entry.
 *
 *	The link argument is present if available to make debugging
 *	easier.
 *
 *	da_rm_list_entry removes an entry from the linked list of devices.
 *
 *	Returns 1 if the devname was removed successfully,
 *	0 if not found, -1 for error.
 */
/*ARGSUSED*/
int
da_rm_list_entry(devlist_t *dlist, char *link, int type, char *devname)
{
	int		retval = 0;
	deventry_t	**dentry, *current, *prev;

	switch (type) {
	case DA_AUDIO:
		dentry = &(dlist->audio);
		break;
	case DA_CD:
		dentry = &(dlist->cd);
		break;
	case DA_FLOPPY:
		dentry = &(dlist->floppy);
		break;
	case DA_TAPE:
		dentry = &(dlist->tape);
		break;
	case DA_RMDISK:
		dentry = &(dlist->rmdisk);
		break;
	default:
		return (-1);
	}

	/* Presumably in daemon mode, no need to remove entry, list is empty */
	if (*dentry == (deventry_t *)NULL)
		return (0);

	prev = NULL;
	for (current = *dentry; current != NULL;
	    prev = current, current = current->next) {
		if (strcmp(devname, current->devinfo.devname))
			continue;
		retval = 1;
		break;
	}
	if (retval == 0)
		return (0);
	free(current->devinfo.devname);
	if (current->devinfo.devlist != NULL)
		free(current->devinfo.devlist);
	if (current->devinfo.devopts != NULL)
		free(current->devinfo.devopts);

	if (prev == NULL)
		*dentry = current->next;
	else
		prev->next = current->next;

	free(current);
	return (retval);
}

/*
 * da_is_on -
 *	checks if device allocation feature is turned on.
 *	returns 1 if on, 0 if off, -1 if status string not
 *	found in device_allocate.
 */
int
da_is_on()
{
	return (getdaon());
}

/*
 * da_print_device -
 *	debug routine to print device entries.
 */
void
da_print_device(int flag, devlist_t *devlist)
{
	deventry_t	*entry, *dentry;
	devinfo_t	*devinfo;

	if (flag & DA_AUDIO)
		dentry = devlist->audio;
	else if (flag & DA_CD)
		dentry = devlist->cd;
	else if (flag & DA_FLOPPY)
		dentry = devlist->floppy;
	else if (flag & DA_TAPE)
		dentry = devlist->tape;
	else if (flag & DA_RMDISK)
		dentry = devlist->rmdisk;
	else
		return;

	for (entry = dentry; entry != NULL; entry = entry->next) {
		devinfo = &(entry->devinfo);
		(void) fprintf(stdout, "name: %s\n", devinfo->devname);
		(void) fprintf(stdout, "type: %s\n", devinfo->devtype);
		(void) fprintf(stdout, "auth: %s\n", devinfo->devauths);
		(void) fprintf(stdout, "exec: %s\n", devinfo->devexec);
		(void) fprintf(stdout, "list: %s\n\n", devinfo->devlist);
	}
}
