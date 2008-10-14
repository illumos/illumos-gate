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

#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include <locale.h>
#include <errno.h>

#include <sys/nsctl/cfg.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>
#include <sys/unistat/spcs_s_impl.h>

#include <sys/nsctl/sv.h>
#include <sys/nsctl/nsc_hash.h>

#define	DEV_EXPAND 32

#define	DO_DISABLE 0
#define	DO_ENABLE 1

/*
 * Utility functions for iiadm and rdcadm/sndradm.
 */

typedef struct hash_data_s {
	union {
		char *users;
		char *mode;
	} u;
	char *path;
	char *node;
	int setno;
} hash_data_t;

typedef struct {
	dev_t	rdev;
	mode_t  mode;
	char	*path;
} device_t;

static hash_data_t *make_svol_data(char *, char *, char *, int);
static hash_data_t *make_dsvol_data(char *, char *, char *, int);
static void delete_svol_data(void *);
static void delete_dsvol_data(void *);
static int sv_action(char *, CFGFILE *, char *, int);

static int add_dev_entry(const char *);
static int compare(const void *, const void *);
static char *find_devid(const char *);
static void free_dev_entries();
static void rebuild_devhash();

static hash_node_t **dsvol;
static int dsvol_loaded = 0;

static hash_node_t **svol;
static int svol_loaded = 0;

static hash_node_t **shadowvol;

static hash_node_t **devhash;
static device_t *devlist;
static int devcount = 0;
static int devalloc = 0;

/*
 * cfg_add_user
 *
 * Description:
 *	Adds the calling tool as a user of the volume.
 *
 * Inputs:
 *	char *path: The pathname of the volume to be enabled.
 *	char *cnode: The device group name, or NULL if -C local or not cluster
 *	CFGFILE *cfg: A pointer to the current config file, or NULL if this
 *		function is to open/write/commit/close the change itself.
 *
 * Return values:
 *	CFG_USER_FIRST: Indicates that this is the first user of this
 *		particular volume.
 *	CFG_USER_OK: Indicates that the volume has already been entered into
 *		the config file.
 *	CFG_USER_ERR: Indicates that some failure has occurred and no changes
 *		to the config file have been made.
 *	CFG_USER_REPEAT: Indicates that this user has already registered for
 *		the volume.
 */
int
cfg_add_user(CFGFILE* cfg, char *path, char *cnode, char *user)
{
	int self_open, self_loaded, change_made;
	char *ctag, search_key[ CFG_MAX_KEY ], buf[ CFG_MAX_BUF ];
	int retval, rc;
	hash_data_t *data;

	self_open = (cfg == NULL);
	self_loaded = 0;
	change_made = 0;

	if (self_open) {
		cfg = cfg_open(NULL);
		if (cfg == NULL) {
			return (CFG_USER_ERR);
		}

		if (!cfg_lock(cfg, CFG_WRLOCK)) {
			/* oops */
			cfg_close(cfg);
			return (CFG_USER_ERR);
		}
	}

	/* Check cnode */
	ctag = cfg_get_resource(cfg);
	if (cnode) {
		if (ctag) {
			if (strcmp(cnode, ctag))
				return (CFG_USER_ERR);
		} else
			cfg_resource(cfg, cnode);
	} else
		cnode = ctag;

	if (!dsvol_loaded) {
		if (cfg_load_dsvols(cfg) < 0) {
			if (self_open) {
				cfg_close(cfg);
			}
			return (CFG_USER_ERR);
		}
		self_loaded = 1;
	}

	/* find the volume */
	(void) snprintf(search_key, CFG_MAX_KEY, "%s:%s", path, cnode);
	data = nsc_lookup(dsvol, search_key);

	if (!data) {
		/* whoops, not found.  Add as new user */
		cfg_rewind(cfg, CFG_SEC_CONF);
		(void) snprintf(buf, CFG_MAX_BUF, "%s %s %s", path, cnode,
		    user);
		rc = cfg_put_cstring(cfg, "dsvol", buf, strlen(buf));
		if (rc < 0) {
			if (self_loaded) {
				cfg_unload_dsvols();
			}
			if (self_open) {
				cfg_close(cfg);
			}
			return (CFG_USER_ERR);
		}
		/* reload hash, if we need to */
		if (!self_loaded) {
			cfg_unload_dsvols();
			if (cfg_load_dsvols(cfg) < 0) {
				if (self_open) {
					cfg_close(cfg);
				}
				return (CFG_USER_ERR);
			}
		}
		retval = CFG_USER_FIRST;
		change_made = 1;
	} else {
		/* Check to ensure we're not already listed */
		char *p = strdup(data->u.users);
		char *q = strtok(p, ",");
		while (q && (strcmp(q, user) != 0)) {
			q = strtok(0, ",");
		}
		free(p);	/* not using data; only testing 'q' ptr */

		if (!q) {
			/* not listed as a user */
			cfg_rewind(cfg, CFG_SEC_CONF);
			(void) snprintf(buf, CFG_MAX_BUF, "%s %s %s,%s",
			    data->path, data->node, data->u.users, user);
			(void) snprintf(search_key, CFG_MAX_KEY, "dsvol.set%d",
			    data->setno);
			if (cfg_put_cstring(cfg, search_key, buf,
			    strlen(buf)) < 0) {
				if (self_loaded) {
					cfg_unload_dsvols();
				}
				if (self_open) {
					cfg_close(cfg);
				}
				return (CFG_USER_ERR);
			}

			/*
			 * Since we deleted an entry from the config
			 * file, we don't know what all the new
			 * set numbers are.  We need to reload
			 * everything
			 */
			if (!self_loaded) {
				cfg_unload_dsvols();
				if (cfg_load_dsvols(cfg) < 0) {
					if (self_open) {
						cfg_close(cfg);
					}
					return (CFG_USER_ERR);
				}
			}
			change_made = 1;
			retval = CFG_USER_OK;
		} else {
			retval = CFG_USER_REPEAT;
		}
	}

	if (self_loaded) {
		cfg_unload_dsvols();
	}

	if (self_open) {
		if (change_made)
			(void) cfg_commit(cfg);
		cfg_close(cfg);
	}

	return (retval);
}

/*
 * cfg_rem_user
 *
 * Description:
 *	Removes a user from the config file.
 *
 * Inputs:
 *	char *path: The pathname of the volume to be enabled.
 *	char *cnode: The device group name, or NULL if -C local or not cluster
 *	char *user: The subsystem that is adding this tag (sv, ii, sndr)
 *	CFGFILE *cfg: A pointer to the current config file, or NULL if this
 *		function is to open/write/commit/close the change itself.
 * Return values:
 *	CFG_USER_ERR: An error occurred during the processing of this
 *		directive.
 *	CFG_USER_OK: User successfully removed; volume in use by other(s).
 *	CFG_USER_LAST: User successfuly removed; no other users registered
 *	CFG_USER_GONE: The volume is no longer listed in the dsvol section,
 *		indicating some sort of application-level error.
 *
 */
int
cfg_rem_user(CFGFILE *cfg, char *path, char *cnode, char *user)
{
	int self_open, self_loaded, change_made;
	char *ctag, search_key[ CFG_MAX_KEY ], buf[ CFG_MAX_BUF ];
	char cfg_key[ CFG_MAX_KEY ];
	hash_data_t *data;
	int retval;
	int force_remove;

	self_open = (cfg == NULL);
	self_loaded = 0;
	change_made = 0;
	force_remove = (strcmp(user, "sv") == 0);

	if ('-' == *user) {
		++user;
	}

	/* Check cnode */
	ctag = cfg_get_resource(cfg);
	if (cnode) {
		if (ctag) {
			if (strcmp(cnode, ctag))
				return (CFG_USER_ERR);
		} else
			cfg_resource(cfg, cnode);
	} else
		cnode = ctag;

	if (self_open) {
		cfg = cfg_open(NULL);
		if (cfg == NULL) {
			return (CFG_USER_ERR);
		}

		if (!cfg_lock(cfg, CFG_WRLOCK)) {
			/* oops */
			cfg_close(cfg);
			return (CFG_USER_ERR);
		}
	}


	change_made = 0;
	if (!dsvol_loaded) {
		if (cfg_load_dsvols(cfg) < 0) {
			if (self_open) {
				cfg_close(cfg);
			}
			return (CFG_USER_ERR);
		}
		self_loaded = 1;
	}

	/* find the volume */
	(void) snprintf(search_key, CFG_MAX_KEY, "%s:%s", path, cnode);
	data = nsc_lookup(dsvol, search_key);

	if (!data) {
		/* yipes */
		retval = CFG_USER_GONE;
	} else if (force_remove) {
		retval = CFG_USER_LAST;
		cfg_rewind(cfg, CFG_SEC_CONF);
		(void) snprintf(cfg_key, CFG_MAX_KEY, "dsvol.set%d",
		    data->setno);
		if (cfg_put_cstring(cfg, cfg_key, NULL, 0) < 0) {
			if (self_loaded) {
				cfg_unload_dsvols();
			}
			if (self_open) {
				cfg_close(cfg);
			}
			return (CFG_USER_ERR);
		}
		if (!self_loaded) {
			cfg_unload_dsvols();
			if (cfg_load_dsvols(cfg) < 0) {
				if (self_open) {
					cfg_close(cfg);
				}
				return (CFG_USER_ERR);
			}
		}
	} else {
		char *p = strdup(data->u.users);
		char *q = strtok(p, ",");
		int appended = 0;

		(void) snprintf(buf, CFG_MAX_BUF, "%s %s ", data->path,
		    data->node);
		while (q && (strcmp(q, user) != 0)) {
			if (appended) {
				strcat(buf, ",");
				strcat(buf, q);
			} else {
				strcat(buf, q);
				appended = 1;
			}
			q = strtok(0, ",");
		}

		if (!q) {
			/* uh-oh */
			retval = CFG_USER_GONE;
		} else {
			/* old user skipped; add in remaining users */
			while (q = strtok(0, ", ")) {
				if (appended) {
					strcat(buf, ",");
					strcat(buf, q);
				} else {
					strcat(buf, q);
					appended = 1;
				}
			}

			if (appended) {
				retval = CFG_USER_OK;
				cfg_rewind(cfg, CFG_SEC_CONF);
				(void) snprintf(cfg_key, CFG_MAX_KEY,
				    "dsvol.set%d", data->setno);
				if (cfg_put_cstring(cfg, cfg_key, buf,
				    strlen(buf)) < 0) {
					if (self_loaded) {
						cfg_unload_dsvols();
					}
					if (self_open) {
						cfg_close(cfg);
					}
					return (CFG_USER_ERR);
				}
				if (!self_loaded) {
					cfg_unload_dsvols();
					if (cfg_load_dsvols(cfg) < 0) {
						if (self_open) {
							cfg_close(cfg);
						}
						return (CFG_USER_ERR);
					}
				}
			} else {
				retval = CFG_USER_LAST;
				cfg_rewind(cfg, CFG_SEC_CONF);
				(void) snprintf(cfg_key, CFG_MAX_KEY,
				    "dsvol.set%d", data->setno);
				if (cfg_put_cstring(cfg, cfg_key, NULL,
				    0) < 0) {
					if (self_loaded) {
						cfg_unload_dsvols();
					}
					if (self_open) {
						cfg_close(cfg);
					}
					return (CFG_USER_ERR);
				}
				/*
				 * Since we deleted an entry from the config
				 * file, we don't know what all the new
				 * set numbers are.  We need to reload
				 * everything
				 */
				if (!self_loaded) {
					cfg_unload_dsvols();
					if (cfg_load_dsvols(cfg) < 0) {
						if (self_open) {
							cfg_close(cfg);
						}
						return (CFG_USER_ERR);
					}
				}
			}
			change_made = 1;
		}
	}

	if (self_loaded) {
		cfg_unload_dsvols();
	}

	if (self_open) {
		if (change_made)
			(void) cfg_commit(cfg);
		cfg_close(cfg);
	}

	return (retval);
}

/*
 * Enable a volume under SV control (or add this char *user to the list
 * of users of that volume).
 *
 * Parameters:
 *	cfg	- The config file to use.
 *	path	- The pathname of the volume
 *	ctag	- The cluster tag for this volume (if any)
 *	user	- The user (sv, ii, sndr) of the volume.
 */
int
cfg_vol_enable(CFGFILE *cfg, char *path, char *ctag, char *user)
{
	int rc;
	int retval;

	if (!ctag || *ctag == '\0') {
		ctag = "-";
	}

	retval = -1;
	rc = cfg_add_user(cfg, path, ctag, user);
	switch (rc) {
	case CFG_USER_ERR:
		spcs_log("dsvol", NULL,
		    gettext("unable to set up dsvol section of config for %s"),
		    path);
		break;
	case CFG_USER_OK:
		retval = 0;
		break;
	case CFG_USER_FIRST:
		/* enable sv! */
		retval = sv_action(path, cfg, ctag, DO_ENABLE);
		if (retval < 0) {
			(void) cfg_rem_user(cfg, path, ctag, user);
		}
		break;
	default:
		spcs_log("dsvol", NULL,
		    gettext("unexpected return from cfg_add_user(%d)"), rc);
		break;
	}

	return (retval);
}

/*
 * Disable a volume from SV control (or remove this char *user from the list
 * of users of that volume).
 *
 * Parameters:
 *	cfg	- The config file to use.
 *	path	- The pathname of the volume
 *	ctag	- The cluster tag for this volume (if any)
 *	user	- The user (sv, ii, sndr) of the volume.
 */
int
cfg_vol_disable(CFGFILE *cfg, char *path, char *ctag, char *user)
{
	int rc;
	int retval;

	if (!ctag || *ctag == '\0') {
		ctag = "-";
	}

	retval = -1;
	rc = cfg_rem_user(cfg, path, ctag, user);
	switch (rc) {
	case CFG_USER_ERR:
		spcs_log("dsvol", NULL,
		    gettext("unable to set up dsvol section of config for %s"),
		    path);
		break;
	case CFG_USER_OK:
		retval = 0;
		break;
	case CFG_USER_GONE:
		spcs_log("dsvol", NULL,
		    gettext("%s tried to remove non-existent tag for %s"),
		    user, path);
		break;
	case CFG_USER_LAST:
		/* diable sv! */
		retval = sv_action(path, cfg, ctag, DO_DISABLE);
		break;
	default:
		spcs_log("dsvol", NULL,
		    gettext("unexpected return from cfg_rem_user(%d)"), rc);
		break;
	}

	return (retval);
}

/*
 * cfg_load_dsvols
 *
 * Description:
 *	Loads the dsvol section of the config file into a giant hash, to
 *	make searching faster.  The important bit to remember is to not
 *	release the write lock between calling cfg_load_dsvols() and the
 *	cfg_*_user() functions.
 *
 * Assumptions:
 *	1/ cfg file is open
 *	2/ cfg file has been write-locked
 *	3/ user of this routine may already be using hcreate/hsearch
 *
 * Return value:
 *	-1 if error, or total number of sets found
 */
int
cfg_load_dsvols(CFGFILE *cfg)
{
	int set, rc, entries;
	char search_key[ CFG_MAX_KEY ];
	char *buf;
	char **entry, *path, *cnode, *users;
	hash_data_t *data;
	int devs_added = 0;
	int offset = 0;
	char *ctag = cfg_get_resource(cfg);
	if (!ctag || *ctag == '\0') {
		ctag = "-";
	}

	dsvol = nsc_create_hash();
	if (!dsvol) {
		return (-1);
	}

	rc = 0;
	cfg_rewind(cfg, CFG_SEC_CONF);
	entries = cfg_get_section(cfg, &entry, "dsvol");
	for (set = 1; set <= entries; set++) {
		buf = entry[set - 1];

		/* split up the line */
		if (!(path = strtok(buf, " "))) {
			/* oops, now what? */
			free(buf);
			break;
		}
		if (!(cnode = strtok(0, " "))) {
			free(buf);
			break;
		}
		if (ctag && (strcmp(cnode, ctag) != 0)) {
			++offset;
			free(buf);
			continue;
		}

		if (!(users = strtok(0, " "))) {
			free(buf);
			break;
		}

		data = make_dsvol_data(path, cnode, users, set - offset);
		if (!data) {
			free(buf);
			break;
		}
		(void) snprintf(search_key, CFG_MAX_KEY, "%s:%s", path, cnode);
		rc = nsc_insert_node(dsvol, data, search_key);
		if (rc < 0) {
			free(buf);
			break;
		}

		/* we also need to keep track of node information */
		rc = add_dev_entry(path);
		if (rc < 0) {
			free(buf);
			break;
		} else if (rc)
			++devs_added;

		free(buf);
		rc = 0;
	}

	while (set < entries)
		free(entry[set++]);
	if (entries)
		free(entry);

	if (devs_added) {
		qsort(devlist, devcount, sizeof (device_t), compare);
		rebuild_devhash();
	}

	dsvol_loaded = 1;
	return (rc < 0? rc : entries);
}

/*
 * cfg_unload_dsvols
 *
 * Description:
 *	Free all memory allocated with cfg_load_dsvols.
 */
void
cfg_unload_dsvols()
{
	if (dsvol) {
		nsc_remove_all(dsvol, delete_dsvol_data);
		dsvol = 0;
		dsvol_loaded = 0;
	}
}

/*
 * cfg_load_svols
 *
 * Description:
 *	Loads the sv section of the config file into a giant hash, to make
 *	searching faster.  The important bit to remember is to not release
 *	the write lock between calling cfg_load_svols() and the cfg_*_user()
 *	functions.
 *
 * Assumptions:
 *	1/ cfg file is open
 *	2/ cfg file has been write-locked
 *	3/ user of this routine may already be using builtin hcreate/hsearch
 */
int
cfg_load_svols(CFGFILE *cfg)
{
	int set, entries, offset = 0;
	char *buf, **entry;
	char *path, *mode, *cnode;
	hash_data_t *data;
	char *ctag = cfg_get_resource(cfg);
	if (!ctag || *ctag == '\0') {
		ctag = "-";
	}

	svol = nsc_create_hash();
	if (!svol) {
		return (-1);
	}

	cfg_rewind(cfg, CFG_SEC_CONF);
	entries = cfg_get_section(cfg, &entry, "sv");
	for (set = 1; set <= entries; set++) {
		buf = entry[set - 1];

		/* split up the line */
		if (!(path = strtok(buf, " "))) {
			free(buf);
			break;
		}
		if (!(mode = strtok(0, " "))) {
			free(buf);
			break;
		}
		if (!(cnode = strtok(0, " "))) {
			cnode = "";
		}

		if (ctag && (strcmp(cnode, ctag) != 0)) {
			++offset;
			free(buf);
			continue;
		}

		data = make_svol_data(path, mode, cnode, set - offset);
		if (!data) {
			free(buf);
			break;
		}
		if (nsc_insert_node(svol, data, path) < 0) {
			free(buf);
			break;
		}
		free(buf);
	}
	while (set < entries)
		free(entry[set++]);
	if (entries)
		free(entry);

	svol_loaded = 1;
	return (0);
}

/*
 * cfg_unload_svols
 *
 * Description:
 *	Frees all memory allocated with cfg_load_dsvols
 */
void
cfg_unload_svols()
{
	if (svol) {
		nsc_remove_all(svol, delete_svol_data);
		svol = 0;
		svol_loaded = 0;
	}
}

/*
 * cfg_get_canonical_name
 *
 * Description:
 *	Find out whether a device is already known by another name in
 *	the config file.
 *
 * Parameters:
 *	cfg - The config file to use
 *	path - The pathname of the device
 *	result - (output) The name it is otherwise known as.  This parameter
 *			must be freed by the caller.
 *
 * Return values:
 *	-1: error
 *	0: name is as expected, or is not known
 *	1: Name is known by different name (stored in 'result')
 */
int
cfg_get_canonical_name(CFGFILE *cfg, const char *path, char **result)
{
	int self_loaded;
	char *alt_path;
	int retval;

	if (devlist) {
		self_loaded = 0;
	} else {
		if (cfg_load_shadows(cfg) < 0) {
			return (-1);
		}
		self_loaded = 1;
	}

	/* see if it exists under a different name */
	alt_path = find_devid(path);
	if (!alt_path || strcmp(path, alt_path) == 0) {
		*result = NULL;
		retval = 0;
	} else {
		/* a-ha */
		*result = strdup(alt_path);
		retval = 1;
	}

	if (self_loaded) {
		free_dev_entries();
	}

	return (retval);
}

/*
 * cfg_load_shadows
 *
 * Description:
 *	Load in shadow and bitmap volumes from the II section of the
 *	config file.  SNDR's volumes are handled already by cfg_load_dsvols.
 *	Not all shadow volumes are listed under dsvol: they can be exported.
 *
 * Parameters:
 *	cfg - The config file to use
 *
 * Return values:
 *	-1: error
 *	0: success
 */
int
cfg_load_shadows(CFGFILE *cfg)
{
	int set, self_loaded, rc, entries;
	char *buf, **entry, *ptr;
	int devs_added = 0;

	if (dsvol_loaded) {
		self_loaded = 0;
	} else {
		if (cfg_load_dsvols(cfg) < 0) {
			return (-1);
		}
		self_loaded = 1;
	}

	shadowvol = nsc_create_hash();
	if (!shadowvol) {
		return (-1);
	}

	rc = 0;
	cfg_rewind(cfg, CFG_SEC_CONF);
	entries = cfg_get_section(cfg, &entry, "ii");
	for (set = 1; set <= entries; set++) {
		buf = entry[set - 1];

		/* skip the master vol */
		ptr = strtok(buf, " ");

		/* shadow is next */
		ptr = strtok(NULL, " ");

		rc = add_dev_entry(ptr);
		if (rc < 0) {
			free(buf);
			break;
		} else if (rc)
			++devs_added;

		/* and next is bitmap */
		ptr = strtok(NULL, " ");

		rc = add_dev_entry(ptr);
		if (rc < 0) {
			free(buf);
			break;
		} else if (rc)
			++devs_added;
		rc = 0;
		free(buf);
	}
	while (set < entries)
		free(entry[set++]);
	if (entries)
		free(entry);

	if (self_loaded) {
		cfg_unload_dsvols();
	}

	if (devs_added) {
		/* sort it, in preparation for lookups */
		qsort(devlist, devcount, sizeof (device_t), compare);
		rebuild_devhash();
	}

	return (rc);
}

void
cfg_unload_shadows()
{
	/* do nothing */
}

/* ---------------------------------------------------------------------- */

static hash_data_t *
make_dsvol_data(char *path, char *cnode, char *users, int set)
{
	hash_data_t *data;

	data = (hash_data_t *)malloc(sizeof (hash_data_t));
	if (!data) {
		return (0);
	}

	data->u.users = strdup(users);
	data->path = strdup(path);
	data->node = strdup(cnode);
	data->setno = set;

	return (data);
}

static void
delete_dsvol_data(void *data)
{
	hash_data_t *p = (hash_data_t *)data;

	free(p->u.users);
	free(p->path);
	free(p->node);
	free(p);
}

static hash_data_t *
make_svol_data(char *path, char *mode, char *cnode, int set)
{
	hash_data_t *data;

	data = (hash_data_t *)malloc(sizeof (hash_data_t));
	if (!data) {
		return (0);
	}

	data->u.mode = strdup(mode);
	data->path = strdup(path);
	data->node = strdup(cnode);
	data->setno = set;

	return (data);
}


static void
delete_svol_data(void *data)
{
	hash_data_t *p = (hash_data_t *)data;

	free(p->u.mode);
	free(p->path);
	free(p->node);
	free(p);
}

static int
sv_action(char *path, CFGFILE *caller_cfg, char *ctag, int enable)
{
	struct stat stb;
	sv_conf_t svc;
	int fd = -1;
	int cfg_changed = 0;
	CFGFILE *cfg;
	int print_log = 0;
	int err = 0, rc;
	int sv_ioctl, spcs_err, self_loaded;
	char *log_str1, *log_str2;
	char key[ CFG_MAX_KEY ];
	char buf[ CFG_MAX_BUF ];
	hash_data_t *node;
	device_t *statinfo = 0;

	if (caller_cfg == NULL) {
		cfg = cfg_open(NULL);
		if (cfg == NULL)
			return (-1);

		if (ctag)
			cfg_resource(cfg, ctag);
	} else
		cfg = caller_cfg;


	self_loaded = 0;
	sv_ioctl = (enable? SVIOC_ENABLE : SVIOC_DISABLE);
	log_str1 = (enable? gettext("enabled %s") : gettext("disabled %s"));
	log_str2 = (enable? gettext("unable to enable %s") :
	    gettext("unable to disable %s"));
	spcs_err = (enable? SV_EENABLED : SV_EDISABLED);
	bzero(&svc, sizeof (svc));

	if (devhash)
		statinfo = nsc_lookup(devhash, path);

	if (statinfo) {
		if (!S_ISCHR(statinfo->mode))
			goto error;
		svc.svc_major = major(statinfo->rdev);
		svc.svc_minor = minor(statinfo->rdev);
	} else {
		if (stat(path, &stb) != 0)
			goto error;

		if (!S_ISCHR(stb.st_mode))
			goto error;
		svc.svc_major = major(stb.st_rdev);
		svc.svc_minor = minor(stb.st_rdev);
	}

	strncpy(svc.svc_path, path, sizeof (svc.svc_path));

	fd = open(SV_DEVICE, O_RDONLY);
	if (fd < 0)
		goto error;

	svc.svc_flag = (NSC_DEVICE | NSC_CACHE);
	svc.svc_error = spcs_s_ucreate();

	do {
		rc = ioctl(fd, sv_ioctl, &svc);
	} while (rc < 0 && errno == EINTR);

	if (rc < 0) {
		if (errno != spcs_err) {
			spcs_log("sv", &svc.svc_error, log_str2, svc.svc_path);
			if (enable)
				goto error;
			else
				err = errno;
		} else
			err = spcs_err;
	}

	spcs_log("sv", NULL, log_str1, svc.svc_path);

	/* SV enable succeeded */
	if (caller_cfg == NULL)	 /* was not previously locked */
		if (!cfg_lock(cfg, CFG_WRLOCK))
			goto error;

	if (err != spcs_err) { /* already enabled, already in config */
		if (enable) {
			cfg_rewind(cfg, CFG_SEC_CONF);
			(void) snprintf(buf, CFG_MAX_BUF, "%s - %s", path,
			    ctag? ctag : "-");
			if (cfg_put_cstring(cfg, "sv", buf, CFG_MAX_BUF) < 0) {
				/* SV config not updated, so SV disable again */
				(void) ioctl(fd, SVIOC_DISABLE, &svc);
				print_log++;
			} else
				cfg_changed = 1;
		} else {
			/* pull it out of the config */
			if (!svol_loaded) {
				if (cfg_load_svols(cfg) < 0) {
					if (NULL == caller_cfg) {
						cfg_close(cfg);
					}
					return (-1);
				}
				self_loaded = 1;
			}
			node = nsc_lookup(svol, svc.svc_path);
			if (node) {
				cfg_rewind(cfg, CFG_SEC_CONF);
				(void) snprintf(key, CFG_MAX_KEY, "sv.set%d",
				    node->setno);
				if (cfg_put_cstring(cfg, key, NULL, NULL) < 0) {
					spcs_log("sv", NULL,
					    gettext("failed to remove %s from "
					    "sv config"), svc.svc_path);
				}
				/*
				 * Since we deleted an entry from the config
				 * file, we don't know what all the new
				 * set numbers are.  We need to reload
				 * everything
				 */
				if (!self_loaded) {
					cfg_unload_svols();
					if (cfg_load_svols(cfg) < 0) {
						if (NULL == caller_cfg) {
							cfg_close(cfg);
						}
						return (-1);
					}
				}
				cfg_changed = 1;
			}
			if (self_loaded) {
				cfg_unload_svols();
				self_loaded = 0;
			}
		}
	}

#ifdef lint
	(void) printf("extra line to shut lint up %s\n", module_names[0]);
#endif

error:
	if (fd >= 0)
		(void) close(fd);

	if (cfg == NULL)
		return (-1);

	if (cfg_changed)
		if (caller_cfg == NULL) /* we opened config */
			(void) cfg_commit(cfg);

	if (caller_cfg == NULL)
		cfg_close(cfg);
	if ((cfg_changed) || (err == spcs_err))
		return (1);
	if (print_log)
		spcs_log("sv", NULL,
			gettext("unable to add to configuration, disabled %s"),
			svc.svc_path);
	spcs_s_ufree(&svc.svc_error);

	return (-1);
}

/*
 * add_dev_entry
 *
 * Add an entry into the devlist and the devhash for future lookups.
 *
 * Return values:
 *  -1  An error occurred.
 *   0  Entry added
 *   1  Entry already exists.
 */
static int
add_dev_entry(const char *path)
{
	struct stat buf;
	device_t *newmem;
	hash_data_t *data;

	if (!devhash) {
		devhash = nsc_create_hash();
		if (!devhash) {
			return (-1);
		}
	} else {
		data = nsc_lookup(devhash, path);
		if (data) {
			return (1);
		}
	}

	if (stat(path, &buf) < 0) {
		/* ignore error, we are most likely deleting entry anyway */
		buf.st_rdev = 0;
	}

	if (devcount >= devalloc) {
		/* make some room */
		devalloc += DEV_EXPAND;
		newmem = (device_t *)realloc(devlist, devalloc *
		    sizeof (device_t));
		if (!newmem) {
			free_dev_entries();
			return (-1);
		} else {
			devlist = newmem;
		}
	}

	devlist[ devcount ].path = strdup(path);
	devlist[ devcount ].rdev = buf.st_rdev;
	devlist[ devcount ].mode = buf.st_mode;

	if (nsc_insert_node(devhash, &devlist[devcount], path) < 0) {
		return (-1);
	}

	++devcount;
	return (0);
}

static void
rebuild_devhash()
{
	int i;

	if (!devhash)
		nsc_remove_all(devhash, 0);

	devhash = nsc_create_hash();
	if (!devhash)
		return;

	for (i = 0; i < devcount; i++) {
		nsc_insert_node(devhash, &devlist[i], devlist[i].path);
	}
}

static int
compare(const void *va, const void *vb)
{
	device_t *a = (device_t *)va;
	device_t *b = (device_t *)vb;

	return (b->rdev - a->rdev);
}

static char *
find_devid(const char *path)
{
	device_t key;
	device_t *result;
	struct stat buf;

	if (!devlist || !devhash)
		return (NULL);

	/* See if we already know the device id by this name */
	result = (device_t *)nsc_lookup(devhash, path);
	if (result) {
		return (NULL);
	}

	/* try to find it by another name */
	if (stat(path, &buf) < 0)
		return (NULL);

	key.rdev = buf.st_rdev;

	/* it's storted, so we use the binary-chop method to find it */
	result = bsearch(&key, devlist, devcount, sizeof (device_t), compare);

	if (result) {
		return (result->path);
	}

	return (NULL);
}

static void
free_dev_entries()
{
	int i;
	device_t *p;

	if (!devlist) {
		return;
	}
	for (i = 0, p = devlist; i < devcount; i++, p++) {
		free(p->path);
	}
	free(devlist);
	devlist = NULL;
	devcount = 0;
	devalloc = 0;

	if (devhash) {
		nsc_remove_all(devhash, 0);
		devhash = NULL;
	}
}
