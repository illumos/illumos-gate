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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * This module fetches group and passwd structs for the caller. It
 * uses a hash table to speed up retrieval of repeated entries. If
 * the attempts to initialize the hash tables fail, this just
 * continues the slow way.
 */

#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "pkglib.h"
#include "pkglocale.h"
#include "nhash.h"

#define	HASHSIZE	151
#define	BSZ		4

#define	ERR_DUPFAIL	"%s: strdup(%s) failed.\n"
#define	ERR_ADDFAIL	"%s: add_cache() failed.\n"
#define	ERR_BADMEMB	"%s: %s in \"%s\" %s structure is invalid.\n"
#define	ERR_NOGRP	"dup_gr_ent(): no group entry provided.\n"
#define	ERR_NOPWD	"dup_pw_ent(): no passwd entry provided.\n"
#define	ERR_NOINIT	"%s: init_cache() failed.\n"
#define	ERR_MALLOC	"%s: malloc(%d) failed for %s.\n"

static Cache *pwnam_cache = (Cache *) NULL;
static Cache *grnam_cache = (Cache *) NULL;
static Cache *pwuid_cache = (Cache *) NULL;
static Cache *grgid_cache = (Cache *) NULL;

static int dup_gr_ent(struct group *grp);
static int dup_pw_ent(struct passwd *pwp);

/*
 * These indicate whether the hash table has been initialized for the four
 * categories.
 */
static int is_a_pwnam_cache;
static int is_a_grnam_cache;
static int is_a_pwuid_cache;
static int is_a_grgid_cache;

extern char *get_install_root(void);

/*
 * If there's a grnam cache, then update it with this new
 * group, otherwise, skip it.
 */
static Item *
cache_alloc(char *fname, int len, size_t struct_size)
{
	Item *itemp;

	/*
	 * Allocate space for the Item pointer, key and data.
	 */
	if ((itemp = (Item *) malloc(sizeof (*itemp))) ==
	    Null_Item) {
		(void) fprintf(stderr,
		    pkg_gt(ERR_MALLOC), fname,
		    sizeof (*itemp), "itemp");
	} else if ((itemp->key = (char *)malloc(len)) == NULL) {
		(void) fprintf(stderr, pkg_gt(ERR_MALLOC), fname, len,
		    "itemp->key");
		free(itemp);
	} else if ((itemp->data = malloc(struct_size)) == NULL) {
		(void) fprintf(stderr, pkg_gt(ERR_MALLOC), fname,
		    struct_size, "itemp->data");
		free(itemp->key);
		free(itemp);
	} else {
		/* Set length parameters. */
		itemp->keyl = len;
		itemp->datal = struct_size;

		return (itemp);
	}

	return ((Item *) NULL);
}

/* Get the required group structure based upon the group name. */
struct group *
cgrnam(char *nam)
{
	struct group *grp;
	Item *itemp;
	int len;
	static int cache_failed;

	/* Attempt to initialize the grname cache. */
	if (!is_a_grnam_cache && !cache_failed) {
		if (init_cache(&grnam_cache, HASHSIZE, BSZ,
		    (int (*)())NULL, (int (*)())NULL) == -1) {
			(void) fprintf(stderr, pkg_gt(ERR_NOINIT), "cgrnam()");
			grnam_cache = (Cache *) NULL;
			cache_failed = 1;
		} else
			is_a_grnam_cache = 1;
	}

	len = strlen(nam) + 1;

	/* First look in the cache. Failing that, do it the hard way. */
	if ((itemp = lookup_cache(grnam_cache, nam, len)) == Null_Item) {

		/* Get the group by name. */
		if ((grp = clgrnam(nam)) != NULL ||
				(grp = getgrnam(nam)) != NULL) {
			/* A group by that name exists on this machine. */
			if (dup_gr_ent(grp))
				/*
				 * Effectively no such group since struct
				 * couldn't be duplicated.
				 */
				grp = (struct group *)NULL;
			/*
			 * If there's a grnam cache, then update it with this
			 * new group, otherwise, skip it.
			 */
			else if (is_a_grnam_cache) {
				if ((itemp = cache_alloc("cgrnam()", len,
				    sizeof (struct group))) != Null_Item) {
					/*
					 * With that allocated, insert the
					 * group name as key and set the key
					 * length.
					 */
					(void) memmove(itemp->key, nam, len);

					/*
					 * Insert the data associated with
					 * the key and the data length.
					 */
					(void) memmove(itemp->data, grp,
					    sizeof (struct group));

					/* Insert the Item into the cache. */
					if (add_cache(grnam_cache, itemp) == -1)
						(void) fprintf(stderr,
						    pkg_gt(ERR_ADDFAIL),
						    "cgrnam()");
				}
			}
		}
		return (grp);
	} else	/* Found it in the cache. */
		return ((struct group *)itemp->data);
}

struct passwd *
cpwnam(char *nam)
{
	struct passwd *pwd;
	Item *itemp;
	int len;
	static int cache_failed;

	if (!is_a_pwnam_cache && !cache_failed) {
		if (init_cache(&pwnam_cache, HASHSIZE, BSZ,
		    (int (*)())NULL, (int (*)())NULL) == -1) {
			(void) fprintf(stderr, pkg_gt(ERR_NOINIT), "cpwnam()");
			pwnam_cache = (Cache *) NULL;
			cache_failed = 1;
		} else
			is_a_pwnam_cache = 1;
	}

	len = strlen(nam) + 1;

	/* First look in the cache. Failing that, do it the hard way. */
	if ((itemp = lookup_cache(pwnam_cache, nam, len)) == Null_Item) {

		/* Get the passwd by name. */
		if ((pwd = clpwnam(nam)) != NULL ||
				(pwd = getpwnam(nam)) != NULL) {
			/* A passwd by that name exists on this machine. */
			if (dup_pw_ent(pwd))
				/*
				 * Effectively no such passwd since struct
				 * couldn't be duplicated.
				 */
				pwd = (struct passwd *)NULL;
			/*
			 * If there's a pwnam cache, then update it with this
			 * new passwd, otherwise, skip it.
			 */
			else if (is_a_pwnam_cache) {
				/*
				 * Allocate space for the Item pointer, key
				 * and data.
				 */
				if ((itemp = cache_alloc("cpwnam()", len,
				    sizeof (struct passwd))) != Null_Item) {
					/*
					 * With that allocated, insert the
					 * group name as key and set the key
					 * length.
					 */
					(void) memmove(itemp->key, nam, len);

					/*
					 * Insert the data associated with
					 * the key and the data length.
					 */
					(void) memmove(itemp->data, pwd,
					    sizeof (struct passwd));

					if (add_cache(pwnam_cache, itemp) == -1)
						(void) fprintf(stderr,
						    pkg_gt(ERR_ADDFAIL),
						    "cpwnam()");
				}
			}
		}
		return (pwd);
	} else	/* Found it in the cache. */
		return ((struct passwd *)itemp->data);
}

static int
uid_hash(void *datap, int datalen, int hsz)
{
#ifdef lint
	int i = datalen;
	datalen = i;
#endif	/* lint */

	return (*((uid_t *)datap) % hsz);
}

static int
uid_comp(void *datap1, void *datap2, int datalen)
{
#ifdef lint
	int i = datalen;
	datalen = i;
#endif	/* lint */

	return (*((uid_t *)datap1) - *((uid_t *)datap2));
}

struct group *
cgrgid(gid_t gid)
{
	struct group *grp;
	Item *itemp;
	int len;
	static int cache_failed;

	if (!is_a_grgid_cache && !cache_failed) {
		if (init_cache(&grgid_cache, HASHSIZE, BSZ,
		    uid_hash, uid_comp) == -1) {
			(void) fprintf(stderr, pkg_gt(ERR_NOINIT), "cgrgid()");
			grgid_cache = (Cache *) NULL;
			cache_failed = 1;
		} else
			is_a_grgid_cache = 1;
	}

	len = sizeof (uid_t);

	/* First look in the cache. Failing that, do it the hard way. */
	if ((itemp = lookup_cache(grgid_cache, &gid, len)) == Null_Item) {
		if ((grp = clgrgid(gid)) != NULL ||
				(grp = getgrgid(gid)) != NULL) {
			/* A group by that number exists on this machine. */
			if (dup_gr_ent(grp))
				/*
				 * Effectively no such group since struct
				 * couldn't be duplicated.
				 */
				grp = (struct group *)NULL;
			/*
			 * If there's a grnam cache, then update it with this
			 * new group, otherwise, skip it.
			 */
			else if (is_a_grgid_cache) {
				if ((itemp = cache_alloc("cgrgid()", len,
				    sizeof (struct group))) != Null_Item) {
					/*
					 * With that allocated, insert the
					 * group name as key and set the key
					 * length.
					 */
					(void) memmove(itemp->key, &gid, len);

					/*
					 * Insert the data associated with
					 * the key and the data length.
					 */
					(void) memmove(itemp->data, grp,
					    sizeof (struct group));

					if (add_cache(grgid_cache, itemp) == -1)
						(void) fprintf(stderr,
						    pkg_gt(ERR_ADDFAIL),
						    "cgrgid()");
				}
			}
		}
		return (grp);
	} else	/* Found it in the cache. */
		return ((struct group *)itemp->data);
}

struct passwd *
cpwuid(uid_t uid)
{
	struct passwd *pwd;
	Item *itemp;
	int len;
	static int cache_failed;

	if (!is_a_pwuid_cache && !cache_failed) {
		if (init_cache(&pwuid_cache, HASHSIZE, BSZ,
		    uid_hash, uid_comp) == -1) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_NOINIT), "cpwuid()");
			pwuid_cache = (Cache *) NULL;
			cache_failed = 1;
		} else
			is_a_pwuid_cache = 1;
	}

	len = sizeof (uid_t);

	/* First look in the cache. Failing that, do it the hard way. */
	if ((itemp = lookup_cache(pwuid_cache, &uid, len)) == Null_Item) {

		/* Get the passwd by number. */
		if ((pwd = clpwuid(uid)) != NULL ||
				(pwd = getpwuid(uid)) != NULL) {
			/* A passwd by that user ID exists on this machine. */
			if (dup_pw_ent(pwd))
				/*
				 * Effectively no such passwd since struct
				 * couldn't be duplicated.
				 */
				pwd = (struct passwd *)NULL;
			/*
			 * If there's a pwuid cache, then update it with this
			 * new passwd, otherwise, skip it.
			 */
			else if (is_a_pwuid_cache) {
				if ((itemp = cache_alloc("cpwuid()", len,
				    sizeof (struct passwd))) != Null_Item) {
					/*
					 * With that allocated, insert the
					 * group name as key and set the key
					 * length.
					 */
					(void) memmove(itemp->key, &uid, len);

					/*
					 * Insert the data associated with
					 * the key and the data length.
					 */
					(void) memmove(itemp->data, pwd,
					    sizeof (struct passwd));

					if (add_cache(pwuid_cache, itemp) == -1)
						(void) fprintf(stderr,
						    pkg_gt(ERR_ADDFAIL),
						    "cpwuid()");
				}
			}
		}
		return (pwd);
	} else	/* Found it in the cache. */
		return ((struct passwd *)itemp->data);
}

/*
 * This function duplicates the group structure provided from kernel static
 * memory. There is a lot of defensive coding here because there have been
 * problems with the getgr*() functions. They will sometimes provide NULL
 * values instead of pointers to NULL values. There has been no explanation
 * for the reason behind this; but, this function takes a NULL to be an
 * invalid (char *) and returns an error.
 */
static int
dup_gr_ent(struct group *grp)
{
	char **tp = NULL;
	char **memp = NULL;
	int	nent = 0;	/* Number of entries in the member list. */

	if (grp) {
		if (grp->gr_name == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_gr_ent()", "gr_name",
			    "unknown", "group");
			return (-1);
		} else if ((grp->gr_name = strdup(grp->gr_name)) == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_DUPFAIL), "dup_gr_ent()", "gr_name");
			return (-1);
		}
		if (grp->gr_passwd == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_gr_ent()", "gr_passwd",
			    grp->gr_name, "group");
			return (-1);
		} else if ((grp->gr_passwd = strdup(grp->gr_passwd)) == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_DUPFAIL), "dup_gr_ent()", "gr_passwd");
			return (-1);
		}
		/*
		 * Allocate space for the member list and move the members
		 * into it.
		 */
		if (grp->gr_mem) {
			/*
			 * First count the members. The nent variable will be
			 * the number of members + 1 for the terminator.
			 */
			for (tp = grp->gr_mem; *tp; nent++, tp++);

			/* Now allocate room for the pointers. */
			memp = malloc(sizeof (char **)* (nent+1));

			if (memp == NULL) {
				(void) fprintf(stderr,
				    pkg_gt(ERR_MALLOC), "dup_gr_ent()",
				    (sizeof (char **)* (nent+1)),
				    "memp");
				return (-1);
			}

			/*
			 * Now copy over the pointers and entries. It should
			 * be noted that if the structure is messed up here,
			 * the resulting member list will be truncated at the
			 * NULL entry.
			 */
			for (nent = 0, tp = grp->gr_mem; *tp; tp++) {
				if ((memp[nent++] = strdup(*tp)) == NULL) {
					(void) fprintf(stderr,
					    pkg_gt(ERR_DUPFAIL), "dup_gr_ent()",
					    "gr_mem");
					return (-1);
				}
			}
		} else {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_gr_ent()", "gr_mem",
			    grp->gr_name, "group");
			return (-1);
		}
	} else {
		(void) fprintf(stderr, pkg_gt(ERR_NOGRP));
		return (-1);
	}
	memp[nent++] = '\0';
	return (0);
}

/*
 * This function duplicates the passwd structure provided from kernel static
 * memory. As in the above function, since there have been problems with the
 * getpw*() functions, the structure provided is rigorously scrubbed. This
 * function takes a NULL to be an invalid (char *) and returns an error if
 * one is detected.
 */
static int
dup_pw_ent(struct passwd *pwd)
{
	if (pwd) {
		if (pwd->pw_name == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_pw_ent()", "pw_name",
			    "unknown", "passwd");
			return (-1);
		} else if ((pwd->pw_name = strdup(pwd->pw_name)) == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_DUPFAIL), "dup_pw_ent()", "pw_name");
			return (-1);
		}

		if (pwd->pw_passwd == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_pw_ent()", "pw_passwd",
			    pwd->pw_name, "passwd");
			return (-1);
		} else if ((pwd->pw_passwd = strdup(pwd->pw_passwd)) == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_DUPFAIL), "dup_pw_ent()", "pw_passwd");
			return (-1);
		}

		if (pwd->pw_age == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_pw_ent()", "pw_age",
			    pwd->pw_name, "passwd");
			return (-1);
		} else if ((pwd->pw_age = strdup(pwd->pw_age)) == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_DUPFAIL), "dup_pw_ent()", "pw_age");
			return (-1);
		}

		if (pwd->pw_comment == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_pw_ent()", "pw_comment",
			    pwd->pw_name, "passwd");
			return (-1);
		} else if ((pwd->pw_comment = strdup(pwd->pw_comment)) ==
		    NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_DUPFAIL), "dup_pw_ent()", "pw_comment");
			return (-1);
		}

		if (pwd->pw_gecos == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_pw_ent()", "pw_gecos",
			    pwd->pw_name, "passwd");
			return (-1);
		} else if ((pwd->pw_gecos = strdup(pwd->pw_gecos)) == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_DUPFAIL), "dup_pw_ent()", "pw_gecos");
			return (-1);
		}

		if (pwd->pw_dir == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_pw_ent()", "pw_dir",
			    pwd->pw_name, "passwd");
			return (-1);
		} else if ((pwd->pw_dir = strdup(pwd->pw_dir)) == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_DUPFAIL), "dup_pw_ent()", "pw_dir");
			return (-1);
		}

		if (pwd->pw_shell == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_BADMEMB), "dup_pw_ent()", "pw_shell",
			    pwd->pw_name, "passwd");
			return (-1);
		} else if ((pwd->pw_shell = strdup(pwd->pw_shell)) == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_DUPFAIL), "dup_pw_ent()", "pw_shell");
			return (-1);
		}
	} else {
		(void) fprintf(stderr, pkg_gt(ERR_NOPWD));
		return (-1);
	}

	return (0);
}

/*
 * Check the client's etc/group file for the group name
 *
 * returns a pointer to the group structure if the group is found
 * returns NULL if not found
 */
struct group *
clgrnam(char *nam)
{
	struct group *gr;
	char *instroot, *buf;
	FILE *gr_ptr;
	size_t bufsz;

	if ((instroot = get_install_root()) != NULL) {
		bufsz = strlen(instroot) + strlen(GROUP) + 1;
		if ((buf = (char *)malloc(bufsz)) == NULL) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_MALLOC), "clgrnam()",
			    strlen(instroot) + strlen(GROUP), "buf");
		}
		(void) snprintf(buf, bufsz, "%s%s", instroot, GROUP);
		if ((gr_ptr = fopen(buf, "r")) == NULL) {
			free(buf);
			return (NULL);
		} else {
			while ((gr = fgetgrent(gr_ptr)) != NULL) {
				if (strcmp(gr->gr_name, nam) == 0) {
					break;
				}
			}
		}
		free(buf);
		(void) fclose(gr_ptr);
		return (gr);
	} else {
		return (NULL);
	}
}

/*
 * Check the client's etc/passwd file for the user name
 *
 * returns a pointer to the passwd structure if the passwd is found
 * returns NULL if not found
 */
struct passwd *
clpwnam(char *nam)
{
	struct passwd *pw;
	char *instroot, *buf;
	FILE *pw_ptr;

	if ((instroot = get_install_root()) != NULL) {
		if (asprintf(&buf, "%s%s", instroot, PASSWD) < 0) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_MALLOC), "clpwnam()",
			    strlen(instroot) + strlen(PASSWD), "buf");
			return (NULL);
		}
		if ((pw_ptr = fopen(buf, "r")) == NULL) {
			free(buf);
			return (NULL);
		} else {
			while ((pw = fgetpwent(pw_ptr)) != NULL) {
				if (strcmp(pw->pw_name, nam) == 0) {
					break;
				}
			}
		}
		free(buf);
		(void) fclose(pw_ptr);
		return (pw);
	} else {
		return (NULL);
	}
}

/*
 * Check the client's etc/group file for the group id
 *
 * returns a pointer to the group structure if the group id is found
 * returns NULL if not found
 */
struct group *
clgrgid(gid_t gid)
{
	struct group *gr;
	char *instroot, *buf;
	FILE *gr_ptr;

	if ((instroot = get_install_root()) != NULL) {
		if (asprintf(&buf, "%s%s", instroot, GROUP) < 0) {
			(void) fprintf(stderr,
			    pkg_gt(ERR_MALLOC), "clgrgid()",
			    strlen(instroot) + strlen(GROUP), "buf");
			return (NULL);
		}

		if ((gr_ptr = fopen(buf, "r")) == NULL) {
			free(buf);
			return (NULL);
		} else {
			while ((gr = fgetgrent(gr_ptr)) != NULL) {
				if (gr->gr_gid == gid) {
					break;
				}
			}
		}
		free(buf);
		(void) fclose(gr_ptr);
		return (gr);
	} else {
		return (NULL);
	}
}

/*
 * Check the client's etc/passwd file for the user id
 *
 * returns a pointer to the passwd structure if the user id is found
 * returns NULL if not found
 */
struct passwd *
clpwuid(uid_t uid)
{
	struct passwd *pw;
	char *instroot, *buf;
	FILE *pw_ptr;

	if ((instroot = get_install_root()) != NULL) {
		if (asprintf(&buf, "%s%s", instroot, PASSWD) < 0) {
			(void) fprintf(stderr, pkg_gt(ERR_MALLOC), "clpwuid()",
			    strlen(instroot) + strlen(PASSWD), "buf");
			return (NULL);
		}
		if ((pw_ptr = fopen(buf, "r")) == NULL) {
			free(buf);
			return (NULL);
		} else {
			while ((pw = fgetpwent(pw_ptr)) != NULL) {
				if (pw->pw_uid == uid) {
					break;
				}
			}
		}
		free(buf);
		(void) fclose(pw_ptr);
		return (pw);
	} else {
		return (NULL);
	}
}
