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

#ifndef	_CFG_H
#define	_CFG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/nsctl/nsctl.h>

#define	CFG_MAX_BUF	1024    /* maximum buffer size for cfg_get_?string() */
#define	CFG_MAX_KEY	256	/* maximum key size for cfg_get_?string() */

#ifndef _CFG_IMPL_H
/*
 * These are really declared in cfg_impl.h, declare as dummy's here to
 * allow clients to compile without including cfg_impl.h.
 */
typedef struct cfgfile CFGFILE;
typedef struct cfp cfp_t;

#endif	/* _CFG_IMPL_H */

int cfg_get_cstring(CFGFILE *cfg, const char *key, void *value, int value_len);
int cfg_put_cstring(CFGFILE *cfg, const char *key, void *value, int value_len);
int cfg_find_cstring(CFGFILE *cfg, const char *target, const char *section,
    int numflds, ...);
int cfg_get_options(CFGFILE *cfg, int section, const char *basekey,
				char *tag, int tag_len, char *val, int val_len);
int cfg_put_options(CFGFILE *cfg, int section, const char *basekey,
				char *tag, char *val);
int cfg_get_single_option(CFGFILE *, int, const char *, char *, char *, int);
int cfg_del_option(CFGFILE *, int, const char *, char *);

int cfg_get_num_entries(CFGFILE *cfg, char *section);

int cfg_get_tags(CFGFILE *cfg, char ***taglist);

int cfg_cfg_isempty(CFGFILE *cfg);
int cfg_get_section(CFGFILE *cfg, char ***buf, const char *section);
CFGFILE *cfg_open(char *filename);
void cfg_rewind(CFGFILE *cfg, int section);
int cfg_is_cfg(CFGFILE *cfg);
int cfg_shldskip_vtoc(int fd, const char *loc);
int cfg_get_srtdsec(CFGFILE *cfg, char ***list,
	const char *sec, const char *field);
void cfg_free_section(char ***, int);


/*
 * Handle cluster configuration
 */
#define	FP_SUN_CLUSTER(x) \
	(((x->cf_node) && (x->cf[1].cf_fd)) ? &x->cf[1] : &x->cf[0])

/*
 * rewind sections
 */
#define	CFG_SEC_CONF	0	/* configuration section */
#define	CFG_SEC_PERS	1	/* persistent section */
#define	CFG_SEC_ALL	2	/* rewind both sections */

int cfg_update_parser_config(CFGFILE *, const char *key, int section);
/*
 * parser sections
 */
#define	CFG_PARSE_CONF	0	/* config section key */
#define	CFG_PARSE_PERS	1	/* persistent section key */

char *cfg_error(int *severity);
/*
 * error codes
 */
#define	CFG_ENONFATAL	0	/* non fatal error */
#define	CFG_EFATAL	1	/* fatal error exit */

/*
 * some error strings
 */
#define	CFG_NOTLOCKED	"Configuration not locked"
#define	CFG_RDFAILED	"Unable to read configuration"
#define	CFG_EINVAL	"Invalid Argument"
#define	CFG_EGENERIC	"Generic cfg failure"


char *cfg_location(char *location, int mode, char *altroot);

/*
 * location modes
 */
#define	CFG_LOC_SET_LOCAL	0
#define	CFG_LOC_GET_LOCAL	1
#define	CFG_LOC_SET_CLUSTER	2
#define	CFG_LOC_GET_CLUSTER	3

/*
 * location strings
 */
#define	CFG_LOCAL_LOCATION	"/etc/dscfg_local"
#define	CFG_CLUSTER_LOCATION	"/etc/dscfg_cluster"

void cfg_close(CFGFILE *);

/*
 * lock mode
 */
typedef enum {
	CFG_RDLOCK,
	CFG_WRLOCK,
	CFG_UPGRADE
} CFGLOCK;

int cfg_lock(CFGFILE *, CFGLOCK);	/* lock the configuration */
void cfp_unlock(cfp_t *);		/* unlock the configuration */
void cfg_unlock(CFGFILE *);
int cfg_get_lock(CFGFILE *, CFGLOCK *, pid_t *);	/* get config lock */

int cfg_commit(CFGFILE *);
void cfg_resource(CFGFILE *, const char *);	/* Set/clear cluster node */
char *cfg_get_resource(CFGFILE *);		/* get current cluster node */
char *cfg_dgname(const char *, char *, size_t);	/* parse dg from pathname */
char *cfg_l_dgname(const char *, char *, size_t); /* parse dg from pathname */
int cfg_dgname_islocal(char *, char **);	/* find locality of dg */
int cfg_iscluster(void);			/* running in a cluster? */
int cfg_issuncluster(void);			/* running in a Sun Cluster? */
void cfg_invalidate_sizes(int);

/*
 * add/rem result codes
 */
#define	CFG_USER_ERR 1
#define	CFG_USER_OK 2
#define	CFG_USER_FIRST 3
#define	CFG_USER_LAST 4
#define	CFG_USER_GONE 5
#define	CFG_USER_REPEAT 6

int cfg_add_user(CFGFILE *, char *, char *, char *);	/* add volume user */
int cfg_rem_user(CFGFILE *, char *, char *, char *);	/* remove vol user */
int cfg_vol_enable(CFGFILE *, char *, char *, char *);	/* enable volume */
int cfg_vol_disable(CFGFILE *, char *, char *, char *);	/* disable volume */

int cfg_load_dsvols(CFGFILE *);		/* load dsvol: section */
void cfg_unload_dsvols();		/* unload dsvol: section */
int cfg_load_svols(CFGFILE *);		/* load sv: section */
void cfg_unload_svols();		/* unload sv: section */
int cfg_load_shadows(CFGFILE *);	/* load shadows & bitmaps from ii: */
void cfg_unload_shadows();		/* unload ii: */

int cfg_get_canonical_name(CFGFILE *, const char *, char **);

#ifdef	__cplusplus
}
#endif

#endif /* _CFG_H */
