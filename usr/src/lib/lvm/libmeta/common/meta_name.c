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

#include <meta.h>
#include <metad.h>

#include <ctype.h>
#include <string.h>
#include <sys/fs/ufs_fsdir.h>

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 *	Macros to produce a quoted string containing the value of a
 *	preprocessor macro. For example, if SIZE is defined to be 256,
 *	VAL2STR(SIZE) is "256". This is used to construct format
 *	strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

extern	char	*getfullblkname();
extern	char	*getfullrawname();

/*
 * caches
 */
static	mdsetnamelist_t		*setlistp = NULL;
static	mddrivenamelist_t	*drivelistp = NULL;
static	mdnamelist_t		*fastnmlp = NULL;
static	mdhspnamelist_t		*hsplistp = NULL;

/*
 * Static definitions
 */
static int chksetname(mdsetname_t **spp, char *sname, md_error_t *ep);

/*
 * leak proof name conversion
 */
static char *
rawname(
	char	*uname
)
{
	char	*p;
	struct stat	sbuf1, sbuf2;

	if ((p = getfullrawname(uname)) == NULL) {
		return (NULL);
	} else if (*p == '\0') {
		Free(p);
		return (NULL);
	} else {
		if (stat(uname, &sbuf1) != 0) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "device to mount in /etc/vfstab is "
			    "invalid for device %s\n"), uname);
			exit(1);
		}
		if (stat(p, &sbuf2) != 0) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "device to fsck in /etc/vfstab is "
			    "invalid for raw device %s\n"), p);
			exit(1);
		}
		if (sbuf1.st_rdev != sbuf2.st_rdev) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "/etc/vfstab entries inconsistent on "
			    "line containing device %s\n"), uname);
			exit(1);
		}
		if (!S_ISCHR(sbuf2.st_mode)) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "/etc/vfstab device to fsck is not a "
			    "raw device for device %s\n"), p);
			exit(1);
		}
		return (p);
	}
}

char *
blkname(
	char	*uname
)
{
	char	*p;

	if ((p = getfullblkname(uname)) == NULL) {
		return (NULL);
	} else if (*p == '\0') {
		Free(p);
		return (NULL);
	} else {
		return (p);
	}
}

/*
 * FUNCTION:	parse_device()
 * INPUT:	sp - pointer to setname struct
 *		uname - Name of either a hotspare pool or metadevice
 *			This can either be a fully qualified path or
 *			in the form [set name/]device
 * OUTPUT:	snamep - name of the set that uname is in
 *		fnamep - metadevice or hsp with path and set name info stripped
 *		    This parameter is dynamically allocated and must be
 *		    freed by the calling function.
 * PURPOSE:	Parse uname and sp into the set name and device name strings.
 *		If the set name is specified as part of uname then use that
 *		otherwise attempt to get the set name from sp.
 */
void
parse_device(
	mdsetname_t	*sp,
	char		*uname,
	char		**fnamep, /* dynamically alloced - caller must free */
	char		**snamep  /* dynamically alloced - caller must free */
)
{
	char		setname[FILENAME_MAX+1];
	char		devname[FILENAME_MAX+1];
	char		*tname = Malloc(strlen(uname) + 1);

	int		len;
	char *up;
	char *tp;
	int lcws;	/* last character was slash */

	/* Now copy uname to tname by throwing away any duplicate '/' */
	for (lcws = 0, tp = tname, up = uname; *up; up++) {
		if (lcws) {
			if (*up == '/') {
				continue;
			} else {
				lcws = 0;
			}
		}
		if (*up == '/') {
			lcws = 1;
		}
		*tp++ = *up; /* ++ is done by for loop */
	}
	*tp = '\0';

	/* fully-qualified  - local set */
	if (((sscanf(tname, "/dev/md/dsk/%" VAL2STR(FILENAME_MAX) "s%n",
			devname, &len) == 1) && (strlen(tname) == len)) ||
	    ((sscanf(tname, "/dev/md/rdsk/%" VAL2STR(FILENAME_MAX) "s%n",
			devname, &len) == 1) && (strlen(tname) == len))) {
		*snamep = Strdup(MD_LOCAL_NAME);
		*fnamep = Strdup(devname);
		Free(tname);
		return;
	}

	/* with setname specified - either fully qualified and relative spec */
	if (((sscanf(tname, "%[^/]/%" VAL2STR(FILENAME_MAX) "s%n",
		setname, devname, &len) == 2) && (strlen(tname) == len)) ||
	    ((sscanf(tname, "/dev/md/%[^/]/dsk/%" VAL2STR(FILENAME_MAX) "s%n",
		setname, devname, &len) == 2) && (strlen(tname) == len)) ||
	    ((sscanf(tname, "/dev/md/%[^/]/rdsk/%" VAL2STR(FILENAME_MAX) "s%n",
		setname, devname, &len) == 2) && (strlen(tname) == len))) {

		*snamep = Strdup(setname);
		*fnamep = Strdup(devname);
		Free(tname);
		return;
	}

	/* without setname specified */
	*fnamep = tname;
	if (sp != NULL && !metaislocalset(sp))
		*snamep = Strdup(sp->setname);
	else
		*snamep = NULL;
}

/*
 * check for "all"
 */
int
meta_is_all(char *s)
{
	if ((strcoll(s, gettext("all")) == 0) ||
	    (strcoll(s, gettext("ALL")) == 0))
		return (1);
	return (0);
}

/*
 * check for "none"
 */
int
meta_is_none(char *s)
{
	if ((strcoll(s, gettext("none")) == 0) ||
	    (strcoll(s, gettext("NONE")) == 0))
		return (1);
	return (0);
}

static int
valid_name_syntax(char *uname)
{
	int	i;
	int	uname_len;

	if (uname == NULL || !isalpha(uname[0]))
		return (0);

	uname_len = strlen(uname);
	if (uname_len > MAXNAMLEN)
		return (0);

	/* 'all' and 'none' are reserved */
	if (meta_is_all(uname) || meta_is_none(uname))
		return (0);

	for (i = 1; i < uname_len; i++) {
		if ((isalnum(uname[i]) || uname[i] == '-' ||
		    uname[i] == '_' || uname[i] == '.'))
			continue;
		break;
	}

	if (i < uname_len)
		return (0);

	return (1);

}

/*
 * canonicalize name
 */
char *
meta_canonicalize(
	mdsetname_t	*sp,
	char		*uname
)
{
	char	*sname = NULL;
	char	*tname = NULL;
	char	*cname;

	/* return the dev name and set name */
	parse_device(sp, uname, &tname, &sname);

	if (!valid_name_syntax(tname)) {
		Free(tname);
		if (sname != NULL)
		    Free(sname);
		return (NULL);
	}

	if ((sname == NULL) || (strcmp(sname, MD_LOCAL_NAME) == 0))
		cname = tname;
	else {
		size_t	cname_len;

		cname_len = strlen(tname) + strlen(sname) + 2;
		cname = Malloc(cname_len);
		(void) snprintf(
		    cname, cname_len, "%s/%s", sname, tname);
		Free(tname);
	}

	if (sname != NULL)
	    Free(sname);

	return (cname);
}

/*
 * canonicalize name and check the set
 */
char *
meta_canonicalize_check_set(
	mdsetname_t	**spp,
	char		*uname,
	md_error_t	*ep
)
{
	char		*sname = NULL;
	char		*tname = NULL;
	char		*cname;

	/* return the dev name and set name */
	parse_device(*spp, uname, &tname, &sname);

	if (!valid_name_syntax(tname)) {
		(void) mderror(ep, MDE_NAME_ILLEGAL, tname);
		if (sname != NULL)
			Free(sname);
		Free(tname);
		return (NULL);
	}

	/* check the set name returned from the name for validity */
	if (chksetname(spp, sname, ep) != 0) {
		Free(tname);
		if (sname != NULL)
		    Free(sname);
		return (NULL);
	}

	if ((sname == NULL) || (strcmp(sname, MD_LOCAL_NAME) == 0))
		cname = tname;
	else {
		size_t	cname_len;

		cname_len = strlen(tname) + strlen(sname) + 2;
		cname = Malloc(cname_len);
		(void) snprintf(
		    cname, cname_len, "%s/%s", sname, tname);
		Free(tname);
	}

	if (sname != NULL)
	    Free(sname);

	return (cname);
}

/*
 * Verify that the name is a valid hsp/metadevice name
 */
static int
parse_meta_hsp_name(char *uname)
{
	char	*sname = NULL;
	char	*tname = NULL;
	int	ret;

	/* return the dev name and set name */
	parse_device(NULL, uname, &tname, &sname);

	ret = valid_name_syntax(tname);
	if (sname != NULL)
		Free(sname);
	Free(tname);
	return (ret);
}

/*
 * check that name is a metadevice
 */
int
is_metaname(
	char	*uname
)
{
	return (parse_meta_hsp_name(uname));
}

/*
 * check that name is a hotspare pool
 */
int
is_hspname(
	char	*uname
)
{
	return (parse_meta_hsp_name(uname));
}

/*
 * check to verify that name is an existing metadevice
 */
int
is_existing_metadevice(
	mdsetname_t	*sp,
	char		*uname
)
{
	char		*raw_name;
	char		*set_name;
	char		*full_path;
	char		*fname = NULL;
	int		pathlen;
	int		retval = 0;

	assert(uname != NULL);
	/*
	 * If it is an absolute name of a metadevice, then just call rawname
	 * on the input
	 */
	if (uname[0] == '/') {
		if (strncmp("/dev/md", uname, strlen("/dev/md")) == 0 &&
			(raw_name = rawname(uname)) != NULL) {
		    Free(raw_name);
		    return (1);
		}
		return (0);
	}

	/* create a fully specified path from the parsed string */
	parse_device(sp, uname, &fname, &set_name);

	if ((set_name == NULL) || (strcmp(set_name, MD_LOCAL_NAME) == 0)) {
		pathlen = strlen("/dev/md/rdsk/") + strlen(fname) + 1;
		full_path = Zalloc(pathlen);
		(void) snprintf(full_path, pathlen, "/dev/md/rdsk/%s", fname);
	} else {
		pathlen = strlen("/dev/md//rdsk/") + strlen(fname) +
		    strlen(set_name) + 1;
		full_path = Zalloc(pathlen);
		(void) snprintf(full_path, pathlen, "/dev/md/%s/rdsk/%s",
		    set_name, fname);
	}

	if ((raw_name = rawname(full_path)) != NULL) {
	    Free(raw_name);
	    retval = 1;
	}

	if (set_name != NULL)
		Free(set_name);

	Free(fname);
	Free(full_path);
	return (retval);
}

/*
 * check to verify that name is an existing hsp
 */
int
is_existing_hsp(
	mdsetname_t	*sp,
	char		*uname
)
{
	md_error_t	status = mdnullerror;
	hsp_t		hsp;
	set_t		cur_set;

	if (sp != NULL)
		cur_set = sp->setno;
	else
		cur_set = 0;

	hsp = meta_gethspnmentbyname(cur_set, MD_SIDEWILD, uname, &status);

	if (hsp == MD_HSP_NONE) {
		mdclrerror(&status);
		return (0);
	}
	return (1);
}

/*
 * check to verify that name is an existing metadevice or hotspare pool
 */
int
is_existing_meta_hsp(
	mdsetname_t	*sp,
	char		*uname
)
{
	if (is_existing_metadevice(sp, uname) ||
	    is_existing_hsp(sp, uname))
		return (1);

	return (0);
}

/*
 *	mdsetname_t stuff
 */

/*
 * initialize setname
 */
static void
metainitsetname(
	mdsetname_t	*sp
)
{
	(void) memset(sp, '\0', sizeof (*sp));
}

static void
metafreesetdesc(md_set_desc *sd)
{
	md_mnnode_desc	*nd;

	if (MD_MNSET_DESC(sd)) {
		nd = sd->sd_nodelist;
		while (nd) {
			sd->sd_nodelist = nd->nd_next;
			Free(nd);
			nd = sd->sd_nodelist;
		}
	}
	metafreedrivedesc(&sd->sd_drvs);
	Free(sd);
}

/*
 * free allocated setname
 */
static void
metafreesetname(
	mdsetname_t	*sp
)
{
	if (sp->setname != NULL)
		Free(sp->setname);
	if (sp->setdesc != NULL)
		metafreesetdesc(sp->setdesc);
	metainitsetname(sp);
}

/*
 * flush the setname cache
 */
static void
metaflushsetnames()
{
	mdsetnamelist_t		*p, *n;

	for (p = setlistp, n = NULL; (p != NULL); p = n) {
		n = p->next;
		metafreesetname(p->sp);
		Free(p->sp);
		Free(p);
	}
	setlistp = NULL;
}

/*
 * get set number
 */
static int
getsetno(
	char		*sname,
	set_t		*setnop,
	md_error_t	*ep
)
{
	md_set_record	*sr;
	size_t		len;

	/* local set */
	if ((sname == NULL) || (strcmp(sname, MD_LOCAL_NAME) == 0)) {
		*setnop = 0;
		return (0);
	}

	/* shared set */
	if ((sr = getsetbyname(sname, ep)) == NULL) {
		if (mdisrpcerror(ep, RPC_PROGNOTREGISTERED)) {
			char	*p;

			len = strlen(sname) + 30;
			p = Malloc(len);

			(void) snprintf(p, len, "setname \"%s\"", sname);
			(void) mderror(ep, MDE_NO_SET, p);
			Free(p);
		}
		return (-1);
	}
	*setnop = sr->sr_setno;
	free_sr(sr);
	return (0);
}

/*
 * find setname from name
 */
mdsetname_t *
metasetname(
	char		*sname,
	md_error_t	*ep
)
{
	mdsetnamelist_t	**tail;
	set_t		setno;
	mdsetname_t	*sp;

	/* look for cached value first */
	assert(sname != NULL);
	for (tail = &setlistp; (*tail != NULL); tail = &(*tail)->next) {
		sp = (*tail)->sp;
		if (strcmp(sp->setname, sname) == 0) {
			return (sp);
		}
	}

	/* setup set */
	if (getsetno(sname, &setno, ep) != 0)
		return (NULL);

	/* allocate new list element and setname */
	*tail = Zalloc(sizeof (**tail));
	sp = (*tail)->sp = Zalloc(sizeof (*sp));

	sp->setname = Strdup(sname);
	sp->setno = setno;
	sp->lockfd = MD_NO_LOCK;

	return (sp);
}

/*
 * find setname from setno
 */
mdsetname_t *
metasetnosetname(
	set_t		setno,
	md_error_t	*ep
)
{
	mdsetnamelist_t	*slp;
	mdsetname_t	*sp;
	md_set_record	*sr;

	/* look for cached value first */
	for (slp = setlistp; (slp != NULL); slp = slp->next) {
		sp = slp->sp;
		if (sp->setno == setno)
			return (sp);
	}

	/* local set */
	if (setno == MD_LOCAL_SET)
		return (metasetname(MD_LOCAL_NAME, ep));

	/* shared set */
	if ((sr = getsetbynum(setno, ep)) == NULL)
		return (NULL);
	sp = metasetname(sr->sr_setname, ep);
	free_sr(sr);
	return (sp);
}

mdsetname_t *
metafakesetname(
	set_t		setno,
	char		*sname
)
{
	mdsetnamelist_t	**tail;
	mdsetname_t	*sp;

	/* look for cached value first */
	for (tail = &setlistp; (*tail != NULL); tail = &(*tail)->next) {
		sp = (*tail)->sp;
		if (sp->setno == setno) {
			if ((sp->setname == NULL) && (sname != NULL))
				sp->setname = Strdup(sname);
			return (sp);
		}
	}

	/* allocate new list element and setname */
	*tail = Zalloc(sizeof (**tail));
	sp = (*tail)->sp = Zalloc(sizeof (*sp));

	if (sname != NULL)
		sp->setname = Strdup(sname);
	sp->setno = setno;
	sp->lockfd = MD_NO_LOCK;

	return (sp);
}


/*
 * setup set record (sr) and cache it in the mdsetname_t struct
 */
md_set_desc *
sr2setdesc(
	md_set_record	*sr
)
{
	md_set_desc	*sd;
	int		i;
	md_mnset_record	*mnsr;
	md_mnnode_desc	*nd, *nd_prev = 0;
	md_mnnode_record	*nr;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		nodecnt, nrcnt;
	mndiskset_membershiplist_t *nl, *nl2;

	sd = Zalloc(sizeof (*sd));
	sd->sd_ctime = sr->sr_ctime;
	sd->sd_genid = sr->sr_genid;
	sd->sd_setno = sr->sr_setno;
	sd->sd_flags = sr->sr_flags;

	if (MD_MNSET_DESC(sd)) {
		mnsr = (md_mnset_record *)sr;
		(void) strlcpy(sd->sd_mn_master_nodenm,
		    mnsr->sr_master_nodenm, sizeof (sd->sd_mn_master_nodenm));
		sd->sd_mn_master_nodeid = mnsr->sr_master_nodeid;
		if (strcmp(mnsr->sr_master_nodenm, mynode()) == 0) {
			sd->sd_mn_am_i_master = 1;
		}

		/*
		 * Get membershiplist from API routine.  If there's
		 * an error, just use a NULL nodelist.
		 */
		if (meta_read_nodelist(&nodecnt, &nl, ep) == -1) {
			nodecnt = 0;  /* no nodes are alive */
			nl = NULL;
		}
		nr = mnsr->sr_nodechain;
		nrcnt = 0;
		/*
		 * Node descriptor node list must be built in
		 * ascending order of nodeid.  The nodechain
		 * in the mnset record is in ascending order,
		 * so just make them the same.
		 */
		while (nr) {
			nd = Zalloc(sizeof (*nd));
			if (nd_prev) {
				nd_prev->nd_next = nd;
			} else {
				sd->sd_nodelist = nd;
			}
			nd->nd_ctime = nr->nr_ctime;
			nd->nd_genid = nr->nr_genid;
			nd->nd_flags = nr->nr_flags;

			(void) strlcpy(nd->nd_nodename, nr->nr_nodename,
			    sizeof (nd->nd_nodename));
			nd->nd_nodeid = nr->nr_nodeid;
			if (strcmp(nd->nd_nodename, mynode()) == 0) {
				sd->sd_mn_mynode = nd;
			}
			if (nd->nd_nodeid == sd->sd_mn_master_nodeid) {
				sd->sd_mn_masternode = nd;
			}

			/*
			 * If node is marked ALIVE, then set priv_ic
			 * from membership list.  During the early part
			 * of a reconfig cycle, the membership list may
			 * have been changed, (a node entering or leaving
			 * the cluster), but rpc.metad hasn't flushed
			 * its data yet.  So, if node is marked alive, but
			 * is no longer in the membership list (node has
			 * left the cluster) then just leave priv_ic to NULL.
			 */
			if (nd->nd_flags & MD_MN_NODE_ALIVE) {
				nl2 = nl;
				while (nl2) {
					if (nl2->msl_node_id == nd->nd_nodeid) {
						(void) strlcpy(nd->nd_priv_ic,
						    nl2->msl_node_addr,
						    sizeof (nd->nd_priv_ic));
						break;
					}
					nl2 = nl2->next;
				}
			}

			nr = nr->nr_next;
			nrcnt++;
			nd_prev = nd;
		}
		sd->sd_mn_numnodes = nrcnt;
		if (nodecnt)
			meta_free_nodelist(nl);

		/* Just copying to keep consistent view between sr & sd */
		(void) strlcpy(sd->sd_nodes[0], mnsr->sr_nodes_bw_compat[0],
		    sizeof (sd->sd_nodes[0]));
	} else {
		for (i = 0; i < MD_MAXSIDES; i++)
			(void) strlcpy(sd->sd_nodes[i], sr->sr_nodes[i],
			    sizeof (sd->sd_nodes[i]));
	}

	sd->sd_med = sr->sr_med;		/* structure assignment */

	return (sd);
}

md_set_desc *
metaget_setdesc(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	md_set_record	*sr;

	if (sp->setdesc != NULL)
		return (sp->setdesc);

	if (sp->setname != NULL) {
		if ((sr = getsetbyname(sp->setname, ep)) != NULL) {
			sp->setdesc = sr2setdesc(sr);
			free_sr(sr);
			return (sp->setdesc);
		}
	}

	if (sp->setno > 0) {
		if ((sr = getsetbynum(sp->setno, ep)) != NULL) {
			sp->setdesc = sr2setdesc(sr);
			free_sr(sr);
			return (sp->setdesc);
		}
	}

	return (NULL);
}

void
metaflushsetname(mdsetname_t *sp)
{
	if (sp == NULL)
		return;

	if (sp->setdesc == NULL)
		return;

	metafreesetdesc(sp->setdesc);
	sp->setdesc = NULL;
}

/*
 * check for local set
 */
int
metaislocalset(
	mdsetname_t	*sp
)
{
	assert(sp->setname != NULL);
	if (strcmp(sp->setname, MD_LOCAL_NAME) == 0) {
		assert(sp->setno == MD_LOCAL_SET);
		return (1);
	} else {
		assert(sp->setno != MD_LOCAL_SET);
		return (0);
	}
}

/*
 * check for same set
 */
int
metaissameset(
	mdsetname_t	*sp1,
	mdsetname_t	*sp2
)
{
	if (strcmp(sp1->setname, sp2->setname) == 0) {
		assert(sp1->setno == sp2->setno);
		return (1);
	} else {
		assert(sp1->setno != sp2->setno);
		return (0);
	}
}

/*
 * check to see if set changed
 */
static int
chkset(
	mdsetname_t	**spp,
	char		*sname,
	md_error_t	*ep
)
{
	/* if we already have a set, make sure it's the same */
	if (*spp != NULL && !metaislocalset(*spp)) {
		if ((*spp)->setname != sname &&
				strcmp((*spp)->setname, sname) != 0) {
			return (mderror(ep, MDE_SET_DIFF, sname));
		}
		return (0);
	}

	/* otherwise store new set name and number */
	if ((*spp = metasetname(sname, ep)) == NULL) {
		return (-1);
	}

	/* return success */
	return (0);
}

/*
 * check to see if set changed from default
 */
static int
chksetname(
	mdsetname_t	**spp,
	char		*sname,
	md_error_t	*ep
)
{
	/* default to *spp's setname, or if that is NULL to MD_LOCAL_NAME */
	if (sname == NULL) {
		if (*spp) {
			return (0);
		} else {
			sname = MD_LOCAL_NAME;
		}
	}

	/* see if changed */
	return (chkset(spp, sname, ep));
}

/*
 * check setname from setno
 */
static int
chksetno(
	mdsetname_t	**spp,
	set_t		setno,
	md_error_t	*ep
)
{
	md_set_record	*sr;
	int		rval;

	/* local set */
	if (setno == 0)
		return (chkset(spp, MD_LOCAL_NAME, ep));

	/* shared set */
	if ((sr = getsetbynum(setno, ep)) == NULL)
		return (-1);
	rval = chkset(spp, sr->sr_setname, ep);
	free_sr(sr);
	return (rval);
}

/*
 *	mddrivename_t stuff
 */

/*
 * initialize name
 */
static void
metainitname(
	mdname_t	*np
)
{
	(void) memset(np, 0, sizeof (*np));
	np->dev = NODEV64;
	np->key = MD_KEYBAD;
	np->end_blk = -1;
	np->start_blk = -1;
}

/*
 * free allocated name
 */
static void
metafreename(
	mdname_t	*np
)
{
	if (np->cname != NULL)
		Free(np->cname);
	if (np->bname != NULL)
		Free(np->bname);
	if (np->rname != NULL)
		Free(np->rname);
	if (np->devicesname != NULL)
		Free(np->devicesname);
	metainitname(np);
}

/*
 * initialize drive name
 */
static void
metainitdrivename(
	mddrivename_t	*dnp
)
{
	(void) memset(dnp, 0, sizeof (*dnp));
	dnp->side_names_key = MD_KEYBAD;
}

/*
 * flush side names
 */
void
metaflushsidenames(
	mddrivename_t	*dnp
)
{
	mdsidenames_t	*p, *n;

	for (p = dnp->side_names, n = NULL; (p != NULL); p = n) {
		n = p->next;
		if (p->dname != NULL)
			Free(p->dname);
		if (p->cname != NULL)
			Free(p->cname);
		Free(p);
	}
	dnp->side_names = NULL;
}

/*
 * free drive name
 */
void
metafreedrivename(
	mddrivename_t	*dnp
)
{
	uint_t		slice;

	if (dnp->cname != NULL)
		Free(dnp->cname);
	if (dnp->rname != NULL)
		Free(dnp->rname);
	metafreevtoc(&dnp->vtoc);
	for (slice = 0; (slice < dnp->parts.parts_len); ++slice)
		metafreename(&dnp->parts.parts_val[slice]);
	if (dnp->parts.parts_val != NULL)
		Free(dnp->parts.parts_val);
	metaflushsidenames(dnp);
	if (dnp->miscname != NULL)
		Free(dnp->miscname);
	meta_free_unit(dnp);
	metainitdrivename(dnp);
}

/*
 * flush the drive name cache
 */
void
metaflushdrivenames()
{
	mddrivenamelist_t	*p, *n;

	for (p = drivelistp, n = NULL; (p != NULL); p = n) {
		n = p->next;
		metafreedrivename(p->drivenamep);
		Free(p->drivenamep);
		Free(p);
	}
	drivelistp = NULL;
}

/*
 * peel off s%u from name
 */
char *
metadiskname(
	char	*name
)
{
	char	*p, *e;
	char	onmb[BUFSIZ+1], cnmb[BUFSIZ];
	uint_t	d = 0;
	int	l = 0;
	int	cl = strlen(name);

	/*
	 * Handle old style names, which are of the form /dev/rXXNN[a-h].
	 */
	if (sscanf(name, "/dev/r%" VAL2STR(BUFSIZ) "[^0-9/]%u%*[a-h]%n",
	    onmb, &d, &l) == 2 && l == cl) {
		(void) snprintf(cnmb, sizeof (cnmb), "/dev/r%s%u", onmb, d);
		return (Strdup(cnmb));
	}

	/*
	 * Handle old style names, which are of the form /dev/XXNN[a-h].
	 */
	if (sscanf(name, "/dev/%" VAL2STR(BUFSIZ) "[^0-9/]%u%*[a-h]%n",
	    onmb, &d, &l) == 2 && l == cl) {
		(void) snprintf(cnmb, sizeof (cnmb), "/dev/%s%u", onmb, d);
		return (Strdup(cnmb));
	}

	/* gobble number and 's' */
	p = e = name + strlen(name) - 1;
	for (; (p > name); --p) {
		if (!isdigit(*p))
			break;
	}
	if ((p == e) || (p <= name))
		return (Strdup(name));

	if (*p != 's' && strchr("dt", *p) == NULL)
		return (Strdup(name));
	else if (strchr("dt", *p) != NULL)
		return (Strdup(name));
	p--;

	if ((p <= name) || (!isdigit(*p)))
		return (Strdup(name));

	*(++p) = '\0';
	e = Strdup(name);
	*p = 's';

	return (e);
}

/*
 * free list of drivenames
 */
void
metafreedrivenamelist(
	mddrivenamelist_t	*dnlp
)
{
	mddrivenamelist_t	*next = NULL;

	for (/* void */; (dnlp != NULL); dnlp = next) {
		next = dnlp->next;
		Free(dnlp);
	}
}

/*
 * build list of drivenames
 */
int
metadrivenamelist(
	mdsetname_t		**spp,
	mddrivenamelist_t	**dnlpp,
	int			argc,
	char			*argv[],
	md_error_t		*ep
)
{
	mddrivenamelist_t	**tailpp = dnlpp;
	int			count = 0;

	for (*dnlpp = NULL; (argc > 0); ++count, --argc, ++argv) {
		mddrivenamelist_t	*dnlp = Zalloc(sizeof (*dnlp));

		if ((dnlp->drivenamep = metadrivename(spp, argv[0],
		    ep)) == NULL) {
			metafreedrivenamelist(*dnlpp);
			*dnlpp = NULL;
			return (-1);
		}
		*tailpp = dnlp;
		tailpp = &dnlp->next;
	}
	return (count);
}

/*
 * append to end of drivename list
 */
mddrivename_t *
metadrivenamelist_append(
	mddrivenamelist_t	**dnlpp,
	mddrivename_t		*dnp
)
{
	mddrivenamelist_t	*dnlp;

	/* run to end of list */
	for (; (*dnlpp != NULL); dnlpp = &(*dnlpp)->next)
		;

	/* allocate new list element */
	dnlp = *dnlpp = Zalloc(sizeof (*dnlp));

	/* append drivename */
	dnlp->drivenamep = dnp;
	return (dnp);
}

/*
 * FUNCTION:	meta_drivenamelist_append_wrapper()
 * INPUT:	tailpp	- pointer to the list tail pointer
 *		dnp	- name node to be appended to list
 * OUTPUT:	none
 * RETURNS:	mddrivenamelist_t * - new tail of the list.
 * PURPOSE:	wrapper to meta_namelist_append for performance.
 *		metanamelist_append finds the tail each time which slows
 *		down long lists.  By keeping track of the tail ourselves
 *		we can change metadrivenamelist_append into a
 *		constant time operation.
 */
mddrivenamelist_t **
meta_drivenamelist_append_wrapper(
	mddrivenamelist_t	**tailpp,
	mddrivename_t	*dnp
)
{
	(void) metadrivenamelist_append(tailpp, dnp);

	/* If it's the first item in the list, return it instead of the next */
	if ((*tailpp)->next == NULL)
		return (tailpp);

	return (&(*tailpp)->next);
}


/*
 *	mdname_t stuff
 */

/*
 * check set and get comparison name
 *
 * NOTE: This function has a side effect of setting *spp if the setname
 * has been specified and *spp is not already set.
 */
char *
meta_name_getname(
	mdsetname_t		**spp,
	char			*uname,
	meta_device_type_t	uname_type,
	md_error_t		*ep
)
{
	if (uname_type == META_DEVICE || uname_type == HSP_DEVICE ||
	    (uname_type == UNKNOWN && is_existing_metadevice(*spp, uname))) {

		/*
		 * if the setname is specified in uname, *spp is set,
		 * and the set names don't agree then canonical name will be
		 * returned as NULL
		 */
		return (meta_canonicalize_check_set(spp, uname, ep));
	}

	/* if it is not a meta/hsp and *spp is not set then set it to local */
	if (chksetname(spp, NULL, ep) != 0)
		return (NULL);

	/* if it is not a meta/hsp name then just return uname */
	return (Strdup(uname));
}

/*
 * FUNCTION:	getrname()
 * INPUT:	spp	- the setname struct
 *		uname	- the possibly unqualified device name
 *		type 	- ptr to the device type of uname
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	char*	- character string containing the fully
 *			qualified raw device name
 * PURPOSE:	Create the fully qualified raw name for the possibly
 *		unqualified device name.  If uname is an absolute
 *		path the raw name is derived from the input string.
 *		Otherwise, an attempt is made to get the rawname by
 *		catting "/dev/md/rdsk" and "/dev/rdsk". If the input
 *		value of type is UNKNOWN and it can be successfully
 *		determined then update type to the correct value.
 */
static	char *
getrname(mdsetname_t **spp, char *uname,
    meta_device_type_t *type, md_error_t *ep)
{
	char			*rname,
				*fname;
	int			i;
	int 			rname_cnt = 0;
	char			*rname_list[3];
	meta_device_type_t	tmp_type;

	assert(uname != NULL);
	/* if it is an absolute name then just call rawname on the input */
	if (uname[0] == '/') {
	    if ((rname = rawname(uname)) != NULL) {
		/*
		 * If the returned rname does not match with
		 * the specified uname type, we'll return null.
		 */
		if (strncmp(rname, "/dev/md", strlen("/dev/md")) == 0) {
			if (*type == LOGICAL_DEVICE) {
				(void) mdsyserror(ep, ENOENT, uname);
				return (NULL);
			}
			*type = META_DEVICE;
		} else {
			if (*type == META_DEVICE) {
				(void) mdsyserror(ep, ENOENT, uname);
				return (NULL);
			}
			*type = LOGICAL_DEVICE;
		}
		return (rname);
	    }

	    /* out of luck */
	    (void) mdsyserror(ep, ENOENT, uname);
	    return (NULL);
	}

	/*
	 * Get device that matches the requested type. If
	 * a match is found, return immediately. If type is
	 * UNKNOWN, save all the found devices in rname_list
	 * so we can determine later whether the input uname
	 * is ambiguous.
	 *
	 * Check for metadevice before physical device.
	 * With the introduction of softpartitions it is more
	 * likely to be a metadevice.
	 */

	/* metadevice short form */
	if (*type == META_DEVICE || *type == UNKNOWN) {
		if (metaislocalset(*spp)) {
			fname = Malloc(strlen(uname) +
			    strlen("/dev/md/rdsk/") + 1);
			(void) strcpy(fname, "/dev/md/rdsk/");
			(void) strcat(fname, uname);
		} else {
			char	*p;
			size_t	len;

			if ((p = strchr(uname, '/')) != NULL) {
				++p;
			} else {
				p = uname;
			}
			len = strlen((*spp)->setname) + strlen(p) +
			    strlen("/dev/md//rdsk/") + 1;
			fname = Malloc(len);
			(void) snprintf(fname, len, "/dev/md/%s/rdsk/%s",
			    (*spp)->setname, p);
		}
		rname = rawname(fname);

		if (*type == META_DEVICE) {
			/*
			 * Handle the case where we have a new metadevice
			 * that does not yet exist in the name-space(e.g
			 * metarecover in MN sets where /dev/md entry is
			 * not yet created in the non-master nodes). In
			 * this case we return the constructed metadevice
			 * name as that will exist after the metainit call
			 * has created it.
			 */
			if (rname == NULL) {
				rname = Strdup(fname);
			}

			Free(fname);
			return (rname);
		}

		Free(fname);
		if ((rname != NULL) && (*type == UNKNOWN)) {
			/* Save this result */
			rname_list[rname_cnt] = rname;
			rname_cnt ++;
		}
	}

	if (*type == LOGICAL_DEVICE || *type == UNKNOWN) {
		fname = Malloc(strlen(uname) + strlen("/dev/rdsk/") + 1);
		(void) strcpy(fname, "/dev/rdsk/");
		(void) strcat(fname, uname);
		rname = rawname(fname);

		Free(fname);
		if (rname != NULL) {
			/* Simply return if a logical device was requested */
			if (*type == LOGICAL_DEVICE) {
				return (rname);
			} else {
				rname_list[rname_cnt] = rname;
				rname_cnt ++;
			}
		}
	}

	/*
	 * If all else fails try the straight uname.
	 * NOTE: This check was at the beginning of getrname instead
	 * of here. It was moved to avoid a conflict with SC3.0. If
	 * a diskset was mounted with the same name it would hang
	 * the cluster in a loop. Example:
	 *
	 *	fubar/d10 -m fubar/d0 fubar/d1
	 *	mount /dev/md/fubar/dsk/d10 /fubar
	 *
	 * When the system was booted SVM would try to take ownership
	 * of diskset fubar. This would cause rawname("fubar/d10") to be
	 * called. rawname() stats the string which caused the cluster
	 * reservation code to try and take ownership which it was already
	 * doing and a deadlock would occur. By moving this final attempt
	 * at resolving the rawname to the end we avoid this deadlock.
	 */
	if (rname = rawname(uname)) {
		/*
		 * It's only possible to get a logical device from this
		 * rawname call since a metadevice would have been
		 * detected earlier.
		 */
		if (*type == LOGICAL_DEVICE &&
		    (strncmp(rname, "/dev/md/", strlen("/dev/md"))) != 1)
			return (rname);
		else {
			rname_list[rname_cnt] = rname;
			rname_cnt++;
		}
	}

	/*
	 * At this point, we've searched /dev/md/rdsk, /dev/rdsk and
	 * ./ for the specified device. rname_list contains all
	 * the matches we've found and rname_cnt is the number of
	 * matches.
	 *
	 * We know that either we don't have a match if a specific
	 * type was given, in which case we simply return NULL or
	 * we have an UNKNOWN device with 1-3 entries in rname_list.
	 *
	 * If we get 3 entries, rname_cnt == 3, it's ambiguous.
	 * If we only get 1 entry, rname_cnt == 1, return rname_list[0].
	 * If we get 2 entries that are not the same, it's ambigous.
	 */
	rname = NULL;
	if (rname_cnt == 0 || *type != UNKNOWN) {
		/* out of luck */
		(void) mdsyserror(ep, ENOENT, uname);
		return (NULL);
	} else {
		if (rname_cnt == 3) {
			(void) mderror(ep, MDE_AMBIGUOUS_DEV, uname);
			(void) printf(dgettext(TEXT_DOMAIN,
			    "Error: ambiguous device name.\n%s %s %s\n\n"),
			    rname_list[0], rname_list[1], rname_list[2]);
			rname = NULL;
		}

		/* grab the type in case it is not ambiguous */
		if (strncmp(rname_list[0], "/dev/md", strlen("/dev/md")) == 0)
			tmp_type =  META_DEVICE;
		else
			tmp_type =  LOGICAL_DEVICE;

		if (rname_cnt == 1) {
			rname = Strdup(rname_list[0]);
			*type = tmp_type;
		} else {
			/*
			 * Prevent the case where the command is run in
			 * either /dev/md/rdsk or /dev/rdsk so the both
			 * rname_list[0] and rname_list[1] are the same.
			 */
			if (strcmp(rname_list[0], rname_list[1]) != 0) {
				(void) mderror(ep, MDE_AMBIGUOUS_DEV, uname);
				if (rname_cnt != 3) {
					/*
					 * For the rname_cnt == 3 case, the
					 * error was printed above.
					 */
					(void) printf(dgettext(TEXT_DOMAIN,
						"Error: ambiguous device "
						"name.\n%s %s\n\n"),
						rname_list[0], rname_list[1]);
				}
				rname = NULL;
			} else {
				rname = Strdup(rname_list[0]);
				*type = tmp_type;
			}
		}
		for (i = 0; i < rname_cnt; i++)
			Free(rname_list[i]);
		return (rname);
	}
}

/*
 * get raw slice and drive names
 */
static char *
getrawnames(
	mdsetname_t		**spp,
	char			*uname,
	char			**dnamep,
	meta_device_type_t	*uname_type,
	md_error_t		*ep
)
{
	char		*rname = NULL;
	size_t		len;

	/*
	 * Incorrect code path if type is HSP_DEVICE
	 */
	assert(*uname_type != HSP_DEVICE);

	/* initialize */
	*dnamep = NULL;

	/* get slice name */
	if ((rname = getrname(spp, uname, uname_type, ep)) != NULL) {
		*dnamep = metadiskname(rname);
		return (rname);
	}

	/*
	 * If name cannot be found, if may be because is is not accessible.
	 * If it is an absolute name, try all possible disk name formats and
	 * if it is device name, assume it is /dev/rdsk/..
	 * Since the code below assumes logical devices, if the given
	 * uname_type is META_DEVICE, there's nothing to do.
	 */
	if (mdissyserror(ep, ENOENT) && *uname_type != META_DEVICE) {
		if (uname[0] == '/') {
			/* Absolute name */
			char			*p;
			uint_t			d = 0;
			int			l = 0;
			char			onmb[BUFSIZ+1], snm[BUFSIZ+1];

			/*
			 * Handle old style raw names
			 */
			if (sscanf(uname,
			    "/dev/r%" VAL2STR(BUFSIZ) "[^0-9/]%u"
			    "%" VAL2STR(BUFSIZ) "[a-h]%n",
			    onmb, &d, snm, &l) == 3 && l == strlen(uname)) {
				mdclrerror(ep);
				rname = Strdup(uname);
				*dnamep = metadiskname(rname);
				*uname_type = LOGICAL_DEVICE;
				return (rname);
			}

			/*
			 * Handle old style block names
			 */
			if (sscanf(uname,
			    "/dev/%" VAL2STR(BUFSIZ) "[^0-9/]%u"
			    "%" VAL2STR(BUFSIZ) "[a-h]%n",
			    onmb, &d, snm, &l) == 3 && l == strlen(uname)) {
				len = strlen(uname) + 1 + 1;
				rname = Malloc(len);
				(void) snprintf(rname, len, "/dev/r%s%u%s",
				    onmb, d, snm);
				*dnamep = metadiskname(rname);
				*uname_type = LOGICAL_DEVICE;
				return (rname);
			}

			/* /.../dsk/... */
			if ((p = strstr(uname, "/dsk/")) != NULL) {
				mdclrerror(ep);
				++p;
				rname = Malloc(strlen(uname) + 1 + 1);
				(void) strncpy(rname, uname, (p - uname));
				rname[(p - uname)] = 'r';
				(void) strcpy(&rname[(p - uname) + 1], p);
				*dnamep = metadiskname(rname);
				*uname_type = LOGICAL_DEVICE;
				return (rname);
			}

			/* /.../rdsk/... */
			else if (strstr(uname, "/rdsk/") != NULL) {
				mdclrerror(ep);
				rname = Strdup(uname);
				*dnamep = metadiskname(rname);
				*uname_type = LOGICAL_DEVICE;
				return (rname);
			}
		} else {
			/*
			 * If it's not an absolute name but is a valid ctd name,
			 * guess at /dev/rdsk/...
			 */
			uint_t	s;
			if (parse_ctd(uname, &s) == 0) {
				len = strlen(uname) + strlen("/dev/rdsk/") + 1;
				rname = Malloc(len);
				(void) snprintf(rname, len, "/dev/rdsk/%s",
				    uname);
				*dnamep = metadiskname(rname);
				*uname_type = LOGICAL_DEVICE;
				return (rname);
			}
		}
	}

	/* out of luck */
	if (!mdiserror(ep, MDE_AMBIGUOUS_DEV))
		(void) mderror(ep, MDE_UNIT_NOT_FOUND, uname);
	return (NULL);
}

/*
 * get number of slices for name
 */
static int
getnslice(
	char		*rname,
	char		*dname,
	uint_t		*slicep
)
{
	char		*srname;
	uint_t		nslice;
	size_t		dl = strlen(dname);
	size_t		rl = strlen(rname);
	size_t		l = 0;
	size_t		len;

	/*
	 * get our slice number - works only with names that end in s%u -
	 * all others return -1.
	 */
	if (dl >= rl ||
	    sscanf(&rname[dl], "s%u%n", slicep, &l) != 1 || l != rl ||
	    (int)*slicep < 0) {
		return (-1);
	}

	/*
	 * go find how many slices there really are
	 */
	len = strlen(dname) + 20 + 1;
	srname = Malloc(len);
	for (nslice = 0; /* void */; ++nslice) {
		struct stat	statbuf;

		/* build slice name */
		(void) snprintf(srname, len, "%ss%u", dname, nslice);

		/* see if it's there */
		if ((meta_stat(srname, &statbuf) != 0) ||
		    (! S_ISCHR(statbuf.st_mode))) {
			break;
		}
	}
	Free(srname);

	/* Need to make sure that we at least have V_NUMPAR */
	nslice = max(nslice, V_NUMPAR);

	/* make sure we have at least our slice */
	if (nslice < *slicep)
		return (-1);

	/* return number of slices */
	return (nslice);
}

/*
 * Attempt to parse the input string as a c[t]ds specifier
 * The target can either be a SCSI target id or if the device
 * is in a fabric configuration in a fibre channel setup then
 * the target is a standard WWN (world wide name).
 *
 * if successful	return 0
 * if c[t]dp name	return 1
 * otherwise		return -1
 */
int
parse_ctd(
	char	*uname,
	uint_t	*slice)
{
	uint_t	channel;
	uint_t	target;
	uint_t	device;
	int	has_target = 1;
	uint_t	cl;
	uint_t	target_str_len;
	char	*partial_ctd_str;
	char	*target_str;
	char	*device_start_pos;
	int	l = -1;

	/* pull off the channel spec and the 't' for the target */
	if (sscanf(uname, "c%ut%n", &channel, &l) != 1 || l == -1) {
		/* check for cds style name */
		if (sscanf(uname, "c%ud%n", &channel, &l) != 1 || l == -1) {
			return (-1);
		} else {
			l--;	/* we want to be on the 'd' */
			has_target = 0;
		}
	}
	partial_ctd_str = uname + l;

	/* find the beginning of the device specifier */
	device_start_pos = strrchr(partial_ctd_str, 'd');
	if (device_start_pos == NULL) {
		return (-1);
	}

	/* check to see if it is a ctd with a WWN or SCSI target */
	if (has_target) {
		/* pull off the target and see if it is a WWN */
		target_str_len = device_start_pos - partial_ctd_str + 2;
		target_str = (char *)Malloc(target_str_len+1);
		(void) strcpy(target_str, "0X");
		(void) strncpy(target_str+2, partial_ctd_str,
		    target_str_len - 2);
		target_str[target_str_len] = '\0';
		if (sscanf(target_str, "%x%n", &target, &l) != 1 ||
		    l != target_str_len) {
			Free(target_str);
			return (-1);
		}
		Free(target_str);
	}

	/* check the device and slice */
	cl = strlen(device_start_pos);
	if (sscanf(device_start_pos, "d%us%u%n", &device, slice, &l) != 2 ||
			l != cl) {
		/* check the device and partition */
		if (sscanf(device_start_pos, "d%up%u%n", &device, slice, &l)
		    == 2 && l == cl) {
			return (1);
		}
		return (-1);
	}

	return (0);
}


/*
 * get number of slices for name
 */
static int
uname2sliceno(
	char			*uname,
	meta_device_type_t	uname_type,
	uint_t			*slicep,
	md_error_t		*ep
)
{
	uint_t			c = 0, t = 0, d = 0;
	int			l = 0, cl = 0;
	int			fd;
	struct dk_cinfo		cinfo;
	char			*p;
	char			*rname = NULL;


	if (uname_type == META_DEVICE)
		return (*slicep = 0);

	if ((p = strrchr(uname, '/')) != NULL)
		p++;
	else
		p = uname;

	cl = strlen(p);

	if (parse_ctd(p, slicep) == 0)
		return (*slicep);
	else if (sscanf(p, "mc%ut%ud%us%u%n", &c, &t, &d, slicep, &l) == 4 &&
	    l == cl)
		return (*slicep);
	else if (sscanf(p, "d%us%u%n", &d, slicep, &l) == 2 && l == cl)
		return (*slicep);

	/*
	 * If we can't get the slice from the name, then we have to do it the
	 * hard and expensive way.
	 */
	if ((rname = rawname(uname)) == NULL)
		return (-1);

	/* get controller info */
	if ((fd = open(rname, (O_RDONLY|O_NDELAY), 0)) < 0) {
		Free(rname);
		return (-1);
	}

	if (ioctl(fd, DKIOCINFO, &cinfo) != 0) {
		int	save = errno;

		if (save == ENOTTY)
			(void) mddeverror(ep, MDE_NOT_DISK, NODEV64, rname);
		else
			(void) mdsyserror(ep, save, rname);

		Free(rname);
		(void) close(fd);
		return (-1);
	}
	(void) close(fd);	/* sd/ssd bug */

	if (cinfo.dki_partition < V_NUMPAR) {
		Free(rname);
		return (*slicep = cinfo.dki_partition);
	}

	return (mddeverror(ep, MDE_NOT_DISK, NODEV64, rname));
}

/*
 * get partition info
 */
static int
getparts(
	mddrivename_t		*dnp,
	char			*rname,
	char			*dname,
	meta_device_type_t	uname_type,
	uint_t			*npartsp,
	uint_t			*partnop,
	md_error_t		*ep
)
{
	int		nparts;
	uint_t		partno;
	mdname_t	name;
	mdvtoc_t	*vtocp;

	/* metadevice */
	if (uname_type == META_DEVICE) {
		dnp->type = MDT_META;
		nparts = 1;
		partno = 0;
		goto gotit;
	}

	/* see how many partitions in drive, this is really tricky */
	metainitname(&name);
	name.rname = rname;
	name.drivenamep = dnp;
	if ((vtocp = metagetvtoc(&name, TRUE, &partno, ep)) != NULL) {
		dnp->type = MDT_COMP;
		nparts = vtocp->nparts;
		/* partno already setup */
		/* dname already setup */
		goto gotit;
	}

	if ((ep->info.errclass == MDEC_DEV) &&
	    (ep->info.md_error_info_t_u.dev_error.errnum == MDE_TOO_MANY_PARTS))
		return (-1);

	/* fallback and try and guess (used to check for just EACCES here) */
	if ((dname != NULL) &&
	    ((nparts = getnslice(rname, dname, &partno)) > 0)) {
		dnp->type = MDT_ACCES;
		if (mdanysyserror(ep)) {
			dnp->errnum =
			    ep->info.md_error_info_t_u.sys_error.errnum;
		} else {
			dnp->errnum = ENOENT;
		}
		mdclrerror(ep);
		/* nparts already setup */
		/* partno already setup */
		/* dname already setup */
		nparts = roundup(nparts, V_NUMPAR);
		goto gotit;
	}

	/* nothing worked */
	dnp->type = MDT_UNKNOWN;
	if (mdissyserror(ep, EACCES))
		dnp->type = MDT_ACCES;

	if (mdanysyserror(ep)) {
		dnp->errnum = ep->info.md_error_info_t_u.sys_error.errnum;
	} else {
		dnp->errnum = ENOENT;
	}

	mdclrerror(ep);
	nparts = V_NUMPAR;
	if (uname2sliceno(rname, uname_type, &partno, ep) < 0) {
		mdclrerror(ep);
		partno = 0;
	}

	/* return success */
gotit:
	assert(nparts > 0);

	if (partno >= nparts)
		return (mdsyserror(ep, ENOENT, rname));

	*npartsp = nparts;
	*partnop = partno;
	return (0);
}

/*
 * get block name
 */
static int
getbname(
	mdname_t	*np,
	md_error_t	*ep
)
{
	char		*rname = np->rname;
	char		*bname;

	/* fully qualified */
	assert(rname != NULL);
	if ((bname = blkname(rname)) != NULL) {
		if (np->bname)
			Free(np->bname);
		np->bname = bname;
		return (0);
	}

	/* out of luck */
	return (mdsyserror(ep, ENOENT, rname));
}

static void
getcname(
	mdsetname_t	*sp,
	mdname_t	*np
)
{
	char		*sname = sp->setname;
	char		*bname = np->bname;
	char		*p;
	size_t		len;

	assert(sname != NULL);
	assert(bname != NULL);
	assert(np->drivenamep->type != MDT_FAST_COMP &&
	    np->drivenamep->type != MDT_FAST_META);

	/* regular device */
	if ((strncmp(bname, "/dev/dsk/", strlen("/dev/dsk/")) == 0) &&
	    (strchr((p = bname + strlen("/dev/dsk/")), '/') == NULL)) {
		if (np->cname)
			Free(np->cname);
		np->cname = Strdup(p);
		return;
	}

	if ((strncmp(bname, "/dev/ap/dsk/", strlen("/dev/ap/dsk/")) == 0) &&
	    (strchr((p = bname + strlen("/dev/ap/dsk/")), '/') == NULL)) {
		if (np->cname)
			Free(np->cname);
		np->cname = Strdup(p);
		return;
	}

	if ((strncmp(bname, "/dev/did/dsk/", strlen("/dev/did/dsk/")) == 0) &&
	    (strchr((p = bname + strlen("/dev/did/dsk/")), '/') == NULL)) {
		if (np->cname)
			Free(np->cname);
		np->cname = Strdup(p);
		return;
	}

	/* anything else but metadevice */
	if (np->drivenamep->type != MDT_META) {
		if (np->cname)
			Free(np->cname);
		np->cname = Strdup(bname);
		return;
	}

	/* metadevice */
	p = strrchr(bname, '/');
	assert(p != NULL);
	++p;
	if (metaislocalset(sp)) {
		if (np->cname)
			Free(np->cname);
		np->cname = Strdup(p);
	} else {
		assert(sname[0] != '\0');
		if (np->cname)
			Free(np->cname);
		len = strlen(sname) + 1 + strlen(p) + 1;
		np->cname = Malloc(len);
		(void) snprintf(np->cname, len, "%s/%s", sname, p);
	}
}

/*
 * get dev
 */
int
meta_getdev(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	struct stat	statbuf;

	/* get dev */
	if (meta_stat(np->rname, &statbuf) != 0)
		return (mdsyserror(ep, errno, np->rname));
	else if (! S_ISCHR(statbuf.st_mode))
		return (mddeverror(ep, MDE_NOT_DISK, NODEV64, np->rname));
	np->dev = meta_expldev(statbuf.st_rdev);

	assert(np->drivenamep->type != MDT_FAST_META &&
	    np->drivenamep->type != MDT_FAST_COMP);

	/* check set */
	assert((np->drivenamep->type == MDT_META) ?
	    (sp->setno == MD_MIN2SET(meta_getminor(np->dev))) : 1);

	/* return sucess */
	return (0);
}

/*
 * set up names for a slice
 */
static int
getnames(
	mdsetname_t	*sp,
	mdname_t	*np,
	char		*rname,
	md_error_t	*ep
)
{
	/* get names */
	if (np->rname)
		Free(np->rname);
	np->rname = Strdup(rname);
	if (getbname(np, ep) != 0)
		return (-1);
	getcname(sp, np);
	if (meta_getdev(sp, np, ep) != 0)
		return (-1);

	/* return success */
	return (0);
}

/*
 * fake up names for a slice
 */
static void
getfakenames(
	mdsetname_t	*sp,
	mdname_t	*np,
	char		*rname
)
{
	char		*p;
	char		onmb[BUFSIZ+1], snm[BUFSIZ+1];
	uint_t		d = 0;
	int		l = 0;

	/* fake names */
	if (np->rname != NULL)
		Free(np->rname);
	np->rname = Strdup(rname);

	if (np->bname != NULL)
		Free(np->bname);
	np->bname = Strdup(rname);

	/*
	 * Fixup old style names
	 */
	if (sscanf(rname, "/dev/r%" VAL2STR(BUFSIZ) "[^0-9/]%u"
	    "%" VAL2STR(BUFSIZ) "[a-h]%n",
	    onmb, &d, snm, &l) == 3 && l == strlen(rname))
		(void) snprintf(np->bname, l, "/dev/%s%u%s", onmb, d, snm);

	/*
	 * Fixup new style names
	 */
	if ((p = strstr(np->bname, "/rdsk/")) != NULL) {
		for (++p; (*(p + 1) != '\0'); ++p)
			*p = *(p + 1);
		*p = '\0';
	}

	if (np->cname != NULL)
		Free(np->cname);
	getcname(sp, np);
}

static mdname_t *
setup_slice(
	mdsetname_t		*sp,
	meta_device_type_t	uname_type,
	mddrivename_t		*dnp,
	char			*uname,
	char			*rname,
	char			*dname,
	uint_t			partno,
	md_error_t		*ep
)
{
	char			*srname = NULL;
	mdname_t		*np;

	/* must have a set */
	assert(sp != NULL);
	assert(partno < dnp->parts.parts_len);
	assert(dname != NULL);

	np = &dnp->parts.parts_val[partno];

	if (rname)
		srname = rname;
	else if (uname_type == META_DEVICE)
		srname = dname;
	else {
		char	onmb[BUFSIZ+1];
		uint_t	d = 0;
		int	l = 0, cl = strlen(dname);
		size_t	len;

		len = cl + 20 + 1;
		srname = Malloc(len);

		/*
		 * Handle /dev/rXXNN.
		 */
		if (sscanf(dname, "/dev/r%" VAL2STR(BUFSIZ) "[^0-9/]%u%n",
		    onmb, &d, &l) == 2 && l == cl) {
			(void) snprintf(srname, len, "/dev/r%s%u%c", onmb, d,
			    'a' + partno);
		} else if (sscanf(dname, "/dev/%" VAL2STR(BUFSIZ) "[^0-9/]%u%n",
		    onmb, &d, &l) == 2 && l == cl) {
			    (void) snprintf(srname, len, "/dev/%s%u%c", onmb, d,
				'a' + partno);
		} else {
			/* build the slice that is wanted */
			(void) snprintf(srname, len, "%ss%u", dname, partno);
		}
	}

	if (getnames(sp, np, srname, ep) != 0) {
		if (dnp->type == MDT_UNKNOWN) {
			mdclrerror(ep);
			getfakenames(sp, np, srname);
		} else if (dnp->type == MDT_COMP && mdissyserror(ep, ENOENT)) {
			dnp->type = MDT_UNKNOWN;
			if (mdanysyserror(ep)) {
				dnp->errnum =
				    ep->info.md_error_info_t_u.sys_error.errnum;
			} else {
				dnp->errnum = ENOENT;
			}
			mdclrerror(ep);
			getfakenames(sp, np, srname);
		} else {
			mdclrerror(ep);
			if (getnames(sp, np, dname, ep) != 0) {
				np = NULL;
				goto fixup;
			}
		}
	}

out:
	if ((srname != rname) && (srname != dname))
		Free(srname);

	/* return name */
	return (np);

fixup:
	if (mdanysyserror(ep)) {
		char	*p;
		int	errnum = ep->info.md_error_info_t_u.sys_error.errnum;

		mdclrerror(ep);
		if (uname && *uname) {
			if ((p = strrchr(uname, '/')) != NULL)
				(void) mdsyserror(ep, errnum, ++p);
			else
				(void) mdsyserror(ep, errnum, uname);
		} else {
			if ((p = strrchr(srname, '/')) != NULL)
				(void) mdsyserror(ep, errnum, ++p);
			else
				(void) mdsyserror(ep, errnum, srname);
		}
	}
	goto out;
}

/*
 * flush the fast name cache
 */
static void
metafreefastnm(mdname_t **np)
{
	mddrivename_t	*dnp;

	assert(np != NULL && *np != NULL);

	if ((dnp = (*np)->drivenamep) != NULL) {
		if (dnp->cname != NULL)
			Free(dnp->cname);
		if (dnp->rname != NULL)
			Free(dnp->rname);
		if (dnp->miscname != NULL)
			Free(dnp->miscname);
		meta_free_unit(dnp);
		Free(dnp);
	}
	if ((*np)->cname != NULL)
		Free((*np)->cname);
	if ((*np)->bname != NULL)
		Free((*np)->bname);
	if ((*np)->rname != NULL)
		Free((*np)->rname);
	if ((*np)->devicesname != NULL)
		Free((*np)->devicesname);
	Free(*np);
	*np = NULL;
}

/*
 * flush the fast name cache
 */
static void
metaflushfastnames()
{
	mdnamelist_t	*p, *n;

	for (p = fastnmlp, n = NULL; (p != NULL); p = n) {
		n = p->next;
		metafreefastnm(&p->namep);
		Free(p);
	}
	fastnmlp = NULL;
}
static char *
getrname_fast(char *unm, meta_device_type_t uname_type, md_error_t *ep)
{
	uint_t			d = 0;
	int			l = 0;
	int			cl = strlen(unm);
	char			onmb[BUFSIZ+1], snm[BUFSIZ+1], cnmb[BUFSIZ];
	char			*rnm;
	char			*p;
	size_t			len;

	if (uname_type == META_DEVICE) {
		/* fully qualified  - local set */
		if (((sscanf(unm, "/dev/md/dsk/%" VAL2STR(BUFSIZ) "s%n",
				onmb, &len) == 1) && (cl == len)) ||
		    ((sscanf(unm, "/dev/md/rdsk/%" VAL2STR(BUFSIZ) "s%n",
				onmb, &len) == 1) && (cl == len))) {
			len = strlen("/dev/md/rdsk/") +	strlen(onmb) + 1;
			rnm = Zalloc(len);
			(void) snprintf(rnm, len, "/dev/md/rdsk/%s", onmb);
			return (rnm);
		}

		/* fully qualified - setname specified */
		if (((sscanf(unm, "/dev/md/%[^/]/dsk/%"
				VAL2STR(BUFSIZ) "s%n",
				snm, onmb, &len) == 2) && (cl == len)) ||
		    ((sscanf(unm, "/dev/md/%[^/]/rdsk/%"
				VAL2STR(BUFSIZ) "s%n",
				snm, onmb, &len) == 2) && (cl == len))) {

			len = strlen("/dev/md//rdsk/") + strlen(snm) +
				strlen(onmb) + 1;
			rnm = Zalloc(len);
			(void) snprintf(rnm, len, "/dev/md/%s/rdsk/%s",
			    snm, onmb);
			return (rnm);
		}

		/* Fully qualified path - error */
		if (unm[0] == '/') {
			(void) mdsyserror(ep, EINVAL, unm);
			return (NULL);
		}

		/* setname specified <setname>/<metadev> */
		if (((sscanf(unm, "%[^/]/%" VAL2STR(BUFSIZ) "s%n",
				snm, onmb, &len) == 2) && (cl == len))) {
			/* Not <setname>/<metadev>  - error */
			if (strchr(onmb, '/') != NULL) {
				(void) mdsyserror(ep, EINVAL, unm);
				return (NULL);
			}

			len = strlen("/dev/md//rdsk/") + strlen(snm) +
				strlen(onmb) + 1;
			rnm = Zalloc(len);
			(void) snprintf(rnm, len, "/dev/md/%s/rdsk/%s",
			    snm, onmb);
			return (rnm);
		}

		/* Must be simple metaname/hsp pool name */
		len = strlen("/dev/md/rdsk/") + strlen(unm) + 1;
		rnm = Zalloc(len);
		(void) snprintf(rnm, len, "/dev/md/rdsk/%s", unm);
		return (rnm);
	}

	/* NOT Fully qualified path, done */
	if (unm[0] != '/') {
		(void) mdsyserror(ep, EINVAL, unm);
		return (NULL);
	}

	/*
	 * Get slice information from old style names of the form
	 * /dev/rXXNN[a-h] or /dev/XXNN[a-h], must be done before regular
	 * devices, but after metadevices.
	 */
	if ((sscanf(unm, "/dev/r%" VAL2STR(BUFSIZ) "[^0-9/]%u"
	    "%" VAL2STR(BUFSIZ) "[a-h]%n",
	    onmb, &d, snm, &l) == 3 ||
	    sscanf(unm, "/dev/%" VAL2STR(BUFSIZ) "[^0-9/]%u"
	    "%" VAL2STR(BUFSIZ) "[a-h]%n",
	    onmb, &d, snm, &l) == 3) && l == cl) {
		if ((p = strchr("abcdefgh", snm[0])) != NULL) {
			(void) snprintf(cnmb, sizeof (cnmb), "/dev/r%s%u%s",
			    onmb, d, snm);
			return (Strdup(cnmb));
		}
	}

	if ((p = strstr(unm, "/dsk/")) != NULL) {	/* /.../dsk/... */
		++p;
		rnm = Zalloc(strlen(unm) + 1 + 1);
		(void) strncpy(rnm, unm, (p - unm));
		rnm[(p - unm)] = 'r';
		(void) strcpy(&rnm[(p - unm) + 1], p);
		return (rnm);
	} else if (strstr(unm, "/rdsk/") != NULL) {	/* /.../rdsk/... */
		return (Strdup(unm));
	}

	/*
	 * Shouldn't get here but if we do then we have an unrecognized
	 * fully qualified path - error
	 */
	(void) mdsyserror(ep, EINVAL, unm);
	return (NULL);
}

static mdname_t *
metainitfastname(
	mdsetname_t		*sp,
	char			*uname,
	meta_device_type_t	uname_type,
	md_error_t		*ep
)
{
	uint_t			c = 0, t = 0, d = 0, s = 0;
	int			l = 0;
	mddrivename_t		*dnp;
	mdname_t		*np;
	mdnamelist_t		**fnlpp;
	char			*cname;

	for (fnlpp = &fastnmlp; (*fnlpp != NULL); fnlpp = &(*fnlpp)->next) {
		np = (*fnlpp)->namep;

		if (strcmp(np->bname, uname) == 0)
			return (np);
	}

	*fnlpp = Zalloc(sizeof (**fnlpp));
	np = (*fnlpp)->namep = Zalloc(sizeof (mdname_t));
	metainitname(np);
	dnp = np->drivenamep = Zalloc(sizeof (mddrivename_t));
	metainitdrivename(dnp);


	/* Metadevices */
	if (uname_type == META_DEVICE &&
	    (cname = meta_canonicalize(sp, uname)) != NULL) {

		np->cname = cname;
		dnp->type = MDT_FAST_META;
		goto done;
	}

	/* Others */
	dnp->type = MDT_FAST_COMP;

	if (((sscanf(uname, "/dev/rdsk/c%ut%ud%us%u%n", &c, &t, &d,
		&s, &l) == 4 ||
	    sscanf(uname, "/dev/dsk/c%ut%ud%us%u%n", &c, &t, &d,
		&s, &l) == 4 ||
	    sscanf(uname, "/dev/ap/rdsk/mc%ut%ud%us%u%n", &c, &t, &d,
		&s, &l) == 4 ||
	    sscanf(uname, "/dev/ap/dsk/mc%ut%ud%us%u%n", &c, &t, &d,
		&s, &l) == 4 ||
	    sscanf(uname, "/dev/did/rdsk/d%us%u%n", &t, &s, &l) == 2 ||
	    sscanf(uname, "/dev/did/dsk/d%us%u%n", &t, &s, &l) == 2||
	    sscanf(uname, "/dev/rdsk/c%ud%us%u%n", &c, &d, &s, &l) == 3 ||
	    sscanf(uname, "/dev/dsk/c%ud%us%u%n", &c, &d, &s, &l) == 3 ||
	    sscanf(uname, "/dev/rdsk/c%ut%ud%u%n", &c, &t, &d, &l) == 3 ||
	    sscanf(uname, "/dev/dsk/c%ut%ud%u%n", &c, &t, &d, &l) == 3 ||
	    sscanf(uname, "/dev/ap/rdsk/mc%ut%ud%u%n", &c, &t, &d, &l) == 3 ||
	    sscanf(uname, "/dev/ap/dsk/mc%ut%ud%u%n", &c, &t, &d, &l) == 3 ||
	    sscanf(uname, "/dev/did/rdsk/d%u%n", &t, &l) == 1 ||
	    sscanf(uname, "/dev/did/dsk/d%u%n", &t, &l) == 1 ||
	    sscanf(uname, "/dev/rdsk/c%ud%u%n", &c, &d, &l) == 2 ||
	    sscanf(uname, "/dev/dsk/c%ud%u%n", &c, &d, &l) == 2) &&
		l == strlen(uname))) {
		if ((np->cname = strrchr(uname, '/')) == NULL)
			np->cname = Strdup(uname);
		else
			np->cname = Strdup(++np->cname);
	} else {
		np->cname = Strdup(uname);
	}

done:
	/* Driver always gives us block names */
	np->bname = Strdup(uname);

	/* canonical disk name */
	if ((dnp->cname = metadiskname(np->cname)) == NULL)
		dnp->cname = Strdup(np->cname);

	if ((np->rname = getrname_fast(uname, uname_type, ep)) != NULL) {
		if ((dnp->rname = metadiskname(np->rname)) == NULL)
			dnp->rname = Strdup(np->rname);
	} else {
		metafreefastnm(&(*fnlpp)->namep);
		Free(*fnlpp);
		*fnlpp = NULL;
		return (NULL);
	}

	/* cleanup, return success */
	return (np);
}

/*
 * set up names for a device
 */
static mdname_t *
metaname_common(
	mdsetname_t	**spp,
	char		*uname,
	int		fast,
	meta_device_type_t	uname_type,
	md_error_t	*ep
)
{
	mddrivenamelist_t	**tail;
	mddrivename_t		*dnp;
	uint_t			slice;
	mdname_t		*np;
	char			*rname = NULL;
	char			*dname = NULL;
	char			*cname = NULL;
	uint_t			nparts, partno;

	assert(uname != NULL);

	/* check setname */
	if ((cname = meta_name_getname(spp, uname, uname_type, ep)) == NULL)
		return (NULL);

	assert(*spp != NULL);
	Free(cname);

	/* get raw name (rname) of the slice and drive (dname) we have */
	if ((rname = getrawnames(spp, uname,
				&dname, &uname_type, ep)) == NULL) {
		return (NULL);
	}

	assert(uname_type != UNKNOWN);

	/* look in cache first */
	for (tail = &drivelistp; (*tail != NULL); tail = &(*tail)->next) {
		dnp = (*tail)->drivenamep;

		/* check to see if the drive name is already in the cache */
		if ((dnp->rname != NULL) && strcmp(dnp->rname, dname) == 0) {

			Free(rname);
			if (dname != NULL)
				Free(dname);

			if (uname2sliceno(uname, uname_type, &partno, ep) < 0)
				return (NULL);

			return (metaslicename(dnp, partno, ep));
		}
	}

	/*
	 * If a fast names is OK, then get one, and be done.
	 */
	if (fast) {
		Free(rname);
		if (dname != NULL)
			Free(dname);

		return (metainitfastname(*spp, uname, uname_type, ep));
	}

	/* allocate new list element and drive */
	*tail = Zalloc(sizeof (**tail));
	dnp = (*tail)->drivenamep = Zalloc(sizeof (*dnp));

	metainitdrivename(dnp);

	/* get parts info */
	if (getparts(dnp, rname, dname, uname_type, &nparts, &partno, ep) != 0)
		goto out;

	/*
	 * libmeta needs at least V_NUMPAR partitions.
	 * If we have an EFI partition with less than V_NUMPAR slices,
	 * we nevertheless reserve space for V_NUMPAR
	 */
	if (nparts < V_NUMPAR) {
		nparts = V_NUMPAR;
	}

	/* allocate and link in parts */
	dnp->parts.parts_len = nparts;
	dnp->parts.parts_val = Zalloc((sizeof (*dnp->parts.parts_val)) *
	    dnp->parts.parts_len);
	for (slice = 0; (slice < nparts); ++slice) {
		np = &dnp->parts.parts_val[slice];
		metainitname(np);
		np->drivenamep = dnp;
	}

	/* setup name_t (or slice) wanted */
	if ((np = setup_slice(*spp, uname_type, dnp, uname, rname,
	    dname, partno, ep)) == NULL)
		goto out;

	/* canonical disk name */
	if ((dnp->cname = metadiskname(np->cname)) == NULL)
		dnp->cname = Strdup(np->cname);
	if ((dnp->rname = metadiskname(np->rname)) == NULL)
		dnp->rname = Strdup(np->rname);

	/* cleanup, return success */
	if (dname != NULL)
		Free(dname);
	Free(rname);
	return (np);

	/* cleanup, return error */
out:
	if (dname != NULL)
		Free(dname);
	if (rname != NULL)
		Free(rname);

	metafreedrivename(dnp);
	Free(dnp);
	Free(*tail);
	*tail = NULL;
	return (NULL);
}

/*
 * metaname()
 *
 * Wrapper function for metaname_common()
 * If the second arg is a metadevice name then it is important that this should
 * be a canonical name (eg d30 rather than /dev/md/dsk/d30). If this is not the
 * case then a bad entry may be placed into the drivelistp cache.
 */
mdname_t *
metaname(
	mdsetname_t	**spp,
	char		*uname,
	meta_device_type_t	uname_type,
	md_error_t	*ep
)
{
	return (metaname_common(spp, uname, 0, uname_type, ep));
}

mdname_t *
metaname_fast(
	mdsetname_t	**spp,
	char		*uname,
	meta_device_type_t	uname_type,
	md_error_t	*ep
)
{
	return (metaname_common(spp, uname, 1, uname_type, ep));
}
/*
 * Get the dnp using the device id.
 *
 * We have the potential to have more than 1 dnp with the same disk name but
 * have different device ids. This would happen in the case of a partial
 * diskset. The unavailable disk name is relative to the prior host and could
 * possibly be the same as a disk on this system. The only way to tell which
 * dnp belongs with this disk is by searching by device id. We have the
 * potential to have the case where 1) the disk who's device id we pass in is
 * in the system. In this case the name and the device id are both valid for
 * the disk. 2) The disk whose device id we've been passed is not in the
 * system and no disk with the same name has a dnp on the list. And 3) The
 * disk whose device id we've been passed is not on the system but there is
 * a disk with the same name (different devid) that is on the system. Here's
 * what we return for each of those cases:
 * 1) If disk is in system:
 * 	disk is found on drivelistp or we create a new drivename and it's
 * 	fully populated as expected.
 * 2) If disk not in system, no collision
 *	Disk with the same devid is not found on drivelistp, we create a new
 *	drivename structure and the dnp->devid is filled in not from getparts
 *	but from the devidp passed in. No other disk in the system has the
 *	same "name" or devid.
 *	This situation would be caused by the import of a partial diskset.
 * 3) If disk not in system, collision
 *	Disk with the same devid is not found on the drivelistp, we create a
 *	new drivename struct but getparts will use the information from the
 *	name which is actually in reference to another disk of the same name
 *	in the system. getparts will fill in the dnp->devid with the value
 *	from the other disk and	we overwrite this with the value of this disk.
 *	To get into this situation one of the disks is actually unavailable
 *	as in the case of a partial import.
 */
mddrivename_t *
meta_getdnp_bydevid(
	mdsetname_t	*sp,
	side_t		sideno,
	ddi_devid_t	devidp,
	mdkey_t		key,
	md_error_t	*ep
)
{
	ddi_devid_t		dnp_devidp;
	char			*nm;
	mddrivenamelist_t	**tail;
	mddrivename_t		*dnp;
	uint_t			slice;
	mdname_t		*np;
	char			*rname = NULL;
	char			*dname = NULL;
	uint_t			nparts, partno;
	int			ret;
	md_set_desc		*sd = NULL;
	meta_device_type_t	uname_type = LOGICAL_DEVICE;

	/* look in the cache first */
	for (tail = &drivelistp; (*tail != NULL); tail = &(*tail)->next) {
		dnp = (*tail)->drivenamep;
		if (dnp->type != MDT_COMP)
			continue;
		ret = devid_str_decode(dnp->devid, &dnp_devidp, NULL);
		if (ret != 0) {
			/* unable to decode the devid */
			return (NULL);
		}
		/* compare with the devid passed in. */
		if (devid_compare(devidp, dnp_devidp) == 0) {
			/* match! We have the same disk */
			devid_free(dnp_devidp);
			return (dnp);
		}
		devid_free(dnp_devidp);
	}

	/* drive not in the cache */

	if ((sd = metaget_setdesc(sp, ep)) == NULL) {
		return (NULL);
	}
	/* get namespace info */
	if (MD_MNSET_DESC(sd)) {
		if ((nm = meta_getnmbykey(MD_LOCAL_SET, sideno,
		    key, ep)) == NULL)
			return (NULL);
	} else {
		if ((nm = meta_getnmbykey(MD_LOCAL_SET,
		    sideno+SKEW, key, ep)) == NULL)
			return (NULL);
	}

	/* get raw name (rname) of the slice and drive name (dname) */
	if ((rname = getrawnames(&sp, nm, &dname, &uname_type, ep)) == NULL) {
		return (NULL);
	}

	/* allocate new list element and drive */
	*tail = Zalloc(sizeof (**tail));
	dnp = (*tail)->drivenamep = Zalloc(sizeof (*dnp));
	metainitdrivename(dnp);

	/* get parts info */
	/*
	 * Note that if the disk is unavailable this name will point to
	 * either a nonexistent disk and thus the part info and devid will
	 * be empty or the name will point to the wrong disk and this
	 * information will be invalid. Because of this, we overwrite the
	 * dnp->devid with the correct one after getparts returns.
	 */
	if (getparts(dnp, rname, dname, uname_type, &nparts, &partno, ep) != 0)
		goto out;

	dnp->devid = devid_str_encode(devidp, NULL);

	/*
	 * libmeta needs at least V_NUMPAR partitions.
	 * If we have an EFI partition with less than V_NUMPAR slices,
	 * we nevertheless reserve space for V_NUMPAR
	 */
	if (nparts < V_NUMPAR) {
		nparts = V_NUMPAR;
	}

	/* allocate and link in parts */
	dnp->parts.parts_len = nparts;
	dnp->parts.parts_val = Zalloc((sizeof (*dnp->parts.parts_val)) *
	    dnp->parts.parts_len);

	for (slice = 0; (slice < nparts); ++slice) {
		np = &dnp->parts.parts_val[slice];
		metainitname(np);
		np->drivenamep = dnp;
	}

	/* setup name_t (or slice) wanted */
	if ((np = setup_slice(sp, uname_type, dnp, nm, rname,
	    dname, partno, ep)) == NULL)
		goto out;

	/* canonical disk name */
	if ((dnp->cname = metadiskname(np->cname)) == NULL)
		dnp->cname = Strdup(np->cname);
	if ((dnp->rname = metadiskname(np->rname)) == NULL)
		dnp->rname = Strdup(np->rname);

	if (dname != NULL)
		Free(dname);
	Free(rname);
	return (dnp);

out:
	if (dname != NULL)
		Free(dname);

	if (rname != NULL)
		Free(rname);

	metafreedrivename(dnp);
	Free(dnp);
	Free(*tail);
	*tail = NULL;
	return (NULL);
}

/*
 * Search the drivename list by devid instead of name. If you don't find
 * an entry with the same device id, create one for the uname passed in.
 */
mddrivename_t *
metadrivenamebydevid(
	mdsetname_t		**spp,
	char			*devid,
	char			*uname,
	md_error_t		*ep
)
{
	ddi_devid_t		dnp_devidp, in_devidp;
	mdname_t		*np;
	mddrivenamelist_t	**tail;
	char			*rname = NULL;
	mddrivename_t		*dnp;
	char			*dname;
	int			ret;
	uint_t			nparts, partno;
	uint_t			slice;
	meta_device_type_t	uname_type = LOGICAL_DEVICE;

	/* look in the cache first */
	for (tail = &drivelistp; (*tail != NULL); tail = &(*tail)->next) {
		dnp = (*tail)->drivenamep;
		if (dnp->type != MDT_COMP)
			continue;

		/* decode the dnp devid */
		ret = devid_str_decode(dnp->devid, &dnp_devidp, NULL);
		if (ret != 0) {
			/* unable to decode the devid */
			return (NULL);
		}
		/* decode the passed in devid */
		ret = devid_str_decode(devid, &in_devidp, NULL);
		if (ret != 0) {
			/* unable to decode the devid */
			devid_free(dnp_devidp);
			return (NULL);
		}
		/* compare with the devids */
		if (devid_compare(in_devidp, dnp_devidp) == 0) {
			/* match! We have the same disk */
			devid_free(dnp_devidp);
			devid_free(in_devidp);
			return (dnp);
		}
	}
	devid_free(dnp_devidp);
	devid_free(in_devidp);

	/* not in the cache */

	/* get raw name (rname) of the slice and drive (dname) we have */
	if ((rname = getrawnames(spp, uname, &dname, &uname_type,
	    ep)) == NULL) {
		return (NULL);
	}

	/* allocate new list element and drive */
	*tail = Zalloc(sizeof (**tail));
	dnp = (*tail)->drivenamep = Zalloc(sizeof (*dnp));

	metainitdrivename(dnp);

	/* get parts info */
	if (getparts(dnp, rname, dname, uname_type, &nparts, &partno, ep) != 0)
		goto out;

	/*
	 * libmeta needs at least V_NUMPAR partitions.
	 * If we have an EFI partition with less than V_NUMPAR slices,
	 * we nevertheless reserve space for V_NUMPAR
	 */
	if (nparts < V_NUMPAR) {
		nparts = V_NUMPAR;
	}

	/* allocate and link in parts */
	dnp->parts.parts_len = nparts;
	dnp->parts.parts_val = Zalloc((sizeof (*dnp->parts.parts_val)) *
	    dnp->parts.parts_len);
	for (slice = 0; (slice < nparts); ++slice) {
		np = &dnp->parts.parts_val[slice];
		metainitname(np);
		np->drivenamep = dnp;
	}

	/* setup name_t (or slice) wanted */
	if ((np = setup_slice(*spp, uname_type, dnp, uname, rname,
	    dname, partno, ep)) == NULL)
		goto out;

	/* canonical disk name */
	if ((dnp->cname = metadiskname(np->cname)) == NULL)
		dnp->cname = Strdup(np->cname);
	if ((dnp->rname = metadiskname(np->rname)) == NULL)
		dnp->rname = Strdup(np->rname);

	/* cleanup, return success */
	if (dname != NULL)
		Free(dname);
	Free(rname);
	return (dnp);

	/* cleanup, return error */
out:
	if (dname != NULL)
		Free(dname);
	if (rname != NULL)
		Free(rname);

	metafreedrivename(dnp);
	Free(dnp);
	Free(*tail);
	*tail = NULL;
	return (NULL);
}
/*
 * set up names for a drive
 */
mddrivename_t *
metadrivename(
	mdsetname_t		**spp,
	char			*uname,
	md_error_t		*ep
)
{
	char		*slicename;
	mdname_t	*np;

	mddrivenamelist_t **tail;
	mddrivename_t	*dnp;
	char		*dname;
	int		i;
	int		mplen;
	size_t		len;

	assert(uname != NULL);

	if ((dname = metadiskname(uname)) == NULL) {
		(void) mdsyserror(ep, ENOENT, uname);
		return (NULL);
	}

	/* look in cache first */
	for (tail = &drivelistp; (*tail != NULL); tail = &(*tail)->next) {
		dnp = (*tail)->drivenamep;
		if ((dnp->cname != NULL &&
		    (strcmp(dnp->cname, dname) == 0)) ||
		    (dnp->rname != NULL &&
		    (strcmp(dnp->rname, dname) == 0))) {
			Free(dname);
			return (dnp);
		}
	}
	Free(dname);

	/* Check each possible slice name based on MD_MAX_PARTS. */

	/*
	 * Figure out how much string space to reserve to fit
	 * (MD_MAX_PARTS - 1) into the name string; the loop will
	 * increment the mplen counter once for each decimal digit in
	 * (MD_MAX_PARTS - 1).
	 */
	for (i = MD_MAX_PARTS - 1, mplen = 0; i; i /= 10, ++mplen);
	len = strlen(uname) + mplen + 2;
	slicename = Malloc(len);

	/* Check for each slice in turn until we find one */
	for (np = NULL, i = 0; ((np == NULL) && (i < MD_MAX_PARTS)); ++i) {
		(void) snprintf(slicename, len, "%ss%d", uname, i);
		np = metaname(spp, slicename, LOGICAL_DEVICE, ep);
	}
	Free(slicename);

	if (np == NULL) {
		if ((mdiserror(ep, MDE_UNIT_NOT_FOUND)) &&
		    ((dname = metadiskname(uname)) != NULL)) {
			Free(dname);
			(void) mderror(ep, MDE_NOT_DRIVENAME, uname);
		}
		return (NULL);
	}
	return (np->drivenamep);
}

/*
 * FUNCTION:	metaslicename_type()
 * INPUT:	dnp	- the drivename structure
 *		sliceno	- the slice on the drive to return
 *		type - LOGICAL_DEVICE or META_DEVICE
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	mdname_t- pointer the the slice name structure
 * PURPOSE:	interface to the parts struct in the drive name struct
 *		Since there is no guarantee that the slice name
 *		structures are populated users should call this
 *		function rather than accessing the structure directly
 *		since it will populate the structure values if they
 *		haven't already been populated before returning.
 */
mdname_t *
metaslicename_type(
	mddrivename_t		*dnp,
	uint_t			sliceno,
	meta_device_type_t	uname_type,
	md_error_t		*ep
)
{
	mdsetname_t	*sp = NULL;
	char		*namep = NULL;
	mdname_t	*np;

	assert(dnp->type != MDT_FAST_COMP && dnp->type != MDT_FAST_META);

	if (sliceno >= dnp->parts.parts_len) {
		(void) mderror(ep, MDE_NOSLICE, dnp->cname);
		return (NULL);
	}

	np = &dnp->parts.parts_val[sliceno];

	/* check to see if the struct is already populated */
	if (np->cname) {
		return (np);
	}

	if ((namep = meta_name_getname(&sp, dnp->cname,
					uname_type, ep)) == NULL)
		return (NULL);

	np = setup_slice(sp, uname_type, dnp, NULL, NULL, dnp->rname,
	    sliceno, ep);

	Free(namep);

	return (np);
}

/*
 * FUNCTION:	metaslicename()
 * INPUT:	dnp	- the drivename structure
 *		sliceno	- the slice on the drive to return
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	mdname_t- pointer the the slice name structure
 * PURPOSE:	interface to the parts struct in the drive name struct
 *		Since there is no guarantee that the slice name
 *		structures are populated users should call this
 *		function rather than accessing the structure directly
 *		since it will populate the structure values if they
 *		haven't already been populated before returning.
 */
mdname_t *
metaslicename(
	mddrivename_t	*dnp,
	uint_t		sliceno,
	md_error_t	*ep
)
{
	return (metaslicename_type(dnp, sliceno, LOGICAL_DEVICE, ep));
}

/*
 * set up metadevice name from id
 */
mdname_t *
metamnumname(
	mdsetname_t	**spp,
	minor_t		mnum,
	int		fast,
	md_error_t	*ep
)
{
	set_t		setno = MD_MIN2SET(mnum);
	mdsetname_t	*sp = NULL;
	char		*uname;
	mdname_t	*np;
	md_dev64_t	dev;
	mdkey_t		key;

	/* check set first */
	if (spp == NULL)
		spp = &sp;
	if (chksetno(spp, setno, ep) != 0)
		return (NULL);
	assert(*spp != NULL);
	sp = *spp;

	/* get corresponding device name */
	dev = metamakedev(mnum);
	if ((uname = meta_getnmentbydev(sp->setno, MD_SIDEWILD, dev,
	    NULL, NULL, &key, ep)) == NULL)
		return (NULL);

	/* setup name */
	if (fast) {
		np = metaname_fast(spp, uname, META_DEVICE, ep);
		if (np) {
			np->dev = dev;
			np->key = key;
		}
	} else
		np = metaname(spp, uname, META_DEVICE, ep);

	Free(uname);
	return (np);
}

/*
 * return metadevice name
 */
char *
get_mdname(
	mdsetname_t	*sp,
	minor_t		mnum
)
{
	mdname_t	*np;
	md_error_t	status = mdnullerror;
	mdsetname_t	**spp = NULL;

	if (sp != NULL)
		spp = &sp;

	/* get name */
	if ((np = metamnumname(spp, mnum, 0, &status)) == NULL) {
		return (NULL);
	}
	assert(meta_getminor(np->dev) == mnum);

	/* return name */
	return (np->cname);
}

/*
 * check for device type
 */
int
metaismeta(
	mdname_t	*np
)
{
	return (np->drivenamep->type == MDT_META ||
		np->drivenamep->type == MDT_FAST_META);
}

int
metachkmeta(
	mdname_t	*np,
	md_error_t	*ep
)
{
	if (! metaismeta(np)) {
		return (mddeverror(ep, MDE_NOT_META, np->dev,
		    np->cname));
	}
	return (0);
}

int
metachkdisk(
	mdname_t	*np,
	md_error_t	*ep
)
{
	mddrivename_t	*dnp = np->drivenamep;

	assert(dnp->type != MDT_FAST_COMP && dnp->type != MDT_FAST_META);

	if ((! metaismeta(np)) && (dnp->type != MDT_COMP)) {
		switch (dnp->type) {
		    case MDT_ACCES:
		    case MDT_UNKNOWN:
			    return (mdsyserror(ep, dnp->errnum, np->bname));
		    default:
			    assert(0);
			    return (mddeverror(ep, MDE_NOT_DISK, np->dev,
				np->cname));
		}
	}
	return (0);
}

int
metachkcomp(
	mdname_t	*np,
	md_error_t	*ep
)
{
	if (metaismeta(np)) {
		return (mddeverror(ep, MDE_IS_META, np->dev,
		    np->cname));
	}
	return (metachkdisk(np, ep));
}

/*
 * free list of names
 */
void
metafreenamelist(
	mdnamelist_t	*nlp
)
{
	mdnamelist_t	*next = NULL;

	for (/* void */; (nlp != NULL); nlp = next) {
		next = nlp->next;
		Free(nlp);
	}
}

/*
 * build list of names
 */
int
metanamelist(
	mdsetname_t	**spp,
	mdnamelist_t	**nlpp,
	int		argc,
	char		*argv[],
	meta_device_type_t	type,
	md_error_t	*ep
)
{
	mdnamelist_t	**tailpp = nlpp;
	int		count = 0;

	for (*nlpp = NULL; (argc > 0); ++count, --argc, ++argv) {
		mdnamelist_t	*nlp = Zalloc(sizeof (*nlp));

		if ((nlp->namep = metaname(spp, argv[0],
		    type, ep)) == NULL) {
			metafreenamelist(*nlpp);
			*nlpp = NULL;
			return (-1);
		}
		*tailpp = nlp;
		tailpp = &nlp->next;
	}
	return (count);
}

/*
 * append to end of name list
 */
mdname_t *
metanamelist_append(
	mdnamelist_t	**nlpp,
	mdname_t	*np
)
{
	mdnamelist_t	*nlp;

	/* run to end of list */
	for (; (*nlpp != NULL); nlpp = &(*nlpp)->next)
		;

	/* allocate new list element */
	nlp = *nlpp = Zalloc(sizeof (*nlp));

	/* append name */
	nlp->namep = np;
	return (np);
}

/*
 * FUNCTION:	meta_namelist_append_wrapper()
 * INPUT:	tailpp	- pointer to the list tail pointer
 *		np	- name node to be appended to list
 * OUTPUT:	none
 * RETURNS:	mdnamelist_t * - new tail of the list.
 * PURPOSE:	wrapper to meta_namelist_append for performance.
 *		metanamelist_append finds the tail each time which slows
 *		down long lists.  By keeping track of the tail ourselves
 *		we can change metanamelist_append into a constant time
 *		operation.
 */
mdnamelist_t **
meta_namelist_append_wrapper(
	mdnamelist_t	**tailpp,
	mdname_t	*np
)
{
	(void) metanamelist_append(tailpp, np);

	/* If it's the first item in the list, return it instead of the next */
	if ((*tailpp)->next == NULL)
		return (tailpp);

	return (&(*tailpp)->next);
}


/*
 *	mdhspname_t stuff
 */

/*
 * initialize hspname
 */
static void
metainithspname(
	mdhspname_t	*hspnamep
)
{
	(void) memset(hspnamep, '\0', sizeof (*hspnamep));
	hspnamep->hsp = MD_HSP_NONE;
}

/*
 * free allocated hspname
 */
static void
metafreehspname(
	mdhspname_t	*hspnamep
)
{
	if (hspnamep->hspname != NULL)
		Free(hspnamep->hspname);
	if (hspnamep->unitp != NULL)
		meta_invalidate_hsp(hspnamep);
	metainithspname(hspnamep);
}

/*
 * clear the hspname cache
 */
static void
metaflushhspnames()
{
	mdhspnamelist_t		*p, *n;

	for (p = hsplistp, n = NULL; (p != NULL); p = n) {
		n = p->next;
		metafreehspname(p->hspnamep);
		Free(p->hspnamep);
		Free(p);
	}
	hsplistp = NULL;
}

/*
 * check set and get comparison name
 */
static char *
gethspname(
	mdsetname_t	**spp,
	char		*uname,
	md_error_t	*ep
)
{
	char		*cname = NULL;

	cname = meta_canonicalize(*spp, uname);
	/* if it is not a meta/hsp name then flag an error */
	if (cname == NULL) {
		(void) mdsyserror(ep, ENOENT, uname);
		return (NULL);
	}
	return (cname);
}

/*
 * set up a hotspare pool name structure using both the name
 * and the self id
 */
static mdhspname_t *
metahspname_hsp(
	mdsetname_t	**spp,
	char		*uname,
	hsp_t		hsp,
	md_error_t	*ep
)
{
	char		*cname;
	mdhspnamelist_t	**tail;
	mdhspname_t	*hspnp;

	/* check setname */
	assert(uname != NULL);
	if ((cname = gethspname(spp, uname, ep)) == NULL)
		return (NULL);
	assert(*spp != NULL);

	/* look in cache first */
	for (tail = &hsplistp; (*tail != NULL); tail = &(*tail)->next) {
		hspnp = (*tail)->hspnamep;
		if (strcmp(hspnp->hspname, cname) == 0) {
			Free(cname);
			/* if the hsp value has not been set then set it now */
			if (hspnp->hsp == MD_HSP_NONE)
				hspnp->hsp = hsp;
			return (hspnp);
		}
	}

	/* if the hsp number isn't specified then attempt to get it */
	if (hsp == MD_HSP_NONE && (hsp = meta_gethspnmentbyname((*spp)->setno,
	    MD_SIDEWILD, cname, ep)) == MD_HSP_NONE) {
		if (! mdisok(ep)) {
			/*
			 * If the error is ENOENT, then we will continue on,
			 * because the device does not yet exist.
			 * For other types of errors, however, we'll bail out.
			 */
			if (! mdissyserror(ep, ENOENT)) {
				Free(cname);
				return (NULL);
			}
			mdclrerror(ep);
		}
	}

	/* allocate new list element and hspname */
	*tail = Zalloc(sizeof (**tail));
	hspnp = (*tail)->hspnamep = Zalloc(sizeof (*hspnp));
	metainithspname(hspnp);

	/* save hspname and number */
	hspnp->hspname = cname;
	hspnp->hsp = hsp;

	/* success */
	return (hspnp);
}

/*
 * set up names for a hotspare pool
 */
mdhspname_t *
metahspname(
	mdsetname_t	**spp,
	char		*uname,
	md_error_t	*ep
)
{
	return (metahspname_hsp(spp, uname, MD_HSP_NONE, ep));
}

/*
 * set up hotspare pool name from key
 */
mdhspname_t *
metahsphspname(
	mdsetname_t	**spp,
	hsp_t		hsp,
	md_error_t	*ep
)
{
	set_t		setno = HSP_SET(hsp);
	mdsetname_t	*sp = NULL;
	char		*uname;
	mdhspname_t	*hspnp;

	/* check set first */
	if (spp == NULL)
		spp = &sp;
	if (chksetno(spp, setno, ep) != 0)
		return (NULL);
	assert(*spp != NULL);
	sp = *spp;

	/* get corresponding hotspare pool name */
	if ((uname = meta_gethspnmentbyid(sp->setno,
			MD_SIDEWILD, hsp, ep)) == NULL)
		return (NULL);

	/* setup name */
	hspnp = metahspname_hsp(spp, uname, hsp, ep);
	Free(uname);
	return (hspnp);
}

/*
 * return hotspare pool name
 */
char *
get_hspname(mdsetname_t *sp, hsp_t hsp)
{
	mdhspname_t	*hspnp;
	md_error_t	status = mdnullerror;
	mdsetname_t	**spp = NULL;

	if (sp != NULL)
		spp = &sp;

	/* get name */
	if ((hspnp = metahsphspname(spp, hsp, &status)) == NULL) {
		mdclrerror(&status);
		return (NULL);
	}

	/* return name */
	return (hspnp->hspname);
}

/*
 * free hotspare pool list
 */
void
metafreehspnamelist(mdhspnamelist_t *hspnlp)
{
	mdhspnamelist_t	*next = NULL;

	for (/* void */; (hspnlp != NULL); hspnlp = next) {
		next = hspnlp->next;
		Free(hspnlp);
	}
}

/*
 * build list of hotspare pool names
 */
int
metahspnamelist(
	mdsetname_t	**spp,
	mdhspnamelist_t	**hspnlpp,
	int		argc,
	char		*argv[],
	md_error_t	*ep
)
{
	mdhspnamelist_t	**tailpp = hspnlpp;
	int		count = 0;

	for (*hspnlpp = NULL; (argc > 0); ++count, --argc, ++argv) {
		mdhspnamelist_t	*hspnlp = Zalloc(sizeof (*hspnlp));

		if ((hspnlp->hspnamep = metahspname(spp, argv[0],
		    ep)) == NULL) {
			metafreehspnamelist(*hspnlpp);
			*hspnlpp = NULL;
			return (-1);
		}
		*tailpp = hspnlp;
		tailpp = &hspnlp->next;
	}
	return (count);
}

/*
 * append to end of hotspare pool list
 */
mdhspname_t *
metahspnamelist_append(mdhspnamelist_t **hspnlpp, mdhspname_t *hspnp)
{
	mdhspnamelist_t	*hspnlp;

	/* run to end of list */
	for (; (*hspnlpp != NULL); hspnlpp = &(*hspnlpp)->next)
		;

	/* allocate new list element */
	hspnlp = *hspnlpp = Zalloc(sizeof (*hspnlp));

	/* append hotspare pool name */
	hspnlp->hspnamep = hspnp;
	return (hspnp);
}

/*
 * get name from dev
 */
mdname_t *
metadevname(
	mdsetname_t **spp,
	md_dev64_t dev,
	md_error_t *ep)
{
	char		*device_name;
	mdname_t	*namep;
	mdkey_t		key;

	/* short circuit metadevices */
	assert(dev != NODEV64);
	if (meta_dev_ismeta(dev))
		return (metamnumname(spp, meta_getminor(dev), 0, ep));

	/* create local set, if necessary */
	if (*spp == NULL) {
		if ((*spp = metasetname(MD_LOCAL_NAME, ep)) == NULL)
			return (NULL);
	}

	/* get name from namespace */
	if ((device_name = meta_getnmentbydev((*spp)->setno, MD_SIDEWILD,
	    dev, NULL, NULL, &key, ep)) == NULL) {
		return (NULL);
	}
	namep = metaname_fast(spp, device_name, LOGICAL_DEVICE, ep);
	if (namep != NULL)
		namep->key = key;

	Free(device_name);
	return (namep);
}

/*
 * return cached name from md_dev64_t
 */
static char *
metadevtocachename(md_dev64_t dev)
{
	mddrivenamelist_t	*dnlp;

	/* look in cache */
	for (dnlp = drivelistp; (dnlp != NULL); dnlp = dnlp->next) {
		mddrivename_t	*dnp = dnlp->drivenamep;
		uint_t		i;

		for (i = 0; (i < dnp->parts.parts_len); ++i) {
			mdname_t	*np = &dnp->parts.parts_val[i];

			if (np->dev == dev)
				return (np->cname);
		}
	}

	/* not found */
	return (NULL);
}

/*
 * Ask the driver for the name, which has been stored in the
 * metadevice state database (on behalf of the utilities).
 * (by devno)
 */
char *
get_devname(
	set_t setno,
	md_dev64_t dev)
{
	mdsetname_t	*sp;
	mdname_t	*np;
	md_error_t	status = mdnullerror;

	/* get name */
	if ((setno == MD_SET_BAD) ||
	    ((sp = metasetnosetname(setno, &status)) == NULL) ||
	    ((np = metadevname(&sp, dev, &status)) == NULL)) {
		mdclrerror(&status);
		return (metadevtocachename(dev));
	}

	/* return name */
	return (np->cname);
}

/*
 * get name from key
 */
mdname_t *
metakeyname(
	mdsetname_t	**spp,
	mdkey_t		key,
	int		fast,
	md_error_t	*ep
)
{
	char		*device_name;
	md_dev64_t	dev = NODEV64;
	mdname_t	*namep;

	/* create local set, if necessary */
	if (*spp == NULL) {
		if ((*spp = metasetname(MD_LOCAL_NAME, ep)) == NULL)
			return (NULL);
	}

	/* get name from namespace */
	if ((device_name = meta_getnmentbykey((*spp)->setno, MD_SIDEWILD,
	    key, NULL, NULL, &dev, ep)) == NULL) {
		return (NULL);
	}
	if (fast)
		namep = metaname_fast(spp, device_name, UNKNOWN, ep);
	else
		namep = metaname(spp, device_name, UNKNOWN, ep);

	assert(dev != NODEV64);
	if (namep)
		namep->dev = dev;
	Free(device_name);
	return (namep);
}

/*
 * completely flush metadev/hsp caches
 */
void
metaflushmetanames()
{
	metaflushhspnames();
	metaflushdrivenames();
	metaflushfastnames();
	metaflushstatcache();
}

/*
 * completely flush the caches
 */
void
metaflushnames(int flush_sr_cache)
{
	metaflushhspnames();
	metaflushdrivenames();
	metaflushsetnames();
	metaflushctlrcache();
	metaflushfastnames();
	metaflushstatcache();
	if (flush_sr_cache)
		sr_cache_flush(0);
}

/*
 * meta_get_hotspare_names
 *  returns an mdnamelist_t of hot spare names
 */

int
meta_get_hotspare_names(
	mdsetname_t	*sp,
	mdnamelist_t	**nlpp,
	int		options,
	md_error_t	*ep
)
{
	mdhspnamelist_t		*hspnlp	= NULL;
	mdhspnamelist_t		*hspp;
	int			cnt = 0;

	assert(nlpp != NULL);

	/* get hotspare names */
	if (meta_get_hsp_names(sp, &hspnlp, options, ep) < 0) {
		cnt = -1;
		goto out;
	}

	/* build name list */
	for (hspp = hspnlp; (hspp != NULL); hspp = hspp->next) {
		md_hsp_t	*hsp;
		int		i;

		if ((hsp = meta_get_hsp(sp, hspp->hspnamep, ep)) == NULL) {
			cnt = -1;
			goto out;
		}
		for (i = 0; (i < hsp->hotspares.hotspares_len); i++) {
			md_hs_t	*hs = &hsp->hotspares.hotspares_val[i];

			(void) metanamelist_append(nlpp, hs->hsnamep);
			++cnt;
		}
	}

	/* cleanup and return count or error */
out:
	metafreehspnamelist(hspnlp);
	if ((cnt == -1) && mdisok(ep)) {
		/*
		 * At least try to give some sort of meaningful error
		 */
		(void) mderror(ep, MDE_NO_HSPS, "Generic Hotspare Error");
	}

	return (cnt);
}
/*
 * meta_create_non_dup_list
 *    INPUT: mdnp mdname_t pointer to add to the list if a new name
 *           ldevidp list of non-duplicate names.
 *    OUTPUT: ldevidp list of non-duplicate names.
 * meta_create_non_dup_list will take a mdname_t pointer and if the device
 *    is not in the list (ldevidp) will add it to the list.
 *    User needs to free allocated memory.
 */
void
meta_create_non_dup_list(
	mdname_t	*mdnp,
	mddevid_t	**ldevidpp
)
{
	char		*lcname;
	mddevid_t	*tmp;
	mddevid_t	*lastdevidp;
	mddevid_t	*lldevidp;
	char		*ctd, *slice;
	mddevid_t	*ldevidp;

	if (mdnp == NULL)
		return;

	ldevidp = *ldevidpp;
	/*
	 * Grab the name of the device and strip off slice information
	 */
	lcname = Strdup(mdnp->cname);
	if (lcname == NULL) {
		return;
	}
	ctd = strrchr(lcname, '/');
	if (ctd != NULL)
		slice = strrchr(ctd, 's');
	else
		slice = strrchr(lcname, 's');

	if (slice != NULL)
		*slice = '\0';

	if (ldevidp == NULL) {
		/* first item in list */
		ldevidp = Zalloc(sizeof (mddevid_t));
		ldevidp->ctdname = lcname;
		ldevidp->key = mdnp->key;
		*ldevidpp = ldevidp;
	} else {
		for (tmp = ldevidp; (tmp != NULL); tmp = tmp->next) {
			if (strcmp(tmp->ctdname, lcname) == 0) {
				/* already there so just return */
				Free(lcname);
				return;
			}
			lastdevidp = tmp;
		}
		lldevidp = Zalloc(sizeof (mddevid_t));
		lldevidp->ctdname = lcname;
		lldevidp->key = mdnp->key;
		lastdevidp->next = lldevidp;
	}
}
