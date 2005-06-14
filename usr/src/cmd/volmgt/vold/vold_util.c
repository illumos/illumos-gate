/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
#include	<ctype.h>
#include	<string.h>
#include	<dirent.h>
#include	<pwd.h>
#include	<grp.h>
#include	<dlfcn.h>
#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/file.h>
#include	<sys/time.h>
#include	<sys/mnttab.h>
#include	<sys/tiuser.h>
#include	<sys/mkdev.h>
#include	<sys/vtoc.h>
#include	<sys/vol.h>
#include	<sys/dkio.h>
#include	<rpc/types.h>
#include	<rpc/auth.h>
#include	<rpc/auth_unix.h>
#include	<rpc/xdr.h>
#include	<rpc/clnt.h>
#include	<rpcsvc/nis.h>
#include	<rpcsvc/nfs_prot.h>
#include	<netinet/in.h>
#include	<regex.h>

#include	"vold.h"
#include	"md4.h"

extern int	vol_fd;

#define	MNR_SETSIZE		262144		/* 2^18 */

typedef	int	mnr_mask;

#define	NMNRBITS		(sizeof (mnr_mask) * NBBY) /* bits per mask */
#define	MNRHOWMANY(x, y)	(((x)+((y)-1))/(y))

typedef	struct mnr_set {
	mnr_mask	mnr_bits[MNRHOWMANY(MNR_SETSIZE, NMNRBITS)];
} mnr_set;

#define	MNR_SET(n, p)	\
	((p)->mnr_bits[(n)/NMNRBITS] |= (1 << ((n) % NMNRBITS)))

#define	MNR_CLR(n, p)  \
	((p)->mnr_bits[(n)/NMNRBITS] &= ~(1 << ((n) % NMNRBITS)))

#define	MNR_ISSET(n, p)	\
	((p)->mnr_bits[(n)/NMNRBITS] & (1 << ((n) % NMNRBITS)))

static mnr_set	mnr_map;
static int	minor_initted;

#define	MNR_HASH_SIZE	64
static struct q	mnr_q_hash[MNR_HASH_SIZE];

struct mnr_track {
	struct q	q;		/* linked hashed list */
	vol_t		*mt_vol;	/* pointer to the volume */
	minor_t		mt_mnr;		/* minor number */
};

struct fentry {
	char		*fname;
	struct fentry	*fnext;
#define	FENTRY_MATCH		0x1
#define	FENTRY_NO_FILE		0x2
#define	FENTRY_REMOVABLE	0x4
#define	FENTRY_NOT_REMOVABLE	0x8
	int		flag;
};

static struct dentry {
	char		*dirname;
	struct dentry	*dnext;
	struct fentry	*files;
} *dir_entry_cache;

/*
 * Property management for volume flags.
 */
#define	PROP_ACC	"s-access"
#define	PROP_ACC_TAPE	"seq"
#define	PROP_ACC_DISK	"rand"
#define	PROP_DIST	"s-distr"
#define	PROP_DIST_LOC	"local"
#define	PROP_DIST_GLOB	"global"
#define	PROP_DENS	"s-density"
#define	PROP_DENS_L	"low"
#define	PROP_DENS_M	"medium"
#define	PROP_DENS_H	"high"
#define	PROP_DENS_U	"ultra"
#define	PROP_PART	"s-parts"
#define	PROP_RMONEJECT	"s-rmoneject"
#define	PROP_ENXIO	"s-enxio"
#define	PROP_MEJECTABLE	"s-mejectable"	/* if dev. is easily ejectable */
#define	PROP_LOCATION	"s-location"	/* path of device */

#define	PROP_TRUE	"true"
#define	PROP_FALSE	"false"



static uint_t	part_to_bits(char *val, uchar_t *);

/*
 * This is the list of properties that the owner is allowed to set.
 */
static char	*owner_props[] = {
	PROP_DIST,
	PROP_RMONEJECT,
	"s-stack",
	"s-readlabel",
	PROP_ENXIO,
	""
};


#ifdef	VOLMGT_DEV_TO_TTY_WORKED

/*
 * This slop is stolen from the ttyname function in the C library.
 * ttyname didn't do what I wanted.
 */
typedef struct {
	char *name;
	int flags;
} entry_t;


#define	MAX_DEV_PATH	128
#define	MAX_SRCH_DEPTH	4

#define	MATCH_MM	1
#define	MATCH_FS	2
#define	MATCH_INO	4
#define	MATCH_ALL	7

#define	DEV		"/dev"
#define	TTYSRCH		"/etc/ttysrch"
#define	CONSOLE		"/dev/console"

static  entry_t dev_dir =
	{ "/dev", MATCH_ALL };

static  entry_t def_srch_dirs[] = {	/* default search list */
	{ "/dev/term", MATCH_ALL },
	{ "/dev/pts", MATCH_ALL },
	{ "/dev/xt", MATCH_ALL },
	{ NULL, 0 }
};

static char *dir_buf = NULL;		/* directory buffer for ttysrch body */
static entry_t *dir_vec = NULL;		/* directory vector for ttysrch ptrs */
static char *rbuf = NULL;		/* perfect match file name */


#define	START_STATE	1
#define	COMMENT_STATE	2
#define	DIRNAME_STATE	3
#define	FLAG_STATE	4
#define	CHECK_STATE	5

#define	COMMENT_CHAR	'#'
#define	EOLN_CHAR	'\n'

#endif	/* VOLMGT_DEV_TO_TTY_WORKED */


/*
 * CRC Calculation code stolen from cp.
 */
#define	CRCMAGIC 987654


#define	HEXNUM_SIZE	10	/* 8 digits + "0x" */

static char	*unsafe_list[DEFAULT_UNSAFE];
static uint_t	unsafe_ind = 0;


/* length of buffer for printing numbers */
#define	VOLD_NUMBUFLEN	512

/* length of buffer for printing properties */
#define	VOLD_PROPBUFLEN	(MAXNAMELEN * 2)

/* length of buffer used to convert a regex to a shell regex */
#define	VOLD_REGEXNAME_LEN	(MAXNAMELEN * 2)


/*
 * insert "item" into the from of the queue pointed to by "head"
 *
 * this routines a.k.a. INSQUE() (see util.h)
 */
void
my_insque(struct q *head, struct q *item)
{
	item->q_next = head->q_head;
	item->q_prev = NULL;
	head->q_head = item;
	if (item->q_next != NULL) {
		item->q_next->q_prev = item;
	}
	if (head->q_tail == NULL) {
		head->q_tail = item;
	}
}


void
my_remque(struct q *head, struct q *item)
{
	if (item->q_prev != NULL) {
		item->q_prev->q_next = item->q_next;
	} else {
		head->q_head = item->q_next;
	}
	if (item->q_next != NULL) {
		item->q_next->q_prev = item->q_prev;
	} else {
		head->q_tail = item->q_prev;
	}
	item->q_next = item->q_prev = NULL;
}


void
makeargv(int *argc, char **argv, char *buf)
{
	char	*s;
	bool_t	getit = TRUE;
	bool_t	setnull = FALSE;


	*argc = 0;

	for (s = buf; *s != NULLC; s++) {
		if (setnull) {
			s[-1] = NULL;
			setnull = FALSE;
		}
		if (*s == '\n') {
			*s = NULLC;
		}
		if (!isspace(*s) && getit) {
			*argv++ = s;
			(*argc)++;
			getit = FALSE;
		} else if (isspace(*s)) {
			getit = TRUE;
			setnull = TRUE;
		}
		if (*argc > MAXARGC) {
			break;
		}
	}
}


/*
 * Allocate and free from the minor number space.
 * We keep a bitmap, with each bit representing a minor number,
 * there are 18 bits of minor number.  This means we dedicate
 * 32k to this array.  Not bad, really.
 *
 * Bits are initialized ON.  Minor number 0 is reserved as it is
 * the control device for the vol driver.
 *
 * Bit manipulation code stolen from the select(2) stuff.
 */
static void
minor_init()
{
	(void) memset(&mnr_map, 0xff, sizeof (mnr_map));
	/* minor 0 is reserved */
	MNR_CLR(0, &mnr_map);
	minor_initted = 1;
}


dev_t
minor_alloc(vol_t *v)
{
	int	size = MNRHOWMANY(MNR_SETSIZE, NMNRBITS);
	int	i;
	uint_t	mnr;
	struct mnr_track *mt;
	extern major_t vol_major;


	if (!minor_initted) {
		minor_init();
	}

	for (i = 0; i < size; i++) {
		if ((mnr = ffs(mnr_map.mnr_bits[i])) != 0) {
			mnr--;
			mnr += i * NMNRBITS;
			MNR_CLR(mnr, &mnr_map);

			/* issue ioctl to create the minor nodes for vol unit */
			if (ioctl(vol_fd, VOLIOCCMINOR, mnr) < 0) {
				fatal(gettext("minor_alloc: "
				    "failed to create minor %d!\n"), mnr);
				/*NOTREACHED*/
			}

			mt = (struct mnr_track *)calloc(1,
				    sizeof (struct mnr_track));
			mt->mt_mnr = mnr;
			mt->mt_vol = v;
			INSQUE(mnr_q_hash[mnr % MNR_HASH_SIZE], mt);
#ifdef	DEBUG_MINOR
			debug(7, "minor_alloc: allocated minor# %d\n", mnr);
#endif
			return (makedev(vol_major, mnr));
		}
	}
	/* should this be a fatal? */
	debug(1, "minor_alloc: out of minor numbers!!\n");
	return (0);
}


static struct mnr_track *
minor_getmt(uint_t minr)
{
	struct mnr_track *mt;


	mt = HEAD(struct mnr_track, mnr_q_hash[minr % MNR_HASH_SIZE]);
#ifdef	DEBUG_MINOR
	debug(11, "minor_getmt: head of hash queue for minor=%u is %#x\n",
	    minr, (char *)mt);
#endif
	while (mt) {
#ifdef	DEBUG_MINOR
		debug(11, "minor_getmt: comparing minr=%u with mt_mnr=%u\n",
		    minr, mt->mt_mnr);
#endif
		if (mt->mt_mnr == minr) {
			return (mt);
		}
		mt = NEXT(struct mnr_track, mt);
	}
	return (NULL);
}


void
minor_free(minor_t minr)
{
	struct mnr_track *mt;


#ifdef	DEBUG
	debug(7, "minor_free: freeing minor# %d\n", minr);
#endif
	if (!minor_initted) {
		minor_init();
	}

	if (minr == 0) {
		fatal(gettext("minor_free: tried to free minor_t 0!\n"));
		/*NOTREACHED*/
	}

	/* issue ioctl to remove the minor nodes for vol unit */
	if (ioctl(vol_fd, VOLIOCRMINOR, minr) < 0) {
		fatal(gettext("minor_free: failed to release minor %d!\n"),
		    minr);
		/*NOTREACHED*/
	}
	mt = minor_getmt((uint_t)minr);
	REMQUE(mnr_q_hash[(uint_t)minr % MNR_HASH_SIZE], mt);
	free(mt);
	MNR_SET(minr, &mnr_map);
}


/*
 * Leave the minor number allocated, but null out the pointer to
 * to vol.  This will give us the ability to garbage collect the
 * minor numbers at some point.
 *
 * Probably want to create a special list to hang these guys off of
 * to make collecting them easier.
 */
void
minor_clrvol(minor_t mnr)
{
	struct mnr_track *mt;


	if ((mt = minor_getmt((uint_t)mnr)) != NULL) {
		mt->mt_vol = NULL;
	}

	debug(7, "minor_clrvol: cleared vol mapping for minor# %d\n", mnr);
}


/*
 * garbage collect the minor numbers that are still hanging around.
 * wander through the list of mt's and see which minor numbers no
 * longer have volumes associated with them.  if they don't have
 * any volume, try to unmap them.  If it succeeds, go ahead and
 * free up the minor number.
 *
 * XXX: not currently used
 */
void
minor_gc()
{
	/* we should probably do something ... */
	debug(3, "minor_gc: not actually collecting any garbage\n");
}


/*
 * Return the vol structure that a minor number maps.  used for
 * taking messages from the driver and figuring out what volume
 * they refer to.
 */
vol_t *
minor_getvol(minor_t mnr)
{
	struct mnr_track *mt;

	if ((mt = minor_getmt((uint_t)mnr)) != NULL) {
		return (mt->mt_vol);
	}
	debug(5, "minor_getvol: no mapping for %d\n", mnr);
	return (NULL);
}

void
minor_chgvol(minor_t mnr, vol_t *v)
{
	struct mnr_track *mt;

	if ((mt = minor_getmt((uint_t)mnr)) == NULL) {
		debug(5, "minor_getvol: no mapping for %d\n", mnr);
		return;
	}
	mt->mt_vol = v;
}

static int
isbadchar(int c)
{
	int	ret_val = 0;			/* default is 'char is ok' */


	switch (c) {
	case '/':
	case ';':
	case '|':
		ret_val = 1;
		break;
	default:
		if (iscntrl(c) || isspace(c)) {
			ret_val = 1;
		}
	}

	return (ret_val);
}


char *
makename(char *name, size_t len)
{
	char	buf[MAXNAMELEN+1];
	char	*s = buf;
	int	i;


#ifdef	DEBUG
	debug(11, "makename: scanning \"%s\" (max len %d)\n", name, len);
#endif
	if (len > MAXNAMELEN) {
#ifdef	DEBUG
		debug(11, "makename: truncating name length to %d (was %d)\n",
		    MAXNAMELEN, len);
#endif
		len = MAXNAMELEN;
	}

	for (i = 0; i < len; i++) {
		if (name[i] == NULLC) {
			break;			/* we've reached the end */
		}
		if (isgraph((int)name[i])) {
			if (isupper((int)name[i])) {
				*s++ = tolower((int)name[i]);
			} else if (isbadchar((int)name[i])) {
#ifdef	DEBUG
				debug(5, "makename: '%c' (0%o) -> '_'\n",
				    name[i]);
#endif
				*s++ = '_';
			} else {
				*s++ = name[i];
			}
		}
	}
	*s = NULLC;				/* null terminate */
	s = strdup(buf);
#ifdef	DEBUG
	debug(11, "makename: returning \"%s\" (len %d)\n", s, strlen(s));
#endif
	return (s);
}



#ifdef	VOLD_HANDLES_TAPE
/*
 * These are various bits that we use in the minor number to
 * differentiate between different types of devices.  They should
 * NEVER be used by anyone but this volmakedev function, because
 * they are subject to change in the future.
 */
#define	MINOR_TAPE	0x20000	/* device is a tape */
#define	MINOR_PART	0x1c000	/* partition number for disk */
#define	MINOR_PARTSHFT	14	/* bits to shift */
#define	MINOR_SVR4	0x10000	/* an svr4 style tape device */
#define	MINOR_REWIND	0x08000	/* a rewind tape device */
#define	MINOR_MAX	0x03fff	/* biggest minor supported */


/*
 * if part >= 0, create the dev_t for that partition.  If it's -1,
 * return the lowest dev_t that will match this volume;
 */
dev_t
volmakedev(vol_t *v, uint_t arg)
{
	static major_t	vol_major = -1;
	minor_t		m;
	int		i;

	if (vol_major == -1) {
		struct stat sb;
		(void) fstat(vol_fd, &sb);
		vol_major = major(sb.st_rdev);
	}

	/* make sure he's got an id */
	if (v->v_id == 0) {
		v->v_id = volumeid_get();
	} else {
		volumeid_register(v->v_id);
	}

	m = v->v_id;

	/* XXX better error recovery! */
	if (m > MINOR_MAX) {
		fatal(gettext("volmakedev: can't have an id that big!"));
	}

	/* set up the bits in the minor number for tape, etc. */
	if (v->v_flags & V_TAPE) {
		/* we are a tape */
		m |= MINOR_TAPE;
		if (arg != -1) {
			if (arg & V_REWIND) {
				m |= MINOR_REWIND;
			}
			if (arg & V_SVR4) {
				m |= MINOR_SVR4;
			}
		}
	} else {
		/* we are a disk */
		if (v->v_nparts != 0) {
			if (arg == -1) {
				/* find the lowest partition number */
				for (i = 0; i < V_NUMPAR; i++) {
					if (v->v_parts & (1<<i)) {
						arg = i;
						break;
					}
				}
			}
			m |= arg<<MINOR_PARTSHFT;
		}
	}
	return (makedev(vol_major, m));
}


uint_t
volcheckdev(dev_t dev)
{
	uint_t	retval = 0;
	uint_t 	part;


	if (dev & MINOR_TAPE) {
		retval |= V_TAPE;
		if (dev & MINOR_SVR4) {
			retval |= V_SVR4;
		}
		if (dev & MINOR_REWIND) {
			retval |= V_REWIND;
		}
		return (retval);
	}
	/* we are a disk */
	if ((part = (dev & MINOR_PART)) != 0) {
		/* is this ok w/o V_PARTSHIFT ?? */
		retval = part >> MINOR_PARTSHFT;
	}
	return (retval);
}


/*
 * take a minor number and return what the volume id must have been.
 */

uint_t
volid(uint_t devmin)
{
	return (devmin&MINOR_MAX);
}

#endif	/* VOLD_HANDLES_TAPE */


/*
 * Return a props string that represents the vol_t.
 *
 * This function might be expensive, but I don't think we'll call it
 * often.  A more efficient way to do this would be to build the
 * prop string by hand, just once, rather than calling prop_attr_put.
 */
char *
props_get(vol_t *v)
{
	char 		*ps = NULL;
	char 		*s;
	char		tmpstr[VOLD_PROPBUFLEN];
	char		partstr[VOLD_PROPBUFLEN];
	ulong_t		parts;
	uint_t		i;
	struct vnwrap	*vw;
	char		*path;
	char		**vopp;



	/* flags */

	ps = prop_attr_put(ps, PROP_ACC,
	    (v->v_flags & V_TAPE) ? PROP_ACC_TAPE : PROP_ACC_DISK);

	ps = prop_attr_put(ps, PROP_DIST,
	    (v->v_flags & V_NETWIDE) ? PROP_DIST_GLOB : PROP_DIST_LOC);

	if (v->v_flags & V_RMONEJECT) {
		ps = prop_attr_put(ps, PROP_RMONEJECT, PROP_TRUE);
	}

	if (v->v_flags & V_TAPE) {
		if (v->v_flags & V_DENS_L) {
			ps = prop_attr_put(ps, PROP_DENS, PROP_DENS_L);
		}
		if (v->v_flags & V_DENS_M) {
			ps = prop_attr_put(ps, PROP_DENS, PROP_DENS_M);
		}
		if (v->v_flags & V_DENS_H) {
			ps = prop_attr_put(ps, PROP_DENS, PROP_DENS_H);
		}
		if (v->v_flags & V_DENS_U) {
			ps = prop_attr_put(ps, PROP_DENS, PROP_DENS_U);
		}
	} else { /* we are a disk, do we have partitions? */
		if ((parts = v->v_parts) != 0L) {
			partstr[0] = NULLC;
			for (i = 0; i < V_NUMPAR; i++) {
				if (1<<i & parts) {
					(void) sprintf(tmpstr, "%d", i);
					(void) strcat(partstr, tmpstr);
					(void) strcat(partstr, ",");
				}
			}
			/* gets rid of that last comma */
			partstr[strlen(partstr)-1] = NULLC;
			ps = prop_attr_put(ps, PROP_PART, partstr);
		}
	}

	if (v->v_flags & V_ENXIO) {
		ps = prop_attr_put(ps, PROP_ENXIO, PROP_TRUE);
	}

	if (v->v_flags & V_MEJECTABLE) {
		ps = prop_attr_put(ps, PROP_MEJECTABLE, PROP_TRUE);
	}

	vopp = &(v->v_obj.o_props); /* get ptr to vol obj props */

	/* see if location is in the vol obj prop field */
	path = prop_attr_get(*vopp, PROP_LOCATION);

	/* is the volume in but the location isn't ?? */
	if (v->v_confirmed && (path == NULL)) {
		/* add in the location property */
		vw = node_findnode(v->v_obj.o_id, FN_ANY, FN_ANY, FN_ANY);
		path = path_make(vw->vw_node);
		node_findnode_free(vw);
		ps = prop_attr_put(ps, PROP_LOCATION, path);
	} else if (!v->v_confirmed && (path != NULL)) {
		/* the loc's there but the vol isn't -- remove loc */
		*vopp = prop_attr_del(*vopp, PROP_LOCATION);
	}

	if (path != NULL) {
		free(path);	/* free result gotten earlier */
	}

	/*
	 * Stick the other properties on the tail.
	 */
	if (v->v_obj.o_props != NULL) {
		s = (char *)malloc(strlen(ps) + strlen(v->v_obj.o_props) + 1);
		(void) strcpy(s, ps);
		(void) strcat(s, v->v_obj.o_props);
		free(ps);
		ps = s;
	}

	return (ps);
}


/*
 * given a volume, check to see if the driver needs to be notified that
 * the V_ENXIO flag has been set
 *
 * this used to be done at "unmap" time, but that was sometimes too late
 */
static void
check_for_enxio(vol_t *v)
{
	int			i;
	struct vioc_flags	vfl;
	minor_t			volume;


	for (i = 0; i < (int)v->v_ndev; i++) {

		volume = minor(v->v_devmap[i].dm_voldev);

		/*
		 * if someone set the enxio flag, we'll tell the driver
		 * about it now
		 */
		if (v->v_flags & V_ENXIO) {

			vfl.vfl_unit = volume;
			vfl.vfl_flags = VFL_ENXIO;
#ifdef	DEBUG
			debug(1,
		"check_for_enxio: calling VOLIOCFLAGS(VFL_ENXIO), unit %d\n",
			    volume);
#endif
			if (ioctl(vol_fd, VOLIOCFLAGS, &vfl) < 0) {
				debug(1,
			"check_for_enxio: VOLIOCFLAGS (%d) of \"%s\"; %m\n",
				    vol_fd, v->v_obj.o_name);
			}
		}
	}
}


/*
 * take the props out of the string and stick them into the vol
 */
void
props_set(vol_t *v, char *props)
{
	char	*val;
	char	*ps = strdup(props);


	v->v_flags = 0;

	if ((val = prop_attr_get(ps, PROP_ACC)) != NULL) {
		if (strcmp(val, PROP_ACC_TAPE) == 0) {
			v->v_flags |= V_TAPE;
		}
		free(val);
		ps = prop_attr_del(ps, PROP_ACC);
	}

	if ((val = prop_attr_get(ps, PROP_DIST)) != NULL) {
		if (strcmp(val, PROP_DIST_GLOB) == 0) {
			v->v_flags |= V_NETWIDE;
		}
		free(val);
		ps = prop_attr_del(ps, PROP_DIST);
	}

	if ((val = prop_attr_get(ps, PROP_ENXIO)) != NULL) {

		v->v_flags |= V_ENXIO;
		free(val);
		ps = prop_attr_del(ps, PROP_ENXIO);

		/*
		 * acutally tell the driver about the enxio stuff *now*
		 * (if needed)
		 */
		check_for_enxio(v);
	}

	if ((val = prop_attr_get(ps, PROP_DENS)) != NULL) {
		if (strcmp(val, PROP_DENS_L) == 0) {
			/*LINTED: null effect is ok*/
			v->v_flags |= V_DENS_L;
		}
		if (strcmp(val, PROP_DENS_M) == 0) {
			v->v_flags |= V_DENS_M;
		}
		if (strcmp(val, PROP_DENS_H) == 0) {
			v->v_flags |= V_DENS_H;
		}
		if (strcmp(val, PROP_DENS_U) == 0) {
			v->v_flags |= V_DENS_U;
		}
		free(val);
		ps = prop_attr_del(ps, PROP_DENS);
	}

	if ((val = prop_attr_get(ps, PROP_PART)) != NULL) {
		v->v_parts = part_to_bits(val, &(v->v_ndev));
		free(val);
		ps = prop_attr_del(ps, PROP_PART);
	}

	if ((val = prop_attr_get(ps, PROP_RMONEJECT)) != NULL) {
		v->v_flags |= V_RMONEJECT;
		free(val);
		ps = prop_attr_del(ps, PROP_RMONEJECT);
	}

	/*
	 * Save off any props that weren't slurped up into flags
	 */
	if (v->v_obj.o_props != NULL) {
		free(v->v_obj.o_props);
	}
	v->v_obj.o_props = ps;
}


/*
 * This function checks three things:
 *	1) permission to write attributes
 *		(user == owner, root, owner == nobody)
 *	2) no funky characters to screw us in attr or value
 *		in particular ";" and "="
 *	3) if it's a "system" parameter (starts with s-), make
 *		sure it's a writeable one (owner_props).
 */
bool_t
props_check(vol_t *v, struct ve_attr *vea)
{
	char	**s, *p;
	char	*attr = vea->viea_attr, *val = vea->viea_value;


	/* only the owner can change any attributes */
	if ((vea->viea_uid != v->v_obj.o_uid) &&
	    (v->v_obj.o_uid != default_uid) &&
	    (v->v_obj.o_uid != 0)) {
		return (FALSE);
	}

	/* check for "correctness"... does he use; anywhere? */
	for (p = val; *p; p++) {
		if ((*p == ';') || (*p == '=')) {
			debug(1, "props: bad character in value (%s)\n", val);
			return (FALSE);
		}
	}
	for (p = attr; *p; p++) {
		if ((*p == ';') || (*p == '=')) {
			debug(1, "props: bad character in attribute (%s)\n",
				attr);
			return (FALSE);
		}
	}
	/* If it's a "system" prop, make sure it's settable */
	if ((attr[0] == 's') && (attr[1] == '-')) {
		for (s = owner_props; **s; s++) {
			if (strcmp(*s, vea->viea_attr) == 0) {
				return (TRUE);
			}
		}
		return (FALSE);
	}

	return (TRUE);
}


void
props_merge(vol_t *v, vol_t *v1)
{
	char	*merged;

	merged = prop_attr_merge(props_get(v), props_get(v1));
	props_set(v, merged);
}


/*
 * Take a string like "0, 2, 7" and return a bit mask that
 * has these bits turned on.  Converts from a partition
 * value string from the nis+ database into our local way of
 * keeping track of partitions.
 */
static uint_t
part_to_bits(char *val, uchar_t *npart)
{
	uint_t 	parts = 0;
	char	*p, *q;


	q = val;
	*npart = 0;

	for (;;) {
		p = strchr(q, ',');
		if (p != NULL) {
			*p = NULLC;
			parts |= (1<<atoi(q));
			(*npart)++;
			q = p+1;
		} else {
			parts |= (1<<atoi(q));
			(*npart)++;
			break;
		}
	}
	return (parts);
}


char *
location_newdev(char *ls, char *path)
{
	extern char self[];
	char	*nls;


	nls = prop_attr_put(ls, self, path);
	return (nls);
}


dev_t
location_localdev(char *ls)
{
	char		*val;
	extern char 	self[];
	struct stat	sb;
	dev_t		res = (dev_t)NODEV;


	if ((val = prop_attr_get(ls, self)) != NULL) {
		if (stat(val, &sb) == 0) {
			res = sb.st_rdev;
		}
	}

	if (val != NULL) {
		free(val);
	}
	return (res);
}


#ifdef	VOLMGT_DEV_TO_TTY_WORKED

/*
 * This slop is stolen from the ttyname function in the C library.
 * ttyname didn't do what I wanted.
 *
 * called (if working) by action_buildenv()
 */
char *
devtotty(dev_t dev)
{
	static int	srch_dir(entry_t, int, entry_t *, dev_t);
	static entry_t	*get_pri_dirs(void);
	struct stat	tfsb;
	entry_t		*srch_dirs;	/* priority directories */
	int		found = 0;
	int		dirno = 0;
	int		is_console = 0;


	/*
	 * search the priority directories
	 */
	srch_dirs = get_pri_dirs();

	/*
	 * match /dev/console first before searching other directories
	 */
	if (stat(CONSOLE, &tfsb) == 0) {
		if (tfsb.st_rdev == dev) {
			is_console = 1;
			found = 1;
		}
	}

	while ((!found) && (srch_dirs[dirno].name != NULL)) {

		/*
		 * if /dev is one of the priority directories, only
		 * search its top level (set depth = MAX_SEARCH_DEPTH)
		 */
		found = srch_dir(srch_dirs[dirno],
		    ((strcmp(srch_dirs[dirno].name, dev_dir.name) ==
		    0) ? MAX_SRCH_DEPTH : 1), 0, dev);
		dirno++;
	}

	/*
	 * search the /dev/ directory, skipping priority directories
	 */
	if (!found) {
		found = srch_dir(dev_dir, 0, srch_dirs, dev);
	}

	if (dir_buf != NULL) {
		free(dir_buf);
		dir_buf = NULL;
	}
	if (dir_vec != NULL) {
		free(dir_vec);
		dir_vec = NULL;
	}

	/*
	 * return
	 */
	if (found) {
		if (is_console) {
			return (CONSOLE);
		} else {
			return (rbuf);
		}
	} else {
		return (NULL);
	}
}


/*
 * srch_dir() searches directory path and all directories under it up
 * to depth directories deep for a file described by a stat structure
 * fsb.  It puts the answer into rbuf.  If a match is found on device
 * number only, the file name is put into dev_rbuf and dev_flag is set.
 *
 * srch_dir() returns 1 if a match (on device and inode) is found,
 * or 0 otherwise.
 *
 * called by devtotty()
 */
static int
srch_dir(
	entry_t path,			/* current path */
	int depth,			/* current depth (/dev = 0) */
	entry_t skip_dirs[],		/* dirs not needing searching */
	dev_t dev)
{
	DIR		*dirp;
	struct dirent	*direntp;
	struct stat	tsb;
	char		file_name[MAX_DEV_PATH];
	entry_t		file;
	char		*last_comp;
	int		found = 0;
	int		dirno = 0;
	int		path_len;


	file.name = file_name;
	file.flags = path.flags;
	if (rbuf == NULL) {
		if ((rbuf = (char *)malloc(2 * MAX_DEV_PATH)) == NULL) {
			return (0);
		}
	}

	/*
	 * do we need to search this directory? (always search /dev at depth 0)
	 */
	if ((skip_dirs != NULL) && (depth != 0)) {
		while (skip_dirs[dirno].name != NULL) {
			if (strcmp(skip_dirs[dirno++].name, path.name) == 0) {
				return (0);
			}
		}
	}

	/*
	 * open directory
	 */
	if ((dirp = opendir(path.name)) == NULL) {
		return (0);
	}

	/*
	 * skip two first entries ('.' and '..')
	 */
	if (((direntp = readdir(dirp)) == NULL) ||
	    ((direntp = readdir(dirp)) == NULL)) {
		(void) closedir(dirp);
		return (0);
	}

	path_len = strlen(path.name);
	(void) strcpy(file_name, path.name);
	last_comp = file_name + path_len;
	*last_comp++ = '/';

	/*
	 * read thru the directory
	 */
	while (!found && ((direntp = readdir(dirp)) != NULL)) {

		/*
		 * if the file name (path + "/" + d_name + NULL) would be too
		 * long, skip it
		 */
		if ((unsigned)(path_len + strlen(direntp->d_name) + 2) >
		    MAX_DEV_PATH) {
			continue;
		}

		(void) strcpy(last_comp, direntp->d_name);

		if (stat(file_name, &tsb) < 0) {
			continue;
		}

		/*
		 * if a file is a directory and we are not too deep, recurse
		 */
		if (S_ISDIR(tsb.st_mode)) {
			if (depth < MAX_SRCH_DEPTH) {
				found = srch_dir(file, depth+1,
				    skip_dirs, dev);
			} else {
				continue;
			}
		/*
		 * else if it is not a directory, is it a character special
		 * file?
		 */
		} else if (S_ISCHR(tsb.st_mode)) {
			if (dev == tsb.st_dev) {
				(void) strcpy(rbuf, file.name);
				found = 1;
			}
		}
	}

	(void) closedir(dirp);
	return (found);
}


/*
 * get_pri_dirs() - returns a pointer to an array of strings, where each string
 * is a priority directory name.  The end of the array is marked by a NULL
 * pointer.  The priority directories' names are obtained from the file
 * /etc/ttysrch if it exists and is readable, or if not, a default hard-coded
 * list of directories.
 *
 * /etc/ttysrch, if used, is read in as a string of characters into memory and
 * then parsed into strings of priority directory names, omitting comments and
 * blank lines.
 *
 * called by devtotty()
 */
static entry_t *
get_pri_dirs()
{
	int fd, size, state;
	size_t sz;
	struct stat sb;
	register char *buf, *ebuf;
	register entry_t *vec;


	/*
	 * if no /etc/ttysrch, use defaults
	 */
	if (((fd = open(TTYSRCH, 0)) < 0) || (stat(TTYSRCH, &sb) < 0)) {
		return (def_srch_dirs);
	}
	sz = sb.st_size;
	if (((dir_buf = (char *)malloc(sz + 1)) == NULL) ||
	    ((size = read(fd, dir_buf, sz)) < 0)) {
		(void) close(fd);
		return (def_srch_dirs);
	}
	(void) close(fd);

	/*
	 * ensure newline termination for buffer.  Add an extra
	 * entry to dir_vec for null terminator
	 */
	ebuf = &dir_buf[size];
	*ebuf++ = '\n';
	for (sz = 1, buf = dir_buf; buf < ebuf; ++buf) {
		if (*buf == '\n') {
			++sz;
		}
	}
	if ((dir_vec = (entry_t *)malloc(sz * sizeof (*dir_vec))) == NULL) {
		return (def_srch_dirs);
	}

	state = START_STATE;
	for (buf = dir_buf, vec = dir_vec; buf < ebuf; ++buf) {
		switch (state) {

		case START_STATE:
			if (*buf == COMMENT_CHAR) {
				state = COMMENT_STATE;
				break;
			}
			/* skip leading white space */
			if (!isspace(*buf)) {
				state = DIRNAME_STATE;
				vec->name = buf;
				vec->flags = 0;
			}
			break;

		case COMMENT_STATE:
			if (*buf == EOLN_CHAR) {
				state = START_STATE;
			}
			break;

		case DIRNAME_STATE:
			if (*buf == EOLN_CHAR) {
				state = CHECK_STATE;
				*buf = NULLC;
			} else if (isspace(*buf)) {
				/* skip trailing white space */
				state = FLAG_STATE;
				*buf = NULLC;
			}
			break;

		case FLAG_STATE:
			switch (*buf) {
				case 'M':
					vec->flags |= MATCH_MM;
					break;
				case 'F':
					vec->flags |= MATCH_FS;
					break;
				case 'I':
					vec->flags |= MATCH_INO;
					break;
				case EOLN_CHAR:
					state = CHECK_STATE;
					break;
			}
			break;

		case CHECK_STATE:
			if (strncmp(vec->name, DEV, strlen(DEV)) != 0) {
				int	tfd = open("/dev/console", O_WRONLY);

				if (tfd >= 0) {
					char buf[256];
					(void) sprintf(buf, (char *)gettext(
			"ERROR: Entry '%s' in /etc/ttysrch ignored.\n"),
						vec->name);
					(void) write(tfd, buf, strlen(buf));
					(void) close(tfd);
				}
			} else {
				char *slash;

				slash = vec->name + strlen(vec->name) - 1;
				while (*slash == '/') {
					*slash-- = NULLC;
				}
				if (vec->flags == 0) {
					vec->flags = MATCH_ALL;
				}
				vec++;
			}
			state = START_STATE;
			/*
			 * This state does not consume a character, so
			 * reposition the pointer.
			 */
			buf--;
			break;

		}
	}
	vec->name = NULL;
	return ((entry_t *)dir_vec);
}

#endif	/* VOLMGT_DEV_TO_TTY_WORKED */



/*
 * Build a table that makes the crc calculation much faster.
 *
 * called by calc_crc()
 */
static ulong_t *
crcgentab()
{
	register int	b, i;
	ulong_t		v;
	ulong_t		poly = 0x04c11db7;
	static		ulong_t *crctab = NULL;


	if (crctab != NULL) {
		return (crctab);
	}

	crctab = (ulong_t *)malloc(256 * sizeof (ulong_t));

	for (b = 0; b < 256; b++) {
		for (v = b << (24), i = 0; i < 8; i++) {
			if (v & ((ulong_t)1 << 31)) {
				v = (v << 1) ^ poly;
			} else {
				v = v << 1;
			}
		}
		crctab[b] = v;
	}
	return (crctab);
}


/*
 * Calculate the CRC for a given record.
 */
ulong_t
calc_crc(uchar_t *buf, size_t len)
{
	ulong_t crc;
	ulong_t *crctab;


	crctab = crcgentab();

	crc = CRCMAGIC;
	while (len--) {
		crc = (crc << 8) ^ crctab[(crc>>(24)) ^ *buf++];
	}
	return (crc);
}


/*
 * Calculate the MD4 signature for a given buffer.
 */
void
calc_md4(uchar_t *buf, size_t len, u_longlong_t *sig)
{
	MD4_CTX		context;


	MD4Init(&context);
	MD4Update(&context, buf, len);
	MD4Final((uchar_t *)sig, &context);
}


/*
 * Generate a unique key, checking the database to make sure the
 * triple <medtype, labtype, 0x%x> does not exist.  This assumes
 * the label_key function generates the key into a string as
 * a standard hex number.
 *
 * Note that the label functions do not have to use this to generate
 * a unique key, they can use the db_testkey function directly to
 * perform check for unique key.
 */
ulong_t
unique_key(char *medtype, char *labtype)
{
	static bool_t	initialized = FALSE;
	struct timeval	tv;
	ulong_t		key;
	char		keyname[HEXNUM_SIZE+1];
	int		loopcnt = 0;


	if (!initialized) {
		(void) gettimeofday(&tv, NULL);
		/*
		 * We use the time in seconds and usecs as the
		 * seed.  The "most interesting" bits of the
		 * tv_usec are 4 - 19, so we just shift over
		 * some and pass that time seed48.
		 */
		tv.tv_usec <<= 12;
		(void) seed48((ushort_t *)&tv);
		initialized = TRUE;
	}

	for (;;) {
		key = (ulong_t)mrand48();
		(void) sprintf(keyname, "0x%lx", key);
		if (db_testkey(medtype, labtype, keyname) == FALSE) {
			return (key);
		}
		/*
		 * If we try more than 10 random numbers, we just
		 * give up... something is very wrong.  Hopefully we
		 * will not be hosing things too badly.
		 */
		if (loopcnt++ > 10) {
			debug(1, "unique_key: bad key 0x%x for (%s,%s,%s)\n",
				key, medtype, labtype, keyname);
			return (key);
		}
	}
	/*NOTREACHED*/
}


/*
 * return a "unique" time value
 *
 * this is done by taking the current time, then decrementing by a random
 * number which we ensure is less than the current time value, thus ensuring
 * that the resulting "unique" time value is positive
 *
 * we ensure that the random subtactor is less than the current time value
 * by dividing it in half until it is
 */
time_t
unique_time(char *medtype, char *labtype)
{
	char		keyname[HEXNUM_SIZE+1];	/* temp hex num. storage */
	int		loopcnt = 0;
	time_t		tloc;			/* time value */
	ulong_t		rval;			/* random value */
	const int	loopmax = 10;		/* max # loops to do */
	static bool_t	initialized = FALSE;
	struct timeval	tv;


	if (!initialized) {
		(void) gettimeofday(&tv, NULL);
		/*
		 * we use the time in seconds and usecs as the seed
		 *
		 * the "most interesting" bits of the tv_usec are 4 - 19,
		 * so we just shift over some and pass that time seed48
		 */
		tv.tv_usec <<= 12;
		(void) seed48((ushort_t *)&tv);
		initialized = TRUE;
	}

	/* start with current time for our "random time" value */
	(void) time(&tloc);

	/*
	 * "uniqeify" the time by changing tloc to be between 0 and the
	 * "real" time using a pseudo-random number
	 *
	 * ensure that the pseudo-random subtractor is less than tloc by
	 * halving it until its cooperative
	 */
	rval = (ulong_t)mrand48();
	while ((time_t)rval >= tloc) {
		rval >>= 1;
	}

	/*
	 * decrement tloc by the "random" key value, after which tloc
	 * is "uniquified"
	 */
	tloc -= (time_t)rval;

	/*
	 * look until we either find a unique (database-wise) key or we
	 * decide to give up trying
	 */
	while (tloc > (time_t)0) {

		/* create an ascii version of our "key" */
		(void) sprintf(keyname, "0x%lx", tloc);

		/* see if the key already exists */
		if (db_testkey(medtype, labtype, keyname) == FALSE) {
			break;			/* success */
		}

		/*
		 * if we try more than loopmax times we just give up since
		 * something is very wrong
		 */
		if (++loopcnt > loopmax) {
			debug(1,
			    "unique_time: bad time 0x%x for (%s,%s,%s)\n",
			    tloc, medtype, labtype, keyname);
			tloc = (time_t)0;	/* to signal an error */
			break;			/* failure */
		}

		tloc--;		/* since time moves forward we go backward */
	}

#ifdef	DEBUG_DB
	debug(6, "unique_time: returning %#lx\n", tloc);
#endif
	return (tloc);
}


#ifdef	DEBUG_VTOC

static char
*ver_to_str(ulong_t ver)
{
	/*
	 * return an evaluation of the version number
	 */
	static char		ret_str[80];


	switch (ver) {
	case 0:
		(void) strcpy(ret_str, "OLD");
		break;
	case V_VERSION:
		(void) strcpy(ret_str, "ok");
		break;
	default:
		(void) strcpy(ret_str, "AFU");
		break;
	}
	return (ret_str);
}


static void
print_vtoc(char *tag, int odl, int part_cnt, uint_t maxoff, struct vtoc *vtoc)
{
	/*
	 * print the vtoc info
	 */
	extern int	debug_level;
	char		vol_name_buf[LEN_DKL_VVOL+1];
	ushort_t	i;



	if (debug_level < odl) {
		return;
	}

	debug(odl, "%s (%u bytes) (max offset %u):\n", tag,
	    sizeof (struct vtoc), maxoff);

	debug(odl, " v_sanity:     0x%X (%s)\n",
	    vtoc->v_sanity, vtoc->v_sanity == VTOC_SANE ? "ok" : "AFU");

	debug(odl, " v_version:    %u (%s)\n",
	    vtoc->v_version, ver_to_str(vtoc->v_version));

	(void) strcpy(vol_name_buf, vtoc->v_volume);
	vol_name_buf[LEN_DKL_VVOL] = NULLC;
	debug(odl, " v_volume:     \"%s\"\n", vol_name_buf);

	debug(odl, " v_sectorsz:   %u\n", vtoc->v_sectorsz);

	debug(odl, " v_nparts:     %u (of %u, %u bytes each), %d used:\n",
	    vtoc->v_nparts, V_NUMPAR, sizeof (struct partition), part_cnt);

	if (part_cnt > 0) {

		debug(odl, "  v_part  p_tag p_flag  p_start  p_size\n");
		for (i = 0; i < V_NUMPAR; i++) {
			if (vtoc->v_part[i].p_size != 0) {
				debug(odl,
				    "   %2d      %02d     %2d     %7d %7d\n",
				    i, vtoc->v_part[i].p_tag,
				    vtoc->v_part[i].p_flag,
				    vtoc->v_part[i].p_start,
				    vtoc->v_part[i].p_size);
			}
		}
	}
}

#endif	/* DEBUG_VTOC */


/*
 * Take a vtoc and return a pmask and npart that represents the
 * valid partitions.
 * maxoff is the maximum block offset that is valid for this media.
 *   In some cases it will be 0xffffffff, where there is no way to tell.
 *   In other cases (like the cdrom), it will be consistent for the media.
 *   The reason for this is that some people put junky labels on devices
 *   (like cdrom) and we need to be able to differentiate between a
 *   bogus partition and a good one.
 * We also detect duplicate partitions, and remove the duplication.  There
 *   is no point in making available the duplicate, so we don't.
 * There is also code to detect for a canonical floppy partition.
 *   It is really stupid to put a Sun label (for example) on a floppy,
 *   but we do.  We don't support the notion of partitions on a floppy,
 *   we just always return the "c" partition.
 *
 * NOTE: this routine handles up to 32 partitions.  The original routine
 *	(partition_conv) only handled up to eight.  It is included, after
 *	this routine, for compatibility
 */
void
partition_conv_2(struct vtoc *v, uint_t maxoff, ulong_t *pmask, uchar_t *npart)
{
	int		i;
	int		j;
#ifdef	DEBUG_VTOC
	const int	odl = 5;		/* output debug level */
#endif


	*npart = 0;
	*pmask = 0;

	if (v->v_sanity != VTOC_SANE) {
		debug(1, "partition_conv_2: insane vtoc found\n");
		return;
	}

	for (i = 0; i < V_NUMPAR; i++) {
		if ((v->v_part[i].p_size > 0) &&
		    ((v->v_part[i].p_start + v->v_part[i].p_size - 1) <=
		    maxoff)) {
#ifdef	DEBUG_VTOC
			debug(odl, "partition_conv_2: adding in part %d\n",
			    i);
#endif
			*pmask |= (1<<i);
			(*npart)++;
		}
	}

#ifdef	DEBUG_VTOC
	print_vtoc("partition_conv_2: entering with vtoc", odl,
	    (int)*npart, maxoff, v);
#endif
	if (*npart == 0) {
		/*
		 * No valid partitions?!?!  It must be that stupid
		 * answerbook CD.  Those guys should be shot.
		 * If the default base partition is valid,
		 * we'll just use that one.
		 */
		if ((v->v_part[DEFAULT_PARTITION].p_size > 0) &&
		    (v->v_part[DEFAULT_PARTITION].p_start == 0)) {
#ifdef	DEBUG_VTOC
			debug(odl, "partition_conv_2: no parts -> 1 part\n");
#endif
			*pmask |= (1<<DEFAULT_PARTITION);
			*npart = 1;
		}
	}

	/*
	 * Remove duplicates.  The canonical cd-rom label is captured
	 * here, since the driver returns the A and C partitions
	 * as the same (on sparc, at least).
	 */
	for (i = 0; i < V_NUMPAR-1; i++) {
		if ((*pmask & (1 << i)) == 0) {
			continue;
		}
		for (j = i+1; j < V_NUMPAR; j++) {
			if ((v->v_part[i].p_size == v->v_part[j].p_size) &&
			    (v->v_part[i].p_start == v->v_part[j].p_start)) {
#ifdef	DEBUG_VTOC
				debug(odl,
				    "partition_conv_2: part %d == part %d\n",
				    i, j);
#endif
				*pmask &= ~(1<<j);
				(*npart)--;
			}
		}
	}

	/* check for canonical floppy partition. */
	/*
	 * A bit of a hack, yes, but do you want it to do the
	 * right thing, or do you want it elegant...
	 */
	if ((*npart == 3) &&
	    (v->v_part[0].p_size == 2844) &&
	    (v->v_part[0].p_start == 0) &&
	    (v->v_part[1].p_size == 36) &&
	    (v->v_part[1].p_start == 2844) &&
	    (v->v_part[2].p_size == 2880) &&
	    (v->v_part[2].p_start == 0)) {
#ifdef	DEBUG_VTOC
		debug(odl, "partition_conv_2: 3 parts -> 1\n");
#endif
		*pmask = (1<<2);	/* ds/dd floppies */
		*npart = 1;
	}
	if ((*npart == 3) &&
	    (v->v_part[0].p_size == 1422) &&
	    (v->v_part[0].p_start == 0) &&
	    (v->v_part[1].p_size == 18) &&
	    (v->v_part[1].p_start == 1422) &&
	    (v->v_part[2].p_size == 1440) &&
	    (v->v_part[2].p_start == 0)) {
#ifdef	DEBUG_VTOC
		debug(odl, "partition_conv_2: 3 parts -> 1\n");
#endif
		*pmask = (1<<2);	/* ds/md floppies */
		*npart = 1;
	}

#ifdef	DEBUG_VTOC
	debug(5, "partition_conv_2: returning %d part(s), mask=0x%X\n",
	    *npart, *pmask);
#endif
}


/*
 * Take a vtoc and return the first partition that maps the lowest
 * sector,  while still mapping something.
 *
 * Return -1 if none found.
 */
int
partition_low(struct vtoc *v)
{
	int		i;		/* index */
	int		lowi = -1;	/* gets lowest slice number */
	unsigned long	lowst = ~0UL;	/* start of lowest partition */



	if (v->v_sanity != VTOC_SANE) {
		return (-1);
	}

	/*
	 * algorithm: scan the partition table.  If we have
	 * a partition of a positive size, we look at the
	 * starting address.  If it's zero, that's great,
	 * just return it.  If it's nonzero, remember it so
	 * we can return the lowest possible number if
	 * necessary.
	 * We return -1 if there are no partitions with a size,
	 * but this is an error in the vtoc, really.
	 */
	for (i = 0; i < V_NUMPAR; i++) {
		if (v->v_part[i].p_size != 0) {
			if (v->v_part[i].p_start == 0) {
				return (i);
			}
			if (lowst > v->v_part[i].p_start) {
				lowi = i;
				lowst = v->v_part[i].p_start;
			}
		}
	}
	return (lowi);
}


/*
 * implements the "nobody" semantic, in addition to fooling around
 * with the dumb nis+ network names.
 *
 * I do assume that DEFAULT_USER is the same (probably "nobody") in
 * all domains, so I don't bother checking other domains for the
 * user DEFAULT_USER or the group DEFAULT_GROUP.  Seems like
 * an efficient thing to do, but it may not be right in all
 * (any?) cases.
 *
 * At one time, I was using the nis_local_principal() to represent
 * root.  I decided that this was a bug, because things owned/created
 * as root on one machine would appear as owned by "nobody" on
 * other machines.  This was not the desired semantic (by me),
 * so I decided to make all roots the same on the network.
 */

/*
 * Return a (malloced) char * that is a valid "network" user
 * name, as defined by nis+.  So, given for the uid for the
 * "bar" user, this function will return: "bar.foo.you.sun.com.",
 * if "foo.you.sun.com." is your domain name.
 */
char *
network_username(uid_t uid)
{
	struct passwd 	*pw;
	char		*uname;


	pw = getpwuid(uid);
	if ((pw != NULL) && (strcmp(pw->pw_name, DEFAULT_USER) != 0)) {
#ifdef notdef
		if (uid == 0) {	/* root! */
			/* assume we always run as root */
			uname = strdup(nis_local_principal());
		} else {
#endif
			/* +2 == "." plus null */
			uname = (void *)malloc(strlen(pw->pw_name)+
			    strlen(nis_local_directory())+2);
			(void) strcpy(uname, pw->pw_name);
			(void) strcat(uname, ".");
			(void) strcat(uname, nis_local_directory());
#ifdef notdef
		}
#endif
	} else {
		/* +2 == "." plus null */
		uname = strdup(DEFAULT_USER);
	}
	return (uname);
}


/*
 * Take apart a name like: "bar.foo.you.sun.com." and return the
 * local uid for that user in that domain.  Also just works for
 * "bar".
 * XXX: Note that the remote domain case is currently unimplemented.
 * XXX: Also note that we don't search the remote domain for anyone
 * XXX: named DEFAULT_USER.  This is considered a feature.
 */
uid_t
network_uid(char *uname)
{
	struct passwd	*pw;
	char		*dirn = NULL;
	uid_t		uid;


	if (strcmp(uname, nis_local_principal()) == 0) {
		uname = "root"; /* XXX: this is not quite right */
	} else if ((dirn = strchr(uname, '.')) != NULL) {
		*dirn++ = NULLC;
		if ((nis_dir_cmp(nis_local_directory(), dirn) != SAME_NAME) &&
		    (strcmp(uname, DEFAULT_USER) != 0)) {
			/*
			 * XXX: bummer.  It's a some other domain.
			 * XXX: Someday, we'll go ask that domain for the
			 * XXX: right info, for now...
			 * XXX: When (if) we implement this, we'll want to
			 * XXX: build a small cache to keep from doing this
			 * XXX: all the time...
			 * NNN: Please note that there are sometimes
			 * NNN: significant network delays which will
			 * NNN: *hang the server* if it has to wander
			 * NNN: off to some remote domain.  This is probably
			 * NNN: better off done in a separate thread.
			 */
			info(gettext(
			    "can't reach domain name %s to find user %s\n"),
			    dirn, uname);
			*(dirn-1) = '.';
			return (default_uid);
		}
		/* FALL THROUGH... for local domain case */
	}
	pw = getpwnam(uname);

	if (pw != NULL) {
		uid = pw->pw_uid;
	} else {
		uid = default_uid;
	}

	if (dirn != NULL) {
		*(dirn-1) = '.';
	}
	return (uid);
}


/*
 * Return a (malloced) char * that is a valid "network" group
 * name, as defined by nis+.  So, given for the gid for the
 * "foo" group, this function will return: "foo@bar.you.sun.com.",
 * if "foo.you.sun.com." is your domain name.
 */
char *
network_groupname(gid_t gid)
{
	struct group 	*gr;
	char		*gname;

	gr = getgrgid(gid);
	if ((gr != NULL) && (strcmp(gr->gr_name, DEFAULT_GROUP) != 0)) {
		/* +2 == "@" plus null */
		gname = (void *)malloc(strlen(gr->gr_name) +
		    strlen(nis_local_directory()) + 2);
		(void) strcpy(gname, gr->gr_name);
		(void) strcat(gname, "@");
		(void) strcat(gname, nis_local_directory());

	} else {
		gname = strdup(DEFAULT_GROUP);
	}
	return (gname);
}


/*
 * Take apart a name like: "foo@bar.you.sun.com." and return the
 * local gid for that group in that domain.  Also just works for
 * "foo".
 * XXX: Note that the remote domain case is currently unimplemented.
 * XXX: Also note that we don't search the remote domain for any
 * XXX: group named DEFAULT_GROUP.  This is considered a feature.
 */
gid_t
network_gid(char *gname)
{
	struct group	*gr;
	char		*dirn;
	gid_t		gid;


	if ((dirn = strchr(gname, '@')) != NULL) {
		*dirn++ = NULLC;
		if ((nis_dir_cmp(nis_local_directory(), dirn) != SAME_NAME) &&
		    (strcmp(gname, DEFAULT_GROUP) != 0)) {
			/*
			 * XXX: bummer.  It's a some other domain.
			 * XXX: Someday, we'll go ask that domain for the
			 * XXX: right info, for now...
			 * XXX: When (if) we implement this, we'll want to
			 * XXX: build a small cache to keep from doing this
			 * XXX: all the time...
			 * NNN: Please note that there are sometimes
			 * NNN: significant network delays which will
			 * NNN: *hang the server* if it has to wander
			 * NNN: off to some remote domain.  This is probably
			 * NNN: better off done in a separate thread.
			 */
			info(gettext(
			    "can't reach domain name %s to find group %s\n"),
			    dirn, gname);
			*(dirn-1) = '@';
			return (default_gid);
		}
		/* FALL THROUGH... for local domain case */
	}
	gr = getgrnam(gname);

	if (gr != NULL) {
		gid = gr->gr_gid;
	} else {
		gid = default_gid;
	}

	if (dirn != NULL) {
		*(dirn-1) = '@';
	}
	return (gid);
}


/*
 * Compute a 32 bit number from a string of characters.  Not great,
 * but seems to work okay.
 */
uint_t
hash_string(char *s)
{
	uint_t	rval = 0;
	int	rotor;


	for (rotor = 0;
		*s != NULLC;
		rotor = (uint_t)((rotor+1) % sizeof (rval))) {
			rval |= (rval ^ *s++) << (rotor * NBBY);
	}
	return (rval);
}


/*
 * Load a dso named "name" into our address space, and call the
 * function named "funcname"
 */
bool_t
dso_load(char *name, char *funcname, int vers)
{
	extern char	*vold_devdir;
	char		namebuf[MAXPATHLEN+1];
	void		*dso_handle = NULL;
	bool_t		(*initfunc)() = NULL;
	struct stat	sb;
	bool_t		res;

	/*
	 * Look for the name with the correct version in various places.
	 * Algorithm:  	/usr/lib/vold/name.version
	 *		./name.version
	 *		/usr/lib/vold/name	(warning)
	 *		./name			(warning)
	 */

	(void) snprintf(namebuf, sizeof (namebuf), "%s/%s.%d",
		vold_devdir, name, vers);

	if (stat(namebuf, &sb) < 0) {

		(void) snprintf(namebuf, sizeof (namebuf), "%s.%d", name, vers);

		if (stat(namebuf, &sb) < 0) {

			(void) snprintf(namebuf, sizeof (namebuf), "%s/%s",
				vold_devdir, name);

			if (stat(namebuf, &sb) < 0) {

				(void) snprintf(namebuf,
					sizeof (namebuf), "%s", name);

				if (stat(namebuf, &sb) < 0) {
					warning(gettext(
					    "dso_load: %s/%s.%d not found\n"),
					    vold_devdir, name, vers);
					res = FALSE;
					goto dun;
				}
			}

			warning(gettext(
			    "trying unversioned dso %s (want ver %d)\n"),
			    namebuf, vers);

		}
	}

	/*
	 * decided on a name, now on to the real work.
	 */
	debug(1, "dso_load(): opening %s \n", namebuf);
	if ((dso_handle = dlopen(namebuf, RTLD_LAZY)) != NULL) {
		initfunc = (int (*)())dlsym(dso_handle, funcname);
	} else {
		warning(gettext("db_dlopen: %s in %s\n"), dlerror(),
		    namebuf);
		res = FALSE;
		goto dun;
	}
	if (initfunc != NULL) {
		/*
		 * Call the initialization function.  If it returns
		 * FALSE, we have no interest in it, so we just dump
		 * it.
		 */

		if ((*initfunc)() == FALSE) {
#ifdef DEBUG
			info(
gettext("dso_load: would have unloaded %s, but didn't because of a dbx bug\n"),
			    name);
#else
			info(gettext("dso_load: unloading %s\n"), name);
			(void) dlclose(dso_handle);
#endif
			res = FALSE;
			goto dun;
		} else {
			info(gettext("dso_load: loaded %s\n"), namebuf);
		}
	} else {
		warning(gettext("dso_load: %s in %s\n"), dlerror(),
		    namebuf);
		res = FALSE;
		goto dun;
	}

	res = TRUE;
dun:
	return (res);
}


bool_t
add_to_unsafe_list(char *fs)
{
	if (unsafe_ind >= DEFAULT_UNSAFE) {
		return (FALSE);
	}

	debug(10, "%s(%d): 'fs' is considered unsafe\n", __FILE__,
		__LINE__, fs);
	unsafe_list[unsafe_ind++] = strdup(fs);
	return (TRUE);
}


/*
 * flush the unsafe list
 */
void
unsafe_flush()
{
	int	i;


	for (i = 0; i < unsafe_ind; i++) {
		if (unsafe_list[i] != NULL) {
			debug(10, "%s(%d): flushing unsafe fs '%s'\n",
				__FILE__, __LINE__, unsafe_list[i]);
			free(unsafe_list[i]);
			unsafe_list[i] = NULL;
		}
	}
	unsafe_ind = 0;
}


static bool_t
unsafe_fs(char *path)
{
	struct mnttab	*mnt = NULL;
	char		*special = NULL;
	int		i;
	bool_t		res = FALSE;



	if ((special = mnt_special_test(path)) == NULL) {
		goto dun;
	}

	if ((mnt = mnt_mnttab(special)) == NULL) {
		goto dun;
	}

	for (i = 0; i < unsafe_ind; i++) {
		if (unsafe_list[i] == NULL) {
			/* reached end of list */
			break;
		}
		if (strcmp(unsafe_list[i], mnt->mnt_fstype) == 0) {
			debug(1,
			    "unsafe_fs: %s mounted on %s w/unsafe fs %s\n",
			    path, mnt->mnt_mountp, unsafe_list[i]);
			res = TRUE;
			break;
		}
	}

dun:
	if (mnt != NULL) {
		mnt_free_mnttab(mnt);
	}
	if (special != NULL) {
		free(special);
	}
	return (res);
}


bool_t
unsafe_check(vol_t *v)
{
	struct vnwrap	*vw, *ovw;
	char		namebuf[MAXPATHLEN];
	char		*path;
	int		i;

	/*
	 * Find the name for the block devices of this volume,
	 * and call unsafe_fs with them.
	 */
	ovw = node_findnode(v->v_obj.o_id, FN_ANY, FN_ANY, FN_ANY);
	if (ovw == NULL) {
		return (FALSE);
	}

	for (vw = ovw; vw != NULL; vw = vw->vw_next) {

		if ((vw->vw_node->vn_type != VV_BLK) &&
		    (vw->vw_node->vn_otype != VV_BLK)) {
			continue;
		}

		path = path_make(vw->vw_node);
		if (v->v_ndev > 1) {
			/* partitions */
			for (i = 0; i < (int)v->v_ndev; i++) {
				(void) snprintf(namebuf, sizeof (namebuf),
				    "%s/s%d", path, dev_to_part(v, i));
				if (unsafe_fs(namebuf) != FALSE) {
					node_findnode_free(vw);
					return (TRUE);
				}
			}
		} else {
			if (unsafe_fs(path) != FALSE) {
				node_findnode_free(vw);
				return (TRUE);
			}
		}
		free(path);
	}
	node_findnode_free(ovw);
	return (FALSE);
}


int
dev_to_part(vol_t *v, int devno)
{
	int		partno;
	ulong_t		partmask = v->v_parts;
	int		i;


	/*
	 * note that we start counting devno, and partno the same
	 * as we count bits (i.e. bitpos 0, bitpos 1, ...)
	 */
	partno = 0;
	for (i = 0; i < V_NUMPAR; i++) {
		if (partmask & (1<<i)) {
			if (devno == partno) {
				break;
			}
			partno++;
		}
	}
	return (i);
}


/*
 * Convert a shell regular expression to a RE (regular expression)
 * (thanks to Sam Falkner)
 */
char *
sh_to_regex(char *s)
{
	char vi[VOLD_REGEXNAME_LEN];
	char *c;

	vi[0] = '^';
	for (c = vi+1; *s; ++c, ++s) {
		if (*s == '\\') {
			*(c++) = *(s++);
		} else if (*s == '*') {
			*(c++) = '.';
		} else if ((*s == '.') || (*s == '$') || (*s == '^')) {
			*(c++) = '\\';
		} else if (*s == '?') {
			*s = '.';
		}
		*c = *s;
		if (*s == NULLC) {
			++c;
			break;
		}
	}
	*(c++) = '$';
	*c = NULLC;
	return (strdup(vi));
}


/*
 * Take a path and return the character device.  The getfullrawname
 * function only works with dsk and rdsk names.  I also do the
 * irritating floppy name.  Unlike getfullrawname, we return
 * NULL if we can't find the right stuff.
 */
char *
rawpath(char *n)
{
	extern char	*getfullrawname(char *);

	char		*rval;
	char		namebuf[MAXPATHLEN];
	char		*s;


	rval = getfullrawname(n);
	if ((rval != NULL) && (*rval != NULLC)) {
		return (rval);
	}

	if (rval != NULL) {
		free(rval);
	}

	/* ok, so we either have a bad device or a floppy. */

	/* the fd# form */
	s = strstr(n, "/fd");
	if (s != NULL) {
		s++;	/* point at 'f' */
		*s = NULLC;
		(void) strcpy(namebuf, n);
		*s = 'f';
		(void) strcat(namebuf, "r");
		(void) strcat(namebuf, s);
		return (strdup(namebuf));
	}

	/* the diskette form */
	s = strstr(n, "/diskette");
	if (s != NULL) {
		s++;	/* point at 'd' */
		*s = NULLC;
		(void) strcpy(namebuf, n);
		*s = 'd';
		(void) strcat(namebuf, "r");
		(void) strcat(namebuf, s);
		return (strdup(namebuf));
	}
	return (strdup(""));
}

void
match_path_cache_clear()
{
	struct dentry *dent, *dentn;
	struct fentry *p, *np;

	for (dent = dir_entry_cache; dent != NULL; dent = dentn) {
		for (p = dent->files; p != NULL; p = np) {
			np = p->fnext;
			free(p->fname);
			free(p);
		}
		dentn = dent->dnext;
		free(dent->dirname);
		free(dent);
	}
	dir_entry_cache = NULL;
}

/*
 * given a regular expression, or a path, return a list of
 * paths that match it.
 */
char **
match_path(char *p, int (*testpath)(char *))
{
	static int	fentrycmp(const void *a, const void *b);
	struct stat	sb;			/* set but not used */
	char		**rval;
	int		i, ret, nents, nrval, fd;
	regex_t		re_cmp;			/* regexec version of re */
	char		*dn, *bn, *cp, *rp;
	size_t		len;
	struct dentry	*dent;
	struct fentry	*fent, **ents;

	/*
	 * Check to see if the path is something real.
	 * If so, just return it as the only one.
	 */
	if (stat(p, &sb) == 0) {
		/* the name has no RE in it: use it as is (if it passes) */
		if (testpath != NULL && (*testpath)(p) != TRUE) {
			debug(3, "match_path: failed for \"%s\"\n", p);
			return (NULL);
		}
		rval = vold_malloc(sizeof (char *) * 2);
		rval[0] = vold_strdup(p);
		rval[1] = NULL;
		return (rval);	/* found a single match */
	}

	/* the filename must have a wildcard in it -- does anything match? */

	/*
	 * separate the directory name from the path name
	 */
	dn = vold_strdup(p);
	if ((bn = strrchr(dn, '/')) == NULL) {
		debug(3, "no '/' in %s\n", p);
		free(dn);
		return (NULL);	/* pathname syntax error */
	}
	/*
	 * put a null where the last slash was,
	 * bn will have the "tail" of the name (the basename), which should
	 *	have the RE), and
	 * dn has the directory part of the name (the dirname)
	 */
	*bn++ = NULL;

	/* First look up the cache to see if we have the dir entry */
	for (dent = dir_entry_cache; dent != NULL; dent = dent->dnext) {
		if (strcmp(dent->dirname, dn) == 0)
			break;
	}

	if (dent == NULL) {
		/* no cache found */
		DIR		*dirp = NULL;
		struct dirent	*dp;

		if ((dirp = opendir(dn)) == NULL) {
			debug(3, "opendir of %s failed; %m\n", dn);
			free(dn);
			return (NULL);	/* no such directory? */
		}

		dent = vold_calloc(1, sizeof (struct dentry));
		nents = 0;
		while ((dp = readdir(dirp)) != NULL) {
			if ((strcmp(dp->d_name, ".") == 0) ||
			    (strcmp(dp->d_name, "..") == 0)) {
				continue;
			}
			fent = vold_malloc(sizeof (struct fentry));
			fent->fname = vold_strdup(dp->d_name);
			fent->flag = 0;
			fent->fnext = dent->files;
			dent->files = fent;
			nents++;
		}

		(void) closedir(dirp);

		if (nents != 0) {
			/*
			 * allocate an array of all pointers to give to qsort
			 */
			ents = vold_malloc((sizeof (struct fentry *) * nents));
			fent = dent->files;
			for (i = 0; i < nents; i++) {
				ents[i] = fent;
				fent = fent->fnext;
			}
			/*
			 * sort the directory entries.
			 */
			qsort(ents, nents, sizeof (struct fentry *), fentrycmp);

			/* re-construct the linked list */
			for (i = 0; i < (nents-1); i++) {
				ents[i]->fnext = ents[i+1];
			}
			ents[nents-1]->fnext = NULL;
			dent->files = ents[0];
			free(ents);
		}
		dent->dirname = vold_strdup(dn);
		dent->dnext = dir_entry_cache;
		dir_entry_cache = dent;
	}

	if (dent->files == NULL) {
		/*
		 * directory is empty.
		 */
		free(dn);
		return (NULL);
	}

	/*
	 * XXX this only deals with regular expressions in the
	 * XXX filename part of the path, and ignores any fancy stuff in
	 * XXX the rest of the path.
	 */

	/* compile the regular expression */
	cp = sh_to_regex(bn);
	if ((ret = regcomp(&re_cmp, cp, REG_NOSUB)) != REG_OK) {
		char *errmsg;
		/* get the RE err msg, then print it and exit */
		len = regerror(ret, &re_cmp, NULL, 0);
		errmsg = vold_malloc(len + 1);
		(void) regerror(ret, &re_cmp, errmsg, len);
		debug(3, "bad regular expression \"%s\" (%s)\n", cp, errmsg);
		free(errmsg);
		free(cp);
		free(dn);
		return (NULL);	/* RE AFU */
	}

	/*
	 * First, mark the files if it does match the pattern.
	 */
	nents = 0;
	for (fent = dent->files; fent != NULL; fent = fent->fnext) {
		fent->flag &= ~FENTRY_MATCH;
		ret = regexec(&re_cmp, fent->fname, 0, NULL, 0);
		if (ret == REG_NOMATCH)
			continue;
		if (ret != REG_OK) {
			debug(1,
			    "can't compare RE \"%s\" to \"%s\" (ret %s)\n",
			    cp, fent->fname, ret);
			continue;
		}
		fent->flag |= FENTRY_MATCH;
		nents++;	/* count only match */
	}
	free(cp);
	regfree(&re_cmp);

	/*
	 * We found nents files which match the pattern. Although
	 * some of them may be known to be inappropriate, we allocate
	 * nents + 1(for NULL) array to simplify the code.
	 */
	rval = vold_malloc(sizeof (char *) * (nents + 1));
	nrval = 0;
	len = strlen(dn);
	for (fent = dent->files; fent != NULL; fent = fent->fnext) {
		/* just skip the device files which we don't want */
		if ((fent->flag & FENTRY_MATCH) == 0)
			continue;

		/* if the path is known to be inappropriate, just skip */
		if ((fent->flag & FENTRY_NO_FILE) ||
		    (fent->flag & FENTRY_NOT_REMOVABLE)) {
			debug(3, "%s known to be inappropriate\n",
				fent->fname);
			continue;
		}
		/* allocate buffer for full path */
		cp = vold_malloc(len + 1 + strlen(fent->fname) + 1);
		(void) strcpy(cp, dn);
		cp[len] = '/';
		(void) strcpy(cp + len + 1, fent->fname);

		/* if the device has not been evaluated, then do it. */
		if ((fent->flag & FENTRY_REMOVABLE) == 0) {
			/* need to invoke ioctl against char device */
			if ((rp = rawpath(cp)) == NULL || *rp == '\0') {
				debug(3, "%s has no raw device\n", cp);
				fent->flag |= FENTRY_NO_FILE;
				goto out;
			}
			if (stat(rp, &sb) < 0) {
				debug(3, "%s does not exist\n", rp);
				fent->flag |= FENTRY_NO_FILE;
				goto out;
			}
			if (!S_ISCHR(sb.st_mode)) {
				debug(3, "%s is not a raw device\n", rp);
				fent->flag |= FENTRY_NO_FILE;
				goto out;
			}
			/* see if the device has been managed */
			if (dev_search_dp(sb.st_rdev) == NULL) {
				if ((fd = open(rp, O_RDONLY|O_NONBLOCK)) < 0) {
					debug(3,
						"can't access device %s\n", rp);
					fent->flag |= FENTRY_NO_FILE;
					goto out;
				}
				if (ioctl(fd, DKIOCREMOVABLE, &ret) < 0 ||
				    ret == 0) {
					debug(3, "%s is not a "
						"removable device\n", rp);
					fent->flag |= FENTRY_NOT_REMOVABLE;
					(void) close(fd);
					goto out;
				}
				(void) close(fd);
			}
			fent->flag |= FENTRY_REMOVABLE;
out:
			free(rp);
		}

		/* see if it's the kind of device we hope it is */
		if ((fent->flag & FENTRY_REMOVABLE) == 0 ||
			(testpath != NULL && (*testpath)(cp) != TRUE)) {
			debug(3, "%s wrong kind of device\n", cp);
			free(cp);
		} else {
			rval[nrval++] = cp;
		}
	}
	rval[nrval] = NULL;	/* null terminate */

	free(dn);
	return (rval);
}

/*
 * used for qsort in find_paths
 */
static int
fentrycmp(const void *a, const void *b)
{
	struct fentry	**fa = (struct fentry **)a;
	struct fentry	**fb = (struct fentry **)b;


	return (strcmp((*fa)->fname, (*fb)->fname));
}

/*
 * swiped from rmmount/rmm_util.c, which was in turn swiped from mkdir.c
 * (at some time)
 *
 * NOTE: this routine modifies the "dir" string passed in (although
 * not permanently)
 */
int
makepath(char *dir, mode_t mode)
{
	int		err;
	char		*slash;


	if (mkdir(dir, mode) == 0) {
		return (0);			/* the mkdir succeeded */
	}
	if (errno == EEXIST) {
		return (0);			/* the dir already exists */
	}
	if (errno != ENOENT) {
		return (-1);			/* oh oh */
	}
	if ((slash = strrchr(dir, '/')) == NULL) {
		return (-1);
	}

	/* the mkdir failed with errno==ENOENT, so make it's parent(s) */
	*slash = NULLC;
	err = makepath(dir, mode);
	*slash++ = '/';

	if (err || (*slash == NULLC)) {
		return (err);
	}

	return (mkdir(dir, mode));
}

void *
vold_malloc(size_t size)
{
	void *ptr;
	extern int	umount_all(char *);

	if ((ptr = malloc(size)) == NULL) {
		(void) umount_all(vold_root);
		fatal("Out of memory.");
	}
	return (ptr);
}

void *
vold_realloc(void *ptr, size_t size)
{
	void *rptr;
	extern int	umount_all(char *);

	if ((rptr = realloc(ptr, size)) == NULL) {
		(void) umount_all(vold_root);
		fatal("Out of memory.");
	}
	return (rptr);
}

void *
vold_calloc(size_t nelem, size_t elsize)
{
	void *ptr;

	ptr = vold_malloc(nelem * elsize);
	(void) memset(ptr, 0, nelem * elsize);
	return (ptr);
}

char *
vold_strdup(const char *s)
{
	size_t len = strlen(s);
	char *ptr;

	ptr = vold_malloc(len + 1);
	(void) strcpy(ptr, s);
	return (ptr);
}
