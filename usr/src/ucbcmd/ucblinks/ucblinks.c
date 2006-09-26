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

/*
 * ucblinks - create 4.x /dev compatibility names
 *
 * The basic algorithm is:
 *
 *	find block and character special files in /devices with major
 *	numbers of devices that need compatibility names
 *
 *	determine compatibility names from minor number, driver name, and
 *	/devices name
 *
 *	create symlinks for the compatibility names to 5.x /dev
 *	entries if possible or /devices entries if necessary
 *
 * The name space that ucblinks creates has a number of problems.
 * Unfortunately people have, to an unknown extent, come to depend
 * on the broken name space.  Fixing ucblinks to be more compatible
 * with 4.x would make it less compatible with previous releases of
 * 5.x.  The places were it is broken are noted throughout the code
 * and summarized here:
 *
 *	1157501 ucblinks creates completely broken 4.x links for IPI
 *	1157616 ucblinks does 0 <-> 3 swap for disks when it shouldn't
 *	1157617 ucblinks creates /dev/rxt* names instead of /dev/rmt*
 *	1157970 ucblinks creates incompatible and overlapping links for tapes
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ftw.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/param.h>
#include <locale.h>
#include <libdevinfo.h>

static char *progname;
static char *rootdir = NULL;	/* an alternate root to / */
static int debug = 0;		/* only print what is right and wrong */
static int depth;		/* num descriptors to use for nftw() */

/*
 * Each block or character device entry in /devices is
 * represented by one of these structures.
 */
struct devices_ent {
	char			*devicename;	/* /devices name */
	char			*min_comp;	/* minor component of name */
	int			minor;		/* minor number */
	int			israw;		/* character device? */
	int			iscd;		/* cdrom? */
	int			issd;		/* simple sd use? */
	int			csum;		/* checksum of name */
	struct symlink		*linksto;	/* symlinks to this name */
	struct drvinfo		*drp;		/* driver for this name */
	struct devices_ent	*next;		/* for hash table */
};

/*
 * There are a set of devices for which we'll create
 * compatibility names.  Each driver for the devices
 * is represented by a drvinfo structure.  The rule_func
 * field points to a rule function for that driver.
 */
typedef void (rule_func_t)(struct devices_ent *);

struct drvinfo {
	char		*name;		/* driver name from name_to_major */
	int		major;		/* major number */
	int		index;		/* index, for sorting */
	rule_func_t	*rule_func;	/* rule for this driver */
};

/*
 * The rules for the drivers.
 */
static rule_func_t rule_ar;		/* Archive tapes */
static rule_func_t rule_atapicd;	/* PCI cdrom drive */
static rule_func_t rule_fbs;		/* frame buffers */
static rule_func_t rule_fd;		/* floppy disk */
static rule_func_t rule_id;		/* IPI disks */
static rule_func_t rule_mt;		/* mt tapes */
static rule_func_t rule_sd;		/* scsi disks */
static rule_func_t rule_stxt;		/* scsi and xt tapes */
static rule_func_t rule_xdxy;		/* xd and xy disks */
static rule_func_t rule_zs;		/* zs serial */

#define	NOMAJ	(-1)			/* no entry in /etc/name_to_major */

/*
 * Below are the devices for which we create compatibility
 * links.  Some are obsolete as they have no /etc/name_to_major
 * entry, but they're here to be compatible with the awk-based
 * version of ucblinks.  This list should be in alphabetical
 * order with the index field set for the position in the array
 * (we could compute it at runtime, but we know it so we set
 * it here).  See dcomp() for more about sort order.
 */
static struct drvinfo drvs[] = {
	{ "ar",		NOMAJ,	0,	rule_ar },	/* obsolete */
	{ "atapicd",	NOMAJ,	1,	rule_atapicd },
	{ "bwtwo",	NOMAJ,	1,	rule_fbs },
	{ "cgeight",	NOMAJ,	2,	rule_fbs },
	{ "cgfour",	NOMAJ,	3,	rule_fbs },	/* obsolete */
	{ "cgfourteen",	NOMAJ,	4,	rule_fbs },	/* obsolete */
	{ "cgnine",	NOMAJ,	5,	rule_fbs },
	{ "cgsix",	NOMAJ,	6,	rule_fbs },
	{ "cgthree",	NOMAJ,	7,	rule_fbs },
	{ "cgtwelve",	NOMAJ,	8,	rule_fbs },	/* obsolete */
	{ "fd",		NOMAJ,	9,	rule_fd },
	{ "id",		NOMAJ,	10,	rule_id },
	{ "mt",		NOMAJ,	11,	rule_mt },	/* obsolete */
	{ "sd",		NOMAJ,	12,	rule_sd },
	{ "st",		NOMAJ,	13,	rule_stxt },
	{ "xd",		NOMAJ,	14,	rule_xdxy },
	{ "xt",		NOMAJ,	15,	rule_stxt },
	{ "xy",		NOMAJ,	16,	rule_xdxy },
	{ "zs",		NOMAJ,	17,	rule_zs },
	{ "se",		NOMAJ,	18,	rule_zs }, /* Fast serial */
	{ "su",		NOMAJ,	19,	rule_zs }, /* PC/16550 serial */
	{ NULL },
};

/*
 * Each symlink in /dev is represented by a symlink structure.
 * We record all of them, not just those that point to interesting
 * /devices entries, because when we have determined what a
 * compatibility link should point to we want to know if it
 * already points to the correct target and it is much cheaper to
 * look it up in our list than to make a system call.
 */
struct symlink {
	char		*linkname;	/* name of link */
	char		*target;	/* what the link points to */
	int		csum;		/* checksum of linkname */
	int		already;	/* link already made */
	struct symlink	*hashnext;	/* next on hash list */
	struct symlink	*deventnext;	/* next on /devices ent list */
};

/*
 * The /devices entries and the /dev symlinks are kept in
 * (separate) hash tables.  HASHSIZE was pulled out of the
 * air although it seems to work ok and we get a good
 * distribution.  Some theory says this should be prime,
 * but I don't understand why and that would make "% HASHSIZE"
 * a call to mod routine rather than a simple bit-wise and.
 */
#define	HASHSIZE	256
static struct devices_ent *de_hashtab[HASHSIZE];
static struct devices_ent **devices_list;
static int num_devices_ents;

static struct symlink *link_hashtab[HASHSIZE];

/*
 * Buffers used by the rule functions to construct link names.
 */
static char namebuf[MAXPATHLEN + 1];
static char namebuf2[MAXPATHLEN + 1];

/*
 * Handle used for the link database
 */
static di_devlink_handle_t link_handle;

static void exec_script(char **argv);
static void get_major_nums(void);
static void set_depth(void);
static void get_devices(void);
static void get_dev_links(void);
static void call_device_rules(void);
static int is_blank(char *);

/*
 * The command-line arguments to ucblinks are:
 *
 *	-r	specify a root relative to which ./devices and ./dev
 *		are used to create links.
 *
 *	-e	the awk-based ucblinks had a default rule-base and
 *		allowed alternate rule-bases with -e.  If the user
 *		specifies a rule-base we run the awk-based ucblinks
 *		and pass all the args to it.
 *
 *	-d	undocumented debug option (like the awk-based version);
 *		print what would be created, fixed, or is already correct.
 */
int
main(int argc, char **argv)
{
	int c;
	int err = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];	/* save program name for error messages */

	while ((c = getopt(argc, argv, "r:e:d")) != EOF) {
		switch (c) {
		case 'r':
			rootdir = optarg;
			break;
		case 'e':
			exec_script(argv);
			/* exec_script doesn't return */
			break;
		case 'd':
			debug = 1;
			break;
		case '?':
		default:
			err = 1;
			break;
		}
	}

	if (err || (optind != argc)) {
		(void) fprintf(stderr, gettext("usage: %s [ -r rootdir ] "
		    "[ -e rulebase ]\n"), progname);
		exit(1);
	}

	get_major_nums();

	set_depth();

	get_devices();

	get_dev_links();

	call_device_rules();

	return (0);
}

/*
 * A utility function so we don't have to check the return
 * value of malloc for NULL all over the place.
 */
static void *
xmalloc(size_t size)
{
	void *p;

	p = malloc(size);
	if (p != NULL)
		return (p);
	else {
		(void) fprintf(stderr, gettext("%s: malloc failed, "
		    "out of memory\n"), progname);
		exit(1);
#ifdef lint
		return (NULL);
#endif
	}
}

/*
 * A utility function so we don't have to check the return
 * value of strdup (which gets space from malloc) for NULL
 * all over the place.
 */
static char *
xstrdup(const char *s1)
{
	char *s2;

	s2 = strdup(s1);
	if (s2 != NULL)
		return (s2);
	else {
		(void) fprintf(stderr, gettext("%s: malloc failed, "
		    "out of memory\n"), progname);
		exit(1);
#ifdef lint
		return (NULL);
#endif
	}
}

/*
 * A utility function that prepends the program name to
 * perror output.
 */
static void
xperror(const char *errstr)
{
	int len1, len2;
	char *msg;

	len1 = strlen(progname);
	len2 = strlen(errstr);

	msg = xmalloc(len1 + 2 + len2 + 1);
	(void) sprintf(msg, "%s: %s", progname, errstr);
	perror(msg);
	free(msg);
}

/*
 * The awk-based ucblinks allowed an alternate rule-base with
 * the -e option.  Obviously we don't do awk, so pass off all
 * our command-line arguments to the awk-based version which
 * was moved from /usr/ucb to /usr/ucblib.
 */
#define	SCRIPT	"/usr/ucblib/ucblinks.sh"

static void
exec_script(char **argv)
{
	argv[0] = SCRIPT;
	if (execv(SCRIPT, argv) == -1)
		xperror(gettext("cannot execute " SCRIPT));
	exit(1);
}

/*
 * Construct a name with the rootdir, if specified with -r,
 * prepended.  Don't free this because when rootdir isn't
 * set we return what was passed in (this is called at most
 * four times so it's no big deal to not free it).
 */
static char *
root_name(char *name)
{
	int len1, len2;
	char *buf;

	if (rootdir == NULL)
		return (name);
	else {
		len1 = strlen(rootdir);
		len2 = strlen(name);
		buf = xmalloc(len1 + len2 + 1);

		(void) strcpy(buf, rootdir);
		(void) strcpy(buf + len1, name);
		return (buf);
	}
}

/*
 * Read /etc/name_to_major to find the major numbers associated
 * with the names in the drvinfo array.  We silently ignore
 * what we don't understand.
 */
static void
get_major_nums(void)
{
	FILE *fp;
	char line[FILENAME_MAX*2 + 1];	/* use the same size as add_drv does */
	char *name, *maj, *end, *cp;
	int majnum;
	struct drvinfo *drp;

	fp = fopen("/etc/name_to_major", "r");
	if (fp == NULL) {
		(void) fprintf(stderr, gettext("%s: cannot open "
		    "/etc/name_to_major\n"), progname);
		exit(1);
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		/* cut off comments starting with '#' */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(line))
			continue;
		name = strtok(line, " \t"); /* must not be NULL */
		if ((maj = strtok(NULL, "\n")) == NULL)
			continue;
		majnum = strtol(maj, &end, 10);
		if (end == maj)
			continue;
		/*
		 * Compare against our list and set the major
		 * number it it's a name we care about.
		 */
		for (drp = drvs; drp->name != NULL; drp++) {
			if (strcmp(name, drp->name) == 0) {
				drp->major = majnum;
				break;
			}
		}
	}

	(void) fclose(fp);
}

/*
 * Pick some reasonable number of file descriptors to let nftw()
 * have open at a time.  The number shouldn't be more than the
 * currently available file descriptors but should be at least equal
 * to the depth of the trees we're traversing for efficiency.  Of
 * course we don't know how deep the trees are before hand, so
 * just use half the allowable descriptors which usually comes
 * out to 32 which is usually more than enough.  Using a depth
 * smaller than the tree depth doesn't prevent traversal of the tree,
 * it just makes it slower.  sysconf() can't fail, but if it does
 * use a depth of 1.
 */
static void
set_depth(void)
{
	long num;

	num = sysconf(_SC_OPEN_MAX);
	if (num == -1)
		depth = 1;
	else
		depth = num / 2;
}

/*
 * Given a major number look it up in our list to see if it
 * is associated with a device that needs a compatibility
 * link.  We cache the last lookup to avoid going through
 * the list each time.
 */
static struct drvinfo *
interesting_major(int major)
{
	struct drvinfo *drp;
	static int last_major = -1;
	static struct drvinfo *last_result = NULL;

	if (major == last_major)
		return (last_result);
	last_major = major;

	for (drp = drvs; drp->name != NULL; drp++) {
		if (major == drp->major) {
			last_result = drp;
			return (drp);
		}
	}

	last_result = NULL;
	return (NULL);
}

/*
 * Find the minor component of the device name which is what
 * comes between the ':' and ',' in the last component of
 * the pathname; make a copy and return a pointer to it.
 */
static char *
find_min_comp(char *name)
{
	char *cp1, *cp2;
	int len;
	char *buf;

	cp1 = strrchr(name, '/');
	if (cp1 == NULL)
		cp1 = name;
	else
		cp1++;			/* skip '/' */
	cp1 = strchr(cp1, ':');
	if (cp1 == NULL)
		return ("");

	cp1++;				/* skip ':' */
	cp2 = cp1;
	while (*cp2 != ',' && *cp2 != '\0')
		cp2++;
	len = cp2 - cp1;
	if (len == 0)
		return ("");

	buf = xmalloc(len + 1);
	(void) strncpy(buf, cp1, len);
	buf[len] = '\0';
	return (buf);
}

/*
 * To get an index into the hash table we compute a checksum
 * of the string and mod HASHSIZE.  The checksum came from
 * awk, although we do a shift and subtract to implement
 * multiplication by 31.  We return the index as well as
 * the whole checksum.  The checksum is useful for efficient
 * symbol lookup because the hash table will contain long strings
 * that can be the same for the first 70 characters or more, so
 * we compare checksums first before using strcmp().
 */
static int
hash_sym(char *name, int *csp)
{
	char c;
	unsigned int csum = 0;

	while ((c = *name++) != '\0')
		csum = ((csum << 5) - csum) + c;

	*csp = csum;
	return (csum % HASHSIZE);
}

/*
 * Insert a /devices entry symbol into the devices entry
 * hash table.
 */
static void
insert_devices_sym(struct devices_ent *dep)
{
	int hash;
	struct devices_ent **pp;

	hash = hash_sym(dep->devicename, &dep->csum);
	pp = &de_hashtab[hash];
	dep->next = *pp;
	*pp = dep;
}

/*
 * Lookup a symbol in the devices entry hash table.  Use
 * the checksum to reduce the number of strcmp() calls.
 */
static struct devices_ent *
lookup_devices_sym(char *devicename)
{
	int hash;
	struct devices_ent *dep;
	int csum;

	hash = hash_sym(devicename, &csum);
	dep = de_hashtab[hash];
	while (dep != NULL) {
		if (csum == dep->csum) {
			if (strcmp(devicename, dep->devicename) == 0)
				return (dep);
		}
		dep = dep->next;
	}

	return (NULL);
}

/*
 * This routine is called from nftw() for each /devices entry.
 * If it isn't a device special file or doesn't have the major
 * number of something we care about, don't do anything.
 * Otherwise, allocate a structure for it and put it in the
 * hash table.
 */
/* ARGSUSED2 */
static int
devices_entry(const char *name, const struct stat *sp,
    int flags, struct FTW *ftwp)
{
	int type;
	struct drvinfo *drp;
	struct devices_ent *dep;

	if (flags == FTW_NS) {		/* couldn't stat the file */
		(void) fprintf(stderr, gettext("%s: cannot stat %s\n"),
		    progname, name);
		return (0);
	}
	if (flags == FTW_DNR) {		/* couldn't read a directory */
		(void) fprintf(stderr, gettext("%s: cannot read "
		    "directory %s\n"), progname, name);
		return (0);
	}

	type = sp->st_mode & S_IFMT;
	if (!(type == S_IFCHR || type == S_IFBLK))
		return (0);

	drp = interesting_major(major(sp->st_rdev));
	if (drp == NULL)
		return (0);

	name += 2;				/* skip "./" */
	dep = xmalloc(sizeof (struct devices_ent));
	dep->devicename = xstrdup(name);
	dep->min_comp = find_min_comp(dep->devicename);
	dep->minor = minor(sp->st_rdev);
	dep->israw = (type == S_IFCHR);
	dep->iscd = 0;
	dep->issd = 0;
	dep->linksto = NULL;
	dep->drp = drp;

	insert_devices_sym(dep);
	num_devices_ents++;

	return (0);
}

/*
 * dcomp is the sort function called from qsort().  When comparing
 * two device entries we sort by alphabetical order of the device's
 * driver name, then minor number, then block vs. character, then
 * the name of the device entry itself.
 */
static int
dcomp(const void *p1, const void *p2)
{
	struct devices_ent *dep1 = *((struct devices_ent **)p1);
	struct devices_ent *dep2 = *((struct devices_ent **)p2);

	if (dep1->drp->index == dep2->drp->index) {
		if (dep1->minor == dep2->minor) {
			if (dep1->israw == dep2->israw) {
				return (strcoll(dep1->devicename,
				    dep2->devicename));
			} else {
				return (dep1->israw - dep2->israw);
			}
		} else {
			return (dep1->minor - dep2->minor);
		}
	} else {
		return (dep1->drp->index - dep2->drp->index);
	}
}

/*
 * Go to the /devices directory and recursively find all
 * the device special files (with the handy library function
 * nftw).  nftw() will call devices_entry() which will put
 * the entry in the hash table.  After we find all the
 * entries allocate a table and put pointers in it so
 * we can sort the entries.
 */
static void
get_devices(void)
{
	char *dir;
	int i;
	struct devices_ent *dep, **pht, **pdep;

	dir = root_name("/devices");
	if (chdir(dir) == -1) {
		xperror(dir);
		exit(1);
	}

	/*
	 * Errors related to access permissions are handled
	 * by devices_entry() and devices_entry doesn't return
	 * non-zero so the only thing left is some other type
	 * of error.
	 */
	if (nftw(".", devices_entry, depth, FTW_PHYS) == -1)
		xperror("nftw()");

	devices_list = xmalloc(sizeof (struct devices_ent *) *
	    num_devices_ents);

	pdep = devices_list;
	pht = de_hashtab;
	for (i = 0; i < HASHSIZE; i++) {
		dep = *pht;
		while (dep != NULL) {
			*pdep++ = dep;
			dep = dep->next;
		}
		pht++;
	}

	/*
	 * After all the /devices entries are put in the hash
	 * table we sort the entries.  We do this for two
	 * reasons: the rule functions may count on the order of
	 * devices it is called with (like the cdrom stuff in
	 * rule_sd) and if the rules create overlapping names the
	 * links will be made in an order based on sorted entries
	 * rather than be dependent on the order the entries
	 * happen to be in in a directory.
	 */
	qsort((void *) devices_list, num_devices_ents,
	    sizeof (struct devices_ent *), dcomp);
}

/*
 * Like insert_devices_sym, but for link names and symlink
 * structures.
 */
static void
insert_link_sym(struct symlink *slp)
{
	int hash;
	struct symlink **pp;

	hash = hash_sym(slp->linkname, &slp->csum);
	pp = &link_hashtab[hash];
	slp->hashnext = *pp;
	*pp = slp;
}

/*
 * Like lookup_devices_sym, but for link names and symlink
 * structures.
 */
static struct symlink *
lookup_link_sym(char *linkname)
{
	int hash;
	struct symlink *slp;
	int csum;

	hash = hash_sym(linkname, &csum);
	slp = link_hashtab[hash];
	while (slp != NULL) {
		if (csum == slp->csum) {
			if (strcmp(linkname, slp->linkname) == 0)
				return (slp);
		}
		slp = slp->hashnext;
	}

	return (NULL);
}

/*
 * Check this symlink to see if it points to an interesting
 * /devices entry and hang it off the entry if it does.
 */
static void
check_link(struct symlink *slp)
{
	int dirs;
	char *cp;
	int len;
	char *devices = "../devices/";
	char *buf;
	int i, off;
	struct devices_ent *dep;

	if (*slp->target != '.')
		return;

	/*
	 * Figure out how many directories deep the entry is
	 * so we can see if its link has the right number of
	 * ".."s to point to the /devices directory.
	 */
	dirs = 0;
	cp = strchr(slp->linkname, '/');
	while (cp != NULL) {
		dirs++;
		cp = strchr(cp + 1, '/');
	}
	len = strlen(devices);
	buf = xmalloc(dirs * 3 + len + 1);
	for (i = 0, off = 0; i < dirs; i++, off += 3)
		(void) strcpy(buf + off, "../");
	(void) strcpy(buf + off, devices);
	off += len;

	/*
	 * The correct prefix of the path has been built up
	 * in "buf", compare it to the link and return
	 * if it doesn't match.
	 */
	if (strncmp(slp->target, buf, strlen(buf)) != 0) {
		free(buf);
		return;
	}
	free(buf);

	/*
	 * Look up the /devices path (minus the prefix) and
	 * return if not found.
	 */
	dep = lookup_devices_sym(slp->target + off);
	if (dep == NULL)
		return;

	/* hang it off the /devices entry */
	slp->deventnext = dep->linksto;
	dep->linksto = slp;

}

/*
 * This routine is called from nftw() for each /dev entry.
 * We record all of the symlinks, not just those that point to
 * interesting /devices entries, because when we have determined
 * what a compatibility link should point to we want to know
 * if it already points to the correct target and it is much
 * cheaper to look it up in out list than to make a system call.
 */
/* ARGSUSED2 */
static int
dev_entry(const char *name, const struct stat *sp,
    int flags, struct FTW *ftwp)
{
	int type;
	char target[MAXPATHLEN + 1];
	int targetlen;
	struct symlink *slp;

	if (flags == FTW_NS) {		/* couldn't stat the file */
		(void) fprintf(stderr, gettext("%s: cannot stat %s\n"),
		    progname, name);
		return (0);
	}
	if (flags == FTW_DNR) {		/* couldn't read a directory */
		(void) fprintf(stderr, gettext("%s: cannot read "
		    "directory %s\n"), progname, name);
		return (0);
	}

	type = sp->st_mode & S_IFMT;
	if (type != S_IFLNK)
		return (0);

	name += 2;				/* skip "./" */
	targetlen = readlink(name, target, sizeof (target));
	if (targetlen == -1)
		xperror(name);

	target[targetlen] = '\0';

	slp = xmalloc(sizeof (struct symlink));
	slp->linkname = xstrdup(name);
	slp->target = xstrdup(target);
	slp->already = 0;
	insert_link_sym(slp);
	check_link(slp);

	return (0);
}

/*
 * Go to the /dev directory and recursively find all the
 * symlinks.  nftw() will call dev_entry() which will put
 * the entry in the hash table.
 */
static void
get_dev_links(void)
{
	char *devdir;

	devdir = root_name("/dev");
	if (chdir(devdir) == -1) {
		xperror(devdir);
		exit(1);
	}

	/*
	 * Errors related to access permissions are handled
	 * by dev_entry() and dev_entry doesn't return non-zero
	 * so the only thing left is some other type of error.
	 */
	if (nftw(".", dev_entry, depth, FTW_PHYS) == -1)
		xperror("nftw()");
}

/*
 * Spin through our sorted list of /devices entries and call
 * the rule function for each.
 */
static void
call_device_rules(void)
{
	struct devices_ent **pdep;
	struct devices_ent *dep;
	int i;
	char *root_etc;

	root_etc = root_name("/etc");
	link_handle = di_devlink_open(root_etc, 0);

	pdep = devices_list;
	for (i = 0; i < num_devices_ents; i++) {
		dep = *pdep++;
		dep->drp->rule_func(dep);
	}

	di_devlink_close(&link_handle, 0);
}

static void
update_db(char *compat_link, char *target, int link_type)
{
	if (debug) {
		(void) printf("adding %s link to database: %s -> %s\n",
		    link_type == DI_PRIMARY_LINK ? "primary" : "secondary",
		    compat_link, target);
	} else {
		(void) di_devlink_add_link(link_handle, compat_link, target,
		    link_type);
	}
}

/*
 * Create a symlink called compat_link that points to target.
 * If it already exists correctly don't do anything.  If it
 * exists but is incorrect, delete the link and make it.  If
 * it doesn't exist just make it.
 */
static void
make_link(
	char *compat_link,
	char *target,
	struct symlink *compat_slp,
	int link_type)
{
	if (compat_slp->target != NULL) {
		if (strcmp(target, compat_slp->target) == 0) {
			if (debug)
				(void) printf("already %s -> %s\n",
				    compat_link, compat_slp->target);
			update_db(compat_link, target, link_type);
			return;
		} else {
			if (debug)
				(void) printf("remove %s, link wrong (%s)\n",
				    compat_link, compat_slp->target);
			else {
				if (unlink(compat_link) == -1)
					xperror(compat_link);
				else
					(void) di_devlink_rm_link(link_handle,
					    compat_link);
			}
			compat_slp->target = target;
		}
	} else
		compat_slp->target = target;

	if (debug)
		(void) printf("link %s -> %s\n", compat_link, target);
	else {
		if (symlink(target, compat_link) == -1)
			xperror(compat_link);
		else
			update_db(compat_link, target, link_type);
	}
}

/*
 * addlink is called from the rule functions when they want a
 * compatibility link made.  At this point we only know the
 * link name, the /devices entry, and the prefix of a 5.x /dev
 * name (that points to the /devices entry) that the rule would
 * prefer the compatibility link point to.  If a symlink already
 * exists with the required prefix that points to the /devices
 * entry, make the compatibility link point to that link.
 * If a link with the required prefix doesn't exist, make the
 * link point directly to the /devices entry.  The idea is that
 * someone looking at a compatibility link will be reminded of
 * the "real" 5.x /dev name.  For example, ls -l will show sd0a ->
 * dsk/c0t3d0s0.
 *
 * If the symlink we're creating isn't already in the hash
 * table we add it for possible future use by make_link.
 * If multiple /devices entries exist with the same major
 * and minor numbers this prevents problems with trying to
 * make the link twice.  Generally, though, there shouldn't
 * be multiple /devices entries of the same type, major, and
 * minor, except for tape devices.  The tape rules pass 1 for
 * the unique argument (all others pass 0) so we keep track
 * and only create the first link for a particular compatibility
 * name.
 */
static void
addlink(char *compat_link, char *prefix, struct devices_ent *dep, int unique)
{
	int len, link_type = 0;
	struct symlink *devent_slp;
	struct symlink *compat_slp;
	char *target = NULL;
	char linkbuf[MAXPATHLEN + 1];

	compat_slp = lookup_link_sym(compat_link);
	if (compat_slp == NULL) {
		compat_slp = xmalloc(sizeof (struct symlink));
		compat_slp->linkname = xstrdup(compat_link);
		compat_slp->target = NULL;
		compat_slp->already = 0;
		insert_link_sym(compat_slp);
	}

	if (unique) {
		if (compat_slp->already)
			return;
		else
			compat_slp->already = 1;
	}

	/*
	 * Look for a name with the correct prefix.
	 */
	len = strlen(prefix);
	devent_slp = dep->linksto;
	while (devent_slp != NULL) {
		if (strncmp(prefix, devent_slp->linkname, len) == 0) {
			target = devent_slp->linkname;
			link_type = DI_SECONDARY_LINK;
			break;
		}
		devent_slp = devent_slp->deventnext;
	}

	/*
	 * If we didn't find one with the prefix, point directly
	 * to the /devices entry.
	 */
	if (target == NULL) {
		link_type = DI_PRIMARY_LINK;
		(void) sprintf(linkbuf, "../devices/%s", dep->devicename);
		target = xstrdup(linkbuf);
	}
	make_link(compat_link, target, compat_slp, link_type);
}

/*
 * This is like addlink(), but it doesn't try to find a 5.x
 * link to point to.  It is used by the rule functions to add
 * additional links to links already created with addlink().
 */
static void
addlink_nolookup(char *compat_link, char *target, int unique)
{
	struct symlink *slp;
	char *oldtarg;

	slp = lookup_link_sym(compat_link);
	if (slp == NULL) {
		slp = xmalloc(sizeof (struct symlink));
		slp->linkname = xstrdup(compat_link);
		slp->target = NULL;
		slp->already = 0;
		insert_link_sym(slp);
	}
	oldtarg = slp->target;

	if (unique) {
		if (slp->already)
			return;
		else
			slp->already = 1;
	}

	make_link(compat_link, target, slp, DI_SECONDARY_LINK);

	/*
	 * If it didn't exist or pointed to the wrong
	 * thing we need to duplicate the target and
	 * note that the symlink now points to it.
	 */
	if (slp->target != oldtarg)
		slp->target = xstrdup(target);
}

/*
 * The rest of this file is rule functions and support routines
 * for the rules.  Each rule is passed a pointer to a devices_ent
 * struct which should be all it needs to determine what
 * compatibility link is needed.  The rule functions use
 * addlink() and addlink_nolookup() to have the links
 * made.
 */

/*
 * Rule for Archive tapes.  "ar" isn't in name_to_major but
 * the awk-based version had a rule so it is here too.  The
 * rule works the same as the awk rule, but who knows if it
 * is correct.
 */
static void
rule_ar(struct devices_ent *dep)
{
	char *min_comp = dep->min_comp;

	if (*min_comp != '\0') {
		if (min_comp[strlen(min_comp) - 1] == 'n')
			(void) sprintf(namebuf, "%s%d", "nrar",
			    (dep->minor - 16) / 4);
		else
			(void) sprintf(namebuf, "%s%d", "rar", dep->minor / 4);

		addlink(namebuf, "rmt/", dep, 1);
	}
}

/*
 * Rule for frame buffers.
 */
static void
rule_fbs(struct devices_ent *dep)
{
	addlink(dep->min_comp, "fbs/", dep, 0);
}

/*
 * Rule for floppy drivers.
 */
static void
rule_fd(struct devices_ent *dep)
{
	int c_slice;
	int minor = dep->minor;
	char *link_pfx;
	char *targ_pfx;

	c_slice = (strcmp(dep->min_comp, "c") == 0);

	if (dep->israw) {
		link_pfx = "r";
		targ_pfx = "rdiskette";
	} else {
		link_pfx = "";
		targ_pfx = "diskette";
	}

	(void) sprintf(namebuf, "%sfd%d%s", link_pfx, minor / 8,
	    dep->min_comp);
	addlink(namebuf, targ_pfx, dep, 0);
	if (c_slice) {
		(void) sprintf(namebuf2, "%sfd%d", link_pfx, minor / 8);
		addlink_nolookup(namebuf2, namebuf, 0);
	}
}

/*
 * Rule for IPI disks.  This is hopelessly broken (see bug 1157501)
 * but someone may have come to depend on the broken names.
 */
static void
rule_id(struct devices_ent *dep)
{
	char *targ_pfx;
	char *link_pfx;

	if (dep->israw) {
		link_pfx = "r";
		targ_pfx = "rdsk/";
	} else {
		link_pfx = "";
		targ_pfx = "dsk/";
	}

	(void) sprintf(namebuf, "%sid%x%s", link_pfx, dep->minor,
	    dep->min_comp);
	addlink(namebuf, targ_pfx, dep, 0);
}

/*
 * Rule for obsolete mt devices.  It works like the awk rule,
 * but unknown if correct.
 */
static void
rule_mt(struct devices_ent *dep)
{
	int minor = dep->minor;

	if ((minor % 8) >= 4) {
		(void) sprintf(namebuf, "rmt%d", minor);
		addlink(namebuf, "rmt/", dep, 1);
		(void) sprintf(namebuf2, "nrmt%d", minor - 4);
		addlink_nolookup(namebuf2, namebuf, 1);
	} else {
		(void) sprintf(namebuf, "rmt%d", minor);
		addlink(namebuf, "rmt/", dep, 1);
	}
}

static int
find_cd_nodes(di_node_t node, di_minor_t minor, void *arg)
{
	char	*path;
	char	devpath[MAXPATHLEN];
	struct devices_ent *dep;

	path = di_devfs_path(node);

	if (*path == '/') {
		(void) strcpy(devpath, path+1);
		(void) strcat(devpath, ":");
		(void) strcat(devpath, di_minor_name(minor));

		dep = lookup_devices_sym(devpath);
		if (dep != NULL) {
			dep->iscd = 1;
		}
	}

	di_devfs_path_free(path);

	return (DI_WALK_CONTINUE);
}

static int
find_sd_nodes(di_node_t node, di_minor_t minor, void *arg)
{
	char	*path;
	char	devpath[MAXPATHLEN];
	struct devices_ent *dep;

	path = di_devfs_path(node);

	if (*path == '/') {
		(void) strcpy(devpath, path+1);
		(void) strcat(devpath, ":");
		(void) strcat(devpath, di_minor_name(minor));

		dep = lookup_devices_sym(devpath);
		if (dep != NULL) {
			dep->issd = 1;
		}
	}

	di_devfs_path_free(path);

	return (DI_WALK_CONTINUE);
}

/*
 * The rule for scsi disks uses this to determine if the /devices
 * entry corresponds to a cdrom drive.  Use libdevinfo to walk
 * the device tree:
 *	 calling find_cd_nodes() for each minor node of type DDI_NT_CD.
 *	 calling find_sd_nodes() for each minor node of type DDI_NT_BLOCK_CHAN.
 */
static void
find_cdsd(void)
{
	di_node_t	root_node;

	root_node = di_init("/", DINFOSUBTREE|DINFOMINOR);
	if (root_node == DI_NODE_NIL) {
		return;
	}
	di_walk_minor(root_node, DDI_NT_CD, 0, NULL, find_cd_nodes);
	di_walk_minor(root_node, DDI_NT_BLOCK_CHAN, 0, NULL, find_sd_nodes);
	di_fini(root_node);
}


/*
 * Rule for scsi disks.  If the entry is for a cdrom drive
 * we create srN and rsrN where N is logically numbered
 * starting at 0 in order of minor number.  For regular
 * disks we do the 0 <-> 3 swap, i.e., sd0a will point
 * to c0t3d0s0 and sd3a will point to c0t0d0s0.  This should
 * only be done on sun4m machines to be compatible
 * with 4.x (see bug 1157616) but we're probably stuck with it
 * being done on all machines because people may be used
 * to using the swapped names on other machines.
 */
static void
rule_sd(struct devices_ent *dep)
{
	static int first = 1;
	static int cdnum = -1;
	static int last_minor = -1;
	char *min_comp = dep->min_comp;
	int minor = dep->minor;
	char *targ_pfx;
	char *link_pfx;

	if (first) {
		find_cdsd();
		first = 0;
	}

	if (dep->iscd) {
		if (strcmp(min_comp, "c") == 0) {
			if (minor != last_minor) {
				cdnum++;
				last_minor = minor;
			}
			if (dep->israw) {
				(void) sprintf(namebuf, "rsr%d", cdnum);
				addlink(namebuf, "rdsk/", dep, 0);
			} else {
				(void) sprintf(namebuf, "sr%d", cdnum);
				addlink(namebuf, "dsk/", dep, 0);
			}
		}
		return;
	}

	if (!dep->issd)
		return;

	if (dep->israw) {
		link_pfx = "r";
		targ_pfx = "rdsk/";
	} else {
		link_pfx = "";
		targ_pfx = "dsk/";
	}

	if (minor < 8)
		(void) sprintf(namebuf, "%ssd%d%s", link_pfx, 3, min_comp);
	else if (minor >= 24 && minor < 32)
		(void) sprintf(namebuf, "%ssd%d%s", link_pfx, 0, min_comp);
	else
		(void) sprintf(namebuf, "%ssd%d%s", link_pfx, minor / 8,
		    min_comp);

	addlink(namebuf, targ_pfx, dep, 0);
}

/*
 * Rule for PCI cdrom drives.
 */
static void
rule_atapicd(struct devices_ent *dep)
{
	static int last_minor = -1;
	static int cdnum = -1;
	char *min_comp = dep->min_comp;
	int minor = dep->minor;

	if (strcmp(min_comp, "c") == 0) {
		if (minor != last_minor) {
			cdnum++;
			last_minor = minor;
		}
		if (dep->israw) {
			(void) sprintf(namebuf, "rsr%d", cdnum);
			addlink(namebuf, "rdsk/", dep, 0);
		} else {
			(void) sprintf(namebuf, "sr%d", cdnum);
			addlink(namebuf, "dsk/", dep, 0);
		}
	}
}

/*
 * Rule for scsi and xt tapes.  The tape name space has several
 * problems (see bug 1157970) and the xt names should really appear
 * as an "mt" name (see bug 1157617) but, again, we probably shouldn't
 * change this now as it will break compatibility with earlier
 * 5.x releases.
 */

#include <sys/mtio.h>
/*
 * MTUNIT() and MT_DENSITY() use getminor(), but we already have
 * the minor number and including sysmacros.h to get getminor()
 * conflicts with mkdev.h.  Barf.
 */
#define	getminor(d)	(d)

static void
rule_stxt(struct devices_ent *dep)
{
	char *min_comp = dep->min_comp;
	int minor = dep->minor;
	int drive, den;
	char *link_pfx;

	if (*min_comp != 'b' && *min_comp != 'n') {
		if ((minor & MT_BSD) == 0)
			return;		/* not BSD-style */

		drive = MTUNIT(minor);
		den = MT_DENSITY(minor);

		if (min_comp[strlen(min_comp) - 1] == 'n')
			link_pfx = "nr";
		else
			link_pfx = "r";
		(void) sprintf(namebuf, "%s%s%d", link_pfx, dep->drp->name,
		    (den * 8) + drive);
		addlink(namebuf, "rmt/", dep, 1);
	}
}

/*
 * Rule for xd and xy disks.  This is broken because it does
 * the 0 <-> 3 swap that should only be done for scsi disks
 * on sun4m (see bug 1157616).  Again, we probably
 * can't change this now.
 */
static void
rule_xdxy(struct devices_ent *dep)
{
	char *min_comp = dep->min_comp;
	char *majname = dep->drp->name;
	int minor = dep->minor;
	char *targ_pfx;
	char *link_pfx;

	if (dep->israw) {
		link_pfx = "r";
		targ_pfx = "rdsk/";
	} else {
		link_pfx = "";
		targ_pfx = "dsk/";
	}

	if (minor < 8)
		(void) sprintf(namebuf, "%s%s%d%s", link_pfx, majname, 3,
		    min_comp);
	else if (minor >= 24 && minor < 32)
		(void) sprintf(namebuf, "%s%s%d%s", link_pfx, majname, 0,
		    min_comp);
	else
		(void) sprintf(namebuf, "%s%s%d%s", link_pfx, majname,
		    minor / 8, min_comp);

	addlink(namebuf, targ_pfx, dep, 0);
}

/*
 * Rule for zs (serial) devices.  This rule is different from
 * the rest because it doesn't create a link based on the
 * /devices entry.  It just uses the /devices entry to trigger
 * the rule to create ttyN -> dev/term/N for all dev/term
 * entries.
 */
#include <dirent.h>

static void
rule_zs(struct devices_ent *dep)
{
	static int beenhere = 0;
	int len;
	DIR *dirp;
	struct dirent *direntp;
	char *termdir;
	char *entry;
	char *devicename = dep->devicename;

	len = strlen(devicename);
	if (strncmp(&devicename[len - 3], ",cu", 3) == 0)
		return;

	if (beenhere)
		return;
	else
		beenhere = 1;

	termdir = root_name("/dev/term");

	dirp = opendir(termdir);
	if (dirp == NULL) {
		xperror(termdir);
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		entry = direntp->d_name;
		if (entry[0] == '.')
			continue;
		(void) sprintf(namebuf, "tty%s", direntp->d_name);
		(void) sprintf(namebuf2, "term/%s", direntp->d_name);
		addlink_nolookup(namebuf, namebuf2, 0);
	}

	(void) closedir(dirp);
}

/*
 * is_blank() returns 1 (true) if a line specified is composed of
 * whitespace characters only. otherwise, it returns 0 (false).
 *
 * Note. the argument (line) must be null-terminated.
 */
static int
is_blank(char *line)
{
	for (/* nothing */; *line != '\0'; line++)
		if (!isspace(*line))
			return (0);
	return (1);
}
