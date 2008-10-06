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

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * soft partition operations
 *
 * Soft Partitions provide a virtual disk mechanism which is used to
 * divide a large volume into many small pieces, each appearing as a
 * separate device.  A soft partition consists of a series of extents,
 * each having an offset and a length.  The extents are logically
 * contiguous, so where the first extent leaves off the second extent
 * picks up.  Which extent a given "virtual offset" belongs to is
 * dependent on the size of all the previous extents in the soft
 * partition.
 *
 * Soft partitions are represented in memory by an extent node
 * (sp_ext_node_t) which contains all of the information necessary to
 * create a unit structure and update the on-disk format, called
 * "watermarks".  These extent nodes are typically kept in a doubly
 * linked list and are manipulated by list manipulation routines.  A
 * list of extents may represent all of the soft partitions on a volume,
 * a single soft partition, or perhaps just a set of extents that need
 * to be updated.  Extent lists may be sorted by extent or by name/seq#,
 * depending on which compare function is used.  Most of the routines
 * require the list be sorted by offset to work, and that's the typical
 * configuration.
 *
 * In order to do an allocation, knowledge of all soft partitions on the
 * volume is required.  Then free space is determined from the space
 * that is not allocated, and new allocations can be made from the free
 * space.  Once the new allocations are made, a unit structure is created
 * and the watermarks are updated.  The status is then changed to "okay"
 * on the unit structure to commit the transaction.  If updating the
 * watermarks fails, the unit structure is in an intermediate state and
 * the driver will not allow access to the device.
 *
 * A typical sequence of events is:
 *     1. Fetch the list of names for all soft partitions on a volume
 *         meta_sp_get_by_component()
 *     2. Construct an extent list from the name list
 *         meta_sp_extlist_from_namelist()
 *     3. Fill the gaps in the extent list with free extents
 *         meta_sp_list_freefill()
 *     4. Allocate from the free extents
 *         meta_sp_alloc_by_len()
 *         meta_sp_alloc_by_list()
 *     5. Create the unit structure from the extent list
 *         meta_sp_createunit()
 *         meta_sp_updateunit()
 *     6. Write out the watermarks
 *         meta_sp_update_wm()
 *     7. Set the status to "Okay"
 *         meta_sp_setstatus()
 *
 */

#include <stdio.h>
#include <meta.h>
#include "meta_repartition.h"
#include <sys/lvm/md_sp.h>
#include <sys/lvm/md_crc.h>
#include <strings.h>
#include <sys/lvm/md_mirror.h>
#include <sys/bitmap.h>

extern int	md_in_daemon;

typedef struct sp_ext_node {
	struct sp_ext_node	*ext_next;	/* next element */
	struct sp_ext_node	*ext_prev;	/* previous element */
	sp_ext_type_t		ext_type;	/* type of extent */
	sp_ext_offset_t		ext_offset;	/* starting offset */
	sp_ext_length_t		ext_length;	/* length of this node */
	uint_t			ext_flags;	/* extent flags */
	uint32_t		ext_seq;	/* watermark seq no */
	mdname_t		*ext_namep;	/* name pointer */
	mdsetname_t		*ext_setp;	/* set pointer */
} sp_ext_node_t;

/* extent flags */
#define	EXTFLG_UPDATE	(1)

/* Extent node compare function for list sorting */
typedef int (*ext_cmpfunc_t)(sp_ext_node_t *, sp_ext_node_t *);


/* Function Prototypes */

/* Debugging Functions */
static void meta_sp_debug(char *format, ...);
static void meta_sp_printunit(mp_unit_t *mp);

/* Misc Support Functions */
int meta_sp_parsesize(char *s, sp_ext_length_t *szp);
static int meta_sp_parsesizestring(char *s, sp_ext_length_t *szp);
static int meta_sp_setgeom(mdname_t *np, mdname_t *compnp, mp_unit_t *mp,
	md_error_t *ep);
static int meta_sp_get_by_component(mdsetname_t *sp, mdname_t *compnp,
    mdnamelist_t **nlpp, int force, md_error_t *ep);
static sp_ext_length_t meta_sp_get_default_alignment(mdsetname_t *sp,
    mdname_t *compnp, md_error_t *ep);

/* Extent List Manipulation Functions */
static int meta_sp_cmp_by_nameseq(sp_ext_node_t *e1, sp_ext_node_t *e2);
static int meta_sp_cmp_by_offset(sp_ext_node_t *e1, sp_ext_node_t *e2);
static void meta_sp_list_insert(mdsetname_t *sp, mdname_t *np,
    sp_ext_node_t **head, sp_ext_offset_t offset, sp_ext_length_t length,
    sp_ext_type_t type, uint_t seq, uint_t flags, ext_cmpfunc_t compare);
static void meta_sp_list_free(sp_ext_node_t **head);
static void meta_sp_list_remove(sp_ext_node_t **head, sp_ext_node_t *ext);
static sp_ext_length_t meta_sp_list_size(sp_ext_node_t *head,
    sp_ext_type_t exttype, int exclude_wm);
static sp_ext_node_t *meta_sp_list_find(sp_ext_node_t *head,
    sp_ext_offset_t offset);
static void meta_sp_list_freefill(sp_ext_node_t **extlist,
    sp_ext_length_t size);
static void meta_sp_list_dump(sp_ext_node_t *head);
static int meta_sp_list_overlaps(sp_ext_node_t *head);

/* Extent List Query Functions */
static boolean_t meta_sp_enough_space(int desired_number_of_sps,
	blkcnt_t desired_sp_size, sp_ext_node_t **extent_listpp,
	sp_ext_length_t alignment);
static boolean_t meta_sp_get_extent_list(mdsetname_t *mdsetnamep,
	mdname_t *device_mdnamep, sp_ext_node_t **extent_listpp,
	md_error_t *ep);
static boolean_t meta_sp_get_extent_list_for_drive(mdsetname_t *mdsetnamep,
	mddrivename_t *mddrivenamep, sp_ext_node_t **extent_listpp);


/* Extent Allocation Functions */
static void meta_sp_alloc_by_ext(mdsetname_t *sp, mdname_t *np,
    sp_ext_node_t **extlist, sp_ext_node_t *free_ext,
    sp_ext_offset_t alloc_offset, sp_ext_length_t alloc_length, uint_t seq);
static int meta_sp_alloc_by_len(mdsetname_t *sp, mdname_t *np,
    sp_ext_node_t **extlist, sp_ext_length_t *lp,
    sp_ext_offset_t last_off, sp_ext_length_t alignment);
static int meta_sp_alloc_by_list(mdsetname_t *sp, mdname_t *np,
    sp_ext_node_t **extlist, sp_ext_node_t *oblist);

/* Extent List Population Functions */
static int meta_sp_extlist_from_namelist(mdsetname_t *sp, mdnamelist_t *spnlp,
    sp_ext_node_t **extlist, md_error_t *ep);
static int meta_sp_extlist_from_wm(mdsetname_t *sp, mdname_t *compnp,
    sp_ext_node_t **extlist, ext_cmpfunc_t compare, md_error_t *ep);

/* Print (metastat) Functions */
static int meta_sp_short_print(md_sp_t *msp, char *fname, FILE *fp,
    mdprtopts_t options, md_error_t *ep);
static char *meta_sp_status_to_name(xsp_status_t xsp_status, uint_t tstate);
static int meta_sp_report(mdsetname_t *sp, md_sp_t *msp, mdnamelist_t **nlpp,
    char *fname, FILE *fp, mdprtopts_t options, md_error_t *ep);

/* Watermark Manipulation Functions */
static int meta_sp_update_wm(mdsetname_t *sp, md_sp_t *msp,
    sp_ext_node_t *extlist, md_error_t *ep);
static int meta_sp_clear_wm(mdsetname_t *sp, md_sp_t *msp, md_error_t *ep);
static int meta_sp_read_wm(mdsetname_t *sp, mdname_t *compnp,
    mp_watermark_t *wm, sp_ext_offset_t offset,  md_error_t *ep);
static diskaddr_t meta_sp_get_start(mdsetname_t *sp, mdname_t *compnp,
    md_error_t *ep);

/* Unit Structure Manipulation Functions */
static void meta_sp_fillextarray(mp_unit_t *mp, sp_ext_node_t *extlist);
static mp_unit_t *meta_sp_createunit(mdname_t *np, mdname_t *compnp,
    sp_ext_node_t *extlist, int numexts, sp_ext_length_t len,
    sp_status_t status, md_error_t *ep);
static mp_unit_t *meta_sp_updateunit(mdname_t *np,  mp_unit_t *old_un,
    sp_ext_node_t *extlist, sp_ext_length_t grow_len, int numexts,
    md_error_t *ep);
static int meta_create_sp(mdsetname_t *sp, md_sp_t *msp, sp_ext_node_t *oblist,
    mdcmdopts_t options, sp_ext_length_t alignment, md_error_t *ep);
static int meta_check_sp(mdsetname_t *sp, md_sp_t *msp, mdcmdopts_t options,
    int *repart_options, md_error_t *ep);

/* Reset (metaclear) Functions */
static int meta_sp_reset_common(mdsetname_t *sp, mdname_t *np, md_sp_t *msp,
    md_sp_reset_t reset_params, mdcmdopts_t options, md_error_t *ep);

/* Recovery (metarecover) Functions */
static void meta_sp_display_exthdr(void);
static void meta_sp_display_ext(sp_ext_node_t *ext);
static int meta_sp_checkseq(sp_ext_node_t *extlist);
static int meta_sp_resolve_name_conflict(mdsetname_t *, mdname_t *,
    mdname_t **, md_error_t *);
static int meta_sp_validate_wm(mdsetname_t *sp, mdname_t *np,
    mdcmdopts_t options, md_error_t *ep);
static int meta_sp_validate_unit(mdsetname_t *sp, mdname_t *compnp,
    mdcmdopts_t options, md_error_t *ep);
static int meta_sp_validate_wm_and_unit(mdsetname_t *sp, mdname_t *np,
    mdcmdopts_t options, md_error_t *ep);
static int meta_sp_validate_exts(mdname_t *np, sp_ext_node_t *wmext,
    sp_ext_node_t *unitext, md_error_t *ep);
static int meta_sp_recover_from_wm(mdsetname_t *sp, mdname_t *compnp,
    mdcmdopts_t options, md_error_t *ep);
static int meta_sp_recover_from_unit(mdsetname_t *sp, mdname_t *np,
    mdcmdopts_t options, md_error_t *ep);

/*
 * Private Constants
 */

static const int FORCE_RELOAD_CACHE = 1;
static const uint_t NO_FLAGS = 0;
static const sp_ext_offset_t NO_OFFSET = 0ULL;
static const uint_t NO_SEQUENCE_NUMBER = 0;
static const int ONE_SOFT_PARTITION = 1;

static unsigned long sp_parent_printed[BT_BITOUL(MD_MAXUNITS)];

#define	TEST_SOFT_PARTITION_NAMEP NULL
#define	TEST_SETNAMEP NULL

#define	EXCLUDE_WM	(1)
#define	INCLUDE_WM	(0)

#define	SP_UNALIGNED	(0LL)

/*
 * **************************************************************************
 *                          Debugging Functions                             *
 * **************************************************************************
 */

/*PRINTFLIKE1*/
static void
meta_sp_debug(char *format, ...)
{
	static int debug;
	static int debug_set = 0;
	va_list ap;

	if (!debug_set) {
		debug = getenv(META_SP_DEBUG) ? 1 : 0;
		debug_set = 1;
	}

	if (debug) {
		va_start(ap, format);
		(void) vfprintf(stderr, format, ap);
		va_end(ap);
	}
}

static void
meta_sp_printunit(mp_unit_t *mp)
{
	int i;

	if (mp == NULL)
		return;

	/* print the common fields we know about */
	(void) fprintf(stderr, "\tmp->c.un_type: %d\n", mp->c.un_type);
	(void) fprintf(stderr, "\tmp->c.un_size: %u\n", mp->c.un_size);
	(void) fprintf(stderr, "\tmp->c.un_self_id: %lu\n", MD_SID(mp));

	/* sp-specific fields */
	(void) fprintf(stderr, "\tmp->un_status: %u\n", mp->un_status);
	(void) fprintf(stderr, "\tmp->un_numexts: %u\n", mp->un_numexts);
	(void) fprintf(stderr, "\tmp->un_length: %llu\n", mp->un_length);
	(void) fprintf(stderr, "\tmp->un_dev(32): 0x%llx\n", mp->un_dev);
	(void) fprintf(stderr, "\tmp->un_dev(64): 0x%llx\n", mp->un_dev);
	(void) fprintf(stderr, "\tmp->un_key: %d\n", mp->un_key);

	/* print extent information */
	(void) fprintf(stderr, "\tExt#\tvoff\t\tpoff\t\tLen\n");
	for (i = 0; i < mp->un_numexts; i++) {
		(void) fprintf(stderr, "\t%d\t%llu\t\t%llu\t\t%llu\n", i,
		    mp->un_ext[i].un_voff, mp->un_ext[i].un_poff,
		    mp->un_ext[i].un_len);
	}
}

/*
 * FUNCTION:    meta_sp_parsesize()
 * INPUT:       s       - the string to parse
 * OUTPUT:      *szp    - disk block count (0 for "all")
 * RETURNS:     -1 for error, 0 for success
 * PURPOSE:     parses the command line parameter that specifies the
 *              requested size of a soft partition.  The input string
 *              is either the literal "all" or a numeric value
 *              followed by a single character, b for disk blocks, k
 *              for kilobytes, m for megabytes, g for gigabytes, or t
 *              for terabytes.  p for petabytes and e for exabytes
 *              have been added as undocumented features for future
 *              expansion.  For example, 100m is 100 megabytes, while
 *              50g is 50 gigabytes.  All values are rounded up to the
 *              nearest block size.
 */
int
meta_sp_parsesize(char *s, sp_ext_length_t *szp)
{
	if (s == NULL || szp == NULL) {
		return (-1);
	}

	/* Check for literal "all" */
	if (strcasecmp(s, "all") == 0) {
		*szp = 0;
		return (0);
	}

	return (meta_sp_parsesizestring(s, szp));
}

/*
 * FUNCTION:	meta_sp_parsesizestring()
 * INPUT:	s	- the string to parse
 * OUTPUT:	*szp	- disk block count
 * RETURNS:	-1 for error, 0 for success
 * PURPOSE:	parses a string that specifies size. The input string is a
 *		numeric value followed by a single character, b for disk blocks,
 *		k for kilobytes, m for megabytes, g for gigabytes, or t for
 *		terabytes.  p for petabytes and e for exabytes have been added
 *		as undocumented features for future expansion.  For example,
 *		100m is 100 megabytes, while 50g is 50 gigabytes.  All values
 *		are rounded up to the nearest block size.
 */
static int
meta_sp_parsesizestring(char *s, sp_ext_length_t *szp)
{
	sp_ext_length_t	len = 0;
	char		len_type[2];

	if (s == NULL || szp == NULL) {
		return (-1);
	}

	/*
	 * make sure block offset does not overflow 2^64 bytes.
	 */
	if ((sscanf(s, "%llu%1[BbKkMmGgTt]", &len, len_type) != 2) ||
	    (len == 0LL) ||
	    (len > (1LL << (64 - DEV_BSHIFT))))
		return (-1);

	switch (len_type[0]) {
	case 'B':
	case 'b':
		len = lbtodb(roundup(len * DEV_BSIZE, DEV_BSIZE));
		break;
	case 'K':
	case 'k':
		len = lbtodb(roundup(len * 1024ULL, DEV_BSIZE));
		break;
	case 'M':
	case 'm':
		len = lbtodb(roundup(len * 1024ULL*1024ULL, DEV_BSIZE));
		break;
	case 'g':
	case 'G':
		len = lbtodb(roundup(len * 1024ULL*1024ULL*1024ULL, DEV_BSIZE));
		break;
	case 't':
	case 'T':
		len = lbtodb(roundup(len * 1024ULL*1024ULL*1024ULL*1024ULL,
		    DEV_BSIZE));
		break;
	case 'p':
	case 'P':
		len = lbtodb(roundup(
		    len * 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL,
		    DEV_BSIZE));
		break;
	case 'e':
	case 'E':
		len = lbtodb(roundup(
		    len * 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL*1024ULL,
		    DEV_BSIZE));
		break;
	default:
		/* error */
		return (-1);
	}

	*szp = len;
	return (0);
}

/*
 * FUNCTION:	meta_sp_setgeom()
 * INPUT:	np      - the underlying device to setup geometry for
 *		compnp	- the underlying device to setup geometry for
 *		mp	- the unit structure to set the geometry for
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 otherwise
 * PURPOSE:	establishes geometry information for a device
 */
static int
meta_sp_setgeom(
	mdname_t	*np,
	mdname_t	*compnp,
	mp_unit_t	*mp,
	md_error_t	*ep
)
{
	mdgeom_t	*geomp;
	uint_t		round_cyl = 0;

	if ((geomp = metagetgeom(compnp, ep)) == NULL)
		return (-1);
	if (meta_setup_geom((md_unit_t *)mp, np, geomp, geomp->write_reinstruct,
	    geomp->read_reinstruct, round_cyl, ep) != 0)
		return (-1);

	return (0);
}

/*
 * FUNCTION:	meta_sp_setstatus()
 * INPUT:	sp	- the set name for the devices to set the status on
 *		minors	- an array of minor numbers of devices to set status on
 *		num_units - number of entries in the array
 *		status	- status value to set all units to
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 success
 * PURPOSE:	sets the status of one or more soft partitions to the
 *		requested value
 */
int
meta_sp_setstatus(
	mdsetname_t	*sp,
	minor_t		*minors,
	int		num_units,
	sp_status_t	status,
	md_error_t	*ep
)
{
	md_sp_statusset_t	status_params;

	assert(minors != NULL);

	/* update status of all soft partitions to the status passed in */
	(void) memset(&status_params, 0, sizeof (status_params));
	status_params.num_units = num_units;
	status_params.new_status = status;
	status_params.size = num_units * sizeof (minor_t);
	status_params.minors = (uintptr_t)minors;
	MD_SETDRIVERNAME(&status_params, MD_SP, sp->setno);
	if (metaioctl(MD_IOC_SPSTATUS, &status_params, &status_params.mde,
	    NULL) != 0) {
		(void) mdstealerror(ep, &status_params.mde);
		return (-1);
	}
	return (0);
}

/*
 * FUNCTION:	meta_get_sp_names()
 * INPUT:	sp	- the set name to get soft partitions from
 *		options	- options from the command line
 * OUTPUT:	nlpp	- list of all soft partition names
 *		ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 success
 * PURPOSE:	returns a list of all soft partitions in the metadb
 *		for all devices in the specified set
 */
int
meta_get_sp_names(
	mdsetname_t	*sp,
	mdnamelist_t	**nlpp,
	int		options,
	md_error_t	*ep
)
{
	return (meta_get_names(MD_SP, sp, nlpp, options, ep));
}

/*
 * FUNCTION:	meta_get_by_component()
 * INPUT:	sp	- the set name to get soft partitions from
 *		compnp	- the name of the device containing the soft
 *			  partitions that will be returned
 *		force	- 0 - reads cached namelist if available,
 *			  1 - reloads cached namelist, frees old namelist
 * OUTPUT:	nlpp	- list of all soft partition names
 *		ep	- return error pointer
 * RETURNS:	int	- -1 error, otherwise the number of soft partitions
 *			  found on the component (0 = none found).
 * PURPOSE:	returns a list of all soft partitions on a given device
 *		from the metadb information
 */
static int
meta_sp_get_by_component(
	mdsetname_t	*sp,
	mdname_t	*compnp,
	mdnamelist_t	**nlpp,
	int		force,
	md_error_t	*ep
)
{
	static mdnamelist_t	*cached_list = NULL;	/* cached namelist */
	static int		cached_count = 0;	/* cached count */
	mdnamelist_t		*spnlp = NULL;		/* all sp names */
	mdnamelist_t		*namep;			/* list iterator */
	mdnamelist_t		**tailpp = nlpp;	/* namelist tail */
	mdnamelist_t		**cachetailpp;		/* cache tail */
	md_sp_t			*msp;			/* unit structure */
	int			count = 0;		/* count of sp's */
	int			err;
	mdname_t		*curnp;

	if ((cached_list != NULL) && (!force)) {
		/* return a copy of the cached list */
		for (namep = cached_list; namep != NULL; namep = namep->next)
			tailpp = meta_namelist_append_wrapper(tailpp,
			    namep->namep);
		return (cached_count);
	}

	/* free the cache and reset values to zeros to prepare for a new list */
	metafreenamelist(cached_list);
	cached_count = 0;
	cached_list = NULL;
	cachetailpp = &cached_list;
	*nlpp = NULL;

	/* get all the softpartitions first of all */
	if (meta_get_sp_names(sp, &spnlp, 0, ep) < 0)
		return (-1);

	/*
	 * Now for each sp, see if it resides on the component we
	 * are interested in, if so then add it to our list
	 */
	for (namep = spnlp; namep != NULL; namep = namep->next) {
		curnp = namep->namep;

		/* get the unit structure */
		if ((msp = meta_get_sp_common(sp, curnp, 0, ep)) == NULL)
			continue;

		/*
		 * If the current soft partition is not on the same
		 * component, continue the search.  If it is on the same
		 * component, add it to our namelist.
		 */
		err = meta_check_samedrive(compnp, msp->compnamep, ep);
		if (err <= 0) {
			/* not on the same device, check the next one */
			continue;
		}

		/* it's on the same drive */

		/*
		 * Check for overlapping partitions if the component is not
		 * a metadevice.
		 */
		if (!metaismeta(msp->compnamep)) {
			/*
			 * if they're on the same drive, neither
			 * should be a metadevice if one isn't
			 */
			assert(!metaismeta(compnp));

			if (meta_check_overlap(msp->compnamep->cname,
			    compnp, 0, -1, msp->compnamep, 0, -1, ep) == 0)
				continue;

			/* in this case it's not an error for them to overlap */
			mdclrerror(ep);
		}

		/* Component is on the same device, add to the used list */
		tailpp = meta_namelist_append_wrapper(tailpp, curnp);
		cachetailpp = meta_namelist_append_wrapper(cachetailpp,
		    curnp);

		++count;
		++cached_count;
	}

	assert(count == cached_count);
	return (count);

out:
	metafreenamelist(*nlpp);
	*nlpp = NULL;
	return (-1);
}

/*
 * FUNCTION:    meta_sp_get_default_alignment()
 * INPUT:       sp      - the pertinent set name
 *              compnp  - the name of the underlying component
 * OUTPUT:      ep      - return error pointer
 * RETURNS:     sp_ext_length_t =0: no default alignment
 *                              >0: default alignment
 * PURPOSE:     returns the default alignment for soft partitions to
 *              be built on top of the specified component or
 *              metadevice
 */
static sp_ext_length_t
meta_sp_get_default_alignment(
	mdsetname_t	*sp,
	mdname_t	*compnp,
	md_error_t	*ep
)
{
	sp_ext_length_t	a = SP_UNALIGNED;
	char		*mname;

	assert(compnp != NULL);

	/*
	 * We treat raw devices as opaque, and assume nothing about
	 * their alignment requirements.
	 */
	if (!metaismeta(compnp))
		return (SP_UNALIGNED);

	/*
	 * We already know it's a metadevice from the previous test;
	 * metagetmiscname() will tell us which metadevice type we
	 * have
	 */
	mname = metagetmiscname(compnp, ep);
	if (mname == NULL)
		goto out;

	/*
	 * For a mirror, we want to deal with the stripe that is the
	 * primary side.  If it happens to be asymmetrically
	 * configured, there is no simple way to fake a universal
	 * alignment.  There's a chance that the least common
	 * denominator of the set of interlaces from all stripes of
	 * all submirrors would do it, but nobody that really cared
	 * that much about this issue would create an asymmetric
	 * config to start with.
	 *
	 * If the component underlying the soft partition is a mirror,
	 * then at the exit of this loop, compnp will have been
	 * updated to describe the first active submirror.
	 */
	if (strcmp(mname, MD_MIRROR) == 0) {
		md_mirror_t	*mp;
		int		smi;
		md_submirror_t	*smp;

		mp = meta_get_mirror(sp, compnp, ep);
		if (mp == NULL)
			goto out;

		for (smi = 0; smi < NMIRROR; smi++) {

			smp = &mp->submirrors[smi];
			if (smp->state == SMS_UNUSED)
				continue;

			compnp = smp->submirnamep;
			assert(compnp != NULL);

			mname = metagetmiscname(compnp, ep);
			if (mname == NULL)
				goto out;

			break;
		}

		if (smi == NMIRROR)
			goto out;
	}

	/*
	 * Handle stripes and submirrors identically; just return the
	 * interlace of the first row.
	 */
	if (strcmp(mname, MD_STRIPE) == 0) {
		md_stripe_t	*stp;

		stp = meta_get_stripe(sp, compnp, ep);
		if (stp == NULL)
			goto out;

		a = stp->rows.rows_val[0].interlace;
		goto out;
	}

	/*
	 * Raid is even more straightforward; the interlace applies to
	 * the entire device.
	 */
	if (strcmp(mname, MD_RAID) == 0) {
		md_raid_t	*rp;

		rp = meta_get_raid(sp, compnp, ep);
		if (rp == NULL)
			goto out;

		a = rp->interlace;
		goto out;
	}

	/*
	 * If we have arrived here with the alignment still not set,
	 * then we expect the error to have been set by one of the
	 * routines we called.  If neither is the case, something has
	 * really gone wrong above.  (Probably the submirror walk
	 * failed to produce a valid submirror, but that would be
	 * really bad...)
	 */
out:
	meta_sp_debug("meta_sp_get_default_alignment: miscname %s, "
	    "alignment %lld\n", (mname == NULL) ? "NULL" : mname, a);

	if (getenv(META_SP_DEBUG) && !mdisok(ep)) {
		mde_perror(ep, NULL);
	}

	assert((a > 0) || (!mdisok(ep)));

	return (a);
}



/*
 * FUNCTION:	meta_check_insp()
 * INPUT:	sp	- the set name for the device to check
 *		np	- the name of the device to check
 *		slblk	- the starting offset of the device to check
 *		nblks	- the number of blocks in the device to check
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	-  0 - device contains soft partitions
 *			  -1 - device does not contain soft partitions
 * PURPOSE:	determines whether a device contains any soft partitions
 */
/* ARGSUSED */
int
meta_check_insp(
	mdsetname_t	*sp,
	mdname_t	*np,
	diskaddr_t	slblk,
	diskaddr_t	nblks,
	md_error_t	*ep
)
{
	mdnamelist_t	*spnlp = NULL;	/* soft partition name list */
	int		count;
	int		rval;

	/* check set pointer */
	assert(sp != NULL);

	/*
	 * Get a list of the soft partitions that currently reside on
	 * the component.  We should ALWAYS force reload the cache,
	 * because if we're using the md.tab, we must rebuild
	 * the list because it won't contain the previous (if any)
	 * soft partition.
	 */
	/* find all soft partitions on the component */
	count = meta_sp_get_by_component(sp, np, &spnlp, 1, ep);

	if (count == -1) {
		rval = -1;
	} else if (count > 0) {
		rval = mduseerror(ep, MDE_ALREADY, np->dev,
		    spnlp->namep->cname, np->cname);
	} else {
		rval = 0;
	}

	metafreenamelist(spnlp);
	return (rval);
}

/*
 * **************************************************************************
 *                    Extent List Manipulation Functions                    *
 * **************************************************************************
 */

/*
 * FUNCTION:	meta_sp_cmp_by_nameseq()
 * INPUT:	e1	- first node to compare
 *		e2	- second node to compare
 * OUTPUT:	none
 * RETURNS:	int	- =0 - nodes are equal
 *			  <0 - e1 should go before e2
 *			  >0 - e1 should go after e2
 * PURPOSE:	used for sorted list inserts to build a list sorted by
 *		name first and sequence number second.
 */
static int
meta_sp_cmp_by_nameseq(sp_ext_node_t *e1, sp_ext_node_t *e2)
{
	int rval;

	if (e1->ext_namep == NULL)
		return (1);
	if (e2->ext_namep == NULL)
		return (-1);
	if ((rval = strcmp(e1->ext_namep->cname, e2->ext_namep->cname)) != 0)
		return (rval);

	/* the names are equal, compare sequence numbers */
	if (e1->ext_seq > e2->ext_seq)
		return (1);
	if (e1->ext_seq < e2->ext_seq)
		return (-1);
	/* sequence numbers are also equal */
	return (0);
}

/*
 * FUNCTION:	meta_sp_cmp_by_offset()
 * INPUT:	e1	- first node to compare
 *		e2	- second node to compare
 * OUTPUT:	none
 * RETURNS:	int	- =0 - nodes are equal
 *			  <0 - e1 should go before e2
 *			  >0 - e1 should go after e2
 * PURPOSE:	used for sorted list inserts to build a list sorted by offset
 */
static int
meta_sp_cmp_by_offset(sp_ext_node_t *e1, sp_ext_node_t *e2)
{
	if (e1->ext_offset > e2->ext_offset)
		return (1);
	if (e1->ext_offset < e2->ext_offset)
		return (-1);
	/* offsets are equal */
	return (0);
}

/*
 * FUNCTION:	meta_sp_list_insert()
 * INPUT:	sp	- the set name for the device the node belongs to
 *		np	- the name of the device the node belongs to
 *		head	- the head of the list, must be NULL for empty list
 *		offset	- the physical offset of this extent in sectors
 *		length	- the length of this extent in sectors
 *		type	- the type of the extent being inserted
 *		seq	- the sequence number of the extent being inserted
 *		flags	- extent flags (eg. whether it needs to be updated)
 *		compare	- the compare function to use
 * OUTPUT:	head	- points to the new head if a node was inserted
 *			  at the beginning
 * RETURNS:	void
 * PURPOSE:	inserts an extent node into a sorted doubly linked list.
 *		The sort order is determined by the compare function.
 *		Memory is allocated for the node in this function and it
 *		is up to the caller to free it, possibly using
 *		meta_sp_list_free().  If a node is inserted at the
 *		beginning of the list, the head pointer is updated to
 *		point to the new first node.
 */
static void
meta_sp_list_insert(
	mdsetname_t	*sp,
	mdname_t	*np,
	sp_ext_node_t	**head,
	sp_ext_offset_t	offset,
	sp_ext_length_t	length,
	sp_ext_type_t	type,
	uint_t		seq,
	uint_t		flags,
	ext_cmpfunc_t	compare
)
{
	sp_ext_node_t	*newext;
	sp_ext_node_t	*curext;

	assert(head != NULL);

	/* Don't bother adding zero length nodes */
	if (length == 0ULL)
		return;

	/* allocate and fill in new ext_node */
	newext = Zalloc(sizeof (sp_ext_node_t));

	newext->ext_offset = offset;
	newext->ext_length = length;
	newext->ext_flags = flags;
	newext->ext_type = type;
	newext->ext_seq = seq;
	newext->ext_setp = sp;
	newext->ext_namep = np;

	/* first node in the list */
	if (*head == NULL) {
		newext->ext_next = newext->ext_prev = NULL;
		*head = newext;
	} else if ((*compare)(*head, newext) >= 0) {
		/* the first node has a bigger offset, so insert before it */
		assert((*head)->ext_prev == NULL);

		newext->ext_prev = NULL;
		newext->ext_next = *head;
		(*head)->ext_prev = newext;
		*head = newext;
	} else {
		/*
		 * find the next node whose offset is greater than
		 * the one we want to insert, or the end of the list.
		 */
		for (curext = *head;
		    (curext->ext_next != NULL) &&
		    ((*compare)(curext->ext_next, newext) < 0);
		    (curext = curext->ext_next))
			;

		/* link the new node in after the current node */
		newext->ext_next = curext->ext_next;
		newext->ext_prev = curext;

		if (curext->ext_next != NULL)
			curext->ext_next->ext_prev = newext;

		curext->ext_next = newext;
	}
}

/*
 * FUNCTION:	meta_sp_list_free()
 * INPUT:	head	- the head of the list, must be NULL for empty list
 * OUTPUT:	head	- points to NULL on return
 * RETURNS:	void
 * PURPOSE:	walks a double linked extent list and frees each node
 */
static void
meta_sp_list_free(sp_ext_node_t **head)
{
	sp_ext_node_t	*ext;
	sp_ext_node_t	*next;

	assert(head != NULL);

	ext = *head;
	while (ext) {
		next = ext->ext_next;
		Free(ext);
		ext = next;
	}
	*head = NULL;
}

/*
 * FUNCTION:	meta_sp_list_remove()
 * INPUT:	head	- the head of the list, must be NULL for empty list
 *		ext	- the extent to remove, must be a member of the list
 * OUTPUT:	head	- points to the new head of the list
 * RETURNS:	void
 * PURPOSE:	unlinks the node specified by ext from the list and
 *		frees it, possibly moving the head pointer forward if
 *		the head is the node being removed.
 */
static void
meta_sp_list_remove(sp_ext_node_t **head, sp_ext_node_t *ext)
{
	assert(head != NULL);
	assert(*head != NULL);

	if (*head == ext)
		*head = ext->ext_next;

	if (ext->ext_prev != NULL)
		ext->ext_prev->ext_next = ext->ext_next;
	if (ext->ext_next != NULL)
		ext->ext_next->ext_prev = ext->ext_prev;
	Free(ext);
}

/*
 * FUNCTION:	meta_sp_list_size()
 * INPUT:	head	- the head of the list, must be NULL for empty list
 *		exttype	- the type of the extents to sum
 *		exclude_wm - subtract space for extent headers from total
 * OUTPUT:	none
 * RETURNS:	sp_ext_length_t	- the sum of all of the lengths
 * PURPOSE:	sums the lengths of all extents in the list matching the
 *		specified type.  This could be used for computing the
 *		amount of free or used space, for example.
 */
static sp_ext_length_t
meta_sp_list_size(sp_ext_node_t *head, sp_ext_type_t exttype, int exclude_wm)
{
	sp_ext_node_t	*ext;
	sp_ext_length_t	size = 0LL;

	for (ext = head; ext != NULL; ext = ext->ext_next)
		if (ext->ext_type == exttype)
			size += ext->ext_length -
			    ((exclude_wm) ? MD_SP_WMSIZE : 0);

	return (size);
}

/*
 * FUNCTION:	meta_sp_list_find()
 * INPUT:	head	- the head of the list, must be NULL for empty list
 *		offset	- the offset contained by the node to find
 * OUTPUT:	none
 * RETURNS:	sp_ext_node_t *	- the node containing the requested offset
 *				  or NULL if no such nodes were found.
 * PURPOSE:	finds a node in a list containing the requested offset
 *		(inclusive).  If multiple nodes contain this offset then
 *		only the first will be returned, though typically these
 *		lists are managed with non-overlapping nodes.
 *
 *		*The list MUST be sorted by offset for this function to work.*
 */
static sp_ext_node_t *
meta_sp_list_find(
	sp_ext_node_t	*head,
	sp_ext_offset_t	offset
)
{
	sp_ext_node_t	*ext;

	for (ext = head; ext != NULL; ext = ext->ext_next) {
		/* check if the offset lies within this extent */
		if ((offset >= ext->ext_offset) &&
		    (offset < ext->ext_offset + ext->ext_length)) {
			/*
			 * the requested extent should always be a
			 * subset of an extent in the list.
			 */
			return (ext);
		}
	}
	return (NULL);
}

/*
 * FUNCTION:	meta_sp_list_freefill()
 * INPUT:	head	- the head of the list, must be NULL for empty list
 *		size	- the size of the volume this extent list is
 *			  representing
 * OUTPUT:	head	- the new head of the list
 * RETURNS:	void
 * PURPOSE:	finds gaps in the extent list and fills them with a free
 *		node.  If there is a gap at the beginning the head
 *		pointer will be changed to point to the new free node.
 *		If there is free space at the end, the last free extent
 *		will extend all the way out to the size specified.
 *
 *		*The list MUST be sorted by offset for this function to work.*
 */
static void
meta_sp_list_freefill(
	sp_ext_node_t	**head,
	sp_ext_length_t	size
)
{
	sp_ext_node_t	*ext;
	sp_ext_offset_t	curoff = 0LL;

	for (ext = *head; ext != NULL; ext = ext->ext_next) {
		if (curoff < ext->ext_offset)
			meta_sp_list_insert(NULL, NULL, head,
			    curoff, ext->ext_offset - curoff,
			    EXTTYP_FREE, 0, 0, meta_sp_cmp_by_offset);
		curoff = ext->ext_offset + ext->ext_length;
	}

	/* pad inverse list out to the end */
	if (curoff < size)
		meta_sp_list_insert(NULL, NULL, head, curoff, size - curoff,
		    EXTTYP_FREE, 0, 0, meta_sp_cmp_by_offset);

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_sp_list_freefill: Extent list with "
		    "holes freefilled:\n");
		meta_sp_list_dump(*head);
	}
}

/*
 * FUNCTION:	meta_sp_list_dump()
 * INPUT:	head	- the head of the list, must be NULL for empty list
 * OUTPUT:	none
 * RETURNS:	void
 * PURPOSE:	dumps the entire extent list to stdout for easy debugging
 */
static void
meta_sp_list_dump(sp_ext_node_t *head)
{
	sp_ext_node_t	*ext;

	meta_sp_debug("meta_sp_list_dump: dumping extent list:\n");
	meta_sp_debug("%5s %10s %5s %7s %10s %10s %5s %10s %10s\n", "Name",
	    "Addr", "Seq#", "Type", "Offset", "Length", "Flags", "Prev",
	    "Next");
	for (ext = head; ext != NULL; ext = ext->ext_next) {
		if (ext->ext_namep != NULL)
			meta_sp_debug("%5s", ext->ext_namep->cname);
		else
			meta_sp_debug("%5s", "NONE");

		meta_sp_debug("%10p %5u ", (void *) ext, ext->ext_seq);
		switch (ext->ext_type) {
		case EXTTYP_ALLOC:
			meta_sp_debug("%7s ", "ALLOC");
			break;
		case EXTTYP_FREE:
			meta_sp_debug("%7s ", "FREE");
			break;
		case EXTTYP_END:
			meta_sp_debug("%7s ", "END");
			break;
		case EXTTYP_RESERVED:
			meta_sp_debug("%7s ", "RESV");
			break;
		default:
			meta_sp_debug("%7s ", "INVLD");
			break;
		}

		meta_sp_debug("%10llu %10llu %5u %10p %10p\n",
		    ext->ext_offset, ext->ext_length,
		    ext->ext_flags, (void *) ext->ext_prev,
		    (void *) ext->ext_next);
	}
	meta_sp_debug("\n");
}

/*
 * FUNCTION:	meta_sp_list_overlaps()
 * INPUT:	head	- the head of the list, must be NULL for empty list
 * OUTPUT:	none
 * RETURNS:	int	- 1 if extents overlap, 0 if ok
 * PURPOSE:	checks a list for overlaps.  The list MUST be sorted by
 *		offset for this function to work properly.
 */
static int
meta_sp_list_overlaps(sp_ext_node_t *head)
{
	sp_ext_node_t	*ext;

	for (ext = head; ext->ext_next != NULL; ext = ext->ext_next) {
		if (ext->ext_offset + ext->ext_length >
		    ext->ext_next->ext_offset)
			return (1);
	}
	return (0);
}

/*
 * **************************************************************************
 *                        Extent Allocation Functions                       *
 * **************************************************************************
 */

/*
 * FUNCTION:	meta_sp_alloc_by_ext()
 * INPUT:	sp	- the set name for the device the node belongs to
 *		np	- the name of the device the node belongs to
 *		head	- the head of the list, must be NULL for empty list
 *		free_ext	- the free extent being allocated from
 *		alloc_offset	- the offset of the allocation
 *		alloc_len	- the length of the allocation
 *		seq		- the sequence number of the allocation
 * OUTPUT:	head	- the new head pointer
 * RETURNS:	void
 * PURPOSE:	allocates a portion of the free extent free_ext.  The
 *		allocated portion starts at alloc_offset and is
 *		alloc_length long.  Both (alloc_offset) and (alloc_offset +
 *		alloc_length) must be contained within the free extent.
 *
 *		The free extent is split into as many as 3 pieces - a
 *		free extent containing [ free_offset .. alloc_offset ), an
 *		allocated extent containing the range [ alloc_offset ..
 *		alloc_end ], and another free extent containing the
 *		range ( alloc_end .. free_end ].  If either of the two
 *		new free extents would be zero length, they are not created.
 *
 *		Finally, the original free extent is removed.  All newly
 *		created extents have the EXTFLG_UPDATE flag set.
 */
static void
meta_sp_alloc_by_ext(
	mdsetname_t	*sp,
	mdname_t	*np,
	sp_ext_node_t	**head,
	sp_ext_node_t	*free_ext,
	sp_ext_offset_t	alloc_offset,
	sp_ext_length_t	alloc_length,
	uint_t		seq
)
{
	sp_ext_offset_t	free_offset = free_ext->ext_offset;
	sp_ext_length_t	free_length = free_ext->ext_length;

	sp_ext_offset_t	alloc_end = alloc_offset + alloc_length;
	sp_ext_offset_t	free_end  = free_offset  + free_length;

	/* allocated extent must be a subset of the free extent */
	assert(free_offset <= alloc_offset);
	assert(free_end >= alloc_end);

	meta_sp_list_remove(head, free_ext);

	if (free_offset < alloc_offset) {
		meta_sp_list_insert(NULL, NULL, head, free_offset,
		    (alloc_offset - free_offset), EXTTYP_FREE, 0,
		    EXTFLG_UPDATE, meta_sp_cmp_by_offset);
	}

	if (free_end > alloc_end) {
		meta_sp_list_insert(NULL, NULL, head, alloc_end,
		    (free_end - alloc_end), EXTTYP_FREE, 0, EXTFLG_UPDATE,
		    meta_sp_cmp_by_offset);
	}

	meta_sp_list_insert(sp, np, head, alloc_offset, alloc_length,
	    EXTTYP_ALLOC, seq, EXTFLG_UPDATE, meta_sp_cmp_by_offset);

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_sp_alloc_by_ext: extent list:\n");
		meta_sp_list_dump(*head);
	}
}

/*
 * FUNCTION:	meta_sp_alloc_by_len()
 * INPUT:	sp	- the set name for the device the node belongs to
 *		np	- the name of the device the node belongs to
 *		head	- the head of the list, must be NULL for empty list
 *		*lp	- the requested length to allocate
 *		last_off	- the last offset already allocated.
 *		alignment	- the desired extent alignmeent
 * OUTPUT:	head	- the new head pointer
 *		*lp	- the length allocated
 * RETURNS:	int	- -1 if error, the number of new extents on success
 * PURPOSE:	allocates extents from free space to satisfy the requested
 *		length.  If requested length is zero, allocates all
 *		remaining free space.  This function provides the meat
 *		of the extent allocation algorithm.  Allocation is a
 *		three tier process:
 *
 *		1. If last_off is nonzero and there is free space following
 *		   that node, then it is extended to allocate as much of that
 *		   free space as possible.  This is useful for metattach.
 *		2. If a free extent can be found to satisfy the remaining
 *		   requested space, then satisfy the rest of the request
 *		   from that extent.
 *		3. Start allocating space from any remaining free extents until
 *		   the remainder of the request is satisified.
 *
 *              If alignment is non-zero, then every extent modified
 *              or newly allocated will be aligned modulo alignment,
 *              with a length that is an integer multiple of
 *              alignment.
 *
 *		The EXTFLG_UPDATE flag is set for all nodes (free and
 *		allocated) that require updated watermarks.
 *
 *		This algorithm may have a negative impact on fragmentation
 *		in pathological cases and may be improved if it turns out
 *		to be a problem.  This may be exacerbated by particularly
 *		large alignments.
 *
 * NOTE:	It's confusing, so it demands an explanation:
 *		- len is used to represent requested data space; it
 *		  does not include room for a watermark.  On each full
 *		  or partial allocation, len will be decremented by
 *		  alloc_len (see next paragraph) until it reaches
 *		  zero.
 *		- alloc_len is used to represent data space allocated
 *		  from a particular extent; it does not include space
 *		  for a watermark.  In the rare event that a_length
 *		  (see next paragraph) is equal to MD_SP_WMSIZE,
 *		  alloc_len will be zero and the resulting MD_SP_WMSIZE
 *		  fragment of space will be utterly unusable.
 *		- a_length is used to represent all space to be
 *		  allocated from a particular extent; it DOES include
 *		  space for a watermark.
 */
static int
meta_sp_alloc_by_len(
	mdsetname_t	*sp,
	mdname_t	*np,
	sp_ext_node_t	**head,
	sp_ext_length_t	*lp,
	sp_ext_offset_t	last_off,
	sp_ext_offset_t	alignment
)
{
	sp_ext_node_t	*free_ext;
	sp_ext_node_t	*alloc_ext;
	uint_t		last_seq = 0;
	uint_t		numexts = 0;
	sp_ext_length_t	freespace;
	sp_ext_length_t	alloc_len;
	sp_ext_length_t	len;

	/* We're DOA if we can't read *lp */
	assert(lp != NULL);
	len = *lp;

	/*
	 * Process the nominal case first: we've been given an actual
	 * size argument, rather than the literal "all"
	 */

	if (len != 0) {

		/*
		 * Short circuit the check for free space.  This may
		 * tell us we have enough space when we really don't
		 * because each extent loses space to a watermark, but
		 * it will always tell us there isn't enough space
		 * correctly.  Worst case we do some extra work.
		 */
		freespace = meta_sp_list_size(*head, EXTTYP_FREE,
		    INCLUDE_WM);

		if (freespace < len)
			return (-1);

		/*
		 * First see if we can extend the last extent for an
		 * attach.
		 */
		if (last_off != 0LL) {
			int align = 0;

			alloc_ext =
			    meta_sp_list_find(*head, last_off);
			assert(alloc_ext != NULL);

			/*
			 * The offset test reflects the
			 * inclusion of the watermark in the extent
			 */
			align = (alignment > 0) &&
			    (((alloc_ext->ext_offset + MD_SP_WMSIZE) %
			    alignment) == 0);

			/*
			 * If we decided not to align here, we should
			 * also reset "alignment" so we don't bother
			 * later, either.
			 */
			if (!align) {
				alignment = 0;
			}

			last_seq = alloc_ext->ext_seq;

			free_ext = meta_sp_list_find(*head,
			    alloc_ext->ext_offset +
			    alloc_ext->ext_length);

			/*
			 * If a free extent follows our last allocated
			 * extent, then remove the last allocated
			 * extent and increase the size of the free
			 * extent to overlap it, then allocate the
			 * total space from the new free extent.
			 */
			if (free_ext != NULL &&
			    free_ext->ext_type == EXTTYP_FREE) {
				assert(free_ext->ext_offset ==
				    alloc_ext->ext_offset +
				    alloc_ext->ext_length);

				alloc_len =
				    MIN(len, free_ext->ext_length);

				if (align && (alloc_len < len)) {
					/* No watermark space needed */
					alloc_len -= alloc_len % alignment;
				}

				if (alloc_len > 0) {
					free_ext->ext_offset -=
					    alloc_ext->ext_length;
					free_ext->ext_length +=
					    alloc_ext->ext_length;

					meta_sp_alloc_by_ext(sp, np, head,
					    free_ext, free_ext->ext_offset,
					    alloc_ext->ext_length + alloc_len,
					    last_seq);

					/*
					 * now remove the original allocated
					 * node.  We may have overlapping
					 * extents for a short time before
					 * this node is removed.
					 */
					meta_sp_list_remove(head, alloc_ext);
					len -= alloc_len;
				}
			}
			last_seq++;
		}

		if (len == 0LL)
			goto out;

		/*
		 * Next, see if we can find a single allocation for
		 * the remainder.  This may make fragmentation worse
		 * in some cases, but there's no good way to allocate
		 * that doesn't have a highly fragmented corner case.
		 */
		for (free_ext = *head; free_ext != NULL;
		    free_ext = free_ext->ext_next) {
			sp_ext_offset_t	a_offset;
			sp_ext_offset_t	a_length;

			if (free_ext->ext_type != EXTTYP_FREE)
				continue;

			/*
			 * The length test should include space for
			 * the watermark
			 */

			a_offset = free_ext->ext_offset;
			a_length = free_ext->ext_length;

			if (alignment > 0) {

				/*
				 * Shortcut for extents that have been
				 * previously added to pad out the
				 * data space
				 */
				if (a_length < alignment) {
					continue;
				}

				/*
				 * Round up so the data space begins
				 * on a properly aligned boundary.
				 */
				a_offset += alignment -
				    (a_offset % alignment) - MD_SP_WMSIZE;

				/*
				 * This is only necessary in case the
				 * watermark size is ever greater than
				 * one.  It'll never happen, of
				 * course; we'll get rid of watermarks
				 * before we make 'em bigger.
				 */
				if (a_offset < free_ext->ext_offset) {
					a_offset += alignment;
				}

				/*
				 * Adjust the length to account for
				 * the space lost above (if any)
				 */
				a_length -=
				    (a_offset - free_ext->ext_offset);
			}

			if (a_length >= len + MD_SP_WMSIZE) {
				meta_sp_alloc_by_ext(sp, np, head,
				    free_ext, a_offset,
				    len + MD_SP_WMSIZE, last_seq);

				len = 0LL;
				numexts++;
				break;
			}
		}

		if (len == 0LL)
			goto out;


		/*
		 * If the request could not be satisfied by extending
		 * the last extent or by a single extent, then put
		 * multiple smaller extents together until the request
		 * is satisfied.
		 */
		for (free_ext = *head; (free_ext != NULL) && (len > 0);
		    free_ext = free_ext->ext_next) {
			sp_ext_offset_t a_offset;
			sp_ext_length_t a_length;

			if (free_ext->ext_type != EXTTYP_FREE)
				continue;

			a_offset = free_ext->ext_offset;
			a_length = free_ext->ext_length;

			if (alignment > 0) {

				/*
				 * Shortcut for extents that have been
				 * previously added to pad out the
				 * data space
				 */
				if (a_length < alignment) {
					continue;
				}

				/*
				 * Round up so the data space begins
				 * on a properly aligned boundary.
				 */
				a_offset += alignment -
				    (a_offset % alignment) - MD_SP_WMSIZE;

				/*
				 * This is only necessary in case the
				 * watermark size is ever greater than
				 * one.  It'll never happen, of
				 * course; we'll get rid of watermarks
				 * before we make 'em bigger.
				 */
				if (a_offset < free_ext->ext_offset) {
					a_offset += alignment;
				}

				/*
				 * Adjust the length to account for
				 * the space lost above (if any)
				 */
				a_length -=
				    (a_offset - free_ext->ext_offset);

				/*
				 * Adjust the length to be properly
				 * aligned if it is NOT to be the
				 * last extent in the soft partition.
				 */
				if ((a_length - MD_SP_WMSIZE) < len)
					a_length -=
					    (a_length - MD_SP_WMSIZE)
					    % alignment;
			}

			alloc_len = MIN(len, a_length - MD_SP_WMSIZE);
			if (alloc_len == 0)
				continue;

			/*
			 * meta_sp_alloc_by_ext() expects the
			 * allocation length to include the watermark
			 * size, which is why we don't simply pass in
			 * alloc_len here.
			 */
			meta_sp_alloc_by_ext(sp, np, head, free_ext,
			    a_offset, MIN(len + MD_SP_WMSIZE, a_length),
			    last_seq);

			len -= alloc_len;
			numexts++;
			last_seq++;
		}


		/*
		 * If there was not enough space we can throw it all
		 * away since no real work has been done yet.
		 */
		if (len != 0) {
			meta_sp_list_free(head);
			return (-1);
		}
	}

	/*
	 * Otherwise, the literal "all" was specified: allocate all
	 * available free space.  Don't bother with alignment.
	 */
	else {
		/* First, extend the last extent if this is a grow */
		if (last_off != 0LL) {
			alloc_ext =
			    meta_sp_list_find(*head, last_off);
			assert(alloc_ext != NULL);

			last_seq = alloc_ext->ext_seq;

			free_ext = meta_sp_list_find(*head,
			    alloc_ext->ext_offset +
			    alloc_ext->ext_length);

			/*
			 * If a free extent follows our last allocated
			 * extent, then remove the last allocated
			 * extent and increase the size of the free
			 * extent to overlap it, then allocate the
			 * total space from the new free extent.
			 */
			if (free_ext != NULL &&
			    free_ext->ext_type == EXTTYP_FREE) {
				assert(free_ext->ext_offset ==
				    alloc_ext->ext_offset +
				    alloc_ext->ext_length);

				len = alloc_len =
				    free_ext->ext_length;

				free_ext->ext_offset -=
				    alloc_ext->ext_length;
				free_ext->ext_length +=
				    alloc_ext->ext_length;

				meta_sp_alloc_by_ext(sp, np, head,
				    free_ext, free_ext->ext_offset,
				    alloc_ext->ext_length + alloc_len,
				    last_seq);

				/*
				 * now remove the original allocated
				 * node.  We may have overlapping
				 * extents for a short time before
				 * this node is removed.
				 */
				meta_sp_list_remove(head, alloc_ext);
			}

			last_seq++;
		}

		/* Next, grab all remaining free space */
		for (free_ext = *head; free_ext != NULL;
		    free_ext = free_ext->ext_next) {

			if (free_ext->ext_type == EXTTYP_FREE) {
				alloc_len =
				    free_ext->ext_length - MD_SP_WMSIZE;
				if (alloc_len == 0)
					continue;

				/*
				 * meta_sp_alloc_by_ext() expects the
				 * allocation length to include the
				 * watermark size, which is why we
				 * don't simply pass in alloc_len
				 * here.
				 */
				meta_sp_alloc_by_ext(sp, np, head,
				    free_ext, free_ext->ext_offset,
				    free_ext->ext_length,
				    last_seq);

				len += alloc_len;
				numexts++;
				last_seq++;
			}
		}
	}

out:
	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_sp_alloc_by_len: Extent list after "
		    "allocation:\n");
		meta_sp_list_dump(*head);
	}

	if (*lp == 0) {
		*lp = len;

		/*
		 * Make sure the callers hit a no space error if we
		 * didn't actually find anything.
		 */
		if (len == 0) {
			return (-1);
		}
	}

	return (numexts);
}

/*
 * FUNCTION:	meta_sp_alloc_by_list()
 * INPUT:	sp	- the set name for the device the node belongs to
 *		np	- the name of the device the node belongs to
 *		head	- the head of the list, must be NULL for empty list
 *		oblist	- an extent list containing requested nodes to allocate
 * OUTPUT:	head	- the new head pointer
 * RETURNS:	int	- -1 if error, the number of new extents on success
 * PURPOSE:	allocates extents from free space to satisfy the requested
 *		extent list.  This is primarily used for the -o/-b options
 *		where the user may specifically request extents to allocate.
 *		Each extent in the oblist must be a subset (inclusive) of a
 *		free extent and may not overlap each other.  This
 *		function sets the EXTFLG_UPDATE flag for each node that
 *		requires a watermark update after allocating.
 */
static int
meta_sp_alloc_by_list(
	mdsetname_t	*sp,
	mdname_t	*np,
	sp_ext_node_t	**head,
	sp_ext_node_t	*oblist
)
{
	sp_ext_node_t	*ext;
	sp_ext_node_t	*free_ext;
	uint_t		numexts = 0;

	for (ext = oblist; ext != NULL; ext = ext->ext_next) {

		free_ext = meta_sp_list_find(*head,
		    ext->ext_offset - MD_SP_WMSIZE);

		/* Make sure the allocation is within the free extent */
		if ((free_ext == NULL) ||
		    (ext->ext_offset + ext->ext_length >
		    free_ext->ext_offset + free_ext->ext_length) ||
		    (free_ext->ext_type != EXTTYP_FREE))
			return (-1);

		meta_sp_alloc_by_ext(sp, np, head, free_ext,
		    ext->ext_offset - MD_SP_WMSIZE,
		    ext->ext_length + MD_SP_WMSIZE, ext->ext_seq);

		numexts++;
	}

	assert(meta_sp_list_overlaps(*head) == 0);

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_sp_alloc_by_list: Extent list after "
		    "allocation:\n");
		meta_sp_list_dump(*head);
	}

	return (numexts);
}

/*
 * **************************************************************************
 *                     Extent List Population Functions                     *
 * **************************************************************************
 */

/*
 * FUNCTION:	meta_sp_extlist_from_namelist()
 * INPUT:	sp	- the set name for the device the node belongs to
 *		spnplp	- the namelist of soft partitions to build a list from
 * OUTPUT:	extlist	- the extent list built from the SPs in the namelist
 *		ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 on success
 * PURPOSE:	builds an extent list representing the soft partitions
 *		specified in the namelist.  Each extent in each soft
 *		partition is added to the list with the type EXTTYP_ALLOC.
 *		The EXTFLG_UPDATE flag is not set on any nodes.  Each
 *		extent in the list includes the space occupied by the
 *		watermark, which is not included in the unit structures.
 */
static int
meta_sp_extlist_from_namelist(
	mdsetname_t	*sp,
	mdnamelist_t	*spnlp,
	sp_ext_node_t	**extlist,
	md_error_t	*ep
)
{
	int		extn;
	md_sp_t		*msp;		/* unit structure of the sp's */
	mdnamelist_t	*namep;

	assert(sp != NULL);

	/*
	 * Now go through the soft partitions and add a node to the used
	 * list for each allocated extent.
	 */
	for (namep = spnlp; namep != NULL; namep = namep->next) {
		mdname_t	*curnp = namep->namep;

		/* get the unit structure */
		if ((msp = meta_get_sp_common(sp, curnp, 0, ep)) == NULL)
			return (-1);

		for (extn = 0; (extn < msp->ext.ext_len); extn++) {
			md_sp_ext_t	*extp = &msp->ext.ext_val[extn];

			/*
			 * subtract from offset and add to the length
			 * to account for the watermark, which is not
			 * contained in the extents in the unit structure.
			 */
			meta_sp_list_insert(sp, curnp, extlist,
			    extp->poff - MD_SP_WMSIZE, extp->len + MD_SP_WMSIZE,
			    EXTTYP_ALLOC, extn, 0, meta_sp_cmp_by_offset);
		}
	}
	return (0);
}

/*
 * FUNCTION:	meta_sp_extlist_from_wm()
 * INPUT:	sp	- the set name for the device the node belongs to
 *		compnp	- the name of the device to scan watermarks on
 * OUTPUT:	extlist	- the extent list built from the SPs in the namelist
 *		ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 on success
 * PURPOSE:	builds an extent list representing the soft partitions
 *		specified in the namelist.  Each extent in each soft
 *		partition is added to the list with the type EXTTYP_ALLOC.
 *		The EXTFLG_UPDATE flag is not set on any nodes.  Each
 *		extent in the list includes the space occupied by the
 *		watermark, which is not included in the unit structures.
 */
static int
meta_sp_extlist_from_wm(
	mdsetname_t	*sp,
	mdname_t	*compnp,
	sp_ext_node_t	**extlist,
	ext_cmpfunc_t	compare,
	md_error_t	*ep
)
{
	mp_watermark_t	wm;
	mdname_t	*np = NULL;
	mdsetname_t	*spsetp = NULL;
	sp_ext_offset_t	cur_off;
	md_set_desc	*sd;
	int		init = 0;
	mdkey_t		key;
	minor_t		mnum;

	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
	}

	if ((cur_off = meta_sp_get_start(sp, compnp, ep)) == MD_DISKADDR_ERROR)
		return (-1);

	for (;;) {
		if (meta_sp_read_wm(sp, compnp, &wm, cur_off, ep) != 0) {
			return (-1);
		}

		/* get the set and name pointers */
		if (strcmp(wm.wm_setname, MD_SP_LOCALSETNAME) != 0) {
			if ((spsetp = metasetname(wm.wm_setname, ep)) == NULL) {
				return (-1);
			}
		}

		/*
		 * For the MN set, meta_init_make_device needs to
		 * be run on all the nodes so the entries for the
		 * softpart device name and its comp can be created
		 * in the same order in the replica namespace.  If
		 * we have it run on mdmn_do_iocset then the mddbs
		 * will be out of sync between master node and slave
		 * nodes.
		 */
		if (strcmp(wm.wm_mdname, MD_SP_FREEWMNAME) != 0) {

			if (!metaislocalset(sp) && MD_MNSET_DESC(sd)) {
				md_mn_msg_addmdname_t	*send_params;
				int			result;
				md_mn_result_t		*resp = NULL;
				int			message_size;

				message_size =  sizeof (*send_params) +
				    strlen(wm.wm_mdname) + 1;
				send_params = Zalloc(message_size);
				send_params->addmdname_setno = sp->setno;
				(void) strcpy(&send_params->addmdname_name[0],
				    wm.wm_mdname);
				result = mdmn_send_message(sp->setno,
				    MD_MN_MSG_ADDMDNAME,
				    MD_MSGF_PANIC_WHEN_INCONSISTENT,
				    (char *)send_params, message_size, &resp,
				    ep);
				Free(send_params);
				if (resp != NULL) {
					if (resp->mmr_exitval != 0) {
						free_result(resp);
						return (-1);
					}
					free_result(resp);
				}
				if (result != 0)
					return (-1);
			} else {

				if (!is_existing_meta_hsp(sp, wm.wm_mdname)) {
					if ((key = meta_init_make_device(&sp,
					    wm.wm_mdname, ep)) <= 0) {
						return (-1);
					}
					init = 1;
				}
			}

			np = metaname(&spsetp, wm.wm_mdname, META_DEVICE, ep);
			if (np == NULL) {
				if (init) {
					if (meta_getnmentbykey(sp->setno,
					    MD_SIDEWILD, key, NULL, &mnum,
					    NULL, ep) != NULL) {
						(void) metaioctl(MD_IOCREM_DEV,
						    &mnum, ep, NULL);
					}
					(void) del_self_name(sp, key, ep);
				}
				return (-1);
			}
		}

		/* insert watermark into extent list */
		meta_sp_list_insert(spsetp, np, extlist, cur_off,
		    wm.wm_length + MD_SP_WMSIZE, wm.wm_type, wm.wm_seq,
		    EXTFLG_UPDATE, compare);

		/* if we see the end watermark, we're done */
		if (wm.wm_type == EXTTYP_END)
			break;

		cur_off += wm.wm_length + 1;

		/* clear out set and name pointers for next iteration */
		np = NULL;
		spsetp = NULL;
	}

	return (0);
}

/*
 * **************************************************************************
 *                        Print (metastat) Functions                        *
 * **************************************************************************
 */

/*
 * FUNCTION:	meta_sp_short_print()
 * INPUT:	msp	- the unit structure to display
 *		fp	- the file pointer to send output to
 *		options	- print options from the command line processor
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 on success
 * PURPOSE:	display a short report of the soft partition in md.tab
 *		form, primarily used for metastat -p.
 */
static int
meta_sp_short_print(
	md_sp_t		*msp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	int	extn;

	if (options & PRINT_LARGEDEVICES) {
		if ((msp->common.revision & MD_64BIT_META_DEV) == 0)
			return (0);
	}

	if (options & PRINT_FN) {
		if ((msp->common.revision & MD_FN_META_DEV) == 0)
			return (0);
	}

	/* print name and -p */
	if (fprintf(fp, "%s -p", msp->common.namep->cname) == EOF)
		return (mdsyserror(ep, errno, fname));

	/* print the component */
	/*
	 * Always print the full path name
	 */
	if (fprintf(fp, " %s", msp->compnamep->rname) == EOF)
		return (mdsyserror(ep, errno, fname));

	/* print out each extent */
	for (extn = 0; (extn < msp->ext.ext_len); extn++) {
		md_sp_ext_t	*extp = &msp->ext.ext_val[extn];
		if (fprintf(fp, " -o %llu -b %llu ", extp->poff,
		    extp->len) == EOF)
			return (mdsyserror(ep, errno, fname));
	}

	if (fprintf(fp, "\n") == EOF)
		return (mdsyserror(ep, errno, fname));

	/* success */
	return (0);
}

/*
 * FUNCTION:	meta_sp_status_to_name()
 * INPUT:	xsp_status	- the status value to convert to a string
 *		tstate		- transient errored device state. If set the
 *				  device is Unavailable
 * OUTPUT:	none
 * RETURNS:	char *	- a pointer to the string representing the status value
 * PURPOSE:	return an internationalized string representing the
 *		status value for a soft partition.  The strings are
 *		strdup'd and must be freed by the caller.
 */
static char *
meta_sp_status_to_name(
	xsp_status_t	xsp_status,
	uint_t		tstate
)
{
	char *rval = NULL;

	/*
	 * Check to see if we have MD_INACCESSIBLE set. This is the only valid
	 * value for an 'Unavailable' return. tstate can be set because of
	 * other multi-node reasons (e.g. ABR being set)
	 */
	if (tstate & MD_INACCESSIBLE) {
		return (Strdup(dgettext(TEXT_DOMAIN, "Unavailable")));
	}

	switch (xsp_status) {
	case MD_SP_CREATEPEND:
		rval = Strdup(dgettext(TEXT_DOMAIN, "Creating"));
		break;
	case MD_SP_GROWPEND:
		rval = Strdup(dgettext(TEXT_DOMAIN, "Growing"));
		break;
	case MD_SP_DELPEND:
		rval = Strdup(dgettext(TEXT_DOMAIN, "Deleting"));
		break;
	case MD_SP_OK:
		rval = Strdup(dgettext(TEXT_DOMAIN, "Okay"));
		break;
	case MD_SP_ERR:
		rval = Strdup(dgettext(TEXT_DOMAIN, "Errored"));
		break;
	case MD_SP_RECOVER:
		rval = Strdup(dgettext(TEXT_DOMAIN, "Recovering"));
		break;
	}

	if (rval == NULL)
		rval = Strdup(dgettext(TEXT_DOMAIN, "Invalid"));

	return (rval);
}

/*
 * FUNCTION:	meta_sp_report()
 * INPUT:	sp	- the set name for the unit being displayed
 *		msp	- the unit structure to display
 *		nlpp	- pass back the large devs
 *		fp	- the file pointer to send output to
 *		options	- print options from the command line processor
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 on success
 * PURPOSE:	print a full report of the device specified
 */
static int
meta_sp_report(
	mdsetname_t	*sp,
	md_sp_t		*msp,
	mdnamelist_t	**nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	uint_t		extn;
	char		*status;
	char		*devid = "";
	mdname_t	*didnp = NULL;
	ddi_devid_t	dtp;
	int		len;
	uint_t		tstate = 0;

	if (options & PRINT_LARGEDEVICES) {
		if ((msp->common.revision & MD_64BIT_META_DEV) == 0) {
			return (0);
		} else {
			if (meta_getdevs(sp, msp->common.namep, nlpp, ep) != 0)
				return (-1);
		}
	}

	if (options & PRINT_FN) {
		if ((msp->common.revision & MD_FN_META_DEV) == 0) {
			return (0);
		} else {
			if (meta_getdevs(sp, msp->common.namep, nlpp, ep) != 0)
				return (-1);
		}
	}

	if (options & PRINT_HEADER) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN, "%s: Soft Partition\n"),
		    msp->common.namep->cname) == EOF)
			return (mdsyserror(ep, errno, fname));
	}

	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Device: %s\n"),
	    msp->compnamep->cname) == EOF)
		return (mdsyserror(ep, errno, fname));

	/* Determine if device is available before displaying status */
	if (metaismeta(msp->common.namep)) {
		if (meta_get_tstate(msp->common.namep->dev, &tstate, ep) != 0)
			return (-1);
	}
	status = meta_sp_status_to_name(msp->status, tstate & MD_DEV_ERRORED);

	/* print out "State" to be consistent with other metadevices */
	if (tstate & MD_ABR_CAP) {
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    State: %s - Application Based Recovery (ABR)\n"),
		    status) == EOF) {
			Free(status);
			return (mdsyserror(ep, errno, fname));
		}
	} else {
		if (fprintf(fp, dgettext(TEXT_DOMAIN,
		    "    State: %s\n"), status) == EOF) {
			Free(status);
			return (mdsyserror(ep, errno, fname));
		}
	}
	free(status);

	if (fprintf(fp, dgettext(TEXT_DOMAIN, "    Size: %llu blocks (%s)\n"),
	    msp->common.size,
	    meta_number_to_string(msp->common.size, DEV_BSIZE)) == EOF)
		return (mdsyserror(ep, errno, fname));

	/* print component details */
	if (! metaismeta(msp->compnamep)) {
		diskaddr_t	start_blk;
		int		has_mddb;
		char		*has_mddb_str;

		/* print header */
		/*
		 * Building a format string on the fly that will
		 * be used in (f)printf. This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		len = strlen(msp->compnamep->cname);
		len = max(len, strlen(dgettext(TEXT_DOMAIN, "Device")));
		len += 2;
		if (fprintf(fp,
		    "\t%-*.*s %-12.12s %-5.5s %s\n",
		    len, len,
		    dgettext(TEXT_DOMAIN, "Device"),
		    dgettext(TEXT_DOMAIN, "Start Block"),
		    dgettext(TEXT_DOMAIN, "Dbase"),
		    dgettext(TEXT_DOMAIN, "Reloc")) == EOF) {
			return (mdsyserror(ep, errno, fname));
		}


		/* get info */
		if ((start_blk = meta_sp_get_start(sp, msp->compnamep, ep)) ==
		    MD_DISKADDR_ERROR)
			return (-1);

		if ((has_mddb = metahasmddb(sp, msp->compnamep, ep)) < 0)
			return (-1);

		if (has_mddb)
			has_mddb_str = dgettext(TEXT_DOMAIN, "Yes");
		else
			has_mddb_str = dgettext(TEXT_DOMAIN, "No");

		/* populate the key in the name_p structure */
		didnp = metadevname(&sp, msp->compnamep->dev, ep);
		if (didnp == NULL) {
			return (-1);
		}

		/* determine if devid does NOT exist */
		if (options & PRINT_DEVID) {
			if ((dtp = meta_getdidbykey(sp->setno,
			    getmyside(sp, ep), didnp->key, ep)) == NULL)
				devid = dgettext(TEXT_DOMAIN, "No ");
			else {
				devid = dgettext(TEXT_DOMAIN, "Yes");
				free(dtp);
			}
		}

		/* print info */
		/*
		 * This allows the length
		 * of the ctd to vary from small to large without
		 * looking horrible.
		 */
		if (fprintf(fp, "\t%-*s %8lld     %-5.5s %s\n",
		    len, msp->compnamep->cname,
		    start_blk, has_mddb_str, devid) == EOF) {
			return (mdsyserror(ep, errno, fname));
		}
		(void) fprintf(fp, "\n");
	}


	/* print the headers */
	if (fprintf(fp, "\t%6.6s %24.24s %24.24s\n",
	    dgettext(TEXT_DOMAIN, "Extent"),
	    dgettext(TEXT_DOMAIN, "Start Block"),
	    dgettext(TEXT_DOMAIN, "Block count")) == EOF)
		return (mdsyserror(ep, errno, fname));

	/* print out each extent */
	for (extn = 0; (extn < msp->ext.ext_len); extn++) {
		md_sp_ext_t	*extp = &msp->ext.ext_val[extn];

		/* If PRINT_TIMES option is ever supported, add output here */
		if (fprintf(fp, "\t%6u %24llu %24llu\n",
		    extn, extp->poff, extp->len) == EOF)
			return (mdsyserror(ep, errno, fname));
	}

	/* separate records with a newline */
	(void) fprintf(fp, "\n");
	return (0);
}

/*
 * FUNCTION:	meta_sp_print()
 * INPUT:	sp	- the set name for the unit being displayed
 *		np	- the name of the device to print
 *		fname	- ??? not used
 *		fp	- the file pointer to send output to
 *		options	- print options from the command line processor
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 on success
 * PURPOSE:	print a full report of the device specified by metastat.
 *		This is the main entry point for printing.
 */
int
meta_sp_print(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdnamelist_t	**nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	md_error_t	*ep
)
{
	md_sp_t		*msp;
	md_unit_t	*mdp;
	int		rval = 0;

	/* should always have the same set */
	assert(sp != NULL);

	/* print all the soft partitions */
	if (np == NULL) {
		mdnamelist_t	*nlp = NULL;
		mdnamelist_t	*p;
		int		cnt;

		if ((cnt = meta_get_sp_names(sp, &nlp, options, ep)) < 0)
			return (-1);
		else if (cnt == 0)
			return (0);

		/* recusively print them out */
		for (p = nlp; (p != NULL); p = p->next) {
			mdname_t	*curnp = p->namep;

			/*
			 * one problem with the rval of -1 here is that
			 * the error gets "lost" when the next device is
			 * printed, but we want to print them all anyway.
			 */
			rval = meta_sp_print(sp, curnp, nlpp, fname, fp,
			    options, ep);
		}

		/* clean up, return success */
		metafreenamelist(nlp);
		return (rval);
	}

	/* get the unit structure */
	if ((msp = meta_get_sp_common(sp, np,
	    ((options & PRINT_FAST) ? 1 : 0), ep)) == NULL)
		return (-1);

	/* check for parented */
	if ((! (options & PRINT_SUBDEVS)) &&
	    (MD_HAS_PARENT(msp->common.parent))) {
		return (0);
	}

	/* print appropriate detail */
	if (options & PRINT_SHORT) {
		if (meta_sp_short_print(msp, fname, fp, options, ep) != 0)
			return (-1);
	} else {
		if (meta_sp_report(sp, msp, nlpp, fname, fp, options, ep) != 0)
			return (-1);
	}

	/*
	 * Print underlying metadevices if they are parented to us and
	 * if the info for the underlying metadevice has not been printed.
	 */
	if (metaismeta(msp->compnamep)) {
		/* get the unit structure for the subdevice */
		if ((mdp = meta_get_mdunit(sp, msp->compnamep, ep)) == NULL)
			return (-1);

		/* If info not already printed, recurse */
		if (!BT_TEST(sp_parent_printed, MD_MIN2UNIT(MD_SID(mdp)))) {
			if (meta_print_name(sp, msp->compnamep, nlpp, fname, fp,
			    (options | PRINT_HEADER | PRINT_SUBDEVS),
			    NULL, ep) != 0) {
				return (-1);
			}
			BT_SET(sp_parent_printed, MD_MIN2UNIT(MD_SID(mdp)));
		}
	}
	return (0);
}

/*
 * **************************************************************************
 *                     Watermark Manipulation Functions                     *
 * **************************************************************************
 */

/*
 * FUNCTION:	meta_sp_get_start()
 * INPUT:	sp	- the operating set
 *		np 	- device upon which the sp is being built
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	daddr_t	- -1 if error, otherwise the start block
 * PURPOSE:	Encapsulate the determination of the start block of the
 *		device upon which the sp is built or being built.
 */
static diskaddr_t
meta_sp_get_start(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	daddr_t		start_block;

	if ((start_block = metagetstart(sp, np, ep)) != MD_DISKADDR_ERROR)
		start_block += MD_SP_START;

	return (start_block);
}

/*
 * FUNCTION:	meta_sp_update_wm()
 * INPUT:	sp	- the operating set
 *		msp	- a pointer to the XDR unit structure
 *		extlist	- the extent list specifying watermarks to update
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 on success
 * PURPOSE:	steps backwards through the extent list updating
 *		watermarks for all extents with the EXTFLG_UPDATE flag
 *		set.  Writing the watermarks guarantees consistency when
 *		extents must be broken into pieces since the original
 *		watermark will be the last to be updated, and will be
 *		changed to point to a new watermark that is already
 *		known to be consistent.  If one of the writes fails, the
 *		original watermark stays intact and none of the changes
 *		are realized.
 */
static int
meta_sp_update_wm(
	mdsetname_t	*sp,
	md_sp_t		*msp,
	sp_ext_node_t	*extlist,
	md_error_t	*ep
)
{
	sp_ext_node_t	*ext;
	sp_ext_node_t	*tail;
	mp_watermark_t	*wmp, *watermarks;
	xsp_offset_t	*osp, *offsets;
	int		update_count = 0;
	int		rval = 0;
	md_unit_t	*mdp;
	md_sp_update_wm_t	update_params;

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_sp_update_wm: Updating watermarks:\n");
		meta_sp_list_dump(extlist);
	}

	/*
	 * find the last node so we can write the watermarks backwards
	 * and count watermarks to update so we can allocate space
	 */
	for (ext = extlist; ext != NULL; ext = ext->ext_next) {
		if ((ext->ext_flags & EXTFLG_UPDATE) != 0) {
			update_count++;
		}

		if (ext->ext_next == NULL) {
			tail = ext;
		}
	}
	ext = tail;

	wmp = watermarks =
	    Zalloc(update_count * sizeof (mp_watermark_t));
	osp = offsets =
	    Zalloc(update_count * sizeof (sp_ext_offset_t));

	while (ext != NULL) {
		if ((ext->ext_flags & EXTFLG_UPDATE) != 0) {
			/* update watermark */
			wmp->wm_magic = MD_SP_MAGIC;
			wmp->wm_version = MD_SP_VERSION;
			wmp->wm_type = ext->ext_type;
			wmp->wm_seq = ext->ext_seq;
			wmp->wm_length = ext->ext_length - MD_SP_WMSIZE;

			/* fill in the volume name and set name */
			if (ext->ext_namep != NULL)
				(void) strcpy(wmp->wm_mdname,
				    ext->ext_namep->cname);
			else
				(void) strcpy(wmp->wm_mdname, MD_SP_FREEWMNAME);
			if (ext->ext_setp != NULL &&
			    ext->ext_setp->setno != MD_LOCAL_SET)
				(void) strcpy(wmp->wm_setname,
				    ext->ext_setp->setname);
			else
				(void) strcpy(wmp->wm_setname,
				    MD_SP_LOCALSETNAME);

			/* Generate the checksum */
			wmp->wm_checksum = 0;
			crcgen((uchar_t *)wmp, (uint_t *)&wmp->wm_checksum,
			    sizeof (*wmp), NULL);

			/* record the extent offset */
			*osp = ext->ext_offset;

			/* Advance the placeholders */
			osp++; wmp++;
		}
		ext = ext->ext_prev;
	}

	mdp = meta_get_mdunit(sp, msp->common.namep, ep);
	if (mdp == NULL) {
		rval = -1;
		goto out;
	}

	(void) memset(&update_params, 0, sizeof (update_params));
	update_params.mnum = MD_SID(mdp);
	update_params.count = update_count;
	update_params.wmp = (uintptr_t)watermarks;
	update_params.osp = (uintptr_t)offsets;
	MD_SETDRIVERNAME(&update_params, MD_SP,
	    MD_MIN2SET(update_params.mnum));

	if (metaioctl(MD_IOC_SPUPDATEWM, &update_params,
	    &update_params.mde, msp->common.namep->cname) != 0) {
		(void) mdstealerror(ep, &update_params.mde);
		rval = -1;
		goto out;
	}

out:
	Free(watermarks);
	Free(offsets);

	return (rval);
}

/*
 * FUNCTION:	meta_sp_clear_wm()
 * INPUT:	sp	- the operating set
 *		msp	- the unit structure for the soft partition to clear
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 on success
 * PURPOSE:	steps through the extents for a soft partition unit and
 *		creates an extent list designed to mark all of the
 *		watermarks for those extents as free.  The extent list
 *		is then passed to meta_sp_update_wm() to actually write
 *		the watermarks out.
 */
static int
meta_sp_clear_wm(
	mdsetname_t	*sp,
	md_sp_t		*msp,
	md_error_t	*ep
)
{
	sp_ext_node_t	*extlist = NULL;
	int		numexts = msp->ext.ext_len;
	uint_t		i;
	int		rval = 0;

	/* for each watermark must set the flag to SP_FREE */
	for (i = 0; i < numexts; i++) {
		md_sp_ext_t	*extp = &msp->ext.ext_val[i];

		meta_sp_list_insert(NULL, NULL, &extlist,
		    extp->poff - MD_SP_WMSIZE, extp->len + MD_SP_WMSIZE,
		    EXTTYP_FREE, 0, EXTFLG_UPDATE, meta_sp_cmp_by_offset);
	}

	/* update watermarks */
	rval = meta_sp_update_wm(sp, msp, extlist, ep);

	meta_sp_list_free(&extlist);
	return (rval);
}

/*
 * FUNCTION:	meta_sp_read_wm()
 * INPUT:	sp	- setname for component
 *		compnp	- mdname_t for component
 *		offset	- the offset of the watermark to read (sectors)
 * OUTPUT:	wm	- the watermark structure to read into
 *		ep	- return error pointer
 * RETURNS:	int	- -1 if error, 0 on success
 * PURPOSE:	seeks out to the requested offset and reads a watermark.
 *		It then verifies that the magic number is correct and
 *		that the checksum is valid, returning an error if either
 *		is wrong.
 */
static int
meta_sp_read_wm(
	mdsetname_t	*sp,
	mdname_t	*compnp,
	mp_watermark_t	*wm,
	sp_ext_offset_t	offset,
	md_error_t	*ep
)
{
	md_sp_read_wm_t	read_params;

	/*
	 * make sure block offset does not overflow 2^64 bytes and it's a
	 * multiple of the block size.
	 */
	assert(offset <= (1LL << (64 - DEV_BSHIFT)));
	/* LINTED */
	assert((sizeof (*wm) % DEV_BSIZE) == 0);

	(void) memset(wm, 0, sizeof (*wm));

	(void) memset(&read_params, 0, sizeof (read_params));
	read_params.rdev = compnp->dev;
	read_params.wmp = (uintptr_t)wm;
	read_params.offset = offset;
	MD_SETDRIVERNAME(&read_params, MD_SP, sp->setno);

	if (metaioctl(MD_IOC_SPREADWM, &read_params,
	    &read_params.mde, compnp->cname) != 0) {

		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "Extent header read failed, block %llu.\n"), offset);
		return (mdstealerror(ep, &read_params.mde));
	}

	/* make sure magic number is correct */
	if (wm->wm_magic != MD_SP_MAGIC) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "found incorrect magic number %x, expected %x.\n"),
		    wm->wm_magic, MD_SP_MAGIC);
		/*
		 * Pass NULL for the device name as we don't have
		 * valid watermark contents.
		 */
		return (mdmderror(ep, MDE_SP_BADWMMAGIC, 0, NULL));
	}

	if (crcchk((uchar_t *)wm, (uint_t *)&wm->wm_checksum,
	    sizeof (*wm), NULL)) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "found incorrect checksum %x.\n"),
		    wm->wm_checksum);
		return (mdmderror(ep, MDE_SP_BADWMCRC, 0, wm->wm_mdname));
	}

	return (0);
}

/*
 * **************************************************************************
 *                  Query Functions
 * **************************************************************************
 */

/*
 * IMPORTANT NOTE: This is a static function that assumes that
 *		   its input parameters have been checked and
 *		   have valid values that lie within acceptable
 *		   ranges.
 *
 * FUNCTION:	meta_sp_enough_space()
 * INPUT:	desired_number_of_sps - the number of soft partitions desired;
 *					must be > 0
 *		desired_sp_size - the desired soft partition size in blocks;
 *				  must be > 0
 *		extent_listpp - a reference to a reference to an extent
 *				list that lists the extents on a device;
 *				must be a reference to a reference to a
 *				valid extent list
 *		alignment - the desired data space alignment for the sp's
 * OUTPUT:	boolean_t return value
 * RETURNS:	boolean_t - B_TRUE if there's enough space in the extent
 *			    list to create the desired soft partitions,
 *			    B_FALSE if there's not enough space
 * PURPOSE:	determines whether there's enough free space in an extent
 *		list to allow creation of a set of soft partitions
 */
static boolean_t
meta_sp_enough_space(
	int		desired_number_of_sps,
	blkcnt_t	desired_sp_size,
	sp_ext_node_t	**extent_listpp,
	sp_ext_length_t	alignment
)
{
	boolean_t		enough_space;
	int			number_of_sps;
	int			number_of_extents_used;
	sp_ext_length_t		desired_ext_length = desired_sp_size;

	enough_space = B_TRUE;
	number_of_sps = 0;
	while ((enough_space == B_TRUE) &&
	    (number_of_sps < desired_number_of_sps)) {
		/*
		 * Use the extent allocation algorithm implemented by
		 * meta_sp_alloc_by_len() to test whether the free
		 * extents in the extent list referenced by *extent_listpp
		 * contain enough space to accomodate a soft partition
		 * of size desired_ext_length.
		 *
		 * Repeat the test <desired_number_of_sps> times
		 * or until it fails, whichever comes first,
		 * each time allocating the extents required to
		 * create the soft partition without actually
		 * creating the soft partition.
		 */
		number_of_extents_used = meta_sp_alloc_by_len(
		    TEST_SETNAMEP, TEST_SOFT_PARTITION_NAMEP,
		    extent_listpp, &desired_ext_length,
		    NO_OFFSET, alignment);
		if (number_of_extents_used == -1) {
			enough_space = B_FALSE;
		} else {
			number_of_sps++;
		}
	}
	return (enough_space);
}

/*
 * IMPORTANT NOTE: This is a static function that calls other functions
 *		   that check its mdsetnamep and device_mdnamep
 *		   input parameters, but expects extent_listpp to
 *		   be a initialized to a valid address to which
 *		   it can write a reference to the extent list that
 *		   it creates.
 *
 * FUNCTION:	meta_sp_get_extent_list()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the device for
 *			     which the extents are to be listed
 *		device_mdnamep - a reference to the mdname_t structure
 *				 for the device for which the extents
 *				 are to be listed
 * OUTPUT:	*extent_listpp - a reference to the extent list for
 *				 the device; NULL if the function fails
 *		*ep - the libmeta error encountered, if any
 * RETURNS:	boolean_t - B_TRUE if the function call was successful,
 *			    B_FALSE if not
 * PURPOSE:	gets the extent list for a device
 */
static boolean_t
meta_sp_get_extent_list(
	mdsetname_t	*mdsetnamep,
	mdname_t	*device_mdnamep,
	sp_ext_node_t	**extent_listpp,
	md_error_t	*ep
)
{
	diskaddr_t		device_size_in_blocks;
	mdnamelist_t		*sp_name_listp;
	diskaddr_t		start_block_address_in_blocks;

	*extent_listpp = NULL;
	sp_name_listp = NULL;

	start_block_address_in_blocks = meta_sp_get_start(mdsetnamep,
	    device_mdnamep, ep);
	if (start_block_address_in_blocks == MD_DISKADDR_ERROR) {
		if (getenv(META_SP_DEBUG)) {
			mde_perror(ep,
			    "meta_sp_get_extent_list:meta_sp_get_start");
		}
		return (B_FALSE);
	}

	device_size_in_blocks = metagetsize(device_mdnamep, ep);
	if (device_size_in_blocks == MD_DISKADDR_ERROR) {
		if (getenv(META_SP_DEBUG)) {
			mde_perror(ep,
			    "meta_sp_get_extent_list:metagetsize");
		}
		return (B_FALSE);
	}

	/*
	 * Sanity check: the start block will have skipped an integer
	 * number of cylinders, C.  C will usually be zero.  If (C > 0),
	 * and the disk slice happens to only be C cylinders in total
	 * size, we'll fail this check.
	 */
	if (device_size_in_blocks <=
	    (start_block_address_in_blocks + MD_SP_WMSIZE)) {
		(void) mdmderror(ep, MDE_SP_NOSPACE, 0, device_mdnamep->cname);
		return (B_FALSE);
	}

	/*
	 * After this point, we will have allocated resources, so any
	 * failure returns must be through the supplied "fail" label
	 * to properly deallocate things.
	 */

	/*
	 * Create an empty extent list that starts one watermark past
	 * the start block of the device and ends one watermark before
	 * the end of the device.
	 */
	meta_sp_list_insert(TEST_SETNAMEP, TEST_SOFT_PARTITION_NAMEP,
	    extent_listpp, NO_OFFSET,
	    (sp_ext_length_t)start_block_address_in_blocks,
	    EXTTYP_RESERVED, NO_SEQUENCE_NUMBER, NO_FLAGS,
	    meta_sp_cmp_by_offset);
	meta_sp_list_insert(TEST_SETNAMEP, TEST_SOFT_PARTITION_NAMEP,
	    extent_listpp, (sp_ext_offset_t)(device_size_in_blocks -
	    MD_SP_WMSIZE), MD_SP_WMSIZE, EXTTYP_END, NO_SEQUENCE_NUMBER,
	    NO_FLAGS, meta_sp_cmp_by_offset);

	/*
	 * Get the list of soft partitions that are already on the
	 * device.
	 */
	if (meta_sp_get_by_component(mdsetnamep, device_mdnamep,
	    &sp_name_listp, FORCE_RELOAD_CACHE, ep) < 1) {
		if (getenv(META_SP_DEBUG)) {
			mde_perror(ep,
			    "meta_sp_get_extent_list:meta_sp_get_by_component");
		}
		goto fail;
	}

	if (sp_name_listp != NULL) {
		/*
		 * If there are soft partitions on the device, add the
		 * extents used in them to the extent list.
		 */
		if (meta_sp_extlist_from_namelist(mdsetnamep, sp_name_listp,
		    extent_listpp, ep) == -1) {
			if (getenv(META_SP_DEBUG)) {
				mde_perror(ep, "meta_sp_get_extent_list:"
				    "meta_sp_extlist_from_namelist");
			}
			goto fail;
		}
		metafreenamelist(sp_name_listp);
	}

	/*
	 * Add free extents to the extent list to represent
	 * the remaining regions of free space on the
	 * device.
	 */
	meta_sp_list_freefill(extent_listpp, device_size_in_blocks);
	return (B_TRUE);

fail:
	if (sp_name_listp != NULL) {
		metafreenamelist(sp_name_listp);
	}

	if (*extent_listpp != NULL) {
		/*
		 * meta_sp_list_free sets *extent_listpp to NULL.
		 */
		meta_sp_list_free(extent_listpp);
	}
	return (B_FALSE);
}

/*
 * IMPORTANT NOTE: This is a static function that calls other functions
 *		   that check its mdsetnamep and mddrivenamep
 *		   input parameters, but expects extent_listpp to
 *		   be a initialized to a valid address to which
 *		   it can write a reference to the extent list that
 *		   it creates.
 *
 * FUNCTION:	meta_sp_get_extent_list_for_drive()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the drive for
 *			     which the extents are to be listed
 *		mddrivenamep   - a reference to the mddrivename_t structure
 *				 for the drive for which the extents
 *				 are to be listed
 * OUTPUT:	*extent_listpp - a reference to the extent list for
 *				 the drive; NULL if the function fails
 * RETURNS:	boolean_t - B_TRUE if the function call was successful,
 *			    B_FALSE if not
 * PURPOSE:	gets the extent list for a drive when the entire drive
 *		is to be soft partitioned
 */
static boolean_t
meta_sp_get_extent_list_for_drive(
	mdsetname_t	*mdsetnamep,
	mddrivename_t	*mddrivenamep,
	sp_ext_node_t	**extent_listpp
)
{
	boolean_t		can_use;
	diskaddr_t		free_space;
	md_error_t		mderror;
	mdvtoc_t		proposed_vtoc;
	int			repartition_options;
	int			return_value;
	md_sp_t			test_sp_struct;

	can_use = B_TRUE;
	*extent_listpp = NULL;
	mderror = mdnullerror;
	test_sp_struct.compnamep = metaslicename(mddrivenamep, MD_SLICE0,
	    &mderror);
	if (test_sp_struct.compnamep == NULL) {
		can_use = B_FALSE;
	}

	if (can_use == B_TRUE) {
		mderror = mdnullerror;
		repartition_options = 0;
		return_value = meta_check_sp(mdsetnamep, &test_sp_struct,
		    MDCMD_USE_WHOLE_DISK, &repartition_options, &mderror);
		if (return_value != 0) {
			can_use = B_FALSE;
		}
	}

	if (can_use == B_TRUE) {
		mderror = mdnullerror;
		repartition_options = repartition_options |
		    (MD_REPART_FORCE | MD_REPART_DONT_LABEL);
		return_value = meta_repartition_drive(mdsetnamep, mddrivenamep,
		    repartition_options, &proposed_vtoc, &mderror);
		if (return_value != 0) {
			can_use = B_FALSE;
		}
	}

	if (can_use == B_TRUE) {
		free_space = proposed_vtoc.parts[MD_SLICE0].size;
		if (free_space <= (MD_SP_START + MD_SP_WMSIZE)) {
			can_use = B_FALSE;
		}
	}

	if (can_use == B_TRUE) {
		/*
		 * Create an extent list that starts with
		 * a reserved extent that ends at the start
		 * of the usable space on slice zero of the
		 * proposed VTOC, ends with an extent that
		 * reserves space for a watermark at the end
		 * of slice zero, and contains a single free
		 * extent that occupies the rest of the space
		 * on the slice.
		 *
		 * NOTE:
		 *
		 * Don't use metagetstart() or metagetsize() to
		 * find the usable space.  They query the mdname_t
		 * structure that represents an actual device to
		 * determine the amount of space on the device that
		 * contains metadata and the total amount of space
		 * on the device.  Since this function creates a
		 * proposed extent list that doesn't reflect the
		 * state of an actual device, there's no mdname_t
		 * structure to be queried.
		 *
		 * When a drive is reformatted to prepare for
		 * soft partitioning, all of slice seven is
		 * reserved for metadata, all of slice zero is
		 * available for soft partitioning, and all other
		 * slices on the drive are empty.  The proposed
		 * extent list for the drive therefore contains
		 * only three extents: a reserved extent that ends
		 * at the start of the usable space on slice zero,
		 * a single free extent that occupies all the usable
		 * space on slice zero, and an ending extent that
		 * reserves space for a watermark at the end of
		 * slice zero.
		 */
		meta_sp_list_insert(TEST_SETNAMEP, TEST_SOFT_PARTITION_NAMEP,
		    extent_listpp, NO_OFFSET, (sp_ext_length_t)(MD_SP_START),
		    EXTTYP_RESERVED, NO_SEQUENCE_NUMBER, NO_FLAGS,
		    meta_sp_cmp_by_offset);
		meta_sp_list_insert(TEST_SETNAMEP, TEST_SOFT_PARTITION_NAMEP,
		    extent_listpp, (sp_ext_offset_t)(free_space - MD_SP_WMSIZE),
		    MD_SP_WMSIZE, EXTTYP_END, NO_SEQUENCE_NUMBER, NO_FLAGS,
		    meta_sp_cmp_by_offset);
		meta_sp_list_freefill(extent_listpp, free_space);
	}
	return (can_use);
}

/*
 * FUNCTION:	meta_sp_can_create_sps()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the device for
 *			     which the extents are to be listed
 *		mdnamep - a reference to the mdname_t of the device
 *			  on which the soft parititions are to be created
 *		number_of_sps - the desired number of soft partitions
 *		sp_size - the desired soft partition size
 * OUTPUT:	boolean_t return value
 * RETURNS:	boolean_t - B_TRUE if the soft partitionns can be created,
 *			    B_FALSE if not
 * PURPOSE:	determines whether a set of soft partitions can be created
 *		on a device
 */
boolean_t
meta_sp_can_create_sps(
	mdsetname_t	*mdsetnamep,
	mdname_t	*mdnamep,
	int		number_of_sps,
	blkcnt_t	sp_size
)
{
	sp_ext_node_t	*extent_listp;
	boolean_t	succeeded;
	md_error_t	mde;

	if ((number_of_sps > 0) && (sp_size > 0)) {
		succeeded = meta_sp_get_extent_list(mdsetnamep, mdnamep,
		    &extent_listp, &mde);
	} else {
		succeeded = B_FALSE;
	}

	/*
	 * We don't really care about an error return from the
	 * alignment call; that will just result in passing zero,
	 * which will be interpreted as no alignment.
	 */

	if (succeeded == B_TRUE) {
		succeeded = meta_sp_enough_space(number_of_sps,
		    sp_size, &extent_listp,
		    meta_sp_get_default_alignment(mdsetnamep, mdnamep, &mde));
		meta_sp_list_free(&extent_listp);
	}
	return (succeeded);
}

/*
 * FUNCTION:	meta_sp_can_create_sps_on_drive()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the drive for
 *			     which the extents are to be listed
 *		mddrivenamep - a reference to the mddrivename_t of the drive
 *			       on which the soft parititions are to be created
 *		number_of_sps - the desired number of soft partitions
 *		sp_size - the desired soft partition size
 * OUTPUT:	boolean_t return value
 * RETURNS:	boolean_t - B_TRUE if the soft partitionns can be created,
 *			    B_FALSE if not
 * PURPOSE:	determines whether a set of soft partitions can be created
 *		on a drive if the entire drive is soft partitioned
 */
boolean_t
meta_sp_can_create_sps_on_drive(
	mdsetname_t	*mdsetnamep,
	mddrivename_t	*mddrivenamep,
	int		number_of_sps,
	blkcnt_t	sp_size
)
{
	sp_ext_node_t	*extent_listp;
	boolean_t	succeeded;

	if ((number_of_sps > 0) && (sp_size > 0)) {
		succeeded = meta_sp_get_extent_list_for_drive(mdsetnamep,
		    mddrivenamep, &extent_listp);
	} else {
		succeeded = B_FALSE;
	}

	/*
	 * We don't care about alignment on the space call because
	 * we're specifically dealing with a drive, which will have no
	 * inherent alignment.
	 */

	if (succeeded == B_TRUE) {
		succeeded = meta_sp_enough_space(number_of_sps, sp_size,
		    &extent_listp, SP_UNALIGNED);
		meta_sp_list_free(&extent_listp);
	}
	return (succeeded);
}

/*
 * FUNCTION:	meta_sp_get_free_space()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the device for
 *			     which the free space is to be returned
 *		mdnamep - a reference to the mdname_t of the device
 *			  for which the free space is to be returned
 * OUTPUT:	blkcnt_t return value
 * RETURNS:	blkcnt_t - the number of blocks of free space on the device
 * PURPOSE:	returns the number of blocks of free space on a device
 */
blkcnt_t
meta_sp_get_free_space(
	mdsetname_t	*mdsetnamep,
	mdname_t	*mdnamep
)
{
	sp_ext_node_t		*extent_listp;
	sp_ext_length_t		free_blocks;
	boolean_t		succeeded;
	md_error_t		mde;

	extent_listp = NULL;
	free_blocks = 0;
	succeeded = meta_sp_get_extent_list(mdsetnamep, mdnamep,
	    &extent_listp, &mde);
	if (succeeded == B_TRUE) {
		free_blocks = meta_sp_list_size(extent_listp,
		    EXTTYP_FREE, INCLUDE_WM);
		meta_sp_list_free(&extent_listp);
		if (free_blocks > (10 * MD_SP_WMSIZE)) {
			/*
			 * Subtract a safety margin for watermarks when
			 * computing the number of blocks available for
			 * use.  The actual number of watermarks can't
			 * be calculated without knowing the exact numbers
			 * and sizes of both the free extents and the soft
			 * partitions to be created.  The calculation is
			 * highly complex and error-prone even if those
			 * quantities are known.  The approximate value
			 * 10 * MD_SP_WMSIZE is within a few blocks of the
			 * correct value in all practical cases.
			 */
			free_blocks = free_blocks - (10 * MD_SP_WMSIZE);
		} else {
			free_blocks = 0;
		}
	} else {
		mdclrerror(&mde);
	}

	return (free_blocks);
}

/*
 * FUNCTION:	meta_sp_get_free_space_on_drive()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the drive for
 *			     which the free space is to be returned
 *		mddrivenamep - a reference to the mddrivename_t of the drive
 *			       for which the free space is to be returned
 * OUTPUT:	blkcnt_t return value
 * RETURNS:	blkcnt_t - the number of blocks of free space on the drive
 * PURPOSE:	returns the number of blocks of space usable for soft
 *		partitions on an entire drive, if the entire drive is
 *		soft partitioned
 */
blkcnt_t
meta_sp_get_free_space_on_drive(
	mdsetname_t	*mdsetnamep,
	mddrivename_t	*mddrivenamep
)
{
	sp_ext_node_t		*extent_listp;
	sp_ext_length_t		free_blocks;
	boolean_t		succeeded;

	extent_listp = NULL;
	free_blocks = 0;
	succeeded = meta_sp_get_extent_list_for_drive(mdsetnamep,
	    mddrivenamep, &extent_listp);
	if (succeeded == B_TRUE) {
		free_blocks = meta_sp_list_size(extent_listp,
		    EXTTYP_FREE, INCLUDE_WM);
		meta_sp_list_free(&extent_listp);
		if (free_blocks > (10 * MD_SP_WMSIZE)) {
			/*
			 * Subtract a safety margin for watermarks when
			 * computing the number of blocks available for
			 * use.  The actual number of watermarks can't
			 * be calculated without knowing the exact numbers
			 * and sizes of both the free extents and the soft
			 * partitions to be created.  The calculation is
			 * highly complex and error-prone even if those
			 * quantities are known.  The approximate value
			 * 10 * MD_SP_WMSIZE is within a few blocks of the
			 * correct value in all practical cases.
			 */
			free_blocks = free_blocks - (10 * MD_SP_WMSIZE);
		} else {
			free_blocks = 0;
		}
	}
	return (free_blocks);
}

/*
 * FUNCTION:	meta_sp_get_number_of_possible_sps()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the device for
 *			     which the number of possible soft partitions
 *			     is to be returned
 *		mdnamep - a reference to the mdname_t of the device
 *			  for which the number of possible soft partitions
 *			  is to be returned
 * OUTPUT:	int return value
 * RETURNS:	int - the number of soft partitions of the desired size
 *		      that can be created on the device
 * PURPOSE:	returns the number of soft partitions of a given size
 *		that can be created on a device
 */
int
meta_sp_get_number_of_possible_sps(
	mdsetname_t	*mdsetnamep,
	mdname_t	*mdnamep,
	blkcnt_t	sp_size
)
{
	sp_ext_node_t	*extent_listp;
	int		number_of_possible_sps;
	boolean_t	succeeded;
	md_error_t	mde;
	sp_ext_length_t	alignment;

	extent_listp = NULL;
	number_of_possible_sps = 0;
	if (sp_size > 0) {
		if ((succeeded = meta_sp_get_extent_list(mdsetnamep,
		    mdnamep, &extent_listp, &mde)) == B_FALSE)
			mdclrerror(&mde);
	} else {
		succeeded = B_FALSE;
	}

	if (succeeded == B_TRUE) {
		alignment = meta_sp_get_default_alignment(mdsetnamep,
		    mdnamep, &mde);
	}

	while (succeeded == B_TRUE) {
		/*
		 * Keep allocating space from the extent list
		 * for soft partitions of the desired size until
		 * there's not enough free space left in the list
		 * for another soft partiition of that size.
		 * Add one to the number of possible soft partitions
		 * for each soft partition for which there is
		 * enough free space left.
		 */
		succeeded = meta_sp_enough_space(ONE_SOFT_PARTITION,
		    sp_size, &extent_listp, alignment);
		if (succeeded == B_TRUE) {
			number_of_possible_sps++;
		}
	}
	if (extent_listp != NULL) {
		meta_sp_list_free(&extent_listp);
	}
	return (number_of_possible_sps);
}

/*
 * FUNCTION:	meta_sp_get_number_of_possible_sps_on_drive()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the drive for
 *			     which the number of possible soft partitions
 *			     is to be returned
 *		mddrivenamep - a reference to the mddrivename_t of the drive
 *			       for which the number of possible soft partitions
 *			       is to be returned
 *		sp_size - the size in blocks of the proposed soft partitions
 * OUTPUT:	int return value
 * RETURNS:	int - the number of soft partitions of the desired size
 *		      that can be created on the drive
 * PURPOSE:	returns the number of soft partitions of a given size
 *		that can be created on a drive, if the entire drive is
 *		soft partitioned
 */
int
meta_sp_get_number_of_possible_sps_on_drive(
	mdsetname_t	*mdsetnamep,
	mddrivename_t	*mddrivenamep,
	blkcnt_t	sp_size
)
{
	sp_ext_node_t	*extent_listp;
	int		number_of_possible_sps;
	boolean_t	succeeded;

	extent_listp = NULL;
	number_of_possible_sps = 0;
	if (sp_size > 0) {
		succeeded = meta_sp_get_extent_list_for_drive(mdsetnamep,
		    mddrivenamep, &extent_listp);
	} else {
		succeeded = B_FALSE;
	}
	while (succeeded == B_TRUE) {
		/*
		 * Keep allocating space from the extent list
		 * for soft partitions of the desired size until
		 * there's not enough free space left in the list
		 * for another soft partition of that size.
		 * Add one to the number of possible soft partitions
		 * for each soft partition for which there is
		 * enough free space left.
		 *
		 * Since it's a drive, not a metadevice, make no
		 * assumptions about alignment.
		 */
		succeeded = meta_sp_enough_space(ONE_SOFT_PARTITION,
		    sp_size, &extent_listp, SP_UNALIGNED);
		if (succeeded == B_TRUE) {
			number_of_possible_sps++;
		}
	}
	if (extent_listp != NULL) {
		meta_sp_list_free(&extent_listp);
	}
	return (number_of_possible_sps);
}

/*
 * FUNCTION:	meta_sp_get_possible_sp_size()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the device for
 *			     which the possible soft partition size
 *			     is to be returned
 *		mdnamep - a reference to the mdname_t of the device
 *			  for which the possible soft partition size
 *			  is to be returned
 *		number_of_sps - the desired number of soft partitions
 * OUTPUT:	blkcnt_t return value
 * RETURNS:	blkcnt_t - the possible soft partition size in blocks
 * PURPOSE:	returns the maximum possible size of each of a given number of
 *		soft partitions of equal size that can be created on a device
 */
blkcnt_t
meta_sp_get_possible_sp_size(
	mdsetname_t	*mdsetnamep,
	mdname_t	*mdnamep,
	int		number_of_sps
)
{
	blkcnt_t	free_blocks;
	blkcnt_t	sp_size;
	boolean_t	succeeded;

	sp_size = 0;
	if (number_of_sps > 0) {
		free_blocks = meta_sp_get_free_space(mdsetnamep, mdnamep);
		sp_size = free_blocks / number_of_sps;
		succeeded = meta_sp_can_create_sps(mdsetnamep, mdnamep,
		    number_of_sps, sp_size);
		while ((succeeded == B_FALSE) && (sp_size > 0)) {
			/*
			 * To compensate for space that may have been
			 * occupied by watermarks, reduce sp_size by a
			 * number of blocks equal to the number of soft
			 * partitions desired, and test again to see
			 * whether the desired number of soft partitions
			 * can be created.
			 */
			sp_size = sp_size - ((blkcnt_t)number_of_sps);
			succeeded = meta_sp_can_create_sps(mdsetnamep, mdnamep,
			    number_of_sps, sp_size);
		}
		if (sp_size < 0) {
			sp_size = 0;
		}
	}
	return (sp_size);
}

/*
 * FUNCTION:	meta_sp_get_possible_sp_size_on_drive()
 * INPUT:	mdsetnamep - a reference to the mdsetname_t structure
 *			     for the set containing the drive for
 *			     which the possible soft partition size
 *			     is to be returned
 *		mddrivenamep - a reference to the mddrivename_t of the drive
 *			       for which the possible soft partition size
 *			       is to be returned
 *		number_of_sps - the desired number of soft partitions
 * OUTPUT:	blkcnt_t return value
 * RETURNS:	blkcnt_t - the possible soft partition size in blocks
 * PURPOSE:	returns the maximum possible size of each of a given number of
 *		soft partitions of equal size that can be created on a drive
 *              if the entire drive is soft partitioned
 */
blkcnt_t
meta_sp_get_possible_sp_size_on_drive(
	mdsetname_t	*mdsetnamep,
	mddrivename_t	*mddrivenamep,
	int		number_of_sps
)
{
	blkcnt_t	free_blocks;
	blkcnt_t	sp_size;
	boolean_t	succeeded;

	sp_size = 0;
	if (number_of_sps > 0) {
		free_blocks = meta_sp_get_free_space_on_drive(mdsetnamep,
		    mddrivenamep);
		sp_size = free_blocks / number_of_sps;
		succeeded = meta_sp_can_create_sps_on_drive(mdsetnamep,
		    mddrivenamep, number_of_sps, sp_size);
		while ((succeeded == B_FALSE) && (sp_size > 0)) {
			/*
			 * To compensate for space that may have been
			 * occupied by watermarks, reduce sp_size by a
			 * number of blocks equal to the number of soft
			 * partitions desired, and test again to see
			 * whether the desired number of soft partitions
			 * can be created.
			 */
			sp_size = sp_size - ((blkcnt_t)number_of_sps);
			succeeded = meta_sp_can_create_sps_on_drive(mdsetnamep,
			    mddrivenamep, number_of_sps, sp_size);
		}
		if (sp_size < 0) {
			sp_size = 0;
		}
	}
	return (sp_size);
}

/*
 * **************************************************************************
 *                  Unit Structure Manipulation Functions                   *
 * **************************************************************************
 */

/*
 * FUNCTION:	meta_sp_fillextarray()
 * INPUT:	mp	- the unit structure to fill
 *		extlist	- the list of extents to fill with
 * OUTPUT:	none
 * RETURNS:	void
 * PURPOSE:	fills in the unit structure extent list with the extents
 *		specified by extlist.  Only extents in extlist with the
 *		EXTFLG_UPDATE flag are changed in the unit structure,
 *		and the index into the unit structure is the sequence
 *		number in the extent list.  After all of the nodes have
 *		been updated the virtual offsets in the unit structure
 *		are updated to reflect the new lengths.
 */
static void
meta_sp_fillextarray(
	mp_unit_t	*mp,
	sp_ext_node_t	*extlist
)
{
	int	i;
	sp_ext_node_t	*ext;
	sp_ext_offset_t	curvoff = 0LL;

	assert(mp != NULL);

	/* go through the allocation list and fill in our unit structure */
	for (ext = extlist; ext != NULL; ext = ext->ext_next) {
		if ((ext->ext_type == EXTTYP_ALLOC) &&
		    (ext->ext_flags & EXTFLG_UPDATE) != 0) {
			mp->un_ext[ext->ext_seq].un_poff =
			    ext->ext_offset + MD_SP_WMSIZE;
			mp->un_ext[ext->ext_seq].un_len =
			    ext->ext_length - MD_SP_WMSIZE;
		}
	}

	for (i = 0; i < mp->un_numexts; i++) {
		assert(mp->un_ext[i].un_poff != 0);
		assert(mp->un_ext[i].un_len  != 0);
		mp->un_ext[i].un_voff = curvoff;
		curvoff += mp->un_ext[i].un_len;
	}
}

/*
 * FUNCTION:	meta_sp_createunit()
 * INPUT:	np	- the name of the device to create a unit structure for
 *		compnp	- the name of the device the soft partition is on
 *		extlist	- the extent list to populate the new unit with
 *		numexts	- the number of extents in the extent list
 *		len	- the total size of the soft partition (sectors)
 *		status	- the initial status of the unit structure
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	mp_unit_t * - the new unit structure.
 * PURPOSE:	allocates and fills in a new soft partition unit
 *		structure to be passed to the soft partitioning driver
 *		for creation.
 */
static mp_unit_t *
meta_sp_createunit(
	mdname_t	*np,
	mdname_t	*compnp,
	sp_ext_node_t	*extlist,
	int		numexts,
	sp_ext_length_t	len,
	sp_status_t	status,
	md_error_t	*ep
)
{
	mp_unit_t	*mp;
	uint_t		ms_size;

	ms_size = (sizeof (*mp) - sizeof (mp->un_ext[0])) +
	    (numexts * sizeof (mp->un_ext[0]));

	mp = Zalloc(ms_size);

	/* fill in fields in common unit structure */
	mp->c.un_type = MD_METASP;
	mp->c.un_size = ms_size;
	MD_SID(mp) = meta_getminor(np->dev);
	mp->c.un_total_blocks = len;
	mp->c.un_actual_tb = len;

	/* set up geometry */
	(void) meta_sp_setgeom(np, compnp, mp, ep);

	/* if we're building on metadevice we can't parent */
	if (metaismeta(compnp))
		MD_CAPAB(mp) = MD_CANT_PARENT;
	else
		MD_CAPAB(mp) = MD_CAN_PARENT;

	/* fill soft partition-specific fields */
	mp->un_dev = compnp->dev;
	mp->un_key = compnp->key;

	/* mdname_t start_blk field is not 64-bit! */
	mp->un_start_blk = (sp_ext_offset_t)compnp->start_blk;
	mp->un_status = status;
	mp->un_numexts = numexts;
	mp->un_length = len;

	/* fill in the extent array */
	meta_sp_fillextarray(mp, extlist);

	return (mp);
}

/*
 * FUNCTION:	meta_sp_updateunit()
 * INPUT:	np       - name structure for the metadevice being updated
 *		old_un	 - the original unit structure that is being updated
 *		extlist	 - the extent list to populate the new unit with
 *		grow_len - the amount by which the partition is being grown
 *		numexts	 - the number of extents in the extent list
 *		ep       - return error pointer
 * OUTPUT:	none
 * RETURNS:	mp_unit_t * - the updated unit structure
 * PURPOSE:	allocates and fills in a new soft partition unit structure to
 *		be passed to the soft partitioning driver for creation.  The
 *		old unit structure is first copied in, and then the updated
 *		extents are changed in the new unit structure.  This is
 *		typically used when the size of an existing unit is changed.
 */
static mp_unit_t *
meta_sp_updateunit(
	mdname_t	*np,
	mp_unit_t	*old_un,
	sp_ext_node_t	*extlist,
	sp_ext_length_t	grow_len,
	int		numexts,
	md_error_t	*ep
)
{
	mp_unit_t	*new_un;
	sp_ext_length_t	new_len;
	uint_t		new_size;

	assert(old_un != NULL);
	assert(extlist != NULL);

	/* allocate new unit structure and copy in old unit */
	new_size = (sizeof (*old_un) - sizeof (old_un->un_ext[0])) +
	    ((old_un->un_numexts + numexts) * sizeof (old_un->un_ext[0]));
	new_len = old_un->un_length + grow_len;
	new_un = Zalloc(new_size);
	bcopy(old_un, new_un, old_un->c.un_size);

	/* update size and geometry information */
	new_un->c.un_size = new_size;
	new_un->un_length = new_len;
	new_un->c.un_total_blocks = new_len;
	new_un->c.un_actual_tb = new_len;
	if (meta_adjust_geom((md_unit_t *)new_un, np,
	    old_un->c.un_wr_reinstruct, old_un->c.un_rd_reinstruct,
	    0, ep) != 0) {
		Free(new_un);
		return (NULL);
	}

	/* update extent information */
	new_un->un_numexts += numexts;

	meta_sp_fillextarray(new_un, extlist);

	return (new_un);
}

/*
 * FUNCTION:	meta_get_sp()
 * INPUT:	sp	- the set name for the device to get
 *		np	- the name of the device to get
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	md_sp_t * - the XDR unit structure for the soft partition
 * PURPOSE:	interface to the rest of libmeta for fetching a unit structure
 *		for the named device.  Just a wrapper for meta_get_sp_common().
 */
md_sp_t *
meta_get_sp(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	return (meta_get_sp_common(sp, np, 0, ep));
}

/*
 * FUNCTION:	meta_get_sp_common()
 * INPUT:	sp	- the set name for the device to get
 *		np	- the name of the device to get
 *		fast	- whether to use the cache or not (NOT IMPLEMENTED!)
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	md_sp_t * - the XDR unit structure for the soft partition,
 *			    NULL if np is not a soft partition
 * PURPOSE:	common routine for fetching a soft partition unit structure
 */
md_sp_t *
meta_get_sp_common(
	mdsetname_t	*sp,
	mdname_t	*np,
	int		fast,
	md_error_t	*ep
)
{
	mddrivename_t	*dnp = np->drivenamep;
	char		*miscname;
	mp_unit_t	*mp;
	md_sp_t		*msp;
	int		i;

	/* must have set */
	assert(sp != NULL);

	/* short circuit */
	if (dnp->unitp != NULL) {
		if (dnp->unitp->type != MD_METASP)
			return (NULL);
		return ((md_sp_t *)dnp->unitp);
	}
	/* get miscname and unit */
	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (NULL);

	if (strcmp(miscname, MD_SP) != 0) {
		(void) mdmderror(ep, MDE_NOT_SP, 0, np->cname);
		return (NULL);
	}

	if ((mp = (mp_unit_t *)meta_get_mdunit(sp, np, ep)) == NULL)
		return (NULL);

	assert(mp->c.un_type == MD_METASP);

	/* allocate soft partition */
	msp = Zalloc(sizeof (*msp));

	/* get the common information */
	msp->common.namep = np;
	msp->common.type = mp->c.un_type;
	msp->common.state = mp->c.un_status;
	msp->common.capabilities = mp->c.un_capabilities;
	msp->common.parent = mp->c.un_parent;
	msp->common.size = mp->c.un_total_blocks;
	msp->common.user_flags = mp->c.un_user_flags;
	msp->common.revision = mp->c.un_revision;

	/* get soft partition information */
	if ((msp->compnamep = metakeyname(&sp, mp->un_key, fast, ep)) == NULL)
		goto out;

	/*
	 * Fill in the key and the start block.  Note that the start
	 * block in the unit structure is 64 bits but the name pointer
	 * only supports 32 bits.
	 */
	msp->compnamep->key = mp->un_key;
	msp->compnamep->start_blk = mp->un_start_blk;

	/* fill in status field */
	msp->status = mp->un_status;

	/* allocate the extents */
	msp->ext.ext_val = Zalloc(mp->un_numexts * sizeof (*msp->ext.ext_val));
	msp->ext.ext_len = mp->un_numexts;

	/* do the extents for this soft partition */
	for (i = 0; i < mp->un_numexts; i++) {
		struct mp_ext	*mde = &mp->un_ext[i];
		md_sp_ext_t	*extp = &msp->ext.ext_val[i];

		extp->voff = mde->un_voff;
		extp->poff = mde->un_poff;
		extp->len = mde->un_len;
	}

	/* cleanup, return success */
	Free(mp);
	dnp->unitp = (md_common_t *)msp;
	return (msp);

out:
	/* clean up and return error */
	Free(mp);
	Free(msp);
	return (NULL);
}


/*
 * FUNCTION:	meta_init_sp()
 * INPUT:	spp	- the set name for the new device
 *		argc	- the remaining argument count for the metainit cmdline
 *		argv	- the remainder of the unparsed command line
 *		options	- global options parsed by metainit
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- -1 failure, 0 success
 * PURPOSE:	provides the command line parsing and name management overhead
 *		for creating a new soft partition.  Ultimately this calls
 *		meta_create_sp() which does the real work of allocating space
 *		for the new soft partition.
 */
int
meta_init_sp(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	char		*compname = NULL;
	mdname_t	*spcompnp = NULL;	/* name of component volume */
	char		*devname = argv[0];	/* unit name */
	mdname_t	*np = NULL;		/* name of soft partition */
	md_sp_t		*msp = NULL;
	int		c;
	int		old_optind;
	sp_ext_length_t	len = 0LL;
	int		rval = -1;
	uint_t		seq;
	int		oflag;
	int		failed;
	mddrivename_t	*dnp = NULL;
	sp_ext_length_t	alignment = 0LL;
	sp_ext_node_t	*extlist = NULL;

	assert(argc > 0);

	/* expect sp name, -p, optional -e, compname, and size parameters */
	/* grab soft partition name */
	if ((np = metaname(spp, devname, META_DEVICE, ep)) == NULL)
		goto out;

	/* see if it exists already */
	if (metagetmiscname(np, ep) != NULL) {
		(void) mdmderror(ep, MDE_UNIT_ALREADY_SETUP,
		    meta_getminor(np->dev), devname);
		goto out;
	} else if (! mdismderror(ep, MDE_UNIT_NOT_SETUP)) {
		goto out;
	} else {
		mdclrerror(ep);
	}
	--argc, ++argv;

	if (argc == 0)
		goto syntax;

	/* grab -p */
	if (strcmp(argv[0], "-p") != 0)
		goto syntax;
	--argc, ++argv;

	if (argc == 0)
		goto syntax;

	/* see if -e is there */
	if (strcmp(argv[0], "-e") == 0) {
		/* use the whole disk */
		options |= MDCMD_USE_WHOLE_DISK;
		--argc, ++argv;
	}

	if (argc == 0)
		goto syntax;

	/* get component name */
	compname = Strdup(argv[0]);

	if (options & MDCMD_USE_WHOLE_DISK) {
		if ((dnp = metadrivename(spp, compname, ep)) == NULL) {
			goto out;
		}
		if ((spcompnp = metaslicename(dnp, 0, ep)) == NULL) {
			goto out;
		}
	} else if ((spcompnp = metaname(spp, compname, UNKNOWN, ep)) == NULL) {
		goto out;
	}
	assert(*spp != NULL);

	if (!(options & MDCMD_NOLOCK)) {
		/* grab set lock */
		if (meta_lock(*spp, TRUE, ep))
			goto out;

		if (meta_check_ownership(*spp, ep) != 0)
			goto out;
	}

	/* allocate the soft partition */
	msp = Zalloc(sizeof (*msp));

	/* setup common */
	msp->common.namep = np;
	msp->common.type = MD_METASP;

	compname = spcompnp->cname;

	assert(spcompnp->rname != NULL);
	--argc, ++argv;

	if (argc == 0) {
		goto syntax;
	}

	if (*argv[0] == '-') {
		/*
		 * parse any other command line options, this includes
		 * the recovery options -o and -b. The special thing
		 * with these options is that the len needs to be
		 * kept track of otherwise when the geometry of the
		 * "device" is built it will create an invalid geometry
		 */
		old_optind = optind = 0;
		opterr = 0;
		oflag = 0;
		seq = 0;
		failed = 0;
		while ((c = getopt(argc, argv, "A:o:b:")) != -1) {
			sp_ext_offset_t	offset;
			sp_ext_length_t	length;
			longlong_t	tmp_size;

			switch (c) {
			case 'A':	/* data alignment */
				if (meta_sp_parsesizestring(optarg,
				    &alignment) == -1) {
					failed = 1;
				}
				break;
			case 'o':	/* offset in the partition */
				if (oflag == 1) {
					failed = 1;
				} else {
					tmp_size = atoll(optarg);
					if (tmp_size <= 0) {
						failed = 1;
					} else {
						oflag = 1;
						options |= MDCMD_DIRECT;

						offset = tmp_size;
					}
				}

				break;
			case 'b':	/* number of blocks */
				if (oflag == 0) {
					failed = 1;
				} else {
					tmp_size = atoll(optarg);
					if (tmp_size <= 0) {
						failed = 1;
					} else {
						oflag = 0;

						length = tmp_size;

						/* we have a pair of values */
						meta_sp_list_insert(*spp, np,
						    &extlist, offset, length,
						    EXTTYP_ALLOC, seq++,
						    EXTFLG_UPDATE,
						    meta_sp_cmp_by_offset);
						len += length;
					}
				}

				break;
			default:
				argc -= old_optind;
				argv += old_optind;
				goto options;
			}

			if (failed) {
				argc -= old_optind;
				argv += old_optind;
				goto syntax;
			}

			old_optind = optind;
		}
		argc -= optind;
		argv += optind;

		/*
		 * Must have matching pairs of -o and -b flags
		 */
		if (oflag != 0)
			goto syntax;

		/*
		 * Can't specify both layout (indicated indirectly by
		 * len being set by thye -o/-b cases above) AND
		 * alignment
		 */
		if ((len > 0LL) && (alignment > 0LL))
			goto syntax;

		/*
		 * sanity check the allocation list
		 */
		if ((extlist != NULL) && meta_sp_list_overlaps(extlist))
			goto syntax;
	}

	if (len == 0LL) {
		if (argc == 0)
			goto syntax;
		if (meta_sp_parsesize(argv[0], &len) == -1)
			goto syntax;
		--argc, ++argv;
	}

	msp->ext.ext_val = Zalloc(sizeof (*msp->ext.ext_val));
	msp->ext.ext_val->len = len;
	msp->compnamep = spcompnp;

	/* we should be at the end */
	if (argc != 0)
		goto syntax;

	/* create soft partition */
	if (meta_create_sp(*spp, msp, extlist, options, alignment, ep) != 0)
		goto out;
	rval = 0;

	/* let em know */
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Soft Partition is setup\n"),
		    devname);
		(void) fflush(stdout);
	}
	goto out;

syntax:
	/* syntax error */
	rval = meta_cook_syntax(ep, MDE_SYNTAX, compname, argc, argv);
	goto out;

options:
	/* options error */
	rval = meta_cook_syntax(ep, MDE_OPTION, compname, argc, argv);
	goto out;

out:
	if (msp != NULL) {
		if (msp->ext.ext_val != NULL) {
			Free(msp->ext.ext_val);
		}
		Free(msp);
	}

	return (rval);
}

/*
 * FUNCTION:	meta_free_sp()
 * INPUT:	msp	- the soft partition unit to free
 * OUTPUT:	none
 * RETURNS:	void
 * PURPOSE:	provides an interface from the rest of libmeta for freeing a
 *		soft partition unit
 */
void
meta_free_sp(md_sp_t *msp)
{
	Free(msp);
}

/*
 * FUNCTION:	meta_sp_issp()
 * INPUT:	sp	- the set name to check
 *		np	- the name to check
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- 0 means sp,np is a soft partition
 *			  1 means sp,np is not a soft partition
 * PURPOSE:	determines whether the given device is a soft partition
 *		device.  This is called by other metadevice check routines.
 */
int
meta_sp_issp(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	if (meta_get_sp_common(sp, np, 0, ep) == NULL)
		return (1);

	return (0);
}

/*
 * FUNCTION:	meta_check_sp()
 * INPUT:	sp	- the set name to check
 *		msp	- the unit structure to check
 *		options	- creation options
 * OUTPUT:	repart_options - options to be passed to
 *				meta_repartition_drive()
 *		ep	- return error pointer
 * RETURNS:	int	-  0 ok to create on this component
 *			  -1 error or not ok to create on this component
 * PURPOSE:	Checks to determine whether the rules for creation of
 *		soft partitions allow creation of a soft partition on
 *		the device described by the mdname_t structure referred
 *		to by msp->compnamep.
 *
 *		NOTE: Does NOT check to determine whether the extents
 *		      described in the md_sp_t structure referred to by
 *		      msp will fit on the device described by the mdname_t
 *		      structure located at msp->compnamep.
 */
static int
meta_check_sp(
	mdsetname_t	*sp,
	md_sp_t		*msp,
	mdcmdopts_t	options,
	int		*repart_options,
	md_error_t	*ep
)
{
	md_common_t	*mdp;
	mdname_t	*compnp = msp->compnamep;
	uint_t		slice;
	mddrivename_t	*dnp;
	mdname_t	*slicenp;
	mdvtoc_t	*vtocp;

	/* make sure it is in the set */
	if (meta_check_inset(sp, compnp, ep) != 0)
		return (-1);

	if ((options & MDCMD_USE_WHOLE_DISK) != 0) {
		uint_t	rep_slice;

		/*
		 * check to make sure we can partition this drive.
		 * we cannot continue if any of the following are
		 * true:
		 * The drive is a metadevice.
		 * The drive contains a mounted slice.
		 * The drive contains a slice being swapped to.
		 * The drive contains slices which are part of other
		 * metadevices.
		 * The drive contains a metadb.
		 */
		if (metaismeta(compnp))
			return (mddeverror(ep, MDE_IS_META, compnp->dev,
			    compnp->cname));

		assert(compnp->drivenamep != NULL);

		/*
		 * ensure that we have slice 0 since the disk will be
		 * repartitioned in the USE_WHOLE_DISK case.  this check
		 * is redundant unless the user incorrectly specifies a
		 * a fully qualified drive AND slice name (i.e.,
		 * /dev/dsk/cXtXdXsX), which will be incorrectly
		 * recognized as a drive name by the metaname code.
		 */

		if ((vtocp = metagetvtoc(compnp, FALSE, &slice, ep)) == NULL)
			return (-1);
		if (slice != MD_SLICE0)
			return (mderror(ep, MDE_NOT_DRIVENAME, compnp->cname));

		dnp = compnp->drivenamep;
		if (meta_replicaslice(dnp, &rep_slice, ep) != 0)
			return (-1);

		for (slice = 0; slice < vtocp->nparts; slice++) {

			/* only check if the slice really exists */
			if (vtocp->parts[slice].size == 0)
				continue;

			slicenp = metaslicename(dnp, slice, ep);
			if (slicenp == NULL)
				return (-1);

			/* check to ensure that it is not already in use */
			if (meta_check_inuse(sp,
			    slicenp, MDCHK_INUSE, ep) != 0) {
				return (-1);
			}

			/*
			 * Up to this point, tests are applied to all
			 * slices uniformly.
			 */

			if (slice == rep_slice) {
				/*
				 * Tests inside the body of this
				 * conditional are applied only to
				 * slice seven.
				 */
				if (meta_check_inmeta(sp, slicenp,
				    options | MDCHK_ALLOW_MDDB |
				    MDCHK_ALLOW_REPSLICE, 0, -1, ep) != 0)
					return (-1);

				/*
				 * For slice seven, a metadb is NOT an
				 * automatic failure. It merely means
				 * that we're not allowed to muck
				 * about with the partitioning of that
				 * slice.  We indicate this by masking
				 * in the MD_REPART_LEAVE_REP flag.
				 */
				if (metahasmddb(sp, slicenp, ep)) {
					assert(repart_options !=
					    NULL);
					*repart_options |=
					    MD_REPART_LEAVE_REP;
				}

				/*
				 * Skip the remaining tests for slice
				 * seven
				 */
				continue;
			}

			/*
			 * Tests below this point will be applied to
			 * all slices EXCEPT for the replica slice.
			 */


			/* check if component is in a metadevice */
			if (meta_check_inmeta(sp, slicenp, options, 0,
			    -1, ep) != 0)
				return (-1);

			/* check to see if component has a metadb */
			if (metahasmddb(sp, slicenp, ep))
				return (mddeverror(ep, MDE_HAS_MDDB,
				    slicenp->dev, slicenp->cname));
		}
		/*
		 * This should be all of the testing necessary when
		 * the MDCMD_USE_WHOLE_DISK flag is set; the rest of
		 * meta_check_sp() is oriented towards component
		 * arguments instead of disks.
		 */
		goto meta_check_sp_ok;

	}

	/* check to ensure that it is not already in use */
	if (meta_check_inuse(sp, compnp, MDCHK_INUSE, ep) != 0) {
		return (-1);
	}

	if (!metaismeta(compnp)) {	/* handle non-metadevices */

		/*
		 * The component can have one or more soft partitions on it
		 * already, but can't be part of any other type of metadevice,
		 * so if it is used for a metadevice, but the metadevice
		 * isn't a soft partition, return failure.
		 */

		if (meta_check_inmeta(sp, compnp, options, 0, -1, ep) != 0 &&
		    meta_check_insp(sp, compnp, 0, -1, ep) == 0) {
			return (-1);
		}
	} else {			/* handle metadevices */
		/* get underlying unit & check capabilities */
		if ((mdp = meta_get_unit(sp, compnp, ep)) == NULL)
			return (-1);

		if ((! (mdp->capabilities & MD_CAN_PARENT)) ||
		    (! (mdp->capabilities & MD_CAN_SP)))
			return (mdmderror(ep, MDE_INVAL_UNIT,
			    meta_getminor(compnp->dev), compnp->cname));
	}

meta_check_sp_ok:
	mdclrerror(ep);
	return (0);
}

/*
 * FUNCTION:	meta_create_sp()
 * INPUT:	sp	- the set name to create in
 *		msp	- the unit structure to create
 *		oblist	- an optional list of requested extents (-o/-b options)
 *		options	- creation options
 *		alignment - data alignment
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	-  0 success, -1 error
 * PURPOSE:	does most of the work for creating a soft partition.  If
 *		metainit -p -e was used, first partition the drive.  Then
 *		create an extent list based on the existing soft partitions
 *		and assume all space not used by them is free.  Storage for
 *		the new soft partition is allocated from the free extents
 *		based on the length specified on the command line or the
 *		oblist passed in.  The unit structure is then committed and
 *		the watermarks are updated.  Finally, the status is changed to
 *		Okay and the process is complete.
 */
static int
meta_create_sp(
	mdsetname_t	*sp,
	md_sp_t		*msp,
	sp_ext_node_t	*oblist,
	mdcmdopts_t	options,
	sp_ext_length_t	alignment,
	md_error_t	*ep
)
{
	mdname_t	*np = msp->common.namep;
	mdname_t	*compnp = msp->compnamep;
	mp_unit_t	*mp = NULL;
	mdnamelist_t	*keynlp = NULL, *spnlp = NULL;
	md_set_params_t	set_params;
	int		rval = -1;
	diskaddr_t	comp_size;
	diskaddr_t	sp_start;
	sp_ext_node_t	*extlist = NULL;
	int		numexts = 0;	/* number of extents */
	int		count = 0;
	int		committed = 0;
	int		repart_options = MD_REPART_FORCE;
	int		create_flag = MD_CRO_32BIT;

	md_set_desc	*sd;
	mm_unit_t	*mm;
	md_set_mmown_params_t	*ownpar = NULL;
	int		comp_is_mirror = 0;

	/* validate soft partition */
	if (meta_check_sp(sp, msp, options, &repart_options, ep) != 0)
		return (-1);

	if ((options & MDCMD_USE_WHOLE_DISK) != 0) {
		if ((options & MDCMD_DOIT) != 0) {
			if (meta_repartition_drive(sp,
			    compnp->drivenamep,
			    repart_options,
			    NULL, /* Don't return the VTOC */
			    ep) != 0)

				return (-1);
		} else {
			/*
			 * If -n and -e are both specified, it doesn't make
			 * sense to continue without actually partitioning
			 * the drive.
			 */
			return (0);
		}
	}

	/* populate the start_blk field of the component name */
	if ((sp_start = meta_sp_get_start(sp, compnp, ep)) ==
	    MD_DISKADDR_ERROR) {
		rval = -1;
		goto out;
	}

	if (options & MDCMD_DOIT) {
		/* store name in namespace */
		if (add_key_name(sp, compnp, &keynlp, ep) != 0) {
			rval = -1;
			goto out;
		}
	}

	/*
	 * Get a list of the soft partitions that currently reside on
	 * the component.  We should ALWAYS force reload the cache,
	 * because if this is a single creation, there will not BE a
	 * cached list, and if we're using the md.tab, we must rebuild
	 * the list because it won't contain the previous (if any)
	 * soft partition.
	 */
	count = meta_sp_get_by_component(sp, compnp, &spnlp, 1, ep);
	if (count < 0) {
		/* error occured */
		rval = -1;
		goto out;
	}

	/*
	 * get the size of the underlying device.  if the size is smaller
	 * than or equal to the watermark size, we know there isn't
	 * enough space.
	 */
	if ((comp_size = metagetsize(compnp, ep)) == MD_DISKADDR_ERROR) {
		rval = -1;
		goto out;
	} else if (comp_size <= MD_SP_WMSIZE) {
		(void) mdmderror(ep, MDE_SP_NOSPACE, 0, compnp->cname);
		rval = -1;
		goto out;
	}
	/*
	 * seed extlist with reserved space at the beginning of the volume and
	 * enough space for the end watermark.  The end watermark always gets
	 * updated, but if the underlying device changes size it may not be
	 * pointed to until the extent before it is updated.  Since the
	 * end of the reserved space is where the first watermark starts,
	 * the reserved extent should never be marked for updating.
	 */

	meta_sp_list_insert(NULL, NULL, &extlist,
	    0ULL, sp_start, EXTTYP_RESERVED, 0, 0, meta_sp_cmp_by_offset);
	meta_sp_list_insert(NULL, NULL, &extlist,
	    (sp_ext_offset_t)(comp_size - MD_SP_WMSIZE), MD_SP_WMSIZE,
	    EXTTYP_END, 0, EXTFLG_UPDATE, meta_sp_cmp_by_offset);

	if (meta_sp_extlist_from_namelist(sp, spnlp, &extlist, ep) == -1) {
		rval = -1;
		goto out;
	}

	metafreenamelist(spnlp);

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_create_sp: list of used extents:\n");
		meta_sp_list_dump(extlist);
	}

	meta_sp_list_freefill(&extlist, metagetsize(compnp, ep));

	/* get extent list from -o/-b options or from free space */
	if (options & MDCMD_DIRECT) {
		if (getenv(META_SP_DEBUG)) {
			meta_sp_debug("meta_create_sp: Dumping -o/-b list:\n");
			meta_sp_list_dump(oblist);
		}

		numexts = meta_sp_alloc_by_list(sp, np, &extlist, oblist);
		if (numexts == -1) {
			(void) mdmderror(ep, MDE_SP_OVERLAP, 0, np->cname);
			rval = -1;
			goto out;
		}
	} else {
		numexts = meta_sp_alloc_by_len(sp, np, &extlist,
		    &msp->ext.ext_val->len, 0LL, (alignment > 0) ? alignment :
		    meta_sp_get_default_alignment(sp, compnp, ep));
		if (numexts == -1) {
			(void) mdmderror(ep, MDE_SP_NOSPACE, 0, np->cname);
			rval = -1;
			goto out;
		}
	}

	assert(extlist != NULL);

	/* create soft partition */
	mp = meta_sp_createunit(msp->common.namep, msp->compnamep,
	    extlist, numexts, msp->ext.ext_val->len, MD_SP_CREATEPEND, ep);

	create_flag = meta_check_devicesize(mp->c.un_total_blocks);

	/* if we're not doing anything (metainit -n), return success */
	if (! (options & MDCMD_DOIT)) {
		rval = 0;	/* success */
		goto out;
	}

	(void) memset(&set_params, 0, sizeof (set_params));

	if (create_flag == MD_CRO_64BIT) {
		mp->c.un_revision |= MD_64BIT_META_DEV;
		set_params.options = MD_CRO_64BIT;
	} else {
		mp->c.un_revision &= ~MD_64BIT_META_DEV;
		set_params.options = MD_CRO_32BIT;
	}

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_create_sp: printing unit structure\n");
		meta_sp_printunit(mp);
	}

	/*
	 * Check to see if we're trying to create a partition on a mirror. If so
	 * we may have to enforce an ownership change before writing the
	 * watermark out.
	 */
	if (metaismeta(compnp)) {
		char *miscname;

		miscname = metagetmiscname(compnp, ep);
		if (miscname != NULL)
			comp_is_mirror = (strcmp(miscname, MD_MIRROR) == 0);
		else
			comp_is_mirror = 0;
	} else {
		comp_is_mirror = 0;
	}

	/*
	 * For a multi-node environment we have to ensure that the master
	 * node owns an underlying mirror before we issue the MD_IOCSET ioctl.
	 * If the master does not own the device we will deadlock as the
	 * implicit write of the watermarks (in sp_ioctl.c) will cause an
	 * ownership change that will block as the MD_IOCSET is still in
	 * progress. To close this window we force an owner change to occur
	 * before issuing the MD_IOCSET. We cannot simply open the device and
	 * write to it as this will only work for the first soft-partition
	 * creation.
	 */

	if (comp_is_mirror && !metaislocalset(sp)) {

		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			rval = -1;
			goto out;
		}
		if (MD_MNSET_DESC(sd) && sd->sd_mn_am_i_master) {
			mm = (mm_unit_t *)meta_get_unit(sp, compnp, ep);
			if (mm == NULL) {
				rval = -1;
				goto out;
			} else {
				rval = meta_mn_change_owner(&ownpar, sp->setno,
				    meta_getminor(compnp->dev),
				    sd->sd_mn_mynode->nd_nodeid,
				    MD_MN_MM_PREVENT_CHANGE |
				    MD_MN_MM_SPAWN_THREAD);
				if (rval == -1)
					goto out;
			}
		}
	}

	set_params.mnum = MD_SID(mp);
	set_params.size = mp->c.un_size;
	set_params.mdp = (uintptr_t)mp;
	MD_SETDRIVERNAME(&set_params, MD_SP, MD_MIN2SET(set_params.mnum));

	/* first phase of commit. */
	if (metaioctl(MD_IOCSET, &set_params, &set_params.mde,
	    np->cname) != 0) {
		(void) mdstealerror(ep, &set_params.mde);
		rval = -1;
		goto out;
	}

	/* we've successfully committed the record */
	committed = 1;

	/* write watermarks */
	if (meta_sp_update_wm(sp, msp, extlist, ep) < 0) {
		rval = -1;
		goto out;
	}

	/*
	 * Allow mirror ownership to change. If we don't succeed in this
	 * ioctl it isn't fatal, but the cluster will probably hang fairly
	 * soon as the mirror owner won't change. However, we have
	 * successfully written the watermarks out to the device so the
	 * softpart creation has succeeded
	 */
	if (ownpar) {
		(void) meta_mn_change_owner(&ownpar, sp->setno, ownpar->d.mnum,
		    ownpar->d.owner,
		    MD_MN_MM_ALLOW_CHANGE | MD_MN_MM_SPAWN_THREAD);
	}

	/* second phase of commit, set status to MD_SP_OK */
	if (meta_sp_setstatus(sp, &(MD_SID(mp)), 1, MD_SP_OK, ep) < 0) {
		rval = -1;
		goto out;
	}
	rval = 0;
out:
	Free(mp);
	if (ownpar)
		Free(ownpar);

	if (extlist != NULL)
		meta_sp_list_free(&extlist);

	if (rval != 0 && keynlp != NULL && committed != 1)
		(void) del_key_names(sp, keynlp, NULL);

	metafreenamelist(keynlp);

	return (rval);
}

/*
 * **************************************************************************
 *                      Reset (metaclear) Functions                         *
 * **************************************************************************
 */

/*
 * FUNCTION:	meta_sp_reset_common()
 * INPUT:	sp	- the set name of the device to reset
 *		np	- the name of the device to reset
 *		msp	- the unit structure to reset
 *		options	- metaclear options
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	-  0 success, -1 error
 * PURPOSE:	"resets", or more accurately deletes, the soft partition
 *		specified.  First the state is set to "deleting" and then the
 *		watermarks are all cleared out.  Once the watermarks have been
 *		updated, the unit structure is deleted from the metadb.
 */
static int
meta_sp_reset_common(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_sp_t		*msp,
	md_sp_reset_t	reset_params,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	char	*miscname;
	int	rval = -1;
	int	is_open = 0;

	/* make sure that nobody owns us */
	if (MD_HAS_PARENT(msp->common.parent))
		return (mdmderror(ep, MDE_IN_USE, meta_getminor(np->dev),
		    np->cname));

	/* make sure that the soft partition isn't open */
	if ((is_open = meta_isopen(sp, np, ep, options)) < 0)
		return (-1);
	else if (is_open)
		return (mdmderror(ep, MDE_IS_OPEN, meta_getminor(np->dev),
		    np->cname));

	/* get miscname */
	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (-1);

	/* fill in reset params */
	MD_SETDRIVERNAME(&reset_params, miscname, sp->setno);
	reset_params.mnum = meta_getminor(np->dev);
	reset_params.force = (options & MDCMD_FORCE) ? 1 : 0;

	/*
	 * clear soft partition - phase one.
	 * place the soft partition into the "delete pending" state.
	 */
	if (meta_sp_setstatus(sp, &reset_params.mnum, 1, MD_SP_DELPEND, ep) < 0)
		return (-1);

	/*
	 * Now clear the watermarks.  If the force flag is specified,
	 * ignore any errors writing the watermarks and delete the unit
	 * structure anyway.  An error may leave the on-disk format in a
	 * corrupt state.  If force is not specified and we fail here,
	 * the soft partition will remain in the "delete pending" state.
	 */
	if ((meta_sp_clear_wm(sp, msp, ep) < 0) &&
	    ((options & MDCMD_FORCE) == 0))
		goto out;

	/*
	 * clear soft partition - phase two.
	 * the driver removes the soft partition from the metadb and
	 * zeros out incore version.
	 */
	if (metaioctl(MD_IOCRESET, &reset_params,
	    &reset_params.mde, np->cname) != 0) {
		(void) mdstealerror(ep, &reset_params.mde);
		goto out;
	}

	/*
	 * Wait for the /dev to be cleaned up. Ignore the return
	 * value since there's not much we can do.
	 */
	(void) meta_update_devtree(meta_getminor(np->dev));

	rval = 0;	/* success */

	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Soft Partition is cleared\n"),
		    np->cname);
		(void) fflush(stdout);
	}

	/*
	 * if told to recurse and on a metadevice, then attempt to
	 * clear the subdevices.  Indicate failure if the clear fails.
	 */
	if ((options & MDCMD_RECURSE) &&
	    (metaismeta(msp->compnamep)) &&
	    (meta_reset_by_name(sp, msp->compnamep, options, ep) != 0))
		rval = -1;

out:
	meta_invalidate_name(np);
	return (rval);
}

/*
 * FUNCTION:	meta_sp_reset()
 * INPUT:	sp	- the set name of the device to reset
 *		np	- the name of the device to reset
 *		options	- metaclear options
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	-  0 success, -1 error
 * PURPOSE:	provides the entry point to the rest of libmeta for deleting a
 *		soft partition.  If np is NULL, then soft partitions are
 *		all deleted at the current level and then recursively deleted.
 *		Otherwise, if a name is specified either directly or as a
 *		result of a recursive operation, it deletes only that name.
 *		Since something sitting under a soft partition may be parented
 *		to it, we have to reparent that other device to another soft
 *		partition on the same component if we're deleting the one it's
 *		parented to.
 */
int
meta_sp_reset(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_sp_t		*msp;
	int		rval = -1;
	mdnamelist_t	*spnlp = NULL, *nlp = NULL;
	md_sp_reset_t	reset_params;
	int		num_sp;

	assert(sp != NULL);

	/* reset/delete all soft paritions */
	if (np == NULL) {
		/*
		 * meta_reset_all sets MDCMD_RECURSE, but this behavior
		 * is incorrect for soft partitions.  We want to clear
		 * all soft partitions at a particular level in the
		 * metadevice stack before moving to the next level.
		 * Thus, we clear MDCMD_RECURSE from the options.
		 */
		options &= ~MDCMD_RECURSE;

		/* for each soft partition */
		rval = 0;
		if (meta_get_sp_names(sp, &spnlp, 0, ep) < 0)
			rval = -1;

		for (nlp = spnlp; (nlp != NULL); nlp = nlp->next) {
			np = nlp->namep;
			if ((msp = meta_get_sp(sp, np, ep)) == NULL) {
				rval = -1;
				break;
			}
			/*
			 * meta_reset_all calls us twice to get soft
			 * partitions at the top and bottom of the stack.
			 * thus, if we have a parent, we'll get deleted
			 * on the next call.
			 */
			if (MD_HAS_PARENT(msp->common.parent))
				continue;
			/*
			 * If this is a multi-node set, we send a series
			 * of individual metaclear commands.
			 */
			if (meta_is_mn_set(sp, ep)) {
				if (meta_mn_send_metaclear_command(sp,
				    np->cname, options, 0, ep) != 0) {
					rval = -1;
					break;
				}
			} else {
				if (meta_sp_reset(sp, np, options, ep) != 0) {
					rval = -1;
					break;
				}
			}
		}
		/* cleanup return status */
		metafreenamelist(spnlp);
		return (rval);
	}

	/* check the name */
	if (metachkmeta(np, ep) != 0)
		return (-1);

	/* get the unit structure */
	if ((msp = meta_get_sp(sp, np, ep)) == NULL)
		return (-1);

	/* clear out reset parameters */
	(void) memset(&reset_params, 0, sizeof (reset_params));

	/* if our child is a metadevice, we need to deparent/reparent it */
	if (metaismeta(msp->compnamep)) {
		/* get sp's on this component */
		if ((num_sp = meta_sp_get_by_component(sp, msp->compnamep,
		    &spnlp, 1, ep)) <= 0)
			/* no sp's on this device.  error! */
			return (-1);
		else if (num_sp == 1)
			/* last sp on this device, so we deparent */
			reset_params.new_parent = MD_NO_PARENT;
		else {
			/* have to reparent this metadevice */
			for (nlp = spnlp; nlp != NULL; nlp = nlp->next) {
				if (meta_getminor(nlp->namep->dev) ==
				    meta_getminor(np->dev))
					continue;
				/*
				 * this isn't the softpart we are deleting,
				 * so use this device as the new parent.
				 */
				reset_params.new_parent =
				    meta_getminor(nlp->namep->dev);
				break;
			}
		}
		metafreenamelist(spnlp);
	}

	if (meta_sp_reset_common(sp, np, msp, reset_params, options, ep) != 0)
		return (-1);

	return (0);
}

/*
 * FUNCTION:	meta_sp_reset_component()
 * INPUT:	sp	- the set name of the device to reset
 *		name	- the string name of the device to reset
 *		options	- metaclear options
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	-  0 success, -1 error
 * PURPOSE:	provides the ability to delete all soft partitions on a
 *		specified device (metaclear -p).  It first gets all of the
 *		soft partitions on the component and then deletes each one
 *		individually.
 */
int
meta_sp_reset_component(
	mdsetname_t	*sp,
	char		*name,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdname_t	*compnp, *np;
	mdnamelist_t	*spnlp = NULL;
	mdnamelist_t	*nlp = NULL;
	md_sp_t		*msp;
	int		count;
	md_sp_reset_t	reset_params;

	if ((compnp = metaname(&sp, name, UNKNOWN, ep)) == NULL)
		return (-1);

	/* If we're starting out with no soft partitions, it's an error */
	count = meta_sp_get_by_component(sp, compnp, &spnlp, 1, ep);
	if (count == 0)
		return (mdmderror(ep, MDE_SP_NOSP, 0, compnp->cname));
	else if (count < 0)
		return (-1);

	/*
	 * clear all soft partitions on this component.
	 * NOTE: we reparent underlying metadevices as we go so that
	 * things stay sane.  Also, if we encounter an error, we stop
	 * and go no further in case recovery might be needed.
	 */
	for (nlp = spnlp; nlp != NULL; nlp = nlp->next) {
		/* clear out reset parameters */
		(void) memset(&reset_params, 0, sizeof (reset_params));

		/* check the name */
		np = nlp->namep;

		if (metachkmeta(np, ep) != 0) {
			metafreenamelist(spnlp);
			return (-1);
		}

		/* get the unit structure */
		if ((msp = meta_get_sp(sp, np, ep)) == NULL) {
			metafreenamelist(spnlp);
			return (-1);
		}

		/* have to deparent/reparent metadevices */
		if (metaismeta(compnp)) {
			if (nlp->next == NULL)
				reset_params.new_parent = MD_NO_PARENT;
			else
				reset_params.new_parent =
				    meta_getminor(spnlp->next->namep->dev);
		}

		/* clear soft partition */
		if (meta_sp_reset_common(sp, np, msp, reset_params,
		    options, ep) < 0) {
			metafreenamelist(spnlp);
			return (-1);
		}
	}
	metafreenamelist(spnlp);
	return (0);
}

/*
 * **************************************************************************
 *                      Grow (metattach) Functions                          *
 * **************************************************************************
 */

/*
 * FUNCTION:	meta_sp_attach()
 * INPUT:	sp	- the set name of the device to attach to
 *		np	- the name of the device to attach to
 *		addsize	- the unparsed string holding the amount of space to add
 *		options	- metattach options
 *		alignment - data alignment
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	-  0 success, -1 error
 * PURPOSE:	grows a soft partition by reading in the existing unit
 *		structure and setting its state to Growing, allocating more
 *		space (similar to meta_create_sp()), updating the watermarks,
 *		and then writing out the new unit structure in the Okay state.
 */
int
meta_sp_attach(
	mdsetname_t	*sp,
	mdname_t	*np,
	char		*addsize,
	mdcmdopts_t	options,
	sp_ext_length_t	alignment,
	md_error_t	*ep
)
{
	md_grow_params_t	grow_params;
	sp_ext_length_t		grow_len;	/* amount to grow */
	mp_unit_t		*mp, *new_un;
	mdname_t		*compnp = NULL;

	sp_ext_node_t		*extlist = NULL;
	int			numexts;
	mdnamelist_t		*spnlp = NULL;
	int			count;
	md_sp_t			*msp;
	daddr_t			start_block;

	/* should have the same set */
	assert(sp != NULL);
	assert(sp->setno == MD_MIN2SET(meta_getminor(np->dev)));

	/* check name */
	if (metachkmeta(np, ep) != 0)
		return (-1);

	if (meta_sp_parsesize(addsize, &grow_len) == -1) {
		return (mdmderror(ep, MDE_SP_BAD_LENGTH, 0, np->cname));
	}

	if ((mp = (mp_unit_t *)meta_get_mdunit(sp, np, ep)) == NULL)
		return (-1);

	/* make sure we don't have a parent */
	if (MD_HAS_PARENT(mp->c.un_parent)) {
		Free(mp);
		return (mdmderror(ep, MDE_INVAL_UNIT, 0, np->cname));
	}

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_sp_attach: Unit structure before new "
		    "space:\n");
		meta_sp_printunit(mp);
	}

	/*
	 * NOTE: the fast option to metakeyname is 0 as opposed to 1
	 * If this was not the case we would suffer the following
	 * assertion failure:
	 * Assertion failed: type1 != MDT_FAST_META && type1 != MDT_FAST_COMP
	 * file meta_check.x, line 315
	 * I guess this is because we have not "seen" this drive before
	 * and hence hit the failure - this is of course the attach routine
	 */
	if ((compnp = metakeyname(&sp, mp->un_key, 0, ep)) == NULL) {
		Free(mp);
		return (-1);
	}

	/* metakeyname does not fill in the key. */
	compnp->key = mp->un_key;

	/* work out the space on the component that we are dealing with */
	count = meta_sp_get_by_component(sp, compnp, &spnlp, 0, ep);

	/*
	 * see if the component has been soft partitioned yet, or if an
	 * error occurred.
	 */
	if (count == 0) {
		Free(mp);
		return (mdmderror(ep, MDE_NOT_SP, 0, np->cname));
	} else if (count < 0) {
		Free(mp);
		return (-1);
	}

	/*
	 * seed extlist with reserved space at the beginning of the volume and
	 * enough space for the end watermark.  The end watermark always gets
	 * updated, but if the underlying device changes size it may not be
	 * pointed to until the extent before it is updated.  Since the
	 * end of the reserved space is where the first watermark starts,
	 * the reserved extent should never be marked for updating.
	 */
	if ((start_block = meta_sp_get_start(sp, compnp, ep)) ==
	    MD_DISKADDR_ERROR) {
		Free(mp);
		return (-1);
	}

	meta_sp_list_insert(NULL, NULL, &extlist, 0ULL, start_block,
	    EXTTYP_RESERVED, 0, 0, meta_sp_cmp_by_offset);
	meta_sp_list_insert(NULL, NULL, &extlist,
	    metagetsize(compnp, ep) - MD_SP_WMSIZE, MD_SP_WMSIZE,
	    EXTTYP_END, 0, EXTFLG_UPDATE, meta_sp_cmp_by_offset);

	if (meta_sp_extlist_from_namelist(sp, spnlp, &extlist, ep) == -1) {
		Free(mp);
		return (-1);
	}

	metafreenamelist(spnlp);

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_sp_attach: list of used extents:\n");
		meta_sp_list_dump(extlist);
	}

	meta_sp_list_freefill(&extlist, metagetsize(compnp, ep));

	assert(mp->un_numexts >= 1);
	numexts = meta_sp_alloc_by_len(sp, np, &extlist, &grow_len,
	    mp->un_ext[mp->un_numexts - 1].un_poff,
	    (alignment > 0) ? alignment :
	    meta_sp_get_default_alignment(sp, compnp, ep));

	if (numexts == -1) {
		Free(mp);
		return (mdmderror(ep, MDE_SP_NOSPACE, 0, np->cname));
	}

	/* allocate new unit structure and copy in old unit */
	if ((new_un = meta_sp_updateunit(np, mp, extlist,
	    grow_len, numexts, ep)) == NULL) {
		Free(mp);
		return (-1);
	}
	Free(mp);

	/* If running in dryrun mode (-n option), we're done here */
	if ((options & MDCMD_DOIT) == 0) {
		if (options & MDCMD_PRINT) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Soft Partition would grow\n"),
			    np->cname);
			(void) fflush(stdout);
		}
		return (0);
	}

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_sp_attach: updated unit structure:\n");
		meta_sp_printunit(new_un);
	}

	assert(new_un != NULL);

	(void) memset(&grow_params, 0, sizeof (grow_params));
	if (new_un->c.un_total_blocks > MD_MAX_BLKS_FOR_SMALL_DEVS) {
		grow_params.options = MD_CRO_64BIT;
		new_un->c.un_revision |= MD_64BIT_META_DEV;
	} else {
		grow_params.options = MD_CRO_32BIT;
		new_un->c.un_revision &= ~MD_64BIT_META_DEV;
	}
	grow_params.mnum = MD_SID(new_un);
	grow_params.size = new_un->c.un_size;
	grow_params.mdp = (uintptr_t)new_un;
	MD_SETDRIVERNAME(&grow_params, MD_SP, MD_MIN2SET(grow_params.mnum));

	if (metaioctl(MD_IOCGROW, &grow_params, &grow_params.mde,
	    np->cname) != 0) {
		(void) mdstealerror(ep, &grow_params.mde);
		return (-1);
	}

	/* update all watermarks */

	if ((msp = meta_get_sp(sp, np, ep)) == NULL)
		return (-1);
	if (meta_sp_update_wm(sp, msp, extlist, ep) < 0)
		return (-1);


	/* second phase of commit, set status to MD_SP_OK */
	if (meta_sp_setstatus(sp, &(MD_SID(new_un)), 1, MD_SP_OK, ep) < 0)
		return (-1);

	meta_invalidate_name(np);

	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Soft Partition has been grown\n"),
		    np->cname);
		(void) fflush(stdout);
	}

	return (0);
}

/*
 * **************************************************************************
 *                    Recovery (metarecover) Functions                      *
 * **************************************************************************
 */

/*
 * FUNCTION:	meta_recover_sp()
 * INPUT:	sp	- the name of the set we are recovering on
 *		compnp	- name pointer for device we are recovering on
 *		argc	- argument count
 *		argv	- left over arguments not parsed by metarecover command
 *		options	- metarecover options
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- 0 - success, -1 - error
 * PURPOSE:	parse soft partitioning-specific metarecover options and
 *		dispatch to the appropriate function to handle recovery.
 */
int
meta_recover_sp(
	mdsetname_t	*sp,
	mdname_t	*compnp,
	int		argc,
	char		*argv[],
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_set_desc	*sd;

	if (argc > 1) {
		(void) meta_cook_syntax(ep, MDE_SYNTAX, compnp->cname,
		    argc, argv);
		return (-1);
	}

	/*
	 * For a MN set, this operation must be performed on the master
	 * as it is responsible for maintaining the watermarks
	 */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL)
			return (-1);
		if (MD_MNSET_DESC(sd) && !sd->sd_mn_am_i_master) {
			(void) mddserror(ep, MDE_DS_MASTER_ONLY, sp->setno,
			    sd->sd_mn_master_nodenm, NULL, NULL);
			return (-1);
		}
	}
	if (argc == 0) {
		/*
		 * if no additional arguments are passed, metarecover should
		 * validate both on-disk and metadb structures as well as
		 * checking that both are consistent with each other
		 */
		if (meta_sp_validate_wm(sp, compnp, options, ep) < 0)
			return (-1);
		if (meta_sp_validate_unit(sp, compnp, options, ep) < 0)
			return (-1);
		if (meta_sp_validate_wm_and_unit(sp, compnp, options, ep) < 0)
			return (-1);
	} else if (strcmp(argv[0], "-d") == 0) {
		/*
		 * Ensure that there is no existing valid record for this
		 * soft-partition. If there is we have nothing to do.
		 */
		if (meta_sp_validate_unit(sp, compnp, options, ep) == 0)
			return (-1);
		/* validate and recover from on-disk structures */
		if (meta_sp_validate_wm(sp, compnp, options, ep) < 0)
			return (-1);
		if (meta_sp_recover_from_wm(sp, compnp, options, ep) < 0)
			return (-1);
	} else if (strcmp(argv[0], "-m") == 0) {
		/* validate and recover from metadb structures */
		if (meta_sp_validate_unit(sp, compnp, options, ep) < 0)
			return (-1);
		if (meta_sp_recover_from_unit(sp, compnp, options, ep) < 0)
			return (-1);
	} else {
		/* syntax error */
		(void) meta_cook_syntax(ep, MDE_SYNTAX, compnp->cname,
		    argc, argv);
		return (-1);
	}

	return (0);
}

/*
 * FUNCTION:	meta_sp_display_exthdr()
 * INPUT:	none
 * OUTPUT:	none
 * RETURNS:	void
 * PURPOSE:	print header line for sp_ext_node_t information.  to be used
 *		in conjunction with meta_sp_display_ext().
 */
static void
meta_sp_display_exthdr(void)
{
	(void) printf("%20s %5s %7s %20s %20s\n",
	    dgettext(TEXT_DOMAIN, "Name"),
	    dgettext(TEXT_DOMAIN, "Seq#"),
	    dgettext(TEXT_DOMAIN, "Type"),
	    dgettext(TEXT_DOMAIN, "Offset"),
	    dgettext(TEXT_DOMAIN, "Length"));
}


/*
 * FUNCTION:	meta_sp_display_ext()
 * INPUT:	ext	- extent to display
 * OUTPUT:	none
 * RETURNS:	void
 * PURPOSE:	print selected fields from sp_ext_node_t.
 */
static void
meta_sp_display_ext(sp_ext_node_t *ext)
{
	/* print extent information */
	if (ext->ext_namep != NULL)
		(void) printf("%20s ", ext->ext_namep->cname);
	else
		(void) printf("%20s ", "NONE");

	(void) printf("%5u ", ext->ext_seq);

	switch (ext->ext_type) {
	case EXTTYP_ALLOC:
		(void) printf("%7s ", "ALLOC");
		break;
	case EXTTYP_FREE:
		(void) printf("%7s ", "FREE");
		break;
	case EXTTYP_RESERVED:
		(void) printf("%7s ", "RESV");
		break;
	case EXTTYP_END:
		(void) printf("%7s ", "END");
		break;
	default:
		(void) printf("%7s ", "INVLD");
		break;
	}

	(void) printf("%20llu %20llu\n", ext->ext_offset, ext->ext_length);
}


/*
 * FUNCTION:	meta_sp_checkseq()
 * INPUT:	extlist	- list of extents to be checked
 * OUTPUT:	none
 * RETURNS:	int	- 0 - success, -1 - error
 * PURPOSE:	check soft partition sequence numbers.  this function assumes
 *		that a list of extents representing 1 or more soft partitions
 *		is passed in sorted in sequence number order.  within a
 *		single soft partition, there may not be any missing or
 *		duplicate sequence numbers.
 */
static int
meta_sp_checkseq(sp_ext_node_t *extlist)
{
	sp_ext_node_t *ext;

	assert(extlist != NULL);

	for (ext = extlist;
	    ext->ext_next != NULL && ext->ext_next->ext_type == EXTTYP_ALLOC;
	    ext = ext->ext_next) {
		if (ext->ext_next->ext_namep != NULL &&
		    strcmp(ext->ext_next->ext_namep->cname,
		    ext->ext_namep->cname) != 0)
				continue;

		if (ext->ext_next->ext_seq != ext->ext_seq + 1) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "%s: sequence numbers are "
			    "incorrect: %d should be %d\n"),
			    ext->ext_next->ext_namep->cname,
			    ext->ext_next->ext_seq, ext->ext_seq + 1);
			return (-1);
		}
	}
	return (0);
}


/*
 * FUNCTION:	meta_sp_resolve_name_conflict()
 * INPUT:	sp	- name of set we're are recovering in.
 *		old_np	- name pointer of soft partition we found on disk.
 * OUTPUT:	new_np	- name pointer for new soft partition name.
 *		ep	- error pointer returned.
 * RETURNS:	int	- 0 - name not replace, 1 - name replaced, -1 - error
 * PURPOSE:	Check to see if the name of one of the soft partitions we found
 *		on disk already exists in the metadb.  If so, prompt for a new
 *		name.  In addition, we keep a static array of names that
 *		will be recovered from this device since these names don't
 *		exist in the configuration at this point but cannot be
 *		recovered more than once.
 */
static int
meta_sp_resolve_name_conflict(
	mdsetname_t	*sp,
	mdname_t	*old_np,
	mdname_t	**new_np,
	md_error_t	*ep
)
{
	char		yesno[255];
	char		*yes;
	char		newname[MD_SP_MAX_DEVNAME_PLUS_1];
	int		nunits;
	static int	*used_names = NULL;

	assert(old_np != NULL);

	if (used_names == NULL) {
		if ((nunits = meta_get_nunits(ep)) < 0)
			return (-1);
		used_names = Zalloc(nunits * sizeof (int));
	}

	/* see if it exists already */
	if (used_names[MD_MIN2UNIT(meta_getminor(old_np->dev))] == 0 &&
	    metagetmiscname(old_np, ep) == NULL) {
		if (! mdismderror(ep, MDE_UNIT_NOT_SETUP))
			return (-1);
		else {
			used_names[MD_MIN2UNIT(meta_getminor(old_np->dev))] = 1;
			mdclrerror(ep);
			return (0);
		}
	}

	/* name exists, ask the user for a new one */
	(void) printf(dgettext(TEXT_DOMAIN,
	    "WARNING: A soft partition named %s was found in the extent\n"
	    "headers, but this name already exists in the metadb "
	    "configuration.\n"
	    "In order to continue recovery you must supply\n"
	    "a new name for this soft partition.\n"), old_np->cname);
	(void) printf(dgettext(TEXT_DOMAIN,
	    "Would you like to continue and supply a new name? (yes/no) "));

	(void) fflush(stdout);
	if ((fgets(yesno, sizeof (yesno), stdin) == NULL) ||
	    (strlen(yesno) == 1))
		(void) snprintf(yesno, sizeof (yesno), "%s\n",
		    dgettext(TEXT_DOMAIN, "no"));
	yes = dgettext(TEXT_DOMAIN, "yes");
	if (strncasecmp(yesno, yes, strlen(yesno) - 1) != 0) {
		return (-1);
	}

	(void) fflush(stdin);

	/* get the new name */
	for (;;) {
		(void) printf(dgettext(TEXT_DOMAIN, "Please enter a new name "
		    "for this soft partition (dXXXX) "));
		(void) fflush(stdout);
		if (fgets(newname, MD_SP_MAX_DEVNAME_PLUS_1, stdin) == NULL)
			(void) strcpy(newname, "");

		/* remove newline character */
		if (newname[strlen(newname) - 1] == '\n')
			newname[strlen(newname) - 1] = '\0';

		if (!(is_metaname(newname)) ||
		    (meta_init_make_device(&sp, newname, ep) <= 0)) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Invalid metadevice name\n"));
			(void) fflush(stderr);
			continue;
		}

		if ((*new_np = metaname(&sp, newname,
		    META_DEVICE, ep)) == NULL) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Invalid metadevice name\n"));
			(void) fflush(stderr);
			continue;
		}

		assert(MD_MIN2UNIT(meta_getminor((*new_np)->dev)) < nunits);
		/* make sure the name isn't already being used */
		if (used_names[MD_MIN2UNIT(meta_getminor((*new_np)->dev))] ||
		    metagetmiscname(*new_np, ep) != NULL) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "That name already exists\n"));
			continue;
		} else if (! mdismderror(ep, MDE_UNIT_NOT_SETUP))
			return (-1);

		break;
	}

	/* got a new name, place in used array and return */
	used_names[MD_MIN2UNIT(meta_getminor((*new_np)->dev))] = 1;
	mdclrerror(ep);
	return (1);
}

/*
 * FUNCTION:	meta_sp_validate_wm()
 * INPUT:	sp	- set name we are recovering in
 *		compnp	- name pointer for device we are recovering from
 *		options	- metarecover options
 * OUTPUT:	ep	- error pointer returned
 * RETURNS:	int	- 0 - success, -1 - error
 * PURPOSE:	validate and display watermark configuration.  walk the
 *		on-disk watermark structures and validate the information
 *		found within.  since a watermark configuration is
 *		"self-defining", the act of traversing the watermarks
 *		is part of the validation process.
 */
static int
meta_sp_validate_wm(
	mdsetname_t	*sp,
	mdname_t	*compnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	sp_ext_node_t	*extlist = NULL;
	sp_ext_node_t	*ext;
	int		num_sps = 0;
	int		rval;

	if ((options & MDCMD_VERBOSE) != 0)
		(void) printf(dgettext(TEXT_DOMAIN,
		    "Verifying on-disk structures on %s.\n"),
		    compnp->cname);

	/*
	 * for each watermark, build an ext_node, place on list.
	 */
	rval = meta_sp_extlist_from_wm(sp, compnp, &extlist,
	    meta_sp_cmp_by_nameseq, ep);

	if ((options & MDCMD_VERBOSE) != 0) {
		/* print out what we found */
		if (extlist == NULL)
			(void) printf(dgettext(TEXT_DOMAIN,
			    "No extent headers found on %s.\n"),
			    compnp->cname);
		else {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "The following extent headers were found on %s.\n"),
			    compnp->cname);
			meta_sp_display_exthdr();
		}
		for (ext = extlist; ext != NULL; ext = ext->ext_next)
			meta_sp_display_ext(ext);
	}

	if (rval < 0) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: On-disk structures invalid or "
		    "no soft partitions found.\n"),
		    compnp->cname);
		return (-1);
	}

	assert(extlist != NULL);

	/* count number of soft partitions */
	for (ext = extlist;
	    ext != NULL && ext->ext_type == EXTTYP_ALLOC;
	    ext = ext->ext_next) {
		if (ext->ext_next != NULL &&
		    ext->ext_next->ext_namep != NULL &&
		    strcmp(ext->ext_next->ext_namep->cname,
		    ext->ext_namep->cname) == 0)
				continue;
		num_sps++;
	}

	if ((options & MDCMD_VERBOSE) != 0)
		(void) printf(dgettext(TEXT_DOMAIN,
		    "Found %d soft partition(s) on %s.\n"), num_sps,
		    compnp->cname);

	if (num_sps == 0) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: No soft partitions.\n"), compnp->cname);
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));
	}

	/* check sequence numbers */
	if ((options & MDCMD_VERBOSE) != 0)
		(void) printf(dgettext(TEXT_DOMAIN,
		    "Checking sequence numbers.\n"));

	if (meta_sp_checkseq(extlist) != 0)
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));

	return (0);
}

/*
 * FUNCTION:	meta_sp_validate_unit()
 * INPUT:	sp	- name of set we are recovering in
 *		compnp	- name of component we are recovering from
 *		options	- metarecover options
 * OUTPUT:	ep	- error pointer returned
 * RETURNS:	int	- 0 - success, -1 - error
 * PURPOSE:	validate and display metadb configuration.  begin by getting
 *		all soft partitions built on the specified component.  get
 *		the unit structure for each one and validate the fields within.
 */
static int
meta_sp_validate_unit(
	mdsetname_t	*sp,
	mdname_t	*compnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	md_sp_t		*msp;
	mdnamelist_t	*spnlp = NULL;
	mdnamelist_t	*namep = NULL;
	int		count;
	uint_t		extn;
	sp_ext_length_t	size;

	if ((options & MDCMD_VERBOSE) != 0)
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Validating soft partition metadb entries.\n"),
		    compnp->cname);

	if ((size = metagetsize(compnp, ep)) == MD_DISKADDR_ERROR)
		return (-1);

	/* get all soft partitions on component */
	count = meta_sp_get_by_component(sp, compnp, &spnlp, 0, ep);

	if (count == 0) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: No soft partitions.\n"), compnp->cname);
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));
	} else if (count < 0) {
		return (-1);
	}

	/* Now go through the soft partitions and check each one */
	for (namep = spnlp; namep != NULL; namep = namep->next) {
		mdname_t	*curnp = namep->namep;
		sp_ext_offset_t	curvoff;

		/* get the unit structure */
		if ((msp = meta_get_sp_common(sp, curnp, 0, ep)) == NULL)
			return (-1);

		/* verify generic unit structure parameters */
		if ((options & MDCMD_VERBOSE) != 0)
			(void) printf(dgettext(TEXT_DOMAIN,
			    "\nVerifying device %s.\n"),
			    curnp->cname);

		/*
		 * MD_SP_LAST is an invalid state and is always the
		 * highest numbered.
		 */
		if (msp->status >= MD_SP_LAST) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: status value %u is out of range.\n"),
			    curnp->cname, msp->status);
			return (mdmderror(ep, MDE_RECOVER_FAILED,
			    0, curnp->cname));
		} else if ((options & MDCMD_VERBOSE) != 0) {
			uint_t	tstate = 0;

			if (metaismeta(msp->compnamep)) {
				if (meta_get_tstate(msp->common.namep->dev,
				    &tstate, ep) != 0)
					return (-1);
			}
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Status \"%s\" is valid.\n"),
			    curnp->cname, meta_sp_status_to_name(msp->status,
			    tstate & MD_DEV_ERRORED));
		}

		/* Now verify each extent */
		if ((options & MDCMD_VERBOSE) != 0)
			(void) printf("%14s %21s %21s %21s\n",
			    dgettext(TEXT_DOMAIN, "Extent Number"),
			    dgettext(TEXT_DOMAIN, "Virtual Offset"),
			    dgettext(TEXT_DOMAIN, "Physical Offset"),
			    dgettext(TEXT_DOMAIN, "Length"));

		curvoff = 0ULL;
		for (extn = 0; extn < msp->ext.ext_len; extn++) {
			md_sp_ext_t	*extp = &msp->ext.ext_val[extn];

			if ((options & MDCMD_VERBOSE) != 0)
				(void) printf("%14u %21llu %21llu %21llu\n",
				    extn, extp->voff, extp->poff, extp->len);

			if (extp->voff != curvoff) {
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "%s: virtual offset for extent %u "
				    "is inconsistent, expected %llu, "
				    "got %llu.\n"), curnp->cname, extn,
				    curvoff, extp->voff);
				return (mdmderror(ep, MDE_RECOVER_FAILED,
				    0, compnp->cname));
			}

			/* make sure extent does not drop off the end */
			if ((extp->poff + extp->len) == size) {
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "%s: extent %u at offset %llu, "
				    "length %llu exceeds the size of the "
				    "device, %llu.\n"), curnp->cname,
				    extn, extp->poff, extp->len, size);
				return (mdmderror(ep, MDE_RECOVER_FAILED,
				    0, compnp->cname));
			}

			curvoff += extp->len;
		}
	}
	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Soft Partition metadb configuration is valid\n"),
		    compnp->cname);
	}
	return (0);
}

/*
 * FUNCTION:	meta_sp_validate_wm_and_unit()
 * INPUT:	sp	- name of set we are recovering in
 *		compnp	- name of device we are recovering from
 *		options	- metarecover options
 * OUTPUT:	ep	- error pointer returned
 * RETURNS:	int	- 0 - success, -1 error
 * PURPOSE:	cross-validate and display watermarks and metadb records.
 *		get both the unit structures for the soft partitions built
 *		on the specified component and the watermarks found on that
 *		component and check to make sure they are consistent with
 *		each other.
 */
static int
meta_sp_validate_wm_and_unit(
	mdsetname_t	*sp,
	mdname_t	*np,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	sp_ext_node_t	*wmlist = NULL;
	sp_ext_node_t	*unitlist = NULL;
	sp_ext_node_t	*unitext;
	sp_ext_node_t	*wmext;
	sp_ext_offset_t	tmpunitoff;
	mdnamelist_t	*spnlp = NULL;
	int		count;
	int		rval = 0;
	int		verbose = (options & MDCMD_VERBOSE);

	/* get unit structure list */
	count = meta_sp_get_by_component(sp, np, &spnlp, 0, ep);
	if (count <= 0)
		return (-1);

	meta_sp_list_insert(NULL, NULL, &unitlist,
	    metagetsize(np, ep) - MD_SP_WMSIZE, MD_SP_WMSIZE,
	    EXTTYP_END, 0, EXTFLG_UPDATE, meta_sp_cmp_by_offset);

	if (meta_sp_extlist_from_namelist(sp, spnlp, &unitlist, ep) == -1) {
		metafreenamelist(spnlp);
		return (-1);
	}

	metafreenamelist(spnlp);

	meta_sp_list_freefill(&unitlist, metagetsize(np, ep));

	if (meta_sp_extlist_from_wm(sp, np, &wmlist,
	    meta_sp_cmp_by_offset, ep) < 0) {
		meta_sp_list_free(&unitlist);
		return (-1);
	}

	if (getenv(META_SP_DEBUG)) {
		meta_sp_debug("meta_sp_validate_wm_and_unit: unit list:\n");
		meta_sp_list_dump(unitlist);
		meta_sp_debug("meta_sp_validate_wm_and_unit: wm list:\n");
		meta_sp_list_dump(wmlist);
	}

	/*
	 * step through both lists and compare allocated nodes.  Free
	 * nodes and end watermarks may differ between the two but
	 * that's generally ok, and if they're wrong will typically
	 * cause misplaced allocated extents.
	 */
	if (verbose)
		(void) printf(dgettext(TEXT_DOMAIN, "\n%s: Verifying metadb "
		    "allocations match extent headers.\n"), np->cname);

	unitext = unitlist;
	wmext = wmlist;
	while ((wmext != NULL) && (unitext != NULL)) {
		/* find next allocated extents in each list */
		while (wmext != NULL && wmext->ext_type != EXTTYP_ALLOC)
			wmext = wmext->ext_next;

		while (unitext != NULL && unitext->ext_type != EXTTYP_ALLOC)
			unitext = unitext->ext_next;

		if (wmext == NULL || unitext == NULL)
			break;

		if (verbose) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "Metadb extent:\n"));
			meta_sp_display_exthdr();
			meta_sp_display_ext(unitext);
			(void) printf(dgettext(TEXT_DOMAIN,
			    "Extent header extent:\n"));
			meta_sp_display_exthdr();
			meta_sp_display_ext(wmext);
			(void) printf("\n");
		}

		if (meta_sp_validate_exts(np, wmext, unitext, ep) < 0)
			rval = -1;

		/*
		 * if the offsets aren't equal, only increment the
		 * lowest one in hopes of getting the lists back in sync.
		 */
		tmpunitoff = unitext->ext_offset;
		if (unitext->ext_offset <= wmext->ext_offset)
			unitext = unitext->ext_next;
		if (wmext->ext_offset <= tmpunitoff)
			wmext = wmext->ext_next;
	}

	/*
	 * if both lists aren't at the end then there are extra
	 * allocated nodes in one of them.
	 */
	if (wmext != NULL) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: extent headers contain allocations not in "
		    "the metadb\n\n"), np->cname);
		rval = -1;
	}

	if (unitext != NULL) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: metadb contains allocations not in the extent "
		    "headers\n\n"), np->cname);
		rval = -1;
	}

	if (options & MDCMD_PRINT) {
		if (rval == 0) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Soft Partition metadb matches extent "
			    "header configuration\n"), np->cname);
		} else {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "%s: Soft Partition metadb does not match extent "
			    "header configuration\n"), np->cname);
		}
	}

	return (rval);
}

/*
 * FUNCTION:	meta_sp_validate_exts()
 * INPUT:	compnp	- name pointer for device we are recovering from
 *		wmext	- extent node representing watermark
 *		unitext	- extent node from unit structure
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- 0 - succes, mdmderror return code - error
 * PURPOSE:	Takes two extent nodes and checks them against each other.
 *		offset, length, sequence number, set, and name are compared.
 */
static int
meta_sp_validate_exts(
	mdname_t	*compnp,
	sp_ext_node_t	*wmext,
	sp_ext_node_t	*unitext,
	md_error_t	*ep
)
{
	if (wmext->ext_offset != unitext->ext_offset) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: unit structure and extent header offsets differ.\n"),
		    compnp->cname);
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));
	}

	if (wmext->ext_length != unitext->ext_length) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: unit structure and extent header lengths differ.\n"),
		    compnp->cname);
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));
	}

	if (wmext->ext_seq != unitext->ext_seq) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: unit structure and extent header sequence numbers "
		    "differ.\n"), compnp->cname);
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));
	}

	if (wmext->ext_type != unitext->ext_type) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: unit structure and extent header types differ.\n"),
		    compnp->cname);
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));
	}

	/*
	 * If one has a set pointer and the other doesn't, error.
	 * If both extents have setnames, then make sure they match
	 * If both are NULL, it's ok, they match.
	 */
	if ((unitext->ext_setp == NULL) ^ (wmext->ext_setp == NULL)) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: unit structure and extent header set values "
		    "differ.\n"), compnp->cname);
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));
	}

	if (unitext->ext_setp != NULL) {
		if (strcmp(unitext->ext_setp->setname,
		    wmext->ext_setp->setname) != 0) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "%s: unit structure and extent header set names "
			    "differ.\n"), compnp->cname);
			return (mdmderror(ep, MDE_RECOVER_FAILED,
			    0, compnp->cname));
		}
	}

	/*
	 * If one has a name pointer and the other doesn't, error.
	 * If both extents have names, then make sure they match
	 * If both are NULL, it's ok, they match.
	 */
	if ((unitext->ext_namep == NULL) ^ (wmext->ext_namep == NULL)) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: unit structure and extent header name values "
		    "differ.\n"), compnp->cname);
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));
	}

	if (unitext->ext_namep != NULL) {
		if (strcmp(wmext->ext_namep->cname,
		    unitext->ext_namep->cname) != 0) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "%s: unit structure and extent header names "
			    "differ.\n"), compnp->cname);
			return (mdmderror(ep, MDE_RECOVER_FAILED,
			    0, compnp->cname));
		}
	}

	return (0);
}

/*
 * FUNCTION:	update_sp_status()
 * INPUT:	sp	- name of set we are recovering in
 *		minors	- pointer to an array of soft partition minor numbers
 *		num_sps	- number of minor numbers in array
 *		status	- new status to be applied to all soft parts in array
 *		mn_set	- set if current set is a multi-node set
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- 0 - success, -1 - error
 * PURPOSE:	update  status of soft partitions to new status. minors is an
 *		array of minor numbers to apply the new status to.
 *		If mn_set is set, a message is sent to all nodes in the
 *		cluster to update the status locally.
 */
static int
update_sp_status(
	mdsetname_t	*sp,
	minor_t		*minors,
	int		num_sps,
	sp_status_t	status,
	bool_t		mn_set,
	md_error_t	*ep
)
{
	int	i;
	int	err = 0;

	if (mn_set) {
		md_mn_msg_sp_setstat_t	sp_setstat_params;
		int			result;
		md_mn_result_t		*resp = NULL;

		for (i = 0; i < num_sps; i++) {
			sp_setstat_params.sp_setstat_mnum = minors[i];
			sp_setstat_params.sp_setstat_status = status;

			result = mdmn_send_message(sp->setno,
			    MD_MN_MSG_SP_SETSTAT, MD_MSGF_DEFAULT_FLAGS,
			    (char *)&sp_setstat_params,
			    sizeof (sp_setstat_params),
			    &resp, ep);
			if (resp != NULL) {
				if (resp->mmr_exitval != 0)
					err = -1;
				free_result(resp);
			}
			if (result != 0) {
				err = -1;
			}
		}
	} else {
		if (meta_sp_setstatus(sp, minors, num_sps, status, ep) < 0)
			err = -1;
	}
	if (err < 0) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "Error updating status on recovered soft "
		    "partitions.\n"));
	}
	return (err);
}

/*
 * FUNCTION:	meta_sp_recover_from_wm()
 * INPUT:	sp	- name of set we are recovering in
 *		compnp	- name pointer for component we are recovering from
 *		options	- metarecover options
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- 0 - success, -1 - error
 * PURPOSE:	update metadb records to match watermarks.  begin by getting
 *		an extlist representing all soft partitions on the component.
 *		then build a unit structure for each soft partition.
 *		notify user of changes, then commit each soft partition to
 *		the metadb one at a time in the "recovering" state.  update
 *		any watermarks that may need it	(to reflect possible name
 *		changes), and, finally, set the status of all recovered
 *		partitions to the "OK" state at once.
 */
static int
meta_sp_recover_from_wm(
	mdsetname_t	*sp,
	mdname_t	*compnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	sp_ext_node_t		*extlist = NULL;
	sp_ext_node_t		*sp_list = NULL;
	sp_ext_node_t		*update_list = NULL;
	sp_ext_node_t		*ext;
	sp_ext_node_t		*sp_ext;
	mp_unit_t		*mp;
	mp_unit_t		**un_array;
	int			numexts = 0, num_sps = 0, i = 0;
	int			err = 0;
	int			not_recovered = 0;
	int			committed = 0;
	sp_ext_length_t		sp_length = 0LL;
	mdnamelist_t		*keynlp = NULL;
	mdname_t		*np;
	mdname_t		*new_np;
	int			new_name;
	md_set_params_t		set_params;
	minor_t			*minors = NULL;
	char			yesno[255];
	char			*yes;
	bool_t			mn_set = 0;
	md_set_desc		*sd;
	mm_unit_t		*mm;
	md_set_mmown_params_t	*ownpar = NULL;
	int			comp_is_mirror = 0;

	/*
	 * if this component appears in another metadevice already, do
	 * NOT recover from it.
	 */
	if (meta_check_inmeta(sp, compnp, options, 0, -1, ep) != 0)
		return (-1);

	/* set flag if dealing with a MN set */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			return (-1);
		}
		if (MD_MNSET_DESC(sd))
			mn_set = 1;
	}
	/*
	 * for each watermark, build an ext_node, place on list.
	 */
	if (meta_sp_extlist_from_wm(sp, compnp, &extlist,
	    meta_sp_cmp_by_nameseq, ep) < 0)
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));

	assert(extlist != NULL);

	/* count number of soft partitions */
	for (ext = extlist;
	    ext != NULL && ext->ext_type == EXTTYP_ALLOC;
	    ext = ext->ext_next) {
		if (ext->ext_next != NULL &&
		    ext->ext_next->ext_namep != NULL &&
		    strcmp(ext->ext_next->ext_namep->cname,
		    ext->ext_namep->cname) == 0)
				continue;
		num_sps++;
	}

	/* allocate array of unit structure pointers */
	un_array = Zalloc(num_sps * sizeof (mp_unit_t *));

	/*
	 * build unit structures from list of ext_nodes.
	 */
	for (ext = extlist;
	    ext != NULL && ext->ext_type == EXTTYP_ALLOC;
	    ext = ext->ext_next) {
		meta_sp_list_insert(ext->ext_setp, ext->ext_namep,
		    &sp_list, ext->ext_offset, ext->ext_length,
		    ext->ext_type, ext->ext_seq, ext->ext_flags,
		    meta_sp_cmp_by_nameseq);

		numexts++;
		sp_length += ext->ext_length - MD_SP_WMSIZE;

		if (ext->ext_next != NULL &&
		    ext->ext_next->ext_namep != NULL &&
		    strcmp(ext->ext_next->ext_namep->cname,
		    ext->ext_namep->cname) == 0)
				continue;

		/*
		 * if we made it here, we are at a soft partition
		 * boundary in the list.
		 */
		if (getenv(META_SP_DEBUG)) {
			meta_sp_debug("meta_recover_from_wm: dumping wm "
			    "list:\n");
			meta_sp_list_dump(sp_list);
		}

		assert(sp_list != NULL);
		assert(sp_list->ext_namep != NULL);

		if ((new_name = meta_sp_resolve_name_conflict(sp,
		    sp_list->ext_namep, &new_np, ep)) < 0) {
			err = 1;
			goto out;
		} else if (new_name) {
			for (sp_ext = sp_list;
			    sp_ext != NULL;
			    sp_ext = sp_ext->ext_next) {
				/*
				 * insert into the update list for
				 * watermark update.
				 */
				meta_sp_list_insert(sp_ext->ext_setp,
				    new_np, &update_list, sp_ext->ext_offset,
				    sp_ext->ext_length, sp_ext->ext_type,
				    sp_ext->ext_seq, EXTFLG_UPDATE,
				    meta_sp_cmp_by_offset);
			}

		}
		if (options & MDCMD_DOIT) {
			/* store name in namespace */
			if (mn_set) {
				/* send message to all nodes to return key */
				md_mn_msg_addkeyname_t	*send_params;
				int			result;
				md_mn_result_t		*resp = NULL;
				int			message_size;

				message_size =  sizeof (*send_params) +
				    strlen(compnp->cname) + 1;
				send_params = Zalloc(message_size);
				send_params->addkeyname_setno = sp->setno;
				(void) strcpy(&send_params->addkeyname_name[0],
				    compnp->cname);
				result = mdmn_send_message(sp->setno,
				    MD_MN_MSG_ADDKEYNAME, MD_MSGF_DEFAULT_FLAGS,
				    (char *)send_params, message_size, &resp,
				    ep);
				Free(send_params);
				if (resp != NULL) {
					if (resp->mmr_exitval >= 0) {
						compnp->key =
						    (mdkey_t)resp->mmr_exitval;
					} else {
						err = 1;
						free_result(resp);
						goto out;
					}
					free_result(resp);
				}
				if (result != 0) {
					err = 1;
					goto out;
				}
				(void) metanamelist_append(&keynlp, compnp);
			} else {
				if (add_key_name(sp, compnp, &keynlp,
				    ep) != 0) {
					err = 1;
					goto out;
				}
			}
		}

		/* create the unit structure */
		if ((mp = meta_sp_createunit(
		    (new_name) ? new_np : sp_list->ext_namep, compnp,
		    sp_list, numexts, sp_length, MD_SP_RECOVER, ep)) == NULL) {
			err = 1;
			goto out;
		}

		if (getenv(META_SP_DEBUG)) {
			meta_sp_debug("meta_sp_recover_from_wm: "
			    "printing newly created unit structure");
			meta_sp_printunit(mp);
		}

		/* place in unit structure array */
		un_array[i++] = mp;

		/* free sp_list */
		meta_sp_list_free(&sp_list);
		sp_list = NULL;
		numexts = 0;
		sp_length = 0LL;
	}

	/* display configuration updates */
	(void) printf(dgettext(TEXT_DOMAIN,
	    "The following soft partitions were found and will be added to\n"
	    "your metadevice configuration.\n"));
	(void) printf("%5s %15s %18s\n",
	    dgettext(TEXT_DOMAIN, "Name"),
	    dgettext(TEXT_DOMAIN, "Size"),
	    dgettext(TEXT_DOMAIN, "No. of Extents"));
	for (i = 0; i < num_sps; i++) {
		(void) printf("%5s%lu %15llu %9d\n", "d",
		    MD_MIN2UNIT(MD_SID(un_array[i])),
		    un_array[i]->un_length, un_array[i]->un_numexts);
	}

	if (!(options & MDCMD_DOIT)) {
		not_recovered = 1;
		goto out;
	}

	/* ask user for confirmation */
	(void) printf(dgettext(TEXT_DOMAIN,
	    "WARNING: You are about to add one or more soft partition\n"
	    "metadevices to your metadevice configuration.  If there\n"
	    "appears to be an error in the soft partition(s) displayed\n"
	    "above, do NOT proceed with this recovery operation.\n"));
	(void) printf(dgettext(TEXT_DOMAIN,
	    "Are you sure you want to do this (yes/no)? "));

	(void) fflush(stdout);
	if ((fgets(yesno, sizeof (yesno), stdin) == NULL) ||
	    (strlen(yesno) == 1))
		(void) snprintf(yesno, sizeof (yesno), "%s\n",
		    dgettext(TEXT_DOMAIN, "no"));
	yes = dgettext(TEXT_DOMAIN, "yes");
	if (strncasecmp(yesno, yes, strlen(yesno) - 1) != 0) {
		not_recovered = 1;
		goto out;
	}

	/* commit records one at a time */
	for (i = 0; i < num_sps; i++) {
		(void) memset(&set_params, 0, sizeof (set_params));
		set_params.mnum = MD_SID(un_array[i]);
		set_params.size = (un_array[i])->c.un_size;
		set_params.mdp = (uintptr_t)(un_array[i]);
		set_params.options =
		    meta_check_devicesize(un_array[i]->un_length);
		if (set_params.options == MD_CRO_64BIT) {
			un_array[i]->c.un_revision |= MD_64BIT_META_DEV;
		} else {
			un_array[i]->c.un_revision &= ~MD_64BIT_META_DEV;
		}
		MD_SETDRIVERNAME(&set_params, MD_SP,
		    MD_MIN2SET(set_params.mnum));

		np = metamnumname(&sp, MD_SID(un_array[i]), 0, ep);

		/*
		 * If this is an MN set, send the MD_IOCSET ioctl to all nodes
		 */
		if (mn_set) {
			md_mn_msg_iocset_t	send_params;
			int			result;
			md_mn_result_t		*resp = NULL;
			int			mess_size;

			/*
			 * Calculate message size. md_mn_msg_iocset_t only
			 * contains one extent, so increment the size to
			 * include all extents
			 */
			mess_size = sizeof (send_params) -
			    sizeof (mp_ext_t) +
			    (un_array[i]->un_numexts * sizeof (mp_ext_t));

			send_params.iocset_params = set_params;
			(void) memcpy(&send_params.unit, un_array[i],
			    sizeof (*un_array[i]) - sizeof (mp_ext_t) +
			    (un_array[i]->un_numexts * sizeof (mp_ext_t)));
			result = mdmn_send_message(sp->setno,
			    MD_MN_MSG_IOCSET, MD_MSGF_DEFAULT_FLAGS,
			    (char *)&send_params, mess_size, &resp,
			    ep);
			if (resp != NULL) {
				if (resp->mmr_exitval != 0)
					err = 1;
				free_result(resp);
			}
			if (result != 0) {
				err = 1;
			}
		} else {
			if (metaioctl(MD_IOCSET, &set_params, &set_params.mde,
			    np->cname) != 0) {
				err = 1;
			}
		}

		if (err == 1) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "%s: Error committing record to metadb.\n"),
			    np->cname);
			goto out;
		}

		/* note that we've committed a record */
		if (!committed)
			committed = 1;

		/* update any watermarks that need it */
		if (update_list != NULL) {
			md_sp_t *msp;

			/*
			 * Check to see if we're trying to create a partition
			 * on a mirror. If so we may have to enforce an
			 * ownership change before writing the watermark out.
			 */
			if (metaismeta(compnp)) {
				char *miscname;

				miscname = metagetmiscname(compnp, ep);
				if (miscname != NULL)
					comp_is_mirror = (strcmp(miscname,
					    MD_MIRROR) == 0);
				else
					comp_is_mirror = 0;
			}
			/*
			 * If this is a MN set and the component is a mirror,
			 * change ownership to this node in order to write the
			 * watermarks
			 */
			if (mn_set && comp_is_mirror) {
				mm = (mm_unit_t *)meta_get_unit(sp, compnp, ep);
				if (mm == NULL) {
					err = 1;
					goto out;
				} else {
					err = meta_mn_change_owner(&ownpar,
					    sp->setno,
					    meta_getminor(compnp->dev),
					    sd->sd_mn_mynode->nd_nodeid,
					    MD_MN_MM_PREVENT_CHANGE |
					    MD_MN_MM_SPAWN_THREAD);
					if (err != 0)
						goto out;
				}
			}

			if ((msp = meta_get_sp(sp, np, ep)) == NULL) {
				err = 1;
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "%s: Error updating extent headers.\n"),
				    np->cname);
				goto out;
			}
			if (meta_sp_update_wm(sp, msp, update_list, ep) < 0) {
				err = 1;
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "%s: Error updating extent headers "
				    "on disk.\n"), np->cname);
				goto out;
			}
		}
		/*
		 * If we have changed ownership earlier and prevented any
		 * ownership changes, we can now allow ownership changes
		 * again.
		 */
		if (ownpar) {
			(void) meta_mn_change_owner(&ownpar, sp->setno,
			    ownpar->d.mnum,
			    ownpar->d.owner,
			    MD_MN_MM_ALLOW_CHANGE | MD_MN_MM_SPAWN_THREAD);
		}
	}

	/* update status of all soft partitions to OK */
	minors = Zalloc(num_sps * sizeof (minor_t));
	for (i = 0; i < num_sps; i++)
		minors[i] = MD_SID(un_array[i]);

	err = update_sp_status(sp, minors, num_sps, MD_SP_OK, mn_set, ep);
	if (err != 0)
		goto out;

	if (options & MDCMD_PRINT)
		(void) printf(dgettext(TEXT_DOMAIN, "%s: "
		    "Soft Partitions recovered from device.\n"),
		    compnp->cname);
out:
	/* free memory */
	if (extlist != NULL)
		meta_sp_list_free(&extlist);
	if (sp_list != NULL)
		meta_sp_list_free(&sp_list);
	if (update_list != NULL)
		meta_sp_list_free(&update_list);
	if (un_array != NULL)	{
		for (i = 0; i < num_sps; i++)
			Free(un_array[i]);
		Free(un_array);
	}
	if (minors != NULL)
		Free(minors);
	if (ownpar != NULL)
		Free(ownpar);
	(void) fflush(stdout);

	if ((keynlp != NULL) && (committed != 1)) {
		/*
		 * if we haven't committed any softparts, either because of an
		 * error or because the user decided not to proceed, delete
		 * namelist key for the component
		 */
		if (mn_set) {
			mdnamelist_t	*p;

			for (p = keynlp; (p != NULL); p = p->next) {
				mdname_t		*np = p->namep;
				md_mn_msg_delkeyname_t	send_params;
				md_mn_result_t		*resp = NULL;

				send_params.delkeyname_dev = np->dev;
				send_params.delkeyname_setno = sp->setno;
				send_params.delkeyname_key = np->key;
				(void) mdmn_send_message(sp->setno,
				    MD_MN_MSG_DELKEYNAME, MD_MSGF_DEFAULT_FLAGS,
				    (char *)&send_params, sizeof (send_params),
				    &resp, ep);
				if (resp != NULL) {
					free_result(resp);
				}
			}
		} else {
			(void) del_key_names(sp, keynlp, NULL);
		}
	}

	metafreenamelist(keynlp);

	if (err)
		return (mdmderror(ep, MDE_RECOVER_FAILED, 0, compnp->cname));

	if (not_recovered)
		if (options & MDCMD_PRINT)
			(void) printf(dgettext(TEXT_DOMAIN, "%s: "
			    "Soft Partitions NOT recovered from device.\n"),
			    compnp->cname);
	return (0);
}

/*
 * FUNCTION:	meta_sp_recover_from_unit()
 * INPUT:	sp	- name of set we are recovering in
 *		compnp	- name of component we are recovering from
 *		options	- metarecover options
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- 0 - success, -1 - error
 * PURPOSE:	update watermarks to match metadb records.  begin by getting
 *		a namelist representing all soft partitions on the specified
 *		component.  then, build an extlist representing the soft
 *		partitions, filling in the freespace extents.  notify user
 *		of changes, place all soft partitions into the "recovering"
 *		state and update the watermarks.  finally, return all soft
 *		partitions to the "OK" state.
 */
static int
meta_sp_recover_from_unit(
	mdsetname_t	*sp,
	mdname_t	*compnp,
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdnamelist_t	*spnlp = NULL;
	mdnamelist_t	*nlp = NULL;
	sp_ext_node_t	*ext = NULL;
	sp_ext_node_t	*extlist = NULL;
	int		count;
	char		yesno[255];
	char		*yes;
	int		rval = 0;
	minor_t		*minors = NULL;
	int		i;
	md_sp_t		*msp;
	md_set_desc	*sd;
	bool_t		mn_set = 0;
	daddr_t		start_block;

	count = meta_sp_get_by_component(sp, compnp, &spnlp, 0, ep);
	if (count <= 0)
		return (-1);

	/* set flag if dealing with a MN set */
	if (!metaislocalset(sp)) {
		if ((sd = metaget_setdesc(sp, ep)) == NULL) {
			return (-1);
		}
		if (MD_MNSET_DESC(sd))
			mn_set = 1;
	}
	/*
	 * Save the XDR unit structure for one of the soft partitions;
	 * we'll use this later to provide metadevice context to
	 * update the watermarks so the device can be resolved by
	 * devid instead of dev_t.
	 */
	if ((msp = meta_get_sp(sp, spnlp->namep, ep)) == NULL) {
		metafreenamelist(spnlp);
		return (-1);
	}

	if ((start_block = meta_sp_get_start(sp, compnp, ep)) ==
	    MD_DISKADDR_ERROR) {
		return (-1);
	}

	meta_sp_list_insert(NULL, NULL, &extlist, 0ULL, start_block,
	    EXTTYP_RESERVED, 0, 0, meta_sp_cmp_by_offset);
	meta_sp_list_insert(NULL, NULL, &extlist,
	    metagetsize(compnp, ep) - MD_SP_WMSIZE, MD_SP_WMSIZE,
	    EXTTYP_END, 0, EXTFLG_UPDATE, meta_sp_cmp_by_offset);

	if (meta_sp_extlist_from_namelist(sp, spnlp, &extlist, ep) == -1) {
		metafreenamelist(spnlp);
		return (-1);
	}

	assert(extlist != NULL);
	if ((options & MDCMD_VERBOSE) != 0) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "Updating extent headers on device %s from metadb.\n\n"),
		    compnp->cname);
		(void) printf(dgettext(TEXT_DOMAIN,
		    "The following extent headers will be written:\n"));
		meta_sp_display_exthdr();
	}

	meta_sp_list_freefill(&extlist, metagetsize(compnp, ep));

	for (ext = extlist; ext != NULL; ext = ext->ext_next) {

		/* mark every node for updating except the reserved space */
		if (ext->ext_type != EXTTYP_RESERVED) {
			ext->ext_flags |= EXTFLG_UPDATE;

			/* print extent information */
			if ((options & MDCMD_VERBOSE) != 0)
				meta_sp_display_ext(ext);
		}
	}

	/* request verification and then update all watermarks */
	if ((options & MDCMD_DOIT) != 0) {

		(void) printf(dgettext(TEXT_DOMAIN,
		    "\nWARNING: You are about to overwrite portions of %s\n"
		    "with soft partition metadata. The extent headers will be\n"
		    "written to match the existing metadb configuration.  If\n"
		    "the device was not previously setup with this\n"
		    "configuration, data loss may result.\n\n"),
		    compnp->cname);
		(void) printf(dgettext(TEXT_DOMAIN,
		    "Are you sure you want to do this (yes/no)? "));

		(void) fflush(stdout);
		if ((fgets(yesno, sizeof (yesno), stdin) == NULL) ||
		    (strlen(yesno) == 1))
			(void) snprintf(yesno, sizeof (yesno),
			    "%s\n", dgettext(TEXT_DOMAIN, "no"));
		yes = dgettext(TEXT_DOMAIN, "yes");
		if (strncasecmp(yesno, yes, strlen(yesno) - 1) == 0) {
			/* place soft partitions into recovering state */
			minors = Zalloc(count * sizeof (minor_t));
			for (nlp = spnlp, i = 0;
			    nlp != NULL && i < count;
			    nlp = nlp->next, i++) {
				assert(nlp->namep != NULL);
				minors[i] = meta_getminor(nlp->namep->dev);
			}
			if (update_sp_status(sp, minors, count,
			    MD_SP_RECOVER, mn_set, ep) != 0) {
				rval = -1;
				goto out;
			}

			/* update the watermarks */
			if (meta_sp_update_wm(sp, msp, extlist, ep) < 0) {
				rval = -1;
				goto out;
			}

			if (options & MDCMD_PRINT) {
				(void) printf(dgettext(TEXT_DOMAIN, "%s: "
				    "Soft Partitions recovered from metadb\n"),
				    compnp->cname);
			}

			/* return soft partitions to the OK state */
			if (update_sp_status(sp, minors, count,
			    MD_SP_OK, mn_set, ep) != 0) {
				rval = -1;
				goto out;
			}

			rval = 0;
			goto out;
		}
	}

	if (options & MDCMD_PRINT) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "%s: Soft Partitions NOT recovered from metadb\n"),
		    compnp->cname);
	}

out:
	if (minors != NULL)
		Free(minors);
	metafreenamelist(spnlp);
	meta_sp_list_free(&extlist);
	(void) fflush(stdout);
	return (rval);
}


/*
 * FUNCTION:	meta_sp_update_abr()
 * INPUT:	sp	- name of set we are recovering in
 * OUTPUT:	ep	- return error pointer
 * RETURNS:	int	- 0 - success, -1 - error
 * PURPOSE:	update the ABR state for all soft partitions in the set. This
 *		is called when joining a set. It sends a message to the master
 *		node for each soft partition to get the value of tstate and
 *		then sets ABR ,if required, by opening the sp, setting ABR
 *		and then closing the sp. This approach is taken rather that
 *		just issuing the MD_MN_SET_CAP ioctl, in order to deal with
 *		the case when we have another node simultaneously unsetting ABR.
 */
int
meta_sp_update_abr(
	mdsetname_t	*sp,
	md_error_t	*ep
)
{
	mdnamelist_t	*devnlp = NULL;
	mdnamelist_t	*p;
	mdname_t	*devnp = NULL;
	md_unit_t	*un;
	char		fname[MAXPATHLEN];
	int		mnum, fd;
	volcap_t	vc;
	uint_t		tstate;


	if (meta_get_sp_names(sp, &devnlp, 0, ep) < 0) {
		return (-1);
	}

	/* Exit if no soft partitions in this set */
	if (devnlp == NULL)
		return (0);

	/* For each soft partition */
	for (p = devnlp; (p != NULL); p = p->next) {
		devnp = p->namep;

		/* check if this is a top level metadevice */
		if ((un = meta_get_mdunit(sp, devnp, ep)) == NULL)
			goto out;
		if (MD_HAS_PARENT(MD_PARENT(un))) {
			Free(un);
			continue;
		}
		Free(un);

		/* Get tstate from Master */
		if (meta_mn_send_get_tstate(devnp->dev, &tstate, ep) != 0) {
			mdname_t	*np;
			np = metamnumname(&sp, meta_getminor(devnp->dev), 0,
			    ep);
			if (np) {
				md_perror(dgettext(TEXT_DOMAIN,
				    "Unable to get tstate for %s"), np->cname);
			}
			continue;
		}
		/* If not set on the master, nothing to do */
		if (!(tstate & MD_ABR_CAP))
			continue;

		mnum = meta_getminor(devnp->dev);
		(void) snprintf(fname, MAXPATHLEN, "/dev/md/%s/rdsk/d%u",
		    sp->setname, (unsigned)MD_MIN2UNIT(mnum));
		if ((fd = open(fname, O_RDWR, 0)) < 0) {
			md_perror(dgettext(TEXT_DOMAIN,
			    "Could not open device %s"), fname);
			continue;
		}

		/* Set ABR state */
		vc.vc_info = 0;
		vc.vc_set = 0;
		if (ioctl(fd, DKIOCGETVOLCAP, &vc) < 0) {
			(void) close(fd);
			continue;
		}

		vc.vc_set = DKV_ABR_CAP;
		if (ioctl(fd, DKIOCSETVOLCAP, &vc) < 0) {
			(void) close(fd);
			goto out;
		}

		(void) close(fd);
	}
	metafreenamelist(devnlp);
	return (0);
out:
	metafreenamelist(devnlp);
	return (-1);
}

/*
 * FUNCTION:	meta_mn_sp_update_abr()
 * INPUT:	arg	- Given set.
 * PURPOSE:	update the ABR state for all soft partitions in the set by
 *		forking a process to call meta_sp_update_abr()
 *		This function is only called via rpc.metad when adding a node
 *		to a set, ie this node is beong joined to the set by another
 *		node.
 */
void *
meta_mn_sp_update_abr(void *arg)
{
	set_t		setno = *((set_t *)arg);
	mdsetname_t	*sp;
	md_error_t	mde = mdnullerror;
	int		fval;

	/* should have a set */
	assert(setno != NULL);

	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		mde_perror(&mde, "");
		return (NULL);
	}

	if (!(meta_is_mn_set(sp, &mde))) {
		mde_perror(&mde, "");
		return (NULL);
	}

	/* fork a process */
	if ((fval = md_daemonize(sp, &mde)) != 0) {
		/*
		 * md_daemonize will fork off a process.  The is the
		 * parent or error.
		 */
		if (fval > 0) {
			return (NULL);
		}
		mde_perror(&mde, "");
		return (NULL);
	}
	/*
	 * Child process should never return back to rpc.metad, but
	 * should exit.
	 * Flush all internally cached data inherited from parent process
	 * since cached data will be cleared when parent process RPC request
	 * has completed (which is possibly before this child process
	 * can complete).
	 * Child process can retrieve and cache its own copy of data from
	 * rpc.metad that won't be changed by the parent process.
	 *
	 * Reset md_in_daemon since this child will be a client of rpc.metad
	 * not part of the rpc.metad daemon itself.
	 * md_in_daemon is used by rpc.metad so that libmeta can tell if
	 * this thread is rpc.metad or any other thread.  (If this thread
	 * was rpc.metad it could use some short circuit code to get data
	 * directly from rpc.metad instead of doing an RPC call to rpc.metad).
	 */
	md_in_daemon = 0;
	metaflushsetname(sp);
	sr_cache_flush_setno(setno);
	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		mde_perror(&mde, "");
		md_exit(sp, 1);
	}


	/*
	 * Closing stdin/out/err here.
	 */
	(void) close(0);
	(void) close(1);
	(void) close(2);
	assert(fval == 0);

	(void) meta_sp_update_abr(sp, &mde);

	md_exit(sp, 0);
	/*NOTREACHED*/
	return (NULL);
}

int
meta_sp_check_component(
	mdsetname_t	*sp,
	mdname_t	*np,
	md_error_t	*ep
)
{
	md_sp_t	*msp;
	minor_t	mnum = 0;
	md_dev64_t	dev = 0;
	mdnm_params_t	nm;
	md_getdevs_params_t	mgd;
	side_t	sideno;
	char	*miscname;
	md_dev64_t	*mydev = NULL;
	char	*pname = NULL, *t;
	char	*ctd_name = NULL;
	char	*devname = NULL;
	int	len;
	int	rval = -1;

	(void) memset(&nm, '\0', sizeof (nm));
	if ((msp = meta_get_sp_common(sp, np, 0, ep)) == NULL)
		return (-1);

	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (-1);

	sideno = getmyside(sp, ep);

	meta_sp_debug("meta_sp_check_component: %s is on %s key: %d"
	    " dev: %llu\n",
	    np->cname, msp->compnamep->cname, msp->compnamep->key,
	    msp->compnamep->dev);

	/*
	 * Now get the data from the unit structure. The compnamep stuff
	 * contains the data from the namespace and we need the un_dev
	 * from the unit structure.
	 */
	(void) memset(&mgd, '\0', sizeof (mgd));
	MD_SETDRIVERNAME(&mgd, miscname, sp->setno);
	mgd.cnt = 1;		    /* sp's only have one subdevice */
	mgd.mnum = meta_getminor(np->dev);

	mydev = Zalloc(sizeof (*mydev));
	mgd.devs = (uintptr_t)mydev;

	if (metaioctl(MD_IOCGET_DEVS, &mgd, &mgd.mde, np->cname) != 0) {
		meta_sp_debug("meta_sp_check_component: ioctl failed\n");
		(void) mdstealerror(ep, &mgd.mde);
		rval = 0;
		goto out;
	} else if (mgd.cnt <= 0) {
		assert(mgd.cnt >= 0);
		rval = 0;
		goto out;
	}

	/* Get the devname from the name space. */
	if ((devname = meta_getnmentbykey(sp->setno, sideno,
	    msp->compnamep->key, NULL, &mnum, &dev, ep)) == NULL) {
		meta_sp_debug("meta_sp_check_component: key %d not"
		    "found\n", msp->compnamep->key);
		goto out;
	}

	meta_sp_debug("dev %s from component: (%lu, %lu)\n",
	    devname,
	    meta_getmajor(*mydev),
	    meta_getminor(*mydev));
	meta_sp_debug("minor from the namespace: %lu\n", mnum);

	if (mnum != meta_getminor(*mydev)) {
		/*
		 * The minor numbers are different. Update the namespace
		 * with the information from the component.
		 */

		t = strrchr(devname, '/');
		t++;
		ctd_name = Strdup(t);

		meta_sp_debug("meta_sp_check_component: ctd_name: %s\n",
		    ctd_name);

		len = strlen(devname);
		t = strrchr(devname, '/');
		t++;
		pname = Zalloc((len - strlen(t)) + 1);
		(void) strncpy(pname, devname, (len - strlen(t)));
		meta_sp_debug("pathname: %s\n", pname);

		meta_sp_debug("updating the minor number to %lu\n", nm.mnum);

		if (meta_update_namespace(sp->setno, sideno,
		    ctd_name, *mydev, msp->compnamep->key, pname,
		    ep) != 0) {
			goto out;
		}
	}
out:
	if (pname != NULL)
		Free(pname);
	if (ctd_name != NULL)
		Free(ctd_name);
	if (devname != NULL)
		Free(devname);
	if (mydev != NULL)
		Free(mydev);
	return (rval);
}
