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

#include <meta.h>
#include <assert.h>
#include <ctype.h>
#include <mdiox.h>
#include <meta.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <strings.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_names.h>
#include <sys/lvm/md_crc.h>
#include <sys/lvm/md_convert.h>


/*
 * Design Notes:
 *
 * All of the code in this file supports the addition of metastat -c output
 * for the verbose option of metaimport.  Some of this code is also used by
 * the command metastat for concise output(cmd/lvm/util/metastat.c).
 * The code is designed to produce the same output as metastat -c does for a
 * given diskset--with a couple exceptions.
 * The primary differences between the output for the metastat -c command and
 * metastat output for metaimport -v are:
 *  - the set name is not printed next to each metadevice
 *  - top-level state information is not printed for some metadevices
 *  - the percent that a disk has completed resyncing is not listed
 * in metaimport -v.
 *
 *
 * The general layout of this file is as follows:
 *
 *  - report_metastat_info()
 *	This is the primary entry point for the functions in this file, with
 *	the exception of several functions that are also called from
 *	cmd/io/lvm/util/metastat.c
 *	report_metastat_info() calls functions to read in all the the
 *	Directory blocks and Record blocks and then process the information
 *	needed to print out the metadevice records in the same format as
 *	metastat -c.
 *
 *  - read_all_mdrecords()
 *	Reads in all the Directory blocks in the diskset and verifies their
 *	validity.  For each Directly block, it loops through all Directory
 *	Entries and for each one that contains a metadevice record calls
 *	read_md_record().  Because the output is designed to imitate the
 *	output of metastat -c, we ignore metadevice records for
 *	optimized resync, changelog, and translog.
 *
 *  - read_md_record()
 *	Reads in a Directory Entry and its associated Record block.  The
 *	revision information for the Record block is checked and it is
 *	determined whether or not it is a 64bit Record block or a 32bit record
 *	block.  For each valid Record block, it allocates an md_im_rec_t
 *	structure and calls extract_mduser_data().
 *
 *  - extract_mduser_data()
 *	Populates the md_im_rec_t data structure with information about the
 *	record's associated metadevice.  Also, the name of the metadevice is
 *	either copied from the NM namespace(if it exists there) or is generated
 *	from the record's un_self_id.
 *
 *  - process_toplevel_devices()
 *	For a given metadevice type, searchs through the md_im_rec_t **mdimpp,
 *	list of all metadevices in the set, to find all records of the
 *	specified type that do not have a parent and puts them on a temp list.
 *	The temp list is then iterated through and the associated processing
 *	function is called.
 *
 *  - process_(trans, hotspare, hotspare_pool, soft_part, mirror, stripe, raid)
 *	These functions are called by using the dfunc field in the mdimpp list.
 *	Each process function only understands its own type of metadevice. Once
 *	it processes the metadevice it was called for, it then loops through
 *	all of the underlying metadevices.  After printing the name of the
 *	underlying metadevice, it puts in on a list to be processed.  If the
 *	underlying device is a physical device, then print_physical_device is
 *	called.
 *	Once all information about the original metadevice is processed, it
 *	loops through the list of underlying metadevices and calls the
 *	appropriate function to process them.
 *
 *  - process_toplevel_softparts()
 *	To match the output for metastat -c, all top-level softpartions
 *	are printed out in groups based on their underlying metadevice--so that
 *	the underlying metadevice only needs to be processed once.
 *
 *  - meta_get_(sm_state, raid_col_state, stripe_state, hs_state)
 *	These functions are used to retrieve the metadevice state information.
 *	They are also used by the metastat concise routines in
 *	cmd/lvm/util/metastat.c.
 *
 */


/*
 * md_im_rec is a doubly linked list used to store the rb_data for each
 * directory entry that corresponds to a metadevice.
 * n_key: is set, if there is an associated entry in the NM namespace.
 * dfunc: is set to point to the function that processes the particular
 * metadevice associated with the record.
 * hs_record_id: is only set, if the metadevice is a hotspare.
 * un_self_id: is set for all other records. This is also used to generate
 * the name of the metadevice if there is no entry for the metadevice in
 * the NM namespace--n_key is not set.
 */
typedef struct md_im_rec {
	mdkey_t			n_key; /* NM namespace key */
	struct md_im_rec 	*next;
	struct md_im_rec 	*prev;
	uint_t			md_type;
	uint_t			has_parent; /* either 0(no parent) or 1 */
	minor_t			un_self_id;
	mddb_recid_t		hs_record_id; /* hotspare recid */
	char 			*n_name;  /* name of metadevice */
	void 			(*dfunc) ();
	ushort_t		record_len;
	/* pointer to the unit structure for the metadevice, e.g. rb_data[0] */
	void			*record;
} md_im_rec_t;

/*
 * md_im_list is used to group toplevel metadevices by type and to group
 * the underlying devices for a particular metadevice.
 */
typedef struct md_im_list {
	struct md_im_list	*next;
	struct md_im_rec 	*mdrec;
} md_im_list_t;


/*
 * MAXSIZEMDRECNAME is the value that has historically been used to allocate
 * space for the metadevice name
 */
#define	MAXSIZEMDRECNAME	20
#define	NAMEWIDTH		16
#define	NOT_PHYSICAL_DEV	0
#define	PHYSICAL_DEV		1


/*
 * strip_blacks()
 *
 * Strip blanks from string.  Used for size field in concise output.
 */
static char *
strip_blanks(char *s)
{
	char *p;

	for (p = s; *p; ) {
		if (*p == ' ') {
			char *t;
			for (t = p; *t; t++) {
				*t = *(t + 1);
			}
		} else {
			p++;
		}
	}

	return (s);
}


/*
 * print_concise_entry()
 *
 * Print properly indented metadevice name, type and size for concise output.
 * This function is also called from: cmd/lvm/util/metastat.c.
 */
void
print_concise_entry(int indent, char *name, diskaddr_t size, char mtype)
{
	int	i;
	int	width = NAMEWIDTH;	/* minumum field width for name */
	char	in[MAXPATHLEN];
	char	*sz;

	in[0] = 0;
	for (i = 0; i < indent; i++)
		(void) strlcat(in, " ", sizeof (in));

	/* set up minimum field width. negative for left justified */
	width -= indent;
	if (width < 0)
		width = 0;	/* overflowed; no minimum field needed */
	else
		width = 0 - width; /* negative for left justification */

	if (size == 0) {
		sz = "-";
	} else {
		sz = strip_blanks(meta_number_to_string(size, DEV_BSIZE));
	}

	(void) printf("%s%*s %c %6s", in, width, name, mtype, sz);
}


/*
 * free_mdrec_list_entry()
 *
 * Removing entry from the list of metadevices in the diskset(mdimpp).
 * This function will not remove the dummy entry at the head of the
 * list, so we don't have to set mdrec equal to NULL.
 */
static void
free_mdrec_list_entry(md_im_rec_t  **mdrec)
{
	(*mdrec)->prev->next = (*mdrec)->next;
	if ((*mdrec)->next != NULL) {
		(*mdrec)->next->prev = (*mdrec)->prev;
	}
	Free((*mdrec)->record);
	Free((*mdrec)->n_name);
	Free(*mdrec);
}


/*
 * ucomponent_append()
 *
 * Appending entry to the underlying component list.  The list
 * is used to group all of the underlying devices before
 * processing them.
 */
static void
ucomponent_append(
	md_im_list_t	**ucomp_head,
	md_im_list_t	**ucomp_tail,
	md_im_list_t	*ucomp
)
{
	ucomp->next = NULL;
	if (*ucomp_head == NULL) {
		*ucomp_head = ucomp;
		*ucomp_tail = ucomp;
	} else {
		(*ucomp_tail)->next = ucomp;
		*ucomp_tail = (*ucomp_tail)->next;
	}
}


/*
 * free_md_im_list_entries()
 *
 * Freeing entries on an md_im_list_t.  This list is used to group
 * underlying components for processing and to group top-level metadevices
 * by type.
 */
static void
free_md_im_list_entries(md_im_list_t **list_head)
{
	md_im_list_t	*tmp_list_entry = *list_head;
	md_im_list_t	*rm_list_entry;

	while (tmp_list_entry != NULL) {
		rm_list_entry = tmp_list_entry;
		tmp_list_entry = tmp_list_entry->next;
		Free(rm_list_entry);
	}
}


/*
 * print_physical_device()
 *
 * If a metadevice has an underlying component that is a physical
 * device, then this searches the pnm_rec_t list to match an entry's
 * n_key to the key for the underlying component.  The ctd name of the
 * physical device is printed on the same line as the metadevice.
 */
static void
print_physical_device(
	pnm_rec_t	*phys_nm,
	mdkey_t		key
)
{
	pnm_rec_t	*tmpphys_nm;

	for (tmpphys_nm = phys_nm; tmpphys_nm != NULL;
	    tmpphys_nm = tmpphys_nm->next) {
		if (tmpphys_nm->n_key == key) {
			(void) printf(" %s", tmpphys_nm->n_name);
			break;
		}
	}
}


/*
 * get_stripe_req_size()
 *
 * Given a 64bit stripe unit, compute the size of the stripe unit.
 * This function is a derivation of:
 *	common/lvm/md_convert.c:get_big_stripe_req_size()
 * and any changes made to either this function or get_big_stripe_req_size()
 * should be reviewed to make sure the functionality in both places is correct.
 *
 * Returns:
 *	total size of the 64bit stripe
 */
size_t
get_stripe_req_size(ms_unit_t *un)
{
	struct ms_row *mdr;
	uint_t row;
	uint_t ncomps = 0;
	size_t mdsize = 0;
	size_t first_comp = 0;


	/* Compute the offset of the first component */
	first_comp = sizeof (ms_unit_t) +
	    sizeof (struct ms_row) * (un->un_nrows - 1);
	first_comp = roundup(first_comp, sizeof (long long));

	/*
	 * Requestor wants to have the total size, add the sizes of
	 * all components
	 */
	mdr = &un->un_row[0];
	for (row = 0; (row < un->un_nrows); row++)
	    ncomps += mdr[row].un_ncomp;
	mdsize = first_comp + sizeof (ms_comp_t) * ncomps;
	return (mdsize);
}


/*
 * meta_get_sm_state()
 *
 * Gets the state for the underlying components(submirrors) of a mirror.
 * This function is also called from: cmd/lvm/util/metastat.c.
 *
 * Returns:
 *	string for state of the sub-mirror
 */
static char *
meta_get_sm_state(
	sm_state_t	state
)
{
	/* all is well */
	if (state & SMS_RUNNING) {
		return (NULL);
	}

	/* resyncing, needs repair */
	if ((state & (SMS_COMP_RESYNC | SMS_ATTACHED_RESYNC |
	    SMS_OFFLINE_RESYNC))) {
		return (gettext("resyncing"));
	}

	/* needs repair */
	if (state & (SMS_COMP_ERRED | SMS_ATTACHED | SMS_OFFLINE))
		return (gettext("maint"));

	/* unknown */
	return (gettext("unknown"));
}


/*
 * meta_get_raid_col_state()
 *
 * Gets the state for the underlying components(columns) of a raid.
 * This function is also called from: cmd/lvm/util/metastat.c.
 *
 * Returns:
 *	string for state of the raid column
 *
 */
char *
meta_get_raid_col_state(
	rcs_state_t	state
)
{
	switch (state) {
		case RCS_INIT:
			return (gettext("initializing"));
		case RCS_OKAY:
			return (NULL);
		case RCS_INIT_ERRED:
			/*FALLTHROUGH*/
		case RCS_ERRED:
			return (gettext("maint"));
		case RCS_LAST_ERRED:
			return (gettext("last-erred"));
		case RCS_RESYNC:
			return (gettext("resyncing"));
		default:
			return (gettext("unknown"));
	}
}


/*
 * meta_get_stripe_state()
 *
 * Gets the state for the underlying components of a stripe.
 * This function is also called from: cmd/lvm/util/metastat.c.
 *
 * Returns:
 *	string for state of the stripe
 *
 */
char *
meta_get_stripe_state(
	comp_state_t	state
)
{
	switch (state) {
		case CS_OKAY:
			return (NULL);
		case CS_ERRED:
			return (gettext("maint"));
		case CS_LAST_ERRED:
			return (gettext("last-erred"));
		case CS_RESYNC:
			return (gettext("resyncing"));
		default:
			return (gettext("invalid"));
	}
}


/*
 * meta_get_hs_state()
 *
 * Gets the state for the underlying components(hotspares) of a hotspare pool.
 * This function is also called from: cmd/lvm/util/metastat.c.
 *
 * Returns:
 *	string for state of the hotspare
 *
 */
char *
meta_get_hs_state(
	hotspare_states_t	state
)
{
	switch (state) {
		case HSS_AVAILABLE:
			return (NULL);
		case HSS_RESERVED:
			return (gettext("in-use"));
		case HSS_BROKEN:
			return (gettext("broken"));
		case HSS_UNUSED:
			/* FALLTHROUGH */
		default:
			return (gettext("invalid"));
	}
}


/*
 * process_trans()
 *
 * Prints unit information for a trans metadevice and calls the respective
 * functions to process the underlying metadevices.
 *
 */
static void
process_trans(
	md_im_rec_t	**mdimpp,
	int		indent,
	pnm_rec_t	*phys_nm,
	md_im_rec_t	*mdrec
)
{
	mt_unit_t	*mt;
	mdc_unit_t	uc;
	md_im_rec_t	*tmpmdrec;
	int		underlying_device = PHYSICAL_DEV;

	mt = (mt_unit_t *)mdrec->record;
	uc = mt->c;

	/* Printing name, size, and type of metadevice */
	print_concise_entry(indent, mdrec->n_name,
	    uc.un_total_blocks, 't');

	/*
	 * Loops through md_im_rec_t **mdimpp list of all metadevices to find
	 * record that matches the underlying device.
	 * Trans devices can only have one underlying device, so once a
	 * match is found, we are done.
	 */
	for (tmpmdrec = *mdimpp; tmpmdrec != NULL;
	    tmpmdrec = tmpmdrec->next) {
		if (tmpmdrec->n_key == mt->un_m_key) {
			/* Printing name of the underlying metadevice */
			(void) printf(" %s", tmpmdrec->n_name);
			underlying_device = NOT_PHYSICAL_DEV;
			break;
		}
	}

	/*
	 * If a metadevice was not found, then the underlying device must be a
	 * physical device.  Otherwise, call the functions to process the
	 * underlying devices.
	 */
	if (underlying_device == PHYSICAL_DEV) {
		print_physical_device(phys_nm, mt->un_m_key);
		(void) printf("\n");
	} else {
		/* process underlying component */
		(void) printf("\n");
		indent += META_INDENT;
		tmpmdrec->dfunc(mdimpp, indent, phys_nm, tmpmdrec);
	}

	/*
	 * Removing the md_entry from the list
	 * of all metadevices
	 */
	free_mdrec_list_entry(&mdrec);
}


/*
 * process_hotspare()
 *
 * Searches though list of physical devices to match hotspare record.
 * Prints physical device name and state of a hotspare unit.
 *
 */
/*ARGSUSED*/
static void
process_hotspare(
	md_im_rec_t	**mdimpp,
	int		indent,
	pnm_rec_t	*phys_nm,
	md_im_rec_t	*mdrec
)
{
	hot_spare_t	*hs;
	pnm_rec_t	*tmpphys_nm;
	char 		*state = NULL;

	hs =  (hot_spare_t *)mdrec->record;

	/*
	 * Loops through physical namespace to find the device that matches
	 * the hotspare entry.
	 */
	for (tmpphys_nm = phys_nm; tmpphys_nm != NULL;
	    tmpphys_nm = tmpphys_nm->next) {
		if (tmpphys_nm->n_key ==
		    ((hot_spare_t *)hs)->hs_key) {
			/* Printing name of hotspare device */
			(void) printf(" %s", tmpphys_nm->n_name);
			break;
		}
	}

	state = meta_get_hs_state(hs->hs_state);
	if (state != NULL)
		(void) printf(" (%s)", state);

	/* Not removing entry, because it can be processed more than once. */
}


/*
 * process_hotspare_pool()
 *
 * Prints concise unit information for a hotspare pool metadevice and calls a
 * function to process each attached hotspare device.
 *
 */
static void
process_hotspare_pool(
	md_im_rec_t	**mdimpp,
	int		indent,
	pnm_rec_t	*phys_nm,
	md_im_rec_t	*mdrec
)
{
	hot_spare_pool_ond_t	*hsp;
	int			i;
	md_im_rec_t		*tmpmdrec;

	hsp =  (hot_spare_pool_ond_t *)mdrec->record;

	/*
	 * Printing name, size, and type of metadevice. Setting size field to
	 * 0, so that output is the as metastat -c.
	 */
	print_concise_entry(indent, mdrec->n_name,
	    0, 'h');

	/* Looping through list of attached hotspare devices. */
	for (i = 0; i < hsp->hsp_nhotspares; i++) {
		/* Looking for the matching record for the hotspare device. */
		for (tmpmdrec = *mdimpp; tmpmdrec != NULL;
		    tmpmdrec = tmpmdrec->next) {
			if (tmpmdrec->hs_record_id == hsp->hsp_hotspares[i]) {
				/* Calling function to print name of hotspare */
				tmpmdrec->dfunc(mdimpp, indent, phys_nm,
				    tmpmdrec);
			}
		}
	}
	(void) printf("\n");

	/*
	 * Removing the md_entry from the list
	 * of all metadevices
	 */
	free_mdrec_list_entry(&mdrec);
}


/*
 * process_raid()
 *
 * Prints concise unit information for a raid metadevice and calls the
 * respective functions to process the underlying metadevices.
 *
 */
static void
process_raid(
	md_im_rec_t	**mdimpp,
	int		indent,
	pnm_rec_t	*phys_nm,
	md_im_rec_t	*mdrec
)
{
	mr_unit_t	*mr;
	mr_column_t	*mc;
	mdc_unit_t	uc;
	int		i;
	md_im_rec_t	*tmpmdrec;
	md_im_rec_t	*hstmpmdrec;
	md_im_list_t	*ucomp_head = NULL;
	md_im_list_t	*ucomp_tail = NULL;
	md_im_list_t	*ucomp = NULL;
	pnm_rec_t	*tmpphys_nm;
	int		underlying_device;

	mr =  (mr_unit_t *)mdrec->record;
	uc = mr->c;

	/* Printing name, size, and type of metadevice */
	print_concise_entry(indent, mdrec->n_name,
	    uc.un_total_blocks, 'r');

	/* Loops through raid columns to find underlying metadevices */
	for (i = 0, mc = &mr->un_column[0];  i < mr->un_totalcolumncnt;
	    i++, mc++) {
		char	*state = NULL;
		char	*hsname = NULL;

		/*
		 * Need to assume that underlying device is a physical device,
		 * unless we find a matching metadevice record.
		 */
		underlying_device = PHYSICAL_DEV;

		/*
		 * Loops through list of metadevices to find record that matches
		 * the underlying device.
		 */
		for (tmpmdrec = *mdimpp; tmpmdrec != NULL;
		    tmpmdrec = tmpmdrec->next) {
			if (tmpmdrec->n_key == mc->un_orig_key) {
				/* check if hotspare device enabled */
				if (mc->un_hs_id !=  NULL) {
					/*
					 * Find matching metadevice record
					 * for the hotspare device.
					 */
					for (hstmpmdrec = *mdimpp;
					    hstmpmdrec != NULL;
					    hstmpmdrec = hstmpmdrec->next) {
						if (hstmpmdrec->hs_record_id ==
						    mc->un_hs_id) {
							/* print name of hs */
							hstmpmdrec->dfunc(
							    mdimpp, indent,
							    phys_nm,
							    hstmpmdrec);
							break;
						}
					}
				}
				/* print name of underlying metadevice */
				(void) printf(" %s", tmpmdrec->n_name);
				underlying_device = NOT_PHYSICAL_DEV;
				ucomp = Zalloc(sizeof (md_im_list_t));
				ucomp->mdrec = tmpmdrec;
				ucomponent_append(&ucomp_head, &ucomp_tail,
				    ucomp);
			}
		}

		if (underlying_device == PHYSICAL_DEV) {
			print_physical_device(phys_nm, mc->un_orig_key);
		}
		state = meta_get_raid_col_state(mc->un_devstate);

		/*
		 * An underlying hotspare must be a physical device.
		 * If support is ever added for soft-partitions under
		 * hotspare pools, then this code should be updated to
		 * include a search for underlying metadevices.
		 */
		if (mc->un_hs_id != 0) {
			for (tmpphys_nm = phys_nm; tmpphys_nm != NULL;
			    tmpphys_nm = tmpphys_nm->next) {
				if (tmpphys_nm->n_key == mc->un_hs_key) {
					hsname = tmpphys_nm->n_name;
					break;
				}
			}
		}

		if (state != NULL) {
			if (hsname != NULL)
				(void) printf(" (%s-%s)", state,
				    hsname);
			else
				(void) printf(" (%s)", state);
		} else if (hsname != NULL) {
			(void) printf(gettext(" (spared-%s)"), hsname);
		}
	}
	(void) printf("\n");

	/* process underlying components */
	indent += META_INDENT;
	for (ucomp = ucomp_head; ucomp != NULL;
	    ucomp = ucomp->next) {
		ucomp->mdrec->dfunc(mdimpp, indent, phys_nm,
		    ucomp->mdrec);
	}
	free_md_im_list_entries(&ucomp_head);

	/*
	 * Removing the md_entry from the list
	 * of all metadevices
	 */
	free_mdrec_list_entry(&mdrec);
}


/*
 * process_mirror()
 *
 * Prints concise unit information for a mirror metadevice and calls the
 * respective functions to process the underlying metadevices.
 *
 */
static void
process_mirror(
	md_im_rec_t	**mdimpp,
	int		indent,
	pnm_rec_t	*phys_nm,
	md_im_rec_t	*mdrec
)
{
	mm_unit_t	*mm;
	mm_submirror_t 	*sm;
	mdc_unit_t	uc;
	int		i;
	md_im_rec_t	*tmpmdrec;
	md_im_list_t	*ucomp_head = NULL;
	md_im_list_t	*ucomp_tail = NULL;
	md_im_list_t	*ucomp = NULL;

	mm =  (mm_unit_t *)mdrec->record;
	uc = mm->c;

	/* Printing name, size, and type of metadevice */
	print_concise_entry(indent, mdrec->n_name,
	    uc.un_total_blocks, 'm');

	/* Looping through sub-mirrors to find underlying devices */
	for (i = 0, sm = &mm->un_sm[0]; i < mm->un_nsm; i++, sm++) {
		char 	*state = NULL;

		for (tmpmdrec = *mdimpp; tmpmdrec != NULL;
		    tmpmdrec = tmpmdrec->next) {
			if (tmpmdrec->n_key == sm->sm_key) {
				(void) printf(" %s", tmpmdrec->n_name);
				ucomp = Zalloc(sizeof (md_im_list_t));
				ucomp->mdrec = tmpmdrec;
				ucomponent_append(&ucomp_head, &ucomp_tail,
				    ucomp);
			}
		}

		/*
		 * It is not possible to have an underlying physical device
		 * for a submirror, so there is no need to search the phys_nm
		 * list.
		 */

		/* Printing the state for the submirror */
		state = meta_get_sm_state(sm->sm_state);
		if (state != NULL) {
			(void) printf(" (%s)", state);
		}
	}
	(void) printf("\n");

	/* process underlying components */
	indent += META_INDENT;
	for (ucomp = ucomp_head; ucomp != NULL;
	    ucomp = ucomp->next) {
		ucomp->mdrec->dfunc(mdimpp, indent, phys_nm,
		    ucomp->mdrec);
	}
	free_md_im_list_entries(&ucomp_head);

	/*
	 * Removing the md_entry from the list
	 * of all metadevices
	 */
	free_mdrec_list_entry(&mdrec);
}


/*
 * process_stripe()
 *
 * Prints concise unit information for a stripe metadevice and calls the
 * respective functions to process the underlying metadevices.
 *
 */
static void
process_stripe(
	md_im_rec_t	**mdimpp,
	int		indent,
	pnm_rec_t	*phys_nm,
	md_im_rec_t	*mdrec
)
{
	ms_unit_t	*ms;
	mdc_unit_t	uc;
	md_im_rec_t	*tmpmdrec;
	md_im_list_t	*ucomp_head = NULL;
	md_im_list_t	*ucomp_tail = NULL;
	md_im_list_t	*ucomp = NULL;
	pnm_rec_t	*tmpphys_nm;
	int		underlying_device;
	uint_t		row;

	ms =  (ms_unit_t *)mdrec->record;
	uc = ms->c;

	/* Printing name, size, and type of metadevice */
	print_concise_entry(indent, mdrec->n_name,
	    uc.un_total_blocks, 's');

	/* Looping through stripe rows */
	for (row = 0; (row < ms->un_nrows); ++row) {
		struct ms_row	*mdr = &ms->un_row[row];
		ms_comp_t	*mdcomp = (void *)&((char *)ms)
		    [ms->un_ocomp];
		uint_t		comp, c;

		/*
		 * Looping through the components in each row to find the
		 * underlying devices.
		 */
		for (comp = 0, c = mdr->un_icomp; (comp < mdr->un_ncomp);
		    ++comp, ++c) {
			char		*state = NULL;
			char		*hsname = NULL;
			ms_comp_t	*mdc = &mdcomp[c];
			md_m_shared_t 	*mdm = &mdc->un_mirror;

			/*
			 * Need to assume that underlying device is a
			 * physical device, unless we find a matching
			 * metadevice record.
			 */
			underlying_device = PHYSICAL_DEV;

			for (tmpmdrec = *mdimpp; tmpmdrec != NULL;
			    tmpmdrec = tmpmdrec->next) {
				if (tmpmdrec->n_key == mdc->un_key) {
					(void) printf(" %s", tmpmdrec->n_name);
					underlying_device = NOT_PHYSICAL_DEV;
					ucomp = Zalloc(sizeof (md_im_list_t));
					ucomp->mdrec = tmpmdrec;
					ucomponent_append(&ucomp_head,
					    &ucomp_tail, ucomp);
				}
			}
			/* if an underlying metadevice was not found */
			if (underlying_device == PHYSICAL_DEV) {
				print_physical_device(phys_nm, mdc->un_key);
			}
			state = meta_get_stripe_state(mdm->ms_state);

			/*
			 * An underlying hotspare must be a physical device.
			 * If support is ever added for soft-partitions under
			 * hotspare pools, then this code should be updated to
			 * include a search for underlying metadevices.
			 */
			if (mdm->ms_hs_key != 0) {
				for (tmpphys_nm = phys_nm; tmpphys_nm != NULL;
				    tmpphys_nm = tmpphys_nm->next) {
					if (tmpphys_nm->n_key ==
					    mdm->ms_hs_key) {
						hsname = tmpphys_nm->n_name;
						break;
					}
				}
			}
			if (state != NULL) {
				if (hsname != NULL) {
					(void) printf(" (%s-%s)", state,
					    hsname);
				} else {
					(void) printf(" (%s)", state);
				}
			} else if (hsname != NULL) {
				(void) printf(gettext(" (spared-%s)"), hsname);
			}
		}
	}
	(void) printf("\n");

	/* Process underlying metadevices */
	indent += META_INDENT;
	for (ucomp = ucomp_head; ucomp != NULL;
	    ucomp = ucomp->next) {
		ucomp->mdrec->dfunc(mdimpp, indent, phys_nm,
		    ucomp->mdrec);
	}
	free_md_im_list_entries(&ucomp_head);

	/*
	 * Removing the md_entry from the list
	 * of all metadevices
	 */
	free_mdrec_list_entry(&mdrec);
}


/*
 * process_softpart()
 *
 * Prints concise unit information for a softpart metadevice and calls the
 * respective functions to process the underlying metadevices.
 *
 */
static void
process_softpart(
	md_im_rec_t	**mdimpp,
	int		indent,
	pnm_rec_t	*phys_nm,
	md_im_rec_t	*mdrec
)
{
	mp_unit_t	*mp;
	mdc_unit_t	uc;
	md_im_rec_t	*tmpmdrec;
	int		underlying_device = PHYSICAL_DEV;

	mp =  (mp_unit_t *)mdrec->record;
	uc = mp->c;

	/* Printing name, size, and type of metadevice */
	print_concise_entry(indent, mdrec->n_name,
	    uc.un_total_blocks, 'p');

	/*
	 * Loops through md_im_rec_t **mdimpp list of all metadevices to find
	 * record that matches the underlying device.
	 * Softpartitions can only have one underlying device, so once a
	 * match is found, we are done.
	 */
	for (tmpmdrec = *mdimpp; tmpmdrec != NULL;
	    tmpmdrec = tmpmdrec->next) {
		if (tmpmdrec->n_key == mp->un_key) {
			/* Printing name of the underlying metadevice */
			(void) printf(" %s", tmpmdrec->n_name);
			underlying_device = NOT_PHYSICAL_DEV;
			break;
		}
	}

	/* This is only executed if an underlying metadevice was not found */
	if (underlying_device == PHYSICAL_DEV) {
		print_physical_device(phys_nm, mp->un_key);
		(void) printf("\n");
	} else {
		/* Process underlying metadevice */
		(void) printf("\n");
		indent += META_INDENT;
		tmpmdrec->dfunc(mdimpp, indent, phys_nm,
		    tmpmdrec);
	}

	/*
	 * Removing the md_entry from the list
	 * of all metadevices
	 */
	free_mdrec_list_entry(&mdrec);
}


/*
 * process_toplevel_softparts()
 *
 * Toplevel softpartions need to be grouped so that their underlying devices
 * can be printed just once.
 */
static void
process_toplevel_softparts(
	md_im_rec_t	**mdimpp,
	int		indent,
	pnm_rec_t	*phys_nm
)
{
	mp_unit_t	*mp;
	mdc_unit_t	uc;
	md_im_rec_t	*mdrec;
	md_im_rec_t	*comp_mdrec; /* pntr to underlying component's record */
	md_im_rec_t	*tmp_mdrec, *rm_mdrec;
	mp_unit_t	*tmp_mp;
	int		underlying_device;

	/*
	 * Loops through md_im_rec_t **mdimpp list of all metadevices to find
	 * all softpartions that are toplevel softpartitions(softparts w/out
	 * a parent). Groups output for these entries so that the function to
	 * process the underlying metadevice is only called once.
	 */
	for (mdrec = *mdimpp; mdrec != NULL; mdrec = mdrec->next) {

		underlying_device = PHYSICAL_DEV;
		if ((mdrec->md_type == MDDB_F_SOFTPART) &&
		    (mdrec->has_parent == 0)) {
			mp =  (mp_unit_t *)mdrec->record;
			uc = mp->c;
			/* Printing name, size, and type of metadevice */
			print_concise_entry(indent, mdrec->n_name,
			    uc.un_total_blocks, 'p');
			/*
			 * Looking for record that matches underlying
			 * component.
			 */
			for (comp_mdrec = *mdimpp; comp_mdrec != NULL;
			    comp_mdrec = comp_mdrec->next) {
				if (comp_mdrec->n_key == mp->un_key) {
					/* Print name of underlying device */
					(void) printf(" %s",
					    comp_mdrec->n_name);
					underlying_device = NOT_PHYSICAL_DEV;
					break;
				}
			}
			if (underlying_device == PHYSICAL_DEV) {
				print_physical_device(phys_nm, mp->un_key);
			}
			(void) printf("\n");

			/*
			 * Looking for any other toplevel softpartitions with
			 * same underlying device. We know that all other
			 * matching metadevices, that share the same underlying
			 * metadevice, are also soft-partitions.
			 */
			for (tmp_mdrec = mdrec->next; tmp_mdrec != NULL; ) {
				tmp_mp = (mp_unit_t *)tmp_mdrec->record;
				if ((tmp_mdrec->has_parent == 0) &&
				    (tmp_mp->un_key == mp->un_key)) {
					uc = tmp_mp->c;
					print_concise_entry(indent,
					    tmp_mdrec->n_name,
					    uc.un_total_blocks, 'p');
					if (underlying_device ==
					    NOT_PHYSICAL_DEV) {
						(void) printf(" %s",
						    comp_mdrec->n_name);
					} else {
						print_physical_device(
						    phys_nm, tmp_mp->un_key);
					}
					(void) printf("\n");
					/*
					 * Need to advance so that will not lose
					 * position after removing processed
					 * record.
					 */
					rm_mdrec = tmp_mdrec;
					tmp_mdrec = tmp_mdrec->next;
					/*
					 * Removing the md_entry from the list
					 * of all metadevices.
					 */
					free_mdrec_list_entry(&rm_mdrec);
				} else {
					tmp_mdrec = tmp_mdrec->next;
				}
			}
			/* Process the underlying device */
			if (underlying_device == NOT_PHYSICAL_DEV) {
				indent += META_INDENT;
				comp_mdrec->dfunc(mdimpp, indent, phys_nm,
				    comp_mdrec);
			}
		}
	}
}


/*
 * process_toplevel_devices()
 *
 * Search through list of metadevices for metadevices of md_type that do not
 * have a parent.
 *
 */
static void
process_toplevel_devices(
	md_im_rec_t	**mdimpp,
	pnm_rec_t	*pnm,
	uint_t		md_type
)
{
	md_im_rec_t	*mdrec;
	md_im_list_t	*mdrec_tl_tail = NULL;
	md_im_list_t	*mdrec_tl_head = NULL;
	md_im_list_t	*tmp_tl_list = NULL;
	int		indent = 0;

	indent += META_INDENT;

	/*
	 * Need to group soft partitions so that common underlying device
	 * are only processed once.
	 */
	if (md_type == MDDB_F_SOFTPART) {
		process_toplevel_softparts(mdimpp, indent, pnm);
		return;
	}

	/*
	 * Search the list of metadevices to find all metadevices that match
	 * the type and don't have a parent.  Put them on a separate list
	 * that will be processed.
	 */
	for (mdrec = *mdimpp; mdrec != NULL; mdrec = mdrec->next) {
		if ((mdrec->md_type == md_type)&&(mdrec->has_parent == 0)) {
			tmp_tl_list = Zalloc(sizeof (md_im_list_t));
			tmp_tl_list->mdrec = mdrec;
			tmp_tl_list->next = NULL;
			if (mdrec_tl_tail == NULL) {
				mdrec_tl_tail = tmp_tl_list;
				mdrec_tl_head = mdrec_tl_tail;
			} else {
				mdrec_tl_tail->next = tmp_tl_list;
				mdrec_tl_tail = mdrec_tl_tail->next;
			}
		}

	}

	/*
	 * Loop through list and process all top-level metadevices of a
	 * given type.
	 */
	for (tmp_tl_list = mdrec_tl_head; tmp_tl_list != NULL;
	    tmp_tl_list = tmp_tl_list->next) {
		tmp_tl_list->mdrec->dfunc(mdimpp, indent, pnm,
		    tmp_tl_list->mdrec);
	}

	free_md_im_list_entries(&mdrec_tl_head);
}


/*
 * extract_mduser_data()
 *
 * Converts or copies the (mddb_rb_t->rb_data) metadevice record to a 64bit
 * record.
 * Sets the dfunc field to point to the appropriate function to process the
 * metadevice.
 * Sets the parent field for the metadevice.
 * Extracts the name from the NM namespace if it is available, otherwise
 * generates it from the metadevice's minor number.
 *
 * Returns:
 *	< 0 for failure
 *	  0 for success
 *
 */
static int
extract_mduser_data(
	mddb_rb_t		*nm,
	md_im_rec_t		*mdrec,
	void			*rbp,
	int 			is_32bit_record,
	md_error_t		*ep
)
{
	mdc_unit_t		uc;
	hot_spare_t 		*hs;
	hot_spare_pool_ond_t 	*hsp;
	size_t			newreqsize;
	mddb_rb_t		*rbp_nm = nm;
	struct nm_rec		*nm_record;
	struct nm_name		*nmname;
	char 			*uname = NULL;


	/*LINTED*/
	nm_record = (struct nm_rec *)((caddr_t)(&rbp_nm->rb_data));

	/*
	 * Setting the un_self_id or the hs_self_id, in the case of hotspare
	 * records, for each metadevice entry. Also setting has_parent and
	 * setting dfunc so that it points to the correct function to process
	 * the record type.
	 * If the record was stored ondisk in 32bit format, then it is
	 * converted to the 64bits equivalent 64bit format and the memory
	 * for the 32bit pointer is freed.
	 */
	switch (mdrec->md_type) {
		case MDDB_F_SOFTPART:
			if (is_32bit_record) {
				mp_unit32_od_t	*small_un;
				mp_unit_t	*big_un;

				small_un = (mp_unit32_od_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = sizeof (mp_unit_t) +
				    ((small_un->un_numexts - 1) *
				    sizeof (struct mp_ext));
				big_un = (void *)Zalloc(newreqsize);
				softpart_convert((caddr_t)small_un,
				    (caddr_t)big_un, SMALL_2_BIG);
				mdrec->record = (void *)big_un;
			} else {
				mp_unit_t	*big_un;

				big_un = (mp_unit_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = sizeof (mp_unit_t) +
				    ((big_un->un_numexts - 1) *
				    sizeof (struct mp_ext));
				mdrec->record = (void *)Zalloc(newreqsize);
				bcopy(big_un, mdrec->record, newreqsize);
			}
			uc = ((mp_unit_t *)mdrec->record)->c;
			mdrec->dfunc = &process_softpart;
			mdrec->un_self_id = uc.un_self_id;
			mdrec->has_parent = MD_HAS_PARENT(
			    uc.un_parent);
			break;
		case MDDB_F_STRIPE:
			if (is_32bit_record) {
				ms_unit32_od_t	*small_un;
				ms_unit_t	*big_un;

				small_un = (ms_unit32_od_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = get_big_stripe_req_size(
				    small_un, COMPLETE_STRUCTURE);
				    big_un = (void *)Zalloc(newreqsize);
				stripe_convert((caddr_t)small_un,
				    (caddr_t)big_un, SMALL_2_BIG);
				mdrec->record = (void *)big_un;
			} else {
				ms_unit_t	*big_un;

				big_un = (ms_unit_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = get_stripe_req_size(big_un);
				mdrec->record = (void *)Zalloc(newreqsize);
				bcopy(big_un, mdrec->record, newreqsize);
			}
			uc = ((ms_unit_t *)mdrec->record)->c;
			mdrec->dfunc = &process_stripe;
			mdrec->un_self_id = uc.un_self_id;
			mdrec->has_parent = MD_HAS_PARENT(
			    uc.un_parent);
			break;
		case MDDB_F_MIRROR:
			if (is_32bit_record) {
				mm_unit32_od_t	*small_un;
				mm_unit_t	*big_un;

				small_un = (mm_unit32_od_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = sizeof (mm_unit_t);
				big_un = (void *)Zalloc(newreqsize);
				mirror_convert((caddr_t)small_un,
				    (caddr_t)big_un, SMALL_2_BIG);
				mdrec->record = (void *)big_un;
			} else {
				mm_unit_t	*big_un;

				big_un = (mm_unit_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = sizeof (mm_unit_t);
				mdrec->record = (void *)Zalloc(newreqsize);
				bcopy(big_un, mdrec->record, newreqsize);
			}
			uc = ((mm_unit_t *)mdrec->record)->c;
			mdrec->dfunc = &process_mirror;
			mdrec->un_self_id = uc.un_self_id;
			mdrec->has_parent = MD_HAS_PARENT(
			    uc.un_parent);
			break;
		case MDDB_F_RAID:
			if (is_32bit_record) {
				mr_unit32_od_t	*small_un;
				mr_unit_t	*big_un;
				uint_t		ncol;

				small_un = (mr_unit32_od_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				ncol = small_un->un_totalcolumncnt;
				newreqsize = sizeof (mr_unit_t) +
				    ((ncol - 1) * sizeof (mr_column_t));
				big_un = (void *)Zalloc(newreqsize);
				raid_convert((caddr_t)small_un,
				    (caddr_t)big_un, SMALL_2_BIG);
				mdrec->record = (void *)big_un;
			} else {
				mr_unit_t	*big_un;
				uint_t		ncol;

				big_un = (mr_unit_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				ncol = big_un->un_totalcolumncnt;
				newreqsize = sizeof (mr_unit_t) +
				    ((ncol - 1) * sizeof (mr_column_t));
				mdrec->record = (void *)Zalloc(newreqsize);
				bcopy(big_un, mdrec->record, newreqsize);
			}
			uc = ((mr_unit_t *)mdrec->record)->c;
			mdrec->dfunc = &process_raid;
			mdrec->un_self_id = uc.un_self_id;
			mdrec->has_parent = MD_HAS_PARENT(
			    uc.un_parent);
			break;
		case MDDB_F_TRANS_MASTER:
			if (is_32bit_record) {
				mt_unit32_od_t	*small_un;
				mt_unit_t	*big_un;

				small_un = (mt_unit32_od_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = sizeof (mt_unit_t);
				big_un = (void *)Zalloc(newreqsize);
				trans_master_convert((caddr_t)small_un,
				    (caddr_t)big_un, SMALL_2_BIG);
				mdrec->record = (void *)big_un;
			} else {
				mt_unit_t	*big_un;

				big_un = (mt_unit_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = sizeof (mt_unit_t);
				mdrec->record = (void *)Zalloc(newreqsize);
				bcopy(big_un, mdrec->record, newreqsize);
			}
			uc = ((mt_unit_t *)mdrec->record)->c;
			mdrec->dfunc = &process_trans;
			mdrec->un_self_id = uc.un_self_id;
			mdrec->has_parent = MD_HAS_PARENT(
			    uc.un_parent);
			break;
		case MDDB_F_HOTSPARE:
			if (is_32bit_record) {
				hot_spare32_od_t	*small_un;
				hot_spare_t		*big_un;

				small_un = (hot_spare32_od_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = sizeof (hot_spare_t);
				big_un = (void *)Zalloc(newreqsize);
				hs_convert((caddr_t)small_un,
				    (caddr_t)big_un, SMALL_2_BIG);
				mdrec->record = (void *)big_un;
			} else {
				hot_spare_t		*big_un;

				big_un = (hot_spare_t *)((uintptr_t)rbp +
				    (sizeof (mddb_rb_t) - sizeof (int)));
				newreqsize = sizeof (hot_spare_t);
				mdrec->record = (void *)Zalloc(newreqsize);
				bcopy(big_un, mdrec->record, newreqsize);
			}
			hs = (hot_spare_t *)mdrec->record;
			mdrec->dfunc = &process_hotspare;
			mdrec->un_self_id = NULL;
			mdrec->hs_record_id = hs->hs_record_id;
			mdrec->has_parent = 1;
			break;
		case MDDB_F_HOTSPARE_POOL:
			/*
			 * Ondisk and incore records are always same size.
			 */
			hsp = (hot_spare_pool_ond_t *)((uintptr_t)rbp +
			    (sizeof (mddb_rb_t) - sizeof (int)));
			newreqsize = sizeof (hot_spare_pool_ond_t) +
			    (sizeof (mddb_recid_t) * hsp->hsp_nhotspares);
			mdrec->record = (void *)Zalloc(newreqsize);
			bcopy(hsp, mdrec->record, newreqsize);
			hsp = (hot_spare_pool_ond_t *)mdrec->record;
			mdrec->dfunc = &process_hotspare_pool;
			/*
			 * If the hsp has descriptive name we'll get
			 * the un_self_id
			 */
			if (HSP_ID_IS_FN(hsp->hsp_self_id))
				mdrec->un_self_id = hsp->hsp_self_id;
			else
				mdrec->un_self_id = NULL;
			mdrec->has_parent = 0;
			break;
		/* All valid cases have been dealt with */
		default:
			(void) mdmddberror(ep, MDE_DB_NODB, 0, 0, 0, NULL);
			return (-1);
	}

	/*
	 * If metadevice record has an entry in the NM namespace
	 * then it is copied into the mdrec->n_name field.
	 */
	if (mdrec->un_self_id != NULL) {
		for (nmname = &nm_record->r_name[0]; nmname->n_key != 0;
		/*LINTED*/
		    nmname = (struct nm_name *)((char *)nmname +
		    NAMSIZ(nmname))) {
			/*
			 * Extract the metadevice/hsp name if it is
			 * in the namespace.
			 *
			 * If it is a hot spare pool we will find our
			 * match by comparing the NM record's n_key
			 * with the extracted key from the hsp_self_id
			 * Else, match the un_self_id for the record
			 * to the n_minor name in the NM record.
			 */
			    if (mdrec->md_type == MDDB_F_HOTSPARE_POOL) {
				if (nmname->n_key ==
				    HSP_ID_TO_KEY(hsp->hsp_self_id)) {
					mdrec->n_key = nmname->n_key;
					uname = Strdup(nmname->n_name);
					mdrec->n_name = uname;
					break;
				}
			    } else {
				if ((nmname->n_minor) == (uc.un_self_id)) {
					(*mdrec).n_key = nmname->n_key;
					uname = Strdup(nmname->n_name);
					mdrec->n_name = uname;
					break;
				}
			    }
		}
	}

	/*
	 * If the metadevice name is not in the namespace, then
	 * then we will generate the name from the minor number
	 * for the metadevice.  In the case of records for a hotspare
	 * pool we use hsp_self_id, otherwise we use un_self_id.
	 */
	if (uname == NULL) {
		if (mdrec->md_type == MDDB_F_HOTSPARE_POOL) {
			uname = Malloc(MAXSIZEMDRECNAME);
			(void) sprintf(uname, "hsp%03u",
			    HSP_ID(hsp->hsp_self_id));
			mdrec->n_name = uname;
		} else if (mdrec->md_type != MDDB_F_HOTSPARE) {
			/*
			 * Generate the metadevice name for all other records
			 * (except for hotspares, because hotspares can only
			 * be physical devices.)
			 */
			uname = Malloc(MAXSIZEMDRECNAME);
			(void) sprintf(uname, "d%lu",
			    MD_MIN2UNIT(mdrec->un_self_id));
			mdrec->n_name = uname;
		}
	}

	return (0);
}


/*
 * read_mdrecord()
 *
 * Reads the mddb_rb32_od_t or mddb_rb_t and the associated metadevice record
 * from the disk.  Runs magic, checksum, and revision checks on the record
 * block.
 *
 * Returns:
 *	< 0 for failure
 *	  0 for success
 *
 */
static int
read_mdrecord(
	md_im_rec_t	**mdimpp,
	mddb_mb_t	*mbp,
	mddb_rb_t	*nm,
	mddb_de_t	*dep,
	char		*diskname,
	int 		fd,
	md_timeval32_t	*lastaccess,
	md_error_t 	*ep
)
{
	int		cnt, rval = 0;
	daddr_t		pblk;
	md_im_rec_t	*tmp_mdrec;
	void 		*rbp = NULL;
	char 		*rbp_tmp = NULL;
	mddb_rb32_t	*rbp_32;
	mddb_rb_t	*rbp_64;
	crc_skip_t	*skip = NULL;
	int		is_32bit_record;

	tmp_mdrec = Zalloc(sizeof (md_im_rec_t));
	rbp = (void *)Zalloc(dbtob(dep->de_blkcount));
	rbp_tmp = (char *)rbp;

	/* Read in the appropriate record and return configurations */
	for (cnt = 0; cnt < dep->de_blkcount; cnt++) {
		if ((pblk = getphysblk(dep->de_blks[cnt], mbp)) < 0) {
			rval = mdmddberror(ep, MDE_DB_BLKRANGE,
			    NODEV32, MD_LOCAL_SET,
			    dep->de_blks[cnt], diskname);
			return (rval);
		}

		if (lseek(fd, (off_t)dbtob(pblk), SEEK_SET) < 0) {
			rval = mdsyserror(ep, errno, diskname);
			return (rval);
		}

		if (read(fd, rbp_tmp, DEV_BSIZE) != DEV_BSIZE) {
			rval = mdsyserror(ep, errno, diskname);
			return (rval);
		}

		rbp_tmp += DEV_BSIZE;
	}
	tmp_mdrec->md_type = dep->de_flags;

	/*
	 * The only place to discover whether or not the record is a
	 * 32bit or 64bit record is from the record's rb_revision field.
	 * The mddb_rb_t and mddb_rb32_t structures are identical for the
	 * following fields:
	 *	rb_magic, rb_revision, rb_checksum, and rb_checksum_fiddle.
	 * So we can assume that the record is a 32bit structure when we
	 * check the record's magic number and revision and when we calculate
	 * the records checksum.
	 */
	rbp_32 = (mddb_rb32_t *)rbp;

	/*
	 * Checking the magic number for the record block.
	 */
	if (rbp_32->rb_magic != MDDB_MAGIC_RB) {
		rval = -1;
		(void) mdmddberror(ep, MDE_DB_NODB, 0, 0, 0, NULL);
		goto out;
	}

	/*
	 * Checking the revision for the record block. Must match either
	 * revision for the current 64bit or 32bit record block.  Also,
	 * setting the flag for whether or not it is a 32bit record.
	 */
	is_32bit_record = 0;
	switch (rbp_32->rb_revision) {
	case MDDB_REV_RB:
	case MDDB_REV_RBFN:
		is_32bit_record = 1;
		break;
	case MDDB_REV_RB64:
	case MDDB_REV_RB64FN:
		break;
	default:
		rval = -1;
		(void) mdmddberror(ep, MDE_DB_NODB, 0, 0, 0, NULL);
		goto out;
	}

	/*
	 * Calculating the checksum for this record block. Need
	 * to skip the rb's checksum fiddle.
	 */
	skip = (crc_skip_t *)Malloc(sizeof (crc_skip_t));
	skip->skip_next = NULL;
	skip->skip_offset = offsetof(mddb_rb_t, rb_checksum_fiddle);
	skip->skip_size = 3 * sizeof (uint_t);
	if (crcchk(rbp_32, &rbp_32->rb_checksum, dep->de_recsize, skip)) {
		rval = -1;
		(void) mdmddberror(ep, MDE_DB_NODB, 0, 0, 0, NULL);
		goto out;
	}

	/* mddb_rb_t and mddb_rb32_t differ before the rb_timestamp field */
	if (!is_32bit_record) {
		if ((*lastaccess).tv_sec < rbp_32->rb_timestamp.tv_sec) {
		    *lastaccess = rbp_32->rb_timestamp;
		} else if ((*lastaccess).tv_sec ==
		    rbp_32->rb_timestamp.tv_sec) {
			if ((*lastaccess).tv_usec <
			    rbp_32->rb_timestamp.tv_usec)
				*lastaccess = rbp_32->rb_timestamp;
		}
	} else {
		rbp_64 = (mddb_rb_t *)rbp;
		if ((*lastaccess).tv_sec < rbp_64->rb_timestamp.tv_sec) {
		    *lastaccess = rbp_64->rb_timestamp;
		} else if ((*lastaccess).tv_sec ==
		    rbp_64->rb_timestamp.tv_sec) {
			if ((*lastaccess).tv_usec <
			    rbp_64->rb_timestamp.tv_usec)
				*lastaccess = rbp_64->rb_timestamp;
		}
	}

	/* Populates the fields in md_im_rec_t *tmp_mdrec. */
	rval = extract_mduser_data(nm, tmp_mdrec, rbp, is_32bit_record, ep);
	if (rval < 0)
		goto out;

	/* Adding record to the head of the list of all metadevices. */
	tmp_mdrec->prev = NULL;
	if (*mdimpp == NULL) {
		tmp_mdrec->next = NULL;
		*mdimpp = tmp_mdrec;
	} else {
		(*mdimpp)->prev = tmp_mdrec;
		tmp_mdrec->next = *mdimpp;
		*mdimpp = tmp_mdrec;
	}

out:
	/* Free the skip list */
	while (skip) {
		crc_skip_t	*skip_rm = skip;

		skip = skip->skip_next;
		Free(skip_rm);
	}

	if (rbp)
		Free(rbp);

	return (rval);
}


/*
 * read_all_mdrecords()
 *
 * Reads the directory block and directory entries.
 * Runs magic, checksum, and revision checks on the directory block.
 *
 * Returns:
 *	< 0 for failure
 *	  0 for success
 */
static int
read_all_mdrecords(
	md_im_rec_t	**mdimpp,
	mddb_mb_t	*mbp,
	mddb_lb_t	*lbp,
	mddb_rb_t	*nm,
	mdname_t	*rsp,
	int 		fd,
	md_timeval32_t	*lastaccess,
	md_error_t 	*ep
)
{
	int		dbblk, rval = 0;
	char		db[DEV_BSIZE];
	mddb_de_t	*dep;
	int		desize;
	/*LINTED*/
	mddb_db_t	*dbp = (mddb_db_t *)&db;

	/* Read in all directory blocks */
	for (dbblk = lbp->lb_dbfirstblk;
	    dbblk != 0;
	    dbblk = dbp->db_nextblk) {

		if ((rval = read_database_block(ep, fd, mbp, dbblk,
		    dbp, sizeof (db))) <= 0)
			goto out;

		/*
		 * Set ep with error code for MDE_DB_NODB.  This is the
		 * error code used in the kernel when there is a problem
		 * with reading records in.  Checks the magic number, the
		 * revision, and the checksum for each directory block.
		 */
		if (dbp->db_magic != MDDB_MAGIC_DB) {
			rval = -1;
			(void) mdmddberror(ep, MDE_DB_NODB, 0, 0, 0, NULL);
			goto out;
		}

		if (revchk(MDDB_REV_DB, dbp->db_revision)) {
			rval = -1;
			(void) mdmddberror(ep, MDE_DB_NODB, 0, 0, 0, NULL);
			goto out;
		}

		if (crcchk(dbp, &dbp->db_checksum, MDDB_BSIZE, NULL)) {
			rval = -1;
			(void) mdmddberror(ep, MDE_DB_NODB, 0, 0, 0, NULL);
			goto out;
		}

		/*
		 * If db timestamp is more recent than the previously recorded
		 * last modified timestamp, then update last modified.
		 */
		if ((*lastaccess).tv_sec < dbp->db_timestamp.tv_sec) {
			*lastaccess = dbp->db_timestamp;
		} else if ((*lastaccess).tv_sec == dbp->db_timestamp.tv_sec) {
			if ((*lastaccess).tv_usec < dbp->db_timestamp.tv_usec)
				*lastaccess = dbp->db_timestamp;
		}

		/* Creates dep list of all directory entries in the db */
		if (dbp->db_firstentry != NULL) {
			/* LINTED */
			dep = (mddb_de_t *)((caddr_t)(&dbp->db_firstentry)
			    + sizeof (dbp->db_firstentry));
			dbp->db_firstentry = dep;
			while (dep && dep->de_next) {
				desize = sizeof (*dep) -
				    sizeof (dep->de_blks) +
				    sizeof (daddr_t) * dep->de_blkcount;
				/* LINTED */
				dep->de_next = (mddb_de_t *)
				    ((caddr_t)dep + desize);
				dep = dep->de_next;
			}
		}

		/*
		 * Process all directory entries in the directory block.
		 * For each directory entry, read_mdrec is called to read
		 * in the record data.
		 */
		for (dep = dbp->db_firstentry; dep != NULL;
		    dep = dep->de_next) {

			/*
			 * de_flags is set to the type of metadevice.
			 * If directory entry does not correspond to a
			 * specific metadevice then it is set to zero.
			 * All namespace records(NM, SHR_NM, DID_SHR_NM) have a
			 * value of zero in their de_flags field.
			 */
			if ((dep->de_flags != 0)&&
			    (dep->de_flags != MDDB_F_OPT) &&
			    (dep->de_flags != MDDB_F_TRANS_LOG) &&
			    (dep->de_flags != MDDB_F_CHANGELOG)) {
				rval = read_mdrecord(mdimpp, mbp, nm, dep,
				    rsp->cname, fd, lastaccess, ep);
				if (rval < 0)
					goto out;
			}
		}
	}

out:
	return (rval);
}


/*
 * report_metastat_info()
 *
 * Generates the metastat -c output.  Also, updates the global variable
 * for a last accessed timestamp.
 *
 * Returns:
 *	< 0 for failure
 *	  0 for success
 *
 */
int
report_metastat_info(
	mddb_mb_t		*mb,
	mddb_lb_t		*lbp,
	mddb_rb_t		*nm,
	pnm_rec_t		**pnm,
	mdname_t		*rsp,
	int			fd,
	md_timeval32_t		*lastaccess,
	md_error_t		*ep
)
{
	int rval = 0;
	/* list of all metadevices in diskset */
	md_im_rec_t	*mdimp = NULL;
	md_im_rec_t	*tmp_mdrec, *rm_mdrec;

	/* Read in metadevice records and add entries to mdimp list. */
	rval = read_all_mdrecords(&mdimp, mb, lbp, nm, rsp, fd, lastaccess,
	    ep);
	if (rval < 0)
		goto out;

	/* Adding a fake record to the head of the list of all metadevices. */
	if (mdimp != NULL) {
		tmp_mdrec = Zalloc(sizeof (md_im_rec_t));
		tmp_mdrec->prev = NULL;
		mdimp->prev = tmp_mdrec;
		tmp_mdrec->next = mdimp;
		mdimp = tmp_mdrec;
	}

	/* Calling functions to process all metadevices on mdimp list */
	process_toplevel_devices(&mdimp, *pnm, MDDB_F_SOFTPART);
	process_toplevel_devices(&mdimp, *pnm, MDDB_F_TRANS_MASTER);
	process_toplevel_devices(&mdimp, *pnm, MDDB_F_MIRROR);
	process_toplevel_devices(&mdimp, *pnm, MDDB_F_RAID);
	process_toplevel_devices(&mdimp, *pnm, MDDB_F_STRIPE);
	process_toplevel_devices(&mdimp, *pnm, MDDB_F_HOTSPARE_POOL);
	(void) printf("\n");

out:
	/*
	 * If mdreclist is not null, then this will walk through all
	 * elements and free them.
	 */
	tmp_mdrec = mdimp;
	while (tmp_mdrec != NULL) {
		rm_mdrec = tmp_mdrec;
		tmp_mdrec = tmp_mdrec->next;
		if (rm_mdrec->record != NULL)
			Free(rm_mdrec->record);
		if (rm_mdrec->n_name != NULL)
			Free(rm_mdrec->n_name);
		Free(rm_mdrec);
	}

	free_pnm_rec_list(pnm);
	return (rval);
}
