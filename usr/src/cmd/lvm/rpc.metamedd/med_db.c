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

#include "med_local.h"
#include "med_hash.h"
#include <sys/lvm/mdio.h>
#include <sys/lvm/md_mdiox.h>
#include <sys/lvm/md_crc.h>

static	int		med_db_is_inited = 0;
static	Cache		*med_db_cache = (Cache *) NULL;
static	med_rec_t	*med_db_medrp = NULL;
static	int		med_db_nma = 0;
static	int		med_db_nmu = 0;
static	int		rec_size = roundup(sizeof (med_rec_t), DEV_BSIZE);
static	char 		*rec_buf = NULL;
static	int		dbfd = -1;

#define		OP_FLAGS	(O_RDWR | O_SYNC)
#define		CR_FLAGS	(OP_FLAGS | O_CREAT)

#define	HASHSIZE	151
#define	BSZ		4

#ifdef DEBUG
void
med_pr(void *keyp, int keyl, void *datap, int datal)
{
	med_med_t	*medp = (med_med_t *)keyp;
	int		medridx = *(int *)datap;
	med_rec_t	*medrp = &med_db_medrp[medridx];

	med_eprintf(
	    "key (%d)[keyp=0x%08x]: setno=%ld, setname=<%s>, caller=<%s>\n",
	    keyl, (unsigned)keyp, medp->med_setno, medp->med_setname,
	    medp->med_caller);
	med_eprintf("data(%d)[datap=0x%x08][medrp=0x%x08]: medridx=%d\n",
	    datal, (unsigned)datap, (unsigned)medrp, medridx);
}
#endif	/* DEBUG */

static int
med_hash(void *datap, int datalen, int hsz)
{
	med_med_t	*medp = (med_med_t *)datap;
	int		i = datalen;
	char		*cp;

	i = 0;
	cp = medp->med_setname;
	while (*cp != '\0')
		i += *cp++;

	cp = medp->med_caller;
	while (*cp != '\0')
		i += *cp++;

	i *= medp->med_setno;

	return (i % hsz);
}

/*ARGSUSED*/
static int
med_comp(void *datap1, void *datap2, int datalen)
{
	med_med_t	*medp1 = (med_med_t *)datap1;
	med_med_t	*medp2 = (med_med_t *)datap2;
	int		ret;


	ret = medp1->med_setno - medp2->med_setno;

	if (ret != 0)
		return (ret);

	ret = strcmp(medp1->med_caller, medp2->med_caller);

	if (ret != 0)
		return (ret);

	return (strcmp(medp1->med_setname, medp2->med_setname));
}

static void
med_kfree(void *keyp)
{
	med_med_t	*medp = (med_med_t *)keyp;

	(void) Free(medp->med_caller);
	(void) Free(medp->med_setname);
	(void) Free(keyp);
}

static int
add_key(med_med_t *medp, int medridx)
{
	Item		*itemp;
	int		len;
	med_med_t	*tmedp;

	if (med_db_cache == (Cache *) NULL) {
		len = init_cache(&med_db_cache, HASHSIZE, BSZ, med_hash,
		    med_comp, med_kfree, (void (*)())NULL);
		if (len == -1) {
			med_eprintf("add_key(): init_cache() failed.\n");
			return (-1);
		}
	}

	len = sizeof (med_med_t);

	if ((itemp = lookup_cache(med_db_cache, medp, len)) == Null_Item) {
		if ((itemp = (Item *) Malloc(sizeof (*itemp))) == NULL) {
			med_eprintf("add_key(): itemp = Malloc(%d)\n",
			    sizeof (*itemp));
			return (-1);
		}
		if ((tmedp = itemp->key = Malloc(len)) == NULL) {
			med_eprintf("add_key(): itemp->key = Malloc(%d)\n",
			    len);
			return (-1);
		}

		*tmedp = *medp;			/* structure assignment */

		tmedp->med_caller = Malloc(strlen(medp->med_caller) + 1);
		if (tmedp->med_caller == NULL) {
			med_eprintf(
			    "add_key(): tmedp->med_caller = Malloc(%d)\n",
			    strlen(medp->med_caller) + 1);
			return (-1);
		}
		(void) strcpy(tmedp->med_caller, medp->med_caller);

		tmedp->med_setname = Malloc(strlen(medp->med_setname) + 1);
		if (tmedp->med_setname == NULL) {
			med_eprintf(
			    "add_key(): tmedp->med_setname = Malloc(%d)\n",
			    strlen(medp->med_setname) + 1);
			return (-1);
		}
		(void) strcpy(tmedp->med_setname, medp->med_setname);

		itemp->keyl = len;

		if ((itemp->data = Malloc(sizeof (int))) == NULL) {
			med_eprintf("add_key(): itemp->data = Malloc(%d)\n",
			    sizeof (med_rec_t *));
			return (-1);
		}

		*(int *)itemp->data = medridx;

		itemp->datal = sizeof (int);

		if (add_cache(med_db_cache, itemp) == -1) {
			med_eprintf("add_key(): add_cache() failed.\n");
			return (-1);
		}
		return (0);
	}
	return (1);
}

static int
del_key(med_med_t *medp)
{
	Item		*itemp;
	int		len;

	if (med_db_cache == (Cache *) NULL)
		return (0);

	len = sizeof (med_med_t);

	if ((itemp = lookup_cache(med_db_cache, medp, len)) == Null_Item)
		return (0);

	(void) del_cache(med_db_cache, itemp);

	return (0);
}

static int
find_key(med_med_t *medp)
{
	Item		*itemp;
	int		len;

	if (med_db_cache == (Cache *) NULL)
		return (-1);

	len = sizeof (med_med_t);

	if ((itemp = lookup_cache(med_db_cache, medp, len)) == Null_Item)
		return (-1);

	return (*(int *)itemp->data);
}

static int
add_db_keys(int medridx, med_err_t *medep)
{
	med_med_t	med;
	med_rec_t	*medrp;
	int		i;

	medrp = &med_db_medrp[medridx];
	med.med_setno = medrp->med_rec_sn;
	med.med_setname = medrp->med_rec_snm;

	for (i = 0; i < MD_MAXSIDES; i++) {
		if (medrp->med_rec_nodes[i][0] == '\0')
			continue;
		med.med_caller  = medrp->med_rec_nodes[i];
		if (add_key(&med, medridx) == -1)
			return (med_error(medep, MDE_MED_DBKEYADDFAIL,
			    medrp->med_rec_nodes[i]));
	}

	/*
	 * Looping through the actual list of mediator hosts
	 * because a mediator host may not actually be a host
	 * in the diskset and so access for such a host needs
	 * to be added.
	 */
	for (i = 0; i < MED_MAX_HOSTS; i++) {
		if ((medrp->med_rec_meds.n_cnt > 0) &&
		    (medrp->med_rec_meds.n_lst[i].a_cnt != 0)) {
			med.med_caller  =
			    medrp->med_rec_meds.n_lst[i].a_nm[0];
			if (add_key(&med, medridx) == -1)
				return (med_error(medep, MDE_MED_DBKEYADDFAIL,
				    medrp->med_rec_meds.n_lst[i].a_nm[0]));
		}
	}
	return (0);
}

static int
del_db_keys(int medridx, med_err_t *medep)
{
	med_med_t	med;
	med_rec_t	*medrp;
	int		i;

	medrp = &med_db_medrp[medridx];
	med.med_setno = medrp->med_rec_sn;
	med.med_setname = medrp->med_rec_snm;

	for (i = 0; i < MD_MAXSIDES; i++) {
		if (medrp->med_rec_nodes[i][0] == '\0')
			continue;
		med.med_caller  = medrp->med_rec_nodes[i];
		if (del_key(&med) == -1)
			return (med_error(medep, MDE_MED_DBKEYDELFAIL,
			    medrp->med_rec_nodes[i]));
	}

	for (i = 0; i < MED_MAX_HOSTS; i++) {
		if ((medrp->med_rec_meds.n_cnt > 0) &&
		    (medrp->med_rec_meds.n_lst[i].a_cnt != 0)) {
			med.med_caller  =
			    medrp->med_rec_meds.n_lst[i].a_nm[0];
			if (del_key(&med) == -1)
				return (med_error(medep, MDE_MED_DBKEYDELFAIL,
				    medrp->med_rec_meds.n_lst[i].a_nm[0]));
		}
	}
	return (0);
}

static int
alloc_rec_buf(med_err_t *medep)
{
	if (rec_buf == NULL) {
		if ((rec_buf = Malloc(rec_size)) == NULL)
			return (med_error(medep, errno,
			    "alloc_rec_buf: Malloc()"));
	}

	(void) memset(rec_buf, '\0', rec_size);
	return (0);
}

static void
free_rec_buf(void)
{
	if (rec_buf == NULL)
		return;

	Free(rec_buf);
	rec_buf = NULL;
}

static int
write_hdr(
	int		dbfd,
	med_err_t	*medep
)
{
	med_db_hdr_t	dbh;

	if (alloc_rec_buf(medep))
		return (-1);

	(void) memset(&dbh, '\0', sizeof (med_db_hdr_t));

	/* Setup the new hdr record */
	dbh.med_dbh_mag = MED_DB_MAGIC;
	dbh.med_dbh_rev = MED_DB_REV;
	dbh.med_dbh_nm = med_db_nmu;

	/* Checksum new header */
	crcgen(&dbh, &dbh.med_dbh_cks, sizeof (med_db_hdr_t), NULL);

	/* Position to the beginning of the file */
	if (lseek(dbfd, 0, SEEK_SET) == -1)
		return (med_error(medep, errno, "write_hdr: lseek()"));

	/* Copy the header into the output buffer */
	(void) memmove(rec_buf, &dbh, sizeof (med_db_hdr_t));

	/* Write out the header */
	if (write(dbfd, rec_buf, rec_size) == -1)
		return (med_error(medep, errno, "write_hdr: write()"));

	return (0);
}

static int
write_rec(
	int		dbfd,
	med_rec_t	*medrp,
	med_err_t	*medep
)
{
	uint_t		save_flags = 0;
	uint_t		save_cks = 0;

	if (alloc_rec_buf(medep))
		return (-1);

	if (medrp->med_rec_data.med_dat_fl) {
		save_flags = medrp->med_rec_data.med_dat_fl;
		save_cks = medrp->med_rec_data.med_dat_cks;
		medrp->med_rec_data.med_dat_fl = 0;
		/* Checksum the new data */
		crcgen(&medrp->med_rec_data, &medrp->med_rec_data.med_dat_cks,
		    sizeof (med_data_t), NULL);
	}

	/* Checksum record */
	crcgen(medrp, &medrp->med_rec_cks, sizeof (med_rec_t), NULL);

	/* Load the record into the output buffer */
	(void) memmove(rec_buf, medrp, sizeof (med_rec_t));

	if (save_flags) {
		medrp->med_rec_data.med_dat_fl = save_flags;
		medrp->med_rec_data.med_dat_cks = save_cks;
		/* Re-checksum the updated record */
		crcgen(medrp, &medrp->med_rec_cks, sizeof (med_rec_t), NULL);
	}

	/* Write out the record */
	if (write(dbfd, rec_buf, rec_size) == -1)
		return (med_error(medep, errno, "write_rec: write()"));

	return (0);
}

static int
open_dbfile(med_err_t *medep)
{
	if (dbfd != -1)
		return (0);

	/* Open the database file */
	if ((dbfd = open(MED_DB_FILE, OP_FLAGS, 0644)) == -1) {
		if (errno != ENOENT)
			return (med_error(medep, errno, "open_dbfile: open()"));

		if ((dbfd = open(MED_DB_FILE, CR_FLAGS, 0644)) == -1)
			return (med_error(medep, errno,
			    "open_dbfile: open(create)"));
	}

	/* Try to take an advisory lock on the file */
	if (lockf(dbfd, F_TLOCK, (off_t)0) == -1) {
		(void) med_error(medep, errno, "open_dbfile: lockf(F_TLOCK)");
		medde_perror(medep, "");
		med_exit(1);
	}

	return (0);
}

static int
close_dbfile(med_err_t *medep)
{
	if (dbfd == -1)
		return (0);

	/* Make sure we are at the beginning of the file */
	if (lseek(dbfd, 0, SEEK_SET) == -1)
		return (med_error(medep, errno, "close_dbfile: lseek()"));

	/* Release the advisory lock on the file */
	if (lockf(dbfd, F_ULOCK, 0LL) == -1) {
		(void) med_error(medep, errno, "close_dbfile: lockf(F_ULOCK)");
		medde_perror(medep, "");
		med_exit(1);
	}

	if (close(dbfd) == -1)
		return (med_error(medep, errno, "close_dbfile: close()"));

	dbfd = -1;

	return (0);
}

static int
med_db_del_rec(med_med_t *medp, med_err_t *medep)
{
	med_rec_t	*medrp = NULL;
	int		i;
	int		medridx = -1;


	if (! med_db_is_inited)
		return (med_error(medep, MDE_MED_DBNOTINIT, "med_db_del_rec"));

	if ((medridx = find_key(medp)) == -1)
		return (0);

	/* Delete the old keys */
	if (del_db_keys(medridx, medep))
		return (-1);

	medrp = &med_db_medrp[medridx];

	/* Mark the record in core as deleted */
	medrp->med_rec_fl |= MED_RFL_DEL;

	/* Decrement the used slot count */
	med_db_nmu--;

	/* Get ready to re-write the file */
	if (ftruncate(dbfd, 0) == -1)
		return (med_error(medep, errno, "med_db_del_rec: ftruncate()"));

	if (write_hdr(dbfd, medep))
		return (-1);

	for (i = 0; i < med_db_nma; i++) {
		medrp = &med_db_medrp[i];

		if (medrp->med_rec_fl & MED_RFL_DEL)
			continue;

		/* Determine our location in the file */
		if ((medrp->med_rec_foff = lseek(dbfd, 0, SEEK_CUR)) == -1)
			return (med_error(medep, errno,
			    "med_db_del_rec: lseek()"));

		if (write_rec(dbfd, medrp, medep))
			return (-1);
	}
	return (0);
}

static int
cmp_medrec(med_rec_t *omedrp, med_rec_t *nmedrp)
{
	int	ret;
	int	i;

	if (omedrp->med_rec_mag != nmedrp->med_rec_mag)
		return (0);

	if (omedrp->med_rec_rev != nmedrp->med_rec_rev)
		return (0);

	/* Can't compare checksums, since the new record has no data yet */

	/* Can't compare flags, since the in-core may have golden */

	if (omedrp->med_rec_sn != nmedrp->med_rec_sn)
		return (0);

	if (strcmp(omedrp->med_rec_snm, nmedrp->med_rec_snm) != 0)
		return (0);

	for (i = 0; i < MD_MAXSIDES; i++) {
		if (omedrp->med_rec_nodes[i][0] == '\0' &&
		    nmedrp->med_rec_nodes[i][0] == '\0')
			continue;

		ret = strcmp(omedrp->med_rec_nodes[i],
		    nmedrp->med_rec_nodes[i]);
		if (ret != 0)
			return (0);
	}

	ret = memcmp(&omedrp->med_rec_meds, &nmedrp->med_rec_meds,
	    sizeof (md_h_arr_t));
	if (ret != 0)
		return (0);

	return (1);
}

/*
 * Exported routines
 */

int
med_db_init(med_err_t *medep)
{
	int		i;
	int		err = 0;
	int		ret;
	struct	stat	statb;
	med_db_hdr_t	*dbhp;
	med_rec_t	*medrp;
	int		nm;
	off_t		cur_off;

	if (med_db_is_inited)
		return (0);

	if (open_dbfile(medep))
		return (-1);

	if (fstat(dbfd, &statb) == -1)
		return (med_error(medep, errno, "med_db_init: fstat()"));

	/* Empty file */
	if (statb.st_size == 0)
		goto out;

	/* File should be a multiple of the record size */
	if (((int)(statb.st_size % (off_t)rec_size)) != 0)
		return (med_error(medep, MDE_MED_DBSZBAD, "med_db_init"));

	if (alloc_rec_buf(medep))
		return (-1);

	/* Read in the file header */
	if ((ret = read(dbfd, rec_buf, rec_size)) == -1)
		return (med_error(medep, errno, "med_db_init: read(hdr)"));

	if (ret != rec_size)
		return (med_error(medep, MDE_MED_DBHDRSZBAD, "med_db_init"));

	/*LINTED*/
	dbhp = (med_db_hdr_t *)rec_buf;

	/* Header magic is not OK */
	if (dbhp->med_dbh_mag != MED_DB_MAGIC)
		return (med_error(medep, MDE_MED_DBHDRMAGBAD, "med_db_init"));

	/* Header revision is not OK */
	if (dbhp->med_dbh_rev != MED_DB_REV)
		return (med_error(medep, MDE_MED_DBHDRREVBAD, "med_db_init"));

	/* Header checksum is not OK */
	if (crcchk(dbhp, &dbhp->med_dbh_cks, sizeof (med_db_hdr_t), NULL))
		return (med_error(medep, MDE_MED_DBHDRCKSBAD, "med_db_init"));

	/* File size does not add up */
	if (((off_t)((dbhp->med_dbh_nm * rec_size) + rec_size))
	    != statb.st_size)
		return (med_error(medep, MDE_MED_DBSZBAD, "med_db_init"));

	if ((nm = dbhp->med_dbh_nm) > 0) {
		/* Allocate space to hold the records to be read next */
		med_db_medrp = (med_rec_t *)Calloc(nm, sizeof (med_rec_t));
		if (med_db_medrp == NULL)
			return (med_error(medep, errno,
			    "med_db_init: Calloc(med_db_medrp)"));
	}

	/* Read in all the records */
	for (i = 0; i < nm; i++) {
		if ((cur_off = lseek(dbfd, 0, SEEK_CUR)) == -1) {
			err = med_error(medep, errno,
			    "med_db_init: lseek()");
			goto out;
		}

		(void) memset(rec_buf, '\0', rec_size);

		if ((ret = read(dbfd, rec_buf, rec_size)) == -1) {
			err = med_error(medep, errno,
			    "med_db_init: read() rec");
			goto out;
		}

		if (ret != rec_size) {
			err = med_error(medep, MDE_MED_DBRECSZBAD,
			    "med_db_init");
			goto out;
		}

		/*LINTED*/
		medrp = (med_rec_t *)rec_buf;

		/* Record magic is not OK */
		if (medrp->med_rec_mag != MED_REC_MAGIC) {
			err = med_error(medep, MDE_MED_DBRECMAGBAD,
			    "med_db_init");
			goto out;
		}

		/* Record revision is not OK */
		if (medrp->med_rec_rev != MED_REC_REV) {
			err = med_error(medep, MDE_MED_DBRECREVBAD,
			    "med_db_init");
			goto out;
		}

		/* Record checksum is not OK */
		ret = crcchk(medrp, &medrp->med_rec_cks, sizeof (med_rec_t),
		    NULL);
		if (ret) {
			err = med_error(medep, MDE_MED_DBRECCKSBAD,
			    "med_db_init");
			goto out;
		}

		/* Record is not where it is supposed to be */
		if (medrp->med_rec_foff != cur_off) {
			err = med_error(medep, MDE_MED_DBRECOFFBAD,
			    "med_db_init");
			goto out;
		}

		med_db_medrp[i] = *medrp;	/* structure assignment */
	}

	/* Add the keys to access this record */
	for (i = 0; i < nm; i++)
		if ((err = add_db_keys(i, medep)) == -1)
			goto out;

	med_db_nma = nm;
	med_db_nmu = nm;

out:
	if (err && med_db_medrp != NULL)
		Free(med_db_medrp);

	if (!err)
		med_db_is_inited = 1;

	return (err);
}

med_rec_t *
med_db_get_rec(med_med_t *medp, med_err_t *medep)
{
	int		medridx = -1;

	if ((medridx = find_key(medp)) == -1) {
		(void) med_error(medep, MDE_MED_DBRECNOENT, "med_db_get_rec");
		return (NULL);
	}

	return (&med_db_medrp[medridx]);
}

med_data_t *
med_db_get_data(med_med_t *medp, med_err_t *medep)
{
	int		medridx = -1;

	if ((medridx = find_key(medp)) == -1) {
		(void) med_error(medep, MDE_MED_DBRECNOENT, "med_db_get_data");
		return (NULL);
	}

	return (&med_db_medrp[medridx].med_rec_data);
}

int
med_db_put_rec(med_med_t *medp, med_rec_t *nmedrp, med_err_t *medep)
{
	med_rec_t	*medrp = NULL;
	med_rec_t	*tmedrp = NULL;
	int		i;
	int		found = 0;
	int		medridx = -1;


	if (! med_db_is_inited)
		return (med_error(medep, MDE_MED_DBNOTINIT, "med_db_put_rec"));

	if (medp->med_setno != nmedrp->med_rec_sn)
		return (med_error(medep, MDE_MED_DBARGSMISMATCH,
		    "med_db_put_rec"));

	/* See if we are still considered a mediator - is this a delete? */
	for (i = 0; i < MED_MAX_HOSTS; i++) {
		if (nmedrp->med_rec_meds.n_lst[i].a_cnt == 0)
			continue;

		if (strcmp(nmedrp->med_rec_meds.n_lst[i].a_nm[0],
		    mynode()) == 0) {
			found = 1;
			break;
		}
	}

	/* If it is a delete, make it happen */
	if (! found)
		return (med_db_del_rec(medp, medep));

	/* See if there is an existing record */
	if ((medridx = find_key(medp)) != -1) {

		medrp = &med_db_medrp[medridx];

		/* Delete the old keys */
		if (del_db_keys(medridx, medep))
			return (-1);

		/* Decrement the used slot count */
		med_db_nmu--;
	} else {
		for (i = 0; i < MED_MAX_HOSTS; i++) {
			med_med_t	tmed;

			if (nmedrp->med_rec_meds.n_lst[i].a_cnt == 0)
				continue;

			if (strcmp(nmedrp->med_rec_meds.n_lst[i].a_nm[0],
			    medp->med_caller) == 0)
				continue;

			tmed = *medp;		/* structure assignment */

			tmed.med_caller =
			    Strdup(nmedrp->med_rec_meds.n_lst[i].a_nm[0]);

			medridx = find_key(&tmed);

			Free(tmed.med_caller);

			if (medridx != -1) {
				medrp = &med_db_medrp[medridx];

				if (cmp_medrec(medrp, nmedrp))
					return (0);
			}
		}
	}

	/* Allocate more space if needed */
	if ((med_db_nmu + 1) > med_db_nma) {

		/* Allocate more space to hold the new record */
		tmedrp = (med_rec_t *)Calloc((med_db_nmu + 1),
		    sizeof (med_rec_t));
		if (tmedrp == NULL)
			return (med_error(medep, errno,
			    "med_db_put_rec: Re-Calloc(tmedrp)"));

		/* Copy the existing information into the new area */
		for (i = 0; i < med_db_nma; i++)
			tmedrp[i] = med_db_medrp[i]; /* structure assignment */

		med_db_nmu++;
		med_db_nma = med_db_nmu;

		if (med_db_medrp)
			Free(med_db_medrp);

		med_db_medrp = tmedrp;

		medridx = med_db_nma - 1;

		/* Initialize */
		medrp = &med_db_medrp[medridx];
		medrp->med_rec_mag = MED_REC_MAGIC;
		medrp->med_rec_rev = MED_REC_REV;
		medrp->med_rec_sn = nmedrp->med_rec_sn;
		(void) strcpy(medrp->med_rec_snm, nmedrp->med_rec_snm);

		/* Calculate the record offset */
		medrp->med_rec_foff = (off_t)(((med_db_nma - 1) * rec_size) +
		    rec_size);
	} else {
		/*
		 * We did not find the record, but have space allocated.
		 * Find an empty slot.
		 */
		if (medrp == NULL) {
			for (i = 0; i < med_db_nma; i++) {
				medrp = &med_db_medrp[i];

				if (! (medrp->med_rec_fl & MED_RFL_DEL))
					continue;

				medridx = i;

				/* Mark as no longer deleted */
				medrp->med_rec_fl &= ~MED_RFL_DEL;

				/* Initialize */
				medrp->med_rec_mag = MED_REC_MAGIC;
				medrp->med_rec_rev = MED_REC_REV;
				medrp->med_rec_sn = nmedrp->med_rec_sn;
				(void) strcpy(medrp->med_rec_snm,
				    nmedrp->med_rec_snm);

				/* Calculate the new offset of the record */
				medrp->med_rec_foff = (off_t)
				    ((med_db_nmu * rec_size) + rec_size);

				/* Clear the old data */
				(void) memset(&medrp->med_rec_data, '\0',
				    sizeof (med_data_t));

				break;
			}
		}
		med_db_nmu++;
	}

	assert(medridx != -1);

	/* Update the record with the new information */
	medrp->med_rec_meds = nmedrp->med_rec_meds;  /* structure assignment */

	for (i = 0; i < MD_MAXSIDES; i++)
		(void) strcpy(medrp->med_rec_nodes[i],
		    nmedrp->med_rec_nodes[i]);

	if (write_hdr(dbfd, medep))
		return (-1);

	/* Position to record location */
	if (lseek(dbfd, medrp->med_rec_foff, SEEK_SET) == -1)
		return (med_error(medep, errno, "med_db_put_rec: lseek(rec)"));

	if (write_rec(dbfd, medrp, medep))
		return (-1);

	/* Add the keys for this record */
	if (add_db_keys(medridx, medep))
		return (-1);

	return (0);
}

int
med_db_put_data(med_med_t *medp, med_data_t *meddp, med_err_t *medep)
{
	med_rec_t	*medrp = NULL;
	int		medridx = -1;


	if (! med_db_is_inited)
		return (med_error(medep, MDE_MED_DBNOTINIT, "med_db_put_data"));

	if (medp->med_setno != meddp->med_dat_sn)
		return (med_error(medep, MDE_MED_DBARGSMISMATCH,
		    "med_db_put_data"));

	if ((medridx = find_key(medp)) == -1)
		return (med_error(medep, MDE_MED_DBRECNOENT,
		    "med_db_put_data"));

	medrp = &med_db_medrp[medridx];

	medrp->med_rec_data = *meddp;		/* structure assignment */

	/* Go to location of the record */
	if (lseek(dbfd, medrp->med_rec_foff, SEEK_SET) == -1)
		return (med_error(medep, errno, "med_db_put_data: lseek()"));

	if (write_rec(dbfd, medrp, medep))
		return (-1);

	return (0);
}

int
med_db_finit(med_err_t *medep)
{
	des_cache(&med_db_cache);
	Free(med_db_medrp);
	free_rec_buf();
	if (close_dbfile(medep))
		return (-1);
	return (0);
}
