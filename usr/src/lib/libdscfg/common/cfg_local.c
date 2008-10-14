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

#include <stdio.h>

#include <sys/types.h>
#include <sys/vtoc.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include "cfg_impl.h"
#include "cfg.h"
#include "cfg_local.h"

#if 0
#define	DEBUG_CFGLIST
#define	DEBUG_CFGLISTRM
#endif

extern	int	cfg_severity;
extern	char	*cfg_perror_str;

long
get_bsize(cfp_t *cfp, char *name)
{
	char char_name[PATH_MAX];
	char *rest;
	struct vtoc vtoc;
	int slice;
	int fd;

	if (strlen(name) >= PATH_MAX - 1)
		return (0);

	rest = strstr(name, "/dsk/");
	if (rest == NULL) {
		if ((rest = strstr(name, "/rdsk/")) == NULL)
			return (0);
		strcpy(char_name, name);
		goto do_open;

	}
	strcpy(char_name, name);
	char_name[strlen(name) - strlen(rest)] = 0;
	strcat(char_name, "/rdsk/");
	strcat(char_name, rest + 5);

do_open:
	fd = open(char_name, O_RDONLY);
	if (fd < 0)
		return (0);

	slice = read_vtoc(fd, &vtoc);
	if (slice < 0) {
		(void) close(fd);
		return (0);
	}

	(void) close(fd);
	if (vtoc.v_part[slice].p_start < CFG_VTOC_SIZE)
		cfp->cf_flag |= CFG_NOWRVTOC;

	return (vtoc.v_part[slice].p_size);
}

/*
 * round up to the next block size
 */
int
get_block_size(int size)
{
	int ret;

	if (size % CFG_BLOCK_SIZE != 0)
		ret = size + CFG_BLOCK_SIZE - (size % CFG_BLOCK_SIZE);
	else
		ret = size;
	return (ret);
}

/*
 * get a chunk of mem rounded up to next block size
 */
char *
get_block_buf(int size)
{
	int blk_size;
	char *blk_buf;

	blk_size = get_block_size(size);

	if ((blk_buf = (char *)calloc(blk_size, sizeof (char))) == NULL) {
		cfg_severity = CFG_EFATAL;
		cfg_perror_str = dgettext("cfg", strerror(errno));
		return (NULL);
	}
	return (blk_buf);
}

void
free_block_buf(char *buf)
{
	if (buf)
		free(buf);
}

void
localcf_close(cfp_t *cfp)
{
	fsync(cfp->cf_fd);
	cfp_unlock(cfp);
	close(cfp->cf_fd);
}


/*
 * cfg_open
 * Open the current configuration file
 * Sets file descriptor in cfp->cf_fd for use by other routines
 */
cfp_t *
localcf_open(cfp_t *cfp, char *name)
{
	struct stat sb;
	int rc;


	if (name == NULL) {
		cfg_perror_str = dgettext("cfg",
		    "cfg_open: unable to open configuration location");
		cfg_severity = CFG_EFATAL;
		return (NULL);
	}

	cfp->cf_fd = open(name, O_RDWR|O_CREAT|O_DSYNC|O_RSYNC, 0640);
	if (cfp->cf_fd == -1) {
		if ((cfp->cf_fd = open(name, O_RDONLY, 0640)) == -1) {
			cfg_perror_str = dgettext("cfg",
			    "cfg_open: unable to open configuration location");
			cfg_severity = CFG_EFATAL;
			return (NULL);
		}
		cfp->cf_flag |= CFG_RDONLY;
	}

	if (fstat(cfp->cf_fd, &sb) == -1) {
		close(cfp->cf_fd);
		cfg_perror_str = dgettext("cfg",
		    "cfg_open: unable to stat configuration location");
		cfg_severity = CFG_EFATAL;
		return (NULL);
	}


	if (S_ISBLK(sb.st_mode) || S_ISCHR(sb.st_mode)) {
		cfp->cf_size = get_bsize(cfp, name);

		/* skip the vtoc if necessary */
		if (cfp->cf_flag & CFG_NOWRVTOC) {
			do {
				rc = lseek(cfp->cf_fd, CFG_VTOC_SKIP, SEEK_SET);
			} while (rc == -1 && errno == EINTR);

			if (rc == -1) {
				cfg_perror_str = dgettext("cfg",
				    strerror(errno));
				cfg_severity = CFG_EFATAL;
				close(cfp->cf_fd);
				return (NULL);
			}
		}

	} else if (S_ISREG(sb.st_mode)) {
		cfp->cf_flag |= CFG_FILE;
		cfp->cf_size = FBA_NUM(FBA_SIZE(1) - 1 + sb.st_size);
	} else {
		cfg_perror_str = dgettext("cfg", "cfg_open: unknown file type");
		cfg_severity = CFG_EFATAL;
		close(cfp->cf_fd);
		cfp->cf_fd = NULL;
		return (NULL);
	}
	return (cfp);
}

int
localcf_seekblk(cfp_t *cfp, int off, int mode)
{
	int rc;

	do {
		rc = lseek(cfp->cf_fd, off, mode);
	} while (rc == -1 && errno == EINTR);

	return (rc);
}

int
localcf_readblk(cfp_t *cfp, void *buf, int size)
{
	int rc;

	do {
		rc = read(cfp->cf_fd, buf, size);
	} while (rc == -1 && errno == EINTR);

	return (rc);
}

int
localcf_writeblk(cfp_t *cfp, void *buf, int size)
{
	int rc;

	do {
		rc = write(cfp->cf_fd, buf, size);
	} while (rc == -1 && errno == EINTR);

	return (rc);
}

int
localcf_seek(cfp_t *cfp, int off, int mode)
{
	int rc;
	int offset;

	offset = get_block_size(off);

	if ((mode == SEEK_SET) && (cfp->cf_flag & CFG_NOWRVTOC)) {
		offset += CFG_VTOC_SKIP;
	}

	do {
		rc = lseek(cfp->cf_fd, offset, mode);
	} while (rc == -1 && errno == EINTR);

	return (rc);
}

int
localcf_read(cfp_t *cfp, void *buf, int size)
{
	int rc;
	int blk_size;
	char *blk_buf;

	blk_size = get_block_size(size);
	if ((blk_buf = get_block_buf(size)) == NULL)
		return (-1);

	do {
		rc = read(cfp->cf_fd, blk_buf, blk_size);
	} while (rc == -1 && errno == EINTR);

	bcopy(blk_buf, buf, size);
	free_block_buf(blk_buf);

	return (rc);
}

int
localcf_write(cfp_t *cfp, void *buf, int size)
{
	int rc;
	int blk_size;
	char *blk_buf;

	blk_size = get_block_size(size);
	if ((blk_buf = get_block_buf(size)) == NULL)
		return (-1);

	bcopy(buf, blk_buf, size);

	do {
		rc = write(cfp->cf_fd, blk_buf, blk_size);
	} while (rc == -1 && errno == EINTR);

	free_block_buf(blk_buf);

	return (rc);
}
/*
 * Routines which operate on internal version of configuration
 */

/*
 * Add entry to end  of configuration section
 */

int
addcfline(cfp_t *cfp, char *line, int table_index)
{
	int len = strlen(line)+1;
	int newsize = DEFAULT_ENTRY_SIZE / 2;
	cfgheader_t *hd;
	cfglist_t *cfl;
	char *q;

#ifdef DEBUG_CFGLIST
	fprintf(stderr, "addcfline: pre l_size %d h_cfgsizes[%d]"
	    " %d l_free %u adding len %d\n",
	    cfp->cf_head->h_cfgs[table_index].l_size, table_index,
	    cfp->cf_head->h_cfgsizes[table_index],
	    cfp->cf_head->h_cfgs[table_index].l_free, len);
#endif

	hd = cfp->cf_head;
	cfl = &cfp->cf_head->h_cfgs[table_index];
	if (cfl->l_free < len) {

#ifdef DEBUG_CFGLIST
		fprintf(stderr, "resizing l_entry from %d to %d\n",
		    cfl->l_size + cfl->l_free, cfl->l_size +
		    cfl->l_free + newsize);
#endif
		cfl->l_entry = (char *)realloc(cfl->l_entry, (cfl->l_size +
		    cfl->l_free + newsize) * sizeof (char));
		if (cfl->l_entry == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		cfl->l_free += newsize;

	}
	cfl->l_free -= len;

	/* out of list slots, get some more */
	if (cfl->l_nentry % DEFAULT_NENTRIES == 0) {
		/*
		 * first, figure out how much bigger, than realloc
		 */

#ifdef DEBUG_CFGLIST
		fprintf(stderr,
		    "list %d getting more nentries, I have %d\n",
		    table_index, cfl->l_nentry);
#endif
		cfl->l_esiz = (int *)
		    realloc(cfl->l_esiz, (cfl->l_nentry + DEFAULT_NENTRIES) *
		    sizeof (int));
		if (cfl->l_esiz == NULL) {
			errno = ENOMEM;
			return (-1);
		}
	}


	cfl->l_esiz[cfl->l_nentry] = len;
	cfl->l_nentry++;

	/* add line to end of list */
	q = cfl->l_entry + cfl->l_size;

	strcpy(q, line);
	q += len;

	/* set sizes */
	hd->h_cfgs[table_index].l_size += len;
	hd->h_cfgsizes[table_index] = cfl->l_size;
	cfp->cf_head->h_csize += len;

#ifdef DEBUG_CFGLIST
	fprintf(stderr, "addcfline: post l_size %d h_cfgsizes[%d]"
	    " %d l_free %u\n h_csize %d\n",
	    cfp->cf_head->h_cfgs[table_index].l_size,
	    table_index, cfp->cf_head->h_cfgsizes[table_index],
	    cfp->cf_head->h_cfgs[table_index].l_free, cfp->cf_head->h_csize);
#endif

	return (1);
}

/*
 * remove entry from configuration section
 */
int
remcfline(cfp_t *cfp, int table_offset, int setnum)
{
	cfgheader_t *ch;
	char *p, *q;
	int len;
	int copylen;
	int i;
	cfglist_t *cfl;
	ch = cfp->cf_head;

	cfl = &cfp->cf_head->h_cfgs[table_offset];

	q = cfl->l_entry;

	if (cfl->l_size == 0) {
		/* list is empty */
		return (-1);
	}

	if (!q) { /* somethings wrong here */
		return (-1);
	}


	for (i = 1; i < setnum; i++) {
		q += cfl->l_esiz[i - 1];
		if (i >= cfl->l_nentry) { /* end of list */
			return (-1);
		}
	}

	if (q >= cfl->l_entry + cfl->l_size)
		return (-1);

	len = cfl->l_esiz[i - 1];


#ifdef DEBUG_CFGLISTRM
	fprintf(stderr, "remcfline: pre: l_size %d h_cfgsizes[%d] %d free %d"
	    " removing len %d\n",
	    ch->h_cfgs[table_offset].l_size, table_offset,
	    ch->h_cfgsizes[table_offset],
	    ch->h_cfgs[table_offset].l_free, len);
#endif

	p = q + len; /* next string */

	if (!(p >= cfl->l_entry + cfl->l_size)) {
		/* if we didn't delete the last string in list */
		/* LINTED possible overflow */
		copylen = cfl->l_entry + cfl->l_size - p;
		bcopy(p, q, copylen);
		copylen = (cfl->l_nentry - i) * sizeof (int);
		bcopy(&cfl->l_esiz[i], &cfl->l_esiz[i - 1], copylen);
	}

	/* decrement the number of sets in this list */
	cfl->l_nentry--;
	/* not really necessary, but.. */
	cfl->l_esiz[cfl->l_nentry] = 0;

	cfl->l_size -= len;
	cfl->l_free += len;

	p = cfl->l_entry + cfl->l_size;
	bzero(p, cfl->l_free);

	ch->h_cfgsizes[table_offset] = cfl->l_size;
	ch->h_csize -= len;


#ifdef DEBUG_CFGLIST
	fprintf(stderr,
	    "remcfline: post: l_size %d h_cfgsizes[%d] %d free %d\n ",
	    ch->h_cfgs[table_offset].l_size, table_offset,
	    ch->h_cfgsizes[table_offset], ch->h_cfgs[table_offset].l_free);
#endif

	return (0);

}
/*
 * Read entry from configuration section
 */
char *
readcfline(cfp_t *cfp, char *buf, int table_offset, int num)
{

	char *q;
	int i;
	cfgheader_t *ch;
	cfglist_t  *cfl;

	/* this means they couldn't even find it in the parser tree */
	if (table_offset < 0)
		return (NULL);

	ch = cfp->cf_head;
	cfl = &ch->h_cfgs[table_offset];

	q = cfl->l_entry;

	for (i = 1; i < num; i++) {
		q += cfl->l_esiz[i - 1];
		if (i >= cfl->l_nentry) /* end of list */
			return (NULL);
	}

	if (q >= cfl->l_entry + cfl->l_size)
		return (NULL);
	strcpy(buf, q);
	return (q);
}


/*
 * overwrite from current position with new value
 */
int
replacecfline(cfp_t *cfp, char *line, int table_offset, int num)
{
/*
 * take a table offset and a num to replace
 * index in, bump the list up, leaving a hole big
 * enough for the new string, or bcopying the rest of the list
 * down only leaving a hole big enough.
 * make sure not to overflow the
 * allocated list size.
 */
	cfgheader_t *ch;
	cfglist_t  *cfl;
	char *p, *q;
	int len = strlen(line) + 1;
	int diff = 0;
	int i;
	int newsize = DEFAULT_ENTRY_SIZE / 2;


	ch = cfp->cf_head;
	cfl = &ch->h_cfgs[table_offset];

	q = cfl->l_entry;
	for (i = 1; i < num; i++) {
		q += cfl->l_esiz[i - 1];
		if (i >= cfl->l_nentry) /* end of list */
			return (-1);
	}
	diff = len - cfl->l_esiz[i - 1];
	/* check for > 0, comparing uint to int */
	if ((diff > 0) && (diff > cfl->l_free)) {
		/*
		 * we are going to overflow, get more mem, but only
		 * 1/2 as much as initial calloc, we don't need to be greedy
		 */
#ifdef DEBUG_CFGLIST
		fprintf(stderr,
		    "resizing at replacecfline from %d to %d \n",
		    cfl->l_size + cfl->l_free, cfl->l_size +
		    cfl->l_free + newsize);
#endif
		cfl->l_entry = (char *)realloc(cfl->l_entry,
		    (cfl->l_size + cfl->l_free + newsize) * sizeof (char));
		if (cfl->l_entry == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		cfl->l_free += (DEFAULT_ENTRY_SIZE / 2);

		/* re-find q, we could have a whole new chunk of memory here */
		q = cfl->l_entry;
		for (i = 1; i < num; i++) {
			q += cfl->l_esiz[i - 1];
			if (i >= cfl->l_nentry) /* end of list */
				return (-1);
		}
	}

	p = q + cfl->l_esiz[i - 1]; /* next string */
	cfl->l_esiz[i - 1] += diff; /* the new entry size */
	if (diff != 0) { /* move stuff over/back for correct fit */
		/* LINTED possible overflow */
		bcopy(p, p + diff, (cfl->l_entry + cfl->l_size - p));
		cfl->l_free -= diff; /* 0 - (-1) = 1 */
		cfl->l_size += diff;

		/* total of all h_cfgs[n].l_entry */
		cfp->cf_head->h_csize += diff;
		cfp->cf_head->h_cfgsizes[table_offset] = cfl->l_size; /* disk */
		bzero((cfl->l_entry + cfl->l_size), cfl->l_free);
	}

	strcpy(q, line);
	return (1);

}

static cfg_io_t _cfg_raw_io_def = {
	NULL,
	"Local",
	localcf_open,
	localcf_close,
	localcf_seek,
	localcf_read,
	localcf_write,
	readcfline,
	addcfline,
	remcfline,
	replacecfline,

};

static cfg_io_t _cfg_block_io_def = {
	NULL,
	"Local",
	localcf_open,
	localcf_close,
	localcf_seekblk,
	localcf_readblk,
	localcf_writeblk,
	readcfline,
	addcfline,
	remcfline,
	replacecfline,
};

cfg_io_t *
cfg_raw_io_provider(void)
{
	return (&_cfg_raw_io_def);
}

cfg_io_t *
cfg_block_io_provider(void)
{
	return (&_cfg_block_io_def);
}
