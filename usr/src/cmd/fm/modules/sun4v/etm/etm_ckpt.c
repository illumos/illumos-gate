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
 * etm_ckpt.c
 * Description:
 *    Checkpoint the ereport events for persitence across fmd restart.
 *
 *    Each ereport is stored in a named buffer. Each ereport is uniquely
 *    indentified by a id which is consists of a number of ereport fields. The
 *    name of the buffer is derived from the id.
 *
 *    All ereport ids are stored in the circular list which is saved in a
 *    separate buffer.
 */

#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fm/ldom.h>
#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <fm/topo_hc.h>

#include "etm_etm_proto.h"
#include "etm_iosvc.h"
#include "etm_ckpt.h"
#include "etm_filter.h"

#define	ETM_ATTR_PRIMARY	"primary"
#define	ETM_ATTR_TOD		"__tod"
#define	ETM_LDOM_PRIMARY	"primary"

/*
 * -------------------------- private variables ------------------------------
 */

static etm_ckpt_id_list_t *etm_id_lst = NULL;	/* list of ereports ids */

static pthread_mutex_t etm_id_lst_lock;		/* list lock */

/*
 * -------------------------- functions --------------------------------------
 */

/*
 * etm_ckpt_str_hash()
 * Description:
 *     Hash a class name to a number
 */
static uint_t
etm_ckpt_str_hash(char *str)
{
	uint_t		hash = 0;	/* hash value */

	if (str == NULL)
		return (0);

	while (*str != '\0')
		hash += *str++;

	return (hash);
}

/*
 * etm_ckpt_id2str()
 * Description:
 *     Get the string of an ereport id. It is used as the named buffer that
 *     store the ereport.
 */
static void
etm_ckpt_id2str(etm_ckpt_erpt_id_t *id, char *str, size_t size) {
	(void) snprintf(str, size, "%s_%llx_%d_%x_%d", ETM_CKPT_ERPT_PREFIX,
	    id->ei_ena, id->ei_hash, id->ei_tod1, id->ei_pri);
}

/*
 * etm_ckpt_erpt2id()
 * Description:
 *     Get the buffer name and ereport id of a given ereport
 */
static int
etm_ckpt_erpt2id(fmd_hdl_t *hdl, nvlist_t *erpt, etm_ckpt_erpt_id_t *id,
    char *str, int size) {
	char		*class = NULL;
	uint64_t	*tod;
	uint_t		sz;
	boolean_t	pri = B_FALSE;

	bzero(id, sizeof (etm_ckpt_erpt_id_t));

	/* ena */
	if (nvlist_lookup_uint64(erpt, FM_EREPORT_ENA, &id->ei_ena) != 0) {
		fmd_hdl_debug(hdl, "Ena not found\n");
		return (-1);
	}

	/* class name */
	(void) nvlist_lookup_string(erpt, FM_CLASS, &class);
	if (class == NULL) {
		fmd_hdl_debug(hdl, "%s not found\n", FM_CLASS);
		return (-1);
	}
	if (strncmp(class, FM_EREPORT_CLASS, strlen(FM_EREPORT_CLASS)) != 0) {
		fmd_hdl_debug(hdl, "Only support checkpointing %s\n",
		    FM_EREPORT_CLASS);
		return (-1);
	}
	id->ei_hash = etm_ckpt_str_hash(class);

	/* tod[1]: fractional of a second */
	if (nvlist_lookup_uint64_array(erpt, ETM_ATTR_TOD, &tod, &sz) == 0) {
		if (sz >= 2) {
			id->ei_tod1 = (uint32_t)tod[1];
		}
	}

	/* primary flag */
	if (nvlist_lookup_boolean_value(erpt, ETM_ATTR_PRIMARY, &pri) == 0) {
		id->ei_pri = pri ? 1 : 0;
	}

	etm_ckpt_id2str(id, str, size);

	return (0);
}

/*
 * etm_ckpt_il_equal()
 * Description:
 *     Test if two ereport ids are equal.
 */
static boolean_t
etm_ckpt_il_equal(etm_ckpt_erpt_id_t *i1, etm_ckpt_erpt_id_t *i2)
{
	return ((i1->ei_ena == i2->ei_ena) && (i1->ei_tod1 == i2->ei_tod1) &&
	    (i1->ei_pri == i2->ei_pri) && (i1->ei_hash == i2->ei_hash));
}

/*
 * etm_ckpt_il_resize()
 * Description:
 *     Increase the size of the circular list and pack its entries.
 */
static void
etm_ckpt_il_resize(fmd_hdl_t *hdl, uint_t factor)
{
	etm_ckpt_id_list_t	*il1, *il2;		/* temp lists */
	size_t			sz1, sz2;		/* sizes of lists */
	int			i, next;		/* temp counters */
	etm_ckpt_erpt_id_t	*p1, *p2, *s1, *s2;	/* temp id pointers */
	etm_ckpt_erpt_id_t	blank;			/* blank ereport id */

	if (factor == 0)
		return;

	/* the present queue */
	il1 = etm_id_lst;
	sz1 = sizeof (etm_ckpt_id_list_t) + il1->il_ids_sz;

	/* Create an empty queue with a new size */
	sz2 = sizeof (etm_ckpt_id_list_t) + (factor * il1->il_ids_sz);
	il2 = fmd_hdl_zalloc(hdl, sz2, FMD_SLEEP);
	il2->il_ver = ETM_CKPT_VERSION;
	il2->il_max = factor * etm_id_lst->il_max;
	il2->il_ids_sz = factor * il1->il_ids_sz;

	/* pointers to the two arrays of entries */
	bzero(&blank, sizeof (blank));
	s1 = (etm_ckpt_erpt_id_t *)
	    ((ptrdiff_t)il1 + sizeof (etm_ckpt_id_list_t));
	s2 = (etm_ckpt_erpt_id_t *)
	    ((ptrdiff_t)il2 + sizeof (etm_ckpt_id_list_t));

	/* copy non-empty ereport ids from list il1 to il2. Toss the blank. */
	if (il1->il_head != il1->il_tail) {
		for (i = il1->il_head; i != il1->il_tail; i = next) {
			next = (i + 1) % il1->il_max;
			p1 = s1 + next;
			if (!etm_ckpt_il_equal(p1, &blank)) {
				/* copy non-empty entries */
				il2->il_tail = (il2->il_tail + 1) % il2->il_max;
				fmd_hdl_debug(hdl, "Copying entry %d to %d\n",
				    next, il2->il_tail);
				p2 = s2 +  il2->il_tail;
				*p2 = *p1;
				il2->il_cnt++;
			}
		}
	}

	if (factor == 1) {
		/* both lists have the same size, update the present list */
		bcopy(il2, il1, sz1);
		fmd_hdl_free(hdl, il2, sz2);
		fmd_buf_write(hdl, NULL, ETM_CKPT_IL_BUF, (void *) il1, sz1);
	} else {
		/* replace the present list */
		etm_id_lst = il2;
		fmd_hdl_free(hdl, il1, sz1);
		/* write to new buffer */
		fmd_buf_destroy(hdl, NULL, ETM_CKPT_IL_BUF);
		fmd_buf_create(hdl, NULL, ETM_CKPT_IL_BUF, sz2);
		fmd_buf_write(hdl, NULL, ETM_CKPT_IL_BUF, (void *) il2, sz2);
	}
}

/*
 * etm_ckpt_il_find()
 * Description:
 *     Find the ereport id in the list.
 */
/* ARGSUSED */
static int
etm_ckpt_il_find(fmd_hdl_t *hdl, etm_ckpt_erpt_id_t *id)
{
	int			i, next;	/* temp counter */
	etm_ckpt_erpt_id_t	*p, *s;		/* temp erpt id */

	fmd_hdl_debug(hdl, "etm_ckpt_il_find()\n");

	/* empty list */
	if (etm_id_lst->il_head == etm_id_lst->il_tail) {
		fmd_hdl_debug(hdl, "find an empty list\n");
		return (-1);
	}
	s = (etm_ckpt_erpt_id_t *)((ptrdiff_t)etm_id_lst +
	    sizeof (etm_ckpt_id_list_t));
	for (i = etm_id_lst->il_head; i != etm_id_lst->il_tail; i = next) {
		next = (i + 1) % etm_id_lst->il_max;
		p = s + next;
		if (etm_ckpt_il_equal(p, id))
			return (i);
	}

	return (-1);
}

/*
 * etm_ckpt_il_add()
 * Description:
 *     Add an ereport id in the list.
 */
static int
etm_ckpt_il_add(fmd_hdl_t *hdl, etm_ckpt_erpt_id_t *id) {
	int			next;
	etm_ckpt_erpt_id_t	*p, *s;	/* temp id */

	/*
	 * resize the q if it is full.
	 * If the capacity is less 80%, purge the emtpy entries to make more
	 * room for new entries. Otherwise, double the queue size.
	 */
	next = (etm_id_lst->il_tail + 1) % etm_id_lst->il_max;
	if (next == etm_id_lst->il_head) {
		if ((etm_id_lst->il_cnt * 1.0 / etm_id_lst->il_max) < 0.8) {
			etm_ckpt_il_resize(hdl, 1);
		} else {
			etm_ckpt_il_resize(hdl, 2);
		}

		/* test if the list again */
		next = (etm_id_lst->il_tail + 1) % etm_id_lst->il_max;
		if (next == etm_id_lst->il_head) {
			fmd_hdl_error(hdl, "List is full %d %d\n",
			    etm_id_lst->il_head, etm_id_lst->il_tail);
		}
	}

	/* Add the id entry at the head */
	s = (etm_ckpt_erpt_id_t *)((ptrdiff_t)etm_id_lst +
	    sizeof (etm_ckpt_id_list_t));
	etm_id_lst->il_tail = (etm_id_lst->il_tail + 1) % etm_id_lst->il_max;
	p = s + etm_id_lst->il_tail;
	*p = *id;
	etm_id_lst->il_cnt++;

	return (etm_id_lst->il_tail);
}

/*
 * etm_ckpt_il_delete()
 * Description:
 *     Delete an ereport id from the list.
 */
int
etm_ckpt_il_delete(fmd_hdl_t *hdl, etm_ckpt_erpt_id_t *id) {

	int			i, next;	/* temp counter */
	etm_ckpt_erpt_id_t	*p, *s;		/* temp id pointers */
	etm_ckpt_erpt_id_t	blank;		/* blank id */

	/* empty list */
	if (etm_id_lst->il_tail == etm_id_lst->il_head) {
		fmd_hdl_debug(hdl, "Empty queue(%d)\n", etm_id_lst->il_head);
		return (-1);
	}

	bzero(&blank, sizeof (blank));
	s = (etm_ckpt_erpt_id_t *)((ptrdiff_t)etm_id_lst +
	    sizeof (etm_ckpt_id_list_t));

	/* delete leading empty entries */
	for (i = etm_id_lst->il_head; i != etm_id_lst->il_tail; i = next) {
		next = (i + 1) % etm_id_lst->il_max;
		p = s + next;
		if (!etm_ckpt_il_equal(p, &blank)) {
			break;
		}
		etm_id_lst->il_cnt--;
		etm_id_lst->il_head = next;
	}

	/* empty queue */
	if (etm_id_lst->il_head == etm_id_lst->il_tail) {
		fmd_hdl_debug(hdl, "Empty queue(%d)\n", etm_id_lst->il_head);
		return (-1);
	}

	/* find the entry and clear it */
	for (i = etm_id_lst->il_head; i != etm_id_lst->il_tail; i = next) {
		next = (i + 1) % etm_id_lst->il_max;
		p = s + next;
		if (etm_ckpt_il_equal(p, id)) {
			/* clear the entry */
			*p = blank;
			etm_id_lst->il_cnt--;

			/* remove the entry if it is the last one */
			if (i == etm_id_lst->il_head) {
				etm_id_lst->il_head = next;
			}
			return (i);
		}
	}

	return (-1);
}


/*
 * etm_ckpt_il_restore()
 * Description:
 *     Restore the idlist named buffer which is the circular list of the
 *     the ereport ids.
 */
void
etm_ckpt_il_restore(fmd_hdl_t *hdl)
{
	size_t	size;		/* buffer size */

	/* get the buffer of the id list */
	size = fmd_buf_size(hdl, NULL, ETM_CKPT_IL_BUF);
	if (size < sizeof (etm_ckpt_id_list_t)) {
		fmd_hdl_debug(hdl, "Buffer name %s do not exist\n",
		    ETM_CKPT_IL_BUF);
		return;
	}
	etm_id_lst = (etm_ckpt_id_list_t *)fmd_hdl_zalloc(hdl, size, FMD_SLEEP);
	fmd_buf_read(hdl, NULL, ETM_CKPT_IL_BUF, (void *) etm_id_lst, size);

	/* check version */
	if (etm_id_lst->il_ver > ETM_CKPT_VERSION) {

		fmd_hdl_error(hdl, "Unsupport checkpoint version (%#x)\n",
		    etm_id_lst->il_ver);
		fmd_hdl_free(hdl, (void *) etm_id_lst, size);
		etm_id_lst = NULL;
		return;
	}

	/* check the length */
	if (etm_id_lst->il_ids_sz != (size - sizeof (etm_ckpt_id_list_t))) {
		fmd_hdl_debug(hdl, "Invalid ids buffer size (%d, %d)\n",
		    etm_id_lst->il_ids_sz, size);
		fmd_hdl_free(hdl, (void *) etm_id_lst, size);
		etm_id_lst = NULL;
		return;
	}
}

/*
 * etm_ckpt_recover()
 * Description:
 *    Recover ereports from the checkpointed data and dispatch them to the
 *    ldom queue(s).
 */
void
etm_ckpt_recover(fmd_hdl_t *hdl)
{
	int			size;			/* buffer size */
	int			i, next;		/* temp counter */
	boolean_t		dirty = B_FALSE;	/* dirty flag */
	uint64_t		did;			/* domain id */
	char			name[ETM_LINE_LEN];	/* temp str */
	char			ldom[ETM_LINE_LEN];	/* ldom id */
	etm_ckpt_erpt_id_t	*p, *s;			/* temp ereport id */
	etm_ckpt_erpt_id_t	blank;			/* blank ereport id */
	etm_ckpt_erpt_buf_t	*ep;			/* ereport buffer */
	size_t			sz;			/* size of ep */
	char			*buf;			/* temp buf */
	nvlist_t		*nvl;			/* ereport */
	etm_iosvc_t		*iosvc;			/* iosvc data struct */

	/*
	 * restore the circular list of ereport ids
	 */
	etm_ckpt_il_restore(hdl);
	if (etm_id_lst == NULL) {
		fmd_hdl_debug(hdl, "Initialize a new id list\n");
		size = sizeof (etm_ckpt_id_list_t) +
		    ETM_CKPT_IL_MIN_SIZE * sizeof (etm_ckpt_erpt_id_t);
		etm_id_lst = fmd_hdl_zalloc(hdl, size, FMD_SLEEP);
		etm_id_lst->il_ver = ETM_CKPT_VERSION;
		etm_id_lst->il_max = ETM_CKPT_IL_MIN_SIZE;
		etm_id_lst->il_head = 0;
		etm_id_lst->il_tail = 0;
		etm_id_lst->il_ids_sz =
		    ETM_CKPT_IL_MIN_SIZE * sizeof (etm_ckpt_erpt_id_t);
		fmd_buf_destroy(hdl, NULL, ETM_CKPT_IL_BUF);
		fmd_buf_create(hdl, NULL, ETM_CKPT_IL_BUF, size);
		fmd_buf_write(hdl, NULL, ETM_CKPT_IL_BUF, (void *) etm_id_lst,
		    size);

		/* commit */
		fmd_thr_checkpoint(hdl);

		return;
	}

	/* Empty list */
	if ((etm_id_lst->il_head == etm_id_lst->il_tail) ||
	    (etm_id_lst->il_cnt == 0)) {
		return;
	}

	/* Visit all the entries in the list */
	bzero(&blank, sizeof (blank));
	s = (etm_ckpt_erpt_id_t *)((ptrdiff_t)etm_id_lst +
	    sizeof (etm_ckpt_id_list_t));
	for (i = etm_id_lst->il_head; i != etm_id_lst->il_tail; i = next) {
		next = (i + 1) % etm_id_lst->il_max;
		p = s + next;
		if (etm_ckpt_il_equal(p, &blank)) {
			fmd_hdl_debug(hdl, "Skip empty entry %d\n", i);
			continue;
		}

		etm_ckpt_id2str(p, name, sizeof (name));
		fmd_hdl_debug(hdl, "Restoring entry %s\n", name);
		if ((sz = fmd_buf_size(hdl, NULL, name)) == 0) {
			fmd_hdl_error(hdl, "Clear the stale entry %s\n", name);
			*p = blank;
			continue;
		}
		ep = (etm_ckpt_erpt_buf_t *)fmd_hdl_zalloc(hdl, sz, FMD_SLEEP);
		fmd_buf_read(hdl, NULL, name, (void *) ep, sz);
		buf = (char *)((ptrdiff_t)ep + sizeof (etm_ckpt_erpt_buf_t));
		nvl = NULL;
		if (nvlist_unpack(buf, ep->eb_len, &nvl, 0)) {
			fmd_hdl_debug(hdl, "failed to unpack %s\n", name);
			fmd_hdl_free(hdl, ep, sz);
			continue;
		}
		fmd_hdl_free(hdl, ep, sz);
		if (etm_filter_find_ldom_id(hdl, nvl, ldom, ETM_LINE_LEN,
		    &did) || (strcmp(name, ETM_LDOM_PRIMARY) == 0)) {
			fmd_hdl_debug(hdl, "Discard event %s\n", name);
			fmd_buf_destroy(hdl, NULL, name);
			*p = blank;
			nvlist_free(nvl);
			dirty = B_TRUE;
			continue;
		}

		fmd_hdl_debug(hdl, "Dispatch %s to ldom %s\n", name, ldom);

		/*
		 * Find the queue of the ldom, create it if not exist.
		 * Then insert this event into the queue.
		 */
		iosvc = etm_iosvc_lookup(hdl, ldom, DS_INVALID_HDL, B_TRUE);
		if (iosvc != NULL) {
			(void) etm_pack_ds_msg(hdl, iosvc, NULL, 0, nvl, SP_MSG,
			    ETM_CKPT_RESTORE);
		}
		nvlist_free(nvl);
	}
	if (dirty) {
		/* update the buffer of the queue */
		size = sizeof (etm_ckpt_id_list_t) + etm_id_lst->il_ids_sz;
		fmd_buf_write(hdl, NULL, ETM_CKPT_IL_BUF, (void *) etm_id_lst,
		    size);

		/* commit */
		fmd_thr_checkpoint(hdl);
	}

} /* etm_ckpt_recover */


/*
 * etm_ckpt_add_entry()
 * Description:
 *     Save an ereport for persistence.
 */
int
etm_ckpt_add_entry(fmd_hdl_t *hdl, nvlist_t *erpt) {
	etm_ckpt_erpt_id_t	id;
	char			name[ETM_LINE_LEN];
	int			rc;			/* gen use */
	size_t			sz;			/* size */
	size_t			buflen;			/* sz of packed erpt */
	uint8_t			*buf;			/* buffer of erpt */
	etm_ckpt_erpt_buf_t	*hdr;

	/* map ereport to id */
	bzero(name, ETM_LINE_LEN);
	rc = etm_ckpt_erpt2id(hdl, erpt, &id, name, ETM_LINE_LEN);
	if (rc != 0) {
		fmd_hdl_debug(hdl, "Invalid ereport\n");
		return (rc);
	}

	/*
	 * check for a duplicate entry in the id list
	 * find the ereport buffer and search for the id
	 */
	if (fmd_buf_size(hdl, NULL, name) > 0 &&
	    etm_ckpt_il_find(hdl, &id) >= 0) {
		fmd_hdl_debug(hdl, "Duplicate id %s\n", name);
		return (-1);
	}

	/* Create the ereport buffer */
	if (nvlist_size(erpt, &buflen, NV_ENCODE_XDR) != 0) {
		fmd_hdl_debug(hdl, "nvlist_size fails\n");
		return (-1);
	}
	sz = sizeof (etm_ckpt_erpt_buf_t) + buflen;
	hdr = (etm_ckpt_erpt_buf_t *)fmd_hdl_zalloc(hdl, sz, FMD_SLEEP);
	buf = (uint8_t *)((ptrdiff_t)hdr + sizeof (etm_ckpt_erpt_buf_t));
	hdr->eb_ver = ETM_CKPT_VERSION;
	hdr->eb_len = buflen;
	if (nvlist_pack(erpt, (char **)&buf, &buflen, NV_ENCODE_XDR, 0) != 0) {
		fmd_hdl_free(hdl, hdr, sz);
		fmd_hdl_debug(hdl, "unpack fails\n");
		return (-1);
	}
	fmd_hdl_debug(hdl, "Add ckpt event(%s, %d)\n", name, sz);
	fmd_buf_create(hdl, NULL, name, sz);
	fmd_buf_write(hdl, NULL, name, hdr, sz);
	fmd_hdl_free(hdl, hdr, sz);

	/* Insert the ereport id into the id list */
	if (etm_ckpt_il_add(hdl, &id) < 0) {
		fmd_hdl_debug(hdl, "Insert id %s failed\n", name);
		fmd_buf_destroy(hdl, NULL, name);
		return (-1);
	}

	/* update the buffer of the queue */
	sz = sizeof (etm_ckpt_id_list_t) + etm_id_lst->il_ids_sz;
	fmd_buf_write(hdl, NULL, ETM_CKPT_IL_BUF, (void *) etm_id_lst, sz);

	/* commit */
	fmd_thr_checkpoint(hdl);

	return (0);
}

/*
 * etm_ckpt_delete_entry()
 * Description:
 *     Delete an ereport id in the list.
 */
static int
etm_ckpt_delete_entry(fmd_hdl_t *hdl, nvlist_t *erpt) {
	etm_ckpt_erpt_id_t	id;
	char			name[ETM_LINE_LEN];
	int			rc;			/* return code */
	size_t			sz;			/* size */

	/* get id, id name */
	bzero(name, ETM_LINE_LEN);
	if (etm_ckpt_erpt2id(hdl, erpt, &id, name, ETM_LINE_LEN) != 0) {
		fmd_hdl_debug(hdl, "Invalid ereport\n");
		return (-1);
	}
	fmd_hdl_debug(hdl, "Delete ckpt event(%s)\n", name);

	/* delete the ereport buffer */
	if (fmd_buf_size(hdl, NULL, name) > 0) {
		fmd_buf_destroy(hdl, NULL, name);
	}

	rc = etm_ckpt_il_delete(hdl, &id);
	if (rc < 0) {
		fmd_hdl_debug(hdl, "Delete id %s failed\n", name);
		return (rc);
	}

	/* update the buffer of the queue */
	sz = sizeof (etm_ckpt_id_list_t) + etm_id_lst->il_ids_sz;
	fmd_buf_write(hdl, NULL, ETM_CKPT_IL_BUF, (void *) etm_id_lst, sz);

	/* commit */
	fmd_thr_checkpoint(hdl);

	return (rc);
}

int
etm_ckpt_add(fmd_hdl_t *hdl, nvlist_t *erpt) {

	int		rc;		/* return code */

	(void) pthread_mutex_lock(&etm_id_lst_lock);

	rc = etm_ckpt_add_entry(hdl, erpt);

	(void) pthread_mutex_unlock(&etm_id_lst_lock);

	return (rc >= 0 ? 0 : rc);
}

int
etm_ckpt_delete(fmd_hdl_t *hdl, nvlist_t *erpt) {
	int		rc;		/* return code */

	(void) pthread_mutex_lock(&etm_id_lst_lock);

	rc = etm_ckpt_delete_entry(hdl, erpt);

	(void) pthread_mutex_unlock(&etm_id_lst_lock);

	return (rc >= 0 ? 0 : rc);
}

/* ARGSUSED */
void
etm_ckpt_init(fmd_hdl_t *hdl) {
	(void) pthread_mutex_init(&etm_id_lst_lock, NULL);
	etm_id_lst = NULL;
}

void
etm_ckpt_fini(fmd_hdl_t *hdl) {
	if (etm_id_lst != NULL) {
		fmd_hdl_free(hdl, etm_id_lst,
		    sizeof (etm_ckpt_id_list_t) + etm_id_lst->il_ids_sz);
	}
	(void) pthread_mutex_destroy(&etm_id_lst_lock);
}
