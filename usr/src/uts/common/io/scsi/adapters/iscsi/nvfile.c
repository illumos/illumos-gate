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

#include "iscsi.h"
#include "nvfile.h"
#include <sys/file.h>	    /* defines:	FKIOCTL */
#include <sys/kobj.h>

#define	NVF_GETF	16
static kmutex_t		nvf_getf_lock;
static file_t		*nvf_fd[NVF_GETF];
extern int modrootloaded;

/*
 * file names
 */
#define	NVF_FILENAME		"/etc/iscsi/iscsi"
#define	NVF_CURR_FILE_SUFFIX	"dbc"
#define	NVF_PREV_FILE_SUFFIX	"dbp"
#define	NVF_TMP_FILENAME	"/etc/iscsi/iscsi.dbt"
#define	NVF_MAX_FILENAME_LEN	40

/*
 * file header definitions
 */
#define	NVF_HDR_MAGIC		0x15C510DB		/* iSCSI DB */
#define	NVF_HDR_VERSION		1
#define	NVF_HDR_SIZE		128


/*
 * file flag definitions
 *
 * These flags describe the current state of reading or writing
 * the NVFILE/NVPAIR or the backing file.
 *
 * These flags are derived from a like NVPAIR/NVFILE implementation
 * in usr/src/uts/common/sys/devctl_impl.h
 */
#define	NVF_ACTIVE	0x01	/* nvlist/nvpair file is active */
#define	NVF_DIRTY	0x02	/* needs to be flushed */
#define	NVF_SCHED	0x04	/* flush thread is currently scheduled */
#define	NVF_FLUSHING	0x08	/* in process of being flushed */
#define	NVF_ERROR	0x10	/* most recent flush failed */

#define	NVF_IS_ACTIVE(flag)	(flag & NVF_ACTIVE)
#define	NVF_MARK_ACTIVE(flag)	(flag |= NVF_ACTIVE)
#define	NVF_CLEAR_ACTIVE(flag)	(flag &= ~NVF_ACTIVE)

#define	NVF_IS_DIRTY(flag)	(flag & NVF_DIRTY)
#define	NVF_MARK_DIRTY(flag)	(flag |= NVF_DIRTY)
#define	NVF_CLEAR_DIRTY(flag)	(flag &= ~NVF_DIRTY)

#define	NVF_IS_SCHED(flag)	(flag & NVF_SCHED)
#define	NVF_MARK_SCHED(flag)	(flag |= NVF_SCHED)
#define	NVF_CLEAR_SCHED(flag)	(flag &= ~NVF_SCHED)

/*
 * file flush time constants
 */
#define	NVF_FLUSH_DELAY		10	/* number of ticks before flush */
#define	NVF_RESCHED_MIN_TICKS	5	/* min # of ticks to resched thread */
#define	NVF_FLUSH_BACKOFF_DELAY	(SEC_TO_TICK(300))   /* re-try flush in 5 min */

/*
 * file access operations
 */
static file_t		*nvf_getf(int fdes);
static void		nvf_releasef(int fdes);
static int		nvf_setf(file_t *fp);

static int		nvf_open(char *path, int flags, int mode);
static int		nvf_close(int fdes);
static int		nvf_remove(char *filename);
static int		nvf_rename(char *oldname, char *newname);
static ssize_t		nvf_read(int fdes, void *cbuf, ssize_t count);
static ssize_t		nvf_write(int fdes, void *cbuf, ssize_t count);

int			nvf_errno;

/*
 * file header data structure definition
 *
 * This data structure definition was derived from a like data structure
 * (nvpf_hdr_t) in usr/src/uts/common/sys/devctl_impl.h
 *
 * This header is larger than need in order to support extensability in the
 * future
 *
 */
typedef struct nvf_hdr {
	union {
		struct hdr {
			uint32_t	h_magic;
			int32_t		h_ver;
			int64_t		h_size;
			uint16_t	h_hdrsum;
			uint16_t	h_datasum;
		} h_info;
		uchar_t h_pad[NVF_HDR_SIZE];
	} h_u;
} nvf_hdr_t;

#define	nvfh_magic	h_u.h_info.h_magic
#define	nvfh_ver	h_u.h_info.h_ver
#define	nvfh_size	h_u.h_info.h_size
#define	nvfh_hdrsum	h_u.h_info.h_hdrsum
#define	nvfh_datasum	h_u.h_info.h_datasum


/*
 *  Local Global Variables
 */
static nvlist_t		*nvf_list;		/* pointer to root nvlist */
static uint32_t		nvf_flags;		/* nvfile state flags */
static kmutex_t		nvf_lock;		/* lock	for file */
static krwlock_t	nvf_list_lock;		/* lock for nvlist access */
static timeout_id_t	nvf_thread_id;		/* thread identifier */
static clock_t		nvf_thread_ticks;	/* timeout tick value */
static char		nvf_curr_filename[NVF_MAX_FILENAME_LEN];
static char		nvf_prev_filename[NVF_MAX_FILENAME_LEN];
static boolean_t	nvf_written_once; 	/* File has been written once */
/*
 *  Local Function Prototypes
 */
static uint16_t		nvf_chksum(char *buf, int64_t buflen);
static void		nvf_thread(void *arg);
static boolean_t	nvf_flush(void);
static boolean_t	nvf_parse(char *filename);

/*
 *  NVLIST/NVPAIR FILE External Interfaces
 */

void
nvf_init(void)
{
	mutex_init(&nvf_getf_lock, NULL, MUTEX_DRIVER, NULL);
	nvf_list = NULL;
	nvf_flags = 0;
	NVF_MARK_ACTIVE(nvf_flags);
	nvf_thread_id = 0;
	nvf_thread_ticks = 0;
	nvf_written_once = B_FALSE;
	(void) snprintf(nvf_curr_filename, NVF_MAX_FILENAME_LEN, "%s_v%d.%s",
	    NVF_FILENAME, NVF_HDR_VERSION, NVF_CURR_FILE_SUFFIX);
	(void) snprintf(nvf_prev_filename, NVF_MAX_FILENAME_LEN, "%s_v%d.%s",
	    NVF_FILENAME, NVF_HDR_VERSION, NVF_PREV_FILE_SUFFIX);
	mutex_init(&nvf_lock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&nvf_list_lock, NULL, RW_DRIVER, NULL);
}

void
nvf_fini(void)
{
	mutex_enter(&nvf_lock);
	NVF_CLEAR_ACTIVE(nvf_flags);
	if (NVF_IS_SCHED(nvf_flags)) {
		nvf_thread_ticks = 0;
		mutex_exit(&nvf_lock);
		(void) untimeout(nvf_thread_id);
		mutex_enter(&nvf_lock);
	}

	rw_enter(&nvf_list_lock, RW_WRITER);
	if (nvf_list) {
		nvlist_free(nvf_list);
	}
	nvf_list = NULL;
	rw_exit(&nvf_list_lock);
	mutex_exit(&nvf_lock);

	rw_destroy(&nvf_list_lock);
	mutex_destroy(&nvf_lock);
}

/*
 * nvf_load - load contents of NVLIST/NVPAIR file into memory.
 */
boolean_t
nvf_load(void)
{
	char		corrupt_filename[NVF_MAX_FILENAME_LEN];
	boolean_t	rval;

	mutex_enter(&nvf_lock);

	/*
	 * try to load current file
	 */
	if (!modrootloaded) {
		mutex_exit(&nvf_lock);
		return (B_TRUE);
	} else {
		rval = nvf_parse(nvf_curr_filename);
	}
	if (rval == B_TRUE) {
		mutex_exit(&nvf_lock);
		return (rval);
	} else {
		/*
		 * Rename current file to add corrupted suffix
		 */
		(void) snprintf(corrupt_filename, NVF_MAX_FILENAME_LEN,
		    "%s.corrupt", nvf_curr_filename);
		(void) nvf_rename(nvf_curr_filename, corrupt_filename);
	}

	/*
	 * try to load previous file
	 */
	if (!modrootloaded) {
		mutex_exit(&nvf_lock);
		return (B_TRUE);
	} else {
		rval = nvf_parse(nvf_curr_filename);
	}

	if (rval == B_TRUE) {
		mutex_exit(&nvf_lock);
		return (rval);
	} else {
		/*
		 * Rename previous file to add corrupted suffix
		 */
		(void) snprintf(corrupt_filename, NVF_MAX_FILENAME_LEN,
		    "%s.corrupt", nvf_prev_filename);
		(void) nvf_rename(nvf_prev_filename, corrupt_filename);
	}

	/*
	 * non-existent or corrupted files are OK.  We just create
	 * an empty root nvlist and then write to file when
	 * something added.  However, ensure that any current root nvlist
	 * is deallocated before allocating a new one.
	 */
	rw_enter(&nvf_list_lock, RW_WRITER);
	if (nvf_list != NULL) {
		nvlist_free(nvf_list);
		nvf_list = NULL;
	}
	rw_exit(&nvf_list_lock);

	rval = nvlist_alloc(&nvf_list, NV_UNIQUE_NAME, KM_SLEEP);
	if (rval != 0) {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to "
		    "allocate root list (%d)", rval);
	}

	mutex_exit(&nvf_lock);
	return (rval == 0 ? B_TRUE : B_FALSE);
}

/*
 * nvf_update - start process of updating the NVPAIR/NVLIST file.
 *
 * This function is derived from a like NVPAIR/NVFILE implementation
 * in usr/src/uts/common/os/devctl.c
 *
 */
void
nvf_update(void)
{
	mutex_enter(&nvf_lock);

	/*
	 * set dirty flag to indicate data flush is needed
	 */
	NVF_MARK_DIRTY(nvf_flags);

	/*
	 * If thread is already started just update number of
	 * ticks before flush, otherwise start thread and set
	 * number of ticks.  The thread will is responsible
	 * for starting the actual store to file.
	 *
	 * If update error occured previously, reschedule flush to
	 * occur almost immediately.  If error still exists, the
	 * update thread will be backed off again
	 */
	if (!NVF_IS_SCHED(nvf_flags)) {
		NVF_MARK_SCHED(nvf_flags);
		mutex_exit(&nvf_lock);
		nvf_thread_id = timeout(nvf_thread, NULL, NVF_FLUSH_DELAY);
	} else {
		nvf_thread_ticks = ddi_get_lbolt() + NVF_FLUSH_DELAY;
		/*
		 * If update error occured previously, reschedule flush
		 * attempt to occur quickly.  If an error still exists
		 * after a flush attempt, the update thread will be backed
		 * off again
		 */
		if (nvf_flags & NVF_ERROR) {
			mutex_exit(&nvf_lock);
			(void) untimeout(nvf_thread_id);
			nvf_thread_id = timeout(nvf_thread, NULL,
			    NVF_FLUSH_DELAY);
		} else {
			mutex_exit(&nvf_lock);
		}
	}
}

/*
 * nvf_data_check -- check if specified list exists
 */
boolean_t
nvf_list_check(char *id)
{
	nvlist_t	*list = NULL;
	int		rval;

	/*
	 * find the specified list
	 */
	rw_enter(&nvf_list_lock, RW_READER);
	rval = nvlist_lookup_nvlist(nvf_list, id, &list);
	rw_exit(&nvf_list_lock);

	return (rval == 0 ? B_TRUE : B_FALSE);
}

/*
 * nvf_node_value_set - store value associated with node
 */
boolean_t
nvf_node_value_set(char *id, uint32_t value)
{
	int	rval;

	ASSERT(id != NULL);

	rw_enter(&nvf_list_lock, RW_WRITER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * update value.  If value already exists, it will be replaced
	 * by this update.
	 */
	rval =  nvlist_add_uint32(nvf_list, id, value);
	if (rval == 0) {
		/*
		 * value was set, so update associated file
		 */
		nvf_update();
	} else {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to "
		    "store %s value (%d)", id, rval);
	}

	rw_exit(&nvf_list_lock);
	return (rval == 0 ? B_TRUE : B_FALSE);
}

/*
 * nvf_node_value_get - obtain value associated with node
 */
boolean_t
nvf_node_value_get(char *id, uint32_t *value)
{
	boolean_t	rval;

	ASSERT(id != NULL);
	ASSERT(value != NULL);

	rw_enter(&nvf_list_lock, RW_READER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	rval = nvlist_lookup_uint32(nvf_list, id, value);

	rw_exit(&nvf_list_lock);
	return (rval == 0 ? B_TRUE : B_FALSE);
}

/*
 * nvf_node_name_set - store a specific type of name
 */
boolean_t
nvf_node_name_set(char *id, char *name)
{
	boolean_t	rval = B_TRUE;

	rw_enter(&nvf_list_lock, RW_WRITER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	rval =  nvlist_add_string(nvf_list, id, name);
	if (rval == 0) {
		nvf_update();
	} else {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to "
		    "store %s name (%d)", id, rval);
	}

	rw_exit(&nvf_list_lock);
	return (rval == 0 ? B_TRUE : B_FALSE);
}

/*
 * nvf_node_name_get - return a specific type of name
 */
boolean_t
nvf_node_name_get(char *id, char *name, uint_t nsize)
{
	boolean_t	rval = B_FALSE;
	char		*tmpname;

	rw_enter(&nvf_list_lock, RW_READER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	rval = nvlist_lookup_string(nvf_list, id, &tmpname);
	if (rval == 0) {
		/*
		 *  ensure name is able to fit into given buffer
		 */
		if (strlen(tmpname) < nsize) {
			(void) strcpy(name, tmpname);
			rval = B_TRUE;
		} else {
			cmn_err(CE_NOTE, "!iscsi persistent store "
			    "unable to fit %s node name into buffer %d %s",
			    tmpname, nsize, id);
			rval = B_FALSE;
		}
	} else {
		rval = B_FALSE;
	}

	rw_exit(&nvf_list_lock);
	return (rval);
}

/*
 * nvf_node_data_set -- store data element associated with node
 */
boolean_t
nvf_node_data_set(char *name, void *data, uint_t dsize)
{
	int		rval;

	ASSERT(name != NULL);
	ASSERT(data != NULL);

	rw_enter(&nvf_list_lock, RW_WRITER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * update the address configuration element in the specific
	 * list.  If this element already exists, it will be
	 * replaced by this update.
	 */
	rval = nvlist_add_byte_array(nvf_list, name, (uchar_t *)data, dsize);
	if (rval == 0) {
		/*
		 * data was set, so update associated file
		 */
		nvf_update();
	} else {
		cmn_err(CE_NOTE, "!iscsi persistent store failed "
		    "to store %s name (%d)", name, rval);
	}

	rw_exit(&nvf_list_lock);
	return (rval == 0 ? B_TRUE : B_FALSE);
}

/*
 * nvf_node_data_get -- obtain a data element associated with node
 */
iscsi_nvfile_status_t
nvf_node_data_get(char *name, void *data, uint_t dsize)
{
	uchar_t			*value = NULL;
	uint_t			vsize;
	int			rval = 0;
	iscsi_nvfile_status_t	status = ISCSI_NVFILE_SUCCESS;

	ASSERT(name != NULL);
	ASSERT(data != NULL);

	rw_enter(&nvf_list_lock, RW_READER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (ISCSI_NVFILE_NVF_LIST_NOT_FOUND);
	}

	rval = nvlist_lookup_byte_array(nvf_list, name, &value, &vsize);
	if (rval == 0) {
		/*
		 *  ensure data is able to fit into given buffer
		 */
		if (vsize <= dsize) {
			bcopy(value, data, vsize);
		} else {
			bcopy(value, data, dsize);
		}
		status = ISCSI_NVFILE_SUCCESS;
	} else if (rval == ENOENT) {
		status = ISCSI_NVFILE_NAMEVAL_NOT_FOUND;
	} else {
		status = ISCSI_NVFILE_FAILURE;
	}

	rw_exit(&nvf_list_lock);
	return (status);
}

/*
 * nvf_node_data_clear -- remove a data element associated with node
 */
boolean_t
nvf_node_data_clear(char *name)
{
	int	rval;

	ASSERT(name != NULL);

	rw_enter(&nvf_list_lock, RW_WRITER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * remove the specified data element
	 */
	rval = nvlist_remove(nvf_list, name, DATA_TYPE_BYTE_ARRAY);
	if (rval == 0) {
		/*
		 * data was set, so update associated file
		 */
		nvf_update();
	}

	rw_exit(&nvf_list_lock);
	return (rval == 0 ? B_TRUE : B_FALSE);
}

/*
 * nvf_data_set -- store a data element in the specified list
 */
boolean_t
nvf_data_set(char *id, char *name, void *data, uint_t dsize)
{
	nvlist_t	*list = NULL;
	int		rval;
	boolean_t	list_alloc = B_FALSE;

	ASSERT(id != NULL);
	ASSERT(name != NULL);
	ASSERT(data != NULL);

	rw_enter(&nvf_list_lock, RW_WRITER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * find the specified list
	 */
	rval = nvlist_lookup_nvlist(nvf_list, id, &list);
	if (rval != 0) {
		rval = nvlist_alloc(&list, NV_UNIQUE_NAME, KM_SLEEP);
		if (rval != 0) {
			cmn_err(CE_NOTE, "!iscsi persistent store failed to "
			    "allocate %s list (%d)", id, rval);
			rw_exit(&nvf_list_lock);
			return (B_FALSE);
		}
		list_alloc = B_TRUE;
	}

	/*
	 * update the data element in the specified list.  If this element
	 * already exists, it will be replaced by this update.
	 */
	rval = nvlist_add_byte_array(list, name, (uchar_t *)data, dsize);
	if (rval == 0) {
		rval = nvlist_add_nvlist(nvf_list, id, list);
		if (rval != 0) {
			cmn_err(CE_NOTE, "!iscsi persistent store failed "
			    "to add %s list to root (%d)", id, rval);
			rw_exit(&nvf_list_lock);
			return (B_FALSE);
		}
		/*
		 * data was set, so update file
		 */
		nvf_update();
	} else {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to "
		    "store %s in %s list (%d)", name, id, rval);
	}

	if (list_alloc) {
		nvlist_free(list);
	}

	rw_exit(&nvf_list_lock);
	return (rval == 0 ? B_TRUE : B_FALSE);
}

/*
 * nvf_data_get -- get a data element from the specified list
 */
boolean_t
nvf_data_get(char *id, char *name, void *data, uint_t dsize)
{
	nvlist_t	*list = NULL;
	uchar_t		*value = NULL;
	uint_t		vsize;
	int		rval;

	ASSERT(id != NULL);
	ASSERT(name != NULL);
	ASSERT(data != NULL);

	rw_enter(&nvf_list_lock, RW_READER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * find the specified list
	 */
	rval = nvlist_lookup_nvlist(nvf_list, id, &list);
	if (rval != 0) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/* obtain data element from list */
	ASSERT(list != NULL);
	rval = nvlist_lookup_byte_array(list, name, &value, &vsize);
	if (rval == 0) {
		/*
		 *  ensure data is able to fit into given buffer
		 */
		if (vsize <= dsize) {
			bcopy(value, data, vsize);
		} else {
			bcopy(value, data, dsize);
		}
	}

	rw_exit(&nvf_list_lock);
	return (rval == 0 ? B_TRUE : B_FALSE);
}


/*
 * nvf_data_next -- get the next data element in the specified list
 */
boolean_t
nvf_data_next(char *id, void **v, char *name, void *data, uint_t dsize)
{
	nvlist_t	*list = NULL;
	nvpair_t	*pair = NULL;
	uchar_t		*value = NULL;
	uint_t		vsize;
	int		rval;

	ASSERT(id != NULL);
	ASSERT(v != NULL);
	ASSERT(name != NULL);
	ASSERT(data != NULL);

	rw_enter(&nvf_list_lock, RW_READER);
	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * find the specified list
	 */
	rval = nvlist_lookup_nvlist(nvf_list, id, &list);
	if (rval != 0) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * get the next nvpair data item in the list
	 */
	pair = nvlist_next_nvpair(list, (nvpair_t *)*v);
	*v = (void *)pair;
	if (pair == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * get the data bytes
	 */
	rval = nvpair_value_byte_array(pair, &value, &vsize);
	if (rval != 0) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 *  ensure data is able to fit into given buffer
	 */
	(void) strcpy(name, nvpair_name(pair));
	if (vsize <= dsize) {
		bcopy(value, data, vsize);
	} else {
		bcopy(value, data, dsize);
	}

	rw_exit(&nvf_list_lock);
	return (B_TRUE);
}

/*
 * nvf_data_clear -- remove a data element from the specified list
 */
boolean_t
nvf_data_clear(char *id, char *name)
{
	nvlist_t	*list = NULL;
	int		rval = B_FALSE;

	ASSERT(id != NULL);
	ASSERT(name != NULL);

	rw_enter(&nvf_list_lock, RW_WRITER);

	if (nvf_list == NULL) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * find the specified list
	 */
	rval = nvlist_lookup_nvlist(nvf_list, id, &list);
	if (rval != 0) {
		rw_exit(&nvf_list_lock);
		return (B_FALSE);
	}

	/*
	 * remove the specified data element
	 */
	rval = nvlist_remove(list, name, DATA_TYPE_BYTE_ARRAY);
	if (rval == 0) {
		/*
		 * data was set, so update associated file
		 */
		nvf_update();
	}

	rw_exit(&nvf_list_lock);
	return (rval == 0 ? B_TRUE : B_FALSE);
}

/*
 * +--------------------------------------------------------------------+
 * | Internal Helper Functions                                          |
 * +--------------------------------------------------------------------+
 */

/*
 * nvf_cksum - calculate checksum of given buffer.
 *
 * This function was derived from like function (nvp_cksum) in
 * usr/src/uts/common/os/devctl.c
 */
static uint16_t
nvf_chksum(char *buf, int64_t buflen)
{
	uint16_t cksum = 0;
	uint16_t *p = (uint16_t *)buf;
	int64_t n;

	if ((buflen & 0x01) != 0) {
		buflen--;
		cksum = buf[buflen];
	}
	n = buflen / 2;
	while (n-- > 0)
		cksum ^= *p++;
	return (cksum);
}


/*
 * nvf_thread - determines when writing of NVLIST/NVPAIR data to a file
 * should occur.
 */
/* ARGSUSED */
static void
nvf_thread(void *arg)
{
	clock_t		nticks;
	boolean_t	rval;

	mutex_enter(&nvf_lock);
	nticks = nvf_thread_ticks - ddi_get_lbolt();

	/*
	 * check whether its time to write to file.  If not, reschedule self
	 */
	if ((nticks > NVF_RESCHED_MIN_TICKS) || !modrootloaded) {
		if (NVF_IS_ACTIVE(nvf_flags)) {
			mutex_exit(&nvf_lock);
			nvf_thread_id = timeout(nvf_thread, NULL, nticks);
			mutex_enter(&nvf_lock);
		}
		mutex_exit(&nvf_lock);
		return;
	}

	/*
	 * flush NVLIST/NVPAIR data to file
	 */
	NVF_CLEAR_DIRTY(nvf_flags);
	nvf_flags |= NVF_FLUSHING;
	mutex_exit(&nvf_lock);

	rval = nvf_flush();

	mutex_enter(&nvf_lock);
	nvf_flags &= ~NVF_FLUSHING;
	if (rval == B_FALSE) {
		NVF_MARK_DIRTY(nvf_flags);
		if ((nvf_flags & NVF_ERROR) == 0) {
			if (nvf_written_once) {
				cmn_err(CE_NOTE,
				    "!iscsi persistent store update "
				    "failed file:%s", nvf_curr_filename);
			}
			nvf_flags |= NVF_ERROR;
		}
		nvf_thread_ticks = NVF_FLUSH_BACKOFF_DELAY + ddi_get_lbolt();
	} else if (nvf_flags & NVF_ERROR) {
		cmn_err(CE_NOTE, "!iscsi persistent store update ok now "
		    "filename:%s", nvf_curr_filename);
		nvf_flags &= ~NVF_ERROR;
	}

	/*
	 * re-check whether data is dirty and reschedule if necessary
	 */
	if (NVF_IS_ACTIVE(nvf_flags) && NVF_IS_DIRTY(nvf_flags)) {
		nticks = nvf_thread_ticks - ddi_get_lbolt();
		mutex_exit(&nvf_lock);
		if (nticks > NVF_FLUSH_DELAY) {
			nvf_thread_id = timeout(nvf_thread, NULL, nticks);
		} else {
			nvf_thread_id = timeout(nvf_thread, NULL,
			    NVF_FLUSH_DELAY);
		}
	} else {
		NVF_CLEAR_SCHED(nvf_flags);
		mutex_exit(&nvf_lock);
	}
}

/*
 * nvf_flush - write contents of NVLIST/NVPAIR to a backing file.
 *
 * This function is derived from a like NVPAIR/NVFILE implementation
 * in usr/src/uts/common/os/devctl.c
 */
static boolean_t
nvf_flush(void)
{
	int		rval;
	nvlist_t	*tmpnvl;
	char		*nvfbuf;
	char		*nvlbuf;
	size_t		nvllen;
	size_t		nvflen;
	int		file;
	int		bytes_written;

	/*
	 * duplicate data so access isn't blocked while writing to disk
	 */
	mutex_enter(&nvf_lock);
	rval = nvlist_dup(nvf_list, &tmpnvl, KM_SLEEP);
	if (rval != 0) {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to "
		    "duplicate nvf_list (%d)", rval);
		mutex_exit(&nvf_lock);
		return (B_FALSE);
	}
	mutex_exit(&nvf_lock);

	/*
	 * pack duplicated list to get ready for file write
	 */
	nvlbuf = NULL;
	rval = nvlist_pack(tmpnvl, &nvlbuf, &nvllen, NV_ENCODE_NATIVE, 0);
	if (rval != 0) {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to pack "
		    "nvf_list (%d)", rval);
		nvlist_free(tmpnvl);
		return (B_FALSE);
	}

	/*
	 * allocate buffer to store both the header and the data.
	 */
	nvflen = nvllen + sizeof (nvf_hdr_t);
	nvfbuf = kmem_zalloc(nvflen, KM_SLEEP);

	/*
	 * fill buffer with contents of file header
	 */
	((nvf_hdr_t *)nvfbuf)->nvfh_magic = NVF_HDR_MAGIC;
	((nvf_hdr_t *)nvfbuf)->nvfh_ver = NVF_HDR_VERSION;
	((nvf_hdr_t *)nvfbuf)->nvfh_size = nvllen;
	((nvf_hdr_t *)nvfbuf)->nvfh_datasum = nvf_chksum((char *)nvlbuf,
	    nvllen);
	((nvf_hdr_t *)nvfbuf)->nvfh_hdrsum = nvf_chksum((char *)nvfbuf,
	    sizeof (nvf_hdr_t));

	/*
	 * copy packed nvlist into buffer
	 */
	bcopy(nvlbuf, nvfbuf + sizeof (nvf_hdr_t), nvllen);

	/*
	 * free memory used for packed nvlist
	 */
	nvlist_free(tmpnvl);
	kmem_free(nvlbuf, nvllen);

	/*
	 *  To make it unlikely we suffer data loss, write
	 * data to the new temporary file.  Once successful
	 * complete the transaction by renaming the new file
	 * to replace the previous.
	 */

	/*
	 * remove temporary file to ensure data content is written correctly
	 */
	rval = nvf_remove(NVF_TMP_FILENAME);
	if (rval == -1) {
		kmem_free(nvfbuf, nvflen);
		return (B_FALSE);
	}

	/*
	 * create tempororary file
	 */
	file = nvf_open(NVF_TMP_FILENAME, O_RDWR | O_CREAT, 0600);
	if (file == -1) {
		mutex_enter(&nvf_lock);
		if (nvf_written_once) {
			cmn_err(CE_NOTE,
			    "!iscsi persistent store failed to create "
			    "%s (errno:%d)", NVF_TMP_FILENAME, nvf_errno);
		}
		mutex_exit(&nvf_lock);
		kmem_free(nvfbuf, nvflen);
		return (B_FALSE);
	}

	/*
	 * write data to tempororary file
	 */
	bytes_written = nvf_write(file, nvfbuf, nvflen);
	kmem_free(nvfbuf, nvflen);
	if (bytes_written == -1) {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to write "
		    "%s (errno:%d)", NVF_TMP_FILENAME, nvf_errno);
		return (B_FALSE);
	}

	if (bytes_written != nvflen) {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to write "
		    "%s (errno:%d)\n\tpartial write %d of %ld bytes\n",
		    NVF_TMP_FILENAME, nvf_errno, bytes_written, nvflen);
		return (B_FALSE);
	}

	/*
	 * close tempororary file
	 */
	rval = nvf_close(file);
	if (rval == -1) {
		return (B_FALSE);
	}

	mutex_enter(&nvf_lock);
	/*
	 * File has been written.  Set flag to allow the create and update
	 * messages to be displayed in case of create or update failures.
	 */
	nvf_written_once = B_TRUE;

	/*
	 * rename current original file to previous original file
	 */
	rval = nvf_rename(nvf_curr_filename, nvf_prev_filename);
	if (rval == -1) {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to "
		    "rename %s (errno:%d)", nvf_curr_filename, nvf_errno);
		mutex_exit(&nvf_lock);
		return (B_FALSE);
	}

	/*
	 * rename temporary file to current original file
	 */
	rval = nvf_rename(NVF_TMP_FILENAME, nvf_curr_filename);
	if (rval == -1) {
		cmn_err(CE_NOTE, "!iscsi persistent store failed to "
		    "rename %s (errno:%d)", NVF_TMP_FILENAME, nvf_errno);
		mutex_exit(&nvf_lock);
		return (B_FALSE);
	}

	NVF_CLEAR_DIRTY(nvf_flags);

	mutex_exit(&nvf_lock);
	return (B_TRUE);
}

/*
 * nvf_parse - read contents of NVLIST/NVPAIR file.
 *
 * This function is derived from a like NVPAIR/NVFILE implementation
 * in usr/src/uts/common/os/devctl.c
 */
static boolean_t
nvf_parse(char *filename)
{
	int		file;
	nvf_hdr_t	hdr;
	int		bytes_read;
	int		rval;
	uint16_t	chksum;
	uint16_t	hdrsum;
	char		*buf;
	char		overfill;
	nvlist_t	*nvl;
	nvlist_t	*old_nvl;


	/*
	 * open current file
	 */
	file = nvf_open(filename, O_RDONLY, 0600);
	if (file == -1) {
		return (B_FALSE);
	}

	/*
	 * read file header
	 */
	bytes_read = nvf_read(file, (char *)&hdr, sizeof (hdr));
	if (bytes_read != sizeof (hdr)) {
		(void) nvf_close(file);
		return (B_FALSE);
	}

	/*
	 * calculate checksum over file header bytes
	 */
	chksum = hdr.nvfh_hdrsum;
	hdr.nvfh_hdrsum = 0;
	hdrsum = nvf_chksum((char *)&hdr, sizeof (hdr));

	/*
	 * validate file header is as expected
	 */
	if ((hdr.nvfh_magic != NVF_HDR_MAGIC) ||
	    (hdr.nvfh_ver != NVF_HDR_VERSION) ||
	    (hdrsum != chksum)) {
		(void) nvf_close(file);
		if (hdrsum != chksum) {
			cmn_err(CE_NOTE, "!iscsi persistent store "
			    "checksum error %s actual:0x%x expected:0x%x",
			    filename, hdrsum, chksum);
		}
		cmn_err(CE_NOTE, "!iscsi persistent store %s has an "
		    "incorrect header", filename);
		return (B_FALSE);
	}

	ASSERT(hdr.nvfh_size >= 0);

	/*
	 * read expected remaining content of file
	 */
	buf = kmem_alloc(hdr.nvfh_size, KM_SLEEP);
	bytes_read = nvf_read(file, buf, hdr.nvfh_size);
	if (bytes_read != hdr.nvfh_size) {
		kmem_free(buf, hdr.nvfh_size);
		(void) nvf_close(file);
		if (bytes_read < 0) {
			cmn_err(CE_NOTE, "!iscsi persistent store failed "
			    "to read %s bytes:%d", filename, bytes_read);
		} else {
			cmn_err(CE_NOTE, "!iscsi persistent store incomplete "
			    "read %s bytes:%d/%lld", filename,
			    bytes_read, (longlong_t)hdr.nvfh_size);
		}
		return (B_FALSE);
	}

	/*
	 * check whether file has anymore data.  If so this is an error
	 */
	bytes_read = nvf_read(file, &overfill, 1);
	(void) nvf_close(file);
	if (bytes_read > 0) {
		kmem_free(buf, hdr.nvfh_size);
		cmn_err(CE_NOTE, "!iscsi persistent store file is larger "
		    "than expected %s bytes:%lld",
		    filename, (longlong_t)hdr.nvfh_size);
		return (B_FALSE);
	}

	DTRACE_PROBE1(hdr, nvf_hdr_t *, &hdr);

	/*
	 * validate file data is as expected
	 */
	chksum = nvf_chksum(buf, hdr.nvfh_size);
	if (hdr.nvfh_datasum != chksum) {
		kmem_free(buf, hdr.nvfh_size);
		cmn_err(CE_NOTE, "!iscsi persistent store checksum error %s "
		    "actual:0x%x expected:0x%x", filename,
		    hdr.nvfh_datasum, chksum);
		return (B_FALSE);
	}

	nvl = NULL;
	rval = nvlist_unpack(buf, hdr.nvfh_size, &nvl, 0);
	if (rval != 0) {
		kmem_free(buf, hdr.nvfh_size);
		cmn_err(CE_NOTE, "!iscsi persistent store failed unpacking "
		    "nvlist %s (%d)", filename, rval);
		return (B_FALSE);
	}

	kmem_free(buf, hdr.nvfh_size);

	/*
	 * activate nvlist
	 */
	rw_enter(&nvf_list_lock, RW_WRITER);
	old_nvl = nvf_list;
	nvf_list = nvl;
	rw_exit(&nvf_list_lock);

	/*
	 * free up old nvlist
	 */
	if (old_nvl) {
		nvlist_free(old_nvl);
	}

	return (B_TRUE);
}

/*
 * iscsid_getf -- given a file descriptor returns a file pointer
 */
static file_t *
nvf_getf(int fdes)
{
	file_t	*fp = NULL;

	mutex_enter(&nvf_getf_lock);
	if ((fdes >= 0) && (fdes < NVF_GETF)) {
		fp = nvf_fd[fdes];
		if (fp != NULL)
			mutex_enter(&fp->f_tlock);
	}
	mutex_exit(&nvf_getf_lock);

	return (fp);
}

/*
 * nvf_releasef -- release lock on file pointer
 */
static void
nvf_releasef(int fdes)
{
	file_t  *fp;

	mutex_enter(&nvf_getf_lock);
	if ((fdes >= 0) && (fdes < NVF_GETF)) {
		fp = nvf_fd[fdes];
		mutex_exit(&fp->f_tlock);
	}
	mutex_exit(&nvf_getf_lock);
}

/*
 * nvf_setf -- stores the file pointer in an empty slot returning index
 */
static int
nvf_setf(file_t *fp)
{
	int	i = -1;

	mutex_enter(&nvf_getf_lock);
	for (i = 0; i < NVF_GETF; i++) {
		if (nvf_fd[i] == 0) {
			nvf_fd[i] = fp;
			break;
		}
	}
	mutex_exit(&nvf_getf_lock);
	return (i);
}

/*
 * nvf_freef -- gets the file pointer based on index and releases memory.
 */
static void
nvf_freef(int fdes)
{
	file_t *fp;

	mutex_enter(&nvf_getf_lock);
	if ((fdes >= 0) && (fdes < NVF_GETF)) {
		fp = nvf_fd[fdes];
		unfalloc(fp);
		nvf_fd[fdes] = NULL;
	}
	mutex_exit(&nvf_getf_lock);
}

/*
 * nvf_open -- acts like syscall open, but works for kernel
 *
 * Note: This works for regular files only. No umask is provided to
 * vn_open which means whatever mode is passed in will be used to
 * create a file.
 */
static int
nvf_open(char *path, int flags, int mode)
{
	file_t		*fp	= NULL;
	vnode_t		*vp	= NULL;
	int		fdes	= -1;
	int		fflags;

	/*
	 * Need to convert from user mode flags to file system flags.
	 * It's unfortunate that the kernel doesn't define a mask for
	 * the read/write bits which would make this conversion easier.
	 * Only O_RDONLY/O_WRONLY/O_RDWR are different than their FXXXXX
	 * counterparts. If one was provided something like
	 *	fflags = ((flags & mask) + 1) | (flags & ~mask)
	 * would work. But, that would only be true if the relationship
	 * be O_XXX and FXXX was defined and it's not. So we have the
	 * following.
	 */
	if (flags & O_WRONLY)
		fflags = FWRITE;
	else if (flags & O_RDWR)
		fflags = FWRITE | FREAD;
	else
		fflags = FREAD;

	/*
	 * Now that fflags has been initialized with the read/write bits
	 * look at the other flags and OR them in.
	 */
	if (flags & O_CREAT)
		fflags |= FCREAT;
	if (flags & O_TRUNC)
		fflags |= FTRUNC;

	if (nvf_errno = vn_open(path, UIO_SYSSPACE, fflags,
	    mode & MODEMASK, &vp, CRCREAT, 0)) {
		return (-1);
	}

	if (falloc(vp, fflags, &fp, NULL) != 0) {
		VN_RELE(vp);
		return (-1);
	}
	/* ---- falloc returns with f_tlock held on success ---- */
	mutex_exit(&fp->f_tlock);

	if ((fdes = nvf_setf(fp)) == -1) {
		VN_RELE(vp);
	}
	return (fdes);
}

/*
 * nvf_close -- closes down the file by releasing locks and memory.
 */
static int
nvf_close(int fdes)
{
	file_t  *fp;
	vnode_t *vp;

	if ((fp = nvf_getf(fdes)) == NULL)
		return (-1);
	vp = fp->f_vnode;

	(void) VOP_CLOSE(vp, fp->f_flag, 1, 0, kcred, NULL);
	VN_RELE(vp);
	/*
	 * unfalloc which is called from here will do a mutex_exit
	 * on t_lock in the fp. So don't call nvf_releasef() here.
	 */
	nvf_freef(fdes);

	return (0);
}

/*
 * nvf_remove -- remove file from filesystem
 */
static int
nvf_remove(char *filename)
{
	return (vn_remove(filename, UIO_SYSSPACE, RMFILE));
}

/*
 * nvf_rename -- rename file from one name to another
 */
static int
nvf_rename(char *oldname, char *newname)
{
	return (vn_rename(oldname, newname, UIO_SYSSPACE));
}

/*
 * nvf_rw -- common read/write code. Very simplistic.
 */
static ssize_t
nvf_rw(int fdes, void *cbuf, ssize_t count, enum uio_rw rw)
{
	file_t	*fp;
	vnode_t	*vp;
	ssize_t	resid   = 0;

	if ((fp  = nvf_getf(fdes)) == NULL)
		return (-1);
	vp = fp->f_vnode;

	if (nvf_errno = vn_rdwr(rw, vp, (caddr_t)cbuf, count, fp->f_offset,
	    UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid)) {
		nvf_releasef(fdes);
		return (-1);
	}

	if ((count - resid) > 0)
		fp->f_offset += count;

	nvf_releasef(fdes);
	return (count - resid);
}

/*
 * nvf_write -- kernel write function
 */
static ssize_t
nvf_write(int fdes, void *cbuf, ssize_t count)
{
	return (nvf_rw(fdes, cbuf, count, UIO_WRITE));
}

/*
 * nvf_read -- kernel read function
 */
static ssize_t
nvf_read(int fdes, void *cbuf, ssize_t count)
{
	return (nvf_rw(fdes, cbuf, count, UIO_READ));
}
