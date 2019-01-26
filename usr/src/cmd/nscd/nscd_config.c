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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>		/* gettext */
#include <dlfcn.h>
#include <string.h>
#include <sys/varargs.h>
#include <errno.h>
#include "nscd_db.h"
#include "nscd_config.h"
#include "nscd_cfgdef.h"
#include "nscd_log.h"

typedef struct {
	rwlock_t	*global;
	rwlock_t	*alldb;
	rwlock_t	*nswdb;
} nscd_cfg_lock_t;

static rwlock_t		cfg_paramDB_rwlock = DEFAULTRWLOCK;
static nscd_db_t	*cfg_paramDB = NULL;

static	nscd_cfg_global_data_t	*nscd_cfg_global_current;
static	nscd_cfg_nsw_db_data_t	*nscd_cfg_nsw_db_data_current;
static	nscd_cfg_nsw_db_data_t	*nscd_cfg_nsw_alldb_current;
static	rwlock_t		*nscd_cfg_global_rwlock;
static	rwlock_t		*nscd_cfg_nsw_db_data_rwlock;
static	rwlock_t		*nscd_cfg_nsw_alldb_rwlock;

extern	int			_nscd_cfg_num_nsw_src_all;
extern	nscd_cfg_id_t		*_nscd_cfg_nsw_src_all;

nscd_cfg_error_t *
_nscd_cfg_make_error(
	nscd_rc_t	rc,
	char		*msg)
{

	nscd_cfg_error_t	*ret;
	int			size, msglen;

	msglen = (msg != NULL ? strlen(msg) + 1 : 0);

	size = sizeof (nscd_cfg_error_t) + msglen;

	ret = calloc(1, size);
	if (ret == NULL)
		return (NULL);

	ret->rc = rc;
	if (msg != NULL) {
		ret->msg = (char *)ret +
		    sizeof (nscd_cfg_error_t);
		(void) memcpy(ret->msg, msg, msglen);
	}

	return (ret);
}

static nscd_rc_t
_nscd_cfg_get_list(
	nscd_cfg_list_t		**list,
	nscd_cfg_list_type_t	type)
{
	char			*me = "_nscd_cfg_get_list";
	int			i, num, size;
	nscd_cfg_id_t		*l;
	nscd_cfg_list_t		*ret;
	nscd_cfg_param_desc_t	*pl;
	nscd_cfg_stat_desc_t	*sl;
	void			*p;

	if (list == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "invalid argument: list = %p\n", list);

		return (NSCD_INVALID_ARGUMENT);
	}
	*list = NULL;

	switch (type) {
	case NSCD_CFG_LIST_NSW_DB:

		num = _nscd_cfg_num_nsw_db;
		l = &_nscd_cfg_nsw_db[0];
		break;

	case NSCD_CFG_LIST_NSW_SRC:

		num = _nscd_cfg_num_nsw_src_all;
		l = _nscd_cfg_nsw_src_all;
		break;

	case NSCD_CFG_LIST_PARAM:

		num = _nscd_cfg_num_param;
		pl = &_nscd_cfg_param_desc[0];
		break;

	case NSCD_CFG_LIST_STAT:

		num = _nscd_cfg_num_stat;
		sl = &_nscd_cfg_stat_desc[0];
		break;

	default:
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "invalid argument: type (%d)\n", type);

		return (NSCD_INVALID_ARGUMENT);
	}

	size =  sizeof (nscd_cfg_list_t) + sizeof (nscd_cfg_id_t *) * (num + 1);

	ret = calloc(1, size);
	if (ret == NULL)
		return (NSCD_NO_MEMORY);

	ret->num = num;
	p = (char *)ret + sizeof (nscd_cfg_list_t);
	ret->list = (nscd_cfg_id_t **)p;

	if (type == NSCD_CFG_LIST_PARAM) {
		for (i = 0; i <= num; i++)
			ret->list[i] = (nscd_cfg_id_t *)&pl[i];
	} else if (type == NSCD_CFG_LIST_STAT) {
		for (i = 0; i <= num; i++)
			ret->list[i] = (nscd_cfg_id_t *)&sl[i];
	} else {
		for (i = 0; i <= num; i++)
			ret->list[i] = &l[i];
	}

	*list = ret;

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_cfg_get_param_desc_list(
	nscd_cfg_param_desc_list_t **list)
{
	return (_nscd_cfg_get_list((nscd_cfg_list_t **)list,
	    NSCD_CFG_LIST_PARAM));
}

/*
 * FUNCTION: _nscd_cfg_create_paramDB
 *
 * Create the internal config parameter database
 */
static nscd_db_t *
_nscd_cfg_create_paramDB()
{

	nscd_db_t	*ret;

	(void) rw_wrlock(&cfg_paramDB_rwlock);

	ret = _nscd_alloc_db(NSCD_DB_SIZE_MEDIUM);

	if (ret != NULL)
		cfg_paramDB = ret;

	(void) rw_unlock(&cfg_paramDB_rwlock);

	return (ret);
}

/*
 * FUNCTION: _nscd_cfg_add_index_entry
 *
 * Add a config index entry (a name to index mapping)
 * to the internal configuration database.
 */
static nscd_rc_t
_nscd_cfg_add_index_entry(
	char			*name,
	int			index,
	nscd_cfg_list_type_t	type)
{
	int		*idx;
	int		size;
	int		dbe_type;
	nscd_db_entry_t	*db_entry;

	if (name == NULL)
		return (NSCD_INVALID_ARGUMENT);

	if (type == NSCD_CFG_LIST_NSW_DB)
		dbe_type = NSCD_DATA_CFG_NSW_DB_INDEX;
	else if (type == NSCD_CFG_LIST_NSW_SRC)
		dbe_type = NSCD_DATA_CFG_NSW_SRC_INDEX;
	else if (type == NSCD_CFG_LIST_PARAM)
		dbe_type = NSCD_DATA_CFG_PARAM_INDEX;
	else if (type == NSCD_CFG_LIST_STAT)
		dbe_type = NSCD_DATA_CFG_STAT_INDEX;

	size = sizeof (int);

	db_entry = _nscd_alloc_db_entry(dbe_type, (const char *)name,
	    size, 1, 1);
	if (db_entry == NULL)
		return (NSCD_NO_MEMORY);

	idx = (int *)*(db_entry->data_array);
	*idx = index;

	(void) rw_wrlock(&cfg_paramDB_rwlock);
	(void) _nscd_add_db_entry(cfg_paramDB, name, db_entry,
	    NSCD_ADD_DB_ENTRY_FIRST);
	(void) rw_unlock(&cfg_paramDB_rwlock);

	return (NSCD_SUCCESS);
}

/*
 * FUNCTION: _nscd_cfg_get_index
 *
 * Get the index of a config data item by searching the internal config
 * database. Do not free the returned data.
 */
static int
_nscd_cfg_get_index(
	char			*name,
	nscd_cfg_list_type_t	type)
{
	int			index = -1, dbe_type;
	const nscd_db_entry_t	*db_entry;

	if (name == NULL)
		return (-1);

	if (type == NSCD_CFG_LIST_NSW_DB)
		dbe_type = NSCD_DATA_CFG_NSW_DB_INDEX;
	else if (type == NSCD_CFG_LIST_NSW_SRC)
		dbe_type = NSCD_DATA_CFG_NSW_SRC_INDEX;
	else if (type == NSCD_CFG_LIST_PARAM)
		dbe_type = NSCD_DATA_CFG_PARAM_INDEX;
	else if (type == NSCD_CFG_LIST_STAT)
		dbe_type = NSCD_DATA_CFG_STAT_INDEX;
	else
		return (-1);

	db_entry = _nscd_get_db_entry(cfg_paramDB, dbe_type,
	    (const char *)name, NSCD_GET_FIRST_DB_ENTRY, 0);

	if (db_entry != NULL)
		index = *(int *)*(db_entry->data_array);

	return (index);
}

static nscd_rc_t
_nscd_cfg_verify_group_info(
	nscd_cfg_group_info_t	*g_info,
	nscd_cfg_param_desc_t	*gdesc)
{

	char			*me = "_nscd_cfg_verify_group_info";
	void			*vp;
	nscd_cfg_group_info_t	*gi;

	if (_nscd_cfg_flag_is_set(gdesc->pflag, NSCD_CFG_PFLAG_GLOBAL)) {
		vp = (char *)&nscd_cfg_global_default +
		    gdesc->g_offset;
		gi = (nscd_cfg_group_info_t *)vp;
	} else {
		vp = (char *)&nscd_cfg_nsw_db_data_default +
		    gdesc->g_offset;
		gi = (nscd_cfg_group_info_t *)vp;

	}

	if (g_info->num_param == gi->num_param &&
	    _nscd_cfg_bitmap_is_equal(g_info->bitmap, gi->bitmap))
		return (NSCD_SUCCESS);

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
	(me, "ERROR: group (%s) info mismatched: group info "
	    "(%d, %#6.4x) not equal to that of default configuration data "
	    "(%d, %#6.4x)\n", gdesc->id.name, g_info->num_param,
	    _nscd_cfg_bitmap_value(g_info->bitmap), gi->num_param,
	    _nscd_cfg_bitmap_value(gi->bitmap));

	return (NSCD_CFG_PARAM_DESC_ERROR);

}


static nscd_rc_t
_nscd_cfg_init_nsw()
{
	char			*me = "_nscd_cfg_init_nsw";
	int			i, j, idx, rc, num;
	nscd_cfg_id_t		*id;
	nscd_cfg_list_type_t	type[2] = { NSCD_CFG_LIST_NSW_DB,
					NSCD_CFG_LIST_NSW_SRC };

	nscd_cfg_id_t		*list[2] = { _nscd_cfg_nsw_db, NULL};

	list[1] = _nscd_cfg_nsw_src_all;

	for (j = 0; j < 2; j++) {

		if (j == 0)
			num = _nscd_cfg_num_nsw_db + 1;
		else
			num = _nscd_cfg_num_nsw_src_all;

		for (i = 0; i < num; i++) {

			/*
			 * _nscd_cfg_nsw_alldb is the id for the
			 * special ALLDB (defaults for all db)
			 */
			if (j == 0 && i == _nscd_cfg_num_nsw_db) {
				id = &_nscd_cfg_nsw_alldb;
				idx = NSCD_CFG_NSW_ALLDB_INDEX;
			} else {
				id = &(list[j])[i];
				id->index = idx = i;
			}

			if (id->name == NULL)
				continue;

			if ((rc = _nscd_cfg_add_index_entry(id->name,
			    idx, type[j])) != NSCD_SUCCESS) {

				_NSCD_LOG(NSCD_LOG_CONFIG,
				    NSCD_LOG_LEVEL_ERROR)
				(me, "unable to add index entry for "
				"nsswitch entry %s\n", id->name);

				_nscd_free_db(cfg_paramDB);
				return (rc);
			}
		}
	}

	return (NSCD_SUCCESS);
}

static nscd_rc_t
_nscd_cfg_init_param()
{
	char			*me = "_nscd_cfg_init_param";
	int			i, gi, fn = 0;
	nscd_cfg_id_t		*id;
	nscd_cfg_param_desc_t	*desc, *gdesc = NULL;
	nscd_cfg_group_info_t	g_info;
	nscd_cfg_list_type_t	type = NSCD_CFG_LIST_PARAM;
	nscd_rc_t		rc;
	void			*nfunc, *vfunc;

	if (_nscd_cfg_create_paramDB() == NULL)
		return (NSCD_NO_MEMORY);

	desc = &_nscd_cfg_param_desc[0];

	/*
	 * need to loop to the last (+1) param description
	 * which is a fake group and which marks the end
	 * of list. It is used to signal the end of the
	 * previous group so that the proper data will be
	 * set for that group
	 */
	for (i = 0; i < _nscd_cfg_num_param + 1; i++, desc++) {

		id = (nscd_cfg_id_t *)desc;

		if (_nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_GROUP)) {

			if (gdesc != NULL) {
				g_info.num_param = fn;
				gdesc->p_fn = fn;

				if ((rc = _nscd_cfg_verify_group_info(
				    &g_info, gdesc)) != NSCD_SUCCESS)
					return (rc);
			}

			gi = i;
			fn = 0;
			gdesc = desc;
			g_info.bitmap = NSCD_CFG_BITMAP_ZERO;

			/*
			 * set the notify/verify functions
			 */
			nfunc = (void *)gdesc->notify;
			vfunc = (void *)gdesc->verify;
		} else {
			if (i == 0) {

				_NSCD_LOG(NSCD_LOG_CONFIG,
				    NSCD_LOG_LEVEL_ERROR)
				(me, "ERROR: first parameter "
				"description is not for a group\n");

				return (NSCD_CFG_PARAM_DESC_ERROR);
			}

			/*
			 * set bitmap: the rightmost bit represents
			 * the first member (index = 0) in the group,
			 * the next bit is for the second member
			 * (index = 1), and so on
			 */
			_nscd_cfg_bitmap_set_nth(g_info.bitmap, fn);

			desc->p_fn = fn++;

			/*
			 * set the notify/verify functions
			 */
			if (desc->notify == NSCD_CFG_FUNC_NOTIFY_AS_GROUP) {
				(void) memcpy(&desc->notify, &nfunc,
				    sizeof (void *));
			}
			if (desc->verify == NSCD_CFG_FUNC_VERIFY_AS_GROUP) {
				(void) memcpy(&desc->verify, &vfunc,
				    sizeof (void *));
			}
		}

		/* if end of list reached, we are done */
		if (i == _nscd_cfg_num_param)
			break;

		desc->g_index = gi;

		id->index = i;

		if ((rc = _nscd_cfg_add_index_entry(id->name,
		    i, type)) != NSCD_SUCCESS) {

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to add index entry for parameter "
			"%s\n", id->name);

			_nscd_free_db(cfg_paramDB);
			return (rc);
		} else {
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
			(me, "index entry for parameter "
			"%s added\n", id->name);
		}
	}

	return (_nscd_cfg_init_nsw());
}

static nscd_rc_t
_nscd_cfg_init_stat()
{
	char			*me = "_nscd_cfg_init_stat";
	int			i, gi, fn = 0;
	nscd_cfg_id_t		*id;
	nscd_cfg_stat_desc_t	*desc, *gdesc = NULL;
	nscd_cfg_group_info_t	g_info;
	nscd_cfg_list_type_t	type = NSCD_CFG_LIST_STAT;
	nscd_rc_t		rc;
	void			*gsfunc;

	desc = &_nscd_cfg_stat_desc[0];

	/*
	 * need to loop to the last (+1) stat description
	 * which is a fake group and which marks the end
	 * of list. It is used to signal the end of the
	 * previous group so that the proper data will be
	 * set for that group
	 */
	for (i = 0; i < _nscd_cfg_num_stat + 1; i++, desc++) {

		id = (nscd_cfg_id_t *)desc;

		if (_nscd_cfg_flag_is_set(desc->sflag,
		    NSCD_CFG_SFLAG_GROUP)) {

			if (gdesc != NULL) {
				g_info.num_param = fn;
				gdesc->s_fn = fn;

				if (g_info.num_param !=
				    gdesc->gi.num_param ||
				    !_nscd_cfg_bitmap_is_equal(
				    g_info.bitmap, gdesc->gi.bitmap)) {

					_NSCD_LOG(NSCD_LOG_CONFIG,
					    NSCD_LOG_LEVEL_ERROR)
					(me, "ERROR: group (%s) "
					    "info mismatched: "
					    "group info (%d, %#6.4x) not "
					    "equal to the predefined one "
					    "(%d, %#6.4x)\n", gdesc->id.name,
					    g_info.num_param,
					    _nscd_cfg_bitmap_value(
					    g_info.bitmap),
					    gdesc->gi.num_param,
					    _nscd_cfg_bitmap_value(
					    gdesc->gi.bitmap));

					exit(1);
					return (NSCD_CFG_STAT_DESC_ERROR);
				}
			}

			gi = i;
			fn = 0;
			gdesc = desc;
			g_info.bitmap = NSCD_CFG_BITMAP_ZERO;

			/*
			 * set the get_stat function
			 */
			gsfunc = (void *)gdesc->get_stat;
		} else {
			if (i == 0) {

				_NSCD_LOG(NSCD_LOG_CONFIG,
				    NSCD_LOG_LEVEL_ERROR)
				(me, "ERROR: first stat "
				    "description is not for a group\n");

				return (NSCD_CFG_STAT_DESC_ERROR);
			}

			/*
			 * set bitmap: the rightmost bit represents
			 * the first member (index = 0) in the group,
			 * the next bit is for the second member
			 * (index = 1), and so on
			 */
			_nscd_cfg_bitmap_set_nth(g_info.bitmap, fn);

			desc->s_fn = fn++;

			/*
			 * set the get_stat function
			 */
			if (desc->get_stat == NSCD_CFG_FUNC_GET_STAT_AS_GROUP) {
				(void) memcpy(&desc->get_stat, &gsfunc,
				    sizeof (void *));
			}
		}

		/* if end of list reached, we are done */
		if (i == _nscd_cfg_num_stat)
			break;

		desc->g_index = gi;

		id->index = i;

		if ((rc = _nscd_cfg_add_index_entry(id->name,
		    i, type)) != NSCD_SUCCESS) {

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to add index entry for stat "
			"description %s\n", id->name);

			_nscd_free_db(cfg_paramDB);
			return (rc);
		} else {
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
			(me, "index entry for stat description "
			"%s added\n", id->name);
		}
	}

	return (NSCD_SUCCESS);
}

static nscd_rc_t
_nscd_cfg_copy_vlen_data(
	void			*data,
	void			**new_data_p,
	nscd_cfg_param_desc_t	*desc,
	int			*data_len,
	nscd_bool_t		in)
{
	int			len, dlen;
	nscd_cfg_vlen_data_t	*v = NULL;

	*new_data_p = NULL;
	*data_len = 0;

	/* it is OK if there is nothing to copy */
	if (data == NULL)
		return (NSCD_SUCCESS);

	/*
	 * if copy to the config store we need to allocate space
	 * for the extra vlen header
	 */
	if (desc->type == NSCD_CFG_DATA_STRING) {
		len = dlen = strlen((char *)data) + 1;
		if (in == nscd_true)
			len += sizeof (nscd_cfg_vlen_data_t);
	} else {
		/*
		 * should not be here, since for now
		 * only string variable length data
		 * is supported
		 */
		*new_data_p = NULL;
		return (NSCD_CFG_PARAM_DESC_ERROR);
	}

	v = calloc(1, len);
	if (v == NULL) {
		*new_data_p = NULL;
		return (NSCD_NO_MEMORY);
	}

	/*
	 * if copy to the config store, set up
	 * the extra vlen header in which the
	 * pointer to, and length of, the real
	 * data are kept. The pointer to the real
	 * data, not the vlen header, is returned.
	 */
	if (in == nscd_true) {
		v->ptr = (char *)v + sizeof (nscd_cfg_vlen_data_t);
		v->len = dlen;
		(void) memcpy(v->ptr, data, dlen);
		*new_data_p = v->ptr;
	} else {
		(void) memcpy(v, data, dlen);
		*new_data_p = v;
	}
	*data_len = dlen;

	return (NSCD_SUCCESS);
}

static void
_nscd_cfg_free_vlen_data_int(
	void	*data)
{
	nscd_cfg_vlen_data_t	*v = NULL;
	void			*p;

	if (data == NULL)
		return;

	p = (char *)data - sizeof (nscd_cfg_vlen_data_t);
	v = (nscd_cfg_vlen_data_t *)p;
	if (v->ptr == data)
		free(v);
}

static nscd_rc_t
_nscd_cfg_set_vlen_data_int(
	void		*src,
	void		*dest,
	nscd_bool_t	global)
{
	int			i, offset, dlen = 0;
	void			*s, *d, *new;
	void			*cptr;
	nscd_rc_t		rc;
	nscd_cfg_param_desc_t	*desc;

	desc = &_nscd_cfg_param_desc[0];
	for (i = 0; i < _nscd_cfg_num_param; i++, desc++) {

		if (global == nscd_true &&
		    _nscd_cfg_flag_is_not_set(desc->pflag,
		    NSCD_CFG_PFLAG_GLOBAL))
			continue;
		else if (global != nscd_true &&
		    _nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_GLOBAL))
			continue;

		if (_nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_VLEN_DATA)) {

			offset = desc->g_offset + desc->p_offset;

			s = (char *)src + offset;
			cptr = *(char **)s;

			rc = _nscd_cfg_copy_vlen_data(cptr, &new,
			    desc, &dlen, nscd_true);
			if (rc != NSCD_SUCCESS)
				return (rc);

			d = (char *)dest + offset;
			/* free the old vlen data */
			if (*(char **)d == NULL)
				_nscd_cfg_free_vlen_data_int(*(char **)d);

			*(char **)d = new;
		}
	}

	return (NSCD_SUCCESS);
}

static void *
_nscd_cfg_locate_vlen_data(
	void	*cfg_data,
	int	*len)
{
	void	*ptr, *ret;

	ptr = *(char **)cfg_data;
	ret = ptr;
	if (ret == NULL) {
		*len = 0;
		return (NULL);
	}
	ptr = (char *)ptr - sizeof (nscd_cfg_vlen_data_t);
	*len = ((nscd_cfg_vlen_data_t *)ptr)->len;

	return (ret);
}

static void
_nscd_cfg_lock(
	nscd_bool_t	is_read,
	nscd_cfg_lock_t	*cfglock)
{

	int	(*lockfunc)(rwlock_t *);

	if (cfglock == NULL)
		return;

	if (is_read == nscd_true)
		lockfunc = rw_rdlock;
	else
		lockfunc = rw_wrlock;

	if (cfglock->global != NULL) {

		(lockfunc)(cfglock->global);
		return;
	}

	if (cfglock->alldb != NULL)
		(lockfunc)(cfglock->alldb);

	if (cfglock->nswdb != NULL)
		(lockfunc)(cfglock->nswdb);
}

static void
_nscd_cfg_unlock(
	nscd_cfg_lock_t	*cfglock)
{
	if (cfglock == NULL)
		return;

	if (cfglock->global != NULL) {

		(void) rw_unlock(cfglock->global);
		free(cfglock);
		return;
	}

	if (cfglock->nswdb != NULL)
		(void) rw_unlock(cfglock->nswdb);

	if (cfglock->alldb != NULL)
		(void) rw_unlock(cfglock->alldb);

	free(cfglock);
}

/*
 * If vlen_data_addr is given, it will be set to the
 * address of the pointer pointing to the vlen data.
 * 'cfglock' will be set to point to the reader/writer
 * lock(s) protecting the (group) configuration data.
 */
static nscd_rc_t
_nscd_cfg_locate_cfg_data(
	void			**cfg_data,
	nscd_bool_t		is_read,
	nscd_cfg_param_desc_t	*desc,
	nscd_cfg_id_t		*nswdb,
	nscd_bool_t		get_group,
	void			**vlen_data_addr,
	int			*len,
	nscd_cfg_lock_t		**cfglock)
{
	int		offset;

	*cfg_data = NULL;
	if (len != NULL)
		*len = 0;
	if (vlen_data_addr != NULL)
		*vlen_data_addr = NULL;

	if (cfglock != NULL) {
		*cfglock = calloc(1, sizeof (nscd_cfg_lock_t));
		if (*cfglock == NULL)
			return (NSCD_NO_MEMORY);
	}

	/* assume if nswdb is NULL, the param is a global one */
	if (nswdb == NULL) {

		offset = desc->g_offset;
		if (get_group != nscd_true)
			offset += desc->p_offset;
		*cfg_data = (char *)nscd_cfg_global_current + offset;

		if (cfglock != NULL)
			(*cfglock)->global = nscd_cfg_global_rwlock;

	} else if (nswdb->index == NSCD_CFG_NSW_ALLDB_INDEX) {

		offset = desc->g_offset;
		if (get_group != nscd_true)
			offset += desc->p_offset;
		*cfg_data = (char *)nscd_cfg_nsw_alldb_current +
		    offset;

		if (cfglock != NULL)
			(*cfglock)->alldb = nscd_cfg_nsw_alldb_rwlock;

	} else {

		offset = nswdb->index *
		    (sizeof (nscd_cfg_nsw_db_data_t)) + desc->g_offset;
		if (get_group != nscd_true)
			offset += desc->p_offset;
		*cfg_data = (char *)nscd_cfg_nsw_db_data_current +
		    offset;

		if (cfglock != NULL) {
			(*cfglock)->nswdb =
			    &nscd_cfg_nsw_db_data_rwlock[nswdb->index];

			(*cfglock)->alldb = nscd_cfg_nsw_alldb_rwlock;
		}
	}

	/* lock the config data */
	if (cfglock != NULL)
		_nscd_cfg_lock(is_read, *cfglock);

	if (get_group != nscd_true &&
	    _nscd_cfg_flag_is_not_set(desc->pflag,
	    NSCD_CFG_PFLAG_GROUP) &&
	    (_nscd_cfg_flag_is_set(desc->pflag,
	    NSCD_CFG_PFLAG_VLEN_DATA))) {
		if (vlen_data_addr != NULL)
			*vlen_data_addr = *cfg_data;
		*cfg_data = _nscd_cfg_locate_vlen_data(*cfg_data, len);
		return (NSCD_SUCCESS);
	}

	if (len != NULL) {
		if (get_group == nscd_true)
			*len = desc->g_size;
		else
			*len = desc->p_size;
	}

	return (NSCD_SUCCESS);
}

/*
 * perform the preliminary (range) check on 'data' based on the
 * datatype (desc->datatype) of the config parameter
 */
nscd_rc_t
_nscd_cfg_prelim_check(
	nscd_cfg_param_desc_t	*desc,
	void			*data,
	nscd_cfg_error_t	**errorp)
{

	char			*me = "_nscd_cfg_prelim_check";
	char			msg[NSCD_CFG_MAX_ERR_MSG_LEN];
	nscd_cfg_str_check_t	*sc;
	nscd_cfg_int_check_t	*ic;
	nscd_cfg_bitmap_check_t	*bmc;
	nscd_rc_t		rc = NSCD_CFG_PRELIM_CHECK_FAILED;

	if ((nscd_cfg_str_check_t *)desc->p_check == NULL)
		return (NSCD_SUCCESS);

	switch (desc->type) {

	case NSCD_CFG_DATA_STRING:

		sc = (nscd_cfg_str_check_t *)desc->p_check;
		if (sc->must_not_null == nscd_true && data == NULL) {

			if (errorp == NULL)
				break;

			(void) snprintf(msg, sizeof (msg),
			    gettext("data must be specified for %s"),
			    desc->id.name);

			break;
		}

		if (data == NULL) {
			rc = NSCD_SUCCESS;
			break;
		}

		if (sc->maxlen != 0 &&
		    strlen((char *)data) > sc->maxlen) {

			if (errorp == NULL)
				break;

			(void) snprintf(msg, sizeof (msg),
			    gettext("length of data (%s) for %s larger "
			    "than %d"),
			    (char *)data, desc->id.name, sc->maxlen);
			break;
		}

		rc = NSCD_SUCCESS;

		break;

	case NSCD_CFG_DATA_INTEGER:

		ic = (nscd_cfg_int_check_t *)desc->p_check;
		if (*(int *)data > ic->max ||
		    *(int *)data < ic->min) {

			if (errorp == NULL)
				break;

			(void) snprintf(msg, sizeof (msg),
			    gettext("data (%d) for %s out of range "
			    "(%d - %d)"),
			    *(int *)data, desc->id.name,
			    ic->min, ic->max);

			break;
		}

		rc = NSCD_SUCCESS;

		break;

	case NSCD_CFG_DATA_BITMAP:

		bmc = (nscd_cfg_bitmap_check_t *)desc->p_check;
		if (_nscd_cfg_bitmap_value(*(nscd_cfg_bitmap_t *)data) &
		    ~(bmc->valid_bits)) {

			if (errorp == NULL)
				break;

			(void) snprintf(msg, sizeof (msg),
			    gettext("data (%#6.4x) for %s contain bit "
			    "not in 0x%x"),
			    _nscd_cfg_bitmap_value(
			    *(nscd_cfg_bitmap_t *)data),
			    desc->id.name,
			    _nscd_cfg_bitmap_value(bmc->valid_bits));
			break;
		}

		rc = NSCD_SUCCESS;

		break;
	}

	if (rc != NSCD_SUCCESS && errorp != NULL) {
		*errorp = _nscd_cfg_make_error(rc, msg);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "invalid argument: %s\n", (*errorp)->msg);
	}

	return (rc);
}

static nscd_rc_t
_nscd_cfg_notify_i(
	nscd_cfg_param_desc_t	*desc,
	nscd_cfg_id_t		*nswdb,
	int			*skip,
	nscd_cfg_error_t	**errorp)
{

	char			*me = "_nscd_cfg_notify_i";
	int			i, num, skip_bk;
	void			*cfg_data, *cdata;
	void			*cookie = NULL;
	nscd_rc_t		rc;
	nscd_cfg_flag_t		dflag, dflag1;
	nscd_cfg_bitmap_t	bitmap_c, bitmap_s, *bitmap_addr;
	nscd_cfg_group_info_t	*gi;

	if (errorp != NULL)
		*errorp = NULL;

	if (skip == NULL)
		skip = &skip_bk;

	*skip = 0;

	if (_nscd_cfg_flag_is_not_set(desc->pflag,
	    NSCD_CFG_PFLAG_GROUP)) {

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "ERROR: expect parameter description for group, "
		    "but receive parameter description is for %s\n",
		    desc->id.name);

		return (NSCD_CFG_PARAM_DESC_ERROR);
	}

	/*
	 * Set data flag going with data to be sent to the
	 * verify/notify routines. Allowing the config flag
	 * be exipandable, set the bits one by one.
	 */
	dflag = NSCD_CFG_FLAG_ZERO;
	dflag = _nscd_cfg_flag_set(dflag, NSCD_CFG_DFLAG_STATIC_DATA);
	dflag = _nscd_cfg_flag_set(dflag, NSCD_CFG_DFLAG_INIT);
	dflag = _nscd_cfg_flag_set(dflag, NSCD_CFG_DFLAG_GROUP);
	if (_nscd_cfg_flag_is_set(desc->pflag,
	    NSCD_CFG_PFLAG_INIT_SET_ALL_DB))
		dflag = _nscd_cfg_flag_set(dflag,
		    NSCD_CFG_DFLAG_SET_ALL_DB);

	/* get to the group data in the config store */
	rc = _nscd_cfg_locate_cfg_data(&cfg_data, nscd_true,
	    desc, nswdb, nscd_true, NULL, NULL, NULL);
	if (rc != NSCD_SUCCESS)
		goto error;

	/*
	 * the static bitmap associated with the group
	 * may be replaced before sending to the components,
	 * so save the bitmap for later use
	 */
	gi = _nscd_cfg_get_gi(cfg_data);
	bitmap_c = gi->bitmap;
	bitmap_addr = &(gi->bitmap);

	/*
	 * the elements in this group will all be handled
	 * so the caller can skip them
	 */
	*skip = desc->p_fn;

	if (_nscd_cfg_flag_is_set(desc->pflag,
	    NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP))
		/* send the entire group just once */
		num = 1;

	else { /* send individual members one by one */

		num = desc->p_fn;

		/*
		 * skip the first desc which is for the group
		 * and get to the desc for the first member
		 */
		desc++;

		dflag = _nscd_cfg_flag_unset(dflag,
		    NSCD_CFG_DFLAG_GROUP);
	}

	dflag1 = dflag;
	for (i = 0; i < num; i++, desc++) {

		dflag = dflag1;

		if (_nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_SEND_BIT_SELECTED)) {

			/* set the bitmap to select just this member */
			bitmap_s = NSCD_CFG_BITMAP_ZERO;
			_nscd_cfg_bitmap_set_nth(bitmap_s, i);
			/* replace the bitmap in the cfg data */
			_nscd_cfg_bitmap_set(bitmap_addr, bitmap_s);

			/*
			 * send the whole group but with only one
			 * member selected
			 */
			cdata = cfg_data;

			dflag = _nscd_cfg_flag_set(dflag,
			    NSCD_CFG_DFLAG_GROUP);
			dflag = _nscd_cfg_flag_set(dflag,
			    NSCD_CFG_DFLAG_BIT_SELECTED);
		} else {
			/*
			 * send param data or group data:
			 * param data - non-xero desc->p_offset
			 * group data - zero desc->p_offset
			 */
			cdata = (char *)cfg_data + desc->p_offset;

			/*
			 * if variable length data, need to send pointer
			 * to the data (not the address of the pointer)
			 */
			if (_nscd_cfg_flag_is_set(desc->pflag,
			    NSCD_CFG_PFLAG_VLEN_DATA))
				cdata = *(char **)cdata;
		}

		if (desc->verify != NULL) {
			dflag = _nscd_cfg_flag_set(dflag,
			    NSCD_CFG_DFLAG_VERIFY);
			rc = desc->verify(cdata, desc, nswdb,
			    dflag, errorp, &cookie);
			if (rc != NSCD_SUCCESS)
				goto error;
		}

		if (desc->notify != NULL) {
			dflag = _nscd_cfg_flag_set(dflag,
			    NSCD_CFG_DFLAG_NOTIFY);

			rc = desc->notify(cfg_data, desc, nswdb,
			    dflag, errorp, cookie);
			if (rc != NSCD_SUCCESS)
				goto error;
		}
	}

	rc = NSCD_SUCCESS;

	/* restore the bitmap in the cfg data */
	_nscd_cfg_bitmap_set(bitmap_addr, bitmap_c);

	error:

	return (rc);

}

static nscd_rc_t
_nscd_cfg_notify_init(
	nscd_cfg_error_t	**errorp)
{
	int			i, j, skip;
	nscd_rc_t		rc;
	nscd_cfg_id_t		*nswdb = NULL;
	nscd_cfg_param_desc_t	*desc;

	if (errorp != NULL)
		*errorp = NULL;

	for (i = 0; i < _nscd_cfg_num_param; i++) {

		desc = &_nscd_cfg_param_desc[i];

		if (_nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_GLOBAL)) { /* global cfg data */

			rc = _nscd_cfg_notify_i(desc, NULL, &skip, errorp);
		} else {

			/*
			 * if use defaults for all nsswitch database,
			 * send the config data to verify/notify once
			 */
			if (_nscd_cfg_flag_is_set(desc->pflag,
			    NSCD_CFG_PFLAG_INIT_SET_ALL_DB)) {

				nswdb = &_nscd_cfg_nsw_alldb;

				rc = _nscd_cfg_notify_i(desc, nswdb,
				    &skip, errorp);
			} else { /* send data once for each nsw db */

				for (j = 0; j < _nscd_cfg_num_nsw_db; j++) {

					nswdb = &_nscd_cfg_nsw_db[j];

					rc = _nscd_cfg_notify_i(desc,
					    nswdb, &skip, errorp);

					if (rc != NSCD_SUCCESS)
						break;
				}
			}
		}

		if (rc != NSCD_SUCCESS)
			return (rc);

		i += skip;
	}

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_cfg_init(
	nscd_cfg_error_t		**errorp)
{

	int				i, j, datalen;
	int				dbi = 0, dbj = 0;
	char				*dest, *src;
	char				*dbni = NULL, *dbnj = NULL;
	nscd_rc_t			rc;
	nscd_cfg_nsw_spc_default_t	*spc;

	if (errorp != NULL)
		*errorp = NULL;

	rc = _nscd_cfg_init_param();
	if (rc != NSCD_SUCCESS)
		return (rc);

	rc = _nscd_cfg_init_stat();
	if (rc != NSCD_SUCCESS)
		return (rc);

	nscd_cfg_global_current = calloc(1,
	    sizeof (nscd_cfg_global_data_t));
	if (nscd_cfg_global_current == NULL)
		return (NSCD_NO_MEMORY);

	nscd_cfg_nsw_alldb_current = calloc(1,
	    sizeof (nscd_cfg_nsw_db_data_t));
	if (nscd_cfg_nsw_alldb_current == NULL)
		return (NSCD_NO_MEMORY);

	nscd_cfg_nsw_db_data_current = calloc(_nscd_cfg_num_nsw_db,
	    sizeof (nscd_cfg_nsw_db_data_t));
	if (nscd_cfg_nsw_db_data_current == NULL)
		return (NSCD_NO_MEMORY);

	nscd_cfg_global_rwlock = calloc(1, sizeof (rwlock_t));
	if (nscd_cfg_global_rwlock == NULL)
		return (NSCD_NO_MEMORY);
	(void) rwlock_init(nscd_cfg_global_rwlock, USYNC_THREAD, NULL);

	*nscd_cfg_global_current = nscd_cfg_global_default;

	rc = _nscd_cfg_set_vlen_data_int(&nscd_cfg_global_default,
	    nscd_cfg_global_current, nscd_true);
	if (rc != NSCD_SUCCESS)
		return (rc);

	nscd_cfg_nsw_db_data_rwlock = calloc(_nscd_cfg_num_nsw_db,
	    sizeof (rwlock_t));
	if (nscd_cfg_nsw_db_data_rwlock == NULL)
		return (NSCD_NO_MEMORY);

	/* set per switch db config to the default for all db's */
	for (i = 0; i < _nscd_cfg_num_nsw_db; i++) {

		nscd_cfg_nsw_db_data_current[i] =
		    nscd_cfg_nsw_db_data_default;

		(void) rwlock_init(&nscd_cfg_nsw_db_data_rwlock[i],
		    0, NULL);
	}

	/* add db specific defaults */
	for (i = 0; i < _nscd_cfg_num_nsw_default; i++) {

		if (_nscd_cfg_nsw_spc_default[i].data == NULL)
			continue;

		if (_nscd_cfg_nsw_spc_default[i].db != dbni) {
			for (j = 0; j < _nscd_cfg_num_nsw_db; j++) {

				if (strcmp(_nscd_cfg_nsw_db[j].name,
				    _nscd_cfg_nsw_spc_default[i].db) != 0)
					continue;

				dbi = _nscd_cfg_nsw_db[j].index;
				dbni = _nscd_cfg_nsw_db[j].name;
				break;
			}
		}

		dest = (char *)&nscd_cfg_nsw_db_data_current[dbi] +
		    _nscd_cfg_nsw_spc_default[i].group_off +
		    _nscd_cfg_nsw_spc_default[i].param_off;

		src = _nscd_cfg_nsw_spc_default[i].data;
		datalen = _nscd_cfg_nsw_spc_default[i].data_len;

		(void) memcpy(dest, src, datalen);
	}

	/* add db specific defaults via links */
	for (i = 0; i < _nscd_cfg_num_link_default; i++) {

		if (_nscd_cfg_nsw_link_default[i].data == NULL)
			continue;

		spc = _nscd_cfg_nsw_link_default[i].data;

		if (_nscd_cfg_nsw_link_default[i].db != dbni) {
			for (j = 0; j < _nscd_cfg_num_nsw_db; j++) {

				if (strcmp(_nscd_cfg_nsw_db[j].name,
				    _nscd_cfg_nsw_link_default[i].db) != 0)
					continue;

				dbi = _nscd_cfg_nsw_db[j].index;
				dbni = _nscd_cfg_nsw_db[j].name;
				break;
			}
		}

		dest = (char *)&nscd_cfg_nsw_db_data_current[dbi] +
		    _nscd_cfg_nsw_link_default[i].group_off +
		    _nscd_cfg_nsw_link_default[i].param_off;

		if (_nscd_cfg_nsw_db[j].name != dbnj) {
			for (j = 0; j < _nscd_cfg_num_nsw_db; j++) {

				if (strcmp(spc->db,
				    _nscd_cfg_nsw_db[j].name) != 0)
					continue;

				dbnj = _nscd_cfg_nsw_db[j].name;
				dbj = _nscd_cfg_nsw_db[j].index;
				break;
			}
		}

		src = (char *)&nscd_cfg_nsw_db_data_current[dbj] +
		    spc->group_off + spc->param_off;
		datalen = spc->data_len;

		(void) memcpy(dest, src, datalen);
	}

	/* fix up variable length fields */
	for (i = 0; i < _nscd_cfg_num_nsw_db; i++) {

		rc = _nscd_cfg_set_vlen_data_int(
		    &nscd_cfg_nsw_db_data_current[i],
		    &nscd_cfg_nsw_db_data_current[i], nscd_false);
		if (rc != NSCD_SUCCESS)
			return (rc);
	}

	nscd_cfg_nsw_alldb_rwlock = calloc(1, sizeof (rwlock_t));
	if (nscd_cfg_nsw_alldb_rwlock == NULL)
		return (NSCD_NO_MEMORY);

	(void) rwlock_init(nscd_cfg_nsw_alldb_rwlock, 0, NULL);

	rc = _nscd_cfg_set_vlen_data_int(
	    &nscd_cfg_nsw_db_data_default,
	    nscd_cfg_nsw_alldb_current, nscd_false);
	if (rc != NSCD_SUCCESS)
		return (rc);

	/*
	 * notify and send the configuration data to
	 * the nscd components
	 */
	rc = _nscd_cfg_notify_init(errorp);
	if (rc != NSCD_SUCCESS)
		return (rc);

	return (NSCD_SUCCESS);
}

static nscd_rc_t
_nscd_cfg_get_handle_common(
	nscd_cfg_list_type_t	type,
	char			*name,
	char			*nswdb_name,
	nscd_cfg_handle_t	**handle,
	nscd_cfg_error_t	**errorp)
{

	int			i, is_global;
	char			*desc_str;
	nscd_cfg_handle_t	*h;
	nscd_cfg_param_desc_t	*pdesc;
	nscd_cfg_stat_desc_t	*sdesc;
	char			*me = "_nscd_cfg_get_handle_common";
	char			msg[NSCD_CFG_MAX_ERR_MSG_LEN];
	nscd_rc_t		rc = NSCD_INVALID_ARGUMENT;

	if (handle == NULL) {

		(void) snprintf(msg, sizeof (msg),
		    gettext("address of handle not specified"));
		if (errorp)
			*errorp = _nscd_cfg_make_error(rc, msg);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "invalid argument: %s\n", msg);

		return (rc);
	}

	*handle = NULL;

	if (name == NULL) {

		(void) snprintf(msg, sizeof (msg),
		    gettext("name not specified"));
		if (errorp)
			*errorp = _nscd_cfg_make_error(rc, msg);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "invalid argument: %s\n");

		return (rc);
	}

	h = calloc(1, sizeof (nscd_cfg_handle_t));
	if (h == NULL)
		return (NSCD_NO_MEMORY);
	h->type = type;

	if (type == NSCD_CFG_LIST_PARAM)
		desc_str = gettext("configuration parameter");
	else
		desc_str = gettext("statistics");

	/* get param or stat descriptor */
	i = _nscd_cfg_get_index(name, type);
	if (i != -1) {

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: index of %s is %d\n", desc_str, name, i);

		if (type == NSCD_CFG_LIST_PARAM) {
			pdesc = &_nscd_cfg_param_desc[i];
			(void) memcpy(&h->desc, &pdesc, sizeof (pdesc));
			is_global = _nscd_cfg_flag_is_set(
			    pdesc->pflag, NSCD_CFG_PFLAG_GLOBAL);

			/* hidden params are not exposed */
			if (_nscd_cfg_flag_is_set(
			    pdesc->pflag, NSCD_CFG_PFLAG_HIDDEN))
				i = -1;

			if (_nscd_cfg_flag_is_set(pdesc->pflag,
			    NSCD_CFG_PFLAG_OBSOLETE)) {
				_NSCD_LOG(NSCD_LOG_CONFIG,
				    NSCD_LOG_LEVEL_WARNING)
				(me, gettext("%s: %s is obsolete and "
				    "will be ignored\n"),
				    desc_str, name);
			}
		} else {
			sdesc = &_nscd_cfg_stat_desc[i];
			(void) memcpy(&h->desc, &sdesc, sizeof (sdesc));
			is_global = _nscd_cfg_flag_is_set(
			    sdesc->sflag, NSCD_CFG_SFLAG_GLOBAL);
		}
	}

	if (i == -1) {

		(void) snprintf(msg, sizeof (msg),
		    gettext("%s: unknown name \"%s\""), desc_str, name);
		if (errorp)
			*errorp = _nscd_cfg_make_error(rc, msg);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "%s\n", msg);

		free(h);
		return (rc);
	}

	/*
	 * if the param/stat is not a global one, we need to
	 * know which nsswitch database we are dealing with
	 */
	if (is_global == 0) {
		if (nswdb_name == NULL) {

			(void) snprintf(msg, sizeof (msg),
			gettext("%s: switch database name not specified"),
			    desc_str);
			if (errorp)
				*errorp = _nscd_cfg_make_error(rc, msg);

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "%s for non-global param or stat %s\n",
			    msg, name);

			free(h);
			return (rc);
		}
	} else {

		if (nswdb_name != NULL) {

			(void) snprintf(msg, sizeof (msg),
			    gettext("%s: switch database specified for "
			    "global data"), desc_str);
			if (errorp)
				*errorp = _nscd_cfg_make_error(rc, msg);

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "%s %s\n", msg, name);

			free(h);
			return (rc);
		}

		*handle = h;
		return (NSCD_SUCCESS);
	}

	/* get nsw DB id */
	i = _nscd_cfg_get_index(nswdb_name, NSCD_CFG_LIST_NSW_DB);
	if (i != -1) {

		if (i == NSCD_CFG_NSW_ALLDB_INDEX)
			h->nswdb = &_nscd_cfg_nsw_alldb;
		else
			h->nswdb = &_nscd_cfg_nsw_db[i];

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "%s: index of %s is %d\n",
		    desc_str, nswdb_name, i);
	} else {

		(void) snprintf(msg, sizeof (msg),
		    gettext("%s: unknown switch database name \"%s\""),
		    desc_str, nswdb_name);
		if (errorp)
			*errorp = _nscd_cfg_make_error(rc, msg);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "%s\n", msg);

		free(h);
		return (NSCD_CFG_UNSUPPORTED_SWITCH_DB);
	}

	*handle = h;

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_cfg_get_handle(
	char			*param_name,
	char			*nswdb_name,
	nscd_cfg_handle_t	**handle,
	nscd_cfg_error_t	**errorp)
{

	return (_nscd_cfg_get_handle_common(NSCD_CFG_LIST_PARAM,
	    param_name, nswdb_name, handle, errorp));
}

nscd_rc_t
_nscd_cfg_get_stat_handle(
	char			*stat_name,
	char			*nswdb_name,
	nscd_cfg_handle_t	**handle,
	nscd_cfg_error_t	**errorp)
{

	return (_nscd_cfg_get_handle_common(NSCD_CFG_LIST_STAT,
	    stat_name, nswdb_name, handle, errorp));
}

void
_nscd_cfg_free_handle(
	nscd_cfg_handle_t	*handle)
{

	free(handle);

}

static void
_nscd_cfg_free_vlen_data_group(
	nscd_cfg_param_desc_t	*gdesc,
	void			*group_data,
	nscd_bool_t		in)
{
	int			num;
	void			*dest, *ptr;
	nscd_cfg_param_desc_t	*desc;

	desc = gdesc;

	num = ((nscd_cfg_group_info_t *)group_data)->num_param;

	while (num-- > 0) {

		desc++;

		/* skip fixed length data */
		if (_nscd_cfg_flag_is_not_set(desc->pflag,
		    NSCD_CFG_PFLAG_VLEN_DATA))
			continue;

		dest = (char *)group_data + desc->p_offset;
		ptr = *(char **)dest;
		if (ptr == NULL)
			continue;
		if (in == nscd_true)
			_nscd_cfg_free_vlen_data_int(ptr);
		else
			free(ptr);
	}
}

void
_nscd_cfg_free_param_data(
	void			*data)
{

	if (data == NULL)
		return;

	free(data);
}

void
_nscd_cfg_free_group_data(
	nscd_cfg_handle_t	*handle,
	void			*data)
{

	nscd_cfg_param_desc_t	*desc;
	nscd_cfg_group_info_t	*gi;

	if (handle == NULL || data == NULL)
		return;

	desc = _nscd_cfg_get_desc(handle);
	gi = (nscd_cfg_group_info_t *)data;
	if (desc->p_fn != gi->num_param)
		return;

	_nscd_cfg_free_vlen_data_group(desc, data, nscd_false);

	free(data);
}

void
_nscd_cfg_free_error(
	nscd_cfg_error_t	*error)
{

	if (error == NULL)
		return;

	free(error);
}

static nscd_rc_t
_nscd_cfg_copy_param_data(
	nscd_cfg_param_desc_t	*desc,
	void			*dest,
	void			*pdata,
	nscd_bool_t		in,
	nscd_bool_t		set_addr)
{

	char			*me = "_nscd_cfg_copy_param_data";
	void			*tmp;
	int			dlen;
	nscd_rc_t		rc = NSCD_SUCCESS;

	if (desc == NULL || dest == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "input desc == %p, dest == %p\n", desc, dest);
		return (NSCD_INVALID_ARGUMENT);
	}

	/* fixed length data */
	if (_nscd_cfg_flag_is_not_set(desc->pflag,
	    NSCD_CFG_PFLAG_VLEN_DATA)) {
		(void) memcpy(dest, pdata, desc->p_size);
		goto done;
	}


	/* variable length data from this point on */

	/* make a copy of the variable length data */
	rc = _nscd_cfg_copy_vlen_data(pdata, &tmp, desc, &dlen, in);
	if (rc != NSCD_SUCCESS)
		goto done;

	if (in == nscd_true) { /* data to internal */

		/* free the variable length data in the config store */
		if (*(char **)dest != NULL)
			_nscd_cfg_free_vlen_data_int(*(char **)dest);
	}

	if (set_addr == nscd_true) {
		/*
		 * set the addr of the vlen data
		 */
		*(char **)dest = tmp;
	} else {
		/*
		 * copy the data content (not address)
		 */
		(void) memcpy(dest, tmp, dlen);
	}

	done:

	return (rc);
}

static nscd_rc_t
_nscd_cfg_copy_group_data_in(
	nscd_cfg_param_desc_t	*gdesc,
	nscd_cfg_group_info_t	*gi,
	void			*group_dest,
	void			*group_src)
{
	int			i, num;
	nscd_cfg_param_desc_t	*desc;
	void			*src, *dest;

	i = 0;
	num = gi->num_param;
	desc = gdesc;

	while (num-- > 0) {

		desc++;

		/* if member not selected by bitmap, skip */
		if (_nscd_cfg_bitmap_is_not_set(gi->bitmap, i++))
			continue;

		src = (char *)group_src + desc->p_offset;
		dest = (char *)group_dest + desc->p_offset;

		/*
		 * if variable length data, free and replace the old
		 * with the new
		 */
		if (_nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_VLEN_DATA)) {
			_nscd_cfg_free_vlen_data_int(*(char **)dest);
			*(char **)dest = *(char **)src;
			*(char **)src = NULL;
		} else {
			/*
			 * fixed length data, just copy it
			 */
			(void) memcpy(dest, src, desc->p_size);
		}
	}

	return (NSCD_SUCCESS);
}

static nscd_rc_t
_nscd_cfg_copy_group_data_out(
	nscd_cfg_param_desc_t	*gdesc,
	void			*group_dest,
	void			*group_src)
{

	char			*me = "_nscd_cfg_copy_group_data_out";
	void			*src, *dest;
	int			dlen;
	int			num;
	nscd_cfg_group_info_t	*gi;
	nscd_rc_t		rc = NSCD_SUCCESS;
	nscd_cfg_param_desc_t	*desc;

	if (group_dest == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "input group_dest = NULL\n");
		return (NSCD_INVALID_ARGUMENT);
	}

	gi = _nscd_cfg_get_gi(group_src);
	num = gi->num_param;
	desc = gdesc;

	while (num-- > 0) {

		desc++;

		dest = (char *)group_dest + desc->p_offset;
		src = (char *)group_src + desc->p_offset;

		/*
		 * if variable length data, get the real
		 * address and length of the data
		 */
		if (_nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_VLEN_DATA)) {
			src = _nscd_cfg_locate_vlen_data(src, &dlen);
			if (dlen == 0)
				continue;
		}

		/*
		 * The nscd_true asks _nscd_cfg_copy_param_data
		 * to set addr of the vlen data in 'dest' rather
		 * than copying the data content
		 */
		rc = _nscd_cfg_copy_param_data(desc, dest, src,
		    nscd_false, nscd_true);
		if (rc != NSCD_SUCCESS) {
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to copy param data for %s\n",
			    desc->id.name);

			_nscd_cfg_free_vlen_data_group(gdesc,
			    group_dest, nscd_false);

			free(group_dest);

			return (rc);
		}
	}

	/*
	 * set group bitmap
	 */
	(void) memcpy(group_dest, group_src,
	    sizeof (nscd_cfg_group_info_t));

	return (rc);
}


/*
 * group_cfg is needed always; group_src may be NULL if
 * param_index not zero and pdata not NULL; group_cfg and
 * pdata should not be both non-NULL
 */
static nscd_rc_t
_nscd_cfg_copy_group_data_merge(
	nscd_cfg_param_desc_t	*gdesc,
	void			**group_dest,
	void			*group_src,
	void			*group_cfg,
	int			param_index,
	void			*pdata)
{

	char			*me = "_nscd_cfg_copy_group_data_merge";
	void			*src, *dest, *tmp_dest = NULL;
	int			num, i = 0;
	nscd_cfg_group_info_t	*gi;
	nscd_rc_t		rc = NSCD_SUCCESS;
	nscd_cfg_param_desc_t	*desc;
	nscd_cfg_bitmap_t	bitmap;

	if (group_dest == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "input **group_dest == NULL\n");
		return (NSCD_INVALID_ARGUMENT);
	}

	if (group_cfg == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "input **group_cfg == NULL\n");
		return (NSCD_INVALID_ARGUMENT);
	}

	if (param_index != 0 && pdata == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "param_index != NULL but pdata == %p\n", pdata);
		return (NSCD_INVALID_ARGUMENT);
	}

	tmp_dest = calloc(1, gdesc->g_size);
	if (tmp_dest == NULL)
		return (NSCD_NO_MEMORY);

	if (group_src != NULL)
		gi = _nscd_cfg_get_gi(group_src);
	else {
		gi = _nscd_cfg_get_gi(group_cfg);
		bitmap = NSCD_CFG_BITMAP_ZERO;
	}

	num = gi->num_param;
	desc = gdesc;

	while (num-- > 0) {

		desc++;

		dest = (char *)tmp_dest + desc->p_offset;

		/*
		 * if member not selected by bitmap in group_src,
		 * get the member data in group_cfg
		 */
		if (_nscd_cfg_bitmap_is_not_set(gi->bitmap, i++) ||
		    group_src == NULL) {
			src = (char *)group_cfg + desc->p_offset;
		} else
			src = (char *)group_src + desc->p_offset;

		if (desc->id.index == param_index) {

			/* use the param data in pdata if provided */
			src = pdata;
			_nscd_cfg_bitmap_set_nth(bitmap, i);
		}

		/*
		 * if variable length data, get to the data
		 * instead of pointer to the data
		 */
		if (_nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_VLEN_DATA))
			src = *(char **)src;

		/*
		 * nscd_true asks _nscd_cfg_copy_param_data to
		 * set addr of the vlen data in 'dest' rather
		 * than copying the data content
		 */
		rc = _nscd_cfg_copy_param_data(desc, dest, src,
		    nscd_true, nscd_true);
		if (rc != NSCD_SUCCESS) {
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to copy param data for %s\n",
			    desc->id.name);

			_nscd_cfg_free_vlen_data_group(gdesc,
			    tmp_dest, nscd_true);

			free(tmp_dest);

			return (rc);
		}
	}

	*group_dest = tmp_dest;

	/*
	 * set bitmap: if input is group data, use the one
	 * given; if input is param data, use the one computed
	 * above
	 */
	if (group_src != NULL)
		(void) memcpy(*group_dest, group_src,
		    sizeof (nscd_cfg_group_info_t));
	else {
		gi = _nscd_cfg_get_gi(*group_dest);
		_nscd_cfg_bitmap_set(&gi->bitmap, bitmap);
	}

	return (rc);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_get(
	nscd_cfg_handle_t	*handle,
	void			**data,
	int			*data_len,
	nscd_cfg_error_t	**errorp)
{
	char			*me = "_nscd_cfg_get";
	int			dlen;
	nscd_rc_t		rc = NSCD_SUCCESS;
	nscd_cfg_id_t		*nswdb;
	nscd_cfg_param_desc_t	*desc;
	void			*cfg_data, *ptr = NULL;
	nscd_bool_t		get_group = nscd_false;
	nscd_bool_t		out = nscd_false;
	nscd_cfg_lock_t		*lock = NULL;

	if (data_len != NULL)
		*data_len = 0;

	if (data == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "input data = %p\n", data);
		return (NSCD_INVALID_ARGUMENT);
	}

	*data = NULL;

	if (handle == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "handle is NULL\n");
		return (NSCD_INVALID_ARGUMENT);
	}

	nswdb = handle->nswdb;
	desc = (nscd_cfg_param_desc_t *)handle->desc;

	if (_nscd_cfg_flag_is_set(desc->pflag, NSCD_CFG_PFLAG_GROUP))
		get_group = nscd_true;

	/*
	 * locate the current value of the param or group
	 * and lock the config data for reading
	 */
	rc = _nscd_cfg_locate_cfg_data(&cfg_data, nscd_true, desc,
	    nswdb, get_group, NULL, &dlen, &lock);
	if (rc != NSCD_SUCCESS) {

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to locate config data\n");
		return (rc);

	} else if (cfg_data == NULL) /* NULL vlen data */
		goto done;

	ptr = calloc(1, dlen);
	if (ptr == NULL) {
		rc = NSCD_NO_MEMORY;
		goto error_exit;
	}

	if (get_group == nscd_true) {

		rc = _nscd_cfg_copy_group_data_out(desc, ptr, cfg_data);
		if (rc != NSCD_SUCCESS) {
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to copy group data %p: "
			"error = %d\n", cfg_data, rc);

			goto error_exit;
		}
	} else {
		/*
		 * nscd_false asks _nscd_cfg_copy_param_data to
		 * copy the data content rather than just setting
		 * the addr of the vlen data in 'ptr'
		 */
		rc = _nscd_cfg_copy_param_data(desc, ptr, cfg_data,
		    out, nscd_false);

		if (rc != NSCD_SUCCESS) {
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to copy param data %p: "
			"error = %d\n", cfg_data, rc);

			goto error_exit;
		}
	}

	*data = ptr;

	done:

	if (data_len != NULL)
		*data_len = dlen;

	_nscd_cfg_unlock(lock);

	return (NSCD_SUCCESS);

	error_exit:

	_nscd_cfg_unlock(lock);
	if (ptr != NULL)
		free(ptr);

	return (rc);
}

/*
 * three type of data:
 * 1 - single param
 *	desc is that of the param
 * 2 - single param to be sent in a group
 *	a single bit is set in the bitmap,
 *	desc is that of the group
 * 3 - group data
 *	one of more bits are set in the bitmap,
 *	desc is that of the group
 */
static nscd_rc_t
_nscd_cfg_notify_s(
	nscd_cfg_param_desc_t	*desc,
	nscd_cfg_id_t		*nswdb,
	void			*data,
	nscd_cfg_error_t	**errorp)
{
	int			i, num, is_group = 0;
	void			*cookie = NULL;
	void			*cdata;
	nscd_rc_t		rc;
	nscd_cfg_flag_t		dflag, dflag1;
	nscd_cfg_bitmap_t	bitmap_s, bitmap_in, *bitmap_addr = NULL;
	nscd_cfg_group_info_t	*gi;

	if (errorp != NULL)
		*errorp = NULL;

	/*
	 * Set data flag going with data to be sent to the
	 * verify/notify routines. To allow the config flag
	 * be exipandable, set the bits one by one.
	 */
	dflag = NSCD_CFG_FLAG_ZERO;
	dflag = _nscd_cfg_flag_set(dflag, NSCD_CFG_DFLAG_STATIC_DATA);
	if (_nscd_cfg_flag_is_set(desc->pflag, NSCD_CFG_PFLAG_GROUP)) {
		dflag = _nscd_cfg_flag_set(dflag, NSCD_CFG_DFLAG_GROUP);
		is_group = 1;
	}
	if (nswdb != NULL &&
	    strcmp(NSCD_CFG_NSW_ALLDB, nswdb->name) == 0)
		dflag = _nscd_cfg_flag_set(dflag,
		    NSCD_CFG_DFLAG_SET_ALL_DB);

	/*
	 * the bitmap in the input data may be replaced before
	 * sending to the components, so save the bitmap for
	 * later use
	 */
	if (is_group == 1) {
		gi = _nscd_cfg_get_gi(data);
		bitmap_in = gi->bitmap;
		bitmap_addr = &(gi->bitmap);

		if (_nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP))
			/* send the entire group just once */
			num = 1;

		else { /* send individual members one by one */

			num = desc->p_fn;

			/*
			 * skip the first desc which is for the group
			 * and get to the desc for the first member
			 */
			desc++;

			dflag = _nscd_cfg_flag_unset(dflag,
			    NSCD_CFG_DFLAG_GROUP);
		}
	} else {
		/* not group data, send the member once */
			num = 1;
	}

	dflag1 = dflag;
	for (i = 0; i < num; i++, desc++) {

		dflag = dflag1;

		if (is_group == 0) {
			cdata = data;
			goto verify_data;
		}

		if (_nscd_cfg_flag_is_set(desc->pflag,
		    NSCD_CFG_PFLAG_SEND_BIT_SELECTED)) {

			/* set the bitmap to select just this member */
			bitmap_s = NSCD_CFG_BITMAP_ZERO;
			_nscd_cfg_bitmap_set_nth(bitmap_s, i);
			/* replace the bitmap in the input data */
			_nscd_cfg_bitmap_set(bitmap_addr, bitmap_s);

			/*
			 * send the whole group but with only one
			 * member selected
			 */
			cdata = data;

			dflag = _nscd_cfg_flag_set(dflag,
			    NSCD_CFG_DFLAG_GROUP);
			dflag = _nscd_cfg_flag_set(dflag,
			    NSCD_CFG_DFLAG_BIT_SELECTED);
		} else {
			/*
			 * send param data or group data:
			 * param data - non-xero desc->p_offset
			 * group data - zero desc->p_offset
			 */
			cdata = (char *)data + desc->p_offset;

			/*
			 * if variable length data, need to send pointer
			 * to the data (not the address of the pointer)
			 */
			if (_nscd_cfg_flag_is_set(desc->pflag,
			    NSCD_CFG_PFLAG_VLEN_DATA))
				cdata = *(char **)cdata;
		}

		verify_data:

		if (desc->verify != NULL) {
			dflag = _nscd_cfg_flag_set(dflag,
			    NSCD_CFG_DFLAG_VERIFY);
			rc = desc->verify(cdata, desc, nswdb,
			    dflag, errorp, &cookie);
			if (rc != NSCD_SUCCESS)
				goto error_exit;
		}

		if (desc->notify != NULL) {
			dflag = _nscd_cfg_flag_set(dflag,
			    NSCD_CFG_DFLAG_NOTIFY);

			rc = desc->notify(data, desc, nswdb,
			    dflag, errorp, cookie);
			if (rc != NSCD_SUCCESS)
				goto error_exit;
		}
	}

	rc = NSCD_SUCCESS;

	error_exit:

	/* restore the bitmap in the input data */
	if (bitmap_addr != NULL)
		_nscd_cfg_bitmap_set(bitmap_addr, bitmap_in);

	return (rc);
}

/*
 * Convert string 'str' to data based on the data type in 'desc'.
 * 'data' points to the buffer in which the converted data
 * is placed. '*data_p' points to the buffer, or in the case
 * of a string data type, points to the untoched string (i.e.,
 * 'str').
 */
nscd_rc_t
_nscd_cfg_str_to_data(
	nscd_cfg_param_desc_t	*desc,
	char			*str,
	void			*data,
	void			**data_p,
	nscd_cfg_error_t	**errorp)
{

	char			*me = "_nscd_cfg_str_to_data";
	char			*c;
	nscd_cfg_bitmap_t	bitmap;
	char			msg[NSCD_CFG_MAX_ERR_MSG_LEN];
	nscd_rc_t		rc = NSCD_CFG_DATA_CONVERSION_FAILED;

	if (desc == NULL || str == NULL || data == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "ERROR: one of the following is NULL "
		    "desc = %p, str = %p, data = %p, data_p = %p\n",
		    desc, str, data, data_p);

		return (NSCD_INVALID_ARGUMENT);
	}
	*data_p = data;

	/* if description is that of a group, return error */
	if (_nscd_cfg_flag_is_set(desc->pflag, NSCD_CFG_PFLAG_GROUP)) {

		(void) snprintf(msg, sizeof (msg),
		gettext("single data specified for group %s"), desc->id.name);

		if (errorp != NULL)
			*errorp = _nscd_cfg_make_error(NSCD_INVALID_ARGUMENT,
			    msg);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "ERROR: %s)\n", msg);

		return (NSCD_INVALID_ARGUMENT);

	}

	if (desc->type == NSCD_CFG_DATA_STRING) {
		if (strcmp(str, NSCD_NULL) == 0)
			*(char **)data_p = NULL;
		else {
			/* remove the " char if quoted string */
			if (str[0] == '"') {
				c = str + strlen(str) - 1;
				if (*c == '"')
					*c = '\0';
				*(char **)data_p = str + 1;
			} else
				*(char **)data_p = str;

		}
		return (NSCD_SUCCESS);
	}

	if (str == NULL) {

		(void) snprintf(msg, sizeof (msg),
		gettext("data must be specified for %s"), desc->id.name);

		if (errorp != NULL)
			*errorp = _nscd_cfg_make_error(NSCD_INVALID_ARGUMENT,
			    msg);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "ERROR: %s\n", msg);

		return (NSCD_INVALID_ARGUMENT);

	}

	switch (desc->type) {

	case NSCD_CFG_DATA_BOOLEAN:

		if (strcasecmp(str, "yes") == 0)
			*(nscd_bool_t *)data = nscd_true;
		else if (strcasecmp(str, "no") == 0)
			*(nscd_bool_t *)data = nscd_false;
		else {

		(void) snprintf(msg, sizeof (msg),
		gettext("data (%s) must be 'yes' or 'no' for %s"),
		    str, desc->id.name);

		if (errorp != NULL)
			*errorp = _nscd_cfg_make_error(NSCD_INVALID_ARGUMENT,
			    msg);

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "ERROR: %s\n", msg);

			return (NSCD_INVALID_ARGUMENT);
		}

		break;

	case NSCD_CFG_DATA_INTEGER:

		errno = 0;
		*(int *)data = (int)strtol(str, NULL, 10);
		if (errno != 0) {

			(void) snprintf(msg, sizeof (msg),
			gettext("unable to convert data (%s) for %s"),
			    str, desc->id.name);

			if (errorp != NULL)
				*errorp = _nscd_cfg_make_error(rc, msg);

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "ERROR: %s\n", msg);

			return (rc);
		}

		break;

	case NSCD_CFG_DATA_BITMAP:

		errno = 0;
		bitmap = (nscd_cfg_bitmap_t)strtol(str, NULL, 10);
		if (errno != 0) {

			(void) snprintf(msg, sizeof (msg),
			gettext("unable to convert data (%s) for %s"),
			    str, desc->id.name);

			if (errorp != NULL)
				*errorp = _nscd_cfg_make_error(rc, msg);

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "ERROR: %s\n", msg);

			return (rc);
		}

		_nscd_cfg_bitmap_set(data, bitmap);

		break;

	}

	return (NSCD_SUCCESS);
}


nscd_rc_t
_nscd_cfg_set(
	nscd_cfg_handle_t	*handle,
	void			*data,
	nscd_cfg_error_t	**errorp)
{
	char			*me = "_nscd_cfg_set";
	int			dlen;
	nscd_cfg_id_t		*nswdb;
	nscd_cfg_param_desc_t	*desc, *gdesc;
	nscd_cfg_group_info_t	*gi;
	char			*nswdb_name, *param_name;
	void			*pdata = NULL;
	void			*cfg_data, *vdata_addr = NULL;
	nscd_bool_t		get_group = 0;
	nscd_bool_t		in = nscd_true;
	nscd_cfg_lock_t		*lock = NULL;
	nscd_rc_t		rc = NSCD_SUCCESS;

	if (handle == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "handle is NULL\n");
		return (NSCD_INVALID_ARGUMENT);
	}

	nswdb = handle->nswdb;
	desc = (nscd_cfg_param_desc_t *)handle->desc;
	if (nswdb == NULL)
		nswdb_name = "global";
	else
		nswdb_name = nswdb->name;
	param_name = desc->id.name;

	if (data == NULL && _nscd_cfg_flag_is_not_set(desc->pflag,
	    NSCD_CFG_PFLAG_VLEN_DATA)) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "data == NULL\n");
		return (NSCD_INVALID_ARGUMENT);
	}

	if (_nscd_cfg_flag_is_set(desc->pflag,
	    NSCD_CFG_PFLAG_UPDATE_SEND_WHOLE_GROUP) ||
	    _nscd_cfg_flag_is_set(desc->pflag, NSCD_CFG_PFLAG_GROUP))
		get_group = nscd_true;

	/*
	 * locate the current value of the param or group
	 * and lock the config data for writing
	 */
	rc = _nscd_cfg_locate_cfg_data(&cfg_data, nscd_false, desc,
	    nswdb, get_group, &vdata_addr, &dlen, &lock);
	if (rc != NSCD_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to locate config data (rc = %d)\n", rc);
		return (rc);
	}

	if (_nscd_cfg_flag_is_set(desc->pflag, NSCD_CFG_PFLAG_GROUP) &&
	    ((nscd_cfg_group_info_t *)cfg_data)->num_param !=
	    ((nscd_cfg_group_info_t *)data)->num_param) {

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "number of parameters in group <%s : %s> not equal: "
		    "%d in input data, should be %d\n",
		    NSCD_STR_OR_GLOBAL(nswdb_name),
		    NSCD_STR_OR_NULL(param_name),
		    ((nscd_cfg_group_info_t *)data)->num_param,
		    ((nscd_cfg_group_info_t *)cfg_data)->num_param);

		rc = NSCD_INVALID_ARGUMENT;
		goto error_exit;
	}

	/*
	 * if variable length data, we want the address
	 * of the pointer pointing to the data
	 */
	if (vdata_addr != NULL)
		cfg_data = vdata_addr;

	/*
	 * just copy in the specified data, if no need
	 * to verify the data or notify the associated
	 * component
	 */
		if (get_group == nscd_true) {

			gdesc = &_nscd_cfg_param_desc[desc->g_index];

			rc = _nscd_cfg_copy_group_data_merge(
			    gdesc, &pdata, data, cfg_data,
			    desc->id.index, data);

			if (rc != NSCD_SUCCESS) {
				_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
				(me, "unable to copy group data <%s : %s>\n",
				    NSCD_STR_OR_GLOBAL(nswdb_name),
				    NSCD_STR_OR_NULL(param_name));

				goto error_exit;
			}

			rc = _nscd_cfg_notify_s(gdesc, nswdb,
			    pdata, errorp);

		} else
			rc = _nscd_cfg_notify_s(desc, nswdb, data,
			    errorp);

		if (rc != NSCD_SUCCESS) {

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "verifying/notifying  of new configuration "
			    "parameter <%s : %s> failed. %s\n",
			    NSCD_STR_OR_GLOBAL(nswdb_name),
			    param_name, (*errorp && (*errorp)->msg) ?
			    (*errorp)->msg : "");

			goto error_exit;
		}

	/*
	 * Move the new config into the config store
	 */
	rc = NSCD_CFG_SET_PARAM_FAILED;
	if (_nscd_cfg_flag_is_set(desc->pflag,
	    NSCD_CFG_PFLAG_GROUP)) {
		gi = _nscd_cfg_get_gi(pdata);
		rc = _nscd_cfg_copy_group_data_in(gdesc, gi,
		    cfg_data, pdata);
	} else {
		/*
		 * nscd_true asks _nscd_cfg_copy_param_data to
		 * set addr of the vlen data in 'cfg_data' rather
		 * than copying the data content
		 */
		if (pdata != NULL)
			_nscd_cfg_free_vlen_data_group(gdesc,
			    pdata, in);

		rc = _nscd_cfg_copy_param_data(desc,
		    cfg_data, data, in, nscd_true);
	}

	if (rc != NSCD_SUCCESS) {

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to make new param data <%s : %s> current\n",
		    NSCD_STR_OR_GLOBAL(nswdb_name),
		    NSCD_STR_OR_NULL(param_name));
	}

	error_exit:

	_nscd_cfg_unlock(lock);

	return (rc);
}

nscd_rc_t
_nscd_cfg_set_linked(
	nscd_cfg_handle_t		*handle,
	void				*data,
	nscd_cfg_error_t		**errorp)
{
	char				*me = "_nscd_cfg_set_linked";
	nscd_cfg_id_t			*nswdb;
	nscd_cfg_handle_t		*hl;
	nscd_cfg_param_desc_t		*desc;
	char				*nswdb_name, *param_name, *dbl;
	nscd_rc_t			rc = NSCD_SUCCESS;
	nscd_cfg_nsw_spc_default_t	*spc;
	int				i;
	char				msg[NSCD_CFG_MAX_ERR_MSG_LEN];

	if (handle == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "handle is NULL\n");
		return (NSCD_INVALID_ARGUMENT);
	}

	nswdb = handle->nswdb;
	desc = (nscd_cfg_param_desc_t *)handle->desc;

	/*
	 * no need to do the special linking thing,
	 * if a global param, or a group, or not a linked param
	 */
	if (nswdb == NULL || _nscd_cfg_flag_is_set(desc->pflag,
	    NSCD_CFG_PFLAG_GROUP) ||
	    _nscd_cfg_flag_is_not_set(desc->pflag,
	    NSCD_CFG_PFLAG_LINKED))
		return (_nscd_cfg_set(handle, data, errorp));
	else
		nswdb_name = nswdb->name;
	param_name = desc->id.name;

	/*
	 * if a param is linked to another, it can not be
	 * changed directly
	 */
	for (i = 0; i < _nscd_cfg_num_link_default; i++) {

		if (_nscd_cfg_nsw_link_default[i].data == NULL)
			continue;

		if (strcmp(_nscd_cfg_nsw_link_default[i].db,
		    nswdb_name) == 0 &&
		    _nscd_cfg_nsw_link_default[i].group_off ==
		    desc->g_offset &&
		    _nscd_cfg_nsw_link_default[i].param_off ==
		    desc->p_offset) {

			rc = NSCD_CFG_READ_ONLY;

			(void) snprintf(msg, sizeof (msg),
			    gettext("value of \'%s\' not changeable, "
			    "change that of \'%s\' instead"),
			    nswdb->name, "passwd");

			if (errorp != NULL)
				*errorp = _nscd_cfg_make_error(rc, msg);

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "ERROR: %s\n", msg);

			return (rc);
		}
	}

	/*
	 * if a param is linked from another, it should be verify
	 * and changed first
	 */
	for (i = 0; i < _nscd_cfg_num_link_default; i++) {

		if (_nscd_cfg_nsw_link_default[i].data == NULL)
			continue;

		spc = _nscd_cfg_nsw_link_default[i].data;

		if (strcmp(spc->db, nswdb_name) == 0 &&
		    spc->group_off == desc->g_offset &&
		    spc->param_off == desc->p_offset) {

			rc = _nscd_cfg_set(handle, data, errorp);
			if (rc != NSCD_SUCCESS)
				return (rc);
			break;
		}
	}

	/*
	 * then change all those linked to the one that has been changed
	 */
	for (i = 0; i < _nscd_cfg_num_link_default; i++) {

		if (_nscd_cfg_nsw_link_default[i].data == NULL)
			continue;

		spc = _nscd_cfg_nsw_link_default[i].data;

		if (strcmp(spc->db, nswdb_name) == 0 &&
		    spc->group_off == desc->g_offset &&
		    spc->param_off == desc->p_offset &&
		    _nscd_cfg_nsw_link_default[i].group_off ==
		    desc->g_offset &&
		    _nscd_cfg_nsw_link_default[i].param_off ==
		    desc->p_offset) {

			dbl = _nscd_cfg_nsw_link_default[i].db;

			rc = _nscd_cfg_get_handle(param_name, dbl,
			    &hl, errorp);
			if (rc != NSCD_SUCCESS)
				return (rc);
			rc = _nscd_cfg_set(hl, data, errorp);
			_nscd_cfg_free_handle(hl);
			if (rc != NSCD_SUCCESS)
				return (rc);
		}
	}

	return (_nscd_cfg_set(handle, data, errorp));
}

/*
 * Return a list of comma-separated database names that
 * have at least one of the input sources (the srcs array)
 * appears in their configured nsswitch policy string.
 * That is, if srcs contains "ldap" and "passwd: files ldap"
 * "group: files ldap" are in /etc/nsswitch.conf, then
 * "passwd,group" will be returned. The return string
 * should be freed by the caller.
 *
 * For compat nsswitch configuration, "group" and/or
 * "passwd,user_attr,shadow,audit_user" (not "group_compat"
 * or "passwd_compat") will be returned. Note that the
 * user_attr, shadow, and audit_user databases share the
 * same policy with the passwd database.
 *
 * For example, if srcs has "ldap" and in /etc/nsswitch.conf,
 * there are:
 *   passwd:		compat
 *   passwd_compat:	ldap
 *   group:		compat
 *   group_compat:	ldap
 *   netgroup:		ldap
 * then "netgroup,passwd,group,user_attr,shadow,audit_user"
 * will be returned.
 */
char *
_nscd_srcs_in_db_nsw_policy(
	int			num_src,
	char			**srcs)
{
	uint8_t			i, j, n = 0, nc = 0;
	uint8_t			compat_grp = 0, compat_pwd = 0;
	uint8_t			*db;
	uint8_t			*db_compat;
	int			dlen = 0;
	nscd_cfg_nsw_db_data_t	*dbcfg;
	nscd_cfg_switch_t	*sw;
	char			*outstr = NULL;
	char			*dbname;

	db = (uint8_t *)calloc(_nscd_cfg_num_nsw_db, sizeof (uint8_t));
	if (db == NULL)
		return (NULL);

	db_compat = (uint8_t *)calloc(_nscd_cfg_num_nsw_db,
	    sizeof (uint8_t));
	if (db_compat == NULL) {
		free(db);
		return (NULL);
	}

	for (i = 0; i < _nscd_cfg_num_nsw_db; i++) {

		(void) rw_rdlock(&nscd_cfg_nsw_db_data_rwlock[i]);

		dbcfg = &nscd_cfg_nsw_db_data_current[i];
		sw = &dbcfg->sw;
		if (sw->nsw_config_string == NULL) {
			(void) rw_unlock(&nscd_cfg_nsw_db_data_rwlock[i]);
			continue;
		}

		dbname = _nscd_cfg_nsw_db[i].name;
		for (j = 0; j < num_src; j++) {
			if (strstr(sw->nsw_config_string, srcs[j]) !=
			    NULL) {
				db[n++] = i;
				dlen += strlen(dbname) + 1;
			} else if (strcmp(sw->nsw_config_string,
			    "compat") == 0) {
				if (strcmp(dbname, "passwd") == 0) {
					compat_pwd = 1;
					dlen += 7;
				} else if (strcmp(dbname, "group") == 0) {
					compat_grp = 1;
					dlen += 6;
				} else {
					db_compat[nc++] = i;
					dlen += strlen(dbname) + 1;

				}
			}
		}
		(void) rw_unlock(&nscd_cfg_nsw_db_data_rwlock[i]);
	}

	if (dlen != 0)
		outstr = (char *)calloc(1, dlen);
	if (outstr == NULL) {
		free(db_compat);
		free(db);
		return (NULL);
	}

	for (j = 0; j < n; j++) {
		dbname = _nscd_cfg_nsw_db[db[j]].name;
		if (strstr(dbname, "group_compat") != NULL) {
			if (compat_grp == 1)
				dbname = "group";
			else
				continue;
		} else if (strstr(dbname, "passwd_compat") != NULL) {
			if (compat_pwd == 1)
				dbname = "passwd";
			else
				continue;
		}

		(void) strlcat(outstr, dbname, dlen);
		(void) strlcat(outstr, ",", dlen);
	}

	for (j = 0; j < nc; j++) {
		dbname = _nscd_cfg_nsw_db[db_compat[j]].name;
		if (compat_pwd == 1) {
			(void) strlcat(outstr, dbname, dlen);
			(void) strlcat(outstr, ",", dlen);
		}
	}

	/* remove the last comma */
	i = strlen(outstr) - 1;
	if (outstr[i] == ',')
		outstr[i] = '\0';

	free(db);
	free(db_compat);
	return (outstr);

}
