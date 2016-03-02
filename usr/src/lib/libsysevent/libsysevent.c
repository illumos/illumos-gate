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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <door.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <synch.h>
#include <pthread.h>
#include <signal.h>
#include <thread.h>
#include <libnvpair.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/mnttab.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>

#include "libsysevent.h"
#include "libsysevent_impl.h"

/*
 * libsysevent - The system event framework library
 *
 *		This library provides routines to help with marshalling
 *		and unmarshalling of data contained in a sysevent event
 *		buffer.
 */

#define	SE_ENCODE_METHOD	NV_ENCODE_NATIVE

#define	dprint	if (libsysevent_debug) (void) printf
static int libsysevent_debug = 0;

static sysevent_t *se_unpack(sysevent_t *);
static int cleanup_id(sysevent_handle_t *shp, uint32_t id, int type);

/*
 * The following routines allow system event publication to the sysevent
 * framework.
 */

/*
 * sysevent_alloc - allocate a sysevent buffer
 */
static sysevent_t *
sysevent_alloc(char *class, int class_sz, char *subclass, int subclass_sz,
	char *pub, int pub_sz, nvlist_t *attr_list)
{
	int payload_sz;
	int aligned_class_sz, aligned_subclass_sz, aligned_pub_sz;
	size_t nvlist_sz = 0;
	char *attr;
	uint64_t attr_offset;
	sysevent_t *ev;

	if (attr_list != NULL) {
		if (nvlist_size(attr_list, &nvlist_sz, SE_ENCODE_METHOD)
		    != 0) {
			return (NULL);
		}
	}

	/*
	 * Calculate and reserve space for the class, subclass and
	 * publisher strings in the event buffer
	 */

	/* String sizes must be 64-bit aligned in the event buffer */
	aligned_class_sz = SE_ALIGN(class_sz);
	aligned_subclass_sz = SE_ALIGN(subclass_sz);
	aligned_pub_sz = SE_ALIGN(pub_sz);

	payload_sz = (aligned_class_sz - sizeof (uint64_t)) +
	    (aligned_subclass_sz - sizeof (uint64_t)) +
	    (aligned_pub_sz - sizeof (uint64_t)) - sizeof (uint64_t) +
	    nvlist_sz;

	/*
	 * Allocate event buffer plus additional payload overhead.
	 */
	ev = calloc(1, sizeof (sysevent_impl_t) + payload_sz);
	if (ev == NULL) {
		return (NULL);
	}

	/* Initialize the event buffer data */
	SE_VERSION(ev) = SYS_EVENT_VERSION;
	(void) bcopy(class, SE_CLASS_NAME(ev), class_sz);

	SE_SUBCLASS_OFF(ev) = SE_ALIGN(offsetof(sysevent_impl_t, se_class_name))
		+ aligned_class_sz;
	(void) bcopy(subclass, SE_SUBCLASS_NAME(ev), subclass_sz);

	SE_PUB_OFF(ev) = SE_SUBCLASS_OFF(ev) + aligned_subclass_sz;
	(void) bcopy(pub, SE_PUB_NAME(ev), pub_sz);

	SE_PAYLOAD_SZ(ev) = payload_sz;
	SE_ATTR_PTR(ev) = (uint64_t)0;

	/* Check for attribute list */
	if (attr_list == NULL) {
		return (ev);
	}

	/* Copy attribute data to contiguous memory */
	SE_FLAG(ev) = SE_PACKED_BUF;
	attr_offset = SE_ATTR_OFF(ev);
	attr = (char *)((caddr_t)ev + attr_offset);
	if (nvlist_pack(attr_list, &attr, &nvlist_sz, SE_ENCODE_METHOD,
	    0) != 0) {
		free(ev);
		return (NULL);
	}

	return (ev);
}

/*
 * sysevent_post_event - generate a system event via the sysevent framework
 */
int
sysevent_post_event(char *class, char *subclass, char *vendor, char *pub_name,
	nvlist_t *attr_list, sysevent_id_t *eid)
{
	int error;
	sysevent_t *ev;

	ev = sysevent_alloc_event(class, subclass, vendor, pub_name, attr_list);
	if (ev == NULL) {
		return (-1);
	}

	error = modctl(MODEVENTS, (uintptr_t)MODEVENTS_POST_EVENT,
	    (uintptr_t)ev, (uintptr_t)SE_SIZE(ev), (uintptr_t)eid, 0);

	sysevent_free(ev);

	if (error) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

/*
 * The following routines are used to free or duplicate a
 * sysevent event buffer.
 */

/*
 * sysevent_dup - Allocate and copy an event buffer
 *	Copies both packed and unpacked to unpacked sysevent.
 */
sysevent_t *
sysevent_dup(sysevent_t *ev)
{
	nvlist_t *nvl, *cnvl = NULL;
	uint64_t attr_offset;
	sysevent_t *copy;

	if (SE_FLAG(ev) == SE_PACKED_BUF)
		return (se_unpack(ev));

	/* Copy event header information */
	attr_offset = SE_ATTR_OFF(ev);
	copy = calloc(1, attr_offset);
	if (copy == NULL)
		return (NULL);
	bcopy(ev, copy, attr_offset);

	nvl = (nvlist_t *)(uintptr_t)SE_ATTR_PTR(ev);
	if (nvl && nvlist_dup(nvl, &cnvl, 0) != 0) {
		free(copy);
		return (NULL);
	}

	SE_ATTR_PTR(copy) = (uintptr_t)cnvl;
	SE_FLAG(copy) = 0;	/* unpacked */
	return (copy);
}

/*
 * sysevent_free - Free memory allocated for an event buffer
 */
void
sysevent_free(sysevent_t *ev)
{
	nvlist_t *attr_list = (nvlist_t *)(uintptr_t)SE_ATTR_PTR(ev);

	nvlist_free(attr_list);
	free(ev);
}

/*
 * The following routines are used to extract attribute data from a sysevent
 * handle.
 */

/*
 * sysevent_get_attr_list - allocate and return an attribute associated with
 *			the given sysevent buffer.
 */
int
sysevent_get_attr_list(sysevent_t *ev, nvlist_t **nvlist)
{
	int error;
	caddr_t attr;
	size_t attr_len;
	uint64_t attr_offset;
	nvlist_t *nvl;

	*nvlist = NULL;

	/* Duplicate attribute for an unpacked sysevent buffer */
	if (SE_FLAG(ev) != SE_PACKED_BUF) {
		nvl = (nvlist_t *)(uintptr_t)SE_ATTR_PTR(ev);
		if (nvl == NULL) {
			return (0);
		}
		if ((error = nvlist_dup(nvl, nvlist, 0)) != 0) {
			if (error == ENOMEM) {
				errno = error;
			} else {
				errno = EINVAL;
			}
			return (-1);
		}
		return (0);
	}

	attr_offset = SE_ATTR_OFF(ev);
	if (SE_SIZE(ev) == attr_offset) {
		return (0);
	}

	/* unpack nvlist */
	attr = (caddr_t)ev + attr_offset;
	attr_len = SE_SIZE(ev) - attr_offset;
	if ((error = nvlist_unpack(attr, attr_len, nvlist, 0)) != 0) {
		if (error == ENOMEM) {
			errno = error;
		} else 	{
			errno = EINVAL;
		}
		return (-1);
	}

	return (0);
}

/*
 * sysevent_attr_name - Get name of attribute
 */
char *
sysevent_attr_name(sysevent_attr_t *attr)
{
	if (attr == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return (nvpair_name((nvpair_t *)attr));
}

/*
 * sysevent_attr_value - Get attribute value data and type
 */
int
sysevent_attr_value(sysevent_attr_t *attr, sysevent_value_t *se_value)
{
	nvpair_t *nvp = attr;

	if (nvp == NULL)
		return (EINVAL);

	/* Convert DATA_TYPE_* to SE_DATA_TYPE_* */
	switch (nvpair_type(nvp)) {
	case DATA_TYPE_BYTE:
		se_value->value_type = SE_DATA_TYPE_BYTE;
		(void) nvpair_value_byte(nvp, &se_value->value.sv_byte);
		break;
	case DATA_TYPE_INT16:
		se_value->value_type = SE_DATA_TYPE_INT16;
		(void) nvpair_value_int16(nvp, &se_value->value.sv_int16);
		break;
	case DATA_TYPE_UINT16:
		se_value->value_type = SE_DATA_TYPE_UINT16;
		(void) nvpair_value_uint16(nvp, &se_value->value.sv_uint16);
		break;
	case DATA_TYPE_INT32:
		se_value->value_type = SE_DATA_TYPE_INT32;
		(void) nvpair_value_int32(nvp, &se_value->value.sv_int32);
		break;
	case DATA_TYPE_UINT32:
		se_value->value_type = SE_DATA_TYPE_UINT32;
		(void) nvpair_value_uint32(nvp, &se_value->value.sv_uint32);
		break;
	case DATA_TYPE_INT64:
		se_value->value_type = SE_DATA_TYPE_INT64;
		(void) nvpair_value_int64(nvp, &se_value->value.sv_int64);
		break;
	case DATA_TYPE_UINT64:
		se_value->value_type = SE_DATA_TYPE_UINT64;
		(void) nvpair_value_uint64(nvp, &se_value->value.sv_uint64);
		break;
	case DATA_TYPE_STRING:
		se_value->value_type = SE_DATA_TYPE_STRING;
		(void) nvpair_value_string(nvp, &se_value->value.sv_string);
		break;
	case DATA_TYPE_BYTE_ARRAY:
		se_value->value_type = SE_DATA_TYPE_BYTES;
		(void) nvpair_value_byte_array(nvp,
		    &se_value->value.sv_bytes.data,
		    (uint_t *)&se_value->value.sv_bytes.size);
		break;
	case DATA_TYPE_HRTIME:
		se_value->value_type = SE_DATA_TYPE_TIME;
		(void) nvpair_value_hrtime(nvp, &se_value->value.sv_time);
		break;
	default:
		return (ENOTSUP);
	}
	return (0);
}

/*
 * sysevent_attr_next - Get next attribute in event attribute list
 */
sysevent_attr_t *
sysevent_attr_next(sysevent_t *ev, sysevent_attr_t *attr)
{
	nvlist_t *nvl;
	nvpair_t *nvp = attr;

	/* all user visible sysevent_t's are unpacked */
	assert(SE_FLAG(ev) != SE_PACKED_BUF);

	if (SE_ATTR_PTR(ev) == (uint64_t)0) {
		return (NULL);
	}

	nvl = (nvlist_t *)(uintptr_t)SE_ATTR_PTR(ev);
	return (nvlist_next_nvpair(nvl, nvp));
}

/*
 * sysevent_lookup_attr - Lookup attribute by name and datatype.
 */
int
sysevent_lookup_attr(sysevent_t *ev, char *name, int datatype,
	sysevent_value_t *se_value)
{
	nvpair_t *nvp;
	nvlist_t *nvl;

	assert(SE_FLAG(ev) != SE_PACKED_BUF);

	if (SE_ATTR_PTR(ev) == (uint64_t)0) {
		return (ENOENT);
	}

	/*
	 * sysevent matches on both name and datatype
	 * nvlist_look mataches name only. So we walk
	 * nvlist manually here.
	 */
	nvl = (nvlist_t *)(uintptr_t)SE_ATTR_PTR(ev);
	nvp = nvlist_next_nvpair(nvl, NULL);
	while (nvp) {
		if ((strcmp(name, nvpair_name(nvp)) == 0) &&
		    (sysevent_attr_value(nvp, se_value) == 0) &&
		    (se_value->value_type == datatype))
			return (0);
		nvp = nvlist_next_nvpair(nvl, nvp);
	}
	return (ENOENT);
}

/* Routines to extract event header information */

/*
 * sysevent_get_class - Get class id
 */
int
sysevent_get_class(sysevent_t *ev)
{
	return (SE_CLASS(ev));
}

/*
 * sysevent_get_subclass - Get subclass id
 */
int
sysevent_get_subclass(sysevent_t *ev)
{
	return (SE_SUBCLASS(ev));
}

/*
 * sysevent_get_class_name - Get class name string
 */
char *
sysevent_get_class_name(sysevent_t *ev)
{
	return (SE_CLASS_NAME(ev));
}

typedef enum {
	PUB_VEND,
	PUB_KEYWD,
	PUB_NAME,
	PUB_PID
} se_pub_id_t;

/*
 * sysevent_get_pub - Get publisher name string
 */
char *
sysevent_get_pub(sysevent_t *ev)
{
	return (SE_PUB_NAME(ev));
}

/*
 * Get the requested string pointed by the token.
 *
 * Return NULL if not found or for insufficient memory.
 */
static char *
parse_pub_id(sysevent_t *ev, se_pub_id_t token)
{
	int i;
	char *pub_id, *pub_element, *str, *next;

	next = pub_id = strdup(sysevent_get_pub(ev));
	for (i = 0; i <= token; ++i) {
		str = strtok_r(next, ":", &next);
		if (str == NULL) {
			free(pub_id);
			return (NULL);
		}
	}

	pub_element = strdup(str);
	free(pub_id);
	return (pub_element);
}

/*
 * Return a pointer to the string following the token
 *
 * Note: This is a dedicated function for parsing
 * publisher strings and not for general purpose.
 */
static const char *
pub_idx(const char *pstr, int token)
{
	int i;

	for (i = 1; i <= token; i++) {
		if ((pstr = index(pstr, ':')) == NULL)
			return (NULL);
		pstr++;
	}

	/* String might be empty */
	if (pstr) {
		if (*pstr == '\0' || *pstr == ':')
			return (NULL);
	}
	return (pstr);
}

char *
sysevent_get_vendor_name(sysevent_t *ev)
{
	return (parse_pub_id(ev, PUB_VEND));
}

char *
sysevent_get_pub_name(sysevent_t *ev)
{
	return (parse_pub_id(ev, PUB_NAME));
}

/*
 * Provide the pid encoded in the publisher string
 * w/o allocating any resouces.
 */
void
sysevent_get_pid(sysevent_t *ev, pid_t *pid)
{
	const char *part_str;
	const char *pub_str = sysevent_get_pub(ev);

	*pid = (pid_t)SE_KERN_PID;

	part_str = pub_idx(pub_str, PUB_KEYWD);
	if (part_str != NULL && strstr(part_str, SE_KERN_PUB) != NULL)
		return;

	if ((part_str = pub_idx(pub_str, PUB_PID)) == NULL)
		return;

	*pid = (pid_t)atoi(part_str);
}

/*
 * sysevent_get_subclass_name - Get subclass name string
 */
char *
sysevent_get_subclass_name(sysevent_t *ev)
{
	return (SE_SUBCLASS_NAME(ev));
}

/*
 * sysevent_get_seq - Get event sequence id
 */
uint64_t
sysevent_get_seq(sysevent_t *ev)
{
	return (SE_SEQ(ev));
}

/*
 * sysevent_get_time - Get event timestamp
 */
void
sysevent_get_time(sysevent_t *ev, hrtime_t *etime)
{
	*etime = SE_TIME(ev);
}

/*
 * sysevent_get_size - Get event buffer size
 */
size_t
sysevent_get_size(sysevent_t *ev)
{
	return ((size_t)SE_SIZE(ev));
}

/*
 * The following routines are used by devfsadm_mod.c to propagate event
 * buffers to devfsadmd.  These routines will serve as the basis for
 * event channel publication and subscription.
 */

/*
 * sysevent_alloc_event -
 *	allocate a sysevent buffer for sending through an established event
 *	channel.
 */
sysevent_t *
sysevent_alloc_event(char *class, char *subclass, char *vendor, char *pub_name,
	nvlist_t *attr_list)
{
	int class_sz, subclass_sz, pub_sz;
	char *pub_id;
	sysevent_t *ev;

	if ((class == NULL) || (subclass == NULL) || (vendor == NULL) ||
	    (pub_name == NULL)) {
		errno = EINVAL;
		return (NULL);
	}

	class_sz = strlen(class) + 1;
	subclass_sz = strlen(subclass) + 1;
	if ((class_sz > MAX_CLASS_LEN) ||
	    (subclass_sz > MAX_SUBCLASS_LEN)) {
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * Calculate the publisher size plus string seperators and maximum
	 * pid characters
	 */
	pub_sz = strlen(vendor) + sizeof (SE_USR_PUB) + strlen(pub_name) + 14;
	if (pub_sz > MAX_PUB_LEN) {
		errno = EINVAL;
		return (NULL);
	}
	pub_id = malloc(pub_sz);
	if (pub_id == NULL) {
		errno = ENOMEM;
		return (NULL);
	}
	if (snprintf(pub_id, pub_sz, "%s:%s%s:%d", vendor, SE_USR_PUB,
	    pub_name, (int)getpid()) >= pub_sz) {
		free(pub_id);
		errno = EINVAL;
		return (NULL);
	}
	pub_sz = strlen(pub_id) + 1;

	ev = sysevent_alloc(class, class_sz, subclass, subclass_sz,
	    pub_id, pub_sz, attr_list);
	free(pub_id);
	if (ev == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	return (ev);
}

/*
 * se_unpack - unpack nvlist to a searchable list.
 *	If already unpacked, will do a dup.
 */
static sysevent_t *
se_unpack(sysevent_t *ev)
{
	caddr_t attr;
	size_t attr_len;
	nvlist_t *attrp = NULL;
	uint64_t attr_offset;
	sysevent_t *copy;

	assert(SE_FLAG(ev) == SE_PACKED_BUF);

	/* Copy event header information */
	attr_offset = SE_ATTR_OFF(ev);
	copy = calloc(1, attr_offset);
	if (copy == NULL)
		return (NULL);
	bcopy(ev, copy, attr_offset);
	SE_FLAG(copy) = 0;	/* unpacked */

	/* unpack nvlist */
	attr = (caddr_t)ev + attr_offset;
	attr_len = SE_SIZE(ev) - attr_offset;
	if (attr_len == 0) {
		return (copy);
	}
	if (nvlist_unpack(attr, attr_len, &attrp, 0) != 0) {
		free(copy);
		return (NULL);
	}

	SE_ATTR_PTR(copy) = (uintptr_t)attrp;
	return (copy);
}

/*
 * se_print - Prints elements in an event buffer
 */
void
se_print(FILE *fp, sysevent_t *ev)
{
	char *vendor, *pub;
	pid_t pid;
	hrtime_t hrt;
	nvlist_t *attr_list = NULL;

	(void) sysevent_get_time(ev, &hrt);
	(void) fprintf(fp, "received sysevent id = 0X%llx:%llx\n",
	    hrt, (longlong_t)sysevent_get_seq(ev));
	(void) fprintf(fp, "\tclass = %s\n", sysevent_get_class_name(ev));
	(void) fprintf(fp, "\tsubclass = %s\n", sysevent_get_subclass_name(ev));
	if ((vendor =  sysevent_get_vendor_name(ev)) != NULL) {
		(void) fprintf(fp, "\tvendor = %s\n", vendor);
		free(vendor);
	}
	if ((pub = sysevent_get_pub_name(ev)) != NULL) {
		sysevent_get_pid(ev, &pid);
		(void) fprintf(fp, "\tpublisher = %s:%d\n", pub, (int)pid);
		free(pub);
	}

	if (sysevent_get_attr_list(ev, &attr_list) == 0 && attr_list != NULL) {
		nvlist_print(fp, attr_list);
		nvlist_free(attr_list);
	}
}

/*
 * The following routines are provided to support establishment and use
 * of sysevent channels.  A sysevent channel is established between
 * publishers and subscribers of sysevents for an agreed upon channel name.
 * These routines currently support sysevent channels between user-level
 * applications running on the same system.
 *
 * Sysevent channels may be created by a single publisher or subscriber process.
 * Once established, up to MAX_SUBSRCIBERS subscribers may subscribe interest in
 * receiving sysevent notifications on the named channel.  At present, only
 * one publisher is allowed per sysevent channel.
 *
 * The registration information for each channel is kept in the kernel.  A
 * kernel-based registration was chosen for persistence and reliability reasons.
 * If either a publisher or a subscriber exits for any reason, the channel
 * properties are maintained until all publishers and subscribers have exited.
 * Additionally, an in-kernel registration allows the API to be extended to
 * include kernel subscribers as well as userland subscribers in the future.
 *
 * To insure fast lookup of subscriptions, a cached copy of the registration
 * is kept and maintained for the publisher process.  Updates are made
 * everytime a change is made in the kernel.  Changes to the registration are
 * expected to be infrequent.
 *
 * Channel communication between publisher and subscriber processes is
 * implemented primarily via doors.  Each publisher creates a door for
 * registration notifications and each subscriber creates a door for event
 * delivery.
 *
 * Most of these routines are used by syseventd(1M), the sysevent publisher
 * for the syseventd channel.  Processes wishing to receive sysevent
 * notifications from syseventd may use a set of public
 * APIs designed to subscribe to syseventd sysevents.  The subscription
 * APIs are implemented in accordance with PSARC/2001/076.
 *
 */

/*
 * Door handlers for the channel subscribers
 */

/*
 * subscriber_event_handler - generic event handling wrapper for subscribers
 *			This handler is used to process incoming sysevent
 *			notifications from channel publishers.
 *			It is created as a seperate thread in each subscriber
 *			process per subscription.
 */
static void
subscriber_event_handler(sysevent_handle_t *shp)
{
	subscriber_priv_t *sub_info;
	sysevent_queue_t *evqp;

	sub_info = (subscriber_priv_t *)SH_PRIV_DATA(shp);

	/* See hack alert in sysevent_bind_subscriber_cmn */
	if (sub_info->sp_handler_tid == NULL)
		sub_info->sp_handler_tid = thr_self();

	(void) mutex_lock(&sub_info->sp_qlock);
	for (;;) {
		while (sub_info->sp_evq_head == NULL && SH_BOUND(shp)) {
			(void) cond_wait(&sub_info->sp_cv, &sub_info->sp_qlock);
		}
		evqp = sub_info->sp_evq_head;
		while (evqp) {
			(void) mutex_unlock(&sub_info->sp_qlock);
			(void) sub_info->sp_func(evqp->sq_ev);
			(void) mutex_lock(&sub_info->sp_qlock);
			sub_info->sp_evq_head = sub_info->sp_evq_head->sq_next;
			free(evqp->sq_ev);
			free(evqp);
			evqp = sub_info->sp_evq_head;
		}
		if (!SH_BOUND(shp)) {
			(void) mutex_unlock(&sub_info->sp_qlock);
			return;
		}
	}

	/* NOTREACHED */
}

/*
 * Data structure used to communicate event subscription cache updates
 * to publishers via a registration door
 */
struct reg_args {
	uint32_t ra_sub_id;
	uint32_t ra_op;
	uint64_t ra_buf_ptr;
};


/*
 * event_deliver_service - generic event delivery service routine.  This routine
 *		is called in response to a door call to post an event.
 *
 */
/*ARGSUSED*/
static void
event_deliver_service(void *cookie, char *args, size_t alen,
    door_desc_t *ddp, uint_t ndid)
{
	int	ret = 0;
	subscriber_priv_t *sub_info;
	sysevent_handle_t *shp;
	sysevent_queue_t *new_eq;

	if (args == NULL || alen < sizeof (uint32_t)) {
		ret = EINVAL;
		goto return_from_door;
	}

	/* Publisher checking on subscriber */
	if (alen == sizeof (uint32_t)) {
		ret = 0;
		goto return_from_door;
	}

	shp = (sysevent_handle_t *)cookie;
	if (shp == NULL) {
		ret = EBADF;
		goto return_from_door;
	}

	/*
	 * Mustn't block if we are trying to update the registration with
	 * the publisher
	 */
	if (mutex_trylock(SH_LOCK(shp)) != 0) {
		ret = EAGAIN;
		goto return_from_door;
	}

	if (!SH_BOUND(shp)) {
		ret = EBADF;
		(void) mutex_unlock(SH_LOCK(shp));
		goto return_from_door;
	}

	sub_info = (subscriber_priv_t *)SH_PRIV_DATA(shp);
	if (sub_info == NULL) {
		ret = EBADF;
		(void) mutex_unlock(SH_LOCK(shp));
		goto return_from_door;
	}

	new_eq = (sysevent_queue_t *)calloc(1,
	    sizeof (sysevent_queue_t));
	if (new_eq == NULL) {
		ret = EAGAIN;
		(void) mutex_unlock(SH_LOCK(shp));
		goto return_from_door;
	}

	/*
	 * Allocate and copy the event buffer into the subscriber's
	 * address space
	 */
	new_eq->sq_ev = calloc(1, alen);
	if (new_eq->sq_ev == NULL) {
		free(new_eq);
		ret = EAGAIN;
		(void) mutex_unlock(SH_LOCK(shp));
		goto return_from_door;
	}
	(void) bcopy(args, new_eq->sq_ev, alen);

	(void) mutex_lock(&sub_info->sp_qlock);
	if (sub_info->sp_evq_head == NULL) {
		sub_info->sp_evq_head = new_eq;
	} else {
		sub_info->sp_evq_tail->sq_next = new_eq;
	}
	sub_info->sp_evq_tail = new_eq;

	(void) cond_signal(&sub_info->sp_cv);
	(void) mutex_unlock(&sub_info->sp_qlock);
	(void) mutex_unlock(SH_LOCK(shp));

return_from_door:
	(void) door_return((void *)&ret, sizeof (ret), NULL, 0);
	(void) door_return(NULL, 0, NULL, 0);
}

/*
 * Sysevent subscription information is maintained in the kernel.  Updates
 * to the in-kernel registration database is expected to be infrequent and
 * offers consistency for publishers and subscribers that may come and go
 * for a given channel.
 *
 * To expedite registration lookups by publishers, a cached copy of the
 * kernel registration database is kept per-channel.  Caches are invalidated
 * and refreshed upon state changes to the in-kernel registration database.
 *
 * To prevent stale subscriber data, publishers may remove subsriber
 * registrations from the in-kernel registration database in the event
 * that a particular subscribing process is unresponsive.
 *
 * The following routines provide a mechanism to update publisher and subscriber
 * information for a specified channel.
 */

/*
 * clnt_deliver_event - Deliver an event through the consumer's event
 *			delivery door
 *
 * Returns -1 if message not delivered. With errno set to cause of error.
 * Returns 0 for success with the results returned in posting buffer.
 */
static int
clnt_deliver_event(int service_door, void *data, size_t datalen,
	void *result, size_t rlen)
{
	int error = 0;
	door_arg_t door_arg;

	door_arg.rbuf = result;
	door_arg.rsize = rlen;
	door_arg.data_ptr = data;
	door_arg.data_size = datalen;
	door_arg.desc_ptr = NULL;
	door_arg.desc_num = 0;

	/*
	 * Make door call
	 */
	while ((error = door_call(service_door, &door_arg)) != 0) {
		if (errno == EAGAIN || errno == EINTR) {
			continue;
		} else {
			error = errno;
			break;
		}
	}

	return (error);
}

static int
update_publisher_cache(subscriber_priv_t *sub_info, int update_op,
	uint32_t sub_id, size_t datasz, uchar_t *data)
{
	int pub_fd;
	uint32_t result = 0;
	struct reg_args *rargs;

	rargs = (struct reg_args *)calloc(1, sizeof (struct reg_args) +
	    datasz);
	if (rargs == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	rargs->ra_sub_id = sub_id;
	rargs->ra_op = update_op;
	bcopy(data, (char *)&rargs->ra_buf_ptr, datasz);

	pub_fd = open(sub_info->sp_door_name, O_RDONLY);
	(void) clnt_deliver_event(pub_fd, (void *)rargs,
	    sizeof (struct reg_args) + datasz, &result, sizeof (result));
	(void) close(pub_fd);

	free(rargs);
	if (result != 0) {
		errno = result;
		return (-1);
	}

	return (0);
}


/*
 * update_kernel_registration - update the in-kernel registration for the
 * given channel.
 */
static int
update_kernel_registration(sysevent_handle_t *shp, int update_type,
	int update_op, uint32_t *sub_id, size_t datasz, uchar_t *data)
{
	int error;
	char *channel_name = SH_CHANNEL_NAME(shp);
	se_pubsub_t udata;

	udata.ps_channel_name_len = strlen(channel_name) + 1;
	udata.ps_op = update_op;
	udata.ps_type = update_type;
	udata.ps_buflen = datasz;
	udata.ps_id = *sub_id;

	if ((error = modctl(MODEVENTS, (uintptr_t)MODEVENTS_REGISTER_EVENT,
	    (uintptr_t)channel_name, (uintptr_t)data, (uintptr_t)&udata, 0))
	    != 0) {
		return (error);
	}

	*sub_id = udata.ps_id;

	return (error);
}

/*
 * get_kernel_registration - get the current subscriber registration for
 * the given channel
 */
static nvlist_t *
get_kernel_registration(char *channel_name, uint32_t class_id)
{
	char *nvlbuf;
	nvlist_t *nvl;
	se_pubsub_t udata;

	nvlbuf = calloc(1, MAX_SUBSCRIPTION_SZ);
	if (nvlbuf == NULL) {
		return (NULL);
	}

	udata.ps_buflen = MAX_SUBSCRIPTION_SZ;
	udata.ps_channel_name_len = strlen(channel_name) + 1;
	udata.ps_id = class_id;
	udata.ps_op = SE_GET_REGISTRATION;
	udata.ps_type = PUBLISHER;

	if (modctl(MODEVENTS, (uintptr_t)MODEVENTS_REGISTER_EVENT,
	    (uintptr_t)channel_name, (uintptr_t)nvlbuf, (uintptr_t)&udata, 0)
	    != 0) {

		/* Need a bigger buffer to hold channel registration */
		if (errno == EAGAIN) {
			free(nvlbuf);
			nvlbuf = calloc(1, udata.ps_buflen);
			if (nvlbuf == NULL)
				return (NULL);

			/* Try again */
			if (modctl(MODEVENTS,
			    (uintptr_t)MODEVENTS_REGISTER_EVENT,
			    (uintptr_t)channel_name, (uintptr_t)nvlbuf,
			    (uintptr_t)&udata, 0) != 0) {
				free(nvlbuf);
				return (NULL);
			}
		} else {
			free(nvlbuf);
			return (NULL);
		}
	}

	if (nvlist_unpack(nvlbuf, udata.ps_buflen, &nvl, 0) != 0) {
		free(nvlbuf);
		return (NULL);
	}
	free(nvlbuf);

	return (nvl);
}

/*
 * The following routines provide a mechanism for publishers to maintain
 * subscriber information.
 */

static void
dealloc_subscribers(sysevent_handle_t *shp)
{
	int i;
	subscriber_data_t *sub;

	for (i = 1; i <= MAX_SUBSCRIBERS; ++i) {
		sub = SH_SUBSCRIBER(shp, i);
		if (sub != NULL) {
			free(sub->sd_door_name);
			free(sub);
		}
		SH_SUBSCRIBER(shp, i) = NULL;
	}
}

/*ARGSUSED*/
static int
alloc_subscriber(sysevent_handle_t *shp, uint32_t sub_id, int oflag)
{
	subscriber_data_t *sub;
	char door_name[MAXPATHLEN];

	if (SH_SUBSCRIBER(shp, sub_id) != NULL) {
		return (0);
	}

	/* Allocate and initialize the subscriber data */
	sub = (subscriber_data_t *)calloc(1,
	    sizeof (subscriber_data_t));
	if (sub == NULL) {
		return (-1);
	}
	if (snprintf(door_name, MAXPATHLEN, "%s/%d",
	    SH_CHANNEL_PATH(shp), sub_id) >= MAXPATHLEN) {
		free(sub);
		return (-1);
	}

	sub->sd_flag = ACTIVE;
	sub->sd_door_name = strdup(door_name);
	if (sub->sd_door_name == NULL) {
		free(sub);
		return (-1);
	}

	SH_SUBSCRIBER(shp, sub_id) = sub;
	return (0);

}

/*
 * The following routines are used to update and maintain the registration cache
 * for a particular sysevent channel.
 */

static uint32_t
hash_func(const char *s)
{
	uint32_t result = 0;
	uint_t g;

	while (*s != '\0') {
		result <<= 4;
		result += (uint32_t)*s++;
		g = result & 0xf0000000;
		if (g != 0) {
			result ^= g >> 24;
			result ^= g;
		}
	}

	return (result);
}

subclass_lst_t *
cache_find_subclass(class_lst_t *c_list, char *subclass)
{
	subclass_lst_t *sc_list;

	if (c_list == NULL)
		return (NULL);

	sc_list = c_list->cl_subclass_list;

	while (sc_list != NULL) {
		if (strcmp(sc_list->sl_name, subclass) == 0) {
			return (sc_list);
		}
		sc_list = sc_list->sl_next;
	}

	return (NULL);
}


static class_lst_t *
cache_find_class(sysevent_handle_t *shp, char *class)
{
	int index;
	class_lst_t *c_list;
	class_lst_t **class_hash = SH_CLASS_HASH(shp);

	if (strcmp(class, EC_ALL) == 0) {
		return (class_hash[0]);
	}

	index = CLASS_HASH(class);
	c_list = class_hash[index];
	while (c_list != NULL) {
		if (strcmp(class, c_list->cl_name) == 0) {
			break;
		}
		c_list = c_list->cl_next;
	}

	return (c_list);
}

static int
cache_insert_subclass(class_lst_t *c_list, char **subclass_names,
	int subclass_num, uint32_t sub_id)
{
	int i;
	subclass_lst_t *sc_list;

	for (i = 0; i < subclass_num; ++i) {
		if ((sc_list = cache_find_subclass(c_list, subclass_names[i]))
		    != NULL) {
			sc_list->sl_num[sub_id] = 1;
		} else {
			sc_list = (subclass_lst_t *)calloc(1,
			    sizeof (subclass_lst_t));
			if (sc_list == NULL)
				return (-1);

			sc_list->sl_name = strdup(subclass_names[i]);
			if (sc_list->sl_name == NULL) {
				free(sc_list);
				return (-1);
			}

			sc_list->sl_num[sub_id] = 1;
			sc_list->sl_next = c_list->cl_subclass_list;
			c_list->cl_subclass_list = sc_list;
		}
	}

	return (0);
}

static int
cache_insert_class(sysevent_handle_t *shp, char *class,
	char **subclass_names, int subclass_num, uint32_t sub_id)
{
	class_lst_t *c_list;

	if (strcmp(class, EC_ALL) == 0) {
		char *subclass_all = EC_SUB_ALL;

		(void) cache_insert_subclass(SH_CLASS_HASH(shp)[0],
		    (char **)&subclass_all, 1, sub_id);
		return (0);
	}

	/* New class, add to the registration cache */
	if ((c_list = cache_find_class(shp, class)) == NULL) {

		c_list = (class_lst_t *)calloc(1, sizeof (class_lst_t));
		if (c_list == NULL) {
			return (1);
		}
		c_list->cl_name = strdup(class);
		if (c_list->cl_name == NULL) {
			free(c_list);
			return (1);
		}

		c_list->cl_subclass_list = (subclass_lst_t *)
		    calloc(1, sizeof (subclass_lst_t));
		if (c_list->cl_subclass_list == NULL) {
			free(c_list->cl_name);
			free(c_list);
			return (1);
		}
		c_list->cl_subclass_list->sl_name = strdup(EC_SUB_ALL);
		if (c_list->cl_subclass_list->sl_name == NULL) {
			free(c_list->cl_subclass_list);
			free(c_list->cl_name);
			free(c_list);
			return (1);
		}
		c_list->cl_next = SH_CLASS_HASH(shp)[CLASS_HASH(class)];
		SH_CLASS_HASH(shp)[CLASS_HASH(class)] = c_list;

	}

	/* Update the subclass list */
	if (cache_insert_subclass(c_list, subclass_names, subclass_num,
	    sub_id) != 0)
		return (1);

	return (0);
}

static void
cache_remove_all_class(sysevent_handle_t *shp, uint32_t sub_id)
{
	int i;
	class_lst_t *c_list;
	subclass_lst_t *sc_list;

	for (i = 0; i < CLASS_HASH_SZ + 1; ++i) {
		c_list = SH_CLASS_HASH(shp)[i];
		while (c_list != NULL) {
			sc_list = c_list->cl_subclass_list;
			while (sc_list != NULL) {
				sc_list->sl_num[sub_id] = 0;
				sc_list = sc_list->sl_next;
			}
			c_list = c_list->cl_next;
		}
	}
}

static void
cache_remove_class(sysevent_handle_t *shp, char *class, uint32_t sub_id)
{
	class_lst_t *c_list;
	subclass_lst_t *sc_list;

	if (strcmp(class, EC_ALL) == 0) {
		cache_remove_all_class(shp, sub_id);
		return;
	}

	if ((c_list = cache_find_class(shp, class)) == NULL) {
		return;
	}

	sc_list = c_list->cl_subclass_list;
	while (sc_list != NULL) {
		sc_list->sl_num[sub_id] = 0;
		sc_list = sc_list->sl_next;
	}
}

static void
free_cached_registration(sysevent_handle_t *shp)
{
	int i;
	class_lst_t *clist, *next_clist;
	subclass_lst_t *sc_list, *next_sc;

	for (i = 0; i < CLASS_HASH_SZ + 1; i++) {
		clist = SH_CLASS_HASH(shp)[i];
		while (clist != NULL) {
			sc_list = clist->cl_subclass_list;
			while (sc_list != NULL) {
				free(sc_list->sl_name);
				next_sc = sc_list->sl_next;
				free(sc_list);
				sc_list = next_sc;
			}
			free(clist->cl_name);
			next_clist = clist->cl_next;
			free(clist);
			clist = next_clist;
		}
		SH_CLASS_HASH(shp)[i] = NULL;
	}
}

static int
create_cached_registration(sysevent_handle_t *shp,
	class_lst_t **class_hash)
{
	int i, j, new_class;
	char *class_name;
	uint_t num_elem;
	uchar_t *subscribers;
	nvlist_t *nvl;
	nvpair_t *nvpair;
	class_lst_t *clist;
	subclass_lst_t *sc_list;

	for (i = 0; i < CLASS_HASH_SZ + 1; ++i) {

		if ((nvl = get_kernel_registration(SH_CHANNEL_NAME(shp), i))
		    == NULL) {
			if (errno == ENOENT) {
				class_hash[i] = NULL;
				continue;
			} else {
				goto create_failed;
			}
		}


		nvpair = NULL;
		if ((nvpair = nvlist_next_nvpair(nvl, nvpair)) == NULL) {
			goto create_failed;
		}

		new_class = 1;
		while (new_class) {
			/* Extract the class name from the nvpair */
			if (nvpair_value_string(nvpair, &class_name) != 0) {
				goto create_failed;
			}
			clist = (class_lst_t *)
			    calloc(1, sizeof (class_lst_t));
			if (clist == NULL) {
				goto create_failed;
			}

			clist->cl_name = strdup(class_name);
			if (clist->cl_name == NULL) {
				free(clist);
				goto create_failed;
			}

			/*
			 * Extract the subclass name and registration
			 * from the nvpair
			 */
			if ((nvpair = nvlist_next_nvpair(nvl, nvpair))
			    == NULL) {
				free(clist->cl_name);
				free(clist);
				goto create_failed;
			}

			clist->cl_next = class_hash[i];
			class_hash[i] = clist;

			for (;;) {

				sc_list = (subclass_lst_t *)calloc(1,
				    sizeof (subclass_lst_t));
				if (sc_list == NULL) {
					goto create_failed;
				}

				sc_list->sl_next = clist->cl_subclass_list;
				clist->cl_subclass_list = sc_list;

				sc_list->sl_name = strdup(nvpair_name(nvpair));
				if (sc_list->sl_name == NULL) {
					goto create_failed;
				}

				if (nvpair_value_byte_array(nvpair,
				    &subscribers, &num_elem) != 0) {
					goto create_failed;
				}
				bcopy(subscribers, (uchar_t *)sc_list->sl_num,
				    MAX_SUBSCRIBERS + 1);

				for (j = 1; j <= MAX_SUBSCRIBERS; ++j) {
					if (sc_list->sl_num[j] == 0)
						continue;

					if (alloc_subscriber(shp, j, 1) != 0) {
						goto create_failed;
					}
				}

				/*
				 * Check next nvpair - either subclass or
				 * class
				 */
				if ((nvpair = nvlist_next_nvpair(nvl, nvpair))
				    == NULL) {
					new_class = 0;
					break;
				} else if (strcmp(nvpair_name(nvpair),
				    CLASS_NAME) == 0) {
					break;
				}
			}
		}
		nvlist_free(nvl);
	}
	return (0);

create_failed:
	dealloc_subscribers(shp);
	free_cached_registration(shp);
	nvlist_free(nvl);
	return (-1);

}

/*
 * cache_update_service - generic event publisher service routine.  This routine
 *		is called in response to a registration cache update.
 *
 */
/*ARGSUSED*/
static void
cache_update_service(void *cookie, char *args, size_t alen,
    door_desc_t *ddp, uint_t ndid)
{
	int ret = 0;
	uint_t num_elem;
	char *class, **event_list;
	size_t datalen;
	uint32_t sub_id;
	nvlist_t *nvl;
	nvpair_t *nvpair = NULL;
	struct reg_args *rargs;
	sysevent_handle_t *shp;
	subscriber_data_t *sub;

	if (alen < sizeof (struct reg_args) || cookie == NULL) {
		ret = EINVAL;
		goto return_from_door;
	}

	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	rargs = (struct reg_args *)args;
	shp = (sysevent_handle_t *)cookie;

	datalen = alen - sizeof (struct reg_args);
	sub_id = rargs->ra_sub_id;

	(void) mutex_lock(SH_LOCK(shp));

	switch (rargs->ra_op) {
	case SE_UNREGISTER:
		class = (char *)&rargs->ra_buf_ptr;
		cache_remove_class(shp, (char *)class,
		    sub_id);
		break;
	case SE_UNBIND_REGISTRATION:

		sub = SH_SUBSCRIBER(shp, sub_id);
		if (sub == NULL)
			break;

		free(sub->sd_door_name);
		free(sub);
		cache_remove_class(shp, EC_ALL, sub_id);
		SH_SUBSCRIBER(shp, sub_id) = NULL;

		break;
	case SE_BIND_REGISTRATION:

		/* New subscriber */
		if (alloc_subscriber(shp, sub_id, 0) != 0) {
			ret = ENOMEM;
			break;
		}
		break;
	case SE_REGISTER:

		if (SH_SUBSCRIBER(shp, sub_id) == NULL) {
			ret = EINVAL;
			break;
		}
		/* Get new registration data */
		if (nvlist_unpack((char *)&rargs->ra_buf_ptr, datalen,
		    &nvl, 0) != 0) {
			ret =  EFAULT;
			break;
		}
		if ((nvpair = nvlist_next_nvpair(nvl, nvpair)) == NULL) {
			nvlist_free(nvl);
			ret = EFAULT;
			break;
		}
		if (nvpair_value_string_array(nvpair, &event_list, &num_elem)
		    != 0) {
			nvlist_free(nvl);
			ret =  EFAULT;
			break;
		}
		class = nvpair_name(nvpair);

		ret = cache_insert_class(shp, class,
		    event_list, num_elem, sub_id);
		if (ret != 0) {
			cache_remove_class(shp, class, sub_id);
			nvlist_free(nvl);
			ret =  EFAULT;
			break;
		}

		nvlist_free(nvl);

		break;
	case SE_CLEANUP:
		/* Cleanup stale subscribers */
		sysevent_cleanup_subscribers(shp);
		break;
	default:
		ret =  EINVAL;
	}

	(void) mutex_unlock(SH_LOCK(shp));

return_from_door:
	(void) door_return((void *)&ret, sizeof (ret), NULL, 0);
	(void) door_return(NULL, 0, NULL, 0);
}

/*
 * sysevent_send_event -
 * Send an event via the communication channel associated with the sysevent
 * handle.  Event notifications are broadcast to all subscribers based upon
 * the event class and subclass.  The handle must have been previously
 * allocated and bound by
 * sysevent_open_channel() and sysevent_bind_publisher()
 */
int
sysevent_send_event(sysevent_handle_t *shp, sysevent_t *ev)
{
	int i, error, sub_fd, result = 0;
	int deliver_error = 0;
	int subscribers_sent = 0;
	int want_resend, resend_cnt = 0;
	char *event_class, *event_subclass;
	uchar_t *all_class_subscribers, *all_subclass_subscribers;
	uchar_t *subclass_subscribers;
	subscriber_data_t *sub;
	subclass_lst_t *sc_lst;

	/* Check for proper registration */
	event_class = sysevent_get_class_name(ev);
	event_subclass = sysevent_get_subclass_name(ev);

	(void) mutex_lock(SH_LOCK(shp));

send_event:

	want_resend = 0;
	if (!SH_BOUND(shp)) {
		(void) mutex_unlock(SH_LOCK(shp));
		errno = EINVAL;
		return (-1);
	}

	/* Find all subscribers for this event class/subclass */
	sc_lst = cache_find_subclass(
	    cache_find_class(shp, EC_ALL), EC_SUB_ALL);
	all_class_subscribers = sc_lst->sl_num;

	sc_lst = cache_find_subclass(
	    cache_find_class(shp, event_class), EC_SUB_ALL);
	if (sc_lst)
		all_subclass_subscribers = sc_lst->sl_num;
	else
		all_subclass_subscribers = NULL;

	sc_lst = cache_find_subclass(
	    cache_find_class(shp, event_class), event_subclass);
	if (sc_lst)
		subclass_subscribers = sc_lst->sl_num;
	else
		subclass_subscribers = NULL;

	/* Send event buffer to all valid subscribers */
	for (i = 1; i <= MAX_SUBSCRIBERS; ++i) {
		if ((all_class_subscribers[i] |
		    (all_subclass_subscribers && all_subclass_subscribers[i]) |
		    (subclass_subscribers && subclass_subscribers[i])) == 0)
			continue;

		sub = SH_SUBSCRIBER(shp, i);
		assert(sub != NULL);

		/* Check for active subscriber */
		if (!(sub->sd_flag & ACTIVE)) {
			dprint("sysevent_send_event: subscriber %d inactive\n",
			    i);
			continue;
		}

		/* Process only resend requests */
		if (resend_cnt > 0 && !(sub->sd_flag & SEND_AGAIN)) {
			continue;
		}

		if ((sub_fd = open(sub->sd_door_name, O_RDONLY)) == -1) {
			dprint("sysevent_send_event: Failed to open "
			    "%s: %s\n", sub->sd_door_name, strerror(errno));
			continue;
		}
		result = 0;
		error = clnt_deliver_event(sub_fd, ev,
		    sysevent_get_size(ev), &result, sizeof (result));

		(void) close(sub_fd);

		/* Successful door call */
		if (error == 0) {
			switch (result) {
			/* Subscriber requested EAGAIN */
			case EAGAIN:
				if (resend_cnt > SE_MAX_RETRY_LIMIT) {
					deliver_error = 1;
				} else {
					want_resend = 1;
					dprint("sysevent_send_event: resend "
					    "requested for %d\n", i);
					sub->sd_flag |= SEND_AGAIN;
				}
				break;
			/* Bad sysevent handle for subscriber */
			case EBADF:
			case EINVAL:
				dprint("sysevent_send_event: Bad sysevent "
				    "handle for %s", sub->sd_door_name);
				sub->sd_flag = 0;
				deliver_error = 1;
				break;
			/* Successful delivery */
			default:
				sub->sd_flag &= ~SEND_AGAIN;
				++subscribers_sent;
			}
		} else {
			dprint("sysevent_send_event: Failed door call "
			    "to %s: %s: %d\n", sub->sd_door_name,
			    strerror(errno), result);
			sub->sd_flag = 0;
			deliver_error = 1;
		}
	}

	if (want_resend) {
		resend_cnt++;
		goto send_event;
	}

	if (deliver_error) {
		sysevent_cleanup_subscribers(shp);
		(void) mutex_unlock(SH_LOCK(shp));
		errno = EFAULT;
		return (-1);
	}

	(void) mutex_unlock(SH_LOCK(shp));

	if (subscribers_sent == 0) {
		dprint("sysevent_send_event: No subscribers for %s:%s\n",
		    event_class, event_subclass);
		errno = ENOENT;
		return (-1);
	}

	return (0);
}

/*
 * Common routine to establish an event channel through which an event
 * publisher or subscriber may post or receive events.
 */
static sysevent_handle_t *
sysevent_open_channel_common(const char *channel_path)
{
	uint32_t sub_id = 0;
	char *begin_path;
	struct stat chan_stat;
	sysevent_handle_t *shp;


	if (channel_path == NULL || strlen(channel_path) + 1 > MAXPATHLEN) {
		errno = EINVAL;
		return (NULL);
	}

	if (mkdir(channel_path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) < 0) {
		if (errno != EEXIST) {
			errno = EACCES;
			return (NULL);
		}
	}

	/* Check channel file permissions */
	if (stat(channel_path, &chan_stat) != 0) {
		dprint("sysevent_open_channel: Invalid permissions for channel "
		    "%s\n", channel_path);
		errno = EACCES;
		return (NULL);
	} else if (chan_stat.st_uid != getuid() ||
	    !S_ISDIR(chan_stat.st_mode)) {
		dprint("sysevent_open_channel: Invalid "
		    "permissions for channel %s\n: %d:%d:%d", channel_path,
		    (int)chan_stat.st_uid, (int)chan_stat.st_gid,
		    (int)chan_stat.st_mode);

		errno = EACCES;
		return (NULL);
	}

	shp = calloc(1, sizeof (sysevent_impl_hdl_t));
	if (shp == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	SH_CHANNEL_NAME(shp) = NULL;
	SH_CHANNEL_PATH(shp) = strdup(channel_path);
	if (SH_CHANNEL_PATH(shp) == NULL) {
		free(shp);
		errno = ENOMEM;
		return (NULL);
	}

	/* Extract the channel name */
	begin_path = SH_CHANNEL_PATH(shp);
	while (*begin_path != '\0' &&
	    (begin_path = strpbrk(begin_path, "/")) != NULL) {
		++begin_path;
		SH_CHANNEL_NAME(shp) = begin_path;
	}

	if (update_kernel_registration(shp, 0,
	    SE_OPEN_REGISTRATION, &sub_id, 0, NULL) != 0) {
		dprint("sysevent_open_channel: Failed for channel %s\n",
		    SH_CHANNEL_NAME(shp));
		free(SH_CHANNEL_PATH(shp));
		free(shp);
		errno = EFAULT;
		return (NULL);
	}

	(void) mutex_init(SH_LOCK(shp), USYNC_THREAD, NULL);

	return (shp);
}

/*
 * Establish a sysevent channel for publication and subscription
 */
sysevent_handle_t *
sysevent_open_channel(const char *channel)
{
	int var_run_mounted = 0;
	char full_channel[MAXPATHLEN + 1];
	FILE *fp;
	struct stat chan_stat;
	struct extmnttab m;

	if (channel == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * Check that /var/run is mounted as tmpfs before allowing a channel
	 * to be opened.
	 */
	if ((fp = fopen(MNTTAB, "rF")) == NULL) {
		errno = EACCES;
		return (NULL);
	}

	resetmnttab(fp);

	while (getextmntent(fp, &m, sizeof (struct extmnttab)) == 0) {
		if (strcmp(m.mnt_mountp, "/var/run") == 0 &&
		    strcmp(m.mnt_fstype, "tmpfs") == 0) {
			var_run_mounted = 1;
			break;
		}
	}
	(void) fclose(fp);

	if (!var_run_mounted) {
		errno = EACCES;
		return (NULL);
	}

	if (stat(CHAN_PATH, &chan_stat) < 0) {
		if (mkdir(CHAN_PATH,
		    S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) < 0) {
			dprint("sysevent_open_channel: Unable "
			    "to create channel directory %s:%s\n", CHAN_PATH,
			    strerror(errno));
			if (errno != EEXIST) {
				errno = EACCES;
				return (NULL);
			}
		}
	}

	if (snprintf(full_channel, MAXPATHLEN, "%s/%s", CHAN_PATH, channel) >=
	    MAXPATHLEN) {
		errno = EINVAL;
		return (NULL);
	}

	return (sysevent_open_channel_common(full_channel));
}

/*
 * Establish a sysevent channel for publication and subscription
 * Full path to the channel determined by the caller
 */
sysevent_handle_t *
sysevent_open_channel_alt(const char *channel_path)
{
	return (sysevent_open_channel_common(channel_path));
}

/*
 * sysevent_close_channel - Clean up resources associated with a previously
 *				opened sysevent channel
 */
void
sysevent_close_channel(sysevent_handle_t *shp)
{
	int error = errno;
	uint32_t sub_id = 0;

	if (shp == NULL) {
		return;
	}

	(void) mutex_lock(SH_LOCK(shp));
	if (SH_BOUND(shp)) {
		(void) mutex_unlock(SH_LOCK(shp));
		if (SH_TYPE(shp) == PUBLISHER)
			sysevent_unbind_publisher(shp);
		else if (SH_TYPE(shp) == SUBSCRIBER)
			sysevent_unbind_subscriber(shp);
		(void) mutex_lock(SH_LOCK(shp));
	}

	(void) update_kernel_registration(shp, 0,
	    SE_CLOSE_REGISTRATION, &sub_id, 0, NULL);
	(void) mutex_unlock(SH_LOCK(shp));

	free(SH_CHANNEL_PATH(shp));
	free(shp);
	errno = error;
}

/*
 * sysevent_bind_publisher - Bind an event publisher to an event channel
 */
int
sysevent_bind_publisher(sysevent_handle_t *shp)
{
	int error = 0;
	int fd = -1;
	char door_name[MAXPATHLEN];
	uint32_t pub_id;
	struct stat reg_stat;
	publisher_priv_t *pub;

	if (shp == NULL) {
		errno = EINVAL;
		return (-1);
	}

	(void) mutex_lock(SH_LOCK(shp));
	if (SH_BOUND(shp)) {
		(void) mutex_unlock(SH_LOCK(shp));
		errno = EINVAL;
		return (-1);
	}

	if ((pub = (publisher_priv_t *)calloc(1, sizeof (publisher_priv_t))) ==
	    NULL) {
		(void) mutex_unlock(SH_LOCK(shp));
		errno = ENOMEM;
		return (-1);
	}
	SH_PRIV_DATA(shp) = (void *)pub;

	if (snprintf(door_name, MAXPATHLEN, "%s/%s",
	    SH_CHANNEL_PATH(shp), REG_DOOR) >= MAXPATHLEN) {
		free(pub);
		(void) mutex_unlock(SH_LOCK(shp));
		errno = ENOMEM;
		return (-1);
	}
	if ((SH_DOOR_NAME(shp) = strdup(door_name)) == NULL) {
		free(pub);
		(void) mutex_unlock(SH_LOCK(shp));
		errno = ENOMEM;
		return (-1);
	}

	/* Only one publisher allowed per channel */
	if (stat(SH_DOOR_NAME(shp), &reg_stat) != 0) {
		if (errno != ENOENT) {
			error = EINVAL;
			goto fail;
		}
	}

	/*
	 * Remove door file for robustness.
	 */
	if (unlink(SH_DOOR_NAME(shp)) != 0)
		dprint("sysevent_bind_publisher: Unlink of %s failed.\n",
		    SH_DOOR_NAME(shp));

	/* Open channel registration door */
	fd = open(SH_DOOR_NAME(shp), O_CREAT|O_RDWR,
	    S_IREAD|S_IWRITE);
	if (fd == -1) {
		error = EINVAL;
		goto fail;
	}

	/*
	 * Create the registration service for this publisher.
	 */
	if ((SH_DOOR_DESC(shp) = door_create(cache_update_service,
	    (void *)shp, DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		dprint("sysevent_bind_publisher: door create failed: "
		    "%s\n", strerror(errno));
		error = EFAULT;
		goto fail;
	}

	(void) fdetach(SH_DOOR_NAME(shp));
	if (fattach(SH_DOOR_DESC(shp), SH_DOOR_NAME(shp)) != 0) {
		dprint("sysevent_bind_publisher: unable to "
		    "bind event channel: fattach: %s\n",
		    SH_DOOR_NAME(shp));
		error = EACCES;
		goto fail;
	}

	/* Bind this publisher in the kernel registration database */
	if (update_kernel_registration(shp, PUBLISHER,
	    SE_BIND_REGISTRATION, &pub_id, 0, NULL) != 0) {
		error = errno;
		goto fail;
	}

	SH_ID(shp) = pub_id;
	SH_BOUND(shp) = 1;
	SH_TYPE(shp) = PUBLISHER;


	/* Create the subscription registration cache */
	if (create_cached_registration(shp, SH_CLASS_HASH(shp)) != 0) {
		(void) update_kernel_registration(shp,
		    PUBLISHER, SE_UNBIND_REGISTRATION, &pub_id, 0, NULL);
		error = EFAULT;
		goto fail;
	}
	(void) close(fd);

	(void) mutex_unlock(SH_LOCK(shp));

	return (0);

fail:
	SH_BOUND(shp) = 0;
	(void) door_revoke(SH_DOOR_DESC(shp));
	(void) fdetach(SH_DOOR_NAME(shp));
	free(SH_DOOR_NAME(shp));
	free(pub);
	(void) close(fd);
	(void) mutex_unlock(SH_LOCK(shp));
	errno = error;
	return (-1);
}

static pthread_once_t xdoor_thrattr_once = PTHREAD_ONCE_INIT;
static pthread_attr_t xdoor_thrattr;

static void
xdoor_thrattr_init(void)
{
	(void) pthread_attr_init(&xdoor_thrattr);
	(void) pthread_attr_setdetachstate(&xdoor_thrattr,
	    PTHREAD_CREATE_DETACHED);
	(void) pthread_attr_setscope(&xdoor_thrattr, PTHREAD_SCOPE_SYSTEM);
}

static int
xdoor_server_create(door_info_t *dip, void *(*startf)(void *),
    void *startfarg, void *cookie)
{
	struct sysevent_subattr_impl *xsa = cookie;
	pthread_attr_t *thrattr;
	sigset_t oset;
	int err;

	if (xsa->xs_thrcreate) {
		return (xsa->xs_thrcreate(dip, startf, startfarg,
		    xsa->xs_thrcreate_cookie));
	}

	if (xsa->xs_thrattr == NULL) {
		(void) pthread_once(&xdoor_thrattr_once, xdoor_thrattr_init);
		thrattr = &xdoor_thrattr;
	} else {
		thrattr = xsa->xs_thrattr;
	}

	(void) pthread_sigmask(SIG_SETMASK, &xsa->xs_sigmask, &oset);
	err = pthread_create(NULL, thrattr, startf, startfarg);
	(void) pthread_sigmask(SIG_SETMASK, &oset, NULL);

	return (err == 0 ? 1 : -1);
}

static void
xdoor_server_setup(void *cookie)
{
	struct sysevent_subattr_impl *xsa = cookie;

	if (xsa->xs_thrsetup) {
		xsa->xs_thrsetup(xsa->xs_thrsetup_cookie);
	} else {
		(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		(void) pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	}
}

static int
sysevent_bind_subscriber_cmn(sysevent_handle_t *shp,
	void (*event_handler)(sysevent_t *ev),
	sysevent_subattr_t *subattr)
{
	int fd = -1;
	int error = 0;
	uint32_t sub_id = 0;
	char door_name[MAXPATHLEN];
	subscriber_priv_t *sub_info;
	int created;
	struct sysevent_subattr_impl *xsa =
	    (struct sysevent_subattr_impl *)subattr;

	if (shp == NULL || event_handler == NULL) {
		errno = EINVAL;
		return (-1);
	}

	(void) mutex_lock(SH_LOCK(shp));
	if (SH_BOUND(shp)) {
		errno = EINVAL;
		(void) mutex_unlock(SH_LOCK(shp));
		return (-1);
	}

	if ((sub_info = (subscriber_priv_t *)calloc(1,
	    sizeof (subscriber_priv_t))) == NULL) {
		errno = ENOMEM;
		(void) mutex_unlock(SH_LOCK(shp));
		return (-1);
	}

	if (snprintf(door_name, MAXPATHLEN, "%s/%s",
	    SH_CHANNEL_PATH(shp), REG_DOOR) >= MAXPATHLEN) {
		free(sub_info);
		errno = EINVAL;
		(void) mutex_unlock(SH_LOCK(shp));
		return (-1);
	}

	if ((sub_info->sp_door_name = strdup(door_name)) == NULL) {
		free(sub_info);
		errno = ENOMEM;
		(void) mutex_unlock(SH_LOCK(shp));
		return (-1);
	}
	(void) cond_init(&sub_info->sp_cv, USYNC_THREAD, NULL);
	(void) mutex_init(&sub_info->sp_qlock, USYNC_THREAD, NULL);
	sub_info->sp_func = event_handler;

	/* Update the in-kernel registration */
	if (update_kernel_registration(shp, SUBSCRIBER,
	    SE_BIND_REGISTRATION, &sub_id, 0, NULL) != 0) {
		error = errno;
		goto fail;
	}
	SH_ID(shp) = sub_id;

	if (snprintf(door_name, MAXPATHLEN, "%s/%d",
	    SH_CHANNEL_PATH(shp), sub_id) >= MAXPATHLEN) {
		error = EINVAL;
		goto fail;
	}
	if ((SH_DOOR_NAME(shp) = strdup(door_name)) == NULL) {
		error = ENOMEM;
		goto fail;
	}

	/*
	 * Remove door file for robustness.
	 */
	if (unlink(SH_DOOR_NAME(shp)) != 0)
		dprint("sysevent_bind_subscriber: Unlink of %s failed.\n",
		    SH_DOOR_NAME(shp));

	fd = open(SH_DOOR_NAME(shp), O_CREAT|O_RDWR, S_IREAD|S_IWRITE);
	if (fd == -1) {
		error = EFAULT;
		goto fail;
	}

	/*
	 * Create the sysevent door service for this client.
	 * syseventd will use this door service to propagate
	 * events to the client.
	 */
	if (subattr == NULL) {
		SH_DOOR_DESC(shp) = door_create(event_deliver_service,
		    (void *)shp, DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
	} else {
		SH_DOOR_DESC(shp) = door_xcreate(event_deliver_service,
		    (void *)shp,
		    DOOR_REFUSE_DESC | DOOR_NO_CANCEL | DOOR_NO_DEPLETION_CB,
		    xdoor_server_create, xdoor_server_setup,
		    (void *)subattr, 1);
	}

	if (SH_DOOR_DESC(shp) == -1) {
		dprint("sysevent_bind_subscriber: door create failed: "
		    "%s\n", strerror(errno));
		error = EFAULT;
		goto fail;
	}

	(void) fdetach(SH_DOOR_NAME(shp));
	if (fattach(SH_DOOR_DESC(shp), SH_DOOR_NAME(shp)) != 0) {
		error = EFAULT;
		goto fail;
	}
	(void) close(fd);

	if (update_publisher_cache(sub_info, SE_BIND_REGISTRATION,
	    sub_id, 0, NULL) != 0) {
		error = errno;
		(void) update_kernel_registration(shp, SUBSCRIBER,
		    SE_UNBIND_REGISTRATION, &sub_id, 0, NULL);
		goto fail;
	}

	SH_BOUND(shp) = 1;
	SH_TYPE(shp) = SUBSCRIBER;
	SH_PRIV_DATA(shp) = (void *)sub_info;

	/* Create an event handler thread */
	if (xsa == NULL || xsa->xs_thrcreate == NULL) {
		created = thr_create(NULL, NULL,
		    (void *(*)(void *))subscriber_event_handler,
		    shp, THR_BOUND, &sub_info->sp_handler_tid) == 0;
	} else {
		/*
		 * A terrible hack.  We will use the extended private
		 * door thread creation function the caller passed in to
		 * create the event handler thread.  That function will
		 * be called with our chosen thread start function and arg
		 * instead of the usual libc-provided ones, but that's ok
		 * as it is required to use them verbatim anyway.  We will
		 * pass a NULL door_info_t pointer to the function - so
		 * callers depending on this hack had better be prepared
		 * for that.  All this allow the caller to rubberstamp
		 * the created thread as it wishes.  But we don't get
		 * the created threadid with this, so we modify the
		 * thread start function to stash it.
		 */

		created = xsa->xs_thrcreate(NULL,
		    (void *(*)(void *))subscriber_event_handler,
		    shp, xsa->xs_thrcreate_cookie) == 1;
	}

	if (!created) {
		error = EFAULT;
		goto fail;
	}

	(void) mutex_unlock(SH_LOCK(shp));

	return (0);

fail:
	(void) close(fd);
	(void) door_revoke(SH_DOOR_DESC(shp));
	(void) fdetach(SH_DOOR_NAME(shp));
	(void) cond_destroy(&sub_info->sp_cv);
	(void) mutex_destroy(&sub_info->sp_qlock);
	free(sub_info->sp_door_name);
	free(sub_info);
	if (SH_ID(shp)) {
		(void) update_kernel_registration(shp, SUBSCRIBER,
		    SE_UNBIND_REGISTRATION, &sub_id, 0, NULL);
		SH_ID(shp) = 0;
	}
	if (SH_BOUND(shp)) {
		(void) update_publisher_cache(sub_info, SE_UNBIND_REGISTRATION,
		    sub_id, 0, NULL);
		free(SH_DOOR_NAME(shp));
		SH_BOUND(shp) = 0;
	}
	(void) mutex_unlock(SH_LOCK(shp));

	errno = error;

	return (-1);
}

/*
 * sysevent_bind_subscriber - Bind an event receiver to an event channel
 */
int
sysevent_bind_subscriber(sysevent_handle_t *shp,
	void (*event_handler)(sysevent_t *ev))
{
	return (sysevent_bind_subscriber_cmn(shp, event_handler, NULL));
}

/*
 * sysevent_bind_xsubscriber - Bind a subscriber using door_xcreate with
 * attributes specified.
 */
int
sysevent_bind_xsubscriber(sysevent_handle_t *shp,
	void (*event_handler)(sysevent_t *ev), sysevent_subattr_t *subattr)
{
	return (sysevent_bind_subscriber_cmn(shp, event_handler, subattr));
}

/*
 * sysevent_register_event - register an event class and associated subclasses
 *		for an event subscriber
 */
int
sysevent_register_event(sysevent_handle_t *shp,
	const char *ev_class, const char **ev_subclass,
	int subclass_num)
{
	int error;
	char *event_class = (char *)ev_class;
	char **event_subclass_list = (char **)ev_subclass;
	char *nvlbuf = NULL;
	size_t datalen;
	nvlist_t *nvl;

	(void) mutex_lock(SH_LOCK(shp));
	if (event_class == NULL || event_subclass_list == NULL ||
	    event_subclass_list[0] == NULL || SH_BOUND(shp) != 1 ||
	    subclass_num <= 0) {
		(void) mutex_unlock(SH_LOCK(shp));
		errno = EINVAL;
		return (-1);
	}

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, 0) != 0) {
		(void) mutex_unlock(SH_LOCK(shp));
		return (-1);
	}
	if (nvlist_add_string_array(nvl, event_class, event_subclass_list,
	    subclass_num) != 0) {
		nvlist_free(nvl);
		(void) mutex_unlock(SH_LOCK(shp));
		return (-1);
	}
	if (nvlist_pack(nvl, &nvlbuf, &datalen, NV_ENCODE_NATIVE, 0) != 0) {
		nvlist_free(nvl);
		(void) mutex_unlock(SH_LOCK(shp));
		return (-1);
	}
	nvlist_free(nvl);

	/* Store new subscriber in in-kernel registration */
	if (update_kernel_registration(shp, SUBSCRIBER,
	    SE_REGISTER, &SH_ID(shp), datalen, (uchar_t *)nvlbuf)
	    != 0) {
		error = errno;
		free(nvlbuf);
		(void) mutex_unlock(SH_LOCK(shp));
		errno = error;
		return (-1);
	}
	/* Update the publisher's cached registration */
	if (update_publisher_cache(
	    (subscriber_priv_t *)SH_PRIV_DATA(shp), SE_REGISTER,
	    SH_ID(shp), datalen, (uchar_t *)nvlbuf) != 0) {
		error = errno;
		free(nvlbuf);
		(void) mutex_unlock(SH_LOCK(shp));
		errno = error;
		return (-1);
	}

	free(nvlbuf);

	(void) mutex_unlock(SH_LOCK(shp));

	return (0);
}

/*
 * sysevent_unregister_event - Unregister an event class and associated
 *				subclasses for an event subscriber
 */
void
sysevent_unregister_event(sysevent_handle_t *shp, const char *class)
{
	size_t class_sz;

	(void) mutex_lock(SH_LOCK(shp));

	if (!SH_BOUND(shp)) {
		(void) mutex_unlock(SH_LOCK(shp));
		return;
	}

	/* Remove subscriber from in-kernel registration */
	class_sz = strlen(class) + 1;
	(void) update_kernel_registration(shp, SUBSCRIBER,
	    SE_UNREGISTER, &SH_ID(shp), class_sz, (uchar_t *)class);
	/* Update the publisher's cached registration */
	(void) update_publisher_cache(
	    (subscriber_priv_t *)SH_PRIV_DATA(shp), SE_UNREGISTER,
	    SH_ID(shp), class_sz, (uchar_t *)class);

	(void) mutex_unlock(SH_LOCK(shp));
}

static int
cleanup_id(sysevent_handle_t *shp, uint32_t id, int type)
{
	dprint("cleanup_id: Cleaning up %s/%d\n", SH_CHANNEL_NAME(shp), id);

	/* Remove registration from the kernel */
	if (update_kernel_registration(shp, type, SE_CLEANUP, &id,
	    0, NULL) != 0) {
		dprint("cleanup_id: Unable to clean "
		    "up %s/%d\n", SH_CHANNEL_NAME(shp), id);
		return (-1);
	}

	return (0);
}

/*
 * sysevent_cleanup_subscribers: Allows the caller to cleanup resources
 *		allocated to unresponsive subscribers.
 */
void
sysevent_cleanup_subscribers(sysevent_handle_t *shp)
{
	uint32_t ping, result;
	int i, error, sub_fd;
	subscriber_data_t *sub;

	if (!SH_BOUND(shp)) {
		return;
	}

	for (i = 1; i <= MAX_SUBSCRIBERS; ++i) {

		sub = SH_SUBSCRIBER(shp, i);
		if (sub == NULL) {
			continue;
		}

		if ((sub_fd = open(sub->sd_door_name, O_RDONLY)) == -1) {
			continue;
		}
		/* Check for valid and responsive subscriber */
		error = clnt_deliver_event(sub_fd, &ping,
		    sizeof (uint32_t), &result, sizeof (result));
		(void) close(sub_fd);

		/* Only cleanup on EBADF (Invalid door descriptor) */
		if (error != EBADF)
			continue;

		if (cleanup_id(shp, i, SUBSCRIBER) != 0)
			continue;

		cache_remove_class(shp, EC_ALL, i);

		free(sub->sd_door_name);
		free(sub);
		SH_SUBSCRIBER(shp, i) = NULL;
	}

}

/*
 * sysevent_cleanup_publishers: Allows stale publisher handles to be deallocated
 *		as needed.
 */
void
sysevent_cleanup_publishers(sysevent_handle_t *shp)
{
	(void) cleanup_id(shp, 1, PUBLISHER);
}

/*
 * sysevent_unbind_subscriber: Unbind the subscriber from the sysevent channel.
 */
void
sysevent_unbind_subscriber(sysevent_handle_t *shp)
{
	subscriber_priv_t *sub_info;

	if (shp == NULL)
		return;

	(void) mutex_lock(SH_LOCK(shp));
	if (SH_BOUND(shp) == 0) {
		(void) mutex_unlock(SH_LOCK(shp));
		return;
	}

	/* Update the in-kernel registration */
	(void) update_kernel_registration(shp, SUBSCRIBER,
	    SE_UNBIND_REGISTRATION, &SH_ID(shp), 0, NULL);

	/* Update the sysevent channel publisher */
	sub_info = (subscriber_priv_t *)SH_PRIV_DATA(shp);
	(void) update_publisher_cache(sub_info, SE_UNBIND_REGISTRATION,
	    SH_ID(shp), 0, NULL);

	/* Close down event delivery facilities */
	(void) door_revoke(SH_DOOR_DESC(shp));
	(void) fdetach(SH_DOOR_NAME(shp));

	/*
	 * Release resources and wait for pending event delivery to
	 * complete.
	 */
	(void) mutex_lock(&sub_info->sp_qlock);
	SH_BOUND(shp) = 0;
	/* Signal event handler and drain the subscriber's event queue */
	(void) cond_signal(&sub_info->sp_cv);
	(void) mutex_unlock(&sub_info->sp_qlock);
	if (sub_info->sp_handler_tid != NULL)
		(void) thr_join(sub_info->sp_handler_tid, NULL, NULL);

	(void) cond_destroy(&sub_info->sp_cv);
	(void) mutex_destroy(&sub_info->sp_qlock);
	free(sub_info->sp_door_name);
	free(sub_info);
	free(SH_DOOR_NAME(shp));
	(void) mutex_unlock(SH_LOCK(shp));
}

/*
 * sysevent_unbind_publisher: Unbind publisher from the sysevent channel.
 */
void
sysevent_unbind_publisher(sysevent_handle_t *shp)
{
	if (shp == NULL)
		return;

	(void) mutex_lock(SH_LOCK(shp));
	if (SH_BOUND(shp) == 0) {
		(void) mutex_unlock(SH_LOCK(shp));
		return;
	}

	/* Close down the registration facilities */
	(void) door_revoke(SH_DOOR_DESC(shp));
	(void) fdetach(SH_DOOR_NAME(shp));

	/* Update the in-kernel registration */
	(void) update_kernel_registration(shp, PUBLISHER,
	    SE_UNBIND_REGISTRATION, &SH_ID(shp), 0, NULL);
	SH_BOUND(shp) = 0;

	/* Free resources associated with bind */
	free_cached_registration(shp);
	dealloc_subscribers(shp);

	free(SH_PRIV_DATA(shp));
	free(SH_DOOR_NAME(shp));
	SH_ID(shp) = 0;
	(void) mutex_unlock(SH_LOCK(shp));
}

/*
 * Evolving APIs to subscribe to syseventd(1M) system events.
 */

static sysevent_handle_t *
sysevent_bind_handle_cmn(void (*event_handler)(sysevent_t *ev),
    sysevent_subattr_t *subattr)
{
	sysevent_handle_t *shp;

	if (getuid() != 0) {
		errno = EACCES;
		return (NULL);
	}

	if (event_handler == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if ((shp = sysevent_open_channel(SYSEVENTD_CHAN)) == NULL) {
		return (NULL);
	}

	if (sysevent_bind_xsubscriber(shp, event_handler, subattr) != 0) {
		/*
		 * Ask syseventd to clean-up any stale subcribers and try to
		 * to bind again
		 */
		if (errno == EBUSY) {
			int pub_fd;
			char door_name[MAXPATHLEN];
			uint32_t result;
			struct reg_args rargs;

			if (snprintf(door_name, MAXPATHLEN, "%s/%s",
			    SH_CHANNEL_PATH(shp), REG_DOOR) >= MAXPATHLEN) {
				sysevent_close_channel(shp);
				errno = EINVAL;
				return (NULL);
			}

			rargs.ra_op = SE_CLEANUP;
			pub_fd = open(door_name, O_RDONLY);
			(void) clnt_deliver_event(pub_fd, (void *)&rargs,
			    sizeof (struct reg_args), &result, sizeof (result));
			(void) close(pub_fd);

			/* Try to bind again */
			if (sysevent_bind_xsubscriber(shp, event_handler,
			    subattr) != 0) {
				sysevent_close_channel(shp);
				return (NULL);
			}
		} else {
			sysevent_close_channel(shp);
			return (NULL);
		}
	}

	return (shp);
}

/*
 * sysevent_bind_handle - Bind application event handler for syseventd
 *		subscription.
 */
sysevent_handle_t *
sysevent_bind_handle(void (*event_handler)(sysevent_t *ev))
{
	return (sysevent_bind_handle_cmn(event_handler, NULL));
}

/*
 * sysevent_bind_xhandle - Bind application event handler for syseventd
 *		subscription, using door_xcreate and attributes as specified.
 */
sysevent_handle_t *
sysevent_bind_xhandle(void (*event_handler)(sysevent_t *ev),
    sysevent_subattr_t *subattr)
{
	return (sysevent_bind_handle_cmn(event_handler, subattr));
}

/*
 * sysevent_unbind_handle - Unbind caller from syseventd subscriptions
 */
void
sysevent_unbind_handle(sysevent_handle_t *shp)
{
	sysevent_unbind_subscriber(shp);
	sysevent_close_channel(shp);
}

/*
 * sysevent_subscribe_event - Subscribe to system event notification from
 *			syseventd(1M) for the class and subclasses specified.
 */
int
sysevent_subscribe_event(sysevent_handle_t *shp, const char *event_class,
	const char **event_subclass_list, int num_subclasses)
{
	return (sysevent_register_event(shp, event_class,
	    event_subclass_list, num_subclasses));
}

void
sysevent_unsubscribe_event(sysevent_handle_t *shp, const char *event_class)
{
	sysevent_unregister_event(shp, event_class);
}
