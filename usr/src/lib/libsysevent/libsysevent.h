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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBSYSEVENT_H
#define	_LIBSYSEVENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <thread.h>
#include <stddef.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/sysevent.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SYSEVENTD_CHAN	"syseventd_channel"

/* sysevent loadable module ops structure and related defines */
#define	SE_MAX_RETRY_LIMIT	3
#define	SE_RETRY_TIME		1 /* seconds */
#define	SE_NO_RETRY		1
#define	SE_MAJOR_VERSION	0
#define	SE_MINOR_VERSION	0

struct slm_mod_ops {
	int	major_version;
	int	minor_version;
	int	retry_limit;
	int	(*deliver_event)();
};

typedef void *sysevent_handle_t;
typedef void *subscriber_t;

int sysevent_post_event(char *event_class, char *event_subclass, char *vendor,
	char *pub_name, nvlist_t *attr_list, sysevent_id_t *eid);
sysevent_t *sysevent_dup(sysevent_t *ev);
void sysevent_free(sysevent_t *ev);
int sysevent_get_attr_list(sysevent_t *ev, nvlist_t **nvlist);
int sysevent_lookup_attr(sysevent_t *ev, char *name, int datatype,
	sysevent_value_t *se_value);
sysevent_attr_t *sysevent_attr_next(sysevent_t *ev, sysevent_attr_t *attr);
char *sysevent_attr_name(sysevent_attr_t *attr);
int sysevent_attr_value(sysevent_attr_t *attr, sysevent_value_t *se_value);
int sysevent_get_class(sysevent_t *ev);
char *sysevent_get_class_name(sysevent_t *ev);
int sysevent_get_subclass(sysevent_t *ev);
char *sysevent_get_subclass_name(sysevent_t *ev);
char *sysevent_get_pub(sysevent_t *ev);
char *sysevent_get_vendor_name(sysevent_t *ev);
char *sysevent_get_pub_name(sysevent_t *ev);
void sysevent_get_pid(sysevent_t *ev, pid_t *pid);
uint64_t sysevent_get_seq(sysevent_t *ev);
void sysevent_get_time(sysevent_t *ev, hrtime_t *etime);
size_t sysevent_get_size(sysevent_t *ev);

/* syseventd subscriber interfaces */
sysevent_handle_t *sysevent_bind_handle(void (*event_handler)(sysevent_t *ev));
void sysevent_unbind_handle(sysevent_handle_t *sysevent_hdl);
int sysevent_subscribe_event(sysevent_handle_t *sysevent_hdl,
	const char *event_class, const char **event_subclass_list,
	int num_subclasses);
void sysevent_unsubscribe_event(sysevent_handle_t *sysevent_hdl,
	const char *event_class);

/* Subscriber private interfaces */
sysevent_t *sysevent_alloc_event(char *event_class, char *event_subclass,
	char *vendor, char *pub_name, nvlist_t *attr_list);
int sysevent_send_event(sysevent_handle_t *shp, sysevent_t *ev);
sysevent_handle_t *sysevent_open_channel(const char *channel);
sysevent_handle_t *sysevent_open_channel_alt(const char *channel_path);
void sysevent_close_channel(sysevent_handle_t *shp);
int sysevent_bind_subscriber(sysevent_handle_t *shp,
	void (*event_handler)(sysevent_t *ev));
void sysevent_unbind_subscriber(sysevent_handle_t *shp);
int sysevent_bind_publisher(sysevent_handle_t *shp);
void sysevent_unbind_publisher(sysevent_handle_t *shp);
int sysevent_register_event(sysevent_handle_t *shp, const char *event_class,
	const char **event_subclass_list, int num_subclasses);
void sysevent_unregister_event(sysevent_handle_t *shp,
	const char *event_class);
void sysevent_cleanup_subscribers(sysevent_handle_t *shp);
void sysevent_cleanup_publishers(sysevent_handle_t *shp);

/* Debug interfaces */
void se_print(FILE *fp, sysevent_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSYSEVENT_H */
