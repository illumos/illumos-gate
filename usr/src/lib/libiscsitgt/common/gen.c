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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support routines for library
 */
#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <libscf.h>
#include <door.h>
#include <libxml/xmlreader.h>
#include <sys/mman.h>

#include "iscsitgt_impl.h"

#define	WAIT_FOR_SERVICE	15
#define	WAIT_FOR_DOOR		15
static char *service = "system/iscsitgt:default";
static char *bad_call_str = "<error><code>1</code>"
	"<message>Can't call daemon</message></error>";

static Boolean_t check_and_online(int);

tgt_node_t *
tgt_door_call(char *str, int smf_flags)
{
	tgt_node_t		*n	= NULL;
	door_arg_t		d;
	int			s;
	xmlTextReaderPtr	r;

	d.data_ptr	= str;
	d.data_size	= strlen(str) + 1;
	d.desc_ptr	= NULL;
	d.desc_num	= 0;
	d.rbuf		= NULL;
	d.rsize		= 0;

	if (((s = open(ISCSI_TARGET_MGMT_DOOR, 0)) < 0) ||
	    (door_call(s, &d) < 0)) {
		if (s != -1)
			(void) close(s);
		if (check_and_online(smf_flags) == False) {
			d.rbuf = bad_call_str;
		} else if ((s = open(ISCSI_TARGET_MGMT_DOOR, 0)) < 0) {
			d.rbuf = bad_call_str;
		} else if (door_call(s, &d) < 0)
			d.rbuf = bad_call_str;
	}
	if ((r = (xmlTextReaderPtr)xmlReaderForMemory(d.rbuf, strlen(d.rbuf),
	    NULL, NULL, 0)) == NULL)
		return (NULL);

	while (xmlTextReaderRead(r) == 1)
		if (tgt_node_process(r, &n) == False)
			break;
	xmlFreeTextReader(r);
	if (d.rbuf != bad_call_str)
		(void) munmap(d.rbuf, d.rsize);
	(void) close(s);

	return (n);
}

static Boolean_t
is_online(void)
{
	char		*s;
	Boolean_t	rval = False;

	if ((s = smf_get_state(service)) != NULL) {
		if (strcmp(s, SCF_STATE_STRING_ONLINE) == 0)
			rval = True;
		free(s);
	}

	return (rval);
}

static Boolean_t
is_auto_enabled(void)
{
	scf_simple_prop_t	*prop;
	uint8_t			*ret;
	Boolean_t		rval = True;

	if ((prop = scf_simple_prop_get(NULL, service, "application",
	    "auto_enable")) == NULL)
		return (True);

	if ((ret = scf_simple_prop_next_boolean(prop)) != NULL)
		rval = (*ret != 0);

	scf_simple_prop_free(prop);

	return (rval);
}

static Boolean_t
check_and_online(int smf_flags)
{
	int	i,
		fd;
	door_arg_t	d;

	if (!is_online()) {
		if (!is_auto_enabled())
			return (False);

		if (smf_enable_instance(service, smf_flags) != 0)
			return (False);

		for (i = 0; i < WAIT_FOR_SERVICE; i++) {
			if (is_online() == True)
				break;
			(void) sleep(1);
		}

		if (i == WAIT_FOR_SERVICE)
			return (False);
	}

	for (i = 0; i < WAIT_FOR_DOOR; i++) {
		if ((fd = open(ISCSI_TARGET_MGMT_DOOR, 0)) >= 0) {
			/*
			 * There's at least a file with the same name as our
			 * door. Let's see if someone is currently answering
			 * by sending an empty XML request.
			 */
			d.data_ptr	= "<config></config>";
			d.data_size	= strlen(d.data_ptr) + 1;
			d.desc_ptr	= NULL;
			d.desc_num	= 0;
			d.rbuf		= NULL;
			d.rsize		= 0;

			if (door_call(fd, &d) == 0) {
				/*
				 * The daemon is now ready to handle requests.
				 */
				(void) close(fd);
				return (True);
			} else
				(void) close(fd);

		}
		if (!is_online())
			break;
		(void) sleep(1);
	}
	return (False);
}
