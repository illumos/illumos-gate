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

/*
 * sun4v DR Utility functions
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/sysevent.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/ldoms.h>

#include <sys/dr_util.h>

extern int ppvm_enable;

boolean_t
dr_is_disabled(dr_type_t type)
{
	/*
	 * The type argument is currently unused. However, it
	 * keeps the interface flexible enough to allows for
	 * only disabling certain types of DR.
	 */
	_NOTE(ARGUNUSED(type))

	/*
	 * DR requires that the kernel is using its own CIF
	 * handler. If that is not the case, either because
	 * domaining has been explicitly disabled, or because
	 * the firmware does not support it, the system must
	 * remain static and DR must be disabled.
	 */
	if (!domaining_enabled()) {
		cmn_err(CE_NOTE, "!Kernel CIF handler is not enabled, DR "
		    "is not available\n");
		return (B_TRUE);
	}

	if (type == DR_TYPE_MEM && ppvm_enable == 0) {
		cmn_err(CE_NOTE, "!Memory DR is disabled\n");
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Generate a DR sysevent based on the type of resource and
 * sysevent hint specified. The hint indicates whether the
 * resource was added or removed.
 */
void
dr_generate_event(dr_type_t type, int se_hint)
{
	int			rv;
	sysevent_id_t		eid;
	sysevent_t		*ev = NULL;
	sysevent_attr_list_t	*evnt_attr_list = NULL;
	sysevent_value_t	evnt_val;
	static char		pubname[] = SUNW_KERN_PUB"dr";

	DR_DBG_ALL("generate_event: type=%s, hint=%s\n", DR_TYPE2STR(type),
	    SE_HINT2STR(se_hint));

	/*
	 * Add the attachment point attribute
	 */
	ev = sysevent_alloc(EC_DR, ESC_DR_AP_STATE_CHANGE, pubname, KM_SLEEP);
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = DR_TYPE2STR(type);

	rv = sysevent_add_attr(&evnt_attr_list, DR_AP_ID, &evnt_val, KM_SLEEP);
	if (rv != 0) {
		DR_DBG_ALL("generate_event: failed to add attr '%s' for "
		    "'%s' event\n", DR_AP_ID, EC_DR);
		goto done;
	}

	/*
	 * Add the DR hint attribute
	 */
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = SE_HINT2STR(se_hint);

	rv = sysevent_add_attr(&evnt_attr_list, DR_HINT, &evnt_val, KM_SLEEP);
	if (rv != 0) {
		DR_DBG_ALL("generate_event: failed to add attr '%s' for "
		    "'%s' event\n", DR_HINT, EC_DR);
		sysevent_free_attr(evnt_attr_list);
		goto done;
	}

	/*
	 * Attach the attribute list to the event
	 */
	rv = sysevent_attach_attributes(ev, evnt_attr_list);
	if (rv != 0) {
		DR_DBG_ALL("generate_event: failed to add attr list for "
		    "'%s' event\n", EC_DR);
		sysevent_free_attr(evnt_attr_list);
		goto done;
	}

	/*
	 * Log the event
	 */
	rv = log_sysevent(ev, KM_NOSLEEP, &eid);
	if (rv != 0) {
		DR_DBG_ALL("generate_event: failed to log event (%d)\n", rv);
	}

done:
	if (ev != NULL)
		sysevent_free(ev);
}

/*
 * Debugging Features
 */
#ifdef DEBUG

uint_t dr_debug = 0x0;

#define	BYTESPERLINE    8
#define	LINEWIDTH	((BYTESPERLINE * 3) + (BYTESPERLINE + 2) + 1)
#define	ASCIIOFFSET	((BYTESPERLINE * 3) + 2)
#define	ISPRINT(c)	((c >= ' ') && (c <= '~'))

/*
 * Output a buffer formatted with a set number of bytes on
 * each line. Append each line with the ASCII equivalent of
 * each byte if it falls within the printable ASCII range,
 * and '.' otherwise.
 */
void
dr_dbg_dump_msg(void *buf, size_t len)
{
	int	i, j;
	char	*msg = buf;
	char	*curr;
	char	*aoff;
	char	line[LINEWIDTH];

	/* abort if not debugging transport */
	if (!(dr_debug & DR_DBG_FLAG_TRANS)) {
		return;
	}

	/* walk the buffer one line at a time */
	for (i = 0; i < len; i += BYTESPERLINE) {

		bzero(line, LINEWIDTH);

		curr = line;
		aoff = line + ASCIIOFFSET;

		/*
		 * Walk the bytes in the current line, storing
		 * the hex value for the byte as well as the
		 * ASCII representation in a temporary buffer.
		 * All ASCII values are placed at the end of
		 * the line.
		 */
		for (j = 0; (j < BYTESPERLINE) && ((i + j) < len); j++) {
			(void) sprintf(curr, " %02x", msg[i + j]);
			*aoff = (ISPRINT(msg[i + j])) ? msg[i + j] : '.';
			curr += 3;
			aoff++;
		}

		/*
		 * Fill in to the start of the ASCII translation
		 * with spaces. This will only be necessary if
		 * this is the last line and there are not enough
		 * bytes to fill the whole line.
		 */
		while (curr != (line + ASCIIOFFSET))
			*curr++ = ' ';

		DR_DBG_TRANS("%s\n", line);
	}
}
#endif /* DEBUG */
