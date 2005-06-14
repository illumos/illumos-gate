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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <libintl.h>
#include <syslog.h>
#include "fcal_leds.h"

/*
 * function templates for static functions
 */
static token_t get_token(char **pptr, int lineNo, actfun_t *fun);
static int get_cstr(str *p_str, cstr *p_cstr_res);
static int get_assert(str *p_str, int *assert);
static int get_pnz(str *p_str, int *pnz);
static int get_mask(str *p_str, int n_disks, int *p_intarray);

/*
 * Templates for functions which may be returned by get_token().
 * These functions are all called with a pointer to the position just
 * beyond the token being actioned.
 */
static int act_version(str *p_str, led_dtls_t *dtls);
static int act_leds_board(str *p_str, led_dtls_t *dtls);
static int act_status_board(str *p_str, led_dtls_t *dtls);
static int act_disk_driver(str *p_str, led_dtls_t *dtls);
static int act_n_disks(str *p_str, led_dtls_t *dtls);
static int act_asrt_pres(str *p_str, led_dtls_t *dtls);
static int act_asrt_fault(str *p_str, led_dtls_t *dtls);
static int act_led_on(str *p_str, led_dtls_t *dtls);
static int act_disk_present(str *p_str, led_dtls_t *dtls);
static int act_disk_fault(str *p_str, led_dtls_t *dtls);
static int act_led_id(str *p_str, led_dtls_t *dtls);
static int act_slow_poll(str *p_str, led_dtls_t *dtls);
static int act_fast_poll(str *p_str, led_dtls_t *dtls);
static int act_relax_interval(str *p_str, led_dtls_t *dtls);
static int act_test_interval(str *p_str, led_dtls_t *dtls);
static int act_disk_parent(str *p_str, led_dtls_t *dtls);
static int act_unit_parent(str *p_str, led_dtls_t *dtls);
static int act_led_nodes(str *p_str, led_dtls_t *dtls);

/*
 * The table below is used to lookup .conf file keywords to yield either
 * a corresponding enum or a function to process the keyword.
 */
static lookup_t table[] = {
	{ FCAL_VERSION,		"VERSION", 		act_version	},
	{ FCAL_REMOK_LED,	"REMOK",		NULL		},
	{ FCAL_FAULT_LED,	"FAULT",		NULL		},
	{ FCAL_READY_LED,	"READY",		NULL		},
	{ FCAL_LEDS_BOARD,	"FCAL-LEDS",		act_leds_board	},
	{ FCAL_STATUS_BOARD,	"FCAL-STATUS",		act_status_board },
	{ FCAL_DISK_DRIVER,	"FCAL-DISK-DRIVER",	act_disk_driver },
	{ FCAL_N_DISKS,		"N-DISKS",		act_n_disks	},
	{ FCAL_ASSERT_PRESENT,	"ASSERT-PRESENT",	act_asrt_pres	},
	{ FCAL_ASSERT_FAULT,	"ASSERT-FAULT",		act_asrt_fault	},
	{ FCAL_LED_ON,		"LED-ON",		act_led_on	},
	{ FCAL_DISK_PRESENT,	"DISK-PRESENT",		act_disk_present },
	{ FCAL_DISK_FAULT,	"DISK-FAULT",		act_disk_fault	},
	{ FCAL_LED_ID,		"LED",			act_led_id	},
	{ FCAL_SLOW_POLL,	"SLOW-POLL",		act_slow_poll	},
	{ FCAL_FAST_POLL,	"FAST-POLL",		act_fast_poll	},
	{ FCAL_RELAX_INTERVAL,	"RELAX-INTERVAL",	act_relax_interval },
	{ FCAL_TEST_INTERVAL,	"LED-TEST-INTERVAL",	act_test_interval },
	{ FCAL_DISK_PARENT,	"FCAL-DISK-PARENT",	act_disk_parent	},
	{ FCAL_UNIT_PARENT,	"DISK-UNIT-PARENT",	act_unit_parent	},
	{ FCAL_LED_NODES,	"DISK-LED-NODES",	act_led_nodes	}
};

/*
 * length of longest string in table (with space for null terminator)
 */
#define	MAX_FCAL_TOKEN_LEN	18

static const int tab_len = (sizeof (table))/sizeof (table[0]);

/*
 * get_token
 * Parses the current line of data and returns the next token.
 * If there are no significant characters in the line, NO_TOKEN is returned.
 * If a syntax error is encountered, TOKEN_ERROR is returned.
 * Pointer to position in current line is updated to point to the terminator
 * of the token, unless TOKEN_ERROR is returned.
 */
static token_t
get_token(
	char **pptr,	/* pointer to pointer to position in current line */
			/* *ptr is updated by the function */
	int lineNo,	/* current line number, used for syslog. If set to */
			/* zero, syslogging is supressed */
	actfun_t *fun)	/* pointer to function variable to receive action */
			/* pointer for the token found. NULL may be returned */
{
	char		*ptr;
	char		*token_start;
	int		toklen;
	int		i;
	int		ch;

	*fun = NULL;
	ptr = *pptr;

	/* strip leading white space */
	do {
		ch = (unsigned)(*ptr++);

	} while (isspace(ch));

	if ((ch == '\0') || (ch == '#')) {
		*pptr = ptr;
		return (NO_TOKEN);	/* empty line or comment */
	}

	if (!isalpha(ch)) {
		if (lineNo != 0)
			SYSLOG(LOG_ERR, EM_NONALF_TOK, lineNo);
		return (TOKEN_ERROR);
	}
	token_start = ptr - 1;
	toklen = strcspn(token_start, ",: \t");
	*pptr = token_start + toklen;
	/*
	 * got token, now look it up
	 */
	for (i = 0; i < tab_len; i++) {
		if ((strncasecmp(token_start, table[i].tok_str,
		    toklen) == 0) && (table[i].tok_str[toklen] == '\0')) {
			*fun = table[i].action;
			return (table[i].tok);
		}
	}
	if (lineNo != 0)
		SYSLOG(LOG_ERR, EM_UNKN_TOK, lineNo);
	return (TOKEN_ERROR);
}

static int
act_version(str *p_str, led_dtls_t *dtls)
{
	dtls->ver_maj = strtoul(*p_str, p_str, 0);
	if (*(*p_str)++ != '.') {
		SYSLOG(LOG_ERR, EM_VER_FRMT);
		return (-1);
	}
	dtls->ver_min = strtoul(*p_str, p_str, 0);
	if ((**p_str != '\0') && !isspace(**p_str)) {
		SYSLOG(LOG_ERR, EM_VER_FRMT);
		return (-1);
	}
	if ((dtls->ver_maj != 1) || (dtls->ver_min != 0)) {
		SYSLOG(LOG_ERR, EM_WRNGVER, dtls->ver_maj, dtls->ver_min);
		return (-1);
	}
	return (0);
}

/*
 * get space to hold white-space terminated string at *p_str
 * advance *p_str to point to terminator
 * return copy of string, null terminated
 */
static int
get_cstr(str *p_str, cstr *p_cstr_res)
{
	int ch;
	int len;
	char *ptr;

	while (isspace(**p_str))
		(*p_str)++;
	ptr = *p_str;

	do {
		ch = *++ptr;
	} while ((ch != '\0') && (!isspace(ch)));

	len = ptr - *p_str;
	if (*p_cstr_res != NULL)
		free((void *)(*p_cstr_res));
	ptr = malloc(len + 1);
	*p_cstr_res = ptr;
	if (ptr == NULL) {
		return (ENOMEM);
	}
	(void) memcpy(ptr, *p_str, len);
	ptr[len] = '\0';
	(*p_str) += len;
	return (0);
}

static int
act_leds_board(str *p_str, led_dtls_t *dtls)
{
	int res = get_cstr(p_str, &dtls->fcal_leds);
	if (res == 0) {
		if (dtls->fcal_leds[0] != '/') {
			free((void *)dtls->fcal_leds);
			dtls->fcal_leds = NULL;
			SYSLOG(LOG_ERR, EM_REL_PATH);
			return (-1);
		}
	}
	return (res);
}

static int
act_status_board(str *p_str, led_dtls_t *dtls)
{
	int res = get_cstr(p_str, &dtls->fcal_status);
	if (res == 0) {
		if (dtls->fcal_status[0] != '/') {
			free((void *)dtls->fcal_status);
			dtls->fcal_status = NULL;
			SYSLOG(LOG_ERR, EM_REL_PATH);
			return (-1);
		}
	}
	return (res);
}

static int
act_disk_driver(str *p_str, led_dtls_t *dtls)
{
	return (get_cstr(p_str, &dtls->fcal_driver));
}

static int
act_disk_parent(str *p_str, led_dtls_t *dtls)
{
	return (get_cstr(p_str, &dtls->fcal_disk_parent));
}

static int
act_unit_parent(str *p_str, led_dtls_t *dtls)
{
	return (get_cstr(p_str, &dtls->disk_unit_parent));
}

static int
act_led_nodes(str *p_str, led_dtls_t *dtls)
{
	return (get_cstr(p_str, &dtls->disk_led_nodes));
}

/*
 * A number of fields in the led_dtls_t structure have per-disk copies.
 * This action routine creates the space for all such fields.
 * Following any failure, an error is returned and the calling routine
 * must handle the fact that only a subset of these fields are populated.
 * In practice, this function is only called by get_token() on behalf of
 * fc_led_parse(). fc_led_parse calls free_led_dtls() after any error.
 */
static int
act_n_disks(str *p_str, led_dtls_t *dtls)
{
	int i;

	if (dtls->n_disks != 0) {
		SYSLOG(LOG_ERR, EM_NDISKS_DBL);
		return (-1);
	}
	dtls->n_disks = strtoul(*p_str, p_str, 0);
	if ((**p_str != '\0') && !isspace(**p_str)) {
		SYSLOG(LOG_ERR, EM_NUM_TERM);
		return (-1);
	}
	if (dtls->n_disks < 1) {
		SYSLOG(LOG_ERR, EM_NO_DISKS);
		return (-1);
	}
	dtls->presence = calloc(dtls->n_disks, sizeof (int));
	if (dtls->presence == NULL)
		return (ENOMEM);
	dtls->faults = calloc(dtls->n_disks, sizeof (int));
	if (dtls->faults == NULL)
		return (ENOMEM);
	dtls->disk_detected = calloc(dtls->n_disks, sizeof (int));
	if (dtls->disk_detected == NULL)
		return (ENOMEM);
	dtls->disk_ready = calloc(dtls->n_disks, sizeof (int));
	if (dtls->disk_ready == NULL)
		return (ENOMEM);
	dtls->disk_prev = calloc(dtls->n_disks, sizeof (int));
	if (dtls->disk_prev == NULL)
		return (ENOMEM);
	dtls->led_test_end = calloc(dtls->n_disks, sizeof (int));
	if (dtls->led_test_end == NULL)
		return (ENOMEM);
	dtls->picl_retry = calloc(dtls->n_disks, sizeof (boolean_t));
	if (dtls->picl_retry == NULL)
		return (ENOMEM);
	dtls->disk_port = calloc(dtls->n_disks, sizeof (char *));
	if (dtls->disk_port == NULL) {
		return (ENOMEM);
	}
	for (i = 0; i < FCAL_LED_CNT; i++) {
		dtls->led_addr[i] = calloc(dtls->n_disks, sizeof (int));
		if (dtls->led_addr[i] == NULL)
			return (ENOMEM);
		dtls->led_state[i] = calloc(dtls->n_disks,
		    sizeof (led_state_t));
		if (dtls->led_state[i] == NULL)
			return (ENOMEM);
	}
	return (0);
}

static int
get_assert(str *p_str, int *assert)
{
	int i = strtoul(*p_str, p_str, 0);
	if ((**p_str != '\0') && !isspace(**p_str)) {
		SYSLOG(LOG_ERR, EM_NUM_TERM);
		return (-1);
	}
	if ((i != 0) && (i != 1)) {
		SYSLOG(LOG_ERR, EM_LOGIC_LVL);
		return (-1);
	}
	*assert = i;
	return (0);
}

static int
get_pnz(str *p_str, int *pnz)
{
	int i = strtoul(*p_str, p_str, 0);
	if ((**p_str != '\0') && !isspace(**p_str)) {
		SYSLOG(LOG_ERR, EM_NUM_TERM);
		return (-1);
	}
	if (i < 1) {
		SYSLOG(LOG_ERR, EM_NOTPOS);
		return (-1);
	}
	*pnz = i;
	return (0);
}

static int
act_asrt_pres(str *p_str, led_dtls_t *dtls)
{
	return (get_assert(p_str, &dtls->assert_presence));
}

static int
act_asrt_fault(str *p_str, led_dtls_t *dtls)
{
	return (get_assert(p_str, &dtls->assert_fault));
}

static int
act_led_on(str *p_str, led_dtls_t *dtls)
{
	return (get_assert(p_str, &dtls->assert_led_on));
}

static int
get_mask(str *p_str, int n_disks, int *p_intarray)
{
	int i;
	int j = strtoul(*p_str, p_str, 0);
	if (*(*p_str)++ != ',') {
		SYSLOG(LOG_ERR, EM_NUM_TERM);
		return (-1);
	}
	if ((j < 0) || (j > n_disks)) {
		SYSLOG(LOG_ERR, EM_DISK_RANGE);
		return (-1);
	}
	i = strtoul(*p_str, p_str, 0);
	if ((**p_str != '\0') && !isspace(**p_str)) {
		SYSLOG(LOG_ERR, EM_NUM_TERM);
		return (-1);
	}
	p_intarray[j] = i;
	return (0);
}

static int
act_disk_present(str *p_str, led_dtls_t *dtls)
{
	return (get_mask(p_str, dtls->n_disks, dtls->presence));
}

static int
act_disk_fault(str *p_str, led_dtls_t *dtls)
{
	return (get_mask(p_str, dtls->n_disks, dtls->faults));
}

static int
act_led_id(str *p_str, led_dtls_t *dtls)
{
	token_t		tok;
	actfun_t	action;
	int		i;
	int		j = strtoul(*p_str, p_str, 0);

	if (*(*p_str)++ != ',') {
		SYSLOG(LOG_ERR, EM_NUM_TERM);
		return (-1);
	}
	if ((j < 0) || (j >= dtls->n_disks)) {
		SYSLOG(LOG_ERR, EM_DISK_RANGE);
		return (-1);
	}
	tok = get_token(p_str, 0, &action);
	if ((tok <= LED_PROPS_START) || (tok >= LED_PROPS_END)) {
		SYSLOG(LOG_ERR, EM_NO_LED_PROP);
		return (-1);
	}
	if (*(*p_str)++ != ',') {
		SYSLOG(LOG_ERR, EM_PROP_TERM);
		return (-1);
	}
	i = strtoul(*p_str, p_str, 0);
	if ((**p_str != '\0') && !isspace(**p_str)) {
		SYSLOG(LOG_ERR, EM_NUM_TERM);
		return (-1);
	}
	dtls->led_addr[tok - FCAL_REMOK_LED][j] = i;
	return (0);
}

static int
act_slow_poll(str *p_str, led_dtls_t *dtls)
{
	return (get_pnz(p_str, &dtls->slow_poll_ticks));
}

static int
act_fast_poll(str *p_str, led_dtls_t *dtls)
{
	return (get_pnz(p_str, &dtls->fast_poll));
}

static int
act_relax_interval(str *p_str, led_dtls_t *dtls)
{
	return (get_pnz(p_str, &dtls->relax_time_ticks));
}

static int
act_test_interval(str *p_str, led_dtls_t *dtls)
{
	return (get_pnz(p_str, &dtls->led_test_time));
}

/*
 * Create a led_dtls_t structure
 * Parse configuration file and populate the led_dtls_t
 * In the event of an error, free the structure and return an error
 */
int
fc_led_parse(FILE *fp, led_dtls_t **p_dtls)
{
	int		lineNo = 0;
	int		err = 0;
	char		linebuf[160];
	char		*ptr;
	led_dtls_t	*dtls = calloc(1, sizeof (led_dtls_t));
	actfun_t	action;
	token_t		tok;

	*p_dtls = dtls;
	if (dtls == NULL) {
		return (ENOMEM);
	}
	dtls->ver_min = -1;	/* mark as version unknown */

	while ((ptr = fgets(linebuf, sizeof (linebuf), fp)) != NULL) {
		lineNo++;
		tok = get_token(&ptr, lineNo, &action);
		if (tok == NO_TOKEN)
			continue;
		if (tok == TOKEN_ERROR) {
			err = -1;
			break;
		}
		if (tok == FCAL_VERSION) {
			if ((err = (*action)(&ptr, dtls)) != 0)
				break;
			else
				continue;
		}
		if (dtls->ver_min < 0) {
			SYSLOG(LOG_ERR, EM_NOVERS);
			err = -1;
			break;
		}
		if (tok <= LINE_DEFS) {
			SYSLOG(LOG_ERR, EM_INVAL_TOK, lineNo);
			err = -1;
			break;
		}
		if (*ptr++ != ':') {
			SYSLOG(LOG_ERR, EM_NOCOLON, lineNo);
			err = -1;
			break;
		}
		if ((err = (*action)(&ptr, dtls)) != 0) {
			SYSLOG(LOG_ERR, EM_ERRLINE, lineNo);
			break;
		}
		else
			continue;
	}

	if (err == 0) {
		err = -1;	/* just in case */
		if (dtls->ver_min < 0) {
			SYSLOG(LOG_ERR, EM_NOVERS);
		} else if (dtls->n_disks == 0) {
			SYSLOG(LOG_ERR, EM_NO_DISKS);
		} else if (dtls->fcal_leds == NULL) {
			SYSLOG(LOG_ERR, EM_STR_NOT_SET, "fcal-leds");
		} else if (dtls->fcal_status == NULL) {
			SYSLOG(LOG_ERR, EM_STR_NOT_SET, "fcal-status");
		} else if (dtls->fcal_driver == NULL) {
			SYSLOG(LOG_ERR, EM_STR_NOT_SET, "fcal-driver");
		} else
			err = 0;
	}

	if (err != 0) {
		/*
		 * clean up after error detected
		 */
		free_led_dtls(dtls);
		*p_dtls = NULL;
		return (err);
	}

	/*
	 * set any unset timers to default time
	 */
	if (dtls->slow_poll_ticks == 0)
		dtls->slow_poll_ticks = DFLT_SLOW_POLL;
	if (dtls->fast_poll == 0)
		dtls->fast_poll = DFLT_FAST_POLL;
	if (dtls->relax_time_ticks == 0)
		dtls->relax_time_ticks = DFLT_RELAX_TIME;
	if (dtls->led_test_time == 0)
		dtls->led_test_time = DFLT_TEST_TIME;

	/*
	 * set polling flag to avoid a start-up glitch
	 * it will be cleared again if the poll thread fails
	 */
	dtls->polling = B_TRUE;

	/*
	 * convert derived timers to multiples of fast poll time
	 */
	dtls->slow_poll_ticks += dtls->fast_poll - 1;	/* for round up */
	dtls->slow_poll_ticks /= dtls->fast_poll;
	dtls->relax_time_ticks += dtls->fast_poll - 1;
	dtls->relax_time_ticks /= dtls->fast_poll;
	dtls->led_test_time += dtls->fast_poll - 1;
	dtls->led_test_time /= dtls->fast_poll;
	return (0);
}

void
free_led_dtls(led_dtls_t *dtls)
{
	int	i;

	if (dtls == NULL)
		return;
	if (dtls->fcal_leds != NULL)
		free((void *)dtls->fcal_leds);
	if (dtls->fcal_status != NULL)
		free((void *)dtls->fcal_status);
	if (dtls->fcal_driver != NULL)
		free((void *)dtls->fcal_driver);
	if (dtls->presence != NULL)
		free((void *)dtls->presence);
	if (dtls->faults != NULL)
		free((void *)dtls->faults);
	if (dtls->disk_detected != NULL)
		free((void *)dtls->disk_detected);
	if (dtls->disk_ready != NULL)
		free((void *)dtls->disk_ready);
	if (dtls->disk_prev != NULL)
		free((void *)dtls->disk_prev);
	if (dtls->led_test_end != NULL)
		free((void *)dtls->led_test_end);
	if (dtls->picl_retry != NULL)
		free((void *)dtls->picl_retry);
	if (dtls->disk_port != NULL) {
		for (i = 0; i < dtls->n_disks; i++) {
			if (dtls->disk_port[i] != NULL)
				free(dtls->disk_port[i]);
		}
		free(dtls->disk_port);
	}
	for (i = 0; i < FCAL_LED_CNT; i++) {
		if (dtls->led_addr[i] != NULL)
			free((void *)dtls->led_addr[i]);
		if (dtls->led_state[i] != NULL)
			free((void *)dtls->led_state[i]);
	}

	free(dtls);
}
