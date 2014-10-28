/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#define	DEF_MSG_STRUCT	/* Needed for emlxs_messages.h in emlxs_msg.h */
#include <emlxs.h>

uint32_t emlxs_log_size		= 2048;
uint32_t emlxs_log_debugs	= 0x7FFFFFFF;
uint32_t emlxs_log_notices	= 0xFFFFFFFF;
uint32_t emlxs_log_warnings	= 0xFFFFFFFF;
uint32_t emlxs_log_errors	= 0xFFFFFFFF;

static uint32_t	emlxs_msg_log_check(emlxs_port_t *port, emlxs_msg_t *msg);
static uint32_t	emlxs_msg_print_check(emlxs_port_t *port, emlxs_msg_t *msg);
static void	emlxs_msg_sprintf(char *buffer, emlxs_msg_entry_t *entry);


uint32_t
emlxs_msg_log_create(emlxs_hba_t *hba)
{
	emlxs_msg_log_t *log = &LOG;
	uint32_t size = sizeof (emlxs_msg_entry_t) * emlxs_log_size;
	ddi_iblock_cookie_t iblock;

	/* Check if log is already created */
	if (log->entry) {
		cmn_err(CE_WARN, "?%s%d: message log already created. log=%p",
		    DRIVER_NAME, hba->ddiinst, (void *)log);
		return (0);
	}

	/* Clear the log */
	bzero(log, sizeof (emlxs_msg_log_t));

	/* Allocate the memory needed for the log file */
	log->entry = (emlxs_msg_entry_t *)kmem_zalloc(size, KM_SLEEP);

	/* Initialize */
	log->size = emlxs_log_size;
	log->instance = hba->ddiinst;
	log->start_time = emlxs_device.log_timestamp;

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		/* Get the current interrupt block cookie */
		(void) ddi_get_iblock_cookie(hba->dip, (uint_t)EMLXS_INUMBER,
		    &iblock);

		/* Create the log mutex lock */
		mutex_init(&log->lock, NULL, MUTEX_DRIVER, (void *)iblock);
	}
#ifdef  MSI_SUPPORT
	else {
		/* Create the temporary log mutex lock */
		mutex_init(&log->lock, NULL, MUTEX_DRIVER, NULL);
	}
#endif

	return (1);

} /* emlxs_msg_log_create() */


void
emlxs_msg_lock_reinit(emlxs_hba_t *hba)
{
	emlxs_msg_log_t *log = &LOG;

	/* Check if log is already destroyed */
	if (!log->entry) {
		cmn_err(CE_WARN,
		    "?%s%d: message log already destroyed. log=%p",
		    DRIVER_NAME, hba->ddiinst, (void *)log);

		return;
	}

	/* Destroy the temporary lock */
	mutex_destroy(&log->lock);

	/* Re-create the log mutex lock */
	mutex_init(&log->lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(hba->intr_arg));

	return;

} /* emlxs_msg_lock_reinit() */

void
emlxs_msg_log_destroy(emlxs_hba_t *hba)
{
	emlxs_msg_log_t *log = &LOG;
	uint32_t size;

	/* Check if log is already destroyed */
	if (!log->entry) {
		cmn_err(CE_WARN,
		    "?%s%d: message log already destroyed. log=%p",
		    DRIVER_NAME, hba->ddiinst, (void *)log);

		return;
	}

	/* Destroy the lock */
	mutex_destroy(&log->lock);

	/* Free the log buffer */
	size = sizeof (emlxs_msg_entry_t) * log->size;
	kmem_free(log->entry, size);

	/* Clear the log */
	bzero(log, sizeof (emlxs_msg_log_t));

	return;

} /* emlxs_msg_log_destroy() */


uint32_t
emlxs_msg_log(emlxs_port_t *port, const uint32_t fileno, const uint32_t line,
    emlxs_msg_t *msg, char *buffer)
{
	emlxs_hba_t *hba = HBA;
	emlxs_msg_entry_t *entry;
	emlxs_msg_entry_t *entry2;
	clock_t time;
	emlxs_msg_log_t *log;
	uint32_t last;
	emlxs_msg_t *msg2;

	/* Get the log file for this instance */
	log = &LOG;

	/* Check if log is initialized */
	if (log->entry == NULL) {
		return (0);
	}

	mutex_enter(&log->lock);

	/* Get the pointer to the last log entry */
	if (log->next == 0) {
		last = log->size - 1;
	} else {
		last = log->next - 1;
	}
	entry = &log->entry[last];

	/* Check if this matches the last message */
	if ((entry->instance == log->instance) &&
	    (entry->vpi == port->vpi) &&
	    (entry->fileno == fileno) &&
	    (entry->line == line) &&
	    (entry->msg == msg) &&
	    (strcmp(entry->buffer, buffer) == 0)) {
		/* If the same message is being logged then increment */
		log->repeat++;

		mutex_exit(&log->lock);

		return (0);
	} else if (log->repeat) {
		/* Get the pointer to the next log entry */
		entry2 = &log->entry[log->next];

		/* Increment and check the next entry index */
		if (++(log->next) >= log->size) {
			log->next = 0;
		}

		switch (entry->msg->level) {
		case EMLXS_NOTICE:
			msg2 = &emlxs_notice_msg;
			break;

		case EMLXS_WARNING:
			msg2 = &emlxs_warning_msg;
			break;

		case EMLXS_ERROR:
			msg2 = &emlxs_error_msg;
			break;

		case EMLXS_PANIC:
			msg2 = &emlxs_panic_msg;
			break;

		case EMLXS_DEBUG:
		default:
			msg2 = &emlxs_debug_msg;
			break;
		}

		/* Initialize */
		entry2->id = log->count++;
		entry2->fileno = entry->fileno;
		entry2->line = entry->line;
		entry2->msg = msg2;
		entry2->instance = log->instance;
		entry2->vpi = port->vpi;

		/* Save the additional info buffer */
		(void) snprintf(entry2->buffer, MAX_LOG_INFO_LENGTH,
		    "Last message repeated %d time(s).",
		    log->repeat);

		/* Set the entry time stamp */
		(void) drv_getparm(LBOLT, &time);
		entry2->time = time - log->start_time;

		gethrestime(&entry2->id_time);

		log->repeat = 0;
	}

	/* Get the pointer to the next log entry */
	entry = &log->entry[log->next];

	/* Increment and check the next entry index */
	if (++(log->next) >= log->size) {
		log->next = 0;
	}

	/* Initialize */
	entry->id = log->count++;
	entry->fileno = fileno;
	entry->line = line;
	entry->msg = msg;
	entry->instance = log->instance;
	entry->vpi = port->vpi;

	/* Save the additional info buffer */
	(void) strncpy(entry->buffer, buffer, (MAX_LOG_INFO_LENGTH - 1));
	entry->buffer[MAX_LOG_INFO_LENGTH - 1] = 0;

	/* Set the entry time stamp */
	(void) drv_getparm(LBOLT, &time);
	entry->time = time - log->start_time;

	gethrestime(&entry->id_time);

	mutex_exit(&log->lock);

	return (0);

} /* emlxs_msg_log() */


/*ARGSUSED*/
static uint32_t
emlxs_msg_log_check(emlxs_port_t *port, emlxs_msg_t *msg)
{

	switch (msg->level) {
	case EMLXS_DEBUG:
		if (msg->mask & emlxs_log_debugs) {
			return (1);
		}
		break;

	case EMLXS_NOTICE:
		if (msg->mask & emlxs_log_notices) {
			return (1);
		}
		break;

	case EMLXS_WARNING:
		if (msg->mask & emlxs_log_warnings) {
			return (1);
		}
		break;

	case EMLXS_ERROR:
		if (msg->mask & emlxs_log_errors) {
			return (1);
		}
		break;

	case EMLXS_PANIC:
		return (1);
	}

	return (0);

} /* emlxs_msg_log_check() */


static uint32_t
emlxs_msg_print_check(emlxs_port_t *port, emlxs_msg_t *msg)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg;
	uint32_t rval = 0;

	cfg = &CFG;

	switch (msg->level) {
	case EMLXS_DEBUG:
		if (msg->mask & cfg[CFG_CONSOLE_DEBUGS].current) {
			rval |= 2;
		}

		if (msg->mask & cfg[CFG_LOG_DEBUGS].current) {
			rval |= 1;
		}

		break;

	case EMLXS_NOTICE:
		if (msg->mask & cfg[CFG_CONSOLE_NOTICES].current) {
			rval |= 2;
		}

		if (msg->mask & cfg[CFG_LOG_NOTICES].current) {
			rval |= 1;
		}

		break;

	case EMLXS_WARNING:
		if (msg->mask & cfg[CFG_CONSOLE_WARNINGS].current) {
			rval |= 2;
		}

		if (msg->mask & cfg[CFG_LOG_WARNINGS].current) {
			rval |= 1;
		}

		break;

	case EMLXS_ERROR:
		if (msg->mask & cfg[CFG_CONSOLE_ERRORS].current) {
			rval |= 2;
		}

		if (msg->mask & cfg[CFG_LOG_ERRORS].current) {
			rval |= 1;
		}
		break;

	case EMLXS_PANIC:
	default:
		rval |= 1;

	}

	return (rval);

} /* emlxs_msg_print_check() */


void
emlxs_msg_printf(emlxs_port_t *port, const uint32_t fileno,
    const uint32_t line, emlxs_msg_t *msg,
    const char *fmt, ...)
{
	emlxs_hba_t *hba = HBA;
	va_list valist;
	char va_str[256];
	char msg_str[512];
	char *level;
	int32_t cmn_level;
	uint32_t rval;
	char driver[32];

	va_str[0] = 0;

	if (fmt) {
		va_start(valist, fmt);
		(void) vsnprintf(va_str, sizeof (va_str), fmt, valist);
		va_end(valist);
	}

#ifdef FMA_SUPPORT
	if (msg->fm_ereport_code) {
		emlxs_fm_ereport(hba, msg->fm_ereport_code);
	}

	if (msg->fm_impact_code) {
		emlxs_fm_service_impact(hba, msg->fm_impact_code);
	}
#endif	/* FMA_SUPPORT */

	/* Check if msg should be logged */
	if (emlxs_msg_log_check(port, msg)) {
		/* Log the message */
		if (emlxs_msg_log(port, fileno, line, msg, va_str)) {
			return;
		}
	}

	/* Check if msg should be printed */
	if (rval = emlxs_msg_print_check(port, msg)) {
		cmn_level = CE_CONT;

		switch (msg->level) {
		case EMLXS_DEBUG:
			level = "  DEBUG";
			break;

		case EMLXS_NOTICE:
			level = " NOTICE";
			break;

		case EMLXS_WARNING:
			level = "WARNING";
			break;

		case EMLXS_ERROR:
			level = "  ERROR";
			break;

		case EMLXS_PANIC:
			cmn_level = CE_PANIC;
			level = "  PANIC";
			break;

		default:
			level = "UNKNOWN";
			break;
		}

		if (port->vpi == 0) {
			(void) snprintf(driver, sizeof (driver), "%s%d",
			    DRIVER_NAME, hba->ddiinst);
		} else {
			(void) snprintf(driver, sizeof (driver), "%s%d.%d",
			    DRIVER_NAME, hba->ddiinst, port->vpi);
		}

		/* Generate the message string */
		if (msg->buffer[0] != 0) {
			if (va_str[0] != 0) {
				(void) snprintf(msg_str, sizeof (msg_str),
				    "[%2X.%04X]%s:%7s:%4d: %s (%s)\n", fileno,
				    line, driver, level, msg->id, msg->buffer,
				    va_str);
			} else {
				(void) snprintf(msg_str, sizeof (msg_str),
				    "[%2X.%04X]%s:%7s:%4d: %s\n",
				    fileno, line, driver, level, msg->id,
				    msg->buffer);
			}
		} else {
			if (va_str[0] != 0) {
				(void) snprintf(msg_str, sizeof (msg_str),
				    "[%2X.%04X]%s:%7s:%4d: (%s)\n", fileno,
				    line, driver, level, msg->id, va_str);
			} else {
				(void) snprintf(msg_str, sizeof (msg_str),
				    "[%2X.%04X]%s:%7s:%4d\n",
				    fileno, line, driver, level, msg->id);
			}
		}

		switch (rval) {
		case 1:	/* MESSAGE LOG ONLY */
			/* Message log & console, if system booted in */
			/* verbose mode (CE_CONT only) */
			cmn_err(cmn_level, "?%s", msg_str);
			break;

		case 2:	/* CONSOLE ONLY */
			cmn_err(cmn_level, "^%s", msg_str);
			break;

		case 3:	/* CONSOLE AND MESSAGE LOG */
			cmn_err(cmn_level, "%s", msg_str);
			break;

		}

	}

	return;

} /* emlxs_msg_printf() */


uint32_t
emlxs_msg_log_get(emlxs_hba_t *hba, emlxs_log_req_t *req,
    emlxs_log_resp_t *resp)
{
	emlxs_msg_log_t *log;
	uint32_t first;
	uint32_t last;
	uint32_t count;
	uint32_t index;
	uint32_t i;
	char *resp_buf;

	log = &LOG;

	mutex_enter(&log->lock);

	/* Check if buffer is empty */
	if (log->count == 0) {
		/* If so, exit now */
		resp->first = 0;
		resp->last = 0;
		resp->count = 0;
		mutex_exit(&log->lock);

		return (1);
	}

	/* Get current log entry ranges */

	/* Get last entry id saved */
	last = log->count - 1;

	/* Check if request is out of current range */
	if (req->first > last) {
		/* if so, exit now */
		resp->first = last;
		resp->last = last;
		resp->count = 0;
		mutex_exit(&log->lock);

		return (0);
	}

	/* Get oldest entry id and its index */

	/* Check if buffer has already been filled once */
	if (log->count >= log->size) {
		first = log->count - log->size;
		index = log->next;
	} else {	/* Buffer not yet filled */

		first = 0;
		index = 0;
	}

	/* Check if requested first message is greater than actual. */
	/* If so, adjust for it.  */
	if (req->first > first) {
		/* Adjust entry index to first requested message */
		index += (req->first - first);
		if (index >= log->size) {
			index -= log->size;
		}

		first = req->first;
	}

	/* Get the total number of messages available for return */
	count = last - first + 1;

	/* Check if requested count is less than actual.  If so, adjust it. */
	if (req->count < count) {
		count = req->count;
	}

	/* Fill in the response header */
	resp->count = count;
	resp->first = first;
	resp->last = last;

	/* Fill the response buffer */
	resp_buf = (char *)resp + sizeof (emlxs_log_resp_t);
	for (i = 0; i < count; i++) {
		emlxs_msg_sprintf(resp_buf, &log->entry[index]);

		/* Increment the response buffer */
		resp_buf += MAX_LOG_MSG_LENGTH;

		/* Increment index */
		if (++index >= log->size) {
			index = 0;
		}
	}

	mutex_exit(&log->lock);

	return (1);

} /* emlxs_msg_log_get() */



static void
emlxs_msg_sprintf(char *buffer, emlxs_msg_entry_t *entry)
{
	char *level;
	emlxs_msg_t *msg;
	uint32_t secs;
	uint32_t hsecs;
	char buf[256];
	uint32_t buflen;
	char driver[32];

	msg = entry->msg;

	hsecs = (entry->time % 100);
	secs = entry->time / 100;

	switch (msg->level) {
	case EMLXS_DEBUG:
		level = "  DEBUG";
		break;

	case EMLXS_NOTICE:
		level = " NOTICE";
		break;

	case EMLXS_WARNING:
		level = "WARNING";
		break;

	case EMLXS_ERROR:
		level = "  ERROR";
		break;

	case EMLXS_PANIC:
		level = "  PANIC";
		break;

	default:
		level = "UNKNOWN";
		break;
	}

	if (entry->vpi == 0) {
		(void) snprintf(driver, sizeof (driver), "%s%d", DRIVER_NAME,
		    entry->instance);
	} else {
		(void) snprintf(driver, sizeof (driver), "%s%d.%d", DRIVER_NAME,
		    entry->instance, entry->vpi);
	}

	/* Generate the message string */
	if (msg->buffer[0] != 0) {
		if (entry->buffer[0] != 0) {
			(void) snprintf(buf, sizeof (buf),
			    "%8d.%02d: %6d:[%2X.%04X]%s:%7s:%4d: %s (%s)\n",
			    secs, hsecs, entry->id, entry->fileno,
			    entry->line, driver, level, msg->id, msg->buffer,
			    entry->buffer);

		} else {
			(void) snprintf(buf, sizeof (buf),
			    "%8d.%02d: %6d:[%2X.%04X]%s:%7s:%4d: %s\n", secs,
			    hsecs, entry->id, entry->fileno, entry->line,
			    driver, level, msg->id, msg->buffer);
		}
	} else {
		if (entry->buffer[0] != 0) {
			(void) snprintf(buf, sizeof (buf),
			    "%8d.%02d: %6d:[%2X.%04X]%s:%7s:%4d: (%s)\n",
			    secs, hsecs, entry->id, entry->fileno,
			    entry->line, driver, level, msg->id,
			    entry->buffer);
		} else {
			(void) snprintf(buf, sizeof (buf),
			    "%8d.%02d: %6d:[%2X.%04X]%s:%7s:%4d\n",
			    secs, hsecs, entry->id, entry->fileno,
			    entry->line, driver, level, msg->id);
		}
	}

	bzero(buffer, MAX_LOG_MSG_LENGTH);
	buflen = strlen(buf);

	if (buflen > (MAX_LOG_MSG_LENGTH - 1)) {
		(void) strncpy(buffer, buf, (MAX_LOG_MSG_LENGTH - 2));
		buffer[MAX_LOG_MSG_LENGTH - 2] = '\n';
	} else {
		(void) strncpy(buffer, buf, buflen);
	}

	return;

} /* emlxs_msg_sprintf() */
