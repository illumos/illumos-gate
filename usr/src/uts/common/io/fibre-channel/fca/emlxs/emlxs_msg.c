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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#define	 DEF_MSG_STRUCT	/* Needed for emlxs_messages.h in emlxs_msg.h */
#include "emlxs.h"


/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_MSG_C);

uint32_t emlxs_log_size = 1024;
/* uint32_t emlxs_log_debugs   = 0x000FFFFF; */
uint32_t emlxs_log_debugs = 0x7FFFFFFF;
uint32_t emlxs_log_notices = 0xFFFFFFFF;
uint32_t emlxs_log_warnings = 0xFFFFFFFF;
uint32_t emlxs_log_errors = 0xFFFFFFFF;

static uint32_t emlxs_msg_log_check(emlxs_port_t *port, emlxs_msg_t *msg);
static uint32_t emlxs_msg_print_check(emlxs_port_t *port, emlxs_msg_t *msg);
static void emlxs_msg_sprintf(char *buffer, emlxs_msg_entry_t *entry);


uint32_t
emlxs_msg_log_create(emlxs_hba_t *hba)
{
	emlxs_msg_log_t *log = &LOG;
	uint32_t size = sizeof (emlxs_msg_entry_t) * emlxs_log_size;
	char buf[40];
#ifdef MSI_SUPPORT
	ddi_intr_handle_t handle;
	uint32_t intr_pri;
	int32_t actual;
	uint32_t ret;
#endif	/* MSI_SUPPORT */
	ddi_iblock_cookie_t iblock;

	/* Check if log is already created */
	if (log->entry) {
		cmn_err(CE_WARN, "?%s%d: message log already created. log=%p",
		    DRIVER_NAME, hba->ddiinst, (void *) log);
		return (0);
	}
	/* Clear the log */
	bzero(log, sizeof (emlxs_msg_log_t));

	/* Allocate the memory needed for the log file */
	if (!(log->entry = (emlxs_msg_entry_t *)kmem_zalloc(size, KM_SLEEP))) {
		cmn_err(CE_WARN, "?%s%d: Unable to allocate log memory. log=%p",
		    DRIVER_NAME, hba->ddiinst, (void *) log);
		return (0);
	}
	/* Initialize */
	log->size = emlxs_log_size;
	log->instance = hba->ddiinst;
	log->start_time = emlxs_device.log_timestamp;

	(void) sprintf(buf, "?%s%d_log_lock control variable", DRIVER_NAME,
	    hba->ddiinst);
	cv_init(&log->lock_cv, buf, CV_DRIVER, NULL);

	(void) sprintf(buf, "?%s%d_log_lock mutex", DRIVER_NAME, hba->ddiinst);

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		/* Get the current interrupt block cookie */
		(void) ddi_get_iblock_cookie(hba->dip, (uint_t)EMLXS_INUMBER,
		    &iblock);

		/* Create the log mutex lock */
		mutex_init(&log->lock, buf, MUTEX_DRIVER, (void *) iblock);
	}
#ifdef  MSI_SUPPORT
	else {

		/* Allocate a temporary interrupt handle */
		actual = 0;
		ret = ddi_intr_alloc(hba->dip, &handle, DDI_INTR_TYPE_FIXED,
		    EMLXS_MSI_INUMBER, 1, &actual, DDI_INTR_ALLOC_NORMAL);

		if (ret != DDI_SUCCESS || actual == 0) {
			cmn_err(CE_WARN, "?%s%d: Unable to allocate "
			    "temporary interrupt handle. ret=%d actual=%d",
			    DRIVER_NAME, hba->ddiinst, ret, actual);

			/* Free the log buffer */
			kmem_free(log->entry, size);
			bzero(log, sizeof (emlxs_msg_log_t));

			return (0);
		}
		/* Get the current interrupt priority */
		ret = ddi_intr_get_pri(handle, &intr_pri);

		if (ret != DDI_SUCCESS) {
			cmn_err(CE_WARN, "?%s%d: Unable to get interrupt "
			    "priority. ret=%d", DRIVER_NAME, hba->ddiinst, ret);

			/* Free the log buffer */
			kmem_free(log->entry, size);
			bzero(log, sizeof (emlxs_msg_log_t));

			return (0);
		}
		/* Create the log mutex lock */
		mutex_init(&log->lock, buf, MUTEX_DRIVER,
		    (void *)(unsigned long) intr_pri);

		/* Free the temporary handle */
		(void) ddi_intr_free(handle);
	}
#endif

	return (1);

} /* emlxs_msg_log_create() */


uint32_t
emlxs_msg_log_destroy(emlxs_hba_t *hba)
{
	emlxs_msg_log_t *log = &LOG;
	uint32_t size;
	emlxs_msg_entry_t *entry;
	uint32_t i;

	/* Check if log is already destroyed */
	if (!log->entry) {
		cmn_err(CE_WARN, "?%s%d: message log already destroyed. log=%p",
		    DRIVER_NAME, hba->ddiinst, (void *) log);

		return (1);
	}
	/*
	 * If events are being logged there might be threads waiting so
	 * release them
	 */
	if (hba->log_events) {
		mutex_enter(&log->lock);
		hba->log_events = 0;
		cv_broadcast(&log->lock_cv);
		mutex_exit(&log->lock);

		DELAYMS(1);
	}
	/* Destroy the lock */
	mutex_destroy(&log->lock);
	cv_destroy(&log->lock_cv);

	/* Free the context buffers */
	for (i = 0; i < log->size; i++) {
		entry = &log->entry[i];

		if (entry->bp && entry->size) {
			kmem_free(entry->bp, entry->size);
		}
	}

	/* Free the log buffer */
	size = sizeof (emlxs_msg_entry_t) * log->size;
	kmem_free(log->entry, size);

	/* Clear the log */
	bzero(log, sizeof (emlxs_msg_log_t));

	return (1);

} /* emlxs_msg_log_destroy() */



uint32_t
emlxs_msg_log(emlxs_port_t *port, const uint32_t fileno, const uint32_t line,
    void *bp, uint32_t size, emlxs_msg_t *msg, char *buffer)
{
	emlxs_hba_t *hba = HBA;
	emlxs_msg_entry_t *entry;
	emlxs_msg_entry_t *entry2;
	clock_t time;
	emlxs_msg_log_t *log;
	uint32_t last;
	uint32_t mask;
	emlxs_msg_t *msg2;
	uint32_t i;

	/* Get the log file for this instance */
	log = &LOG;

	/* Check if log is initialized */
	if (log->entry == NULL) {

		if (port->vpi == 0) {
			cmn_err(CE_WARN, "?%s%d: message log not created. "
			    "log=%p", DRIVER_NAME, hba->ddiinst, (void *) log);
		} else {
			cmn_err(CE_WARN, "?%s%d.%d: message log not created. "
			    "log=%p", DRIVER_NAME, hba->ddiinst, port->vpi,
			    (void *) log);
		}

		if (bp && size) {
			kmem_free(bp, size);
		}
		return (1);
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
	    (entry->bp == bp) &&
	    (entry->size == size) &&
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
		case EMLXS_DEBUG:
			msg2 = &emlxs_debug_msg;
			break;

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

		case EMLXS_EVENT:
			msg2 = &emlxs_event_msg;
			break;
		}

		/* Check if we are about to overwrite an event entry */
		if (entry2->msg && (entry2->msg->level == EMLXS_EVENT)) {
			/* Check if this event has not been acquired */
			if (log->count > (hba->hba_event.last_id + log->size)) {
				hba->hba_event.missed++;
			}
		}
		/* Free the old context buffer since we are about to erase it */
		if (entry2->bp && entry2->size) {
			kmem_free(entry2->bp, entry2->size);
		}
		/* Initialize */
		entry2->id = log->count++;
		entry2->fileno = entry->fileno;
		entry2->line = entry->line;
		entry2->bp = 0;
		entry2->size = 0;
		entry2->msg = msg2;
		entry2->instance = log->instance;
		entry2->vpi = port->vpi;

		/* Save the additional info buffer */
		(void) sprintf(entry2->buffer,
		    "Last message repeated %d time(s).",
		    log->repeat);

		/* Set the entry time stamp */
		(void) drv_getparm(LBOLT, &time);
		entry2->time = time - log->start_time;

		log->repeat = 0;
	}
	/* Get the pointer to the next log entry */
	entry = &log->entry[log->next];

	/* Increment and check the next entry index */
	if (++(log->next) >= log->size) {
		log->next = 0;
	}
	/* Check if we are about to overwrite an event entry */
	if (entry->msg && (entry->msg->level == EMLXS_EVENT)) {
		/* Check if this event has not been acquired */
		if (log->count > (hba->hba_event.last_id + log->size)) {
			hba->hba_event.missed++;
		}
	}
	/* Free the old context buffer since we are about to erase it */
	if (entry->bp && entry->size) {
		kmem_free(entry->bp, entry->size);
	}
	/* Initialize */
	entry->id = log->count++;
	entry->fileno = fileno;
	entry->line = line;
	entry->bp = bp;
	entry->size = size;
	entry->msg = msg;
	entry->instance = log->instance;
	entry->vpi = port->vpi;

	/* Save the additional info buffer */
	(void) strncpy(entry->buffer, buffer, (MAX_LOG_INFO_LENGTH - 1));
	entry->buffer[MAX_LOG_INFO_LENGTH - 1] = 0;

	/* Set the entry time stamp */
	(void) drv_getparm(LBOLT, &time);
	entry->time = time - log->start_time;

	/* Check for a new event */
	if (msg->level == EMLXS_EVENT) {
		/* Update the event id */
		mask = msg->mask;
		for (i = 0; i < 32; i++) {
			if (mask & 0x01) {
				hba->hba_event.new++;
				log->event_id[i] = entry->id;
				cv_broadcast(&log->lock_cv);
				break;
			}
			mask >>= 1;
		}
	}
	mutex_exit(&log->lock);

	return (0);

} /* emlxs_msg_log() */


static uint32_t
emlxs_msg_log_check(emlxs_port_t *port, emlxs_msg_t *msg)
{
	emlxs_hba_t *hba = HBA;

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

	case EMLXS_EVENT:
		if (msg->mask & hba->log_events) {
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

	case EMLXS_EVENT:
		/* Only print an event if it is being logged internally */
		if (msg->mask & hba->log_events) {
			if (msg->mask & cfg[CFG_CONSOLE_EVENTS].current) {
				rval |= 2;
			}
			if (msg->mask & cfg[CFG_LOG_EVENTS].current) {
				rval |= 1;
			}
		}
		break;

	case EMLXS_PANIC:
	default:
		rval |= 1;

	}

	return (rval);

} /* emlxs_msg_print_check() */


void
emlxs_msg_printf(emlxs_port_t *port, const uint32_t fileno, const uint32_t line,
    void *bp, uint32_t size, emlxs_msg_t *msg, const char *fmt, ...)
{
	emlxs_hba_t *hba = HBA;
	va_list valist;
	char va_str[256];
	char msg_str[512];
	char *level;
	int32_t cmn_level;
	uint32_t rval;
	uint32_t logged;
	char driver[32];

	va_str[0] = 0;

	if (fmt) {
		va_start(valist, fmt);
		(void) vsprintf(va_str, fmt, valist);
		va_end(valist);
	}
	/* Check if msg should be logged */
	if ((logged = emlxs_msg_log_check(port, msg))) {
		/* Log the message */
		if (emlxs_msg_log(port, fileno, line, bp, size, msg, va_str)) {
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

		case EMLXS_EVENT:
			level = "  EVENT";
			break;

		default:
			level = "UNKNOWN";
			break;
		}

		if (port->vpi == 0) {
			(void) sprintf(driver, "%s%d", DRIVER_NAME,
			    hba->ddiinst);
		} else {
			(void) sprintf(driver, "%s%d.%d", DRIVER_NAME,
			    hba->ddiinst, port->vpi);
		}

		/* Generate the message string */
		if (msg->buffer[0] != 0) {
			if (va_str[0] != 0) {
				(void) sprintf(msg_str,
				    "[%2X.%04X]%s:%7s:%4d: %s (%s)\n",
				    fileno, line, driver, level, msg->id,
				    msg->buffer, va_str);
			} else {
				(void) sprintf(msg_str,
				    "[%2X.%04X]%s:%7s:%4d: %s\n",
				    fileno, line, driver, level, msg->id,
				    msg->buffer);
			}
		} else {
			if (va_str[0] != 0) {
				(void) sprintf(msg_str,
				    "[%2X.%04X]%s:%7s:%4d: (%s)\n",
				    fileno, line, driver, level, msg->id,
				    va_str);
			} else {
				(void) sprintf(msg_str,
				    "[%2X.%04X]%s:%7s:%4d\n",
				    fileno, line, driver, level, msg->id);
			}
		}

		switch (rval) {
		case 1:	/* MESSAGE LOG ONLY */
			/* cmn_err(cmn_level, "!%s", msg_str); */
			/*
			 * Message log & console, if system booted in verbose
			 *   mode (CE_CONT only)
			 */
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
	/* If message was not logged, then free any context buffer provided */
	if (!logged && bp && size) {
		kmem_free(bp, size);
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

	/*
	 * Check if requested first message is greater than actual. If so,
	 * adjust for it.
	 */
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

	case EMLXS_EVENT:
		level = "  EVENT";
		break;

	default:
		level = "UNKNOWN";
		break;
	}

	if (entry->vpi == 0) {
		(void) sprintf(driver, "%s%d", DRIVER_NAME, entry->instance);
	} else {
		(void) sprintf(driver, "%s%d.%d", DRIVER_NAME, entry->instance,
		    entry->vpi);
	}

	/* Generate the message string */
	if (msg->buffer[0] != 0) {
		if (entry->buffer[0] != 0) {
			(void) sprintf(buf,
			    "%8d.%02d: %6d:[%2X.%04X]%s:%7s:%4d: %s (%s)\n",
			    secs, hsecs, entry->id, entry->fileno, entry->line,
			    driver, level, msg->id, msg->buffer, entry->buffer);

		} else {
			(void) sprintf(buf,
			    "%8d.%02d: %6d:[%2X.%04X]%s:%7s:%4d: %s\n",
			    secs, hsecs, entry->id, entry->fileno, entry->line,
			    driver, level, msg->id, msg->buffer);
		}
	} else {
		if (entry->buffer[0] != 0) {
			(void) sprintf(buf,
			    "%8d.%02d: %6d:[%2X.%04X]%s:%7s:%4d: (%s)\n",
			    secs, hsecs, entry->id, entry->fileno, entry->line,
			    driver, level, msg->id, entry->buffer);
		} else {
			(void) sprintf(buf,
			    "%8d.%02d: %6d:[%2X.%04X]%s:%7s:%4d\n",
			    secs, hsecs, entry->id, entry->fileno, entry->line,
			    driver, level, msg->id);
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




void
emlxs_log_rscn_event(emlxs_port_t *port, uint8_t *payload, uint32_t size)
{
#ifdef DFC_SUPPORT
	uint8_t *bp;
	uint32_t *ptr;

	/* Check if the event is being requested */
	/*
	 * if(!(hba->log_events & EVT_RSCN)) { return; }
	 */

	if (size > MAX_RSCN_PAYLOAD) {
		size = MAX_RSCN_PAYLOAD;
	}
	size += sizeof (uint32_t);

	/* Save a copy of the payload for the event log */
	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		return;
	}
	/*
	 * Buffer Format: word[0] = DID of the RSCN word[1] = RSCN Payload
	 */
	ptr = (uint32_t *)bp;
	*ptr++ = port->did;
	bcopy(payload, (char *)ptr, (size - sizeof (uint32_t)));

	EMLXS_MSGF(EMLXS_CONTEXT_BP, bp, size, &emlxs_rscn_event,
	    "bp=%p size=%d", bp, size);

#endif	/* DFC_SUPPORT */
	return;

} /* emlxs_log_rscn_event() */


void
emlxs_log_ct_event(emlxs_port_t *port, uint8_t *payload, uint32_t size,
    uint32_t rxid)
{
#ifdef DFC_SUPPORT
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;
	uint32_t *ptr;

	/* Check if the event is being requested */
	if (!(hba->log_events & EVT_CT)) {
		return;
	}
	if (size > MAX_CT_PAYLOAD) {
		size = MAX_CT_PAYLOAD;
	}
	size += sizeof (uint32_t);

	/* Save a copy of the payload for the event log */
	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		return;
	}
	/*
	 * Buffer Format: word[0] = RXID tag for outgoing reply to this CT
	 * request word[1] = CT Payload
	 */
	ptr = (uint32_t *)bp;
	*ptr++ = rxid;

	bcopy(payload, (char *)ptr, (size - sizeof (uint32_t)));

	EMLXS_MSGF(EMLXS_CONTEXT_BP, bp, size, &emlxs_ct_event,
	    "bp=%p size=%d rxid=%x", bp, size, rxid);

#endif	/* DFC_SUPPORT */

	return;

} /* emlxs_log_ct_event() */


void
emlxs_log_link_event(emlxs_port_t *port)
{
#ifdef DFC_SUPPORT
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;
	dfc_linkinfo_t *linkinfo;
	uint8_t *byte;
	uint8_t *linkspeed;
	uint8_t *liptype;
	uint8_t *resv1;
	uint8_t *resv2;
	uint32_t size;

	/* Check if the event is being requested */
	/*
	 * if(!(hba->log_events & EVT_LINK)) { return; }
	 */
	size = sizeof (dfc_linkinfo_t) + sizeof (uint32_t);

	/* Save a copy of the buffer for the event log */
	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		return;
	}
	/*
	 * Buffer Format: word[0] = Linkspeed:8 word[0] = LIP_type:8 word[0]
	 * = resv1:8 word[0] = resv2:8 word[1] = dfc_linkinfo_t data
	 */
	byte = (uint8_t *)bp;
	linkspeed = &byte[0];
	liptype = &byte[1];
	resv1 = &byte[2];
	resv2 = &byte[3];
	linkinfo = (dfc_linkinfo_t *)& byte[4];

	*resv1 = 0;
	*resv2 = 0;

	if (hba->state <= FC_LINK_DOWN) {
		*linkspeed = 0;
		*liptype = 0;
	} else {
		/* Set linkspeed */
		if (hba->linkspeed == LA_2GHZ_LINK) {
			*linkspeed = HBA_PORTSPEED_2GBIT;
		} else if (hba->linkspeed == LA_4GHZ_LINK) {
			*linkspeed = HBA_PORTSPEED_4GBIT;
		} else if (hba->linkspeed == LA_8GHZ_LINK) {
			*linkspeed = HBA_PORTSPEED_8GBIT;
		} else if (hba->linkspeed == LA_10GHZ_LINK) {
			*linkspeed = HBA_PORTSPEED_10GBIT;
		} else {
			*linkspeed = HBA_PORTSPEED_1GBIT;
		}

		/* Set LIP type */
		*liptype = port->lip_type;
	}

	bzero(linkinfo, sizeof (dfc_linkinfo_t));

	linkinfo->a_linkEventTag = hba->link_event_tag;
	linkinfo->a_linkUp = HBASTATS.LinkUp;
	linkinfo->a_linkDown = HBASTATS.LinkDown;
	linkinfo->a_linkMulti = HBASTATS.LinkMultiEvent;

	if (hba->state <= FC_LINK_DOWN) {
		linkinfo->a_linkState = LNK_DOWN;
		linkinfo->a_DID = port->prev_did;
	} else if (hba->state < FC_READY) {
		linkinfo->a_linkState = LNK_DISCOVERY;
	} else {
		linkinfo->a_linkState = LNK_READY;
	}

	if (linkinfo->a_linkState != LNK_DOWN) {
		if (hba->topology == TOPOLOGY_LOOP) {
			if (hba->flag & FC_FABRIC_ATTACHED) {
				linkinfo->a_topology = LNK_PUBLIC_LOOP;
			} else {
				linkinfo->a_topology = LNK_LOOP;
			}

			linkinfo->a_alpa = port->did & 0xff;
			linkinfo->a_DID = linkinfo->a_alpa;
			linkinfo->a_alpaCnt = port->alpa_map[0];

			if (linkinfo->a_alpaCnt > 127) {
				linkinfo->a_alpaCnt = 127;
			}
			bcopy((void *) &port->alpa_map[1], linkinfo->a_alpaMap,
			    linkinfo->a_alpaCnt);
		} else {
			if (port->node_count == 1) {
				linkinfo->a_topology = LNK_PT2PT;
			} else {
				linkinfo->a_topology = LNK_FABRIC;
			}

			linkinfo->a_DID = port->did;
		}
	}
	bcopy(&hba->wwpn, linkinfo->a_wwpName, 8);
	bcopy(&hba->wwnn, linkinfo->a_wwnName, 8);

	EMLXS_MSGF(EMLXS_CONTEXT_BP, bp, size, &emlxs_link_event,
	    "bp=%p size=%d tag=%x", bp, size, hba->link_event_tag);

#endif	/* DFC_SUPPORT */

	return;

} /* emlxs_log_link_event() */


void
emlxs_log_dump_event(emlxs_port_t *port, uint8_t *buffer, uint32_t size)
{
#ifdef DFC_SUPPORT
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;

	/* Check if the event is being requested */
	if (!(hba->log_events & EVT_DUMP)) {
		return;
	}
	if (buffer && size) {
		/* Save a copy of the buffer for the event log */
		if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
			return;
		}
		bcopy(buffer, bp, size);
	} else {
		bp = NULL;
		size = 0;
	}

	EMLXS_MSGF(EMLXS_CONTEXT_BP, bp, size, &emlxs_dump_event,
	    "bp=%p size=%d", bp, size);

#endif	/* DFC_SUPPORT */

	return;

} /* emlxs_log_dump_event() */


extern void
emlxs_log_temp_event(emlxs_port_t *port, uint32_t type, uint32_t temp)
{
#ifdef DFC_SUPPORT
	emlxs_hba_t *hba = HBA;
	uint32_t *bp;
	uint32_t size;

	/* Check if the event is being requested */
	if (!(hba->log_events & EVT_TEMP)) {
		return;
	}
	size = 2 * sizeof (uint32_t);

	if (!(bp = (uint32_t *)kmem_alloc(size, KM_NOSLEEP))) {
		return;
	}
	bp[0] = type;
	bp[1] = temp;

	EMLXS_MSGF(EMLXS_CONTEXT_BP, bp, size, &emlxs_temp_event,
	    "type=%x temp=%d bp=%p size=%d", type, temp, bp, size);

#endif	/* DFC_SUPPORT */

	return;

} /* emlxs_log_temp_event() */



extern void
emlxs_log_fcoe_event(emlxs_port_t *port, menlo_init_rsp_t *init_rsp)
{
#ifdef DFC_SUPPORT
	emlxs_hba_t *hba = HBA;
	uint8_t *bp;
	uint32_t size;

	/* Check if the event is being requested */
	if (!(hba->log_events & EVT_FCOE)) {
		return;
	}
	/* Check if this is a FCOE adapter */
	if (hba->model_info.device_id != PCI_DEVICE_ID_LP21000_M) {
		return;
	}
	size = sizeof (menlo_init_rsp_t);

	if (!(bp = (uint8_t *)kmem_alloc(size, KM_NOSLEEP))) {
		return;
	}
	bcopy((uint8_t *)init_rsp, bp, size);

	EMLXS_MSGF(EMLXS_CONTEXT_BP, bp, size, &emlxs_fcoe_event,
	    "bp=%p size=%d", bp, size);

#endif	/* DFC_SUPPORT */

	return;

} /* emlxs_log_fcoe_event() */



#ifdef DFC_SUPPORT

extern uint32_t
emlxs_get_dfc_eventinfo(emlxs_port_t *port, HBA_EVENTINFO *eventinfo,
    uint32_t *eventcount, uint32_t *missed)
{
	emlxs_hba_t *hba = HBA;
	emlxs_msg_log_t *log;
	uint32_t first;
	uint32_t last;
	uint32_t count;
	uint32_t index;
	emlxs_msg_entry_t *entry;
	dfc_linkinfo_t *linkinfo;
	uint32_t *word;
	uint8_t *byte;
	uint8_t linkspeed;
	uint8_t liptype;
	fc_affected_id_t *aid;
	uint32_t max_events;
	uint32_t events;
	emlxs_hba_event_t *hba_event;

	if (!eventinfo || !eventcount || !missed) {
		return (DFC_ARG_NULL);
	}
	hba_event = &hba->hba_event;
	max_events = *eventcount;
	*eventcount = 0;

	log = &LOG;

	mutex_enter(&log->lock);

	/* Check if log is empty */
	if (log->count == 0) {
		/* Make sure everything is initialized */
		hba_event->new = 0;
		hba_event->missed = 0;
		hba_event->last_id = 0;

		mutex_exit(&log->lock);
		return (0);
	}
	/* Safety check */
	if (hba_event->last_id > (log->count - 1)) {
		hba_event->last_id = log->count - 1;
	}
	/* Account for missed events */
	if (hba_event->new > hba_event->missed) {
		hba_event->new -= hba_event->missed;
	} else {
		hba_event->new = 0;
	}

	*missed = hba_event->missed;
	hba_event->missed = 0;

	if (!hba_event->new) {
		hba_event->last_id = log->count;
		mutex_exit(&log->lock);
		return (0);
	}
	/* A new event has occurred since last acquisition */
	/* Calculate the current buffer boundaries */

	/* Get last entry id saved */
	last = log->count - 1;

	/* Get oldest entry id and its index */
	/* Check if buffer has already been filled once */
	if (log->count >= log->size) {
		first = log->count - log->size;
		index = log->next;
	} else {	/* Buffer not yet filled */
		first = 0;
		index = 0;
	}

	/*
	 * Check if requested first event is greater than actual. If so,
	 * adjust for it.
	 */
	if (hba_event->last_id > first) {
		/* Adjust entry index to first requested message */
		index += (hba_event->last_id - first);
		if (index >= log->size) {
			index -= log->size;
		}
		first = hba_event->last_id;
	}
	/* Get the total number of new messages */
	count = last - first;

	/* Scan log for next event */
	events = 0;
	while (count-- && (events < max_events)) {
		if (++index >= log->size) {
			index = 0;
		}
		entry = &log->entry[index];

		if (!entry->msg) {
			break;
		}
		if ((entry->msg->level == EMLXS_EVENT) &&
		    (entry->msg->mask & (EVT_LINK | EVT_RSCN))) {
			/* Process this event */
			switch (entry->msg->mask) {
			case EVT_LINK:
				byte = (uint8_t *)entry->bp;
				linkspeed = byte[0];
				liptype = byte[1];
				linkinfo = (dfc_linkinfo_t *)& byte[4];

				if (linkinfo->a_linkState == LNK_DOWN) {
					eventinfo->EventCode =
					    HBA_EVENT_LINK_DOWN;
					eventinfo->Event.Link_EventInfo.
					    PortFcId = linkinfo->a_DID;
					eventinfo->Event.Link_EventInfo.
					    Reserved[0] = 0;
					eventinfo->Event.Link_EventInfo.
					    Reserved[1] = 0;
					eventinfo->Event.Link_EventInfo.
					    Reserved[2] = 0;
				} else {
					eventinfo->EventCode =
					    HBA_EVENT_LINK_UP;
					eventinfo->Event.Link_EventInfo.
					    PortFcId = linkinfo->a_DID;

					if ((linkinfo->a_topology ==
					    LNK_PUBLIC_LOOP) ||
					    (linkinfo->a_topology ==
					    LNK_LOOP)) {
						eventinfo->Event.Link_EventInfo.
						    Reserved[0] = 2;
					} else {
						eventinfo->Event.Link_EventInfo.
						    Reserved[0] = 1;
					}

					eventinfo->Event.Link_EventInfo.
					    Reserved[1] = liptype;
					eventinfo->Event.Link_EventInfo.
					    Reserved[2] = linkspeed;
				}

				break;

			case EVT_RSCN:
				word = (uint32_t *)entry->bp;
				eventinfo->EventCode = HBA_EVENT_RSCN;
				eventinfo->Event.RSCN_EventInfo.PortFcId =
				    word[0] & 0xFFFFFF;
				/* word[1] is the RSCN payload command */

				aid = (fc_affected_id_t *)& word[2];

				switch (aid->aff_format) {
				case 0:	/* Port */
					eventinfo->Event.RSCN_EventInfo.
					    NPortPage =
					    aid->aff_d_id & 0x00ffffff;
					break;

				case 1:	/* Area */
					eventinfo->Event.RSCN_EventInfo.
					    NPortPage =
					    aid->aff_d_id & 0x00ffff00;
					break;

				case 2:	/* Domain */
					eventinfo->Event.RSCN_EventInfo.
					    NPortPage =
					    aid->aff_d_id & 0x00ff0000;
					break;

				case 3:	/* Network */
					eventinfo->Event.RSCN_EventInfo.
					    NPortPage = 0;
					break;
				}

				eventinfo->Event.RSCN_EventInfo.Reserved[0] = 0;
				eventinfo->Event.RSCN_EventInfo.Reserved[1] = 0;

				break;
			}

			eventinfo++;
			events++;
		}
		hba_event->last_id = entry->id;
	}

	/* Adjust new count */
	if (!count || (events >= hba_event->new)) {
		hba_event->new = 0;
	} else {
		hba_event->new -= events;
	}

	/* Return number of events acquired */
	*eventcount = events;

	mutex_exit(&log->lock);

	return (0);

} /* emlxs_get_dfc_eventinfo() */


uint32_t
emlxs_get_dfc_event(emlxs_port_t *port, emlxs_dfc_event_t *dfc_event,
    uint32_t sleep)
{
	emlxs_hba_t *hba = HBA;
	emlxs_msg_log_t *log;
	uint32_t first;
	uint32_t last;
	uint32_t count;
	uint32_t index;
	uint32_t mask;
	uint32_t i;
	emlxs_msg_entry_t *entry;
	uint32_t size;
	uint32_t rc;

	size = 0;

	if (dfc_event->dataout && dfc_event->size) {
		size = dfc_event->size;
	}
	dfc_event->size = 0;

	/* Get the log file pointer */
	log = &LOG;

	/* Calculate the event index */
	mask = dfc_event->event;
	for (i = 0; i < 32; i++) {
		if (mask & 0x01) {
			break;
		}
		mask >>= 1;
	}
	if (i == 32) {
		return (DFC_ARG_INVALID);
	}
	mutex_enter(&log->lock);

	/* Check if log is empty */
	if (log->count == 0) {
		/* Make sure everything is initialized */
		log->event_id[i] = 0;
		dfc_event->last_id = 0;
	} else {
		/* Check ranges for safety */
		if (log->event_id[i] > (log->count - 1)) {
			log->event_id[i] = log->count - 1;
		}
		if (dfc_event->last_id > log->event_id[i]) {
			dfc_event->last_id = log->event_id[i];
		}
	}

wait_for_event:

	/* Check if no new event has ocurred */
	if (dfc_event->last_id == log->event_id[i]) {
		if (!sleep) {
			mutex_exit(&log->lock);
			return (0);
		}
		/*
		 * While event is still active and no new event has been
		 * logged
		 */
		while ((dfc_event->event & hba->log_events) &&
		    (dfc_event->last_id == log->event_id[i])) {
			rc = cv_wait_sig(&log->lock_cv, &log->lock);

			/* Check if thread was killed by kernel */
			if (rc == 0) {
				dfc_event->pid = 0;
				dfc_event->event = 0;
				mutex_exit(&log->lock);
				return (0);
			}
		}

		/*
		 * If the event is no longer registered then return
		 * immediately
		 */
		if (!(dfc_event->event & hba->log_events)) {
			mutex_exit(&log->lock);
			return (0);
		}
	}
	/* !!! An event has occurred since last_id !!! */

	/* Check if event data is not being requested */
	if (!size) {
		/* If so, then just return the last event id */
		dfc_event->last_id = log->event_id[i];

		mutex_exit(&log->lock);
		return (0);
	}
	/* !!! The requester wants the next event buffer !!! */

	/* Calculate the current buffer boundaries */

	/* Get last entry id saved */
	last = log->count - 1;

	/* Get oldest entry id and its index */
	/* Check if buffer has already been filled once */
	if (log->count >= log->size) {
		first = log->count - log->size;
		index = log->next;
	} else {	/* Buffer not yet filled */
		first = 0;
		index = 0;
	}

	/* Check to see if the buffer has wrapped since the last event */
	if (first > log->event_id[i]) {
		/* Update last_id to the last known event */
		dfc_event->last_id = log->event_id[i];

		/* Try waiting again if we can */
		goto wait_for_event;
	}
	/*
	 * Check if requested first event is greater than actual. If so,
	 * adjust for it.
	 */
	if (dfc_event->last_id > first) {
		/* Adjust entry index to first requested message */
		index += (dfc_event->last_id - first);
		if (index >= log->size) {
			index -= log->size;
		}
		first = dfc_event->last_id;
	}
	/* Get the total number of new messages */
	count = last - first + 1;

	/* Scan log for next event */
	while (count--) {
		if (++index >= log->size) {
			index = 0;
		}
		entry = &log->entry[index];

		if ((entry->msg->level == EMLXS_EVENT) &&
		    (entry->msg->mask == dfc_event->event)) {
			break;
		}
	}

	/*
	 * Check if no new event was found in the current log buffer.
	 * This would indicate that the buffer wrapped since that last event
	 */
	if (!count) {
		/* Update last_id to the last known event */
		dfc_event->last_id = log->event_id[i];

		/* Try waiting again if we can */
		goto wait_for_event;
	}
	/* !!! Next event found !!! */

	/* Copy the context buffer to the buffer provided */
	if (entry->bp && entry->size) {
		if (entry->size < size) {
			size = entry->size;
		}
		if (ddi_copyout((void *) entry->bp, dfc_event->dataout, size,
		    dfc_event->mode) != 0) {
			mutex_exit(&log->lock);

			return (DFC_COPYOUT_ERROR);
		}
		dfc_event->size = size;
	}
	dfc_event->last_id = entry->id;

	mutex_exit(&log->lock);
	return (0);

} /* emlxs_get_dfc_event() */


uint32_t
emlxs_kill_dfc_event(emlxs_port_t *port, emlxs_dfc_event_t *dfc_event)
{
	emlxs_hba_t *hba = HBA;
	emlxs_msg_log_t *log;

	/* Get the log file pointer */
	log = &LOG;

	mutex_enter(&log->lock);
	dfc_event->pid = 0;
	dfc_event->event = 0;
	cv_broadcast(&log->lock_cv);
	mutex_exit(&log->lock);

	return (0);

} /* emlxs_kill_dfc_event() */



#endif	/* DFC_SUPPORT */
