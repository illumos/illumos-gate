/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdlib.h>
#include "tlm.h"
#include "tlm_proto.h"
#include <sys/errno.h>


extern	tlm_chain_link_t *tlm_un_ref(tlm_chain_link_t *old_top,
    tlm_chain_link_t *link);

static	tlm_info_t tlm_info;

/*
 * Mutex for concurrent access to job_stats
 */
mutex_t jstat_mtx;


/*
 * get the number of libraries
 */
int
tlm_library_count(void)
{
	int	lib;
	tlm_library_t	*library;

	for (lib = 1; lib <= tlm_info.ti_library_count; lib++) {
		library = tlm_library(lib);
		if (library != NULL &&
		    library->tl_drive_count == 0) {
			return (0);
		}
	}
	return (tlm_info.ti_library_count);
}

/*
 * get the library whose number matches
 */
tlm_library_t *
tlm_library(int lib)
{
	tlm_library_t	*library = tlm_info.ti_library;
	while (library != NULL) {
		if (library->tl_number == lib) {
			return (library);
		}
		library = library->tl_next;
	}
	errno = TLM_ERROR_RANGE;
	return (NULL);
}

/*
 * get the info about this drive
 */
tlm_drive_t *
tlm_drive(int lib, int drv)
{
	tlm_drive_t	*drive;
	tlm_library_t	*library = tlm_library(lib);

	if (library == NULL) {
		return (NULL);
	}
	drive = library->tl_drive;
	while (drive != NULL) {
		if (drv == drive->td_number) {
			return (drive);
		}
		drive = drive->td_next;
	}
	return (NULL);
}

/*
 * get the info about this slot
 */
tlm_slot_t *
tlm_slot(int lib, int slt)
{
	tlm_slot_t	*slot = NULL;
	tlm_library_t	*library = tlm_library(lib);

	if (library != NULL)
		slot = library->tl_slot;
	while (slot != NULL) {
		if (slt == slot->ts_number) {
			return (slot);
		}
		slot = slot->ts_next;
	}
	return (NULL);
}

/*
 * add a link to the INFO chain
 */
tlm_job_stats_t	*
tlm_new_job_stats(char *name)
{
	tlm_chain_link_t *new_link;
	tlm_job_stats_t *job_stats;

	new_link = ndmp_malloc(sizeof (tlm_chain_link_t));
	if (new_link == 0)
		return (0);

	job_stats = ndmp_malloc(sizeof (tlm_job_stats_t));
	if (job_stats == 0) {
		free(new_link);
		return (0);
	}

	new_link->tc_ref_count = 1;
	new_link->tc_data = (void *)job_stats;
	(void) strlcpy(job_stats->js_job_name, name, TLM_MAX_BACKUP_JOB_NAME);

	(void) mutex_lock(&jstat_mtx);
	if (tlm_info.ti_job_stats == 0) {
		new_link->tc_next = new_link;
		new_link->tc_prev = new_link;
	} else {
		tlm_chain_link_t *next_link = tlm_info.ti_job_stats;
		tlm_chain_link_t *prev_link = next_link->tc_prev;

		new_link->tc_next = next_link;
		new_link->tc_prev = prev_link;
		prev_link->tc_next = new_link;
		next_link->tc_prev = new_link;
	}
	tlm_info.ti_job_stats = new_link;
	(void) mutex_unlock(&jstat_mtx);

	return (job_stats);
}

/*
 * make sure this Job Stats buffer is not deleted while we use it
 */
tlm_job_stats_t	*
tlm_ref_job_stats(char *name)
{
	static	tlm_job_stats_t	fake_job_stats;
	tlm_chain_link_t	*link;

	(void) mutex_lock(&jstat_mtx);
	link = tlm_info.ti_job_stats;
	if (link == 0) {
		/*
		 * our tables are empty
		 */
		(void) mutex_unlock(&jstat_mtx);
		return (&fake_job_stats);
	}

	do {
		tlm_job_stats_t *job_stats;
		job_stats = (tlm_job_stats_t *)link->tc_data;

		if (strcmp(job_stats->js_job_name, name) == 0) {
			link->tc_ref_count++;
			(void) mutex_unlock(&jstat_mtx);
			return (job_stats);
		}
		link = link->tc_next;
	} while (link != tlm_info.ti_job_stats);
	NDMP_LOG(LOG_DEBUG,
	    "TAPE BACKUP> Ref for job [%s] was not found", name);
	(void) mutex_unlock(&jstat_mtx);

	return (&fake_job_stats);
}

/*
 * remove a link to the INFO chain
 */
void
tlm_un_ref_job_stats(char *name)
{
	tlm_chain_link_t *link;

	(void) mutex_lock(&jstat_mtx);
	link = tlm_info.ti_job_stats;
	if (link == 0) {
		NDMP_LOG(LOG_DEBUG, "TAPE BACKUP>"
		    " Internal error for job [%s], could not delete", name);
		return;
	}
	do {
		tlm_job_stats_t *job_stats;
		job_stats = (tlm_job_stats_t *)link->tc_data;

		if (strcmp(job_stats->js_job_name, name) == 0) {
			tlm_info.ti_job_stats =
			    tlm_un_ref(tlm_info.ti_job_stats, link);
			(void) mutex_unlock(&jstat_mtx);
			return;
		}
		link = link->tc_next;
	} while (link != tlm_info.ti_job_stats);
	(void) mutex_unlock(&jstat_mtx);
	NDMP_LOG(LOG_DEBUG,
	    "TAPE BACKUP> Delete for job [%s] was not found", name);
}

/*
 * one party does not care about this blob, can we let it go?
 */
tlm_chain_link_t *
tlm_un_ref(tlm_chain_link_t *old_top, tlm_chain_link_t *link)
{
	tlm_chain_link_t *chain_link = old_top;
	tlm_chain_link_t *new_top;

	/*
	 * count down the number of
	 * interested parties for this blob
	 */
	link->tc_ref_count--;
	if (link->tc_ref_count > 0) {
		/*
		 * there is still interest in this blob,
		 * no change yet
		 *
		 * returning "old_top" means there is no change in the links
		 */
		return (old_top);
	}

	/*
	 * no one cares about this data anymore
	 * find out how to delete it
	 */
	do {
		if (chain_link == link) {
			tlm_chain_link_t *next;
			tlm_chain_link_t *prev;

			/*
			 * If there are one or two elements in the list, then
			 * the prev and next pointers point to one element in
			 * the list, the element itself and the other element
			 * correspondingly.  So we must distinguish if there
			 * are only one or two elements in the list.  If
			 * either of the 'prev' or 'next' pointers point to
			 * the link itself, then we have only one element in
			 * the list.
			 */
			if (link->tc_next == link->tc_prev &&
			    link->tc_next == link) {
				/*
				 * there is only this one link in the chain
				 * delete this and the chain is empty
				 */
				new_top = 0;
			} else {
				new_top = link->tc_next;
			}
			next = link->tc_next;
			prev = link->tc_prev;
			prev->tc_next = next;
			next->tc_prev = prev;
			free(link->tc_data);
			free(link);
			return (new_top);
		}
		chain_link = chain_link->tc_next;
	} while (chain_link != old_top);
	NDMP_LOG(LOG_DEBUG, "TAPE BACKUP> un_ref target not found.");
	return (old_top);
}

/*
 * the following section is global, but not really part of the
 * public interface.  Use of this outside of the tlm_*.c files
 * is for special cases only.
 */

/*
 * add a new tape library data blob to the list of libraries
 * returns the new tape library data blob just created
 */
int
tlm_insert_new_library(scsi_link_t *slink)
{
	tlm_library_t **p_library = &tlm_info.ti_library;
	tlm_library_t *library = ndmp_malloc(sizeof (tlm_library_t));

	while (*p_library != NULL) {
		p_library = &(*p_library)->tl_next;
	}
	tlm_info.ti_library_count++;
	library->tl_number = tlm_info.ti_library_count;
	library->tl_slink = slink;
	library->tl_capability_robot = TRUE;
	*p_library = library;
	return (library->tl_number);
}

/*
 * add a new tape drive data blob to the list of drives in a library
 * returns the new tape drive data blob just created
 */
int
tlm_insert_new_drive(int lib)
{
	tlm_library_t *library = tlm_library(lib);
	tlm_drive_t *drive = ndmp_malloc(sizeof (tlm_drive_t));
	tlm_drive_t **p_drive = &library->tl_drive;

	while (*p_drive != NULL) {
		p_drive = &(*p_drive)->td_next;
	}
	library->tl_drive_count++;
	library->tl_capability_drives = TRUE;

	drive->td_library = library;
	drive->td_number = library->tl_drive_count;
	*p_drive = drive;
	return (drive->td_number);
}

/*
 * add a new tape slot data blob to the list of slots in a library
 * returns the new tape slot data blob just created
 */
int
tlm_insert_new_slot(int lib)
{
	tlm_library_t *library = tlm_library(lib);
	tlm_slot_t *slot = ndmp_malloc(sizeof (tlm_slot_t));
	tlm_slot_t **p_slot = &library->tl_slot;

	while (*p_slot != NULL) {
		p_slot = &(*p_slot)->ts_next;
	}
	library->tl_slot_count++;
	library->tl_capability_slots = TRUE;

	slot->ts_library = library;
	slot->ts_number = library->tl_slot_count;
	*p_slot = slot;
	return (slot->ts_number);
}
