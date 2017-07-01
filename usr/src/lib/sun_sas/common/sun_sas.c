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


#include <sys/byteorder.h>
#include <sun_sas.h>

/*
 * creates a handle each time Sun_sas_OpenAdapter() is called.
 *
 * a open_handle_struct was created to keep track of which handles are currently
 * open.  This prevents a user from using an old handle that corresponds to
 * an hba that has already been closed.
 */
HBA_HANDLE
CreateHandle(int adapterIndex)
{
	const char		ROUTINE[] = "CreateHandle";
	struct open_handle	*new_open_handle;
	HBA_UINT32		new_handle_index;
	HBA_UINT8		max_handle_wrap = 0;

	if (global_hba_head == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "an error as occurred.  global_hba_head is "
		    "NULL.  Library may not be loaded yet.");
		return (HANDLE_ERROR);
	}

	while (RetrieveIndex(open_handle_index) != -1)  {
		open_handle_index = open_handle_index + 1;
		if (open_handle_index == 0) {
			/*
			 * If open_handle_index wraps back to zero again,
			 * that means all handles are currently in use.
			 * Spec only allows for 16 bits of handles
			 */
			if (max_handle_wrap == 1) {
				log(LOG_DEBUG, ROUTINE,
				    "Max number of handles reached.");
				return (HANDLE_ERROR);
			}
			open_handle_index = 1;
			max_handle_wrap = 1;
		}
	}

	new_handle_index = open_handle_index;
	if ((new_open_handle = (struct open_handle *)calloc(1,
	    sizeof (struct open_handle))) == NULL) {
		OUT_OF_MEMORY(ROUTINE);
		return (HANDLE_ERROR);
	}
	(void) memset(new_open_handle, 0, sizeof (struct open_handle));
	new_open_handle->adapterIndex = adapterIndex;
	new_open_handle->handle = new_handle_index;

	lock(&open_handles_lock);

	/* add new open handle struct to the open_handles list */
	if (global_hba_head->open_handles == NULL) {
		global_hba_head->open_handles = new_open_handle;
	} else {
		new_open_handle->next = global_hba_head->open_handles;
		global_hba_head->open_handles = new_open_handle;
	}

	unlock(&open_handles_lock);
	open_handle_index = open_handle_index + 1;
	if (open_handle_index == 0) {
		open_handle_index = 1;
	}

	return (new_handle_index);
}

/*
 * given a handle, returns the adapterIndex number.
 *
 * This functions checkes to see if the given handle corresponds to an open
 * HBA.  If it does, the adapterIndex is returned.
 */
int
RetrieveIndex(HBA_HANDLE handle)
{

	struct open_handle	*open_handle_ptr;

	lock(&open_handles_lock);

	open_handle_ptr = RetrieveOpenHandle(handle);

	unlock(&open_handles_lock);
	if (open_handle_ptr == NULL) {
		return (-1);
	}

	return (open_handle_ptr->adapterIndex);
}
/*
 * Given a handle, returns the open_handle structure
 * The routine assumes that the open_handles_lock has already
 * been taken.
 */
struct open_handle *
RetrieveOpenHandle(HBA_HANDLE handle)
{

	const char		ROUTINE[] = "RetrieveOpenHandle";
	struct open_handle	*open_handle_ptr = NULL;

	if (global_hba_head == NULL) {
		log(LOG_DEBUG, ROUTINE, "No adapter is found.");
		return (NULL);
	}

	for (open_handle_ptr = global_hba_head->open_handles;
	    open_handle_ptr != NULL;
	    open_handle_ptr = open_handle_ptr->next) {
		if (open_handle_ptr->handle == handle) {
			break;
		}
	}

	return (open_handle_ptr);
}

/*
 * Given an adapterIndex, this functions returns a pointer to the handle
 * structure.  This handle structure holds the hba's information
 * Caller must take all_hbas_lock first.
 */
struct sun_sas_hba *
RetrieveHandle(int index)
{
	struct sun_sas_hba 	*hba_ptr = NULL;

	for (hba_ptr = global_hba_head; hba_ptr != NULL;
	    hba_ptr = hba_ptr->next) {
		if (hba_ptr->index == index)
			break;
	}

	return (hba_ptr);
}

/*
 * Given an adapterIndex, this functions returns a pointer to the handle
 * structure and extracts it from the global list.
 *
 * all_hbas_lock must be taken already.
 */
struct sun_sas_hba *
ExtractHandle(int index)
{
	struct sun_sas_hba 	*last = NULL;
	struct sun_sas_hba 	*hba_ptr = NULL;

	for (hba_ptr = global_hba_head;
	    hba_ptr != NULL;
	    last = hba_ptr, hba_ptr = hba_ptr->next) {
		if (hba_ptr->index == index) {
			if (last) {
				last->next = hba_ptr->next;
			} else {
				/* Hmm, must be the head of the list. */
				global_hba_head = hba_ptr->next;
			}
			hba_ptr->next = NULL; /* Zap it to be safe */
			break;
		}
	}

	return (hba_ptr);
}


/*
 * Given an handle, this functions returns a pointer to the handle structure
 * for that hba
 *
 * Caller must take all_hbas_lock first.
 */
struct sun_sas_hba *
Retrieve_Sun_sasHandle(HBA_HANDLE handle)
{
	const char		    ROUTINE[] = "Retrieve_Sun_sasHandle";
	struct	sun_sas_hba	    *handle_struct = NULL;
	int			    index;

	/* Retrieve fp device path from handle */
	index = RetrieveIndex(handle);
	if (index == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "handle could not be found.");
		return (handle_struct);
	}
	lock(&open_handles_lock);
	handle_struct = RetrieveHandle(index);
	if (handle_struct == NULL) {
		log(LOG_DEBUG, ROUTINE,
		    "could not find index in the handle list.");
		unlock(&open_handles_lock);
		return (handle_struct);
	}
	unlock(&open_handles_lock);

	return (handle_struct);
}

/*
 * Take a mutex lock.  The routine will try, and if it fails,
 * it will loop for a while and retry.  If it fails many times,
 * it will start writing to the log file.
 */
void
lock(mutex_t *mp)
{
	int status;
	int loop = 0;
	const char ROUTINE[] = "lock";

	do {
		loop++;
		status = mutex_trylock(mp);
		switch (status) {
			case 0:
				break;
			case EFAULT:
				log(LOG_DEBUG, ROUTINE,
				    "Lock failed: fault 0x%x", mp);
				break;
			case EINVAL:
				log(LOG_DEBUG, ROUTINE,
				    "Lock failed: invalid 0x%x", mp);
				break;
			case EBUSY:
				if (loop > DEADLOCK_WARNING) {
					log(LOG_DEBUG, ROUTINE,
					    "Lock busy, possible deadlock:0x%x",
					    mp);
				}
				break;
			case EOWNERDEAD:
				log(LOG_DEBUG, ROUTINE,
				    "Lock failed: owner dead 0x%x",
				    mp);
				break;
			case ELOCKUNMAPPED:
				log(LOG_DEBUG, ROUTINE,
				    "Lock failed: unmapped 0x%x",
				    mp);
				break;
			case ENOTRECOVERABLE:
				log(LOG_DEBUG, ROUTINE,
				    "Lock failed: not recoverable 0x%x", mp);
				break;
			default:
				if (loop > DEADLOCK_WARNING) {
					log(LOG_DEBUG, ROUTINE,
					    "Lock failed: %s 0x%x",
					    strerror(status), mp);
					break;
				}
		}

		if (status) {
			(void) sleep(LOCK_SLEEP);
		}

	} while (status);
}

/*
 * Unlock a mutex lock.
 */
void
unlock(mutex_t *mp)
{
	(void) mutex_unlock(mp);
}


/*
 * Get the Port WWN of the first adapter port.  This routine
 * is used by the old V1 interfaces so that they can call
 * the new V2 interfaces and exhibit the same behavior.
 * In the event of error the WWN will be zero.
 *
 * This function will transition to PAA state but it will not
 * verfiy whether data is stale or not
 */
HBA_WWN
getFirstAdapterPortWWN(HBA_HANDLE handle)
{
	const char	ROUTINE[] = "getFirstAdapterPortWWN";
	HBA_WWN			pwwn = {0, 0, 0, 0, 0, 0, 0, 0};
	struct sun_sas_hba	*hba_ptr = NULL;
	int			index = 0;
	HBA_STATUS		status;

	lock(&all_hbas_lock);
	index = RetrieveIndex(handle);
	lock(&open_handles_lock);
	hba_ptr = RetrieveHandle(index);
	if (hba_ptr == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid handle %08lx", handle);
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (pwwn); /* zero WWN */
	}

	/* Check for stale data */
	status = verifyAdapter(hba_ptr);
	if (status != HBA_STATUS_OK) {
		log(LOG_DEBUG, ROUTINE, "Verify adapter failed");
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (pwwn);
	}

	if (hba_ptr->first_port == NULL) {
		/* This is probably an internal failure of the library */
		if (hba_ptr->device_path) {
			log(LOG_DEBUG, ROUTINE,
			    "Internal failure:  Adapter %s contains no "
			    "port data", hba_ptr->device_path);
		} else {
			log(LOG_DEBUG, ROUTINE,
			    "Internal failure:  Adapter at index %d contains "
			    " no support data", hba_ptr->index);
		}
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (pwwn); /* zero WWN */
	}
	/* Set the WWN now and return it */
	pwwn = hba_ptr->first_port->port_attributes.PortSpecificAttribute.\
	    SASPort->LocalSASAddress;
	unlock(&open_handles_lock);
	unlock(&all_hbas_lock);

	return (pwwn);
}

u_longlong_t
wwnConversion(uchar_t *wwn)
{
	u_longlong_t tmp;
	(void) memcpy(&tmp, wwn, sizeof (u_longlong_t));
	tmp = ntohll(tmp);
	return (tmp);
}

/*
 * Using ioctl to send uscsi command out
 */
HBA_STATUS
send_uscsi_cmd(const char *devpath, struct uscsi_cmd *ucmd)
{
	const char	ROUTINE[] = "send_uscsi_cmd";
	int		fd;
	HBA_STATUS	ret;

	/* set default timeout to 200 */
	ucmd->uscsi_timeout = 200;

	/* reset errno. */
	errno = 0;
	if ((fd = open(devpath, O_RDONLY | O_NDELAY)) == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "open devpath %s failed: %s", devpath, strerror(errno));
		return (HBA_STATUS_ERROR);
	}

	if (ioctl(fd, USCSICMD, ucmd) == -1) {
		if (errno == EBUSY) {
			ret = HBA_STATUS_ERROR_BUSY;
		} else if (errno == EAGAIN) {
			ret = HBA_STATUS_ERROR_TRY_AGAIN;
		} else {
			ret = HBA_STATUS_ERROR;
		}
		log(LOG_DEBUG, ROUTINE,
		    "ioctl send uscsi to devpath: %s failed: %s",
		    devpath, strerror(errno));
		(void) close(fd);
		return (ret);
	}

	(void) close(fd);

	return (HBA_STATUS_OK);
}

/*
 * Check whether the given Domain Address is valid.
 */
HBA_STATUS
validateDomainAddress(struct sun_sas_port *hba_port_ptr, HBA_WWN DomainAddr)
{
	if (hba_port_ptr->first_phy != NULL &&
	    wwnConversion(hba_port_ptr->first_phy->
	    phy.domainPortWWN.wwn) ==
	    wwnConversion(DomainAddr.wwn)) {
		return (HBA_STATUS_OK);
	}
	return (HBA_STATUS_ERROR);
}
