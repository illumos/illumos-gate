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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Functions used to save and read the binding table for persistence across
 * mipagent reboots.
 * Saving should be invoked by sending mipagent the proper signal.
 * After the signal is trapped, the functions here are invoked and save
 * the state into the binary file:
 *	"/var/inet/mipagent_state"
 * The file
 *	"/var/inet/mipagent_state.lock"
 * is used as a mutex.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "impl.h"

#include "agent.h"
#include "setup.h"
#include "hash.h"
#include "conflib.h"

#define	MAXLINELENGTH 200
/* file to save all mobility bindings to capture state across reboots */
#define	SAVE_BINDINGS_FILE		"/var/inet/mipagent_state"
#ifdef	LOCKFILE
#define	SAVE_BINDINGS_LOCK_FILE		"/var/inet/mipagent_state.lock"
#endif	/* LOCKFILE */
#define	ENVVAR				"MIPAGENT_SAVE_STATE"

/* Controls verbosity of debug messages when compiled w/ "-D MIP_DEBUG" */
extern int	logVerbosity;

/*
 * Counters maintained by Home Agents
 */
extern HomeAgentCounters haCounters;

/* Home Agent specific data structures. */
extern HashTable haMobileNodeHash;
extern HashTable mipSecAssocHash;
extern HashTable mipAgentHash;

extern int installIPsecPolicy(char *);
extern MobilityAgentEntry *findMaeFromIp(ipaddr_t, int);

static FILE *agentStateFile;		/* file ptr for the state file */
#ifdef	LOCKFILE
static int  lockFile;			/* lock file file descriptor */
#endif	/* LOCKFILE */

static int preFileAccess(boolean_t forReading);
static int postFileAccess(void);
static void removeStateFile(void);
static size_t saveOneEntry(void *ptr, size_t  size);
static size_t readOneEntry(void *ptr, size_t  size);
int restoreIPsecPolicies(MobilityAgentEntry *, MobilityAgentEntry *);

extern char *validIPsecAction[];
extern char *ntoa(uint32_t, char *);

/*
 * Function: saveAgentState
 *
 * Arguments:	None.
 *
 * Description:	Save mobile node binding entries. ret 1 if ok, 0 otherwise.
 *
 *		Note: This routine must be called only when everything
 *		is quiescent. Otherwise inconsistent state may result
 *		if new security associations, mobile node entries
 *		or binding entries are being created as the state
 *		is being saved.
 *
 * Returns:	1 if ok, 0 otherwise.
 */

int
saveAgentState(void)
{
	HashEntry *hashEntry;
	HaMobileNodeEntry *hamne;
	HaBindingEntry *habe;
	MipSecAssocEntry *sae;
	MobilityAgentEntry *mae;
	int EntriesSaved, numBindings;
	int i;

	/* Prepare for security association file access. */
	if (preFileAccess(_B_FALSE) == -1) {
		mipverbose(("Could not prepare state file for writing.\n"));
		return (0);
	}

	/*
	 * Only save the *dynamic* security associations.
	 * First: count them, and write that number.
	 * Then: do the actual saves.
	 */
	EntriesSaved = 0;
	for (i = 0; i < HASH_TBL_SIZE; i++) {
		if (mipSecAssocHash.buckets[i]) {
			for (hashEntry = mipSecAssocHash.buckets[i];
			    hashEntry != NULL;
			    hashEntry = hashEntry->next) {
				sae = hashEntry->data;
				if (sae == NULL)
					continue;
				if (! sae->mipSecIsEntryDynamic)
					continue;
				++EntriesSaved;
			}
		}
	}

	/*
	 * First item to write out: the number of dynamic security
	 * associations which follow.
	 */
	if (saveOneEntry((void *) &EntriesSaved, sizeof (EntriesSaved)) != 1) {
		mipverbose(("Problem saving the number of dynamic of"
		    "security associations.\n"));
		(void) postFileAccess();
		(void) rw_unlock(&sae->mipSecNodeLock);
		(void) rw_unlock(&mipSecAssocHash.bucketLock[i]);
		return (0);
	}

	/*
	 * Now: write out the actual dynamic security
	 * associations.
	 */
	for (i = 0; (EntriesSaved > 0) && (i < HASH_TBL_SIZE); i++) {
		if (mipSecAssocHash.buckets[i]) {
			for (hashEntry = mipSecAssocHash.buckets[i];
			    hashEntry != NULL;
			    hashEntry = hashEntry->next) {

				sae = hashEntry->data;
				if (sae == NULL)
					continue;

				/*
				 * If the entry is static there is
				 * no need to save it, as it will
				 * get restored out of the configuration
				 * file.
				 */
				if (! sae->mipSecIsEntryDynamic)
					continue;
				/*
				 * Now it's safe to write out the sec
				 * association entry.
				 */
				if (saveOneEntry((void *) sae,
				    sizeof (MipSecAssocEntry)) != 1) {
					mipverbose(("Problem saving a mobile "
					    "node entry.\n"));
					(void)  postFileAccess();
					return (0);
				}
				--EntriesSaved;
			}
		}
	}

	/*
	 * Now we'll save the agent-peer entries.
	 * First: count them, and write that number.
	 * Then: do the actual saves.
	 */
	EntriesSaved = 0;
	for (i = 0; i < HASH_TBL_SIZE; i++) {
		if (mipAgentHash.buckets[i]) {
			for (hashEntry = mipAgentHash.buckets[i];
			    hashEntry != NULL;
			    hashEntry = hashEntry->next) {
				mae = hashEntry->data;
				if (mae == NULL)
					continue;
				++EntriesSaved;
			}
		}
	}

	/*
	 * Now write out the number of agent-peer entries which follow
	 */
	if (saveOneEntry((void *) &EntriesSaved, sizeof (EntriesSaved)) != 1) {
		mipverbose(("Problem saving the number of "
		    "agent-peer entries.\n"));
		(void) postFileAccess();
		(void) rw_unlock(&mipAgentHash.bucketLock[i]);
		return (0);
	}

	/*
	 * Now: write out the actual agent-peer entries.
	 */
	for (i = 0; (EntriesSaved > 0) && (i < HASH_TBL_SIZE); i++) {
		if (mipAgentHash.buckets[i]) {
			for (hashEntry = mipAgentHash.buckets[i];
			    hashEntry != NULL;
			    hashEntry = hashEntry->next) {

				mae = hashEntry->data;

				if (mae == NULL)
					continue;

				/*
				 * Write out the agent-peer entry
				 */
				if (saveOneEntry((void *) mae,
				    sizeof (MobilityAgentEntry)) != 1) {
					mipverbose(("Problem saving an agent-"
					    "peer entry.\n"));
					(void)  postFileAccess();
					return (0);
				}
				--EntriesSaved;
			}
		}
	}


	/*
	 * Now save each mobile node entry.
	 */
	for (i = 0; i < HASH_TBL_SIZE; i++) {
		if (haMobileNodeHash.buckets[i]) {

			for (hashEntry = haMobileNodeHash.buckets[i];
			    hashEntry != NULL;
			    hashEntry = hashEntry->next) {

				hamne = hashEntry->data;
				/*
				 * This should have been != NULL, instead
				 * of == NULL. The issue is that we would
				 * never properly reload existing registrations
				 * if the agent was re-started.
				 */
				if (hamne != NULL)
				/*
				 * Instead of trusting it to really
				 * know how many bindings it has, i'll
				 * go ahead and count them just to really
				 * make sure. Otherwise we could end up with
				 * null pointers, core dumps, etc...  it's
				 * one more traversal, but most of the time
				 * there's zero or one binding, and the max
				 * is small anyway... Little extra price to pay
				 * to be able to sleep at night...
				 * This way, when we read the mn entry we
				 * know we can trust the number of bindings to
				 * know how many binding entries to read after
				 * that.
				 */
					for (numBindings = 0,
					    habe = hamne->bindingEntries;
					    habe != NULL &&
					    (numBindings <
					    MAX_SIMULTANEOUS_BINDINGS);
					    ++numBindings, habe = habe->next);

				/*
				 * finished counting the number of
				 * bindings...
				 */
				if (numBindings != hamne->haMnBindingCnt) {
					mipverbose(("Miscounted number of "
					    "bindings! (fixing...)\n"));
					hamne->haMnBindingCnt = numBindings;
				}

				if (numBindings != 0) {
					/*
					 * Now it's safe to write out the
					 * mobile node entry.
					 */
					if (saveOneEntry((void *) hamne,
					    sizeof (HaMobileNodeEntry)) != 1) {
						mipverbose(("Problem saving "
						    "a mobile node entry.\n"));
						(void) postFileAccess();
						return (0);
					}

#ifdef RADIUS_ENABLED
					/*
					 * Save any haRadiusState as
					 * len:radiusState
					 */

					if (MobileNodeEntry->haRadiusState !=
					    NULL) {
						size_t len = strlen(
							hamne->haRadiusState);
						if (1 != fwrite((void *) &len,
						    sizeof (size_t), 1,
						    agentStateFile)) {
							mipverbose((
							    "Problem saving "
							    "length %d of "
							    "radius state"
							    "%s.\n", len,
							    hamne->
							    haRadiusState));
						(void) postFileAccess();
						return (0);
					}
					if (len != fwrite((void *)
					    hamne->haRadiusState,
					    sizeof (char),
					    len, agentStateFile)) {
						mipverbose((
							"Problem saving "
							    "radius state %s."
							    "\n",
							    hamne->
							    haRadiusState));
						(void) postFileAccess();
						return (0);
					}
				}
#endif /* RADIUS_ENABLED */

				/*
				 * 2nd traversal of the bindings chain:
				 * save each binding
				 */
				for (habe = hamne->bindingEntries;
				    habe != NULL;
				    habe = habe->next) {

					if (saveOneEntry((void *) habe,
					    sizeof (HaBindingEntry))
					    != 1) {
						mipverbose(("Problem "
						    "saving a binding"
						    "entry.\n"));
						(void) postFileAccess();
						return (0);
					}
				}
			}
		}
	}
}

if (postFileAccess() == -1)
	return (0);
	return (1);
	} /* saveAgentState(void)  */

/* returns 1 if ok, 0 otherwise. */
static int
restoreAllMobilityBindings(void)
{
	HaMobileNodeEntry hamne, *mnEntry = NULL;
	HaBindingEntry habe;
	MipSecAssocEntry sa, *sap;
	MobilityAgentEntry ma, *map;
	time_t currentTime;
	time_t timeout;
	boolean_t existing;
	uint32_t sessionLifetime;
	int EntriesSaved = 0;
	int i;

	if (preFileAccess(_B_TRUE) == -1) {
		mipverbose(("Could not prepare state file for reading.\n"));
		return (0);
	}

	/*
	 * First: how many dynamic security assoc's are there?
	 */

	if ((int)readOneEntry((void *) &EntriesSaved, sizeof (EntriesSaved))
	    != 1) {
		mipverbose(("Problem reading the number of dynamic sa's.\n"));
		(void) postFileAccess();
		return (0);
	}

	for (i = 0; i < EntriesSaved; i++) {
		if ((int)readOneEntry((void *) &sa,
		    sizeof (MipSecAssocEntry)) != 1) {
			mipverbose(("Problem reading a security assoc.\n"));
			(void) postFileAccess();
			return (0);
		}

		/*
		 * Create the relevant security association
		 * (locked upon return).
		 * NOTE: Must rewrite the key lifetime as
		 * the create routing clobbers the previous
		 * value.
		 */
		sap = CreateSecAssocEntry(sa.mipSecIsEntryDynamic,
		    sa.mipSecSPI,
		    sa.mipSecReplayMethod,
		    sa.mipSecAlgorithmType,
		    sa.mipSecAlgorithmMode,
		    sa.mipSecKeyLen,
		    (char *)&sa.mipSecKey[0],
		    sa.mipSecKeyLifetime);

		if (sap == NULL) {
			mipverbose(("Unable to create dynamic SA Entry\n"));
			haCounters.haInsufficientResourceCnt++;
			(void) postFileAccess();
			return (0);
		}

		sap->mipSecKeyLifetime = sa.mipSecKeyLifetime;
		mipverbose(("Created a dynamic Mobile Node Entry\n"));

		/*
		 * The Create function ends up locking the sa, so
		 * we need to free it.
		 */
		(void) rw_unlock(&sap->mipSecNodeLock);
	}

	/*
	 * the next entry should indicate the number of agent-peer entries.
	 */
	if ((int)readOneEntry((void *) &EntriesSaved, sizeof (EntriesSaved))
	    != 1) {
		mipverbose(("Problem reading the number of agent-peers.\n"));
		(void) postFileAccess();
		return (0);
	}

	/* now restore that many agent-peer entries */
	for (i = 0; i < EntriesSaved; i++) {
		if ((int)readOneEntry((void *) &ma,
		    sizeof (MobilityAgentEntry)) != 1) {
			mipverbose(("Problem reading an agent-peer entry.\n"));
			(void) postFileAccess();
			return (0);
		}

		/*
		 * Agent entries are read from the config file BEFORE this
		 * function is called.  Therefore, any we find here that
		 * aren't in the config file must have been deleted, and
		 * hence we don't have a SA with them any longer.  Conversely
		 * if there are new agent's configured, any SA that's
		 * configued with them is obviously not currently active.
		 */
		if ((map = findMaeFromIp(ma.maAddr, LOCK_READ)) == NULL) {
			/*
			 * This is the former case - we saved this agent,
			 * but it hasn't been read from the config file,
			 * and so was delted.  We no longer have to worry
			 * about this agent-peer, but let the user know
			 * in case the deletion was accidental.
			 */
			char peerAddr[IPv4_ADDR_LEN];

			(void) ntoa(ma.maAddr, peerAddr);
			mipverbose(("agent-peer entry for %s "
			    "no longer configured\n", peerAddr));
			continue;
		}

		/* Restore the active IPsec Policies */
		(void) restoreIPsecPolicies(map, &ma);

		/*
		 * The Create function ends up locking the map, so
		 * we need to free it.
		 */
		(void) rw_unlock(&map->maNodeLock);
	}

	/*
	 * Read the mobile node entries till eof.
	 */
	/* CONSTCOND */
	while (_B_TRUE) {
		rwlock_t nl;

		if ((int)readOneEntry((void *) &hamne,
		    sizeof (HaMobileNodeEntry)) != 1) {
			if (ferror(agentStateFile)) {
				mipverbose((
				    "Problem reading a mobile node entry.\n"));
				(void) postFileAccess();
				return (0);
			} else if (feof(agentStateFile)) {
				mipverbose(("Done restoring agent state.\n"));
				clearerr(agentStateFile);
			}
			return ((postFileAccess() == -1) ? 0 : 1);
		}

		/*
		 * if its a dynamic type, we must explicitly create it here
		 * Otherwise, it was created upon initialization.
		 * Note: creation produces a *locked* node.
		 */

		if (hamne.haMnIsEntryDynamic) {
			/* First, create the mobile node. */

			mnEntry = CreateMobileNodeEntry(_B_TRUE,
			    hamne.haMnAddr,
			    (char *)&hamne.haMnNAI[0],
			    MAX_NAI_LENGTH,
			    hamne.haBindingIfaceAddr,
			    hamne.haMnSPI,
			    NULL,
			    hamne.haPoolIdentifier);

			if (mnEntry == NULL) {
				mipverbose((
				    "Unable to create dynamic MN Entry\n"));
				haCounters.haInsufficientResourceCnt++;
				(void) postFileAccess();
				return (0);
			}
			mipverbose(("Created a dynamic Mobile Node Entry\n"));
		} else {
			mnEntry = findHashTableEntryUint(&haMobileNodeHash,
			    hamne.haMnAddr, LOCK_WRITE, NULL, 0, 0, 0);

			if (mnEntry == NULL) {
				/*
				 * Search for the MobileNodeEntry based on the
				 * NAI.
				 */
				mnEntry = findHashTableEntryString(
				    &haMobileNodeHash,
				    (unsigned char *)&hamne.haMnNAI,
				    strlen((char *)&hamne.haMnNAI),
				    LOCK_WRITE,
				    NULL, 0, 0, 0);

				if (mnEntry == NULL) {
					mipverbose(("Unable to find a "
					    "static MN Entry\n"));
					(void) postFileAccess();
					return (0);
				}
			}
			mipverbose(("Found a static Mobile Node Entry\n"));
		}

		/*
		 * Copy all the fields to the (locked) mobile node entry.
		 * Must make sure the lock info does not get clobbered.
		 * Also, make sure we explicitly clobber the bindingEntries
		 * pointer, as it has no significance until we restore those
		 * entries one by one.
		 * Must also clobber the haMnBindingCnt and let restoreHABE
		 * increment that upon successful restoration of each binding
		 * entry.
		 */

		nl = mnEntry->haMnNodeLock;
		(void) memcpy((void *)mnEntry, (void *)&hamne,
		    sizeof (HaMobileNodeEntry));
		mnEntry->haMnNodeLock = nl;
		mnEntry->bindingEntries = NULL;
		mnEntry->haMnBindingCnt = 0;

#if 0
		/* This is not persistent friendly yet. */
		/* read the radiusState string if needed. */
		if (mnEntry->haRadiusState != NULL) {
			size_t len;
			if (1 != fread((void *) &len, sizeof (size_t), 1,
			    agentStateFile)) {
				mipverbose((
				    "Problem reading radius state length.\n"));
				(void) postFileAccess();
				(void) rw_unlock(&mnEntry->haMnNodeLock);
				return (0);
			}

			/* allocate some space for the radius state */
			if (len != fread((void *) mnEntry->haRadiusState,
			    sizeof (char), len, agentStateFile)) {
				mipverbose((
				    "Problem reading radius state.\n"));
				(void) postFileAccess();
				(void) rw_unlock(&mnEntry->haMnNodeLock);
				return (0);
			}
		}
		mnEntry->haRadiusState = NULL;
#endif

		/*
		 * Read all binding entries for this
		 * mn entry.
		 */
		for (i = 0; i < (int)hamne.haMnBindingCnt; i++) {
			if ((int)readOneEntry((void *) &habe,
			    sizeof (HaBindingEntry)) != 1) {
				mipverbose(("Problem reading a "
				    "binding entry.\n"));
				(void) postFileAccess();
				(void) rw_unlock(&mnEntry->haMnNodeLock);
				return (0);
			}

			/*
			 * Figure out when the entry should expire.
			 */
			GET_TIME(currentTime);

			if (habe.haBindingTimeExpires > currentTime) {
				timeout = habe.haBindingTimeExpires -
				    currentTime;
				/* create the relevant binding entry */
				(void) addHABE(mnEntry, habe.haBindingSrcAddr,
				    habe.haBindingSrcPort, NULL,
				    habe.haBindingRegFlags,
				    habe.haBindingMN,
				    habe.haBindingCOA,
				    mnEntry->haBindingIfaceAddr, timeout,
				    &existing, &sessionLifetime);
			}
		}

		/*
		 * Done with this mn entry, but before
		 * moving on to the next, let's unlock it.
		 */
		(void) rw_unlock(&mnEntry->haMnNodeLock);
	}

	return (0);
} /* restoreAllMobilityBindings(void)  */

int
restoreAgentState(void)
{
	(void)  restoreAllMobilityBindings();
	removeStateFile();
	return (0);
}

/* ------------------------------------------------------------ */
/*	FILE			FUNCTIONS			*/
/* ------------------------------------------------------------ */

/*
 * Prepares the file to write out the state.
 */

static char	host_file[MAXLINELENGTH] = "";
#ifdef	LOCKFILE
static char	lock_file[MAXLINELENGTH] = "";
#endif	/* LOCKFILE */

/* returns -1 if error, 0 if ok */

static int
preFileAccess(boolean_t forReading)
{
	char	*envres;
	mode_t	mask;

	/* find out which files we should be using */

	if ((envres = getenv(ENVVAR)) == NULL) {
		(void) strcpy(host_file, SAVE_BINDINGS_FILE);
#ifdef	LOCKFILE
		(void) strcpy(lock_file, SAVE_BINDINGS_LOCK_FILE);
#endif	/* LOCKFILE */
	} else {
		(void) strcpy(host_file, envres);
#ifdef	LOCKFILE
		(void) strcpy(lock_file, envres);
		(void) strcat(lock_file, ".lock");
#endif	/* LOCKFILE */
	}

#ifdef	LOCKFILE
	/* open the lock file */

	if ((lockFile = open(lock_file, O_RDWR | O_CREAT)) == -1) {
		mipverbose(("preFileAccess: cannot open lock file\n"));
		return (-1);
	}

	/* lock it; block if already locked */

	if ((lockf(lockFile, F_LOCK, 0L)) == -1) {
		mipverbose(("preFileAccess: cannot lock %s\n",
		    lock_file));
		return (-1);
	}
#endif	/* LOCKFILE */

	/*
	 * Must first set umask so as not to allow anybody else
	 * to read these files. They may have keyeing material.
	 */
	mask = umask(~(S_IRUSR|S_IWUSR));

	/* open for reading/writing the file */
	if ((agentStateFile = fopen(host_file, (forReading ? "r" : "w")))
	    == NULL) {
		mipverbose(("preFileAccess: can't open %s for %s\n",
		    host_file, (forReading ? "reading" : "writing")));
#ifdef	LOCKFILE
		if ((lockf(lockFile, F_ULOCK, 0L)) == -1) {
			mipverbose(("preFileAccess: can't unlock %s\n",
			    lock_file));
		}
		(void) close(lockFile);
#endif	/* LOCKFILE */
		(void) umask(mask);
		return (-1);
	}
	(void) umask(mask);
	return (0);
} /* preFileAccess() */

/*
 * Called after file access.
 * Returns 0 if ok, -1 if error.
 */
static int
postFileAccess(void)
{
	int ret = 0;

	(void) fclose(agentStateFile);

#ifdef	LOCKFILE
	/* unlock the lock file */

	if ((lockf(lockFile, F_ULOCK, 0L)) == -1) {
		mipverbose(("postFileAccess can't unlock %s\n",
		    lock_file));
		ret = -1;
	}
	(void) close(lockFile);
#endif	/* LOCKFILE */
	return (ret);
} /* postFileAccess() */

/*
 * Delete the state and lock file after restoring.
 */
static void
removeStateFile(void)
{
	(void) unlink(host_file);
#ifdef	LOCKFILE
	(void) unlink(lock_file);
#endif	/* LOCKFILE */
} /* removeStateFile() */

/* returns 0 if error, otherwise 1 (nitems) */
static size_t
saveOneEntry(void *ptr, size_t	size)
{
	size_t nitems = fwrite(ptr, size, 1, agentStateFile);

	if (nitems != 1) {
		if (feof(agentStateFile)) {
			mipverbose(("saveOneEntry: eof! \n"));
			(void) postFileAccess();
			return (0);
		}
		if (ferror(agentStateFile)) {
			mipverbose(("saveOneEntry: error! \n"));
			(void) postFileAccess();
			return (0);
		}
	}
	return (nitems);
}

/* returns 0 if error, otherwise 1 (nitems) */
static size_t
readOneEntry(void *ptr, size_t	size)
{
	size_t nitems = fread(ptr, size, 1, agentStateFile);

	if (nitems != 1) {
		if (feof(agentStateFile)) {
			mipverbose(("readOneEntry: eof! \n"));
			(void) postFileAccess();
			return (0);
		}
		if (ferror(agentStateFile)) {
			mipverbose(("readOneEntry: error! \n"));
			(void) postFileAccess();
			return (0);
		}
	}
	return (nitems);
}

/*
 * Function: restoreIPsecPolicies()
 *
 * Arguments:	new   - Pointer to the new MobilityAgentEntry info.
 *			This is what we've just read from the config file.
 *		saved - Pointer to what we read as our exit config.
 *			This is how we were configured, and what IPsec
 *			policies were in place when we were told to shutdown.
 *
 * Description: Compares what was parsed from the config file with how we were
 *		configured when we exited.  Config file settings, and hence
 *		IPsec policies can change between executions.  We want to
 *		restore those that were installed with the new settings,
 *		informing the user when policies have changed, and which have
 *		been restored - especially when those that were in place have
 *		been removed.
 *
 * Returns:	1 if OK, 0 if not (like the others called from
 *		restoreAllMobilityBindings()).
 */
int
restoreIPsecPolicies(MobilityAgentEntry *new, MobilityAgentEntry *saved)
{
	/*
	 * Check the new policies, and restore any that were installed.  We're
	 * really just doing this as a convenience for the user.  Those that
	 * were installed because of bound mobile nodes will again be installed
	 * even if the policies are changed (we do NOT second-guess that sort
	 * of thing).  However, since this sort of thing can be confusing
	 * when it fails, we'll log the new policies so the user has a place
	 * to start if there are problems.
	 */
	int action;
	char peerAddr[IPv4_ADDR_LEN];

	(void) ntoa(new->maAddr, peerAddr);

	/*
	 * maPeerFlags will be restored when we restore the MN entries.
	 *
	 * We don't copy maIPsecFlags because the tunnel flags will be restored
	 * when the MN entries are restored, and the registration flags will
	 * be set as we [re]install each one.
	 *
	 * The maIPsecSAFlags[] aren't overwritten since they've been parsed
	 * based on the potentially new settings in conf-land!
	 *
	 * For readability, we first run through the policies, and see what's
	 * changed, then restore whatever was installed.
	 */
	for (action = FIRST_IPSEC_ACTION;
	    action < LAST_IPSEC_ACTION;
	    action++) {
		/* check all for IPSEC_APPLY, then IPSEC_PERMIT */
		if (memcmp(&new->maIPsecRequestIPSR[action],
		    &saved->maIPsecRequestIPSR[action],
		    sizeof (ipsec_req_t)) != 0) {
			/* SA has changed, tell the user. */
			mipverbose(("IPsecRequest %s policy for %s changed.\n",
			    validIPsecAction[action], peerAddr));

			/* was the policy active? */
			if (saved->maIPsecFlags & REQUEST(action)) {
				/* A problem if the user *unconfigured* it! */
				if (*new->maIPsecRequest[action] != 0)
					/* tell the user we know */
					mipverbose(("new IPsecRequest %s policy"
					    " will be installed.\n",
					    validIPsecAction[action]));
			}
		}

		if (memcmp(&new->maIPsecReplyIPSR[action],
		    &saved->maIPsecReplyIPSR[action],
		    sizeof (ipsec_req_t)) != 0) {
			/* SA has changed, tell the user. */
			mipverbose(("IPsecReply %s policy for %s changed.\n",
			    validIPsecAction[action], peerAddr));

			/* was the policy active? */
			if (saved->maIPsecFlags & REPLY(action)) {
				/* A problem if the user *unconfigured* it! */
				if (*new->maIPsecReply[action] != 0)
					/* tell the user we know */
					mipverbose(("new IPsecReply %s policy "
					    "will be installed.\n",
					    validIPsecAction[action]));
			}
		}

		if (memcmp(&new->maIPsecTunnelIPSR[action],
		    &saved->maIPsecTunnelIPSR[action],
		    sizeof (ipsec_req_t)) != 0) {
			/* SA has changed, tell the user. */
			mipverbose(("IPsecTunnel %s policy for %s changed.\n",
			    validIPsecAction[action], peerAddr));

			/* was the policy active? */
			if (saved->maIPsecFlags & TUNNEL(action)) {
				/* A problem if the user *unconfigured* it! */
				if (!IPSEC_TUNNEL_ANY(
				    new->maIPsecSAFlags[action])) {
					/* tell the user we know */
					mipverbose(("new IPsecTunnel %s policy "
					    "will be installed.\n",
					    validIPsecAction[action]));
				}
			}
		}

		if (memcmp(&new->maIPsecReverseTunnelIPSR[action],
		    &saved->maIPsecReverseTunnelIPSR[action],
		    sizeof (ipsec_req_t)) != 0) {
			/* SA has changed, tell the user. */
			mipverbose((
			    "IPsecReverseTunnel %s policy for %s changed.\n",
			    validIPsecAction[action], peerAddr));

			/* was the policy active? */
			if (saved->maIPsecFlags & REVERSE_TUNNEL(action)) {
				/* A problem if the user *unconfigured* it! */
				if (!IPSEC_REVERSE_TUNNEL_ANY(
				    new->maIPsecSAFlags[action]))
					/* tell the user we know. */
					mipverbose((
					    "new IPsecReverseTunnel %s policy "
					    "will be installed.\n",
					    validIPsecAction[action]));
			}
		}
	}

	/*
	 * Restore those that were installed.  Warn the user if any of these
	 * went away!
	 */
	for (action = FIRST_IPSEC_ACTION;
	    action < LAST_IPSEC_ACTION;
	    action++) {
		/* restore for IPSEC_APPLY, then IPSEC_PERMIT */

		/*
		 * note: there is a potential problem with restoring REQUESTs.
		 * Before we restore, we parse the config file, which is when
		 * IPSEC_REQUEST_PERMIT policies need to be installed.  That
		 * means if this is what we're restoring, it's been done (and
		 * it's the new = correct policy).
		 */
		if ((action != IPSEC_PERMIT) &&
		    (saved->maIPsecFlags & REQUEST(action))) {
			/* restore, IFF still configured */
			if (*new->maIPsecRequest[action] != 0) {
				if (installIPsecPolicy(
				    new->maIPsecRequest[action]) < 0) {
					/* we wont be able to communicate */
					mipverbose((
					    "Can't restore %s's ipsec %s"
					    "registration request policy.\n",
					    validIPsecAction[action],
					    peerAddr));
					return (0);
				}

				/* set the installed flag */
				new->maIPsecFlags |= REQUEST(action);

			} else {
				/* one WAS installed, but isn't configured */
				mipverbose(("WARNING: IPsecRequest %s policy "
				    "for %s was installed but is no longer "
				    "configured!  Registration request will be "
				    "in the clear!", validIPsecAction[action],
				    peerAddr));
				return (0);
			}
		}

		if (saved->maIPsecFlags & REPLY(action)) {
			/* restore, IFF still configured */
			if (*new->maIPsecReply[action] != 0) {
				if (installIPsecPolicy(
				    new->maIPsecReply[action]) < 0) {
					/* we wont be able to communicate */
					mipverbose((
					    "Can't restore %s's ipsec %s"
					    "registration reply policy.\n",
					    validIPsecAction[action],
					    peerAddr));
					return (0);
				}

				/* set the installed flag */
				new->maIPsecFlags |= REPLY(action);

			} else {
				/* one WAS installed, but isn't configured */
				mipverbose(("WARNING: IPsecReply %s policy "
				    "for %s was installed but is no longer "
				    "configured!  Registration reply will be "
				    "in the clear!", validIPsecAction[action],
				    peerAddr));
				return (0);
			}
		}

		/*
		 * Note:
		 * tunnel entries are added when we restore the MNs still
		 * registered with us.  An existing MN causes addHABE() to be
		 * called, which calls encapadd() where the correct ipsec_req_t
		 * is passed to ioctl() via settaddr() - exactly as if the MN
		 * registered.  At this time, warn the user if any policies
		 * went away, yet we're likely to restore the policy with a MN!
		 */
		if (saved->maIPsecFlags & TUNNEL(action)) {
			if (!IPSEC_TUNNEL_ANY(new->maIPsecSAFlags[action]))
				/* tell the user the config's gone */
				mipverbose((
				    "WARNING: IPsecTunnel %s policy for "
				    " %s was installed, but is no longer "
				    "configured.  Restoring with no policy!",
				    validIPsecAction[action], peerAddr));
		}

		if (saved->maIPsecFlags & REVERSE_TUNNEL(action)) {
			if (!IPSEC_REVERSE_TUNNEL_ANY(
			    new->maIPsecSAFlags[action]))
				/* tell the user the config's gone */
				mipverbose((
				    "WARNING: IPsecReverseTunnel %s policy for "
				    " %s was installed, but is no longer "
				    "configured.  Restoring with no policy!",
				    validIPsecAction[action], peerAddr));
		}
	}

	return (1);
}
