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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include "HBAList.h"
#include "Exceptions.h"
#include "Trace.h"
#include "sun_fc_version.h"
#include <string>
#include <sstream>
#include "FCHBA.h"
#include "TgtFCHBA.h"

using namespace std;

/**
 * @memo	    Private constructor (used to create singleton instance)
 * @see		    HBAList::instance
 */
HBAList::HBAList() { }

/**
 * Internal singleton instance
 */
HBAList* HBAList::_instance = 0;

/**
 * Max number of adapters that this class supports.
 */
const int32_t HBAList::HBA_MAX_PER_LIST = INT_MAX;

/**
 * @memo	    Free up resources held by this HBA list
 * @postcondition   All memory used by this list will be freed
 * @return	    HBA_STATUS_OK on success
 * 
 */
HBA_STATUS HBAList::unload() {
	Trace log("HBAList::unload");
	lock();
	_instance = NULL;
	unlock();
	return (HBA_STATUS_OK);
}

/**
 * @memo	    Fetch the singleton instance
 * @return	    The singleton instance
 * 
 * @doc		    Only one instance of HBAList must be present
 *		    per address space at a time.  The singleton design pattern
 *		    is used to enforce this behavior.
 */
HBAList* HBAList::instance() {
	Trace log("HBAList::instance");
	if (_instance == 0) {
	    _instance = new HBAList();
	}
	return (_instance);
}

/**
 * @memo	    Fetch an HBA based on name.
 *		    Always returns  non-null or throw an Exception.
 * @precondition    HBAs must be loaded in the list
 * @postcondition   A handle will be opened.  The caller must close the handle
 *		    at some later time to prevent leakage.
 * @exception	    BadArgumentException if the name is not properly formatted
 * @exception	    IllegalIndexException if the name does not match any
 *		    present HBAs within this list.
 * @return	    A valid handle for future API calls
 * @param	    name The name of the HBA to open
 * 
 * @doc		    This routine will always return a handle (ie, non null)
 *		    or will throw an exception.
 */
Handle* HBAList::openHBA(string name) {
	Trace log("HBAList::openHBA(name)");
	int index = -1;
	try {
	    string::size_type offset = name.find_last_of("-");
	    if (offset >= 0) {
		string indexString = name.substr(offset+1);
		index = atoi(indexString.c_str());
	    }
	} catch (...) {
	    throw BadArgumentException();
	}
	lock();
	if (index < 0 || index > hbas.size()) {
	    unlock();
	    throw IllegalIndexException();
	} else {
	    HBA *tmp = hbas[index];
	    unlock();
	    tmp->validatePresent();
	    return (new Handle(tmp));
	}
}

/**
 * @memo	    Fetch an target mode FC HBA based on name.
 *		    Always returns  non-null or throw an Exception.
 * @precondition    Target mode HBAs must be loaded in the list
 * @postcondition   A handle will be opened.  The caller must close the handle
 *		    at some later time to prevent leakage.
 * @exception	    BadArgumentException if the name is not properly formatted
 * @exception	    IllegalIndexException if the name does not match any
 *		    present HBAs within this list.
 * @return	    A valid handle for future API calls
 * @param	    name The name of the target mode HBA to open
 * 
 * @doc		    This routine will always return a handle (ie, non null)
 *		    or will throw an exception.
 */
Handle* HBAList::openTgtHBA(string name) {
	Trace log("HBAList::openHBA(name)");
	int index = -1;
	try {
	    string::size_type offset = name.find_last_of("-");
	    if (offset >= 0) {
		string indexString = name.substr(offset+1);
		index = atoi(indexString.c_str());
	    }
	} catch (...) {
	    throw BadArgumentException();
	}
	lock();
	if (index < 0 || index > tgthbas.size()) {
	    unlock();
	    throw IllegalIndexException();
	} else {
	    HBA *tmp = tgthbas[index];
	    unlock();
	    tmp->validatePresent();
	    return (new Handle(tmp));
	}
}

/**
 * @memo	    Get the name of an HBA at the given index
 * @precondition    HBAs must be loaded in the list
 * @exception	    IllegalIndexException Thrown if the index doesn't match any
 *		    HBA in the list
 * @return	    The name of the specified HBA
 * @param	    index The zero based index of the desired HBA
 * 
 */
string HBAList::getHBAName(int index) {
	Trace log("HBAList::getHBAName");
	lock();
	if (index < 0 || index > hbas.size()) {
	    unlock();
	    throw IllegalIndexException();
	} else {
	    HBA *tmp = hbas[index];
	    unlock();
	    tmp->validatePresent();
	    char buf[128];
	    snprintf(buf, 128, "%s-%d", tmp->getName().c_str(), index);
	    string name = buf;
	    return (name);
	}
}

/**
 * @memo	    Get the name of an target mode HBA at the given index
 * @precondition    Target mode HBAs must be loaded in the list
 * @exception	    IllegalIndexException Thrown if the index doesn't match any
 *		    HBA in the list
 * @return	    The name of the specified target mode HBA
 * @param	    index The zero based index of the desired target mode HBA
 * 
 */
string HBAList::getTgtHBAName(int index) {
	Trace log("HBAList::getTgtHBAName");
	lock();
	if (index < 0 || index > tgthbas.size()) {
	    unlock();
	    throw IllegalIndexException();
	} else {
	    HBA *tmp = tgthbas[index];
	    unlock();
	    tmp->validatePresent();
	    char buf[128];
	    snprintf(buf, 128, "%s-%d", tmp->getName().c_str(), index);
	    string name = buf;
	    return (name);
	}
}

/**
 * @memo	    Open an HBA based on a WWN
 * @precondition    HBAs must be loaded in the list
 * @postcondition   A handle will be opened.  The caller must close the handle
 *		    at some later time to prevent leakage.
 * @exception	    IllegalWWNException Thrown if the wwn doesn't match any
 *		    HBA in the list
 * @return	    A valid Handle for later use by API calls
 * @param	    wwn The node or any port WWN of HBA to open
 * @see		    HBA::containsWWN
 * 
 * @doc		    This routine will accept both Node and Port WWNs based
 *		    on the HBA routine containsWWN
 */
Handle* HBAList::openHBA(uint64_t wwn) {

	Trace log("HBAList::openHBA(wwn)");
	lock();
	HBA *tmp;
	for (int i = 0; i < hbas.size(); i++) {
	    if (hbas[i]->containsWWN(wwn)) {
		tmp = hbas[i];
		unlock();
		tmp->validatePresent();
		return (new Handle(tmp));
	    }
	}
	unlock();
	throw IllegalWWNException();
}

/**
 * @memo	    Open an target mode HBA based on a WWN
 * @precondition    Targee mode HBAs must be loaded in the list
 * @postcondition   A handle will be opened.  The caller must close the handle
 *		    at some later time to prevent leakage.
 * @exception	    IllegalWWNException Thrown if the wwn doesn't match any
 *		    target mode HBA in the list
 * @return	    A valid Handle for later use by API calls
 * @param	    The node WWN or any port WWN of target mode HBA to open
 * @see		    HBA::containsWWN
 * 
 * @doc		    This routine will accept both Node and Port WWNs based
 *		    on the HBA routine containsWWN
 */
Handle* HBAList::openTgtHBA(uint64_t wwn) {

	Trace log("HBAList::openTgtHBA(wwn)");
	lock();
	HBA *tmp;
	for (int i = 0; i < tgthbas.size(); i++) {
	    if (tgthbas[i]->containsWWN(wwn)) {
		tmp = tgthbas[i];
		unlock();
		tmp->validatePresent();
		return (new Handle(tmp));
	    }
	}
	unlock();
	throw IllegalWWNException();
}

/**
 * @memo	    Get the number of adapters present in the list
 * @postcondition   List of HBAs will be loaded
 * @exception	    ... Underlying exceptions will be thrown
 * @return	    The number of adapters in the list
 * 
 * @doc		    This routine will triger discovery of HBAs on the system.
 *		    It will also handle addition/removal of HBAs in the list
 *		    based on dynamic reconfiguration operations.  The max 
 *		    number of HBAs that HBA API supports is up to the
 *		    uint32_t size.  VSL supports up to int32_t size thus
 *		    it gives enough room for the HBA API library
 *		    to handle up to max uint32_t number if adapters. 
 */
int HBAList::getNumberofAdapters() {
	Trace log("HBAList::getNumberofAdapters");
	lock();

	try {
	if (hbas.size() == 0) {
	    // First pass, just store them all blindly
	    FCHBA::loadAdapters(hbas);
	} else {
	    // Second pass, do the update operation
	    vector<HBA*> tmp;
	    FCHBA::loadAdapters(tmp);
	    bool matched;
	    for (int i = 0; i < tmp.size(); i++) {
		matched = false;
		for (int j = 0; j < hbas.size(); j++) {
		    if (*tmp[i] == *hbas[j]) {
			matched = true;
			break;
		    }
		}
		if (matched) {
		    delete (tmp[i]);
		} else {
		    hbas.insert(hbas.end(), tmp[i]);
		}
	    }
	}
	} catch (...) {
	    unlock();
	    throw;
	}

	unlock();

	// When there is more than HBA_MAX_PER_LIST(= int32_max)
	// VSL returns an error so it is safe to cast it here.
	return ((uint32_t)hbas.size());
}

/**
 * @memo	    Get the number of target mode adapters present in the list
 * @postcondition   List of TgtHBAs will be loaded
 * @exception	    ... Underlying exceptions will be thrown
 * @return	    The number of target mode adapters in the list
 * 
 * @doc		    This routine will triger discovery of Target mode HBAs on
 *		    the system. It will also handle addition/removal of Target
 * 		    mode HBAs in the list based on dynamic reconfiguration 
 *		    operations. The max number of target mode HBAs that
 *		    HBA API supports is up to the
 *		    uint32_t size.  VSL supports up to int32_t size thus
 *		    it gives enough room for the HBA API library
 *		    to handle up to max uint32_t number of adapters. 
 */
int HBAList::getNumberofTgtAdapters() {
	Trace log("HBAList::getNumberofTgtAdapters");
	lock();

	try {
	    if (tgthbas.size() == 0) {
		// First pass, just store them all blindly
		TgtFCHBA::loadAdapters(tgthbas);
	    } else {
		// Second pass, do the update operation
		vector<HBA*> tmp;
		TgtFCHBA::loadAdapters(tmp);
		bool matched;
		for (int i = 0; i < tmp.size(); i++) {
		    matched = false;
		    for (int j = 0; j < tgthbas.size(); j++) {
			if (*tmp[i] == *tgthbas[j]) {
			    matched = true;
			    break;
			}
		    }
		    if (matched) {
			delete (tmp[i]);
		    } else {
			tgthbas.insert(tgthbas.end(), tmp[i]);
		    }
		}
	    }
	} catch (...) {
	    unlock();
	    throw;
	}

	unlock();

	// When there is more than HBA_MAX_PER_LIST(= int32_max)
	// VSL returns an error so it is safe to cast it here.
	return ((uint32_t)tgthbas.size());
}

/**
 * @memo	    Load the list
 * @return	    HBA_STATUS_OK
 * 
 * @doc		    Currently this routine is a no-op and may be a cantidate
 *		    for removal in the future.
 */
HBA_STATUS HBAList::load() {
	Trace log("HBAList::load");

	// No lock is required since no VSL specific action requried.
	return (HBA_STATUS_OK);
}

/**
 * @memo	    Free up resources
 */
HBAList::~HBAList() {
	Trace log("HBAList::~HBAList");
	for (int i = 0; i < hbas.size(); i++) {
	    delete (hbas[i]);
	}
	for (int i = 0; i < tgthbas.size(); i++) {
	    delete (tgthbas[i]);
	}
}

HBA_LIBRARYATTRIBUTES HBAList::getVSLAttributes() {
	HBA_LIBRARYATTRIBUTES attrs;
	char	build_time[] = BUILD_TIME;
	attrs.final = 0;
	memset(&attrs, 0, sizeof(attrs));
	strlcpy(attrs.VName, VSL_NAME, sizeof (attrs.VName));
	strlcpy(attrs.VVersion, VSL_STRING_VERSION, sizeof (attrs.VVersion));
	strptime(build_time, "%c", &attrs.build_date);

	return (attrs);
}
