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

#ifndef	_HBALIST_H
#define	_HBALIST_H



#include "Lockable.h"
#include "HBA.h"
#include "Handle.h"
#include <vector>
#include <string>
#include <hbaapi.h>

/**
 * @memo	    Singleton class that represents the entire list of HBAs
 *		    known to the system.
 *
 * @doc		    This class and its single instance is used to track
 *		    all the known HBAs on the system.  This class
 *		    will gracefully handle dynamic reconfiguration
 *		    in accordance with the FC-HBA specification.
 *		    HBA_MAX_PER_LIST represents the maximum number of
 *		    adapters that are supported by this class.
 */
class HBAList : public Lockable{
public:
    static HBAList*	    instance();
    ~HBAList();
    static const int32_t    HBA_MAX_PER_LIST;
    HBA_STATUS		    load();
    HBA_STATUS		    unload();
    int			    getNumberofAdapters();
    int			    getNumberofTgtAdapters();
    std::string		    getHBAName(int index);
    std::string		    getTgtHBAName(int index);
    Handle*		    openHBA(std::string name);
    Handle*		    openTgtHBA(std::string name);
    Handle*		    openHBA(uint64_t wwn);
    Handle*		    openTgtHBA(uint64_t wwn);
    HBA_LIBRARYATTRIBUTES   getVSLAttributes();

protected:
    HBAList(); // Singleton

    // Prevent ambiguity
    using Lockable::lock;
    using Lockable::unlock;

private:
    static HBAList*	    _instance;
    std::vector<HBA*>	    hbas;
    std::vector<HBA*>	    tgthbas;
};

#endif /* _HBALIST_H */
