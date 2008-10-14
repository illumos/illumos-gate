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

#ifndef	_HANDLE_H
#define	_HANDLE_H



// Forward Declarations
class Handle;
class HandlePort;

#include "Lockable.h"
#include "HBA.h"
#include "HandlePort.h"
#include <map>
#include <hbaapi.h>
#include <hbaapi-sun.h>


/**
 * @memo	    Represents an open HBA port
 *
 * @doc		    This class represents an open HBA.  However,
 *		    what we really care about is the HBA port's underneath.
 *		    So, we also track HandlePorts internally.
 */
class Handle : public Lockable {
public:
    enum MODE { INITIATOR, TARGET };
    Handle(HBA *hba); // Generate ID, and add to vector
    //    Handle(HBA *hba, MODE m); // Generate ID based on target or initiator mode
    ~Handle(); // Free and remove from vector

    static Handle*	    findHandle(HBA_HANDLE index);
    static Handle*	    findHandle(uint64_t wwn);
    static void		    closeHandle(HBA_HANDLE index);

    HBA_HANDLE		    getHandle();

    bool		    operator==(Handle comp);

    HBA*		    getHBA() { return (hba); }
    HandlePort*		    getHandlePortByIndex(int index);
    HandlePort*		    getHandlePort(uint64_t wwn);
    MODE		    getMode() { return (modeVal); };
    void		    refresh();

    HBA_ADAPTERATTRIBUTES	    getHBAAttributes();
    HBA_ADAPTERATTRIBUTES	    npivGetHBAAttributes();
    HBA_PORTATTRIBUTES		    getPortAttributes(uint64_t wwn);

private:
    HBA				    *hba;
    HBA_HANDLE			    id;
    MODE			    modeVal;
    static pthread_mutex_t	    staticLock;

    static HBA_HANDLE		    prevOpen;
    static HBA_HANDLE		    prevTgtOpen;
    static std::map<HBA_HANDLE, Handle*>    openHandles;
    std::map<uint64_t, HandlePort*>	    portHandles;
};

#endif /* _HANDLE_H */
