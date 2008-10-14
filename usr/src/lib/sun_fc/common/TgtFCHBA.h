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

#ifndef	_TGTFCHBA_H
#define	_TGTFCHBA_H




#include "HBA.h"
#include "TgtFCHBAPort.h"
#include <map>
#include <string>
#include <hbaapi.h>


/**
 * Represents an individual FCHBA
 */
class TgtFCHBA : public HBA {
public:
    TgtFCHBA(std::string path);
    /**
     * Fetch the name, excluding the trailing "-" and index number
     */
    virtual std::string		    getName();
    virtual HBA_ADAPTERATTRIBUTES   getHBAAttributes();
    static void loadAdapters(std::vector<HBA*> &list);
    virtual HBA_ADAPTERATTRIBUTES   npivGetHBAAttributes() {
					throw NotSupportedException(); }

private:
    std::string			name;
    static const std::string	FCT_DRIVER_PATH;
    static const std::string	FCT_ADAPTER_NAME_PREFIX;
    static const std::string	FCT_DRIVER_PKG;
    static const int		MAX_FCTIO_MSG_LEN;
};


#endif /* _TGTFCHBA_H */
