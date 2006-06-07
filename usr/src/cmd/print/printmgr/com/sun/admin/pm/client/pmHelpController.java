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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmHelpController.java
 * Help subsystem implementation
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.io.*;
import javax.swing.JPanel;
import javax.swing.border.*;
import javax.swing.*;

import com.sun.admin.pm.server.*;

class pmHelpController {

    public pmHelpFrame frame = null;

    /*
     * request presentation of the specified help item.
     */
    public void showHelpItem(String tag) {
        Debug.info("HELP: controller.showHelpitem "  + tag);
        if (tag != null) {
            pmHelpItem item = viewPanel.loadItemForTag(tag);
            outerPanel.setSelectedComponent(viewPanel);
        }
    }

    public void showHelpItem(pmHelpItem item) {
        if (item != null)
            showHelpItem(item.tag);
    }

    JTabbedPane outerPanel;
    pmHelpDetailPanel viewPanel;
    pmHelpIndexPanel indexPanel;
    pmHelpSearchPanel searchPanel;

    Vector history;

    public JTabbedPane getTopPane() {
        return outerPanel;
    }

    public pmHelpController(pmHelpFrame f) {

        frame = f;

        outerPanel = new JTabbedPane();

        viewPanel = new pmHelpDetailPanel(this);
        indexPanel = new pmHelpIndexPanel(this);
        searchPanel = new pmHelpSearchPanel(this);

        outerPanel.add(pmUtility.getResource("View"), viewPanel);
        outerPanel.add(pmUtility.getResource("Index"), indexPanel);
        outerPanel.add(pmUtility.getResource("Search"), searchPanel);

        pmHelpRepository.populateHelpItemDB();
        pmHelpRepository.populateHelpKeywordDB();
        pmHelpRepository.populateHelpTitleDB();

	indexPanel.queryPanel.handleText("");	// prime it... ugly.

        history = new Vector();

        frame.setDefaultComponent(outerPanel);
    }


}
