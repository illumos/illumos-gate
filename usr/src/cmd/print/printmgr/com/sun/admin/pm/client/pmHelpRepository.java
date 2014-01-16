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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * pmHelpRepository.java
 * Database of help articles
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import com.sun.admin.pm.server.*;



/*
 * The help repository manages three distinct databases.
 *
 * helpItemDB:      String tag -> pmHelpItem
 *      Returns a pmHelpItem given its unique tag.
 *      Used to resolve a reference from the app.
 *
 * helpKeywordDB:   String -> Vector(of pmHelpItems)
 *      Returns a Vector containing all pmHelpItems whose `keywords'
 *      property contains the specifed keyword.
 *
 * helpTitleDB:     String -> Vector (of pmHelpItems)
 *      Returns a Vector containing all pmHelpItems whose `title'
 *      property is a partial match for the specified string.
 */

final class pmHelpRepository  {

    private static Hashtable helpItemDB = null;
    private static Hashtable helpKeywordDB = null;
    private static BST helpTitleDB = null;


    // database of HelpItems, by tag string
    static void populateHelpItemDB() {
        helpItemDB = new Hashtable();
        loadHelpItemDB();
        // Debug.message("HELP:  helpItemDB: " + helpItemDB);
    }

    // database of Vectors of HelpItems, by keyword string
    static void populateHelpKeywordDB() {
        if (helpItemDB == null)
            return;

	/*
	 * Strategy:
	 *  for each item
	 *    for each keyword
	 *	   if kw not in db
	 *		add ititem.tag
	 *		    add item to keyword entry
	 */

        helpKeywordDB = new Hashtable();

        Vector v = null;
        Enumeration items = helpItemDB.elements();
        while (items.hasMoreElements()) {
            pmHelpItem item = (pmHelpItem) items.nextElement();
            Enumeration keywords = item.keywords.elements();
            while (keywords.hasMoreElements()) {
                String keyword = (String) keywords.nextElement();
                v = (Vector) helpKeywordDB.get(keyword);
                if (v == null)
                    helpKeywordDB.put(keyword, v = new Vector());
                v.addElement(item);
            }
        }

        // Debug.message("HELP:  KeywordDB: " + helpKeywordDB);
    }


    // database of HelpItems, by (partial) title string
    static void populateHelpTitleDB() {
        if (helpItemDB == null)
            return;

	/*
	 * strategy:
	 *   assume itemDB is loaded
	 *   for each item in itemDB
	 *	create an entry in titleDB
	 */

        helpTitleDB = new BST();

        Enumeration items = helpItemDB.elements();
        while (items.hasMoreElements()) {
            pmHelpItem item = (pmHelpItem) items.nextElement();
            helpTitleDB.insert(item.title, item);
        }
    }


    static public pmHelpItem helpItemForTag(String tag) {
        if (helpItemDB == null || tag == null)
            return null;
        return (pmHelpItem) helpItemDB.get(tag);
    }

    static public Vector helpItemsForKeyword(String keyword) {
        if (helpKeywordDB == null)
            return null;

        return (Vector) helpKeywordDB.get(keyword.toLowerCase());
    }


    static public Vector helpItemsForString(String partialTitle)
        throws pmHelpException {

        Debug.info("HELP:  helpItemsForString: " + partialTitle);

        if (helpTitleDB == null)
            return new Vector();

        Vector v = new Vector();
        helpTitleDB.traverse_find_vector(v, partialTitle);

        Debug.info("HELP:  helpItemsForString: vector contains " +
                   v.size() + " items");

        return v;
    }




    // this should go in utils...
    public static String getResource(String key) {
        String keyvalue = null;
        ResourceBundle bundle = null;

        Debug.message("HELP:  getResource(" + key + ")");

        try {
            try {
                bundle = ResourceBundle.getBundle(
                    "com.sun.admin.pm.client.pmHelpResources");
            } catch (MissingResourceException e) {
                Debug.fatal("HELP:  Could not load pmHelpResources file");
            }

            try {
                keyvalue = bundle.getString(key);
            } catch (MissingResourceException e) {
                keyvalue = bundle.getString("Missing:") + key;
                Debug.error("HELP:  Missing: " + key);
            }
        } catch (Exception other) {
            Debug.error("HELP:  getResource(" + key + ") : " + other);
        }

	return keyvalue;
    }


    // from resources, presumably
    static public void loadHelpItemDB() {

        // Debug.setDebugLevel(new pmHelpRepository(), Debug.ALL);

	/*
	 * strategy:
	 *   for each tag name (from pmHelpTagNameEnumerator):
	 *	get the property values from the resource bundle
	 */

        Debug.message("HELP:  Starting help item load");

        ResourceBundle bundle = null;

        try {
            bundle = ResourceBundle.getBundle(
                "com.sun.admin.pm.client.pmHelpResources");
        } catch (MissingResourceException e) {
            Debug.fatal("HELP:  Could not load pmHelpResources file");
            return;
        }
        Enumeration e = bundle.getKeys();
        while (e.hasMoreElements()) {
            String key = (String) e.nextElement();
            if (key.endsWith(".tag")) {
                String tagName = null;
                try {
                    tagName = bundle.getString(key);
                } catch (MissingResourceException x) {
                    Debug.warning("HELP:  Unable to find tag for " + key);
                    continue;
                }

                Debug.message("HELP:  Making new item " + tagName);

                pmHelpItem item = new pmHelpItem(tagName);

                String theTitle = getResource(tagName + ".title");
                item.setTitle(theTitle);

                item.setContent(new pmHelpContent(
                getResource(tagName + ".content")));

                Vector v = null;
                StringTokenizer st = null;

                String s = getResource(tagName + ".seealso");
                if (s != null) {
                    v = new Vector();
                    st = new StringTokenizer(s);
                    while (st.hasMoreTokens())
                        v.addElement(st.nextToken());
                    item.setSeeAlso(v);
                }

                v = new Vector();
                s = getResource(tagName + ".keywords");
                if (s != null) {
                    st = new StringTokenizer(s);
                    while (st.hasMoreTokens()) {
                        String word = st.nextToken();
                        String quotelessWord = word.replace('\"', ' ');
                        v.addElement(quotelessWord.trim());
                    }
                } else
                    Debug.warning("HELP:  Item " + tagName +
                                  " keywords is empty");


                // insert item's title words into its keywords
                st = new StringTokenizer(theTitle);
                while (st.hasMoreTokens()) {
                    String word = (st.nextToken()).toLowerCase();

                    // ignore useless words
                    if (ignoreKeyTitleWords.indexOf(word) != -1) {
                        Debug.message("HELP:  ignoring " + word +
                                      " from " + theTitle);
                        continue;
                    }

                    Debug.message("HELP:  adding " + word +
                                  " from " + theTitle);

                    v.addElement(word);
                }

                item.setKeywords(v);


                Debug.message("HELP:  New item: " + item);

                helpItemDB.put(item.tag, item);
            }
        }
    }


    // these words are not to be treated as keywords when they appear in title
    static final private String
		/* JSTYLED */
		ignoreKeyTitleWords = pmUtility.getResource("help.ignore.words");                    
}
