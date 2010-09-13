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
 * BST.java
 * Simple binary search tree implementation for help articles
 *
 */

package com.sun.admin.pm.client;

import java.lang.*;
import java.util.*;
import com.sun.admin.pm.server.*;


public class BST extends Object {

    // these should be protected...
    public BST left = null;
    public BST right = null;
    public BST parent = null;
    public BSTItem data;

    static public int comparisons;

    public BST(BSTItem theItem) {
        // Debug.info("HELP: New BST(" + theItem + ")");

        left = right = null;
        data = theItem;
    }


    public BST() {
        this(new BSTItem("", null));
    }

    public BST insert(String key, Object data) {
        return insert(new BSTItem(key,  data));
    }


    // normal bst insertion
    public BST insert(BSTItem theItem) {

        int comp = data.compare(theItem);
        BST node = null;

        if (comp == 0) {
            Debug.info("HELP: Duplicate insert: " +
                        theItem.toString());
        } else if (comp > 0) {
            if (left != null)
                left.insert(theItem);
            else
                left = node = new BST(theItem);
        } else if (comp < 0) {
            if (right != null)
                right.insert(theItem);
            else
                right = node = new BST(theItem);
        }

        return node;
    }


    public BST find_tree(String newKey) {
        return find_tree(newKey, true);
    }

    public BSTItem find(String newKey) {
        return find(newKey, true);
    }


    public BST find_tree(String newKey, boolean exactMatch) {
        /*
         * Debug.info("HELP: Finding " +(exactMatch ? "exact " : "partial ") +
         * newKey);
         */

        BST rv = null;
        int comp = data.compare(newKey, exactMatch);

        ++comparisons;

        if (comp > 0) {
            if (left != null)
                rv = left.find_tree(newKey, exactMatch);
        } else if (comp < 0) {
            if (right != null)
                rv = right.find_tree(newKey, exactMatch);
        } else {
            rv = this;
            // Debug.info("HELP: Found " + newKey + " in " + data);
        }

        return rv;
    }

    public BSTItem find(String newKey, boolean exactMatch) {
        Debug.info("HELP: Finding " +(exactMatch ? "exact " : "partial ") +
                    newKey);

        BSTItem rv = null;
        int comp = data.compare(newKey, exactMatch);

        ++comparisons;

        if (comp > 0) {
            if (left != null)
                rv = left.find(newKey, exactMatch);
        } else if (comp < 0) {
            if (right != null)
                rv = right.find(newKey, exactMatch);
        } else {
            Debug.info("HELP: Found " + newKey + " in " + data);
            rv = this.data;
        }

        return rv;
    }



    public void traverse() {
        if (left != null)
            left.traverse();
        Debug.info("HELP: Traverse: " + data);
        if (right != null)
            right.traverse();
    }

    public void traverse_right() {
        Debug.info("HELP: Traverse: " + data);
        if (right != null)
            right.traverse();
    }


    public void traverse_find(String key) {
        if (left != null)
            left.traverse_find(key);
        if (data.compare(key, false) < 0)
            return;
        Debug.info("HELP: Traverse_find: " + data.key);
        if (right != null)
            right.traverse_find(key);
    }

    // empty search string is a wildcard...
    public void traverse_find_vector(Vector v, String key) {
        /*
         * Debug.info("HELP: traverse_find_vector: node " +
         * data.key + "[" +(left!=null?left.data.key:"null") + "]" +
         * "[" +(right!=null ?right.data.key:"null") + "]" +
         * " seeking " + key);
         */
        int c = 0;

        if (key.length() > 0)
            c = data.compare(key, false);

        /*
         * Debug.info("HELP: traverse_find_vector: compare " +
         * data.key + " to "+ key + " = " + c);
         */

        if (c >= 0 && left != null)
            left.traverse_find_vector(v, key);

        if (c == 0) {
            // Debug.info("HELP: traverse_find_vector: adding " + data.key);
            v.addElement(data.data);
        }

        if (c <= 0) {
            if (right != null)
                right.traverse_find_vector(v, key);
        }
    }


    public void dump() {
        Debug.info("HELP: \nDump: this = " + data.key);

        if (left != null)
            Debug.info("HELP: Dump: left = " + left.data.key);
        else
            Debug.info("HELP: Dump: left = null");


        if (right != null)
            Debug.info("HELP: Dump: right = " + right.data.key);
        else
            Debug.info("HELP: Dump: right = null");

        if (left != null)
            left.dump();
        if (right != null)
            right.dump();

    }

    public static void main(String args[]) {
        BSTItem root = new BSTItem("Root");
        BSTItem a = new BSTItem("Alpha");
        BSTItem b = new BSTItem("Bravo");
        BSTItem c = new BSTItem("Charlie");
        BSTItem d = new BSTItem("Delta");
        BSTItem e = new BSTItem("Echo");
        BSTItem x = new BSTItem("Xray");
        BSTItem aa = new BSTItem("aspect");
        BSTItem ab = new BSTItem("assess");
        BSTItem ad = new BSTItem("assist");
        BSTItem ae = new BSTItem("asphalt");
        BSTItem af = new BSTItem("asap");
        BSTItem ag = new BSTItem("adroit");
        BSTItem ah = new BSTItem("adept");
        BSTItem ai = new BSTItem("asdf");

        BST bst = new BST(root);

        BST.comparisons = 0;
        bst.insert(a);
        System.out.println(BST.comparisons +
                            " comparisons\n");
        BST.comparisons = 0;
        bst.insert(x);
        System.out.println(BST.comparisons +
                            " comparisons\n");
        BST.comparisons = 0;
        bst.insert(e);
        System.out.println(BST.comparisons +
                            " comparisons\n");
        BST.comparisons = 0;
        bst.insert(c);
        System.out.println(BST.comparisons +
                            " comparisons\n");
        BST.comparisons = 0;
        bst.insert(b);
        System.out.println(BST.comparisons +
                            " comparisons\n");
        BST.comparisons = 0;
        bst.insert(d);
        System.out.println(BST.comparisons +
                            " comparisons\n");

        bst.insert(aa);
        bst.insert(ab);
        bst.insert(ad);
        bst.insert(ae);
        bst.insert(af);
        bst.insert(ag);
        bst.insert(ah);
        bst.insert(ai);

        bst.traverse();

        BST.comparisons = 0;
        bst.find("Echo");
        System.out.println(BST.comparisons +
                            " comparisons\n");
        BST.comparisons = 0;
        bst.find("Xray");
        System.out.println(BST.comparisons +
                            " comparisons\n");
        BST.comparisons = 0;
        bst.find("Delta");
        System.out.println(BST.comparisons +
                            " comparisons\n");
        BST.comparisons = 0;
        bst.find("Root");
        System.out.println(BST.comparisons +
                            " comparisons\n");
        bst.find("Alpha");

        bst.dump();
        if (bst.left != null)
            bst.left.dump();
        if (bst.right != null)
            bst.right.dump();

        {
            Debug.info("HELP: Looking for a");
            BST result = bst.find_tree("a", false);
            result.traverse_find("a");

            Debug.info("HELP: Looking for as");
            result = result.find_tree("as", false);
            result.traverse_find("as");

            Debug.info("HELP: Looking for ass");
            result = result.find_tree("ass", false);
            result.traverse_find("ass");

            Debug.info("HELP: Looking for ad");
            result = bst.find_tree("ad", false);
            result.traverse_find("ad");
        }
    }
}
