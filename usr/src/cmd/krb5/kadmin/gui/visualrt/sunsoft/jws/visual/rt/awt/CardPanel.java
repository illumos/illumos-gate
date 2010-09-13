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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) CardPanel.java 1.8 - last change made 06/17/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;

import java.awt.*;
import java.util.*;

public class CardPanel extends VJPanel {
    public static final int FETCHCARD = 68496;
    public static final int CURRENTCARD = 68497;
    
    protected Vector tabs;
    private Label cardLabel;
    private CardLayout cardLayout;
    private String currentCard;
    private Hashtable cards;
    
    public CardPanel() {
        cardLayout = new CardLayout();
        setLayout(cardLayout);
        
        tabs = new Vector();
        cards = new Hashtable();
        
        cardLabel = newCardLabel();
        add(cardLabel, /* NOI18N */"foobar");
        // JDK1.1 requires a constraint
    }
    
    protected Label newCardLabel() {
        return new Label(Global.getMsg(
/* JSTYLED */
				       "sunsoft.jws.visual.rt.awt.CardPanel.Card__Panel"));
    }
    
    public Component add(String name, Component comp) {
        boolean isFront =
	    (currentCard != null && cards.get(currentCard) == comp);
        
        super.add(name, comp);
        
        if (isFront) {
            comp.show();
            currentCard = name;
        }
        
        return comp;
    }
    
    public void addTab(String name) {
        tabs.addElement(name);
    }
    
    public void addTab(String name, int index) {
        tabs.insertElementAt(name, index);
    }
    
    public String getTab(int index) {
        int size = tabs.size();
        if (index >= 0 && index < size)
            return (String)tabs.elementAt(index);
        else
            return null;
    }
    
    public int getTabIndex(String name) {
        return tabs.indexOf(name);
    }
    
    public void removeTab(String name) {
        tabs.removeElement(name);
        removeCard(name);
    }
    
    public void renameTab(String oldName, String newName) {
        int index = tabs.indexOf(oldName);
        if (index != -1) {
            tabs.removeElementAt(index);
            tabs.insertElementAt(newName, index);
            renameCard(oldName, newName);
        }
    }
    
    public void removeAllTabs() {
        tabs.removeAllElements();
        removeAllCards();
    }
    
    public Enumeration tabs() {
        return tabs.elements();
    }
    
    public Component addCard(String name, Component card) {
        if (cardLabel.getParent() == this)
            remove(cardLabel);
        
        if (!tabs.contains(name)) {
	    /* BEGIN JSTYLED */
	    throw new Error(Global.fmtMsg("sunsoft.jws.visual.rt.awt.CardPanel.FMT.0", /* NOI18N */"\r\n",
					  Global.getMsg("sunsoft.jws.visual.rt.awt.CardPanel.________There__is__no__tab__.0"), name, /* NOI18N */"\".\r\n",
					  Global.getMsg("sunsoft.jws.visual.rt.awt.CardPanel.________You__must__call__ad.1")));
	    /* END JSTYLED */
        }
        
        cards.put(name, card);
        
        // The first card that is added will be shown by the cardLayout,
        // and thusly it must become the currentCard.
        if (currentCard == null) {
            currentCard = name;
            postEvent(new Event(this, CURRENTCARD, name));
        }
        
        return add(name, card);
    }
    
    public Component getCard(String name) {
        return (Component)cards.get(name);
    }
    
    public String getCardName(Component comp) {
        Enumeration e = cards.keys();
        while (e.hasMoreElements()) {
            String key = (String)e.nextElement();
            if (cards.get(key) == comp)
                return key;
        }
        
        return null;
    }
    
    // Call renameTab to rename the card
    private void renameCard(String oldName, String newName) {
        Component comp = (Component)cards.get(oldName);
        
        if (comp != null) {
            cards.remove(oldName);
            cards.put(newName, comp);
            
            remove(comp);
            add(newName, comp);
            
            if (oldName.equals(currentCard)) {
                currentCard = newName;
                comp.show();
            }
        }
    }
    
    // Call removeTab to remove the card
    private void removeCard(String name) {
        if (name.equals(currentCard))
            currentCard = null;
        
        Component comp = (Component)cards.get(name);
        if (comp != null) {
            cards.remove(name);
            remove(comp);
        }
        
        if (cardLabel.getParent() != this &&
	    countComponents() == 0)
	    add(cardLabel, /* NOI18N */"foobar");
        // JDK1.1 requires a constraint
    }
    
    // Call removeAllTabs to remove all the cards
    private void removeAllCards() {
        cards.clear();
        
        if (cardLabel.getParent() != this)
            add(cardLabel, /* NOI18N */"foobar");
    }
    
    public String getCurrentCard() {
        return currentCard;
    }
    
    public void show(String name) {
        if (cards.get(name) == null) {
            postEvent(new Event(this, FETCHCARD, name));
        }
        
        if (cards.get(name) != null) {
            currentCard = name;
            cardLayout.show(this, name);
            postEvent(new Event(this, CURRENTCARD, name));
        }
    }
    
    public void first() {
        if (tabs.size() > 0)
            show((String)tabs.elementAt(0));
    }
    
    public void next() {
        int index = frontIndex();
        if (tabs.size() > (index+1))
            show((String)tabs.elementAt(index+1));
    }
    
    void previous() {
        int index = frontIndex();
        if (tabs.size() > 0 && (index-1) >= 0)
            show((String)tabs.elementAt(index-1));
    }
    
    public void last() {
        int index = tabs.size()-1;
        if (index >= 0)
            show((String)tabs.elementAt(index));
    }
    
    private int frontIndex() {
        if (currentCard == null)
            return -1;
        else
            return tabs.indexOf(currentCard);
    }
}
