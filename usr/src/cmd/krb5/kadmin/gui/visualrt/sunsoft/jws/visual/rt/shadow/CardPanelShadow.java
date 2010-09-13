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
 * @(#) CardPanelShadow.java 1.33 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.awt.*;
import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.shadow.java.awt.*;

import java.awt.*;
import java.util.*;

/**
 * CardPanelShadow - Panel with card layout.
 * The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre >
name            type                      default value
-----------------------------------------------------------------------
cards           [Lrt.shadow.GBPanelShadow initial label
delayedCreation java.lang.Boolean         true
currentCard     java.lang.String          null
*  < /pre>
*
* Check the super class for additional attributes. < p>
*
* The "delayedCreation" attribute delays the creation of cards until
* after they are shown.  This is good for performance.  But it is bad
* because the initial size of the card panel will be determined by the
* first card, and not by the largest card in the panel.  So if
* "delayedCreation" is set to true, you need to make sure that the
* initial card is bigger than all the other cards.
*
* @see CardLayout
* @version 	1.33, 07/25/97
*/
public class CardPanelShadow extends VJPanelShadow {
    
    protected CardPanel cardPanel;
    private GBPanelShadow cards[];
    
    // Layout mode stuff
    private boolean inDesignerRoot;
    private Choice cardMenu;
    private GBLayout gridbag;
    private GBConstraints cardMenuConstraints;
    
    public CardPanelShadow() {
        attributes.add(/* NOI18N */"cards",
	       /* NOI18N */"[Lsunsoft.jws.visual.rt.shadow.GBPanelShadow;",
		       null, DEFAULT | TRANSIENT);
        attributes.add(/* NOI18N */"delayedCreation",
		       /* NOI18N */"java.lang.Boolean", Boolean.FALSE, 0);
        attributes.add(/* NOI18N */"currentCard",
		       /* NOI18N */"java.lang.String", null,
		       HIDDEN | TRANSIENT);
    }
    
    //
    // Public methods
    //
    
    public void show(String name) {
        set(/* NOI18N */"currentCard", name);
    }
    
    public GBPanelShadow getCard(String name) {
        GBPanelShadow cards[] = getCards();
        String str;
        
        for (int i = 0; i < cards.length; i++) {
            str = (String)cards[i].get(/* NOI18N */"layoutName");
            if (str != null && str.equals(name))
                return cards[i];
        }
        
        return null;
    }
    
    //
    // Attributes
    //
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"cards")) {
            return getCards();
        } else if (key.equals(/* NOI18N */"delayedCreation")) {
            return getFromTable(key);
        } else if (key.equals(/* NOI18N */"currentCard")) {
            return cardPanel.getCurrentCard();
        } else {
            return super.getOnBody(key);
        }
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"cards")) {
            setCards((GBPanelShadow[])value);
        } else if (key.equals(/* NOI18N */"delayedCreation")) {
            putInTable(key, value);
            if (!((Boolean)value).booleanValue())
                create();
        } else if (key.equals(/* NOI18N */"currentCard")) {
            if (value != null)
                cardPanel.show((String)value);
        } else {
            super.setOnBody(key, value);
        }
    }
    
    public void updateContainerAttribute(AttributeManager child,
					 String key, Object value) {
        if (!key.equals(/* NOI18N */"layoutName"))
            return;
        
        GBPanelShadow cards[] = getCards();
        int i;
        for (i = 0; i < cards.length; i++) {
            if (cards[i] == child)
                break;
        }
        
        String name = (String)value;
        if (name == null)
            name = /* NOI18N */"null";
        
        if (cardPanel != null) {
            Component comp = (Component)((Shadow)child).getBody();
            if (comp != null)
                cardPanel.renameTab(cardPanel.getCardName(comp), name);
            else
                cardPanel.renameTab(cardPanel.getTab(i), name);
        }
    }
    
    //
    // Private methods
    //
    
    private void createCard(String name) {
        GBPanelShadow card = getCard(name);
        if (card != null) {
            if (!card.isCreated()) {
                Group base = null;
                Group g = getGroup();
                if (g != null)
                    base = g.getBase();
                
                if (base != null)
                    base.setCursor(Frame.WAIT_CURSOR);
                card.create();
                if (base != null)
                    base.setCursor(Group.RESTORE_CURSOR);
            }
        }
    }
    
    private void updateCards() {
        GBPanelShadow cards[] = getCards();
        Component comp;
        
        for (int i = 0; i < cards.length; i++) {
            comp = (Component)cards[i].getBody();
            
            boolean shadowVisible =
		/* JSTYLED */
		((Boolean)cards[i].get(/* NOI18N */"visible")).booleanValue();
            boolean compVisible =
		(comp == null) ? false : comp.isVisible();
            
            
            if (shadowVisible != compVisible) {
                // Update the card in the option menu
                if (compVisible && cardMenu != null)
                    cardMenu.select(i);
                
                cards[i].set(/* NOI18N */"visible",
			     new Boolean(compVisible));
            }
        }
    }
    
    protected synchronized GBPanelShadow[] getCards() {
        if (cards == null) {
            int i = 0;
            cards = new GBPanelShadow[getChildCount()];
            
            Enumeration e = getChildList();
            while (e.hasMoreElements())
                cards[i++] = (GBPanelShadow)e.nextElement();
        }
        
        return cards;
    }
    
    protected void setCards(GBPanelShadow cards[]) {
        boolean showFirst = false;
        GBPanelShadow currentCard = getCard(cardPanel.getCurrentCard());
        
        // Remove all cards, and destroy cards that are no longer used.
        Enumeration e = getChildList();
        while (e.hasMoreElements()) {
            GBPanelShadow s = (GBPanelShadow)e.nextElement();
            
            remove(s);
            
            if (cards == null) {
                if (s == currentCard)
                    showFirst = true;
                s.destroy();
            } else {
                int i;
                for (i = 0; i < cards.length; i++) {
                    if (cards[i] == s)
                        break;
                }
                if (i == cards.length) {
                    if (s == currentCard)
                        showFirst = true;
                    s.destroy();
                }
            }
        }
        
        if (cards != null) {
            boolean createFirst = true;
            
            for (int i = 0; i < cards.length; i++) {
                if (cards[i].getParent() != this) {
                    // All new cards start out non-visible
                    cards[i].set(/* NOI18N */"visible", Boolean.FALSE);
                    add(cards[i]);
                    
                    // Make sure the card is created if we
                    // are not delaying creation.
                    if (!isDelayed()) {
                        cards[i].create();
                    }
                } else if (cards[i] == currentCard) {
                    createFirst = false;
                }
            }
            
            if (createFirst && cards.length > 0 && isDelayed()) {
                cards[0].create();
            }
        }
        
        this.cards = cards;
        
        if (showFirst && cards.length > 0) {
            cardPanel.show(
		(String)cards[0].get(/* NOI18N */"layoutName"));
        }
        
        resetChoice();
    }
    
    private boolean isDelayed() {
        return (
	    (Boolean)get(/* NOI18N */"delayedCreation")).booleanValue();
    }
    
    private void resetChoice() {
        if (inDesignerRoot) {
            GBPanelShadow cards[] = getCards();
            Panel panel = (Panel)body;
            
            if (cardMenu != null) {
                panel.remove(cardMenu);
                cardMenu.removeNotify();
                cardMenu = null;
            }
            
            if (cards != null && cards.length != 0) {
                cardMenu = new Choice();
                
                for (int i = 0; i < cards.length; i++)
                    cardMenu.addItem(
			(String)cards[i].get(/* NOI18N */"layoutName"));
                
                gridbag.setConstraints(((Panel)body).add(cardMenu),
				       cardMenuConstraints);
                
                String current = cardPanel.getCurrentCard();
                if (current != null)
                    cardMenu.select(current);
            }
        }
    }
    
    public void add(AttributeManager child) {
        if (cardPanel != null)
            cardPanel.addTab(
		(String)child.get(/* NOI18N */"layoutName"));
        cards = null;
        
        super.add(child);
    }
    
    public void remove(AttributeManager child) {
        if (cardPanel != null)
            cardPanel.removeTab(
		(String)child.get(/* NOI18N */"layoutName"));
        cards = null;
        
        super.remove(child);
    }
    
    public void addChildBody(Shadow child) {
        if (body != null) {
            cardPanel.addCard(
		(String)child.get(/* NOI18N */"layoutName"),
		(Component)child.getBody());
            updateContainerAttributes((AMContainer)this, child);
        }
    }
    
    public void removeChildBody(Shadow child) {
        if (body != null) {
            // Cause the card to be removed, but not the tab
            //  (if the tab is still there).
            String name = (String)child.get(/* NOI18N */"layoutName");
            int index = cardPanel.getTabIndex(name);
            if (index != -1) {
                cardPanel.removeTab(name);
                cardPanel.addTab(name, index);
            }
        }
    }
    
    public void createChildren() {
        if (isDelayed()) {
            super.createChildren();
        } else {
            // Force creation of all the children
            Enumeration e = getChildList();
            while (e.hasMoreElements()) {
                AttributeManager mgr =
		    (AttributeManager) e.nextElement();
                mgr.create();
            }
        }
    }
    
    public void createBody() {
        inDesignerRoot = inDesignerRoot();
        
        if (inDesignerRoot) {
            gridbag = new GBLayout();
            GBConstraints c = new GBConstraints();
            
            VJPanel panel = new VJPanel();
            panel.setLayout(gridbag);
            
            c.insets = new Insets(2, 2, 3, 5);
            c.gridx = 0;
            c.gridy = 0;
            cardMenuConstraints = (GBConstraints)c.clone();
            
            cardPanel = new CardPanel();
            c.insets = new Insets(2, 2, 2, 2);
            c.gridx = 0;
            c.gridy = 1;
            c.weightx = 1;
            c.weighty = 1;
            c.fill = GBConstraints.BOTH;
            gridbag.setConstraints(panel.add(cardPanel), c);
            
            body = panel;
        } else {
            cardPanel = new CardPanel();
            body = cardPanel;
        }
    }
    
    public CardPanel getCardPanel() {
        return cardPanel;
    }
    
    protected void registerBody() {
        GBPanelShadow cards[] = getCards();
        for (int i = 0; i < cards.length; i++) {
            cardPanel.addTab(
		(String)cards[i].get(/* NOI18N */"layoutName"));
        }
        
        super.registerBody();
    }
    
    protected void postCreate() {
        super.postCreate();
        
        if (inDesignerRoot)
            resetChoice();
    }
    
    protected void destroyBody() {
        super.destroyBody();
        cardPanel = null;
        cardMenu = null;
    }
    
    //
    // Layout and preview modes
    //
    
    public void layoutMode() {
        super.layoutMode();
        
        if (inDesignerRoot) {
            VJPanel panel = (VJPanel)body;
            
            if (cardMenu != null)
                cardMenu.show();
            
            GBConstraints c = gridbag.getConstraints(cardPanel);
            c.insets = new Insets(2, 2, 2, 2);
            gridbag.setConstraints(cardPanel, c);
        }
    }
    
    public void previewMode() {
        super.previewMode();
        
        if (inDesignerRoot) {
            if (cardMenu != null)
                cardMenu.hide();
            
            GBConstraints c = gridbag.getConstraints(cardPanel);
            c.insets = null;
            gridbag.setConstraints(cardPanel, c);
        }
    }
    
    //
    // Events
    //
    
    public boolean handleEvent(Message msg, Event evt) {
        if (evt.target == cardPanel) {
            if (evt.id == CardPanel.CURRENTCARD) {
                updateCards();
            } else if (evt.id == CardPanel.FETCHCARD) {
                if (isDelayed())
                    createCard((String)evt.arg);
            }
        }
        
        return super.handleEvent(msg, evt);
    }
    
    public boolean action(Message msg, Event evt, Object what) {
        if (cardMenu != null && msg.target == cardMenu) {
            cardPanel.show((String)what);
        }
        
        return false;
    }
}
