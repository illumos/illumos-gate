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
 * Copyright 2002 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.ui;

import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.*;
import javax.swing.event.*;
import java.util.ArrayList;
import java.util.Arrays;

/*
 * This class is a hack to get around the fact that clearSelection()
 * in DefaultListSelectionModel does not always fire an event to its listeners.
 * We rely on such an event to enable & disable the arrow buttons which
 * move data items between lists.  See bug 4177723.
 */
class FixedSelectionModel extends DefaultListSelectionModel {
    public void clearSelection() {
	super.clearSelection();
	fireValueChanged(getMinSelectionIndex(), getMaxSelectionIndex(), false);
    }
}

/*
 * We implement our own list model rather than use the default so
 * that we can take advantage of some of the more advanced collection
 * features not supported by DefaultListModel
 */
class OurListModel implements ListModel {
    ArrayList data = new ArrayList();
    EventListenerList listenerList = new EventListenerList();

    public OurListModel(Object [] data) {
	if (data != null) {
	    this.data.addAll(Arrays.asList(data));
	}
    }

    public void addListDataListener(ListDataListener l) {
	listenerList.add(ListDataListener.class, l);
    }

    public void removeListDataListener(ListDataListener l) {
	listenerList.remove(ListDataListener.class, l);
    }

    protected void fireContentsChanged() {
	ListDataEvent e =
	    new ListDataEvent(this, ListDataEvent.CONTENTS_CHANGED,
	    0, getSize());
	Object [] listeners = listenerList.getListenerList();
	/*
	 * Listener array is formatted as pairs of (class, listener); walk
	 * the array backwards and call each ListDataListener in turn with
	 * the event.  See javax.swing.event.EventListenerList for more info.
	 */
	for (int i = listeners.length - 2; i >= 0; i -= 2) {
	    if (listeners[i] == ListDataListener.class) {
		((ListDataListener)listeners[i+1]).contentsChanged(e);
	    }
	}
    }

    public Object getElementAt(int index) {
	return data.get(index);
    }

    public int getSize() {
	return data.size();
    }

    public void addElement(Object o) {
	data.add(o);
	fireContentsChanged();
    }

    public void removeElement(Object o) {
	data.remove(data.indexOf(o));
	fireContentsChanged();
    }

    public Object [] toArray(Object [] arr) {
	return data.toArray(arr);
    }
}

/*
 * Our own layout manager which keeps the left & right lists the same size.
 */
class ListPairLayout implements LayoutManager {
    Component leftComponent, centerComponent, rightComponent;
    public static final String LEFT = "left";
    public static final String CENTER = "center";
    public static final String RIGHT = "right";

    public ListPairLayout() {
	leftComponent = centerComponent = rightComponent = null;
    }

    public void addLayoutComponent(String name, Component comp) {
	if (name.equals(LEFT)) {
	    leftComponent = comp;
	} else if (name.equals(CENTER)) {
	    centerComponent = comp;
	} else if (name.equals(RIGHT)) {
	    rightComponent = comp;
	}
    }

    public void layoutContainer(Container target) {
	// Make left & right components same size, center no smaller than min
	Insets insets = target.getInsets();
	Dimension dim = target.getSize();
	int x = insets.left;
	int y = insets.top;
	int totalHeight = dim.height - insets.bottom;
	int totalWidth = dim.width - insets.right;

	// If preferred sizes don't fit, go to minimum.
	Dimension cDim = centerComponent.getPreferredSize();
	Dimension d = preferredLayoutSize(target);
	if (d.width > totalWidth || d.height > totalHeight) {
	    cDim = centerComponent.getMinimumSize();
	}

	// Left & right each get half of what's left after center allocated
	int lrWidth = (totalWidth - cDim.width) / 2;

	// Now place each component
	leftComponent.setBounds(x, y, lrWidth, totalHeight);
	centerComponent.setBounds(x + lrWidth, y, cDim.width, totalHeight);
	rightComponent.setBounds(x + lrWidth + cDim.width, y, lrWidth,
	    totalHeight);
    }

    public Dimension minimumLayoutSize(Container parent) {
	Dimension retDim = new Dimension();
	// Compute minimum width as max(leftwidth, rightwidth) * 2 + centerwidth
	int lrwidth = Math.max(leftComponent.getMinimumSize().width,
	    rightComponent.getMinimumSize().width);
	retDim.width = lrwidth * 2 + centerComponent.getMinimumSize().width;
	// Compute minimum height as max(leftheight, rightheight, centerheight)
	int lrheight = Math.max(leftComponent.getMinimumSize().height,
	    rightComponent.getMinimumSize().height);
	retDim.height = Math.max(centerComponent.getMinimumSize().height,
	    lrheight);
	return retDim;
    }

    public Dimension preferredLayoutSize(Container parent) {
	Dimension retDim = new Dimension();
	// Preferred width is max(leftwidth, rightwidth) * 2 + centerwidth
	int lrwidth = Math.max(leftComponent.getPreferredSize().width,
	    rightComponent.getPreferredSize().width);
	retDim.width = lrwidth * 2 + centerComponent.getPreferredSize().width;
	// Preferred height is max(leftheight, rightheight, centerheight)
	int lrheight = Math.max(leftComponent.getPreferredSize().height,
	    rightComponent.getPreferredSize().height);
	retDim.height = Math.max(centerComponent.getPreferredSize().height,
	    lrheight);
	return retDim;
    }

    public void removeLayoutComponent(Component comp) {
	// Do nothing
    }
}

/**
 * A ListPair provides a way to display two lists of objects and to move
 * objects from one list to another.  It is initialized with the contents
 * of each list, and can be queried at any time for the contents of each list
 */
public class ListPair extends JPanel {
    private JList leftList, rightList;
    private OurListModel leftModel, rightModel;
    private ListSelectionModel leftSelectionModel, rightSelectionModel;
    private LeftButton leftButton = new LeftButton();
    private RightButton rightButton = new RightButton();
    private JScrollPane leftPane, rightPane;

    /**
     * Construct a ListPair with the specified data and captions for each list
     * @param leftCaption Caption for left list
     * @param leftData An array of objects to display in the left list
     * @param rightCaption Caption for right list
     * @param rightData An array of objects to display in the right list
     */
    public ListPair(String leftCaption, Object [] leftData, String rightCaption,
	    Object [] rightData) {

	// Use our custom layout manager
	setLayout(new ListPairLayout());

	// Store data into the list models
	leftModel = new OurListModel(leftData);
	rightModel = new OurListModel(rightData);

	// Now create the lists
	leftList = new JList(leftModel);
	rightList = new JList(rightModel);
	leftList.setSelectionModel(new FixedSelectionModel());
	rightList.setSelectionModel(new FixedSelectionModel());

	// Now do the layout
	JPanel leftPanel = new JPanel(new BorderLayout());

	JLabel leftCapLbl = new JLabel(leftCaption);
	leftCapLbl.setLabelFor(leftPanel);
	leftCapLbl.setToolTipText(leftCaption);
	leftPanel.add(leftCapLbl, BorderLayout.NORTH);

	leftPane = new JScrollPane(leftList);
	leftPanel.add(leftPane, BorderLayout.CENTER);
	add(leftPanel, ListPairLayout.LEFT);

	JPanel centerPanel = new JPanel(new VerticalButtonLayout());
	rightButton.setEnabled(false);
	leftButton.setEnabled(false);
	centerPanel.add(rightButton);
	centerPanel.add(leftButton);
	add(centerPanel, ListPairLayout.CENTER);

	JPanel rightPanel = new JPanel(new BorderLayout());

        JLabel rightCapLbl = new JLabel(rightCaption);
        rightCapLbl.setLabelFor(rightPanel);
        rightCapLbl.setToolTipText(rightCaption);
        rightPanel.add(rightCapLbl, BorderLayout.NORTH);

	rightPane = new JScrollPane(rightList);
	rightPanel.add(rightPane, BorderLayout.CENTER);
	add(rightPanel, ListPairLayout.RIGHT);

	// Now create and hook up the listeners for selection state
	leftSelectionModel = leftList.getSelectionModel();
	leftSelectionModel.addListSelectionListener(
		new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
	    	// Ignore if user is dragging selection state
	    	if (e.getValueIsAdjusting()) {
		    return;
	        }
		// Right enabled only if something is selected in left list
		rightButton.setEnabled(!leftSelectionModel.isSelectionEmpty());
		if (!leftSelectionModel.isSelectionEmpty()) {
		    rightSelectionModel.clearSelection();
		}
	    }
	});

	rightSelectionModel = rightList.getSelectionModel();
	rightSelectionModel.addListSelectionListener(
		new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
		// Ignore if user is dragging selection state
		if (e.getValueIsAdjusting()) {
		    return;
		}
		// Left enabled only if something is selected in the right list
		leftButton.setEnabled(!rightSelectionModel.isSelectionEmpty());
		if (!rightSelectionModel.isSelectionEmpty()) {
		    leftSelectionModel.clearSelection();
		}
	    }
	});

	// Now add listeners to buttons to move data between lists
	rightButton.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		Object [] values = leftList.getSelectedValues();
		for (int i = 0; i < values.length; ++i) {
		    rightModel.addElement(values[i]);
		    leftModel.removeElement(values[i]);
		}
		/*
		 * Clear the selection state; this shouldn't be necessary,
		 * but the selection and data models are unfortunately not
		 * hooked up to handle this automatically
		 */
		leftSelectionModel.clearSelection();
	    }
	});

	leftButton.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		Object [] values = rightList.getSelectedValues();
		for (int i = 0; i < values.length; ++i) {
		    leftModel.addElement(values[i]);
		    rightModel.removeElement(values[i]);
		}
		/*
		 * Clear the selection state; this shouldn't be necessary,
		 * but the selection and data models are unfortunately not
		 * hooked up to handle this automatically
		 */
		rightSelectionModel.clearSelection();
	    }
	});
    }

    /**
     * Retrieve the contents of the left list
     * @return the contents as an array of Object
     */
    public Object [] getLeftContents(Object [] arr) {
	return leftModel.toArray(arr);
    }

    /**
     * Retrieve the contents of the right list
     * @return the contents as an array of Object
     */
    public Object [] getRightContents(Object [] arr) {
	return rightModel.toArray(arr);
    }
}
