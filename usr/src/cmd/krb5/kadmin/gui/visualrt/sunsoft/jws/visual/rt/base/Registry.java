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
 * @(#) Registry.java 1.9 - last change made 07/16/97
 */

package sunsoft.jws.visual.rt.base;

import java.util.Vector;

/**
 * The event registry
 *
 * @version 	1.9, 07/16/97
 */
public class Registry implements Runnable {
    
    private static final char STAR = /* NOI18N */ '*';
    
    /**
     * Constructor.
     */
    public Registry() {
        // Initialize publisher records
        num_pubs =  0;
        pubs =  new RegistryEntry[0];
        
        // Initialize subscriber records
        num_subs =  0;
        sub_events =  new Message[0];
        sub_objects =  new AttributeManager[0];
        
        // The thread
        publish_thread = null;
        queue = new Vector(1);
    }
    
    // Data Members
    private int num_pubs;
    private RegistryEntry pubs[];
    private int num_subs;
    private Message sub_events[];
    private AttributeManager sub_objects[];
    private Thread publish_thread;
    private Vector queue;
    
    
    /**
     * Subscribe to events using the supplied Message as a
     * template for
     * requested events.  <br>
     * Only 'name', 'type' and 'targetName' can be set on the
     * template event.
     * (all other fields should be null, zero or false as
     * appropriate).
     * The strings are compared for equality.  If the last
     * character of the
     * string is '*', then all strings beginning with the
     * rest of the string
     * are considered to be matching. <br>
     * <b>Note:</b> the callback object should be written to
     *  handle callbacks
     * on multiple threads.
     */
    public synchronized int subscribe(Message msg,
				      AttributeManager obj) {
        // Check for bad params
        if ((obj == null) || (msg == null))
            return -1;
        
        // Look for empty subscription ID
        int i;
        for (i = 0; i < sub_events.length; ++i) {
            if (sub_events[i] == null) {
                // Found it
                break;
            }
        }
        if (i >= sub_events.length) {
            // None found, so grow the arrays
            Message new_events[] = new Message[sub_events.length + 5];
            AttributeManager new_objects[] = new AttributeManager[
		                            sub_events.length +5];
            
            System.arraycopy(sub_events, 0, new_events, 0, sub_events.length);
            System.arraycopy(sub_objects, 0, new_objects, 0, sub_events.length);
            
            sub_events = new_events;
            sub_objects = new_objects;
        }
        
        // Add the entry
        sub_events[i] = new Message(msg);
        sub_objects[i] = obj;
        
        return i;
    }
    
    /**
     * Cancel a subscription.The 'id' is the value returned from the
     * subscribe call.
     */
    public synchronized void unsubscribe(int id) {
        if ((id < 0) || (id >= sub_events.length))
            return;
        sub_events[id] = null;
        sub_objects[id] = null;
    }
    
    /**
     * Send an event via the registry to all subscribers.
     */
    public synchronized void publish(Message msg) {
        if (publish_thread == null) {
            publish_thread = new Thread(this);
            publish_thread.setDaemon(true);
            publish_thread.start();
        }
        
        queue.addElement(msg);
        notify();
    }
    
    /**
     * The actual run method
     */
    public void run()
    {
        Message msg =  null;
        
        while (true) {
            synchronized (this) {
                if (queue.size() == 0) {
                    try {
                        wait();
                    } catch (Exception ex) {
                    }
                }
                if (queue.size() != 0) {
                    msg = (Message)queue.firstElement();
                    queue.removeElementAt(0);
                } else {
                    msg = null;
                }
            }
            if (msg != null) {
                // Look for matching subscriptions
                for (int i = 0; i < sub_events.length; ++i) {
                    // Match events code is here
                    if ((sub_events[i] != null) &&
			matchString(sub_events[i].name, msg.name) &&
			matchString(sub_events[i].type, msg.type) &&
			matchString(sub_events[i].targetName,
				    msg.targetName)) {
                        // Call the object
                        sub_objects[i].postMessage(msg);
                    }
                }
            }
        }
    }
    
    /**
     * Compare strings.  A filter value of 'null' matches anything.
     * A filter
     * string ending in '*' matches any string beginning with
     * the filter's
     * string.
     */
    private boolean matchString(String filter, String actual) {
        if ((filter == null) || (filter.equals(actual)))
            return true;
        try {
            if (filter.charAt(filter.length()-1) == STAR) {
                if ((actual != null) &&
		    (actual.startsWith(filter.substring(0, filter.length()-1))))
		    {
			return true;
		    }
            }
        } catch (java.lang.Exception ex) { /* do nothing */ }
        return false;
    }
    
    /**
     * Register a publisher with the registry. 
     * This is not necessary in order
     * to actually publish.  It is just used to advertise
     * yourself in the
     * publishers list.
     */
    public synchronized void register(String publisher_name,
				      String description,
				      Object obj) {
        // Check for illegal params
        if (publisher_name == null)
            return;
        
        // Look for empty publication entry
        int i;
        for (i = 0; i < pubs.length; ++i) {
            if (pubs[i] == null) {
                // Found it
                break;
            }
        }
        if (i >= pubs.length) {
            // None found, so grow the array
            RegistryEntry new_pubs[] = new RegistryEntry[pubs.length + 5];
            
            System.arraycopy(pubs, 0, new_pubs, 0, pubs.length);
            
            pubs = new_pubs;
        }
        
        // Add the entry
        pubs[i] = new RegistryEntry(publisher_name, description, obj);
    }
    
    /**
     * Unregister a publisher.
     */
    public synchronized void unregister(String publisher_name) {
        // Look for the entry
        for (int i = 0; i < pubs.length; ++i) {
            if ((pubs[i] != null) && (publisher_name.equals(pubs[i].name)))
		{
		    // Found it
		    pubs[i] = null;
		}
        }
    }
    
    /**
     * Get the list of registered publishers.
     */
    public synchronized RegistryEntry[] getPublishers() {
        // First count the entries
        int count = 0;
        for (int i = 0; i < pubs.length; ++i) {
            if (pubs[i] != null) ++count;
        }
        
        // Then copy them
        RegistryEntry rc[] = new RegistryEntry[count];
        count = 0;
        for (int i = 0; i < pubs.length; ++i) {
            if (pubs[i] != null) {
                rc[count] = new RegistryEntry(pubs[i]);
                ++count;
            }
        }
        return rc;
    }
}
