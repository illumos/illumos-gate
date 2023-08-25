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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.domain.pools;

import java.io.*;
import java.util.*;
import java.text.SimpleDateFormat;

import com.sun.solaris.service.logging.*;
import com.sun.solaris.service.pools.*;

/**
 * This class maintains history about previous decisions.  It can be
 * used to ratify that a decision made on the basis of observed behavior
 * over a limited time was historically shown to not degrade
 * performance.  The class maintains historical data in a history file.
 * The format of this data is project-private and very likely to change
 * as the implementation improves.
 */
public final class DecisionHistory implements Serializable {
	/**
	 * The number of samples which a decision will be remembered.
	 */
	public static final int DECISION_LIFETIME = 256;

	/**
	 * Map of values of historical decisions.
	 */
	private HashMap decisions = new HashMap();

	/**
	 * Map of resources to be monitored for improvement in
	 * utilization to the corresponding decision.  Maps Resources to
	 * their decision's key string.
	 */
	private transient HashMap resourcesAwaitingImprovement = new HashMap();

	/**
	 * List of decisions, in order of creation, to manage expiry.
	 */
	private transient LinkedList decisionList = new LinkedList();

	/**
	 * Constructor.
	 */
	public DecisionHistory()
	{
	}

	/**
	 * Record a decision that's been made regarding a processor.
	 * Such a decision is a (cpuid, from-pset-name, to-pset-name,
	 * (from-pset-composition), (to-pset-composition),
	 * original-utilization-class) tuple.
	 */
	public void recordProcessorMove(ComponentMove move,
	    double startingUtilization, int sampleCount) throws PoolsException
	{
		Decision decision = Decision.forMove(move, startingUtilization);
		decision.setStartingSampleCount(sampleCount);
		Object o = decisions.put(decision.getKey(), decision);
		Poold.OPT_LOG.log(Severity.DEBUG, "recorded decision (" +
		    decision + ")" + (o == null ? "" : " (displaced " + o +
		    ")"));

		/*
		 * Remember the most-recently-made decision regarding a
		 * resource until the next utilization sample is taken,
		 * so the next solve() may then reocrd the improvement.
		 * If another decision is made regarding this resource,
		 * the previous ones are forgotten, and their
		 * improvement fields are left 0.
		 */
		resourcesAwaitingImprovement.put(move.getTo(),
		    decision.getKey());
		decisionList.add(decision);
	}

	private void recordImprovementWithUtilization(Resource resource,
	    double utilization)
	{
		String decisionKey = (String)resourcesAwaitingImprovement.get(
		    resource);

		if (decisionKey != null) {
			Decision decision = (Decision)decisions.get(
			    decisionKey);
			if (decision != null) {
				decision.setImprovementWithNewUtilization(
				    utilization);
				Poold.OPT_LOG.log(Severity.DEBUG, resource +
				    " improvement measured for decision " +
				    decision.describe());
			}
		}
	}

	/**
	 * A Decision boils down to a tuple describing the resource
	 * configuration involved before and after a particular resource
	 * is moved.  We use a textual representation to describe the
	 * decision, by value, to avoid holding references to any of the
	 * actual resources involved.
	 */
	private static abstract class Decision implements Serializable {
		/**
		 * Utilization of the resource before the move was made.
		 */
		private double startingUtilization = 0.0;

		/**
		 * Improvement in utilization (-1..1) after the move was
		 * made, if the determination is made.
		 */
		private double improvement = 0.0;

		/**
		 * Number of times this decision has been reexamined.
		 */
		private int usage = 0;

		/**
		 * Monitor's sample count when the decision was made,
		 * used to expire this decision after DECISION_LIFETIME
		 * samples.
		 */
		private int startingSampleCount;

		/**
		 * Decision's creation time.
		 */
		private Date date;

		/**
		 * Returns a String key for this Decision.
		 */
		public abstract String getKey();

		/**
		 * Returns a Decision corresponding to a given Move.
		 * @return a Decision corresponding to a given Move.
		 * @throws InvalidArgumentException if there is no
		 * Decision type corresponding to the move.
		 */
		public static final Decision forMove(Move move,
		    double startingUtilization)
		{
			if (move instanceof ComponentMove)
				return (new ComponentMoveDecision(
				    (ComponentMove)move, startingUtilization));
			else
				return (null);
		}

		private Decision()
		{
			date = new Date();
		}

		/**
		 * Invoked after construction, sets the utilization
		 * corresponding to the affected resource before the move
		 * was made.
		 */
		public final void setStartingUtilization(
		    double startingUtilization)
		{
			this.startingUtilization = startingUtilization;
		}

		/**
		 * Invoked after construction, sets the sampleCount from
		 * the monitor, used to expire this decision after
		 * DECISION_LIFETIME samples.
		 */
		public void setStartingSampleCount(int sampleCount)
		{
			this.startingSampleCount = sampleCount;
		}

		/**
		 * sampleCount accessor.
		 */
		public int getStartingSampleCount()
		{
			return (startingSampleCount);
		}

		/**
		 * Stores the improvement, computed in a
		 * subclass-specific way.
		 */
		abstract public void setImprovementWithNewUtilization(
		    double newUtilization);

		/**
		 * Allow subclasses to record the improvement.
		 */
		protected void setImprovement(double improvement)
		{
			this.improvement = improvement;
		}

		/**
		 * Returns the improvement in utilization measured by
		 * the monitor after the move is made.
		 */
		public final double getImprovement()
		{
			return (improvement);
		}

		/**
		 * Returns the utilization corresponding to the affected
		 * resource before the move was made.
		 */
		public final double getStartingUtilization()
		{
			return (startingUtilization);
		}

		public abstract int hashCode();
		public abstract boolean equals(Object o);
		public abstract String toString();

		private static final long serialVersionUID = 0x7860687;

		/**
		 * Number of times this decision has been reexamined.
		 */
		public final int getUsage()
		{
			return (usage);
		}

		private final void incrementUsage()
		{
			usage++;
		}

		/**
		 * Returns the time this decision was created.
		 */
		public final Date getDate()
		{
			return date;
		}

		/**
		 * Formatter for printing creation date.
		 */
		private static SimpleDateFormat dateFormatter;

		/**
		 * Format for printing creation date.
		 */
		private final static String dateFormat = "MMM d kk:mm:ss";

		/**
		 * Returns a more comprehensive textual representation
		 * of this devision than toString().
		 */
		public final String describe()
		{
			if (dateFormatter == null)
				dateFormatter = new SimpleDateFormat(
				    dateFormat);
			return (toString() + " made at " +
			    dateFormatter.format(getDate()) +
			    " with improvement " + getImprovement() +
			    " used " + getUsage() + " times");
		}
	}

	/**
	 * A Decision affecting the transfer of one CPU between
	 * processor sets.
	 */
	private static final class ComponentMoveDecision extends Decision {
		/**
		 * The CPU Id of the involved CPU.
		 */
		private String cpuid;

		/**
		 * The name of the donating processor set.
		 */
		private String fromPsetName;

		/**
		 * The name of the receiving processor set.
		 */
		private String toPsetName;

		/**
		 * The string representation of the list of CPU IDs
		 * composing the donating set.
		 */
		private String fromPsetComposition;

		/**
		 * The string representation of the list of CPU IDs
		 * composing the receiving set.
		 */
		private String toPsetComposition;

		/**
		 * The number of CPUs in the receiving set, after the
		 * move is made.
		 */
		private int toPsetSize;

		/**
		 * A Decision-subclass-specific utilization group.
		 */
		private String utilizationClass;

		/**
		 * Constructs a ComponentMoveDecision based on the
		 * ComponentMove.
		 * @throws IllegalArgumentException if the ComponentMove
		 * can't be interpreted.
		 */
		public ComponentMoveDecision(ComponentMove move,
		    double startingUtilization) throws IllegalArgumentException
		{
			try {
				cpuid = move.getComponents().toString();
				fromPsetName = move.getFrom().toString();
				toPsetName = move.getTo().toString();
				fromPsetComposition = move.getFrom()
				    .getComponents(null).toString();
				toPsetComposition = move.getTo()
				    .getComponents(null).toString();
				toPsetSize = move.getTo().getComponents(null)
				    .size();
				utilizationClass = computeUtilizationClass(
				    startingUtilization);
				setStartingUtilization(startingUtilization);
			} catch (PoolsException pe) {
				throw(IllegalArgumentException)(
				    new IllegalArgumentException().initCause(
				    pe));
			}
		}

		public String getKey()
		{
			StringBuffer sb = new StringBuffer();

			sb.append(cpuid);
			sb.append(", ");
			sb.append(fromPsetName);
			sb.append(", ");
			sb.append(toPsetName);

			return (sb.toString());
		}

		public void setImprovementWithNewUtilization(
		    double newUtilization)
		{
			double sizeRatio = (double)(toPsetSize - 1) /
			    toPsetSize;
			double expectedUtilization = sizeRatio *
			    getStartingUtilization();

			Poold.OPT_LOG.log(Severity.DEBUG,
			    "pset improvement calculation expected " +
			    expectedUtilization + ", got " + newUtilization);
			setImprovement(newUtilization - expectedUtilization);
		}

		public int hashCode() {
			return (((((cpuid.hashCode() ^
			    fromPsetName.hashCode()) ^ toPsetName.hashCode()) ^
			    fromPsetComposition.hashCode()) ^
			    toPsetComposition.hashCode()) ^
			    utilizationClass.hashCode());
		}

		public boolean equals(Object o) {
			if (!(o instanceof ComponentMoveDecision))
				return false;
			else {
				ComponentMoveDecision cmd =
				    (ComponentMoveDecision)o;
				return (cpuid.equals(cmd.cpuid) &&
				    fromPsetName.equals(cmd.fromPsetName) &&
				    toPsetName.equals(cmd.toPsetName) &&
				    fromPsetComposition.equals(
				    cmd.fromPsetComposition) &&
				    toPsetComposition.equals(
				    cmd.toPsetComposition) &&
				    utilizationClass.equals(
				    cmd.utilizationClass));
			}
		}

		/**
		 * Returns the group that this decision's utilization
		 * falls into.  Presently, there is only one group, but
		 * ostensibly decisions will later be grouped (e.g.
		 * into control-zone-wide groups).
		 */
		private String computeUtilizationClass(
		    double startingUtilization)
		{
			return "I";
		}

		public String toString()
		{
			StringBuffer sb = new StringBuffer();

			sb.append(cpuid.toString());
			sb.append(", ");
			sb.append(fromPsetName.toString());
			sb.append(", ");
			sb.append(toPsetName.toString());
			sb.append(", ");
			sb.append(fromPsetComposition.toString());
			sb.append(", ");
			sb.append(toPsetComposition.toString());
			sb.append(", ");
			sb.append(utilizationClass.toString());

			return (sb.toString());
		}

		private static final long serialVersionUID = 0xf7860687;
	}

	/**
	 * Vetoes a Move only if there is a prior decision that showed a
	 * degradation in resource utilization.
	 */
	public boolean veto(Move m, double utilization)
	{
		Decision current = Decision.forMove(m, utilization);
		Decision past;

		if (current != null) {
			past = (Decision)decisions.get(current.getKey());
			if (past != null)
				past.incrementUsage();
			if (past != null && past.getImprovement() < 0.0) {
				Poold.OPT_LOG.log(Severity.DEBUG, m +
				    " vetoed by decision " + past.describe());
				return true;
			}
		}

		return false;
	}

	private static final long serialVersionUID = 0xf7860687;

	/**
	 * Synchronize the decision history with the persistent version.
	 */
	public static DecisionHistory loadFromFile(String path)
	    throws IOException, ClassNotFoundException
	{
		return (load(new FileInputStream(path)));
	}

	/**
	 * Synchronize the persistent decision history with the present
	 * history.
	 */
	public void syncToFile(String path) throws IOException
	{
		FileOutputStream fos = new FileOutputStream(path);
		sync(fos);
		fos.close();
	}

	/**
	 * Synchronize the decision history with the persistent version,
	 * from the given stream.
	 */
	public static DecisionHistory load(InputStream is)
	    throws IOException, ClassNotFoundException
	{
		ObjectInputStream ois = new ObjectInputStream(is);

		DecisionHistory dh = (DecisionHistory)ois.readObject();
		return (dh);
	}

	/**
	 * Serialize the persistent decision history to the given
	 * stream.
	 */
	public void sync(OutputStream os) throws IOException
	{
		new ObjectOutputStream(os).writeObject(this);
	}

	public String toString()
	{
		StringBuffer sb = new StringBuffer();

		sb.append(decisions.keySet().size() + " decisions {");
		Iterator it = decisions.keySet().iterator();
		while (it.hasNext()) {
			String dk = (String)it.next();
			Decision d = (Decision)decisions.get(dk);

			sb.append("\t(");
			sb.append(d.describe());
			sb.append(")\n");
		}
		sb.append("}");

		return (sb.toString());
	}

	/**
	 * Measures the improvement in utilization of any resource for
	 * which a decision was recently made.
	 */
	public void expireAndMeasureImprovements(Monitor mon)
	{
		/*
		 * Measure the improvement in resources involved in
		 * recent decisions.
		 */
		if (mon.isValid()) {
			for (Iterator it = resourcesAwaitingImprovement.
			    keySet().iterator(); it.hasNext(); ) {
				Resource res = (Resource)it.next();
				try {
					double utilization = mon.
					    getUtilization(res);
					recordImprovementWithUtilization(res,
					    utilization);
				} catch (StaleMonitorException sme) {
					/*
					 * We can't access the utilization, so
					 * remove the decision.
					 */
					String decisionKey = (String)
					    resourcesAwaitingImprovement.
					    get(res);
					if (decisionKey != null)
						decisions.remove(decisionKey);
				}
				it.remove();
			}
		}

		/*
		 * Expire decisions which have outlived
		 * DECISION_LIFETIME samples.
		 */
		int cutoff = mon.getSampleCount() - DECISION_LIFETIME;
		if (cutoff > 0) {
			Decision decision;
			ListIterator it = decisionList.listIterator(0);
			while (it.hasNext()) {
				decision = (Decision)it.next();
				int sc = decision.getStartingSampleCount();
				if (sc < cutoff) {
					if (sc > 0) {
						Poold.OPT_LOG.log(
						    Severity.DEBUG,
						    "expiring decision (" +
						    decision + ")");
						it.remove();
						decisions.remove(
						    decision.getKey());
					}
				} else
					break;
			}
		}
	}

	private void readObject(ObjectInputStream s)
	    throws IOException, ClassNotFoundException
	{
		s.defaultReadObject();

		resourcesAwaitingImprovement = new HashMap();
		decisionList = new LinkedList();
		for (Iterator it = decisions.keySet().iterator();
		    it.hasNext(); ) {
			String decisionKey = (String)it.next();
			Decision decision = (Decision)decisions.get(
			    decisionKey);
			decision.setStartingSampleCount(0);
			decisionList.add(decision);
		}
	}
}
