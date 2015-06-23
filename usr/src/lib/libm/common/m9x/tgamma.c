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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak __tgamma = tgamma

/* INDENT OFF */
/*
 * True gamma function
 * double tgamma(double x)
 *
 * Error:
 * ------
 *  	Less that one ulp for both positive and negative arguments.
 *
 * Algorithm:
 * ---------
 *	A: For negative argument
 *		(1) gamma(-n or -inf) is NaN
 *		(2) Underflow Threshold
 *		(3) Reduction to gamma(1+x)
 *	B: For x between 1 and 2
 * 	C: For x between 0 and 1
 *	D: For x between 2 and 8
 *	E: Overflow thresold {see over.c}
 *	F: For overflow_threshold >= x >= 8
 *
 * Implementation details
 * -----------------------
 *							-pi
 * (A) For negative argument, use gamma(-x) = ------------------------.
 *                                            (sin(pi*x)*gamma(1+x))
 *
 *   (1) gamma(-n or -inf) is NaN with invalid signal by SUSv3 spec.
 *	 (Ideally, gamma(-n) = 1/sinpi(n) = (-1)**(n+1) * inf.)
 *
 *   (2) Underflow Threshold. For each precision, there is a value T
 *	such that when x>T and when x is not an integer, gamma(-x) will
 *       always underflow. A table of the underflow threshold value is given
 *	below. For proof, see file "under.c".
 *
 *	Precision	underflow threshold T =
 *	----------------------------------------------------------------------
 *	single	41.000041962					= 41  + 11 ULP
 *		(machine format) 4224000B
 *	double	183.000000000000312639				= 183 + 11 ULP
 *		(machine format) 4066E000 0000000B
 *	quad	1774.0000000000000000000000000000017749370	= 1774 + 9 ULP
 *		(machine format) 4009BB80000000000000000000000009
 *	----------------------------------------------------------------------
 *
 *   (3) Reduction to gamma(1+x).
 *	Because of (1) and (2), we need only consider non-integral x
 *	such that 0<x<T. Let k = [x] and z = x-[x]. Define
 *                  sin(x*pi)                cos(x*pi)
 *	kpsin(x) = --------- and kpcos(x) = --------- . Then
 *                     pi                       pi
 *                                    1
 *		gamma(-x) = --------------------.
 *		            -kpsin(x)*gamma(1+x)
 *	Since x = k+z,
 *                                                  k+1
 *		-sin(x*pi) = -sin(k*pi+z*pi) = (-1)   *sin(z*pi),
 *                               k+1
 *	we have -kpsin(x) = (-1)   * kpsin(z).  We can further
 *	reduce z to t by
 *	   (I)   t = z	     when 0.00000     <= z < 0.31830...
 *	   (II)  t = 0.5-z   when 0.31830...  <= z < 0.681690...
 *	   (III) t = 1-z     when 0.681690... <= z < 1.00000
 *	and correspondingly
 *	   (I)   kpsin(z) = kpsin(t)  	... 0<= z < 0.3184
 *	   (II)  kpsin(z) = kpcos(t) 	... |t|   < 0.182
 *	   (III) kpsin(z) = kpsin(t) 	... 0<= t < 0.3184
 *
 *	Using a special Remez algorithm, we obtain the following polynomial
 *	approximation for kpsin(t) for 0<=t<0.3184:
 *
 *	Computation note: in simulating higher precision arithmetic, kcpsin
 *	return head = t and tail = ks[0]*t^3 + (...) to maintain extra bits.
 *
 *	Quad precision, remez error <= 2**(-129.74)
 *                                   3            5                   27
 *	    kpsin(t) = t + ks[0] * t  + ks[1] * t  + ... + ks[12] * t
 *
 *       ks[ 0] =  -1.64493406684822643647241516664602518705158902870e+0000
 *       ks[ 1] =   8.11742425283353643637002772405874238094995726160e-0001
 *       ks[ 2] =  -1.90751824122084213696472111835337366232282723933e-0001
 *       ks[ 3] =   2.61478478176548005046532613563241288115395517084e-0002
 *       ks[ 4] =  -2.34608103545582363750893072647117829448016479971e-0003
 *       ks[ 5] =   1.48428793031071003684606647212534027556262040158e-0004
 *       ks[ 6] =  -6.97587366165638046518462722252768122615952898698e-0006
 *       ks[ 7] =   2.53121740413702536928659271747187500934840057929e-0007
 *       ks[ 8] =  -7.30471182221385990397683641695766121301933621956e-0009
 *       ks[ 9] =   1.71653847451163495739958249695549313987973589884e-0010
 *       ks[10] =  -3.34813314714560776122245796929054813458341420565e-0012
 *       ks[11] =   5.50724992262622033449487808306969135431411753047e-0014
 *       ks[12] =  -7.67678132753577998601234393215802221104236979928e-0016
 *
 *	Double precision, Remez error <= 2**(-62.9)
 *                                  3            5                  15
 *	    kpsin(t) = t + ks[0] * t  + ks[1] * t  + ... + ks[6] * t
 *
 *       ks[0] =  -1.644934066848226406065691	(0x3ffa51a6 625307d3)
 *       ks[1] =   8.11742425283341655883668741874008920850698590621e-0001
 *       ks[2] =  -1.90751824120862873825597279118304943994042258291e-0001
 *       ks[3] =   2.61478477632554278317289628332654539353521911570e-0002
 *       ks[4] =  -2.34607978510202710377617190278735525354347705866e-0003
 *       ks[5] =   1.48413292290051695897242899977121846763824221705e-0004
 *       ks[6] =  -6.87730769637543488108688726777687262485357072242e-0006
 *
 *	Single precision, Remez error <= 2**(-34.09)
 *                                  3            5                  9
 *	    kpsin(t) = t + ks[0] * t  + ks[1] * t  + ... + ks[3] * t
 *
 *       ks[0] =  -1.64493404985645811354476665052005342839447790544e+0000
 *       ks[1] =   8.11740794458351064092797249069438269367389272270e-0001
 *       ks[2] =  -1.90703144603551216933075809162889536878854055202e-0001
 *       ks[3] =   2.55742333994264563281155312271481108635575331201e-0002
 *
 *	Computation note: in simulating higher precision arithmetic, kcpsin
 *	return head = t and tail = kc[0]*t^3 + (...) to maintain extra bits
 *   	precision.
 *
 *	And for kpcos(t) for |t|< 0.183:
 *
 *	Quad precision, remez <= 2**(-122.48)
 *                                     2            4                  22
 *	    kpcos(t) = 1/pi +  pi/2 * t  + kc[2] * t + ... + kc[11] * t
 *
 *       kc[2] =   1.29192819501249250731151312779548918765320728489e+0000
 *       kc[3] =  -4.25027339979557573976029596929319207009444090366e-0001
 *       kc[4] =   7.49080661650990096109672954618317623888421628613e-0002
 *       kc[5] =  -8.21458866111282287985539464173976555436050215120e-0003
 *       kc[6] =   6.14202578809529228503205255165761204750211603402e-0004
 *       kc[7] =  -3.33073432691149607007217330302595267179545908740e-0005
 *       kc[8] =   1.36970959047832085796809745461530865597993680204e-0006
 *       kc[9] =  -4.41780774262583514450246512727201806217271097336e-0008
 *       kc[10]=   1.14741409212381858820016567664488123478660705759e-0009
 *       kc[11]=  -2.44261236114707374558437500654381006300502749632e-0011
 *
 *	Double precision, remez < 2**(61.91)
 *                                   2            4                  12
 *	    kpcos(t) = 1/pi + pi/2 *t +  kc[2] * t  + ... + kc[6] * t
 *
 *       kc[2] =   1.29192819501230224953283586722575766189551966008e+0000
 *       kc[3] =  -4.25027339940149518500158850753393173519732149213e-0001
 *       kc[4] =   7.49080625187015312373925142219429422375556727752e-0002
 *       kc[5] =  -8.21442040906099210866977352284054849051348692715e-0003
 *       kc[6] =   6.10411356829515414575566564733632532333904115968e-0004
 *
 *	Single precision, remez < 2**(-30.13)
 *                                       2                  6
 *	    kpcos(t) = kc[0] +  kc[1] * t  + ... + kc[3] * t
 *
 *       kc[0] =   3.18309886183790671537767526745028724068919291480e-0001
 *       kc[1] =  -1.57079581447762568199467875065854538626594937791e+0000
 *       kc[2] =   1.29183528092558692844073004029568674027807393862e+0000
 *       kc[3] =  -4.20232949771307685981015914425195471602739075537e-0001
 *
 *	Computation note: in simulating higher precision arithmetic, kcpcos
 *	return head = 1/pi chopped, and tail = pi/2 *t^2 + (tail part of 1/pi
 *	+ ...) to maintain extra bits precision. In particular, pi/2 * t^2
 *	is calculated with great care.
 *
 *	Thus, the computation of gamma(-x), x>0, is:
 *	Let k = int(x), z = x-k.
 *	For z in (I)
 *                                    k+1
 *			          (-1)
 * 		gamma(-x) = ------------------- ;
 *		            kpsin(z)*gamma(1+x)
 *
 *	otherwise, for z in (II),
 *                                      k+1
 *			            (-1)
 * 		gamma(-x) = ----------------------- ;
 *			    kpcos(0.5-z)*gamma(1+x)
 *
 *	otherwise, for z in (III),
 *                                      k+1
 *			            (-1)
 * 		gamma(-x) = --------------------- .
 *		            kpsin(1-z)*gamma(1+x)
 *
 *	Thus, the computation of gamma(-x) reduced to the computation of
 *	gamma(1+x) and kpsin(), kpcos().
 *
 * (B) For x between 1 and 2.  We break [1,2] into three parts:
 *	GT1 = [1.0000, 1.2845]
 * 	GT2 = [1.2844, 1.6374]
 * 	GT3 = [1.6373, 2.0000]
 *
 *    For x in GTi, i=1,2,3, let
 * 	z1  =  1.134861805732790769689793935774652917006
 *	gz1 = gamma(z1)  =   0.9382046279096824494097535615803269576988
 *	tz1 = gamma'(z1) =  -0.3517214357852935791015625000000000000000
 *
 *	z2  =  1.461632144968362341262659542325721328468e+0000
 *	gz2 = gamma(z2)  = 0.8856031944108887002788159005825887332080
 *	tz2 = gamma'(z2) = 0.00
 *
 *	z3  =  1.819773101100500601787868704921606996312e+0000
 *	gz3 = gamma(z3)  = 0.9367814114636523216188468970808378497426
 *	tz3 = gamma'(z3) = 0.2805306315422058105468750000000000000000
 *
 *    and
 *	y = x-zi	... for extra precision, write y = y.h + y.l
 *    Then
 *	gamma(x) = gzi + tzi*(y.h+y.l) + y*y*Ri(y),
 *		 = gzi.h + (tzi*y.h + ((tzi*y.l+gzi.l) +  y*y*Ri(y)))
 *		 = gy.h + gy.l
 *    where
 *	(I) For double precision
 *
 *		Ri(y) = Pi(y)/Qi(y), i=1,2,3;
 *
 *		P1(y) = p1[0] + p1[1]*y + ... + p1[4]*y^4
 *		Q1(y) = q1[0] + q1[1]*y + ... + q1[5]*y^5
 *
 *		P2(y) = p2[0] + p2[1]*y + ... + p2[3]*y^3
 *		Q2(y) = q2[0] + q2[1]*y + ... + q2[6]*y^6
 *
 *		P3(y) = p3[0] + p3[1]*y + ... + p3[4]*y^4
 *		Q3(y) = q3[0] + q3[1]*y + ... + q3[5]*y^5
 *
 *		Remez precision of Ri(y):
 *		|gamma(x)-(gzi+tzi*y) - y*y*Ri(y)|  <= 2**-62.3	... for i = 1
 *					            <= 2**-59.4	... for i = 2
 *					            <= 2**-62.1	... for i = 3
 *
 *	(II) For quad precision
 *
 *		Ri(y) = Pi(y)/Qi(y), i=1,2,3;
 *
 *		P1(y) = p1[0] + p1[1]*y + ... + p1[9]*y^9
 *		Q1(y) = q1[0] + q1[1]*y + ... + q1[8]*y^8
 *
 *		P2(y) = p2[0] + p2[1]*y + ... + p2[9]*y^9
 *		Q2(y) = q2[0] + q2[1]*y + ... + q2[9]*y^9
 *
 *		P3(y) = p3[0] + p3[1]*y + ... + p3[9]*y^9
 *		Q3(y) = q3[0] + q3[1]*y + ... + q3[9]*y^9
 *
 *		Remez precision of Ri(y):
 *		|gamma(x)-(gzi+tzi*y) - y*y*Ri(y)|  <= 2**-118.2 ... for i = 1
 *					            <= 2**-126.8 ... for i = 2
 *					            <= 2**-119.5 ... for i = 3
 *
 *	(III) For single precision
 *
 *		Ri(y) = Pi(y), i=1,2,3;
 *
 *		P1(y) = p1[0] + p1[1]*y + ... + p1[5]*y^5
 *
 *		P2(y) = p2[0] + p2[1]*y + ... + p2[5]*y^5
 *
 *		P3(y) = p3[0] + p3[1]*y + ... + p3[4]*y^4
 *
 *		Remez precision of Ri(y):
 *		|gamma(x)-(gzi+tzi*y) - y*y*Ri(y)|  <= 2**-30.8	... for i = 1
 *					            <= 2**-31.6	... for i = 2
 *					            <= 2**-29.5	... for i = 3
 *
 *    Notes. (1) GTi and zi are choosen to balance the interval width and
 *		minimize the distant between gamma(x) and the tangent line at
 *		zi. In particular, we have
 *		|gamma(x)-(gzi+tzi*(x-zi))|  <=   0.01436... for x in [1,z2]
 *					     <=   0.01265... for x in [z2,2]
 *
 *           (2) zi are slightly adjusted so that tzi=gamma'(zi) is very
 *		close to a single precision value.
 *
 *    Coefficents: Single precision
 *	i= 1:
 *       P1[0] =   7.09087253435088360271451613398019280077561279443e-0001
 *       P1[1] =  -5.17229560788652108545141978238701790105241761089e-0001
 *       P1[2] =   5.23403394528150789405825222323770647162337764327e-0001
 *       P1[3] =  -4.54586308717075010784041566069480411732634814899e-0001
 *       P1[4] =   4.20596490915239085459964590559256913498190955233e-0001
 *	P1[5] =  -3.57307589712377520978332185838241458642142185789e-0001
 *
 *	i = 2:
 *       p2[0] =   4.28486983980295198166056119223984284434264344578e-0001
 *       p2[1] =  -1.30704539487709138528680121627899735386650103914e-0001
 *       p2[2] =   1.60856285038051955072861219352655851542955430871e-0001
 *       p2[3] =  -9.22285161346010583774458802067371182158937943507e-0002
 *       p2[4] =   7.19240511767225260740890292605070595560626179357e-0002
 *       p2[5] =  -4.88158265593355093703112238534484636193260459574e-0002
 *
 *	i = 3
 *       p3[0] =   3.82409531118807759081121479786092134814808872880e-0001
 *       p3[1] =   2.65309888180188647956400403013495759365167853426e-0002
 *       p3[2] =   8.06815109775079171923561169415370309376296739835e-0002
 *       p3[3] =  -1.54821591666137613928840890835174351674007764799e-0002
 *       p3[4] =   1.76308239242717268530498313416899188157165183405e-0002
 *
 *    Coefficents: Double precision
 * 	i = 1:
 *       p1[0]   =   0.70908683619977797008004927192814648151397705078125000
 *       p1[1]   =   1.71987061393048558089579513384356441668351720061e-0001
 *       p1[2]   =  -3.19273345791990970293320316122813960527705450671e-0002
 *       p1[3]   =   8.36172645419110036267169600390549973563534476989e-0003
 *       p1[4]   =   1.13745336648572838333152213474277971244629758101e-0003
 *	 q1[0]   =   1.0
 *       q1[1]   =   9.71980217826032937526460731778472389791321968082e-0001
 *       q1[2]   =  -7.43576743326756176594084137256042653497087666030e-0002
 *       q1[3]   =  -1.19345944932265559769719470515102012246995255372e-0001
 *       q1[4]   =   1.59913445751425002620935120470781382215050284762e-0002
 *	 q1[5]   =   1.12601136853374984566572691306402321911547550783e-0003
 * 	i = 2:
 *       p2[0]   =   0.42848681585558601181418225678498856723308563232421875
 *       p2[1]   =   6.53596762668970816023718845105667418483122103629e-0002
 *       p2[2]   =  -6.97280829631212931321050770925128264272768936731e-0003
 *       p2[3]   =   6.46342359021981718947208605674813260166116632899e-0003
 *	 q2[0]   =   1.0
 *       q2[1]   =   4.57572620560506047062553957454062012327519313936e-0001
 *       q2[2]   =  -2.52182594886075452859655003407796103083422572036e-0001
 *       q2[3]   =  -1.82970945407778594681348166040103197178711552827e-0002
 *       q2[4]   =   2.43574726993169566475227642128830141304953840502e-0002
 *       q2[5]   =  -5.20390406466942525358645957564897411258667085501e-0003
 *       q2[6]   =   4.79520251383279837635552431988023256031951133885e-0004
 * 	i = 3:
 *	 p3[0]   =   0.382409479734567459008331979930517263710498809814453125
 *       p3[1]   =   1.42876048697668161599069814043449301572928034140e-0001
 *       p3[2]   =   3.42157571052250536817923866013561760785748899071e-0003
 *       p3[3]   =  -5.01542621710067521405087887856991700987709272937e-0004
 *       p3[4]   =   8.89285814866740910123834688163838287618332122670e-0004
 *	 q3[0]   =   1.0
 *       q3[1]   =   3.04253086629444201002215640948957897906299633168e-0001
 *       q3[2]   =  -2.23162407379999477282555672834881213873185520006e-0001
 *       q3[3]   =  -1.05060867741952065921809811933670131427552903636e-0002
 *       q3[4]   =   1.70511763916186982473301861980856352005926669320e-0002
 *       q3[5]   =  -2.12950201683609187927899416700094630764182477464e-0003
 *
 *    Note that all pi0 are exact in double, which is obtained by a
 *    special Remez Algorithm.
 *
 *    Coefficents: Quad precision
 * 	i = 1:
 *       p1[0] =   0.709086836199777919037185741507610124611513720557
 *       p1[1] =   4.45754781206489035827915969367354835667391606951e-0001
 *       p1[2] =   3.21049298735832382311662273882632210062918153852e-0002
 *       p1[3] =  -5.71296796342106617651765245858289197369688864350e-0003
 *       p1[4] =   6.04666892891998977081619174969855831606965352773e-0003
 *       p1[5] =   8.99106186996888711939627812174765258822658645168e-0004
 *       p1[6] =  -6.96496846144407741431207008527018441810175568949e-0005
 *       p1[7] =   1.52597046118984020814225409300131445070213882429e-0005
 *       p1[8] =   5.68521076168495673844711465407432189190681541547e-0007
 *       p1[9] =   3.30749673519634895220582062520286565610418952979e-0008
 *       q1[0] =   1.0+0000
 *       q1[1] =   1.35806511721671070408570853537257079579490650668e+0000
 *       q1[2] =   2.97567810153429553405327140096063086994072952961e-0001
 *       q1[3] =  -1.52956835982588571502954372821681851681118097870e-0001
 *       q1[4] =  -2.88248519561420109768781615289082053597954521218e-0002
 *       q1[5] =   1.03475311719937405219789948456313936302378395955e-0002
 *       q1[6] =   4.12310203243891222368965360124391297374822742313e-0004
 *       q1[7] =  -3.12653708152290867248931925120380729518332507388e-0004
 *       q1[8] =   2.36672170850409745237358105667757760527014332458e-0005
 *
 * 	i = 2:
 *       p2[0] =   0.428486815855585429730209907810650616737756697477
 *       p2[1] =   2.63622124067885222919192651151581541943362617352e-0001
 *       p2[2] =   3.85520683670028865731877276741390421744971446855e-0002
 *       p2[3] =   3.05065978278128549958897133190295325258023525862e-0003
 *       p2[4] =   2.48232934951723128892080415054084339152450445081e-0003
 *       p2[5] =   3.67092777065632360693313762221411547741550105407e-0004
 *       p2[6] =   3.81228045616085789674530902563145250532194518946e-0006
 *       p2[7] =   4.61677225867087554059531455133839175822537617677e-0006
 *       p2[8] =   2.18209052385703200438239200991201916609364872993e-0007
 *       p2[9] =   1.00490538985245846460006244065624754421022542454e-0008
 *       q2[0] =   1.0
 *       q2[1] =   9.20276350207639290567783725273128544224570775056e-0001
 *       q2[2] =  -4.79533683654165107448020515733883781138947771495e-0003
 *       q2[3] =  -1.24538337585899300494444600248687901947684291683e-0001
 *       q2[4] =   4.49866050763472358547524708431719114204535491412e-0003
 *       q2[5] =   7.20715455697920560621638325356292640604078591907e-0003
 *       q2[6] =  -8.68513169029126780280798337091982780598228096116e-0004
 *       q2[7] =  -1.25104431629401181525027098222745544809974229874e-0004
 *       q2[8] =   3.10558344839000038489191304550998047521253437464e-0005
 *       q2[9] =  -1.76829227852852176018537139573609433652506765712e-0006
 *
 *	i = 3
 *       p3[0] =   0.3824094797345675048502747661075355640070439388902
 *       p3[1] =   3.42198093076618495415854906335908427159833377774e-0001
 *       p3[2] =   9.63828189500585568303961406863153237440702754858e-0002
 *       p3[3] =   8.76069421042696384852462044188520252156846768667e-0003
 *       p3[4] =   1.86477890389161491224872014149309015261897537488e-0003
 *       p3[5] =   8.16871354540309895879974742853701311541286944191e-0004
 *       p3[6] =   6.83783483674600322518695090864659381650125625216e-0005
 *       p3[7] =  -1.10168269719261574708565935172719209272190828456e-0006
 *       p3[8] =   9.66243228508380420159234853278906717065629721016e-0007
 *       p3[9] =   2.31858885579177250541163820671121664974334728142e-0008
 *       q3[0] =   1.0
 *       q3[1] =   8.25479821168813634632437430090376252512793067339e-0001
 *       q3[2] =  -1.62251363073937769739639623669295110346015576320e-0002
 *       q3[3] =  -1.10621286905916732758745130629426559691187579852e-0001
 *       q3[4] =   3.48309693970985612644446415789230015515365291459e-0003
 *       q3[5] =   6.73553737487488333032431261131289672347043401328e-0003
 *       q3[6] =  -7.63222008393372630162743587811004613050245128051e-0004
 *       q3[7] =  -1.35792670669190631476784768961953711773073251336e-0004
 *       q3[8] =   3.19610150954223587006220730065608156460205690618e-0005
 *       q3[9] =  -1.82096553862822346610109522015129585693354348322e-0006
 *
 * (C) For x between 0 and 1.
 *     Let P stand for the number of significant bits in the working precision.
 *                      -P                            1
 *    (1)For 0 <= x <= 2   , gamma(x) is computed by --- rounded to nearest.
 *                                                    x
 *       The error is bound by 0.739 ulp(gamma(x)) in IEEE double precision.
 *	Proof.
 *                1                       2
 *	Since  --------  ~  x + 0.577...*x  - ...,  we have, for small x,
 *              gamma(x)
 *           1                    1
 *	----------- < gamma(x) < --- and
 *      x(1+0.578x)               x
 *              1                 1           1
 *	  0 <  --- - gamma(x) <= ---  -  ----------- < 0.578
 *              x                 x      x(1+0.578x)
 *                                     1       1                        -P
 * 	The error is thus bounded by --- ulp(---) + 0.578. Since x <= 2   ,
 *                                     2       x
 *       1      P       1           P                                      1
 *	--- >= 2 , ulp(---) >= ulp(2  ) >= 2. Thus 0.578=0.289*2<=0.289ulp(-)
 *       x              x                                                  x
 *       Thus
 *                             1                                 1
 *		| gamma(x) - [---] rounded | <= (0.5+0.289)*ulp(---).
 *			       x	                         x
 *                         -P                              1
 *	Note that for x<= 2  , it is easy to see that ulp(---)=ulp(gamma(x))
 *                                                         x
 *                            n                             1
 *	except only when x = 2 , (n<= -53). In such cases, --- is exact
 *                                                          x
 * 	and therefore the error is bounded by
 *                         1
 *		0.298*ulp(---) = 0.298*2*ulp(gamma(x)) = 0.578ulp(gamma(x)).
 *                         x
 *	Thus we conclude that the error in gamma is less than 0.739 ulp.
 *
 *    (2)Otherwise, for x in GTi-1 (see B), let y = x-(zi-1). From (B) we obtain
 *                                                          gamma(1+x)
 *	gamma(1+x) = gy.h + gy.l,  then compute gamma(x) by -----------.
 *                                                               x
 *                                                          gy.h
 *	Implementaion note. Write x = x.h+x.l, and Let th = ----- chopped to
 *                                                            x
 *	20 bits, then
 *                                gy.h+gy.l
 *		gamma(x) = th + (----------  - th )
 *                                    x
 *                               1
 *			 = th + ---*(gy.h-th*x.h+gy.l-th*x.l)
 *	                         x
 *
 * (D) For x between 2 and 8. Let n = 1+x chopped to an integer. Then
 *
 *               gamma(x)=(x-1)*(x-2)*...*(x-n)*gamma(x-n)
 *
 *     Since x-n is between 1 and 2, we can apply (B) to compute gamma(x).
 *
 *     Implementation detail. The computation of (x-1)(x-2)...(x-n) in simulated
 *     higher precision arithmetic can be somewhat optimized.  For example, in
 *     computing (x-1)*(x-2)*(x-3)*(x-4), if we compute (x-1)*(x-4) = z.h+z.l,
 *     then (x-2)(x-3) = z.h+2+z.l readily. In below, we list the expression
 *     of the formula to compute gamma(x).
 *
 *     Assume x-n is in GTi (i=1,2, or 3, see B for detail). Let y = x - n - zi.
 *     By (B) we have gamma(x-n) = gy.h+gy.l. If x = x.h+x.l, then we have
 *      n=1 (x in [2,3]):
 *	 gamma(x) = (x-1)*gamma(x-1) = (x-1)*(gy.h+gy.l)
 *                 = [(x.h-1)+x.l]*(gy.h+gy.l)
 *      n=2 (x in [3,4]):
 *        gamma(x) = (x-1)(x-2)*gamma(x-2) = (x-1)*(x-2)*(gy.h+gy.l)
 *                 = ((x.h-2)+x.l)*((x.h-1)+x.l)*(gy.h+gy.l)
 *                 = [x.h*(x.h-3)+2+x.l*(x+(x.h-3))]*(gy.h+gy.l)
 *      n=3 (x in [4,5])
 *	 gamma(x) = (x-1)(x-2)(x-3)*(gy.h+gy.l)
 *                 = (x.h*(x.h-3)+2+x.l*(x+(x.h-3)))*[((x.h-3)+x.l)(gy.h+gy.l)]
 *      n=4 (x in [5,6])
 *	 gamma(x) = [(x-1)(x-4)]*[(x-2)(x-3)]*(gy.h+gy.l)
 *                 = [(x.h*(x.h-5)+4+x.l(x+(x.h-5)))]*[(x-2)*(x-3)]*(gy.h+gy.l)
 *                 = (y.h+y.l)*(y.h+1+y.l)*(gy.h+gy.l)
 *      n=5 (x in [6,7])
 *	 gamma(x) = [(x-1)(x-4)]*[(x-2)(x-3)]*[(x-5)*(gy.h+gy.l)]
 *      n=6 (x in [7,8])
 *	 gamma(x) = [(x-1)(x-6)]*[(x-2)(x-5)]*[(x-3)(x-4)]*(gy.h+gy.l)]
 *		  = [(y.h+y.l)(y.h+4+y.l)][(y.h+6+y.l)(gy.h+gy.l)]
 *
 * (E)Overflow Thresold. For x > Overflow thresold of gamma,
 *    return huge*huge (overflow).
 *
 *    By checking whether lgamma(x) >= 2**{128,1024,16384}, one can
 *    determine the overflow threshold for x in single, double, and
 *    quad precision. See over.c for details.
 *
 *    The overflow threshold of gamma(x) are
 *
 *    single: x = 3.5040096283e+01
 *              = 0x420C290F (IEEE single)
 *    double: x = 1.71624376956302711505e+02
 *              = 0x406573FAE561F647 (IEEE double)
 *    quad:   x = 1.7555483429044629170038892160702032034177e+03
 *              = 0x4009B6E3180CD66A5C4206F128BA77F4  (quad)
 *
 * (F)For overflow_threshold >= x >= 8, we use asymptotic approximation.
 *    (1) Stirling's formula
 *
 *      log(G(x)) ~= (x-.5)*(log(x)-1) + .5(log(2*pi)-1) + (1/x)*P(1/(x*x))
 *		  = L1 + L2 + L3,
 *    where
 *		L1(x) = (x-.5)*(log(x)-1),
 *		L2    = .5(log(2pi)-1) = 0.41893853....,
 *		L3(x) = (1/x)P(1/(x*x)),
 *
 *    The range of L1,L2, and L3 are as follows:
 *
 *	------------------------------------------------------------------
 *  	Range(L1) =  (single) [8.09..,88.30..]	 =[2** 3.01..,2**  6.46..]
 *                   (double) [8.09..,709.3..]   =[2** 3.01..,2**  9.47..]
 *		     (quad)   [8.09..,11356.10..]=[2** 3.01..,2** 13.47..]
 *  	Range(L2) = 0.41893853.....
 *	Range(L3) = [0.0104...., 0.00048....]	 =[2**-6.58..,2**-11.02..]
 *	------------------------------------------------------------------
 *
 *    Gamma(x) is then computed by exp(L1+L2+L3).
 *
 *    (2) Error analysis of (F):
 *    --------------------------
 *    The error in Gamma(x) depends on the error inherited in the computation
 *    of L= L1+L2+L3. Let L' be the computed value of L. The absolute error
 *    in L' is t = L-L'. Since exp(L') = exp(L-t) = exp(L)*exp(t) ~
 *    (1+t)*exp(L), the relative error in exp(L') is approximately t.
 *
 *    To guarantee the relatively accuracy in exp(L'), we would like
 *    |t| < 2**(-P-5) where P denotes for the number of significant bits
 *    of the working precision. Consequently, each of the L1,L2, and L3
 *    must be computed with absolute error bounded by 2**(-P-5) in absolute
 *    value.
 *
 *    Since L2 is a constant, it can be pre-computed to the desired accuracy.
 *    Also |L3| < 2**-6; therefore, it suffices to compute L3 with the
 *    working precision.  That is,
 *	L3(x) approxmiate log(G(x))-(x-.5)(log(x)-1)-.5(log(2pi)-1)
 *    to a precision bounded by 2**(-P-5).
 *
 *                                   2**(-6)
 *			    _________V___________________
 *		L1(x):	   |_________|___________________|
 *			           __ ________________________
 *		L2:	          |__|________________________|
 *			              __________________________
 *         +    L3(x):               |__________________________|
 *                       -------------------------------------------
 *                         [leading] + [Trailing]
 *
 *    For L1(x)=(x-0.5)*(log(x)-1), we need ilogb(L1(x))+5 extra bits for
 *    both multiplicants to guarantee L1(x)'s absolute error is bounded by
 *    2**(-P-5) in absolute value. Here ilogb(y) is defined to be the unbias
 *    binary exponent of y in IEEE format.  We can get x-0.5 to the desire
 *    accuracy easily. It remains to compute log(x)-1 with ilogb(L1(x))+5
 *    extra bits accracy. Note that the range of L1 is 88.30.., 709.3.., and
 *    11356.10... for single, double, and quadruple precision, we have
 *
 *                           single     double      quadruple
 *                         ------------------------------------
 *	ilogb(L1(x))+5 <=     11	  14	       18
 *                         ------------------------------------
 *
 *    (3) Table Driven Method for log(x)-1:
 *    --------------------------------------
 *    Let x = 2**n * y, where 1 <= y < 2. Let Z={z(i),i=1,...,m}
 *    be a set of predetermined evenly distributed floating point numbers
 *    in [1, 2]. Let z(j) be the closest one to y, then
 *	log(x)-1 = n*log(2)-1  +  log(y)
 *		 = n*log(2)-1  +  log(z(j)*y/z(j))
 *		 = n*log(2)-1  +  log(z(j))  +  log(y/z(j))
 *		 = T1(n)       +  T2(j)      +  T3,
 *
 *    where T1(n) = n*log(2)-1 and T2(j) = log(z(j)). Both T1 and T2 can be
 *    pre-calculated and be looked-up in a table. Note that 8 <= x < 1756
 *    implies 3<=n<=10 implies 1.079.. < T1(n) < 6.931.
 *
 *
 *                     y-z(i)          y       1+s
 *    For T3, let s = --------; then ----- =  ----- and
 *                     y+z(i)         z(i)     1-s
 *                1+s           2   3    2   5
 *    	T3 = log(-----) = 2s + --- s  + --- s  + ....
 *                1-s           3        5
 *
 *    Suppose the first term 2s is compute in extra precision. The
 *    dominating error in T3 would then be the rounding error of the
 *    second term 2/3*s**3. To force the rounding bounded by
 *    the required accuracy, we have
 *        single:  |2/3*s**3| < 2**-11   == > |s|<0.09014...
 *        double:  |2/3*s**3| < 2**-14   == > |s|<0.04507...
 *        quad  :  |2/3*s**3| < 2**-18   == > |s|<0.01788... = 2**(-5.80..)
 *
 *    Base on this analysis, we choose Z = {z(i)|z(i)=1+i/64+1/128, 0<=i<=63}.
 *    For any y in [1,2), let j = [64*y] chopped to integer, then z(j) is
 *    the closest to y, and it is not difficult to see that |s| < 2**(-8).
 *    Please note that the polynomial approximation of T3 must be accurate
 *        -24-11   -35    -53-14    -67         -113-18   -131
 *    to 2       =2   ,  2       = 2   ,  and  2        =2
 *    for single, double, and quadruple precision respectively.
 *
 *    Inplementation notes.
 *    (1) Table look-up entries for T1(n) and T2(j), as well as the calculation
 *        of the leading term 2s in T3,  are broken up into leading and trailing
 *        part such that (leading part)* 2**24 will always be an integer. That
 *        will guarantee the addition of the leading parts will be exact.
 *
 *                                   2**(-24)
 *			    _________V___________________
 *		T1(n):	   |_________|___________________|
 *			      _______ ______________________
 *		T2(j):	     |_______|______________________|
 *			         ____ _______________________
 *		2s:	        |____|_______________________|
 *			             __________________________
 *         +    T3(s)-2s:           |__________________________|
 *                       -------------------------------------------
 *                         [leading] + [Trailing]
 *
 *    (2) How to compute 2s accurately.
 *        (A) Compute v = 2s to the working precision. If |v| < 2**(-18),
 *            stop.
 *        (B) chopped v to 2**(-24): v = ((int)(v*2**24))/2**24
 *	 (C) 2s = v + (2s - v), where
 *                        1
 *		2s - v = --- * (2(y-z) - v*(y+z) )
 *                       y+z
 *                         1
 *                      = --- * ( [2(y-z) - v*(y+z)_h ]  - v*(y+z)_l  )
 *                        y+z
 *           where (y+z)_h = (y+z) rounded to 24 bits by (double)(float),
 *	    and (y+z)_l = ((z+z)-(y+z)_h)+(y-z).  Note the the quantity
 *	    in [] is exact.
 *                                                      2         4
 *    (3) Remez approximation for (T3(s)-2s)/s = T3[0]*s + T3[1]*s + ...:
 *	 Single precision: 1 term (compute in double precision arithmetic)
 *	    T3(s) = 2s + S1*s^3, S1 = 0.6666717231848518054693623697539230
 *	    Remez error: |T3(s)/s - (2s+S1*s^3)| < 2**(-35.87)
 *	 Double precision: 3 terms, Remez error is bounded by 2**(-72.40),
 *	    see "tgamma_log"
 *	 Quad precision: 7 terms, Remez error is bounded by 2**(-136.54),
 *	    see "tgammal_log"
 *
 *   The computation of 0.5*(ln(2pi)-1):
 *   	0.5*(ln(2pi)-1) =  0.4189385332046727417803297364056176398614...
 *	split 0.5*(ln(2pi)-1) to hln2pi_h + hln2pi_l, where hln2pi_h is the
 *	leading 21 bits of the constant.
 *	    hln2pi_h= 0.4189383983612060546875
 *	    hln2pi_l= 1.348434666870928297364056176398612173648e-07
 *
 *   The computation of 1/x*P(1/x^2) = log(G(x))-(x-.5)(ln(x)-1)-(.5ln(2pi)-1):
 *	Let s = 1/x <= 1/8 < 0.125. We have
 *	quad precision
 *	    |GP(s) - s*P(s^2)| <= 2**(-120.6), where
 *			       3      5            39
 *	    GP(s) = GP0*s+GP1*s +GP2*s +... +GP19*s    ,
 *       GP0  =   0.083333333333333333333333333333333172839171301
 *			hex 0x3ffe5555 55555555 55555555 55555548
 *       GP1  =  -2.77777777777777777777777777492501211999399424104e-0003
 *       GP2  =   7.93650793650793650793635650541638236350020883243e-0004
 *       GP3  =  -5.95238095238095238057299772679324503339241961704e-0004
 *       GP4  =   8.41750841750841696138422987977683524926142600321e-0004
 *       GP5  =  -1.91752691752686682825032547823699662178842123308e-0003
 *       GP6  =   6.41025641022403480921891559356473451161279359322e-0003
 *       GP7  =  -2.95506535798414019189819587455577003732808185071e-0002
 *       GP8  =   1.79644367229970031486079180060923073476568732136e-0001
 *       GP9  =  -1.39243086487274662174562872567057200255649290646e+0000
 *       GP10 =   1.34025874044417962188677816477842265259608269775e+0001
 *       GP11 =  -1.56803713480127469414495545399982508700748274318e+0002
 *       GP12 =   2.18739841656201561694927630335099313968924493891e+0003
 *       GP13 =  -3.55249848644100338419187038090925410976237921269e+0004
 *       GP14 =   6.43464880437835286216768959439484376449179576452e+0005
 *       GP15 =  -1.20459154385577014992600342782821389605893904624e+0007
 *       GP16 =   2.09263249637351298563934942349749718491071093210e+0008
 *       GP17 =  -2.96247483183169219343745316433899599834685703457e+0009
 *       GP18 =   2.88984933605896033154727626086506756972327292981e+0010
 *       GP19 =  -1.40960434146030007732838382416230610302678063984e+0011
 *
 *       double precision
 *	    |GP(s) - s*P(s^2)| <= 2**(-63.5), where
 *			       3      5      7      9      11      13      15
 *	    GP(s) = GP0*s+GP1*s +GP2*s +GP3*s +GP4*s +GP5*s  +GP6*s  +GP7*s  ,
 *
 *		GP0=  0.0833333333333333287074040640618477 (3FB55555 55555555)
 *		GP1= -2.77777777776649355200565611114627670089130772843e-0003
 *		GP2=  7.93650787486083724805476194170211775784158551509e-0004
 *		GP3= -5.95236628558314928757811419580281294593903582971e-0004
 *		GP4=  8.41566473999853451983137162780427812781178932540e-0004
 *		GP5= -1.90424776670441373564512942038926168175921303212e-0003
 *		GP6=  5.84933161530949666312333949534482303007354299178e-0003
 *		GP7= -1.59453228931082030262124832506144392496561694550e-0002
 *       single precision
 *	    |GP(s) - s*P(s^2)| <= 2**(-37.78), where
 *			       3      5
 *	    GP(s) = GP0*s+GP1*s +GP2*s
 *        GP0 =   8.33333330959694065245736888749042811909994573178e-0002
 *        GP1 =  -2.77765545601667179767706600890361535225507762168e-0003
 *        GP2 =   7.77830853479775281781085278324621033523037489883e-0004
 *
 *
 *	Implementation note:
 *	z = (1/x), z2 = z*z, z4 = z2*z2;
 *	p = z*(GP0+z2*(GP1+....+z2*GP7))
 *	  = z*(GP0+(z4*(GP2+z4*(GP4+z4*GP6))+z2*(GP1+z4*(GP3+z4*(GP5+z4*GP7)))))
 *
 *   Adding everything up:
 *	t = rr.h*ww.h+hln2pi_h      		... exact
 *	w = (hln2pi_l + ((x-0.5)*ww.l+rr.l*ww.h)) + p
 *
 *   Computing exp(t+w):
 *	s = t+w; write s = (n+j/32)*ln2+r, |r|<=(1/64)*ln2, then
 *	exp(s) = 2**n * (2**(j/32) + 2**(j/32)*expm1(r)), where
 *	expm1(r) = r + Et1*r^2 + Et2*r^3 + ... + Et5*r^6, and
 *	2**(j/32) is obtained by table look-up S[j]+S_trail[j].
 *	Remez error bound:
 *	|exp(r) - (1+r+Et1*r^2+...+Et5*r^6)| <= 2^(-63).
 */

#include "libm.h"

#define	__HI(x)	((int *) &x)[HIWORD]
#define	__LO(x)	((unsigned *) &x)[LOWORD]

struct Double {
	double h;
	double l;
};

/* Hex value of GP0 shoule be 3FB55555 55555555 */
static const double c[] = {
	+1.0,
	+2.0,
	+0.5,
	+1.0e-300,
	+6.66666666666666740682e-01,				/* A1=T3[0] */
	+3.99999999955626478023093908674902212920e-01,		/* A2=T3[1] */
	+2.85720221533145659809237398709372330980e-01,		/* A3=T3[2] */
	+0.0833333333333333287074040640618477,			/* GP[0] */
	-2.77777777776649355200565611114627670089130772843e-03,
	+7.93650787486083724805476194170211775784158551509e-04,
	-5.95236628558314928757811419580281294593903582971e-04,
	+8.41566473999853451983137162780427812781178932540e-04,
	-1.90424776670441373564512942038926168175921303212e-03,
	+5.84933161530949666312333949534482303007354299178e-03,
	-1.59453228931082030262124832506144392496561694550e-02,
	+4.18937683105468750000e-01,				/* hln2pi_h */
	+8.50099203991780279640e-07,				/* hln2pi_l */
	+4.18938533204672741744150788368695779923320328369e-01,	/* hln2pi */
	+2.16608493865351192653e-02,				/* ln2_32hi */
	+5.96317165397058656257e-12,				/* ln2_32lo */
	+4.61662413084468283841e+01,				/* invln2_32 */
	+5.0000000000000000000e-1,				/* Et1 */
	+1.66666666665223585560605991943703896196054020060e-01,	/* Et2 */
	+4.16666666665895103520154073534275286743788421687e-02,	/* Et3 */
	+8.33336844093536520775865096538773197505523826029e-03,	/* Et4 */
	+1.38889201930843436040204096950052984793587640227e-03,	/* Et5 */
};

#define	one	  c[0]
#define	two	  c[1]
#define	half	  c[2]
#define	tiny	  c[3]
#define	A1	  c[4]
#define	A2	  c[5]
#define	A3	  c[6]
#define	GP0	  c[7]
#define	GP1	  c[8]
#define	GP2	  c[9]
#define	GP3	  c[10]
#define	GP4	  c[11]
#define	GP5	  c[12]
#define	GP6	  c[13]
#define	GP7	  c[14]
#define	hln2pi_h  c[15]
#define	hln2pi_l  c[16]
#define	hln2pi	  c[17]
#define	ln2_32hi  c[18]
#define	ln2_32lo  c[19]
#define	invln2_32 c[20]
#define	Et1	  c[21]
#define	Et2	  c[22]
#define	Et3	  c[23]
#define	Et4	  c[24]
#define	Et5	  c[25]

/*
 * double precision coefficients for computing log(x)-1 in tgamma.
 *  See "algorithm" for details
 *
 *  log(x) - 1 = T1(n) + T2(j) + T3(s), where x = 2**n * y,  1<=y<2,
 *  j=[64*y], z[j]=1+j/64+1/128, s = (y-z[j])/(y+z[j]), and
 *       T1(n) = T1[2n,2n+1] = n*log(2)-1,
 *       T2(j) = T2[2j,2j+1] = log(z[j]),
 *       T3(s) = 2s + T3[0]s^3 + T3[1]s^5 + T3[2]s^7
 *	       = 2s + A1*s^3 + A2*s^5 + A3*s^7  (see const A1,A2,A3)
 *  Note
 *  (1) the leading entries are truncated to 24 binary point.
 *      See Remezpak/sun/tgamma_log_64.c
 *  (2) Remez error for T3(s) is bounded by 2**(-72.4)
 *      See mpremez/work/Log/tgamma_log_4_outr2
 */

static const double T1[] = {
	-1.00000000000000000000e+00,	/* 0xBFF00000 0x00000000 */
	+0.00000000000000000000e+00,	/* 0x00000000 0x00000000 */
	-3.06852817535400390625e-01,	/* 0xBFD3A37A 0x00000000 */
	-1.90465429995776763166e-09,	/* 0xBE205C61 0x0CA86C38 */
	+3.86294305324554443359e-01,	/* 0x3FD8B90B 0xC0000000 */
	+5.57953361754750897367e-08,	/* 0x3E6DF473 0xDE6AF279 */
	+1.07944148778915405273e+00,	/* 0x3FF14564 0x70000000 */
	+5.38906818755173187963e-08,	/* 0x3E6CEEAD 0xCDA06BB5 */
	+1.77258867025375366211e+00,	/* 0x3FFC5C85 0xF0000000 */
	+5.19860275755595544734e-08,	/* 0x3E6BE8E7 0xBCD5E4F2 */
	+2.46573585271835327148e+00,	/* 0x4003B9D3 0xB8000000 */
	+5.00813732756017835330e-08,	/* 0x3E6AE321 0xAC0B5E2E */
	+3.15888303518295288086e+00,	/* 0x40094564 0x78000000 */
	+4.81767189756440192100e-08,	/* 0x3E69DD5B 0x9B40D76B */
	+3.85203021764755249023e+00,	/* 0x400ED0F5 0x38000000 */
	+4.62720646756862482697e-08,	/* 0x3E68D795 0x8A7650A7 */
	+4.54517740011215209961e+00,	/* 0x40122E42 0xFC000000 */
	+4.43674103757284839467e-08,	/* 0x3E67D1CF 0x79ABC9E4 */
	+5.23832458257675170898e+00,	/* 0x4014F40B 0x5C000000 */
	+4.24627560757707130063e-08,	/* 0x3E66CC09 0x68E14320 */
	+5.93147176504135131836e+00,	/* 0x4017B9D3 0xBC000000 */
	+4.05581017758129486834e-08,	/* 0x3E65C643 0x5816BC5D */
};

static const double T2[] = {
	+7.78210163116455078125e-03,	/* 0x3F7FE020 0x00000000 */
	+3.88108903981662140884e-08,	/* 0x3E64D620 0xCF11F86F */
	+2.31670141220092773438e-02,	/* 0x3F97B918 0x00000000 */
	+4.51595251008850513740e-08,	/* 0x3E683EAD 0x88D54940 */
	+3.83188128471374511719e-02,	/* 0x3FA39E86 0x00000000 */
	+5.14549991480218823411e-08,	/* 0x3E6B9FEB 0xD5FA9016 */
	+5.32444715499877929688e-02,	/* 0x3FAB42DC 0x00000000 */
	+4.29688244898971182165e-08,	/* 0x3E671197 0x1BEC28D1 */
	+6.79506063461303710938e-02,	/* 0x3FB16536 0x00000000 */
	+5.55623773783008185114e-08,	/* 0x3E6DD46F 0x5C1D0C4C */
	+8.24436545372009277344e-02,	/* 0x3FB51B07 0x00000000 */
	+1.46738736635337847313e-08,	/* 0x3E4F830C 0x1FB493C7 */
	+9.67295765876770019531e-02,	/* 0x3FB8C345 0x00000000 */
	+4.98708741103424492282e-08,	/* 0x3E6AC633 0x641EB597 */
	+1.10814332962036132812e-01,	/* 0x3FBC5E54 0x00000000 */
	+3.33782539813823062226e-08,	/* 0x3E61EB78 0xE862BAC3 */
	+1.24703466892242431641e-01,	/* 0x3FBFEC91 0x00000000 */
	+1.16087148042227818450e-08,	/* 0x3E48EDF5 0x5D551729 */
	+1.38402283191680908203e-01,	/* 0x3FC1B72A 0x80000000 */
	+3.96674382274822001957e-08,	/* 0x3E654BD9 0xE80A4181 */
	+1.51916027069091796875e-01,	/* 0x3FC371FC 0x00000000 */
	+1.49567501781968021494e-08,	/* 0x3E500F47 0xBA1DE6CB */
	+1.65249526500701904297e-01,	/* 0x3FC526E5 0x80000000 */
	+4.63946052585787334062e-08,	/* 0x3E68E86D 0x0DE8B900 */
	+1.78407609462738037109e-01,	/* 0x3FC6D60F 0x80000000 */
	+4.80100802600100279538e-08,	/* 0x3E69C674 0x8723551E */
	+1.91394805908203125000e-01,	/* 0x3FC87FA0 0x00000000 */
	+4.70914263296092971436e-08,	/* 0x3E694832 0x44240802 */
	+2.04215526580810546875e-01,	/* 0x3FCA23BC 0x00000000 */
	+1.48478803446288209001e-08,	/* 0x3E4FE2B5 0x63193712 */
	+2.16873884201049804688e-01,	/* 0x3FCBC286 0x00000000 */
	+5.40995645549315919488e-08,	/* 0x3E6D0B63 0x358A7E74 */
	+2.29374051094055175781e-01,	/* 0x3FCD5C21 0x00000000 */
	+4.99707906542102284117e-08,	/* 0x3E6AD3EE 0xE456E443 */
	+2.41719901561737060547e-01,	/* 0x3FCEF0AD 0x80000000 */
	+3.53254081075974352804e-08,	/* 0x3E62F716 0x4D948638 */
	+2.53915190696716308594e-01,	/* 0x3FD04025 0x80000000 */
	+1.92842471355435739091e-08,	/* 0x3E54B4D0 0x40DAE27C */
	+2.65963494777679443359e-01,	/* 0x3FD1058B 0xC0000000 */
	+5.37194584979797487125e-08,	/* 0x3E6CD725 0x6A8C4FD0 */
	+2.77868449687957763672e-01,	/* 0x3FD1C898 0xC0000000 */
	+1.31549854251447496506e-09,	/* 0x3E16999F 0xAFBC68E7 */
	+2.89633274078369140625e-01,	/* 0x3FD2895A 0x00000000 */
	+1.85046735362538929911e-08,	/* 0x3E53DE86 0xA35EB493 */
	+3.01261305809020996094e-01,	/* 0x3FD347DD 0x80000000 */
	+2.47691407849191245052e-08,	/* 0x3E5A987D 0x54D64567 */
	+3.12755703926086425781e-01,	/* 0x3FD40430 0x80000000 */
	+6.07781046260499658610e-09,	/* 0x3E3A1A9F 0x8EF4304A */
	+3.24119448661804199219e-01,	/* 0x3FD4BE5F 0x80000000 */
	+1.99924077768719198045e-08,	/* 0x3E557778 0xA0DB4C99 */
	+3.35355520248413085938e-01,	/* 0x3FD57677 0x00000000 */
	+2.16727247443196802771e-08,	/* 0x3E57455A 0x6C549AB7 */
	+3.46466720104217529297e-01,	/* 0x3FD62C82 0xC0000000 */
	+4.72419910516215900493e-08,	/* 0x3E695CE3 0xCA97B7B0 */
	+3.57455849647521972656e-01,	/* 0x3FD6E08E 0x80000000 */
	+3.92742818015697624778e-08,	/* 0x3E6515D0 0xF1C609CA */
	+3.68325531482696533203e-01,	/* 0x3FD792A5 0x40000000 */
	+2.96760111198451042238e-08,	/* 0x3E5FDD47 0xA27C15DA */
	+3.79078328609466552734e-01,	/* 0x3FD842D1 0xC0000000 */
	+2.43255029056564770289e-08,	/* 0x3E5A1E8B 0x17493B14 */
	+3.89716744422912597656e-01,	/* 0x3FD8F11E 0x80000000 */
	+6.71711261571421332726e-09,	/* 0x3E3CD98B 0x1DF85DA7 */
	+4.00243163108825683594e-01,	/* 0x3FD99D95 0x80000000 */
	+1.01818702333557515008e-09,	/* 0x3E117E08 0xACBA92EF */
	+4.10659909248352050781e-01,	/* 0x3FDA4840 0x80000000 */
	+1.57369163351530571459e-08,	/* 0x3E50E5BB 0x0A2BFCA7 */
	+4.20969247817993164062e-01,	/* 0x3FDAF129 0x00000000 */
	+4.68261364720663662040e-08,	/* 0x3E6923BC 0x358899C2 */
	+4.31173443794250488281e-01,	/* 0x3FDB9858 0x80000000 */
	+2.10241208525779214510e-08,	/* 0x3E569310 0xFB598FB1 */
	+4.41274523735046386719e-01,	/* 0x3FDC3DD7 0x80000000 */
	+3.70698288427707487748e-08,	/* 0x3E63E6D6 0xA6B9D9E1 */
	+4.51274633407592773438e-01,	/* 0x3FDCE1AF 0x00000000 */
	+1.07318658117071930723e-08,	/* 0x3E470BE7 0xD6F6FA58 */
	+4.61175680160522460938e-01,	/* 0x3FDD83E7 0x00000000 */
	+3.49616477054305011286e-08,	/* 0x3E62C517 0x9F2828AE */
	+4.70979690551757812500e-01,	/* 0x3FDE2488 0x00000000 */
	+2.46670332000468969567e-08,	/* 0x3E5A7C6C 0x261CBD8F */
	+4.80688512325286865234e-01,	/* 0x3FDEC399 0xC0000000 */
	+1.70204650424422423704e-08,	/* 0x3E52468C 0xC0175CEE */
	+4.90303933620452880859e-01,	/* 0x3FDF6123 0xC0000000 */
	+5.44247409572909703749e-08,	/* 0x3E6D3814 0x5630A2B6 */
	+4.99827861785888671875e-01,	/* 0x3FDFFD2E 0x00000000 */
	+7.77056065794633071345e-09,	/* 0x3E40AFE9 0x30AB2FA0 */
	+5.09261846542358398438e-01,	/* 0x3FE04BDF 0x80000000 */
	+5.52474495483665749052e-08,	/* 0x3E6DA926 0xD265FCC1 */
	+5.18607735633850097656e-01,	/* 0x3FE0986F 0x40000000 */
	+2.85741955344967264536e-08,	/* 0x3E5EAE6A 0x41723FB5 */
	+5.27867078781127929688e-01,	/* 0x3FE0E449 0x80000000 */
	+1.08397144554263914271e-08,	/* 0x3E474732 0x2FDBAB97 */
	+5.37041425704956054688e-01,	/* 0x3FE12F71 0x80000000 */
	+4.01919275998792285777e-08,	/* 0x3E6593EF 0xBC530123 */
	+5.46132385730743408203e-01,	/* 0x3FE179EA 0xA0000000 */
	+5.18673922421792693237e-08,	/* 0x3E6BD899 0xA0BFC60E */
	+5.55141448974609375000e-01,	/* 0x3FE1C3B8 0x00000000 */
	+5.85658922177154808539e-08,	/* 0x3E6F713C 0x24BC94F9 */
	+5.64070105552673339844e-01,	/* 0x3FE20CDC 0xC0000000 */
	+3.27321296262276338905e-08,	/* 0x3E6192AB 0x6D93503D */
	+5.72919726371765136719e-01,	/* 0x3FE2555B 0xC0000000 */
	+2.71900203723740076878e-08,	/* 0x3E5D31EF 0x96780876 */
	+5.81691682338714599609e-01,	/* 0x3FE29D37 0xE0000000 */
	+5.72959078829112371070e-08,	/* 0x3E6EC2B0 0x8AC85CD7 */
	+5.90387403964996337891e-01,	/* 0x3FE2E474 0x20000000 */
	+4.26371800367512948470e-08,	/* 0x3E66E402 0x68405422 */
	+5.99008142948150634766e-01,	/* 0x3FE32B13 0x20000000 */
	+4.66979327646159769249e-08,	/* 0x3E69121D 0x71320557 */
	+6.07555210590362548828e-01,	/* 0x3FE37117 0xA0000000 */
	+3.96341792466729582847e-08,	/* 0x3E654747 0xB5C5DD02 */
	+6.16029858589172363281e-01,	/* 0x3FE3B684 0x40000000 */
	+1.86263416563663175432e-08,	/* 0x3E53FFF8 0x455F1DBE */
	+6.24433279037475585938e-01,	/* 0x3FE3FB5B 0x80000000 */
	+8.97441791510503832111e-09,	/* 0x3E4345BD 0x096D3A75 */
	+6.32766664028167724609e-01,	/* 0x3FE43F9F 0xE0000000 */
	+5.54287010493641158796e-09,	/* 0x3E37CE73 0x3BD393DD */
	+6.41031146049499511719e-01,	/* 0x3FE48353 0xC0000000 */
	+3.33714317793368531132e-08,	/* 0x3E61EA88 0xDF73D5E9 */
	+6.49227917194366455078e-01,	/* 0x3FE4C679 0xA0000000 */
	+2.94307433638127158696e-08,	/* 0x3E5F99DC 0x7362D1DA */
	+6.57358050346374511719e-01,	/* 0x3FE50913 0xC0000000 */
	+2.23619855184231409785e-08,	/* 0x3E5802D0 0xD6979675 */
	+6.65422618389129638672e-01,	/* 0x3FE54B24 0x60000000 */
	+1.41559608102782173188e-08,	/* 0x3E4E6652 0x5EA4550A */
	+6.73422634601593017578e-01,	/* 0x3FE58CAD 0xA0000000 */
	+4.06105737027198329700e-08,	/* 0x3E65CD79 0x893092F2 */
	+6.81359171867370605469e-01,	/* 0x3FE5CDB1 0xC0000000 */
	+5.29405324634793230630e-08,	/* 0x3E6C6C17 0x648CF6E4 */
	+6.89233243465423583984e-01,	/* 0x3FE60E32 0xE0000000 */
	+3.77733853963405370102e-08,	/* 0x3E644788 0xD8CA7C89 */
};

/* S[j],S_trail[j] = 2**(j/32.) for the final computation of exp(t+w) */
static const double S[] = {
	+1.00000000000000000000e+00,	/* 3FF0000000000000 */
	+1.02189714865411662714e+00,	/* 3FF059B0D3158574 */
	+1.04427378242741375480e+00,	/* 3FF0B5586CF9890F */
	+1.06714040067682369717e+00,	/* 3FF11301D0125B51 */
	+1.09050773266525768967e+00,	/* 3FF172B83C7D517B */
	+1.11438674259589243221e+00,	/* 3FF1D4873168B9AA */
	+1.13878863475669156458e+00,	/* 3FF2387A6E756238 */
	+1.16372485877757747552e+00,	/* 3FF29E9DF51FDEE1 */
	+1.18920711500272102690e+00,	/* 3FF306FE0A31B715 */
	+1.21524735998046895524e+00,	/* 3FF371A7373AA9CB */
	+1.24185781207348400201e+00,	/* 3FF3DEA64C123422 */
	+1.26905095719173321989e+00,	/* 3FF44E086061892D */
	+1.29683955465100964055e+00,	/* 3FF4BFDAD5362A27 */
	+1.32523664315974132322e+00,	/* 3FF5342B569D4F82 */
	+1.35425554693689265129e+00,	/* 3FF5AB07DD485429 */
	+1.38390988196383202258e+00,	/* 3FF6247EB03A5585 */
	+1.41421356237309514547e+00,	/* 3FF6A09E667F3BCD */
	+1.44518080697704665027e+00,	/* 3FF71F75E8EC5F74 */
	+1.47682614593949934623e+00,	/* 3FF7A11473EB0187 */
	+1.50916442759342284141e+00,	/* 3FF82589994CCE13 */
	+1.54221082540794074411e+00,	/* 3FF8ACE5422AA0DB */
	+1.57598084510788649659e+00,	/* 3FF93737B0CDC5E5 */
	+1.61049033194925428347e+00,	/* 3FF9C49182A3F090 */
	+1.64575547815396494578e+00,	/* 3FFA5503B23E255D */
	+1.68179283050742900407e+00,	/* 3FFAE89F995AD3AD */
	+1.71861929812247793414e+00,	/* 3FFB7F76F2FB5E47 */
	+1.75625216037329945351e+00,	/* 3FFC199BDD85529C */
	+1.79470907500310716820e+00,	/* 3FFCB720DCEF9069 */
	+1.83400808640934243066e+00,	/* 3FFD5818DCFBA487 */
	+1.87416763411029996256e+00,	/* 3FFDFC97337B9B5F */
	+1.91520656139714740007e+00,	/* 3FFEA4AFA2A490DA */
	+1.95714412417540017941e+00,	/* 3FFF50765B6E4540 */
};

static const double S_trail[] = {
	+0.00000000000000000000e+00,
	+5.10922502897344389359e-17,	/* 3C8D73E2A475B465 */
	+8.55188970553796365958e-17,	/* 3C98A62E4ADC610A */
	-7.89985396684158212226e-17,	/* BC96C51039449B3A */
	-3.04678207981247114697e-17,	/* BC819041B9D78A76 */
	+1.04102784568455709549e-16,	/* 3C9E016E00A2643C */
	+8.91281267602540777782e-17,	/* 3C99B07EB6C70573 */
	+3.82920483692409349872e-17,	/* 3C8612E8AFAD1255 */
	+3.98201523146564611098e-17,	/* 3C86F46AD23182E4 */
	-7.71263069268148813091e-17,	/* BC963AEABF42EAE2 */
	+4.65802759183693679123e-17,	/* 3C8ADA0911F09EBC */
	+2.66793213134218609523e-18,	/* 3C489B7A04EF80D0 */
	+2.53825027948883149593e-17,	/* 3C7D4397AFEC42E2 */
	-2.85873121003886075697e-17,	/* BC807ABE1DB13CAC */
	+7.70094837980298946162e-17,	/* 3C96324C054647AD */
	-6.77051165879478628716e-17,	/* BC9383C17E40B497 */
	-9.66729331345291345105e-17,	/* BC9BDD3413B26456 */
	-3.02375813499398731940e-17,	/* BC816E4786887A99 */
	-3.48399455689279579579e-17,	/* BC841577EE04992F */
	-1.01645532775429503911e-16,	/* BC9D4C1DD41532D8 */
	+7.94983480969762085616e-17,	/* 3C96E9F156864B27 */
	-1.01369164712783039808e-17,	/* BC675FC781B57EBC */
	+2.47071925697978878522e-17,	/* 3C7C7C46B071F2BE */
	-1.01256799136747726038e-16,	/* BC9D2F6EDB8D41E1 */
	+8.19901002058149652013e-17,	/* 3C97A1CD345DCC81 */
	-1.85138041826311098821e-17,	/* BC75584F7E54AC3B */
	+2.96014069544887330703e-17,	/* 3C811065895048DD */
	+1.82274584279120867698e-17,	/* 3C7503CBD1E949DB */
	+3.28310722424562658722e-17,	/* 3C82ED02D75B3706 */
	-6.12276341300414256164e-17,	/* BC91A5CD4F184B5C */
	-1.06199460561959626376e-16,	/* BC9E9C23179C2893 */
	+8.96076779103666776760e-17,	/* 3C99D3E12DD8A18B */
};

/* Primary interval GTi() */
static const double cr[] = {
/* p1, q1 */
	+0.70908683619977797008004927192814648151397705078125000,
	+1.71987061393048558089579513384356441668351720061e-0001,
	-3.19273345791990970293320316122813960527705450671e-0002,
	+8.36172645419110036267169600390549973563534476989e-0003,
	+1.13745336648572838333152213474277971244629758101e-0003,
	+1.0,
	+9.71980217826032937526460731778472389791321968082e-0001,
	-7.43576743326756176594084137256042653497087666030e-0002,
	-1.19345944932265559769719470515102012246995255372e-0001,
	+1.59913445751425002620935120470781382215050284762e-0002,
	+1.12601136853374984566572691306402321911547550783e-0003,
/* p2, q2 */
	+0.42848681585558601181418225678498856723308563232421875,
	+6.53596762668970816023718845105667418483122103629e-0002,
	-6.97280829631212931321050770925128264272768936731e-0003,
	+6.46342359021981718947208605674813260166116632899e-0003,
	+1.0,
	+4.57572620560506047062553957454062012327519313936e-0001,
	-2.52182594886075452859655003407796103083422572036e-0001,
	-1.82970945407778594681348166040103197178711552827e-0002,
	+2.43574726993169566475227642128830141304953840502e-0002,
	-5.20390406466942525358645957564897411258667085501e-0003,
	+4.79520251383279837635552431988023256031951133885e-0004,
/* p3, q3 */
	+0.382409479734567459008331979930517263710498809814453125,
	+1.42876048697668161599069814043449301572928034140e-0001,
	+3.42157571052250536817923866013561760785748899071e-0003,
	-5.01542621710067521405087887856991700987709272937e-0004,
	+8.89285814866740910123834688163838287618332122670e-0004,
	+1.0,
	+3.04253086629444201002215640948957897906299633168e-0001,
	-2.23162407379999477282555672834881213873185520006e-0001,
	-1.05060867741952065921809811933670131427552903636e-0002,
	+1.70511763916186982473301861980856352005926669320e-0002,
	-2.12950201683609187927899416700094630764182477464e-0003,
};

#define	P10   cr[0]
#define	P11   cr[1]
#define	P12   cr[2]
#define	P13   cr[3]
#define	P14   cr[4]
#define	Q10   cr[5]
#define	Q11   cr[6]
#define	Q12   cr[7]
#define	Q13   cr[8]
#define	Q14   cr[9]
#define	Q15   cr[10]
#define	P20   cr[11]
#define	P21   cr[12]
#define	P22   cr[13]
#define	P23   cr[14]
#define	Q20   cr[15]
#define	Q21   cr[16]
#define	Q22   cr[17]
#define	Q23   cr[18]
#define	Q24   cr[19]
#define	Q25   cr[20]
#define	Q26   cr[21]
#define	P30   cr[22]
#define	P31   cr[23]
#define	P32   cr[24]
#define	P33   cr[25]
#define	P34   cr[26]
#define	Q30   cr[27]
#define	Q31   cr[28]
#define	Q32   cr[29]
#define	Q33   cr[30]
#define	Q34   cr[31]
#define	Q35   cr[32]

static const double
	GZ1_h = +0.938204627909682398190,
	GZ1_l = +5.121952600248205157935e-17,
	GZ2_h = +0.885603194410888749921,
	GZ2_l = -4.964236872556339810692e-17,
	GZ3_h = +0.936781411463652347038,
	GZ3_l = -2.541923110834479415023e-17,
	TZ1 = -0.3517214357852935791015625,
	TZ3 = +0.280530631542205810546875;
/* INDENT ON */

/* compute gamma(y=yh+yl) for y in GT1 = [1.0000, 1.2845] */
/* assume yh got 20 significant bits */
static struct Double
GT1(double yh, double yl) {
	double t3, t4, y, z;
	struct Double r;

	y = yh + yl;
	z = y * y;
	t3 = (z * (P10 + y * ((P11 + y * P12) + z * (P13 + y * P14)))) /
		(Q10 + y * ((Q11 + y * Q12) + z * ((Q13 + Q14 * y) + z * Q15)));
	t3 += (TZ1 * yl + GZ1_l);
	t4 = TZ1 * yh;
	r.h = (double) ((float) (t4 + GZ1_h + t3));
	t3 += (t4 - (r.h - GZ1_h));
	r.l = t3;
	return (r);
}

/* compute gamma(y=yh+yl) for y in GT2 = [1.2844, 1.6374] */
/* assume yh got 20 significant bits */
static struct Double
GT2(double yh, double yl) {
	double t3, y, z;
	struct Double r;

	y = yh + yl;
	z = y * y;
	t3 = (z * (P20 + y * P21 + z * (P22 + y * P23))) /
		(Q20 + (y * ((Q21 + Q22 * y) + z * Q23) +
		(z * z) * ((Q24 + Q25 * y) + z * Q26))) + GZ2_l;
	r.h = (double) ((float) (GZ2_h + t3));
	r.l = t3 - (r.h - GZ2_h);
	return (r);
}

/* compute gamma(y=yh+yl) for y in GT3 = [1.6373, 2.0000] */
/* assume yh got 20 significant bits */
static struct Double
GT3(double yh, double yl) {
	double t3, t4, y, z;
	struct Double r;

	y = yh + yl;
	z = y * y;
	t3 = (z * (P30 + y * ((P31 + y * P32) + z * (P33 + y * P34)))) /
		(Q30 + y * ((Q31 + y * Q32) + z * ((Q33 + Q34 * y) + z * Q35)));
	t3 += (TZ3 * yl + GZ3_l);
	t4 = TZ3 * yh;
	r.h = (double) ((float) (t4 + GZ3_h + t3));
	t3 += (t4 - (r.h - GZ3_h));
	r.l = t3;
	return (r);
}

/* INDENT OFF */
/*
 * return tgamma(x) scaled by 2**-m for 8<x<=171.62... using Stirling's formula
 *     log(G(x)) ~= (x-.5)*(log(x)-1) + .5(log(2*pi)-1) + (1/x)*P(1/(x*x))
 *                = L1 + L2 + L3,
 */
/* INDENT ON */
static struct Double
large_gam(double x, int *m) {
	double z, t1, t2, t3, z2, t5, w, y, u, r, z4, v, t24 = 16777216.0,
		p24 = 1.0 / 16777216.0;
	int n2, j2, k, ix, j;
	unsigned lx;
	struct Double zz;
	double u2, ss_h, ss_l, r_h, w_h, w_l, t4;

/* INDENT OFF */
/*
 * compute ss = ss.h+ss.l = log(x)-1 (see tgamma_log.h for details)
 *
 *  log(x) - 1 = T1(n) + T2(j) + T3(s), where x = 2**n * y,  1<=y<2,
 *  j=[64*y], z[j]=1+j/64+1/128, s = (y-z[j])/(y+z[j]), and
 *       T1(n) = T1[2n,2n+1] = n*log(2)-1,
 *       T2(j) = T2[2j,2j+1] = log(z[j]),
 *       T3(s) = 2s + A1[0]s^3 + A2[1]s^5 + A3[2]s^7
 *  Note
 *  (1) the leading entries are truncated to 24 binary point.
 *  (2) Remez error for T3(s) is bounded by 2**(-72.4)
 *                                   2**(-24)
 *                           _________V___________________
 *               T1(n):     |_________|___________________|
 *                             _______ ______________________
 *               T2(j):       |_______|______________________|
 *                                ____ _______________________
 *               2s:             |____|_______________________|
 *                                    __________________________
 *          +    T3(s)-2s:           |__________________________|
 *                       -------------------------------------------
 *                          [leading] + [Trailing]
 */
/* INDENT ON */
	ix = __HI(x);
	lx = __LO(x);
	n2 = (ix >> 20) - 0x3ff;	/* exponent of x, range:3-7 */
	n2 += n2;			/* 2n */
	ix = (ix & 0x000fffff) | 0x3ff00000;	/* y = scale x to [1,2] */
	__HI(y) = ix;
	__LO(y) = lx;
	__HI(z) = (ix & 0xffffc000) | 0x2000;	/* z[j]=1+j/64+1/128 */
	__LO(z) = 0;
	j2 = (ix >> 13) & 0x7e;	/* 2j */
	t1 = y + z;
	t2 = y - z;
	r = one / t1;
	t1 = (double) ((float) t1);
	u = r * t2;		/* u = (y-z)/(y+z) */
	t4 = T2[j2 + 1] + T1[n2 + 1];
	z2 = u * u;
	k = __HI(u) & 0x7fffffff;
	t3 = T2[j2] + T1[n2];
	if ((k >> 20) < 0x3ec) {	/* |u|<2**-19 */
		t2 = t4 + u * ((two + z2 * A1) + (z2 * z2) * (A2 + z2 * A3));
	} else {
		t5 = t4 + u * (z2 * A1 + (z2 * z2) * (A2 + z2 * A3));
		u2 = u + u;
		v = (double) ((int) (u2 * t24)) * p24;
		t2 = t5 + r * ((two * t2 - v * t1) - v * (y - (t1 - z)));
		t3 += v;
	}
	ss_h = (double) ((float) (t2 + t3));
	ss_l = t2 - (ss_h - t3);

	/*
	 * compute ww = (x-.5)*(log(x)-1) + .5*(log(2pi)-1) + 1/x*(P(1/x^2)))
	 * where ss = log(x) - 1 in already in extra precision
	 */
	z = one / x;
	r = x - half;
	r_h = (double) ((float) r);
	w_h = r_h * ss_h + hln2pi_h;
	z2 = z * z;
	w = (r - r_h) * ss_h + r * ss_l;
	z4 = z2 * z2;
	t1 = z2 * (GP1 + z4 * (GP3 + z4 * (GP5 + z4 * GP7)));
	t2 = z4 * (GP2 + z4 * (GP4 + z4 * GP6));
	t1 += t2;
	w += hln2pi_l;
	w_l = z * (GP0 + t1) + w;
	k = (int) ((w_h + w_l) * invln2_32 + half);

	/* compute the exponential of w_h+w_l */
	j = k & 0x1f;
	*m = (k >> 5);
	t3 = (double) k;

	/* perform w - k*ln2_32 (represent as w_h - w_l) */
	t1 = w_h - t3 * ln2_32hi;
	t2 = t3 * ln2_32lo;
	w = w_l - t2;
	w_h = t1 + w_l;
	w_l = t2 - (w_l - (w_h - t1));

	/* compute exp(w_h+w_l) */
	z = w_h - w_l;
	z2 = z * z;
	t1 = z2 * (Et1 + z2 * (Et3 + z2 * Et5));
	t2 = z2 * (Et2 + z2 * Et4);
	t3 = w_h - (w_l - (t1 + z * t2));
	zz.l = S_trail[j] * (one + t3) + S[j] * t3;
	zz.h = S[j];
	return (zz);
}

/* INDENT OFF */
/*
 * kpsin(x)= sin(pi*x)/pi
 *                 3        5        7        9        11        13        15
 *	= x+ks[0]*x +ks[1]*x +ks[2]*x +ks[3]*x +ks[4]*x  +ks[5]*x  +ks[6]*x
 */
static const double ks[] = {
	-1.64493406684822640606569,
	+8.11742425283341655883668741874008920850698590621e-0001,
	-1.90751824120862873825597279118304943994042258291e-0001,
	+2.61478477632554278317289628332654539353521911570e-0002,
	-2.34607978510202710377617190278735525354347705866e-0003,
	+1.48413292290051695897242899977121846763824221705e-0004,
	-6.87730769637543488108688726777687262485357072242e-0006,
};
/* INDENT ON */

/* assume x is not tiny and positive */
static struct Double
kpsin(double x) {
	double z, t1, t2, t3, t4;
	struct Double xx;

	z = x * x;
	xx.h = x;
	t1 = z * x;
	t2 = z * z;
	t4 = t1 * ks[0];
	t3 = (t1 * z) * ((ks[1] + z * ks[2] + t2 * ks[3]) + (z * t2) *
		(ks[4] + z * ks[5] + t2 * ks[6]));
	xx.l = t4 + t3;
	return (xx);
}

/* INDENT OFF */
/*
 * kpcos(x)= cos(pi*x)/pi
 *                     2        4        6        8        10        12
 *	= 1/pi +kc[0]*x +kc[1]*x +kc[2]*x +kc[3]*x +kc[4]*x  +kc[5]*x
 */

static const double one_pi_h = 0.318309886183790635705292970,
		one_pi_l = 3.583247455607534006714276420e-17;
static const double npi_2_h = -1.5625,
		npi_2_l = -0.00829632679489661923132169163975055099555883223;
static const double kc[] = {
	-1.57079632679489661923132169163975055099555883223e+0000,
	+1.29192819501230224953283586722575766189551966008e+0000,
	-4.25027339940149518500158850753393173519732149213e-0001,
	+7.49080625187015312373925142219429422375556727752e-0002,
	-8.21442040906099210866977352284054849051348692715e-0003,
	+6.10411356829515414575566564733632532333904115968e-0004,
};
/* INDENT ON */

/* assume x is not tiny and positive */
static struct Double
kpcos(double x) {
	double z, t1, t2, t3, t4, x4, x8;
	struct Double xx;

	z = x * x;
	xx.h = one_pi_h;
	t1 = (double) ((float) x);
	x4 = z * z;
	t2 = npi_2_l * z + npi_2_h * (x + t1) * (x - t1);
	t3 = one_pi_l + x4 * ((kc[1] + z * kc[2]) + x4 * (kc[3] + z *
		kc[4] + x4 * kc[5]));
	t4 = t1 * t1;	/* 48 bits mantissa */
	x8 = t2 + t3;
	t4 *= npi_2_h;	/* npi_2_h is 5 bits const. The product is exact */
	xx.l = x8 + t4;	/* that will minimized the rounding error in xx.l */
	return (xx);
}

/* INDENT OFF */
static const double
	/* 0.134861805732790769689793935774652917006 */
	t0z1   =  0.1348618057327907737708,
	t0z1_l = -4.0810077708578299022531e-18,
	/* 0.461632144968362341262659542325721328468 */
	t0z2   =  0.4616321449683623567850,
	t0z2_l = -1.5522348162858676890521e-17,
	/* 0.819773101100500601787868704921606996312 */
	t0z3   =  0.8197731011005006118708,
	t0z3_l = -1.0082945122487103498325e-17;
	/* 1.134861805732790769689793935774652917006 */
/* INDENT ON */

/* gamma(x+i) for 0 <= x < 1  */
static struct Double
gam_n(int i, double x) {
	struct Double rr = {0.0L, 0.0L}, yy;
	double r1, r2, t2, z, xh, xl, yh, yl, zh, z1, z2, zl, x5, wh, wl;

	/* compute yy = gamma(x+1) */
	if (x > 0.2845) {
		if (x > 0.6374) {
			r1 = x - t0z3;
			r2 = (double) ((float) (r1 - t0z3_l));
			t2 = r1 - r2;
			yy = GT3(r2, t2 - t0z3_l);
		} else {
			r1 = x - t0z2;
			r2 = (double) ((float) (r1 - t0z2_l));
			t2 = r1 - r2;
			yy = GT2(r2, t2 - t0z2_l);
		}
	} else {
		r1 = x - t0z1;
		r2 = (double) ((float) (r1 - t0z1_l));
		t2 = r1 - r2;
		yy = GT1(r2, t2 - t0z1_l);
	}

	/* compute gamma(x+i) = (x+i-1)*...*(x+1)*yy, 0<i<8 */
	switch (i) {
	case 0:		/* yy/x */
		r1 = one / x;
		xh = (double) ((float) x);	/* x is not tiny */
		rr.h = (double) ((float) ((yy.h + yy.l) * r1));
		rr.l = r1 * (yy.h - rr.h * xh) -
			((r1 * rr.h) * (x - xh) - r1 * yy.l);
		break;
	case 1:		/* yy */
		rr.h = yy.h;
		rr.l = yy.l;
		break;
	case 2:		/* (x+1)*yy */
		z = x + one;	/* may not be exact */
		zh = (double) ((float) z);
		rr.h = zh * yy.h;
		rr.l = z * yy.l + (x - (zh - one)) * yy.h;
		break;
	case 3:		/* (x+2)*(x+1)*yy */
		z1 = x + one;
		z2 = x + 2.0;
		z = z1 * z2;
		xh = (double) ((float) z);
		zh = (double) ((float) z1);
		xl = (x - (zh - one)) * (z2 + zh) - (xh - zh * (zh + one));
		rr.h = xh * yy.h;
		rr.l = z * yy.l + xl * yy.h;
		break;

	case 4:		/* (x+1)*(x+3)*(x+2)*yy */
		z1 = x + 2.0;
		z2 = (x + one) * (x + 3.0);
		zh = z1;
		__LO(zh) = 0;
		__HI(zh) &= 0xfffffff8;	/* zh 18 bits mantissa */
		zl = x - (zh - 2.0);
		z = z1 * z2;
		xh = (double) ((float) z);
		xl = zl * (z2 + zh * (z1 + zh)) - (xh - zh * (zh * zh - one));
		rr.h = xh * yy.h;
		rr.l = z * yy.l + xl * yy.h;
		break;
	case 5:		/* ((x+1)*(x+4)*(x+2)*(x+3))*yy */
		z1 = x + 2.0;
		z2 = x + 3.0;
		z = z1 * z2;
		zh = (double) ((float) z1);
		yh = (double) ((float) z);
		yl = (x - (zh - 2.0)) * (z2 + zh) - (yh - zh * (zh + one));
		z2 = z - 2.0;
		z *= z2;
		xh = (double) ((float) z);
		xl = yl * (z2 + yh) - (xh - yh * (yh - 2.0));
		rr.h = xh * yy.h;
		rr.l = z * yy.l + xl * yy.h;
		break;
	case 6:		/* ((x+1)*(x+2)*(x+3)*(x+4)*(x+5))*yy */
		z1 = x + 2.0;
		z2 = x + 3.0;
		z = z1 * z2;
		zh = (double) ((float) z1);
		yh = (double) ((float) z);
		z1 = x - (zh - 2.0);
		yl = z1 * (z2 + zh) - (yh - zh * (zh + one));
		z2 = z - 2.0;
		x5 = x + 5.0;
		z *= z2;
		xh = (double) ((float) z);
		zh += 3.0;
		xl = yl * (z2 + yh) - (xh - yh * (yh - 2.0));
						/* xh+xl=(x+1)*...*(x+4) */
		/* wh+wl=(x+5)*yy */
		wh = (double) ((float) (x5 * (yy.h + yy.l)));
		wl = (z1 * yy.h + x5 * yy.l) - (wh - zh * yy.h);
		rr.h = wh * xh;
		rr.l = z * wl + xl * wh;
		break;
	case 7:		/* ((x+1)*(x+2)*(x+3)*(x+4)*(x+5)*(x+6))*yy */
		z1 = x + 3.0;
		z2 = x + 4.0;
		z = z2 * z1;
		zh = (double) ((float) z1);
		yh = (double) ((float) z);	/* yh+yl = (x+3)(x+4) */
		yl = (x - (zh - 3.0)) * (z2 + zh) - (yh - (zh * (zh + one)));
		z1 = x + 6.0;
		z2 = z - 2.0;	/* z2 = (x+2)*(x+5) */
		z *= z2;
		xh = (double) ((float) z);
		xl = yl * (z2 + yh) - (xh - yh * (yh - 2.0));
						/* xh+xl=(x+2)*...*(x+5) */
		/* wh+wl=(x+1)(x+6)*yy */
		z2 -= 4.0;	/* z2 = (x+1)(x+6) */
		wh = (double) ((float) (z2 * (yy.h + yy.l)));
		wl = (z2 * yy.l + yl * yy.h) - (wh - (yh - 6.0) * yy.h);
		rr.h = wh * xh;
		rr.l = z * wl + xl * wh;
	}
	return (rr);
}

double
tgamma(double x) {
	struct Double ss, ww;
	double t, t1, t2, t3, t4, t5, w, y, z, z1, z2, z3, z5;
	int i, j, k, m, ix, hx, xk;
	unsigned lx;

	hx = __HI(x);
	lx = __LO(x);
	ix = hx & 0x7fffffff;
	y = x;

	if (ix < 0x3ca00000)
		return (one / x);	/* |x| < 2**-53 */
	if (ix >= 0x7ff00000)
			/* +Inf -> +Inf, -Inf or NaN -> NaN */
		return (x * ((hx < 0)? 0.0 : x));
	if (hx > 0x406573fa ||	/* x > 171.62... overflow to +inf */
	    (hx == 0x406573fa && lx > 0xE561F647)) {
		z = x / tiny;
		return (z * z);
	}
	if (hx >= 0x40200000) {	/* x >= 8 */
		ww = large_gam(x, &m);
		w = ww.h + ww.l;
		__HI(w) += m << 20;
		return (w);
	}
	if (hx > 0) {		/* 0 < x < 8 */
		i = (int) x;
		ww = gam_n(i, x - (double) i);
		return (ww.h + ww.l);
	}

	/* negative x */
	/* INDENT OFF */
	/*
	 * compute: xk =
	 *	-2 ... x is an even int (-inf is even)
	 *	-1 ... x is an odd int
	 *	+0 ... x is not an int but chopped to an even int
	 *	+1 ... x is not an int but chopped to an odd int
	 */
	/* INDENT ON */
	xk = 0;
	if (ix >= 0x43300000) {
		if (ix >= 0x43400000)
			xk = -2;
		else
			xk = -2 + (lx & 1);
	} else if (ix >= 0x3ff00000) {
		k = (ix >> 20) - 0x3ff;
		if (k > 20) {
			j = lx >> (52 - k);
			if ((j << (52 - k)) == lx)
				xk = -2 + (j & 1);
			else
				xk = j & 1;
		} else {
			j = ix >> (20 - k);
			if ((j << (20 - k)) == ix && lx == 0)
				xk = -2 + (j & 1);
			else
				xk = j & 1;
		}
	}
	if (xk < 0)
		/* ideally gamma(-n)= (-1)**(n+1) * inf, but c99 expect NaN */
		return ((x - x) / (x - x));		/* 0/0 = NaN */


	/* negative underflow thresold */
	if (ix > 0x4066e000 || (ix == 0x4066e000 && lx > 11)) {
		/* x < -183.0 - 11ulp */
		z = tiny / x;
		if (xk == 1)
			z = -z;
		return (z * tiny);
	}

	/* now compute gamma(x) by  -1/((sin(pi*y)/pi)*gamma(1+y)), y = -x */

	/*
	 * First compute ss = -sin(pi*y)/pi , so that
	 * gamma(x) = 1/(ss*gamma(1+y))
	 */
	y = -x;
	j = (int) y;
	z = y - (double) j;
	if (z > 0.3183098861837906715377675)
		if (z > 0.6816901138162093284622325)
			ss = kpsin(one - z);
		else
			ss = kpcos(0.5 - z);
	else
		ss = kpsin(z);
	if (xk == 0) {
		ss.h = -ss.h;
		ss.l = -ss.l;
	}

	/* Then compute ww = gamma(1+y), note that result scale to 2**m */
	m = 0;
	if (j < 7) {
		ww = gam_n(j + 1, z);
	} else {
		w = y + one;
		if ((lx & 1) == 0) {	/* y+1 exact (note that y<184) */
			ww = large_gam(w, &m);
		} else {
			t = w - one;
			if (t == y) {	/* y+one exact */
				ww = large_gam(w, &m);
			} else {	/* use y*gamma(y) */
				if (j == 7)
					ww = gam_n(j, z);
				else
					ww = large_gam(y, &m);
				t4 = ww.h + ww.l;
				t1 = (double) ((float) y);
				t2 = (double) ((float) t4);
						/* t4 will not be too large */
				ww.l = y * (ww.l - (t2 - ww.h)) + (y - t1) * t2;
				ww.h = t1 * t2;
			}
		}
	}

	/* compute 1/(ss*ww) */
	t3 = ss.h + ss.l;
	t4 = ww.h + ww.l;
	t1 = (double) ((float) t3);
	t2 = (double) ((float) t4);
	z1 = ss.l - (t1 - ss.h);	/* (t1,z1) = ss */
	z2 = ww.l - (t2 - ww.h);	/* (t2,z2) = ww */
	t3 = t3 * t4;			/* t3 = ss*ww */
	z3 = one / t3;			/* z3 = 1/(ss*ww) */
	t5 = t1 * t2;
	z5 = z1 * t4 + t1 * z2;		/* (t5,z5) = ss*ww */
	t1 = (double) ((float) t3);	/* (t1,z1) = ss*ww */
	z1 = z5 - (t1 - t5);
	t2 = (double) ((float) z3);	/* leading 1/(ss*ww) */
	z2 = z3 * (t2 * z1 - (one - t2 * t1));
	z = t2 - z2;

	/* check whether z*2**-m underflow */
	if (m != 0) {
		hx = __HI(z);
		i = hx & 0x80000000;
		ix = hx ^ i;
		j = ix >> 20;
		if (j > m) {
			ix -= m << 20;
			__HI(z) = ix ^ i;
		} else if ((m - j) > 52) {
			/* underflow */
			if (xk == 0)
				z = -tiny * tiny;
			else
				z = tiny * tiny;
		} else {
			/* subnormal */
			m -= 60;
			t = one;
			__HI(t) -= 60 << 20;
			ix -= m << 20;
			__HI(z) = ix ^ i;
			z *= t;
		}
	}
	return (z);
}
