/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RPC_TRACE_H
#define	_RPC_TRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Trace point definitions.
 *
 * The trace point definitions follow stringent conventions for the benefit
 * of postprocessors wishing to manipulate trace information.  The names
 * all start with TR_, and each definition is followed by a comment whose
 * content is a printf-like formatting string.  Successive format items are
 * fed by successive tr_datum* values from the current trace item.  The only
 * unusual format is %C, which is followed by an angle bracketed, comma
 * separated list of (unquoted) strings, the i-th of which is to be printed
 * when the associated value is i (0-origin).
 *
 * Note that the current trace points confine themselves to the C, d, and
 * x formats so that postprocessors can confine themselves to supporting
 * only these formats.  This situation may change when additional trace
 * points are defined.
 */

#define	TR_Dialout 1
#define	TR___add_group 2
#define	TR___alloc_mbrs 3
#define	TR___authenticate 4
#define	TR___bind_rpc 5
#define	TR___break_name 6
#define	TR___buf 7
#define	TR___callback_error 8
#define	TR___callback_finish 9
#define	TR___callback_stub 10
#define	TR___clnt_create_loopback  11
#define	TR___core_lookup 12
#define	TR___cvt2attr 13
#define	TR___default_domain 14
#define	TR___des_crypt 15
#define	TR___des_encrypt  16
#define	TR___des_setkey  17
#define	TR___do_callback 18
#define	TR___do_ismember 19
#define	TR___domainname 20
#define	TR___free_list 21
#define	TR___get_clnt_uaddr 22
#define	TR___get_group 23
#define	TR___get_local_names 24
#define	TR___get_obj_defaults 25
#define	TR___get_ti_clnt 26
#define	TR___getclnt 27
#define	TR___hostdata 28
#define	TR___implicit_member 29
#define	TR___insert_entry 30
#define	TR___insert_group 31
#define	TR___insert_list 32
#define	TR___make_binding 33
#define	TR___map_addr 34
#define	TR___msgout 35
#define	TR___name_distance 36
#define	TR___name_hash 37
#define	TR___nextsep_of 38
#define	TR___nis_clnt_ibops 39
#define	TR___nis_clnt_nameops 40
#define	TR___nis_get_server 41
#define	TR___nis_init_callback 42
#define	TR___nis_librand 43
#define	TR___nis_map_group 44
#define	TR___nis_path_list 45
#define	TR___nis_pingproc 46
#define	TR___nis_run_callback 47
#define	TR___nis_tagproc 48
#define	TR___remove_entry 49
#define	TR___remove_group 50
#define	TR___rpc_dtbsize 51
#define	TR___rpc_endconf 52
#define	TR___rpc_get_a_size 53
#define	TR___rpc_get_default_domain 54
#define	TR___rpc_get_local_uid 55
#define	TR___rpc_get_t_size 56
#define	TR___rpc_getconf 57
#define	TR___rpc_getconfip 58
#define	TR___rpc_negotiate_uid 59
#define	TR___rpc_openchild 60
#define	TR___rpc_select_to_poll 61
#define	TR___rpc_setconf 62
#define	TR___rpc_timeval_to_msec 63
#define	TR___rpc_trace 64
#define	TR___rpcgettp 65
#define	TR___seterr_reply 66
#define	TR___simple_lookup 67
#define	TR___stop_clock 68
#define	TR___svcauth_des 69
#define	TR___svcauth_null 70
#define	TR___svcauth_short 71
#define	TR___svcauth_sys 72
#define	TR___svcauth_unix 73
#define	TR___yp_dobind 74
#define	TR__alloc_buf 75
#define	TR__dummy 76
#define	TR__null_tiptr 77
#define	TR__rcv_conn_con 78
#define	TR__snd_conn_req 79
#define	TR__t_aligned_copy 80
#define	TR__t_alloc_bufs 81
#define	TR__t_blocksigpoll 82
#define	TR__t_checkfd 83
#define	TR__t_do_ioctl 84
#define	TR__t_is_event 85
#define	TR__t_is_ok 86
#define	TR__t_max 87
#define	TR__t_putback 88
#define	TR__t_restore_state 89
#define	TR__t_setsize 90
#define	TR_accepted 91
#define	TR_addProto 92
#define	TR_add_entry_1 93
#define	TR_additem 94
#define	TR_alarmtr 95
#define	TR_altconn 96
#define	TR_ask 97
#define	TR_assert 98
#define	TR_auth_destroy 99
#define	TR_auth_errmsg 100
#define	TR_authdes_create 101
#define	TR_authdes_destroy 102
#define	TR_authdes_getucred  103
#define	TR_authdes_marshal  104
#define	TR_authdes_nextverf  105
#define	TR_authdes_ops  106
#define	TR_authdes_pk_seccreate 107
#define	TR_authdes_refresh  108
#define	TR_authdes_seccreate  109
#define	TR_authdes_validate  110
#define	TR_authnone_create  111
#define	TR_authnone_destroy  112
#define	TR_authnone_marshal  113
#define	TR_authnone_ops  114
#define	TR_authnone_refresh  115
#define	TR_authnone_validate  116
#define	TR_authnone_verf  117
#define	TR_authsys_create  118
#define	TR_authsys_create_default  119
#define	TR_authsys_destroy  120
#define	TR_authsys_marshal  121
#define	TR_authsys_nextverf  122
#define	TR_authsys_ops  123
#define	TR_authsys_refresh  124
#define	TR_authsys_validate  125
#define	TR_bin2hex  126
#define	TR_bindresvport  127
#define	TR_blank  128
#define	TR_bsfix  129
#define	TR_cache_get  130
#define	TR_cache_init  131
#define	TR_cache_ref  132
#define	TR_cache_set  133
#define	TR_cache_spot  134
#define	TR_cache_victim  135
#define	TR_calchash  136
/*	#define	TR_callit  137			obsolete */
#define	TR_callrpc  138
#define	TR_cbc_crypt  139
#define	TR_chat  140
#define	TR_check_binding  141
#define	TR_check_version  142
#define	TR_chkblk  143
#define	TR_cklock  144
#define	TR_classmatch  145
#define	TR_cleanup  146
#define	TR_clnt_broadcast  147
#define	TR_clnt_call  148
#define	TR_clnt_com_create  149
#define	TR_clnt_control  150
#define	TR_clnt_create  151
#define	TR_clnt_create_vers  152
#define	TR_clnt_destroy  153
#define	TR_clnt_dg_abort  154
#define	TR_clnt_dg_call  155
#define	TR_clnt_dg_control  156
#define	TR_clnt_dg_create  157
#define	TR_clnt_dg_destroy  158
#define	TR_clnt_dg_freeres  159
#define	TR_clnt_dg_geterr  160
#define	TR_clnt_dg_ops  161
#define	TR_clnt_freeres  162
#define	TR_clnt_geterr  163
#define	TR_clnt_pcreateerror  164
#define	TR_clnt_perrno  165
#define	TR_clnt_perror  166
#define	TR_clnt_raw_abort  167
#define	TR_clnt_raw_call  168
#define	TR_clnt_raw_control  169
#define	TR_clnt_raw_create  170
#define	TR_clnt_raw_destroy  171
#define	TR_clnt_raw_freeres  172
#define	TR_clnt_raw_geterr  173
#define	TR_clnt_raw_ops  174
#define	TR_clnt_spcreateerror  175
#define	TR_clnt_sperrno  176
#define	TR_clnt_sperror  177
#define	TR_clnt_tli_create  178
#define	TR_clnt_tp_create  179
#define	TR_clnt_vc_abort  180
#define	TR_clnt_vc_call  181
#define	TR_clnt_vc_control  182
#define	TR_clnt_vc_create  183
#define	TR_clnt_vc_destroy  184
#define	TR_clnt_vc_freeres  185
#define	TR_clnt_vc_geterr  186
#define	TR_clnt_vc_ops  187
#define	TR_clntraw_create  188
#define	TR_clnttcp_create  189
#define	TR_clntudp_bufcreate  190
#define	TR_clntudp_create  191
#define	TR_cmpdatum  192
#define	TR_comment  193
#define	TR_common_crypt  194
#define	TR_conn  195
#define	TR_currdev  196
#define	TR_currdial  197
#define	TR_currsys  198
#define	TR_dbm_access  199
#define	TR_dbmclose  200
#define	TR_dbmflush  201
#define	TR_dbminit  202
#define	TR_delete  203
#define	TR_delitem  204
#define	TR_delock  205
#define	TR_des_setparity  206
#define	TR_detachnode  207
#define	TR_devreset  208
#define	TR_dial  209
#define	TR_dial801  210
#define	TR_dialreset  211
#define	TR_dkbreak  212
#define	TR_dkcall  213
#define	TR_dkdial  214
#define	TR_dkerr  215
#define	TR_dkerrmap  216
#define	TR_dkminor  217
#define	TR_dkndial  218
#define	TR_dksetup  219
#define	TR_dkteardown  220
#define	TR_do_accept 221
#define	TR_doassign  222
#define	TR_dobase  223
#define	TR_doconfig  224
#define	TR_dofirst  225
#define	TR_domaster  226
#define	TR_domatch  227
#define	TR_donext  228
#define	TR_doorder  229
#define	TR_dopop  230
#define	TR_dopush  231
#define	TR_dorun  232
#define	TR_dots_in_name  233
#define	TR_dtnamer  234
#define	TR_eaccess  235
#define	TR_eatwhite  236
#define	TR_ecb_crypt  237
#define	TR_endhostent  238
#define	TR_endnetconfig  239
#define	TR_endnetpath  240
#define	TR_endrpcent  241
#define	TR_err_conv  242
#define	TR_expect  243
#define	TR_exphone  244
#define	TR_extract_secret 245
#define	TR_fd_cklock  246
#define	TR_fd_mklock  247
#define	TR_fd_rmlock  248
#define	TR_fdig  249
#define	TR_fetch  250
#define	TR_ffs  251
#define	TR_fgetnetconfig  252
#define	TR_fill_input_buf  253
#define	TR_findProto  254
#define	TR_finds  255
#define	TR_firsthash  256
#define	TR_firstkey  257
#define	TR_fix_buf_size  258
#define	TR_fixline  259
#define	TR_flush_out  260
#define	TR_fn_cklock  261
#define	TR_forder  262
#define	TR_free_entry  263
#define	TR_free_name_item  264
#define	TR_freenetconfigent  265
#define	TR_freenode  266
#define	TR_gdial  267
#define	TR_getProto  268
#define	TR_get_default_domain  269
#define	TR_get_input_bytes  270
#define	TR_get_myaddress  271
#define	TR_getargs  272
#define	TR_getbit  273
#define	TR_getbroadcastnets  274
#define	TR_getbyte  275
#define	TR_getclnt  276
#define	TR_getclnthandle  277
#define	TR_getdesfd  278
#define	TR_getdevline  279
#define	TR_getdialline  280
#define	TR_getdomainname  281
#define	TR_getflag  282
#define	TR_getgroups  283
#define	TR_gethostbyaddr  284
#define	TR_gethostbynamadr  285
#define	TR_gethostbyname  286
#define	TR_gethostent  287
#define	TR_gethostname  288
#define	TR_getkeys_files 289
#define	TR_getkeys_nis 290
#define	TR_getkeys_nisplus 291
#define	TR_getkeyserv_handle  292
#define	TR_getline  293
#define	TR_getlookups  294
#define	TR_getname  295
#define	TR_getnetconfig  296
#define	TR_getnetconfigent  297
#define	TR_getnetid  298
#define	TR_getnetid_files 299
#define	TR_getnetid_nis 300
#define	TR_getnetid_nisplus 301
#define	TR_getnetlist  302
#define	TR_getnetname  303
#define	TR_getnetpath  304
#define	TR_getnettype  305
#define	TR_getnlookups  306
#define	TR_getpop  307
#define	TR_getpublicandprivatekey  308
#define	TR_getpublickey  309
#define	TR_getpush  310
/* #define	TR_getrpcbynamadr  311 		obsolete */
#define	TR_getrpcbyname  312
#define	TR_getrpcbynumber  313
#define	TR_getrpcent  314
#define	TR_getsecretkey  315
#define	TR_getsysline  316
#define	TR_getto  317
#define	TR_gettoken  318
#define	TR_getvalue  319
#define	TR_got_entry 320
#define	TR_harmless  321
#define	TR_hashinc  322
#define	TR_hex2bin  323
#define	TR_hexval  324
#define	TR_host2netname  325
#define	TR_ifdate  326
#define	TR_inet_addr  327
#define	TR_inet_netof  328
#define	TR_inet_ntoa  329
#define	TR_interface  330
#define	TR_invalidate  331
#define	TR_ioctl  332
#define	TR_key_call  333
#define	TR_key_decryptsession  334
#define	TR_key_decryptsession_pk  335
#define	TR_key_encryptsession  336
#define	TR_key_encryptsession_pk  337
#define	TR_key_gendes  338
#define	TR_key_setsecret  339
#define	TR_load_dom_binding  340
#define	TR_load_xlate  341
#define	TR_local_rpcb  342
#define	TR_logent  343
#define	TR_makdatum  344
#define	TR_makefd_xprt  345
#define	TR_makenode  346
#define	TR_marshal_new_auth  347
#define	TR_memcp  348
#define	TR_mergeProto  349
#define	TR_mklock  350
#define	TR_mlock  351
#define	TR_msgout  352
#define	TR_namematch  353
#define	TR_nameparse  354
#define	TR_nap  355
#define	TR_nc_perror  356
#define	TR_nc_sperror  357
#define	TR_negotiate_broadcast  358
#define	TR_netconfig_dup  359
#define	TR_netconfig_free  360
#define	TR_netdir_free  361
#define	TR_netdir_getbyaddr  362
#define	TR_netdir_getbyname  363
#define	TR_netdir_options  364
#define	TR_netdir_perror  365
#define	TR_netdir_sperror  366
#define	TR_netlist_free  367
#define	TR_netname2host  368
#define	TR_netname2user  369
#define	TR_newborn  370
#define	TR_nextProto  371
#define	TR_nextdevices  372
#define	TR_nextdialers  373
#define	TR_nextkey  374
#define	TR_nextsystems  375
#define	TR_nis_add  376
#define	TR_nis_add_clnt  377
#define	TR_nis_add_entry  378
#define	TR_nis_addmember  379
#define	TR_nis_callback_clnt  380
#define	TR_nis_checkpoint  381
#define	TR_nis_checkpoint_clnt  382
#define	TR_nis_clone_object  383
#define	TR_nis_cptime_clnt  384
#define	TR_nis_creategroup  385
#define	TR_nis_data  386
#define	TR_nis_destroy_object  387
#define	TR_nis_destroygroup  388
#define	TR_nis_dir_cmp  389
#define	TR_nis_domain_of  390
#define	TR_nis_dump  391
#define	TR_nis_dump_clnt  392
#define	TR_nis_dumplog  393
#define	TR_nis_dumplog_clnt  394
#define	TR_nis_find_item  395
#define	TR_nis_finddirectory  396
#define	TR_nis_finddirectory_clnt  397
#define	TR_nis_first_entry  398
#define	TR_nis_flush_namelist  399
#define	TR_nis_flush_table  400
#define	TR_nis_flushgroups  401
#define	TR_nis_free_request  402
#define	TR_nis_freenames  403
#define	TR_nis_freeresult  404
#define	TR_nis_freeservlist  405
#define	TR_nis_get_object  406
#define	TR_nis_get_request  407
#define	TR_nis_get_static_storage  408
#define	TR_nis_getdtblsize  409
#define	TR_nis_getnames  410
#define	TR_nis_getservlist  411
#define	TR_nis_ibadd_clnt  412
#define	TR_nis_ibfirst_clnt  413
#define	TR_nis_iblist_clnt  414
#define	TR_nis_ibmodify_clnt  415
#define	TR_nis_ibnext_clnt  416
#define	TR_nis_ibremove_clnt  417
#define	TR_nis_in_table  418
#define	TR_nis_insert_item  419
#define	TR_nis_insert_name  420
#define	TR_nis_ismember  421
#define	TR_nis_leaf_of  422
#define	TR_nis_lerror  423
#define	TR_nis_list  424
#define	TR_nis_local_directory  425
#define	TR_nis_local_group  426
#define	TR_nis_local_host  427
#define	TR_nis_local_principal  428
#define	TR_nis_lookup  429
#define	TR_nis_lookup_clnt  430
#define	TR_nis_make_error  431
#define	TR_nis_make_rpchandle  432
#define	TR_nis_mkdir  433
#define	TR_nis_mkdir_clnt  434
#define	TR_nis_modify  435
#define	TR_nis_modify_clnt  436
#define	TR_nis_modify_entry  437
#define	TR_nis_name_of  438
#define	TR_nis_next_entry  439
#define	TR_nis_perror  440
#define	TR_nis_ping  441
#define	TR_nis_ping_clnt  442
#define	TR_nis_pop_item  443
#define	TR_nis_print_directory  444
#define	TR_nis_print_entry  445
#define	TR_nis_print_group  446
#define	TR_nis_print_group_entry  447
#define	TR_nis_print_link  448
#define	TR_nis_print_object  449
#define	TR_nis_print_rights  450
#define	TR_nis_print_server  451
#define	TR_nis_print_table  452
#define	TR_nis_read_obj  453
#define	TR_nis_remove  454
#define	TR_nis_remove_clnt  455
#define	TR_nis_remove_entry  456
#define	TR_nis_remove_item  457
#define	TR_nis_remove_name  458
#define	TR_nis_removemember  459
#define	TR_nis_rmdir  460
#define	TR_nis_rmdir_clnt  461
#define	TR_nis_servstate  462
#define	TR_nis_servstate_clnt  463
#define	TR_nis_sperrno  464
#define	TR_nis_sperror  465
#define	TR_nis_stats  466
#define	TR_nis_status_clnt  467
#define	TR_nis_verifygroup  468
#define	TR_nis_write_obj  469
#define	TR_notin  470
#define	TR_onelock  471
#define	TR_open801  472
#define	TR_parsedata 473
#define	TR_passwd2des  474
#define	TR_pmap_getmaps  475
#define	TR_pmap_getport  476
#define	TR_pmap_rmtcall  477
#define	TR_pmap_set  478
#define	TR_pmap_unset  479
#define	TR_pop_push  480
#define	TR_print_column  481
#define	TR_processdev  482
#define	TR_prog_dispatch  483
#define	TR_protoString  484
#define	TR_rddev  485
#define	TR_read_coldstart_1  486
#define	TR_read_vc  487
#define	TR_registerrpc  488
#define	TR_rejected  489
#define	TR_removeProto  490
#define	TR_remove_entry_1  491
#define	TR_rendezvous_request  492
#define	TR_rendezvous_stat  493
#define	TR_repphone  494
#define	TR_restline  495
#define	TR_rmlock  496
#define	TR_rpc_broadcast  497
#define	TR_rpc_call  498
#define	TR_rpc_nullproc  499
#define	TR_rpc_reg  500
#define	TR_rpc_wrap_bcast  501
#define	TR_rpcb_getaddr  502
#define	TR_rpcb_getmaps  503
#define	TR_rpcb_gettime  504
#define	TR_rpcb_rmtcall  505
#define	TR_rpcb_set  506
#define	TR_rpcb_taddr2uaddr  507
#define	TR_rpcb_uaddr2taddr  508
#define	TR_rpcb_unset  509
#define	TR_rtime_tli  510
#define	TR_savline  511
#define	TR_scancfg  512
#define	TR_scansys  513
#define	TR_sendthem  514
#define	TR_set_input_fragment  515
#define	TR_setalarm  516
#define	TR_setbit  517
#define	TR_setconfig  518
#define	TR_setdevcfg  519
#define	TR_setdomainname  520
#define	TR_setfile  521
#define	TR_sethostent  522
#define	TR_sethup  523
#define	TR_setioctl  524
#define	TR_setline  525
#define	TR_setnetconfig  526
#define	TR_setnetpath  527
#define	TR_setrpcent  528
#define	TR_setservice  529
#define	TR_shift1left  530
#define	TR_show_tlook  531
#define	TR_skip_input_bytes  532
#define	TR_stlock  533
#define	TR_stoa  534
#define	TR_store  535
#define	TR_strecpy  536
#define	TR_strlocase  537
#define	TR_strsave  538
#define	TR_svc_auth_reg  539
#define	TR_svc_com_create  540
#define	TR_svc_create  541
#define	TR_svc_destroy  542
#define	TR_svc_dg_create  543
#define	TR_svc_dg_destroy  544
#define	TR_svc_dg_enablecache  545
#define	TR_svc_dg_freeargs  546
#define	TR_svc_dg_getargs  547
#define	TR_svc_dg_ops  548
#define	TR_svc_dg_recv  549
#define	TR_svc_dg_reply  550
#define	TR_svc_dg_stat  551
#define	TR_svc_exit  552
#define	TR_svc_fd_create  553
#define	TR_svc_find  554
#define	TR_svc_freeargs  555
#define	TR_svc_getargs  556
#define	TR_svc_getreq  557
#define	TR_svc_getreq_common  558
#define	TR_svc_getreq_poll  559
#define	TR_svc_getreqset  560
#define	TR_svc_getrpccaller  561
#define	TR_svc_raw_create  562
#define	TR_svc_raw_destroy  563
#define	TR_svc_raw_freeargs  564
#define	TR_svc_raw_getargs  565
#define	TR_svc_raw_ops  566
#define	TR_svc_raw_recv  567
#define	TR_svc_raw_reply  568
#define	TR_svc_raw_stat  569
#define	TR_svc_reg  570
#define	TR_svc_register  571
#define	TR_svc_run  572
#define	TR_svc_sendreply  573
#define	TR_svc_tli_create  574
#define	TR_svc_tp_create  575
#define	TR_svc_unreg  576
#define	TR_svc_unregister  577
#define	TR_svc_vc_create  578
#define	TR_svc_vc_destroy  579
#define	TR_svc_vc_freeargs  580
#define	TR_svc_vc_getargs  581
#define	TR_svc_vc_ops  582
#define	TR_svc_vc_recv  583
#define	TR_svc_vc_rendezvous_ops  584
#define	TR_svc_vc_reply  585
#define	TR_svc_vc_stat  586
#define	TR_svc_versquiet  587
#define	TR_svcerr_auth  588
#define	TR_svcerr_decode  589
#define	TR_svcerr_noproc  590
#define	TR_svcerr_noprog  591
#define	TR_svcerr_progvers  592
#define	TR_svcerr_systemerr  593
#define	TR_svcerr_weakauth  594
#define	TR_svcfd_create  595
#define	TR_svcraw_create  596
#define	TR_svctcp_create  597
#define	TR_svcudp_bufcreate  598
#define	TR_svcudp_create  599
#define	TR_synchronize  600
#define	TR_sysaccess  601
#define	TR_sysreset  602
#define	TR_sytcall  603
#define	TR_sytfix2line  604
#define	TR_sytfixline  605
#define	TR_t_accept  606
#define	TR_t_alloc  607
#define	TR_t_bind  608
#define	TR_t_close  609
#define	TR_t_connect  610
#define	TR_t_error  611
#define	TR_t_free  612
#define	TR_t_getinfo  613
#define	TR_t_getname  614
#define	TR_t_getstate  615
#define	TR_t_listen  616
#define	TR_t_look  617
#define	TR_t_open  618
#define	TR_t_optmgmt  619
#define	TR_t_rcv  620
#define	TR_t_rcvall  621
#define	TR_t_rcvconnect  622
#define	TR_t_rcvdis  623
#define	TR_t_rcvrel  624
#define	TR_t_rcvudata  625
#define	TR_t_rcvuderr  626
#define	TR_t_snd  627
#define	TR_t_snddis  628
#define	TR_t_sndrel  629
#define	TR_t_sndudata  630
#define	TR_t_sync  631
#define	TR_t_unbind  632
#define	TR_taddr2uaddr  633
#define	TR_tcpcall  634
#define	TR_tfaillog  635
#define	TR_time_not_ok  636
#define	TR_timout  637
#define	TR_tioctl  638
#define	TR_tlicall  639
#define	TR_tokenize  640
#define	TR_translate  641
#define	TR_tread  642
#define	TR_tsetup  643
#define	TR_tssetup  644
#define	TR_tteardown  645
#define	TR_ttygenbrk  646
#define	TR_twrite  647
#define	TR_uaddr2taddr  648
#define	TR_undial  649
#define	TR_unetcall  650
#define	TR_universal  651
#define	TR_user2netname  652
#define	TR_usetup  653
#define	TR_usingypmap  654
#define	TR_usralarm  655
#define	TR_uteardown  656
#define	TR_wrchr  657
#define	TR_write_vc  658
#define	TR_wrstr  659
#define	TR_x_destroy  660
#define	TR_x_getpostn  661
#define	TR_x_inline  662
#define	TR_x_putbytes  663
#define	TR_x_putlong  664
#define	TR_x_setpostn  665
#define	TR_xdecrypt  666
#define	TR_xdr_accepted_reply  667
#define	TR_xdr_array  668
#define	TR_xdr_authdes_cred  669
#define	TR_xdr_authdes_verf  670
#define	TR_xdr_authkern  671
#define	TR_xdr_authsys_parms  672
#define	TR_xdr_bool  673
#define	TR_xdr_bytes  674
#define	TR_xdr_callhdr  675
#define	TR_xdr_callmsg  676
#define	TR_xdr_cback_data  677
#define	TR_xdr_char  678
#define	TR_xdr_cp_result  679
#define	TR_xdr_cryptkeyarg  680
#define	TR_xdr_cryptkeyres  681
#define	TR_xdr_datum  682
#define	TR_xdr_des_block  683
#define	TR_xdr_destroy  684
#define	TR_xdr_directory_obj  685
#define	TR_xdr_double  686
#define	TR_xdr_dump_args  687
#define	TR_xdr_endpoint  688
#define	TR_xdr_entry_col  689
#define	TR_xdr_entry_obj  690
#define	TR_xdr_enum  691
#define	TR_xdr_fd_args  692
#define	TR_xdr_fd_result  693
#define	TR_xdr_float  694
#define	TR_xdr_free  695
#define	TR_xdr_getcredres  696
#define	TR_xdr_getpos  697
#define	TR_xdr_gid_t  698
#define	TR_xdr_group_obj  699
#define	TR_xdr_hyper 700
#define	TR_xdr_ib_request  701
#define	TR_xdr_inline  702
#define	TR_xdr_int  703
#define	TR_xdr_keybuf  704
#define	TR_xdr_keystatus  705
#define	TR_xdr_link_obj  706
#define	TR_xdr_log_entry  707
#define	TR_xdr_log_entry_t  708
#define	TR_xdr_log_result  709
#define	TR_xdr_long  710
#define	TR_xdr_longlong_t 711
#define	TR_xdr_netbuf  712
#define	TR_xdr_netconfig  713
#define	TR_xdr_netnamestr  714
#define	TR_xdr_netobj  715
#define	TR_xdr_nis_attr  716
#define	TR_xdr_nis_error  717
#define	TR_xdr_nis_name  718
#define	TR_xdr_nis_object  719
#define	TR_xdr_nis_oid  720
#define	TR_xdr_nis_result  721
#define	TR_xdr_nis_server  722
#define	TR_xdr_nis_tag  723
#define	TR_xdr_nis_taglist  724
#define	TR_xdr_ns_request  725
#define	TR_xdr_nstype  726
#define	TR_xdr_oar_mask  727
#define	TR_xdr_obj_p  728
#define	TR_xdr_objdata  729
#define	TR_xdr_opaque  730
#define	TR_xdr_opaque_auth  731
#define	TR_xdr_ping_args  732
#define	TR_xdr_pmap  733
#define	TR_xdr_pmaplist  734
#define	TR_xdr_pmaplist_ptr 735
#define	TR_xdr_pointer  736
#define	TR_xdr_quadruple 737
#define	TR_xdr_reference  738
#define	TR_xdr_rejected_reply  739
#define	TR_xdr_replymsg  740
#define	TR_xdr_rmtcall_args  741
#define	TR_xdr_rmtcallargs 742
#define	TR_xdr_rmtcallres  743
#define	TR_xdr_rpcb  744
#define	TR_xdr_rpcb_addrp  745
#define	TR_xdr_rpcb_entry  746
#define	TR_xdr_rpcb_entry_list  747
#define	TR_xdr_rpcb_entry_list_ptr 748
#define	TR_xdr_rpcb_rmtcallargs  749
#define	TR_xdr_rpcb_rmtcalllistp  750
#define	TR_xdr_rpcb_rmtcallres  751
#define	TR_xdr_rpcb_stat  752
#define	TR_xdr_rpcb_stat_byvers 753
#define	TR_xdr_rpcblist  754
#define	TR_xdr_rpcblist_ptr 755
#define	TR_xdr_rpcbs_addrlist  756
#define	TR_xdr_rpcbs_addrlist_ptr 757
#define	TR_xdr_rpcbs_proc  758
#define	TR_xdr_rpcbs_rmtcalllist  759
#define	TR_xdr_rpcbs_rmtcalllist_ptr 760
#define	TR_xdr_setpos  761
#define	TR_xdr_short  762
#define	TR_xdr_sizeof  763
#define	TR_xdr_string  764
#define	TR_xdr_table_col  765
#define	TR_xdr_table_obj  766
#define	TR_xdr_u_char  767
#define	TR_xdr_u_hyper 768
#define	TR_xdr_u_int  769
#define	TR_xdr_u_long  770
#define	TR_xdr_u_longlong_t 771
#define	TR_xdr_u_short  772
#define	TR_xdr_uid_t  773
#define	TR_xdr_union  774
#define	TR_xdr_unixcred  775
#define	TR_xdr_vector  776
#define	TR_xdr_void  777
#define	TR_xdr_wrapstring  778
#define	TR_xdr_yp_buf  779
#define	TR_xdr_ypall  780
#define	TR_xdr_ypbind_binding  781
#define	TR_xdr_ypbind_domain  782
#define	TR_xdr_ypbind_resp  783
#define	TR_xdr_ypbind_resptype  784
#define	TR_xdr_ypbind_setdom  785
#define	TR_xdr_ypdelete_args  786
#define	TR_xdr_ypdomain_wrap_string  787
#define	TR_xdr_ypmap_parms  788
#define	TR_xdr_ypmap_wrap_string  789
#define	TR_xdr_ypmaplist  790
#define	TR_xdr_ypmaplist_wrap_string  791
#define	TR_xdr_ypowner_wrap_string  792
#define	TR_xdr_yppushresp_xfr  793
#define	TR_xdr_ypreq_key  794
#define	TR_xdr_ypreq_newname_string  795
#define	TR_xdr_ypreq_newxfr  796
#define	TR_xdr_ypreq_nokey  797
#define	TR_xdr_ypreq_xfr  798
#define	TR_xdr_ypresp_key_val  799
#define	TR_xdr_ypresp_maplist  800
#define	TR_xdr_ypresp_master  801
#define	TR_xdr_ypresp_order  802
#define	TR_xdr_ypresp_val  803
#define	TR_xdr_ypupdate_args  804
#define	TR_xdr_zotypes  805
#define	TR_xdrmbuf_destroy  806
#define	TR_xdrmbuf_getbytes  807
#define	TR_xdrmbuf_getlong  808
#define	TR_xdrmbuf_getmbuf  809
#define	TR_xdrmbuf_getpos  810
#define	TR_xdrmbuf_init  811
#define	TR_xdrmbuf_inline  812
#define	TR_xdrmbuf_putbuf  813
#define	TR_xdrmbuf_putbytes  814
#define	TR_xdrmbuf_putlong  815
#define	TR_xdrmbuf_setpos  816
#define	TR_xdrmem_create  817
#define	TR_xdrmem_destroy  818
#define	TR_xdrmem_getbytes  819
#define	TR_xdrmem_getlong  820
#define	TR_xdrmem_getpos  821
#define	TR_xdrmem_inline  822
#define	TR_xdrmem_ops  823
#define	TR_xdrmem_putbytes  824
#define	TR_xdrmem_putlong  825
#define	TR_xdrmem_setpos  826
#define	TR_xdrrec_create  827
#define	TR_xdrrec_destroy  828
#define	TR_xdrrec_endofrecord  829
#define	TR_xdrrec_eof  830
#define	TR_xdrrec_getbytes  831
#define	TR_xdrrec_getlong  832
#define	TR_xdrrec_getpos  833
#define	TR_xdrrec_inline  834
#define	TR_xdrrec_ops  835
#define	TR_xdrrec_putbytes  836
#define	TR_xdrrec_putlong  837
#define	TR_xdrrec_setpos  838
#define	TR_xdrrec_skiprecord  839
#define	TR_xdrstdio_create  840
#define	TR_xdrstdio_destroy  841
#define	TR_xdrstdio_getbytes  842
#define	TR_xdrstdio_getlong  843
#define	TR_xdrstdio_getpos  844
#define	TR_xdrstdio_inline  845
#define	TR_xdrstdio_ops  846
#define	TR_xdrstdio_putbytes  847
#define	TR_xdrstdio_putlong  848
#define	TR_xdrstdio_setpos  849
#define	TR_xencrypt  850
#define	TR_xfer  851
#define	TR_xprt_register  852
#define	TR_xprt_unregister  853
#define	TR_yp_all  854
#define	TR_yp_bind  855
#define	TR_yp_first  856
#define	TR_yp_get_default_domain  857
#define	TR_yp_master  858
#define	TR_yp_match  859
#define	TR_yp_next  860
#define	TR_yp_order  861
#define	TR_yp_unbind  862
#define	TR_yp_update  863
#define	TR_ypbindproc_domain_3  864
#define	TR_ypbindproc_null_3  865
#define	TR_ypbindproc_setdom_3  866
#define	TR_yperr_string  867
#define	TR_ypprot_err  868

/*
 * XXX: Added later on by hand and not from a TAGS file.
 * Should get added later automatically.
 */
#define	TR_check_cache	869
#define	TR_delete_cache	870
#define	TR_add_cache	871
#define	TR_rpcb_findaddr	872
#define	TR_svc_control	873
#define	TR_svc_dg_control	874
#define	TR_svc_raw_control	875
#define	TR_svc_vc_control	876
#define	TR___svc_versquiet_get	877
#define	TR___svc_versquiet_on	878
#define	TR___svc_versquiet_off	879

/*
 * XXX: added by hand for netnamer, netname files
 */
#define	TR_user2netname_nisplus 880
#define	TR_user2netname_nis 881
#define	TR_parse_netid_str 882
#define	TR_parse_uid_gidlist 883
#define	TR_parse_uid 884
#define	TR_parse_gidlist 885
#define	TR_netname2user_files 886
#define	TR_netname2user_nis 887
#define	TR_netname2user_nisplus 888

/*
 * XXX: added by hand for key_call.c: key_get_conv.
 */
#define	TR_key_get_conv 889

/*
 * XXX: added by hand during MT safing.
 */
#define	TR__t_look_locked  890
#define	TR__td_setnodelay  891

/*
 * MT-switch interfaces
 */
#define	TR__nss_initf_hosts 892
#define	TR__switch_gethostbyname_r 893
#define	TR__switch_gethostbyaddr_r 894
#define	TR_gethostent_r 895
#define	TR_str2hostent 896
#define	TR_gethostbyname_r 897
#define	TR_gethostbyaddr_r 898

#define	TR__nss_initf_rpc 899
#define	TR_getrpcbyname_r 900
#define	TR_getrpcbynumber_r 901
#define	TR_getrpcent_r 902
#define	TR_str2rpcent 903

/*
 * For key_call.c: key_secretkey_is_set()
 */
#define	TR_key_secretkey_is_set 904

/*
 * for clnt_generic.c: clnt_create_vers_timed()
 */
#define	TR_clnt_create_vers_timed 905

/*
 * for svc_vc.c: rendezvous_control()
 */
#define	TR_rendezvous_control 906
#define	TR___gss_authenticate 907

/*
 * for new functions (XNS Issue 5) in libnsl/nsl
 */

#define	TR_t_sndreldata	908
#define	TR_t_sndv	909
#define	TR_t_sndvudata	910
#define	TR_t_rcvreldata	911
#define	TR_t_rcvv	912
#define	TR_t_rcvvudata	913
#define	TR_t_sysconf	914

/*
 * audit_user
 */
#define	TR__nss_initf_auuser	915
#define	TR_str2auuser		916
#define	TR_setauuser		917
#define	TR_endauuser		918
#define	TR_getauuser		919
#define	TR_getauusernam		920
/*
 * auth_attr
 */
#define	TR__nss_initf_authattr	921
#define	TR_str2authattr		922
#define	TR_setauthattr		923
#define	TR_endauthattr		924
#define	TR_getauthattr		925
#define	TR_getauthnam		926
/*
 * exec_attr
 */
#define	TR__nss_initf_execattr	927
#define	TR_str2execattr		928
#define	TR_setexecattr		929
#define	TR_endexecattr		930
#define	TR_getexecattr		931
#define	TR_getexecprof		932
/*
 * prof_attr
 */
#define	TR__nss_initf_profattr	933
#define	TR_str2profattr		934
#define	TR_setprofattr		935
#define	TR_endprofattr		936
#define	TR_getprofattr		937
#define	TR_getprofnam		938
/*
 * user_attr
 */
#define	TR__nss_initf_userattr	939
#define	TR_str2userattr		940
#define	TR_setuserattr		941
#define	TR_enduserattr		942
#define	TR_getuserattr		943
#define	TR_getusernam		944
/*
 * clnt_send
 */
#define	TR_clnt_dg_send		945
#define	TR_clnt_raw_send	946
#define	TR_clnt_vc_send		947


/*
 * Generic format for data saved with trace calls.
 *
 * The format of tr_time varies depending on whether or not there's
 * a high resolution timer available.  If so, it's the timer's value;
 * if not, it's the low 16 bits of time.tv_sec concatenated to the
 * high 16 bits of time.tv_usec.  Tr_pid records the process active
 * at the time of the trace call; it's not meaningful if called from
 * interrupt level.
 */
struct trace_record {
    unsigned long  tr_time;
    short   tr_tag;
    unsigned short tr_pid;
    unsigned long  tr_datum0;
    unsigned long  tr_datum1;
    unsigned long  tr_datum2;
    unsigned long  tr_datum3;
    unsigned long  tr_datum4;
    unsigned long  tr_datum5;
};

#ifdef	TRACE

extern void __rpc_trace();

/*
 * Lint doesn't believe that there are valid reasons for comparing
 * constants to each other...
 */
#ifdef	__lint
#define	trace(ev, d0, d1, d2, d3, d4, d5) \
    __rpc_trace((ev),			  \
	(unsigned long)(d0), (unsigned long)(d1), (unsigned long)(d2), \
	(unsigned long)(d3), (unsigned long)(d4), (unsigned long)(d5))
#else	/* __lint */
#define	trace(ev, d0, d1, d2, d3, d4, d5) \
    __rpc_trace((ev),			  \
	(unsigned long)(d0), (unsigned long)(d1), (unsigned long)(d2), \
	(unsigned long)(d3), (unsigned long)(d4), (unsigned long)(d5))
#endif	/* __lint */

#define	trace6(ev, d0, d1, d2, d3, d4, d5) \
    trace(ev, d0, d1, d2, d3, d4, d5)
#define	trace5(ev, d0, d1, d2, d3, d4)	trace(ev, d0, d1, d2, d3, d4, 0)
#define	trace4(ev, d0, d1, d2, d3)	trace(ev, d0, d1, d2, d3, 0, 0)
#define	trace3(ev, d0, d1, d2)	trace(ev, d0, d1, d2, 0, 0, 0)
#define	trace2(ev, d0, d1)	trace(ev, d0, d1, 0, 0, 0, 0)
#define	trace1(ev, d0)		trace(ev, d0, 0, 0, 0, 0, 0)

#else	/* TRACE */

#define	trace   trace6
#define	trace6(ev, d0, d1, d2, d3, d4, d5)
#define	trace5(ev, d0, d1, d2, d3, d4)
#define	trace4(ev, d0, d1, d2, d3)
#define	trace3(ev, d0, d1, d2)
#define	trace2(ev, d0, d1)
#define	trace1(ev, d0)

#endif	/* TRACE */

#ifdef	__cplusplus
}
#endif

#endif	/* _RPC_TRACE_H */
