[ 1692.024475]  ib_find_cached_gid_by_port+0xe0/0x110 [ib_core]
[ 1692.024478]  rxe_rcv+0x89/0x900 [rdma_rxe]
[ 1692.024481]  rxe_loopback+0xe/0x10 [rdma_rxe]
[ 1692.024483]  ? rxe_loopback+0xe/0x10 [rdma_rxe]
[ 1692.024486]  rxe_requester+0x7f8/0x1220 [rdma_rxe]
[ 1692.024491]  ? ib_create_send_mad+0xf4/0x370 [ib_core]
[ 1692.024494]  rxe_do_task+0x94/0x100 [rdma_rxe]
[ 1692.024496]  rxe_run_task+0x18/0x30 [rdma_rxe]
[ 1692.024498]  rxe_post_send+0x3bd/0x590 [rdma_rxe]
[ 1692.024503]  ? ib_free_send_mad+0x25/0x50 [ib_core]
[ 1692.024506]  rds_ib_xmit+0x543/0x950 [rds_rdma]
[ 1692.024509]  rds_send_xmit+0x355/0x700 [rds]
[ 1692.024512]  rds_send_worker+0x29/0xc0 [rds]
[ 1692.024521]  process_one_work+0x14d/0x410
[ 1692.024523]  worker_thread+0x4b/0x460
[ 1692.024525]  kthread+0x105/0x140
[ 1692.024526]  ? process_one_work+0x410/0x410
[ 1692.024528]  ? kthread_associate_blkcg+0xa0/0xa0
[ 1692.024535]  ? do_syscall_64+0x73/0x130
[ 1692.024538]  ? SyS_exit_group+0x14/0x20
[ 1692.024540]  ret_from_fork+0x35/0x40
