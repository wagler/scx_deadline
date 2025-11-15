/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include <stdint.h>
#include "scx_deadline.bpf.skel.h"
#include "include/deadline_structs.h"

const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

/*
static void read_stats(struct scx_deadline *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 2);

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}
*/

void get_task_absdeadline(struct scx_deadline *skel, pid_t pid)
{
	struct task_ctx ctx;
	int pid_int = (int)pid;
	int res = bpf_map__lookup_elem(skel->maps.task_ctx_stor, &pid_int, sizeof(pid_int), &ctx, sizeof(ctx), 0);
	if (res)
	{
		printf("Error: could not find task_ctx for pid %d. Error code: %d.\n", pid_int, res);
		return;
	}
	printf("PID %d abs deadline = %lu.\n", pid_int, ctx.abs_deadline);
	// int nr_cpus = libbpf_num_possible_cpus();
	// __u64 cnts[2][nr_cpus];
	// __u32 idx;

	// memset(stats, 0, sizeof(stats[0]) * 2);

	// for (idx = 0; idx < 2; idx++) {
	// 	int ret, cpu;

	// 	ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.task_ctx_stor), &idx, cnts[idx]);
	// 	if (ret < 0)
	// 		continue;
	// 	for (cpu = 0; cpu < nr_cpus; cpu++)
	// 		stats[idx] += cnts[idx][cpu];
	// }
}

int main(int argc, char **argv)
{
	struct scx_deadline *skel;
	struct bpf_link *link;
	//__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(deadline_ops, scx_deadline);

	// while ((opt = getopt(argc, argv, "fvh")) != -1) {
	// 	switch (opt) {
	// 	case 'f':
	// 		skel->rodata->fifo_sched = true;
	// 		break;
	// 	case 'v':
	// 		verbose = true;
	// 		break;
	// 	default:
	// 		fprintf(stderr, help_fmt, basename(argv[0]));
	// 		return opt != 'h';
	// 	}
	// }

	SCX_OPS_LOAD(skel, deadline_ops, scx_deadline, uei);
	link = SCX_OPS_ATTACH(skel, deadline_ops, scx_deadline);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		//get_task_absdeadline(struct scx_deadline *skel, pid_t pid, uint64_t abs_deadline)
		//__u64 stats[2];

		//read_stats(skel, stats);
		//printf("local=%llu global=%llu\n", stats[0], stats[1]);
		//fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_deadline__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
