/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <scx/common.h>
#include <stdint.h>
#include <sdt_task_defs.h>
#include "scx_deadline_wheel.bpf.skel.h"

const char help_fmt[] =
"A sched_ext scheduler that implements the earliest deadline first (EDF) algorithm.\n"
"\n"
"The EDF logic is implemented with a deadline wheel structure [1] instead of a priority queue, facilitating O(1) scheduling decisions"
"\n\n"
"[1] M. Short, 'Improved Task Management Techniques for Enforcing EDF Scheduling on Recurring Tasks,'\n"
"2010 16th IEEE Real-Time and Embedded Technology and Applications Symposium, Stockholm, Sweden, 2010, pp. 56-65, doi: 10.1109/RTAS.2010.22."
"\n"
"Usage: %s [-b] [-v]\n"
"\n"
"  -b            Set the number of buckets in the deadline wheel\n"
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

int main(int argc, char **argv)
{
	struct scx_deadline_wheel *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;
	__u64 num_buckets = 10;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	while ((opt = getopt(argc, argv, "b:vh")) != -1) {
		switch (opt) {
		case 'b':
			// Convert string argument to unsigned long long
			num_buckets = strtoull(optarg, NULL, 0);
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}
	skel = SCX_OPS_OPEN(scx_deadline_wheel_ops, scx_deadline_wheel);
	if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 3. Set rodata (must be after open, before load)
    skel->rodata->num_buckets = num_buckets;

	SCX_OPS_LOAD(skel, scx_deadline_wheel_ops, scx_deadline_wheel, uei);

	link = SCX_OPS_ATTACH(skel, scx_deadline_wheel_ops, scx_deadline_wheel);
	if (!link) {
        fprintf(stderr, "Failed to attach struct_ops\n");
        goto out;
    }

	printf("Loaded scx_deadline_wheel scheduler with %lu buckets.", skel->rodata->num_buckets);
	fflush(stdout);
	while (!exit_req && !UEI_EXITED(skel, uei)) 
	{
		sleep(1);
	}
	
out:
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_deadline_wheel__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
