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
#include "bpf_arena_list.h"
#include "scx_deadline_wheel.bpf.skel.h"
//#include "include/deadline_structs.h"

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
int create_bucket_wrapper(struct scx_deadline_wheel * skel, u64 bucket_index)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	u64 old_idx = skel->bss->global_new_bucket_idx;
	skel->bss->global_new_bucket_idx = bucket_index;

	int ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.create_bucket), &opts);
	if (ret != 0) {
		fprintf(stderr, "Failed to run create_bucket: %d\n", ret);
		return 1;
	}
	if (opts.retval != 0) {
		fprintf(stderr, "create_bucket returned %d\n", opts.retval);
		return 1;
	}
	if (skel->bss->skip) {
		printf("SKIP: compiler doesn't support arena_cast\n");
		return 1;
	}

	skel->bss->global_new_bucket_idx = old_idx;
	return 0;
}

int free_all_buckets_wrapper(struct scx_deadline_wheel * skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	int ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.free_all_buckets), &opts);
	if (ret != 0) {
		fprintf(stderr, "Failed to run free_all_buckets: %d\n", ret);
		return 1;
	}
	if (opts.retval != 0) {
		fprintf(stderr, "free_all_buckets returned %d\n", opts.retval);
		return 1;
	}
	if (skel->bss->skip) {
		printf("SKIP: compiler doesn't support arena_cast\n");
		return 1;
	}

	return 0;
}

struct deadline_wheel_slot {
	struct bpf_spin_lock lock;
	u64	abs_deadline;
	arena_list_head_t* list;
};
struct cb {
	struct arena_list_node node;
	__u64 func;
};

int print_deadline_wheel_wrapper(struct scx_deadline_wheel * skel)
{
	size_t key_size = sizeof(uint64_t);
	size_t value_size = sizeof(struct deadline_wheel_slot);
	void *key = calloc(1, key_size);
    void *next_key = calloc(1, key_size);
    void *value = calloc(1, value_size);

	int ret, ret2; 
	ret = bpf_map__get_next_key(skel->maps.deadline_wheel_v2, NULL, next_key, key_size);
	while (ret == 0) {
        // Lookup the value for this key
		ret2 = bpf_map__lookup_elem(skel->maps.deadline_wheel_v2, next_key, key_size, value, value_size, 0);
        if (ret2 == 0) {
			struct deadline_wheel_slot* slot = (struct deadline_wheel_slot*) value;
			struct cb __arena *iter;

			printf("+===================+\n");
			printf("+     Bucket #%lu\n", *(uint64_t*)next_key);
			printf("+    ( AbsDL = %lu ns)\n", slot->abs_deadline);
			printf("+    list-----> ");

			int cnt = 0;
			list_for_each_entry(iter, slot->list, node) {
				cnt++;
				printf("(CB %llu), ", iter->func);		
			}
			printf("\n");
			printf("+    Size = %d cb's\n", cnt);
			printf("+===================+\n");
        }
        // Prepare for next iteration
        memcpy(key, next_key, key_size);
		ret = bpf_map__get_next_key(skel->maps.deadline_wheel_v2, key, next_key, key_size);
    }
    free(key);
    free(next_key);
    free(value);

	return 0;
}
*/
int main(int argc, char **argv)
{
	struct scx_deadline_wheel *skel;
	struct bpf_link *link;
	//__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(deadline_wheel_ops, scx_deadline_wheel);
	SCX_OPS_LOAD(skel, deadline_wheel_ops, scx_deadline_wheel, uei);
	link = SCX_OPS_ATTACH(skel, deadline_wheel_ops, scx_deadline_wheel);

	/*
	int ret = create_bucket_wrapper(skel, 0);
	if (ret) goto out;
	ret = print_deadline_wheel_wrapper(skel);
	if (ret) goto out;
	ret = free_all_buckets_wrapper(skel);
	if (ret) goto out;
	*/

	while (!exit_req && !UEI_EXITED(skel, uei)) 
	{
		sleep(1);
	}
	
// out:
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_deadline_wheel__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
