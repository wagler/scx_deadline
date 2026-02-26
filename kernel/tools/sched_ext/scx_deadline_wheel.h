#pragma once

#include <scx/common.bpf.h>
#include "linked_list.h"

#define NS_IN_SEC 1000000000ULL
// #define NUM_BUCKETS 100

const volatile u64 num_buckets;

struct slock_ctx {
	int *val;
	bool got_lock;
};

__hidden
static inline long slock_work(u32 index, void *ctx)
{	
	struct slock_ctx *lctx = ctx;
	/* Return 1 to stop looping (we got the lock) */
	/* Return 0 to continue looping */
	if (__sync_val_compare_and_swap(lctx->val, 0, 1) == 0)
	{
		lctx->got_lock = true;
		return 1;
	}
	// for(int temp=0; temp<100000; temp++){}
	return 0;
}

__hidden
static void slock(int* val){   	
	struct slock_ctx lctx = { .val = val, .got_lock = false};
	u32 iters = 1<<23;
	long res = bpf_loop(iters, slock_work, &lctx, 0);
	if (res == -E2BIG) 
	{
		bpf_printk("[SLOCK] iters %lu exceeds max", iters);
	}
	else if(res == -EINVAL)
	{
		bpf_printk("[SLOCK] iters %lu is invalid", iters);
	}
	else if(res == iters)
	{
		bpf_printk("[SLOCK] res %lu hit iters %lu",  res, iters);
	}

	if(!lctx.got_lock){
		int cpu = bpf_get_smp_processor_id();
		bpf_printk("[SLOCK] [Cpu %d] Couldn't get lock!!!", cpu);
		scx_bpf_error("[SLOCK] [Cpu %d] Couldn't get lock!!!", cpu);
	}
}

__hidden
static void sunlock(int* val){ 
	*val = 0;
}

static int inited;

struct arena_task_node {
	struct arena_list_node node;
	int pid;
	u64 cpumask;
	u64 bucket;
	bool in_bucket;
};

struct task_ctx {
	struct bpf_spin_lock lock;
	struct arena_task_node __arena* atnode;
	u64	abs_deadline;
	bool valid;
	int pid;
	// int sem;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct deadline_wheel_slot {
	struct bpf_spin_lock lock;
	struct arena_list_head __arena* head_ptr;
	int bucket_count;
	int sem;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u64);
	__type(value, struct deadline_wheel_slot);
	__uint(max_entries, 2048);
} dl_wheel SEC(".maps");

struct cpu_ctx {
	struct bpf_spin_lock lock;
	bool valid;
	int curr_pid;
	u64 curr_abs_dl;
	bool preempted;
	int preempter_pid;
	int sem;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct cpu_ctx);
} cpu_ctx_stor SEC(".maps");

struct task_rel_dl {
	struct bpf_spin_lock lock;
	u64	rel_deadline;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, struct task_rel_dl);
    __uint(max_entries, 10240);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_relative_deadlines_map SEC(".maps");

__hidden
static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx;

	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0))) {
		scx_bpf_error("task_ctx lookup failed");
		return NULL;
	}
	return tctx;
}

__hidden
static u64 get_rel_deadline(struct task_struct *p)
{
	struct task_rel_dl* existing_rel_dl;
	int pid = p->pid;
	existing_rel_dl = bpf_map_lookup_elem(&task_relative_deadlines_map, &pid);
	if (existing_rel_dl)
	{
		bpf_printk("[DEBUG] [HELPER] Found existing rel dl for pid %d: %llu\n", pid, existing_rel_dl->rel_deadline);
		return existing_rel_dl->rel_deadline;
	}

	struct task_rel_dl new_rel_dl = { .rel_deadline = NS_IN_SEC };
	long res = bpf_map_update_elem(&task_relative_deadlines_map, &pid, &new_rel_dl, BPF_ANY|BPF_F_LOCK);
	if (res)
	{
		scx_bpf_error("tsk_rel_dl update failed for pid %d; error = %ld", pid, res);
		return -ENOMEM;
	}
	bpf_printk("[DEBUG] [HELPER] Did not find an existing relative deadline for pid %d. Set new one to: %llu\n", pid, new_rel_dl.rel_deadline);
	return NS_IN_SEC;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	__uint(max_entries, 1 << 16); /* number of pages */
        __ulong(map_extra, (1ull << 32)); /* start of mmap() region */
#else
	__uint(max_entries, 1 << 20); /* number of pages */
        __ulong(map_extra, (1ull << 44)); /* start of mmap() region */
#endif
} arena __weak SEC(".maps");