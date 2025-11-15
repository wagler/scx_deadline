/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A deadline scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* Per-task scheduling context */
struct task_ctx {
	u64	abs_deadline;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} task_ctx_stor SEC(".maps");

struct task_rel_dl {
	struct bpf_spin_lock lock;
	u64	rel_deadline;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, struct task_rel_dl);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tsk_rel_dl SEC(".maps");

struct running_task_ctx {
	struct bpf_spin_lock lock;
	bool valid;
	struct task_ctx* tctx;
	s32 pid;
};

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, u32);
// 	__type(value, struct running_task_ctx);
// } running_tasks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16);
	__type(key, u32);
	__type(value, struct running_task_ctx);
} running_tasks_v2 SEC(".maps");

struct debug_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct debug_timer);
} debug_timer SEC(".maps");

struct deadline_wheel_slot {
	struct bpf_spin_lock lock;
	u64	abs_deadline;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct deadline_wheel_slot);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} deadline_wheel SEC(".maps");

#define DEADLINE_PRIQ_DSQ 1
#define NS_IN_US 1000ULL
#define US_IN_MS 1000ULL
#define MS_IN_S 1000ULL
#define SEC_IN_MIN 60ULL
#define MIN_IN_HOUR 60ULL
#define NS_IN_SEC 1000000000ULL

#define TIMER_INTERVAL_NS 100 * NS_IN_US * US_IN_MS

// Max abs deadline we support
#define ONE_HOUR_IN_NS (NS_IN_SEC * SEC_IN_MIN * MIN_IN_HOUR)
#define MAX_ALLOWED_DL_NS ONE_HOUR_IN_NS

static s32 pick_direct_dispatch_cpu(struct task_struct *p, s32 prev_cpu)
{
	s32 cpu;

	// if (p->nr_cpus_allowed == 1)
	// {
	// 	bpf_printk("Prev cpu (%d) is the only one allowed for %s-%d", prev_cpu, p->comm, p->pid);	
	// 	return prev_cpu;
	// }
	if(scx_bpf_test_and_clear_cpu_idle(prev_cpu))
	{
		bpf_printk("[DEBUG] [HELPER] Prev cpu (%d) was idle", prev_cpu);
		return prev_cpu;
	}
	
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
	{
		bpf_rcu_read_lock();
		u64 nr_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
		bpf_rcu_read_unlock();
		if (nr_queued > 0)
		{
			return -1;
		}
		bpf_printk("[DEBUG] [HELPER] Found idle cpu (%d) that's in mask", cpu);
		return cpu;
	}

	return -1;
}

static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx;

	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0))) {
		scx_bpf_error("task_ctx lookup failed");
		return NULL;
	}
	return tctx;
}

s32 BPF_STRUCT_OPS(deadline_wheel_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bpf_printk("[DEBUG] [SELECT_CPU] Selecting CPU for task %d (%s)\n", p->pid, p->comm);
	struct task_ctx *tctx;
	s32 cpu;
	u64 abs_deadline;

	if (!(tctx = lookup_task_ctx(p)))
		return -ESRCH;

	abs_deadline = tctx->abs_deadline;
	cpu = pick_direct_dispatch_cpu(p, prev_cpu);

	if (cpu >= 0) {
		bpf_printk("[INFO] [SELECT_CPU] Directly dispatching pid %d (abs_deadline %llu) to cpu %d\n", p->pid, abs_deadline, cpu);
		// Should we use these flags? Or should we just use 0?
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_INF, SCX_ENQ_HEAD|SCX_ENQ_PREEMPT);
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		return cpu;
	} else {
		bpf_printk("[DEBUG] [SELECT_CPU] Not directly dispatching pid %d (abs_deadline %llu) to cpu\n", p->pid, abs_deadline);
		return prev_cpu;
	}
}

void BPF_STRUCT_OPS(deadline_wheel_enqueue, struct task_struct *p, u64 enq_flags)
{
	
	if (enq_flags & SCX_ENQ_REENQ)
	{
		bpf_printk("[DEBUG] [ENQUEUE] Reenqueueing task %d (%s) [flags=%x]\n", p->pid, p->comm, enq_flags);
	}
	else {
		bpf_printk("[DEBUG] [ENQUEUE] Enqueueing task %d (%s) [flags=%x]\n", p->pid, p->comm, enq_flags);
	}
	/* if select_cpu() wasn't called, try direct dispatch to an idle CPU */
	s32 cpu;
	if (!(enq_flags & SCX_ENQ_REENQ) && !(enq_flags & SCX_ENQ_CPU_SELECTED) && (cpu = pick_direct_dispatch_cpu(p, scx_bpf_task_cpu(p))) >= 0) {
		bpf_printk("[INFO] [ENQUEUE] Enqueued task %d (%s) directly in cpu %d local dsq.\n", p->pid, p->comm, cpu);
		//scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, enq_flags);

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, enq_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		return;
	}

	// Loop over all the CPUs in p's cpumask and check if there's an scx task running on that CPU
	// whose task_ctx->abs_deadline is greater than p's task_ctx->abs_deadline
	// If there is, then we need to preempt that task and insert p into the local dsq
	// If there is not, then we can insert p into the local dsq
	// If there is more than one task that needs to be preempted, then we need to preempt the task with the greatest abs_deadline

	struct task_ctx *p_tctx;
	struct task_ctx *i_tctx;
	struct task_struct *i_task_struct;

	if (!(p_tctx = lookup_task_ctx(p)))
	{
		return;
	}

	struct running_task_ctx* cpu_i_running_task_ctx;

	if (!(enq_flags & SCX_ENQ_REENQ))
	{
		bpf_printk("[DEBUG] [ENQUEUE] Looking through %d cpus\n", scx_bpf_nr_cpu_ids());
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {

		if(!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		{
			//bpf_printk("Skipping CPU %d for pid %d, because it's out of mask\n", cpu, p->pid);
			continue;
		}

		u32 key = cpu;
		cpu_i_running_task_ctx = bpf_map_lookup_elem(&running_tasks_v2, &key);
    	if (!cpu_i_running_task_ctx)
		{
			bpf_printk("[DEBUG] [ENQUEUE] running_task_ctx lookup failed for cpu %d\n", cpu);
			continue;
		}
		bpf_spin_lock(&cpu_i_running_task_ctx->lock);
		bool valid = cpu_i_running_task_ctx->valid;
		int i_task_pid = cpu_i_running_task_ctx->pid;
		bpf_spin_unlock(&cpu_i_running_task_ctx->lock);
		
			
		// // Check if this cpu already has an scx task assigned to it
		// if (!(cpu_i_running_task_ctx = bpf_map_lookup_percpu_elem(&running_tasks, &zero, cpu))) {
		// 	bpf_printk("running_task_ctx lookup failed for cpu %d\n", cpu);
		// 	continue;
		// }

		if (!valid)
		{
			bpf_printk("[DEBUG] [ENQUEUE] running_task_ctx invalid for cpu %d. Skipping.\n", cpu);
			continue;
		}

		i_task_struct = bpf_task_from_pid(i_task_pid);
		if (!i_task_struct)
		{
			scx_bpf_error("Couldn't retrieve task_struct from SCX task (pid=%d) on cpu %d", 
				i_task_pid, cpu);
			return;
		}

		i_tctx = lookup_task_ctx(i_task_struct);
		bpf_task_release(i_task_struct);
		if (!i_tctx)
		{
			return;
		}

		if (i_tctx->abs_deadline > p_tctx->abs_deadline)
		{
			bpf_printk(
				"[INFO] [ENQUEUE] Task pid=%d (abs_deadline %llu) preempting running task pid=%d (abs_deadline %llu) on core %d, because it has an earlier deadline\n", 
				p->pid, p_tctx->abs_deadline, i_task_pid, i_tctx->abs_deadline, cpu
			);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, 
					enq_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			return;
		}
	}
	}
	// Couldn't find a CPU to dispatch task to. Insert into priority queue.
	u64 vtime = p_tctx->abs_deadline;
	bpf_printk("[INFO] [ENQUEUE] Enqueued task %d (%s) in priority queue. Abs dl = %llu, vtime=%llu\n", p->pid, p->comm, p_tctx->abs_deadline, vtime);
	scx_bpf_dsq_insert_vtime(p, DEADLINE_PRIQ_DSQ, SCX_SLICE_INF, vtime, enq_flags);
}

void BPF_STRUCT_OPS(deadline_wheel_dequeue, struct task_struct *p, u64 deq_flags)
{
	if (deq_flags & SCX_DEQ_SLEEP)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because it's no longer runnable\n", p->pid, p->comm);
	else if (deq_flags & SCX_DEQ_CORE_SCHED_EXEC)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because the generic core-sched layer decided to execute the task even though it hasn't been dispatched yet. Dequeue from the BPF side.\n", p->pid, p->comm);
	else
	bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued\n", p->pid, p->comm);
}


void BPF_STRUCT_OPS(deadline_wheel_dispatch, s32 cpu, struct task_struct *prev)
{
	if (prev && prev->policy == 7)
	{
		bpf_printk("[INFO] [DISPATCH] CPU %d dispatching from PrioQ. Prev was pid %d (%s)(policy %d) with slice %llu.\n", cpu, prev->pid, prev->comm, prev->policy, prev->scx.slice);
	}
	
	scx_bpf_dsq_move_to_local(DEADLINE_PRIQ_DSQ);
}

void BPF_STRUCT_OPS(deadline_wheel_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	
	// Update the map that tells us which SCX task, if any, a core is running.
	//u32 cpu = bpf_get_smp_processor_id();
	//s32 cpu = scx_bpf_task_cpu(p);

	struct task_ctx *tctx;
	if (!(tctx = lookup_task_ctx(p)))
		return;
	struct running_task_ctx* cpu_i_running_task_ctx;
	cpu_i_running_task_ctx = bpf_map_lookup_elem(&running_tasks_v2, &cpu);
	if (!cpu_i_running_task_ctx)
	{
		scx_bpf_error("running_task_ctx lookup failed for cpu %d", cpu);
		return;
	}
	bpf_spin_lock(&cpu_i_running_task_ctx->lock);


	// u32 zero = 0;
	// struct running_task_ctx* cpu_i_running_task_ctx;
	// if (!(cpu_i_running_task_ctx = bpf_map_lookup_percpu_elem(&running_tasks, &zero, cpu))) {
	// 	scx_bpf_error("running_task_ctx lookup failed for cpu %d", cpu);
	// 	return;
	// }

	
	cpu_i_running_task_ctx->tctx = tctx;
	cpu_i_running_task_ctx->pid = p->pid;
	cpu_i_running_task_ctx->valid = true;

	bpf_spin_unlock(&cpu_i_running_task_ctx->lock);
	bpf_printk("[INFO] [RUNNING] Running task %d (%s) on cpu %d (Abs. DL = %llu)\n", p->pid, p->comm, cpu, tctx->abs_deadline);
}

void BPF_STRUCT_OPS(deadline_wheel_runnable, struct task_struct *p, u64 enq_flags)
{
	if (enq_flags &  SCX_ENQ_WAKEUP )
	{
		bpf_printk("[INFO] [RUNNABLE] Task %d (%s) is runnable (waking up)\n", p->pid, p->comm);
	}
	else
	{
		bpf_printk("[INFO] [RUNNABLE] Task %d (%s) is runnable (migrated or restored after attribute change)\n", p->pid, p->comm);
	}
}

void BPF_STRUCT_OPS(deadline_wheel_stopping, struct task_struct *p, bool runnable)
{
	bpf_printk("[INFO] [STOPPING] Stopping task %d (%s), [runnable = %d]\n", p->pid, p->comm, (int)runnable);
	// Update the map that tells us which SCX task, if any, a core is running.
	//u32 cpu = bpf_get_smp_processor_id();
	s32 cpu = scx_bpf_task_cpu(p);
	// u32 zero = 0;
	// struct running_task_ctx* cpu_i_running_task_ctx;
	// if (!(cpu_i_running_task_ctx = bpf_map_lookup_percpu_elem(&running_tasks, &zero, cpu))) {
	// 	scx_bpf_error("running_task_ctx lookup failed for cpu %d", cpu);
	// 	return;
	// }

	struct running_task_ctx* cpu_i_running_task_ctx;
	cpu_i_running_task_ctx = bpf_map_lookup_elem(&running_tasks_v2, &cpu);
	if (!cpu_i_running_task_ctx)
	{
		scx_bpf_error("running_task_ctx lookup failed for cpu %d", cpu);
		return;
	}
	bpf_spin_lock(&cpu_i_running_task_ctx->lock);
	cpu_i_running_task_ctx->tctx = NULL;
	cpu_i_running_task_ctx->pid = -1;
	cpu_i_running_task_ctx->valid = false;
	bpf_spin_unlock(&cpu_i_running_task_ctx->lock);
}

static u64 get_rel_deadline(struct task_struct *p)
{
	struct task_rel_dl* existing_rel_dl;
	int pid = p->pid;
	existing_rel_dl = bpf_map_lookup_elem(&tsk_rel_dl, &pid);
	if (existing_rel_dl)
	{
		bpf_printk("[DEBUG] [HELPER] Found existing rel dl for pid %d: %llu\n", pid, existing_rel_dl->rel_deadline);
	}
	else 
	{
		struct task_rel_dl new_rel_dl;
		new_rel_dl.rel_deadline = NS_IN_SEC;
		int res = bpf_map_update_elem(&tsk_rel_dl, &pid, &new_rel_dl, BPF_ANY|BPF_F_LOCK);
		if (res)
		{
			scx_bpf_error("tsk_rel_dl update failed for pid %d", pid);
			return 0;
		}
		bpf_printk("[DEBUG] [HELPER] Did not find an existing relative deadline for pid %d. Set new one to: %llu\n", pid, new_rel_dl.rel_deadline);
	}

	existing_rel_dl = bpf_map_lookup_elem(&tsk_rel_dl, &pid);
	if (!existing_rel_dl)
	{
		scx_bpf_error("Relative deadline for pid %d failed to set.\n", pid);
		return 0;
	}

	return existing_rel_dl->rel_deadline;
}

void BPF_STRUCT_OPS(deadline_wheel_enable, struct task_struct *p)
{
	bpf_printk("[DEBUG] [ENABLE] Enabling task %d\n", p->pid);
	u64 rel_dl = get_rel_deadline(p);
	bpf_printk("[DEBUG] [ENABLE] Got relative deadline for task %d: %llu\n", p->pid, rel_dl);
	u64 abs_deadline = scx_bpf_now() + rel_dl;

	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("task_ctx lookup/creation failed");
		return;
	}
	tctx->abs_deadline = abs_deadline;
	u64 time_from_now_us = (abs_deadline - scx_bpf_now())/1000ULL;
	bpf_printk("[INFO] [ENABLE] Task %d (%s) policy=%u enabled. Mask = %x. Rel. DL = %llu ns, Abs. DL = %llu (time from now = %llu us)\n",
		p->pid, p->comm, p->policy, *(int*)(p->cpus_ptr), rel_dl, time_from_now_us);
}

void BPF_STRUCT_OPS(deadline_wheel_disable, struct task_struct *p)
{
	bpf_printk("[INFO] [DISABLE] Task %d (%s) disabled\n", p->pid, p->comm);
}

/*
* We have lost the control of this cpu: we cannot run on this cpu for now
* In that case, to make sure we do not lose control over the tasks already in 
* the local dsq, we reenqueue them, so that they either find some other CPU to run on,
* or they are enqueued into the shared dsq.
* 
*/
void BPF_STRUCT_OPS(deadline_wheel_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	bool is_kthread = (args->task->flags & PF_KTHREAD);
	bpf_printk("[DEBUG] [RELEASE] CPU %d is released, reason: %u, next prio: %u, next pid: %lu, next comm: %s, kthread: %d\n", 
		cpu, args->reason, args->task->prio, args->task->pid, args->task->comm, is_kthread);
	// if (!is_kthread)
	// {
	// 	scx_bpf_reenqueue_local();
	// }
}

void BPF_STRUCT_OPS(deadline_wheel_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	bpf_printk("[DEBUG] [ACQUIRE] CPU %d is acquired\n", cpu);
	//scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
}

void BPF_STRUCT_OPS(deadline_wheel_quiescent, struct task_struct *p, u64 deq_flags) {
	s32 cpu = scx_bpf_task_cpu(p);
	if (deq_flags & SCX_DEQ_CORE_SCHED_EXEC)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) going quiescent on cpu %d, because the generic core-sched layer decided to execute the task even though it hasn't been dispatched yet. Dequeue from the BPF side.\n", p->pid, p->comm, cpu);
	else
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) going quiescent, because it's no longer runnable on cpu %d\n", p->pid, p->comm, cpu);
}

static int watchdog_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	bpf_printk("[WATCHDOG] ======[%llu] Watchdog======\n", scx_bpf_now());
	struct task_struct* q; 
	bpf_rcu_read_lock();
	u64 nr_queued = scx_bpf_dsq_nr_queued(DEADLINE_PRIQ_DSQ);
	bpf_printk("[WATCHDOG] %llu tasks in PrioQ\n", nr_queued);
	int i = 0;
    bpf_for_each(scx_dsq, q, DEADLINE_PRIQ_DSQ, 0) {
		bpf_printk("[WATCHDOG] PrioQ [%d]: %s-%d (vtime=%llu)\n", i++, q->comm, q->pid, q->scx.dsq_vtime);
    }
	bpf_rcu_read_unlock();

	s32 cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		bpf_rcu_read_lock();
		struct rq * r = scx_bpf_cpu_rq(cpu);
		if (r->curr && r->curr->policy==7)
		{
			bpf_printk("[WATCHDOG] cpu %d currently running %s-%d\n", cpu, r->curr->comm, r->curr->pid);
		}
		u64 nr_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON|cpu);
		bpf_printk("[WATCHDOG] %llu tasks in CPU %d's DSQ\n", nr_queued, cpu);
		int i = 0;
		bpf_for_each(scx_dsq, q, SCX_DSQ_LOCAL_ON|cpu, 0) {
			bpf_printk("[WATCHDOG] CPU%d-DSQ [%d]: %s-%d\n", cpu, i++, q->comm, q->pid);
		}
		bpf_rcu_read_unlock();
		bpf_printk("\n");
	}	


	bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(deadline_wheel_init)
{
	bpf_printk("[INFO] [INIT] Starting SCX Deadline Wheel Scheduler\n");
	u32 zero = 0;
	struct running_task_ctx* cpu_i_running_task_ctx;
	s32 cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) 
	{
		cpu_i_running_task_ctx = bpf_map_lookup_elem(&running_tasks_v2, &cpu);
		if (!cpu_i_running_task_ctx)
		{
			scx_bpf_error("running_task_ctx lookup failed for cpu %d", cpu);
			return -1;
		}

		bpf_spin_lock(&cpu_i_running_task_ctx->lock);
		cpu_i_running_task_ctx->valid = false;
		cpu_i_running_task_ctx->pid = -1;
		cpu_i_running_task_ctx->tctx = NULL;
		bpf_spin_unlock(&cpu_i_running_task_ctx->lock);

		bpf_printk("[DEBUG] [INIT] Initialized running_task_ctx[cpu %d]", cpu);
	}

	struct bpf_timer *timer = bpf_map_lookup_elem(&debug_timer, &zero);
	if (!timer)
		return -ESRCH;

	bpf_timer_init(timer, &debug_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, watchdog_timerfn);

	int ret = bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
	if (ret)
		scx_bpf_error("bpf_timer_start failed (%d)", ret);

	return 0;
	//return scx_bpf_create_dsq(DEADLINE_PRIQ_DSQ, -1);
}

void BPF_STRUCT_OPS(deadline_wheel_exit, struct scx_exit_info *ei)
{
	bpf_printk("[INFO] [EXIT] Exiting SCX Deadline Wheel Scheduler\n");
	UEI_RECORD(uei, ei);
}

s32 BPF_STRUCT_OPS(deadline_wheel_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	if (p->policy != 7) return 0;
	/*
	 * @p is new. Let's ensure that its task_ctx is available. We can sleep
	 * in this function and the following will automatically use GFP_KERNEL.
	 */
	// if (!bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE))
	// 	return -ENOMEM;
	
	bpf_printk("[INFO] [TASK_INIT] Task %d (%s)initialized. Policy = %d.\n", p->pid, p->comm, p->policy);
	return 0;
}

void BPF_STRUCT_OPS(deadline_wheel_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	if (p->policy != 7) return;
	bpf_printk("[INFO] [TASK_EXIT] Task %d (%s) policy=%u exited\n", p->pid, p->comm, p->policy);
}

void BPF_STRUCT_OPS(deadline_wheel_dump, struct scx_dump_ctx *dctx)
{
	scx_bpf_dump("Deadline scheduler dump printout:\n\n");
	struct task_struct* q; 
	bpf_rcu_read_lock();
	u64 nr_queued = scx_bpf_dsq_nr_queued(DEADLINE_PRIQ_DSQ);
	scx_bpf_dump("%llu tasks in PrioQ\n", nr_queued);
	int i = 0;
    bpf_for_each(scx_dsq, q, DEADLINE_PRIQ_DSQ, 0) {
		scx_bpf_dump("PrioQ[%d]: %s-%d (vtime=%llu)\n", i++, q->comm, q->pid, q->scx.dsq_vtime);
    }
	bpf_rcu_read_unlock();

	scx_bpf_dump("\n\n");

	s32 cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		bpf_rcu_read_lock();
		struct rq * r = scx_bpf_cpu_rq(cpu);
		//rq->scx->{nr_running, struct list_head	runnable_list;}
		u64 nr_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON|cpu);
		scx_bpf_dump("%llu tasks in CPU %d's DSQ\n", nr_queued, cpu);
		int i = 0;
		bpf_for_each(scx_dsq, q, SCX_DSQ_LOCAL_ON|cpu, 0) {
			scx_bpf_dump("CPU%d-DSQ [%d]: %s-%d\n", cpu, i++, q->comm, q->pid);
		}

		if (r->curr)
		{
			scx_bpf_dump("cpu %d currently running %s-%d\n", cpu, r->curr->comm, r->curr->pid);
		}
		
		bpf_rcu_read_unlock();
		scx_bpf_dump("\n");
	}	
}

void BPF_STRUCT_OPS(deadline_wheel_dump_task, struct scx_dump_ctx *dctx, struct task_struct *p)
{
	u64 dsq_id = 101;
	if (p->scx.dsq)
	{
		dsq_id = p->scx.dsq->id;
	}
	u64 ddsp_dsq_id = p->scx.ddsp_dsq_id;
	scx_bpf_dump("Task %d (%s) dump. dsq id: %llu, ddsp dsq id: %llu\n", p->pid, p->comm, dsq_id, ddsp_dsq_id);
}

SCX_OPS_DEFINE(deadline_wheel_ops,
	.select_cpu		= (void *)deadline_wheel_select_cpu,
	.enqueue		= (void *)deadline_wheel_enqueue,
	.dequeue		= (void *)deadline_wheel_dequeue,
	.dispatch		= (void *)deadline_wheel_dispatch,
	.runnable		= (void *)deadline_wheel_runnable,
	.running		= (void *)deadline_wheel_running,
	.stopping		= (void *)deadline_wheel_stopping,
	.quiescent		= (void *)deadline_wheel_quiescent,
	.cpu_acquire	= (void *)deadline_wheel_cpu_acquire,
	.cpu_release	= (void *)deadline_wheel_cpu_release,
	.enable			= (void *)deadline_wheel_enable,
	.disable		= (void *)deadline_wheel_disable,
	.init_task		= (void *)deadline_wheel_init_task,
	.exit_task		= (void *)deadline_wheel_exit_task,
	.init			= (void *)deadline_wheel_init,
	.exit			= (void *)deadline_wheel_exit,
	.dump			= (void *)deadline_wheel_dump,
	.dump_task		= (void *)deadline_wheel_dump_task,
	.flags			= SCX_OPS_ENQ_LAST | SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_MIGRATION_DISABLED,
	.name			= "deadline"
);
