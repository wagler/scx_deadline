#define BPF_NO_KFUNC_PROTOTYPES
// #include <asm-generic/errno-base.h>
#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define BPF_ASSERT(cond) \
    do { \
        if (!(cond)) \
            scx_bpf_error("Error: " #cond " was false"); \
    } while (0)

UEI_DEFINE(uei);

#define NS_IN_SEC 1000000000ULL
#define NUM_BUCKETS 10
#define FALLBACK_DSQ_ID 0

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 100); /* number of pages */
#ifdef __TARGET_ARCH_arm64
    __ulong(map_extra, 0x1ull << 32); /* start of mmap() region */
#else
    __ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
#endif
} arena SEC(".maps");


#include "bpf_arena_alloc.h"
#include "bpf_arena_list.h"

static int inited;
static bool scx_arena_verify_once;

__hidden void scx_arena_subprog_init(void)
{
	if (scx_arena_verify_once)
		return;

	bpf_printk("%s: arena pointer %p", __func__, &arena);
	scx_arena_verify_once = true;
}

struct arena_list_head __arena* list_head;
struct arena_list_head __arena global_head;

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
};

int num_nodes = 0;

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
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct deadline_wheel_slot);
	__uint(max_entries, NUM_BUCKETS);
} dl_wheel SEC(".maps");

struct cpu_curr_task {
	struct bpf_spin_lock lock;
	// struct task_ctx* curr_ctx;
	bool valid;
	int curr_pid;
	u64 curr_abs_dl;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct cpu_curr_task);
} cpu_curr_task_map SEC(".maps");

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
} task_relative_deadlines_map SEC(".maps");

static void print_bucket_list(u64 bucket_idx, struct deadline_wheel_slot* bucket)
{
	struct arena_task_node __arena * atnode = NULL;
	bpf_printk("Bucket %llu (count=%d)", bucket_idx, bucket->bucket_count);
	list_for_each_entry(atnode, bucket->head_ptr, node)
	{
		bpf_printk("%d->", atnode->pid);
	}
}

enum {
	MS_TO_NS		= 1000LLU * 1000,
	TIMER_INTERVAL_NS	= (100 * MS_TO_NS),
};

struct central_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct central_timer);
} central_timer SEC(".maps");

static int central_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	int i;
	struct task_struct* p;
	bpf_printk("[TIMER] FALLBACK_DSQ_ID contents:\n");
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, FALLBACK_DSQ_ID, 0) 
	{
		bpf_printk("%i\n", p->pid);
	}
	bpf_rcu_read_unlock();
	bpf_printk("[TIMER] FALLBACK_DSQ_ID end of contents.\n");

	bpf_for(i, 2, 4) 
	{
		// bpf_printk("Timer checking cpu %d\n", i);
		s32 num_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | i);
		bpf_printk("[TIMER] CPU %d DSQ contents:\n", i);
		bpf_rcu_read_lock();
		bpf_for_each(scx_dsq, p, SCX_DSQ_LOCAL_ON | i, 0) 
		{
			bpf_printk("%i\n", p->pid);
		}
		bpf_rcu_read_unlock();
		bpf_printk("[TIMER] CPU %d DSQ end of contents.\n", i);
		if (num_queued > 1)
		{
			scx_bpf_error("[TIMER] Error: CPU %d has %d tasks in its local DSQ\n", i, num_queued);
		}
		// else {
		// 	bpf_printk("CPU %d has %d tasks in its local DSQ\n", i, num_queued);
		// }
	}

	bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(deadline_wheel_init)
{
	bpf_printk("[INFO] [INIT] Starting SCX Deadline Wheel Scheduler\n");

	int ret = scx_bpf_create_dsq(FALLBACK_DSQ_ID, -1);
	if (ret)
		return ret;

	s32 cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) 
	{
		struct cpu_curr_task curr_task;
		// curr_task.curr_ctx = NULL;
		curr_task.valid = false;
		curr_task.curr_pid = -1;
		curr_task.curr_abs_dl = 0x7FFFFFFFFFFFFFFFULL;
		int res = bpf_map_update_elem(&cpu_curr_task_map, &cpu, &curr_task, BPF_ANY|BPF_F_LOCK);
		if (res)
		{
			scx_bpf_error("Failed to initialize cpu_curr_task_map for cpu %d", cpu);
			return -ENOMEM;
		}
		bpf_printk("[DEBUG] [INIT] Initialized running_task_ctx[cpu %d]", cpu);
	}

	for (u64 i = 0; i < NUM_BUCKETS; i++)
	{
		struct deadline_wheel_slot new_dl_slot;
		new_dl_slot.head_ptr = bpf_alloc(sizeof(*(new_dl_slot.head_ptr)));
		// new_dl_slot.head_ptr->first = NULL;
		new_dl_slot.bucket_count = 0;
		int res = bpf_map_update_elem(&dl_wheel, &i, &new_dl_slot, BPF_ANY|BPF_F_LOCK);
		if (res != 0)
		{
			scx_bpf_error("Error. Failed to initialize deadline wheel slot %llu.", i);
			return -1;
		}
		bpf_printk("[INFO] [INIT] Initialized deadline wheel slot # %llu.\n", i);
	}

	// u32 key = 0;
	// struct bpf_timer* timer = bpf_map_lookup_elem(&central_timer, &key);
	// if (!timer)
	// 	return -ESRCH;
	// bpf_timer_init(timer, &central_timer, CLOCK_MONOTONIC);
	// bpf_timer_set_callback(timer, central_timerfn);

	// ret = bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
	// if (ret)
	// 	scx_bpf_error("bpf_timer_start failed (%d)", ret);


    __sync_fetch_and_add(&inited,1);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(deadline_wheel_exit, struct scx_exit_info *ei)
{
	// struct arena_task_node __arena * atnode;
	// list_head = &global_head;
	// bpf_printk("Exiting. Deleting global list at %x\n", list_head);
	// list_for_each_entry(atnode, list_head, node) {
    //     list_del(&atnode->node);
	// 	//bucket->bucket_count--;
    //     bpf_free(atnode);
	// 	bpf_printk("Freed node at %x\n", atnode);
    // }

	bpf_printk("[INFO] [EXIT] Exiting SCX Deadline Wheel Scheduler\n");
	UEI_RECORD(uei, ei);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(deadline_wheel_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("Failed to allocate task_ctx for pid %d", p->pid);
		return -ENOMEM;
	}

	struct arena_task_node __arena* new_atnode = bpf_alloc(sizeof(*new_atnode));
	if (new_atnode == NULL)
	{
		scx_bpf_error("Failed to allocate new node for pid %d", p->pid);
		return -ENOMEM;
	}
	bpf_printk("Allocated node for pid %d at address 0x%x\n", p->pid, new_atnode);
	tctx->valid = false;
	tctx->atnode = new_atnode;
	tctx->pid = p->pid;
	tctx->abs_deadline = 0x7FFFFFFFFFFFFFFFULL;
	//new_atnode->id = __sync_fetch_and_add(&num_nodes, 1);

	// int node_id = new_atnode->id;
	// int pid = p->pid;
	new_atnode->pid = p->pid;
	new_atnode->cpumask = 0;
	new_atnode->in_bucket = false;
	// int res = bpf_map_update_elem(&node_id_to_pid, &node_id, &pid, BPF_ANY);
	// if (res)
	// {
	// 	scx_bpf_error("Failed to set node id %d mapping for pid %d. Error: %d", node_id, p->pid, res);
	// 	return -ENOMEM;
	// }

	// list_head = &global_head;
	// // list_add_head(&tctx->atnode->node, list_head);
	// bpf_printk("Added node for pid %d (0x%x) to global list.\n", p->pid, new_atnode);
	
	bpf_printk("[INFO] [TASK_INIT] Task %d (%s)initialized. Policy = %d.\n", p->pid, p->comm, p->policy);
	return 0;
}

void BPF_STRUCT_OPS(deadline_wheel_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	if (p->policy != 7) return;
	bpf_printk("[INFO] [TASK_EXIT] Task %d (%s) policy=%u exited\n", p->pid, p->comm, p->policy);
}

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

	struct task_rel_dl new_rel_dl;
	new_rel_dl.rel_deadline = NS_IN_SEC;
	int res = bpf_map_update_elem(&task_relative_deadlines_map, &pid, &new_rel_dl, BPF_ANY|BPF_F_LOCK);
	if (res)
	{
		scx_bpf_error("tsk_rel_dl update failed for pid %d", pid);
		return -ENOMEM;
	}
	bpf_printk("[DEBUG] [HELPER] Did not find an existing relative deadline for pid %d. Set new one to: %llu\n", pid, new_rel_dl.rel_deadline);
	return NS_IN_SEC;
}

void BPF_STRUCT_OPS(deadline_wheel_enable, struct task_struct *p)
{
	scx_arena_subprog_init();
	bpf_printk("[DEBUG] [ENABLE] Enabling task %d\n", p->pid);
	u64 rel_dl = get_rel_deadline(p);
	bpf_printk("[DEBUG] [ENABLE] Got relative deadline for task %d: %llu\n", p->pid, rel_dl);
	u64 abs_deadline = scx_bpf_now() + rel_dl;

	struct task_ctx *tctx;
	// If we start a task and then start the scheduler after, then it's possible we never
	// got into the .init_task function for this task. If this happens, we can't allocate a node now.
	// So error out, if we hit this case.
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("task_ctx lookup failed in enable");
		return;
	}

	// Set the context parameters
	bpf_spin_lock(&tctx->lock);
	tctx->abs_deadline = abs_deadline;
	tctx->pid = p->pid;
	tctx->valid = true;
	tctx->atnode->cpumask = (u64)*(int*)p->cpus_ptr;
	bpf_spin_unlock(&tctx->lock);
	bpf_printk("[INFO] [ENABLE] Set task %d mask to 0x%x\n.", p->pid, tctx->atnode->cpumask);

	// struct bpf_cpumask *kptr;
	// struct cpumasks_kfunc_map_value *v;
	// int key = p->pid;
	// bpf_cpumask_copy(tctx->atnode->cpumask, p->cpus_ptr);
	// int res = bpf_map_update_elem(&cpumasks_kfunc_map, &v, &curr_task, BPF_ANY);
	// if (res)
	// {
	// 	scx_bpf_error("Error looking up cpumask for pid %d.", p->pid);
	// 	return;
	// }

	struct arena_task_node __arena* atnode_addr = tctx->atnode;
	struct arena_list_node __arena* list_node_addr = NULL;
	if (tctx->atnode) list_node_addr = &(tctx->atnode->node);

	u64 time_from_now_us = (abs_deadline - scx_bpf_now())/1000ULL;
	bpf_printk("[DEBUG] [ENABLE] Task %d node = 0x%x, atnode = 0x%x\n", p->pid, list_node_addr, atnode_addr);
	// bpf_printk("[INFO] [ENABLE] Task %d (%s) policy=%u enabled. Mask = %x. Rel. DL = %llu ns, Abs. DL = %llu (time from now = %llu us).\n",
	// 	p->pid, p->comm, p->policy, *(int*)(p->cpus_ptr), rel_dl, time_from_now_us);
	bpf_printk("[INFO] [ENABLE] Task %d (%s) policy=%u enabled. Mask = %x.\n",
		p->pid, p->comm, p->policy, *(int*)(p->cpus_ptr));
}

void BPF_STRUCT_OPS(deadline_wheel_disable, struct task_struct *p)
{
	scx_arena_subprog_init();
	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("task_ctx lookup/creation failed");
		return;
	}

	bpf_spin_lock(&tctx->lock);
	tctx->valid = false;
	tctx->abs_deadline = 0x7FFFFFFFFFFFFFFFULL;
	bpf_spin_unlock(&tctx->lock);
	// bpf_cpumask_release(tctx->atnode->cpumask);
	tctx->atnode->cpumask = 0;

	if (tctx->atnode->in_bucket)
	{
		u64 bucket_idx = tctx->atnode->bucket;
		struct deadline_wheel_slot* bucket;
		if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
			scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
			return;
		}
		if (bucket)
		{
			int deleted_node = 0;
			bpf_spin_lock(&bucket->lock);
			if (tctx->atnode && tctx->atnode->in_bucket)
			{
				list_del(&tctx->atnode->node);
				tctx->atnode->in_bucket = false;
				bucket->bucket_count--;
				deleted_node = 1;
			}
			bpf_spin_unlock(&bucket->lock);
			if (deleted_node)
			{
				struct arena_task_node __arena* atnode2 = NULL;
				int error = 0;
				bpf_spin_lock(&bucket->lock);
				list_for_each_entry(atnode2, bucket->head_ptr, node)
				{
					if (atnode2->pid == tctx->atnode->pid)
					{
						error = 1;
						break;
					}
				}
				bpf_spin_unlock(&bucket->lock);
				if (error)
				{
					scx_bpf_error("Error, pid %d was still in list, after removing it.", tctx->atnode->pid);
				}
				
				if (((&tctx->atnode->node)->next != LIST_POISON1))
					scx_bpf_error("deleted node->next %x != LIST_POISON1(%x)", (u64)((&tctx->atnode->node)->next), (u64)(LIST_POISON1));
				if (((&tctx->atnode->node)->pprev != LIST_POISON2))
					scx_bpf_error("deleted node->pprev %x != LIST_POISON2(%x)", (u64)((&tctx->atnode->node)->pprev), (u64)(LIST_POISON2));
			}
			bpf_printk("[INFO] [DISABLE] Removed pid %d from bucket %llu. %d tasks remain in bucket\n", p->pid, bucket_idx, bucket->bucket_count);
			struct arena_task_node __arena* atnode = NULL;
			print_bucket_list(bucket_idx, bucket);
			if (bucket->bucket_count < 0)
			{
				scx_bpf_error("[ERROR] [DISABLE] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
			}
		}
	}

	bpf_printk("[INFO] [DISABLE] Task %d (%s) disabled\n", p->pid, p->comm);
}

s32 BPF_STRUCT_OPS(deadline_wheel_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bpf_printk("[DEBUG] [SELECT_CPU] Skipping select_cpu for task %d (%s)\n", p->pid, p->comm);
	return prev_cpu;
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

static s32 find_idle_cpu(struct task_struct *p, s32 prev_cpu)
{


	// if (p->nr_cpus_allowed == 1)
	// {
	// 	bpf_printk("Prev cpu (%d) is the only one allowed for %s-%d", prev_cpu, p->comm, p->pid);	
	// 	return prev_cpu;
	// }

	u32 key;
	bool prev_cpu_idle = scx_bpf_test_and_clear_cpu_idle(prev_cpu);
	if(prev_cpu_idle)
	{
		key = prev_cpu;
		struct cpu_curr_task* cpu_curr_task_ctx = bpf_map_lookup_elem(&cpu_curr_task_map, &key);
		if (!cpu_curr_task_ctx || !(cpu_curr_task_ctx->valid))
		{
			bpf_printk("[DEBUG] [HELPER] Prev cpu (%d) was idle", prev_cpu);
			return prev_cpu;
		}	
	}
	
	s32 cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
	{
		// TODO: is this really needed?
		bpf_rcu_read_lock();
		u64 nr_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
		bpf_rcu_read_unlock();
		if (nr_queued > 0)
		{
			return -1;
		}
		key = cpu;
		struct cpu_curr_task* cpu_curr_task_ctx = bpf_map_lookup_elem(&cpu_curr_task_map, &key);
		if (!cpu_curr_task_ctx || !(cpu_curr_task_ctx->valid))
		{
			bpf_printk("[DEBUG] [HELPER] Found idle cpu (%d) that's in mask", cpu);
			return cpu;
		}
	}

	return -1;
}

static s32 find_lower_priority_cpu(struct task_struct* p)
{
	if (!p)
	{
		return -1;
	}

	struct task_ctx *p_tctx = lookup_task_ctx(p);
	if (p_tctx == NULL)
	{
		return -1;
	}

	bpf_spin_lock(&p_tctx->lock);
	u64 p_abs_deadline = p_tctx->abs_deadline;
	bpf_spin_unlock(&p_tctx->lock);

	struct cpu_curr_task* cpu_curr_task_ctx;
	struct task_ctx *curr_ctx;
	s32 cpu;

	// Loop over the CPUs. Check if there's a sched_ext task dispatched to that CPU.
	// It could be running on the CPU or it could be in the CPU's local DSQ.
	// In either case, the task will be referenced in the CPU's cpu_curr_task_map entry.
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {

		// If the current task can't even run on this cpu, then skip it
		if(!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		{
			continue;
		}

		// Check if there's even a valid cpu_curr_task struct setup for this cpu
		u32 key = cpu;
		cpu_curr_task_ctx = bpf_map_lookup_elem(&cpu_curr_task_map, &key);
		if (!cpu_curr_task_ctx)
		{
			// If not, then skip it
			continue;
		}

		// bool valid_curr_ctx = false;
		// bpf_spin_lock(&cpu_curr_task_ctx->lock);
		// valid_curr_ctx = (cpu_curr_task_ctx->curr_ctx != NULL);
		// bpf_spin_unlock(&cpu_curr_task_ctx->lock);
		
		// There isn't a sched_ext task already dispatched to this cpu, then skip it
		// if (cpu_curr_task_ctx->curr_ctx == NULL)
		// {
		// 	continue;
		// }

		if (!(cpu_curr_task_ctx->valid))
		{
			continue;
		}

		// bpf_spin_lock(&curr_ctx->lock);
		u64 curr_task_abs_dl = cpu_curr_task_ctx->curr_abs_dl;
		bool valid = cpu_curr_task_ctx->valid;
		int curr_pid = cpu_curr_task_ctx->curr_pid;
		// bpf_spin_unlock(&curr_ctx->lock);

		if (!valid)
		{
			continue;
		}

		if (curr_task_abs_dl > p_abs_deadline)
		{
			bpf_printk(
				"[INFO] [ENQUEUE] Task pid=%d (abs_deadline %llu) preempting running task pid=%d (abs_deadline %llu) on core %d, because it has an earlier deadline\n", 
				p->pid, p_abs_deadline, curr_pid, curr_task_abs_dl, cpu
			);
			return cpu;
		}
	}
	return -1;
}

static s32 insert_task_into_deadline_wheel_bucket(struct task_ctx *p_tctx, u64 bucket_idx)
{
	if (p_tctx == NULL)
	{
		return -1;
	}
	if (!(p_tctx->valid))
	{
		scx_bpf_error("Tried to insert task_ctx into bucket, but task_ctx->valid==false");
		return -1;
	}

	struct deadline_wheel_slot* bucket;
	if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
		scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
		return -ENOMEM;
	}

	bpf_spin_lock(&bucket->lock);
	list_head = bucket->head_ptr;
	p_tctx->atnode->bucket = bucket_idx;
	struct arena_task_node __arena * atnode = NULL;
	int error = 0;
	list_for_each_entry(atnode, bucket->head_ptr, node)
	{
		if (atnode->pid == p_tctx->atnode->pid)
		{
			error = 1;
			break;
		}
	}
	list_add_head(&p_tctx->atnode->node, list_head);
	p_tctx->atnode->in_bucket = true;
	bucket->bucket_count++;
	bpf_spin_unlock(&bucket->lock);
	if (error)
	{
		scx_bpf_error("Error, pid %d was already in list, but re-inserted it again.", p_tctx->atnode->pid);
	}
	
	
	print_bucket_list(bucket_idx, bucket);
	bpf_printk("Inserted pid %d into deadline wheel bucket %llu. Num tasks in bucket = %d\n", p_tctx->pid, bucket_idx, bucket->bucket_count);

	if (bucket->bucket_count < 0)
	{
		scx_bpf_error("[ERROR] [HELPER] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
	}
	return 0;
}

void BPF_STRUCT_OPS(deadline_wheel_enqueue, struct task_struct *p, u64 enq_flags)
{
    BPF_ASSERT(p->policy == 7);
	scx_arena_subprog_init();
	bpf_printk("[INFO] [ENQUEUE] Enqueueing task %d (%s).\n", p->pid, p->comm);
	//Check for any idle CPUs this task can run on
	// s32 idle_cpu;
	// if (!(enq_flags & SCX_ENQ_REENQ) && !(enq_flags & SCX_ENQ_CPU_SELECTED) && (idle_cpu = find_idle_cpu(p, scx_bpf_task_cpu(p))) >= 0) {
	// 	bpf_printk("[INFO] [ENQUEUE] Enqueued task %d (%s) directly in cpu %d local dsq.\n", p->pid, p->comm, idle_cpu);
	// 	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle_cpu, SCX_SLICE_INF, enq_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
	// 	scx_bpf_kick_cpu(idle_cpu, SCX_KICK_PREEMPT);
	// 	return;
	// }

	// Check if there's a sched_ext task dispatched to a CPU, which has a later absolute deadline
	s32 lower_priority_cpu = find_lower_priority_cpu(p);
	if (lower_priority_cpu >= 0)
	{
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | lower_priority_cpu, SCX_SLICE_INF, enq_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
		scx_bpf_kick_cpu(lower_priority_cpu, SCX_KICK_PREEMPT);
		return;
	}

	// There was no idle CPU or lower priority task to preempt. Insert into the deadline wheel
	struct task_ctx *p_tctx = lookup_task_ctx(p);
	if (p_tctx == NULL)
	{
		scx_bpf_error("task_ctx does not exist for %d in enqueue.", p->pid);
		return;
	}
	scx_bpf_dsq_insert(p, FALLBACK_DSQ_ID, SCX_SLICE_INF, enq_flags);
	u64 bucket_idx = (p_tctx->abs_deadline) % NUM_BUCKETS;
	bpf_printk("[INFO] [ENQUEUE] No idle CPU or CPU w/ lower priority task. Putting pid %d (abs_deadline %llu) into bucket %llu\n", 
			p->pid, p_tctx->abs_deadline, bucket_idx);
	insert_task_into_deadline_wheel_bucket(p_tctx, bucket_idx);
}
void BPF_STRUCT_OPS(deadline_wheel_running, struct task_struct *p)
{
	u32 cpu = scx_bpf_task_cpu(p);
	struct cpu_curr_task* curr_task;
	curr_task = bpf_map_lookup_elem(&cpu_curr_task_map, &cpu);
	if (!curr_task)
	{
		scx_bpf_error("Failed to find cpu_curr_task_map for cpu %d", cpu);
		return;
	}

	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("task_ctx lookup failed in running");
		return;
	}
	if (!tctx->valid)
	{
		scx_bpf_error("Pid %d's task_ctx is invalid in running", p->pid);
		return;
	}

	bpf_spin_lock(&curr_task->lock);
	curr_task->valid = true;
	curr_task->curr_pid = p->pid;
	curr_task->curr_abs_dl = tctx->abs_deadline;
	bpf_spin_unlock(&curr_task->lock);
	
	u64 now = scx_bpf_now();
	bpf_printk("[INFO] [RUNNING] Running task %d (%s) on cpu %d (Abs. DL = %llu) [slice=%llu]\n", p->pid, p->comm, cpu, tctx->abs_deadline, p->scx.slice);
}

void BPF_STRUCT_OPS(deadline_wheel_stopping, struct task_struct *p, bool runnable)
{
	u64 now = scx_bpf_now();
	bpf_printk("[INFO] [STOPPING] Stopping task %d (%s), [slice=%llu][runnable = %d]\n", p->pid, p->comm, p->scx.slice, (int)runnable);
	u32 cpu = scx_bpf_task_cpu(p);
	struct cpu_curr_task* curr_task;
	curr_task = bpf_map_lookup_elem(&cpu_curr_task_map, &cpu);
	if (!curr_task)
	{
		scx_bpf_error("Failed to find cpu_curr_task_map for cpu %d", cpu);
		return;
	}

	if (!curr_task->valid)
	{
		scx_bpf_error("curr_task struct on cpu %d is marked invalid in stopping", cpu);
		return;
	}

	// bpf_printk("[%llu] [INFO] [STOPPING] Stopping task %d (%s) on cpu %d (Abs. DL = %llu)\n", now, p->pid, p->comm, cpu, curr_task->curr_abs_dl);

	bpf_spin_lock(&curr_task->lock);
	curr_task->valid = false;
	curr_task->curr_pid = -1;
	curr_task->curr_abs_dl = 0x7FFFFFFFFFFFFFFFULL;
	bpf_spin_unlock(&curr_task->lock);
}

struct bucket_loop_data {
	u64 start_bucket;
	bool found_task;
	u64 found_task_bucket;
	int pid;
	s32 cpu;
};

static long check_deadline_wheel_slot(u64 iteration, void* ctx)
{
	struct bucket_loop_data* bucket_data = (struct bucket_loop_data*)ctx;

	u64 bucket_idx = (iteration + bucket_data->start_bucket) % NUM_BUCKETS;
	struct deadline_wheel_slot* bucket;
	if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
		scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
		return 1;
	}

	bpf_spin_lock(&bucket->lock);
	if (bucket->bucket_count == 0)
	{
		bpf_spin_unlock(&bucket->lock);
		return 0;
	}

	if (!bucket->head_ptr)
	{
		bpf_spin_unlock(&bucket->lock);
		scx_bpf_error("Invalid bucket head pointer for bucket %llu.", bucket_idx);
		return 1;
	}
	struct arena_task_node __arena* atnode = NULL;
	list_for_each_entry(atnode, bucket->head_ptr, node)	
	{
		u64 mask = ((u64)(1 << bucket_data->cpu)) & atnode->cpumask;
		if (!mask)
		{
			continue;
		}

		list_del(&atnode->node);
		atnode->in_bucket = false;
		bucket->bucket_count--;
		bucket_data->found_task = true;
		bucket_data->found_task_bucket = bucket_idx;
		bucket_data->pid = atnode->pid;
		break;
	}

	bpf_spin_unlock(&bucket->lock);
	
	if (bucket_data->found_task)
	{	
		struct arena_task_node __arena* atnode2 = NULL;
		int error = 0;
		bpf_spin_lock(&bucket->lock);
		list_for_each_entry(atnode2, bucket->head_ptr, node)
		{
			if (atnode2->pid == bucket_data->pid)
			{
				error = 1;
				break;
			}
		}
		bpf_spin_unlock(&bucket->lock);
		if (error)
		{
			scx_bpf_error("Error, pid %d was still in list, after removing it.", bucket_data->pid);
		}

		if (((&atnode->node)->next != LIST_POISON1))
				scx_bpf_error("deleted node->next %x != LIST_POISON1(%x)", (u64)((&atnode->node)->next), (u64)(LIST_POISON1));
		if (((&atnode->node)->pprev != LIST_POISON2))
			scx_bpf_error("deleted node->pprev %x != LIST_POISON2(%x)", (u64)((&atnode->node)->pprev), (u64)(LIST_POISON2));
		
		bpf_printk("[INFO] [DISPATCH] Removed pid %d from bucket %llu. %d tasks remain in bucket\n", bucket_data->pid, bucket_idx, bucket->bucket_count);
		bpf_printk("[INFO] [DISPATCH] [CPU%d] Found node 0x%x (atnode = 0x%x) of task %d in bucket %llu. Mask=0x%x\n", 
		bucket_data->cpu, &atnode->node, atnode, bucket_data->pid, bucket_idx, atnode->cpumask);
		print_bucket_list(bucket_idx, bucket);
		if (bucket->bucket_count < 0)
		{
			scx_bpf_error("[ERROR] [DISPATCH] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
		}
		return 1;
	}
	return 0;
}

void BPF_STRUCT_OPS(deadline_wheel_dispatch, s32 cpu, struct task_struct *prev)
{
	if (cpu != 2 && cpu !=3) return;
	bpf_printk("[INFO] [DISPATCH] CPU %d dispatching\n", cpu);
    if (inited == 0) return;
    // bpf_printk("[INFO] [DISPATCH] Starting dispatch for CPU %d\n", cpu);
	scx_arena_subprog_init();
	if (prev && prev->policy == 7)
	{
		bpf_printk("[INFO] [DISPATCH] CPU %d dispatching from deadline wheel. Prev was pid %d (%s)(policy %d) with slice %llu.\n", cpu, prev->pid, prev->comm, prev->policy, prev->scx.slice);
	}

	u64 curr_time_ns = scx_bpf_now();
	u64 curr_time_bucket_idx = curr_time_ns % NUM_BUCKETS;

	struct bucket_loop_data bucket_data;
	bucket_data.start_bucket = curr_time_bucket_idx;
	bucket_data.found_task = false;
	bucket_data.found_task_bucket = 0x7FFFFFFFFFFFFFFFULL;
	bucket_data.pid = -1;
	bucket_data.cpu = cpu;

	// bpf_printk("[INFO] [DISPATCH] Checking buckets starting with #%llu\n", curr_time_bucket_idx);
	u64 iterations = NUM_BUCKETS;
    void *loop_ctx = (void*)&bucket_data;
    bpf_loop(iterations, check_deadline_wheel_slot, loop_ctx, 0);

	if (bucket_data.found_task)
	{
		if (bucket_data.pid == -1)
		{
			scx_bpf_error("bucket_data.pid == -1 but bucket_data.found_task_bucket==true");
            return;
		}
		int pid = bucket_data.pid;
		struct task_struct* tstruct = bpf_task_from_pid(pid);
        if (!tstruct)
        {
            scx_bpf_error("Invalid task_struct pointer for 'found' task_ctx (pid = %d)", pid);
            return;
        }

		bool can_run_on_cpu = bpf_cpumask_test_cpu(cpu, tstruct->cpus_ptr);
		if (!can_run_on_cpu)
		{
			bpf_printk("[INFO] [DISPATCH] Error: task %d's real mask %llu doesn't match its task_ctx mask. Returning to bucket %llu.\n",
				 tstruct->pid, (u64)*(int*)tstruct->cpus_ptr, bucket_data.found_task_bucket);
			insert_task_into_deadline_wheel_bucket(tstruct, bucket_data.found_task_bucket);
			bpf_task_release(tstruct);
			return;
		}

		pid = tstruct->pid;
		u64 mask = (u64)*(int*)tstruct->cpus_ptr;
		bpf_task_release(tstruct);

		bool success = false;
		struct task_struct *p;
		bpf_for_each(scx_dsq, p, FALLBACK_DSQ_ID, 0) 
		{
			if (p->pid == pid)
			{
				scx_bpf_dsq_move_set_slice(BPF_FOR_EACH_ITER, SCX_SLICE_INF);
				success = scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL_ON | cpu, SCX_ENQ_HEAD);//|SCX_ENQ_PREEMPT);
				if (!success)
				{
					scx_bpf_error("[INFO] [DISPATCH] Failed to dispatch task %d (mask=%llu) to cpu %d\n", pid, mask, cpu);
				}
				bpf_printk("[INFO] [DISPATCH] Dispatched task %d (mask=%llu) to cpu %d\n", p->pid, mask, cpu);
				
				break;
			}
		}
		// scx_bpf_dsq_insert(tstruct, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, SCX_ENQ_HEAD|SCX_ENQ_PREEMPT);
		

        return;
	}
	else 
	{
		s32 num_fallback = scx_bpf_dsq_nr_queued(FALLBACK_DSQ_ID);
		if (num_fallback > 0)
		{
			bpf_printk("Couldn't find a task in the deadline wheel, but the fallback dsq isn't empty (%d tasks).\n", num_fallback);
		}
	}
}

void BPF_STRUCT_OPS(deadline_wheel_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	u64 now = scx_bpf_now();
	bool is_kthread = (args->task->flags & PF_KTHREAD);
	if (true)
	{
		int num_tasks_reenqueued = scx_bpf_reenqueue_local();
		bpf_printk("[DEBUG] [RELEASE] Reenqued %d tasks from CPU %d's local DSQ\n", 
			num_tasks_reenqueued, cpu);
	}
	bpf_printk("[DEBUG] [RELEASE] CPU %d is released, reason: %u, next prio: %u, next pid: %lu, next comm: %s, kthread: %d\n", 
		cpu, args->reason, args->task->prio, args->task->pid, args->task->comm, is_kthread);
}

void BPF_STRUCT_OPS(deadline_wheel_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	u64 now = scx_bpf_now();
	bpf_printk("[DEBUG] [ACQUIRE] CPU %d is acquired\n", cpu);
}

void BPF_STRUCT_OPS(deadline_wheel_quiescent, struct task_struct *p, u64 deq_flags) {
	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	if (deq_flags & SCX_DEQ_CORE_SCHED_EXEC)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) going quiescent on cpu %d, because the generic core-sched layer decided to execute the task even though it hasn't been dispatched yet. Dequeue from the BPF side.\n", p->pid, p->comm, cpu);
	if (deq_flags & 0x01)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) dequeued because it's being sleeped\n", p->pid, p->comm);
	 if (deq_flags & 0x02)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) dequeued because it's being sleeped\n", p->pid, p->comm);
	 if (deq_flags & 0x04)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) dequeued because it's being moved\n", p->pid, p->comm);
	 if (deq_flags & 0x08)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) dequeued because no clock\n", p->pid, p->comm);
	 if (deq_flags & 0x10)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) dequeued because special\n", p->pid, p->comm);
	 if (deq_flags & 0x100)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) dequeued because migrating\n", p->pid, p->comm);
	 if (deq_flags & 0x200)
		bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) dequeued because delayed\n", p->pid, p->comm);
	
	bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) going quiescent [slice=%llu]\n", p->pid, p->comm, p->scx.slice);
}

void BPF_STRUCT_OPS(deadline_wheel_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = scx_bpf_now();
	if (enq_flags &  SCX_ENQ_WAKEUP )
	{
		bpf_printk("[INFO] [RUNNABLE] Task %d (%s) [slice=%llu] is runnable (waking up)\n", p->pid, p->comm, p->scx.slice);
	}
	else
	{
		bpf_printk("[INFO] [RUNNABLE] Task %d (%s) [slice=%llu] is runnable (migrated or restored after attribute change)\n", p->pid, p->comm, p->scx.slice);
	}
}

void BPF_STRUCT_OPS(deadline_wheel_dequeue, struct task_struct *p, u64 deq_flags)
{
	scx_arena_subprog_init();
	if (deq_flags & SCX_DEQ_SLEEP)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because it's no longer runnable\n", p->pid, p->comm);
	else if (deq_flags & SCX_DEQ_CORE_SCHED_EXEC)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because the generic core-sched layer decided to execute the task even though it hasn't been dispatched yet. Dequeue from the BPF side.\n", p->pid, p->comm);
	else if (deq_flags & 0x04)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because it's being moved\n", p->pid, p->comm);
	else if (deq_flags & 0x08)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because no clock\n", p->pid, p->comm);
	else if (deq_flags & 0x10)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because special\n", p->pid, p->comm);
	else if (deq_flags & 0x100)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because migrating\n", p->pid, p->comm);
	else if (deq_flags & 0x200)
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued because delayed\n", p->pid, p->comm);
	else
		bpf_printk("[INFO] [DEQUEUE] Task %d (%s) dequeued\n", p->pid, p->comm);

	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("task_ctx lookup failed in running");
		return;
	}

	u64 bucket_idx = tctx->atnode->bucket;
	struct deadline_wheel_slot* bucket;
	if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
		scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
		return;
	}

	bpf_spin_lock(&bucket->lock);
	if (bucket->bucket_count == 0)
	{
		bpf_spin_unlock(&bucket->lock);
		return;
	}

	int not_in_bucket = 0;
	if(tctx->atnode)
	{
		if (!(tctx->atnode->in_bucket))
		{
			not_in_bucket = 1;

		}
		list_del(&tctx->atnode->node);
		tctx->atnode->in_bucket = false;
		bucket->bucket_count--;
	}
	bpf_spin_unlock(&bucket->lock);

	if(tctx->atnode)
	{
		if (not_in_bucket)
		{
			scx_bpf_error("[ERROR] [DEQUEUE] Error: Tried to dequeue pid %d, but its not in a bucket.", tctx->atnode->pid);
		}
	
		struct arena_task_node __arena* atnode2 = NULL;
		int error = 0;
		bpf_spin_lock(&bucket->lock);
		list_for_each_entry(atnode2, bucket->head_ptr, node)
		{
			if (atnode2->pid == tctx->atnode->pid)
			{
				error = 1;
				break;
			}
		}
		bpf_spin_unlock(&bucket->lock);
		if (error)
		{
			scx_bpf_error("Error, pid %d was still in list, after removing it.", tctx->atnode->pid);
		}
	}

	if (((&tctx->atnode->node)->next != LIST_POISON1))
		scx_bpf_error("deleted node->next %x != LIST_POISON1(%x)", (u64)((&tctx->atnode->node)->next), (u64)(LIST_POISON1));
	if (((&tctx->atnode->node)->pprev != LIST_POISON2))
		scx_bpf_error("deleted node->pprev %x != LIST_POISON2(%x)", (u64)((&tctx->atnode->node)->pprev), (u64)(LIST_POISON2));
	bpf_printk("[INFO] [DEQUEUE] Removed pid %d from bucket %llu. %d tasks remain in bucket\n", p->pid, bucket_idx, bucket->bucket_count);
	print_bucket_list(bucket_idx, bucket);
	if (bucket->bucket_count < 0)
	{
		scx_bpf_error("[ERROR] [DEQUEUE] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
	}
}

void BPF_STRUCT_OPS(deadline_wheel_dump, struct scx_dump_ctx *dctx)
{
	scx_arena_subprog_init();
	scx_bpf_dump("Deadline Wheel Scheduler Dump:\n");
	int num_cpus = scx_bpf_nr_cpu_ids();
	scx_bpf_dump("Num cpus: %d\n", num_cpus);
	int cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) 
	{
		struct cpu_curr_task* curr_task = bpf_map_lookup_elem(&cpu_curr_task_map, &cpu);
		if (!curr_task)
		{
			continue;
		}
		if (curr_task->valid)
		{
			scx_bpf_dump("CPU %d: pid=%d, abs_dl=%llu\n", cpu, curr_task->curr_pid, curr_task->curr_abs_dl);
		}
		else 
		{
			scx_bpf_dump("CPU %d: No SCX task\n", cpu);
		}
	}

	scx_bpf_dump("Deadline Wheel:\n");
	for (u64 i = 0; i < NUM_BUCKETS; i++)
	{
		struct deadline_wheel_slot* bucket;
		if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &i))) {
			continue;
		}
		scx_bpf_dump("[%llu][%d tasks]: ", i, bucket->bucket_count);
		struct arena_task_node __arena * atnode = NULL;
		list_for_each_entry(atnode, bucket->head_ptr, node)
		{
			scx_bpf_dump("\t%d->", atnode->pid);
		}
		scx_bpf_dump("\n");
	}

	int i;
	struct task_struct* p;
	scx_bpf_dump("[TIMER] FALLBACK_DSQ_ID contents:\n");
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, FALLBACK_DSQ_ID, 0) 
	{
		scx_bpf_dump("%i\n", p->pid);
	}
	bpf_rcu_read_unlock();
	scx_bpf_dump("[TIMER] FALLBACK_DSQ_ID end of contents.\n");

	bpf_for(i, 2, 4) 
	{
		s32 num_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | i);
		scx_bpf_dump("[TIMER] CPU %d DSQ contents:\n", i);
		bpf_rcu_read_lock();
		bpf_for_each(scx_dsq, p, SCX_DSQ_LOCAL_ON | i, 0) 
		{
			scx_bpf_dump("%i\n", p->pid);
		}
		bpf_rcu_read_unlock();
		scx_bpf_dump("[TIMER] CPU %d DSQ end of contents.\n", i);
	}
}

void BPF_STRUCT_OPS_SLEEPABLE(deadline_wheel_cpu_online, s32 cpu)
{
	bpf_printk("CPU %d going offline\n", cpu);
}

void BPF_STRUCT_OPS_SLEEPABLE(deadline_wheel_cpu_offline, s32 cpu)
{
	bpf_printk("CPU %d coming online\n", cpu);
}

SCX_OPS_DEFINE(deadline_wheel_ops,
	.flags			= SCX_OPS_ENQ_LAST | SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_MIGRATION_DISABLED,
	.name			= "deadline",
	.init			= (void *)deadline_wheel_init,
	.exit			= (void *)deadline_wheel_exit,
	.init_task		= (void *)deadline_wheel_init_task,
	.exit_task		= (void *)deadline_wheel_exit_task,
	.enable			= (void *)deadline_wheel_enable,
	.disable		= (void *)deadline_wheel_disable,
	.select_cpu		= (void *)deadline_wheel_select_cpu,
	.enqueue		= (void *)deadline_wheel_enqueue,
	.dequeue		= (void *)deadline_wheel_dequeue,
	.running		= (void *)deadline_wheel_running,
	.stopping		= (void *)deadline_wheel_stopping,
	.dispatch		= (void *)deadline_wheel_dispatch,
	.quiescent		= (void *)deadline_wheel_quiescent,
	.cpu_acquire	= (void *)deadline_wheel_cpu_acquire,
	.cpu_release	= (void *)deadline_wheel_cpu_release,
	.cpu_online		= (void *)deadline_wheel_cpu_online,
	.cpu_offline	= (void *)deadline_wheel_cpu_offline,
	.runnable		= (void *)deadline_wheel_runnable,
	.dump			= (void *)deadline_wheel_dump
);

	
	// .runnable		= (void *)deadline_wheel_runnable,
	// .quiescent		= (void *)deadline_wheel_quiescent,
	// .cpu_acquire	= (void *)deadline_wheel_cpu_acquire,
	// .cpu_release	= (void *)deadline_wheel_cpu_release,
	
	// .init_task		= (void *)deadline_wheel_init_task,
	// .exit_task		= (void *)deadline_wheel_exit_task,
	// .dump_task		= (void *)deadline_wheel_dump_task,

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	int cpu = bpf_get_smp_processor_id();
	// if (!(cpu == 2 || cpu == 3))
	// {
    // 	return 0;
	// }

	int prev_pid = BPF_CORE_READ(prev, pid);
	int next_pid = BPF_CORE_READ(next, pid);

	char prev_comm[20];
	char next_comm[20];

	int ret = bpf_probe_read_kernel_str(prev_comm, sizeof(prev_comm), prev->comm);
    if (ret < 0) {
        bpf_printk("Failed to read prev process name, error: %d\n", ret);
        return 0;
    }

	ret = bpf_probe_read_kernel_str(next_comm, sizeof(next_comm), next->comm);
    if (ret < 0) {
        bpf_printk("Failed to read next process name, error: %d\n", ret);
        return 0;
    }

	bool prev_match = ((prev_comm[0] == 's') && (prev_comm[1] == 'a') && (prev_comm[2] == 'm') && (prev_comm[3] == 'p'));
	bool next_match = ((next_comm[0] == 's') && (next_comm[1] == 'a') && (next_comm[2] == 'm') && (next_comm[3] == 'p'));
	if (!(prev_match || next_match))
	{
		return 0;
	}

	int prev_prio = BPF_CORE_READ(prev, prio);
	int next_prio = BPF_CORE_READ(next, prio);

	unsigned int prev_state = BPF_CORE_READ(prev, __state);
	bpf_printk("[%d] Switch %s-%d (prio=%d, state=%d) ==> %s-%d (prio=%d)\n", 
		cpu, prev_comm, prev_pid, prev_prio, prev_state, next_comm, next_pid, next_prio);
	return 0;
}

struct sched_migrate_task_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long __data_loc_comm; 
    pid_t pid;      // offset:12
    int prio;       // offset:16
    int orig_cpu;   // offset:20
    int dest_cpu;   // offset:24
};

// Use the standard function definition, passing the context structure as the only argument
SEC("tp/sched/sched_migrate_task")
int sched_migrate_task_handler(struct sched_migrate_task_args *ctx)
{
    char comm[TASK_COMM_LEN];

    // The verifier now knows R1 is a pointer to struct sched_migrate_task_args
    bpf_get_current_comm(comm, sizeof(comm));

    bpf_printk("MIGRATION: %s (PID: %d) moved from CPU %d to CPU %d",
               comm, 
               ctx->pid, 
               ctx->orig_cpu, 
               ctx->dest_cpu);

    return 0;
}

// SEC("raw_tp/sched_wakeup")
// int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
// {
//  	int cpu = bpf_get_smp_processor_id();
// 	if (!(cpu == 2 || cpu == 3))
// 	{
//     	return 0;
// 	}

// 	int pid = BPF_CORE_READ(p, pid);

// 	char comm[20];
// 	int ret = bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);
//     if (ret < 0) {
//         bpf_printk("Failed to read prev process name, error: %d\n", ret);
//         return 0;
//     }

// 	int prio = BPF_CORE_READ(p, prio);

// 	bpf_printk("[%d] Wakeup %s-%d\n", cpu, comm, pid);
// 	return 0;
// }

// SEC("raw_tp/sched_wakeup_new")
// int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
// {
//  	int cpu = bpf_get_smp_processor_id();
// 	if (!(cpu == 2 || cpu == 3))
// 	{
//     	return 0;
// 	}

// 	int pid = BPF_CORE_READ(p, pid);

// 	char comm[20];
// 	int ret = bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);
//     if (ret < 0) {
//         bpf_printk("Failed to read prev process name, error: %d\n", ret);
//         return 0;
//     }

// 	int prio = BPF_CORE_READ(p, prio);

// 	bpf_printk("[%d] Wakeup new %s-%d\n", cpu, comm, pid);
// 	return 0;
// }

// SEC("raw_tp/sched_waking")
// int BPF_PROG(handle_sched_waking, struct task_struct *p)
// {
//  	int cpu = bpf_get_smp_processor_id();
// 	if (!(cpu == 2 || cpu == 3))
// 	{
//     	return 0;
// 	}

// 	int pid = BPF_CORE_READ(p, pid);

// 	char comm[20];
// 	int ret = bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);
//     if (ret < 0) {
//         bpf_printk("Failed to read prev process name, error: %d\n", ret);
//         return 0;
//     }

// 	int prio = BPF_CORE_READ(p, prio);

// 	bpf_printk("[%d] Waking %s-%d\n", cpu, comm, pid);
// 	return 0;
// }