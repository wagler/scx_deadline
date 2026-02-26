#define BPF_NO_KFUNC_PROTOTYPES
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <sdt_task.h>
#include "scx_deadline_wheel.h"
#include "bitmask_tree.h"
#include "linked_list.h"

char _license[] SEC("license") = "GPL";

#define BPF_ASSERT(cond) \
    do { \
        if (!(cond)) \
            scx_bpf_error("Error: " #cond " was false"); \
    } while (0)

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS_SLEEPABLE(scx_deadline_wheel_init)
{
	bpf_printk("[INIT] Starting scx_deadline_wheel scheduler");

	int ret = scx_task_init(sizeof(struct arena_task_node));
	if (ret < 0) {
		scx_bpf_error("Failed to initialize arena_list_node allocator. Error = %d", ret);
		return ret;
	}

	ret = scx_list_init(sizeof(struct arena_list_head));
	if (ret < 0) {
		scx_bpf_error("Failed to initialize arena_list_head allocator. Error = %d", ret);
		return ret;
	}

	s32 cpu;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) 
	{
		struct cpu_ctx curr_task;
		curr_task.valid = false;
		curr_task.curr_pid = -1;
		curr_task.curr_abs_dl = 0x7FFFFFFFFFFFFFFFULL;
		curr_task.preempted = false;
		curr_task.preempter_pid = -1;
		curr_task.sem = 0;
		int res = bpf_map_update_elem(&cpu_ctx_stor, &cpu, &curr_task, BPF_ANY);
		if (res)
		{
			scx_bpf_error("Failed to initialize cpu_curr_task_map for cpu %d", cpu);
			return -ENOMEM;
		}
	}

	u64 i;
	bpf_for(i, 0, num_buckets) {
		struct deadline_wheel_slot new_dl_slot;
		struct arena_list_head __arena* ptr = scx_list_alloc(i);
		if (!ptr) {
            scx_bpf_error("Allocation failed at bucket %llu", i);
            return -ENOMEM;
        }
		new_dl_slot.head_ptr = ptr;
		new_dl_slot.head_ptr->first = NULL;
		new_dl_slot.bucket_count = 0;
		new_dl_slot.sem = 0;
		int res = bpf_map_update_elem(&dl_wheel, &i, &new_dl_slot, BPF_ANY);
		if (res != 0)
		{
			scx_bpf_error("Error. Failed to initialize deadline wheel slot %llu.", i);
			return -1;
		}
	}

	u32 key = 0;
	struct bucket_bitmask_data *b_data =
		bpf_map_lookup_elem(&bucket_bitmask_map, &key);
	if (!b_data) {
		scx_bpf_error("Failed to lookup bucket_bitmask_map");
		return -1;
	}

	#pragma unroll
    for (int i = 0; i < MAX_STATIC_BITMASK_U64S; i++) {
        if (i >= MAX_STATIC_BITMASK_U64S)
            break;
            
        b_data->bitmasks[i] = 0;
        
        // This prevents Clang from replacing the loop with memset
        __asm__ volatile("" : : : "memory");
    }

	__sync_lock_test_and_set(&b_data->sem, 0);
	__sync_fetch_and_add(&inited, 1);


	bpf_printk("[INFO] [INIT] Initialized SCX Deadline Wheel Scheduler with %d cpus and %llu bucket slots", scx_bpf_nr_cpu_ids(), num_buckets);
	return 0;
}

void BPF_STRUCT_OPS(scx_deadline_wheel_exit, struct scx_exit_info *ei)
{
	// All arena data gets wiped after scheduler exits, so no point freeing arena mem here.	
	UEI_RECORD(uei, ei);
}

void BPF_STRUCT_OPS(deadline_wheel_enable, struct task_struct *p)
{
	const u64 rel_dl = get_rel_deadline(p);
	bpf_printk("[DEBUG] [ENABLE] Enabling task %d with relative deadline %llu\n", p->pid, rel_dl);
	u64 abs_deadline = scx_bpf_now() + rel_dl;

	// Create a new task context structure for this thread
	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("Failed to allocate task_ctx for pid %d", p->pid);
		return;
	}

	struct arena_task_node __arena* new_atnode;
	new_atnode = scx_task_alloc(p);
	if (!new_atnode) {
		scx_bpf_error("arena allocator out of memory");
		return;
	}

	new_atnode->pid = p->pid;
	new_atnode->cpumask = 0;
	new_atnode->in_bucket = false;

	bpf_spin_lock(&tctx->lock);
	tctx->atnode = new_atnode;
	tctx->abs_deadline = abs_deadline;
	tctx->pid = p->pid;
	tctx->valid = true;
	bpf_spin_unlock(&tctx->lock);

	if(p->pid!=tctx->atnode->pid)
	{
		scx_bpf_error("[ENABLE] task's real pid %d does not match atnode's pid %d.", p->pid, tctx->atnode->pid);
	}
	// scx_bpf_task_set_slice(p, SCX_SLICE_INF);
	bpf_printk("[DEBUG] [ENABLE] Task %d (%s) policy=%u, mask=%x, node = 0x%x, atnode = 0x%x\n", 
		p->pid, p->comm, p->policy, *(int*)(p->cpus_ptr), tctx->atnode, new_atnode);
}

void BPF_STRUCT_OPS(deadline_wheel_disable, struct task_struct *p)
{

	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("task_ctx lookup/creation failed");
		return;
	}

	bpf_spin_lock(&tctx->lock);
	tctx->valid = false;
	tctx->abs_deadline = 0x7FFFFFFFFFFFFFFFULL;
	bpf_spin_unlock(&tctx->lock);

	if (tctx->atnode->in_bucket)
	{
		u64 bucket_idx = tctx->atnode->bucket;
		struct deadline_wheel_slot* bucket;
		if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
			scx_bpf_error("[DISABLE] Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
			return;
		}

		slock(&bucket->sem);
		bpf_printk("[DISABLE] Got bucket->sem!!");
		if (tctx->atnode && tctx->atnode->in_bucket)
		{
			list_del(&tctx->atnode->node);
			tctx->atnode->in_bucket = false;
			bucket->bucket_count--;
		}
		bpf_printk("[INFO] [DISABLE] Removed pid %d from bucket %llu. %d tasks remain in bucket\n", p->pid, bucket_idx, bucket->bucket_count);
		if (bucket->bucket_count < 0)
		{
			scx_bpf_error("[ERROR] [DISABLE] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
		}
		sunlock(&bucket->sem);
		
		
	}

    struct arena_list_node __arena* node;
	node = scx_task_data(p);
	if (!node) {
		scx_bpf_error("%s: no node for pid %d", __func__, p->pid);
		return;
	}
	scx_task_free(p);
	tctx->atnode = NULL;

	bpf_printk("[INFO] [DISABLE] Task %d (%s) disabled\n", p->pid, p->comm);
}

s32 BPF_STRUCT_OPS(deadline_wheel_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bpf_printk("[DEBUG] [SELECT_CPU] Skipping select_cpu for task %d (%s)\n", p->pid, p->comm);
	return prev_cpu;
}

static s32 find_idle_cpu(struct task_struct *p, s32 prev_cpu)
{
	// First check if the previous cpu the task ran on is now available. This can help avoid migration
	u32 key;
	bool prev_cpu_idle = scx_bpf_test_and_clear_cpu_idle(prev_cpu);
	if(prev_cpu_idle)
	{
		key = prev_cpu;
		struct cpu_ctx* cpu_curr_task_ctx = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cpu_curr_task_ctx || !(cpu_curr_task_ctx->valid))
		{
			bpf_printk("[DEBUG] [HELPER] Prev cpu (%d) was idle", prev_cpu);
			return prev_cpu;
		}
	}
	
	// Look for any other idle cpu
	s32 cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
	{
		struct cpu_ctx* cpu_curr_task_ctx = bpf_map_lookup_elem(&cpu_ctx_stor, &cpu);
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

	struct cpu_ctx* cpu_curr_task_ctx;
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
		cpu_curr_task_ctx = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cpu_curr_task_ctx)
		{
			// If not, then skip it
			continue;
		}

		slock(&cpu_curr_task_ctx->sem);
		u64 curr_task_abs_dl = cpu_curr_task_ctx->curr_abs_dl;
		bool valid = cpu_curr_task_ctx->valid;
		int curr_pid = cpu_curr_task_ctx->curr_pid;

		if (!valid || cpu_curr_task_ctx->preempted)
		{
			sunlock(&cpu_curr_task_ctx->sem);
			continue;
		}

		if (curr_task_abs_dl > p_abs_deadline)
		{
			cpu_curr_task_ctx->preempted = true;
			cpu_curr_task_ctx->preempter_pid = p->pid;
			sunlock(&cpu_curr_task_ctx->sem);
			bpf_printk(
				"[INFO] [ENQUEUE] Task pid=%d (abs_deadline %llu) preempting running task pid=%d (abs_deadline %llu) on core %d, because it has an earlier deadline\n", 
				p->pid, p_abs_deadline, curr_pid, curr_task_abs_dl, cpu
			);
			return cpu;
		}
		sunlock(&cpu_curr_task_ctx->sem);
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

	// bpf_spin_lock(&bucket->lock);
	u32 bitmask_key = 0;
	struct bucket_bitmask_data *b_data =
		bpf_map_lookup_elem(&bucket_bitmask_map, &bitmask_key);
	if(b_data) slock(&b_data->sem);
	slock(&bucket->sem);

	struct arena_list_head __arena* list_head;
	list_head = bucket->head_ptr;
	p_tctx->atnode->bucket = bucket_idx;
	struct arena_task_node __arena * atnode = NULL;
	int error = 0;
	list_for_each_entry(atnode, bucket->head_ptr, node)
	{
		if (atnode->pid == p_tctx->atnode->pid)
		{
			error = 1;
			bpf_printk("Re-insertion error, pid %d was already in list, but re-inserted it again.", p_tctx->atnode->pid);
			scx_bpf_error("Error, pid %d was already in list, but re-inserted it again.", p_tctx->atnode->pid);
			goto insert_done;
			break;
		}
	}
	list_add_head(&p_tctx->atnode->node, list_head);
	p_tctx->atnode->in_bucket = true;
	bucket->bucket_count++;
	// print_bucket_list(bucket_idx, bucket);
	// bpf_spin_unlock(&bucket->lock);
	bpf_printk("Inserted pid %d into deadline wheel bucket %llu. Num tasks in bucket = %d\n", p_tctx->pid, bucket_idx, bucket->bucket_count);
	// int u64_array_idx = bucket_idx / 64;
	// int bit_idx = bucket_idx % 64;
	// bucket_bitmask_array[u64_array_idx] |= (1 << bit_idx);
	// bpf_printk("Enabled bit for bucket index %llu; array idx = %d, bit idx = %d, bucket_bitmask_array[%d]=0x%x\n", 
	// 		bucket_idx, u64_array_idx, bit_idx, u64_array_idx, bucket_bitmask_array[u64_array_idx]);
	set_bitmask_tree(b_data, bucket_idx);
	// print_bucket_tree();
	
	// if (b_data) {
	// 	// bpf_spin_lock(&b_data->lock);
	// 	// slock(&b_data->sem);
	// 	// bpf_printk("[INSERT] Got b_data lock!!!");
		
	// 	// bpf_spin_unlock(&b_data->lock);
	// 	__sync_val_compare_and_swap(&b_data->sem, 1, 0);
	// }

	if (bucket->bucket_count < 0)
	{
		scx_bpf_error("[ERROR] [HELPER] Number of tasks in bucket %llu is %d\n", bucket_idx, bucket->bucket_count);
	}
insert_done:
	sunlock(&bucket->sem);
	if(b_data) {sunlock(&b_data->sem);}
	
	return 0;
}

void BPF_STRUCT_OPS(deadline_wheel_enqueue, struct task_struct *p, u64 enq_flags)
{
    BPF_ASSERT(p->policy == 7);
	if(p->pid == 0) {
		bpf_printk("[ENQUEUE] Pid %d was trying to enqueue", p->pid);
		return;
	}
	scx_arena_subprog_init();
	bpf_printk("[INFO] [ENQUEUE] Enqueueing task %d (%s).\n", p->pid, p->comm);
	//Check for any idle CPUs this task can run on
	s32 idle_cpu;
	s32 task_cpu = scx_bpf_task_cpu(p);
	if ((enq_flags & SCX_ENQ_REENQ) && !(enq_flags & SCX_ENQ_CPU_SELECTED) && ((idle_cpu = find_idle_cpu(p, scx_bpf_task_cpu(p))) >= 0) && !(is_migration_disabled(p) && task_cpu!=idle_cpu)) {
		bpf_printk("[INFO] [ENQUEUE] Enqueued task %d (%s) directly in cpu %d local dsq.\n", p->pid, p->comm, idle_cpu);
		bpf_printk("[ENQUEUE] printing local dsq, num elements in idle cpu %d: %d", idle_cpu, scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | idle_cpu));
		struct task_struct* q;
		bpf_for_each(scx_dsq, q, SCX_DSQ_LOCAL_ON | idle_cpu, 0)
		{
			bpf_printk("Hello!");
			bpf_printk("[ENQUEUE] %s[%d]", q->comm, q->pid);
		}
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle_cpu, SCX_SLICE_INF, enq_flags | SCX_ENQ_HEAD | SCX_ENQ_PREEMPT);
		scx_bpf_kick_cpu(idle_cpu, SCX_KICK_PREEMPT);
		return;
	}

	// Check if there's a sched_ext task dispatched to a CPU, which has a later absolute deadline
	s32 lower_priority_cpu = find_lower_priority_cpu(p);
	if (lower_priority_cpu >= 0 && !(is_migration_disabled(p) && task_cpu!=lower_priority_cpu))
	{
		bpf_printk("[ENQUEUE] printing local dsq, num elements in lower priority cpu %d: %d", lower_priority_cpu, scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | lower_priority_cpu));
		struct task_struct* q;
		bpf_for_each(scx_dsq, q, SCX_DSQ_LOCAL_ON | lower_priority_cpu, 0)
		{
			bpf_printk("Hello!");
			bpf_printk("[ENQUEUE] %s[%d]", q->comm, q->pid);
		}
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
	
	u64 bucket_idx = (p_tctx->abs_deadline) % num_buckets;
	if (p_tctx->atnode->in_bucket) {
		bpf_printk("[ENQUEUE] Task %d is already in bucket", p_tctx->pid);
		if(p_tctx->atnode->bucket==bucket_idx){
			bpf_printk("[ENQUEUE] Task %d was already in bucket %d", p_tctx->pid, bucket_idx);
			return;
		}
		else{
			scx_bpf_error("[ENQUEUE] Task %d was already in bucket %llu, attempting to reinsert in different bucket %llu", p_tctx->pid, p_tctx->atnode->bucket, bucket_idx);
		} 
    }
	bpf_printk("[INFO] [ENQUEUE] No idle CPU or CPU w/ lower priority task. Putting pid %d (abs_deadline %llu) into bucket %llu\n", 
			p->pid, p_tctx->abs_deadline, bucket_idx);
	insert_task_into_deadline_wheel_bucket(p_tctx, bucket_idx);
}

void BPF_STRUCT_OPS(deadline_wheel_running, struct task_struct *p)
{
	u32 cpu = scx_bpf_task_cpu(p);
	struct cpu_ctx* curr_task;
	curr_task = bpf_map_lookup_elem(&cpu_ctx_stor, &cpu);
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

	// bpf_spin_lock(&curr_task->lock);
	slock(&curr_task->sem);
	// int preempter_pid = curr_task->preempter_pid;
	// bool was_preempter = (curr_task->preempter_pid==p->pid);
	// bool was_preempting = (curr_task->preempted);
	if(curr_task->preempted && curr_task->preempter_pid!=p->pid && curr_task->curr_pid!=p->pid && curr_task->curr_pid!=-1)
	{
		sunlock(&curr_task->sem);
		scx_bpf_error("[RUNNING] task %d was not the latest preempter (%d) or preempted task (%d)", p->pid, curr_task->preempter_pid, curr_task->curr_pid);
		return;
	}
	if(curr_task->preempted && curr_task->preempter_pid==p->pid){
		curr_task->preempter_pid = -1;
		curr_task->preempted = false;
	}
	
	curr_task->valid = true;
	curr_task->curr_pid = p->pid;
	curr_task->curr_abs_dl = tctx->abs_deadline;
	// bpf_spin_unlock(&curr_task->lock);
	sunlock(&curr_task->sem);
	
	bpf_printk("[INFO] [RUNNING] Running task %d (%s) on cpu %d (Abs. DL = %llu) [slice=%llu]\n", p->pid, p->comm, cpu, tctx->abs_deadline, p->scx.slice);
}

void BPF_STRUCT_OPS(deadline_wheel_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = scx_bpf_task_cpu(p);
	bpf_printk("[INFO] [STOPPING] Stopping task %d (%s) on cpu %d, [slice=%llu][runnable = %d]\n", p->pid, p->comm, cpu, p->scx.slice, (int)runnable);
	struct cpu_ctx* curr_task;
	curr_task = bpf_map_lookup_elem(&cpu_ctx_stor, &cpu);
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

__hidden
static inline int fetch_from_bucket(u64 bucket_idx, struct bucket_bitmask_data *b_data, s32 cpu){
	scx_arena_subprog_init();
	struct deadline_wheel_slot* bucket;
	int pid = -1;
	if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
		return -1;
		// scx_bpf_error("Failed to get bucket idx %llu pointer, after creating it", bucket_idx);
	}
	slock(&bucket->sem);
	bpf_printk("[FETCH] Got bucket->sem lock!!!!");
	if (bucket->bucket_count == 0)
	{
		bpf_printk("[FETCH] Bucket %lu is empty", bucket_idx);
		goto done;
	}
	if (!bucket->head_ptr)
	{
		bpf_printk("[FETCH] Bucket %lu head ptr is null", bucket_idx);
		goto done;
		// scx_bpf_error("Invalid bucket head pointer for bucket %llu.", bucket_idx);
	}

	struct arena_task_node __arena* atnode = NULL;
	list_for_each_entry(atnode, bucket->head_ptr, node)	
	{
		struct task_struct *tstruct = bpf_task_from_pid(atnode->pid);
	    if (!tstruct) {
			goto done;
		    // scx_bpf_error(
			//     "Invalid task_struct pointer for 'found' task_ctx (pid = %d)",
			//     atnode->pid);
	    }
		bool can_run_on_cpu = bpf_cpumask_test_cpu(cpu, tstruct->cpus_ptr);
		if((is_migration_disabled(tstruct)) && (cpu != scx_bpf_task_cpu(tstruct)))
		{
			can_run_on_cpu = false;
		}
		
	    if (can_run_on_cpu) {
		    list_del(&atnode->node);
			pid = atnode->pid;
			atnode->in_bucket = false;
			bucket->bucket_count--;
			if(bucket->bucket_count==0){
				// bpf_spin_lock(&b_data->lock);
				clear_bitmask_tree(b_data, bucket_idx);
				bpf_printk("[FETCH] cleared bit %d from bitmask", bucket_idx);
				// print_bucket_tree();
				// bpf_spin_unlock(&b_data->lock);
				
				// bpf_printk(
				// 	"[FETCH_FROM_BUCKET] Disabled bit using clear_bitmask_tree for bucket index %llu",
				// 	bucket_idx);
			}
			bpf_task_release(tstruct);
			break;
	    }
		bpf_task_release(tstruct);
	}

	done:
	sunlock(&bucket->sem);
	return pid;
}

void BPF_STRUCT_OPS(deadline_wheel_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_arena_subprog_init();
    if (inited == 0) return;

	if (cpu != 2 && cpu != 3) return;
	
	u32 bucket_bitmask_key=0;
	struct bucket_bitmask_data *b_data = bpf_map_lookup_elem(&bucket_bitmask_map, &bucket_bitmask_key);
	int pid = -1;
	u64 highest_nonempty_idx;
	if(b_data)
	{
		slock(&b_data->sem);
		highest_nonempty_idx = get_highest_bitmask_tree(b_data);
		if (highest_nonempty_idx!=-1)
		{
			pid = fetch_from_bucket(highest_nonempty_idx, b_data, cpu);
			if(pid == -1) {bpf_printk("[DISPATCH] Found %d but bucket was empty", highest_nonempty_idx);}
		}
		sunlock(&b_data->sem);
	}
	if(!b_data || pid == -1)
	{
		return;
	}
    
	struct task_struct *tstruct = bpf_task_from_pid(pid);
	if (!tstruct) {
		scx_bpf_error(
			"Invalid task_struct pointer for 'found' task_ctx (pid = %d)",
			pid);
		return;
	}

	if (!(is_migration_disabled(tstruct) && (cpu != scx_bpf_task_cpu(tstruct)))) {
		scx_bpf_dsq_insert(tstruct, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_INF, SCX_ENQ_HEAD|SCX_ENQ_PREEMPT);
	}

	bpf_task_release(tstruct);
	bpf_printk("[DISPATCH] Cpu %d dispatched task %d", cpu, pid);
} 

SEC("tp_btf/sched_switch")
int BPF_PROG(deadline_wheel_sched_switch, bool preempt, struct task_struct *prev,
         struct task_struct *next, unsigned long prev_state)
{
    // if (!__COMPAT_scx_bpf_reenqueue_local_from_anywhere())
    //     return 0;

	bool is_kthread = (next->flags & PF_KTHREAD);

    // Core is getting taken by a task of a higher-priority scheduling class.
    // This next task isn't a kthread, so it might take a while before sched-ext gets the core again. 
    // Reenqueue local DSQ tasks in the meantime so they can run elsewhere.
    // if (preempt && !is_kthread) {
    //     scx_bpf_reenqueue_local();
	// 	int cpu = bpf_get_smp_processor_id();
	// 	if (prev->policy == 7 && next->policy != 7)
	// 	{
	// 		bpf_printk("[DEBUG] [SCHED-SWITCH] CPU %d is released, prev pid: %d, next prio: %u, next pid: %lu, next comm: %s, kthread: %d\n", 
	// 			cpu, prev->pid, next->prio, next->pid, next->comm, is_kthread);
	// 	}
    // }

    return 0;
}

void BPF_STRUCT_OPS(deadline_wheel_quiescent, struct task_struct *p, u64 deq_flags) {
	bpf_printk("[DEBUG] [QUIESCENT] Task %d (%s) going quiescent [slice=%llu]\n", p->pid, p->comm, p->scx.slice);
}

void BPF_STRUCT_OPS(deadline_wheel_runnable, struct task_struct *p, u64 enq_flags)
{
	bool enqueue_restore = enq_flags & 0x0002;
	if (enq_flags &  SCX_ENQ_WAKEUP )
	{
		bpf_printk("[INFO] [RUNNABLE] Task %d (%s) [slice=%llu] is runnable (waking up) [ENQUEUE_RESTORE=%d]\n", p->pid, p->comm, p->scx.slice, enqueue_restore);
	}
	else
	{
		bpf_printk("[INFO] [RUNNABLE] Task %d (%s) [slice=%llu] is runnable (migrated or restored after attribute change) [ENQUEUE_RESTORE=%d]\n", p->pid, p->comm, p->scx.slice, enqueue_restore);
	}
}

void BPF_STRUCT_OPS(deadline_wheel_dequeue, struct task_struct *p, u64 deq_flags)
{
	scx_arena_subprog_init();
	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0))) {
		scx_bpf_error("task_ctx lookup failed in running");
		return;
	}

	u64 bucket_idx = tctx->atnode->bucket;
	struct deadline_wheel_slot* bucket;
	if (!(bucket = bpf_map_lookup_elem(&dl_wheel, &bucket_idx))) {
		return;
	}

	s32 key = 0;
	struct bucket_bitmask_data *b_data =
		bpf_map_lookup_elem(&bucket_bitmask_map, &key);
	slock(&b_data->sem);
	slock(&bucket->sem);

	if (bucket->bucket_count == 0)
	{
		goto dequeue_done;
	}
	if (!bucket->head_ptr)
	{
		goto dequeue_done;
		// scx_bpf_error("Invalid bucket head pointer for bucket %llu.", bucket_idx);
	}
	if (tctx->atnode->in_bucket){
		
		list_del(&tctx->atnode->node);
		tctx->atnode->in_bucket = false;
		bucket->bucket_count--;
		bpf_printk("[DEQUEUE] removed task %d from bucket %lu", p->pid, bucket_idx);
		if(bucket->bucket_count==0){
			clear_bitmask_tree(b_data, bucket_idx);
			bpf_printk("[DEQUEUE] cleared bit %d from bitmask", bucket_idx);
		}
	 }

dequeue_done:
	sunlock(&bucket->sem);
	sunlock(&b_data->sem);
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
		struct cpu_ctx* curr_task = bpf_map_lookup_elem(&cpu_ctx_stor, &cpu);
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
	for (u64 i = 0; i < num_buckets; i++)
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

	struct task_struct* p;
	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) 
	{
		s32 num_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
		scx_bpf_dump("[DUMP] CPU %d DSQ contents:\n", cpu);
		bpf_rcu_read_lock();
		bpf_for_each(scx_dsq, p, SCX_DSQ_LOCAL_ON | cpu, 0) 
		{
			scx_bpf_dump("%i\n", p->pid);
		}
		bpf_rcu_read_unlock();
		scx_bpf_dump("[DUMP] CPU %d DSQ end of contents.\n", cpu);
	}
	// dump_bucket_tree();
}


s32 BPF_STRUCT_OPS_SLEEPABLE(scx_deadline_wheel_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	// Create a new task context structure for this thread
	struct task_ctx *tctx;
	if (!(tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE))) {
		scx_bpf_error("Failed to allocate task_ctx for pid %d", p->pid);
		return -ENOMEM;
	}
	return 0;
}

void BPF_STRUCT_OPS(deadline_exit_task, struct task_struct *p, struct scx_exit_task_args *args){
	s32 pid = p->pid;
	bpf_map_delete_elem(&task_relative_deadlines_map, &pid);
}

SCX_OPS_DEFINE(scx_deadline_wheel_ops,
	
	.flags			= SCX_OPS_ENQ_LAST | SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_MIGRATION_DISABLED,
	.name			= "scx_deadline_wheel",
	.init			= (void *)scx_deadline_wheel_init,
	.exit			= (void *)scx_deadline_wheel_exit,
	.enable			= (void *)deadline_wheel_enable,
	.disable		= (void *)deadline_wheel_disable,
	.select_cpu		= (void *)deadline_wheel_select_cpu,
	.enqueue		= (void *)deadline_wheel_enqueue,
	.dequeue		= (void *)deadline_wheel_dequeue,
	.running		= (void *)deadline_wheel_running,
	.stopping		= (void *)deadline_wheel_stopping,
	.dispatch		= (void *)deadline_wheel_dispatch,
	.quiescent		= (void *)deadline_wheel_quiescent,
	.runnable		= (void *)deadline_wheel_runnable,
	.dump			= (void *)deadline_wheel_dump,
	.init_task 		= (void *)scx_deadline_wheel_init_task,
	.exit_task 		= (void *)deadline_exit_task
);