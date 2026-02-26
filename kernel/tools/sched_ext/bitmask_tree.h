// #include <scx/common.bpf.h>
// #include "scx_deadline_wheel.h"

// #define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
// #define NR_L0 DIV_ROUND_UP(NUM_BUCKETS, 64)
// #define NR_L1 (NR_L0 > 1 ? DIV_ROUND_UP(NR_L0, 64) : 0)
// #define NR_L2 (NR_L1 > 1 ? DIV_ROUND_UP(NR_L1, 64) : 0)
// #define NR_L3 (NR_L2 > 1 ? DIV_ROUND_UP(NR_L2, 64) : 0)
// #define MAX_BITMASK_U64S (NR_L0 + NR_L1 + NR_L2 + NR_L3)
// #define NUM_LEVELS ((NR_L0 > 0) + (NR_L1 > 0) + (NR_L2 > 0) + (NR_L3 > 0))
// #define L0_OFF 0
// #define L1_OFF (L0_OFF + NR_L0)
// #define L2_OFF (L1_OFF + NR_L1)
// #define L3_OFF (L2_OFF + NR_L2)

// static inline int 
// get_level_offset(const int level)
// {
// 	switch(level)
//     {
// 		case 0:
// 			return L0_OFF;
// 		case 1:
// 			return L1_OFF;
// 		case 2:
// 			return L2_OFF;
// 		case 3:
// 			return L3_OFF;
// 		default:
// 			return -1;
// 	}
// }

// struct bucket_bitmask_data
// {
// 	struct bpf_spin_lock lock;
// 	int sem;
// 	u64 bitmasks[MAX_BITMASK_U64S];
// };

// struct
// {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, u32);
// 	__type(value, struct bucket_bitmask_data);
// } bucket_bitmask_map SEC(".maps");

// static inline void 
// set_bitmask_tree(struct bucket_bitmask_data *b_data, const u64 bucket_idx)
// {
// 	u64 curr_idx = bucket_idx / 64;
//     u64 bit = bucket_idx % 64;

// 	#pragma unroll
// 	for (int l = 0; l < 4; l++) 
//     {
// 		if (l >= NUM_LEVELS)
//         {
//             break;
//         }

// 		const int offset = get_level_offset(l);
// 		const int final_idx = offset + curr_idx;
// 		if(final_idx >= MAX_BITMASK_U64S || final_idx<0) 
//         {
//             break;
//         }

// 		const u64 old_val = b_data->bitmasks[final_idx];
// 		b_data->bitmasks[final_idx] |= (1ULL << bit);
			 
// 		if (old_val != 0) 
//         {
//             break;
//         }

// 		bit = curr_idx % 64;
// 		curr_idx /= 64;
// 	}
// }

// static inline void
// clear_bitmask_tree(struct bucket_bitmask_data *b_data, const u64 bucket_idx)
// {
// 	u64 curr_idx = bucket_idx / 64;
// 	u64 bit = bucket_idx % 64;

// 	#pragma unroll
// 	for (int l = 0; l < 4; l++) 
//     {
// 		if (l >= NUM_LEVELS)
//         {
//             break;
//         }

// 		const int offset = get_level_offset(l);
// 		const int final_idx = offset + curr_idx;
// 		if (final_idx >= MAX_BITMASK_U64S || final_idx < 0) 
//         {
// 			break;
// 		}
// 		b_data->bitmasks[final_idx] &= ~(1ULL << bit);
	
// 		if (b_data->bitmasks[final_idx] != 0)
//         {
//             break;
//         }

// 		bit = curr_idx % 64;
// 		curr_idx /= 64;
// 	}
// }

// static inline u64
// get_highest_bitmask_tree(struct bucket_bitmask_data *b_data)
// {
// 	u64 curr_idx = 0;
// 	const int root_level = NUM_LEVELS - 1;

// 	#pragma unroll
// 	for (int l = 3; l >= 0; l--) {
// 		if (l > root_level)
//         {
//             continue;
//         }

// 		int offset = get_level_offset(l);
// 		u64 final_idx = offset + curr_idx;
// 		if (final_idx >= MAX_BITMASK_U64S || final_idx<0) {
// 			return ~0ULL; // or break/return depending on the function
// 		}
// 		u64 val = b_data->bitmasks[final_idx];
// 		if (val == 0)
// 			return -1;

// 		int highest_bit = __builtin_ctzll(val);
// 		if (l == 0)
// 			return ((curr_idx * 64) + highest_bit);

// 		curr_idx = (curr_idx * 64) + highest_bit;
// 	}
// 	return -1;
// }

#include <scx/common.bpf.h>
#include "scx_deadline_wheel.h"

/* * We must keep a hard maximum for the BPF verifier to size the array.
 * Example: 4096 buckets -> L0: 64, L1: 1. Total 65.
 * Setting this to a reasonably high value (e.g., 520) allows up to 32k buckets.
 */
#define MAX_STATIC_BITMASK_U64S 520

struct bucket_bitmask_data {
    struct bpf_spin_lock lock;
    int sem;
    u64 bitmasks[MAX_STATIC_BITMASK_U64S];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bucket_bitmask_data);
} bucket_bitmask_map SEC(".maps");

/* * Helper to calculate dynamic offsets based on runtime num_buckets.
 * This replaces your static L0_OFF, L1_OFF, etc.
 */
static inline int get_dynamic_level_offset(int level) {
    u64 l0_size = (num_buckets + 63) / 64;
    if (level == 0) return 0;
    
    u64 l1_size = (l0_size + 63) / 64;
    if (level == 1) return (int)l0_size;
    
    u64 l2_size = (l1_size + 63) / 64;
    if (level == 2) return (int)(l0_size + l1_size);
    
    if (level == 3) return (int)(l0_size + l1_size + l2_size);
    
    return -1;
}

static inline int get_dynamic_num_levels() {
    u64 l0 = (num_buckets + 63) / 64;
    if (l0 <= 1) return 1;
    u64 l1 = (l0 + 63) / 64;
    if (l1 <= 1) return 2;
    u64 l2 = (l1 + 63) / 64;
    if (l2 <= 1) return 3;
    return 4;
}

static inline void 
set_bitmask_tree(struct bucket_bitmask_data *b_data, u64 bucket_idx)
{
    u64 curr_idx = bucket_idx / 64;
    u64 bit = bucket_idx % 64;
    int num_levels = get_dynamic_num_levels();

    #pragma unroll
    for (int l = 0; l < 4; l++) {
        if (l >= num_levels) break;

        int offset = get_dynamic_level_offset(l);
        int final_idx = offset + (int)curr_idx;

        // Safety check for BPF Verifier
        if (final_idx >= MAX_STATIC_BITMASK_U64S || final_idx < 0) break;

        u64 old_val = b_data->bitmasks[final_idx];
        b_data->bitmasks[final_idx] |= (1ULL << bit);
             
        // If the bit was already set, parents are already set
        if (old_val != 0) break;

        bit = curr_idx % 64;
        curr_idx /= 64;
    }
}

static inline void
clear_bitmask_tree(struct bucket_bitmask_data *b_data, u64 bucket_idx)
{
    u64 curr_idx = bucket_idx / 64;
    u64 bit = bucket_idx % 64;
    int num_levels = get_dynamic_num_levels();

    #pragma unroll
    for (int l = 0; l < 4; l++) {
        if (l >= num_levels) break;

        int offset = get_dynamic_level_offset(l);
        int final_idx = offset + (int)curr_idx;

        if (final_idx >= MAX_STATIC_BITMASK_U64S || final_idx < 0) break;
        
        b_data->bitmasks[final_idx] &= ~(1ULL << bit);
    
        // If this mask is still non-zero, we don't need to clear parents
        if (b_data->bitmasks[final_idx] != 0) break;

        bit = curr_idx % 64;
        curr_idx /= 64;
    }
}

static inline u64
get_highest_bitmask_tree(struct bucket_bitmask_data *b_data)
{
    u64 curr_idx = 0;
    int num_levels = get_dynamic_num_levels();
    int root_level = num_levels - 1;

    #pragma unroll
    for (int l = 3; l >= 0; l--) {
        if (l > root_level) continue;

        int offset = get_dynamic_level_offset(l);
        int final_idx = offset + (int)curr_idx;

        if (final_idx >= MAX_STATIC_BITMASK_U64S || final_idx < 0) return -1;
        
        u64 val = b_data->bitmasks[final_idx];
        if (val == 0) return -1;

        // Find the first set bit (highest priority bucket)
        int highest_bit = __builtin_ctzll(val);
        
        if (l == 0) return (curr_idx * 64) + highest_bit;

        curr_idx = (curr_idx * 64) + highest_bit;
    }
    return -1;
}
