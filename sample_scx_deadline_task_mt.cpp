// fib_sched_ext.cpp
// Compile: g++ -std=c++20 sample_scx_deadline_task_mt.cpp -o sample_scx_deadline_task_mt -lpthread -lbpf
// Run: sudo ./sample_scx_deadline_task_mt 100000 4

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>
#include <mutex>
#include <barrier> // C++20
#include <cstring>
#include <sched.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

#define MAP_PIN_PATH "/sys/fs/bpf/task_relative_deadlines_map"

struct task_rel_dl {
    struct bpf_spin_lock lock;
    uint64_t rel_deadline;
};

std::mutex cout_mutex;

// Optimized Addition
void add_to(std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    int carry = 0;
    size_t n = a.size(), m = b.size();
    for (size_t i = 0; i < std::max(n, m) || carry; ++i) {
        if (i == a.size()) a.push_back(0);
        int sum = a[i] + (i < m ? b[i] : 0) + carry;
        a[i] = sum % 10;
        carry = sum / 10;
    }
}

std::string fibonacci_fast(unsigned int n) {
    if (n == 0) return "0";
    if (n <= 2) return "1";
    size_t reserve_size = static_cast<size_t>(n * 0.21) + 2;
    std::vector<uint8_t> a = {1}, b = {1};
    a.reserve(reserve_size); b.reserve(reserve_size);

    for (unsigned int i = 3; i <= n; ++i) {
        std::vector<uint8_t> next = a;
        add_to(next, b);
        a = std::move(b);
        b = std::move(next);
    }
    std::string res; res.reserve(b.size());
    for (auto it = b.rbegin(); it != b.rend(); ++it) res += (*it + '0');
    return res;
}

void set_rel_deadline(int map_fd, int tid, uint64_t rel_dl) {
    if (map_fd < 0) return;
    struct task_rel_dl dl_struct = {};
    dl_struct.rel_deadline = rel_dl;
    bpf_map_update_elem(map_fd, &tid, &dl_struct, BPF_ANY | BPF_F_LOCK);
}

// Thread function now takes a reference to the barrier
void fib_thread(unsigned int n, int id, uint64_t rel_dl, int map_fd, std::barrier<>& sync_point) {
    pid_t tid = gettid();

    // --- THE BARRIER ---
    // Wait here until main thread and all other workers arrive
    sync_point.arrive_and_wait();

    // Now all threads proceed at once
    set_rel_deadline(map_fd, tid, rel_dl);

    struct sched_param sp = { .sched_priority = 0 };
    if (sched_setscheduler(0, SCHED_EXT, &sp) == -1) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "[Thread " << id << "] SCHED_EXT failed: " << strerror(errno) << "\n";
    }

    std::string result = fibonacci_fast(n);

    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "[Thread " << id << "] TID: " << tid << " | Digits: " << result.size() << " | Done.\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <n> <num_threads>\n";
        return 1;
    }

    unsigned int n = std::stoul(argv[1]);
    unsigned int num_threads = std::stoul(argv[2]);
    
    int map_fd = bpf_obj_get(MAP_PIN_PATH);
    if (map_fd < 0) perror("Warning: BPF map not found");

    // Initialize barrier for worker threads + 1 (main thread)
    std::barrier sync_point(num_threads + 1);

    std::vector<std::thread> threads;
    uint64_t current_dl = 1e7;

    for (unsigned int i = 0; i < num_threads; ++i) {
        threads.emplace_back(fib_thread, n, i + 1, current_dl, map_fd, std::ref(sync_point));
        current_dl *= 2;
    }

    std::cout << "[Main] All threads spawned. Releasing barrier...\n";
    
    // Main thread arrives at the barrier to release everyone
    sync_point.arrive_and_wait();

    for (auto& t : threads) t.join();
    if (map_fd >= 0) close(map_fd);

    return 0;
}