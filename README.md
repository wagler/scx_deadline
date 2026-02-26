# scx_deadline_wheel: EDF implemented for sched_ext

## Introduction
This repository provides an implementation of the Earliest Deadline First scheduling algorithm implemented with the Deadline Wheel approach by Michael Short [1] to enable O(1) scheduling operations.


## Quick start
### Build scheduler
```
git clone https://github.com/wagler/scx-tracer.git
cd scx-tracer
```

You need to copy the contents of `tools/sched_ext` into your Linux kernel source path's tools/`sched_ext directory`. For example, if your Linux kernel source is in `~/kernel`, then run:

```
cp tools/sched_ext/* ~/kernel/tools/sched_ext
```

Then, to build:

```
cd ~/kernel
make LLVM=-21 CLANG=clang-21 CC=clang-21 -j24 scx_deadline_wheel
```

### Run demo application with scheduler
To run the scheduler:
```
sudo ~/kernel/tools/sched_ext/build/bin/scx_deadline_wheel # Uses default number of deadline wheel slots (10)
or
sudo ~/kernel/tools/sched_ext/build/bin/scx_deadline_wheel -b 100 # Uses a custom number (100) of deadline wheel slots
```

Once the scheduler is running, you'll see a message like this:
```
Loaded scx_deadline_wheel scheduler with 10 buckets.
```

Once you see that message, open a new terminal and create an isolated cgroup for the sample application we'll run:
```
sudo ./setup_slice.sh
```
Now, run the sample workload (N worker threads each calculate the sume of the first M fibonacci sequence numbers):
```
sudo systemd-run --scope -p Slice=custom-workload.slice -p TasksMax=infinity -p MemoryMax=infinity -p CPUAccounting=yes ./sample_scx_deadline_task_mt 1000 10
```
Here, we set M=1000 (num fibonacci numbers) and N=10 (num worker threads).
