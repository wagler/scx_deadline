systemctl set-property --runtime custom-workload.slice AllowedCPUs=2-3
systemctl set-property --runtime init.scope AllowedCPUs=0-1,4-23
systemctl set-property --runtime system.slice AllowedCPUs=0-1,4-23
systemctl set-property --runtime user.slice AllowedCPUs=0-1,4-23
#systemd-run --scope -p Slice=custom-workload.slice <my-app arg1 ...>
