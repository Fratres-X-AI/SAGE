#!/usr/bin/env bash
# Report effective CPU quota from cgroup (avoid nproc).
set -euo pipefail
if [[ -r /sys/fs/cgroup/cpu.max ]]; then
  read -r quota period < /sys/fs/cgroup/cpu.max
  if [[ "${quota}" == "max" ]]; then
    echo "unlimited"
  else
    awk -v q="${quota}" -v p="${period}" 'BEGIN { printf "%.0f\n", q/p }'
  fi
elif [[ -r /sys/fs/cgroup/cpuset.cpus.effective ]]; then
  tr ',' '\n' < /sys/fs/cgroup/cpuset.cpus.effective | wc -l
else
  echo "unknown"
fi
