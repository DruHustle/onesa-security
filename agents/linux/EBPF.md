# Linux eBPF process activity preview

An operator can capture a ten-second, host-wide count of successful `exec` events on an authorized Linux test host. The fixed probe attaches to `sched:sched_process_exec` and stores one aggregate counter. It collects no process IDs, filenames, arguments, environment variables, or network payloads. The command emits a single JSON sample locally for the operator.

## Run on a disposable Linux VM

Use the distribution's `bpftrace` package and a kernel with the scheduler tracepoint and the privileges required to attach it. Hosted checks target Ubuntu 24.04 on x64 and ARM64. Install the reviewed probe file in a directory writable only by the administrator before running it with elevated privilege.

```sh
sudo -n /usr/bin/python3 -I /opt/onesa/ebpf_activity.py
```

Example shape from a sample with 12 executions:

```json
{"schema":"onesa.linux.process-exec.v1","sample_seconds":10,"process_exec_count":12}
```

Generate ordinary test process launches within the window when verifying the probe. A completed empty window reports zero. Attachment failures, warnings, unexpected output and timeouts exit nonzero without a sample. The process detaches its unpinned probe when it exits. The command does not change kernel settings or install a daemon.

The sample measures activity. It does not identify suspicious executions or establish that a host is healthy. API ingestion, alerting, approved kernel enforcement, and qualification on the production kernel are separate work. The existing Linux inventory collector remains independent.
