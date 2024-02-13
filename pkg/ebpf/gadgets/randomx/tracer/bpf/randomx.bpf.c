#include "../../../../include/amd64/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "randomx.h"
#include "../../../../include/mntns.h"
#include "../../../../include/macros.h"
#include "../../../../include/buffer.h"

/*
name: x86_fpu_regs_deactivated
ID: 107
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:struct fpu * fpu; offset:8;       size:8; signed:0;
        field:bool load_fpu;    offset:16;      size:1; signed:0;
        field:u64 xfeatures;    offset:24;      size:8; signed:0;
        field:u64 xcomp_bv;     offset:32;      size:8; signed:0;
*/

// Define tracer map with 256KB of space for events.
GADGET_TRACER_MAP(events, 1024 * 256);

// Define tracer.
GADGET_TRACER(randomxgogadget, events, event);

SEC("tracepoint/x86_fpu/x86_fpu_regs_deactivated")
int tracepoint__x86_fpu_regs_deactivated(struct trace_event_raw_x86_fpu *ctx) {
    struct event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct task_struct *current_task = (struct task_struct*)bpf_get_current_task();
    if (!current_task) {
        return 0;
    }

    __u32 ppid = BPF_CORE_READ(current_task, real_parent, pid);
    
    uint mxcsr = BPF_CORE_READ(ctx, fpu, fpstate, regs.xsave.i387.mxcsr);

    int fpcr = (mxcsr & 0x6000) >> 13;
    if (fpcr != 0) {
        /* reserve event */
        event = gadget_reserve_buf(&events, sizeof(*event));
        if (!event) {
            return 0;
        }

        /* event data */
        event->timestamp = bpf_ktime_get_boot_ns();
        event->mntns_id = gadget_get_mntns_id();
        event->pid = pid_tgid >> 32;
        event->ppid = ppid;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        
        /* emit event */
        gadget_submit_buf(ctx, &events, event, sizeof(*event));
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
