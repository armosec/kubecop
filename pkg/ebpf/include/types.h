#pragma once
// This file contains inspektor gadget types that are needed untill we move to containerized build.

// Inode id of a mount namespace. It's used to enrich the event in user space
typedef __u64 gadget_mntns_id;

// gadget_timestamp is a type that represents the nanoseconds since the system boot. Gadgets can use
// this type to provide a timestamp. The value contained must be the one returned by
// bpf_ktime_get_boot_ns() and it's automatically converted by Inspektor Gadget to a human friendly
// time.
typedef __u64 gadget_timestamp;
