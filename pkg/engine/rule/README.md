| ID | Rule | Description | Tags | Priority | Application profile | Parameters |
|----|------|-------------|------|----------|---------------------| ---------- |
| R0001 | Unexpected process launched | Detecting exec calls that are not whitelisted by application profile | [exec whitelisted] | 10 | true | false |
| R0002 | Unexpected file access | Detecting file access that are not whitelisted by application profile. File access is defined by the combination of path and flags | [open whitelisted] | 5 | true | [ignoreMounts: bool ignorePrefixes: string[]] |
| R0003 | Unexpected system call | Detecting unexpected system calls that are not whitelisted by application profile. Every unexpected system call will be alerted only once. | [syscall whitelisted] | 5 | true | false |
| R0004 | Unexpected capability used | Detecting unexpected capabilities that are not whitelisted by application profile. Every unexpected capability is identified in context of a syscall and will be alerted only once per container. | [capabilities whitelisted] | 8 | true | false |
| R0005 | Unexpected domain request | Detecting unexpected domain requests that are not whitelisted by application profile. | [dns whitelisted] | 5 | true | false |
| R0006 | Unexpected service account token access | Detecting unexpected service account token access that are not whitelisted by application profile. | [token malicious whitelisted] | 8 | true | false |
| R0007 | Kubernetes Client Executed | Detecting exececution of kubernetes client | [exec malicious whitelisted] | 10 | false | false |
| R1000 | Exec from malicious source | Detecting exec calls that are from malicious source like: /dev/shm, /run, /var/run, /proc/self | [exec signature] | 10 | false | false |
| R1001 | Exec Binary Not In Base Image | Detecting exec calls of binaries that are not included in the base image | [exec malicious binary base image] | 10 | false | false |
| R1002 | Kernel Module Load | Detecting Kernel Module Load. | [syscall kernel module load] | 10 | false | false |
| R1003 | Malicious SSH Connection | Detecting ssh connection to disallowed port | [ssh connection port malicious] | 8 | false | false |
| R1004 | Exec from mount | Detecting exec calls from mounted paths. | [exec mount] | 5 | false | false |
| R1006 | Unshare System Call usage | Detecting Unshare System Call usage. | [syscall escape unshare] | 8 | false | false |
| R1007 | Crypto Miners | Detecting Crypto Miners. | [network crypto miners malicious dns] | 8 | false | false |