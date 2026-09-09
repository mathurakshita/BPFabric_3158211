#include "ebpf_switch.h"
uint64_t prog(struct packet *pkt)
{
	return DROP;
}
char _license[] SEC("license")="GPL";
