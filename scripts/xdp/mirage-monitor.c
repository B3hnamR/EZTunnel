/* Isolated feasibility monitor, not an application receive fast path.
 * SPDX-License-Identifier: GPL-2.0-only
 * PASS every packet, including selected packets: ordinary socket processing is
 * never stolen, ring capacity cannot lose payload, and fragments are not parsed.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(name) __attribute__((section(name), used))
struct xdp_md { u32 data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex; };
#define UINT(name,value) int (*name)[value]
#define TYPE(name,value) value *name
struct {UINT(type,2);UINT(max_entries,2);TYPE(key,u32);TYPE(value,u64);} counters SEC(".maps");
static void *(*lookup)(void *, const void *)=(void *)1;
static __inline u16 be16(const u8 *p){return ((u16)p[0]<<8)|p[1];}
SEC("xdp") int mirage_monitor(struct xdp_md *context){
    u8 *start=(void *)(unsigned long)context->data;
    u8 *end=(void *)(unsigned long)context->data_end;
    u32 index=0;
    if(start+14+20+4>end)goto done;
    if(be16(start+12)!=0x0800)goto done;
    u8 *ip=start+14;
    if(ip[0]!=0x45 || ip[9]!=17 || (be16(ip+6)&0x3fff)!=0)goto done;
    /* Test-only exact 198.18.64.1 -> 198.18.64.2, UDP port45672. */
    if(ip[12]!=198||ip[13]!=18||ip[14]!=64||ip[15]!=1)goto done;
    if(ip[16]!=198||ip[17]!=18||ip[18]!=64||ip[19]!=2)goto done;
    if(be16(ip+22)!=45672)goto done;
    index=1;
done:;
    u64 *value=lookup(&counters,&index);
    if(value)__sync_fetch_and_add(value,1);
    return 2; /* XDP_PASS */
}
char program_license[] SEC("license")="GPL";
