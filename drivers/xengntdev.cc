#include "drivers/xengntdev.hh"

#include <sys/cdefs.h>
#include <osv/mempool.hh>

#include <bsd/porting/netport.h>

#include <machine/xen/xen-os.h>
#include <osv/mempool.hh>

#include <bsd/sys/xen/gnttab.h>
#include <bsd/sys/xen/gntdev.h>


#define DEFAULT_MAX_GRANTS 128

#define DEBUG(_f, _a...)    debugf(_f, _a)
#define printk(_f, _a...)	debugf(_f, _a)

extern struct devops gntdev_device_devops;
extern struct vmaops gntdev_device_vmaops;

namespace gntdev {

struct gntmap {
    int nentries;
    struct gntmap_entry *entries;
};

struct gntdev_device_priv {
    gntdev_device *drv;
    struct gntmap gmap;
};

static gntdev_device_priv *to_priv(device *dev)
{
    return reinterpret_cast<gntdev_device_priv *>(dev->private_data);
}

#ifdef notyet
int
gntmap_set_max_grants(struct gntmap *map, int count);

int
gntmap_munmap(struct gntmap *map, unsigned long start_address, int count);

void*
gntmap_map_grant_refs(struct gntmap *map, 
                      uint32_t count,
                      uint32_t *domids,
                      int domids_stride,
                      uint32_t *refs,
                      int writable);

void
gntmap_init(struct gntmap *map);

void
gntmap_fini(struct gntmap *map);

struct gntmap_entry {
    unsigned long host_addr;
    grant_handle_t handle;
};

static inline int
gntmap_entry_used(struct gntmap_entry *entry)
{
    return entry->host_addr != 0;
}

static struct gntmap_entry*
gntmap_find_free_entry(struct gntmap *map)
{
    int i;

    for (i = 0; i < map->nentries; i++) {
        if (!gntmap_entry_used(&map->entries[i]))
            return &map->entries[i];
    }

    DEBUG("(map=%p): all %d entries full",
           map, map->nentries);
    return NULL;
}

static struct gntmap_entry*
gntmap_find_entry(struct gntmap *map, unsigned long addr)
{
    int i;

    for (i = 0; i < map->nentries; i++) {
        if (map->entries[i].host_addr == addr)
            return &map->entries[i];
    }
    return NULL;
}

int
gntmap_set_max_grants(struct gntmap *map, int count)
{
    DEBUG("(map=%p, count=%d)", map, count);

    if (map->nentries != 0) {
        return -EBUSY;
    }

	map->entries = (struct gntmap_entry *)malloc(sizeof(struct gntmap_entry) * count);
    if (map->entries == NULL)
        return -ENOMEM;

    memset(map->entries, 0, sizeof(struct gntmap_entry) * count);
    map->nentries = count;
    return 0;
}

static int
_gntmap_map_grant_ref(struct gntmap_entry *entry, 
                      unsigned long host_addr,
                      uint32_t domid,
                      uint32_t ref,
                      int writable)
{
    struct gnttab_map_grant_ref op;
    int rc;

    op.ref = (grant_ref_t) ref;
    op.dom = (domid_t) domid;
    op.host_addr = (uint64_t) host_addr;
    op.flags = GNTMAP_host_map;
    if (!writable)
        op.flags |= GNTMAP_readonly;

    rc = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1);
    if (rc != 0 || op.status != GNTST_okay) {
        printk("GNTTABOP_map_grant_ref failed: "
               "returned %d, status %d\n",
               rc, op.status);
        return rc != 0 ? rc : op.status;
    }

    entry->host_addr = host_addr;
    entry->handle = op.handle;
    return 0;
}

static int
_gntmap_unmap_grant_ref(struct gntmap_entry *entry)
{
    struct gnttab_unmap_grant_ref op;
    int rc;

    op.host_addr    = (uint64_t) entry->host_addr;
    op.dev_bus_addr = 0;
    op.handle       = entry->handle;

    rc = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1);
    if (rc != 0 || op.status != GNTST_okay) {
        printk("GNTTABOP_unmap_grant_ref failed: "
               "returned %d, status %d\n",
               rc, op.status);
        return rc != 0 ? rc : op.status;
    }

    entry->host_addr = 0;
    return 0;
}

int
gntmap_munmap(struct gntmap *map, unsigned long start_address, int count)
{
    int i, rc;
    struct gntmap_entry *ent;

    DEBUG("(map=%p, start_address=%lx, count=%d)",
           map, start_address, count);

    for (i = 0; i < count; i++) {
        ent = gntmap_find_entry(map, start_address + PAGE_SIZE * i);
        if (ent == NULL) {
            debugf("gntmap: tried to munmap unknown page\n");
            return -EINVAL;
        }

        rc = _gntmap_unmap_grant_ref(ent);
        if (rc != 0)
            return rc;
    }

    return 0;
}

void*
gntmap_map_grant_refs(struct gntmap *map, 
                      uint32_t count,
                      uint32_t *domids,
                      int domids_stride,
                      uint32_t *refs,
                      int writable)
{
    unsigned long addr;
    struct gntmap_entry *ent;
    unsigned int i;

    DEBUG("(map=%p, count=%u, "
           "domids=%p [%u...], domids_stride=%d, "
           "refs=%p [%u...], writable=%d)",
           map, count,
           domids, domids == NULL ? 0 : domids[0], domids_stride,
           refs, refs == NULL ? 0 : refs[0], writable);

    (void) gntmap_set_max_grants(map, DEFAULT_MAX_GRANTS);

	addr = (long unsigned int)memory::alloc_phys_contiguous_aligned(count * PAGE_SIZE, 1);
    if (addr == 0)
        return NULL;

    for (i = 0; i < count; i++) {
        ent = gntmap_find_free_entry(map);
        if (ent == NULL ||
            _gntmap_map_grant_ref(ent,
                                  addr + PAGE_SIZE * i,
                                  domids[i * domids_stride],
                                  refs[i],
                                  writable) != 0) {

            (void) gntmap_munmap(map, addr, i);
            return NULL;
        }
    }

    return (void*) addr;
}

void
gntmap_init(struct gntmap *map)
{
    DEBUG("(map=%p)", map);
    map->nentries = 0;
    map->entries = NULL;
}

void
gntmap_fini(struct gntmap *map)
{
    struct gntmap_entry *ent;
    int i;

    DEBUG("(map=%p)", map);

    for (i = 0; i < map->nentries; i++) {
        ent = &map->entries[i];
        if (gntmap_entry_used(ent))
            (void) _gntmap_unmap_grant_ref(ent);
    }

    free(map->entries);
    map->entries = NULL;
    map->nentries = 0;
}

static void*
gntdev_mmap(struct device *dev, uintptr_t offset)
{
    void *addr = memory::alloc_page();
    sprintf((char *)addr, "Some content\n");
    return addr;
}

static int
gntdev_open(struct device *dev, int ioflag)
{
    struct gntdev_device_priv *priv;
    priv = (struct gntdev_device_priv *)dev->private_data;
    gntmap_init(&priv->gmap);
    return 0;
}

static int
gntdev_close(struct device *dev)
{
    struct gntdev_device_priv *priv;
    priv = (struct gntdev_device_priv *)dev->private_data;
    gntmap_fini(&priv->gmap);
    return 0;
}

static int
gntdev_alloc_gref(struct device *dev, struct ioctl_gntdev_alloc_gref *arg)
{
    return 0;
}

static int
gntdev_dealloc_gref(struct device *dev, struct ioctl_gntdev_dealloc_gref *arg)
{
    return 0;
}

static int
gntdev_map_grant_ref_wrapper(struct device *dev, struct ioctl_gntdev_map_grant_ref *data)
{
    void *ret;
    uint32_t domids[8], refs_uint[8];
    unsigned int i;
    for (i = 0; i < data->count; i++) {
        domids[i] = data->refs[i].domid;
        refs_uint[i] = data->refs[i].ref;
    }
    ret = gntmap_map_grant_refs((struct gntmap *)dev->private_data, data->count,
        domids, 0, refs_uint, 1);
    return ret != NULL;
}

static int
gntdev_unmap_grant_ref_wrapper(struct device *dev, struct ioctl_gntdev_unmap_grant_ref *data)
{
    return 0;
}

static int
gntdev_ioctl(struct device *dev, u_long cmd, void *data)
{
	int error = 0;

	switch (cmd) {
	// case IOCTL_GNTDEV_SET_UNMAP_NOTIFY:
	// 	error = gntdev_set_unmap_notify(
	// 	    (struct ioctl_gntdev_unmap_notify*) data);
	// 	break;
	case IOCTL_GNTDEV_ALLOC_GREF:
		error = gntdev_alloc_gref(
		    dev, (struct ioctl_gntdev_alloc_gref*) data);
		break;
	case IOCTL_GNTDEV_DEALLOC_GREF:
		error = gntdev_dealloc_gref(
		    dev, (struct ioctl_gntdev_dealloc_gref*) data);
		break;
	case IOCTL_GNTDEV_MAP_GRANT_REF:
		error = gntdev_map_grant_ref_wrapper(dev,
		    (struct ioctl_gntdev_map_grant_ref*) data);
		break;
	case IOCTL_GNTDEV_UNMAP_GRANT_REF:
		error = gntdev_unmap_grant_ref_wrapper(dev,
		    (struct ioctl_gntdev_unmap_grant_ref*) data);
		break;
	// case IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR:
	// 	error = gntdev_get_offset_for_vaddr(
	// 	    (struct ioctl_gntdev_get_offset_for_vaddr*) data, td);
	// 	break;
	default:
		error = ENOSYS;
		break;
	}

    return (error);
}
#endif

struct driver gntdev_device_driver = {
    "gntdev",
    &gntdev_device_devops,
    sizeof(struct gntdev_device_priv),
    0,
    &gntdev_device_vmaops,
};

gntdev_device::gntdev_device()
{
    struct gntdev_device_priv *prv;

    _gntdev_dev = device_create(&gntdev_device_driver, "xen/gntdev", D_CHR);
    prv = to_priv(_gntdev_dev);
    prv->drv = this;
}

gntdev_device::~gntdev_device()
{
    device_destroy(_gntdev_dev);
}

void gntdev_init()
{
    new gntdev_device();
}

}
