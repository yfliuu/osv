#include "drivers/xengntalloc.hh"

#include <sys/cdefs.h>
#include <osv/mempool.hh>

#include <bsd/porting/netport.h>

#include <machine/xen/xen-os.h>
#include <osv/mempool.hh>

#include <bsd/sys/xen/gnttab.h>
#include <bsd/sys/xen/gntalloc.h>


#define DEFAULT_MAX_GRANTS 128

extern struct devops gntalloc_device_devops;
extern struct vmaops gntalloc_device_vmaops;

namespace gntalloc {

struct gntalloc_device_priv {
    gntalloc_device *drv;
};

static gntalloc_device_priv *to_priv(device *dev)
{
    return reinterpret_cast<gntalloc_device_priv *>(dev->private_data);
}

struct driver gntalloc_device_driver = {
    "gntalloc",
    &gntalloc_device_devops,
    sizeof(struct gntalloc_device_priv),
    0,
    &gntalloc_device_vmaops,
};

gntalloc_device::gntalloc_device()
{
    struct gntalloc_device_priv *prv;

    _gntalloc_dev = device_create(&gntalloc_device_driver, "xen/gntalloc", D_CHR);
    prv = to_priv(_gntalloc_dev);
    prv->drv = this;
}

gntalloc_device::~gntalloc_device()
{
    device_destroy(_gntalloc_dev);
}

void gntalloc_init()
{
    new gntalloc_device();
}

}
