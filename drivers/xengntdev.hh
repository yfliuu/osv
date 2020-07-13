#ifndef XENGNTDEV_DEVICE_H
#define XENGNTDEV_DEVICE_H

#include <osv/device.h>
#include <osv/types.h>
#include <sys/types.h>
#include <memory>

namespace gntdev {

class gntdev_device {
public:
    gntdev_device();
    virtual ~gntdev_device();

private:
    device* _gntdev_dev;
};

void gntdev_init();

};

#ifdef notyet
#define IOCTL_GNTDEV_SET_UNMAP_NOTIFY					\
	_IOW('E', 0, struct ioctl_gntdev_unmap_notify)
struct ioctl_gntdev_unmap_notify {
    /* IN parameters */
    uint64_t index;
    uint32_t action;
    uint32_t event_channel_port;
};

#define UNMAP_NOTIFY_CLEAR_BYTE 0x1
#define UNMAP_NOTIFY_SEND_EVENT 0x2

/*-------------------- Grant Allocation IOCTLs  ------------------------------*/

#define IOCTL_GNTDEV_ALLOC_GREF						\
	_IOWR('E', 1, struct ioctl_gntdev_alloc_gref)
struct ioctl_gntdev_alloc_gref {
    /* IN parameters */
    uint16_t domid;
    uint16_t flags;
    uint32_t count;
    /* OUT parameters */
    uint64_t index;
    /* Variable OUT parameter */
    uint32_t *gref_ids;
};

#define GNTDEV_ALLOC_FLAG_WRITABLE 1

#define IOCTL_GNTDEV_DEALLOC_GREF					\
	_IOW('E', 2, struct ioctl_gntdev_dealloc_gref)
struct ioctl_gntdev_dealloc_gref {
    /* IN parameters */
    uint64_t index;
    uint32_t count;
};

/*-------------------- Grant Mapping IOCTLs  ---------------------------------*/

struct ioctl_gntdev_grant_ref {
    uint32_t domid;
    uint32_t ref;
};

#define IOCTL_GNTDEV_MAP_GRANT_REF					\
	_IOWR('E', 3, struct ioctl_gntdev_map_grant_ref)
struct ioctl_gntdev_map_grant_ref {
    /* IN parameters */
    uint32_t count;
    uint32_t pad0;
    /* OUT parameters */
    uint64_t index;
    /* Variable IN parameter */
    struct ioctl_gntdev_grant_ref *refs;
};

#define IOCTL_GNTDEV_UNMAP_GRANT_REF					\
	_IOW('E', 4, struct ioctl_gntdev_unmap_grant_ref)
struct ioctl_gntdev_unmap_grant_ref {
    /* IN parameters */
    uint64_t index;
    uint32_t count;
};

#define IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR				\
	_IOWR('E', 5, struct ioctl_gntdev_get_offset_for_vaddr)
struct ioctl_gntdev_get_offset_for_vaddr {
    /* IN parameters */
    uint64_t vaddr;
    /* OUT parameters */
    uint64_t offset;
    uint32_t count;
};

#endif
#endif