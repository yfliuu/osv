#ifndef XENGNTALLOC_H
#define XENGNTALLOC_H

#include <osv/device.h>
#include <osv/types.h>
#include <sys/types.h>
#include <memory>

namespace gntalloc {

class gntalloc_device {
public:
    gntalloc_device();
    virtual ~gntalloc_device();

private:
    device* _gntalloc_dev;
};

void gntalloc_init();

};

#endif