/*-
 * Copyright (c) 2016 Akshay Jaggi <jaggi@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * gntdev.h
 *
 * Interface to /dev/xen/gntdev.
 *
 * This device provides the user with two kinds of functionalities:
 * 1. Grant Allocation
 *    Allocate a page of our own memory, and share it with a foreign domain.
 * 2. Grant Mapping
 *    Map a grant allocated by a foreign domain, into our own memory.
 *
 *
 * Grant Allocation
 *
 * Steps to allocate a grant:
 * 1. Do an `IOCTL_GNTDEV_ALLOC_GREF ioctl`, with
 *     - `domid`, as the domain-id of the foreign domain
 *     - `flags`, ORed with GNTDEV_ALLOC_FLAG_WRITABLE if you want the foreign
 *       domain to have write access to the shared memory
 *     - `count`, with the number of pages to share with the foreign domain
 *
 *    Ensure that the structure you allocate has enough memory to store
 *    all the allocated grant-refs, i.e., you need to allocate
 *    (sizeof(struct ioctl_gntdev_alloc_gref) + (count - 1)*sizeof(uint32_t))
 *    bytes of memory.
 *
 * 2. Mmap the address given in `index` after a successful ioctl.
 *    This will give you access to the granted pages.
 *
 * Note:
 * 1. The grant is not removed until all three of the following conditions
 *    are met
 *     - The region is not mmaped. That is, munmap() has been called if
 *       the region was mmapped previously.
 *     - IOCTL_GNTDEV_DEALLOC_GREF ioctl has been performed. After you
 *       perform this ioctl, you can no longer mmap or set notify on
 *       the grant.
 *     - The foreign domain has stopped using the grant.
 * 2. Granted pages can only belong to one mmap region.
 * 3. Every page of granted memory is a unit in itself. What this means
 *    is that you can set a unmap notification for each of the granted
 *    pages, individually; you can mmap and dealloc-ioctl a contiguous
 *    range of allocated grants (even if alloc-ioctls were performed
 *    individually), etc.
 *
 *
 * Grant Mapping
 *
 * Steps to map a grant:
 * 1. Do a `IOCTL_GNTDEV_MAP_GRANT_REF` ioctl, with
 *     - `count`, as the number of foreign grants to map
 *     - `refs[i].domid`, as the domain id of the foreign domain
 *     - `refs[i].ref`, as the grant-ref for the grant to be mapped
 *
 * 2. Mmap the address given in `index` after a successful ioctl.
 *    This will give you access to the mapped pages.
 *
 * Note:
 * 1. The map hypercall is not made till the region is mmapped.
 * 2. The unit is defined by the map ioctl. This means that only one
 *    unmap notification can be set on a group of pages that were
 *    mapped together in one ioctl, and also no single mmaping of contiguous
 *    grant-maps is possible.
 * 3. You can mmap the same grant-map region multiple times.
 * 4. The grant is not unmapped until both of the following conditions are met
 *     - The region is not mmaped. That is, munmap() has been called for
 *       as many times as the grant was mmapped.
 *     - IOCTL_GNTDEV_UNMAP_GRANT_REF ioctl has been called.
 * 5. IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR ioctl gives index and count of
 *    a grant-map from the virtual address of the location where the grant
 *    is mmapped.
 *
 *
 * IOCTL_GNTDEV_SET_UNMAP_NOTIFY
 * This ioctl allows us to set notifications to be made when the grant is
 * either unmapped (in case of a mapped grant), or when it is ready to be
 * deallocated by us, ie, the grant is no more mmapped, and the dealloc
 * ioctl has been called (in case of an allocated grant). OR `action` with
 * the required notification masks, and fill in the appropriate fields.
 *  - UNMAP_NOTIFY_CLEAR_BYTE clears the byte at `index`, where index is
 *    the address of the byte in file address space.
 *  - UNMAP_NOTIFY_SEND_EVENT sends an event channel notification on
 *    `event_channel_port`
 * In case of multiple notify ioctls, only the last one survives.
 *
 * $FreeBSD$
 */

#ifndef __XEN_GNTDEV_H__
#define __XEN_GNTDEV_H__

#include <sys/types.h>
#include <bsd/sys/sys/ioccom.h>
#include <bsd/porting/sync_stub.h>
#include <bsd/sys/xen/grant_table_common.h>

struct gntdev_priv {
	/* Maps with visible offsets in the file descriptor. */
	struct list_head maps;
	/* lock protects maps and freeable_maps. */
	mutex_t lock;
};

struct gntdev_unmap_notify {
	int flags;
	/* Address relative to the start of the gntdev_grant_map. */
	int addr;
	evtchn_port_t event;
};

struct gntdev_grant_map {
	struct mmu_interval_notifier notifier;
	struct list_head next;
	// struct vm_area_struct *vma;
	int index;
	int count;
	int flags;
	refcount_t users;
	struct gntdev_unmap_notify notify;
	struct ioctl_gntdev_grant_ref *grants;
	struct gnttab_map_grant_ref   *map_ops;
	struct gnttab_unmap_grant_ref *unmap_ops;
	struct gnttab_map_grant_ref   *kmap_ops;
	struct gnttab_unmap_grant_ref *kunmap_ops;
	struct page **pages;
	unsigned long pages_vm_start;
};

struct xen_page_foreign {
	domid_t domid;
	grant_ref_t gref;
};

struct gntab_unmap_queue_data
{
	// struct delayed_work	gnttab_work;
	void *data;
	// gnttab_unmap_refs_done	done;
	struct gnttab_unmap_grant_ref *unmap_ops;
	struct gnttab_unmap_grant_ref *kunmap_ops;
	struct page **pages;
	unsigned int count;
	unsigned int age;
};

struct gntdev_grant_map *gntdev_alloc_map(struct gntdev_priv *priv, int count,
					  int dma_flags);

void gntdev_add_map(struct gntdev_priv *priv, struct gntdev_grant_map *add);

void gntdev_put_map(struct gntdev_priv *priv, struct gntdev_grant_map *map);

bool gntdev_test_page_count(unsigned int count);

int gntdev_map_grant_pages(struct gntdev_grant_map *map);


struct ioctl_gntdev_grant_ref {
	/* The domain ID of the grant to be mapped. */
	uint32_t domid;
	/* The grant reference of the grant to be mapped. */
	uint32_t ref;
};

#define _IOC_NONE	0U

/*
 * Inserts the grant references into the mapping table of an instance
 * of gntdev. N.B. This does not perform the mapping, which is deferred
 * until mmap() is called with @index as the offset.
 */
#define IOCTL_GNTDEV_MAP_GRANT_REF \
_IOC(_IOC_NONE, 'G', 0, sizeof(struct ioctl_gntdev_map_grant_ref))
struct ioctl_gntdev_map_grant_ref {
	/* IN parameters */
	/* The number of grants to be mapped. */
	uint32_t count;
	uint32_t pad;
	/* OUT parameters */
	/* The offset to be used on a subsequent call to mmap(). */
	uint64_t index;
	/* Variable IN parameter. */
	/* Array of grant references, of size @count. */
	struct ioctl_gntdev_grant_ref refs[1];
};

/*
 * Removes the grant references from the mapping table of an instance of
 * of gntdev. N.B. munmap() must be called on the relevant virtual address(es)
 * before this ioctl is called, or an error will result.
 */
#define IOCTL_GNTDEV_UNMAP_GRANT_REF \
_IOC(_IOC_NONE, 'G', 1, sizeof(struct ioctl_gntdev_unmap_grant_ref))
struct ioctl_gntdev_unmap_grant_ref {
	/* IN parameters */
	/* The offset was returned by the corresponding map operation. */
	uint64_t index;
	/* The number of pages to be unmapped. */
	uint32_t count;
	uint32_t pad;
};

/*
 * Returns the offset in the driver's address space that corresponds
 * to @vaddr. This can be used to perform a munmap(), followed by an
 * UNMAP_GRANT_REF ioctl, where no state about the offset is retained by
 * the caller. The number of pages that were allocated at the same time as
 * @vaddr is returned in @count.
 *
 * N.B. Where more than one page has been mapped into a contiguous range, the
 *      supplied @vaddr must correspond to the start of the range; otherwise
 *      an error will result. It is only possible to munmap() the entire
 *      contiguously-allocated range at once, and not any subrange thereof.
 */
#define IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR \
_IOC(_IOC_NONE, 'G', 2, sizeof(struct ioctl_gntdev_get_offset_for_vaddr))
struct ioctl_gntdev_get_offset_for_vaddr {
	/* IN parameters */
	/* The virtual address of the first mapped page in a range. */
	uint64_t vaddr;
	/* OUT parameters */
	/* The offset that was used in the initial mmap() operation. */
	uint64_t offset;
	/* The number of pages mapped in the VM area that begins at @vaddr. */
	uint32_t count;
	uint32_t pad;
};

/*
 * Sets the maximum number of grants that may mapped at once by this gntdev
 * instance.
 *
 * N.B. This must be called before any other ioctl is performed on the device.
 */
#define IOCTL_GNTDEV_SET_MAX_GRANTS \
_IOC(_IOC_NONE, 'G', 3, sizeof(struct ioctl_gntdev_set_max_grants))
struct ioctl_gntdev_set_max_grants {
	/* IN parameter */
	/* The maximum number of grants that may be mapped at once. */
	uint32_t count;
};

/*
 * Sets up an unmap notification within the page, so that the other side can do
 * cleanup if this side crashes. Required to implement cross-domain robust
 * mutexes or close notification on communication channels.
 *
 * Each mapped page only supports one notification; multiple calls referring to
 * the same page overwrite the previous notification. You must clear the
 * notification prior to the IOCTL_GNTALLOC_DEALLOC_GREF if you do not want it
 * to occur.
 */
#define IOCTL_GNTDEV_SET_UNMAP_NOTIFY \
_IOC(_IOC_NONE, 'G', 7, sizeof(struct ioctl_gntdev_unmap_notify))
struct ioctl_gntdev_unmap_notify {
	/* IN parameters */
	/* Offset in the file descriptor for a byte within the page (same as
	 * used in mmap). If using UNMAP_NOTIFY_CLEAR_BYTE, this is the byte to
	 * be cleared. Otherwise, it can be any byte in the page whose
	 * notification we are adjusting.
	 */
	uint64_t index;
	/* Action(s) to take on unmap */
	uint32_t action;
	/* Event channel to notify */
	uint32_t event_channel_port;
};

struct gntdev_grant_copy_segment {
	union {
		void *virt;
		struct {
			grant_ref_t ref;
			uint16_t offset;
			domid_t domid;
		} foreign;
	} source, dest;
	uint16_t len;

	uint16_t flags;  /* GNTCOPY_* */
	int16_t status; /* GNTST_* */
};

/*
 * Copy between grant references and local buffers.
 *
 * The copy is split into @count @segments, each of which can copy
 * to/from one grant reference.
 *
 * Each segment is similar to struct gnttab_copy in the hypervisor ABI
 * except the local buffer is specified using a virtual address
 * (instead of a GFN and offset).
 *
 * The local buffer may cross a Xen page boundary -- the driver will
 * split segments into multiple ops if required.
 *
 * Returns 0 if all segments have been processed and @status in each
 * segment is valid.  Note that one or more segments may have failed
 * (status != GNTST_okay).
 *
 * If the driver had to split a segment into two or more ops, @status
 * includes the status of the first failed op for that segment (or
 * GNTST_okay if all ops were successful).
 *
 * If -1 is returned, the status of all segments is undefined.
 *
 * EINVAL: A segment has local buffers for both source and
 *         destination.
 * EINVAL: A segment crosses the boundary of a foreign page.
 * EFAULT: A segment's local buffer is not accessible.
 */
#define IOCTL_GNTDEV_GRANT_COPY \
	_IOC(_IOC_NONE, 'G', 8, sizeof(struct ioctl_gntdev_grant_copy))
struct ioctl_gntdev_grant_copy {
	unsigned int count;
	struct gntdev_grant_copy_segment *segments;
};

/* Clear (set to zero) the byte specified by index */
#define UNMAP_NOTIFY_CLEAR_BYTE 0x1
/* Send an interrupt on the indicated event channel */
#define UNMAP_NOTIFY_SEND_EVENT 0x2

/*
 * Flags to be used while requesting memory mapping's backing storage
 * to be allocated with DMA API.
 */

/*
 * The buffer is backed with memory allocated with dma_alloc_wc.
 */
#define GNTDEV_DMA_FLAG_WC		(1 << 0)

/*
 * The buffer is backed with memory allocated with dma_alloc_coherent.
 */
#define GNTDEV_DMA_FLAG_COHERENT	(1 << 1)

/*
 * Create a dma-buf [1] from grant references @refs of count @count provided
 * by the foreign domain @domid with flags @flags.
 *
 * By default dma-buf is backed by system memory pages, but by providing
 * one of the GNTDEV_DMA_FLAG_XXX flags it can also be created as
 * a DMA write-combine or coherent buffer, e.g. allocated with dma_alloc_wc/
 * dma_alloc_coherent.
 *
 * Returns 0 if dma-buf was successfully created and the corresponding
 * dma-buf's file descriptor is returned in @fd.
 *
 * [1] Documentation/driver-api/dma-buf.rst
 */

#define IOCTL_GNTDEV_DMABUF_EXP_FROM_REFS \
	_IOC(_IOC_NONE, 'G', 9, \
	     sizeof(struct ioctl_gntdev_dmabuf_exp_from_refs))
struct ioctl_gntdev_dmabuf_exp_from_refs {
	/* IN parameters. */
	/* Specific options for this dma-buf: see GNTDEV_DMA_FLAG_XXX. */
	uint32_t flags;
	/* Number of grant references in @refs array. */
	uint32_t count;
	/* OUT parameters. */
	/* File descriptor of the dma-buf. */
	uint32_t fd;
	/* The domain ID of the grant references to be mapped. */
	uint32_t domid;
	/* Variable IN parameter. */
	/* Array of grant references of size @count. */
	uint32_t refs[1];
};

/*
 * This will block until the dma-buf with the file descriptor @fd is
 * released. This is only valid for buffers created with
 * IOCTL_GNTDEV_DMABUF_EXP_FROM_REFS.
 *
 * If within @wait_to_ms milliseconds the buffer is not released
 * then -ETIMEDOUT error is returned.
 * If the buffer with the file descriptor @fd does not exist or has already
 * been released, then -ENOENT is returned. For valid file descriptors
 * this must not be treated as error.
 */
#define IOCTL_GNTDEV_DMABUF_EXP_WAIT_RELEASED \
	_IOC(_IOC_NONE, 'G', 10, \
	     sizeof(struct ioctl_gntdev_dmabuf_exp_wait_released))
struct ioctl_gntdev_dmabuf_exp_wait_released {
	/* IN parameters */
	uint32_t fd;
	uint32_t wait_to_ms;
};

/*
 * Import a dma-buf with file descriptor @fd and export granted references
 * to the pages of that dma-buf into array @refs of size @count.
 */
#define IOCTL_GNTDEV_DMABUF_IMP_TO_REFS \
	_IOC(_IOC_NONE, 'G', 11, \
	     sizeof(struct ioctl_gntdev_dmabuf_imp_to_refs))
struct ioctl_gntdev_dmabuf_imp_to_refs {
	/* IN parameters. */
	/* File descriptor of the dma-buf. */
	uint32_t fd;
	/* Number of grant references in @refs array. */
	uint32_t count;
	/* The domain ID for which references to be granted. */
	uint32_t domid;
	/* Reserved - must be zero. */
	uint32_t reserved;
	/* OUT parameters. */
	/* Array of grant references of size @count. */
	uint32_t refs[1];
};

/*
 * This will close all references to the imported buffer with file descriptor
 * @fd, so it can be released by the owner. This is only valid for buffers
 * created with IOCTL_GNTDEV_DMABUF_IMP_TO_REFS.
 */
#define IOCTL_GNTDEV_DMABUF_IMP_RELEASE \
	_IOC(_IOC_NONE, 'G', 12, \
	     sizeof(struct ioctl_gntdev_dmabuf_imp_release))
struct ioctl_gntdev_dmabuf_imp_release {
	/* IN parameters */
	uint32_t fd;
	uint32_t reserved;
};

#endif