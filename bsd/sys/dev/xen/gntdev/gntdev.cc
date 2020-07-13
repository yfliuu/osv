/******************************************************************************
 * gntdev.c
 *
 * Device for accessing (in user-space) pages that have been granted by other
 * domains.
 *
 * Copyright (c) 2006-2007, D G Murray.
 *           (c) 2009 Gerd Hoffmann <kraxel@redhat.com>
 *           (c) 2018 Oleksandr Andrushchenko, EPAM Systems Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#undef DEBUG

#include <sys/cdefs.h>
#include <osv/mempool.hh>

#include <bsd/porting/netport.h>
#include <bsd/porting/synch.h>
#include <bsd/porting/bus.h>
#include <bsd/porting/mmu.h>
#include <bsd/porting/kthread.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/selinfo.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/rman.h>
#include <sys/tree.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/syslog.h>
#include <sys/taskqueue.h>

#include <vm/vm.h>
#include <machine/_inttypes.h>
#include <machine/xen/xen-os.h>
#include <machine/xen/xenvar.h>

#include <xen/hypervisor.h>
#include <xen/xen_intr.h>
#include <xen/gnttab.h>
#include <xen/gntdev.h>
#include <bsd/sys/xen/interface/grant_table.h>
#include <bsd/sys/xen/grant_table_common.h>

static unsigned int limit = 64*1024;

// static int use_ptemod;
static int unmap_grant_pages(struct gntdev_grant_map *map,
			     int offset, int pages);

// static struct miscdevice gntdev_miscdev;

/* --------------------------ADDED WRAPPERS-------------------------- */

static void gnttab_free_pages(int nr_pages, struct page **pages)
{
	int pgno = 0;
	while (pgno < nr_pages) {
		memory::free_page((void *)pages[pgno++]);
	}
}

static int gnttab_set_page_private(int nr_pages, struct page **pages)
{
	return 0;
}

static int gnttab_alloc_pages(int nr_pages, struct page **pages)
{
	int pgno = 0;
	int ret;
	struct page *page;

	while (pgno < nr_pages) {
		page = (struct page *)memory::alloc_page();
		if (!page)
			goto out_undo;
		pages[pgno++] = page;
	}

	ret = gnttab_set_page_private(nr_pages, pages);
	if (ret)
		return ret;
	return 0;

out_undo:
	gnttab_free_pages(pgno, pages);
	return (ENOMEM);
}

// Stupid replacement because the atomic_* version does not seem
// to deal with signed integers
// This is infrequent so this works
mutex_t _refc_lock;
#define WITH_REFC_LOCK(x, lock)	mutex_lock(&lock); do {(x);} while (0); mutex_unlock(&lock);
static inline void refcount_set(refcount_t *r, int n)
{
	WITH_REFC_LOCK((r->refs.counter = n), _refc_lock);
}

static inline void refcount_inc(refcount_t *r)
{
	WITH_REFC_LOCK((r->refs.counter++), _refc_lock);
}

static inline unsigned int refcount_read(const refcount_t *r)
{
	unsigned int ret;
	WITH_REFC_LOCK((ret = r->refs.counter), _refc_lock);
	return ret;
}

static inline int refcount_dec_and_test(refcount_t *r)
{
	unsigned int ret;
	WITH_REFC_LOCK((ret = r->refs.counter--), _refc_lock);
	return ret == 1;
}

static void notify_remote_via_evtchn(evtchn_port_t port)
{

}

static void evtchn_put(evtchn_port_t port)
{

}

static int gnttab_map_refs(struct gnttab_map_grant_ref *map_ops,
		    struct gnttab_map_grant_ref *kmap_ops,
		    struct page **pages, unsigned int count)
{
	int i, ret;

	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, map_ops, count);
	if (ret)
		return ret;

	for (i = 0; i < count; i++) {
		switch (map_ops[i].status) {
		case GNTST_okay:
		{
			// struct xen_page_foreign *foreign;

			// SetPageForeign(pages[i]);
			// foreign = xen_page_foreign(pages[i]);
			// foreign->domid = map_ops[i].dom;
			// foreign->gref = map_ops[i].ref;
			break;
		}

		case GNTST_no_device_space:
			printf("maptrack limit reached, can't map all guest pages\n");
			break;

		// case GNTST_eagain:
		// 	/* Retry eagain maps */
		// 	gnttab_retry_eagain_gop(GNTTABOP_map_grant_ref,
		// 				map_ops + i,
		// 				&map_ops[i].status, __func__);
		// 	/* Test status in next loop iteration. */
		// 	i--;
		// 	break;
		case GNTST_bad_gntref:
			printf("Bad gntref\n");
			break;

		default:
			printf("Unknown status: %d\n", map_ops[i].status);
			break;
		}
	}

	return 0;
}

static int gnttab_unmap_refs(struct gnttab_unmap_grant_ref *unmap_ops, unsigned int count)
{
	return HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, unmap_ops, count);
}

/* ------------------------------------------------------------------ */

bool gntdev_test_page_count(unsigned int count)
{
	return !count || count > limit;
}

static void gntdev_free_map(struct gntdev_grant_map *map)
{
	if (map == NULL)
		return;

	if (map->pages)
		gnttab_free_pages(map->count, map->pages);

	kvfree(map->pages);
	kvfree(map->grants);
	kvfree(map->map_ops);
	kvfree(map->unmap_ops);
	kvfree(map->kmap_ops);
	kvfree(map->kunmap_ops);
	kfree(map);
}

struct gntdev_grant_map *gntdev_alloc_map(struct gntdev_priv *priv, int count,
					  int dma_flags)
{
	struct gntdev_grant_map *add;
	int i;

	add = (struct gntdev_grant_map *)kzalloc(sizeof(*add), GFP_KERNEL);
	if (NULL == add)
		return NULL;

	add->grants    = (struct ioctl_gntdev_grant_ref *)kvcalloc(count, sizeof(add->grants[0]), GFP_KERNEL);
	add->map_ops   = (struct gnttab_map_grant_ref *)kvcalloc(count, sizeof(add->map_ops[0]), GFP_KERNEL);
	add->unmap_ops = (struct gnttab_unmap_grant_ref *)kvcalloc(count, sizeof(add->unmap_ops[0]), GFP_KERNEL);
	add->kmap_ops  = (struct gnttab_map_grant_ref *)kvcalloc(count, sizeof(add->kmap_ops[0]), GFP_KERNEL);
	add->kunmap_ops = (struct gnttab_unmap_grant_ref *)kvcalloc(count,
				   sizeof(add->kunmap_ops[0]), GFP_KERNEL);
	add->pages     = (struct page **)kvcalloc(count, sizeof(add->pages[0]), GFP_KERNEL);
	if (NULL == add->grants    ||
	    NULL == add->map_ops   ||
	    NULL == add->unmap_ops ||
	    NULL == add->kmap_ops  ||
	    NULL == add->kunmap_ops ||
	    NULL == add->pages)
		goto err;

	if (gnttab_alloc_pages(count, add->pages))
		goto err;

	for (i = 0; i < count; i++) {
		add->map_ops[i].handle = -1;
		add->unmap_ops[i].handle = -1;
		add->kmap_ops[i].handle = -1;
		add->kunmap_ops[i].handle = -1;
	}

	add->index = 0;
	add->count = count;
	refcount_set(&add->users, 1);

	return add;

err:
	gntdev_free_map(add);
	return NULL;
}

void gntdev_add_map(struct gntdev_priv *priv, struct gntdev_grant_map *add)
{
	struct gntdev_grant_map *map;

	list_for_each_entry(map, &priv->maps, next) {
		if (add->index + add->count < map->index) {
			list_add_tail(&add->next, &map->next);
			goto done;
		}
		add->index = map->index + map->count;
	}
	list_add_tail(&add->next, &priv->maps);

done:
	return;
}

static struct gntdev_grant_map *gntdev_find_map_index(struct gntdev_priv *priv,
						      int index, int count)
{
	struct gntdev_grant_map *map;

	list_for_each_entry(map, &priv->maps, next) {
		if (map->index != index)
			continue;
		if (count && map->count != count)
			continue;
		return map;
	}
	return NULL;
}

void gntdev_put_map(struct gntdev_priv *priv, struct gntdev_grant_map *map)
{
	if (!map)
		return;

	if (!refcount_dec_and_test(&map->users))
		return;

	if (map->notify.flags & UNMAP_NOTIFY_SEND_EVENT) {
		notify_remote_via_evtchn(map->notify.event);
		evtchn_put(map->notify.event);
	}

	if (map->pages)
		unmap_grant_pages(map, 0, map->count);
	gntdev_free_map(map);
}

/* ------------------------------------------------------------------ */

#if 0
static int find_grant_ptes(pte_t *pte, unsigned long addr, void *data)
{
	struct gntdev_grant_map *map = data;
	unsigned int pgnr = (addr - map->vma->vm_start) >> PAGE_SHIFT;
	int flags = map->flags | GNTMAP_application_map | GNTMAP_contains_pte;
	u64 pte_maddr;

	BUG_ON(pgnr >= map->count);
	pte_maddr = arbitrary_virt_to_machine(pte).maddr;

	/*
	 * Set the PTE as special to force get_user_pages_fast() fall
	 * back to the slow path.  If this is not supported as part of
	 * the grant map, it will be done afterwards.
	 */
	if (xen_feature(XENFEAT_gnttab_map_avail_bits))
		flags |= (1 << _GNTMAP_guest_avail0);

	gnttab_set_map_op(&map->map_ops[pgnr], pte_maddr, flags,
			  map->grants[pgnr].ref,
			  map->grants[pgnr].domid);
	gnttab_set_unmap_op(&map->unmap_ops[pgnr], pte_maddr, flags,
			    -1 /* handle */);
	return 0;
}
#endif

int gntdev_map_grant_pages(struct gntdev_grant_map *map)
{
	int i, err = 0;

	if (map->map_ops[0].handle != -1)
		return 0;
	for (i = 0; i < map->count; i++) {
		unsigned long addr = (unsigned long)virt_to_phys(map->pages[i]);
		gnttab_set_map_op(&map->map_ops[i], addr, map->flags,
						  map->grants[i].ref,
						  map->grants[i].domid);
		gnttab_set_unmap_op(&map->unmap_ops[i], addr,
							map->flags, -1 /* handle */);
	}

	pr_debug("map %d+%d\n", map->index, map->count);
	err = gnttab_map_refs(map->map_ops, NULL, map->pages, map->count);
	if (err)
		return err;

	for (i = 0; i < map->count; i++) {
		if (map->map_ops[i].status) {
			err = -EINVAL;
			continue;
		}

		map->unmap_ops[i].handle = map->map_ops[i].handle;
	}
	return err;
}

static int __unmap_grant_pages(struct gntdev_grant_map *map, int offset,
			       int pages)
{
	int i, err = 0;
	struct gntab_unmap_queue_data unmap_data;

	// if (map->notify.flags & UNMAP_NOTIFY_CLEAR_BYTE) {
	// 	int pgno = (map->notify.addr >> PAGE_SHIFT);
	// 	if (pgno >= offset && pgno < offset + pages) {
	// 		/* No need for kmap, pages are in lowmem */
	// 		uint8_t *tmp = map->pages[pgno];
	// 		tmp[map->notify.addr & (PAGE_SIZE-1)] = 0;
	// 		map->notify.flags &= ~UNMAP_NOTIFY_CLEAR_BYTE;
	// 	}
	// }

	unmap_data.unmap_ops = map->unmap_ops + offset;
	unmap_data.kunmap_ops = NULL;
	unmap_data.pages = map->pages + offset;
	unmap_data.count = pages;

	// err = gnttab_unmap_refs_sync(&unmap_data);
	err = gnttab_unmap_refs(unmap_data.unmap_ops, unmap_data.count);
	if (err)
		return err;

	for (i = 0; i < pages; i++) {
		if (map->unmap_ops[offset+i].status)
			err = -EINVAL;
		pr_debug("unmap handle=%d st=%d\n",
			map->unmap_ops[offset+i].handle,
			map->unmap_ops[offset+i].status);
		map->unmap_ops[offset+i].handle = -1;
	}
	return err;
}

static int unmap_grant_pages(struct gntdev_grant_map *map, int offset,
			     int pages)
{
	int range, err = 0;

	pr_debug("unmap %d+%d [%d+%d]\n", map->index, map->count, offset, pages);

	/* It is possible the requested range will have a "hole" where we
	 * already unmapped some of the grants. Only unmap valid ranges.
	 */
	while (pages && !err) {
		while (pages && map->unmap_ops[offset].handle == -1) {
			offset++;
			pages--;
		}
		range = 0;
		while (range < pages) {
			if (map->unmap_ops[offset+range].handle == -1)
				break;
			range++;
		}
		err = __unmap_grant_pages(map, offset, range);
		offset += range;
		pages -= range;
	}

	return err;
}

/* ------------------------------------------------------------------ */
#if 0
static void gntdev_vma_open(struct vm_area_struct *vma)
{
	struct gntdev_grant_map *map = vma->vm_private_data;

	pr_debug("gntdev_vma_open %p\n", vma);
	refcount_inc(&map->users);
}

static void gntdev_vma_close(struct vm_area_struct *vma)
{
	struct gntdev_grant_map *map = vma->vm_private_data;
	struct file *file = vma->vm_file;
	struct gntdev_priv *priv = file->private_data;

	pr_debug("gntdev_vma_close %p\n", vma);
	if (use_ptemod) {
		WARN_ON(map->vma != vma);
		mmu_interval_notifier_remove(&map->notifier);
		map->vma = NULL;
	}
	vma->vm_private_data = NULL;
	gntdev_put_map(priv, map);
}

static struct page *gntdev_vma_find_special_page(struct vm_area_struct *vma,
						 unsigned long addr)
{
	struct gntdev_grant_map *map = vma->vm_private_data;

	return map->pages[(addr - map->pages_vm_start) >> PAGE_SHIFT];
}

static const struct vm_operations_struct gntdev_vmops = {
	.open = gntdev_vma_open,
	.close = gntdev_vma_close,
	.find_special_page = gntdev_vma_find_special_page,
};
#endif

/* ------------------------------------------------------------------ */
#if 0
static bool gntdev_invalidate(struct mmu_interval_notifier *mn,
			      const struct mmu_notifier_range *range,
			      unsigned long cur_seq)
{
	struct gntdev_grant_map *map =
		container_of(mn, struct gntdev_grant_map, notifier);
	unsigned long mstart, mend;
	int err;

	if (!mmu_notifier_range_blockable(range))
		return false;

	/*
	 * If the VMA is split or otherwise changed the notifier is not
	 * updated, but we don't want to process VA's outside the modified
	 * VMA. FIXME: It would be much more understandable to just prevent
	 * modifying the VMA in the first place.
	 */
	if (map->vma->vm_start >= range->end ||
	    map->vma->vm_end <= range->start)
		return true;

	mstart = max(range->start, map->vma->vm_start);
	mend = min(range->end, map->vma->vm_end);
	pr_debug("map %d+%d (%lx %lx), range %lx %lx, mrange %lx %lx\n",
			map->index, map->count,
			map->vma->vm_start, map->vma->vm_end,
			range->start, range->end, mstart, mend);
	err = unmap_grant_pages(map,
				(mstart - map->vma->vm_start) >> PAGE_SHIFT,
				(mend - mstart) >> PAGE_SHIFT);
	WARN_ON(err);

	return true;
}

static const struct mmu_interval_notifier_ops gntdev_mmu_ops = {
	.invalidate = gntdev_invalidate,
};
#endif

/* ------------------------------------------------------------------ */

static int gntdev_open(struct device *dev, int __unused pad)
{
	struct gntdev_priv *priv;

	priv = (struct gntdev_priv *)kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	INIT_LIST_HEAD(&priv->maps);
	mutex_init(&priv->lock);

	dev->private_data = priv;
	pr_debug("priv %p\n", priv);

	return 0;
}

static int gntdev_release(struct device *dev)
{
	struct gntdev_priv *priv = (struct gntdev_priv *)dev->private_data;
	struct gntdev_grant_map *map;

	pr_debug("priv %p\n", priv);

	mutex_lock(&priv->lock);
	while (!list_empty(&priv->maps)) {
		map = list_entry(priv->maps.next,
				 struct gntdev_grant_map, next);
		list_del(&map->next);
		gntdev_put_map(NULL /* already removed */, map);
	}
	mutex_unlock(&priv->lock);

	kfree(priv);
	return 0;
}

static int gntdev_ioctl_map_grant_ref(struct gntdev_priv *priv,
				       struct ioctl_gntdev_map_grant_ref *u)
{
	struct ioctl_gntdev_map_grant_ref op;
	struct gntdev_grant_map *map;
	int err;

	if (copy_from_user(&op, u, sizeof(op)) != 0)
		return -EFAULT;
	pr_debug("priv %p, add %d\n", priv, op.count);
	if (unlikely(gntdev_test_page_count(op.count)))
		return -EINVAL;

	err = -ENOMEM;
	map = gntdev_alloc_map(priv, op.count, 0 /* This is not a dma-buf. */);
	if (!map)
		return err;

	if (copy_from_user(map->grants, &u->refs,
			   sizeof(map->grants[0]) * op.count) != 0) {
		gntdev_put_map(NULL, map);
		return -EFAULT;
	}

	mutex_lock(&priv->lock);
	gntdev_add_map(priv, map);
	op.index = map->index << PAGE_SHIFT;
	mutex_unlock(&priv->lock);

	if (copy_to_user(u, &op, sizeof(op)) != 0)
		return -EFAULT;

	return 0;
}

static long gntdev_ioctl_unmap_grant_ref(struct gntdev_priv *priv,
					 struct ioctl_gntdev_unmap_grant_ref *u)
{
	struct ioctl_gntdev_unmap_grant_ref op;
	struct gntdev_grant_map *map;
	int err = -ENOENT;

	if (copy_from_user(&op, u, sizeof(op)) != 0)
		return -EFAULT;
	pr_debug("priv %p, del %d+%d\n", priv, (int)op.index, (int)op.count);

	mutex_lock(&priv->lock);
	map = gntdev_find_map_index(priv, op.index >> PAGE_SHIFT, op.count);
	if (map) {
		list_del(&map->next);
		err = 0;
	}
	mutex_unlock(&priv->lock);
	if (map)
		gntdev_put_map(priv, map);
	return err;
}

#if 0
static long gntdev_ioctl_get_offset_for_vaddr(struct gntdev_priv *priv,
					      struct ioctl_gntdev_get_offset_for_vaddr __user *u)
{
	struct ioctl_gntdev_get_offset_for_vaddr op;
	struct vm_area_struct *vma;
	struct gntdev_grant_map *map;
	int rv = -EINVAL;

	if (copy_from_user(&op, u, sizeof(op)) != 0)
		return -EFAULT;
	pr_debug("priv %p, offset for vaddr %lx\n", priv, (unsigned long)op.vaddr);

	mmap_read_lock(current->mm);
	vma = find_vma(current->mm, op.vaddr);
	if (!vma || vma->vm_ops != &gntdev_vmops)
		goto out_unlock;

	map = vma->vm_private_data;
	if (!map)
		goto out_unlock;

	op.offset = map->index << PAGE_SHIFT;
	op.count = map->count;
	rv = 0;

 out_unlock:
	mmap_read_unlock(current->mm);

	if (rv == 0 && copy_to_user(u, &op, sizeof(op)) != 0)
		return -EFAULT;
	return rv;
}

static long gntdev_ioctl_notify(struct gntdev_priv *priv, void __user *u)
{
	struct ioctl_gntdev_unmap_notify op;
	struct gntdev_grant_map *map;
	int rc;
	int out_flags;
	evtchn_port_t out_event;

	if (copy_from_user(&op, u, sizeof(op)))
		return -EFAULT;

	if (op.action & ~(UNMAP_NOTIFY_CLEAR_BYTE|UNMAP_NOTIFY_SEND_EVENT))
		return -EINVAL;

	/* We need to grab a reference to the event channel we are going to use
	 * to send the notify before releasing the reference we may already have
	 * (if someone has called this ioctl twice). This is required so that
	 * it is possible to change the clear_byte part of the notification
	 * without disturbing the event channel part, which may now be the last
	 * reference to that event channel.
	 */
	if (op.action & UNMAP_NOTIFY_SEND_EVENT) {
		if (evtchn_get(op.event_channel_port))
			return -EINVAL;
	}

	out_flags = op.action;
	out_event = op.event_channel_port;

	mutex_lock(&priv->lock);

	list_for_each_entry(map, &priv->maps, next) {
		uint64_t begin = map->index << PAGE_SHIFT;
		uint64_t end = (map->index + map->count) << PAGE_SHIFT;
		if (op.index >= begin && op.index < end)
			goto found;
	}
	rc = -ENOENT;
	goto unlock_out;

 found:
	if ((op.action & UNMAP_NOTIFY_CLEAR_BYTE) &&
			(map->flags & GNTMAP_readonly)) {
		rc = -EINVAL;
		goto unlock_out;
	}

	out_flags = map->notify.flags;
	out_event = map->notify.event;

	map->notify.flags = op.action;
	map->notify.addr = op.index - (map->index << PAGE_SHIFT);
	map->notify.event = op.event_channel_port;

	rc = 0;

 unlock_out:
	mutex_unlock(&priv->lock);

	/* Drop the reference to the event channel we did not save in the map */
	if (out_flags & UNMAP_NOTIFY_SEND_EVENT)
		evtchn_put(out_event);

	return rc;
}

#define GNTDEV_COPY_BATCH 16

struct gntdev_copy_batch {
	struct gnttab_copy ops[GNTDEV_COPY_BATCH];
	struct page *pages[GNTDEV_COPY_BATCH];
	s16 __user *status[GNTDEV_COPY_BATCH];
	unsigned int nr_ops;
	unsigned int nr_pages;
};

static int gntdev_get_page(struct gntdev_copy_batch *batch, void __user *virt,
			   bool writeable, unsigned long *gfn)
{
	unsigned long addr = (unsigned long)virt;
	struct page *page;
	unsigned long xen_pfn;
	int ret;

	ret = get_user_pages_fast(addr, 1, writeable ? FOLL_WRITE : 0, &page);
	if (ret < 0)
		return ret;

	batch->pages[batch->nr_pages++] = page;

	xen_pfn = page_to_xen_pfn(page) + XEN_PFN_DOWN(addr & ~PAGE_MASK);
	*gfn = pfn_to_gfn(xen_pfn);

	return 0;
}

static void gntdev_put_pages(struct gntdev_copy_batch *batch)
{
	unsigned int i;

	for (i = 0; i < batch->nr_pages; i++)
		put_page(batch->pages[i]);
	batch->nr_pages = 0;
}

static int gntdev_copy(struct gntdev_copy_batch *batch)
{
	unsigned int i;

	gnttab_batch_copy(batch->ops, batch->nr_ops);
	gntdev_put_pages(batch);

	/*
	 * For each completed op, update the status if the op failed
	 * and all previous ops for the segment were successful.
	 */
	for (i = 0; i < batch->nr_ops; i++) {
		s16 status = batch->ops[i].status;
		s16 old_status;

		if (status == GNTST_okay)
			continue;

		if (__get_user(old_status, batch->status[i]))
			return -EFAULT;

		if (old_status != GNTST_okay)
			continue;

		if (__put_user(status, batch->status[i]))
			return -EFAULT;
	}

	batch->nr_ops = 0;
	return 0;
}

static int gntdev_grant_copy_seg(struct gntdev_copy_batch *batch,
				 struct gntdev_grant_copy_segment *seg,
				 s16 __user *status)
{
	uint16_t copied = 0;

	/*
	 * Disallow local -> local copies since there is only space in
	 * batch->pages for one page per-op and this would be a very
	 * expensive memcpy().
	 */
	if (!(seg->flags & (GNTCOPY_source_gref | GNTCOPY_dest_gref)))
		return -EINVAL;

	/* Can't cross page if source/dest is a grant ref. */
	if (seg->flags & GNTCOPY_source_gref) {
		if (seg->source.foreign.offset + seg->len > XEN_PAGE_SIZE)
			return -EINVAL;
	}
	if (seg->flags & GNTCOPY_dest_gref) {
		if (seg->dest.foreign.offset + seg->len > XEN_PAGE_SIZE)
			return -EINVAL;
	}

	if (put_user(GNTST_okay, status))
		return -EFAULT;

	while (copied < seg->len) {
		struct gnttab_copy *op;
		void __user *virt;
		size_t len, off;
		unsigned long gfn;
		int ret;

		if (batch->nr_ops >= GNTDEV_COPY_BATCH) {
			ret = gntdev_copy(batch);
			if (ret < 0)
				return ret;
		}

		len = seg->len - copied;

		op = &batch->ops[batch->nr_ops];
		op->flags = 0;

		if (seg->flags & GNTCOPY_source_gref) {
			op->source.u.ref = seg->source.foreign.ref;
			op->source.domid = seg->source.foreign.domid;
			op->source.offset = seg->source.foreign.offset + copied;
			op->flags |= GNTCOPY_source_gref;
		} else {
			virt = seg->source.virt + copied;
			off = (unsigned long)virt & ~XEN_PAGE_MASK;
			len = min(len, (size_t)XEN_PAGE_SIZE - off);

			ret = gntdev_get_page(batch, virt, false, &gfn);
			if (ret < 0)
				return ret;

			op->source.u.gmfn = gfn;
			op->source.domid = DOMID_SELF;
			op->source.offset = off;
		}

		if (seg->flags & GNTCOPY_dest_gref) {
			op->dest.u.ref = seg->dest.foreign.ref;
			op->dest.domid = seg->dest.foreign.domid;
			op->dest.offset = seg->dest.foreign.offset + copied;
			op->flags |= GNTCOPY_dest_gref;
		} else {
			virt = seg->dest.virt + copied;
			off = (unsigned long)virt & ~XEN_PAGE_MASK;
			len = min(len, (size_t)XEN_PAGE_SIZE - off);

			ret = gntdev_get_page(batch, virt, true, &gfn);
			if (ret < 0)
				return ret;

			op->dest.u.gmfn = gfn;
			op->dest.domid = DOMID_SELF;
			op->dest.offset = off;
		}

		op->len = len;
		copied += len;

		batch->status[batch->nr_ops] = status;
		batch->nr_ops++;
	}

	return 0;
}

static long gntdev_ioctl_grant_copy(struct gntdev_priv *priv, void __user *u)
{
	struct ioctl_gntdev_grant_copy copy;
	struct gntdev_copy_batch batch;
	unsigned int i;
	int ret = 0;

	if (copy_from_user(&copy, u, sizeof(copy)))
		return -EFAULT;

	batch.nr_ops = 0;
	batch.nr_pages = 0;

	for (i = 0; i < copy.count; i++) {
		struct gntdev_grant_copy_segment seg;

		if (copy_from_user(&seg, &copy.segments[i], sizeof(seg))) {
			ret = -EFAULT;
			goto out;
		}

		ret = gntdev_grant_copy_seg(&batch, &seg, &copy.segments[i].status);
		if (ret < 0)
			goto out;

		cond_resched();
	}
	if (batch.nr_ops)
		ret = gntdev_copy(&batch);
	return ret;

  out:
	gntdev_put_pages(&batch);
	return ret;
}
#endif

static int gntdev_ioctl(struct device *dev, u_long cmd, void *ptr)
{
	struct gntdev_priv *priv = (struct gntdev_priv *)dev->private_data;

	switch (cmd) {
	case IOCTL_GNTDEV_MAP_GRANT_REF:
		return gntdev_ioctl_map_grant_ref(priv, (struct ioctl_gntdev_map_grant_ref *)ptr);

	case IOCTL_GNTDEV_UNMAP_GRANT_REF:
		return gntdev_ioctl_unmap_grant_ref(priv, (struct ioctl_gntdev_unmap_grant_ref *)ptr);

	// case IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR:
	// 	return gntdev_ioctl_get_offset_for_vaddr(priv, ptr);

	// case IOCTL_GNTDEV_SET_UNMAP_NOTIFY:
	// 	return gntdev_ioctl_notify(priv, ptr);

	// case IOCTL_GNTDEV_GRANT_COPY:
	// 	return gntdev_ioctl_grant_copy(priv, ptr);

	default:
		printf("priv %p, unknown cmd %x\n", priv, cmd);
		return -ENOIOCTL;
	}

	return 0;
}

static int gntdev_mmap(struct device *dev, uintptr_t start, uintptr_t end, uintptr_t off, unsigned write, unsigned share)
{
	struct gntdev_priv *priv = (struct gntdev_priv *)dev->private_data;
	int index = off;
	int count = (end - start) >> PAGE_SHIFT;
	struct gntdev_grant_map *map;
	int err = -EINVAL;

	printf("gntdev_mmap: start: %x, end: %x, off: %x\n", start, end, off);

	mutex_lock(&priv->lock);
	map = gntdev_find_map_index(priv, index, count);
	if (!map)
		goto unlock_out;
	refcount_inc(&map->users);

	if (map->flags) {
		if (write && (map->flags & GNTMAP_readonly))
			goto out_unlock_put;
	} else {
		map->flags = GNTMAP_host_map;
		if (!write)
			map->flags |= GNTMAP_readonly;
	}

	mutex_unlock(&priv->lock);

	err = gntdev_map_grant_pages(map);
	if (err)
		goto out_put_map;

	return 0;

unlock_out:
	printf("unlock out failed\n");
	mutex_unlock(&priv->lock);
	return err;
out_unlock_put:
	mutex_unlock(&priv->lock);
out_put_map:
	printf("out_put_map failed\n");
	gntdev_put_map(priv, map);
	return err;
}

static int gntdev_on_fault(struct device *dev, uintptr_t start, uintptr_t end, 
	uintptr_t off, unsigned write, unsigned share, void **addr_save)
{
	struct gntdev_priv *priv = (struct gntdev_priv *)dev->private_data;
	struct gntdev_grant_map *map;
	// TODO: THIS OFF MAY NOT BE THE OFF
	map = gntdev_find_map_index(priv, off, 1);
	if (!map)
		return 1;
	*addr_save = map->pages[(off & 0x1000) >> PAGE_SHIFT];

	return 0;
}

struct devops gntdev_device_devops = {
    gntdev_open,
    gntdev_release,
    no_read,
    no_write,
    gntdev_ioctl,
    no_devctl,
    no_strategy,
    gntdev_mmap,
};

struct vmaops gntdev_device_vmaops = {
	gntdev_on_fault,
};

/* ------------------------------------------------------------------ */

int gntdev_init(void)
{
	// int err;

	// if (!xen_domain())
	// 	return -ENODEV;

	// use_ptemod = !xen_feature(XENFEAT_auto_translated_physmap);

	// err = misc_register(&gntdev_miscdev);
	// if (err != 0) {
	// 	pr_err("Could not register gntdev device\n");
	// 	return err;
	// }
	return 0;
}

void gntdev_exit(void)
{
	// misc_deregister(&gntdev_miscdev);
}

/* ------------------------------------------------------------------ */
