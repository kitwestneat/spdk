#include "spdk/bdev.h"
#include "spdk/bdev_module.h"
#include "spdk/thread.h"
#include "spdk/log.h"

#include <niova/log.h>
#include <uuid/uuid.h>
#include <niova/nclient.h>
#include <niova/nclient_private.h>

#define NIOVA_QD 32
#define NIOVA_MAX_IO 128*1024

// defined by linux
#define SECTOR_SHIFT 9

int niova_open(const char *bdev_name, const char *tgt_uuid, const char *vdev_uuid, size_t size);

int niovaSectorBits = 12; // XXX should there be a nclient fn?

struct niova_ctx {
	niova_block_client_t *client;
	struct spdk_bdev disk;
	char *tgt_uuid;
	char *vdev_uuid;
};

struct bdev_niova_task {
	ssize_t bnt_rc;
	struct spdk_thread *bnt_submit_td;
};

static int
bdev_niova_initialize(void)
{
	/* init during bdev create rpc -> niova_open() */
	return 0;
}

static void
free_niova_ctx(struct niova_ctx *ctx)
{
	free(ctx->tgt_uuid);
	free(ctx->vdev_uuid);
	free(ctx);
}

static void
bdev_niova_destruct_cb(void *arg)
{
	SIMPLE_FUNC_ENTRY(LL_TRACE);
	struct niova_ctx *ctx = arg;

	assert(ctx != NULL);

	int rc = NiovaBlockClientDestroy(ctx->client);
	if (rc) {
		SPDK_ERRLOG("could not close niova, rc=%d\n", rc);
	}

	free_niova_ctx(ctx);
	SIMPLE_FUNC_EXIT(LL_TRACE);
}

static int
bdev_niova_destruct(void *arg)
{
	SIMPLE_FUNC_ENTRY(LL_TRACE);
	struct niova_ctx *ctx = arg;

	SPDK_NOTICELOG("%s: destroying bdev_niova device\n", ctx->disk.name);

	spdk_io_device_unregister(ctx, bdev_niova_destruct_cb);

	SIMPLE_FUNC_EXIT(LL_TRACE);
	return 0;
}

static void
niova_rw_cb_cb(void *arg)
{
	SIMPLE_FUNC_ENTRY(LL_TRACE);

	struct spdk_bdev_io *bdev_io = arg;
	struct bdev_niova_task *bnt = (struct bdev_niova_task *)bdev_io->driver_ctx;
	ssize_t rc = bnt->bnt_rc;
	ssize_t len = bdev_io->u.bdev.num_blocks << niovaSectorBits;

	SPDK_DEBUGLOG(bdev_niova, "io complete, rc=%d, expected=%d", rc, len);

	if (rc == len) {
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	} else {
		spdk_bdev_io_complete_aio_status(bdev_io, rc);
	}

	SIMPLE_FUNC_EXIT(LL_TRACE);
}

// niova run ctx
static void
niova_rw_cb(void *arg, ssize_t rc)
{
	SIMPLE_FUNC_ENTRY(LL_TRACE);

	struct spdk_bdev_io *bdev_io = arg;
	struct bdev_niova_task *bnt = (struct bdev_niova_task *)bdev_io->driver_ctx;
	bnt->bnt_rc = rc;

	spdk_thread_send_msg(bnt->bnt_submit_td, niova_rw_cb_cb, bdev_io);

	SIMPLE_FUNC_EXIT(LL_TRACE);
}

static int
niova_rw(bool is_read, struct spdk_bdev_io *bdev_io)
{
		SIMPLE_FUNC_ENTRY(LL_TRACE);

		struct niova_ctx *ctx = bdev_io->bdev->ctxt;
		niova_block_client_t *client = ctx->client;

		// XXX what block size is offset_block in? should be 4k
		unsigned long long start_vblk = bdev_io->u.bdev.offset_blocks;

		SIMPLE_LOG_MSG(LL_TRACE, "niova_rw: cli@%p op=%s start=%llu",
						client, is_read ? "read" : "write", start_vblk);

		SIMPLE_LOG_MSG(LL_TRACE, "iovs@%p iovcnt=%d iov[0].len=%d iov[0].base@%p",
					   bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
					   bdev_io->u.bdev.iovs[0].iov_len, bdev_io->u.bdev.iovs[0].iov_base);

		int rc = is_read ?
				NiovaBlockClientReadv(client, start_vblk, bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
									  niova_rw_cb, bdev_io):
				NiovaBlockClientWritev(client, start_vblk, bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
									   niova_rw_cb, bdev_io);

		SIMPLE_LOG_MSG(LL_TRACE, "exit, rc=%d", rc);

		return rc < 0 ? -EIO : 0;
}

static void
bdev_niova_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct bdev_niova_task *bnt = (struct bdev_niova_task *)bdev_io->driver_ctx;
	bnt->bnt_submit_td = spdk_io_channel_get_thread(ch);

	bool is_read = false;
	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		is_read = true;
		/* fall thru */
	case SPDK_BDEV_IO_TYPE_WRITE:
		niova_rw(is_read, bdev_io);
		break;
	default:
		SPDK_ERRLOG("unsupported io type=%d\n", bdev_io->type);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
		break;
	}
}

static bool
bdev_niova_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	switch (io_type) {
	case SPDK_BDEV_IO_TYPE_READ:
	case SPDK_BDEV_IO_TYPE_WRITE:
		return true;
	default:
		return false;
	}
}

static void
bdev_niova_write_json_config(struct spdk_bdev *bdev, struct spdk_json_write_ctx *w)
{
	struct niova_ctx *ctx = bdev->ctxt;

	spdk_json_write_object_begin(w);

	spdk_json_write_named_string(w, "method", "bdev_niova_create");

	spdk_json_write_named_object_begin(w, "params");
	spdk_json_write_named_string(w, "name", bdev->name);
	spdk_json_write_named_string(w, "tgt_uuid", ctx->tgt_uuid);
	spdk_json_write_named_string(w, "vdev_uuid", ctx->vdev_uuid);
	spdk_json_write_named_uint64(w, "size", bdev->blockcnt << niovaSectorBits);
	spdk_json_write_object_end(w);

	spdk_json_write_object_end(w);
}


static const struct spdk_bdev_fn_table niova_fn_table = {
	.destruct			= bdev_niova_destruct,
	.submit_request		= bdev_niova_submit_request,
	.io_type_supported	= bdev_niova_io_type_supported,
	.get_io_channel		= spdk_get_io_channel,
//	.dump_info_json		= bdev_niova_dump_info_json,
	.write_config_json	= bdev_niova_write_json_config,
};

// ctx size is per-IO request context
static int
bdev_niova_get_ctx_size(void)
{
	return sizeof(struct bdev_niova_task);
}

static struct spdk_bdev_module niova_if = {
	.name		= "niova",
	.module_init	= bdev_niova_initialize,
	.get_ctx_size	= bdev_niova_get_ctx_size,
};

static int
bdev_niova_io_channel_create_cb(void *io_device, void *ch)
{
	return 0;
}

static void
bdev_niova_io_channel_destroy_cb(void *io_device, void *ctx)
{
}

int niova_open(const char *bdev_name, const char *tgt_uuid, const char *vdev_uuid, size_t size)
{
	SIMPLE_LOG_MSG(LL_TRACE, "enter niova_open");
	SPDK_NOTICELOG("%s: creating bdev_niova disk on '%s:%s'\n", bdev_name, tgt_uuid, vdev_uuid);

	struct niova_ctx *ctx;
	struct niova_block_client_xopts xopts = {0};
	struct vdev_info vdi;
	int rc;

	NIOVA_ASSERT(tgt_uuid && vdev_uuid);

	uuid_parse(tgt_uuid, xopts.npcx_opts.target_uuid);
	uuid_parse(vdev_uuid, xopts.npcx_opts.vdev_uuid);

	size_t nvblks = size >> niovaSectorBits;
	vdi.vdi_mode = VDEV_MODE_CLIENT_TEST;
	vdi.vdi_num_vblks = nvblks;

	rc = niova_block_client_set_private_opts(&xopts, &vdi, NULL, NULL);
	if (rc) {
		SPDK_ERRLOG("niova_block_client_set_private_opts() rc=%d\n", rc);
		goto err;
	}

	ctx = calloc(1, sizeof(*ctx));

	ctx->disk.name = strdup(bdev_name);
	ctx->disk.product_name = "NIOVA bdev";

	ctx->disk.write_cache = 0;
	ctx->disk.blocklen = 1 << niovaSectorBits;
	ctx->disk.phys_blocklen = 1 << niovaSectorBits;
	ctx->disk.blockcnt = nvblks;

	ctx->disk.ctxt = ctx;
	ctx->disk.fn_table = &niova_fn_table;
	ctx->disk.module = &niova_if;

	ctx->tgt_uuid = strdup(tgt_uuid);
	ctx->vdev_uuid = strdup(vdev_uuid);

	rc = NiovaBlockClientNew(&ctx->client, &xopts.npcx_opts);
	if (rc) {
		SPDK_ERRLOG("error creating niova client, rc=%d\n", rc);
		goto free_err;
	}
	SIMPLE_LOG_MSG(LL_TRACE, "created client@%p", ctx->client);

	SPDK_NOTICELOG("%s: registering bdev_niova disk\n", bdev_name);
	spdk_io_device_register(ctx, bdev_niova_io_channel_create_cb,
				bdev_niova_io_channel_destroy_cb,
				0, // channel ctx size if needed
				bdev_name);
	rc = spdk_bdev_register(&ctx->disk);

	return 0;
free_err:
	free_niova_ctx(ctx);
err:
	return -EINVAL;
}
