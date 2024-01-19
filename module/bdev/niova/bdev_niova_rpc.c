
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk/log.h"

struct rpc_construct_niova {
    char *bdev_name;
	char *tgt_uuid;
	char *vdev_uuid;
	uint64_t size;
};

static const struct spdk_json_object_decoder rpc_construct_niova_decoders[] = {
	{"name", offsetof(struct rpc_construct_niova, bdev_name), spdk_json_decode_string},
	{"target", offsetof(struct rpc_construct_niova, tgt_uuid), spdk_json_decode_string},
	{"vdev", offsetof(struct rpc_construct_niova, vdev_uuid), spdk_json_decode_string},
	{"size", offsetof(struct rpc_construct_niova, size), spdk_json_decode_uint64, true},
};

int niova_open(const char *bdev_name, const char *tgt_uuid, const char *vdev_uuid, size_t size);

static void
rpc_bdev_niova_create(struct spdk_jsonrpc_request *request,
		    const struct spdk_json_val *params)
{
	struct rpc_construct_niova req = { NULL };
	int rc;

	if (spdk_json_decode_object(params, rpc_construct_niova_decoders,
				    SPDK_COUNTOF(rpc_construct_niova_decoders),
				    &req)) {
		SPDK_ERRLOG("spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		return;
	}

	rc = niova_open(req.bdev_name, req.tgt_uuid, req.vdev_uuid, req.size);
	if (rc) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	struct spdk_json_write_ctx *w;

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, req.bdev_name);
	spdk_jsonrpc_end_result(request, w);

cleanup:
    free(req.bdev_name);
    free(req.tgt_uuid);
    free(req.vdev_uuid);
}
SPDK_RPC_REGISTER("bdev_niova_create", rpc_bdev_niova_create, SPDK_RPC_RUNTIME)
