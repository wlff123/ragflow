"""Deliberately narrow endpoint allowlist for the isolated phase-one instance.

Unknown write endpoints (including old API aliases) are denied. This is a
validation mode, not a transparent policy for an existing general-purpose server.
"""

from common.enterprise_redaction import RedactionError, enabled

READ_BLUEPRINTS = frozenset(
    {
        "dataset_api",
        "document_api",
        "chunk_api",
        "file_api",
        "models_api",
        "provider_api",
        "system_api",
        "user_api",
        "tenant_api",
        "stats_api",
        "task_api",
    }
)
WRITE_ENDPOINTS = frozenset(
    {
        "provider_api.add_provider",
        "provider_api.delete_provider",
        "user_api.login",
        "user_api.log_out",
        "user_api.user_add",
        "user_api.setting_user",
        "user_api.set_tenant_info",
        "dataset_api.create",
        "dataset_api.update",
        "dataset_api.delete",
        "dataset_api.check_embedding",
        "document_api.upload_document",
        "document_api.ingest",
        "document_api.parse_documents",
        "document_api.stop_parse_documents",
        "document_api.delete_documents",
        "document_api.batch_update_document_status",
        "chunk_api.parse",
        "chunk_api.stop_parsing",
        "chunk_api.retrieval_test",
        "models_api.set_default_models",
        "provider_api.create_provider_instance",
        "provider_api.verify_provider_api_key",
        "provider_api.update_provider_instance",
        "provider_api.drop_provider_instances",
        "provider_api.add_model_to_instance",
        "provider_api.update_instance_models",
        "provider_api.delete_models_from_instance",
        "provider_api.alter_model",
    }
)


def allowed(endpoint, method, args):
    endpoint = endpoint or ""
    if method == "OPTIONS":
        return True
    if method in {"GET", "HEAD"}:
        return endpoint.split(".", 1)[0] in READ_BLUEPRINTS
    if endpoint not in WRITE_ENDPOINTS:
        return False
    if endpoint == "document_api.upload_document":
        return (args.get("type") or "local").lower() == "local"
    return True


async def validate_dataset_config():
    """Called by dataset routes after authentication, before any writes."""
    if enabled():
        from quart import request
        from common.enterprise_redaction.engine import validate_text_fields
        from common.misc_utils import thread_pool_exec

        await thread_pool_exec(validate_text_fields, await request.get_json())


def install(app):
    if enabled():
        app.config["MAX_CONTENT_LENGTH"] = min(app.config.get("MAX_CONTENT_LENGTH") or 12 * 1024 * 1024, 12 * 1024 * 1024)

    @app.before_request
    async def redaction_ingress_guard():
        from quart import jsonify, request

        if enabled() and not allowed(request.endpoint, request.method, request.args):
            return jsonify(code=403, message="脱敏验证模式仅开放本地 TXT/Markdown/CSV 上传及解析检索；该入口暂未适配。", data=None), 403

    @app.errorhandler(RedactionError)
    async def redaction_error(error):
        from quart import jsonify

        return jsonify(code=400, message=str(error), data=None), 400
