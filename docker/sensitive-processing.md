# Sensitive processing deployment

New datasets enable sensitive processing by default. Deploy the Go API and
ingestor with the same `sensitive_processing` configuration and rule file.
Do not disable the default or send originals to business storage when setup fails.

The bundled local configuration and Docker template use a separate private
`ragflow-sensitive-originals` bucket on MinIO. With `create_bucket: true`, the
first storage check creates a missing bucket; existing buckets are reused.
Access-denied and connection failures remain errors. No public ACL is applied.
Docker explicitly uses `MINIO_USER` / `MINIO_PASSWORD` for this dedicated bucket
unless separate originals credentials are supplied.

For KS3 or another S3-compatible deployment, pre-create a private bucket and set:

- `SENSITIVE_ORIGINAL_ENDPOINT`: complete HTTP(S) endpoint
- `SENSITIVE_ORIGINAL_REGION`: storage region
- `SENSITIVE_ORIGINAL_BUCKET`: dedicated originals bucket
- `SENSITIVE_ORIGINAL_ACCESS_KEY` / `SENSITIVE_ORIGINAL_SECRET_KEY`: credentials
- `SENSITIVE_ORIGINAL_CREATE_BUCKET=false`

These variables render `docker/service_conf.yaml.template`. For a manually
maintained service configuration, copy the `sensitive_processing` section from
`conf/service_conf.yaml`, configure the same fields directly, and use credentials
restricted to the dedicated bucket. Keep the bucket private; do not use a bucket
configured for ordinary files or thumbnails.

When upgrading an installation with a mounted/custom configuration, merge this
section before restarting both API and ingestor. Updating the image alone does
not replace a custom configuration. Run a default dataset upload and parse as a
deployment smoke test; success must report `security_processed=true`.
