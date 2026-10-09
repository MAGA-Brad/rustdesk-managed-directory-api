-- 044: what each RustDrop client can receive (e.g. 'zstd-chunks' compressed transfers), reported on
-- every registration, so senders only use a format the recipient understands.
ALTER TABLE rustdrop_registrations ADD COLUMN IF NOT EXISTS capabilities text[] NOT NULL DEFAULT '{}';
