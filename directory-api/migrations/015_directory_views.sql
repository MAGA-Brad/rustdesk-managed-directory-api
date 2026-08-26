CREATE OR REPLACE VIEW approved_device_directory AS
SELECT
    d.id,
    d.rustdesk_id,
    COALESCE(
        NULLIF(BTRIM(d.friendly_name), ''),
        d.hostname
    ) AS display_name,
    d.hostname,
    d.last_ip,
    d.last_seen_at,
    c.credential_serial,
    c.issued_at AS credential_issued_at,
    c.expires_at AS credential_expires_at
FROM managed_devices d
JOIN device_credentials c
  ON c.device_id = d.id
 AND c.revoked_at IS NULL
 AND (
        c.expires_at IS NULL
        OR c.expires_at > NOW()
 )
WHERE d.status = 'approved';

CREATE OR REPLACE VIEW admin_device_overview AS
SELECT
    d.id,
    d.rustdesk_id,
    d.hostname,
    d.friendly_name,
    d.status,
    d.status_reason,
    d.status_changed_at,
    d.last_ip,
    d.last_seen_at,
    d.created_at,

    EXISTS (
        SELECT 1
        FROM device_credentials c
        WHERE c.device_id = d.id
          AND c.revoked_at IS NULL
          AND (
                c.expires_at IS NULL
                OR c.expires_at > NOW()
          )
    ) AS has_active_credential

FROM managed_devices d;
