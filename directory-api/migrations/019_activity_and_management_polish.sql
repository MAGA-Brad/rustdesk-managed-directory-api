BEGIN;

CREATE TABLE IF NOT EXISTS device_activity_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    peer_device_id UUID REFERENCES managed_devices(id) ON DELETE SET NULL,
    peer_rustdesk_id VARCHAR(64),
    direction VARCHAR(16),
    session_key VARCHAR(128),
    session_type VARCHAR(24),
    source_ip INET,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT device_activity_events_event_type_check CHECK (
        event_type IN (
            'client.active',
            'client.inactive',
            'connection.initiated',
            'connection.established',
            'connection.rejected',
            'connection.denied',
            'connection.ended'
        )
    ),
    CONSTRAINT device_activity_events_direction_check CHECK (
        direction IS NULL OR direction IN ('initiator', 'receiver')
    ),
    CONSTRAINT device_activity_events_session_type_check CHECK (
        session_type IS NULL OR session_type IN ('remote_desktop', 'file_transfer')
    )
);

CREATE INDEX IF NOT EXISTS device_activity_events_time_idx
ON device_activity_events (occurred_at DESC);

CREATE INDEX IF NOT EXISTS device_activity_events_device_idx
ON device_activity_events (device_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS device_activity_events_peer_idx
ON device_activity_events (peer_device_id, occurred_at DESC)
WHERE peer_device_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS device_activity_events_presence_uidx
ON device_activity_events (device_id, event_type, occurred_at)
WHERE event_type IN ('client.active', 'client.inactive');

CREATE UNIQUE INDEX IF NOT EXISTS device_activity_events_session_uidx
ON device_activity_events (device_id, event_type, session_key)
WHERE session_key IS NOT NULL
  AND event_type IN (
      'connection.initiated',
      'connection.established',
      'connection.rejected',
      'connection.denied',
      'connection.ended'
  );

-- Backfill only session facts the existing managed client has already reported
-- authoritatively.  Historical initiator/reject/deny events are intentionally
-- not inferred because the existing telemetry does not carry those facts.
INSERT INTO device_activity_events (
    device_id,
    event_type,
    peer_device_id,
    peer_rustdesk_id,
    direction,
    session_key,
    session_type,
    source_ip,
    details,
    occurred_at
)
SELECT
    s.reporting_device_id,
    'connection.established',
    peer.id,
    s.peer_rustdesk_id,
    'receiver',
    s.session_key,
    s.session_type,
    s.source_ip,
    jsonb_build_object(
        'source', 'device_active_sessions_backfill',
        'authoritative_direction', 'receiver'
    ),
    s.started_at
FROM device_active_sessions s
LEFT JOIN managed_devices peer
  ON peer.rustdesk_id = s.peer_rustdesk_id
ON CONFLICT DO NOTHING;

INSERT INTO device_activity_events (
    device_id,
    event_type,
    peer_device_id,
    peer_rustdesk_id,
    direction,
    session_key,
    session_type,
    source_ip,
    details,
    occurred_at
)
SELECT
    s.reporting_device_id,
    'connection.ended',
    peer.id,
    s.peer_rustdesk_id,
    'receiver',
    s.session_key,
    s.session_type,
    s.source_ip,
    jsonb_build_object(
        'source', 'device_active_sessions_backfill',
        'authoritative_direction', 'receiver'
    ),
    s.ended_at
FROM device_active_sessions s
LEFT JOIN managed_devices peer
  ON peer.rustdesk_id = s.peer_rustdesk_id
WHERE s.ended_at IS NOT NULL
ON CONFLICT DO NOTHING;

UPDATE directory_settings
SET setting_value = to_jsonb('rendezvous.example.com:21116'::text),
    updated_at = NOW()
WHERE setting_key = 'client.id_server';

COMMIT;
