SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY,
        image_path TEXT NOT NULL UNIQUE,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ingestion_events (
        id INTEGER PRIMARY KEY,
        event_key TEXT NOT NULL UNIQUE,
        event_kind TEXT NOT NULL,
        source TEXT NOT NULL,
        channel TEXT NOT NULL,
        host TEXT,
        record_id TEXT,
        event_id INTEGER NOT NULL,
        timestamp TEXT,
        inserted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS process_events (
        id INTEGER PRIMARY KEY,
        ingestion_event_id INTEGER NOT NULL UNIQUE REFERENCES ingestion_events(id),
        application_id INTEGER REFERENCES applications(id),
        timestamp TEXT,
        host TEXT,
        sysmon_event_id INTEGER NOT NULL,
        record_id TEXT,
        process_guid TEXT,
        process_id INTEGER,
        parent_process_guid TEXT,
        parent_process_id INTEGER,
        parent_image TEXT,
        image_path TEXT,
        command_line TEXT,
        hashes_json TEXT NOT NULL,
        current_directory TEXT,
        user_name TEXT,
        integrity_level TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS network_events (
        id INTEGER PRIMARY KEY,
        ingestion_event_id INTEGER NOT NULL UNIQUE REFERENCES ingestion_events(id),
        process_event_id INTEGER REFERENCES process_events(id),
        application_id INTEGER REFERENCES applications(id),
        timestamp TEXT,
        host TEXT,
        sysmon_event_id INTEGER NOT NULL,
        record_id TEXT,
        process_guid TEXT,
        process_id INTEGER,
        image_path TEXT,
        command_line TEXT,
        hashes_json TEXT NOT NULL,
        protocol TEXT,
        initiated INTEGER,
        source_ip TEXT,
        source_port INTEGER,
        destination_ip TEXT,
        destination_hostname TEXT,
        destination_port INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY,
        ingestion_event_id INTEGER NOT NULL UNIQUE REFERENCES ingestion_events(id),
        process_event_id INTEGER REFERENCES process_events(id),
        application_id INTEGER REFERENCES applications(id),
        timestamp TEXT,
        host TEXT,
        sysmon_event_id INTEGER NOT NULL,
        record_id TEXT,
        process_guid TEXT,
        process_id INTEGER,
        image_path TEXT,
        command_line TEXT,
        hashes_json TEXT NOT NULL,
        target_filename TEXT,
        creation_utc TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS behavior_profiles (
        id INTEGER PRIMARY KEY,
        application_identity TEXT NOT NULL,
        profile_version INTEGER NOT NULL,
        observation_start TEXT,
        observation_end TEXT,
        observation_count INTEGER NOT NULL,
        profile_status TEXT NOT NULL,
        profile_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(application_identity, profile_version)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS behavior_features (
        id INTEGER PRIMARY KEY,
        profile_id INTEGER NOT NULL REFERENCES behavior_profiles(id) ON DELETE CASCADE,
        feature_category TEXT NOT NULL,
        feature_key TEXT NOT NULL,
        feature_value_json TEXT NOT NULL,
        UNIQUE(profile_id, feature_category, feature_key)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS detector_models (
        id INTEGER PRIMARY KEY,
        application_identity TEXT NOT NULL,
        profile_version INTEGER NOT NULL,
        model_version TEXT NOT NULL,
        feature_schema_version TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        model_blob BLOB NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(application_identity, profile_version, model_version)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY,
        detection_id TEXT NOT NULL UNIQUE,
        application_identity TEXT NOT NULL,
        timestamp TEXT,
        anomaly_score REAL NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL,
        statistical_contribution REAL NOT NULL,
        deterministic_contribution REAL NOT NULL,
        profile_version INTEGER NOT NULL,
        detector_version TEXT NOT NULL,
        feature_schema_version TEXT NOT NULL,
        reason TEXT,
        provenance_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        host TEXT,
        process_guid TEXT,
        parent_process_guid TEXT,
        process_id INTEGER,
        image_path TEXT,
        model_version TEXT,
        baseline_observation_count INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS detection_signals (
        id INTEGER PRIMARY KEY,
        anomaly_id INTEGER NOT NULL REFERENCES anomalies(id) ON DELETE CASCADE,
        category TEXT NOT NULL,
        signal_type TEXT NOT NULL,
        observed_value_json TEXT,
        baseline_value_json TEXT,
        deviation TEXT NOT NULL,
        weight REAL NOT NULL,
        contribution REAL NOT NULL,
        evidence_reference TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY,
        incident_id TEXT NOT NULL UNIQUE,
        application_identity TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL,
        status TEXT NOT NULL,
        anomaly_count INTEGER NOT NULL,
        signal_count INTEGER NOT NULL,
        correlation_version TEXT NOT NULL,
        incident_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_events (
        id INTEGER PRIMARY KEY,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
        event_reference TEXT NOT NULL,
        timestamp TEXT,
        event_category TEXT NOT NULL,
        process_guid TEXT,
        severity TEXT NOT NULL,
        contribution REAL NOT NULL,
        UNIQUE(incident_id, event_reference, event_category)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_processes (
        id INTEGER PRIMARY KEY,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
        process_guid TEXT,
        process_id INTEGER,
        image_path TEXT,
        parent_guid TEXT,
        parent_pid INTEGER,
        start_time TEXT,
        end_time TEXT,
        hash TEXT,
        UNIQUE(incident_id, process_guid, process_id, image_path)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_explanations (
        id INTEGER PRIMARY KEY,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
        explanation_json TEXT NOT NULL,
        provider TEXT NOT NULL,
        model_identifier TEXT NOT NULL,
        schema_version TEXT NOT NULL,
        prompt_version TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        generation_status TEXT NOT NULL,
        UNIQUE(incident_id, provider, model_identifier, generated_at)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ingestion_source_record ON ingestion_events(source, channel, record_id)",
    "CREATE INDEX IF NOT EXISTS idx_ingestion_event_id ON ingestion_events(event_id)",
    "CREATE INDEX IF NOT EXISTS idx_ingestion_timestamp ON ingestion_events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_process_timestamp ON process_events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_process_guid ON process_events(process_guid)",
    "CREATE INDEX IF NOT EXISTS idx_process_id ON process_events(process_id)",
    "CREATE INDEX IF NOT EXISTS idx_process_parent_guid ON process_events(parent_process_guid)",
    "CREATE INDEX IF NOT EXISTS idx_process_application ON process_events(application_id)",
    "CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_network_process_guid ON network_events(process_guid)",
    "CREATE INDEX IF NOT EXISTS idx_network_destination ON network_events(destination_ip, destination_hostname, destination_port)",
    "CREATE INDEX IF NOT EXISTS idx_network_application ON network_events(application_id)",
    "CREATE INDEX IF NOT EXISTS idx_file_timestamp ON file_events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_file_process_guid ON file_events(process_guid)",
    "CREATE INDEX IF NOT EXISTS idx_file_application ON file_events(application_id)",
    "CREATE INDEX IF NOT EXISTS idx_profile_application ON behavior_profiles(application_identity, profile_version)",
    "CREATE INDEX IF NOT EXISTS idx_feature_category ON behavior_features(feature_category, feature_key)",
    "CREATE INDEX IF NOT EXISTS idx_anomalies_application ON anomalies(application_identity, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_detection_signal_type ON detection_signals(category, signal_type)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_application ON incidents(application_identity, first_seen)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, severity)",
    "CREATE INDEX IF NOT EXISTS idx_incident_events_time ON incident_events(incident_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_incident_process_guid ON incident_processes(process_guid)",
    "CREATE INDEX IF NOT EXISTS idx_explanation_incident ON incident_explanations(incident_id, generated_at)",
)
