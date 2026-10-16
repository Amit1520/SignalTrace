export type Severity =
  | "normal"
  | "low"
  | "medium"
  | "high";

export type IncidentStatus =
  | "open"
  | "updated"
  | "acknowledged"
  | "resolved";

export type ExplanationGenerationStatus =
  | "generated"
  | "fallback"
  | "failed";

/* -------------------------------------------------------------------------- */
/* Process / Incident models                                                  */
/* -------------------------------------------------------------------------- */

export interface ProcessNode {
  process_guid: string | null;
  process_id: number | null;
  image_path: string | null;
  parent_guid: string | null;
  parent_pid: number | null;
  start_time: string | null;
  end_time: string | null;
  hash: string | null;
}

export interface IncidentEvent {
  event_reference: string;
  timestamp: string | null;
  event_category: string;
  process_guid: string | null;
  parent_process_guid: string | null;
  description: string;
  severity: Severity;
  contribution: number;
  provenance: string[];
}

export interface Incident {
  incident_id: string;
  application_identity: string;

  first_seen: string | null;
  last_seen: string | null;
  duration: string | null;

  severity: Severity;
  confidence: number;

  status: IncidentStatus;

  anomaly_count: number;
  signal_count: number;

  affected_processes: string[];

  process_chain: ProcessNode[];
  timeline: IncidentEvent[];

  contributing_evidence: string[];

  correlation_version: string;
}

/* -------------------------------------------------------------------------- */
/* AI Explanation                                                             */
/* -------------------------------------------------------------------------- */

export interface Explanation {
  incident_id: string;

  summary: string;

  what_changed: string[];
  why_unusual: string[];

  evidence: string[];

  uncertainty: string[];

  recommended_investigation: string[];

  generated_at: string;

  provider: string;
  model_identifier: string;

  prompt_version: string;
  schema_version: string;

  generation_status: ExplanationGenerationStatus;
}

/* -------------------------------------------------------------------------- */
/* Runtime                                                                    */
/* -------------------------------------------------------------------------- */

export interface RuntimeCapabilities {
  runtime_name: string;

  runtime_version: string | null;

  available_providers: string[];

  requested_provider: string | null;

  execution_provider: string | null;

  device: string | null;

  platform: string;

  architecture: string;

  windows_version: string | null;

  hardware_label: string | null;

  npu_verified: boolean;

  status:
    | "available"
    | "unavailable"
    | "error"
    | "not_verified";

  error: string | null;
}

/* -------------------------------------------------------------------------- */
/* Local GenAI model metadata                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Returned by GET /ai/model.
 *
 * Current SignalTrace backend example:
 *
 * {
 *   name: "llama-3.2-3b-instruct",
 *   version: "3B",
 *   format: "onnx-genai",
 *   opset: null,
 *   input_requirements: {},
 *   output_requirements: {},
 *   precision: null,
 *   context_limit: 4096,
 *   license_source: null,
 *   model_path: "models\\llama-3.2-3b-instruct",
 *   model_size_bytes: 3661007286,
 *   compatibility_status: "GenAI model package detected"
 * }
 */
export interface ModelMetadata {
  name: string;
  version: string;

  format: string;

  opset: number | null;

  input_requirements?: Record<string, unknown>;
  output_requirements?: Record<string, unknown>;

  precision: string | null;

  context_limit?: number | null;

  license_source?: string | null;

  model_path: string | null;

  model_size_bytes: number | null;

  compatibility_status: string;
}

/* -------------------------------------------------------------------------- */
/* Telemetry                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Persisted normalized telemetry event returned by GET /telemetry.
 *
 * Process, network and file telemetry expose different fields, therefore
 * the interface intentionally keeps the record extensible.
 */
export interface TelemetryEvent {
  id?: number;

  event_key?: string;

  event_kind?: string;
  kind?: string;

  source?: string | null;
  channel?: string | null;
  host?: string | null;

  record_id?: string | null;
  event_id?: number | null;

  timestamp?: string | null;
  inserted_at?: string | null;

  application_identity?: string | null;

  image_path?: string | null;

  process_guid?: string | null;
  process_id?: number | null;

  parent_process_guid?: string | null;
  parent_process_id?: number | null;
  parent_image?: string | null;

  command_line?: string | null;

  user_name?: string | null;
  integrity_level?: string | null;

  protocol?: string | null;
  initiated?: boolean | null;

  source_ip?: string | null;
  source_port?: number | null;

  destination_ip?: string | null;
  destination_hostname?: string | null;
  destination_port?: number | null;

  target_filename?: string | null;

  creation_utc?: string | null;

  [key: string]: unknown;
}

/* -------------------------------------------------------------------------- */
/* Detection                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Persisted behavioral detection returned by GET /detections.
 */
export interface Detection {
  detection_id: string;

  application_identity: string;

  timestamp: string | null;

  anomaly_score: number;

  severity: Severity;

  confidence: number;

  statistical_contribution: number;

  deterministic_contribution: number;

  contributing_signals: Array<Record<string, unknown>>;

  baseline_comparison: Record<string, unknown>;

  provenance_references: string[];

  detector_version: string;

  model_version: string | null;

  feature_schema_version: string;

  reason: string | null;

  host: string | null;

  process_guid: string | null;

  parent_process_guid: string | null;

  process_id: number | null;

  image_path: string | null;

  [key: string]: unknown;
}

/* -------------------------------------------------------------------------- */
/* Applications                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Application/profile summary returned by GET /applications.
 */
export interface Application {
  application_identity: string;

  /**
   * Current backend may expose one of these counters depending on
   * the endpoint/database projection.
   */
  observation_count?: number;
  event_count?: number;

  [key: string]: unknown;
}

/* -------------------------------------------------------------------------- */
/* Ingestion                                                                  */
/* -------------------------------------------------------------------------- */

export interface IngestionStatus {
  active: boolean;

  last_ingestion_time: string | null;

  last_successful_collection: string | null;

  last_inserted_event_time: string | null;

  total_events_inserted: number;

  total_events_read: number;

  total_duplicates_skipped: number;

  total_unsupported_skipped: number;

  total_errors: number;

  last_error: string | null;

  last_error_time: string | null;

  current_interval_seconds: number;

  last_collection_duration_ms: number;

  events_in_last_collection: number;

  last_checkpoint_record_id: string | null;
}

/* -------------------------------------------------------------------------- */
/* Statistics                                                                 */
/* -------------------------------------------------------------------------- */

export interface Statistics {
  total_telemetry_events: number;

  total_applications: number;

  total_detection_results: number;

  behavioral_deviation_count: number;

  total_incidents: number;

  unresolved_incidents: number;
}

/* -------------------------------------------------------------------------- */
/* API configuration                                                          */
/* -------------------------------------------------------------------------- */

const API_BASE =
  import.meta.env.VITE_API_BASE?.replace(/\/+$/, "") ??
  "http://127.0.0.1:8000";

/* -------------------------------------------------------------------------- */
/* HTTP helper                                                                */
/* -------------------------------------------------------------------------- */

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    let detail = "";

    try {
      const body = (await response.json()) as {
        detail?: string;
        message?: string;
      };

      detail = body.detail ?? body.message ?? "";
    } catch {
      // Backend may return an empty/non-JSON error body.
    }

    throw new Error(
      detail
        ? `${response.status} ${response.statusText}: ${detail}`
        : `${response.status} ${response.statusText}`,
    );
  }

  return (await response.json()) as T;
}

/* -------------------------------------------------------------------------- */
/* API                                                                        */
/* -------------------------------------------------------------------------- */

export const api = {
  /* ------------------------------------------------------------------------ */
  /* Telemetry                                                                */
  /* ------------------------------------------------------------------------ */

  /**
   * Persisted normalized Windows telemetry.
   */
  listTelemetry: (limit = 100) => {
    const params = new URLSearchParams({
      limit: String(limit),
    });

    return get<TelemetryEvent[]>(
      `/telemetry?${params.toString()}`,
    );
  },

  /* ------------------------------------------------------------------------ */
  /* Applications                                                             */
  /* ------------------------------------------------------------------------ */

  /**
   * Persisted application identities / behavioral profiles.
   */
  listApplications: () =>
    get<Application[]>("/applications"),

  /**
   * Retrieve a single application profile.
   *
   * This is kept available for future application-detail UI.
   */
  getApplication: (applicationIdentity: string) =>
    get<Record<string, unknown>>(
      `/applications/${encodeURIComponent(applicationIdentity)}/profile`,
    ),

  /* ------------------------------------------------------------------------ */
  /* Detections                                                               */
  /* ------------------------------------------------------------------------ */

  /**
   * Persisted behavioral detections.
   */
  listDetections: (limit = 100) => {
    const params = new URLSearchParams({
      limit: String(limit),
    });

    return get<Detection[]>(
      `/detections?${params.toString()}`,
    );
  },

  /* ------------------------------------------------------------------------ */
  /* Incidents                                                                */
  /* ------------------------------------------------------------------------ */

  /**
   * Backend returns Incident[] directly.
   */
  listIncidents: () =>
    get<Incident[]>("/incidents"),

  /**
   * Retrieve one incident directly.
   *
   * The current App can continue using listIncidents(), but this method
   * makes the API layer ready for direct incident-detail loading.
   */
  getIncident: (incidentId: string) =>
    get<Incident>(
      `/incidents/${encodeURIComponent(incidentId)}`,
    ),

  /**
   * Retrieve the incident timeline directly.
   */
  getIncidentTimeline: (incidentId: string) =>
    get<IncidentEvent[]>(
      `/incidents/${encodeURIComponent(incidentId)}/timeline`,
    ),

  /* ------------------------------------------------------------------------ */
  /* AI Explanation                                                           */
  /* ------------------------------------------------------------------------ */

  /**
   * Generate/retrieve the grounded explanation for an incident.
   *
   * The backend is responsible for selecting the configured local
   * GenAI provider or deterministic fallback.
   */
  getExplanation: (incidentId: string) =>
    get<Explanation>(
      `/incidents/${encodeURIComponent(incidentId)}/explanation`,
    ),

  /* ------------------------------------------------------------------------ */
  /* AI Runtime                                                               */
  /* ------------------------------------------------------------------------ */

  /**
   * Runtime capabilities detected by the backend.
   *
   * Important:
   * npu_verified is authoritative only when the backend explicitly
   * reports true. A Snapdragon hardware label alone does not mean
   * NPU execution has been verified.
   */
  getRuntime: () =>
    get<RuntimeCapabilities>("/ai/runtime"),

  /* ------------------------------------------------------------------------ */
  /* AI Model                                                                 */
  /* ------------------------------------------------------------------------ */

  /**
   * Local model metadata.
   *
   * Current configured model:
   * Llama 3.2 3B Instruct / ONNX Runtime GenAI.
   */
  getModel: () =>
    get<ModelMetadata>("/ai/model"),

  /* ------------------------------------------------------------------------ */
  /* Ingestion                                                                */
  /* ------------------------------------------------------------------------ */

  /**
   * Current Sysmon ingestion state.
   */
  getIngestionStatus: () =>
    get<IngestionStatus>("/ingestion/status"),

  /* ------------------------------------------------------------------------ */
  /* Dashboard statistics                                                     */
  /* ------------------------------------------------------------------------ */

  /**
   * Database-backed dashboard statistics.
   */
  getStatistics: () =>
    get<Statistics>("/statistics"),
};