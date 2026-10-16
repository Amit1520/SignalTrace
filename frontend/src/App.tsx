import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import {
  Activity,
  AlertTriangle,
  AppWindow,
  BrainCircuit,
  ChevronRight,
  CircleDot,
  Cpu,
  FileKey2,
  Gauge,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  RefreshCw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
  X,
} from "lucide-react";

import {
  api,
  type Application,
  type Detection,
  type Explanation,
  type Incident,
  type IncidentEvent,
  type ModelMetadata,
  type ProcessNode,
  type RuntimeCapabilities,
  type Severity,
  type TelemetryEvent,
} from "./api";

const navItems = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "applications", label: "Applications", icon: AppWindow },
  { id: "incidents", label: "Incidents", icon: AlertTriangle },
  { id: "activity", label: "Live Activity", icon: Activity },
  { id: "explanation", label: "AI Explanation", icon: BrainCircuit },
  { id: "runtime", label: "System / Runtime", icon: Cpu },
] as const;

type Page = (typeof navItems)[number]["id"];

type IngestionStatus = {
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
};

type Statistics = {
  total_telemetry_events: number;
  total_applications: number;
  total_detection_results: number;
  behavioral_deviation_count: number;
  total_incidents: number;
  unresolved_incidents: number;
};

/* ============================================================
 * INCIDENT UI HELPERS
 * ============================================================
 */

type AggregatedEvidence = {
  key: string;
  eventCategory: string;
  description: string;
  count: number;
  contributions: number[];
  severity: Severity;
  eventReferences: string[];
  provenance: string[];
};

function sortIncidentTimeline(
  events: IncidentEvent[],
): IncidentEvent[] {
  return [...events].sort((a, b) => {
    const aTime = a.timestamp
      ? Date.parse(a.timestamp)
      : Number.POSITIVE_INFINITY;

    const bTime = b.timestamp
      ? Date.parse(b.timestamp)
      : Number.POSITIVE_INFINITY;

    if (!Number.isFinite(aTime) && !Number.isFinite(bTime)) {
      return a.event_reference.localeCompare(
        b.event_reference,
      );
    }

    if (!Number.isFinite(aTime)) {
      return 1;
    }

    if (!Number.isFinite(bTime)) {
      return -1;
    }

    const difference = aTime - bTime;

    if (difference !== 0) {
      return difference;
    }

    return a.event_reference.localeCompare(
      b.event_reference,
    );
  });
}

function aggregateIncidentEvidence(
  events: IncidentEvent[],
): AggregatedEvidence[] {
  const groups = new Map<
    string,
    AggregatedEvidence
  >();

  const severityRank: Record<Severity, number> = {
    normal: 0,
    low: 1,
    medium: 2,
    high: 3,
  };

  for (const event of events) {
    const key = `${event.event_category}::${event.description}`;

    const existing = groups.get(key);

    if (existing) {
      existing.count += 1;
      existing.contributions.push(event.contribution);
      existing.eventReferences.push(
        event.event_reference,
      );

      for (const reference of event.provenance) {
        if (!existing.provenance.includes(reference)) {
          existing.provenance.push(reference);
        }
      }

      if (
        severityRank[event.severity] >
        severityRank[existing.severity]
      ) {
        existing.severity = event.severity;
      }

      continue;
    }

    groups.set(key, {
      key,
      eventCategory: event.event_category,
      description: event.description,
      count: 1,
      contributions: [event.contribution],
      severity: event.severity,
      eventReferences: [event.event_reference],
      provenance: [...event.provenance],
    });
  }

  return Array.from(groups.values()).sort(
    (a, b) => {
      const aContribution = Math.max(
        ...a.contributions,
        0,
      );

      const bContribution = Math.max(
        ...b.contributions,
        0,
      );

      if (bContribution !== aContribution) {
        return bContribution - aContribution;
      }

      return a.eventCategory.localeCompare(
        b.eventCategory,
      );
    },
  );
}

function processNodeKey(node: ProcessNode): string {
  if (node.process_guid) {
    return `guid:${node.process_guid}`;
  }

  if (node.process_id !== null) {
    return `pid:${node.process_id}`;
  }

  return `unknown:${node.image_path ?? "process"}:${node.start_time ?? ""}:${node.hash ?? ""}`;
}

function processParentKey(
  node: ProcessNode,
): string | null {
  if (node.parent_guid) {
    return `guid:${node.parent_guid}`;
  }

  if (node.parent_pid !== null) {
    return `pid:${node.parent_pid}`;
  }

  return null;
}

function getProcessChildren(
  nodes: ProcessNode[],
): Map<string, ProcessNode[]> {
  const children = new Map<
    string,
    ProcessNode[]
  >();

  for (const node of nodes) {
    const parentKey = processParentKey(node);

    if (!parentKey) {
      continue;
    }

    const existing = children.get(parentKey);

    if (existing) {
      existing.push(node);
    } else {
      children.set(parentKey, [node]);
    }
  }

  for (const childNodes of children.values()) {
    childNodes.sort((a, b) => {
      const aTime = a.start_time
        ? Date.parse(a.start_time)
        : Number.POSITIVE_INFINITY;

      const bTime = b.start_time
        ? Date.parse(b.start_time)
        : Number.POSITIVE_INFINITY;

      if (
        !Number.isFinite(aTime) &&
        !Number.isFinite(bTime)
      ) {
        return processNodeKey(a).localeCompare(
          processNodeKey(b),
        );
      }

      if (!Number.isFinite(aTime)) {
        return 1;
      }

      if (!Number.isFinite(bTime)) {
        return -1;
      }

      const difference = aTime - bTime;

      if (difference !== 0) {
        return difference;
      }

      return processNodeKey(a).localeCompare(
        processNodeKey(b),
      );
    });
  }

  return children;
}

function formatProcessIdentity(node: ProcessNode): string {
  // PID is shown as the primary label because it is short and always
  // distinct. A truncated GUID (first 8 + last 4 characters) can collapse
  // to the SAME display string across many genuinely different sibling
  // processes when they share a GUID prefix/suffix pattern -- which Sysmon
  // GUIDs from the same host/boot commonly do. The full GUID is still
  // available on hover via the `title` attribute in ProcessTreeBranch,
  // which is unchanged.
  if (node.process_id !== null) {
    return `PID ${node.process_id}`;
  }

  if (node.process_guid) {
    const guid = node.process_guid;

    if (guid.length <= 16) {
      return `GUID ${guid}`;
    }

    return `GUID ${guid.slice(0, 8)}…${guid.slice(-4)}`;
  }

  return "Process identity unavailable";
}

function timelineDescription(event: IncidentEvent): string {
  const normalized = event.description.trim().toLowerCase();

  if (normalized && normalized !== "behavioral deviation evidence") {
    return event.description;
  }

  switch (event.event_category.toLowerCase()) {
    case "execution":
      return "Execution behavior deviated from the application baseline.";
    case "process":
      return "Process relationship behavior deviated from the application baseline.";
    case "temporal":
      return "Execution timing deviated from the application baseline.";
    case "network":
      return "Network behavior deviated from the application baseline.";
    case "file":
      return "File activity deviated from the application baseline.";
    default:
      return "Behavioral deviation was recorded for this application.";
  }
}

function ProcessTreeBranch({
  node,
  childrenByParent,
  visited,
}: {
  node: ProcessNode;
  childrenByParent: Map<string, ProcessNode[]>;
  visited: Set<string>;
}) {
  const nodeKey = processNodeKey(node);

  if (visited.has(nodeKey)) {
    return null;
  }

  const nextVisited = new Set(visited);
  nextVisited.add(nodeKey);

  const children =
    childrenByParent.get(nodeKey) ?? [];

  return (
    <div className="process-tree-branch">
      <div className="process-node">
        <div className="process-node-icon">
          <TerminalSquare size={16} />
        </div>

        <div>
          <strong>
            {friendlyApp(node.image_path)}
          </strong>

          <span
            className="process-node-identity"
            title={
              node.process_guid ??
              (node.process_id !== null
                ? `PID ${node.process_id}`
                : "Process identity unavailable")
            }
          >
            {formatProcessIdentity(node)}
          </span>
        </div>
      </div>

      {children.length > 0 && (
        <div className="process-tree-children">
          {children.map((child) => (
            <div
              className="process-tree-child"
              key={processNodeKey(child)}
            >
              <span className="process-tree-connector" />

              <ProcessTreeBranch
                node={child}
                childrenByParent={
                  childrenByParent
                }
                visited={nextVisited}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ============================================================
 * MAIN APP
 * ============================================================
 */

function App() {
  const [page, setPage] =
    useState<Page>("overview");

  const [incidents, setIncidents] = useState<
    Incident[]
  >([]);

  const [applications, setApplications] =
    useState<Application[]>([]);

  const [detections, setDetections] = useState<
    Detection[]
  >([]);

  const [telemetry, setTelemetry] = useState<
    TelemetryEvent[]
  >([]);

  const [selectedId, setSelectedId] = useState<
    string | null
  >(null);

  const [runtime, setRuntime] =
    useState<RuntimeCapabilities | null>(null);

  const [model, setModel] =
    useState<ModelMetadata | null>(null);

  const [apiError, setApiError] = useState<
    string | null
  >(null);

  const [mobileNav, setMobileNav] =
    useState(false);

  const [ingestionStatus, setIngestionStatus] =
    useState<IngestionStatus | null>(null);

  const [statistics, setStatistics] =
    useState<Statistics | null>(null);

  const loadData = async () => {
    try {
      const [
        incidentData,
        runtimeData,
        modelData,
        applicationData,
        detectionData,
        telemetryData,
        ingestionStatusData,
        statisticsData,
      ] = await Promise.all([
        api.listIncidents(),
        api.getRuntime(),
        api.getModel(),
        api.listApplications(),
        api.listDetections(),
        api.listTelemetry(),
        api.getIngestionStatus(),
        api.getStatistics(),
      ]);

      setIncidents(
        Array.isArray(incidentData)
          ? incidentData
          : incidentData
            ? [incidentData]
            : [],
      );

      setRuntime(runtimeData);
      setModel(modelData);
      setApplications(applicationData);
      setDetections(detectionData);
      setTelemetry(telemetryData);
      setIngestionStatus(
        ingestionStatusData,
      );
      setStatistics(statisticsData);
      setApiError(null);
    } catch (error) {
      setApiError(
        error instanceof Error
          ? error.message
          : "Backend unavailable",
      );
    }
  };

  useEffect(() => {
    void loadData();

    const timer = window.setInterval(
      () => void loadData(),
      5000,
    );

    return () =>
      window.clearInterval(timer);
  }, []);

  const selectedIncident =
    incidents.find(
      (item) =>
        item.incident_id === selectedId,
    ) ?? null;

  const navigate = (nextPage: Page) => {
    setPage(nextPage);
    setMobileNav(false);
  };

  const openIncident = (id: string) => {
    setSelectedId(id);
    setPage("incidents");
    setMobileNav(false);
  };

  const openIncidentQueue = () => {
    setSelectedId(null);
    setPage("incidents");
    setMobileNav(false);
  };

  return (
    <div className="app-shell">
      <aside
        className={`sidebar ${
          mobileNav ? "sidebar-open" : ""
        }`}
      >
        <div className="brand-lockup">
          <div className="brand-mark">
            <ShieldCheck
              size={20}
              strokeWidth={1.8}
            />
          </div>

          <div>
            <div className="brand-name">
              SignalTrace
            </div>

            <div className="brand-subtitle">
              Behavioral integrity
            </div>
          </div>

          <button
            className="icon-button sidebar-close"
            onClick={() =>
              setMobileNav(false)
            }
            aria-label="Close navigation"
          >
            <X size={17} />
          </button>
        </div>

        <div className="nav-caption">
          Command center
        </div>

        <nav
          className="primary-nav"
          aria-label="Primary navigation"
        >
          {navItems.map(
            ({ id, label, icon: Icon }) => (
              <button
                key={id}
                className={`nav-item ${
                  page === id
                    ? "nav-active"
                    : ""
                }`}
                onClick={() => navigate(id)}
              >
                <Icon size={17} />
                <span>{label}</span>

                {page === id && (
                  <ChevronRight
                    className="nav-chevron"
                    size={15}
                  />
                )}
              </button>
            ),
          )}
        </nav>

        <div className="sidebar-bottom">
          <div className="local-card">
            <div className="local-dot" />

            <div>
              <strong>Local only</strong>
              <span>
                Telemetry stays on device
              </span>
            </div>
          </div>

          <div className="sidebar-version">
            SIGNALTRACE / PHASE 8
            <br />
            <span>
              Investigation surface
            </span>
          </div>
        </div>
      </aside>

      {mobileNav && (
        <button
          className="sidebar-scrim"
          aria-label="Close navigation"
          onClick={() => setMobileNav(false)}
        />
      )}

      <main className="main-area">
        <header className="topbar">
          <button
            className="icon-button menu-button"
            onClick={() => setMobileNav(true)}
            aria-label="Open navigation"
          >
            <Menu size={20} />
          </button>

          <div className="crumb">
            <span>SignalTrace</span>
            <ChevronRight size={13} />

            <strong>
              {
                navItems.find(
                  (item) => item.id === page,
                )?.label
              }
            </strong>
          </div>

          <div className="topbar-actions">
            <div className="health-pill">
              <span
                className={`status-dot ${
                  apiError
                    ? "status-warn"
                    : ""
                }`}
              />

              {apiError
                ? "Backend unavailable"
                : "System watch active"}
            </div>

            <button
              className="icon-button"
              onClick={() => void loadData()}
              aria-label="Refresh data"
            >
              <RefreshCw size={16} />
            </button>

            <div className="avatar">
              SD
            </div>
          </div>
        </header>

        <div className="page-wrap">
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                <span className="eyebrow-line" />
                LOCAL BEHAVIORAL SECURITY
              </div>

              <h1>
                {page === "overview"
                  ? "Observe the drift."
                  : navItems.find(
                      (item) =>
                        item.id === page,
                    )?.label}
              </h1>

              <p>
                {page === "overview"
                  ? "Don't only ask whether software is known. Ask whether it is behaving like itself."
                  : pageDescription(page)}
              </p>
            </div>

            <div className="heading-meta">
              <span className="meta-label">
                DATA MODE
              </span>

              <strong>
                LIVE / LOCAL
              </strong>
            </div>
          </div>

          {apiError && (
            <div className="error-banner">
              <AlertTriangle size={16} />

              <span>
                API unavailable. The dashboard
                is showing the last available
                state.
              </span>

              <button
                onClick={() =>
                  void loadData()
                }
              >
                Retry
              </button>
            </div>
          )}

          {page === "overview" && (
            <Overview
              incidents={incidents}
              applications={applications}
              detections={detections}
              telemetry={telemetry}
              runtime={runtime}
              ingestionStatus={
                ingestionStatus
              }
              statistics={statistics}
              onIncident={openIncident}
              onActivity={() =>
                setPage("activity")
              }
            />
          )}

          {page === "applications" && (
            <Applications
              applications={applications}
            />
          )}

          {page === "incidents" &&
            (selectedIncident ? (
              <IncidentDetail
                incident={selectedIncident}
                onBack={() =>
                  setSelectedId(null)
                }
              />
            ) : (
              <Incidents
                incidents={incidents}
                onSelect={openIncident}
              />
            ))}

          {page === "activity" && (
            <ActivityPage
              telemetry={telemetry}
              ingestionStatus={
                ingestionStatus
              }
            />
          )}

          {page === "explanation" && (
            <ExplanationPage
              incidents={incidents}
              onOpenQueue={
                openIncidentQueue
              }
            />
          )}

          {page === "runtime" && (
            <RuntimePage
              runtime={runtime}
              model={model}
            />
          )}
        </div>
      </main>
    </div>
  );
}

/* ============================================================
 * OVERVIEW
 * ============================================================
 */

function Overview({
  incidents,
  applications,
  detections,
  telemetry,
  runtime,
  ingestionStatus,
  statistics,
  onIncident,
  onActivity,
}: {
  incidents: Incident[];
  applications: Application[];
  detections: Detection[];
  telemetry: TelemetryEvent[];
  runtime: RuntimeCapabilities | null;
  ingestionStatus: IngestionStatus | null;
  statistics: Statistics | null;
  onIncident: (id: string) => void;
  onActivity: () => void;
}) {
  const active =
    statistics?.unresolved_incidents ??
    incidents.filter(
      (item) =>
        item.status !== "resolved",
    ).length;

  const deviations =
    statistics?.behavioral_deviation_count ??
    detections.length;

  const applicationCount =
    statistics?.total_applications ??
    applications.length;

  const ready =
    runtime?.status === "available";

  const telemetryCount =
    statistics?.total_telemetry_events ??
    telemetry.length;

  const ingestionActive =
    ingestionStatus?.active ?? false;

  const eventsInserted =
    ingestionStatus?.total_events_inserted ??
    0;

  const hasRealData =
    telemetryCount > 0 ||
    deviations > 0 ||
    eventsInserted > 0;

  const recentTelemetry = useMemo(
    () => [...telemetry].slice(0, 5),
    [telemetry],
  );

  return (
    <div className="content-grid">
      <section className="health-card panel accent-panel">
        <div className="panel-kicker">
          <span>SIGNALTRACE HEALTH</span>

          <span className="live-badge">
            <CircleDot size={11} />
            {ingestionActive
              ? "LIVE"
              : "IDLE"}
          </span>
        </div>

        <div className="health-main">
          <div>
            <div className="health-orbit">
              <div className="orbit-core">
                <ShieldCheck size={28} />
                <span>LOCAL</span>
              </div>

              <i />
              <i />
              <i />
            </div>
          </div>

          <div className="health-copy">
            <h2>
              {hasRealData
                ? "Evidence is flowing."
                : "SignalTrace is ready."}
            </h2>

            <p>
              {hasRealData
                ? `${
                    statistics?.total_telemetry_events ??
                    eventsInserted
                  } events persisted, ${
                    statistics?.total_detection_results ??
                    detections.length
                  } detections, ${
                    statistics?.total_applications ??
                    applications.length
                  } applications.`
                : "Waiting for Windows telemetry to establish application baselines."}
            </p>

            <div className="health-tags">
              <span>
                <span className="mini-dot mint" />
                Telemetry{" "}
                {(statistics?.total_telemetry_events ??
                  telemetryCount) > 0
                  ? "connected"
                  : "waiting"}
              </span>

              <span>
                <span
                  className={`mini-dot ${
                    ready
                      ? "mint"
                      : "amber"
                  }`}
                />

                Local AI{" "}
                {ready
                  ? "available"
                  : "fallback"}
              </span>

              <span>
                <span
                  className={`mini-dot ${
                    ingestionActive
                      ? "mint"
                      : "amber"
                  }`}
                />

                Ingestion{" "}
                {ingestionActive
                  ? "active"
                  : "idle"}
              </span>
            </div>
          </div>
        </div>
      </section>

      <section className="metric-grid">
        <Metric
          label="Applications"
          value={applicationCount}
          note={
            applicationCount
              ? "observed locally"
              : "no applications observed"
          }
          icon={<AppWindow />}
        />

        <Metric
          label="Unresolved incidents"
          value={active}
          note={
            active
              ? "requiring review"
              : "no unresolved incidents"
          }
          icon={<AlertTriangle />}
          tone={
            active ? "amber" : ""
          }
        />

        <Metric
          label="Behavioral deviations"
          value={deviations}
          note={
            deviations
              ? "behavioral deviations detected"
              : "no behavioral deviations detected"
          }
          icon={<Gauge />}
          tone={
            deviations ? "rose" : ""
          }
        />

        <Metric
          label="Runtime"
          value={
            runtime?.status ===
            "available"
              ? "READY"
              : "N / A"
          }
          note={
            runtime?.error ??
            (runtime?.status ===
            "available"
              ? "local inference available"
              : "No runtime reported")
          }
          icon={<Cpu />}
          tone={
            runtime?.status ===
            "available"
              ? "mint"
              : ""
          }
          compact
        />
      </section>

      <section className="panel recent-panel">
        <PanelTitle
          label="RECENT INCIDENTS"
          action={
            incidents.length
              ? "View all"
              : undefined
          }
          onAction={() => undefined}
        />

        <div className="incident-list">
          {incidents.length ? (
            incidents
              .slice(0, 4)
              .map((incident) => (
                <IncidentRow
                  key={
                    incident.incident_id
                  }
                  incident={incident}
                  onClick={() =>
                    onIncident(
                      incident.incident_id,
                    )
                  }
                />
              ))
          ) : (
            <EmptyState
              icon={<ShieldCheck />}
              title="No incidents to review"
              copy={
                detections.length
                  ? `${detections.length} behavioral detection${
                      detections.length ===
                      1
                        ? ""
                        : "s"
                    } recorded, but none have met the current incident-correlation threshold.`
                  : "Correlated behavioral stories will appear here once detection evidence meets the incident threshold."
              }
            />
          )}
        </div>
      </section>

      <section className="panel signal-panel">
        <PanelTitle label="BEHAVIORAL SIGNALS" />

        <div className="signal-map">
          {[
            "Process DNA",
            "Network DNA",
            "File DNA",
            "Execution DNA",
            "Temporal DNA",
            "Privilege DNA",
          ].map((name, index) => (
            <div
              className={`signal-chip ${
                telemetry.length &&
                index < 3
                  ? "signal-seen"
                  : ""
              }`}
              key={name}
            >
              <span className="signal-ring" />

              <span>{name}</span>

              <strong>
                {telemetry.length &&
                index < 3
                  ? "observed"
                  : "waiting"}
              </strong>
            </div>
          ))}
        </div>

        <div className="signal-foot">
          <span>
            Profile dimensions
          </span>

          <span className="muted">
            Evidence-backed only
          </span>
        </div>
      </section>

      <section className="panel timeline-panel">
        <PanelTitle
          label="ACTIVITY TIMELINE"
          action={
            telemetry.length
              ? "Live activity"
              : undefined
          }
          onAction={onActivity}
        />

        <div className="mini-timeline">
          {recentTelemetry.map(
            (event, index) => (
              <div
                className="timeline-row"
                key={`${
                  event.event_key ??
                  event.id ??
                  index
                }`}
              >
                <span className="timeline-time">
                  {formatTime(
                    typeof event.timestamp ===
                      "string"
                      ? event.timestamp
                      : null,
                  )}
                </span>

                <span className="timeline-marker severity-normal" />

                <div>
                  <strong>
                    {capitalize(
                      event.event_kind ??
                        event.kind ??
                        "telemetry event",
                    )}
                  </strong>

                  <span>
                    {event.application_identity ??
                      event.image_path ??
                      event.destination_hostname ??
                      event.target_filename ??
                      event.command_line ??
                      "Normalized Windows telemetry event"}
                  </span>
                </div>
              </div>
            ),
          )}

          {!telemetry.length && (
            <EmptyState
              icon={<Activity />}
              title="Waiting for activity"
              copy="New normalized events will become visible here."
            />
          )}
        </div>
      </section>
    </div>
  );
}

/* ============================================================
 * SHARED COMPONENTS
 * ============================================================
 */

function Metric({
  label,
  value,
  note,
  icon,
  tone = "",
  compact = false,
}: {
  label: string;
  value: number | string;
  note: string;
  icon: ReactNode;
  tone?: string;
  compact?: boolean;
}) {
  return (
    <div className={`metric-card ${tone}`}>
      <div className="metric-top">
        <span>{label}</span>

        <span className="metric-icon">
          {icon}
        </span>
      </div>

      <strong
        className={
          compact
            ? "metric-compact"
            : ""
        }
      >
        {value}
      </strong>

      <small>{note}</small>
    </div>
  );
}

function PanelTitle({
  label,
  action,
  onAction,
}: {
  label: string;
  action?: string;
  onAction?: () => void;
}) {
  return (
    <div className="panel-title">
      <span>{label}</span>

      {action && (
        <button onClick={onAction}>
          {action}
          <ChevronRight size={13} />
        </button>
      )}
    </div>
  );
}

function IncidentRow({
  incident,
  onClick,
}: {
  incident: Incident;
  onClick: () => void;
}) {
  return (
    <button
      className="incident-row"
      onClick={onClick}
    >
      <span
        className={`severity-bar severity-${incident.severity}`}
      />

      <div className="incident-row-main">
        <strong>
          {shortId(incident.incident_id)}
        </strong>

        <span>
          {friendlyApp(
            incident.application_identity,
          )}
        </span>
      </div>

      <span
        className={`severity-label severity-text-${incident.severity}`}
      >
        {incident.severity}
      </span>

      <span className="incident-row-time">
        {formatTime(incident.last_seen)}
      </span>

      <ChevronRight size={15} />
    </button>
  );
}

function EmptyState({
  icon,
  title,
  copy,
}: {
  icon?: ReactNode;
  title: string;
  copy: string;
}) {
  return (
    <div className="empty-state">
      {icon && (
        <div className="empty-icon">
          {icon}
        </div>
      )}

      <strong>{title}</strong>

      <p>{copy}</p>
    </div>
  );
}

/* ============================================================
 * APPLICATIONS
 * ============================================================
 */

function Applications({
  applications,
}: {
  applications: Application[];
}) {
  return (
    <section className="panel table-panel">
      <div className="table-toolbar">
        <div>
          <div className="panel-title">
            <span>
              APPLICATION PROFILES
            </span>
          </div>
        </div>

        <div className="status-tag">
          {applications.length} observed
        </div>
      </div>

      {applications.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Application</th>
                <th>Identity</th>
                <th>Observed activity</th>
              </tr>
            </thead>

            <tbody>
              {applications.map(
                (application, index) => {
                  const identity =
                    application.application_identity;

                  const observationCount =
                    typeof application.observation_count ===
                    "number"
                      ? application.observation_count
                      : typeof application.event_count ===
                          "number"
                        ? application.event_count
                        : null;

                  return (
                    <tr
                      key={`${identity}-${index}`}
                    >
                      <td>
                        <div className="incident-row-main">
                          <strong>
                            {friendlyApp(
                              identity,
                            )}
                          </strong>

                          <span>
                            Local application
                          </span>
                        </div>
                      </td>

                      <td className="mono">
                        {identity}
                      </td>

                      <td>
                        {observationCount !==
                        null
                          ? `${observationCount} observations`
                          : "Observed in telemetry"}
                      </td>
                    </tr>
                  );
                },
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          icon={<AppWindow />}
          title="No application profiles available"
          copy="Application profiles will appear after normalized telemetry has been collected and application identities have been observed."
        />
      )}

      <div className="empty-note">
        <LockKeyhole size={15} />
        Local telemetry only
        <span />
        Evidence-backed application identities
      </div>
    </section>
  );
}

/* ============================================================
 * LIVE ACTIVITY
 * ============================================================
 */

function ActivityPage({
  telemetry,
  ingestionStatus,
}: {
  telemetry: TelemetryEvent[];
  ingestionStatus: IngestionStatus | null;
}) {
  const [query, setQuery] =
    useState("");

  const filtered = telemetry.filter(
    (event) => {
      if (!query) {
        return true;
      }

      const haystack = [
        event.event_kind,
        event.kind,
        event.source,
        event.channel,
        event.host,
        event.application_identity,
        event.image_path,
        event.command_line,
        event.destination_ip,
        event.destination_hostname,
        event.target_filename,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return haystack.includes(
        query.toLowerCase(),
      );
    },
  );

  return (
    <section className="panel table-panel">
      <div className="table-toolbar">
        <div className="table-toolbar-left">
          <div className="search-field">
            <Search size={15} />

            <input
              value={query}
              onChange={(event) =>
                setQuery(event.target.value)
              }
              placeholder="Search live telemetry..."
            />
          </div>
        </div>

        <div className="filter-select">
          <Activity size={14} />

          <span>
            {telemetry.length} events
          </span>
        </div>

        <div className="table-toolbar-right">
          <div className="ingestion-status">
            <span
              className={`status-dot ${
                ingestionStatus?.active
                  ? "status-active"
                  : "status-idle"
              }`}
            />

            <span>
              {ingestionStatus?.active
                ? "LIVE"
                : "IDLE"}
            </span>

            <span className="ingestion-meta">
              {ingestionStatus?.active &&
                ingestionStatus.last_successful_collection && (
                  <>
                    Last:{" "}
                    {formatDateTime(
                      ingestionStatus.last_successful_collection,
                    )}
                    {" | "}
                  </>
                )}

              {ingestionStatus?.events_in_last_collection !==
                undefined && (
                <>
                  {
                    ingestionStatus.events_in_last_collection
                  }{" "}
                  new
                </>
              )}
            </span>
          </div>
        </div>
      </div>

      {filtered.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Application</th>
                <th>Source</th>
                <th>Evidence</th>
              </tr>
            </thead>

            <tbody>
              {filtered.map(
                (event, index) => (
                  <tr
                    key={`${
                      event.event_key ??
                      event.id ??
                      "event"
                    }-${index}`}
                  >
                    <td>
                      {formatDateTime(
                        event.timestamp,
                      )}
                    </td>

                    <td>
                      <strong>
                        {capitalize(
                          event.event_kind ??
                            event.kind ??
                            "unknown",
                        )}
                      </strong>
                    </td>

                    <td>
                      {friendlyApp(
                        event.application_identity ??
                          event.image_path ??
                          null,
                      )}
                    </td>

                    <td>
                      {event.source ??
                        event.channel ??
                        "Sysmon"}
                    </td>

                    <td>
                      {event.command_line ??
                        event.destination_hostname ??
                        event.target_filename ??
                        event.destination_ip ??
                        "Normalized event"}
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          icon={<Activity />}
          title={
            telemetry.length
              ? "No matching telemetry"
              : "Waiting for Windows telemetry"
          }
          copy={
            telemetry.length
              ? "Try a different search term."
              : "No simulated events are shown. Persisted normalized Windows events will appear here."
          }
        />
      )}

      <div className="empty-note">
        <RefreshCw size={15} />
        Local polling every 5 seconds
        <span />
        No fabricated activity
      </div>
    </section>
  );
}

/* ============================================================
 * INCIDENT LIST
 * ============================================================
 */

function Incidents({
  incidents,
  onSelect,
}: {
  incidents: Incident[];
  onSelect: (id: string) => void;
}) {
  const [query, setQuery] =
    useState("");

  const [severity, setSeverity] =
    useState("all");

  const filtered = incidents.filter(
    (item) =>
      (!query ||
        friendlyApp(
          item.application_identity,
        )
          .toLowerCase()
          .includes(query.toLowerCase()) ||
        item.incident_id
          .toLowerCase()
          .includes(query.toLowerCase())) &&
      (severity === "all" ||
        item.severity === severity),
  );

  return (
    <section className="panel table-panel">
      <div className="table-toolbar">
        <div className="search-field">
          <Search size={15} />

          <input
            value={query}
            onChange={(event) =>
              setQuery(event.target.value)
            }
            placeholder="Search applications or incident ID"
          />
        </div>

        <div className="filter-select">
          <SlidersHorizontal size={14} />

          <select
            value={severity}
            onChange={(event) =>
              setSeverity(event.target.value)
            }
          >
            <option value="all">
              All severity
            </option>

            <option value="high">
              High
            </option>

            <option value="medium">
              Medium
            </option>

            <option value="low">
              Low
            </option>

            <option value="normal">
              Normal
            </option>
          </select>
        </div>
      </div>

      {filtered.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Incident</th>
                <th>Application</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>First seen</th>
                <th>Last seen</th>
                <th>Evidence</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>

            <tbody>
              {filtered.map((item) => (
                <tr
                  key={item.incident_id}
                  onClick={() =>
                    onSelect(
                      item.incident_id,
                    )
                  }
                >
                  <td className="mono">
                    {shortId(
                      item.incident_id,
                    )}
                  </td>

                  <td>
                    <strong>
                      {friendlyApp(
                        item.application_identity,
                      )}
                    </strong>
                  </td>

                  <td>
                    <span
                      className={`table-severity severity-text-${item.severity}`}
                    >
                      <i />
                      {item.severity}
                    </span>
                  </td>

                  <td>
                    {Math.round(
                      item.confidence * 100,
                    )}
                    %
                  </td>

                  <td>
                    {formatDate(
                      item.first_seen,
                    )}
                  </td>

                  <td>
                    {formatDate(
                      item.last_seen,
                    )}
                  </td>

                  <td>
                    {item.anomaly_count}{" "}
                    anomalies
                  </td>

                  <td>
                    <span className="status-tag">
                      {item.status}
                    </span>
                  </td>

                  <td>
                    <ChevronRight size={15} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          icon={<ShieldCheck />}
          title="No matching incidents"
          copy={
            incidents.length
              ? "Try a different filter."
              : "No correlated behavioral incidents have been created yet. This is independent of persisted telemetry and detections."
          }
        />
      )}
    </section>
  );
}

/* ============================================================
 * INCIDENT DETAIL + REAL AI EXPLANATION
 * ============================================================
 */

function IncidentDetail({
  incident,
  onBack,
}: {
  incident: Incident;
  onBack: () => void;
}) {
  const [explanation, setExplanation] =
    useState<Explanation | null>(null);

  const [loading, setLoading] =
    useState(false);

  const [explanationError, setExplanationError] =
    useState<string | null>(null);

  const fetchExplanation = async () => {
    if (loading) {
      return;
    }

    setLoading(true);
    setExplanationError(null);

    try {
      const result =
        await api.getExplanation(
          incident.incident_id,
        );

      if (!result) {
        throw new Error(
          "The AI explanation endpoint returned no explanation.",
        );
      }

      setExplanation(result);
    } catch (error) {
      setExplanation(null);

      setExplanationError(
        error instanceof Error
          ? error.message
          : "Unable to generate the local AI explanation.",
      );
    } finally {
      setLoading(false);
    }
  };

  const sortedTimeline = useMemo(
    () =>
      sortIncidentTimeline(
        incident.timeline,
      ),
    [incident.timeline],
  );

  const aggregatedEvidence = useMemo(
    () =>
      aggregateIncidentEvidence(
        incident.timeline,
      ),
    [incident.timeline],
  );

  return (
    <div className="investigation">
      <button
        className="back-link"
        onClick={onBack}
      >
        ← All incidents
      </button>

      <div className="incident-header panel">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            CORRELATED BEHAVIORAL INCIDENT
          </div>

          <h2>
            {shortId(
              incident.incident_id,
            )}
          </h2>

          <p className="identity-line">
            <TerminalSquare size={15} />

            {friendlyApp(
              incident.application_identity,
            )}
          </p>
        </div>

        <div className="incident-header-stats">
          <div>
            <span>SEVERITY</span>

            <strong
              className={`severity-text-${incident.severity}`}
            >
              {incident.severity}
            </strong>
          </div>

          <div>
            <span>CONFIDENCE</span>

            <strong>
              {Math.round(
                incident.confidence * 100,
              )}
              %
            </strong>
          </div>

          <div>
            <span>STATUS</span>

            <strong className="status-open">
              {incident.status}
            </strong>
          </div>
        </div>
      </div>

      <div className="investigation-grid">
        {/* ======================================================
            CORRECTED PROCESS CHAIN
            ====================================================== */}

        <section className="panel process-panel">
          <PanelTitle label="PROCESS CHAIN" />

          <div className="process-tree">
            {incident.process_chain.length ? (
              (() => {
                const nodes =
                  incident.process_chain;

                const nodeKeys = new Set(
                  nodes.map(processNodeKey),
                );

                const childrenByParent =
                  getProcessChildren(nodes);

                const roots = nodes.filter(
                  (node) => {
                    const parentKey =
                      processParentKey(node);

                    return (
                      !parentKey ||
                      !nodeKeys.has(parentKey)
                    );
                  },
                );

                /*
                 * Normally roots should contain
                 * the true process-chain roots.
                 *
                 * If the backend returns a cyclic
                 * or incomplete relationship graph,
                 * preserve the nodes rather than
                 * hiding them.
                 */
                const renderRoots =
                  roots.length > 0
                    ? roots
                    : nodes;

                return renderRoots.map(
                  (node) => (
                    <ProcessTreeBranch
                      key={processNodeKey(
                        node,
                      )}
                      node={node}
                      childrenByParent={
                        childrenByParent
                      }
                      visited={new Set()}
                    />
                  ),
                );
              })()
            ) : (
              <EmptyState
                icon={<TerminalSquare />}
                title="No process identity"
                copy="The incident preserved no reliable process GUID or path."
              />
            )}
          </div>
        </section>

        {/* ======================================================
            CORRECTED CHRONOLOGY
            ====================================================== */}

        <section className="panel timeline-detail">
          <PanelTitle label="CHRONOLOGY" />

          <div className="detail-timeline">
            {sortedTimeline.length ? (
              sortedTimeline.map(
                (event) => (
                  <div
                    className="detail-event"
                    key={`${event.event_reference}-${event.event_category}`}
                  >
                    <div className="detail-event-time">
                      {event.timestamp
                        ? formatTime(
                            event.timestamp,
                          )
                        : "Unknown"}

                      <span>
                        {event.timestamp
                          ? formatDate(
                              event.timestamp,
                            )
                          : "Timestamp unavailable"}
                      </span>
                    </div>

                    <div
                      className={`detail-event-dot severity-${event.severity}`}
                    />

                    <div className="detail-event-content">
                      <div>
                        <span className="category-label">
                          {
                            event.event_category
                          }
                        </span>

                        <span
                          className={`severity-label severity-text-${event.severity}`}
                        >
                          {event.severity}
                        </span>
                      </div>

                      <strong className="detail-event-description">
                        {timelineDescription(event)}
                      </strong>

                      {event.description.trim().toLowerCase() ===
                        "behavioral deviation evidence" && (
                        <small className="detail-event-source-label">
                          Recorded as {event.event_category} behavioral evidence
                        </small>
                      )}

                      <small>
                        Evidence ·{" "}
                        {shortId(
                          event.event_reference,
                        )}
                      </small>
                    </div>
                  </div>
                )
              )
            ) : (
              <EmptyState
                icon={<Activity />}
                title="No chronology available"
                copy="No timeline evidence was returned for this incident."
              />
            )}
          </div>
        </section>

        {/* ======================================================
            CORRECTED BEHAVIORAL EVIDENCE
            ====================================================== */}

        <section className="panel evidence-panel">
          <PanelTitle label="BEHAVIORAL EVIDENCE" />

          <div className="evidence-score">
            <span>Peak event contribution</span>

            <strong>
              {Math.round(
                Math.max(
                  ...incident.timeline.map(
                    (item) =>
                      item.contribution,
                  ),
                  0,
                ) * 100,
              )}

              <small>/100</small>
            </strong>
          </div>

          <div className="evidence-list">
            {aggregatedEvidence.length ? (
              aggregatedEvidence.map(
                (evidence) => {
                  const peakContribution =
                    Math.max(
                      ...evidence.contributions,
                      0,
                    );

                  return (
                    <div
                      className="evidence-item"
                      key={evidence.key}
                    >
                      <div
                        className={`evidence-icon severity-${evidence.severity}`}
                      >
                        <Sparkles size={14} />
                      </div>

                      <div className="evidence-item-content">
                        <div className="evidence-item-heading">
                          <strong>
                            {capitalize(
                              evidence.eventCategory,
                            )}{" "}
                            deviation
                          </strong>

                          <span className="evidence-count">
                            {evidence.count} occurrence
                            {evidence.count === 1 ? "" : "s"}
                          </span>
                        </div>

                        <p>
                          {
                            evidence.description
                          }
                        </p>

                        <span className="evidence-contribution">
                          Peak event contribution ·{" "}
                          {Math.round(
                            peakContribution *
                              100,
                          )}
                          %
                        </span>

                        {evidence
                          .eventReferences
                          .length >
                          0 && (
                          <small className="evidence-reference-count">
                            {
                              evidence
                                .eventReferences
                                .length
                            }{" "}
                            supporting event
                            {evidence
                              .eventReferences
                              .length ===
                            1
                              ? ""
                              : "s"}
                          </small>
                        )}

                        {evidence.provenance.length > 0 && (
                          <small className="evidence-provenance-count">
                            {evidence.provenance.length} provenance reference
                            {evidence.provenance.length === 1 ? "" : "s"}
                          </small>
                        )}
                      </div>
                    </div>
                  );
                },
              )
            ) : (
              <EmptyState
                icon={<Sparkles />}
                title="No behavioral evidence"
                copy="No structured evidence was returned for this incident."
              />
            )}
          </div>
        </section>
      </div>

      {/* ========================================================
          LOCAL AI EXPLANATION
          ======================================================== */}

      <section className="panel explanation-panel">
        <div className="explanation-heading">
          <div>
            <div className="panel-title">
              <span>
                LOCAL AI EXPLANATION
              </span>

              <span className="fallback-pill">
                <Sparkles size={12} />

                {explanation
                  ? explanation.generation_status ===
                    "generated"
                    ? `LOCAL AI · ${formatProviderLabel(
                        explanation.provider,
                      )}`
                    : explanation.generation_status ===
                        "fallback"
                      ? "LOCAL / FALLBACK"
                      : "AI / FAILED"
                  : "LOCAL AI EXPLANATION"}
              </span>
            </div>

            <h3>
              {explanation
                ? explanation.summary
                : "Grounded interpretation of this incident"}
            </h3>
          </div>

          {!explanation && (
            <button
              className="primary-button"
              onClick={() =>
                void fetchExplanation()
              }
              disabled={loading}
            >
              {loading
                ? "Generating..."
                : explanationError
                  ? "Retry explanation"
                  : "Generate explanation"}

              <Sparkles size={15} />
            </button>
          )}
        </div>

        {explanation ? (
          <div className="explanation-columns">
            <ExplanationBlock
              title="What changed"
              items={
                explanation.what_changed
              }
            />

            <ExplanationBlock
              title="Why unusual"
              items={
                explanation.why_unusual
              }
            />

            <ExplanationBlock
              title="Good to know"
              items={
                explanation.uncertainty
              }
            />

            <ExplanationBlock
              title="Investigation"
              items={
                explanation.recommended_investigation
              }
            />
          </div>
        ) : explanationError ? (
          <p className="explanation-placeholder">
            Local AI explanation failed:{" "}
            {explanationError}
          </p>
        ) : (
          <p className="explanation-placeholder">
            Explanation uses only the structured
            evidence above. No cloud inference or
            autonomous response is involved.
          </p>
        )}
      </section>
    </div>
  );
}

/* ============================================================
 * EXPLANATION BLOCK
 * ============================================================
 */

function ExplanationBlock({
  title,
  items,
}: {
  title: string;
  items: string[];
}) {
  return (
    <div>
      <span className="block-label">
        {title}
      </span>

      {items.length ? (
        <ul>
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="muted">
          No evidence supplied.
        </p>
      )}
    </div>
  );
}

/* ============================================================
 * AI EXPLANATION PAGE
 * ============================================================
 */

function ExplanationPage({
  incidents,
  onOpenQueue,
}: {
  incidents: Incident[];
  onOpenQueue: () => void;
}) {
  return (
    <section className="empty-page panel">
      <div className="empty-hero-mark violet">
        <BrainCircuit size={32} />
      </div>

      <div className="eyebrow centered">
        <span className="eyebrow-line" />
        EXPLANATION LAYER
      </div>

      <h2>
        {incidents.length
          ? "Select an incident to investigate"
          : "Local explanation is ready"}
      </h2>

      <p>
        SignalTrace explanations are grounded
        in precomputed evidence. They never
        replace detection and never take action.
      </p>

      <button
        className="primary-button"
        onClick={onOpenQueue}
        disabled={!incidents.length}
      >
        Open incident queue
        <ChevronRight size={15} />
      </button>
    </section>
  );
}

/* ============================================================
 * RUNTIME
 * ============================================================
 */

function RuntimePage({
  runtime,
  model,
}: {
  runtime: RuntimeCapabilities | null;
  model: ModelMetadata | null;
}) {
  return (
    <div className="runtime-grid">
      <section className="panel runtime-hero">
        <div className="panel-kicker">
          <span>LOCAL AI RUNTIME</span>

          <span
            className={`availability ${
              runtime?.status ===
              "available"
                ? "available"
                : "unavailable"
            }`}
          >
            {runtime?.status ===
            "available"
              ? "AVAILABLE"
              : "NOT AVAILABLE"}
          </span>
        </div>

        <div className="runtime-title">
          <div className="runtime-icon">
            <Cpu size={24} />
          </div>

          <div>
            <h2>
              {runtime?.runtime_name ??
                "ONNX Runtime"}
            </h2>

            <p>
              {runtime?.runtime_version
                ? `Version ${runtime.runtime_version}`
                : "No runtime installed"}
            </p>
          </div>
        </div>

        <div className="runtime-facts">
          <Fact
            label="Execution provider"
            value={
              runtime?.execution_provider ??
              "Not available"
            }
          />

          <Fact
            label="Device"
            value={
              runtime?.device ??
              "Not verified"
            }
          />

          <Fact
            label="Architecture"
            value={
              runtime?.architecture ??
              "Unknown"
            }
          />

          <Fact
            label="Platform"
            value={
              runtime?.hardware_label ??
              "Platform not detected"
            }
          />
        </div>
      </section>

      <section className="panel accelerator-panel">
        <PanelTitle label="ACCELERATION STATUS" />

        <Accel
          label="CPU"
          state={
            runtime?.available_providers.includes(
              "CPUExecutionProvider",
            )
              ? "AVAILABLE"
              : "NOT AVAILABLE"
          }
          icon={<Cpu />}
        />

        <Accel
          label="GPU"
          state="NOT VERIFIED"
          icon={<Gauge />}
        />

        <Accel
          label="NPU"
          state={
            runtime?.npu_verified
              ? "AVAILABLE"
              : "NOT VERIFIED"
          }
          icon={<Sparkles />}
        />

        <Accel
          label="Snapdragon"
          state={
            runtime?.hardware_label ??
            "NOT VERIFIED"
          }
          icon={<Activity />}
        />

        <p className="runtime-note">
          A detected platform is not evidence
          of accelerator execution. Providers
          are reported only by the installed
          runtime.
        </p>
      </section>

      <section className="panel model-panel">
        <PanelTitle label="MODEL CONFIGURATION" />

        {model?.name ? (
          <div className="model-empty">
            <FileKey2 size={22} />

            <strong>
              {formatModelName(model.name)}
            </strong>

            <span>
              {model.compatibility_status ||
                "Local model package detected"}
            </span>

            <div className="model-meta">
              <span>
                <b>Provider</b>
                ONNX Runtime GenAI
              </span>

              <span>
                <b>Format</b>
                {model.format ||
                  "onnx-genai"}
              </span>

              <span>
                <b>Version</b>
                {model.version ||
                  "Unknown"}
              </span>

              {model.context_limit ? (
                <span>
                  <b>Context</b>
                  {model.context_limit.toLocaleString()}{" "}
                  tokens
                </span>
              ) : null}

              {model.model_size_bytes ? (
                <span>
                  <b>Size</b>
                  {formatBytes(
                    model.model_size_bytes,
                  )}
                </span>
              ) : null}
            </div>

            <span>
              The model is configured locally.
              Actual accelerator execution is
              reported separately by the runtime.
            </span>
          </div>
        ) : (
          <div className="model-empty">
            <FileKey2 size={22} />

            <strong>
              No local model configured
            </strong>

            <span>
              The deterministic local fallback
              is available.
            </span>
          </div>
        )}
      </section>
    </div>
  );
}

/* ============================================================
 * RUNTIME HELPERS
 * ============================================================
 */

function Fact({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Accel({
  label,
  state,
  icon,
}: {
  label: string;
  state: string;
  icon: ReactNode;
}) {
  return (
    <div className="accel-row">
      <span className="accel-icon">
        {icon}
      </span>

      <strong>{label}</strong>

      <span
        className={`availability ${
          state === "AVAILABLE"
            ? "available"
            : "unavailable"
        }`}
      >
        {state}
      </span>
    </div>
  );
}

/* ============================================================
 * FORMATTERS
 * ============================================================
 */

function formatProviderLabel(
  provider: string | null | undefined,
) {
  if (!provider) {
    return "LOCAL";
  }

  const normalized =
    provider.trim().toLowerCase();

  if (
    normalized === "onnxruntime-genai"
  ) {
    return "ONNX RUNTIME GENAI";
  }

  if (
    normalized ===
      "deterministic-fallback" ||
    normalized === "fallback"
  ) {
    return "FALLBACK";
  }

  return provider.toUpperCase();
}

function formatModelName(name: string) {
  const normalized =
    name.trim().toLowerCase();

  if (
    normalized.includes(
      "llama-3.2-3b",
    )
  ) {
    return "Llama 3.2 3B";
  }

  return name;
}

function formatBytes(value: number) {
  if (
    !Number.isFinite(value) ||
    value <= 0
  ) {
    return "Unknown";
  }

  const units = [
    "B",
    "KB",
    "MB",
    "GB",
    "TB",
  ];

  let size = value;
  let index = 0;

  while (
    size >= 1024 &&
    index < units.length - 1
  ) {
    size /= 1024;
    index += 1;
  }

  return `${size.toFixed(
    index >= 3 ? 2 : 1,
  )} ${units[index]}`;
}

function pageDescription(page: Page) {
  return (
    {
      applications:
        "Read the behavioral patterns learned from local telemetry.",

      incidents:
        "Correlated stories assembled from behavioral deviation evidence.",

      activity:
        "A local view of normalized events as they arrive.",

      explanation:
        "Grounded interpretation, never a replacement for detection.",

      runtime:
        "Verified local inference capability and execution status.",

      overview: "",
    } as Record<Page, string>
  )[page];
}

function friendlyApp(
  value: string | null | undefined,
) {
  if (!value) {
    return "Unknown application";
  }

  const parts = value
    .replace(/\\/g, "/")
    .split("/");

  return parts[parts.length - 1] || value;
}

function shortId(value: string) {
  return value
    .slice(0, 8)
    .toUpperCase();
}

function formatTime(
  value: string | null | undefined,
) {
  return value
    ? new Date(
        value,
      ).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      })
    : "--:--";
}

function formatDate(
  value: string | null | undefined,
) {
  return value
    ? new Date(
        value,
      ).toLocaleDateString([], {
        month: "short",
        day: "numeric",
      })
    : "--";
}

function formatDateTime(
  value: string | null | undefined,
) {
  return value
    ? new Date(
        value,
      ).toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Unknown";
}

function capitalize(value: string) {
  return (
    value.charAt(0).toUpperCase() +
    value.slice(1)
  );
}

export default App;
