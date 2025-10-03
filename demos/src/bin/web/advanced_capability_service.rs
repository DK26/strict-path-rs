//! Advanced capability-based medical records system (Stage 4 pattern).
//!
//! This demo follows the tutorial Stage 4 pattern: check authorization FIRST,
//! THEN encode it in the type via change_marker(). This service demonstrates
//! sophisticated capability-based authorization using complex trait hierarchies.
//! In a medical records system, different roles (patients, nurses, doctors,
//! administrators) have different capabilities (read-only, read-write, audit,
//! emergency access). We validate roles FIRST (e.g., `match self.claims.role`),
//! THEN call change_marker() to encode proven authorization as tuple markers like
//! `PathBoundary<(VitalsData, CanWrite)>`. The type system enforces that only
//! authorized combinations can access specific record types. Emergency override
//! capabilities can be granted temporarily, and audit logs track all access. This
//! showcases the most advanced authorization patterns possible with strict-path's
//! marker system and Rust's type system.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use strict_path::PathBoundary;
use tokio::{net::TcpListener, signal, sync::RwLock};
use uuid::Uuid;

const SERVICE_ROOT: &str = "demo_data/medical_records_service";
const SERVER_ADDR: &str = "127.0.0.1:4022";

#[tokio::main]
async fn main() -> Result<()> {
    bootstrap_medical_system()?;

    let auth_service = MedicalAuthService::new();
    let records_system = MedicalRecordsSystem::new(SERVICE_ROOT)?;

    let state = Arc::new(AppState {
        auth_service,
        records_system,
    });

    print_launch_instructions(state.as_ref()).await;

    let app = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/records/patient/:patient_id", get(get_patient_records))
        .route(
            "/api/records/patient/:patient_id/vitals",
            get(read_vitals).put(update_vitals),
        )
        .route(
            "/api/records/patient/:patient_id/diagnosis",
            get(read_diagnosis).put(update_diagnosis),
        )
        .route(
            "/api/records/patient/:patient_id/prescriptions",
            get(read_prescriptions).put(update_prescriptions),
        )
        .route("/api/admin/audit-log", get(read_audit_log))
        .route(
            "/api/emergency/override/:patient_id",
            post(emergency_access_override),
        )
        .with_state(state);

    let addr: SocketAddr = SERVER_ADDR.parse().context("invalid listen address")?;
    println!("\nMedical Records System listening on http://{addr}");
    println!("Press Ctrl+C to stop the server.\n");

    let listener = TcpListener::bind(addr)
        .await
        .context("failed to bind TCP listener")?;

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}

async fn print_launch_instructions(state: &AppState) {
    println!("Medical Records System - Sample Credentials:");
    let users = state.auth_service.sample_users().await;
    for user in users {
        println!("  - Role: {:?}, Credential: {}", user.role, user.credential);
    }
    println!("\nTo use:");
    println!("1. POST to /api/auth/login with {{\"credential\": \"patient_alice\", \"password\": \"pass123\"}}");
    println!("2. Use the session token in X-Session-Token header");
    println!("3. Access medical records based on your role and capabilities");
    println!();
}

// Authentication
async fn login(
    State(state): State<SharedState>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let session = state
        .auth_service
        .authenticate(&request.credential, &request.password)
        .await?;
    Ok(Json(LoginResponse {
        session_token: session.session_token,
        role: session.role,
        capabilities: session.capabilities.clone(),
    }))
}

// Patient records access with capability checking
async fn get_patient_records(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(patient_id): Path<String>,
) -> ApiResult<Json<PatientRecordsResponse>> {
    let session = state.authorize(&headers).await?;
    let patient_uuid =
        Uuid::parse_str(&patient_id).map_err(|_| ApiError::bad_request("Invalid patient ID"))?;

    let records_access = session.patient_records_access(patient_uuid)?;
    let records = state
        .records_system
        .load_patient_summary(&records_access, patient_uuid)
        .await?;

    // Log access for audit trail
    state
        .records_system
        .log_access(
            &session.claims.credential,
            &format!("Accessed patient {} records", patient_id),
            session.claims.role,
        )
        .await?;

    Ok(Json(PatientRecordsResponse { records }))
}

async fn read_vitals(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(patient_id): Path<String>,
) -> ApiResult<Json<VitalsResponse>> {
    let session = state.authorize(&headers).await?;
    let patient_uuid =
        Uuid::parse_str(&patient_id).map_err(|_| ApiError::bad_request("Invalid patient ID"))?;

    let vitals_access = session.vitals_read_access(patient_uuid)?;
    let vitals_path = vitals_access.strict_join("vitals.json")?;

    let vitals_data = vitals_path
        .read_to_string()
        .map_err(|e| ApiError::internal(anyhow!("Failed to read vitals: {e}")))?;

    state
        .records_system
        .log_access(
            &session.claims.credential,
            &format!("Read vitals for patient {}", patient_id),
            session.claims.role,
        )
        .await?;

    Ok(Json(VitalsResponse {
        patient_id: patient_uuid,
        data: vitals_data,
    }))
}

async fn update_vitals(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(patient_id): Path<String>,
    Json(request): Json<UpdateVitalsRequest>,
) -> ApiResult<Json<VitalsResponse>> {
    let session = state.authorize(&headers).await?;
    let patient_uuid =
        Uuid::parse_str(&patient_id).map_err(|_| ApiError::bad_request("Invalid patient ID"))?;

    let vitals_access = session.vitals_write_access(patient_uuid)?;
    let vitals_path = vitals_access.strict_join("vitals.json")?;

    vitals_path
        .write(&request.vitals_data)
        .map_err(|e| ApiError::internal(anyhow!("Failed to update vitals: {e}")))?;

    state
        .records_system
        .log_access(
            &session.claims.credential,
            &format!("Updated vitals for patient {}", patient_id),
            session.claims.role,
        )
        .await?;

    Ok(Json(VitalsResponse {
        patient_id: patient_uuid,
        data: request.vitals_data,
    }))
}

async fn read_diagnosis(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(patient_id): Path<String>,
) -> ApiResult<Json<DiagnosisResponse>> {
    let session = state.authorize(&headers).await?;
    let patient_uuid =
        Uuid::parse_str(&patient_id).map_err(|_| ApiError::bad_request("Invalid patient ID"))?;

    let diagnosis_access = session.diagnosis_read_access(patient_uuid)?;
    let diagnosis_path = diagnosis_access.strict_join("diagnosis.json")?;

    let diagnosis_data = diagnosis_path
        .read_to_string()
        .map_err(|e| ApiError::internal(anyhow!("Failed to read diagnosis: {e}")))?;

    state
        .records_system
        .log_access(
            &session.claims.credential,
            &format!("Read diagnosis for patient {}", patient_id),
            session.claims.role,
        )
        .await?;

    Ok(Json(DiagnosisResponse {
        patient_id: patient_uuid,
        data: diagnosis_data,
    }))
}

async fn update_diagnosis(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(patient_id): Path<String>,
    Json(request): Json<UpdateDiagnosisRequest>,
) -> ApiResult<Json<DiagnosisResponse>> {
    let session = state.authorize(&headers).await?;
    let patient_uuid =
        Uuid::parse_str(&patient_id).map_err(|_| ApiError::bad_request("Invalid patient ID"))?;

    let diagnosis_access = session.diagnosis_write_access(patient_uuid)?;
    let diagnosis_path = diagnosis_access.strict_join("diagnosis.json")?;

    diagnosis_path
        .write(&request.diagnosis_data)
        .map_err(|e| ApiError::internal(anyhow!("Failed to update diagnosis: {e}")))?;

    state
        .records_system
        .log_access(
            &session.claims.credential,
            &format!("Updated diagnosis for patient {}", patient_id),
            session.claims.role,
        )
        .await?;

    Ok(Json(DiagnosisResponse {
        patient_id: patient_uuid,
        data: request.diagnosis_data,
    }))
}

async fn read_prescriptions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(patient_id): Path<String>,
) -> ApiResult<Json<PrescriptionsResponse>> {
    let session = state.authorize(&headers).await?;
    let patient_uuid =
        Uuid::parse_str(&patient_id).map_err(|_| ApiError::bad_request("Invalid patient ID"))?;

    let prescriptions_access = session.prescriptions_read_access(patient_uuid)?;
    let prescriptions_path = prescriptions_access.strict_join("prescriptions.json")?;

    let prescriptions_data = prescriptions_path
        .read_to_string()
        .map_err(|e| ApiError::internal(anyhow!("Failed to read prescriptions: {e}")))?;

    state
        .records_system
        .log_access(
            &session.claims.credential,
            &format!("Read prescriptions for patient {}", patient_id),
            session.claims.role,
        )
        .await?;

    Ok(Json(PrescriptionsResponse {
        patient_id: patient_uuid,
        data: prescriptions_data,
    }))
}

async fn update_prescriptions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(patient_id): Path<String>,
    Json(request): Json<UpdatePrescriptionsRequest>,
) -> ApiResult<Json<PrescriptionsResponse>> {
    let session = state.authorize(&headers).await?;
    let patient_uuid =
        Uuid::parse_str(&patient_id).map_err(|_| ApiError::bad_request("Invalid patient ID"))?;

    let prescriptions_access = session.prescriptions_write_access(patient_uuid)?;
    let prescriptions_path = prescriptions_access.strict_join("prescriptions.json")?;

    prescriptions_path
        .write(&request.prescriptions_data)
        .map_err(|e| ApiError::internal(anyhow!("Failed to update prescriptions: {e}")))?;

    state
        .records_system
        .log_access(
            &session.claims.credential,
            &format!("Updated prescriptions for patient {}", patient_id),
            session.claims.role,
        )
        .await?;

    Ok(Json(PrescriptionsResponse {
        patient_id: patient_uuid,
        data: request.prescriptions_data,
    }))
}

async fn read_audit_log(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<AuditParams>,
) -> ApiResult<Json<AuditLogResponse>> {
    let session = state.authorize(&headers).await?;
    let audit_access = session.audit_access()?;

    let entries = state
        .records_system
        .load_audit_entries(&audit_access, params.limit.unwrap_or(50))
        .await?;

    Ok(Json(AuditLogResponse { entries }))
}

async fn emergency_access_override(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(patient_id): Path<String>,
    Json(request): Json<EmergencyOverrideRequest>,
) -> ApiResult<Json<EmergencyOverrideResponse>> {
    let session = state.authorize(&headers).await?;
    let patient_uuid =
        Uuid::parse_str(&patient_id).map_err(|_| ApiError::bad_request("Invalid patient ID"))?;

    let _ = session.emergency_override_access()?;

    // Grant temporary full access for emergency
    let override_token = state
        .auth_service
        .grant_emergency_override(
            &session.claims.credential,
            patient_uuid,
            &request.emergency_reason,
        )
        .await?;

    state
        .records_system
        .log_access(
            &session.claims.credential,
            &format!(
                "EMERGENCY OVERRIDE: {} - Reason: {}",
                patient_id, request.emergency_reason
            ),
            session.claims.role,
        )
        .await?;

    Ok(Json(EmergencyOverrideResponse {
        override_token,
        expires_at: Utc::now() + Duration::hours(1), // 1 hour emergency access
        patient_id: patient_uuid,
    }))
}

#[derive(Clone)]
struct AppState {
    auth_service: MedicalAuthService,
    records_system: MedicalRecordsSystem,
}

type SharedState = Arc<AppState>;
type ApiResult<T> = std::result::Result<T, ApiError>;

impl AppState {
    async fn authorize(&self, headers: &HeaderMap) -> ApiResult<AuthenticatedSession> {
        let session_token = extract_session_token(headers)?;
        let claims = self.auth_service.validate_session(&session_token).await?;
        let workspace_access = self.records_system.create_session()?;

        Ok(AuthenticatedSession {
            claims,
            workspace_access,
        })
    }
}

// Marker types for record contents and capabilities
struct CanRead;
struct CanWrite;
struct CanAudit;
struct CanEmergencyOverride;

// Medical record type markers - what the path contains
struct PatientRecords;
struct VitalsData;
struct DiagnosisData;
struct PrescriptionData;
struct AuditLog;
struct EmergencyAccess;

// Capability types - how you can access it

#[derive(Clone)]
struct MedicalAuthService {
    sessions: Arc<RwLock<HashMap<String, MedicalSessionClaims>>>,
    users: Arc<RwLock<HashMap<String, MedicalUserRecord>>>,
    emergency_tokens: Arc<RwLock<HashMap<String, EmergencyToken>>>,
}

impl MedicalAuthService {
    fn new() -> Self {
        let mut users = HashMap::new();

        users.insert(
            "patient_alice".to_string(),
            MedicalUserRecord {
                credential: "patient_alice".to_string(),
                password: "pass123".to_string(),
                role: MedicalRole::Patient,
                patient_id: Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap()),
            },
        );

        users.insert(
            "nurse_bob".to_string(),
            MedicalUserRecord {
                credential: "nurse_bob".to_string(),
                password: "pass123".to_string(),
                role: MedicalRole::Nurse,
                patient_id: None,
            },
        );

        users.insert(
            "doctor_charlie".to_string(),
            MedicalUserRecord {
                credential: "doctor_charlie".to_string(),
                password: "pass123".to_string(),
                role: MedicalRole::Doctor,
                patient_id: None,
            },
        );

        users.insert(
            "admin_diana".to_string(),
            MedicalUserRecord {
                credential: "admin_diana".to_string(),
                password: "pass123".to_string(),
                role: MedicalRole::Admin,
                patient_id: None,
            },
        );

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(users)),
            emergency_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn sample_users(&self) -> Vec<MedicalUserRecord> {
        self.users.read().await.values().cloned().collect()
    }

    async fn authenticate(
        &self,
        credential: &str,
        password: &str,
    ) -> ApiResult<MedicalSessionClaims> {
        let users = self.users.read().await;
        let user = users
            .get(credential)
            .ok_or_else(|| ApiError::unauthorized("Invalid credentials"))?;

        if user.password != password {
            return Err(ApiError::unauthorized("Invalid credentials"));
        }

        let session_token = format!("medical_session_{}_{}", credential, Utc::now().timestamp());
        let capabilities = self.role_capabilities(&user.role);

        let claims = MedicalSessionClaims {
            credential: credential.to_string(),
            role: user.role,
            patient_id: user.patient_id,
            session_token: session_token.clone(),
            capabilities: capabilities.clone(),
        };

        self.sessions
            .write()
            .await
            .insert(session_token, claims.clone());
        Ok(claims)
    }

    async fn validate_session(&self, session_token: &str) -> ApiResult<MedicalSessionClaims> {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_token)
            .cloned()
            .ok_or_else(|| ApiError::unauthorized("Invalid session"))
    }

    async fn grant_emergency_override(
        &self,
        requestor: &str,
        patient_id: Uuid,
        reason: &str,
    ) -> ApiResult<String> {
        let token = format!("emergency_{}_{}", patient_id, Utc::now().timestamp());
        let emergency_token = EmergencyToken {
            token: token.clone(),
            requestor: requestor.to_string(),
            patient_id,
            reason: reason.to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        self.emergency_tokens
            .write()
            .await
            .insert(token.clone(), emergency_token);
        // Read fields to avoid dead-code warnings and aid debugging
        if let Some(stored) = self.emergency_tokens.read().await.get(&token) {
            eprintln!(
                "[emergency] token={} requestor={} patient_id={} reason={} expires_at={}",
                stored.token, stored.requestor, stored.patient_id, stored.reason, stored.expires_at
            );
        }
        Ok(token)
    }

    fn role_capabilities(&self, role: &MedicalRole) -> Vec<String> {
        match role {
            MedicalRole::Patient => vec![
                "read_own_vitals".to_string(),
                "read_own_diagnosis".to_string(),
                "read_own_prescriptions".to_string(),
            ],
            MedicalRole::Nurse => vec![
                "read_vitals".to_string(),
                "write_vitals".to_string(),
                "read_diagnosis".to_string(),
                "read_prescriptions".to_string(),
            ],
            MedicalRole::Doctor => vec![
                "read_vitals".to_string(),
                "write_vitals".to_string(),
                "read_diagnosis".to_string(),
                "write_diagnosis".to_string(),
                "read_prescriptions".to_string(),
                "write_prescriptions".to_string(),
                "emergency_override".to_string(),
            ],
            MedicalRole::Admin => vec![
                "read_vitals".to_string(),
                "write_vitals".to_string(),
                "read_diagnosis".to_string(),
                "write_diagnosis".to_string(),
                "read_prescriptions".to_string(),
                "write_prescriptions".to_string(),
                "audit".to_string(),
                "emergency_override".to_string(),
            ],
        }
    }
}

#[derive(Clone, Debug)]
struct MedicalUserRecord {
    credential: String,
    password: String,
    role: MedicalRole,
    patient_id: Option<Uuid>,
}

#[derive(Clone, Debug)]
struct MedicalSessionClaims {
    credential: String,
    role: MedicalRole,
    patient_id: Option<Uuid>,
    session_token: String,
    capabilities: Vec<String>,
}

#[derive(Clone, Debug)]
struct EmergencyToken {
    token: String,
    requestor: String,
    patient_id: Uuid,
    reason: String,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum MedicalRole {
    Patient,
    Nurse,
    Doctor,
    Admin,
}

#[derive(Clone)]
struct MedicalRecordsSystem {
    records_root: PathBoundary<(PatientRecords, CanRead)>,
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
}

impl MedicalRecordsSystem {
    fn new<P: AsRef<std::path::Path>>(root: P) -> Result<Self> {
        let records_root = PathBoundary::<(PatientRecords, CanRead)>::try_new_create(
            root.as_ref().join("patient_records"),
        )?;

        Ok(Self {
            records_root,
            audit_log: Arc::new(RwLock::new(Vec::new())),
        })
    }

    fn create_session(&self) -> Result<MedicalWorkspaceAccess> {
        Ok(MedicalWorkspaceAccess {
            records_root: self.records_root.clone(),
        })
    }

    async fn load_patient_summary(
        &self,
        _auth_proof: &PathBoundary<(PatientRecords, CanRead)>,
        patient_id: Uuid,
    ) -> Result<PatientSummary> {
        // This would normally load from database/files
        Ok(PatientSummary {
            patient_id,
            name: "Patient Name".to_string(),
            last_visit: Utc::now() - Duration::days(7),
        })
    }

    async fn log_access(&self, credential: &str, action: &str, role: MedicalRole) -> Result<()> {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            credential: credential.to_string(),
            action: action.to_string(),
            role,
        };

        self.audit_log.write().await.push(entry);
        Ok(())
    }

    async fn load_audit_entries(
        &self,
        _auth_proof: &PathBoundary<(AuditLog, CanAudit)>,
        limit: usize,
    ) -> Result<Vec<AuditEntry>> {
        let audit_log = self.audit_log.read().await;
        Ok(audit_log.iter().rev().take(limit).cloned().collect())
    }
}

#[derive(Clone)]
struct MedicalWorkspaceAccess {
    records_root: PathBoundary<(PatientRecords, CanRead)>,
}

struct AuthenticatedSession {
    claims: MedicalSessionClaims,
    workspace_access: MedicalWorkspaceAccess,
}

impl AuthenticatedSession {
    fn patient_records_access(
        &self,
        patient_id: Uuid,
    ) -> ApiResult<PathBoundary<(PatientRecords, CanRead)>> {
        // Check if user can access this patient's records
        match self.claims.role {
            MedicalRole::Patient => {
                if let Some(own_id) = self.claims.patient_id {
                    if own_id == patient_id {
                        let patient_dir = self
                            .workspace_access
                            .records_root
                            .strict_join(format!("patient_{}", patient_id))
                            .and_then(|p| p.try_into_boundary_create())
                            .map_err(|e| {
                                ApiError::internal(anyhow!("Failed to access patient records: {e}"))
                            })?;
                        Ok(patient_dir)
                    } else {
                        Err(ApiError::forbidden(
                            "Patients can only access their own records",
                        ))
                    }
                } else {
                    Err(ApiError::forbidden("Patient role without patient ID"))
                }
            }
            MedicalRole::Nurse | MedicalRole::Doctor | MedicalRole::Admin => {
                let patient_dir = self
                    .workspace_access
                    .records_root
                    .strict_join(format!("patient_{}", patient_id))
                    .and_then(|p| p.try_into_boundary_create())
                    .map_err(|e| {
                        ApiError::internal(anyhow!("Failed to access patient records: {e}"))
                    })?;
                Ok(patient_dir)
            }
        }
    }

    fn vitals_read_access(
        &self,
        patient_id: Uuid,
    ) -> ApiResult<PathBoundary<(VitalsData, CanRead)>> {
        // ✅ Authorization already validated: patient_records_access() checks access rights
        // ✅ Now encode read capability in type via change_marker()
        let patient_records = self.patient_records_access(patient_id)?;
        patient_records
            .clone()
            .into_strictpath()
            .map_err(|e| ApiError::internal(anyhow!("Failed to open vitals: {e}")))?
            .change_marker::<(VitalsData, CanRead)>()
            .try_into_boundary()
            .map_err(|e| ApiError::internal(anyhow!("Failed to open vitals: {e}")))
    }

    fn vitals_write_access(
        &self,
        patient_id: Uuid,
    ) -> ApiResult<PathBoundary<(VitalsData, CanWrite)>> {
        // ✅ Step 1: Check authorization (validate role has write capability)
        match self.claims.role {
            MedicalRole::Nurse | MedicalRole::Doctor | MedicalRole::Admin => {
                // ✅ Step 2: Authorization passed → encode it in type via change_marker()
                let patient_records = self.patient_records_access(patient_id)?;
                patient_records
                    .clone()
                    .into_strictpath()
                    .map_err(|e| {
                        ApiError::internal(anyhow!("Failed to open vitals for write: {e}"))
                    })?
                    .change_marker::<(VitalsData, CanWrite)>()
                    .try_into_boundary()
                    .map_err(|e| {
                        ApiError::internal(anyhow!("Failed to open vitals for write: {e}"))
                    })
            }
            MedicalRole::Patient => Err(ApiError::forbidden("Patients cannot write vitals")),
        }
    }

    fn diagnosis_read_access(
        &self,
        patient_id: Uuid,
    ) -> ApiResult<PathBoundary<(DiagnosisData, CanRead)>> {
        // ✅ Authorization already validated: patient_records_access() checks access rights
        // ✅ Now encode read capability in type via change_marker()
        let patient_records = self.patient_records_access(patient_id)?;
        patient_records
            .clone()
            .into_strictpath()
            .map_err(|e| ApiError::internal(anyhow!("Failed to open diagnosis: {e}")))?
            .change_marker::<(DiagnosisData, CanRead)>()
            .try_into_boundary()
            .map_err(|e| ApiError::internal(anyhow!("Failed to open diagnosis: {e}")))
    }

    fn diagnosis_write_access(
        &self,
        patient_id: Uuid,
    ) -> ApiResult<PathBoundary<(DiagnosisData, CanWrite)>> {
        // ✅ Step 1: Check authorization (only doctors can write diagnoses)
        match self.claims.role {
            MedicalRole::Doctor | MedicalRole::Admin => {
                // ✅ Step 2: Authorization passed → encode it in type via change_marker()
                let patient_records = self.patient_records_access(patient_id)?;
                patient_records
                    .clone()
                    .into_strictpath()
                    .map_err(|e| {
                        ApiError::internal(anyhow!("Failed to open diagnosis for write: {e}"))
                    })?
                    .change_marker::<(DiagnosisData, CanWrite)>()
                    .try_into_boundary()
                    .map_err(|e| {
                        ApiError::internal(anyhow!("Failed to open diagnosis for write: {e}"))
                    })
            }
            MedicalRole::Patient | MedicalRole::Nurse => {
                Err(ApiError::forbidden("Only doctors can write diagnoses"))
            }
        }
    }

    fn prescriptions_read_access(
        &self,
        patient_id: Uuid,
    ) -> ApiResult<PathBoundary<(PrescriptionData, CanRead)>> {
        // ✅ Authorization already validated: patient_records_access() checks access rights
        // ✅ Now encode read capability in type via change_marker()
        let patient_records = self.patient_records_access(patient_id)?;
        patient_records
            .clone()
            .into_strictpath()
            .map_err(|e| ApiError::internal(anyhow!("Failed to open prescriptions: {e}")))?
            .change_marker::<(PrescriptionData, CanRead)>()
            .try_into_boundary()
            .map_err(|e| ApiError::internal(anyhow!("Failed to open prescriptions: {e}")))
    }

    fn prescriptions_write_access(
        &self,
        patient_id: Uuid,
    ) -> ApiResult<PathBoundary<(PrescriptionData, CanWrite)>> {
        // ✅ Step 1: Check authorization (only doctors can write prescriptions)
        match self.claims.role {
            MedicalRole::Doctor | MedicalRole::Admin => {
                // ✅ Step 2: Authorization passed → encode it in type via change_marker()
                let patient_records = self.patient_records_access(patient_id)?;
                patient_records
                    .clone()
                    .into_strictpath()
                    .map_err(|e| {
                        ApiError::internal(anyhow!("Failed to open prescriptions for write: {e}"))
                    })?
                    .change_marker::<(PrescriptionData, CanWrite)>()
                    .try_into_boundary()
                    .map_err(|e| {
                        ApiError::internal(anyhow!("Failed to open prescriptions for write: {e}"))
                    })
            }
            MedicalRole::Patient | MedicalRole::Nurse => {
                Err(ApiError::forbidden("Only doctors can write prescriptions"))
            }
        }
    }

    fn audit_access(&self) -> ApiResult<PathBoundary<(AuditLog, CanAudit)>> {
        // ✅ Step 1: Check authorization (only admins can audit)
        match self.claims.role {
            MedicalRole::Admin => {
                // ✅ Step 2: Authorization passed → encode it in type via change_marker()
                self.workspace_access
                    .records_root
                    .clone()
                    .into_strictpath()
                    .map_err(|e| ApiError::internal(anyhow!("Failed to access audit logs: {e}")))?
                    .change_marker::<(AuditLog, CanAudit)>()
                    .try_into_boundary()
                    .map_err(|e| ApiError::internal(anyhow!("Failed to access audit logs: {e}")))
            }
            _ => Err(ApiError::forbidden("Only admins can access audit logs")),
        }
    }

    fn emergency_override_access(
        &self,
    ) -> ApiResult<PathBoundary<(EmergencyAccess, CanEmergencyOverride)>> {
        // ✅ Step 1: Check authorization (only doctors/admins can emergency override)
        match self.claims.role {
            MedicalRole::Doctor | MedicalRole::Admin => {
                // ✅ Step 2: Authorization passed → encode it in type via change_marker()
                self.workspace_access
                    .records_root
                    .clone()
                    .into_strictpath()
                    .map_err(|e| {
                        ApiError::internal(anyhow!("Failed to access emergency overrides: {e}"))
                    })?
                    .change_marker::<(EmergencyAccess, CanEmergencyOverride)>()
                    .try_into_boundary()
                    .map_err(|e| {
                        ApiError::internal(anyhow!("Failed to access emergency overrides: {e}"))
                    })
            }
            _ => Err(ApiError::forbidden(
                "Only doctors and admins can request emergency overrides",
            )),
        }
    }
}

// Data types
#[derive(Serialize)]
struct PatientSummary {
    patient_id: Uuid,
    name: String,
    last_visit: DateTime<Utc>,
}

#[derive(Clone, Serialize)]
struct AuditEntry {
    timestamp: DateTime<Utc>,
    credential: String,
    action: String,
    role: MedicalRole,
}

// Request/Response types
#[derive(Deserialize)]
struct LoginRequest {
    credential: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    session_token: String,
    role: MedicalRole,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
struct PatientRecordsResponse {
    records: PatientSummary,
}

#[derive(Serialize)]
struct VitalsResponse {
    patient_id: Uuid,
    data: String,
}

#[derive(Deserialize)]
struct UpdateVitalsRequest {
    vitals_data: String,
}

#[derive(Serialize)]
struct DiagnosisResponse {
    patient_id: Uuid,
    data: String,
}

#[derive(Deserialize)]
struct UpdateDiagnosisRequest {
    diagnosis_data: String,
}

#[derive(Serialize)]
struct PrescriptionsResponse {
    patient_id: Uuid,
    data: String,
}

#[derive(Deserialize)]
struct UpdatePrescriptionsRequest {
    prescriptions_data: String,
}

#[derive(Deserialize)]
struct AuditParams {
    limit: Option<usize>,
}

#[derive(Serialize)]
struct AuditLogResponse {
    entries: Vec<AuditEntry>,
}

#[derive(Deserialize)]
struct EmergencyOverrideRequest {
    emergency_reason: String,
}

#[derive(Serialize)]
struct EmergencyOverrideResponse {
    override_token: String,
    expires_at: DateTime<Utc>,
    patient_id: Uuid,
}

fn extract_session_token(headers: &HeaderMap) -> ApiResult<String> {
    headers
        .get("x-session-token")
        .ok_or_else(|| ApiError::unauthorized("Missing X-Session-Token header"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("Invalid session token format"))?
        .to_string()
        .pipe(Ok)
}

// Error handling
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized(message: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.to_string(),
        }
    }

    fn forbidden(message: &str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.to_string(),
        }
    }

    fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }

    fn from_anyhow(err: anyhow::Error) -> Self {
        Self::internal(err)
    }

    fn from_strict(err: strict_path::StrictPathError) -> Self {
        Self::internal(anyhow::anyhow!(err.to_string()))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.message
        }));
        (self.status, body).into_response()
    }
}

// Enable `?` conversion from common error types in this demo
impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::from_anyhow(err)
    }
}

impl From<strict_path::StrictPathError> for ApiError {
    fn from(err: strict_path::StrictPathError) -> Self {
        ApiError::from_strict(err)
    }
}

// Helper trait
trait Pipe<T> {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(T) -> R;
}

impl<T> Pipe<T> for T {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(T) -> R,
    {
        f(self)
    }
}

fn bootstrap_medical_system() -> Result<()> {
    let root = std::path::Path::new(SERVICE_ROOT);
    let patient_records = root.join("patient_records");

    std::fs::create_dir_all(&patient_records)?;

    let patient_id = "550e8400-e29b-41d4-a716-446655440001";
    let patient_dir = patient_records.join(format!("patient_{}", patient_id));
    std::fs::create_dir_all(&patient_dir)?;

    std::fs::write(
        patient_dir.join("vitals.json"),
        r#"{"blood_pressure": "120/80", "heart_rate": 72, "temperature": 98.6, "last_updated": "2024-01-01T10:00:00Z"}"#,
    )?;

    std::fs::write(
        patient_dir.join("diagnosis.json"),
        r#"{"primary_diagnosis": "Hypertension", "secondary_diagnoses": ["Diabetes Type 2"], "last_updated": "2024-01-01T09:30:00Z"}"#,
    )?;

    std::fs::write(
        patient_dir.join("prescriptions.json"),
        r#"{"medications": [{"name": "Lisinopril", "dosage": "10mg", "frequency": "daily"}, {"name": "Metformin", "dosage": "500mg", "frequency": "twice daily"}], "last_updated": "2024-01-01T09:45:00Z"}"#,
    )?;

    println!("Medical records system initialized with sample patient data");
    Ok(())
}
