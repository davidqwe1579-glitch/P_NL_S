use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

// ============================================================
// 상수
// ============================================================
/// 좀비 세션 타임아웃 (5분 = 300초)
const ZOMBIE_TIMEOUT_MINUTES: i64 = 5;

// ============================================================
// 앱 상태
// ============================================================
#[derive(Clone)]
struct AppState {
    db: MySqlPool,
}

// ============================================================
// 요청/응답 구조체
// ============================================================

// --- 로그인 ---
#[derive(Deserialize)]
struct LoginRequest {
    user_id: String,
    #[allow(dead_code)]
    program: Option<String>,
}

#[derive(Serialize)]
struct LoginResponse {
    status: String,
    message: Option<String>,
    session_id: Option<String>,
}

// --- Heartbeat ---
#[derive(Deserialize)]
struct HeartbeatRequest {
    user_id: String,
    session_id: String,
    #[allow(dead_code)]
    program: Option<String>,
}

#[derive(Serialize)]
struct HeartbeatResponse {
    action: Option<String>,
}

// --- 로그아웃 ---
#[derive(Deserialize)]
struct LogoutRequest {
    user_id: String,
    session_id: String,
    #[allow(dead_code)]
    program: Option<String>,
}

#[derive(Serialize)]
struct LogoutResponse {
    status: String,
}

// --- DB 유저 모델 (조회용) ---
#[derive(sqlx::FromRow)]
struct UserRow {
    user_id: String,
    expire_date: chrono::NaiveDateTime,
    auto_lie: i8,
    auto_lie_login: i8,
    auto_lie_token_hash: Option<String>,
}

// ============================================================
// 유틸: SHA256 해시
// ============================================================
fn sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ============================================================
// 핸들러: 로그인 (POST /api/login)
// ============================================================
async fn login_handler(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> (StatusCode, Json<LoginResponse>) {
    let user_id = body.user_id.trim();

    if user_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(LoginResponse {
                status: "error".into(),
                message: Some("아이디를 입력해주세요.".into()),
                session_id: None,
            }),
        );
    }

    // 1. 유저 조회
    let user = sqlx::query_as::<_, UserRow>(
        "SELECT user_id, expire_date, auto_lie, auto_lie_login, auto_lie_token_hash \
         FROM users WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(LoginResponse {
                    status: "error".into(),
                    message: Some("등록되지 않은 유저입니다.".into()),
                    session_id: None,
                }),
            );
        }
        Err(e) => {
            eprintln!("❌ DB 조회 실패: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse {
                    status: "error".into(),
                    message: Some("서버 오류가 발생했습니다.".into()),
                    session_id: None,
                }),
            );
        }
    };

    // 2. 권한 확인 (auto_lie == 1 이어야 함)
    if user.auto_lie != 1 {
        return (
            StatusCode::FORBIDDEN,
            Json(LoginResponse {
                status: "error".into(),
                message: Some("거탐 사용 권한이 없습니다.".into()),
                session_id: None,
            }),
        );
    }

    // 3. 만료일 확인 (진짜 서버 시간 기준으로 비교)
    let now = chrono::Local::now().naive_local();
    if user.expire_date < now {
        return (
            StatusCode::FORBIDDEN,
            Json(LoginResponse {
                status: "error".into(),
                message: Some("사용 기간이 만료되었습니다.".into()),
                session_id: None,
            }),
        );
    }

    // 4. 중복 로그인 차단 (auto_lie_login == 1 이면 무조건 차단)
    if user.auto_lie_login == 1 {
        return (
            StatusCode::CONFLICT,
            Json(LoginResponse {
                status: "error".into(),
                message: Some("이미 접속 중입니다. 기존 프로그램을 종료해주세요.".into()),
                session_id: None,
            }),
        );
    }

    // 5. 세션 발급
    let session_id = uuid::Uuid::new_v4().to_string();
    let token_hash = sha256_hash(&session_id);

    let result = sqlx::query(
        "UPDATE users SET auto_lie_login = 1, \
         auto_lie_token_hash = ?, \
         auto_lie_last_ping = NOW() \
         WHERE user_id = ?",
    )
    .bind(&token_hash)
    .bind(user_id)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            println!(
                "✅ [LOGIN] {} 로그인 성공 (만료: {})",
                user.user_id,
                user.expire_date.format("%Y-%m-%d %H:%M")
            );
            (
                StatusCode::OK,
                Json(LoginResponse {
                    status: "ok".into(),
                    message: None,
                    session_id: Some(session_id),
                }),
            )
        }
        Err(e) => {
            eprintln!("❌ DB 업데이트 실패: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse {
                    status: "error".into(),
                    message: Some("로그인 처리 중 오류가 발생했습니다.".into()),
                    session_id: None,
                }),
            )
        }
    }
}

// ============================================================
// 핸들러: Heartbeat (POST /api/heartbeat)
// ============================================================
async fn heartbeat_handler(
    State(state): State<AppState>,
    Json(body): Json<HeartbeatRequest>,
) -> (StatusCode, Json<HeartbeatResponse>) {
    let user_id = body.user_id.trim();
    let token_hash = sha256_hash(&body.session_id);

    // 1. 유저 조회 및 세션 검증
    let user = sqlx::query_as::<_, UserRow>(
        "SELECT user_id, expire_date, auto_lie, auto_lie_login, auto_lie_token_hash \
         FROM users WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        _ => {
            return (
                StatusCode::OK,
                Json(HeartbeatResponse {
                    action: Some("kick".into()),
                }),
            );
        }
    };

    // 2. 세션 토큰 해시 불일치 → kick (다른 곳에서 로그인했거나 세션 무효)
    let stored_hash = user.auto_lie_token_hash.unwrap_or_default();
    if stored_hash != token_hash {
        return (
            StatusCode::OK,
            Json(HeartbeatResponse {
                action: Some("kick".into()),
            }),
        );
    }

    // 3. 만료일 확인 (진짜 서버 시간 기준으로 비교)
    let now = chrono::Local::now().naive_local();
    if user.expire_date < now {
        // 만료 → 로그아웃 처리 후 kick
        let _ = sqlx::query(
            "UPDATE users SET auto_lie_login = 0, auto_lie_token_hash = NULL \
             WHERE user_id = ?",
        )
        .bind(user_id)
        .execute(&state.db)
        .await;

        println!("⏰ [EXPIRE] {} 만료로 kick 처리", user_id);
        return (
            StatusCode::OK,
            Json(HeartbeatResponse {
                action: Some("kick".into()),
            }),
        );
    }

    // 4. last_ping 갱신
    let _ = sqlx::query(
        "UPDATE users SET auto_lie_last_ping = NOW() WHERE user_id = ?",
    )
    .bind(user_id)
    .execute(&state.db)
    .await;

    (
        StatusCode::OK,
        Json(HeartbeatResponse { action: None }),
    )
}

// ============================================================
// 핸들러: 로그아웃 (POST /api/logout)
// ============================================================
async fn logout_handler(
    State(state): State<AppState>,
    Json(body): Json<LogoutRequest>,
) -> (StatusCode, Json<LogoutResponse>) {
    let user_id = body.user_id.trim();
    let token_hash = sha256_hash(&body.session_id);

    // 세션 검증 후 로그아웃
    let result = sqlx::query(
        "UPDATE users SET auto_lie_login = 0, auto_lie_token_hash = NULL \
         WHERE user_id = ? AND auto_lie_token_hash = ?",
    )
    .bind(user_id)
    .bind(&token_hash)
    .execute(&state.db)
    .await;

    match result {
        Ok(r) => {
            if r.rows_affected() > 0 {
                println!("👋 [LOGOUT] {} 정상 로그아웃", user_id);
            }
            (StatusCode::OK, Json(LogoutResponse { status: "ok".into() }))
        }
        Err(_) => (StatusCode::OK, Json(LogoutResponse { status: "ok".into() })),
    }
}

// ============================================================
// 핸들러: 헬스체크 (GET /health)
// ============================================================
async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "p-nl-server (auto_lie)",
        "port": 8090
    }))
}

// ============================================================
// 백그라운드: 좀비 세션 정리 (5분 타임아웃)
// ============================================================
async fn zombie_cleanup_task(pool: MySqlPool) {
    println!("🧹 좀비 세션 정리 태스크 시작 ({}분 타임아웃)", ZOMBIE_TIMEOUT_MINUTES);

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

        let result = sqlx::query(
            "UPDATE users SET auto_lie_login = 0, auto_lie_token_hash = NULL \
             WHERE auto_lie_login = 1 \
             AND auto_lie_last_ping < DATE_SUB(NOW(), INTERVAL ? MINUTE)",
        )
        .bind(ZOMBIE_TIMEOUT_MINUTES)
        .execute(&pool)
        .await;

        match result {
            Ok(r) => {
                let cleaned = r.rows_affected();
                if cleaned > 0 {
                    println!(
                        "🧹 [ZOMBIE] {}개 좀비 세션 자동 로그아웃 처리",
                        cleaned
                    );
                }
            }
            Err(e) => {
                eprintln!("❌ 좀비 정리 실패: {}", e);
            }
        }
    }
}

// ============================================================
// 메인
// ============================================================
#[tokio::main]
async fn main() {
    println!("🚀 P_NL Server (거탐) starting on port 8090 (HTTP)...");

    // DB 연결
    let db_url = "mysql://user_accunt:Aa102331253910!@127.0.0.1:3306/maplestory_bot";
    let pool = MySqlPoolOptions::new()
        .max_connections(20)
        .connect(db_url)
        .await
        .expect("❌ DB 연결 실패");

    println!("✅ DB 연결 성공 (maplestory_bot)");

    // 서버 시작 시 모든 좀비 세션 정리 (이전 서버 크래시 대비)
    let startup_clean = sqlx::query(
        "UPDATE users SET auto_lie_login = 0, auto_lie_token_hash = NULL \
         WHERE auto_lie_login = 1 \
         AND auto_lie_last_ping < DATE_SUB(NOW(), INTERVAL ? MINUTE)",
    )
    .bind(ZOMBIE_TIMEOUT_MINUTES)
    .execute(&pool)
    .await;

    if let Ok(r) = startup_clean {
        let count = r.rows_affected();
        if count > 0 {
            println!("🧹 서버 시작 시 {}개 좀비 세션 정리 완료", count);
        }
    }

    // 좀비 세션 정리 백그라운드 태스크 시작
    let zombie_pool = pool.clone();
    tokio::spawn(async move {
        zombie_cleanup_task(zombie_pool).await;
    });

    let state = AppState { db: pool };

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/api/login", post(login_handler))
        .route("/api/heartbeat", post(heartbeat_handler))
        .route("/api/logout", post(logout_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8090));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("✅ Server is running on http://{}", addr);
    println!("   - GET  /health          (헬스체크)");
    println!("   - POST /api/login       (로그인)");
    println!("   - POST /api/heartbeat   (하트비트)");
    println!("   - POST /api/logout      (로그아웃)");
    println!("   ─────────────────────────────────");
    println!("   좀비 타임아웃: {}분", ZOMBIE_TIMEOUT_MINUTES);

    axum::serve(listener, app).await.unwrap();
}
