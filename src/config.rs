use dotenvy::dotenv;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// ✅ Global Config stored in `OnceLock`
static CONFIG: OnceLock<Arc<Config>> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub auth_disabled: bool,
    pub review_storage_path: PathBuf,
    pub review_image_storage_path: PathBuf,
}

impl Config {
    /// ✅ Load environment variables and set defaults
    pub fn from_env() -> Self {
        dotenv().ok(); // Load .env only once

        Self {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            jwt_secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
            auth_disabled: env::var("AUTH_DISABLED").unwrap_or_else(|_| "false".to_string())
                == "true",
            review_storage_path: PathBuf::from(
                env::var("REVIEW_STORAGE_PATH")
                    .unwrap_or_else(|_| "C:\\reviews\\content".to_string()),
            ),
            review_image_storage_path: PathBuf::from(
                env::var("REVIEW_IMAGE_STORAGE_PATH")
                    .unwrap_or_else(|_| "C:\\reviews\\images".to_string()),
            ),
        }
    }

    /// ✅ Initialize the global config
    pub fn init() {
        CONFIG
            .set(Arc::new(Self::from_env()))
            .expect("Config already initialized");
    }

    /// ✅ Safe access to Config
    pub fn get() -> Arc<Config> {
        CONFIG.get().expect("Config not initialized").clone()
    }

    /// ✅ Check if authentication is disabled
    pub fn auth_disabled() -> bool {
        Config::get().auth_disabled
    }
}
