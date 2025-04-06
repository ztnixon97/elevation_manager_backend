use chrono::{NaiveDate, NaiveDateTime};
use serde::{Deserialize, Serialize};
use sqlx::postgres::types::PgRange;
use sqlx::FromRow;
use std::ops::Bound;
use utoipa::ToSchema;

/// ✅ Wrapper for `PgRange<NaiveDate>` to provide OpenAPI schema support.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(
    example = "[2023-01-01, 2023-12-31)",
    description = "PostgreSQL date range using inclusive/exclusive brackets."
)]
pub struct PgDateRange {
    pub start: Option<NaiveDate>,
    pub start_inclusive: bool,
    pub end: Option<NaiveDate>,
    pub end_inclusive: bool,
}

/// ✅ Convert `PgRange<NaiveDate>` → `PgDateRange`
impl From<PgRange<NaiveDate>> for PgDateRange {
    fn from(range: PgRange<NaiveDate>) -> Self {
        let (start, start_inclusive) = match range.start {
            Bound::Included(d) => (Some(d), true),
            Bound::Excluded(d) => (Some(d), false),
            Bound::Unbounded => (None, false),
        };
        let (end, end_inclusive) = match range.end {
            Bound::Included(d) => (Some(d), true),
            Bound::Excluded(d) => (Some(d), false),
            Bound::Unbounded => (None, false),
        };
        Self {
            start,
            start_inclusive,
            end,
            end_inclusive,
        }
    }
}

/// ✅ Convert `PgDateRange` back into `PgRange<NaiveDate>`
impl Into<PgRange<NaiveDate>> for PgDateRange {
    fn into(self) -> PgRange<NaiveDate> {
        let start = match (self.start, self.start_inclusive) {
            (Some(date), true) => Bound::Included(date),
            (Some(date), false) => Bound::Excluded(date),
            (None, _) => Bound::Unbounded,
        };
        let end = match (self.end, self.end_inclusive) {
            (Some(date), true) => Bound::Included(date),
            (Some(date), false) => Bound::Excluded(date),
            (None, _) => Bound::Unbounded,
        };
        PgRange { start, end }
    }
}

/// ✅ Main Database Model for `TaskOrder`
#[derive(Debug, FromRow, Serialize, Deserialize, ToSchema)]
pub struct TaskOrder {
    pub id: i32,
    pub contract_id: i32,
    pub name: String,
    pub producer: Option<String>,
    pub cor: Option<String>,

    #[serde(
        serialize_with = "serialize_optional_bracket_range",
        deserialize_with = "deserialize_optional_bracket_range"
    )]
    #[schema(value_type = PgDateRange)] // ✅ Use OpenAPI-friendly wrapper
    pub pop: Option<PgRange<NaiveDate>>,

    pub price: Option<f64>,
    pub status: String,
    pub created_at: Option<NaiveDateTime>,
}

/// ✅ Model for Creating a New `TaskOrder`
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewTaskOrder {
    pub contract_id: i32,
    pub name: String,
    pub status: String,

    pub producer: Option<String>,
    pub cor: Option<String>,

    #[serde(default, deserialize_with = "deserialize_optional_bracket_range")]
    #[schema(value_type = PgDateRange)] // ✅ OpenAPI-friendly schema
    pub pop: Option<PgRange<NaiveDate>>,

    pub price: Option<f64>,
}

/// ✅ Model for Updating an Existing `TaskOrder`
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTaskOrder {
    pub contract_id: Option<i32>,
    pub name: Option<String>,
    pub producer: Option<String>,
    pub cor: Option<String>,

    #[serde(default, deserialize_with = "deserialize_optional_bracket_range")]
    #[schema(value_type = PgDateRange)] // ✅ OpenAPI-friendly schema
    pub pop: Option<PgRange<NaiveDate>>,

    pub price: Option<f64>,
    pub status: Option<String>,
}

impl UpdateTaskOrder {
    /// ✅ Returns `true` if all fields are `None`.
    pub fn is_empty(&self) -> bool {
        self.contract_id.is_none()
            && self.name.is_none()
            && self.producer.is_none()
            && self.cor.is_none()
            && self.pop.is_none()
            && self.price.is_none()
            && self.status.is_none()
    }
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct TaskIdResponse {
    pub id: i32,
}

// =========================================================
// ✅ Custom Serde Code for Serializing `PgRange<NaiveDate>`
// =========================================================
use serde::de::Deserializer;
use serde::ser::Serializer;

pub fn serialize_optional_bracket_range<S>(
    range_opt: &Option<PgRange<NaiveDate>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match range_opt {
        Some(range) => {
            let bracket_str = bracket_range_to_string(range);
            serializer.serialize_some(&bracket_str)
        }
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_optional_bracket_range<'de, D>(
    deserializer: D,
) -> Result<Option<PgRange<NaiveDate>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_str: Option<String> = Option::deserialize(deserializer)?;
    if let Some(s) = opt_str {
        let parsed = bracket_str_to_pgrange(&s).map_err(serde::de::Error::custom)?;
        Ok(Some(parsed))
    } else {
        Ok(None)
    }
}

/// ✅ Converts `PgRange<NaiveDate>` into a bracket range string: `[YYYY-MM-DD, YYYY-MM-DD)`
fn bracket_range_to_string(range: &PgRange<NaiveDate>) -> String {
    let (start_char, start_date) = match &range.start {
        Bound::Included(d) => ('[', Some(*d)),
        Bound::Excluded(d) => ('(', Some(*d)),
        Bound::Unbounded => ('(', None),
    };
    let (end_char, end_date) = match &range.end {
        Bound::Included(d) => (']', Some(*d)),
        Bound::Excluded(d) => (')', Some(*d)),
        Bound::Unbounded => (')', None),
    };

    let lower_str = start_date
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();
    let upper_str = end_date
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    format!("{}{}, {}{}", start_char, lower_str, upper_str, end_char)
}

/// ✅ Converts a bracket range string `[YYYY-MM-DD, YYYY-MM-DD)` into `PgRange<NaiveDate>`
fn bracket_str_to_pgrange(s: &str) -> Result<PgRange<NaiveDate>, String> {
    let s = s.trim();
    if s.len() < 2 {
        return Err("Range string too short".into());
    }

    let first_char = s.chars().next().unwrap();
    let last_char = s.chars().last().unwrap();

    let lower_inclusive = first_char == '[';
    let upper_inclusive = last_char == ']';

    let inside = &s[1..s.len() - 1].trim();
    let parts: Vec<&str> = inside.split(',').map(|p| p.trim()).collect();
    if parts.len() != 2 {
        return Err("Range string must have exactly one comma".into());
    }

    let lower_bound = if parts[0].is_empty() {
        Bound::Unbounded
    } else {
        let d = NaiveDate::parse_from_str(parts[0], "%Y-%m-%d").map_err(|e| e.to_string())?;
        if lower_inclusive {
            Bound::Included(d)
        } else {
            Bound::Excluded(d)
        }
    };

    let upper_bound = if parts[1].is_empty() {
        Bound::Unbounded
    } else {
        let d = NaiveDate::parse_from_str(parts[1], "%Y-%m-%d").map_err(|e| e.to_string())?;
        if upper_inclusive {
            Bound::Included(d)
        } else {
            Bound::Excluded(d)
        }
    };

    Ok(PgRange {
        start: lower_bound,
        end: upper_bound,
    })
}
